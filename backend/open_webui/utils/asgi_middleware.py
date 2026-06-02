"""
Pure-ASGI replacements for the project's previous
`@app.middleware('http')` / `BaseHTTPMiddleware` middlewares.

Why this matters
----------------
Starlette's `BaseHTTPMiddleware` (which `@app.middleware('http')` is
sugar for) runs the downstream app inside an `anyio` task group. When
the wrapper exits — for any reason: response complete, client
disconnect, an outer middleware bailing out — the task group cancels
the inner task. That `CancelledError` then propagates into whatever
the inner task was doing, including in-flight DB queries, embedding
calls and disk I/O.

In Open WebUI this surfaces as:

* SQLAlchemy logging multi-page `NotImplementedError:
  terminate_force_close()` tracebacks at ERROR every time a request is
  cancelled mid-DB-call (the aiosqlite connector cleanup path).
* Spurious cancellations cascading through the four stacked
  `@app.middleware('http')` wrappers.

Pure ASGI middleware does not introduce a cancel scope around the
downstream app, so client disconnects propagate the way ASGI was
designed to (via `receive()` returning `http.disconnect`) instead of
being injected as `CancelledError` into arbitrary `await` points.

Reference: https://www.starlette.io/middleware/#limitations
"""

from __future__ import annotations

import logging
import re
import time
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import aiohttp

from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials
from open_webui.env import CUSTOM_API_KEY_HEADER
from open_webui.internal.db import ScopedSession
from open_webui.utils.auth import get_http_authorization_cred
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from open_webui.env import AIOHTTP_CLIENT_SESSION_SSL, CUSTOM_API_KEY_HEADER
from open_webui.internal.db import ScopedSession
from open_webui.utils.auth import get_http_authorization_cred
from open_webui.utils.auth_callback_proxy_security import (
    MAX_CALLBACK_BODY_BYTES,
    is_valid_callback_proxy_config,
    sanitize_url_for_log,
    strip_sensitive_response_headers,
)

log = logging.getLogger(__name__)


class CommitSessionMiddleware:
    """Commit and release the thread-local sync `ScopedSession` after each
    HTTP request.

    Most requests now use the async session; the sync ScopedSession is
    only touched by startup, healthchecks, and a handful of legacy
    helpers (notably the pgvector / opengauss vector-DB clients). The
    middleware exists so that PostgreSQL connections do not accumulate
    as "idle in transaction" and so that any pending sync work made
    inside the request is durably persisted.

    Failure semantics
    -----------------
    * Downstream raised → roll back any pending sync work, release the
      connection, and re-raise so the outer exception middleware can
      turn it into an error response. We never commit work on a
      request that did not complete successfully.
    * Downstream returned → commit pending sync work; on commit
      failure, log loudly, roll back, and re-raise. Note that in pure
      ASGI the response messages have already been emitted by the
      time `await self.app(...)` returns, so a commit failure cannot
      retroactively change what the client sees on the wire — but
      re-raising still surfaces the error in logs and to ASGI servers
      that expose it. We deliberately do not buffer the response to
      gate it on commit success, because that would defeat streaming
      responses (chat completions, SSE) which are core to the app.

    For request paths where commit-before-send is required, manage the
    sync session explicitly inside the handler instead of relying on
    this middleware.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return

        path = scope.get('path', '')
        # Keep health probes independent from sync session commit/remove
        # so DB pressure cannot delay or fail probe responses.
        if path in {'/health', '/ready', '/health/db'}:
            await self.app(scope, receive, send)
            return

        try:
            await self.app(scope, receive, send)
        except BaseException:
            # Downstream did not complete successfully. Roll back any
            # pending sync writes, release the connection, and let the
            # exception propagate.
            try:
                ScopedSession.rollback()
            except Exception:
                log.exception('CommitSessionMiddleware: rollback failed after downstream error')
            finally:
                ScopedSession.remove()
            raise

        # Downstream completed. Commit pending sync work.
        try:
            ScopedSession.commit()
        except Exception:
            log.exception('CommitSessionMiddleware: post-request commit failed; response was already sent to client')
            try:
                ScopedSession.rollback()
            except Exception:
                log.exception('CommitSessionMiddleware: rollback failed after commit failure')
            raise
        finally:
            # CRITICAL: remove() returns the connection to the pool.
            # Without this, connections remain "checked out" and
            # accumulate as "idle in transaction" in PostgreSQL.
            ScopedSession.remove()


class AuthTokenMiddleware:
    """Extract the bearer/cookie/API-key credential and stash it on
    `request.state.token`.

    The header used for API-key transport is controlled by the
    ``CUSTOM_API_KEY_HEADER`` environment variable (default ``x-api-key``).
    This is useful when Open WebUI sits behind a reverse proxy that
    consumes the ``Authorization`` header for its own authentication —
    set the env var to a unique header (e.g. ``X-OpenWebUI-Key``) so
    the middleware checks that instead and avoids the 401 short-circuit.

    Routes that depend on `get_verified_user` etc. read this state.
    Also exposes `request.state.enable_api_keys` (snapshotted at request
    entry from runtime config) and stamps an `X-Process-Time` response
    header.
    """

    def __init__(self, app: ASGIApp, *, fastapi_app) -> None:
        self.app = app
        self._fastapi_app = fastapi_app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return

        start_time = time.monotonic()
        request = Request(scope)

        token = get_http_authorization_cred(request.headers.get('Authorization'))
        if token is None:
            cookie_token = request.cookies.get('token')
            if cookie_token:
                token = HTTPAuthorizationCredentials(scheme='Bearer', credentials=cookie_token)
        if token is None:
            api_key = request.headers.get(CUSTOM_API_KEY_HEADER)
            if api_key:
                token = HTTPAuthorizationCredentials(scheme='Bearer', credentials=api_key)

        request.state.token = token
        request.state.enable_api_keys = self._fastapi_app.state.config.ENABLE_API_KEYS

        async def send_with_timing(message: Message) -> None:
            if message['type'] == 'http.response.start':
                process_time = int(time.monotonic() - start_time)
                headers = MutableHeaders(scope=message)
                headers['X-Process-Time'] = str(process_time)
            await send(message)

        await self.app(scope, receive, send_with_timing)


class AuthCallbackProxyMiddleware:
    """Proxy configured OAuth callback paths to tool servers.

    Configuration is read from ``TOOL_SERVER_CONNECTIONS[].config.auth_callback_proxy``.
    Example:

    ``{"enabled": true, "host": "ai.example.com", "path": "/auth/callback", "url": "http://localhost:8100/auth/callback"}``
    """

    PROXY_METHODS = frozenset({'GET', 'POST', 'HEAD'})
    STRIPPED_RESPONSE_HEADERS = frozenset({'content-length', 'transfer-encoding', 'connection'})

    def __init__(self, app: ASGIApp, *, fastapi_app) -> None:
        self.app = app
        self._fastapi_app = fastapi_app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return

        method = scope.get('method', '').upper()
        if method not in self.PROXY_METHODS:
            await self.app(scope, receive, send)
            return

        target_url = self._resolve_target_url(scope)
        if target_url is None:
            await self.app(scope, receive, send)
            return

        try:
            body = await self._read_request_body(receive)
        except ValueError:
            response = JSONResponse(
                status_code=413,
                content={'detail': 'Auth callback request body too large'},
            )
            await response(scope, receive, send)
            return

        if body is None:
            return

        target_url = self._append_query(target_url, scope.get('query_string', b''))

        request_headers = _scope_headers(scope)
        proxy_headers = {
            key: value
            for key, value in request_headers.items()
            if key not in {'host', 'content-length', 'connection'}
        }

        host_header = request_headers.get('host', '').strip()
        if host_header and 'x-forwarded-host' not in proxy_headers:
            proxy_headers['x-forwarded-host'] = host_header
        if 'x-forwarded-proto' not in proxy_headers:
            proxy_headers['x-forwarded-proto'] = scope.get('scheme', 'http')

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60, connect=10),
                trust_env=True,
            ) as session:
                async with session.request(
                    method=method,
                    url=target_url,
                    headers=proxy_headers,
                    data=body or None,
                    allow_redirects=False,
                    ssl=AIOHTTP_CLIENT_SESSION_SSL,
                ) as upstream_response:
                    response_body = await upstream_response.read()
                    response_headers = [
                        (key.encode('latin-1'), value.encode('latin-1'))
                        for key, value in strip_sensitive_response_headers(upstream_response.headers)
                        if key.lower() not in self.STRIPPED_RESPONSE_HEADERS
                    ]

                    await send(
                        {
                            'type': 'http.response.start',
                            'status': upstream_response.status,
                            'headers': response_headers,
                        }
                    )
                    await send(
                        {
                            'type': 'http.response.body',
                            'body': response_body,
                            'more_body': False,
                        }
                    )
                    return
        except Exception:
            log.exception('Auth callback proxy failed for target=%s', sanitize_url_for_log(target_url))
            response = JSONResponse(status_code=502, content={'detail': 'Auth callback proxy failed'})
            await response(scope, receive, send)

    async def _read_request_body(self, receive: Receive) -> bytes | None:
        chunks = []
        total_size = 0
        while True:
            message = await receive()
            message_type = message.get('type')

            if message_type == 'http.disconnect':
                return None

            if message_type != 'http.request':
                continue

            chunk = message.get('body', b'')
            total_size += len(chunk)
            if total_size > MAX_CALLBACK_BODY_BYTES:
                raise ValueError('auth callback request body exceeds size limit')

            chunks.append(chunk)
            if not message.get('more_body', False):
                break

        return b''.join(chunks)

    def _resolve_target_url(self, scope: Scope) -> str | None:
        request_path = self._normalize_callback_path(scope.get('path', ''))
        if not request_path:
            return None

        request_headers = _scope_headers(scope)
        request_host_full = request_headers.get('host', '').strip().lower()
        request_host_name = request_host_full.split(':', 1)[0]

        connections = getattr(self._fastapi_app.state.config, 'TOOL_SERVER_CONNECTIONS', []) or []

        for connection in connections:
            callback_proxy = (connection.get('config') or {}).get('auth_callback_proxy') or {}
            if not isinstance(callback_proxy, dict) or not callback_proxy.get('enabled'):
                continue

            if not is_valid_callback_proxy_config(callback_proxy):
                continue

            configured_host = str(callback_proxy.get('host', '')).strip().lower()
            if not configured_host:
                continue

            callback_path = self._normalize_callback_path(str(callback_proxy.get('path', '')))
            callback_target_url = str(callback_proxy.get('url', '')).strip()
            if not callback_path or not callback_target_url:
                continue
            if request_path != callback_path:
                continue

            parsed_target = urlsplit(callback_target_url)
            if parsed_target.scheme not in {'http', 'https'} or not parsed_target.netloc:
                continue

            if ':' in configured_host:
                if request_host_full != configured_host:
                    continue
            elif request_host_name != configured_host:
                continue

            return callback_target_url

        return None

    def _normalize_callback_path(self, path: str) -> str:
        normalized = (path or '').strip()
        if not normalized:
            return ''

        if '://' in normalized:
            normalized = urlsplit(normalized).path

        normalized = normalized.split('?', 1)[0]
        if not normalized:
            return ''

        if not normalized.startswith('/'):
            normalized = f'/{normalized}'

        if normalized != '/' and normalized.endswith('/'):
            normalized = normalized[:-1]

        return normalized

    def _append_query(self, target_url: str, query_string_bytes: bytes) -> str:
        raw_query = query_string_bytes.decode('latin-1', errors='replace')
        if not raw_query:
            return target_url

        parsed = urlsplit(target_url)
        merged_query = f'{parsed.query}&{raw_query}' if parsed.query else raw_query
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, merged_query, parsed.fragment))


class WebsocketUpgradeGuardMiddleware:
    """Reject HTTP requests to `/ws/socket.io` that claim
    `transport=websocket` but lack the proper `Upgrade`/`Connection`
    headers.

    Works around https://github.com/miguelgrinberg/python-engineio/issues/367
    where engineio mishandles such requests.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return

        path = scope.get('path', '')
        if '/ws/socket.io' in path:
            query_string = scope.get('query_string', b'').decode('latin-1', errors='replace')
            query_params = parse_qs(query_string)
            if query_params.get('transport', [''])[0] == 'websocket':
                headers = _scope_headers(scope)
                upgrade = headers.get('upgrade', '').lower()
                connection_tokens = [token.strip() for token in headers.get('connection', '').lower().split(',')]
                if upgrade != 'websocket' or 'upgrade' not in connection_tokens:
                    response = JSONResponse(
                        status_code=400,
                        content={'detail': 'Invalid WebSocket upgrade request'},
                    )
                    await response(scope, receive, send)
                    return

        await self.app(scope, receive, send)


class RedirectMiddleware:
    """Rewrites a couple of legacy entry-points to the SPA's own routes:

    * ``GET /watch?v=ID`` (YouTube) → ``/?youtube=ID``
    * ``GET /?shared=…`` (PWA share-target) → ``/?youtube=…`` /
      ``/?load-url=…`` / ``/?q=…``
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] != 'http' or scope.get('method', '').upper() != 'GET':
            await self.app(scope, receive, send)
            return

        path = scope.get('path', '')
        query_string = scope.get('query_string', b'').decode('latin-1', errors='replace')
        query_params = parse_qs(query_string)

        redirect_params: dict[str, str] = {}
        if path.endswith('/watch') and 'v' in query_params and query_params['v']:
            redirect_params['youtube'] = query_params['v'][0]

        if 'shared' in query_params and query_params['shared']:
            text = query_params['shared'][0]
            if text:
                url_match = re.match(r'https://\S+', text)
                if url_match:
                    # Local import: youtube loader pulls heavy deps and is
                    # only needed when a share-target actually contains a
                    # YouTube URL.
                    from open_webui.retrieval.loaders.youtube import _parse_video_id

                    youtube_video_id = _parse_video_id(url_match[0])
                    if youtube_video_id:
                        redirect_params['youtube'] = youtube_video_id
                    else:
                        redirect_params['load-url'] = url_match[0]
                else:
                    redirect_params['q'] = text

        if redirect_params:
            redirect_url = f'/?{urlencode(redirect_params)}'
            response = RedirectResponse(url=redirect_url)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


def _scope_headers(scope: Scope) -> dict[str, str]:
    """Return ASGI scope headers as a lower-cased str→str dict.

    ASGI delivers headers as a list of (bytes, bytes) pairs. For
    convenience, fold duplicate keys with comma-joining (matching
    HTTP/1.1 semantics).
    """
    decoded: dict[str, str] = {}
    for raw_key, raw_value in scope.get('headers', []):
        key = raw_key.decode('latin-1').lower()
        value = raw_value.decode('latin-1')
        if key in decoded:
            decoded[key] = f'{decoded[key]}, {value}'
        else:
            decoded[key] = value
    return decoded

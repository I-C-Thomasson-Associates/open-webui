"""Extension-owned OAuth callback proxy for configured tool servers."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

import aiohttp
from fastapi.responses import JSONResponse
from open_webui.env import AIOHTTP_CLIENT_SESSION_SSL, CUSTOM_API_KEY_HEADER
from open_webui.models.config import Config
from open_webui.utils.auth_callback_proxy_security import (
    MAX_CALLBACK_BODY_BYTES,
    is_valid_callback_proxy_config,
    sanitize_url_for_log,
    strip_sensitive_response_headers,
)
from starlette.types import ASGIApp, Receive, Scope, Send

log = logging.getLogger(__name__)
_HOP_BY_HOP_HEADERS = frozenset({'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade'})


def _scope_headers(scope: Scope) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw_key, raw_value in scope.get('headers', []):
        key = raw_key.decode('latin-1').lower()
        value = raw_value.decode('latin-1')
        headers[key] = f'{headers[key]}, {value}' if key in headers else value
    return headers


def filter_hop_by_hop_headers(
    headers: Mapping[str, str] | Iterable[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Remove standard and Connection-nominated hop-by-hop fields."""
    items = list(headers.items() if isinstance(headers, Mapping) else headers)
    connection_tokens = {
        token.strip().lower()
        for key, value in items
        if key.lower() == 'connection'
        for token in value.split(',')
        if token.strip()
    }
    return [
        (key, value) for key, value in items
        if key.lower() not in _HOP_BY_HOP_HEADERS | connection_tokens
    ]


class AuthCallbackProxyMiddleware:
    """Proxy configured callback paths without forwarding browser credentials."""

    PROXY_METHODS = frozenset({'GET', 'POST', 'HEAD'})
    STRIPPED_RESPONSE_HEADERS = frozenset({'content-length', 'transfer-encoding', 'connection'})

    def __init__(self, app: ASGIApp, *, fastapi_app) -> None:
        self.app = app
        self._fastapi_app = fastapi_app
        self._connections_cache: list[dict] = []
        self._connections_cache_expiry = 0.0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] != 'http' or scope.get('method', '').upper() not in self.PROXY_METHODS:
            await self.app(scope, receive, send)
            return
        target_url = await self._resolve_target_url(scope)
        if target_url is None:
            await self.app(scope, receive, send)
            return
        try:
            body = await self._read_request_body(receive)
        except ValueError:
            await JSONResponse(status_code=413, content={'detail': 'Auth callback request body too large'})(scope, receive, send)
            return
        if body is None:
            return
        target_url = self._append_query(target_url, scope.get('query_string', b''))
        request_headers = _scope_headers(scope)
        sensitive = {'authorization', 'cookie', 'forwarded', 'proxy-authorization', 'x-api-key', CUSTOM_API_KEY_HEADER.lower()}
        headers = {
            key: value for key, value in filter_hop_by_hop_headers(request_headers)
            if key not in {'host', 'content-length'} | sensitive
            and not key.startswith('x-forwarded-') and not key.startswith('x-openwebui-user-')
        }
        if host := request_headers.get('host', '').strip():
            headers['x-forwarded-host'] = host
        headers['x-forwarded-proto'] = scope.get('scheme', 'http')
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60, connect=10), trust_env=True) as session:
                async with session.request(scope['method'], target_url, headers=headers, data=body or None, allow_redirects=False, ssl=AIOHTTP_CLIENT_SESSION_SSL) as upstream:
                    response_body = await self._read_response_body(upstream)
                    response_headers = [
                        (key.encode('latin-1'), value.encode('latin-1'))
                        for key, value in filter_hop_by_hop_headers(
                            strip_sensitive_response_headers(upstream.headers)
                        )
                        if key.lower() not in self.STRIPPED_RESPONSE_HEADERS
                    ]
                    await send({'type': 'http.response.start', 'status': upstream.status, 'headers': response_headers})
                    await send({'type': 'http.response.body', 'body': response_body, 'more_body': False})
        except ValueError:
            await JSONResponse(status_code=502, content={'detail': 'Auth callback response body too large'})(scope, receive, send)
        except Exception:
            log.exception('Auth callback proxy failed for target=%s', sanitize_url_for_log(target_url))
            await JSONResponse(status_code=502, content={'detail': 'Auth callback proxy failed'})(scope, receive, send)

    async def _read_request_body(self, receive: Receive) -> bytes | None:
        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message.get('type') == 'http.disconnect':
                return None
            if message.get('type') != 'http.request':
                continue
            chunk = message.get('body', b'')
            total += len(chunk)
            if total > MAX_CALLBACK_BODY_BYTES:
                raise ValueError
            chunks.append(chunk)
            if not message.get('more_body', False):
                return b''.join(chunks)

    async def _read_response_body(self, response: aiohttp.ClientResponse) -> bytes:
        if response.content_length is not None and response.content_length > MAX_CALLBACK_BODY_BYTES:
            raise ValueError
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.content.iter_chunked(16 * 1024):
            total += len(chunk)
            if total > MAX_CALLBACK_BODY_BYTES:
                raise ValueError
            chunks.append(chunk)
        return b''.join(chunks)

    async def _resolve_target_url(self, scope: Scope) -> str | None:
        path = self._normalize_path(scope.get('path', ''))
        headers = _scope_headers(scope)
        request_host_full = headers.get('host', '').strip().lower()
        request_host_name = request_host_full.split(':', 1)[0]
        for connection in await self._get_connections():
            proxy = (connection.get('config') or {}).get('auth_callback_proxy') or {}
            if not proxy.get('enabled') or not is_valid_callback_proxy_config(proxy):
                continue
            configured_host = str(proxy.get('host', '')).strip().lower()
            if path != self._normalize_path(str(proxy.get('path', ''))):
                continue
            if (':' in configured_host and request_host_full != configured_host) or (':' not in configured_host and request_host_name != configured_host):
                continue
            return str(proxy['url']).strip()
        return None

    async def _get_connections(self) -> list[dict]:
        now = time.monotonic()
        if now < self._connections_cache_expiry:
            return self._connections_cache
        try:
            connections = await Config.get('tool_server.connections', []) or []
            self._connections_cache = connections if isinstance(connections, list) else []
        except Exception:
            log.exception('Auth callback proxy: failed to refresh tool_server.connections cache')
        self._connections_cache_expiry = now + 5.0
        return self._connections_cache

    @staticmethod
    def _normalize_path(path: str) -> str:
        path = (path or '').strip()
        if '://' in path:
            path = urlsplit(path).path
        path = path.split('?', 1)[0]
        if path and not path.startswith('/'):
            path = f'/{path}'
        return path[:-1] if path != '/' and path.endswith('/') else path

    @staticmethod
    def _append_query(url: str, query: bytes) -> str:
        raw_query = query.decode('latin-1', errors='replace')
        if not raw_query:
            return url
        parsed = urlsplit(url)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, f'{parsed.query}&{raw_query}' if parsed.query else raw_query, parsed.fragment))

"""Pure-ASGI application HTTP middleware."""

from __future__ import annotations

import logging
import re
import time
from urllib.parse import parse_qs, urlencode

from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials
from open_webui.env import CUSTOM_API_KEY_HEADER
from open_webui.internal.db import ScopedSession
from open_webui.utils.auth import get_http_authorization_cred
from open_webui.utils.security_headers import set_security_headers
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger(__name__)


class AppHTTPMiddleware:
    """Upstream consolidated HTTP lifecycle middleware."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._security_headers = list(set_security_headers().items())

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return
        if await self._reject_invalid_websocket(scope, receive, send):
            return
        start_time = time.monotonic()
        request = Request(scope)
        self._set_token(request)
        send_with_headers = self._send_with_headers(send, start_time)
        try:
            if await self._redirect_legacy_url(scope, receive, send_with_headers):
                pass
            elif scope.get('path', '') in {'/health', '/ready', '/health/db'}:
                await self.app(scope, receive, send_with_headers)
                return
            else:
                await self.app(scope, receive, send_with_headers)
        except BaseException:
            self._rollback_session('AppHTTPMiddleware: rollback failed after downstream error')
            raise
        self._commit_session()

    def _set_token(self, request: Request) -> None:
        token = get_http_authorization_cred(request.headers.get('Authorization'))
        if token is None and (cookie_token := request.cookies.get('token')):
            token = HTTPAuthorizationCredentials(scheme='Bearer', credentials=cookie_token)
        if token is None and (api_key := request.headers.get(CUSTOM_API_KEY_HEADER)):
            token = HTTPAuthorizationCredentials(scheme='Bearer', credentials=api_key)
        request.state.token = token

    def _send_with_headers(self, send: Send, start_time: float) -> Send:
        async def send_with_headers(message: Message) -> None:
            if message['type'] == 'http.response.start':
                headers = MutableHeaders(scope=message)
                headers['X-Process-Time'] = f'{time.monotonic() - start_time:.6f}'
                for key, value in self._security_headers:
                    headers[key] = value
            await send(message)
        return send_with_headers

    async def _reject_invalid_websocket(self, scope: Scope, receive: Receive, send: Send) -> bool:
        path = scope.get('path', '')
        if '/ws/socket.io' not in path:
            return False
        query_params = parse_qs(scope.get('query_string', b'').decode('latin-1', errors='replace'))
        if query_params.get('transport', [''])[0] != 'websocket':
            return False
        headers = _scope_headers(scope)
        upgrade = headers.get('upgrade', '').lower()
        connection_tokens = [token.strip() for token in headers.get('connection', '').lower().split(',')]
        if upgrade == 'websocket' and 'upgrade' in connection_tokens:
            return False
        await JSONResponse(status_code=400, content={'detail': 'Invalid WebSocket upgrade request'})(scope, receive, send)
        return True

    async def _redirect_legacy_url(self, scope: Scope, receive: Receive, send: Send) -> bool:
        if scope.get('method', '').upper() != 'GET':
            return False
        path = scope.get('path', '')
        raw_query = scope.get('query_string', b'')
        if not (path.endswith('/watch') or b'shared' in raw_query):
            return False
        query_params = parse_qs(raw_query.decode('latin-1', errors='replace'))
        redirect_params: dict[str, str] = {}
        if path.endswith('/watch') and query_params.get('v'):
            redirect_params['youtube'] = query_params['v'][0]
        if query_params.get('shared'):
            text = query_params['shared'][0]
            if text:
                url_match = re.match(r'https://\S+', text)
                if url_match:
                    from open_webui.retrieval.loaders.youtube import _parse_video_id
                    video_id = _parse_video_id(url_match[0])
                    redirect_params['youtube' if video_id else 'load-url'] = video_id or url_match[0]
                else:
                    redirect_params['q'] = text
        if not redirect_params:
            return False
        await RedirectResponse(url=f'/?{urlencode(redirect_params)}')(scope, receive, send)
        return True

    def _rollback_session(self, message: str) -> None:
        if not ScopedSession.registry.has():
            return
        try:
            ScopedSession.rollback()
        except Exception:
            log.exception(message)
        finally:
            ScopedSession.remove()

    def _commit_session(self) -> None:
        if not ScopedSession.registry.has():
            return
        try:
            ScopedSession.commit()
        except Exception:
            log.exception('AppHTTPMiddleware: post-request commit failed; response was already sent to client')
            try:
                ScopedSession.rollback()
            except Exception:
                log.exception('AppHTTPMiddleware: rollback failed after commit failure')
            raise
        finally:
            ScopedSession.remove()


def _scope_headers(scope: Scope) -> dict[str, str]:
    decoded: dict[str, str] = {}
    for raw_key, raw_value in scope.get('headers', []):
        key = raw_key.decode('latin-1').lower()
        value = raw_value.decode('latin-1')
        decoded[key] = f'{decoded[key]}, {value}' if key in decoded else value
    return decoded

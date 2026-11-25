"""Terminal chat authorization at the router ingress (HTTP proxy and WebSocket), AST-loaded.

``find_machine_connection`` is the central authorizer (tested against the real
module in test_terminal_json_resolution.py); here it is a fake so these tests
pin how the router *uses* it: authorize before any gateway/upstream work,
re-authorize on every WebSocket poll, and fail closed without leaking details.
"""

import ast
import asyncio
import copy
import json
import posixpath
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from yarl import URL

from open_webui.ext import terminal_context_authorization as authorization
from open_webui.ext.terminal_discovery_cache import terminal_fingerprint


def _connection(**extra):
    return {'id': 'terminal-id', 'url': 'http://terminal.example', 'key': 'private-key', 'auth_type': 'bearer', **extra}


def _load_terminal_ingress():
    """Execute selected production AST nodes without importing the full router graph."""
    source_path = Path(__file__).resolve().parents[1] / 'routers' / 'machines.py'
    source = ast.parse(source_path.read_text(encoding='utf-8'), filename=str(source_path))
    names = {
        '_sanitize_proxy_path',
        'proxy_machine',
        '_proxy_machine',
        '_resolve_authenticated_connection',
        '_resolve_machine_access',
        '_terminal_identity',
        '_watch_terminal_access',
        'socket_metadata',
    }
    constant_names = {'ADMIN_API_PATHS', 'STREAMING_CONTENT_TYPES', 'STRIPPED_RESPONSE_HEADERS'}
    nodes = []
    for node in source.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in constant_names
        ):
            nodes.append(copy.deepcopy(node))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names:
            node = copy.deepcopy(node)
            node.decorator_list = []
            nodes.append(node)

    globals_ = {
        'asyncio': asyncio,
        'terminal_fingerprint': terminal_fingerprint,
        'posixpath': posixpath,
        'unquote': __import__('urllib.parse').parse.unquote,
        'JSONCodec': SimpleNamespace(loads=json.loads, JSONDecodeError=json.JSONDecodeError),
        'TimeoutError': TimeoutError,
        'WebSocketDisconnect': type('WebSocketDisconnect', (Exception,), {}),
        'HTTPException': HTTPException,
        'Request': Request,
        'WebSocket': object,
        'Depends': lambda dependency: None,
        'get_verified_user': object(),
        'get_verified_user_by_token': AsyncMock(),
        'find_machine_connection': AsyncMock(),
        # Same shape as the real helper: only trusted connection context becomes headers.
        'machine_headers': lambda connection: connection.get('_headers', {}),
        'get_machine_url': lambda connection: connection.get('url', ''),
        'build_terminal_tool_gateway_seed_headers': AsyncMock(return_value={'X-Gateway': 'seed'}),
        'proxy_terminal_upload': AsyncMock(return_value=Response(status_code=204)),
        'bearer_auth_header': lambda token: {'Authorization': f'Bearer {token}'} if token else {},
        'AIOHTTP_CLIENT_SESSION_SSL': None,
        'ENABLE_TOOL_SERVERS': True,
        'MACHINE_PROXY_HEADERS': {},
        'URL': URL,
        'JSONResponse': JSONResponse,
        'Response': Response,
        'StreamingResponse': StreamingResponse,
        'BackgroundTask': object,
        'ClientDisconnect': type('ClientDisconnect', (Exception,), {}),
        'RelayInterrupted': type('RelayInterrupted', (Exception,), {}),
        'CIMultiDict': dict,
        're': __import__('re'),
        'json': json,
        'aiohttp': SimpleNamespace(ClientTimeout=lambda **kwargs: None, ClientConnectionError=ConnectionError),
        'get_machine_client': MagicMock(),
        'log': SimpleNamespace(
            error=lambda *args, **kwargs: None,
            exception=lambda *args, **kwargs: None,
            warning=lambda *args, **kwargs: None,
        ),
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(source_path), 'exec'), globals_)
    return SimpleNamespace(globals=globals_, **{name: globals_[name] for name in names})


def _request(session_id='', path_chat_id=None):
    headers = [(b'x-session-id', session_id.encode())] if session_id else []
    return Request(
        {
            'type': 'http',
            'method': 'POST',
            'path': '/api/v1/terminals/terminal-id/files/upload-stream',
            'headers': headers,
            'query_string': b'',
            'path_params': {'chat_id': path_chat_id} if path_chat_id else {},
            'scheme': 'http',
            'server': ('testserver', 80),
            'client': ('testclient', 50000),
        }
    )


class _WebSocket:
    def __init__(self, payload):
        self.payload = payload
        self.app = SimpleNamespace(state=SimpleNamespace(redis=None))
        self.closed = []
        self.state = SimpleNamespace()

    async def receive_text(self):
        return json.dumps(self.payload)

    async def close(self, code, reason):
        self.closed.append((code, reason))


USER = SimpleNamespace(id='user-id', role='user')


@pytest.mark.asyncio
@pytest.mark.parametrize('ingress_source', ['header', 'path'])
async def test_http_authorizes_with_chat_context_before_gateway_or_upstream(ingress_source):
    ingress = _load_terminal_ingress()
    find = ingress.globals['find_machine_connection']
    find.side_effect = HTTPException(403, 'Chat access denied')
    request = _request('owner-chat') if ingress_source == 'header' else _request('temporary:ignored', 'owner-chat')

    with pytest.raises(HTTPException) as denied:
        await ingress.proxy_machine('terminal-id', 'files/upload-stream', request, USER)

    assert denied.value.status_code == 403
    assert find.await_args.args[:2] == (USER, 'terminal-id')
    assert find.await_args.args[2]['chat_id'] == 'owner-chat'
    ingress.globals['build_terminal_tool_gateway_seed_headers'].assert_not_awaited()
    ingress.globals['proxy_terminal_upload'].assert_not_awaited()


@pytest.mark.asyncio
async def test_http_unknown_terminal_is_404_before_gateway_or_upstream():
    ingress = _load_terminal_ingress()
    ingress.globals['find_machine_connection'].return_value = None
    response = await ingress.proxy_machine('terminal-id', 'files/upload-stream', _request(), USER)
    assert response.status_code == 404
    ingress.globals['build_terminal_tool_gateway_seed_headers'].assert_not_awaited()
    ingress.globals['proxy_terminal_upload'].assert_not_awaited()


@pytest.mark.asyncio
async def test_http_upload_stream_gets_gateway_seed_session_and_trusted_machine_headers():
    ingress = _load_terminal_ingress()
    ingress.globals['find_machine_connection'].return_value = _connection(_headers={'X-Terminal-Chat-Id': 'owner-chat'})

    response = await ingress.proxy_machine('terminal-id', 'files/upload-stream', _request('owner-chat'), USER)

    assert response.status_code == 204
    headers = ingress.globals['proxy_terminal_upload'].await_args.args[2]
    assert headers['X-Session-Id'] == 'owner-chat'
    assert headers['X-User-Id'] == 'user-id'
    assert headers['X-Gateway'] == 'seed'
    assert headers['X-Terminal-Chat-Id'] == 'owner-chat'
    assert headers['Authorization'] == 'Bearer private-key'
    seed_args = ingress.globals['build_terminal_tool_gateway_seed_headers'].await_args.args
    assert seed_args[2:] == ('terminal-id', {'chat_id': 'owner-chat'})


@pytest.mark.asyncio
async def test_http_upload_stream_for_tether_owner_uses_relay_not_raw_proxy():
    ingress = _load_terminal_ingress()
    ingress.globals['find_machine_connection'].return_value = _connection(owner_id='user-id', auth_type='none', url='tether://user-id')
    upstream = SimpleNamespace(
        status=204, headers={}, read=AsyncMock(return_value=b''), release=AsyncMock()
    )
    session = SimpleNamespace(request=AsyncMock(return_value=upstream), close=AsyncMock())
    ingress.globals['get_machine_client'].return_value = session

    response = await ingress.proxy_machine('terminal-id', 'files/upload-stream', _request(), USER)

    assert response.status_code == 204
    ingress.globals['proxy_terminal_upload'].assert_not_awaited()
    session.request.assert_awaited_once()


@pytest.mark.asyncio
async def test_disabled_feature_blocks_http_and_ws_before_authorizer_or_gateway():
    ingress = _load_terminal_ingress()
    ingress.globals['ENABLE_TOOL_SERVERS'] = False
    response = await ingress.proxy_machine('terminal-id', 'files/upload-stream', _request(), USER)
    assert response.status_code == 403
    assert json.loads(response.body) == {'error': 'Tool servers are disabled'}
    ws = _WebSocket({})
    assert await ingress._resolve_machine_access(ws, 'terminal-id', 'token') is None
    assert ws.closed == [(4003, 'Tool servers are disabled')]
    ingress.globals['find_machine_connection'].assert_not_awaited()
    ingress.globals['build_terminal_tool_gateway_seed_headers'].assert_not_awaited()
    ingress.globals['proxy_terminal_upload'].assert_not_awaited()


@pytest.mark.asyncio
async def test_ws_handshake_authorizes_with_socket_chat_and_denial_closes_4003():
    ingress = _load_terminal_ingress()
    connection = _connection()
    ingress.globals['get_verified_user_by_token'].return_value = USER
    find = ingress.globals['find_machine_connection']
    find.return_value = connection
    ws = _WebSocket({'type': 'auth', 'token': 'token', 'chat_id': 'owner-chat'})

    assert await ingress._resolve_authenticated_connection(ws, 'terminal-id') == (USER, connection, 'owner-chat', 'token')
    assert find.await_args.args[2]['chat_id'] == 'owner-chat'
    assert find.await_args.kwargs == {'request': ws}

    find.side_effect = HTTPException(403, 'Chat access denied')
    denied = _WebSocket({'type': 'auth', 'token': 'token', 'chat_id': 'foreign-chat'})
    assert await ingress._resolve_authenticated_connection(denied, 'terminal-id') is None
    assert denied.closed == [(4003, 'Chat access denied')]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'terminal_id, code',
    [('terminal-id', 4004), ('tether:dev', 1013)],
    ids=['missing', 'tether-offline'],
)
async def test_ws_unknown_terminal_closes_without_connection(terminal_id, code):
    ingress = _load_terminal_ingress()
    ingress.globals['get_verified_user_by_token'].return_value = USER
    ingress.globals['find_machine_connection'].return_value = None
    ws = _WebSocket({})
    assert await ingress._resolve_machine_access(ws, terminal_id, 'token') is None
    assert [c for c, _ in ws.closed] == [code]


def _watch(ingress, connection):
    """Open an identity for ``connection`` and run the watcher with instant sleeps."""
    identity = ingress._terminal_identity(USER, connection)
    assert 'private-key' not in repr(identity)
    ingress.globals['get_verified_user_by_token'].return_value = USER
    ingress.globals['asyncio'] = SimpleNamespace(sleep=AsyncMock())
    ws = _WebSocket({})
    ws.state.auth = {'chat_id': 'owner-chat'}
    return ws, identity


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'change, code',
    [
        ('url', 4003),
        ('key', 4003),
        ('trusted-headers', 4003),
        ('invalid-fingerprint', 4003),
        ('deleted', 4004),
        ('chat-denied', 4003),
        ('token', 4001),
        ('store-error', 4003),
    ],
)
async def test_ws_watcher_reauthorizes_and_closes_on_change_or_failure(change, code):
    ingress = _load_terminal_ingress()
    connection = _connection(_headers={'X-Terminal-Chat-Id': 'owner-chat'})
    ws, identity = _watch(ingress, connection)
    find = ingress.globals['find_machine_connection']
    changed = copy.deepcopy(connection)
    find.return_value = changed
    if change in ('url', 'key'):
        changed[change] = 'changed'
    elif change == 'trusted-headers':
        changed['_headers'] = {'X-Terminal-Chat-Id': 'other-chat'}
    elif change == 'invalid-fingerprint':
        changed['id'] = ''
    elif change == 'deleted':
        find.return_value = None
    elif change == 'chat-denied':
        find.side_effect = HTTPException(403, 'Chat access denied')
    elif change == 'token':
        ingress.globals['get_verified_user_by_token'].return_value = None
    elif change == 'store-error':
        find.side_effect = RuntimeError('private chat details')

    await asyncio.wait_for(ingress._watch_terminal_access(ws, 'terminal-id', 'token', identity), timeout=1)

    assert [c for c, _ in ws.closed] == [code]
    assert 'private' not in repr(ws.closed)
    if change not in ('token',):
        # Every poll re-runs the central authorizer with the socket's saved chat.
        assert find.await_args.args[2]['chat_id'] == 'owner-chat'


@pytest.mark.asyncio
async def test_ws_watcher_keeps_unchanged_identity_then_stops_on_revocation():
    ingress = _load_terminal_ingress()
    connection = _connection(_headers={'X-Terminal-Chat-Id': 'owner-chat'})
    ws, identity = _watch(ingress, connection)
    find = ingress.globals['find_machine_connection']
    find.return_value = connection
    polls = 0

    async def poll(_delay):
        nonlocal polls
        polls += 1
        if polls == 3:
            find.side_effect = HTTPException(403, 'Chat access denied')

    ingress.globals['asyncio'] = SimpleNamespace(sleep=poll)
    await asyncio.wait_for(ingress._watch_terminal_access(ws, 'terminal-id', 'token', identity), timeout=1)
    assert polls == 3
    assert find.await_count == 3
    assert ws.closed == [(4003, 'Chat access denied')]


def test_ws_proxy_uses_watcher_in_first_completion_task_group():
    source = (Path(__file__).resolve().parents[1] / 'routers' / 'machines.py').read_text(encoding='utf-8')
    tree = ast.parse(source)
    proxy = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef) and node.name == '_proxy_terminal_websocket')
    assert any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == '_watch_terminal_access' for node in ast.walk(proxy))
    assert 'return_when=asyncio.FIRST_COMPLETED' in ast.get_source_segment(source, proxy)


@pytest.mark.asyncio
async def test_authorized_terminal_context_allows_owner_and_configured_admins(monkeypatch):
    chat = SimpleNamespace(id='admin-chat', user_id='owner', meta={'internal': True})
    monkeypatch.setattr(authorization.Chats, 'get_chat_metadata_by_id', AsyncMock(return_value=chat))
    assert await authorization.authorized_terminal_chat_context(SimpleNamespace(id='owner', role='user'), 'admin-chat') == 'admin-chat'

    monkeypatch.setattr(authorization, 'ENABLE_ADMIN_CHAT_ACCESS', True)
    assert await authorization.authorized_terminal_chat_context(SimpleNamespace(id='admin', role='admin'), 'admin-chat') == 'admin-chat'

    # Upstream 0.13.5 (#35031): internal chats no longer bypass ENABLE_ADMIN_CHAT_ACCESS.
    monkeypatch.setattr(authorization, 'ENABLE_ADMIN_CHAT_ACCESS', False)
    assert await authorization.authorized_terminal_chat_context(SimpleNamespace(id='admin', role='admin'), 'admin-chat') is None


@pytest.mark.asyncio
@pytest.mark.parametrize('meta', [{}, {'shared': True}, {'folder_id': 'folder-id'}])
async def test_authorized_terminal_context_denies_foreign_shared_folder_missing_and_non_admin(monkeypatch, meta):
    chat = SimpleNamespace(id='foreign-chat', user_id='owner', meta=meta)
    get_chat = AsyncMock(return_value=chat)
    monkeypatch.setattr(authorization.Chats, 'get_chat_metadata_by_id', get_chat)
    monkeypatch.setattr(authorization, 'ENABLE_ADMIN_CHAT_ACCESS', False)

    user = SimpleNamespace(id='user-id', role='user')
    assert await authorization.authorized_terminal_chat_context(user, 'foreign-chat') is None
    assert await authorization.authorized_terminal_chat_context(SimpleNamespace(id='admin', role='admin'), 'foreign-chat') is None
    assert await authorization.authorized_terminal_chat_context(user, '') is None
    monkeypatch.setattr(authorization.Chats, 'get_chat_metadata_by_id', AsyncMock(return_value=None))
    assert await authorization.authorized_terminal_chat_context(user, 'missing-chat') is None

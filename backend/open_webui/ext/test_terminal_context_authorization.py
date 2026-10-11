import ast
import asyncio
import copy
import json
import posixpath
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import unquote
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from yarl import URL

from open_webui.ext import terminal_context_authorization as authorization
from open_webui.ext.terminal_discovery_cache import terminal_fingerprint


def _connection(context_id='default'):
    return {
        'id': 'terminal-id',
        'url': 'http://terminal.example',
        'server_type': 'orchestrator',
        'config': {'contexts': {'chat': {'context_id': context_id}}},
    }


def _terminal_context_config(connection, context):
    return ((connection.get('config') or {}).get('contexts') or {}).get(context, {})


def _terminal_context_available(connection, context):
    return _terminal_context_config(connection, context) is not False


def _terminal_context_id(connection, metadata, context):
    config = _terminal_context_config(connection, context)
    if config.get('context_id') == 'chat_id' and metadata.get('chat_id'):
        return f"chat:{metadata['chat_id']}"
    return None


def _load_terminal_ingress():
    """Execute selected production AST nodes without importing the full router graph."""
    source_path = Path(__file__).resolve().parents[1] / 'routers' / 'terminals.py'
    source = ast.parse(source_path.read_text(encoding='utf-8'), filename=str(source_path))
    names = {
        '_sanitize_proxy_path',
        'proxy_terminal',
        '_resolve_authenticated_connection',
        '_resolve_terminal_access',
        '_watch_terminal_access',
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
        'unquote': unquote,
        'JSONCodec': SimpleNamespace(loads=json.loads, JSONDecodeError=json.JSONDecodeError),
        'TimeoutError': TimeoutError,
        'Request': Request,
        'Response': Response,
        'WebSocket': object,
        'Depends': lambda dependency: None,
        'get_verified_user': object(),
        'get_verified_user_by_token': AsyncMock(),
        'Config': SimpleNamespace(get=AsyncMock()),
        'Groups': SimpleNamespace(get_groups_by_member_id=AsyncMock()),
        'has_connection_access': AsyncMock(return_value=True),
        'get_terminal_server_url': lambda connection: connection.get('url', ''),
        'terminal_context_available': _terminal_context_available,
        'terminal_context_config': _terminal_context_config,
        'terminal_context_id': _terminal_context_id,
        'TERMINAL_CONTEXT_HEADER': 'X-Terminal-Context-Id',
        'build_terminal_tool_gateway_seed_headers': AsyncMock(return_value={}),
        'proxy_terminal_upload': AsyncMock(return_value=Response(status_code=204)),
        'resolve_terminal_chat_context': authorization.resolve_terminal_chat_context,
        'bearer_auth_header': lambda token: {},
        'AIOHTTP_CLIENT_SESSION_SSL': None,
        'ENABLE_TOOL_SERVERS': True,
        'TERMINAL_PROXY_HEADERS': {},
        'URL': URL,
        'JSONResponse': JSONResponse,
        'StreamingResponse': StreamingResponse,
        'BackgroundTask': object,
        'ClientDisconnect': Exception,
        'aiohttp': SimpleNamespace(ClientSession=object, ClientTimeout=object, ClientConnectionError=Exception),
        'log': SimpleNamespace(error=lambda *args, **kwargs: None, exception=lambda *args, **kwargs: None, warning=lambda *args, **kwargs: None),
    }
    module = ast.Module(body=nodes, type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(source_path), 'exec'), globals_)
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

    async def receive_text(self):
        return json.dumps(self.payload)

    async def close(self, code, reason):
        self.closed.append((code, reason))


def _configure_ingress(ingress, connection):
    ingress.globals['Config'].get = AsyncMock(return_value=[connection])
    ingress.globals['Groups'].get_groups_by_member_id = AsyncMock(return_value=[])
    ingress.globals['has_connection_access'] = AsyncMock(return_value=True)
    ingress.globals['build_terminal_tool_gateway_seed_headers'] = AsyncMock(return_value={})
    ingress.globals['proxy_terminal_upload'] = AsyncMock(return_value=Response(status_code=204))


@pytest.mark.asyncio
@pytest.mark.parametrize('session_id', ['', 'temporary:chat-id', 'local:chat-id', 'channel:chat-id'])
async def test_http_default_ingress_keeps_only_safe_non_saved_session_ids(monkeypatch, session_id):
    ingress = _load_terminal_ingress()
    _configure_ingress(ingress, _connection())

    response = await ingress.proxy_terminal(
        'terminal-id', 'files/upload-stream', _request(session_id), SimpleNamespace(id='user-id', role='user')
    )

    assert response.status_code == 204
    headers = ingress.globals['proxy_terminal_upload'].await_args.args[2]
    if session_id:
        assert headers['X-Session-Id'] == session_id
    else:
        assert 'X-Session-Id' not in headers
    assert 'X-Terminal-Context-Id' not in headers


@pytest.mark.asyncio
@pytest.mark.parametrize('chat_id', ['foreign-chat', 'missing-chat'])
@pytest.mark.parametrize('ingress_source', ['header', 'path'])
async def test_http_saved_context_rejects_before_gateway_or_upstream(monkeypatch, chat_id, ingress_source):
    ingress = _load_terminal_ingress()
    _configure_ingress(ingress, _connection())
    monkeypatch.setattr(
        authorization.Chats,
        'get_chat_by_id',
        AsyncMock(return_value=SimpleNamespace(id=chat_id, user_id='other-user', meta={}) if chat_id == 'foreign-chat' else None),
    )

    response = await ingress.proxy_terminal(
        'terminal-id', 'files/upload-stream',
        _request(chat_id) if ingress_source == 'header' else _request('temporary:safe', chat_id),
        SimpleNamespace(id='user-id', role='user')
    )

    assert response.status_code == 403
    ingress.globals['build_terminal_tool_gateway_seed_headers'].assert_not_awaited()
    ingress.globals['proxy_terminal_upload'].assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('ingress_source', ['header', 'path'])
async def test_http_chat_scoped_context_requires_owner_and_never_accepts_an_omitted_header(monkeypatch, ingress_source):
    ingress = _load_terminal_ingress()
    _configure_ingress(ingress, _connection('chat_id'))

    response = await ingress.proxy_terminal(
        'terminal-id', 'files/upload-stream', _request(), SimpleNamespace(id='user-id', role='user')
    )
    assert response.status_code == 403
    ingress.globals['build_terminal_tool_gateway_seed_headers'].assert_not_awaited()
    ingress.globals['proxy_terminal_upload'].assert_not_awaited()

    monkeypatch.setattr(
        authorization.Chats,
        'get_chat_by_id',
        AsyncMock(return_value=SimpleNamespace(id='owner-chat', user_id='user-id', meta={})),
    )
    response = await ingress.proxy_terminal(
        'terminal-id', 'files/upload-stream',
        _request('owner-chat') if ingress_source == 'header' else _request('foreign-header', 'owner-chat'),
        SimpleNamespace(id='user-id', role='user')
    )
    assert response.status_code == 204
    headers = ingress.globals['proxy_terminal_upload'].await_args.args[2]
    assert headers['X-Session-Id'] == 'owner-chat'
    assert headers['X-Terminal-Context-Id'] == 'chat:owner-chat'
    assert ingress.globals['build_terminal_tool_gateway_seed_headers'].await_args.args[3] == {'chat_id': 'owner-chat'}
    assert ingress.globals['Groups'].get_groups_by_member_id.await_count == 2
    for call in ingress.globals['Groups'].get_groups_by_member_id.await_args_list:
        assert call.args == ('user-id',)
        assert call.kwargs == {'include_inherited': True}


@pytest.mark.asyncio
async def test_authorized_terminal_context_allows_configured_and_internal_admins(monkeypatch):
    chat = SimpleNamespace(id='admin-chat', user_id='owner', meta={'internal': True})
    monkeypatch.setattr(authorization.Chats, 'get_chat_by_id', AsyncMock(return_value=chat))
    assert await authorization.authorized_terminal_chat_context(SimpleNamespace(id='owner', role='user'), 'admin-chat') == 'admin-chat'

    monkeypatch.setattr(authorization, 'ENABLE_ADMIN_CHAT_ACCESS', True)
    assert await authorization.authorized_terminal_chat_context(SimpleNamespace(id='admin', role='admin'), 'admin-chat') == 'admin-chat'

    monkeypatch.setattr(authorization, 'ENABLE_ADMIN_CHAT_ACCESS', False)
    monkeypatch.setattr(authorization, 'is_internal_chat', lambda meta: meta == {'internal': True})
    assert await authorization.authorized_terminal_chat_context(SimpleNamespace(id='admin', role='admin'), 'admin-chat') == 'admin-chat'


@pytest.mark.asyncio
@pytest.mark.parametrize('meta', [{}, {'shared': True}, {'folder_id': 'folder-id'}])
async def test_authorized_terminal_context_denies_foreign_shared_folder_missing_and_non_admin(monkeypatch, meta):
    chat = SimpleNamespace(id='foreign-chat', user_id='owner', meta=meta)
    get_chat = AsyncMock(return_value=chat)
    monkeypatch.setattr(authorization.Chats, 'get_chat_by_id', get_chat)
    monkeypatch.setattr(authorization, 'ENABLE_ADMIN_CHAT_ACCESS', False)

    user = SimpleNamespace(id='user-id', role='user')
    assert await authorization.authorized_terminal_chat_context(user, 'foreign-chat') is None
    assert await authorization.authorized_terminal_chat_context(SimpleNamespace(id='admin', role='admin'), 'foreign-chat') is None
    assert await authorization.authorized_terminal_chat_context(user, '') is None
    monkeypatch.setattr(authorization.Chats, 'get_chat_by_id', AsyncMock(return_value=None))
    assert await authorization.authorized_terminal_chat_context(user, 'missing-chat') is None


@pytest.mark.asyncio
async def test_ws_default_normalizes_non_saved_context_and_access_keeps_upstream_tuple(monkeypatch):
    ingress = _load_terminal_ingress()
    user = SimpleNamespace(id='user-id', role='user')
    connection = _connection()
    _configure_ingress(ingress, connection)
    ws = _WebSocket({'type': 'auth', 'token': 'token', 'chat_id': 'temporary:chat-id'})
    ingress.globals['_resolve_terminal_access'] = AsyncMock(return_value=(user, connection))

    assert await ingress._resolve_authenticated_connection(ws, 'terminal-id') == (user, connection, '', 'token')
    assert ws.closed == []

    access_ws = _WebSocket({})
    ingress.globals['get_verified_user_by_token'] = AsyncMock(return_value=user)
    assert await ingress._resolve_terminal_access(access_ws, 'terminal-id', 'token') == (user, connection)


@pytest.mark.asyncio
async def test_ws_foreign_saved_context_closes_for_default_and_chat_scoped_contexts(monkeypatch):
    user = SimpleNamespace(id='user-id', role='user')
    monkeypatch.setattr(
        authorization.Chats,
        'get_chat_by_id',
        AsyncMock(return_value=SimpleNamespace(id='foreign-chat', user_id='other-user', meta={})),
    )
    for connection in (_connection(), _connection('chat_id')):
        ingress = _load_terminal_ingress()
        ws = _WebSocket({'type': 'auth', 'token': 'token', 'chat_id': 'foreign-chat'})
        ingress.globals['_resolve_terminal_access'] = AsyncMock(return_value=(user, connection))

        assert await ingress._resolve_authenticated_connection(ws, 'terminal-id') is None
        assert ws.closed == [(4003, 'An accessible saved chat is required for this terminal')]


@pytest.mark.asyncio
async def test_disabled_feature_blocks_http_and_ws_before_config_or_gateway():
    ingress = _load_terminal_ingress()
    ingress.globals['ENABLE_TOOL_SERVERS'] = False
    user = SimpleNamespace(id='user-id', role='user')
    response = await ingress.proxy_terminal('terminal-id', 'files/upload-stream', _request(), user)
    assert response.status_code == 403
    assert json.loads(response.body) == {'error': 'Tool servers are disabled'}
    ws = _WebSocket({})
    assert await ingress._resolve_terminal_access(ws, 'terminal-id', 'token') is None
    assert ws.closed == [(4003, 'Tool servers are disabled')]
    ingress.globals['Config'].get.assert_not_awaited()
    ingress.globals['build_terminal_tool_gateway_seed_headers'].assert_not_awaited()
    ingress.globals['proxy_terminal_upload'].assert_not_awaited()


@pytest.mark.asyncio
async def test_duplicate_terminal_ids_fail_closed_for_http_and_ws():
    ingress = _load_terminal_ingress()
    connection = _connection()
    _configure_ingress(ingress, connection)
    ingress.globals['Config'].get.return_value = [connection, copy.deepcopy(connection)]
    user = SimpleNamespace(id='user-id', role='user')
    response = await ingress.proxy_terminal('terminal-id', 'files/upload-stream', _request(), user)
    assert response.status_code == 404
    ingress.globals['get_verified_user_by_token'].return_value = user
    ws = _WebSocket({})
    assert await ingress._resolve_terminal_access(ws, 'terminal-id', 'token') is None
    assert ws.closed == [(4004, 'Terminal server not found')]
    ingress.globals['build_terminal_tool_gateway_seed_headers'].assert_not_awaited()
    ingress.globals['proxy_terminal_upload'].assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['deleted', 'owner', 'url', 'key', 'auth_type', 'policy_id', 'context', 'access', 'token', 'config-error', 'chat-error'])
async def test_ws_watcher_reauthorizes_pinned_runtime_and_closes_on_failure(monkeypatch, change):
    ingress = _load_terminal_ingress()
    connection = _connection('chat_id')
    connection.update(key='private-key', auth_type='bearer')
    _configure_ingress(ingress, connection)
    user = SimpleNamespace(id='user-id', role='user')
    ingress.globals['get_verified_user_by_token'].return_value = user
    ingress.globals['Groups'].get_groups_by_member_id.return_value = [SimpleNamespace(id='inherited')]
    chat = SimpleNamespace(id='owner-chat', user_id='user-id', meta={})
    get_chat = AsyncMock(return_value=chat)
    monkeypatch.setattr(authorization.Chats, 'get_chat_by_id', get_chat)
    identity = (user.id, terminal_fingerprint(connection, connection['url'], connection['url']), 'chat:owner-chat')
    assert 'private-key' not in repr(identity)
    changed = copy.deepcopy(connection)
    if change == 'deleted':
        get_chat.return_value = None
    elif change == 'owner':
        get_chat.return_value = SimpleNamespace(user_id='other', meta={'shared': True, 'folder_id': 'writable'})
    elif change == 'context':
        changed['config']['contexts']['chat'] = {'context_id': 'default'}
    elif change == 'access':
        ingress.globals['has_connection_access'].return_value = False
    elif change == 'token':
        ingress.globals['get_verified_user_by_token'].return_value = None
    elif change == 'config-error':
        ingress.globals['Config'].get.side_effect = RuntimeError('private connection details')
    elif change == 'chat-error':
        get_chat.side_effect = RuntimeError('private chat details')
    else:
        changed[change] = 'changed'
    ingress.globals['Config'].get.return_value = [changed]
    ingress.globals['asyncio'] = SimpleNamespace(sleep=AsyncMock())
    ws = _WebSocket({})
    await asyncio.wait_for(ingress._watch_terminal_access(ws, 'terminal-id', 'token', 'owner-chat', identity), timeout=1)
    assert len(ws.closed) == 1
    assert ws.closed[0][0] in {4001, 4003}
    assert 'private' not in repr(ws.closed)
    for call in ingress.globals['Groups'].get_groups_by_member_id.await_args_list:
        assert call.kwargs == {'include_inherited': True}
    for call in ingress.globals['has_connection_access'].await_args_list:
        assert call.args[2] == {'inherited'}


@pytest.mark.asyncio
@pytest.mark.parametrize('chat_id', ['', 'owner-chat'])
async def test_ws_watcher_keeps_unchanged_runtime_then_stops_on_revocation(monkeypatch, chat_id):
    ingress = _load_terminal_ingress()
    connection = _connection('chat_id' if chat_id else 'default')
    _configure_ingress(ingress, connection)
    user = SimpleNamespace(id='user-id', role='user')
    ingress.globals['get_verified_user_by_token'].return_value = user
    get_chat = AsyncMock(return_value=SimpleNamespace(user_id='user-id', meta={}))
    monkeypatch.setattr(authorization.Chats, 'get_chat_by_id', get_chat)
    identity = (user.id, terminal_fingerprint(connection, connection['url'], connection['url']), f'chat:{chat_id}' if chat_id else None)
    polls = 0

    async def poll(_delay):
        nonlocal polls
        polls += 1
        if polls == 2:
            ingress.globals['has_connection_access'].return_value = False

    ingress.globals['asyncio'] = SimpleNamespace(sleep=poll)
    ws = _WebSocket({})
    await asyncio.wait_for(ingress._watch_terminal_access(ws, 'terminal-id', 'token', chat_id, identity), timeout=1)
    assert polls == 2
    assert ws.closed == [(4003, 'Access denied')]
    if chat_id:
        get_chat.assert_awaited_once_with(chat_id)
    else:
        get_chat.assert_not_awaited()


def test_ws_proxy_uses_watcher_in_first_completion_task_group():
    source = (Path(__file__).resolve().parents[1] / 'routers' / 'terminals.py').read_text(encoding='utf-8')
    tree = ast.parse(source)
    proxy = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef) and node.name == 'ws_terminal')
    assert any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == '_watch_terminal_access' for node in ast.walk(proxy))
    assert 'return_when=asyncio.FIRST_COMPLETED' in ast.get_source_segment(source, proxy)

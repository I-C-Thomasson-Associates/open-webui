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
        'TERMINAL_PROXY_HEADERS': {},
        'URL': URL,
        'JSONResponse': JSONResponse,
        'StreamingResponse': StreamingResponse,
        'BackgroundTask': object,
        'ClientDisconnect': Exception,
        'aiohttp': SimpleNamespace(ClientSession=object, ClientTimeout=object, ClientConnectionError=Exception),
        'log': SimpleNamespace(error=lambda *args, **kwargs: None, exception=lambda *args, **kwargs: None),
    }
    module = ast.Module(body=nodes, type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(source_path), 'exec'), globals_)
    return SimpleNamespace(globals=globals_, **{name: globals_[name] for name in names})


def _request(session_id=''):
    headers = [(b'x-session-id', session_id.encode())] if session_id else []
    return Request(
        {
            'type': 'http',
            'method': 'POST',
            'path': '/api/v1/terminals/terminal-id/files/upload-stream',
            'headers': headers,
            'query_string': b'',
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
async def test_http_saved_context_rejects_before_gateway_or_upstream(monkeypatch, chat_id):
    ingress = _load_terminal_ingress()
    _configure_ingress(ingress, _connection())
    monkeypatch.setattr(
        authorization.Chats,
        'get_chat_by_id',
        AsyncMock(return_value=SimpleNamespace(id=chat_id, user_id='other-user', meta={}) if chat_id == 'foreign-chat' else None),
    )

    response = await ingress.proxy_terminal(
        'terminal-id', 'files/upload-stream', _request(chat_id), SimpleNamespace(id='user-id', role='user')
    )

    assert response.status_code == 403
    ingress.globals['build_terminal_tool_gateway_seed_headers'].assert_not_awaited()
    ingress.globals['proxy_terminal_upload'].assert_not_awaited()


@pytest.mark.asyncio
async def test_http_chat_scoped_context_requires_owner_and_never_accepts_an_omitted_header(monkeypatch):
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
        'terminal-id', 'files/upload-stream', _request('owner-chat'), SimpleNamespace(id='user-id', role='user')
    )
    assert response.status_code == 204
    headers = ingress.globals['proxy_terminal_upload'].await_args.args[2]
    assert headers['X-Session-Id'] == 'owner-chat'
    assert headers['X-Terminal-Context-Id'] == 'chat:owner-chat'


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

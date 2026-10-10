"""Import-safe terminal read resolution and chat authorization tests (AST-loaded)."""

import ast
import sys
import types
from pathlib import Path
from urllib.parse import quote
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

SRC = Path(__file__).parents[1] / 'utils' / 'terminals.py'


class User:
    def __init__(self, id='u1', role='user', **_):
        self.id = id
        self.role = role


class Response:
    status = 200

    async def json(self):
        return {'ok': True}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _load(monkeypatch, connections, access=True):
    tree = ast.parse(SRC.read_text(encoding='utf-8'))
    names = {
        'get_terminal_json', 'is_terminal_orchestrator', 'get_terminal_server_url',
        'terminal_context_config', 'terminal_context_available', 'terminal_context_id',
    }
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names]
    chat_id_ns = {}
    chat_id_source = SRC.with_name('chat_id.py')
    exec(compile(ast.parse(chat_id_source.read_text(encoding='utf-8')), str(chat_id_source), 'exec'), chat_id_ns)
    chat_store = SimpleNamespace(get_chat_by_id=AsyncMock(return_value=None))
    auth_ns = {
        'Chats': chat_store,
        'ENABLE_ADMIN_CHAT_ACCESS': False,
        'is_internal_chat': lambda meta: bool(meta and meta.get('internal')),
        'is_saved_chat_id': chat_id_ns['is_saved_chat_id'],
    }
    auth_source = SRC.parents[1] / 'ext' / 'terminal_context_authorization.py'
    auth_nodes = [n for n in ast.parse(auth_source.read_text(encoding='utf-8')).body if isinstance(n, ast.AsyncFunctionDef)]
    exec(compile(ast.Module(body=auth_nodes, type_ignores=[]), str(auth_source), 'exec'), auth_ns)
    resolve = AsyncMock(wraps=auth_ns['resolve_terminal_chat_context'])
    config = SimpleNamespace(get=AsyncMock(return_value=connections))
    groups = SimpleNamespace(get_groups_by_member_id=AsyncMock(return_value=[]))
    has_access = AsyncMock(return_value=access)
    build = AsyncMock(return_value=({}, {}))
    session = MagicMock()
    session.get = MagicMock(return_value=Response())
    session_cm = MagicMock()
    session_cm.__aenter__ = AsyncMock(return_value=session)
    session_cm.__aexit__ = AsyncMock(return_value=False)
    aiohttp = types.ModuleType('aiohttp')
    aiohttp.ClientTimeout = lambda **k: None
    aiohttp.ClientSession = MagicMock(return_value=session_cm)

    def mod(name, **attrs):
        m = types.ModuleType(name)
        m.__dict__.update(attrs)
        monkeypatch.setitem(sys.modules, name, m)

    mod('aiohttp', **aiohttp.__dict__)
    mod('open_webui.env', AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL=None, AIOHTTP_CLIENT_TIMEOUT_TOOL_SERVER_DATA=1)
    mod('open_webui.ext.terminal_context_authorization', resolve_terminal_chat_context=resolve)
    mod('open_webui.models.config', Config=config)
    mod('open_webui.models.groups', Groups=groups)
    mod('open_webui.models.users', UserModel=User)
    mod('open_webui.utils.access_control', has_connection_access=has_access)
    mod('open_webui.utils.tools', build_tool_server_headers=build)
    ns = {
        'ENABLE_TOOL_SERVERS': True,
        'is_saved_chat_id': chat_id_ns['is_saved_chat_id'],
        'quote': quote,
        'TERMINAL_CONTEXT_HEADER': 'X-Terminal-Context-Id',
        'TERMINAL_CONTEXT_DEFAULT': 'default',
        'TERMINAL_CONTEXT_TYPES': {'chat', 'automation'},
        'TERMINAL_CONTEXT_ID_SOURCES': {'chat': 'chat_id', 'automation': 'automation_id'},
        'log': SimpleNamespace(debug=MagicMock()),
        'chat_store': chat_store,
        'authorization': auth_ns,
        'resolve': resolve,
        'session': session,
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(SRC), 'exec'), ns)
    return ns, aiohttp.ClientSession, build, has_access


def _conn(**kw):
    return {'id': 't', 'url': 'http://t', **kw}


async def _run(ns, caller):
    return await ns['get_terminal_json'](
        None, User(), {'terminal_id': 't'}, '/x', {'__event_call__': caller}
    )


@pytest.mark.asyncio
async def test_duplicate_ids_reject_before_network_auth_or_browser(monkeypatch):
    ns, session, build, access = _load(monkeypatch, [_conn(), _conn(url='http://other')])
    caller = AsyncMock(return_value={'data': 'browser'})
    assert await _run(ns, caller) is None
    session.assert_not_called()
    build.assert_not_called()
    access.assert_not_called()
    caller.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize('extra', [{'enabled': False}])
async def test_disabled_does_not_use_network_or_browser(monkeypatch, extra):
    ns, session, build, _ = _load(monkeypatch, [_conn(**extra)])
    caller = AsyncMock()
    assert await _run(ns, caller) is None
    session.assert_not_called()
    caller.assert_not_called()


@pytest.mark.asyncio
async def test_access_denied(monkeypatch):
    ns, session, build, _ = _load(monkeypatch, [_conn()], access=False)
    caller = AsyncMock()
    assert await _run(ns, caller) is None
    build.assert_not_called()
    session.assert_not_called()
    caller.assert_not_called()


@pytest.mark.asyncio
async def test_missing_terminal_id_returns_none(monkeypatch):
    ns, session, _, _ = _load(monkeypatch, [_conn()])
    assert await ns['get_terminal_json'](None, User(), {}, '/x') is None
    session.assert_not_called()


@pytest.mark.asyncio
async def test_valid_single_connection_fetches(monkeypatch):
    ns, session, build, _ = _load(monkeypatch, [_conn(), {'id': 'other', 'url': 'http://o'}])
    caller = AsyncMock()
    assert await _run(ns, caller) == {'ok': True}
    session.assert_called_once()
    caller.assert_not_called()


@pytest.mark.asyncio
async def test_unconfigured_id_keeps_personal_browser_path(monkeypatch):
    ns, session, _, _ = _load(monkeypatch, [])
    caller = AsyncMock(return_value={'data': 'browser'})
    assert await ns['get_terminal_json'](
        None, User(), {'terminal_id': 't', 'chat_id': 'foreign-chat', 'session_id': 'socket-session'},
        '/skills', {'__event_call__': caller},
    ) == 'browser'
    caller.assert_awaited_once_with({
        'type': 'request:terminal',
        'data': {'terminal_id': 't', 'path': '/skills', 'session_id': 'socket-session'},
    })
    ns['resolve'].assert_not_awaited()
    session.assert_not_called()


def _scoped_connection(context_id='default', context='chat'):
    return _conn(server_type='orchestrator', config={'contexts': {context: {'context_id': context_id}}})


@pytest.mark.asyncio
@pytest.mark.parametrize('connection', [_conn(), _scoped_connection(), _scoped_connection('chat_id')])
@pytest.mark.parametrize('chat_meta', [{}, {'shared': True}, {'folder_id': 'folder-with-write-access'}])
@pytest.mark.parametrize('path', ['/skills', '/skills/read?name=example', '/files/cwd', '/files/read?path=AGENTS.md'])
async def test_foreign_saved_chat_denied_for_every_admin_read(monkeypatch, connection, chat_meta, path):
    ns, session, build, access = _load(monkeypatch, [connection])
    ns['chat_store'].get_chat_by_id.return_value = SimpleNamespace(user_id='owner', meta=chat_meta)
    caller = AsyncMock()
    metadata = {'terminal_id': 't', 'chat_id': 'foreign-chat'}
    assert await ns['get_terminal_json'](None, User(), metadata, path, {'__event_call__': caller}) is None
    assert metadata == {'terminal_id': 't', 'chat_id': 'foreign-chat'}
    ns['chat_store'].get_chat_by_id.assert_awaited_once_with('foreign-chat')
    build.assert_not_awaited()
    session.assert_not_called()
    access.assert_not_awaited()
    caller.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('role,owner,admin_access,internal,allowed', [
    ('user', 'u1', False, False, True),
    ('admin', 'other', True, False, True),
    ('admin', 'other', False, True, True),
    ('admin', 'other', False, False, False),
    ('user', 'other', True, True, False),
])
@pytest.mark.parametrize('context_id', ['default', 'chat_id'])
async def test_saved_chat_owner_and_admin_rules(monkeypatch, role, owner, admin_access, internal, allowed, context_id):
    ns, session, build, _ = _load(monkeypatch, [_scoped_connection(context_id)])
    ns['authorization']['ENABLE_ADMIN_CHAT_ACCESS'] = admin_access
    ns['chat_store'].get_chat_by_id.return_value = SimpleNamespace(user_id=owner, meta={'internal': internal})
    metadata = {'terminal_id': 't', 'chat_id': 'saved-chat'}
    caller = AsyncMock()
    result = await ns['get_terminal_json'](None, {'id': 'u1', 'role': role}, metadata, '/skills', {'__event_call__': caller})
    assert result == ({'ok': True} if allowed else None)
    caller.assert_not_awaited()
    if not allowed:
        build.assert_not_awaited()
        session.assert_not_called()
        return
    headers = ns['session'].get.call_args.kwargs['headers']
    assert headers['X-Session-Id'] == 'saved-chat'
    assert headers['X-User-Id'] == 'u1'
    assert headers.get('X-Terminal-Context-Id') == ('chat:saved-chat' if context_id == 'chat_id' else None)
    assert build.await_args.kwargs['metadata'] == metadata
    assert build.await_args.kwargs['metadata'] is not metadata


@pytest.mark.asyncio
@pytest.mark.parametrize('chat_id', ['', 'temporary:chat', 'local:chat', 'channel:chat', None, 123])
@pytest.mark.parametrize('context_id', ['default', 'chat_id'])
async def test_non_saved_context_normalized_without_saved_runtime(monkeypatch, chat_id, context_id):
    ns, session, build, _ = _load(monkeypatch, [_scoped_connection(context_id)])
    metadata = {'terminal_id': 't', 'chat_id': chat_id}
    result = await ns['get_terminal_json'](None, User(), metadata, '/skills')
    assert metadata['chat_id'] == chat_id
    ns['chat_store'].get_chat_by_id.assert_not_awaited()
    if context_id == 'chat_id':
        assert result is None
        build.assert_not_awaited()
        session.assert_not_called()
        return
    assert result == {'ok': True}
    normalized_chat_id = chat_id if isinstance(chat_id, str) else ''
    assert build.await_args.kwargs['metadata']['chat_id'] == normalized_chat_id
    assert build.await_args.kwargs['metadata'] is not metadata
    headers = ns['session'].get.call_args.kwargs['headers']
    assert headers.get('X-Session-Id') == (normalized_chat_id or None)
    assert 'X-Terminal-Context-Id' not in headers


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['missing', 'unavailable'])
async def test_saved_chat_resolution_fails_closed(monkeypatch, failure):
    ns, session, build, _ = _load(monkeypatch, [_scoped_connection()])
    if failure == 'unavailable':
        ns['chat_store'].get_chat_by_id.side_effect = RuntimeError('store unavailable')
    caller = AsyncMock()
    assert await ns['get_terminal_json'](
        None, User(), {'terminal_id': 't', 'chat_id': 'saved-chat'}, '/skills', {'__event_call__': caller},
    ) is None
    build.assert_not_awaited()
    session.assert_not_called()
    caller.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('context_id', ['default', 'chat_id'])
async def test_repeated_read_reauthorizes_after_revocation(monkeypatch, context_id):
    ns, session, build, _ = _load(monkeypatch, [_scoped_connection(context_id)])
    ns['chat_store'].get_chat_by_id.side_effect = [
        SimpleNamespace(user_id='u1', meta={}), SimpleNamespace(user_id='new-owner', meta={}),
    ]
    metadata = {'terminal_id': 't', 'chat_id': 'saved-chat'}
    assert await ns['get_terminal_json'](None, User(), metadata, '/files/cwd') == {'ok': True}
    caller = AsyncMock()
    assert await ns['get_terminal_json'](
        None, User(), metadata, '/files/read?path=AGENTS.md', {'__event_call__': caller},
    ) is None
    assert ns['chat_store'].get_chat_by_id.await_count == 2
    build.assert_awaited_once()
    session.assert_called_once()
    ns['session'].get.assert_called_once()
    caller.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('context_id', ['default', 'automation_id'])
async def test_automation_keeps_existing_context_semantics(monkeypatch, context_id):
    ns, session, build, _ = _load(monkeypatch, [_scoped_connection(context_id, 'automation')])
    metadata = {'terminal_id': 't', 'automation_id': 'automation-1', 'chat_id': 'foreign-chat'}
    assert await ns['get_terminal_json'](None, User(), metadata, '/skills') == {'ok': True}
    ns['resolve'].assert_not_awaited()
    ns['chat_store'].get_chat_by_id.assert_not_awaited()
    headers = ns['session'].get.call_args.kwargs['headers']
    assert headers['X-Session-Id'] == 'foreign-chat'
    assert headers.get('X-Terminal-Context-Id') == (
        'automation:automation-1' if context_id == 'automation_id' else None
    )
    assert build.await_args.kwargs['metadata'] == metadata

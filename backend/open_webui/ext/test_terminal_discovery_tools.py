"""Import-safe behavioral tests for terminal discovery's tools integration.

The production module imports configuration during normal application startup.
These tests execute only selected AST nodes with injected collaborators.
"""

import ast
import asyncio
import copy
import hashlib
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Optional
from urllib.parse import quote
from unittest.mock import AsyncMock

import pytest


TOOLS = Path(__file__).parents[1] / 'utils' / 'tools.py'


class Result:
    def __init__(self, data=None, category=None, retry_after=0):
        self.data, self.category, self.retry_after = data, category, retry_after


class Cache:
    def __init__(self):
        self.calls = []
        self.published = []
        self.records = {}
        self.fingerprint = _fingerprint

    async def get_or_discover(self, connection, base_url, spec_url, discover, **kwargs):
        self.calls.append((copy.deepcopy(connection), base_url, spec_url, kwargs))
        # The cache's validation callback is deliberately exercised both before
        # discovery and before publication.  A configuration change while HTTP
        # is in flight must not become a reusable cache record.
        assert await kwargs['validate']()
        key = self.fingerprint(connection, base_url, spec_url)
        if key in self.records:
            return Result(copy.deepcopy(self.records[key]))
        result = await discover()
        if not await kwargs['validate']():
            return Result(None, 'configuration_changed')
        if result.data:
            self.records[key] = copy.deepcopy(result.data)
            self.published.append(copy.deepcopy(result.data))
        return result


def _fingerprint(connection, base_url, spec_url):
    return repr((connection.get('id'), base_url, spec_url, connection.get('policy_id'), connection.get('path'), connection.get('key')))


def _load(monkeypatch):
    tree = ast.parse(TOOLS.read_text(encoding='utf-8'), filename=str(TOOLS))
    terminal_tree = ast.parse((Path(__file__).parents[1] / 'utils' / 'terminals.py').read_text(encoding='utf-8'))
    cache_tree = ast.parse((Path(__file__).parents[1] / 'ext' / 'terminal_discovery_cache.py').read_text(encoding='utf-8'))
    wanted = {
        'resolve_schema', 'convert_openapi_to_tool_payload', 'add_terminal_display_file_inline_param',
        '_fresh_terminal_connection', '_discover_terminal_server', 'get_terminal_tools', 'get_tool_server_url',
        '_apply_terminal_display_name', 'set_terminal_servers', 'get_terminal_servers',
    }
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'OPENAPI_HTTP_METHODS' for target in node.targets):
            nodes.append(copy.deepcopy(node))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in wanted:
            node = copy.deepcopy(node)
            node.decorator_list = []
            nodes.append(node)
    config = SimpleNamespace(get=AsyncMock(return_value=[]))
    fingerprint_globals = {'hashlib': hashlib, 'json': json}
    fingerprint_nodes = [copy.deepcopy(node) for node in cache_tree.body if isinstance(node, ast.FunctionDef) and node.name in {'_digest', 'terminal_fingerprint'}]
    exec(compile(ast.fix_missing_locations(ast.Module(body=fingerprint_nodes, type_ignores=[])), '<terminal-fingerprint>', 'exec'), fingerprint_globals)
    fingerprint = fingerprint_globals['terminal_fingerprint']
    cache = Cache()
    cache.fingerprint = fingerprint
    fake_cache = types.ModuleType('open_webui.ext.terminal_discovery_cache')
    fake_cache.DiscoveryResult = Result
    fake_cache.safe_fetch_openapi = AsyncMock()
    fake_cache.terminal_fingerprint = fingerprint
    fake_cache.TerminalDiscoveryCache = lambda **kwargs: cache
    package = types.ModuleType('open_webui')
    package.__path__ = []
    ext = types.ModuleType('open_webui.ext')
    ext.__path__ = []
    monkeypatch.setitem(sys.modules, 'open_webui', package)
    monkeypatch.setitem(sys.modules, 'open_webui.ext', ext)
    monkeypatch.setitem(sys.modules, 'open_webui.ext.terminal_discovery_cache', fake_cache)
    gateway = types.ModuleType('open_webui.ext.terminal_tool_gateway')
    gateway.build_terminal_tool_gateway_seed_headers = AsyncMock(return_value={'X-Gateway': 'seed'})
    monkeypatch.setitem(sys.modules, 'open_webui.ext.terminal_tool_gateway', gateway)
    globals_ = {
        'asyncio': asyncio, 'copy': copy, 'quote': quote, 'Optional': Optional,
        'logging': SimpleNamespace(getLogger=lambda _: SimpleNamespace()), 'Config': config, 'Groups': SimpleNamespace(get_groups_by_member_id=AsyncMock(return_value=[])),
        'has_connection_access': AsyncMock(return_value=True), 'Request': object, 'UserModel': object, 'AIOHTTP_CLIENT_TIMEOUT_TOOL_SERVER_DATA': 10,
        'AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL': None, 'REDIS_KEY_PREFIX': 'test', 'TERMINAL_CONTEXT_HEADER': 'X-Terminal-Context-Id',
        'ENABLE_TOOL_SERVERS': True,
        'bearer_auth_header': lambda token: {'Authorization': f'Bearer {token}'} if token else {},
        'clean_openai_tool_schema': lambda value: value, 'execute_tool_server': AsyncMock(return_value=({}, {})),
        'get_async_tool_function_and_apply_extra_params': AsyncMock(side_effect=lambda fn, _: fn),
        'get_terminal_cwd': AsyncMock(return_value=None), 'get_terminal_system_prompt': AsyncMock(return_value=None),
        'persist_terminal_file_to_platform': AsyncMock(), 'transfer_platform_file_to_terminal': AsyncMock(),
        'log': SimpleNamespace(debug=lambda *args, **kwargs: None),
    }
    module = ast.Module(body=nodes, type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(TOOLS), 'exec'), globals_)
    chat_tree = ast.parse((Path(__file__).parents[1] / 'utils' / 'chat_id.py').read_text(encoding='utf-8'))
    chat_nodes = [copy.deepcopy(node) for node in chat_tree.body if isinstance(node, (ast.Assign, ast.FunctionDef))]
    terminal_names = {'is_terminal_orchestrator', 'get_terminal_server_url', 'terminal_context_config', 'terminal_context_available', 'terminal_context_id'}
    terminal_nodes = [copy.deepcopy(node) for node in terminal_tree.body if isinstance(node, ast.Assign) or isinstance(node, ast.FunctionDef) and node.name in terminal_names]
    exec(compile(ast.fix_missing_locations(ast.Module(body=chat_nodes + terminal_nodes, type_ignores=[])), '<terminal-routing>', 'exec'), globals_)
    # Execute the real authorization helper with legitimate saved-chat owners;
    # no model/database imports or live stores are used by this AST harness.
    auth_tree = ast.parse((Path(__file__).parents[1] / 'ext' / 'terminal_context_authorization.py').read_text(encoding='utf-8'))
    auth_nodes = [copy.deepcopy(node) for node in auth_tree.body if isinstance(node, ast.AsyncFunctionDef)]
    chats = SimpleNamespace(get_chat_by_id=AsyncMock(side_effect=lambda chat_id: SimpleNamespace(
        id=chat_id, user_id={'chat': 'user-a', 'saved': 'u'}.get(chat_id, 'owner'), meta={}
    )))
    globals_.update(Chats=chats, ENABLE_ADMIN_CHAT_ACCESS=False, is_internal_chat=lambda meta: False)
    exec(compile(ast.fix_missing_locations(ast.Module(body=auth_nodes, type_ignores=[])), '<terminal-authorization>', 'exec'), globals_)
    globals_['_terminal_discovery_cache'] = lambda request: cache
    return SimpleNamespace(g=globals_, cache=cache, config=config, fetch=fake_cache.safe_fetch_openapi, gateway=gateway, chats=chats)


def _connection(id='terminal-a', **extra):
    value = {'id': id, 'url': 'https://orchestrator.example', 'policy_id': 'policy-a', 'key': 'discovery-secret', 'enabled': True, 'auth_type': 'bearer', 'config': {'contexts': {'chat': {'context_id': 'chat_id'}}}}
    value.update(extra)
    return value


def _openapi():
    return {'openapi': '3.0.0', 'info': {'title': 'terminal'}, 'paths': {'/run': {'post': {'operationId': 'run_command', 'responses': {'200': {'description': 'ok'}}}}}}


@pytest.mark.asyncio
async def test_discovery_uses_actual_converter_document_and_static_credentials(monkeypatch):
    subject = _load(monkeypatch)
    connection = _connection(path='https://spec.example/openapi.json')
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)))
    server, category = await subject.g['_discover_terminal_server'](request, connection)
    assert category is None
    assert [spec['name'] for spec in server['specs']] == ['run_command']
    assert subject.fetch.await_args.args[1] == {'Authorization': 'Bearer discovery-secret'}
    assert subject.cache.calls[0][2] == 'https://spec.example/openapi.json'


@pytest.mark.asyncio
async def test_cached_prompt_is_fp_bound_and_live_prompt_failure_falls_back(monkeypatch):
    subject = _load(monkeypatch)
    connection = _connection()
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    subject.g['get_terminal_system_prompt'].side_effect = ['static prompt', None]
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='session')))
    tools, prompt = await subject.g['get_terminal_tools'](
        request, 'terminal-a', SimpleNamespace(id='user-a'), {'__metadata__': {'chat_id': 'chat'}}
    )
    assert tools['run_command']['spec']['name'] == 'run_command'
    assert prompt == 'static prompt'
    static_headers = subject.g['get_terminal_system_prompt'].await_args_list[0].args[1]
    assert static_headers == {'Authorization': 'Bearer discovery-secret', 'X-User-Id': 'system'}


@pytest.mark.asyncio
async def test_name_change_updates_cached_display_without_network_discovery(monkeypatch):
    subject = _load(monkeypatch)
    connection = _connection(name='new terminal')
    subject.config.get.return_value = [connection]
    cached = {'id': 'terminal-a', 'url': 'https://orchestrator.example/p/policy-a', 'openapi': _openapi(), 'info': {'title': 'old terminal'}, 'specs': [{'name': 'run_command'}], 'system_prompt': 'old static'}
    subject.cache.get_or_discover = AsyncMock(return_value=Result(cached))
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)))
    server, category = await subject.g['_discover_terminal_server'](request, connection)
    assert category is None
    assert server['openapi']['info']['title'] == 'new terminal'
    assert server['info']['title'] == 'new terminal'
    subject.fetch.assert_not_awaited()


@pytest.mark.asyncio
async def test_duplicate_disabled_and_context_rejection_happen_before_discovery_or_gateway(monkeypatch):
    subject = _load(monkeypatch)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='session')))
    user = SimpleNamespace(id='user-a')
    connection = _connection(enabled=False)
    subject.config.get.return_value = [connection]
    with pytest.raises(RuntimeError):
        await subject.g['get_terminal_tools'](request, 'terminal-a', user, {'__metadata__': {'chat_id': 'chat'}})
    assert not subject.cache.calls
    assert not subject.gateway.build_terminal_tool_gateway_seed_headers.await_count
    subject.config.get.return_value = [_connection(config={'contexts': {'chat': False}})]
    with pytest.raises(RuntimeError):
        await subject.g['get_terminal_tools'](request, 'terminal-a', user, {'__metadata__': {'chat_id': 'chat'}})
    assert not subject.cache.calls
    subject.config.get.return_value = [_connection()]
    subject.g['has_connection_access'].return_value = False
    with pytest.raises(RuntimeError):
        await subject.g['get_terminal_tools'](request, 'terminal-a', user, {'__metadata__': {'chat_id': 'chat'}})
    assert not subject.cache.calls
    subject.g['has_connection_access'].return_value = True
    connection = _connection()
    subject.config.get.return_value = [connection, copy.deepcopy(connection)]
    with pytest.raises(RuntimeError):
        await subject.g['get_terminal_tools'](request, 'terminal-a', user, {'__metadata__': {'chat_id': 'chat'}})
    assert not subject.cache.calls


@pytest.mark.asyncio
async def test_tool_operation_rechecks_config_and_rebuilds_headers(monkeypatch):
    subject = _load(monkeypatch)
    connection = _connection(forward_cookies=True)
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={'cookie': 'value'}, state=SimpleNamespace(token=SimpleNamespace(credentials='session-one')))
    user = SimpleNamespace(id='user-a')
    tools, _ = await subject.g['get_terminal_tools'](request, 'terminal-a', user, {'__metadata__': {'chat_id': 'chat'}})
    request.state.token.credentials = 'session-two'
    await tools['run_command']['callable']()
    call = subject.g['execute_tool_server'].await_args.kwargs
    assert call['url'] == 'https://orchestrator.example/p/policy-a'
    assert call['headers']['X-User-Id'] == 'user-a'
    assert call['headers']['X-Session-Id'] == 'chat'
    assert call['headers']['X-Terminal-Context-Id'] == 'chat:chat'
    assert call['headers']['X-Gateway'] == 'seed'
    assert call['cookies'] == {'cookie': 'value'}
    subject.config.get.return_value = []
    with pytest.raises(RuntimeError):
        await tools['run_command']['callable']()
    with pytest.raises(RuntimeError):
        await tools['persist_file_to_chat']['callable']('/tmp/x')
    with pytest.raises(RuntimeError):
        await tools['transfer_file_to_terminal']['callable']('file', '/tmp/x')


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('auth_type', 'extra', 'expected'),
    [('bearer', {}, 'Bearer discovery-secret'), ('session', {}, 'Bearer session-one'), ('system_oauth', {'__oauth_token__': {'access_token': 'oauth-token'}}, 'Bearer oauth-token')],
)
async def test_operation_auth_is_current_request_auth_not_discovery_cache(monkeypatch, auth_type, extra, expected):
    subject = _load(monkeypatch)
    connection = _connection(auth_type=auth_type)
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='session-one')))
    params = {'__metadata__': {'chat_id': 'chat'}, **extra}
    tools, _ = await subject.g['get_terminal_tools'](request, 'terminal-a', SimpleNamespace(id='user-a'), params)
    await tools['run_command']['callable']()
    assert subject.g['execute_tool_server'].await_args.kwargs['headers']['Authorization'] == expected


@pytest.mark.asyncio
async def test_projection_skips_empty_disabled_and_duplicate_ids_without_io(monkeypatch):
    subject = _load(monkeypatch)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)))
    subject.config.get.return_value = [
        {}, _connection(id=''), _connection(id='off', enabled=False),
        _connection(id='same'), _connection(id='same'),
    ]
    assert await subject.g['set_terminal_servers'](request) == []
    assert request.app.state.TERMINAL_SERVERS == []
    subject.fetch.assert_not_awaited()
    assert not subject.cache.calls
    subject.gateway.build_terminal_tool_gateway_seed_headers.assert_not_awaited()


@pytest.mark.asyncio
async def test_projection_is_bounded_and_keeps_healthy_results(monkeypatch):
    subject = _load(monkeypatch)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)))
    subject.config.get.return_value = [_connection(id=f't{i}') for i in range(6)]
    entered, release = asyncio.Event(), asyncio.Event()
    active = maximum = 0

    async def discover(_request, connection):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        if active == 4:
            entered.set()
        await release.wait()
        active -= 1
        return ({'id': connection['id']} if connection['id'] != 't2' else None, None)

    subject.g['_discover_terminal_server'] = discover
    task = asyncio.create_task(subject.g['set_terminal_servers'](request))
    await entered.wait()
    assert maximum == 4
    release.set()
    assert [item['id'] for item in await task] == ['t0', 't1', 't3', 't4', 't5']


@pytest.mark.asyncio
@pytest.mark.parametrize('chat_id', [None, 'temporary:x', 'local:x', 'channel:x'], ids=['none', 'temporary', 'local', 'channel'])
async def test_required_saved_chat_context_rejects_before_recovery(monkeypatch, chat_id):
    subject = _load(monkeypatch)
    connection = _connection(config={'contexts': {'chat': {'context_id': 'chat_id'}}})
    subject.config.get.return_value = [connection]
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='s')))
    with pytest.raises(RuntimeError, match='requires a saved chat context'):
        await subject.g['get_terminal_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': chat_id}})
    assert not subject.cache.calls
    subject.gateway.build_terminal_tool_gateway_seed_headers.assert_not_awaited()
    subject.g['get_terminal_cwd'].assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('connection', 'metadata'),
    [
        (_connection(config={'contexts': {'chat': False}}), {'chat_id': 'saved'}),
        (_connection(config={'contexts': {'automation': False}}), {'automation_id': 'job'}),
        (_connection(config={'contexts': {'chat': {'context_id': 'chat_id'}}}), {}),
    ], ids=['chat-disabled', 'automation-disabled', 'chat-required'],
)
async def test_context_rejections_happen_before_discovery(monkeypatch, connection, metadata):
    subject = _load(monkeypatch)
    subject.config.get.return_value = [connection]
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='s')))
    with pytest.raises(RuntimeError):
        await subject.g['get_terminal_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': metadata})
    assert not subject.cache.calls
    subject.g['get_terminal_cwd'].assert_not_awaited()
    subject.g['execute_tool_server'].assert_not_awaited()


@pytest.mark.asyncio
async def test_falsy_automation_id_uses_allowed_legacy_chat_context(monkeypatch):
    """The production selector deliberately chooses automation only for a truthy ID."""
    subject = _load(monkeypatch)
    connection = _connection(config={'contexts': {'chat': {}, 'automation': False}})
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='s')))
    tools, _ = await subject.g['get_terminal_tools'](
        request, 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'automation_id': None, 'chat_id': 'saved'}}
    )
    assert 'run_command' in tools
    assert len(subject.cache.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('field,value', [
    ('url', 'https://changed.example'), ('policy_id', 'other'), ('path', '/other.json'),
    ('key', 'rotated'), ('auth_type', 'session'), ('enabled', False),
], ids=['url', 'policy', 'path', 'key', 'auth', 'disabled'])
async def test_discovery_race_does_not_publish_stale_schema(monkeypatch, field, value):
    subject = _load(monkeypatch)
    connection = _connection()
    subject.config.get.return_value = [connection]
    started, release = asyncio.Event(), asyncio.Event()

    async def fetch(*_args, **_kwargs):
        started.set()
        await release.wait()
        return Result(_openapi())

    subject.fetch.side_effect = fetch
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)))
    task = asyncio.create_task(subject.g['_discover_terminal_server'](request, connection))
    await started.wait()
    changed = copy.deepcopy(connection)
    changed[field] = value
    subject.config.get.return_value = [changed]
    release.set()
    assert await task == (None, 'configuration_changed')
    assert not subject.cache.published


@pytest.mark.asyncio
async def test_discovery_race_context_and_access_are_fail_closed(monkeypatch):
    subject = _load(monkeypatch)
    connection = _connection()
    subject.config.get.return_value = [connection]
    started, release = asyncio.Event(), asyncio.Event()

    async def fetch(*_args, **_kwargs):
        started.set()
        await release.wait()
        return Result(_openapi())

    subject.fetch.side_effect = fetch
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)))
    task = asyncio.create_task(subject.g['_discover_terminal_server'](request, connection))
    await started.wait()
    changed = copy.deepcopy(connection)
    changed['config'] = {'contexts': {'chat': False}}
    subject.config.get.return_value = [changed]
    release.set()
    assert await task == (None, 'configuration_changed')
    subject.g['has_connection_access'].return_value = False
    with pytest.raises(RuntimeError, match='Access denied'):
        await subject.g['get_terminal_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': 'saved'}})
    assert subject.g['get_terminal_cwd'].await_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', [
    lambda c: None, lambda c: c.update(enabled=False), lambda c: c.update(policy_id='other'),
    lambda c: c.update(path='/other.json'), lambda c: c.update(key='rotated'),
    lambda c: c.update(config={'contexts': {'chat': False}}),
], ids=['removed', 'disabled', 'policy', 'path', 'key', 'context'])
async def test_generated_callables_fail_closed_after_configuration_change(monkeypatch, mutation):
    subject = _load(monkeypatch)
    connection = _connection()
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='s')))
    tools, _ = await subject.g['get_terminal_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': 'saved'}})
    baseline = subject.g['execute_tool_server'].await_count
    changed = copy.deepcopy(connection)
    mutation(changed)
    subject.config.get.return_value = [] if mutation.__name__ == '<lambda>' and changed == connection else [changed]
    for name, args in [('run_command', ()), ('persist_file_to_chat', ('/x',)), ('transfer_file_to_terminal', ('f', '/x'))]:
        with pytest.raises(RuntimeError):
            await tools[name]['callable'](*args)
    assert subject.g['execute_tool_server'].await_count == baseline


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('name', 'args'),
    [('run_command', ()), ('persist_file_to_chat', ('/x',)), ('transfer_file_to_terminal', ('file', '/x'))],
    ids=['tool', 'persist', 'transfer'],
)
async def test_generated_callable_rechecks_access_without_upstream_io(monkeypatch, name, args):
    subject = _load(monkeypatch)
    connection = _connection()
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='s')))
    tools, _ = await subject.g['get_terminal_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': 'saved'}})
    subject.g['has_connection_access'].return_value = False
    with pytest.raises(RuntimeError, match='Access denied'):
        await tools[name]['callable'](*args)
    subject.g['execute_tool_server'].assert_not_awaited()
    subject.g['persist_terminal_file_to_platform'].assert_not_awaited()
    subject.g['transfer_platform_file_to_terminal'].assert_not_awaited()
    subject.gateway.build_terminal_tool_gateway_seed_headers.assert_awaited_once()


@pytest.mark.asyncio
async def test_policy_routing_is_quoted_for_discovery_live_calls_and_raw_terminal(monkeypatch):
    subject = _load(monkeypatch)
    connection = _connection(policy_id='team/a b')
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='s')))
    tools, _ = await subject.g['get_terminal_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': 'saved'}})
    expected = 'https://orchestrator.example/p/team%2Fa%20b'
    assert subject.fetch.await_args.args[0] == f'{expected}/openapi.json'
    assert subject.g['get_terminal_cwd'].await_args.args[0] == expected
    await tools['run_command']['callable']()
    assert subject.g['execute_tool_server'].await_args.kwargs['url'] == expected
    await tools['persist_file_to_chat']['callable']('/tmp/x')
    assert subject.g['persist_terminal_file_to_platform'].await_args.kwargs['base_url'] == expected
    await tools['transfer_file_to_terminal']['callable']('file', '/tmp/x')
    assert subject.g['transfer_platform_file_to_terminal'].await_args.kwargs['base_url'] == expected
    assert subject.g['persist_terminal_file_to_platform'].await_args.kwargs['headers']['X-User-Id'] == 'u'
    assert subject.g['transfer_platform_file_to_terminal'].await_args.kwargs['headers']['X-User-Id'] == 'u'
    raw = _connection(policy_id=None, server_type='raw', url='https://raw.example')
    subject.config.get.return_value = [raw]
    subject.fetch.return_value = Result(_openapi())
    raw_tools, _ = await subject.g['get_terminal_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': 'saved'}})
    await raw_tools['run_command']['callable']()
    assert subject.g['execute_tool_server'].await_args.kwargs['url'] == 'https://raw.example'
    await raw_tools['persist_file_to_chat']['callable']('/tmp/x')
    await raw_tools['transfer_file_to_terminal']['callable']('file', '/tmp/x')
    assert subject.g['persist_terminal_file_to_platform'].await_args.kwargs['base_url'] == 'https://raw.example'
    assert subject.g['transfer_platform_file_to_terminal'].await_args.kwargs['base_url'] == 'https://raw.example'
    assert subject.g['persist_terminal_file_to_platform'].await_args.kwargs['headers']['X-User-Id'] == 'u'
    assert subject.g['transfer_platform_file_to_terminal'].await_args.kwargs['headers']['X-User-Id'] == 'u'


@pytest.mark.asyncio
@pytest.mark.parametrize('auth_type', ['bearer', 'none', 'session', 'system_oauth'])
async def test_discovery_uses_only_static_bearer_credentials(monkeypatch, auth_type):
    subject = _load(monkeypatch)
    connection = _connection(auth_type=auth_type, key='configured-schema-key', forward_cookies=True)
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={'browser': 'browser-cookie-private'},
        state=SimpleNamespace(token=SimpleNamespace(credentials='caller-session-private')),
    )
    await subject.g['_discover_terminal_server'](request, connection)
    headers = subject.fetch.await_args.args[1]
    assert headers == ({'Authorization': 'Bearer configured-schema-key'} if auth_type == 'bearer' else {})
    assert 'browser-cookie-private' not in repr(subject.fetch.await_args)
    assert 'caller-session-private' not in repr(subject.fetch.await_args)
    assert 'caller-oauth-private' not in repr(subject.fetch.await_args)


@pytest.mark.asyncio
async def test_session_auth_rotation_is_read_when_the_tool_is_invoked(monkeypatch):
    subject = _load(monkeypatch)
    connection = _connection(auth_type='session')
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='session-one')))
    tools, _ = await subject.g['get_terminal_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': 'saved'}})
    request.state.token.credentials = 'session-two'
    await tools['run_command']['callable']()
    assert subject.g['execute_tool_server'].await_args.kwargs['headers']['Authorization'] == 'Bearer session-two'


@pytest.mark.asyncio
async def test_static_prompt_is_optional_and_display_name_is_a_copy(monkeypatch):
    subject = _load(monkeypatch)
    connection = _connection(name='first')
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    # The discovery-time optional prompt times out; the live prompt lookup is
    # allowed to fail empty so a usable schema still constructs tools.
    subject.g['get_terminal_system_prompt'].side_effect = [asyncio.TimeoutError(), None]
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='s')))
    tools, prompt = await subject.g['get_terminal_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': 'saved'}})
    assert tools and prompt is None
    cached = {'openapi': _openapi(), 'info': {'title': 'old'}, 'specs': [{'name': 'run_command'}]}
    changed = _connection(name='second')
    named = subject.g['_apply_terminal_display_name'](cached, changed)
    assert named['info']['title'] == named['openapi']['info']['title'] == 'second'
    assert cached['info']['title'] == 'old'


@pytest.mark.asyncio
async def test_cached_static_prompt_is_fingerprint_bound_and_usable_after_live_failure(monkeypatch):
    subject = _load(monkeypatch)
    connection = _connection()
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    subject.g['get_terminal_system_prompt'].side_effect = ['cached prompt', 'new prompt']
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)))
    first, _ = await subject.g['_discover_terminal_server'](request, connection)
    second, _ = await subject.g['_discover_terminal_server'](request, connection)
    assert first['system_prompt'] == second['system_prompt'] == 'cached prompt'
    assert subject.fetch.await_count == 1
    changed = _connection(key='rotated')
    subject.config.get.return_value = [changed]
    third, _ = await subject.g['_discover_terminal_server'](request, changed)
    assert third['system_prompt'] == 'new prompt'
    assert subject.fetch.await_count == 2


@pytest.mark.asyncio
async def test_disabled_feature_returns_upstream_shapes_without_config_or_discovery(monkeypatch):
    subject = _load(monkeypatch)
    subject.g['ENABLE_TOOL_SERVERS'] = False
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None, TERMINAL_SERVERS=[{'id': 'stale'}])))
    assert await subject.g['get_terminal_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {}) == {}
    assert await subject.g['get_terminal_servers'](request) == []
    assert await subject.g['set_terminal_servers'](request) == []
    assert request.app.state.TERMINAL_SERVERS == []
    subject.config.get.assert_not_awaited()
    subject.fetch.assert_not_awaited()
    subject.gateway.build_terminal_tool_gateway_seed_headers.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('cwd_enabled', [True, False])
async def test_upstream_config_knobs_and_inherited_access_apply_to_fresh_calls(monkeypatch, cwd_enabled):
    subject = _load(monkeypatch)
    connection = _connection(config={'working_directory_context': cwd_enabled, 'user_shell_tools': 'always'})
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    subject.g['Groups'].get_groups_by_member_id.return_value = [SimpleNamespace(id='parent-group')]
    subject.g['get_terminal_cwd'].return_value = '/workspace'
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={})
    tools, _ = await subject.g['get_terminal_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {})
    assert tools['run_command']['user_shell_tools'] == 'always'
    assert ('/workspace' in tools['run_command']['spec'].get('description', '')) is cwd_enabled
    assert subject.g['get_terminal_cwd'].await_count == int(cwd_enabled)
    await tools['run_command']['callable']()
    for call in subject.g['Groups'].get_groups_by_member_id.await_args_list:
        assert call.kwargs == {'include_inherited': True}
    for call in subject.g['has_connection_access'].await_args_list:
        assert call.args[2] == {'parent-group'}


@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['feature', 'working_directory_context', 'user_shell_tools'])
async def test_existing_callables_fail_closed_when_feature_or_config_knobs_change(monkeypatch, change):
    subject = _load(monkeypatch)
    connection = _connection(config={})
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={})
    tools, _ = await subject.g['get_terminal_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {})
    if change == 'feature':
        subject.g['ENABLE_TOOL_SERVERS'] = False
    else:
        changed = copy.deepcopy(connection)
        changed['config'][change] = False if change == 'working_directory_context' else 'always'
        subject.config.get.return_value = [changed]
    for name, args in [('run_command', ()), ('persist_file_to_chat', ('/x',)), ('transfer_file_to_terminal', ('f', '/x'))]:
        with pytest.raises(RuntimeError):
            await tools[name]['callable'](*args)
    subject.g['execute_tool_server'].assert_not_awaited()
    subject.g['persist_terminal_file_to_platform'].assert_not_awaited()
    subject.g['transfer_platform_file_to_terminal'].assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('meta', [{'shared': True}, {'folder_id': 'writable-folder'}])
@pytest.mark.parametrize('context', ['default', 'chat_id'])
async def test_model_tools_deny_foreign_shared_or_folder_writer_before_discovery(monkeypatch, meta, context):
    subject = _load(monkeypatch)
    subject.config.get.return_value = [_connection(config={'contexts': {'chat': {'context_id': context}}})]
    subject.chats.get_chat_by_id.side_effect = None
    subject.chats.get_chat_by_id.return_value = SimpleNamespace(id='foreign', user_id='owner', meta=meta)
    with pytest.raises(RuntimeError, match='Access denied to terminal chat context'):
        await subject.g['get_terminal_tools'](SimpleNamespace(), 'terminal-a', SimpleNamespace(id='writer', role='user'), {'__metadata__': {'chat_id': 'foreign'}})
    assert not subject.cache.calls
    subject.fetch.assert_not_awaited()
    subject.gateway.build_terminal_tool_gateway_seed_headers.assert_not_awaited()
    subject.g['get_terminal_cwd'].assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('revocation', ['deleted', 'owner-changed', 'store-error'])
async def test_all_model_operations_reauthorize_saved_owner_before_gateway(monkeypatch, revocation):
    subject = _load(monkeypatch)
    subject.config.get.return_value = [_connection()]
    subject.fetch.return_value = Result(_openapi())
    metadata = {'chat_id': 'saved'}
    tools, _ = await subject.g['get_terminal_tools'](SimpleNamespace(cookies={}), 'terminal-a', SimpleNamespace(id='u', role='user'), {'__metadata__': metadata})
    metadata['chat_id'] = 'temporary:redirect'
    subject.chats.get_chat_by_id.side_effect = RuntimeError('private store detail') if revocation == 'store-error' else None
    subject.chats.get_chat_by_id.return_value = None if revocation == 'deleted' else SimpleNamespace(user_id='new-owner', meta={})
    subject.gateway.build_terminal_tool_gateway_seed_headers.reset_mock()
    for name, args in [('run_command', ()), ('persist_file_to_chat', ('/x',)), ('transfer_file_to_terminal', ('f', '/x'))]:
        with pytest.raises(RuntimeError):
            await tools[name]['callable'](*args)
    assert subject.chats.get_chat_by_id.await_args.args == ('saved',)
    subject.gateway.build_terminal_tool_gateway_seed_headers.assert_not_awaited()
    subject.g['execute_tool_server'].assert_not_awaited()
    subject.g['persist_terminal_file_to_platform'].assert_not_awaited()
    subject.g['transfer_platform_file_to_terminal'].assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('chat_id', ['', 'temporary:x', 'local:x', 'channel:x'])
async def test_model_default_context_preserves_non_saved_tracking(monkeypatch, chat_id):
    subject = _load(monkeypatch)
    subject.config.get.return_value = [_connection(config={})]
    subject.fetch.return_value = Result(_openapi())
    tools, _ = await subject.g['get_terminal_tools'](SimpleNamespace(cookies={}), 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': chat_id}})
    await tools['run_command']['callable']()
    headers = subject.g['execute_tool_server'].await_args.kwargs['headers']
    assert headers.get('X-Session-Id', '') == chat_id
    assert 'X-Terminal-Context-Id' not in headers
    subject.chats.get_chat_by_id.assert_not_awaited()


@pytest.mark.asyncio
async def test_model_automation_keeps_automation_context_without_chat_lookup(monkeypatch):
    subject = _load(monkeypatch)
    subject.config.get.return_value = [_connection(config={'contexts': {'automation': {'context_id': 'automation_id'}}})]
    subject.fetch.return_value = Result(_openapi())
    tools, _ = await subject.g['get_terminal_tools'](SimpleNamespace(cookies={}), 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'automation_id': 'job', 'chat_id': 'saved'}})
    await tools['run_command']['callable']()
    assert subject.g['execute_tool_server'].await_args.kwargs['headers']['X-Terminal-Context-Id'] == 'automation:job'
    subject.chats.get_chat_by_id.assert_not_awaited()

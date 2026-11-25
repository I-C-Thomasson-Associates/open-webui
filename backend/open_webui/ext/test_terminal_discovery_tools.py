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
from fastapi import HTTPException


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
    return repr((connection.get('id'), base_url, spec_url, connection.get('path'), connection.get('key')))


def _load(monkeypatch):
    tree = ast.parse(TOOLS.read_text(encoding='utf-8'), filename=str(TOOLS))
    terminal_tree = ast.parse((Path(__file__).parents[1] / 'utils' / 'machines' / '__init__.py').read_text(encoding='utf-8'))
    cache_tree = ast.parse((Path(__file__).parents[1] / 'ext' / 'terminal_discovery_cache.py').read_text(encoding='utf-8'))
    wanted = {
        'resolve_schema', 'convert_openapi_to_tool_payload', 'add_terminal_display_file_inline_param',
        '_fresh_terminal_connection', '_discover_terminal_server', 'get_machine_tools', 'get_tool_server_url',
        '_apply_terminal_display_name', 'set_machines', 'get_machines',
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
    timeout_nodes = [copy.deepcopy(node) for node in cache_tree.body if isinstance(node, ast.FunctionDef) and node.name == 'terminal_discovery_timeout']
    exec(compile(ast.fix_missing_locations(ast.Module(body=fingerprint_nodes, type_ignores=[])), '<terminal-fingerprint>', 'exec'), fingerprint_globals)
    fingerprint = fingerprint_globals['terminal_fingerprint']
    cache = Cache()
    cache.fingerprint = fingerprint
    fake_cache = types.ModuleType('open_webui.ext.terminal_discovery_cache')
    fake_cache.DiscoveryResult = Result
    fake_cache.safe_fetch_openapi = AsyncMock()
    fake_cache.terminal_fingerprint = fingerprint
    timeout_globals = {'POLICY_DISCOVERY_TIMEOUT_SECONDS': 60.0, 'TerminalDiscoveryCache': SimpleNamespace(_timeout=lambda v: float(v))}
    exec(compile(ast.fix_missing_locations(ast.Module(body=timeout_nodes, type_ignores=[])), '<terminal-timeout>', 'exec'), timeout_globals)
    fake_cache.terminal_discovery_timeout = timeout_globals['terminal_discovery_timeout']
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
        'AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL': None, 'REDIS_KEY_PREFIX': 'test',
        'ENABLE_TOOL_SERVERS': True, 'MANAGED_SCHEMES': ('ssh://', 'local://'),
        'bearer_auth_header': lambda token: {'Authorization': f'Bearer {token}'} if token else {},
        'clean_openai_tool_schema': lambda value: value, 'execute_tool_server': AsyncMock(return_value=({}, {})),
        'get_async_tool_function_and_apply_extra_params': AsyncMock(side_effect=lambda fn, _: fn),
        'get_machine_cwd': AsyncMock(return_value=None), 'get_machine_system_prompt': AsyncMock(return_value=None),
        'persist_terminal_file_to_platform': AsyncMock(), 'transfer_platform_file_to_terminal': AsyncMock(),
        'log': SimpleNamespace(debug=lambda *args, **kwargs: None),
        # Tether: without a live device the user's connections are the admin Config list.
        'get_machine_connections': AsyncMock(side_effect=lambda user: config.get.return_value),
        'get_tool_server_data': AsyncMock(),
    }
    module = ast.Module(body=nodes, type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(TOOLS), 'exec'), globals_)
    terminal_names = {'get_machine_url'}
    terminal_nodes = [copy.deepcopy(node) for node in terminal_tree.body if isinstance(node, ast.FunctionDef) and node.name in terminal_names]
    exec(compile(ast.fix_missing_locations(ast.Module(body=terminal_nodes, type_ignores=[])), '<terminal-routing>', 'exec'), globals_)

    # find_machine_connection is the central authorizer (tested against the real
    # module in test_terminal_json_resolution.py).  Its default fake mirrors the
    # admin-connection rules: one enabled Config entry, ambiguous IDs rejected.
    async def find_machine_connection(user, terminal_id, metadata=None, request=None):
        matches = [c for c in config.get.return_value if c.get('id') == terminal_id]
        if len(matches) > 1:
            raise HTTPException(409, 'Ambiguous machine ID')
        return copy.deepcopy(matches[0]) if matches else None

    authorizer = types.ModuleType('open_webui.utils.machines')
    authorizer.find_machine_connection = AsyncMock(side_effect=find_machine_connection)
    # Same contract as the real helper: only trusted connection context becomes headers.
    authorizer.machine_headers = lambda connection: connection.get('_headers', {})
    monkeypatch.setitem(sys.modules, 'open_webui.utils.machines', authorizer)
    globals_['_terminal_discovery_cache'] = lambda request: cache
    return SimpleNamespace(g=globals_, cache=cache, config=config, fetch=fake_cache.safe_fetch_openapi, gateway=gateway, find=authorizer.find_machine_connection)


def _connection(id='terminal-a', **extra):
    value = {'id': id, 'url': 'https://orchestrator.example', 'key': 'discovery-secret', 'enabled': True, 'auth_type': 'bearer', 'config': {}}
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
    subject.g['get_machine_system_prompt'].side_effect = ['static prompt', None]
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='session')))
    tools, prompt = await subject.g['get_machine_tools'](
        request, 'terminal-a', SimpleNamespace(id='user-a'), {'__metadata__': {'chat_id': 'chat'}}
    )
    assert tools['run_command']['spec']['name'] == 'run_command'
    assert prompt == 'static prompt'
    static_headers = subject.g['get_machine_system_prompt'].await_args_list[0].args[1]
    assert static_headers == {'Authorization': 'Bearer discovery-secret'}


@pytest.mark.asyncio
async def test_name_change_updates_cached_display_without_network_discovery(monkeypatch):
    subject = _load(monkeypatch)
    connection = _connection(name='new terminal')
    subject.config.get.return_value = [connection]
    cached = {'id': 'terminal-a', 'url': 'https://orchestrator.example', 'openapi': _openapi(), 'info': {'title': 'old terminal'}, 'specs': [{'name': 'run_command'}], 'system_prompt': 'old static'}
    subject.cache.get_or_discover = AsyncMock(return_value=Result(cached))
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)))
    server, category = await subject.g['_discover_terminal_server'](request, connection)
    assert category is None
    assert server['openapi']['info']['title'] == 'new terminal'
    assert server['info']['title'] == 'new terminal'
    subject.fetch.assert_not_awaited()


@pytest.mark.asyncio
async def test_tool_operation_rechecks_config_and_rebuilds_headers(monkeypatch):
    subject = _load(monkeypatch)
    connection = _connection(forward_cookies=True)
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={'cookie': 'value'}, state=SimpleNamespace(token=SimpleNamespace(credentials='session-one')))
    user = SimpleNamespace(id='user-a')
    tools, _ = await subject.g['get_machine_tools'](request, 'terminal-a', user, {'__metadata__': {'chat_id': 'chat'}})
    request.state.token.credentials = 'session-two'
    await tools['run_command']['callable']()
    call = subject.g['execute_tool_server'].await_args.kwargs
    assert call['url'] == 'https://orchestrator.example'
    assert call['headers']['X-User-Id'] == 'user-a'
    assert call['headers']['X-Session-Id'] == 'chat'
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
    tools, _ = await subject.g['get_machine_tools'](request, 'terminal-a', SimpleNamespace(id='user-a'), params)
    await tools['run_command']['callable']()
    assert subject.g['execute_tool_server'].await_args.kwargs['headers']['Authorization'] == expected


@pytest.mark.asyncio
async def test_projection_skips_empty_disabled_and_duplicate_ids_without_io(monkeypatch):
    subject = _load(monkeypatch)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)))
    subject.config.get.return_value = [
        {}, _connection(id=''), _connection(id='off', enabled=False),
        _connection(id='same'), _connection(id='same'), _connection(id='managed', server_type='orchestrator'),
    ]
    assert await subject.g['set_machines'](request) == []
    assert request.app.state.MACHINES == []
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
    task = asyncio.create_task(subject.g['set_machines'](request))
    await entered.wait()
    assert maximum == 4
    release.set()
    assert [item['id'] for item in await task] == ['t0', 't1', 't3', 't4', 't5']


@pytest.mark.asyncio
@pytest.mark.parametrize('field,value', [
    ('url', 'https://changed.example'), ('path', '/other.json'),
    ('key', 'rotated'), ('auth_type', 'session'), ('enabled', False),
], ids=['url', 'path', 'key', 'auth', 'disabled'])
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
@pytest.mark.parametrize('mutation', [
    lambda c: None, lambda c: c.update(enabled=False), lambda c: c.update(path='/other.json'), lambda c: c.update(key='rotated'),
    lambda c: c.update(config={'working_directory_context': False}),
], ids=['removed', 'disabled', 'path', 'key', 'cwd-policy'])
async def test_generated_callables_fail_closed_after_configuration_change(monkeypatch, mutation):
    subject = _load(monkeypatch)
    connection = _connection()
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='s')))
    tools, _ = await subject.g['get_machine_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': 'saved'}})
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
    tools, _ = await subject.g['get_machine_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': 'saved'}})
    subject.g['has_connection_access'].return_value = False
    with pytest.raises(RuntimeError, match='Access denied'):
        await tools[name]['callable'](*args)
    subject.g['execute_tool_server'].assert_not_awaited()
    subject.g['persist_terminal_file_to_platform'].assert_not_awaited()
    subject.g['transfer_platform_file_to_terminal'].assert_not_awaited()
    subject.gateway.build_terminal_tool_gateway_seed_headers.assert_awaited_once()


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
    assert headers == ({'Authorization': 'Bearer configured-schema-key'} if auth_type in ('bearer', 'session') else {})
    assert 'browser-cookie-private' not in repr(subject.fetch.await_args)
    assert 'caller-session-private' not in repr(subject.fetch.await_args)
    assert 'caller-oauth-private' not in repr(subject.fetch.await_args)


@pytest.mark.asyncio
async def test_tether_connection_bypasses_discovery_cache(monkeypatch):
    subject = _load(monkeypatch)
    connection = _connection('tether:dev', url='tether://dev', owner_id='u', auth_type='none')
    subject.config.get.return_value = [connection]
    subject.g['get_tool_server_data'].return_value = _openapi()
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={})
    tools, _ = await subject.g['get_machine_tools'](request, 'tether:dev', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': 'saved'}})
    assert 'run_command' in tools
    subject.g['get_tool_server_data'].assert_awaited_once_with('tether://dev/openapi.json', {'X-User-Id': 'u'}, service='open_terminal')
    assert subject.cache.calls == [] and subject.fetch.await_count == 0


@pytest.mark.asyncio
async def test_session_auth_rotation_is_read_when_the_tool_is_invoked(monkeypatch):
    subject = _load(monkeypatch)
    connection = _connection(auth_type='session')
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='session-one')))
    tools, _ = await subject.g['get_machine_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': 'saved'}})
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
    subject.g['get_machine_system_prompt'].side_effect = [asyncio.TimeoutError(), None]
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='s')))
    tools, prompt = await subject.g['get_machine_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': 'saved'}})
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
    subject.g['get_machine_system_prompt'].side_effect = ['cached prompt', 'new prompt']
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
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None, MACHINES=[{'id': 'stale'}])))
    assert await subject.g['get_machine_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {}) == {}
    assert await subject.g['get_machines'](request) == []
    assert await subject.g['set_machines'](request) == []
    assert request.app.state.MACHINES == []
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
    subject.g['get_machine_cwd'].return_value = '/workspace'
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={})
    tools, _ = await subject.g['get_machine_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {})
    assert tools['run_command']['user_shell_tools'] == 'always'
    assert ('/workspace' in tools['run_command']['spec'].get('description', '')) is cwd_enabled
    assert subject.g['get_machine_cwd'].await_count == int(cwd_enabled)
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
    tools, _ = await subject.g['get_machine_tools'](request, 'terminal-a', SimpleNamespace(id='u'), {})
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
@pytest.mark.parametrize('extra, expected', [({}, 10), ({'template_id': 'tpl'}, 60.0)], ids=['direct', 'template-floor'])
async def test_template_cold_start_gets_floor_direct_keeps_configured(monkeypatch, extra, expected):
    subject = _load(monkeypatch)
    connection = _connection(**extra)
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)))
    await subject.g['_discover_terminal_server'](request, connection)
    assert subject.cache.calls[0][3]['timeout'] == expected
    assert subject.fetch.await_args.kwargs['timeout'] == expected


@pytest.mark.asyncio
async def test_configured_timeout_above_floor_is_preserved(monkeypatch):
    subject = _load(monkeypatch)
    subject.g['AIOHTTP_CLIENT_TIMEOUT_TOOL_SERVER_DATA'] = 120
    connection = _connection(template_id='tpl')
    subject.config.get.return_value = [connection]
    subject.fetch.return_value = Result(_openapi())
    await subject.g['_discover_terminal_server'](SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None))), connection)
    assert subject.cache.calls[0][3]['timeout'] == 120


def _tool_request():
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None)), cookies={}, state=SimpleNamespace(token=SimpleNamespace(credentials='s')))


@pytest.mark.asyncio
@pytest.mark.parametrize('case', ['disabled', 'no-access', 'duplicate', 'chat-denied', 'missing'])
async def test_authorization_failures_happen_before_discovery_or_gateway(monkeypatch, case):
    subject = _load(monkeypatch)
    connection = _connection()
    subject.config.get.return_value = [connection]
    if case == 'disabled':
        subject.config.get.return_value = [_connection(enabled=False)]
    elif case == 'no-access':
        subject.g['has_connection_access'].return_value = False
    elif case == 'duplicate':
        subject.config.get.return_value = [connection, copy.deepcopy(connection)]
    elif case == 'chat-denied':
        # e.g. fork item 25: a foreign saved chat is rejected by find_machine_connection itself.
        subject.find.side_effect = HTTPException(403, 'Chat access denied')
    else:
        subject.config.get.return_value = []
    with pytest.raises((RuntimeError, HTTPException)):
        await subject.g['get_machine_tools'](_tool_request(), 'terminal-a', SimpleNamespace(id='user-a'), {'__metadata__': {'chat_id': 'chat'}})
    assert subject.find.await_args.args[1] == 'terminal-a'
    assert subject.find.await_args.args[2]['chat_id'] == 'chat'
    assert not subject.cache.calls
    subject.fetch.assert_not_awaited()
    subject.g['get_machine_cwd'].assert_not_awaited()
    subject.gateway.build_terminal_tool_gateway_seed_headers.assert_not_awaited()


@pytest.mark.asyncio
async def test_template_connection_discovers_directly_with_floor_and_trusted_headers(monkeypatch):
    subject = _load(monkeypatch)
    template = _connection('template:conn:tpl', template_id='tpl', _headers={'X-Terminal-Template-Id': 'tpl', 'X-User-Id': 'user-a'})
    subject.config.get.return_value = []
    subject.find.side_effect = None
    subject.find.return_value = template
    subject.fetch.return_value = Result(_openapi())
    metadata = {'chat_id': 'saved'}
    tools, _ = await subject.g['get_machine_tools'](_tool_request(), 'template:conn:tpl', SimpleNamespace(id='user-a'), {'__metadata__': metadata})
    # Not cached/fingerprinted: a template instance is per user, so it is fetched live.
    assert not subject.cache.calls
    fetch = subject.fetch.await_args
    assert fetch.args == ('https://orchestrator.example/openapi.json', {'Authorization': 'Bearer discovery-secret', 'X-Terminal-Template-Id': 'tpl', 'X-User-Id': 'user-a'})
    assert fetch.kwargs['timeout'] == 60.0
    metadata['chat_id'] = 'temporary:redirect'
    await tools['run_command']['callable']()
    call = subject.g['execute_tool_server'].await_args.kwargs
    assert call['headers']['X-Terminal-Template-Id'] == 'tpl'
    assert call['headers']['X-Session-Id'] == 'saved'
    # Every call re-authorizes with the metadata pinned when the tools were built.
    assert subject.find.await_args.args[2] == {'chat_id': 'saved'}
    assert subject.find.await_count >= 2


@pytest.mark.asyncio
@pytest.mark.parametrize('revocation', ['gone', 'disabled', 'chat-denied', 'store-error'])
async def test_every_operation_reauthorizes_through_find_before_gateway(monkeypatch, revocation):
    subject = _load(monkeypatch)
    subject.config.get.return_value = [_connection()]
    subject.fetch.return_value = Result(_openapi())
    tools, _ = await subject.g['get_machine_tools'](_tool_request(), 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': 'saved'}})
    subject.find.side_effect = {
        'gone': AsyncMock(return_value=None),
        'disabled': AsyncMock(return_value=_connection(enabled=False)),
        'chat-denied': HTTPException(403, 'Chat access denied'),
        'store-error': RuntimeError('private store detail'),
    }[revocation]
    subject.gateway.build_terminal_tool_gateway_seed_headers.reset_mock()
    for name, args in [('run_command', ()), ('persist_file_to_chat', ('/x',)), ('transfer_file_to_terminal', ('f', '/x'))]:
        with pytest.raises((RuntimeError, HTTPException)):
            await tools[name]['callable'](*args)
    subject.gateway.build_terminal_tool_gateway_seed_headers.assert_not_awaited()
    subject.g['execute_tool_server'].assert_not_awaited()
    subject.g['persist_terminal_file_to_platform'].assert_not_awaited()
    subject.g['transfer_platform_file_to_terminal'].assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('chat_id', ['', 'temporary:x', 'local:x', 'channel:x'])
async def test_non_saved_chat_ids_still_track_the_session(monkeypatch, chat_id):
    subject = _load(monkeypatch)
    subject.config.get.return_value = [_connection()]
    subject.fetch.return_value = Result(_openapi())
    tools, _ = await subject.g['get_machine_tools'](_tool_request(), 'terminal-a', SimpleNamespace(id='u'), {'__metadata__': {'chat_id': chat_id}})
    await tools['run_command']['callable']()
    assert subject.g['execute_tool_server'].await_args.kwargs['headers'].get('X-Session-Id', '') == chat_id

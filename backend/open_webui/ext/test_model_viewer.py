import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from open_webui.ext import model_viewer as mv

USER = SimpleNamespace(id='u1', role='user')
TOOL = {'tool_id': 'server:forma', 'type': 'external'}
OPEN = {
    'data': {
        'model_viewer': {
            'project_id': 'b.p',
            'version_ids': ['urn:v?version=1', 'urn:p?version=2'],
            'models': [{'version_id': 'urn:v?version=1', 'urn': 'dXJu'}],
            'region': 'US',
            'name': 'Tower',
        }
    }
}


@pytest.mark.parametrize(
    'tool, expected',
    [
        ({'tool_id': 'server:forma', 'type': 'external'}, 'forma'),
        ({'tool_id': 'server:openapi:forma|a,b', 'type': 'external'}, 'forma'),
        ({'tool_id': 'server:mcp:forma', 'type': 'mcp'}, None),
        ({'tool_id': 'server:tether:forma', 'type': 'external'}, None),
        ({'tool_id': 'terminal:x', 'type': 'terminal'}, None),
        (None, None),
    ],
)
def test_server_id_from_tool(tool, expected):
    assert mv.server_id_from_tool(tool) == expected


async def _events(result, tool=TOOL):
    events = []

    async def emit(event):
        events.append(event)

    await mv.model_viewer_event(result, tool, emit)
    return events


@pytest.mark.asyncio
async def test_open_and_command_events_carry_identifiers_only():
    [opened] = await _events(json.dumps(OPEN))
    assert opened == {
        'type': 'model_viewer:open',
        'data': {
            'serverId': 'forma',
            'projectId': 'b.p',
            'versionIds': ['urn:v?version=1', 'urn:p?version=2'],
            'region': 'US',
            'name': 'Tower',
        },
    }
    [command] = await _events(json.dumps({'data': {'model_viewer_command': {'action': 'isolate', 'db_ids': [1]}}}))
    assert command == {'type': 'model_viewer:command', 'data': {'action': 'isolate', 'db_ids': [1]}}


@pytest.mark.asyncio
@pytest.mark.parametrize('result', ['not json', json.dumps({'data': {'items': []}}), json.dumps([1]), None])
async def test_other_results_emit_nothing(result):
    assert await _events(result) == []


@pytest.mark.asyncio
async def test_non_server_tools_emit_nothing():
    assert await _events(json.dumps(OPEN), {'tool_id': 'builtin:x'}) == []


class FakeResponse:
    def __init__(self, status, body):
        self.status, self.content = status, SimpleNamespace(read=self._read)
        self._body = body if isinstance(body, bytes) else json.dumps(body).encode()

    async def _read(self, n):
        return self._body[:n]

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class FakeSession:
    calls = []
    reply = (200, {})

    def __init__(self, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def post(self, url, **kwargs):
        FakeSession.calls.append((url, kwargs))
        return FakeResponse(*FakeSession.reply)


@pytest.fixture
def wired(monkeypatch):
    connection = {'url': 'http://forma:8000', 'headers': {'x-sobe-proxy-secret': 's'}}
    access = {'ok': True}

    async def servers(request):
        return [{'id': 'forma', 'idx': 0, 'url': 'http://forma:8000'}]

    async def config_get(key, default=None):
        return [connection]

    async def groups(user_id, include_inherited=True):
        return []

    async def has_access(user, conn, group_ids):
        return access['ok']

    async def headers(conn, request, user, server_id=''):
        return {'x-sobe-proxy-secret': 's', 'x-open-webui-user-id': user.id}, {}

    monkeypatch.setattr(mv, 'get_tool_servers', servers)
    monkeypatch.setattr(mv.Config, 'get', config_get)
    monkeypatch.setattr(mv.Groups, 'get_groups_by_member_id', groups)
    monkeypatch.setattr(mv, 'has_connection_access', has_access)
    monkeypatch.setattr(mv, 'build_tool_server_headers', headers)
    monkeypatch.setattr(mv.aiohttp, 'ClientSession', FakeSession)
    FakeSession.calls = []
    return access


def _form(**changes):
    return mv.TokenForm(**{'server_id': 'forma', 'project_id': 'b.p', 'version_ids': ['urn:v?version=1'], **changes})


@pytest.mark.asyncio
async def test_token_uses_connection_headers_and_is_not_cached(wired):
    FakeSession.reply = (
        200,
        {'access_token': 'narrow', 'expires_in': 3599, 'models': [{'version_id': 'v', 'urn': 'dXJu'}]},
    )
    response = await mv.viewer_token(SimpleNamespace(), _form(), user=USER)
    assert response.headers['cache-control'] == 'no-store'
    assert json.loads(response.body)['access_token'] == 'narrow'
    url, kwargs = FakeSession.calls[0]
    assert url == 'http://forma:8000/viewer/token' and kwargs['allow_redirects'] is False
    assert kwargs['json'] == {'project_id': 'b.p', 'version_ids': ['urn:v?version=1']}
    assert kwargs['headers']['x-open-webui-user-id'] == 'u1'


@pytest.mark.asyncio
async def test_token_refuses_unknown_or_forbidden_server(wired):
    with pytest.raises(HTTPException) as unknown:
        await mv.viewer_token(SimpleNamespace(), _form(server_id='other'), user=USER)
    wired['ok'] = False
    with pytest.raises(HTTPException) as forbidden:
        await mv.viewer_token(SimpleNamespace(), _form(), user=USER)
    assert unknown.value.status_code == forbidden.value.status_code == 404
    assert FakeSession.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'reply, status',
    [
        ((403, {'detail': 'sign in'}), 403),
        ((500, b'boom'), 502),
        ((200, {'urn': 'x'}), 502),
        ((200, {'access_token': 't', 'models': []}), 502),
        ((200, b'x' * 300_000), 502),
    ],
)
async def test_token_upstream_failures(wired, reply, status):
    FakeSession.reply = reply
    with pytest.raises(HTTPException) as error:
        await mv.viewer_token(SimpleNamespace(), _form(), user=USER)
    assert error.value.status_code == status


@pytest.mark.parametrize(
    'changes', [{'url': 'http://evil'}, {'version_ids': []}, {'version_ids': ['v'] * 6}, {'version_ids': ['']}]
)
def test_form_rejects_bad_requests(changes):
    with pytest.raises(ValueError):
        _form(**changes)


def _layout(tab):
    return {
        'schemaVersion': 1,
        'selectedTerminalId': None,
        'panels': {
            'tabs': [tab],
            'activeId': tab['id'],
            'history': [],
            'groups': [{'id': 'default', 'tabIds': [tab['id']], 'activeId': tab['id']}],
            'activeGroupId': 'default',
            'layout': {'type': 'group', 'groupId': 'default'},
        },
    }


def test_chat_layout_saves_model_viewer_tab_with_identifiers_only():
    from pydantic import ValidationError

    from open_webui.models.chat_views import ChatViewData

    ref = {'serverId': '0', 'projectId': 'b.p', 'versionIds': ['urn:v?version=1'], 'region': 'US', 'name': 'Tower'}
    tab = {'id': 'model-viewer:0:urn:v?version=1', 'kind': 'model-viewer', 'label': 'Tower', 'modelViewer': ref}
    assert ChatViewData.model_validate(_layout(tab)).panels.tabs[0].modelViewer.versionIds == ['urn:v?version=1']
    for bad in ({**ref, 'access_token': 'leak'}, {**ref, 'versionIds': []}, {**ref, 'versionIds': ['v'] * 6}):
        with pytest.raises(ValidationError):
            ChatViewData.model_validate(_layout({**tab, 'modelViewer': bad}))

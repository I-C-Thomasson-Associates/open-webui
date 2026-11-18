"""Persist/transfer tools reach Tether terminals through the user's relay, not plain HTTP."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from open_webui.ext import terminal_persist_tool as tool


class Response:
    """Mimics a Tether RelayResponse: no ``content_length`` attribute."""

    def __init__(self, status, body=b'', headers=None, data=None):
        self.status, self.body, self.headers, self.data = status, body, headers or {}, data or {}
        self.content = self

    async def iter_chunked(self, size):
        yield self.body

    async def text(self):
        return self.body.decode()

    async def json(self, **_):
        return self.data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False


class Client:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    def get(self, url, **kwargs):
        self.calls.append(('GET', url, kwargs))
        return self.responses.pop(0)

    def post(self, url, **kwargs):
        self.calls.append(('POST', url, kwargs))
        return self.responses.pop(0)


@pytest.fixture
def relay(monkeypatch):
    opened = []

    def client(url, user_id=None, service='open_terminal', **kwargs):
        opened.append((url, user_id, service))
        return state['client']

    state = {'opened': opened}
    monkeypatch.setattr(tool, 'get_terminal_client', client)
    monkeypatch.setattr(tool, '_get_terminal_file_max_bytes', AsyncMock(return_value=1024))
    return state


@pytest.mark.asyncio
async def test_persist_reads_a_tether_file_through_the_relay(relay, monkeypatch):
    relay['client'] = Client([Response(404), Response(200, b'hello', {'Content-Type': 'text/plain'})])
    upload = AsyncMock(return_value=SimpleNamespace(id='f1', filename='a.txt'))
    monkeypatch.setattr(tool, 'upload_file_handler', upload)

    result = await tool.persist_terminal_file_to_platform(
        request=None,
        user=SimpleNamespace(id='u1'),
        base_url='tether://device',
        headers={'X-User-Id': 'u1'},
        cookies={},
        path='/home/a.txt',
        service='tether-terminal',
    )

    assert relay['opened'] == [('tether://device', 'u1', 'tether-terminal')]
    assert [call[1] for call in relay['client'].calls] == [
        'tether://device/files/list?directory=%2Fhome%2Fa.txt',
        'tether://device/files/view?path=%2Fhome%2Fa.txt',
    ]
    assert result['file_id'] == 'f1'
    assert upload.await_args.kwargs['file'].file.read() == b'hello'


@pytest.mark.asyncio
async def test_persist_still_enforces_the_size_limit_without_content_length(relay):
    relay['client'] = Client([Response(404), Response(200, b'x' * 2048)])
    with pytest.raises(HTTPException) as exc:
        await tool.persist_terminal_file_to_platform(
            request=None, user=SimpleNamespace(id='u1'), base_url='tether://device', headers={}, cookies={}, path='/a'
        )
    assert exc.value.status_code == 413


@pytest.mark.asyncio
async def test_transfer_uploads_to_a_tether_terminal_as_its_instance_user(relay, monkeypatch):
    relay['client'] = Client([Response(200, data={'path': '/home/b.txt'})])
    source = SimpleNamespace(user_id='u1', filename='b.txt', meta={}, path=None, data={'content': 'hi'})
    monkeypatch.setattr(tool.Files, 'get_file_by_id', AsyncMock(return_value=source))

    result = await tool.transfer_platform_file_to_terminal(
        request=None,
        user=SimpleNamespace(id='u1', role='user'),
        base_url='tether://device',
        headers={'Content-Type': 'application/json', 'X-User-Id': 'u1'},
        cookies={},
        file_id='f1',
        path='/home/',
        instance_user_id='owner',
    )

    assert relay['opened'] == [('tether://device', 'owner', 'open_terminal')]
    method, url, kwargs = relay['client'].calls[0]
    assert (method, url) == ('POST', 'tether://device/files/upload?directory=%2Fhome')
    assert 'Content-Type' not in kwargs['headers']
    assert result['path'] == '/home/b.txt'

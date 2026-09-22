from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request

from open_webui.ext import terminal_upload_proxy


class _ResponseContent:
    async def iter_any(self):
        yield b'redirect '
        yield b'body'


class _UpstreamResponse:
    def __init__(self):
        self.status = 307
        self.headers = {'location': 'https://unexpected.example/upload', 'content-length': '13'}
        self.content = _ResponseContent()
        self.release_calls = 0

    def release(self):
        self.release_calls += 1


class _Session:
    def __init__(self, response):
        self.request = AsyncMock(return_value=response)
        self.close = AsyncMock()


def _request():
    return Request(
        {
            'type': 'http',
            'method': 'POST',
            'path': '/api/v1/terminals/terminal-id/files/upload-stream',
            'headers': [],
            'query_string': b'',
            'scheme': 'http',
            'server': ('testserver', 80),
            'client': ('testclient', 50000),
        }
    )


@pytest.mark.asyncio
@pytest.mark.parametrize('consume_all', [True, False])
async def test_terminal_upload_proxy_returns_redirect_without_following_and_cleans_up(monkeypatch, consume_all):
    upstream_response = _UpstreamResponse()
    session = _Session(upstream_response)
    monkeypatch.setattr(terminal_upload_proxy.aiohttp, 'ClientSession', lambda **kwargs: session)

    response = await terminal_upload_proxy.proxy_terminal_upload(
        _request(),
        'https://terminal.example/files/upload-stream',
        {'X-User-Id': 'user-id'},
        {},
    )

    assert response.status_code == 307
    assert response.headers['location'] == 'https://unexpected.example/upload'
    assert session.request.await_count == 1
    assert session.request.await_args.kwargs['allow_redirects'] is False

    if consume_all:
        assert [chunk async for chunk in response.body_iterator] == [b'redirect ', b'body']
    else:
        iterator = response.body_iterator
        assert await anext(iterator) == b'redirect '
        await iterator.aclose()
    assert upstream_response.release_calls == 1
    session.close.assert_awaited_once()

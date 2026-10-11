import asyncio
import importlib
import sys
import types

import pytest

from open_webui.ext import realtime_provider_config as cfg
from open_webui.ext.realtime_providers import connect_upstream


class FakeSession:
    def __init__(self):
        self.calls = []

    async def ws_connect(self, url, **kw):
        self.calls.append((url, kw))
        return 'ws'


def run(engine, base, session=None, key='k', model='m'):
    session = session or FakeSession()
    out = asyncio.run(
        connect_upstream(engine, session, base, key, model, ssl='SSL', heartbeat=20, max_msg_size=9)
    )
    return out, session


def test_openai_unchanged():
    out, s = run('openai', 'https://api.openai.com/v1/', model='gpt rt')
    url, kw = s.calls[0]
    assert out == 'ws'
    assert url == 'wss://api.openai.com/v1/realtime?model=gpt+rt'
    assert kw == {'headers': {'Authorization': 'Bearer k'}, 'ssl': 'SSL', 'heartbeat': 20, 'max_msg_size': 9}


def test_azure_ga_headers_and_url():
    _, s = run('azure', 'https://r.openai.azure.com/openai/v1', model='dep')
    url, kw = s.calls[0]
    assert url == 'wss://r.openai.azure.com/openai/v1/realtime?model=dep'
    assert kw['headers'] == {'api-key': 'k'}
    assert kw['ssl'] == 'SSL'
    assert 'api-version' not in url


@pytest.mark.parametrize(
    'engine,base',
    [
        ('azure', 'http://r.openai.azure.com/openai/v1'),
        ('azure', 'https://r.openai.azure.com/openai'),
        ('azure', 'https://api.openai.com/openai/v1'),
        ('azure', 'https://openrouter.ai/openai/v1'),
        ('openai', 'https://openrouter.ai/api/v1'),
        ('openrouter', 'https://api.openai.com/v1'),
        ('openai', 'https://u:p@h.example/v1'),
        ('openai', 'https://h.example/v1?x=1'),
        ('openai', 'https://h.example/v1#f'),
        ('openai', 'ftp://h.example/v1'),
        ('openai', 'https://h.example:bad/v1'),
        ('bogus', 'https://h.example/v1'),
    ],
)
def test_rejected(engine, base):
    s = FakeSession()
    with pytest.raises(ValueError):
        run(engine, base, s)
    assert not s.calls


def test_openrouter_lazy_adapter(monkeypatch):
    class Adapter:
        def __init__(self, **kw):
            self.kw = kw

    mod = types.ModuleType('open_webui.ext.realtime_openrouter')
    mod.OpenRouterRealtimeAdapter = Adapter
    monkeypatch.setitem(sys.modules, 'open_webui.ext.realtime_openrouter', mod)
    out, s = run('openrouter', 'https://openrouter.ai/api/v1')
    assert out.kw == {
        'session': s,
        'base_url': 'https://openrouter.ai/api/v1',
        'key': 'k',
        'model': 'm',
        'ssl': 'SSL',
    }
    assert not s.calls


def test_engine_default_and_env(monkeypatch):
    assert cfg.REALTIME_CONFIG_DEFAULTS['audio.realtime.engine'] in cfg.REALTIME_ENGINES
    monkeypatch.setenv('AUDIO_REALTIME_ENGINE', 'azure')
    assert importlib.reload(cfg).REALTIME_CONFIG_DEFAULTS == {'audio.realtime.engine': 'azure'}
    monkeypatch.setenv('AUDIO_REALTIME_ENGINE', 'junk')
    assert importlib.reload(cfg).AUDIO_REALTIME_ENGINE == 'openai'
    monkeypatch.delenv('AUDIO_REALTIME_ENGINE')
    importlib.reload(cfg)

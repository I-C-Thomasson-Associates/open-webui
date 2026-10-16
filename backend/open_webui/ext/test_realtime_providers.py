"""Offline contract tests; extract native helper without importing app/config assets."""

import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode, urlunsplit

import pytest

from open_webui.ext import realtime_provider_config as cfg
from open_webui.ext.realtime_providers import connect_openrouter, validate_base_url


def native_connection(config, token=lambda: 'TOKEN'):
    path = Path(__file__).resolve().parents[1] / 'routers/audio/realtime.py'
    tree = ast.parse(path.read_text(encoding='utf-8'))
    node = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == '_get_realtime_connection')
    scope = {
        'asyncio': asyncio, 'validate_base_url': validate_base_url,
        'urlunsplit': urlunsplit, 'urlencode': urlencode,
        'get_microsoft_entra_id_access_token': token,
    }
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), scope)
    return asyncio.run(scope['_get_realtime_connection'](config))


def settings(provider='openai', auth='api_key', base='https://example.invalid/v1'):
    return {
        'audio.realtime.provider': provider,
        'audio.realtime.auth_type': auth,
        'audio.realtime.openai.api_base_url': base,
        'audio.realtime.openai.api_key': 'KEY',
        'audio.realtime.model': 'gpt rt',
    }


@pytest.mark.parametrize('provider,auth,headers', [
    ('openai', 'api_key', {'Authorization': 'Bearer KEY'}),
    ('azure', 'api_key', {'api-key': 'KEY'}),
    ('azure', 'microsoft_entra_id', {'Authorization': 'Bearer TOKEN'}),
])
def test_native_upstream_auth(provider, auth, headers):
    data = settings(provider, auth)
    if auth == 'microsoft_entra_id':
        data.pop('audio.realtime.openai.api_key')
    url, actual = native_connection(data)
    assert url == 'wss://example.invalid/v1/realtime?model=gpt+rt'
    assert actual == headers


@pytest.mark.parametrize('provider,auth', [('openai', 'microsoft_entra_id'), ('azure', 'bad'), ('bad', 'api_key')])
def test_native_invalid_auth(provider, auth):
    with pytest.raises(ValueError):
        native_connection(settings(provider, auth))


@pytest.mark.parametrize('token', [lambda: '', lambda: (_ for _ in ()).throw(RuntimeError('SECRET'))])
def test_entra_failure_is_sanitized(token):
    with pytest.raises(ValueError, match='Unable to obtain a Microsoft Entra ID token') as error:
        native_connection(settings('azure', 'microsoft_entra_id'), token)
    assert 'SECRET' not in str(error.value)


@pytest.mark.parametrize('provider,base', [
    ('azure', 'https://openrouter.ai/api/v1'),
    ('openai', 'https://openrouter.ai/api/v1'),
    ('openrouter', 'https://api.openai.com/v1'),
    ('openai', 'https://u:p@h.example/v1'),
    ('openai', 'https://h.example/v1?x=1'),
    ('openai', 'https://h.example/v1#f'),
    ('openai', 'ftp://h.example/v1'),
    ('openai', 'https://h.example:bad/v1'),
])
def test_rejected_url(provider, base):
    with pytest.raises(ValueError):
        validate_base_url(provider, base)


def test_openrouter_lazy_adapter(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, 'open_webui.ext.realtime_openrouter', SimpleNamespace(
        OpenRouterRealtimeAdapter=lambda **kwargs: kwargs,
    ))
    session = object()
    out = connect_openrouter(settings('openrouter'), session, ssl='SSL')
    assert out == {'session': session, 'base_url': 'https://example.invalid/v1', 'key': 'KEY', 'model': 'gpt rt', 'ssl': 'SSL'}
    with pytest.raises(ValueError, match='API key authentication'):
        connect_openrouter(settings('openrouter', 'microsoft_entra_id'), session, ssl='SSL')
    data = settings('openrouter')
    data['audio.realtime.openai.api_key'] = ''
    with pytest.raises(ValueError, match='Configure'):
        connect_openrouter(data, session, ssl='SSL')


def test_env_precedence(monkeypatch):
    monkeypatch.delenv('AUDIO_REALTIME_PROVIDER', raising=False)
    monkeypatch.setenv('AUDIO_REALTIME_ENGINE', 'azure')
    assert cfg.provider_from_env() == 'azure'
    monkeypatch.setenv('AUDIO_REALTIME_ENGINE', 'openrouter')
    assert cfg.provider_from_env() == 'openrouter'
    monkeypatch.setenv('AUDIO_REALTIME_PROVIDER', 'openai')
    assert cfg.provider_from_env() == 'openai'
    monkeypatch.setenv('AUDIO_REALTIME_PROVIDER', '')
    assert cfg.provider_from_env() == ''


@pytest.mark.parametrize('legacy', ['azure', 'openrouter'])
def test_legacy_payload(legacy):
    assert cfg.migrate_legacy_fields({'ENGINE': legacy, 'MODEL': 'custom', 'OPENAI_API_KEY': 'key'}) == {
        'PROVIDER': legacy, 'MODEL': 'custom', 'OPENAI_API_KEY': 'key',
    }
    assert cfg.migrate_legacy_fields({'ENGINE': legacy, 'PROVIDER': 'openai'}) == {'PROVIDER': 'openai'}


def test_realtime_form_preserves_partial_update_fields():
    from pydantic import BaseModel, Field, model_validator
    from typing import Literal, Optional

    path = Path(__file__).resolve().parents[1] / 'routers/audio/__init__.py'
    tree = ast.parse(path.read_text(encoding='utf-8'))
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'RealtimeConfigForm')
    scope = {
        'BaseModel': BaseModel, 'Field': Field, 'model_validator': model_validator,
        'Literal': Literal, 'Optional': Optional, 'RealtimeProvider': cfg.RealtimeProvider,
        'migrate_legacy_fields': cfg.migrate_legacy_fields,
    }
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), scope)
    form = scope['RealtimeConfigForm']
    assert form.model_validate({'ENGINE': 'azure'}).model_dump(exclude_unset=True) == {'PROVIDER': 'azure'}
    assert form.model_validate({'ENGINE': 'azure', 'PROVIDER': 'openrouter'}).PROVIDER == 'openrouter'
    assert form.model_validate({'INPUT_PARAMS': {'noise_reduction': {'type': 'near_field'}}}).model_dump(exclude_unset=True) == {
        'INPUT_PARAMS': {'noise_reduction': {'type': 'near_field'}},
    }


def test_partial_switch_does_not_reuse_key_or_entra():
    assert cfg.safe_provider_updates({'PROVIDER': 'openrouter'}, {'PROVIDER': 'azure'}) == {
        'PROVIDER': 'openrouter', 'OPENAI_API_KEY': '', 'AUTH_TYPE': 'api_key',
    }
    assert cfg.safe_provider_updates({'MODEL': 'custom'}, {'PROVIDER': 'azure'}) == {'MODEL': 'custom'}
    assert cfg.safe_provider_updates({'PROVIDER': 'openrouter', 'OPENAI_API_KEY': 'new'}, {'PROVIDER': 'azure'})['OPENAI_API_KEY'] == 'new'


@pytest.mark.parametrize('legacy', ['azure', 'openrouter'])
@pytest.mark.parametrize('explicit', [False, True])
def test_persisted_migration_before_seeding(monkeypatch, legacy, explicit):
    monkeypatch.delenv('AUDIO_REALTIME_PROVIDER', raising=False)
    values = {'audio.realtime.engine': legacy, 'audio.realtime.model': 'custom', 'audio.realtime.openai.api_key': 'key'}
    if explicit:
        values['audio.realtime.provider'] = 'openai'
    calls = []

    async def namespace(name):
        assert name == 'audio.realtime'
        return dict(values)

    async def upsert(updates):
        calls.append(updates)
        values.update(updates)

    config = SimpleNamespace(get_namespace=namespace, upsert=upsert)
    asyncio.run(cfg.migrate_legacy_provider(config))
    asyncio.run(cfg.migrate_legacy_provider(config))
    assert calls == ([] if explicit else [{'audio.realtime.provider': legacy}])
    assert values['audio.realtime.model'] == 'custom'
    assert values['audio.realtime.openai.api_key'] == 'key'


def test_explicit_provider_env_blocks_persisted_migration(monkeypatch):
    monkeypatch.setenv('AUDIO_REALTIME_PROVIDER', 'azure')

    async def namespace(name):
        return {'audio.realtime.engine': 'openrouter'}

    async def unexpected(updates):
        pytest.fail('Explicit provider must not be overridden')

    asyncio.run(cfg.migrate_legacy_provider(SimpleNamespace(get_namespace=namespace, upsert=unexpected)))

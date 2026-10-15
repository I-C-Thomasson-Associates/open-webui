"""Compatibility for the fork's legacy realtime ENGINE setting."""

import os
from typing import Literal

RealtimeProvider = Literal['openai', 'azure', 'openrouter']
REALTIME_PROVIDERS = ('openai', 'azure', 'openrouter')


def provider_from_env() -> str:
    # Presence, not truthiness: an explicit new setting must never be overridden.
    if 'AUDIO_REALTIME_PROVIDER' in os.environ:
        return os.environ['AUDIO_REALTIME_PROVIDER']
    legacy = os.getenv('AUDIO_REALTIME_ENGINE', 'openai').strip().lower()
    return legacy if legacy in REALTIME_PROVIDERS else 'openai'


def migrate_legacy_fields(data: dict) -> dict:
    """Translate old admin payloads without resetting credentials or custom fields."""
    result = dict(data)
    legacy = result.pop('ENGINE', None)
    if 'PROVIDER' not in result and legacy in REALTIME_PROVIDERS:
        result['PROVIDER'] = legacy
    return result


def safe_provider_updates(data: dict, current: dict) -> dict:
    """A partial provider switch cannot silently reuse the previous provider's key."""
    result = migrate_legacy_fields(data)
    if 'PROVIDER' in result and result['PROVIDER'] != current.get('PROVIDER', 'openai'):
        result.setdefault('OPENAI_API_KEY', '')
        result.setdefault('AUTH_TYPE', 'api_key')
    return result


async def migrate_legacy_provider(config) -> None:
    """Run before default seeding, while persisted-key presence is still observable."""
    values = await config.get_namespace('audio.realtime')
    if 'audio.realtime.provider' in values or 'AUDIO_REALTIME_PROVIDER' in os.environ:
        return
    legacy = values.get('audio.realtime.engine')
    if legacy in REALTIME_PROVIDERS:
        await config.upsert({'audio.realtime.provider': legacy})

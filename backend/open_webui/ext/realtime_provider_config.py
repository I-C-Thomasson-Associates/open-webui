"""Realtime provider engine config, kept outside core config for easy merging."""

import os
from typing import Literal

REALTIME_ENGINES = ('openai', 'azure', 'openrouter')
RealtimeEngine = Literal['openai', 'azure', 'openrouter']
REALTIME_ENGINE_KEY = 'audio.realtime.engine'


def _env_engine() -> str:
    value = os.getenv('AUDIO_REALTIME_ENGINE', 'openai').strip().lower()
    return value if value in REALTIME_ENGINES else 'openai'


AUDIO_REALTIME_ENGINE = _env_engine()
REALTIME_CONFIG_DEFAULTS = {REALTIME_ENGINE_KEY: AUDIO_REALTIME_ENGINE}

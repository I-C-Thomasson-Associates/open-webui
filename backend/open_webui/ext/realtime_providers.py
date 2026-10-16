"""Authorized upstream connection factory for realtime voice providers."""

from urllib.parse import urlsplit

_OPENAI_HOST = 'api.openai.com'
_OPENROUTER_HOST = 'openrouter.ai'


def _host_is(host: str, domain: str) -> bool:
    return host == domain or host.endswith('.' + domain)


def validate_base_url(engine: str, base_url: str):
    """Return the parsed URL or raise ValueError for an unsafe/mismatched provider URL."""
    try:
        url = urlsplit(base_url or '')
        host = (url.hostname or '').lower()
        url.port  # raises ValueError when malformed
    except ValueError:
        raise ValueError('Invalid Realtime provider URL') from None
    if (
        url.scheme not in {'http', 'https'}
        or not host
        or url.username is not None
        or url.password is not None
        or '@' in url.netloc
        or url.query
        or url.fragment
    ):
        raise ValueError('Invalid Realtime provider URL')
    if engine == 'openrouter' and _host_is(host, _OPENAI_HOST):
        raise ValueError('OpenRouter engine cannot use the OpenAI endpoint')
    if engine in {'openai', 'azure'} and _host_is(host, _OPENROUTER_HOST):
        raise ValueError(f'{engine} engine cannot use the OpenRouter endpoint')
    return url


def connect_openrouter(config, session, *, ssl):
    """Only the turn-based extension; native providers stay in upstream's router."""
    if config.get('audio.realtime.auth_type', 'api_key') != 'api_key':
        raise ValueError('OpenRouter requires API key authentication')
    base_url = config.get('audio.realtime.openai.api_base_url') or ''
    validate_base_url('openrouter', base_url)
    key = config.get('audio.realtime.openai.api_key')
    model = config.get('audio.realtime.model')
    if not key or not model:
        raise ValueError('Configure the Realtime API key and model')
    from open_webui.ext.realtime_openrouter import OpenRouterRealtimeAdapter

    return OpenRouterRealtimeAdapter(session=session, base_url=base_url, key=key, model=model, ssl=ssl)

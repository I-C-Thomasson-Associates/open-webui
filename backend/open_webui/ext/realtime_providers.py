"""Authorized upstream connection factory for realtime voice providers."""

from urllib.parse import urlencode, urlsplit, urlunsplit

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
    if engine == 'azure':
        if url.scheme != 'https' or _host_is(host, _OPENAI_HOST):
            raise ValueError('Azure Realtime requires an https Azure endpoint')
        if not url.path.rstrip('/').endswith('/openai/v1'):
            raise ValueError('Azure Realtime base URL must end with /openai/v1')
    return url


async def connect_upstream(engine, session, base_url, key, model, *, ssl, heartbeat, max_msg_size):
    if engine not in {'openai', 'azure', 'openrouter'}:
        raise ValueError('Unsupported Realtime engine')
    url = validate_base_url(engine, base_url)
    if engine == 'openrouter':
        from open_webui.ext.realtime_openrouter import OpenRouterRealtimeAdapter

        return OpenRouterRealtimeAdapter(session=session, base_url=base_url, key=key, model=model, ssl=ssl)
    ws_url = urlunsplit(
        (
            'wss' if url.scheme == 'https' else 'ws',
            url.netloc,
            url.path.rstrip('/') + '/realtime',
            urlencode({'model': model}),
            '',
        )
    )
    headers = {'api-key': key} if engine == 'azure' else {'Authorization': f'Bearer {key}'}
    return await session.ws_connect(ws_url, headers=headers, ssl=ssl, heartbeat=heartbeat, max_msg_size=max_msg_size)

from __future__ import annotations

from collections.abc import Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

MAX_CALLBACK_BODY_BYTES = 64 * 1024
_SENSITIVE_RESPONSE_HEADERS = frozenset({'set-cookie', 'set-cookie2'})
_CALLBACK_TARGET_URL_SCHEMES = frozenset({'http', 'https'})
_RESERVED_CALLBACK_PATHS = frozenset({'/health', '/ready', '/health/db'})


def strip_sensitive_response_headers(
    headers: Mapping[str, str] | Iterable[tuple[str, str]],
) -> list[tuple[str, str]]:
    if isinstance(headers, Mapping):
        items = headers.items()
    else:
        items = headers

    return [(key, value) for key, value in items if key.lower() not in _SENSITIVE_RESPONSE_HEADERS]


def sanitize_url_for_log(url: str) -> str:
    parsed = urlsplit((url or '').strip())
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', ''))


def is_valid_callback_proxy_config(proxy_dict: dict | None) -> bool:
    if not isinstance(proxy_dict, dict):
        return False

    host = str(proxy_dict.get('host', '')).strip()
    path = str(proxy_dict.get('path', '')).strip()
    url = str(proxy_dict.get('url', '')).strip()

    if not host or not path or not url:
        return False

    if any(character.isspace() for character in host) or any(character in host for character in '/?#@'):
        return False
    parsed_host = urlsplit(f'//{host}')
    if not parsed_host.hostname:
        return False
    try:
        parsed_host.port
    except ValueError:
        return False

    if not path.startswith('/') or path.startswith('//') or any(character in path for character in '?#'):
        return False
    normalized_path = path[:-1] if path != '/' and path.endswith('/') else path
    if normalized_path in _RESERVED_CALLBACK_PATHS or normalized_path.endswith('/watch'):
        return False

    parsed_url = urlsplit(url)
    if parsed_url.scheme not in _CALLBACK_TARGET_URL_SCHEMES or not parsed_url.hostname:
        return False
    if parsed_url.username is not None or parsed_url.password is not None:
        return False
    if parsed_url.fragment:
        return False
    try:
        parsed_url.port
    except ValueError:
        return False

    return True

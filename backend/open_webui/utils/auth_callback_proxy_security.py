from __future__ import annotations

from collections.abc import Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

MAX_CALLBACK_BODY_BYTES = 64 * 1024
_SENSITIVE_RESPONSE_HEADERS = frozenset({'set-cookie', 'set-cookie2'})
_CALLBACK_TARGET_URL_SCHEMES = frozenset({'http', 'https'})


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

    parsed_url = urlsplit(url)
    if parsed_url.scheme not in _CALLBACK_TARGET_URL_SCHEMES or not parsed_url.netloc:
        return False

    return True

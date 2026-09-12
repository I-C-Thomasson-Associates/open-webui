from open_webui.ext.auth_callback_proxy_middleware import filter_hop_by_hop_headers
from open_webui.utils.auth_callback_proxy_security import is_valid_callback_proxy_config


def test_filters_standard_and_connection_nominated_hop_by_hop_headers():
    filtered = filter_hop_by_hop_headers(
        {
            'Connection': 'X-Remove, Keep-Alive',
            'X-Remove': 'yes',
            'Keep-Alive': 'timeout=5',
            'TE': 'trailers',
            'X-Keep': 'ok',
        }
    )
    assert filtered == [('X-Keep', 'ok')]


def test_filters_tokens_from_duplicate_case_insensitive_connection_headers():
    filtered = filter_hop_by_hop_headers([
        ('Connection', 'X-One'), ('cOnNeCtIoN', 'X-Two'),
        ('X-One', 'remove'), ('x-two', 'remove'), ('Set-Cookie', 'one'), ('Set-Cookie', 'two'),
    ])
    assert filtered == [('Set-Cookie', 'one'), ('Set-Cookie', 'two')]


def test_callback_validation_rejects_reserved_paths_and_accepts_normal_path():
    def config(path):
        return {'host': 'example.test', 'path': path, 'url': 'https://target.test/callback'}

    assert not is_valid_callback_proxy_config(config('/health'))
    assert not is_valid_callback_proxy_config(config('/ready'))
    assert not is_valid_callback_proxy_config(config('/health/db'))
    assert not is_valid_callback_proxy_config(config('/legacy/watch'))
    assert is_valid_callback_proxy_config(config('/oauth/callback'))

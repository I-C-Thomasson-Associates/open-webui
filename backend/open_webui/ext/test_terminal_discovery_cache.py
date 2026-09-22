"""Import-safe behavioural coverage for terminal discovery coordination."""
import asyncio
import importlib.util
import json
import sys
from pathlib import Path

import pytest


def _module():
    path = Path(__file__).with_name('terminal_discovery_cache.py')
    spec = importlib.util.spec_from_file_location('terminal_discovery_cache_test_subject', path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _connection(terminal_id='one', **changes):
    value = {'id': terminal_id, 'url': 'https://terminal.example', 'policy_id': terminal_id, 'key': 'secret', 'enabled': True}
    value.update(changes)
    return value


def _data(terminal_id='one', base='https://base', **changes):
    value = {'id': terminal_id, 'url': base, 'openapi': {'paths': {'/x': {}}}, 'specs': [{'name': 'x'}]}
    value.update(changes)
    return value


class FakeRedis:
    """Faithful enough GET/PTTL/SETNX/fenced-EVAL Redis model for these tests."""
    def __init__(self):
        self.now = 0.0
        self.values = {}
        self.fail = set()
        self.hang = set()
        self.calls = []
        self.replace_after_atomic_read = None
        # redis-py 8 defaults to RESP3 (Lua false -> False); RESP2 decodes it as None.
        self.resp2_null_missing_reply = False

    def _get(self, key):
        item = self.values.get(key)
        if item and item[1] <= self.now:
            self.values.pop(key)
            return None
        return item[0] if item else None

    async def _maybe(self, operation):
        if operation in self.hang:
            await asyncio.Event().wait()
        if operation in self.fail:
            raise RuntimeError('redis unavailable')

    async def get(self, key):
        self.calls.append(('get', key))
        await self._maybe('get')
        return self._get(key)

    async def pttl(self, key):
        self.calls.append(('pttl', key))
        await self._maybe('pttl')
        item = self.values.get(key)
        return int((item[1] - self.now) * 1000) if item and self._get(key) is not None else -2

    async def set(self, key, value, nx=False, px=None, ex=None):
        self.calls.append(('set', key, nx, px))
        await self._maybe('set')
        if nx and self._get(key) is not None:
            return False
        self.values[key] = (value, self.now + (px / 1000 if px is not None else ex))
        return True

    async def eval(self, script, keys, *args):
        self.calls.append(('eval', keys, args))
        kind = 'eval_read' if len(args) == 1 else 'eval_publish' if keys == 2 else 'eval_release'
        await self._maybe(kind)
        await self._maybe('eval')
        if kind == 'eval_read':
            key = args[0]
            value = self._get(key)
            item = self.values.get(key)
            ttl = int((item[1] - self.now) * 1000) if item and value is not None else -2
            replacement = self.replace_after_atomic_read
            if replacement is not None:
                self.replace_after_atomic_read = None
                self.values[key] = replacement
            return [value if value is not None else (None if self.resp2_null_missing_reply else False), ttl]
        if keys == 1:
            key, token = args
            if self._get(key) != token:
                return 0
            self.values.pop(key, None)
            return 1
        record_key, lease_key, token, value, ttl = args
        if self._get(lease_key) != token:
            return 0
        self.values[record_key] = (value, self.now + int(ttl) / 1000)
        self.values.pop(lease_key, None)
        return 1


def _cache(subject, redis=None, now=None):
    now = now or [0.0]
    return subject.TerminalDiscoveryCache(prefix='test', redis=redis, clock=lambda: now[0], jitter=lambda: 0), now


@pytest.mark.asyncio
async def test_fingerprint_separates_all_configuration_dimensions_and_invalid_guards():
    subject = _module()
    original = _connection()
    fingerprint = subject.terminal_fingerprint(original, 'https://base/p/a', 'https://base/p/a/openapi.json')
    changes = ({'id': 'two'}, {'url': 'https://other'}, {'policy_id': 'other'}, {'path': '/other'}, {'key': 'other'},
               {'auth_type': 'api_key'}, {'server_type': 'other'}, {'cookies': {'x': 'y'}}, {'forward_cookies': True},
               {'headers': {'x': 'y'}}, {'config': {'contexts': ['x']}}, {'enabled': False})
    for change in changes:
        assert fingerprint != subject.terminal_fingerprint(_connection(**change), 'https://base/p/a', 'https://base/p/a/openapi.json')
    assert fingerprint != subject.terminal_fingerprint(original, 'https://base/p/a', 'https://base/other/openapi.json')
    assert subject.terminal_fingerprint([], 'base', 'spec') is None
    cache, _ = _cache(subject)
    async def no_call():
        raise AssertionError('invalid configuration must not discover')
    assert (await cache.get_or_discover(_connection(enabled=False), 'base', 'spec', no_call)).category == 'invalid_configuration'
    assert (await cache.get_or_discover({'id': 'one'}, '', 'spec', no_call)).category == 'invalid_configuration'


@pytest.mark.asyncio
async def test_two_workers_single_winner_and_separate_ids_share_neither_data_nor_policy():
    subject = _module(); redis = FakeRedis()
    first, _ = _cache(subject, redis); second, _ = _cache(subject, redis)
    calls = []
    async def for_one():
        calls.append('one'); await asyncio.sleep(0); return subject.DiscoveryResult(_data('one'))
    result = await asyncio.gather(*[cache.get_or_discover(_connection('one', policy_id='same'), 'https://base', 'https://spec', for_one) for cache in (first, second)])
    assert len(calls) == 1 and all(item.data['id'] == 'one' for item in result)
    async def for_two():
        calls.append('two'); return subject.DiscoveryResult(_data('two'))
    two = await first.get_or_discover(_connection('two', policy_id='same'), 'https://base', 'https://spec', for_two)
    assert two.data['id'] == 'two' and calls == ['one', 'two']
    async def wrong_id():
        return subject.DiscoveryResult(_data('one'))
    rejected = await first.get_or_discover(_connection('three'), 'https://base', 'https://spec', wrong_id)
    assert rejected.data is None and rejected.category == 'discovery_error'


@pytest.mark.asyncio
@pytest.mark.parametrize('resp2_null_missing_reply', [False, True])
async def test_atomic_read_missing_reply_is_healthy_and_acquires_distributed_lease(resp2_null_missing_reply):
    subject = _module(); redis = FakeRedis(); redis.resp2_null_missing_reply = resp2_null_missing_reply; cache, _ = _cache(subject, redis)
    calls = 0
    async def discover():
        nonlocal calls
        calls += 1
        return subject.DiscoveryResult(_data())
    result = await cache.get_or_discover(_connection(), 'https://base', 'https://spec', discover)
    assert result.data and calls == 1
    assert any(call[0] == 'set' and call[2] is True for call in redis.calls)
    assert any(call[0] == 'eval' and call[1] == 2 for call in redis.calls)


@pytest.mark.asyncio
async def test_shared_negative_uses_redis_ttl_and_next_worker_adopts_attempt_after_cooldown():
    subject = _module(); redis = FakeRedis(); now = [0.0]
    first, _ = _cache(subject, redis, now); second, _ = _cache(subject, redis, now)
    calls = 0
    async def fail():
        nonlocal calls
        calls += 1
        return subject.DiscoveryResult(None, 'timeout')
    assert (await first.get_or_discover(_connection(), 'https://base', 'https://spec', fail)).retry_after == 5
    blocked = await second.get_or_discover(_connection(), 'https://base', 'https://spec', fail)
    assert blocked.category == 'cooldown' and calls == 1
    now[0] = redis.now = 5
    next_result = await second.get_or_discover(_connection(), 'https://base', 'https://spec', fail)
    assert next_result.category == 'timeout' and next_result.retry_after == 10 and calls == 2


@pytest.mark.asyncio
async def test_positive_ttl_is_not_rebased_and_pttl_failures_or_nonexpiring_records_are_misses():
    subject = _module(); redis = FakeRedis(); now = [0.0]; cache, _ = _cache(subject, redis, now)
    connection = _connection(); fingerprint = subject.terminal_fingerprint(connection, 'https://base', 'https://spec')
    key = subject.cache_key('test', 'one', fingerprint)
    redis.values[key] = (json.dumps(cache._record('one', fingerprint, 'https://base', _data())), 1)
    calls = 0
    async def discover():
        nonlocal calls
        calls += 1
        return subject.DiscoveryResult(_data())
    assert (await cache.get_or_discover(connection, 'https://base', 'https://spec', discover)).data
    now[0] = redis.now = 2
    assert (await cache.get_or_discover(connection, 'https://base', 'https://spec', discover)).data and calls == 1
    cache.local.clear(); redis.values[key] = (json.dumps(cache._record('one', fingerprint, 'https://base', _data())), 99)
    redis.fail.add('eval_read')
    assert (await cache.get_or_discover(connection, 'https://base', 'https://spec', discover)).data and calls == 2


@pytest.mark.asyncio
async def test_corrupt_success_and_negative_records_are_not_trusted_or_crashing():
    subject = _module(); redis = FakeRedis(); cache, _ = _cache(subject, redis)
    connection = _connection(); fingerprint = subject.terminal_fingerprint(connection, 'https://base', 'https://spec')
    key = subject.cache_key('test', 'one', fingerprint)
    redis.values[key] = (json.dumps([_data()]), 99)
    redis.values['test:terminal_openapi:legacy-aggregate'] = (json.dumps([_data()]), 99)
    failure_key = key + ':failure'
    redis.values[failure_key] = (json.dumps({'version': subject.CACHE_VERSION, 'kind': 'failure', 'attempt': 'future'}), 99999)
    async def discover(): return subject.DiscoveryResult(_data())
    assert (await cache.get_or_discover(connection, 'https://base', 'https://spec', discover)).data
    assert cache._usable_data(_data(specs=[{'oops': 1}]), 'one', 'https://base') is None
    assert cache._usable_data(_data(url='https://untrusted'), 'one', 'https://base') is None


@pytest.mark.asyncio
async def test_validation_checked_for_local_waiter_and_prepublication_with_mutable_config():
    subject = _module(); cache, _ = _cache(subject); enabled = {'value': True}
    async def validate(): return enabled['value']
    async def discover(): return subject.DiscoveryResult(_data())
    assert (await cache.get_or_discover(_connection(), 'https://base', 'https://spec', discover, validate=validate)).data
    enabled['value'] = False
    assert (await cache.get_or_discover(_connection(), 'https://base', 'https://spec', discover, validate=validate)).category == 'configuration_changed'
    cache.local.clear(); enabled['value'] = False
    assert (await cache.get_or_discover(_connection('two'), 'https://base', 'https://spec', lambda: asyncio.sleep(0, result=subject.DiscoveryResult(_data('two'))), validate=validate)).category == 'configuration_changed'


@pytest.mark.asyncio
async def test_validation_hang_and_discovery_hang_are_bounded_and_do_not_leave_inflight():
    subject = _module(); cache, _ = _cache(subject)
    async def hang(): await asyncio.Event().wait()
    result = await cache.get_or_discover(_connection(), 'https://base', 'https://spec', hang, validate=hang, timeout=.01)
    assert result.category == 'timeout'
    await asyncio.sleep(0)
    assert not cache.inflight
    async def success(): return subject.DiscoveryResult(_data('two'))
    assert (await cache.get_or_discover(_connection('two'), 'https://base', 'https://spec', success)).data
    validation_timeout = await cache.get_or_discover(_connection('two'), 'https://base', 'https://spec', success, validate=hang, timeout=.01)
    assert validation_timeout.category == 'validation_timeout'


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['eval_read', 'set', 'eval_publish'])
async def test_redis_operation_failures_and_hangs_have_bounded_local_fallback(operation):
    subject = _module(); redis = FakeRedis(); redis.hang.add(operation); cache, _ = _cache(subject, redis)
    async def fail(): return subject.DiscoveryResult(None, 'connection')
    result = await cache.get_or_discover(_connection(), 'https://base', 'https://spec', fail, timeout=.01)
    assert result.category in {'connection', 'timeout'}
    if cache.inflight:
        await asyncio.wait_for(asyncio.shield(next(iter(cache.inflight.values()))), 1)
        await asyncio.sleep(0)
    assert not cache.inflight
    assert (await cache.get_or_discover(_connection(), 'https://base', 'https://spec', fail, timeout=.01)).category == 'cooldown'


@pytest.mark.asyncio
async def test_post_lease_read_failure_does_not_publish_and_lease_timeout_scales_with_configured_timeout():
    subject = _module(); redis = FakeRedis(); cache, _ = _cache(subject, redis)
    original_eval = redis.eval; calls = 0
    async def flaky_eval(script, keys, *args):
        nonlocal calls
        if len(args) == 1:
            calls += 1
            if calls >= 3: raise RuntimeError('post lease read down')
        return await original_eval(script, keys, *args)
    redis.eval = flaky_eval
    async def discover(): return subject.DiscoveryResult(_data())
    assert (await cache.get_or_discover(_connection(), 'https://base', 'https://spec', discover, timeout=20)).data
    assert not any(call[0] == 'eval' and call[1] == 2 for call in redis.calls)
    set_call = next(call for call in redis.calls if call[0] == 'set')
    assert set_call[3] >= int((20 + subject.OWNER_GRACE_SECONDS + subject.CLEANUP_SECONDS) * 1000)


@pytest.mark.asyncio
async def test_atomic_read_does_not_pair_old_payload_with_replaced_record_ttl():
    subject = _module(); redis = FakeRedis(); now = [0.0]; cache, _ = _cache(subject, redis, now)
    connection = _connection(); fingerprint = subject.terminal_fingerprint(connection, 'https://base', 'https://spec')
    key = subject.cache_key('test', 'one', fingerprint)
    old = json.dumps(cache._record('one', fingerprint, 'https://base', _data(specs=[{'name': 'old'}])))
    new = json.dumps(cache._record('one', fingerprint, 'https://base', _data(specs=[{'name': 'new'}])))
    redis.values[key] = (old, 1)
    redis.replace_after_atomic_read = (new, 300)
    async def should_not_discover(): raise AssertionError('atomic old snapshot is usable only for its own TTL')
    result = await cache.get_or_discover(connection, 'https://base', 'https://spec', should_not_discover)
    assert result.data['specs'][0]['name'] == 'old'
    assert cache.local[next(iter(cache.local))]['expires'] == 1
    assert any(call[0] == 'eval' and len(call[2]) == 1 for call in redis.calls)


@pytest.mark.asyncio
async def test_fenced_old_owner_cannot_clobber_new_result_or_release_new_token():
    subject = _module(); redis = FakeRedis(); cache, _ = _cache(subject, redis); started, release = asyncio.Event(), asyncio.Event()
    async def old():
        started.set(); await release.wait(); return subject.DiscoveryResult(_data())
    task = asyncio.create_task(cache.get_or_discover(_connection(), 'https://base', 'https://spec', old, timeout=1))
    await started.wait()
    fingerprint = subject.terminal_fingerprint(_connection(), 'https://base', 'https://spec')
    lease = subject.cache_key('test', 'one', fingerprint) + ':lease'
    redis.values[lease] = ('new-token', 100)
    release.set()
    assert (await task).category == 'lease_lost'
    assert redis._get(lease) == 'new-token' and not cache.local


@pytest.mark.asyncio
async def test_lease_expiry_allows_new_owner_and_old_owner_cannot_clobber_new_publication():
    subject = _module(); redis = FakeRedis(); first, _ = _cache(subject, redis); second, _ = _cache(subject, redis)
    started, release = asyncio.Event(), asyncio.Event()
    async def old():
        started.set(); await release.wait()
        return subject.DiscoveryResult(_data(specs=[{'name': 'old'}]))
    old_task = asyncio.create_task(first.get_or_discover(_connection(), 'https://base', 'https://spec', old, timeout=2))
    await started.wait()
    redis.now = 10  # Expire A's lease without advancing its real owner deadline.
    async def new(): return subject.DiscoveryResult(_data(specs=[{'name': 'new'}]))
    published = await second.get_or_discover(_connection(), 'https://base', 'https://spec', new, timeout=2)
    assert published.data['specs'][0]['name'] == 'new'
    release.set()
    assert (await old_task).category == 'lease_lost'
    assert not first.local


@pytest.mark.asyncio
async def test_all_local_waiters_cancel_owner_still_caches_once_and_cleans_inflight():
    subject = _module(); cache, _ = _cache(subject); started, release = asyncio.Event(), asyncio.Event(); calls = 0
    async def discover():
        nonlocal calls
        calls += 1; started.set(); await release.wait()
        return subject.DiscoveryResult(_data())
    first = asyncio.create_task(cache.get_or_discover(_connection(), 'https://base', 'https://spec', discover))
    await started.wait()
    second = asyncio.create_task(cache.get_or_discover(_connection(), 'https://base', 'https://spec', discover))
    first.cancel(); second.cancel()
    with pytest.raises(asyncio.CancelledError): await first
    with pytest.raises(asyncio.CancelledError): await second
    owner_task = next(iter(cache.inflight.values()))
    release.set(); await asyncio.wait_for(asyncio.shield(owner_task), 1)
    await asyncio.sleep(0)
    assert calls == 1 and not cache.inflight and len(cache.local) == 1


@pytest.mark.asyncio
async def test_mutable_configuration_change_while_fetch_blocked_prevents_publish_and_local_cache():
    subject = _module(); redis = FakeRedis(); cache, _ = _cache(subject, redis); changed = {'value': False}; started, release = asyncio.Event(), asyncio.Event()
    async def validate(): return not changed['value']
    async def discover():
        started.set(); await release.wait(); return subject.DiscoveryResult(_data())
    task = asyncio.create_task(cache.get_or_discover(_connection(), 'https://base', 'https://spec', discover, validate=validate))
    await started.wait(); changed['value'] = True; release.set()
    assert (await task).category == 'configuration_changed'
    assert not cache.local and not any(call[0] == 'eval' and call[1] == 2 for call in redis.calls)


@pytest.mark.asyncio
async def test_ttl_is_absolute_across_delayed_validation_and_redis_publication():
    subject = _module(); redis = FakeRedis(); now = [0.0]; cache, _ = _cache(subject, redis, now)
    connection = _connection(); fingerprint = subject.terminal_fingerprint(connection, 'https://base', 'https://spec')
    key = subject.cache_key('test', 'one', fingerprint)
    redis.values[key] = (json.dumps(cache._record('one', fingerprint, 'https://base', _data())), 1)
    async def delayed_validation():
        now[0] = redis.now = 1
        return True
    async def should_not_run(): raise AssertionError('expired remote data cannot be returned')
    assert (await cache.get_or_discover(connection, 'https://base', 'https://spec', should_not_run, validate=delayed_validation)).category == 'expired'
    now[0] = redis.now = 0; cache.local.clear(); redis.values.clear()
    original_eval = redis.eval
    async def delayed_eval(*args):
        if args[1] == 2:
            now[0] = redis.now = 1
        return await original_eval(*args)
    redis.eval = delayed_eval
    async def success(): return subject.DiscoveryResult(_data())
    assert (await cache.get_or_discover(connection, 'https://base', 'https://spec', success)).data
    assert cache.local[next(iter(cache.local))]['expires'] == subject.SUCCESS_TTL_SECONDS
    cache.local.clear(); redis.values.clear(); now[0] = redis.now = 0
    async def fail(): return subject.DiscoveryResult(None, 'timeout')
    result = await cache.get_or_discover(connection, 'https://base', 'https://spec', fail)
    assert result.retry_after == 5 and cache.failures[next(iter(cache.failures))][1] == 5


@pytest.mark.asyncio
async def test_immediate_local_and_inflight_caps_bound_concurrent_unique_id_work(monkeypatch):
    subject = _module(); monkeypatch.setattr(subject, 'MAX_LOCAL_ENTRIES', 3); monkeypatch.setattr(subject, 'MAX_FAILURE_ENTRIES', 3); monkeypatch.setattr(subject, 'MAX_INFLIGHT_ENTRIES', 3)
    cache, _ = _cache(subject); started, release = asyncio.Event(), asyncio.Event(); running = 0
    async def blocked(identifier):
        nonlocal running
        running += 1
        if running == 3: started.set()
        await release.wait()
        return subject.DiscoveryResult(_data(identifier))
    tasks = [asyncio.create_task(cache.get_or_discover(_connection(str(i)), 'https://base', 'https://spec', lambda i=str(i): blocked(i))) for i in range(4)]
    await started.wait()
    assert (await tasks[3]).category == 'busy'
    release.set(); results = await asyncio.gather(*tasks[:3])
    assert all(item.data for item in results) and len(cache.local) <= 3 and not cache.inflight
    async def fail(): return subject.DiscoveryResult(None, 'timeout')
    for i in range(4, 8): await cache.get_or_discover(_connection(str(i)), 'https://base', 'https://spec', fail)
    assert len(cache.failures) <= 3


@pytest.mark.asyncio
async def test_waiter_cancellation_does_not_cancel_owner_and_diagnostics_hide_sentinels(caplog):
    subject = _module(); cache, _ = _cache(subject); started, release = asyncio.Event(), asyncio.Event()
    async def discover():
        started.set(); await release.wait(); return subject.DiscoveryResult(_data())
    owner = asyncio.create_task(cache.get_or_discover(_connection(key='TOKEN_SENTINEL'), 'https://base', 'https://spec?URL_SENTINEL', discover))
    await started.wait(); waiter = asyncio.create_task(cache.get_or_discover(_connection(key='TOKEN_SENTINEL'), 'https://base', 'https://spec?URL_SENTINEL', discover)); waiter.cancel()
    with pytest.raises(asyncio.CancelledError): await waiter
    release.set(); assert (await owner).data
    assert 'TOKEN_SENTINEL' not in caplog.text and 'URL_SENTINEL' not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize('kind,category', [('utf8', 'invalid_utf8'), ('scalar', 'invalid_document'), ('large', 'size_limit')])
async def test_safe_fetch_rejects_unsafe_documents_without_secret_diagnostics(kind, category, caplog):
    subject = _module()
    document = {'utf8': b'\xff', 'scalar': '[]', 'large': b'x' * (8 * 1024 * 1024 + 1)}[kind]
    async def fetch(url, headers): return document
    result = await subject.safe_fetch_openapi('https://URL_SENTINEL@example/x', {'Authorization': 'TOKEN_SENTINEL'}, timeout=1, ssl=False, fetcher=fetch)
    assert result.category == category
    assert 'TOKEN_SENTINEL' not in caplog.text and 'URL_SENTINEL' not in caplog.text


@pytest.mark.asyncio
async def test_safe_fetch_timeout_yaml_and_scalar_categories():
    subject = _module()
    async def hang(url, headers): await asyncio.Event().wait()
    assert (await subject.safe_fetch_openapi('https://x', {}, timeout=.01, ssl=False, fetcher=hang)).category == 'timeout'
    async def yaml_document(url, headers): return 'openapi: 3.0\npaths: {}'
    assert (await subject.safe_fetch_openapi('https://x', {}, timeout=1, ssl=False, fetcher=yaml_document)).data['paths'] == {}

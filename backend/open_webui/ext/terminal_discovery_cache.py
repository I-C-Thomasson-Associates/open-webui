"""Bounded terminal OpenAPI discovery with local and Redis coordination.

The owner lifetime is ``timeout + OWNER_GRACE_SECONDS`` measured with the event
loop monotonic clock.  Every Redis operation and validation is constrained by
that same lifetime.  ``clock`` remains an injectable storage-TTL clock only.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import random
import secrets
import time
from dataclasses import dataclass
from typing import Awaitable, Callable

import aiohttp
import yaml

CACHE_VERSION = 3
SUCCESS_TTL_SECONDS = 300
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_LOCAL_ENTRIES = 128
MAX_FAILURE_ENTRIES = 128
MAX_INFLIGHT_ENTRIES = 128
FAILURE_HISTORY_SECONDS = 60
OWNER_GRACE_SECONDS = 0.25
CLEANUP_SECONDS = 0.05
WAIT_MARGIN_SECONDS = 0.05
REDIS_OPERATION_SECONDS = 0.5
log = logging.getLogger(__name__)

PUBLISH_SCRIPT = """if redis.call('GET', KEYS[2]) == ARGV[1] then
redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3]); redis.call('DEL', KEYS[2]); return 1 end; return 0"""
RELEASE_SCRIPT = """if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end; return 0"""
READ_SCRIPT = """local value = redis.call('GET', KEYS[1]); if not value then return {false, -2} end; return {value, redis.call('PTTL', KEYS[1])}"""


def _digest(value: object) -> str:
    return hashlib.sha256(str(value or '').strip().encode()).hexdigest()


def _safe_terminal_id(value: str) -> str:
    return _digest(value)[:12]


def terminal_fingerprint(connection: dict, base_url: str, spec_url: str) -> str | None:
    """Return a secret-free identity for one configured terminal."""
    if not isinstance(connection, dict):
        return None
    terminal_id = connection.get('id')
    if not isinstance(terminal_id, str) or not terminal_id.strip():
        return None
    if not isinstance(base_url, str) or not base_url.strip() or not isinstance(spec_url, str) or not spec_url.strip():
        return None
    config = connection.get('config') if isinstance(connection.get('config'), dict) else {}
    source = {
        'id': terminal_id, 'enabled': bool(connection.get('enabled', True)),
        'base_url': base_url.rstrip('/'), 'spec_url': spec_url, 'url': connection.get('url'),
        'policy': connection.get('policy_id'), 'path': connection.get('path'),
        'type': connection.get('server_type', connection.get('type')),
        'auth_type': connection.get('auth_type', 'bearer'),
        'key_digest': _digest(connection.get('key', connection.get('api_key', ''))),
        'cookies': connection.get('cookies'), 'forward_cookies': connection.get('forward_cookies'),
        'headers': connection.get('headers'), 'access': connection.get('access_control'),
        'groups': connection.get('groups'), 'contexts': config.get('contexts'),
        'permissions': config.get('permissions', connection.get('permissions')),
    }
    try:
        return hashlib.sha256(json.dumps(source, sort_keys=True, default=str, separators=(',', ':')).encode()).hexdigest()
    except (TypeError, ValueError):
        return None


def cache_key(prefix: str, terminal_id: str, fingerprint: str) -> str:
    return f'{prefix}:terminal_openapi:{{{_digest(terminal_id)[:24]}}}:{fingerprint}'


@dataclass
class DiscoveryResult:
    data: dict | None
    category: str | None = None
    retry_after: float = 0


class TerminalDiscoveryCache:
    """Bounded local fallback plus fenced distributed single-flight."""

    def __init__(self, *, prefix: str, redis=None, clock: Callable[[], float] = time.monotonic,
                 sleeper=asyncio.sleep, jitter: Callable[[], float] = random.random):
        self.prefix = prefix
        self.redis = redis
        self.clock = clock
        self.sleeper = sleeper
        self.jitter = jitter
        self.local: dict[tuple[str, str], dict] = {}
        self.inflight: dict[tuple[str, str], asyncio.Task] = {}
        self.failures: dict[tuple[str, str], tuple[int, float]] = {}

    def _log(self, terminal_id: str, outcome: str, *, elapsed_ms: int = 0, retry_after: float = 0) -> None:
        log.debug('terminal_discovery id=%s outcome=%s elapsed_ms=%d retry_after=%.3f', _safe_terminal_id(terminal_id), outcome, elapsed_ms, retry_after)

    def _prune(self) -> None:
        now = self.clock()
        self.local = {k: v for k, v in self.local.items() if v['expires'] > now}
        # Retain counts after cooldown, but cap the map to prevent unbounded input.
        for values, limit, expiry in ((self.local, MAX_LOCAL_ENTRIES, lambda v: v['expires']),
                                      (self.failures, MAX_FAILURE_ENTRIES, lambda v: v[1])):
            while len(values) > limit:
                values.pop(min(values, key=lambda k: expiry(values[k])))

    def _backoff(self, key: tuple[str, str], shared_attempt: int = 0) -> tuple[int, float]:
        previous = self.failures.get(key, (0, 0))[0]
        attempt = min(16, max(previous, shared_attempt) + 1)
        delay = min(60.0, 5.0 * (2 ** (attempt - 1)) + min(1.0, max(0.0, self.jitter())))
        return attempt, delay

    def _local_failure(self, key: tuple[str, str], shared_attempt: int = 0) -> tuple[int, float]:
        attempt, delay = self._backoff(key, shared_attempt)
        self._store_failure(key, attempt, delay)
        return attempt, delay

    def _store_failure(self, key: tuple[str, str], attempt: int, delay: float) -> None:
        self._store_failure_until(key, attempt, self.clock() + delay)

    def _store_failure_until(self, key: tuple[str, str], attempt: int, until: float) -> None:
        self.failures[key] = (attempt, until)
        self._prune()

    def _store_local(self, key: tuple[str, str], record: dict, lifetime: float) -> None:
        self._store_local_until(key, record, self.clock() + lifetime)

    def _store_local_until(self, key: tuple[str, str], record: dict, expires: float) -> None:
        self.local[key] = {**record, 'expires': expires}
        self._prune()

    def _local_cooldown(self, key: tuple[str, str]) -> float:
        return max(0.0, self.failures.get(key, (0, 0))[1] - self.clock())

    @staticmethod
    def _record(terminal_id: str, fingerprint: str, base_url: str, data: dict) -> dict:
        return {'version': CACHE_VERSION, 'kind': 'success', 'id': terminal_id,
                'fingerprint': fingerprint, 'base_url': base_url.rstrip('/'), 'data': copy.deepcopy(data)}

    @staticmethod
    def _usable_data(data: object, terminal_id: str, base_url: str) -> dict | None:
        if not isinstance(data, dict) or data.get('id') != terminal_id:
            return None
        openapi, specs = data.get('openapi'), data.get('specs')
        if not isinstance(openapi, dict) or not isinstance(openapi.get('paths'), dict) or not isinstance(specs, list):
            return None
        if 'info' in openapi and not isinstance(openapi['info'], dict):
            return None
        expected = base_url.rstrip('/')
        if data.get('url') is not None and data.get('url') != expected:
            return None
        if not specs or any(not isinstance(spec, dict) or not isinstance(spec.get('name'), str) or not spec['name'].strip() or
                            ('parameters' in spec and not isinstance(spec['parameters'], dict)) for spec in specs):
            return None
        safe = copy.deepcopy(data)
        safe['url'] = expected
        return safe

    def _valid_success(self, record: object, terminal_id: str, fingerprint: str, base_url: str) -> dict | None:
        if not isinstance(record, dict) or record.get('version') != CACHE_VERSION or record.get('kind') != 'success':
            return None
        if record.get('id') != terminal_id or record.get('fingerprint') != fingerprint or record.get('base_url') != base_url.rstrip('/'):
            return None
        return self._usable_data(record.get('data'), terminal_id, base_url)

    def _valid_failure(self, record: object, terminal_id: str, fingerprint: str, base_url: str, expires: float | None) -> tuple[int, float] | None:
        if not isinstance(record, dict) or record.get('version') != CACHE_VERSION or record.get('kind') != 'failure':
            return None
        if record.get('id') != terminal_id or record.get('fingerprint') != fingerprint or record.get('base_url') != base_url.rstrip('/'):
            return None
        try:
            attempt, delay = int(record['attempt']), float(record['delay'])
        except (KeyError, TypeError, ValueError):
            return None
        remaining = expires - self.clock() if expires is not None else 0
        if not 1 <= attempt <= 16 or not 0 < delay <= 60 or remaining <= 0:
            return None
        # Redis TTL is the only shared clock.  A record lasting longer than its
        # declared cooldown plus history tail is corrupt/untrusted.
        if remaining > delay + FAILURE_HISTORY_SECONDS + 1:
            return None
        return attempt, expires - FAILURE_HISTORY_SECONDS

    def _remaining(self, expires: float | None) -> float:
        return max(0.0, (expires or 0) - self.clock())

    async def _redis(self, operation, deadline: float):
        if self.redis is None:
            return False, None
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return False, None
        try:
            return True, await asyncio.wait_for(operation(), min(REDIS_OPERATION_SECONDS, remaining))
        except asyncio.CancelledError:
            raise
        except Exception:
            return False, None

    async def _read(self, key: str, deadline: float) -> tuple[bool, dict | None, float | None]:
        if self.redis is None:
            return False, None, None
        read_started = self.clock()
        ok, reply = await self._redis(lambda: self.redis.eval(READ_SCRIPT, 1, key), deadline)
        if not ok or not isinstance(reply, (list, tuple)) or len(reply) != 2:
            return False, None, None
        raw, milliseconds = reply
        if not isinstance(milliseconds, (int, float)):
            return False, None, None
        try:
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8')
            value = json.loads(raw) if isinstance(raw, str) else raw
        except (UnicodeDecodeError, TypeError, ValueError):
            value = None
        if raw is None or raw is False:
            if milliseconds != -2:
                return False, None, None
            # A normal Redis miss is healthy and may proceed to lease acquisition.
            return True, None, None
        if milliseconds <= 0:
            # Present-but-expired or non-expiring cache records are never trusted.
            return False, None, None
        return True, value if isinstance(value, dict) else None, read_started + float(milliseconds) / 1000

    async def _validate(self, validate, deadline: float) -> bool | None:
        if validate is None:
            return True
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return False
        try:
            return bool(await asyncio.wait_for(validate(), remaining))
        except asyncio.TimeoutError:
            return None
        except asyncio.CancelledError:
            raise
        except Exception:
            return False

    @staticmethod
    def _validation_failure(value: bool | None) -> DiscoveryResult | None:
        if value is True:
            return None
        return DiscoveryResult(None, 'validation_timeout' if value is None else 'configuration_changed')

    @staticmethod
    def _timeout(value: object) -> float:
        try:
            value = float(value)
        except (TypeError, ValueError):
            return 10.0
        return value if 0 < value <= 3600 else 10.0

    async def get_or_discover(self, connection: dict, base_url: str, spec_url: str,
                              discover: Callable[[], Awaitable[DiscoveryResult]], *, validate=None,
                              timeout: float = 10.0) -> DiscoveryResult:
        if not isinstance(connection, dict) or connection.get('enabled') is False:
            return DiscoveryResult(None, 'invalid_configuration')
        terminal_id = connection.get('id')
        fingerprint = terminal_fingerprint(connection, base_url, spec_url)
        if not isinstance(terminal_id, str) or fingerprint is None:
            return DiscoveryResult(None, 'invalid_configuration')
        timeout = self._timeout(timeout)
        key = (terminal_id, fingerprint)
        self._prune()
        loop = asyncio.get_running_loop()
        call_deadline = loop.time() + timeout + OWNER_GRACE_SECONDS
        local = self._valid_success(self.local.get(key), terminal_id, fingerprint, base_url)
        if local:
            validation = self._validation_failure(await self._validate(validate, call_deadline))
            if validation is None:
                if self._remaining(self.local.get(key, {}).get('expires')) <= 0:
                    return DiscoveryResult(None, 'expired')
                self._log(terminal_id, 'local_hit')
                return DiscoveryResult(local)
            self._log(terminal_id, 'configuration_changed')
            return validation
        delay = self._local_cooldown(key)
        if delay:
            validation = self._validation_failure(await self._validate(validate, call_deadline))
            if validation:
                return validation
            self._log(terminal_id, 'cooldown')
            return DiscoveryResult(None, 'cooldown', delay)
        task = self.inflight.get(key)
        initiated = task is None
        if task is None:
            if len(self.inflight) >= MAX_INFLIGHT_ENTRIES:
                self._log(terminal_id, 'busy')
                return DiscoveryResult(None, 'busy', .05)
            task = asyncio.create_task(self._owner(key, terminal_id, fingerprint, base_url, discover, validate, timeout, call_deadline))
            self.inflight[key] = task
            task.add_done_callback(lambda done, k=key: self._finish_task(k, done))
        try:
            wait_budget = max(0.001, call_deadline - loop.time() + CLEANUP_SECONDS + WAIT_MARGIN_SECONDS)
            return await asyncio.wait_for(asyncio.shield(task), wait_budget)
        except asyncio.TimeoutError:
            self._log(terminal_id, 'wait_timeout')
            # The creator owns this timeout classification; the detached owner
            # remains responsible for the single failure/backoff update.
            return DiscoveryResult(None, 'timeout' if initiated else 'in_progress', self._local_cooldown(key) or OWNER_GRACE_SECONDS)

    def _finish_task(self, key: tuple[str, str], task: asyncio.Task) -> None:
        if self.inflight.get(key) is task:
            self.inflight.pop(key, None)
        # Consume unexpected exceptions so detached, cancelled waiters never log an orphan task error.
        if not task.cancelled():
            try:
                task.exception()
            except Exception:
                pass

    async def _owner(self, key, terminal_id, fingerprint, base_url, discover, validate, timeout, deadline) -> DiscoveryResult:
        loop = asyncio.get_running_loop()
        started = time.monotonic()
        record_key = cache_key(self.prefix, terminal_id, fingerprint)
        lease_key, failure_key = record_key + ':lease', record_key + ':failure'
        token, owned = secrets.token_urlsafe(24), False
        shared_attempt = 0
        try:
            self._log(terminal_id, 'cache_miss', elapsed_ms=0)
            async with asyncio.timeout_at(deadline):
                healthy, record, ttl = await self._read(record_key, deadline)
                data = self._valid_success(record, terminal_id, fingerprint, base_url) if healthy else None
                if data:
                    validation = self._validation_failure(await self._validate(validate, deadline))
                    if validation:
                        return validation
                    if self._remaining(ttl) <= 0:
                        return DiscoveryResult(None, 'expired')
                    self._store_local_until(key, self._record(terminal_id, fingerprint, base_url, data), ttl)
                    self._log(terminal_id, 'redis_hit')
                    return DiscoveryResult(data)
                if not healthy:
                    return await self._discover(key, terminal_id, fingerprint, base_url, discover, validate, deadline, 0, False)
                _, failure, failure_ttl = await self._read(failure_key, deadline)
                shared = self._valid_failure(failure, terminal_id, fingerprint, base_url, failure_ttl)
                if shared:
                    shared_attempt, retry_until = shared
                    retry = self._remaining(retry_until)
                    if retry:
                        validation = self._validation_failure(await self._validate(validate, deadline))
                        if validation:
                            return validation
                        retry = self._remaining(retry_until)
                        if retry <= 0:
                            shared_attempt = max(shared_attempt, shared[0])
                        else:
                            self._store_failure_until(key, shared_attempt, retry_until)
                            self._log(terminal_id, 'cooldown', retry_after=retry)
                            return DiscoveryResult(None, 'cooldown', retry)
                lease_ms = max(1000, int((timeout + OWNER_GRACE_SECONDS + 1) * 1000))
                ok, acquired = await self._redis(lambda: self.redis.set(lease_key, token, nx=True, px=lease_ms), deadline)
                if not ok:  # Unknown SETNX outcome: never publish to Redis.
                    return await self._discover(key, terminal_id, fingerprint, base_url, discover, validate, deadline, shared_attempt, False)
                if not acquired:
                    return await self._wait_for_owner(key, terminal_id, fingerprint, base_url, validate, record_key, failure_key, deadline)
                owned = True
                # A post-lease read failure is degraded; the lease is not proof that publishing is safe.
                healthy, record, ttl = await self._read(record_key, deadline)
                if not healthy:
                    return await self._discover(key, terminal_id, fingerprint, base_url, discover, validate, deadline, shared_attempt, False)
                data = self._valid_success(record, terminal_id, fingerprint, base_url)
                if data:
                    validation = self._validation_failure(await self._validate(validate, deadline))
                    if validation:
                        return validation
                    if self._remaining(ttl) <= 0:
                        return DiscoveryResult(None, 'expired')
                    self._store_local_until(key, self._record(terminal_id, fingerprint, base_url, data), ttl)
                    return DiscoveryResult(data)
                return await self._discover(key, terminal_id, fingerprint, base_url, discover, validate, deadline, shared_attempt, True, record_key, lease_key, failure_key, token)
        except asyncio.TimeoutError:
            attempt, delay = self._local_failure(key, shared_attempt)
            self._log(terminal_id, 'timeout')
            return DiscoveryResult(None, 'timeout', delay)
        finally:
            self._log(terminal_id, 'owner_complete', elapsed_ms=int((time.monotonic() - started) * 1000))
            if owned:
                # Cleanup is deliberately bounded outside the owner budget.
                await self._redis(lambda: self.redis.eval(RELEASE_SCRIPT, 1, lease_key, token), loop.time() + CLEANUP_SECONDS)

    async def _wait_for_owner(self, key, terminal_id, fingerprint, base_url, validate, record_key, failure_key, deadline) -> DiscoveryResult:
        loop = asyncio.get_running_loop()
        while loop.time() < deadline:
            await self.sleeper(min(.05, max(.001, deadline - loop.time())))
            healthy, record, ttl = await self._read(record_key, deadline)
            data = self._valid_success(record, terminal_id, fingerprint, base_url) if healthy else None
            if data:
                validation = self._validation_failure(await self._validate(validate, deadline))
                if validation:
                    return validation
                if self._remaining(ttl) <= 0:
                    continue
                self._store_local_until(key, self._record(terminal_id, fingerprint, base_url, data), ttl)
                return DiscoveryResult(data)
            _, failure, failure_ttl = await self._read(failure_key, deadline)
            shared = self._valid_failure(failure, terminal_id, fingerprint, base_url, failure_ttl)
            if shared and self._remaining(shared[1]):
                validation = self._validation_failure(await self._validate(validate, deadline))
                if validation:
                    return validation
                retry = self._remaining(shared[1])
                if retry > 0:
                    self._store_failure_until(key, shared[0], shared[1])
                    return DiscoveryResult(None, 'cooldown', retry)
            if not healthy:
                break
        return DiscoveryResult(None, 'in_progress', .05)

    async def _discover(self, key, terminal_id, fingerprint, base_url, discover, validate, deadline, shared_attempt, publish, record_key=None, lease_key=None, failure_key=None, token=None) -> DiscoveryResult:
        try:
            result = await asyncio.wait_for(discover(), max(.001, deadline - asyncio.get_running_loop().time()))
        except asyncio.TimeoutError:
            result = DiscoveryResult(None, 'timeout')
        except asyncio.CancelledError:
            raise
        except Exception:
            result = DiscoveryResult(None, 'discovery_error')
        data = self._usable_data(result.data, terminal_id, base_url) if isinstance(result, DiscoveryResult) else None
        if data:
            validation = self._validation_failure(await self._validate(validate, deadline))
            if validation:
                self._log(terminal_id, 'configuration_changed')
                return validation
            record = self._record(terminal_id, fingerprint, base_url, data)
            published_started = self.clock()
            if publish:
                ok, published = await self._redis(lambda: self.redis.eval(PUBLISH_SCRIPT, 2, record_key, lease_key, token, json.dumps(record), str(SUCCESS_TTL_SECONDS * 1000)), deadline)
                if ok and not published:
                    self._log(terminal_id, 'lease_lost')
                    return DiscoveryResult(None, 'lease_lost')
            self._store_local_until(key, record, published_started + SUCCESS_TTL_SECONDS)
            self.failures.pop(key, None)
            self._log(terminal_id, 'success')
            return DiscoveryResult(copy.deepcopy(data))
        attempt, delay = self._backoff(key, shared_attempt)
        failure_started = self.clock()
        if publish:
            failure = {'version': CACHE_VERSION, 'kind': 'failure', 'id': terminal_id, 'fingerprint': fingerprint,
                       'base_url': base_url.rstrip('/'), 'attempt': attempt, 'delay': delay}
            ok, published = await self._redis(lambda: self.redis.eval(PUBLISH_SCRIPT, 2, failure_key, lease_key, token, json.dumps(failure), str(int((delay + FAILURE_HISTORY_SECONDS) * 1000))), deadline)
            if ok and not published:
                return DiscoveryResult(None, 'lease_lost')
        self._store_failure_until(key, attempt, failure_started + delay)
        category = result.category if isinstance(result, DiscoveryResult) and isinstance(result.category, str) else 'discovery_error'
        self._log(terminal_id, category)
        return DiscoveryResult(None, category, delay)


async def safe_fetch_openapi(url: str, headers: dict | None, *, timeout: float, ssl, fetcher=None) -> DiscoveryResult:
    """Fetch one non-redirected JSON/YAML mapping without exposing request secrets."""
    started, category = time.monotonic(), 'fetch_error'
    try:
        timeout = TerminalDiscoveryCache._timeout(timeout)
        if fetcher is not None:
            document = await asyncio.wait_for(fetcher(url, headers or {}), timeout)
        else:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), trust_env=True) as session:
                async with session.get(url, headers=headers or {}, ssl=ssl, allow_redirects=False) as response:
                    if response.status != 200:
                        category = f'http_{response.status}'
                        return DiscoveryResult(None, category)
                    chunks, size = [], 0
                    async for chunk in response.content.iter_chunked(65536):
                        size += len(chunk)
                        if size > MAX_DOCUMENT_BYTES:
                            category = 'size_limit'
                            return DiscoveryResult(None, category)
                        chunks.append(chunk)
                    document = b''.join(chunks)
        if isinstance(document, bytes):
            if len(document) > MAX_DOCUMENT_BYTES:
                category = 'size_limit'; return DiscoveryResult(None, category)
            try: document = document.decode('utf-8')
            except UnicodeDecodeError: category = 'invalid_utf8'; return DiscoveryResult(None, category)
        if isinstance(document, str) and len(document.encode('utf-8')) > MAX_DOCUMENT_BYTES:
            category = 'size_limit'; return DiscoveryResult(None, category)
        if isinstance(document, dict):
            category = 'success'; return DiscoveryResult(document)
        try: value = json.loads(document)
        except (TypeError, ValueError):
            try: value = yaml.safe_load(document)
            except yaml.YAMLError: value = None
        category = 'success' if isinstance(value, dict) else 'invalid_document'
        return DiscoveryResult(value if isinstance(value, dict) else None, None if isinstance(value, dict) else category)
    except asyncio.TimeoutError:
        category = 'timeout'; return DiscoveryResult(None, category)
    except aiohttp.ClientConnectionError:
        category = 'connection'; return DiscoveryResult(None, category)
    except Exception:
        return DiscoveryResult(None, category)
    finally:
        log.debug('terminal_openapi_fetch outcome=%s elapsed_ms=%d', category, int((time.monotonic() - started) * 1000))

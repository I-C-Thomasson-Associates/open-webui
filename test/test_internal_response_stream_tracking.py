"""Exercise production task tracking and fan-out without application startup."""

import ast
import asyncio
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

BACKEND = Path(__file__).parents[1] / 'backend' / 'open_webui'


@pytest.fixture
def tracking():
    # Avoid config/.env and Redis telemetry imports; these tests use only fake Redis.
    path = BACKEND / 'tasks.py'
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    tree.body = [
        node
        for node in tree.body
        if not isinstance(node, ast.ImportFrom)
        or not (node.module.startswith('open_webui.') or node.module == 'redis.asyncio')
    ]
    module = ModuleType('stream_tracking_test')
    module.__dict__.update(
        REDIS_KEY_PREFIX='test',
        REDIS_TASK_TTL=60,
        REDIS_RESPONSE_STREAM_TTL=0,
        Redis=object,
        JSONCodec=json,
        dumps_bytes=lambda value: json.dumps(value).encode(),
    )
    exec(compile(tree, str(path), 'exec'), module.__dict__)
    return module


def load_fanout(tracking, process_chat):
    path = BACKEND / 'main.py'
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    chat = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef) and node.name == 'chat_completion')
    fanout = chat.body[-1]
    assert isinstance(fanout, ast.If) and "metadata.get('session_id')" in ast.unparse(fanout.test)
    wrapper = ast.parse('async def fanout(request, form_data, user, metadata, model, tasks, message_ids): pass')
    wrapper.body[0].body = [fanout]
    namespace = {
        'create_task': tracking.create_task,
        'process_chat': process_chat,
        'uuid4': uuid4,
        'TASKS': SimpleNamespace(TITLE_GENERATION='title', TAGS_GENERATION='tags'),
        'get_event_emitter': AsyncMock(),
    }
    exec(compile(ast.fix_missing_locations(wrapper), str(path), 'exec'), namespace)
    return namespace['fanout'], namespace['get_event_emitter']


class MemoryRedis:
    """Only the task registry/stream commands, with no external connections."""

    def __init__(self):
        self.values = {}
        self.hashes = {}
        self.sets = {}

    def pipeline(self, transaction=False):  # noqa: C901 - explicit fake command dispatch
        redis = self

        class Pipeline:
            def __init__(self):
                self.commands = []

            def __getattr__(self, name):
                def queue(*args, **kwargs):
                    self.commands.append((name, args))
                    return self

                return queue

            async def execute(self):
                results = []
                for name, args in self.commands:
                    key, *rest = args
                    if name == 'set':
                        redis.values[key] = rest[0]
                    elif name == 'delete':
                        redis.values.pop(key, None)
                    elif name == 'hset':
                        redis.hashes.setdefault(key, {})[rest[0]] = rest[1]
                    elif name == 'hdel':
                        redis.hashes.get(key, {}).pop(rest[0], None)
                    elif name == 'sadd':
                        redis.sets.setdefault(key, set()).add(rest[0])
                    elif name == 'srem':
                        redis.sets.get(key, set()).discard(rest[0])
                    elif name == 'exists':
                        results.append(key in redis.values)
                        continue
                    else:
                        raise AssertionError(name)
                    results.append(True)
                return results

        return Pipeline()

    async def smembers(self, key):
        return self.sets.get(key, set())

    async def hkeys(self, key):
        return list(self.hashes.get(key, {}))

    async def hmget(self, key, fields):
        return [self.hashes.get(key, {}).get(field) for field in fields]

    async def hset(self, key, field, value):
        self.hashes.setdefault(key, {})[field] = value


async def drain_callbacks():
    # A completed task schedules its done callback, which then schedules cleanup.
    await asyncio.sleep(0)
    await asyncio.sleep(0)


@pytest.mark.asyncio
@pytest.mark.parametrize('use_redis', [False, True])
async def test_internal_stream_is_child_scoped_and_completion_preserves_outer_task(tracking, use_redis):
    redis = MemoryRedis() if use_redis else None
    started, finish, publish = asyncio.Event(), asyncio.Event(), asyncio.Event()
    observed = {}
    result = {'content': 'finished'}

    async def process(request, form_data, user, metadata, model, tasks):
        observed.update(metadata)
        try:
            await tracking.save_response_stream(
                redis, metadata['task_id'], metadata['chat_id'], metadata['message_id'], 'partial', []
            )
            started.set()
            await finish.wait()
            return result
        finally:
            await tracking.cleanup_task(redis, metadata['task_id'], metadata['chat_id'])

    fanout, emitter = load_fanout(tracking, process)
    request = SimpleNamespace(
        state=SimpleNamespace(internal=True), app=SimpleNamespace(state=SimpleNamespace(redis=redis, MODELS={}))
    )

    async def outer():
        response = await fanout(
            request,
            {},
            None,
            {'session_id': 'session', 'chat_id': 'child'},
            {},
            None,
            [{'model_id': 'model', 'message_id': 'message'}],
        )
        await publish.wait()
        return response

    outer_id, task = await tracking.create_task(redis, outer(), id='child')
    try:
        await asyncio.wait_for(started.wait(), 1)
        inner_id = observed['task_id']
        assert inner_id != outer_id
        assert set(await tracking.list_task_ids_by_item_id(redis, 'child')) == {outer_id, inner_id}
        assert await tracking.get_response_streams_by_chat_id(redis, 'child') == [
            {'chat_id': 'child', 'message_id': 'message', 'content': 'partial', 'output': []}
        ]
        assert await tracking.get_response_streams_by_chat_id(redis, 'unrelated-child') == []
        assert not task.done()
        finish.set()
        await drain_callbacks()
        assert await tracking.list_task_ids_by_item_id(redis, 'child') == [outer_id]
        assert await tracking.get_response_streams_by_chat_id(redis, 'child') == []
        publish.set()
        assert await task == {'status': True, 'task_ids': [], 'chat_id': 'child', 'results': [result]}
        emitter.assert_not_awaited()
        await drain_callbacks()
        assert await tracking.list_task_ids_by_item_id(redis, 'child') == []
        assert tracking.tasks == tracking.item_tasks == tracking.response_streams == {}
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await drain_callbacks()


@pytest.mark.asyncio
async def test_external_fanout_returns_registered_task_without_awaiting_body(tracking):
    started = asyncio.Event()

    async def process(*args):
        started.set()
        await asyncio.Event().wait()

    fanout, emitter = load_fanout(tracking, process)
    request = SimpleNamespace(
        state=SimpleNamespace(internal=False), app=SimpleNamespace(state=SimpleNamespace(redis=None, MODELS={}))
    )
    try:
        response = await asyncio.wait_for(
            fanout(
                request,
                {},
                None,
                {'session_id': 'session', 'chat_id': 'external', 'folder_id': 'folder'},
                {},
                None,
                [{'model_id': 'model', 'message_id': 'message'}],
            ),
            1,
        )
        task_id, = response['task_ids']
        assert response == {'status': True, 'task_ids': [task_id], 'chat_id': 'external'}
        await asyncio.wait_for(started.wait(), 1)
        assert tracking.item_tasks == {'external': [task_id]}
        assert not tracking.tasks[task_id].done()
        emitter.assert_awaited_once()
        emitter.return_value.assert_awaited_once_with(
            {'type': 'chat:active', 'data': {'active': True, 'folder_id': 'folder'}}
        )
    finally:
        active = list(tracking.tasks.values())
        for task in active:
            task.cancel()
        await asyncio.gather(*active, return_exceptions=True)
        await drain_callbacks()
    assert tracking.tasks == tracking.item_tasks == tracking.response_streams == {}


@pytest.mark.asyncio
@pytest.mark.parametrize('cancel_by_chat', [False, True])
async def test_outer_or_child_stop_cancels_internal_process(tracking, cancel_by_chat):
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def process(request, form_data, user, metadata, model, tasks):
        try:
            await tracking.save_response_stream(None, metadata['task_id'], 'child', 'message', 'partial', [])
            started.set()
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise
        finally:
            await tracking.cleanup_task(None, metadata['task_id'], 'child')

    fanout, _ = load_fanout(tracking, process)
    request = SimpleNamespace(
        state=SimpleNamespace(internal=True), app=SimpleNamespace(state=SimpleNamespace(redis=None, MODELS={}))
    )
    _, task = await tracking.create_task(
        None,
        fanout(
            request,
            {},
            None,
            {'session_id': 'session', 'chat_id': 'child'},
            {},
            None,
            [{'model_id': 'model', 'message_id': 'message'}],
        ),
        id='child',
    )
    try:
        await asyncio.wait_for(started.wait(), 1)
        if cancel_by_chat:
            assert (await tracking.stop_item_tasks(None, 'child'))['status'] is True
        else:
            task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cancelled.is_set()
        await drain_callbacks()
        assert tracking.tasks == tracking.item_tasks == tracking.response_streams == {}
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await drain_callbacks()


@pytest.mark.asyncio
@pytest.mark.parametrize('cancel_registration', [False, True])
@pytest.mark.parametrize('cleanup_fails', [False, True])
async def test_failed_redis_registration_cancels_task_and_cleans_local_state(
    tracking, monkeypatch, cancel_registration, cleanup_fails, caplog
):
    started, saving = asyncio.Event(), asyncio.Event()
    created = []
    failure = RuntimeError('registration failed')

    async def process():
        started.set()
        await asyncio.Event().wait()

    async def save(*args):
        created.append(tracking.tasks['inner'])
        assert tracking.item_tasks == {'child': ['inner']}
        tracking.response_streams['inner'] = {'content': 'partial'}
        await asyncio.sleep(0)
        saving.set()
        if cancel_registration:
            await asyncio.Event().wait()
        raise failure

    monkeypatch.setattr(tracking, 'redis_save_task', save)
    monkeypatch.setattr(
        tracking, 'redis_cleanup_task', AsyncMock(side_effect=RuntimeError('cleanup failed') if cleanup_fails else None)
    )
    coroutine = process()
    registration = asyncio.create_task(tracking.create_task(object(), coroutine, id='child', task_id='inner'))
    try:
        await asyncio.wait_for(saving.wait(), 1)
        if cancel_registration:
            registration.cancel()
        with pytest.raises(asyncio.CancelledError if cancel_registration else RuntimeError) as error:
            await asyncio.wait_for(registration, 1)
        if not cancel_registration:
            assert error.value is failure
        await drain_callbacks()
        assert not started.is_set()
        assert coroutine.cr_frame is None
        assert created[0].cancelled()
        assert tracking.tasks == tracking.item_tasks == tracking.response_streams == {}
        assert not any(record.name == 'asyncio' for record in caplog.records)
    finally:
        registration.cancel()
        for task in created:
            task.cancel()
        await asyncio.gather(registration, *created, return_exceptions=True)
        await drain_callbacks()


@pytest.mark.asyncio
async def test_registration_failure_before_coroutine_starts(tracking, monkeypatch):
    failure = RuntimeError('registration failed')
    monkeypatch.setattr(tracking, 'redis_save_task', AsyncMock(side_effect=failure))
    monkeypatch.setattr(tracking, 'redis_cleanup_task', AsyncMock())
    process = AsyncMock()
    coroutine = process()
    with pytest.raises(RuntimeError) as error:
        await tracking.create_task(object(), coroutine, id='child', task_id='inner')
    assert error.value is failure
    process.assert_not_awaited()
    await drain_callbacks()
    assert coroutine.cr_frame is None
    assert tracking.tasks == tracking.item_tasks == tracking.response_streams == {}


@pytest.mark.asyncio
async def test_failed_registration_does_not_start_bridge_waiting_for_caller_decision(tracking, monkeypatch):
    gate = asyncio.get_running_loop().create_future()
    coordinator_started, bridge_started = asyncio.Event(), asyncio.Event()
    failure = RuntimeError('registration failed')

    async def coordinator():
        coordinator_started.set()
        while not gate.done():
            try:
                await asyncio.shield(gate)
            except asyncio.CancelledError:
                pass
        return gate.result()

    coordinator_task = asyncio.create_task(coordinator())

    async def bridge():
        bridge_started.set()
        return await coordinator_task

    async def save(*args):
        await asyncio.sleep(0)
        raise failure

    monkeypatch.setattr(tracking, 'redis_save_task', save)
    monkeypatch.setattr(tracking, 'redis_cleanup_task', AsyncMock())
    coroutine = bridge()
    registration = asyncio.create_task(tracking.create_task(object(), coroutine, id='child', task_id='inner'))
    try:
        await asyncio.wait_for(coordinator_started.wait(), 1)
        # wait_for would itself hang if registration swallowed the timeout cancellation.
        done, _ = await asyncio.wait({registration}, timeout=1)
        assert registration in done, 'registration deadlocked waiting for the caller decision'
        with pytest.raises(RuntimeError) as error:
            registration.result()
        assert error.value is failure
        assert not bridge_started.is_set()
        assert coroutine.cr_frame is None
        assert not coordinator_task.done()
        gate.set_result(False)
        assert await coordinator_task is False
        await drain_callbacks()
        assert tracking.tasks == tracking.item_tasks == tracking.response_streams == {}
    finally:
        if not gate.done():
            gate.set_result(False)
        registration.cancel()
        await asyncio.gather(registration, coordinator_task, return_exceptions=True)
        await drain_callbacks()


def load_builtin_delegate(tracking, background):
    path = BACKEND / 'utils' / 'subagents.py'
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    delegate = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef) and node.name == 'delegate')
    reservation_index = next(
        index
        for index, node in enumerate(delegate.body)
        if isinstance(node, ast.Assign) and ast.unparse(node.targets[0]) == 'delegation_id'
    )
    body_index = next(
        index
        for index, node in enumerate(delegate.body)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == 'run_reserved'
    )
    wrapper = ast.parse('async def reserve_and_register(): pass')
    # Keep actual reservation, coroutine bodies, registration handler, and return contract;
    # omit only config/file validation and persisted child-chat creation.
    wrapper.body[0].body = [
        delegate.body[0],
        *delegate.body[reservation_index:reservation_index + 3],
        *delegate.body[body_index:],
    ]

    class Semaphore(asyncio.BoundedSemaphore):
        releases = 0

        def release(self):
            self.releases += 1
            super().release()

    class Reservations(set):
        discards = 0

        def discard(self, value):
            self.discards += 1
            super().discard(value)

    semaphore = Semaphore(1)
    reservations = Reservations({'unrelated'})
    handler = AsyncMock()
    namespace = {
        'asyncio': asyncio,
        'uuid4': uuid4,
        'create_task': tracking.create_task,
        'request': SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(redis=object(), CHAT_COMPLETION_HANDLER=handler))
        ),
        'chat_id': 'child',
        'background': background,
        '_foreground_semaphore': semaphore,
        '_background_active': reservations,
        '_background_lock': asyncio.Lock(),
        'max_concurrent': 1,
        'max_async': 2,
        '_build_request': lambda *args, **kwargs: SimpleNamespace(state=SimpleNamespace()),
        'user': SimpleNamespace(id='user'),
        'max_iterations': 1,
        'max_output': 100,
        'config': {},
        'DEFAULT_SUBAGENT_SYSTEM_PROMPT': 'system',
        'run': {'model_id': 'model'},
        'prompt': 'task',
        'assistant_message_id': 'message',
        'user_message': {},
        'Chats': SimpleNamespace(
            get_message_by_id_and_message_id=AsyncMock(return_value={'content': 'finished'}),
            upsert_message_to_chat_by_id_and_message_id=AsyncMock(),
        ),
    }
    exec(compile(ast.fix_missing_locations(wrapper), str(path), 'exec'), namespace)
    return namespace['reserve_and_register'], semaphore, reservations, handler


@pytest.mark.asyncio
@pytest.mark.parametrize('background', [False, True])
@pytest.mark.parametrize('cancel_registration', [False, True])
async def test_failed_registration_releases_builtin_reservation_once(
    tracking, monkeypatch, background, cancel_registration
):
    delegate, semaphore, reservations, handler = load_builtin_delegate(tracking, background)
    saving = asyncio.Event()
    created = []

    async def save(*args):
        created.extend(tracking.tasks.values())
        await asyncio.sleep(0)
        saving.set()
        if cancel_registration:
            await asyncio.Event().wait()
        raise RuntimeError('registration failed')

    monkeypatch.setattr(tracking, 'redis_save_task', save)
    monkeypatch.setattr(tracking, 'redis_cleanup_task', AsyncMock())
    registration = asyncio.create_task(delegate())
    try:
        await asyncio.wait_for(saving.wait(), 1)
        if cancel_registration:
            registration.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(registration, 1)
        else:
            assert await asyncio.wait_for(registration, 1) == 'Error: registration failed'
        await drain_callbacks()
        assert semaphore.releases == (0 if background else 1)
        assert not semaphore.locked()
        assert reservations == {'unrelated'}
        assert reservations.discards == (1 if background else 0)
        handler.assert_not_awaited()
        assert len(created) == 1 and created[0].cancelled()
        assert tracking.tasks == tracking.item_tasks == tracking.response_streams == {}
    finally:
        registration.cancel()
        for task in created:
            task.cancel()
        await asyncio.gather(registration, *created, return_exceptions=True)
        await drain_callbacks()


@pytest.mark.asyncio
async def test_successful_builtin_body_releases_foreground_reservation_once(tracking, monkeypatch):
    delegate, semaphore, reservations, handler = load_builtin_delegate(tracking, False)
    monkeypatch.setattr(tracking, 'redis_save_task', AsyncMock())
    monkeypatch.setattr(tracking, 'redis_cleanup_task', AsyncMock())
    assert await asyncio.wait_for(delegate(), 1) == 'finished'
    handler.assert_awaited_once()
    assert semaphore.releases == 1
    assert not semaphore.locked()
    assert reservations == {'unrelated'}
    assert reservations.discards == 0
    await drain_callbacks()
    assert tracking.tasks == tracking.item_tasks == tracking.response_streams == {}


@pytest.mark.asyncio
@pytest.mark.parametrize('body_fails', [False, True])
async def test_coroutine_starts_only_after_redis_registration_and_preserves_outcome(tracking, monkeypatch, body_fails):
    saving, registered, started = asyncio.Event(), asyncio.Event(), asyncio.Event()
    failure = RuntimeError('body failed')
    result = {'content': 'finished'}

    async def process():
        started.set()
        if body_fails:
            raise failure
        return result

    async def save(*args):
        saving.set()
        await registered.wait()

    monkeypatch.setattr(tracking, 'redis_save_task', save)
    monkeypatch.setattr(tracking, 'redis_cleanup_task', AsyncMock())
    coroutine = process()
    registration = asyncio.create_task(tracking.create_task(object(), coroutine, id='child', task_id='inner'))
    try:
        await asyncio.wait_for(saving.wait(), 1)
        await asyncio.sleep(0)
        assert not started.is_set()
        assert not tracking.tasks['inner'].done()
        assert tracking.item_tasks == {'child': ['inner']}
        registered.set()
        task_id, task = await asyncio.wait_for(registration, 1)
        assert task_id == 'inner'
        assert isinstance(task, asyncio.Task)
        if body_fails:
            with pytest.raises(RuntimeError) as error:
                await task
            assert error.value is failure
        else:
            assert await task is result
        assert started.is_set()
        await drain_callbacks()
        assert coroutine.cr_frame is None
        assert tracking.tasks == tracking.item_tasks == tracking.response_streams == {}
    finally:
        registration.cancel()
        await asyncio.gather(registration, return_exceptions=True)
        await drain_callbacks()


@pytest.mark.asyncio
@pytest.mark.parametrize('use_redis', [False, True])
async def test_cancellation_before_wrapper_starts_closes_original_coroutine(tracking, use_redis):
    process = AsyncMock()
    coroutine = process()
    task_id, task = await tracking.create_task(
        MemoryRedis() if use_redis else None, coroutine, id='child', task_id='inner'
    )
    assert task_id == 'inner'
    assert isinstance(task, asyncio.Task)
    assert tracking.tasks == {'inner': task}
    assert tracking.item_tasks == {'child': ['inner']}
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await drain_callbacks()
    process.assert_not_awaited()
    assert coroutine.cr_frame is None
    assert tracking.tasks == tracking.item_tasks == tracking.response_streams == {}


@pytest.mark.asyncio
async def test_cancelled_redis_cleanup_still_cleans_local_state(tracking, monkeypatch):
    cleaning = asyncio.Event()

    async def cleanup(*args):
        cleaning.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(tracking, 'redis_cleanup_task', cleanup)
    tracking.tasks['inner'] = object()
    tracking.item_tasks['child'] = ['inner', 'outer']
    tracking.response_streams['inner'] = {'content': 'partial'}
    task = asyncio.create_task(tracking.cleanup_task(object(), 'inner', 'child'))
    try:
        await asyncio.wait_for(cleaning.wait(), 1)
        assert tracking.tasks == tracking.response_streams == {}
        assert tracking.item_tasks == {'child': ['outer']}
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert tracking.tasks == tracking.response_streams == {}
    assert tracking.item_tasks == {'child': ['outer']}

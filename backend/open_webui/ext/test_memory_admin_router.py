from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI

from open_webui.ext import memory_admin_router
from open_webui.utils.auth import get_admin_user


def _request(embedding_function):
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(EMBEDDING_FUNCTION=embedding_function)))


def _memory(memory_id, content, path=None):
    return SimpleNamespace(
        id=memory_id,
        content=content,
        path=path,
        created_at=100,
        updated_at=200,
        type='context',
    )


def test_bulk_reset_route_has_exact_mounted_path_method_and_admin_dependency():
    app = FastAPI()
    app.include_router(memory_admin_router.router, prefix='/api/v1/memories')
    route = next(route for route in app.routes if route.path == '/api/v1/memories/reset/all')

    assert route.methods == {'POST'}
    assert any(dependency.call is get_admin_user for dependency in route.dependant.dependencies)


@pytest.mark.asyncio
async def test_bulk_reset_rebuilds_path_aware_vectors_for_admin(monkeypatch):
    embedding = AsyncMock(side_effect=[[0.1], [0.2]])
    delete_collection = AsyncMock()
    upsert = AsyncMock()
    user = SimpleNamespace(id='user-1')
    memories = [_memory('memory-1', 'first', '/work'), _memory('memory-2', 'second')]

    monkeypatch.setattr(memory_admin_router, '_candidate_user_ids', AsyncMock(return_value=['user-1']))
    monkeypatch.setattr(memory_admin_router.Users, 'get_user_by_id', AsyncMock(return_value=user))
    monkeypatch.setattr(memory_admin_router.Memories, 'get_memories_by_user_id', AsyncMock(return_value=memories))
    monkeypatch.setattr(memory_admin_router.ASYNC_VECTOR_DB_CLIENT, 'delete_collection', delete_collection)
    monkeypatch.setattr(memory_admin_router.ASYNC_VECTOR_DB_CLIENT, 'upsert', upsert)

    result = await memory_admin_router.reset_all_memory_vectors(_request(embedding), _admin_user=SimpleNamespace(role='admin'))

    assert result.model_dump() == {
        'total_candidate_users': 1,
        'succeeded': 1,
        'failed': 0,
        'skipped': 0,
        'memory_count_rebuilt': 2,
        'users': [{'user_id': 'user-1', 'status': 'succeeded', 'memory_count': 2, 'error': None}],
    }
    delete_collection.assert_awaited_once_with('user-memory-user-1')
    items = upsert.await_args.kwargs['items']
    assert [item['id'] for item in items] == ['memory-1', 'memory-2']
    assert [item['text'] for item in items] == ['work\nfirst', 'second']
    assert items[0]['metadata'] == {'created_at': 100, 'updated_at': 200, 'type': 'context', 'path': '/work'}


@pytest.mark.asyncio
async def test_bulk_reset_isolates_user_failures_and_preserves_failed_collection(monkeypatch):
    async def embedding(text, **_kwargs):
        if text == 'bad':
            raise RuntimeError('provider secret detail')
        return [0.1]

    delete_collection = AsyncMock()
    upsert = AsyncMock()
    users = {'bad-user': SimpleNamespace(id='bad-user'), 'good-user': SimpleNamespace(id='good-user')}

    monkeypatch.setattr(memory_admin_router, '_candidate_user_ids', AsyncMock(return_value=['bad-user', 'good-user']))
    monkeypatch.setattr(memory_admin_router.Users, 'get_user_by_id', AsyncMock(side_effect=users.get))
    monkeypatch.setattr(
        memory_admin_router.Memories,
        'get_memories_by_user_id',
        AsyncMock(
            side_effect=[
                [_memory('bad-memory', 'bad')],
                [_memory('good-memory', 'good')],
                [_memory('good-memory', 'good')],
            ]
        ),
    )
    monkeypatch.setattr(memory_admin_router.ASYNC_VECTOR_DB_CLIENT, 'delete_collection', delete_collection)
    monkeypatch.setattr(memory_admin_router.ASYNC_VECTOR_DB_CLIENT, 'upsert', upsert)

    result = await memory_admin_router.reset_all_memory_vectors(_request(embedding), _admin_user=SimpleNamespace(role='admin'))

    assert result.succeeded == 1
    assert result.failed == 1
    assert result.memory_count_rebuilt == 1
    assert result.users[0].error == 'Unable to rebuild memory vectors.'
    assert 'provider secret detail' not in result.users[0].error
    delete_collection.assert_awaited_once_with('user-memory-good-user')
    upsert.assert_awaited_once()


@pytest.mark.asyncio
async def test_bulk_reset_with_no_sql_memories_does_not_touch_vector_db(monkeypatch):
    embedding = AsyncMock()
    delete_collection = AsyncMock()
    upsert = AsyncMock()

    monkeypatch.setattr(memory_admin_router, '_candidate_user_ids', AsyncMock(return_value=[]))
    monkeypatch.setattr(memory_admin_router.ASYNC_VECTOR_DB_CLIENT, 'delete_collection', delete_collection)
    monkeypatch.setattr(memory_admin_router.ASYNC_VECTOR_DB_CLIENT, 'upsert', upsert)

    result = await memory_admin_router.reset_all_memory_vectors(_request(embedding), _admin_user=SimpleNamespace(role='admin'))

    assert result.model_dump() == {
        'total_candidate_users': 0,
        'succeeded': 0,
        'failed': 0,
        'skipped': 0,
        'memory_count_rebuilt': 0,
        'users': [],
    }
    embedding.assert_not_awaited()
    delete_collection.assert_not_awaited()
    upsert.assert_not_awaited()


@pytest.mark.asyncio
async def test_bulk_reset_skips_memory_rows_for_a_deleted_user(monkeypatch):
    monkeypatch.setattr(memory_admin_router, '_candidate_user_ids', AsyncMock(return_value=['deleted-user']))
    monkeypatch.setattr(memory_admin_router.Users, 'get_user_by_id', AsyncMock(return_value=None))

    result = await memory_admin_router.reset_all_memory_vectors(
        _request(AsyncMock()), _admin_user=SimpleNamespace(role='admin')
    )

    assert result.model_dump() == {
        'total_candidate_users': 1,
        'succeeded': 0,
        'failed': 0,
        'skipped': 1,
        'memory_count_rebuilt': 0,
        'users': [
            {
                'user_id': 'deleted-user',
                'status': 'skipped',
                'memory_count': 0,
                'error': 'User no longer exists.',
            }
        ],
    }


@pytest.mark.asyncio
async def test_bulk_reset_reports_sql_read_failure_without_touching_vectors(monkeypatch):
    delete_collection = AsyncMock()
    upsert = AsyncMock()

    monkeypatch.setattr(memory_admin_router, '_candidate_user_ids', AsyncMock(return_value=['user-1']))
    monkeypatch.setattr(memory_admin_router.Users, 'get_user_by_id', AsyncMock(return_value=SimpleNamespace(id='user-1')))
    monkeypatch.setattr(memory_admin_router.Memories, 'get_memories_by_user_id', AsyncMock(return_value=None))
    monkeypatch.setattr(memory_admin_router.ASYNC_VECTOR_DB_CLIENT, 'delete_collection', delete_collection)
    monkeypatch.setattr(memory_admin_router.ASYNC_VECTOR_DB_CLIENT, 'upsert', upsert)

    result = await memory_admin_router.reset_all_memory_vectors(
        _request(AsyncMock()), _admin_user=SimpleNamespace(role='admin')
    )

    assert result.failed == 1
    assert result.users[0].error == 'Unable to rebuild memory vectors.'
    delete_collection.assert_not_awaited()
    upsert.assert_not_awaited()


@pytest.mark.asyncio
async def test_bulk_reset_detects_persistent_drift_without_deleting_collection(monkeypatch):
    initial = _memory('memory-1', 'before')
    changed = _memory('memory-1', 'after')
    delete_collection = AsyncMock()

    monkeypatch.setattr(memory_admin_router, '_candidate_user_ids', AsyncMock(return_value=['user-1']))
    monkeypatch.setattr(memory_admin_router.Users, 'get_user_by_id', AsyncMock(return_value=SimpleNamespace(id='user-1')))
    monkeypatch.setattr(
        memory_admin_router.Memories,
        'get_memories_by_user_id',
        AsyncMock(side_effect=[[initial], [changed], [initial]]),
    )
    monkeypatch.setattr(memory_admin_router.ASYNC_VECTOR_DB_CLIENT, 'delete_collection', delete_collection)

    result = await memory_admin_router.reset_all_memory_vectors(
        _request(AsyncMock(return_value=[0.1])), _admin_user=SimpleNamespace(role='admin')
    )

    assert result.failed == 1
    assert result.memory_count_rebuilt == 0
    assert result.users[0].error == 'Unable to rebuild memory vectors.'
    delete_collection.assert_not_awaited()


@pytest.mark.asyncio
async def test_bulk_reset_retries_a_transient_post_delete_upsert_failure(monkeypatch):
    memory = _memory('memory-1', 'content')
    delete_collection = AsyncMock()
    upsert = AsyncMock(side_effect=[RuntimeError('transient provider error'), None])

    monkeypatch.setattr(memory_admin_router, '_candidate_user_ids', AsyncMock(return_value=['user-1']))
    monkeypatch.setattr(memory_admin_router.Users, 'get_user_by_id', AsyncMock(return_value=SimpleNamespace(id='user-1')))
    monkeypatch.setattr(memory_admin_router.Memories, 'get_memories_by_user_id', AsyncMock(return_value=[memory]))
    monkeypatch.setattr(memory_admin_router.ASYNC_VECTOR_DB_CLIENT, 'delete_collection', delete_collection)
    monkeypatch.setattr(memory_admin_router.ASYNC_VECTOR_DB_CLIENT, 'upsert', upsert)

    result = await memory_admin_router.reset_all_memory_vectors(
        _request(AsyncMock(return_value=[0.1])), _admin_user=SimpleNamespace(role='admin')
    )

    assert result.succeeded == 1
    assert result.memory_count_rebuilt == 1
    delete_collection.assert_awaited_once_with('user-memory-user-1')
    assert upsert.await_count == 2


@pytest.mark.asyncio
async def test_bulk_reset_reports_persistent_post_delete_upsert_failure(monkeypatch):
    memory = _memory('memory-1', 'content')
    delete_collection = AsyncMock()
    upsert = AsyncMock(side_effect=[RuntimeError('provider key detail'), RuntimeError('provider key detail')])

    monkeypatch.setattr(memory_admin_router, '_candidate_user_ids', AsyncMock(return_value=['user-1']))
    monkeypatch.setattr(memory_admin_router.Users, 'get_user_by_id', AsyncMock(return_value=SimpleNamespace(id='user-1')))
    monkeypatch.setattr(memory_admin_router.Memories, 'get_memories_by_user_id', AsyncMock(return_value=[memory]))
    monkeypatch.setattr(memory_admin_router.ASYNC_VECTOR_DB_CLIENT, 'delete_collection', delete_collection)
    monkeypatch.setattr(memory_admin_router.ASYNC_VECTOR_DB_CLIENT, 'upsert', upsert)

    result = await memory_admin_router.reset_all_memory_vectors(
        _request(AsyncMock(return_value=[0.1])), _admin_user=SimpleNamespace(role='admin')
    )

    assert result.failed == 1
    assert result.memory_count_rebuilt == 0
    assert result.users[0].error == 'Unable to rebuild memory vectors.'
    assert 'provider key detail' not in result.users[0].error
    delete_collection.assert_awaited_once_with('user-memory-user-1')
    assert upsert.await_count == 2

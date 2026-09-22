from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from open_webui.models.memories import MemoryModel
from open_webui.routers import memories


def _memory(meta=None):
    return MemoryModel(
        id='memory-id',
        user_id='user-id',
        content='Remember this',
        type='user',
        path='/preferences',
        meta=meta or {},
        created_at=100,
        updated_at=200,
    )


def _request(model=None, embedding=None):
    return SimpleNamespace(
        state=SimpleNamespace(metadata={'model': model}),
        app=SimpleNamespace(state=SimpleNamespace(EMBEDDING_FUNCTION=embedding or AsyncMock(return_value=[0.1]))),
    )


@pytest.mark.asyncio
async def test_memory_import_preserves_metadata_timestamps_and_full_result(monkeypatch):
    applied_operations = []

    async def apply_operations(user_id, operations):
        applied_operations.extend(operations)
        return [{'status': 'created', 'action': 'add', 'memory': _memory({'legacy': 'value'})}]

    monkeypatch.setattr(memories, 'check_memories_permission', AsyncMock())
    monkeypatch.setattr(memories.Memories, 'apply_memory_operations', apply_operations)
    monkeypatch.setattr(memories.ASYNC_VECTOR_DB_CLIENT, 'upsert', AsyncMock())
    monkeypatch.setattr(memories, 'publish_event', AsyncMock())

    response = await memories.update_memories(
        _request(),
        memories.UpdateMemoriesForm(
            source='import',
            operations=[
                {
                    'action': 'add',
                    'content': 'Remember this',
                    'type': 'user',
                    'meta': {'legacy': 'value'},
                    'created_at': 100,
                    'updated_at': 200,
                }
            ],
        ),
        SimpleNamespace(id='user-id', role='user'),
    )

    assert applied_operations[0]['meta'] == {'legacy': 'value', 'created_by': 'import'}
    assert applied_operations[0]['created_at'] == 100
    assert applied_operations[0]['updated_at'] == 200
    assert response[0]['memory']['meta'] == {'legacy': 'value'}
    assert response[0]['memory']['created_at'] == 100


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('model', 'expected_model'),
    [({'id': 'deployment-id'}, 'deployment-id'), ('scalar-model', 'scalar-model')],
)
async def test_memory_update_normalizes_object_model_without_dropping_scalar(monkeypatch, model, expected_model):
    applied_operations = []

    async def apply_operations(user_id, operations):
        applied_operations.extend(operations)
        return []

    monkeypatch.setattr(memories, 'check_memories_permission', AsyncMock())
    monkeypatch.setattr(memories.Memories, 'apply_memory_operations', apply_operations)

    await memories.update_memories(
        _request(model=model),
        memories.UpdateMemoriesForm(source='tool', operations=[{'action': 'add', 'content': 'Remember this'}]),
        SimpleNamespace(id='user-id', role='user'),
    )

    assert applied_operations[0]['meta']['model'] == expected_model


@pytest.mark.asyncio
async def test_memory_import_rolls_back_created_rows_after_vector_failure(monkeypatch):
    created = _memory()
    apply_operations = AsyncMock(side_effect=[[{'status': 'created', 'action': 'add', 'memory': created}], []])
    monkeypatch.setattr(memories, 'check_memories_permission', AsyncMock())
    monkeypatch.setattr(memories.Memories, 'apply_memory_operations', apply_operations)
    monkeypatch.setattr(memories, 'publish_event', AsyncMock())
    vector_delete = AsyncMock()
    monkeypatch.setattr(memories.ASYNC_VECTOR_DB_CLIENT, 'delete', vector_delete)

    async def embedding_failure(*args, **kwargs):
        raise RuntimeError('embedding failure')

    with pytest.raises(RuntimeError, match='embedding failure'):
        await memories.update_memories(
            _request(embedding=embedding_failure),
            memories.UpdateMemoriesForm(source='import', operations=[{'action': 'add', 'content': 'Remember this'}]),
            SimpleNamespace(id='user-id', role='user'),
        )

    assert apply_operations.await_args_list[1].args == (
        'user-id',
        [{'action': 'remove', 'id': 'memory-id'}],
    )
    vector_delete.assert_awaited_once_with(collection_name='user-memory-user-id', ids=['memory-id'])

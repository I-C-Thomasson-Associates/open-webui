"""Admin-only bulk repair for per-user memory vector collections."""

from __future__ import annotations

import asyncio
import logging
from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import select

from open_webui.config import RAG_EMBEDDING_CONTENT_PREFIX
from open_webui.internal.db import get_async_db_context
from open_webui.models.memories import Memory, Memories, MemoryModel
from open_webui.models.users import Users
from open_webui.retrieval.vector.async_client import ASYNC_VECTOR_DB_CLIENT
from open_webui.utils.auth import get_admin_user
from open_webui.utils.memory import memory_vector_text

log = logging.getLogger(__name__)
router = APIRouter()

_REBUILD_ERROR = 'Unable to rebuild memory vectors.'
_MISSING_USER_ERROR = 'User no longer exists.'


class MemorySqlReadError(RuntimeError):
    """The memory repository did not return a SQL result."""


class MemorySnapshotChangedError(RuntimeError):
    """Memory rows changed while vectors were being generated."""


class MemoryVectorUpsertError(RuntimeError):
    """The rebuilt vector collection could not be populated after deletion."""


class MemoryRebuildUserResult(BaseModel):
    user_id: str
    status: Literal['succeeded', 'failed', 'skipped']
    memory_count: int = 0
    error: str | None = None


class MemoryRebuildSummary(BaseModel):
    total_candidate_users: int
    succeeded: int
    failed: int
    skipped: int
    memory_count_rebuilt: int
    users: list[MemoryRebuildUserResult]


async def _candidate_user_ids() -> list[str]:
    """Return only user IDs which currently have persisted memory rows."""
    async with get_async_db_context() as db:
        result = await db.execute(select(Memory.user_id).where(Memory.user_id.is_not(None)).distinct())
        return list(result.scalars().all())


def _memory_metadata(memory: MemoryModel) -> dict:
    return {
        'created_at': memory.created_at,
        'updated_at': memory.updated_at,
        'type': memory.type,
        'path': memory.path,
    }


def _memory_snapshot(memories: list[MemoryModel]) -> tuple[tuple, ...]:
    """Stable comparison view of every field used by a memory vector item."""
    return tuple(
        sorted(
            (
                memory.id,
                memory.content,
                memory.path,
                memory.type,
                memory.created_at,
                memory.updated_at,
            )
            for memory in memories
        )
    )


async def _rebuild_user_memory_vectors(request: Request, user, memories: list[MemoryModel]) -> int | None:
    """Rebuild one collection with one optimistic retry if SQL rows drift."""
    for attempt in range(2):
        vector_texts = [memory_vector_text(memory.content, memory.path) for memory in memories]
        vectors = await asyncio.gather(
            *[
                request.app.state.EMBEDDING_FUNCTION(
                    vector_text,
                    prefix=RAG_EMBEDDING_CONTENT_PREFIX,
                    user=user,
                )
                for vector_text in vector_texts
            ]
        )

        # This is optimistic drift detection, not a cross-process transaction.
        # It prevents a known concurrent SQL update from deleting a collection
        # built from stale rows, but another process can still write after this read.
        current_memories = await Memories.get_memories_by_user_id(user.id)
        if current_memories is None:
            raise MemorySqlReadError('Could not re-read memory rows before vector replacement')
        if _memory_snapshot(memories) != _memory_snapshot(current_memories):
            log.warning('Memory rows changed while rebuilding vectors for user %s', user.id)
            if attempt == 0:
                memories = current_memories
                if not memories:
                    return None
                continue
            raise MemorySnapshotChangedError('Memory rows remained unstable during vector rebuild')

        collection_name = f'user-memory-{user.id}'
        items = [
            {
                'id': memory.id,
                'text': vector_texts[index],
                'vector': vectors[index],
                'metadata': _memory_metadata(memory),
            }
            for index, memory in enumerate(memories)
        ]
        await ASYNC_VECTOR_DB_CLIENT.delete_collection(collection_name)
        try:
            await ASYNC_VECTOR_DB_CLIENT.upsert(collection_name=collection_name, items=items)
        except Exception:
            # The vector facade has no transactional collection swap. Retry the
            # same fully-generated payload once without another deletion.
            log.exception('Memory vector upsert failed after collection deletion for user %s; retrying once', user.id)
            try:
                await ASYNC_VECTOR_DB_CLIENT.upsert(collection_name=collection_name, items=items)
            except Exception as retry_error:
                log.exception('Memory vector upsert retry failed for user %s', user.id)
                raise MemoryVectorUpsertError('Could not repopulate vector collection') from retry_error
            else:
                log.info('Memory vector upsert retry succeeded for user %s', user.id)
        return len(memories)

    raise AssertionError('Memory rebuild retry loop exited unexpectedly')


@router.post('/reset/all', response_model=MemoryRebuildSummary)
async def reset_all_memory_vectors(
    request: Request,
    _admin_user=Depends(get_admin_user),
):
    """Rebuild all extant users' memory collections, isolating each user failure."""
    user_ids = await _candidate_user_ids()
    results: list[MemoryRebuildUserResult] = []
    succeeded = failed = skipped = memory_count_rebuilt = 0

    # Intentionally sequential across users: each user may embed concurrently,
    # but this bounds total embedding-provider load for the administrative run.
    for user_id in user_ids:
        try:
            user = await Users.get_user_by_id(user_id)
            if user is None:
                skipped += 1
                results.append(
                    MemoryRebuildUserResult(
                        user_id=user_id,
                        status='skipped',
                        error=_MISSING_USER_ERROR,
                    )
                )
                continue

            memories = await Memories.get_memories_by_user_id(user_id)
            if memories is None:
                log.error('Could not read SQL memory rows for user %s', user_id)
                raise MemorySqlReadError('Could not read memory rows')
            if not memories:
                skipped += 1
                results.append(MemoryRebuildUserResult(user_id=user_id, status='skipped'))
                continue

            memory_count = await _rebuild_user_memory_vectors(request, user, memories)
            if memory_count is None:
                skipped += 1
                results.append(MemoryRebuildUserResult(user_id=user_id, status='skipped'))
                continue
            succeeded += 1
            memory_count_rebuilt += memory_count
            results.append(
                MemoryRebuildUserResult(
                    user_id=user_id,
                    status='succeeded',
                    memory_count=memory_count,
                )
            )
        except Exception:
            log.exception('Failed to rebuild memory vectors for user %s', user_id)
            failed += 1
            results.append(
                MemoryRebuildUserResult(
                    user_id=user_id,
                    status='failed',
                    error=_REBUILD_ERROR,
                )
            )

    return MemoryRebuildSummary(
        total_candidate_users=len(user_ids),
        succeeded=succeeded,
        failed=failed,
        skipped=skipped,
        memory_count_rebuilt=memory_count_rebuilt,
        users=results,
    )

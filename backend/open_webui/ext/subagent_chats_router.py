"""Owner-only list of hidden Sub Agent child chats for one parent chat."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import and_, func, select

from open_webui.internal.db import get_async_db_context
from open_webui.models.chats import Chat
from open_webui.utils.auth import get_verified_user

router = APIRouter()

_DEFAULT_TITLE = 'New Chat'
_MAX_TITLE_LENGTH = 200  # UTF-16 code units


def _canonical_uuid(value: str) -> bool:
    try:
        return str(UUID(value)) == value
    except (ValueError, AttributeError, TypeError):
        return False


def _internal_is_json_true(dialect_name: str):
    # as_boolean() casts text (SQLite 'true'/'yes', PG CAST ... AS BOOLEAN); require a real JSON true instead.
    # ponytail: Chat.meta is sa.JSON (PG `json`, not `jsonb`); switch to jsonb_typeof if the column type changes.
    if dialect_name == 'sqlite':
        return func.json_type(Chat.meta, '$.internal') == 'true'
    if dialect_name == 'postgresql':
        return and_(func.json_typeof(Chat.meta['internal']) == 'boolean', Chat.meta['internal'].as_string() == 'true')
    raise NotImplementedError(f'Unsupported dialect: {dialect_name}')


def _title(value: str | None) -> str:
    # Frontend checks JS string length (UTF-16 units); cut there, dropping any split surrogate pair.
    units = (value or '').strip().encode('utf-16-le', 'surrogatepass')[: _MAX_TITLE_LENGTH * 2]
    return units.decode('utf-16-le', 'ignore') or _DEFAULT_TITLE


@router.get('/{parent_id}')
async def get_subagent_chats(parent_id: str, user=Depends(get_verified_user)):
    """Return [{chatId, title}] for the current user's child chats, oldest first. No transcript data is read."""
    not_found = HTTPException(status_code=404, detail='Not found')
    if not _canonical_uuid(parent_id):
        raise not_found

    async with get_async_db_context() as db:
        parent = await db.execute(select(Chat.id).where(Chat.id == parent_id, Chat.user_id == user.id))
        if parent.first() is None:
            raise not_found

        rows = await db.execute(
            select(Chat.id, Chat.title)
            .where(
                Chat.user_id == user.id,
                _internal_is_json_true(db.bind.dialect.name),
                Chat.meta['type'].as_string() == 'subagent',
                Chat.meta['source'].as_string() == 'ai_team_delegate',
                Chat.meta['parent_chat_id'].as_string() == parent_id,
            )
            .order_by(Chat.created_at, Chat.id)
        )

    return [{'chatId': chat_id, 'title': _title(title)} for chat_id, title in rows.all() if _canonical_uuid(chat_id)]

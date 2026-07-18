"""Salas O'Brien-specific endpoints. Reads from the chat_message table."""

import base64
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from open_webui.internal.db import get_async_session
from open_webui.models.chat_messages import ChatMessage
from open_webui.models.chats import Chat
from open_webui.models.groups import Group, GroupMember, Groups
from open_webui.models.models import Model
from open_webui.models.users import User
from open_webui.utils.auth import get_admin_user
from open_webui.utils.salasobrien_cost import (
    load_foundry_rates,
    load_litellm_rates,
    resolve_cost,
    strip_connection_prefix,
)

log = logging.getLogger(__name__)


router = APIRouter()


MAX_WINDOW_SECONDS = 366 * 86400
DEFAULT_LIMIT = 10_000
MAX_LIMIT = 100_000


####################
# Response Models
####################


class AnalyticsRow(BaseModel):
    timestamp: int
    chat_id: str
    chat_title: Optional[str] = None
    user_id: str
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    business_unit: Optional[str] = None
    model: Optional[str] = None
    model_name: Optional[str] = None
    backend: Optional[str] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    cost_usd: Optional[float] = None


class AnalyticsResponse(BaseModel):
    rows: list[AnalyticsRow]
    next_cursor: Optional[str] = None


####################
# Helpers
####################


def _coerce_int(v) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _encode_cursor(created_at: int, row_id: str) -> str:
    raw = f'{created_at}:{row_id}'.encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def _decode_cursor(cursor: str) -> tuple[int, str]:
    padding = '=' * (-len(cursor) % 4)
    raw = base64.urlsafe_b64decode(cursor + padding).decode()
    created_at_str, row_id = raw.split(':', 1)
    return int(created_at_str), row_id


def _resolve_pricing_model_id(
    model_id: Optional[str],
    base_model_id: Optional[str],
) -> Optional[str]:
    """Pick the id used for rate-based pricing.

    Custom agents log under their own id (e.g. 'ai-team-submittal-reviewer'),
    which carries no pricing info, so substitute their base model. Direct
    base-model rows have no base_model_id and pass through unchanged.
    """
    if base_model_id:
        return base_model_id
    return model_id


####################
# Endpoints
####################


@router.get('/analytics', response_model=AnalyticsResponse)
async def get_analytics(
    start: int = Query(..., description='Start timestamp (epoch seconds, inclusive)'),
    end: int = Query(..., description='End timestamp (epoch seconds, exclusive)'),
    group: Optional[str] = Query(None, description='Filter by business unit (group name)'),
    cursor: Optional[str] = Query(None, description='Opaque cursor from previous response next_cursor'),
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT, description='Max rows per page'),
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Per-message AI usage rows with business-unit attribution for Power BI."""
    if end <= start:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='end must be greater than start',
        )
    if end - start > MAX_WINDOW_SECONDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='time window must not exceed 366 days',
        )

    cur_created_at: Optional[int] = None
    cur_id: Optional[str] = None
    if cursor is not None:
        try:
            cur_created_at, cur_id = _decode_cursor(cursor)
        except (ValueError, TypeError, UnicodeDecodeError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='invalid cursor',
            )

    user_ids: Optional[list[str]] = None
    if group is not None:
        group_filter_stmt = (
            select(GroupMember.user_id)
            .join(Group, Group.id == GroupMember.group_id)
            .filter(Group.name == group)
        )
        result = await db.execute(group_filter_stmt)
        user_ids = [row[0] for row in result.all()]
        if not user_ids:
            return AnalyticsResponse(rows=[], next_cursor=None)

    stmt = (
        select(
            ChatMessage.id,
            ChatMessage.created_at,
            ChatMessage.chat_id,
            Chat.title.label('chat_title'),
            ChatMessage.user_id,
            User.email.label('user_email'),
            User.name.label('user_name'),
            ChatMessage.model_id,
            Model.name.label('model_name'),
            Model.base_model_id.label('base_model_id'),
            ChatMessage.usage,
        )
        .join(Chat, Chat.id == ChatMessage.chat_id)
        .join(User, User.id == ChatMessage.user_id)
        .outerjoin(Model, Model.id == ChatMessage.model_id)
        .filter(
            ChatMessage.role == 'assistant',
            ChatMessage.usage.isnot(None),
            ChatMessage.created_at >= start,
            ChatMessage.created_at < end,
        )
        .order_by(ChatMessage.created_at.asc(), ChatMessage.id.asc())
        .limit(limit + 1)
    )
    if user_ids is not None:
        stmt = stmt.filter(ChatMessage.user_id.in_(user_ids))
    if cur_created_at is not None:
        stmt = stmt.filter(
            or_(
                ChatMessage.created_at > cur_created_at,
                and_(
                    ChatMessage.created_at == cur_created_at,
                    ChatMessage.id > cur_id,
                ),
            )
        )

    rows = (await db.execute(stmt)).all()
    has_more = len(rows) > limit
    if has_more:
        rows = rows[:limit]

    if not rows:
        return AnalyticsResponse(rows=[], next_cursor=None)

    next_cursor: Optional[str] = None
    if has_more:
        last = rows[-1]
        next_cursor = _encode_cursor(int(last.created_at), last.id)

    foundry_rates = load_foundry_rates()
    litellm_rates = await load_litellm_rates()

    distinct_user_ids = list({row.user_id for row in rows})
    user_groups_map = await Groups.get_groups_by_member_ids(distinct_user_ids, db=db)

    user_business_unit: dict[str, Optional[str]] = {}
    for uid, groups in user_groups_map.items():
        if not groups:
            user_business_unit[uid] = None
        elif len(groups) == 1:
            user_business_unit[uid] = groups[0].name
        else:
            names = sorted(g.name for g in groups)
            log.warning(
                'user %s has %d groups, using first alphabetically: %s',
                uid,
                len(groups),
                names[0],
            )
            user_business_unit[uid] = names[0]

    result_rows: list[AnalyticsRow] = []
    litellm_backends = litellm_rates.get('backend', {})
    for row in rows:
        usage = row.usage or {}
        prompt_tokens = _coerce_int(usage.get('prompt_tokens', usage.get('input_tokens')))
        completion_tokens = _coerce_int(
            usage.get('completion_tokens', usage.get('output_tokens'))
        )
        total_tokens = _coerce_int(usage.get('total_tokens'))

        # Deployment id captured from LiteLLM's x-litellm-model-id header (when
        # present) lets us price by the exact backend and label its source.
        deployment_id = usage.get('litellm_model_id') if isinstance(usage, dict) else None

        # PRICING: agents log under their own id (no pricing info); resolve to
        # the base model. resolve_cost tries inline cost -> exact deployment ->
        # model-name rate -> frozen Key Vault book.
        pricing_model_id = _resolve_pricing_model_id(row.model_id, row.base_model_id)
        cost_usd = resolve_cost(
            pricing_model_id,
            usage,
            litellm_rates,
            foundry_rates,
            deployment_id=deployment_id,
        )

        # DISPLAY: strip only the connection prefix so base models merge across
        # the migration (FOUNDRY.gpt-5.4 and LITELLM.gpt-5.4 -> gpt-5.4). Custom
        # agents carry no connection prefix, so they stay distinct lines.
        display_model = strip_connection_prefix(row.model_id) or row.model_id
        backend = litellm_backends.get(deployment_id) if deployment_id else None

        result_rows.append(
            AnalyticsRow(
                timestamp=int(row.created_at),
                chat_id=row.chat_id,
                chat_title=row.chat_title,
                user_id=row.user_id,
                user_email=row.user_email,
                user_name=row.user_name,
                business_unit=user_business_unit.get(row.user_id),
                model=display_model,
                model_name=row.model_name or display_model,
                backend=backend,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                cost_usd=cost_usd,
            )
        )

    return AnalyticsResponse(rows=result_rows, next_cursor=next_cursor)
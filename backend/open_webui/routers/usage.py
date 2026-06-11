"""Self-serve usage endpoint backed by the rate-limiting filter's Redis counters."""

import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from open_webui.models.groups import Groups
from open_webui.utils.auth import get_verified_user
from open_webui.utils.redis import get_redis_client
from open_webui.utils.usage_limits import (
    EXEMPT_GROUPS,
    get_month_bucket_and_ttl,
    load_tiers,
    monthly_cost_key,
    resolve_division,
    resolve_tier_cap,
)

log = logging.getLogger(__name__)

router = APIRouter()


class UserUsageResponse(BaseModel):
    # Percentage of the monthly tier cap used, capped at 100; None when no
    # cap is resolvable. Dollar amounts are deliberately not exposed --
    # user-facing messaging matches the rate-limiting filter's toasts.
    percent: Optional[int] = None
    tier: Optional[str] = None
    month: str
    reset_at: int
    exempt: bool = False


@router.get('/', response_model=UserUsageResponse)
async def get_user_usage(user=Depends(get_verified_user)):
    """Current user's monthly usage as a percentage of their tier cap."""
    now = int(time.time())
    bucket, ttl = get_month_bucket_and_ttl(now)
    reset_at = now + ttl

    groups = await Groups.get_groups_by_member_id(user.id)
    group_names = [g.name for g in groups if g.name]
    if user.role == 'admin':
        group_names.append('admin')

    if any(g.strip().lower() in EXEMPT_GROUPS for g in group_names):
        return UserUsageResponse(month=bucket, reset_at=reset_at, exempt=True)

    redis = get_redis_client(async_mode=True)
    if redis is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='Usage data is currently unavailable',
        )
    try:
        val = await redis.get(monthly_cost_key(user.id, bucket))
    except Exception as e:
        log.warning('failed to read usage counter for %s: %s', user.id, e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='Usage data is currently unavailable',
        )
    used_microusd = int(val) if val else 0

    percent = None
    tier = None
    all_tiers = load_tiers()
    if all_tiers:
        resolved = resolve_tier_cap(
            group_names, all_tiers, resolve_division(group_names, all_tiers)
        )
        if resolved:
            tier, cap_usd = resolved
            percent = min(
                100, (used_microusd * 100) // int(round(cap_usd * 1_000_000))
            )

    return UserUsageResponse(percent=percent, tier=tier, month=bucket, reset_at=reset_at)

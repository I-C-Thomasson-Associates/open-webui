"""Read-side mirror of the Rate Limiting Filter's monthly cost tracking.

The filter (OWUI function `rate_limiting_filter`) writes per-user monthly
cost counters to Redis and resolves tier caps from the RATE-LIMIT-TIERS
Key Vault secret. The key format and tier schema here must stay in sync
with the filter.
"""

import json
import logging
from datetime import datetime
from typing import Optional
from zoneinfo import ZoneInfo

from open_webui.secrets import get_secret_uncached

log = logging.getLogger(__name__)

# Must match the filter's redis_key_prefix valve (default 'ratelimit:').
REDIS_KEY_PREFIX = 'ratelimit:'
# Key Vault secret RATE-LIMIT-TIERS (secrets.py converts underscores to hyphens).
TIERS_SECRET_KEY = 'RATE_LIMIT_TIERS'
# Must match the filter's exempt_groups valve (default 'admin,Admins').
EXEMPT_GROUPS = {'admin', 'admins'}


def get_month_bucket_and_ttl(now: int) -> tuple[str, int]:
    """Return (YYYYMM bucket, seconds until first of next month CT)."""
    try:
        tz = ZoneInfo('America/Chicago')
        now_local = datetime.fromtimestamp(now, tz=tz)
        bucket = f'{now_local.year:04d}{now_local.month:02d}'
        if now_local.month == 12:
            next_start = datetime(now_local.year + 1, 1, 1, tzinfo=tz)
        else:
            next_start = datetime(now_local.year, now_local.month + 1, 1, tzinfo=tz)
        return bucket, max(1, int(next_start.timestamp()) - now)
    except Exception:
        now_utc = datetime.utcfromtimestamp(now)
        bucket = f'{now_utc.year:04d}{now_utc.month:02d}'
        if now_utc.month == 12:
            next_start = datetime(now_utc.year + 1, 1, 1)
        else:
            next_start = datetime(now_utc.year, now_utc.month + 1, 1)
        return bucket, max(1, int((next_start - now_utc).total_seconds()))


def monthly_cost_key(user_id: str, bucket: str) -> str:
    return f'{REDIS_KEY_PREFIX}user:{user_id}:cost_microusd:month:{bucket}'


def _normalize_tier_dict(raw: dict) -> dict[str, tuple[str, float]]:
    out: dict[str, tuple[str, float]] = {}
    for name, value in raw.items():
        try:
            cap = float(value)
        except (TypeError, ValueError):
            continue
        if cap > 0:
            display = str(name).strip()
            out[display.lower()] = (display, cap)
    return out


def load_tiers() -> Optional[dict[str, dict[str, tuple[str, float]]]]:
    """Return {division_lower: {tier_lower: (display_name, cap_usd)}} or None.

    Accepts both the flat legacy schema and the nested-by-division schema,
    same as the filter.
    """
    raw = get_secret_uncached(TIERS_SECRET_KEY, '')
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError) as e:
        log.warning('tiers secret is not valid JSON: %s', e)
        return None
    if not isinstance(parsed, dict) or not parsed:
        return None

    # Flat schema: any numeric top-level value -> single 'default' division
    if any(isinstance(v, (int, float)) for v in parsed.values()):
        flat = _normalize_tier_dict(parsed)
        return {'default': flat} if flat else None

    out: dict[str, dict[str, float]] = {}
    for division, tier_dict in parsed.items():
        if isinstance(tier_dict, dict):
            normalized = _normalize_tier_dict(tier_dict)
            if normalized:
                out[str(division).strip().lower()] = normalized
    return out or None


def resolve_division(
    group_names: list[str], all_tiers: dict[str, dict[str, tuple[str, float]]]
) -> Optional[str]:
    """Match a BU group prefix (text before the first hyphen) to a division key."""
    tier_names: set[str] = set()
    for tier_dict in all_tiers.values():
        tier_names.update(tier_dict.keys())

    division_keys = set(all_tiers.keys()) - {'default'}
    if not division_keys:
        return None

    for group in group_names:
        g = (group or '').strip().lower()
        if not g or g in tier_names:
            continue
        prefix = g.split('-', 1)[0].strip()
        if prefix and prefix in division_keys:
            return prefix
    return None


def resolve_tier_cap(
    group_names: list[str],
    all_tiers: dict[str, dict[str, tuple[str, float]]],
    division: Optional[str],
) -> Optional[tuple[str, float]]:
    """Return (tier_display_name, monthly_cap_usd); lowest tier when no group matches."""
    if division and division in all_tiers:
        tier_dict = all_tiers[division]
    elif 'default' in all_tiers:
        tier_dict = all_tiers['default']
    else:
        tier_dict = next(iter(all_tiers.values()))
    if not tier_dict:
        return None

    groups_lower = {g.strip().lower() for g in group_names if g and g.strip()}
    matched = [tier for name, tier in tier_dict.items() if name in groups_lower]
    if matched:
        return max(matched, key=lambda t: t[1])
    return min(tier_dict.values(), key=lambda t: t[1])

"""Per-message cost resolution for Salas O'Brien analytics.

OpenRouter returns `cost` in the usage block; Azure Foundry does not, so
Foundry costs are computed from token counts × FOUNDRY_RATES. Update rates
from the Azure portal pricing tab when they change.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

log = logging.getLogger(__name__)


####################
# Rate Table
####################

# USD per million tokens, Standard Global pricing. Verified 2026-04.
FOUNDRY_RATES: dict[str, dict[str, float]] = {
    'gpt-5.5': {
        'input': 5.00,
        'cached_input': 0.50,
        'output': 30.00,
    },
    # gpt-5.4 has tiered pricing above 272K input tokens.
    'gpt-5.4': {
        'input': 2.50,
        'cached_input': 0.25,
        'output': 15.00,
        'input_long': 5.00,
        'cached_input_long': 0.50,
        'output_long': 22.50,
    },
    'gpt-5.4-mini': {
        'input': 0.75,
        'cached_input': 0.08,
        'output': 4.50,
    },
    'gpt-5.3-chat': {
        'input': 1.75,
        'cached_input': 0.18,
        'output': 14.00,
    },
    # DeepSeek V3.2: no separate cached-input rate published.
    'deepseek-v3.2': {
        'input': 0.58,
        'cached_input': 0.58,
        'output': 1.68,
    },
}

GPT_5_4_TIER_THRESHOLD = 272_000


####################
# Helpers
####################


def _coerce_int(value: Any) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _coerce_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_model_id(model_id: Optional[str]) -> Optional[str]:
    if not model_id or not isinstance(model_id, str):
        return None

    cleaned = model_id.strip().lstrip('_').strip()
    if not cleaned:
        return None

    lowered = cleaned.lower()
    if not lowered.startswith('foundry.'):
        return None

    canonical = lowered[len('foundry.'):]
    return canonical if canonical else None


def _foundry_cost(canonical_id: str, usage: dict) -> Optional[float]:
    rates = FOUNDRY_RATES.get(canonical_id)
    if rates is None:
        return None

    prompt_tokens = _coerce_int(usage.get('prompt_tokens') or usage.get('input_tokens'))
    completion_tokens = _coerce_int(
        usage.get('completion_tokens') or usage.get('output_tokens')
    )

    if prompt_tokens == 0 and completion_tokens == 0:
        return None

    cached_tokens = 0
    prompt_details = usage.get('prompt_tokens_details')
    if isinstance(prompt_details, dict):
        cached_tokens = _coerce_int(prompt_details.get('cached_tokens'))
    if cached_tokens > prompt_tokens:
        cached_tokens = prompt_tokens
    non_cached_prompt = prompt_tokens - cached_tokens

    use_long_tier = (
        canonical_id == 'gpt-5.4'
        and prompt_tokens > GPT_5_4_TIER_THRESHOLD
        and 'input_long' in rates
    )
    input_rate = rates['input_long'] if use_long_tier else rates['input']
    cached_rate = rates['cached_input_long'] if use_long_tier else rates['cached_input']
    output_rate = rates['output_long'] if use_long_tier else rates['output']

    cost = (
        non_cached_prompt * input_rate
        + cached_tokens * cached_rate
        + completion_tokens * output_rate
    ) / 1_000_000.0

    return round(cost, 6)


####################
# Public API
####################


def resolve_cost(model_id: Optional[str], usage: Any) -> Optional[float]:
    """Resolve USD cost for an assistant message; None if no rate available."""
    if not isinstance(usage, dict):
        return None

    if 'cost' in usage:
        provider_cost = _coerce_float(usage.get('cost'))
        if provider_cost is not None:
            return provider_cost

    canonical = _normalize_model_id(model_id)
    if canonical is None:
        return None

    return _foundry_cost(canonical, usage)

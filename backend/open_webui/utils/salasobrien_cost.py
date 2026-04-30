"""Per-message cost resolution for Salas O'Brien analytics.

OpenRouter returns `cost` in the usage block; Azure Foundry does not, so
Foundry costs are computed from token counts × rates loaded on every call
from Key Vault secret `FOUNDRY-MODEL-RATES`.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from open_webui.secrets import get_secret_uncached

log = logging.getLogger(__name__)


FOUNDRY_RATES_SECRET_KEY = 'FOUNDRY_MODEL_RATES'


####################
# Rate Loading
####################


def load_foundry_rates() -> dict[str, dict[str, float]]:
    """Fetch the Foundry rate table from Key Vault. Empty dict on any failure."""
    raw = get_secret_uncached(FOUNDRY_RATES_SECRET_KEY, '')
    if not raw:
        log.warning('foundry rates secret %s is empty or missing', FOUNDRY_RATES_SECRET_KEY)
        return {}
    try:
        rates = json.loads(raw)
    except (TypeError, ValueError) as e:
        log.warning('foundry rates secret is not valid JSON: %s', e)
        return {}
    if not isinstance(rates, dict):
        log.warning('foundry rates secret must be a JSON object, got %s', type(rates).__name__)
        return {}
    return rates


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


def _foundry_cost(
    canonical_id: str,
    usage: dict,
    foundry_rates: dict[str, dict[str, float]],
) -> Optional[float]:
    rates = foundry_rates.get(canonical_id)
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

    # Tiered pricing: rate entry can declare a `tier_threshold` and `*_long` rates.
    threshold = rates.get('tier_threshold')
    use_long_tier = (
        isinstance(threshold, (int, float))
        and prompt_tokens > threshold
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


def resolve_cost(
    model_id: Optional[str],
    usage: Any,
    foundry_rates: dict[str, dict[str, float]],
) -> Optional[float]:
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

    return _foundry_cost(canonical, usage, foundry_rates)

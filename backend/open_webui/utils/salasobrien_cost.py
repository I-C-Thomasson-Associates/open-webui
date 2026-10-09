"""Per-message cost resolution for Salas O'Brien analytics.

The cost of record is the one LiteLLM computes for each call. With
`include_cost_in_streaming_usage` enabled, LiteLLM adds it to the usage block and
`merge_usage` sums it across a tool loop into `usage['cost']`. Rows without it
(history, non-streamed calls) are estimated from LiteLLM's `/v1/model/info`
prices -- by the exact deployment when its `x-litellm-model-id` was captured,
otherwise by model name -- then the frozen Key Vault `FOUNDRY-MODEL-RATES` book.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

import httpx

from open_webui.secrets import get_secret_uncached

log = logging.getLogger(__name__)


FOUNDRY_RATES_SECRET_KEY = 'FOUNDRY_MODEL_RATES'
LITELLM_BASE_URL = os.environ.get('LITELLM_BASE_URL', 'http://litellm:4000')
LITELLM_API_KEY = os.environ.get('LITELLM_API_KEY', '')

# Connection prefixes OWUI prepends to model ids (compound first). Peeled to
# recover the base id used as the pricing key. Base ids contain dots, so we
# strip known prefixes only -- never split on '.'.
_CONNECTION_PREFIXES = (
    'foundry.responses.',
    'litellm.responses.',
    'litellm.chat.',
    'litellm.',
    'foundry.',
    'openrouter.',
    'azureai.',
)


####################
# Rate loading
####################


def load_foundry_rates() -> dict[str, dict[str, float]]:
    """Frozen Key Vault historical price book. Empty dict on any failure."""
    raw = get_secret_uncached(FOUNDRY_RATES_SECRET_KEY, '')
    if not raw:
        return {}
    try:
        rates = json.loads(raw)
    except (TypeError, ValueError) as e:
        log.warning('foundry rates secret is not valid JSON: %s', e)
        return {}
    return rates if isinstance(rates, dict) else {}


async def load_litellm_rates() -> dict[str, dict]:
    """Fetch `/v1/model/info` and return price maps.

    Returns ``{'by_name': {model_name: rates}, 'by_id': {deployment_id: rates},
    'backend': {deployment_id: label}}`` -- empty maps on any failure so callers
    fall back to inline cost / the Key Vault book (fail-open).
    """
    empty: dict[str, dict] = {'by_name': {}, 'by_id': {}, 'backend': {}}
    headers = {'Authorization': f'Bearer {LITELLM_API_KEY}'} if LITELLM_API_KEY else {}
    url = f"{LITELLM_BASE_URL.rstrip('/')}/v1/model/info"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            payload = resp.json()
    except Exception as e:
        log.warning('litellm /model/info fetch failed: %s', e)
        return empty

    data = payload.get('data') if isinstance(payload, dict) else None
    if not isinstance(data, list):
        return empty

    by_name: dict[str, dict] = {}
    by_id: dict[str, dict] = {}
    backend: dict[str, str] = {}
    for entry in data:
        if not isinstance(entry, dict):
            continue
        model_info = entry.get('model_info')
        if not isinstance(model_info, dict):
            continue
        rates = _convert_litellm_rates(model_info)
        if not rates:
            continue
        name = str(entry.get('model_name') or '').strip().lower()
        if name:
            by_name[name] = rates
        deployment_id = model_info.get('id')
        if deployment_id:
            by_id[str(deployment_id)] = rates
            backend[str(deployment_id)] = _backend_label(model_info.get('litellm_provider'))
    return {'by_name': by_name, 'by_id': by_id, 'backend': backend}


def _backend_label(provider: Any) -> str:
    """Human label for the provider that served a deployment (PowerBI source)."""
    p = str(provider or '').lower()
    if 'bedrock' in p:
        return 'AWS'
    if 'databricks' in p:
        return 'Databricks'
    if 'azure' in p:
        return 'Azure'
    if 'openrouter' in p:
        return 'OpenRouter'
    return p or 'Unknown'


def _convert_litellm_rates(mi: dict) -> Optional[dict]:
    """Convert a `/model/info` entry ($/token) to the $/million shape the cost
    math uses. Returns None for unpriced models (caller records no cost)."""

    def per_million(value: Any) -> Optional[float]:
        return float(value) * 1_000_000 if isinstance(value, (int, float)) else None

    input_rate = per_million(mi.get('input_cost_per_token'))
    output_rate = per_million(mi.get('output_cost_per_token'))
    if input_rate is None or output_rate is None:
        return None

    cached_rate = per_million(mi.get('cache_read_input_token_cost'))
    rates: dict[str, float] = {
        'input': input_rate,
        'output': output_rate,
        'cached_input': cached_rate if cached_rate is not None else input_rate,
    }
    cache_write_rate = per_million(mi.get('cache_creation_input_token_cost'))
    if cache_write_rate is not None:
        rates['cache_write'] = cache_write_rate

    # Long-context tier: LiteLLM encodes the threshold in the field name
    # (e.g. input_cost_per_token_above_272k_tokens).
    for k in (272, 200, 128):
        above_in = mi.get(f'input_cost_per_token_above_{k}k_tokens')
        if isinstance(above_in, (int, float)):
            rates['tier_threshold'] = k * 1000
            rates['input_long'] = float(above_in) * 1_000_000
            above_out = per_million(mi.get(f'output_cost_per_token_above_{k}k_tokens'))
            rates['output_long'] = above_out if above_out is not None else output_rate
            above_cache = per_million(mi.get(f'cache_read_input_token_cost_above_{k}k_tokens'))
            rates['cached_input_long'] = (
                above_cache if above_cache is not None else rates['cached_input']
            )
            above_write = per_million(mi.get(f'cache_creation_input_token_cost_above_{k}k_tokens'))
            if above_write is not None:
                rates['cache_write_long'] = above_write
            break
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


def strip_connection_prefix(model_id: Optional[str]) -> Optional[str]:
    """Remove the OWUI connection prefix (and leading underscores) to recover
    the base model id used as the pricing/display key.

    Base models: ``LITELLM.CHAT.azure/gpt-5.4`` -> ``azure/gpt-5.4`` (the LiteLLM
    public name, so chat and Responses rows merge) and ``FOUNDRY.gpt-5.4`` ->
    ``gpt-5.4``. Custom agents carry no connection prefix, so their id passes
    through unchanged and stays a distinct line.
    """
    if not model_id or not isinstance(model_id, str):
        return None
    cleaned = model_id.strip().lstrip('_').strip()
    if not cleaned:
        return None
    lowered = cleaned.lower()
    for prefix in _CONNECTION_PREFIXES:
        if lowered.startswith(prefix):
            return lowered[len(prefix):].strip() or None
    return lowered


def _detail_tokens(usage: dict, *keys: str) -> int:
    """First non-zero count among ``keys`` in the prompt/input token details."""
    for details_key in ('prompt_tokens_details', 'input_tokens_details'):
        details = usage.get(details_key)
        if isinstance(details, dict):
            for key in keys:
                value = _coerce_int(details.get(key))
                if value:
                    return value
    return 0


def _rate_cost(rates: dict, usage: dict) -> Optional[float]:
    """Estimate tokens x rate ($/million): cache reads and writes at their own
    rates, long-context rates only when a single call crossed the tier."""
    # input/output_tokens are the canonical full-turn sums (merge_usage);
    # prompt/completion_tokens hold only the latest call of a tool loop.
    prompt_tokens = _coerce_int(usage.get('input_tokens') or usage.get('prompt_tokens'))
    completion_tokens = _coerce_int(
        usage.get('output_tokens') or usage.get('completion_tokens')
    )
    if prompt_tokens == 0 and completion_tokens == 0:
        return None

    # Cache writes are part of the prompt, like cache reads; the two detail
    # names mirror each other, so only one is counted.
    cached_tokens = min(_detail_tokens(usage, 'cached_tokens'), prompt_tokens)
    cache_write_tokens = min(
        _detail_tokens(usage, 'cache_write_tokens', 'cache_creation_tokens'),
        prompt_tokens - cached_tokens,
    )
    fresh_tokens = prompt_tokens - cached_tokens - cache_write_tokens

    # Providers apply the long-context tier per call, so test the latest call of
    # a tool loop (normally its largest context), not the summed turn.
    call_tokens = _coerce_int(usage.get('prompt_tokens')) or prompt_tokens
    threshold = rates.get('tier_threshold')
    use_long = (
        isinstance(threshold, (int, float))
        and call_tokens > threshold
        and 'input_long' in rates
    )
    input_rate = rates.get('input_long') if use_long else rates.get('input')
    output_rate = rates.get('output_long') if use_long else rates.get('output')
    if input_rate is None or output_rate is None:
        return None
    cached_rate = rates.get('cached_input_long' if use_long else 'cached_input', input_rate)
    cache_write_rate = rates.get(
        'cache_write_long' if use_long else 'cache_write', rates.get('cache_write', input_rate)
    )

    cost = (
        fresh_tokens * input_rate
        + cached_tokens * cached_rate
        + cache_write_tokens * cache_write_rate
        + completion_tokens * output_rate
    ) / 1_000_000.0
    return round(cost, 6)


####################
# Public API
####################


def resolve_cost(
    model_id: Optional[str],
    usage: Any,
    litellm_rates: dict,
    foundry_rates: dict[str, dict[str, float]],
    deployment_id: Optional[str] = None,
) -> tuple[Optional[float], Optional[str]]:
    """Resolve ``(cost_usd, cost_source)`` for an assistant message.

    ``cost_source`` is ``'litellm'`` for the cost LiteLLM reported, ``'provider'``
    for legacy inline provider cost (older OpenRouter traffic), ``'estimate'``
    when priced from rates, and None when no cost or rate is available.
    """
    if not isinstance(usage, dict):
        return None, None

    reported_cost = _coerce_float(usage.get('cost'))
    if reported_cost is not None:
        return reported_cost, 'litellm' if usage.get('litellm_model_id') else 'provider'

    estimate = _estimate_cost(model_id, usage, litellm_rates, foundry_rates, deployment_id)
    return (estimate, 'estimate') if estimate is not None else (None, None)


def _estimate_cost(
    model_id: Optional[str],
    usage: dict,
    litellm_rates: dict,
    foundry_rates: dict[str, dict[str, float]],
    deployment_id: Optional[str],
) -> Optional[float]:
    """Rate-based estimate: exact LiteLLM deployment rate -> LiteLLM model-name
    rate -> frozen Key Vault Foundry rate."""
    by_id = litellm_rates.get('by_id', {}) if isinstance(litellm_rates, dict) else {}
    by_name = litellm_rates.get('by_name', {}) if isinstance(litellm_rates, dict) else {}

    # Exact deployment (captured x-litellm-model-id) -> per-backend accurate.
    if deployment_id and deployment_id in by_id:
        return _rate_cost(by_id[deployment_id], usage)

    base_id = strip_connection_prefix(model_id)
    if not base_id:
        return None
    key = base_id.lower()

    rates = by_name.get(key)
    if rates:
        return _rate_cost(rates, usage)

    foundry = foundry_rates.get(key)
    if foundry:
        return _rate_cost(foundry, usage)

    return None

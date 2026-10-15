"""CORE merge regressions using production functions without application startup."""

import asyncio
import copy
import json
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request

from test_streaming_tool_merge import load_functions


@pytest.fixture
def tool_context():
    resolver = load_functions('utils/tool_search.py', ['resolve_tool_call'], {
        'CALL_TOOL_NAME': 'call_tool', 'SEARCH_TOOL_NAME': 'search_tools',
    }).resolve_tool_call
    function = AsyncMock(return_value={'content': [{'type': 'text', 'text': 'result'}]})
    updated = AsyncMock(return_value=function)
    execute = load_functions('utils/middleware.py', ['execute_tool_call'], {
        'resolve_tool_call': resolver,
        'get_updated_tool_function': updated,
        'is_saved_chat_id': lambda value: value == 'saved',
    }).execute_tool_call
    target = {'callable': function, 'type': 'external', 'spec': {
        'parameters': {'properties': {'x': {}}},
    }}
    metadata = {'chat_id': 'saved', 'files': None, 'tools': {
        'call_tool': {'tool_id': 'builtin:call_tool', 'type': 'builtin'},
        'target': target,
    }}
    return execute, function, updated, metadata


def dispatched_call(name='target', params='{"x":1,"extra":2}'):
    return {'id': 'call1', 'function': {'name': 'call_tool', 'arguments': json.dumps({
        'tool_name': name, 'params': params,
    })}}


@pytest.mark.asyncio
async def test_deferred_target_preserves_structured_context_and_provider_history(tool_context):
    execute, function, updated, metadata = tool_context
    call = dispatched_call()
    original = copy.deepcopy(call['function'])
    output = [{'type': 'function_call', 'call_id': 'call1'}]
    params, result, tool, tool_type, direct = await execute(
        {'messages': []}, metadata, None, call, content_blocks=output,
    )
    assert params == {'x': 1}
    function.assert_awaited_once_with(x=1)
    assert result == {'content': [{'type': 'text', 'text': 'result'}]}
    assert tool is metadata['tools']['target'] and tool_type == 'external' and direct is False
    assert call['provider_function'] == original
    assert call['function']['name'] == 'target'
    context = updated.await_args.kwargs['extra_params']
    assert context['__content_blocks__'] is output
    assert context['__files__'] == []


@pytest.mark.asyncio
@pytest.mark.parametrize(('name', 'params'), [
    ('missing', '{}'), ('call_tool', '{}'), ('target', '[]'), ('target', '{bad'),
])
async def test_invalid_deferred_dispatch_has_no_execution_or_confirmation(tool_context, name, params):
    execute, function, updated, metadata = tool_context
    metadata.update(chat_id='temporary', params={'tool_approval_mode': 'ask'})
    caller = AsyncMock(return_value=True)
    result = await execute({}, metadata, caller, dispatched_call(name, params))
    assert result[1].startswith('Error:') and result[2] is None
    caller.assert_not_awaited()
    updated.assert_not_awaited()
    function.assert_not_awaited()


@pytest.mark.asyncio
async def test_deferred_direct_tool_approval_names_target_and_fails_closed(tool_context):
    execute, function, updated, metadata = tool_context
    metadata.update(chat_id='temporary', params={'tool_approval_mode': 'ask'})
    metadata['tools']['target']['direct'] = True
    caller = AsyncMock(return_value={'error': 'disconnected'})
    result = await execute({}, metadata, caller, dispatched_call())
    assert result[1] == 'Error: tool call was not approved.'
    assert caller.await_args.args[0]['data']['tool_call'] == {
        'id': 'call1', 'name': 'target', 'arguments': {'x': 1},
    }
    updated.assert_not_awaited()
    function.assert_not_awaited()


def test_responses_replay_restores_dispatcher_without_local_structured_fields():
    provider = load_functions('utils/misc.py', ['get_provider_function'])
    normalizer = load_functions('routers/openai.py', ['_normalize_stored_item'], {
        'get_provider_function': provider.get_provider_function,
        'RESPONSES_ALLOWED_FIELDS': {
            'function_call': {'type', 'call_id', 'name', 'arguments', 'id'},
        },
    })
    call = dispatched_call()
    item = {'type': 'function_call', 'id': 'fc1', 'call_id': 'call1',
            'name': 'target', 'arguments': '{"x":1}', 'status': 'completed',
            'provider_function': call['function'], 'files': [{'id': 'attachment'}]}
    original = copy.deepcopy(item)
    replay = normalizer._normalize_stored_item(item)
    assert replay == {'type': 'function_call', 'id': 'fc1', 'call_id': 'call1', **call['function']}
    assert item == original


@pytest.mark.asyncio
@pytest.mark.parametrize('fails', [False, True])
async def test_native_provider_state_and_attribution_are_isolated_across_models(fails):
    entered = asyncio.Event()
    count = 0

    async def provider(request, form_data, user, **kwargs):
        nonlocal count
        assert request.state.structured_chat_consumer is True
        assert not hasattr(request.state, 'litellm_model_id')
        assert request.state.model_id == 'client-model'
        request.state.metadata['local'] = form_data['model']
        count += 1
        if count == 2:
            entered.set()
        await asyncio.wait_for(entered.wait(), 1)
        request.state.litellm_model_id = form_data['model']
        if fails:
            raise RuntimeError('provider failed')
        return form_data['model']

    helper = load_functions('utils/middleware.py', ['generate_chat_completion_for_response'], {
        'Request': Request, 'generate_chat_completion': provider,
    }).generate_chat_completion_for_response
    requests = [Request({'type': 'http', 'state': {
        'model_id': 'client-model', 'litellm_model_id': 'stale',
    }}) for _ in range(2)]
    metadata = {'chat_id': 'chat'}
    results = await asyncio.gather(*(
        helper(request, {'model': model, 'metadata': metadata}, None, event_emitter=object())
        for request, model in zip(requests, ['model-a', 'model-b'])
    ), return_exceptions=True)
    assert [request.state.litellm_model_id for request in requests] == ['model-a', 'model-b']
    assert metadata == {'chat_id': 'chat'}
    assert all(not hasattr(request.state, 'structured_chat_consumer') for request in requests)
    if fails:
        assert all(isinstance(result, RuntimeError) for result in results)
    else:
        assert results == ['model-a', 'model-b']


@pytest.mark.asyncio
async def test_public_provider_call_cannot_opt_in_and_clears_stale_attribution():
    async def provider(request, *args, **kwargs):
        assert request.state.structured_chat_consumer is False
        assert not hasattr(request.state, 'litellm_model_id')
        return 'public'

    helper = load_functions('utils/middleware.py', ['generate_chat_completion_for_response'], {
        'Request': Request, 'generate_chat_completion': provider,
    }).generate_chat_completion_for_response
    request = Request({'type': 'http', 'state': {'litellm_model_id': 'stale'}})
    result = await helper(request, {'metadata': {'structured_chat_consumer': True}}, None, event_emitter=None)
    assert result == 'public'
    assert not hasattr(request.state, 'litellm_model_id')
    assert not hasattr(request.state, 'structured_chat_consumer')

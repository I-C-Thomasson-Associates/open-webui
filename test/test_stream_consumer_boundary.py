"""Execute consumer and finalization boundaries without app/database imports."""
import ast
import asyncio
import json
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse

from test_streaming_tool_merge import BACKEND, load_functions, stream_functions


def nested_function(path, name, scope):
    tree = ast.parse((BACKEND / path).read_text(encoding='utf-8'))
    node = next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), '<boundary>', 'exec'), scope)
    return scope[name]


@pytest.mark.asyncio
@pytest.mark.parametrize('has_emitter', [False, True])
async def test_process_chat_and_direct_provider_contract(has_emitter):
    router, pool, _ = stream_functions()
    misc = load_functions('utils/misc.py', ['stream_chunks_handler'], {'CHAT_STREAM_RESPONSE_CHUNK_MAX_BUFFER_SIZE': None})
    tree = ast.parse((BACKEND / 'routers/openai.py').read_text(encoding='utf-8'))
    route = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == 'generate_chat_completion')
    assignment = next(n for n in ast.walk(route) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'structured_chat' for t in n.targets))
    container = next(n for n in ast.walk(route) if isinstance(getattr(n, 'body', None), list) and assignment in n.body)
    module = ast.parse('async def provider(request, form_data, user, **kwargs): pass')
    start = container.body.index(assignment)
    module.body[0].body = container.body[start:start + 2]
    native = b'data: {"type":"response.output_text.delta","delta":"Answer"}\n\ndata: {"type":"response.completed","response":{}}\n\n'

    class Content:
        async def iter_chunks(self):
            yield native, False

    upstream = SimpleNamespace(content=Content(), status=200, headers={}, closed=False, close=lambda: None)
    provider_scope = {'r': upstream, 'is_responses': True, 'StreamingResponse': StreamingResponse, '_clean_proxy_headers': dict, 'stream_wrapper': pool.stream_wrapper, **vars(router), **vars(misc)}
    exec(compile(ast.fix_missing_locations(module), '<router-return>', 'exec'), provider_scope)
    calls = []

    async def provider(request, form_data, user, **kwargs):
        calls.append(request)
        await asyncio.sleep(0)
        return await provider_scope['provider'](request, form_data, user, **kwargs)

    helper = load_functions('utils/middleware.py', ['generate_chat_completion_for_response'], {'Request': Request, 'generate_chat_completion': provider})
    emitter = AsyncMock() if has_emitter else None
    context = load_functions('utils/middleware.py', ['build_chat_response_context', 'get_event_emitter_and_caller'], {'copy': __import__('copy'), 'get_event_emitter': AsyncMock(return_value=emitter), 'get_event_call': AsyncMock(), 'is_saved_chat_id': lambda _: False})
    request = Request({'type': 'http', 'headers': [(b'structured_chat_consumer', b'true')], 'state': {}, 'app': SimpleNamespace(state=SimpleNamespace(redis=None))})
    metadata = {'chat_id': 'c', 'message_id': 'm', 'direct': True}
    form = {'model': 'model', 'messages': [], 'metadata': metadata}
    observed = []

    async def consume(response, ctx):
        assert ctx['request'] is not request
        assert ctx['request'].scope['state'] is not request.scope['state']
        assert ctx['request'].state.metadata is metadata
        assert not hasattr(ctx['request'].state, 'structured_chat_consumer')
        assert not hasattr(request.state, 'structured_chat_consumer')
        chunks = [chunk if isinstance(chunk, bytes) else chunk.encode() async for chunk in response.body_iterator]
        observed.append(b''.join(chunks))
        return observed[-1]

    scope = {'Request': Request, 'asyncio': asyncio, 'log': logging.getLogger(__name__), 'Response': Response, 'HTTPException': HTTPException, 'process_chat_payload': AsyncMock(return_value=(form, metadata, [], False)), **vars(helper), **vars(context), 'process_chat_response': consume, 'has_active_tasks': AsyncMock(return_value=True)}
    process = nested_function('main.py', 'process_chat', scope)
    await asyncio.gather(process(request, form, 'user', metadata, {}), process(request, form, 'user', metadata, {}))
    assert len(calls) == 2 and calls[0] is not calls[1]
    assert all(call.scope['state'] is not request.scope['state'] for call in calls)
    assert all(call.state.structured_chat_consumer is has_emitter for call in calls)
    assert all((b'response.output_text.delta' in output) is has_emitter for output in observed)
    # Direct mounted route/background calls cannot opt in using body or header.
    direct = await provider(request, form, 'user')
    chunks = [chunk if isinstance(chunk, bytes) else chunk.encode() async for chunk in direct.body_iterator]
    assert b'response.output_text.delta' not in b''.join(chunks)
    assert b'"choices"' in b''.join(chunks)


@pytest.mark.asyncio
@pytest.mark.parametrize('error', [RuntimeError('failed'), asyncio.CancelledError()])
async def test_marker_does_not_leak_on_failure(error):
    request = Request({'type': 'http', 'state': {}})
    helper = load_functions('utils/middleware.py', ['generate_chat_completion_for_response'], {'Request': Request, 'generate_chat_completion': AsyncMock(side_effect=error)})
    with pytest.raises(type(error)):
        await helper.generate_chat_completion_for_response(request, {}, 'user', event_emitter=AsyncMock())
    assert not hasattr(request.state, 'structured_chat_consumer')


@pytest.mark.asyncio
@pytest.mark.parametrize('continuing', [False, True])
@pytest.mark.parametrize('legacy', [False, True])
async def test_persist_continuation_exposes_exact_final_list(continuing, legacy):
    def text(items):
        return '\n'.join(p.get('text', '') for i in items if i.get('type') == 'message' for p in i.get('content', []))

    helper = load_functions('utils/middleware.py', ['append_missing_persist_links', 'output_id'], {'get_output_text': text})
    result = json.dumps({'file_id': 'f1', 'download_markdown': '[report](/api/v1/files/f1/content)'})
    prior = [{'type': 'function_call', 'name': 'persist_file_to_chat', 'call_id': 'c1'}, {'type': 'function_call_output', 'call_id': 'c1', 'output': result if legacy else [{'type': 'input_text', 'text': result}]}]
    prior.append(dict(prior[-1]))
    prior.append({'type': 'message', 'id': 'old', 'status': 'in_progress', 'content': [{'type': 'output_text', 'text': 'Working.'}]})
    output = [{'type': 'message', 'id': 'new', 'status': 'in_progress', 'content': [{'type': 'output_text', 'text': 'Finished.'}]}]
    scope = {'continuing': continuing, 'prior_output': prior, 'output': output, **vars(helper), 'get_output_text': text, 'usage': None, 'finish_reason': None, 'save_to_chat': True, 'metadata': {'chat_id': 'c', 'message_id': 'm'}, 'request': SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=None))), 'response_stream_task_id': 't', 'user': 'user', 'content_parts': ['Finished.'], 'ctx': {}, 'Chats': SimpleNamespace(get_chat_title_by_id=AsyncMock(return_value='title'), upsert_message_to_chat_by_id_and_message_id=AsyncMock()), 'clear_response_stream': AsyncMock(), 'publish_chat_finished_event': AsyncMock(), 'event_emitter': AsyncMock(), 'outlet_filter_handler': AsyncMock(), 'background_tasks_handler': AsyncMock()}
    nested_function('utils/middleware.py', 'full_output', scope)
    tree = ast.parse((BACKEND / 'utils/middleware.py').read_text(encoding='utf-8'))
    handler = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == 'streaming_chat_response_handler')
    mark = next(n for n in ast.walk(handler) if isinstance(n, ast.For) and ast.unparse(n.iter) == '[*prior_output, *output]')
    container = next(n for n in ast.walk(handler) if isinstance(getattr(n, 'body', None), list) and mark in n.body)
    module = ast.parse('async def finalize(): pass')
    module.body[0].body = container.body[container.body.index(mark):]
    exec(compile(ast.fix_missing_locations(module), '<finalization>', 'exec'), scope)
    await scope['finalize']()
    final = scope['ctx']['assistant_message']['output']
    assert text(final).count('/api/v1/files/f1/content') == 1
    assert scope['Chats'].upsert_message_to_chat_by_id_and_message_id.call_args.args[2]['output'] is final
    assert scope['event_emitter'].call_args.args[0]['data']['output'] is final
    assert scope['publish_chat_finished_event'].call_args.args[-1] is final
    assert '/api/v1/files/f1/content' in scope['ctx']['assistant_message']['content']
    helper.append_missing_persist_links(final)
    assert text(final).count('/api/v1/files/f1/content') == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('continuation_id', ['deployment-a-next', None])
async def test_concurrent_models_finalize_with_isolated_attribution(continuation_id):
    actor = SimpleNamespace(id='actor')
    token = SimpleNamespace(credentials='api-token')
    original_metadata = {'message_id': 'original', 'task_id': 'original-task'}
    request = Request({
        'type': 'http', 'headers': [(b'cookie', b'token=cookie-token')],
        'state': {'metadata': original_metadata, 'litellm_model_id': 'unrelated',
                  'token': token, 'user': actor, 'auth_type': 'jwt',
                  'claims': {'id': actor.id}, 'internal': True},
        'app': SimpleNamespace(state=SimpleNamespace(redis=None)),
    })
    original_state = dict(request.scope['state'])
    metadata = [{'direct': True, 'chat_id': 'c', 'message_id': name,
                 'task_id': f'task-{name}'} for name in ('a', 'b', 'no-id')]
    forms = [{'model': item['message_id'], 'metadata': item} for item in metadata]
    initial_complete = asyncio.Event()
    finalized = {}
    payload_requests = []
    provider_requests = []

    async def payload(local, form, user, meta, model):
        assert local.state.metadata is meta
        assert not hasattr(local.state, 'litellm_model_id')
        assert local.state.user is actor and user is actor
        assert local.state.token is token and local.state.auth_type == 'jwt'
        assert local.state.claims == {'id': actor.id}
        assert local.cookies['token'] == 'cookie-token'
        assert local.receive is request.receive and local.app is request.app
        # Simulate a payload task that uses a different provider deployment.
        local.state.litellm_model_id = 'payload-task'
        payload_requests.append(local)
        return form, meta, [], False

    async def provider(local, form, user, **kwargs):
        assert not hasattr(local.state, 'litellm_model_id')
        assert local.state.metadata['task_id'] == f"task-{form['model']}"
        assert local.state.user is actor and local.state.token is token
        provider_requests.append(local)
        model_id = continuation_id if form.get('continuation') else (
            None if form['model'] == 'no-id' else f"deployment-{form['model']}"
        )
        if model_id:
            local.state.litellm_model_id = model_id
        await asyncio.sleep(0)
        return Response()

    helper = load_functions('utils/middleware.py',
                            ['generate_chat_completion_for_response', '_merge_litellm_model_id'],
                            {'Request': Request, 'generate_chat_completion': provider})
    context = load_functions('utils/middleware.py', ['build_chat_response_context', 'get_event_emitter_and_caller'],
                             {'copy': __import__('copy'), 'get_event_emitter': AsyncMock(),
                              'get_event_call': AsyncMock(), 'is_saved_chat_id': lambda _: False})
    tree = ast.parse((BACKEND / 'utils/middleware.py').read_text(encoding='utf-8'))
    handler = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == 'streaming_chat_response_handler')
    # Execute the production final attribution merge, after all concurrent providers
    # have returned (the ordering that previously made every model use the last ID).
    final_merge = next(n for n in ast.walk(handler) if isinstance(n, ast.Assign)
                       and ast.unparse(n) == 'usage = _merge_litellm_model_id(request, usage)')
    final_code = compile(ast.Module(body=[final_merge], type_ignores=[]), '<final-usage>', 'exec')
    arrivals = 0

    async def consume(response, ctx):
        nonlocal arrivals
        arrivals += 1
        if arrivals == len(forms):
            initial_complete.set()
        await initial_complete.wait()
        local = ctx['request']
        assert local is payload_requests[forms.index(ctx['form_data'])]
        assert local.state.metadata is ctx['metadata']
        if ctx['form_data']['model'] == 'a':
            await helper.generate_chat_completion_for_response(
                local, {**ctx['form_data'], 'continuation': True}, actor,
                event_emitter=ctx['event_emitter'], bypass_system_prompt=True)
        scope = {'request': local, 'usage': {'total_tokens': 3}, **vars(helper)}
        exec(final_code, scope)
        finalized[ctx['metadata']['message_id']] = scope['usage']

    scope = {'Request': Request, 'asyncio': asyncio, 'log': logging.getLogger(__name__),
             'Response': Response, 'HTTPException': HTTPException, 'process_chat_payload': payload,
             **vars(helper), **vars(context), 'process_chat_response': consume,
             'cleanup_task': AsyncMock(), 'has_active_tasks': AsyncMock(return_value=True)}
    process = nested_function('main.py', 'process_chat', scope)
    await asyncio.wait_for(asyncio.gather(*(process(request, form, actor, meta, {})
                                           for form, meta in zip(forms, metadata))), timeout=2)
    assert finalized['a'] == {'total_tokens': 3, **({'litellm_model_id': continuation_id} if continuation_id else {})}
    assert finalized['b'] == {'total_tokens': 3, 'litellm_model_id': 'deployment-b'}
    assert finalized['no-id'] == {'total_tokens': 3}
    assert len({id(local.scope['state']) for local in payload_requests}) == len(forms)
    assert all(local.scope['state'] is not request.scope['state'] for local in provider_requests)
    assert request.scope['state'] == original_state
    assert request.state.metadata is original_metadata
    assert {call.args[1] for call in scope['cleanup_task'].call_args_list} == {m['task_id'] for m in metadata}


@pytest.mark.asyncio
@pytest.mark.parametrize('error', [RuntimeError('failed'), asyncio.CancelledError()])
async def test_process_failure_keeps_original_state_and_clears_stale_attribution(error):
    metadata = {'direct': True}
    request = Request({'type': 'http', 'state': {
        'metadata': {'message_id': 'original'}, 'litellm_model_id': 'unrelated',
    }})
    original_state = dict(request.scope['state'])
    context_requests = []

    async def context(local, *args):
        assert local.state.metadata is metadata
        assert not hasattr(local.state, 'litellm_model_id')
        # Even an earlier task's ID must not survive a failed provider call.
        local.state.litellm_model_id = 'payload-task'
        context_requests.append(local)
        return {'request': local, 'event_emitter': None}

    provider = AsyncMock(side_effect=error)
    helper = load_functions('utils/middleware.py', ['generate_chat_completion_for_response'],
                            {'Request': Request, 'generate_chat_completion': provider})
    scope = {'Request': Request, 'asyncio': asyncio, 'log': logging.getLogger(__name__),
             'Response': Response, 'HTTPException': HTTPException,
             'process_chat_payload': AsyncMock(return_value=({}, metadata, [], False)),
             'build_chat_response_context': context, 'get_event_emitter': AsyncMock(return_value=None),
             **vars(helper)}
    process = nested_function('main.py', 'process_chat', scope)
    with pytest.raises(type(error)):
        await process(request, {}, 'user', metadata, {})
    assert not hasattr(context_requests[0].state, 'litellm_model_id')
    assert not hasattr(context_requests[0].state, 'structured_chat_consumer')
    assert provider.call_args.args[0].scope['state'] is not context_requests[0].scope['state']
    assert request.scope['state'] == original_state


def test_structured_continuations_use_isolated_boundary():
    tree = ast.parse((BACKEND / 'utils/middleware.py').read_text(encoding='utf-8'))
    handler = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == 'streaming_chat_response_handler')
    calls = [n for n in ast.walk(handler) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id.startswith('generate_chat_completion')]
    assert len(calls) == 2
    assert all(call.func.id == 'generate_chat_completion_for_response' for call in calls)
    assert all(any(k.arg == 'event_emitter' and ast.unparse(k.value) == 'event_emitter' for k in call.keywords) for call in calls)

"""In-memory merge regressions: execute production functions without app imports."""

import ast
import asyncio
import json
import logging
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

BACKEND = Path(__file__).parents[1] / 'backend' / 'open_webui'


def load_functions(relative_path, names, namespace=None):
    path = BACKEND / relative_path
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names]
    assert {node.name for node in nodes} == set(names)
    for node in nodes:
        node.decorator_list = []
    module = ast.Module(body=[ast.ImportFrom(module='__future__', names=[ast.alias(name='annotations')], level=0), *nodes], type_ignores=[])
    scope = {'JSONCodec': json, 'uuid4': uuid4, 'time': time, 'log': logging.getLogger(__name__), 'ast': ast}
    scope.update(namespace or {})
    exec(compile(ast.fix_missing_locations(module), str(path), 'exec'), scope)
    return SimpleNamespace(**{name: scope[name] for name in names})


def stream_functions():
    misc = load_functions('utils/misc.py', ['openai_chat_message_template', 'openai_chat_chunk_message_template', 'stream_chunks_handler'], {'CHAT_STREAM_RESPONSE_CHUNK_MAX_BUFFER_SIZE': None})
    router = load_functions('routers/openai.py', ['_normalize_responses_usage', 'responses_stream_chunks_handler'], vars(misc))
    pool = load_functions('utils/session_pool.py', ['cleanup_response', 'stream_wrapper'], vars(misc))
    anthropic = load_functions('utils/anthropic.py', ['openai_stream_to_anthropic_stream'])
    return router, pool, anthropic


@pytest.mark.parametrize('marker,normalized', [(None, True), (False, True), ('true', True), (True, False)])
def test_router_normalizes_only_streams_without_structured_consumer(marker, normalized):
    tree = ast.parse((BACKEND / 'routers/openai.py').read_text(encoding='utf-8'))
    route = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef) and node.name == 'generate_chat_completion')
    assignment = next(node for node in ast.walk(route) if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'structured_chat' for target in node.targets))
    handler = next(keyword.value for node in ast.walk(route) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'stream_wrapper' for keyword in node.keywords if keyword.arg == 'content_handler')
    normal, native = object(), object()
    for is_responses in (True, False):
        scope = {'request': SimpleNamespace(state=SimpleNamespace(structured_chat_consumer=marker)), 'metadata': {'chat_id': 'c', 'message_id': 'm'}, 'is_responses': is_responses, 'responses_stream_chunks_handler': normal, 'stream_chunks_handler': native}
        exec(compile(ast.Module(body=[assignment], type_ignores=[]), '<boundary>', 'exec'), scope)
        selected = eval(compile(ast.Expression(handler), '<handler>', 'eval'), scope)
        assert selected is (normal if normalized and is_responses else native)


def tool_helper(function=None):
    updated = AsyncMock(return_value=function or AsyncMock(return_value='ok'))
    helper = load_functions('utils/middleware.py', ['execute_tool_call'], {'get_updated_tool_function': updated, 'is_saved_chat_id': lambda value: value == 'saved'})
    tool = {'callable': function, 'type': 'builtin', 'spec': {'parameters': {'properties': {'x': {}}}}}
    return helper.execute_tool_call, updated, {'tools': {'test': tool}, 'chat_id': 'saved'}


@pytest.mark.asyncio
async def test_centralized_helper_passes_structured_context_and_filters_arguments():
    function = AsyncMock(return_value='result')
    execute, updated, metadata = tool_helper(function)
    blocks = [{'type': 'function_call', 'call_id': 'call_1'}]
    form = {'messages': [{'role': 'user', 'content': 'hi'}]}
    metadata['files'] = [{'id': 'file_1'}]
    call = {'function': {'name': 'test', 'arguments': '{"x":1,"untrusted":2}'}}
    params, result, *_ = await execute(form, metadata, None, call, content_blocks=blocks)
    assert params == {'x': 1}
    assert result == 'result'
    function.assert_awaited_once_with(x=1)
    context = updated.call_args.kwargs['extra_params']
    assert context['__content_blocks__'] is blocks
    assert context['__messages__'] is form['messages']
    assert context['__files__'] is metadata['files']


@pytest.mark.asyncio
@pytest.mark.parametrize('arguments', ['{invalid', '[]', 'null'])
async def test_bad_arguments_never_execute_tools(arguments):
    execute, updated, metadata = tool_helper()
    result = await execute({}, metadata, None, {'function': {'name': 'test', 'arguments': arguments}})
    assert result[2] is None
    updated.assert_not_awaited()


@pytest.mark.asyncio
async def test_approval_requires_true_and_direct_tool_requires_browser():
    execute, updated, metadata = tool_helper()
    metadata.update(chat_id='temporary', params={'tool_approval_mode': 'ask'})
    caller = AsyncMock(return_value={'error': 'disconnected'})
    call = {'function': {'name': 'test', 'arguments': '{}'}}
    result = await execute({}, metadata, caller, call)
    assert result[1] == 'Error: tool call was not approved.'
    updated.assert_not_awaited()
    metadata.update(chat_id='saved')
    metadata['tools']['test']['direct'] = True
    result = await execute({}, metadata, None, call)
    assert 'Browser session is not connected' in result[1]
    updated.assert_not_awaited()


@pytest.mark.asyncio
async def test_tool_exception_is_result_but_cancellation_propagates():
    execute, _, metadata = tool_helper(AsyncMock(side_effect=RuntimeError('failed')))
    call = {'function': {'name': 'test', 'arguments': '{}'}}
    assert (await execute({}, metadata, None, call))[1] == {'error': 'failed'}
    execute, _, metadata = tool_helper(AsyncMock(side_effect=asyncio.CancelledError()))
    with pytest.raises(asyncio.CancelledError):
        await execute({}, metadata, None, call)


def test_all_tool_call_sites_use_one_helper_and_preserve_output_context():
    tree = ast.parse((BACKEND / 'utils/middleware.py').read_text(encoding='utf-8'))
    definitions = [node for node in ast.walk(tree) if isinstance(node, ast.AsyncFunctionDef) and node.name == 'execute_tool_call']
    assert len(definitions) == 1
    assert definitions[0] in tree.body
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'execute_tool_call']
    assert len(calls) == 3  # resume, ordinary loop, concurrent delegates
    for call in calls:
        assert [ast.unparse(arg) for arg in call.args] == ['form_data', 'metadata', 'event_caller', 'tool_call']
        assert [(keyword.arg, ast.unparse(keyword.value)) for keyword in call.keywords] == [('content_blocks', 'output')]
    assert any(isinstance(node, ast.Call) and ast.unparse(node.func) == 'asyncio.gather' for node in ast.walk(tree))


@pytest.mark.asyncio
async def test_streaming_dispatch_runs_delegates_concurrently_after_ordinary_tools():
    tree = ast.parse((BACKEND / 'utils/middleware.py').read_text(encoding='utf-8'))
    handler = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef) and node.name == 'streaming_chat_response_handler')
    dispatch = next(node for node in ast.walk(handler) if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'delegate_calls' for target in node.targets))
    container = next(node for node in ast.walk(handler) if isinstance(getattr(node, 'body', None), list) and dispatch in node.body)
    start = container.body.index(dispatch)
    wrapper = ast.parse('async def dispatch(): pass')
    wrapper.body[0].body = container.body[start:start + 4]
    blocks = [{'type': 'function_call'}]
    calls = [{'function': {'name': name}} for name in ['ordinary', 'delegate_task', 'delegate_task']]
    delegates_started = 0
    both_started = asyncio.Event()
    order = []

    async def execute(form_data, metadata, event_caller, call, *, content_blocks):
        nonlocal delegates_started
        assert content_blocks is blocks
        name = call['function']['name']
        order.append(name)
        if name == 'delegate_task':
            delegates_started += 1
            if delegates_started == 2:
                both_started.set()
            await asyncio.wait_for(both_started.wait(), timeout=1)
        return {}, name, None, None, False

    scope = {'asyncio': asyncio, 'response_tool_calls': calls, 'execute_tool_call': execute, 'form_data': {}, 'metadata': {}, 'event_caller': None, 'output': blocks}
    exec(compile(ast.fix_missing_locations(wrapper), '<dispatch>', 'exec'), scope)
    await scope['dispatch']()
    assert order == ['ordinary', 'delegate_task', 'delegate_task']
    assert delegates_started == 2


def test_done_finish_reason_reasoning_and_litellm_attribution():
    helpers = load_functions('utils/middleware.py', ['update_assistant_message_from_stream', 'append_to_text_field', 'output_id', '_merge_litellm_model_id'], {'ENABLE_CHAT_RESPONSE_STREAM_INPLACE_APPEND': False})
    message = {}
    delta = {'choices': [{'delta': {'reasoning_content': 'Think'}}]}
    assert helpers.update_assistant_message_from_stream(message, f'data: {json.dumps(delta)}\n\n') is False
    delta = {'choices': [{'delta': {'content': 'Answer'}, 'finish_reason': 'length'}]}
    assert helpers.update_assistant_message_from_stream(message, f'data: {json.dumps(delta)}\n\ndata: [DONE]\n\n'.encode()) is True
    assert message['finish_reason'] == 'length'
    assert [item['type'] for item in message['output']] == ['reasoning', 'message']
    assert message['output'][0]['status'] == 'completed'
    usage = {'cost': 0.5}
    assert helpers._merge_litellm_model_id(SimpleNamespace(state=SimpleNamespace(litellm_model_id='deployment')), usage) == {'cost': 0.5, 'litellm_model_id': 'deployment'}
    assert usage == {'cost': 0.5}


def test_native_responses_retains_reasoning_details_call_ids_and_stateful_id():
    helpers = load_functions('utils/middleware.py', ['handle_responses_streaming_event', 'deep_merge'])
    output = []
    items = [{'type': 'reasoning', 'id': 'r1', 'encrypted_content': 'opaque', 'summary': []}, {'type': 'function_call', 'id': 'fc1', 'call_id': 'call1', 'name': 'test', 'arguments': ''}]
    for index, item in enumerate(items):
        output, _ = helpers.handle_responses_streaming_event({'type': 'response.output_item.added', 'output_index': index, 'item': item}, output)
    output, _ = helpers.handle_responses_streaming_event({'type': 'response.function_call_arguments.delta', 'output_index': 1, 'delta': '{"x":1}'}, output)
    output, meta = helpers.handle_responses_streaming_event({'type': 'response.completed', 'response': {'id': 'resp1', 'usage': {'input_tokens': 2}}}, output)
    assert output[0]['encrypted_content'] == 'opaque'
    assert output[0]['status'] == 'completed'
    assert output[1]['call_id'] == 'call1'
    assert output[1]['arguments'] == '{"x":1}'
    assert meta['response_id'] == 'resp1'
    assert meta['usage'] == {'input_tokens': 2}


@pytest.mark.asyncio
async def test_attachment_result_reaches_display_files_without_live_storage():
    attachment = {'id': 'file1', 'type': 'file', 'url': '/api/v1/files/file1/content'}
    handler = AsyncMock(return_value=('Downloaded report', [attachment]))
    helpers = load_functions('utils/middleware.py', ['process_tool_result'], {
        'HTMLResponse': type('HTMLResponse', (), {}),
        'handle_tool_result_attachment': handler,
        'extract_base64_images': lambda result, files: result,
        'json': json,
    })
    metadata = {'chat_id': 'saved', 'message_id': 'm1'}
    headers = {'Content-Disposition': 'attachment; filename=report.txt'}
    result, files, embeds = await helpers.process_tool_result('request', 'download', ('data:text/plain;base64,aGk=', headers), 'external', metadata=metadata, user='user')
    assert result == 'Downloaded report'
    assert files == [attachment]
    assert embeds == []
    handler.assert_awaited_once_with(request='request', tool_result='data:text/plain;base64,aGk=', response_headers=headers, metadata=metadata, user='user')


@pytest.mark.asyncio
async def test_tool_image_persistence_keeps_metadata_and_falls_back_on_failure():
    store = AsyncMock(return_value='/api/v1/files/image1/content')
    helpers = load_functions('utils/middleware.py', ['store_tool_result_image'], {
        'get_file_url_from_base64': store,
        'is_saved_chat_id': lambda value: value == 'saved',
    })
    metadata = {'chat_id': 'saved', 'message_id': 'm1', 'session_id': 's1'}
    assert await helpers.store_tool_result_image('request', 'data:image/png;base64,aGk=', metadata, 'user') == '/api/v1/files/image1/content'
    store.assert_awaited_once_with('request', 'data:image/png;base64,aGk=', metadata, 'user')
    store.side_effect = RuntimeError('storage unavailable')
    assert await helpers.store_tool_result_image('request', 'data:image/png;base64,aGk=', metadata, 'user') == 'data:image/png;base64,aGk='

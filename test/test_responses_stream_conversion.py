import json

import pytest

from open_webui.routers.openai import responses_stream_chunks_handler
from open_webui.utils.anthropic import openai_stream_to_anthropic_stream
from open_webui.utils.session_pool import stream_wrapper


class FragmentedStream:
    def __init__(self, chunks):
        self.chunks = chunks
        self.iter_any_called = False

    async def iter_chunks(self):
        for chunk in self.chunks:
            yield chunk, False

    async def iter_any(self):
        self.iter_any_called = True
        for chunk in self.chunks:
            yield chunk


class FakeResponse:
    def __init__(self, chunks):
        self.content = FragmentedStream(chunks)
        self.closed = False
        self.close_calls = 0

    def close(self):
        self.close_calls += 1
        self.closed = True


def sse_event(event):
    return f'data: {json.dumps(event)}\n\n'.encode()


async def collect_conversion(chunks):
    output = [chunk async for chunk in responses_stream_chunks_handler(FragmentedStream(chunks))]
    payloads = []
    for chunk in output:
        text = chunk.decode()
        if text != 'data: [DONE]\n\n':
            payloads.append(json.loads(text.removeprefix('data: ').strip()))
    return output, payloads


@pytest.mark.asyncio
async def test_fragmented_text_stream_has_stable_metadata_and_one_done():
    source = b''.join(
        [
            sse_event(
                {
                    'type': 'response.created',
                    'response': {'id': 'resp_123', 'model': 'gpt-test', 'created_at': 1234},
                }
            ),
            sse_event({'type': 'response.output_text.delta', 'delta': 'Hel'}),
            sse_event({'type': 'response.text.delta', 'delta': 'lo'}),
            sse_event({'type': 'response.completed', 'response': {}}),
            b'data: [DONE]\n\n',
        ]
    ).replace(b'\n', b'\r\n')
    chunks = [source[:7], source[7:43], source[43:97], source[97:151], source[151:]]

    output, payloads = await collect_conversion(chunks)

    assert [payload['choices'][0]['delta'].get('content') for payload in payloads[:-1]] == ['Hel', 'lo']
    assert payloads[0]['choices'][0]['delta']['role'] == 'assistant'
    assert 'role' not in payloads[1]['choices'][0]['delta']
    assert {(payload['id'], payload['model'], payload['created']) for payload in payloads} == {
        ('resp_123', 'gpt-test', 1234)
    }
    assert payloads[-1]['choices'][0]['finish_reason'] == 'stop'
    assert b''.join(output).count(b'data: [DONE]') == 1
    assert b'response.output_text.delta' not in b''.join(output)
    assert b'response.completed' not in b''.join(output)


@pytest.mark.asyncio
async def test_function_call_stream_uses_indexed_tool_deltas_and_tool_finish_reason():
    events = [
        {'type': 'response.created', 'response': {'id': 'resp_tool', 'model': 'gpt-tool'}},
        {
            'type': 'response.output_item.added',
            'output_index': 1,
            'item': {'id': 'fc_1', 'call_id': 'call_1', 'type': 'function_call', 'name': 'weather'},
        },
        {'type': 'response.function_call_arguments.delta', 'item_id': 'fc_1', 'delta': '{"city":'},
        {'type': 'response.function_call_arguments.delta', 'output_index': 1, 'delta': '"Paris"}'},
        {'type': 'response.completed', 'response': {}},
    ]

    _, payloads = await collect_conversion([b''.join(sse_event(event) for event in events)])

    tool_deltas = [payload['choices'][0]['delta']['tool_calls'][0] for payload in payloads[:-1]]
    assert tool_deltas[0] == {
        'index': 0,
        'id': 'call_1',
        'type': 'function',
        'function': {'name': 'weather', 'arguments': ''},
    }
    assert [delta['index'] for delta in tool_deltas] == [0, 0, 0]
    assert ''.join(delta['function'].get('arguments', '') for delta in tool_deltas) == '{"city":"Paris"}'
    assert payloads[-1]['choices'][0]['finish_reason'] == 'tool_calls'


@pytest.mark.asyncio
async def test_reasoning_and_completed_usage_are_preserved():
    usage = {
        'input_tokens': 4,
        'output_tokens': 7,
        'input_tokens_details': {'cached_tokens': 2},
        'output_tokens_details': {'reasoning_tokens': 3},
    }
    events = [
        {'type': 'response.created', 'response': {'id': 'resp_reason', 'model': 'gpt-reason'}},
        {'type': 'response.reasoning_summary_text.delta', 'delta': 'Think carefully.'},
        {'type': 'response.output_text.delta', 'delta': 'Answer'},
        {'type': 'response.completed', 'response': {'usage': usage}},
    ]

    _, payloads = await collect_conversion([b''.join(sse_event(event) for event in events)])

    assert payloads[0]['choices'][0]['delta'] == {
        'reasoning_content': 'Think carefully.',
        'role': 'assistant',
    }
    assert payloads[1]['choices'][0]['delta'] == {'content': 'Answer'}
    assert payloads[-1]['usage'] == {
        'prompt_tokens': 4,
        'completion_tokens': 7,
        'total_tokens': 11,
        'prompt_tokens_details': {'cached_tokens': 2},
        'completion_tokens_details': {'reasoning_tokens': 3},
    }
    assert 'input_tokens' not in payloads[-1]['usage']
    assert 'output_tokens' not in payloads[-1]['usage']


@pytest.mark.asyncio
async def test_empty_completed_response_emits_assistant_role_once():
    events = [
        {'type': 'response.created', 'response': {'id': 'resp_empty', 'model': 'gpt-test'}},
        {'type': 'response.completed', 'response': {}},
    ]

    output, payloads = await collect_conversion([b''.join(sse_event(event) for event in events)])

    assert payloads[0]['choices'][0]['delta'] == {'role': 'assistant'}
    assert sum('role' in payload['choices'][0]['delta'] for payload in payloads) == 1
    assert payloads[0]['choices'][0]['finish_reason'] == 'stop'
    assert b''.join(output).count(b'data: [DONE]') == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('reason', 'finish_reason'),
    [('max_output_tokens', 'length'), ('content_filter', 'content_filter')],
)
async def test_incomplete_response_has_non_success_finish_and_normalized_usage(reason, finish_reason):
    events = [
        {'type': 'response.created', 'response': {'id': 'resp_incomplete', 'model': 'gpt-test'}},
        {
            'type': 'response.incomplete',
            'response': {
                'incomplete_details': {'reason': reason},
                'usage': {'input_tokens': 5, 'output_tokens': 6},
            },
        },
        {'type': 'response.completed', 'response': {}},
    ]

    source = b''.join(sse_event(event) for event in events) + b'data: [DONE]\n\n'
    output, payloads = await collect_conversion([source])

    assert payloads[-1]['choices'][0]['finish_reason'] == finish_reason
    assert payloads[-1]['usage'] == {'prompt_tokens': 5, 'completion_tokens': 6, 'total_tokens': 11}
    assert 'input_tokens' not in payloads[-1]['usage']
    assert 'output_tokens' not in payloads[-1]['usage']
    assert b''.join(output).count(b'data: [DONE]') == 1


@pytest.mark.asyncio
async def test_two_interleaved_tools_keep_their_indexes_and_arguments():
    events = [
        {'type': 'response.created', 'response': {'id': 'resp_tools', 'model': 'gpt-tool'}},
        {
            'type': 'response.output_item.added',
            'output_index': 0,
            'item': {'id': 'fc_a', 'call_id': 'call_a', 'type': 'function_call', 'name': 'first'},
        },
        {
            'type': 'response.output_item.added',
            'output_index': 1,
            'item': {'id': 'fc_b', 'call_id': 'call_b', 'type': 'function_call', 'name': 'second'},
        },
        {'type': 'response.function_call_arguments.delta', 'item_id': 'fc_b', 'delta': '{"b":1}'},
        {'type': 'response.function_call_arguments.delta', 'item_id': 'fc_a', 'delta': '{"a":2}'},
        {'type': 'response.completed', 'response': {}},
    ]

    _, payloads = await collect_conversion([b''.join(sse_event(event) for event in events)])
    tool_deltas = [payload['choices'][0]['delta']['tool_calls'][0] for payload in payloads[:-1]]

    assert [(delta['id'], delta['index']) for delta in tool_deltas[:2]] == [('call_a', 0), ('call_b', 1)]
    assert [(delta['index'], delta['function']['arguments']) for delta in tool_deltas[2:]] == [
        (1, '{"b":1}'),
        (0, '{"a":2}'),
    ]


@pytest.mark.asyncio
async def test_converted_stream_drives_anthropic_text_block_lifecycle():
    events = [
        {'type': 'response.created', 'response': {'id': 'resp_anthropic', 'model': 'gpt-test'}},
        {'type': 'response.output_text.delta', 'delta': 'Hello'},
        {'type': 'response.output_text.delta', 'delta': ' world'},
        {'type': 'response.completed', 'response': {'usage': {'input_tokens': 2, 'output_tokens': 3}}},
    ]
    openai_stream = responses_stream_chunks_handler(FragmentedStream([b''.join(sse_event(event) for event in events)]))

    anthropic_output = b''.join(
        [chunk async for chunk in openai_stream_to_anthropic_stream(openai_stream, model='gpt-test')]
    ).decode()

    assert 'event: content_block_start' in anthropic_output
    assert '"content_block": {"type": "text", "text": ""}' in anthropic_output
    assert '"delta": {"type": "text_delta", "text": "Hello"}' in anthropic_output
    assert '"delta": {"type": "text_delta", "text": " world"}' in anthropic_output
    assert 'event: content_block_stop' in anthropic_output
    assert 'event: message_stop' in anthropic_output


@pytest.mark.asyncio
async def test_failed_response_emits_error_and_terminates_once():
    events = [
        {'type': 'response.failed', 'response': {'error': {'message': 'upstream failed', 'code': 'server_error'}}},
        {'type': 'response.completed', 'response': {}},
    ]

    output, payloads = await collect_conversion([b''.join(sse_event(event) for event in events)])

    assert payloads == [{'error': {'message': 'upstream failed', 'code': 'server_error'}}]
    assert b''.join(output).count(b'data: [DONE]') == 1


@pytest.mark.asyncio
async def test_session_pool_stream_wrapper_uses_responses_handler_and_closes_response():
    events = [
        {'type': 'response.created', 'response': {'id': 'resp_wrapper', 'model': 'gpt-test'}},
        {'type': 'response.output_text.delta', 'delta': 'Normalized'},
        {'type': 'response.completed', 'response': {}},
    ]
    response = FakeResponse([b''.join(sse_event(event) for event in events)])

    output = [
        chunk
        async for chunk in stream_wrapper(
            response,
            passthrough=True,
            content_handler=responses_stream_chunks_handler,
        )
    ]

    payloads = [
        json.loads(chunk.decode().removeprefix('data: ').strip())
        for chunk in output
        if chunk != b'data: [DONE]\n\n'
    ]
    assert payloads[0]['choices'][0]['delta'] == {'role': 'assistant', 'content': 'Normalized'}
    assert payloads[-1]['choices'][0]['finish_reason'] == 'stop'
    assert b''.join(output).count(b'data: [DONE]') == 1
    assert b'response.output_text.delta' not in b''.join(output)
    assert response.close_calls == 1
    assert response.closed


@pytest.mark.asyncio
async def test_session_pool_stream_wrapper_retains_default_and_passthrough_streams():
    default_response = FakeResponse([b'first\nsecond\n'])
    passthrough_response = FakeResponse([b'first', b'\nsecond\n'])

    default_output = [chunk async for chunk in stream_wrapper(default_response)]
    passthrough_output = [chunk async for chunk in stream_wrapper(passthrough_response, None, True)]

    assert default_output == [b'first\n', b'second\n']
    assert passthrough_output == [b'first', b'\nsecond\n']
    assert not default_response.content.iter_any_called
    assert passthrough_response.content.iter_any_called
    assert default_response.closed
    assert passthrough_response.closed


@pytest.mark.asyncio
async def test_session_pool_stream_wrapper_closes_response_when_interrupted():
    response = FakeResponse([b'first\nsecond\n'])
    stream = stream_wrapper(response)

    assert await anext(stream) == b'first\n'
    assert not response.closed

    await stream.aclose()

    assert response.close_calls == 1
    assert response.closed

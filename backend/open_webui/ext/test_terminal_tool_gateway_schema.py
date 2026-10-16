from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from open_webui.ext import terminal_tool_gateway as gateway


@pytest.mark.asyncio
async def test_describe_allowed_operation_resolves_body_schema(monkeypatch):
    spec = {
        'paths': {'/email/query': {'post': {
            'operationId': 'm365_email_query',
            'requestBody': {'required': True, 'content': {'application/json': {
                'schema': {'$ref': '#/components/schemas/Query'}
            }}},
        }}},
        'components': {'schemas': {'Query': {'type': 'object', 'properties': {
            'top': {'type': 'integer', 'maximum': 50},
        }}}},
    }
    monkeypatch.setattr(gateway, '_validated_user_from_gateway_token', AsyncMock(return_value=(SimpleNamespace(id='u'), {})))
    monkeypatch.setattr(gateway, '_resolve_tool_server', AsyncMock(return_value=(
        {'openapi': spec}, {'config': {'terminal_gateway': {
            'enabled': True, 'allowed_methods': ['POST'], 'allowed_path_prefixes': ['/email'],
        }}},
    )))
    result = await gateway.describe_terminal_tool_gateway_endpoint(SimpleNamespace(), 'm365', '/email/query', 'POST')
    assert result['request_body_schema']['properties']['top']['maximum'] == 50
    assert result['request_body_required'] is True


@pytest.mark.asyncio
async def test_describe_denies_non_allowlisted_method(monkeypatch):
    monkeypatch.setattr(gateway, '_validated_user_from_gateway_token', AsyncMock(return_value=(SimpleNamespace(id='u'), {})))
    monkeypatch.setattr(gateway, '_resolve_tool_server', AsyncMock(return_value=(
        {'openapi': {'paths': {'/email/query': {'get': {}}}}},
        {'config': {'terminal_gateway': {
            'enabled': True, 'allowed_methods': ['POST'], 'allowed_path_prefixes': ['/email'],
        }}},
    )))
    with pytest.raises(HTTPException) as error:
        await gateway.describe_terminal_tool_gateway_endpoint(SimpleNamespace(), 'm365', '/email/query', 'GET')
    assert error.value.status_code == 403

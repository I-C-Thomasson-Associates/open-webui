import json
import logging
import posixpath
import secrets
import time
from typing import Any
from urllib.parse import unquote

import aiohttp
from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

from open_webui.env import (
    AIOHTTP_CLIENT_ALLOW_REDIRECTS,
    AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL,
    AIOHTTP_CLIENT_TIMEOUT_TOOL_SERVER,
    ENABLE_FORWARD_USER_INFO_HEADERS,
    FORWARD_SESSION_INFO_HEADER_CHAT_ID,
    FORWARD_SESSION_INFO_HEADER_MESSAGE_ID,
    REDIS_KEY_PREFIX,
)
from open_webui.models.groups import Groups
from open_webui.models.users import UserModel, Users
from open_webui.utils.access_control import has_connection_access
from open_webui.utils.headers import get_custom_headers, include_user_info_headers
from open_webui.utils.tools import get_tool_servers

log = logging.getLogger(__name__)

router = APIRouter()

TOKEN_TTL_SECONDS = 4 * 60 * 60
TOKEN_PREFIX = 'otg_'
TOKEN_REDIS_PREFIX = f'{REDIS_KEY_PREFIX}:terminal_tool_gateway'
GATEWAY_URL_HEADER = 'X-OpenWebUI-Tool-Gateway-Url'
GATEWAY_TOKEN_HEADER = 'X-OpenWebUI-Tool-Gateway-Token'
PROXY_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
HOP_BY_HOP_HEADERS = frozenset(
    {
        'connection',
        'keep-alive',
        'proxy-authenticate',
        'proxy-authorization',
        'te',
        'trailers',
        'transfer-encoding',
        'upgrade',
        'host',
        'content-length',
    }
)
STRIPPED_RESPONSE_HEADERS = frozenset(('transfer-encoding', 'connection', 'content-encoding', 'content-length'))
STREAMING_CONTENT_TYPES = ('application/octet-stream', 'image/', 'application/pdf')

_memory_tokens: dict[str, dict[str, Any]] = {}


def _token_key(token: str) -> str:
    return f'{TOKEN_REDIS_PREFIX}:{token}'


async def _store_token(request: Request, token: str, payload: dict[str, Any]) -> None:
    redis = getattr(request.app.state, 'redis', None)
    if redis is not None:
        await redis.set(_token_key(token), json.dumps(payload), ex=TOKEN_TTL_SECONDS)
        return

    _memory_tokens[token] = payload
    _prune_memory_tokens()


async def _load_token(request: Request, token: str) -> dict[str, Any] | None:
    redis = getattr(request.app.state, 'redis', None)
    if redis is not None:
        value = await redis.get(_token_key(token))
        if not value:
            return None
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        try:
            payload = json.loads(value)
        except Exception:
            return None
    else:
        payload = _memory_tokens.get(token)

    if not isinstance(payload, dict):
        return None
    if int(payload.get('exp', 0)) <= int(time.time()):
        _memory_tokens.pop(token, None)
        return None
    return payload


def _prune_memory_tokens() -> None:
    now = int(time.time())
    for token, payload in list(_memory_tokens.items()):
        if int(payload.get('exp', 0)) <= now:
            _memory_tokens.pop(token, None)


async def build_terminal_tool_gateway_seed_headers(
    request: Request,
    user: UserModel,
    terminal_id: str = '',
    metadata: dict[str, Any] | None = None,
) -> dict[str, str]:
    webui_url = str(getattr(request.app.state.config, 'WEBUI_URL', '') or '').rstrip('/')
    if not webui_url:
        return {}

    now = int(time.time())
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    payload = {
        'user_id': user.id,
        'terminal_id': terminal_id,
        'metadata': metadata or {},
        'iat': now,
        'exp': now + TOKEN_TTL_SECONDS,
    }
    await _store_token(request, token, payload)
    return {
        GATEWAY_URL_HEADER: f'{webui_url}/api/v1/ext/terminal-tool-gateway',
        GATEWAY_TOKEN_HEADER: token,
    }


def _extract_bearer_token(request: Request) -> str:
    authorization = request.headers.get('authorization', '')
    scheme, _, token = authorization.partition(' ')
    if scheme.lower() != 'bearer' or not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Missing terminal tool gateway token')
    return token


async def _validated_user_from_gateway_token(request: Request) -> tuple[UserModel, dict[str, Any]]:
    token = _extract_bearer_token(request)
    payload = await _load_token(request, token)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid or expired terminal tool gateway token')

    user = await Users.get_user_by_id(str(payload.get('user_id', '')))
    if user is None or user.role not in {'user', 'admin'}:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid terminal tool gateway user')
    return user, payload


def _sanitize_proxy_path(path: str) -> str | None:
    decoded = path
    for _ in range(8):
        once = unquote(decoded)
        if once == decoded:
            break
        decoded = once

    had_trailing_slash = decoded.endswith('/')
    normalized = posixpath.normpath(decoded)
    cleaned = normalized.lstrip('/')
    if cleaned.startswith('..') or cleaned == '.':
        return None
    if had_trailing_slash and cleaned and not cleaned.endswith('/'):
        cleaned += '/'
    return cleaned


def _gateway_config(connection: dict[str, Any]) -> dict[str, Any]:
    config = connection.get('config') if isinstance(connection.get('config'), dict) else {}
    gateway = config.get('terminal_gateway') if isinstance(config.get('terminal_gateway'), dict) else {}
    return gateway if gateway.get('enabled') else {}


def _is_gateway_request_allowed(gateway: dict[str, Any], method: str, path: str) -> bool:
    if not gateway:
        return False

    allowed_methods = gateway.get('allowed_methods')
    if isinstance(allowed_methods, list) and allowed_methods:
        if method.upper() not in {str(item).upper() for item in allowed_methods}:
            return False

    allowed_prefixes = gateway.get('allowed_path_prefixes')
    if isinstance(allowed_prefixes, list) and allowed_prefixes:
        normalized_path = '/' + path.lstrip('/')
        prefixes = [('/' + str(prefix).lstrip('/')).rstrip('/') for prefix in allowed_prefixes if str(prefix).strip()]
        return any(normalized_path == prefix or normalized_path.startswith(prefix + '/') for prefix in prefixes)

    return True


async def _resolve_tool_server(request: Request, server_id: str, user: UserModel):
    tool_servers = await get_tool_servers(request)
    server_data = next((server for server in tool_servers if server.get('id') == server_id), None)
    if server_data is None:
        raise HTTPException(status_code=404, detail=f"Tool server '{server_id}' not found")

    idx = server_data.get('idx', 0)
    connections = request.app.state.config.TOOL_SERVER_CONNECTIONS or []
    if idx >= len(connections):
        raise HTTPException(status_code=404, detail=f"Tool server '{server_id}' connection not found")

    connection = connections[idx]
    user_group_ids = {group.id for group in await Groups.get_groups_by_member_id(user.id)}
    if not await has_connection_access(user, connection, user_group_ids):
        raise HTTPException(status_code=403, detail='Access denied')

    return server_data, connection


async def _build_terminal_safe_tool_headers(
    request: Request,
    connection: dict[str, Any],
    user: UserModel,
    server_id: str,
    metadata: dict[str, Any],
) -> tuple[dict[str, str], dict[str, str]]:
    auth_type = connection.get('auth_type', 'bearer')
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}

    if auth_type == 'bearer':
        headers['Authorization'] = f'Bearer {connection.get("key", "")}'
    elif auth_type in ('oauth_2.1', 'oauth_2.1_static'):
        try:
            oauth_server_id = server_id.split(':')[-1]
            connection_type = connection.get('type', 'openapi')
            oauth_token = await request.app.state.oauth_client_manager.get_oauth_token(
                user.id, f'{connection_type}:{oauth_server_id}'
            )
            if oauth_token:
                headers['Authorization'] = f'Bearer {oauth_token.get("access_token", "")}'
        except Exception as e:
            log.error(f'Error getting OAuth token for terminal gateway: {e}')
    elif auth_type in ('session', 'system_oauth'):
        # Deliberately do not forward the user's Open WebUI browser/session credentials into terminal-originated calls.
        pass

    connection_headers = connection.get('headers', None)
    if connection_headers and isinstance(connection_headers, dict):
        headers.update(get_custom_headers(connection_headers, user, metadata))

    if ENABLE_FORWARD_USER_INFO_HEADERS and user:
        headers = include_user_info_headers(headers, user)
        if metadata.get('chat_id'):
            headers[FORWARD_SESSION_INFO_HEADER_CHAT_ID] = metadata['chat_id']
        if metadata.get('message_id'):
            headers[FORWARD_SESSION_INFO_HEADER_MESSAGE_ID] = metadata['message_id']

    return headers, cookies


def _forward_request_headers(request: Request) -> dict[str, str]:
    forwarded = {}
    for key, value in request.headers.items():
        lower = key.lower()
        if lower in HOP_BY_HOP_HEADERS or lower == 'authorization':
            continue
        if lower.startswith('x-openwebui-tool-gateway'):
            continue
        forwarded[key] = value
    return forwarded


@router.api_route('/{server_id}/{path:path}', methods=PROXY_METHODS)
async def proxy_terminal_tool_gateway(server_id: str, path: str, request: Request):
    user, token_payload = await _validated_user_from_gateway_token(request)
    server_data, connection = await _resolve_tool_server(request, server_id, user)

    gateway = _gateway_config(connection)
    safe_path = _sanitize_proxy_path(path)
    if safe_path is None:
        return JSONResponse({'error': 'Invalid path'}, status_code=400)
    if not _is_gateway_request_allowed(gateway, request.method, safe_path):
        return JSONResponse({'error': 'Terminal gateway access is not allowed for this tool server route'}, status_code=403)

    metadata = token_payload.get('metadata') if isinstance(token_payload.get('metadata'), dict) else {}
    tool_headers, cookies = await _build_terminal_safe_tool_headers(request, connection, user, server_id, metadata)
    headers = {**_forward_request_headers(request), **tool_headers}

    target_url = f'{server_data["url"].rstrip("/")}/{safe_path}'
    if request.query_params:
        target_url += f'?{request.query_params}'

    body = await request.body()
    session = aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=AIOHTTP_CLIENT_TIMEOUT_TOOL_SERVER),
        trust_env=True,
    )
    try:
        upstream_response = await session.request(
            method=request.method,
            url=target_url,
            headers=headers,
            cookies=cookies,
            data=body or None,
            ssl=AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL,
            allow_redirects=AIOHTTP_CLIENT_ALLOW_REDIRECTS,
        )

        response_headers = {
            key: value
            for key, value in upstream_response.headers.items()
            if key.lower() not in STRIPPED_RESPONSE_HEADERS
        }
        content_type = upstream_response.headers.get('content-type', '')
        if any(stream_type in content_type for stream_type in STREAMING_CONTENT_TYPES):

            async def cleanup():
                upstream_response.release()
                await session.close()

            return StreamingResponse(
                content=upstream_response.content.iter_any(),
                status_code=upstream_response.status,
                headers=response_headers,
                background=BackgroundTask(cleanup),
            )

        response_body = await upstream_response.read()
        status_code = upstream_response.status
        upstream_response.release()
        await session.close()
        return Response(content=response_body, status_code=status_code, headers=response_headers)
    except Exception as error:
        await session.close()
        log.exception('Terminal tool gateway proxy error: %s', error)
        return JSONResponse({'error': f'Terminal tool gateway proxy error: {error}'}, status_code=502)


async def _list_allowed_servers(request: Request) -> dict[str, Any]:
    user, _ = await _validated_user_from_gateway_token(request)
    tool_servers = await get_tool_servers(request)
    connections = request.app.state.config.TOOL_SERVER_CONNECTIONS or []
    user_group_ids = {group.id for group in await Groups.get_groups_by_member_id(user.id)}

    servers = []
    for server_data in tool_servers:
        idx = server_data.get('idx', 0)
        if idx >= len(connections):
            continue

        connection = connections[idx]
        gateway = _gateway_config(connection)
        if not gateway:
            continue
        if not await has_connection_access(user, connection, user_group_ids):
            continue

        connection_info = connection.get('info') if isinstance(connection.get('info'), dict) else {}
        info = server_data.get('openapi', {}).get('info', {}) or server_data.get('info') or {}
        servers.append(
            {
                'id': server_data.get('id'),
                'name': info.get('title') or info.get('name') or connection_info.get('name') or '',
                'description': info.get('description') or connection_info.get('description') or '',
                'allowed_methods': gateway.get('allowed_methods') or [],
                'allowed_path_prefixes': gateway.get('allowed_path_prefixes') or [],
            }
        )

    return {'servers': servers}


@router.get('')
async def list_terminal_tool_gateway_servers_no_slash(request: Request):
    return await _list_allowed_servers(request)


@router.get('/')
async def list_terminal_tool_gateway_servers(request: Request):
    return await _list_allowed_servers(request)

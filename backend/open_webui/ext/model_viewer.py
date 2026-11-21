"""Model viewer tab: open/drive an ACC Docs model from sobe-forma-service tool results (fork item 32).

Tool results carry identifiers only. The tab asks this router for a short-lived
viewables:read token, which it fetches from the same tool server connection
(its own headers, access grants and user forwarding) and keeps only in memory.
"""

from __future__ import annotations

import json
import logging
from typing import Annotated

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from open_webui.models.config import Config
from open_webui.env import AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL
from open_webui.models.groups import Groups
from open_webui.utils.access_control import has_connection_access
from open_webui.utils.auth import get_verified_user
from open_webui.utils.tools import build_tool_server_headers, get_tool_server_url, get_tool_servers

log = logging.getLogger(__name__)
router = APIRouter()

TOKEN_PATH = '/viewer/token'
MAX_TOKEN_RESPONSE_BYTES = 262_144
MAX_MODELS = 5


class TokenForm(BaseModel):
    model_config = ConfigDict(extra='forbid')
    server_id: str = Field(min_length=1, max_length=256)
    project_id: str = Field(min_length=1, max_length=256)
    version_ids: list[Annotated[str, Field(min_length=1, max_length=2048)]] = Field(min_length=1, max_length=MAX_MODELS)
    region: str | None = Field(None, max_length=16)


def server_id_from_tool(tool: dict | None) -> str | None:
    """OpenAPI tool-server ID from `server:<id>` / `server:openapi:<id>` (optionally `|functions`)."""
    tool_id = str((tool or {}).get('tool_id', ''))
    if (tool or {}).get('type') != 'external' or not tool_id.startswith('server:'):
        return None
    parts = tool_id.split(':')
    if len(parts) == 2:
        server_id = parts[1]
    elif len(parts) >= 3 and parts[1] == 'openapi':
        server_id = ':'.join(parts[2:])
    else:
        return None
    return server_id.split('|')[0] or None


def _data(result) -> dict:
    try:
        parsed = json.loads(result) if isinstance(result, str) else result
    except (TypeError, ValueError):
        return {}
    data = parsed.get('data') if isinstance(parsed, dict) else None
    return data if isinstance(data, dict) else {}


async def model_viewer_event(result, tool: dict | None, event_emitter) -> None:
    """Emit model_viewer:open / model_viewer:command for viewer tool results; ignore everything else."""
    if not event_emitter:
        return
    data = _data(result)
    model, command = data.get('model_viewer'), data.get('model_viewer_command')
    if not isinstance(model, dict) and not isinstance(command, dict):
        return
    server_id = server_id_from_tool(tool)
    if not server_id:
        return
    version_ids = (model or {}).get('version_ids') if isinstance(model, dict) else None
    if (
        isinstance(model, dict)
        and isinstance(model.get('project_id'), str)
        and isinstance(version_ids, list)
        and 0 < len(version_ids) <= MAX_MODELS
        and all(isinstance(v, str) for v in version_ids)
    ):
        await event_emitter(
            {
                'type': 'model_viewer:open',
                'data': {
                    'serverId': server_id,
                    'projectId': model['project_id'],
                    'versionIds': version_ids,
                    'region': model.get('region') if isinstance(model.get('region'), str) else None,
                    'name': str(model.get('name') or 'Model')[:200],
                },
            }
        )
    elif isinstance(command, dict) and isinstance(command.get('action'), str):
        await event_emitter({'type': 'model_viewer:command', 'data': command})


@router.post('/token')
async def viewer_token(request: Request, form: TokenForm, user=Depends(get_verified_user)):
    server = next(
        (s for s in await get_tool_servers(request) if s.get('id') == form.server_id),
        None,
    )
    connections = await Config.get('tool_server.connections', []) or []
    idx = (server or {}).get('idx', 0)
    connection = connections[idx] if server and isinstance(idx, int) and 0 <= idx < len(connections) else None
    if not connection:
        raise HTTPException(404, 'Tool server not found')
    group_ids = {group.id for group in await Groups.get_groups_by_member_id(user.id, include_inherited=True)}
    if not await has_connection_access(user, connection, group_ids):
        raise HTTPException(404, 'Tool server not found')

    headers, cookies = await build_tool_server_headers(connection, request, user, server_id=form.server_id)
    body = form.model_dump(exclude={'server_id'}, exclude_none=True)
    try:
        async with aiohttp.ClientSession(trust_env=True, timeout=aiohttp.ClientTimeout(total=30)) as session:
            async with session.post(
                get_tool_server_url(server.get('url'), TOKEN_PATH),
                json=body,
                headers=headers,
                cookies=cookies,
                ssl=AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL,
                allow_redirects=False,
            ) as response:
                raw = await response.content.read(MAX_TOKEN_RESPONSE_BYTES + 1)
                status = response.status
    except (aiohttp.ClientError, TimeoutError):
        raise HTTPException(502, 'Model viewer token service unavailable') from None
    if len(raw) > MAX_TOKEN_RESPONSE_BYTES:
        raise HTTPException(502, 'Model viewer token response too large')
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = {}
    if status != 200:
        detail = payload.get('detail') if isinstance(payload, dict) and isinstance(payload.get('detail'), str) else None
        raise HTTPException(
            status if status in (401, 403, 404, 422, 429, 503) else 502, detail or 'Model viewer token unavailable'
        )
    models = payload.get('models') if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get('access_token'), str)
        or not isinstance(models, list)
        or not models
        or not all(isinstance(m, dict) and isinstance(m.get('urn'), str) for m in models)
    ):
        raise HTTPException(502, 'Invalid model viewer token response')
    return JSONResponse(payload, headers={'Cache-Control': 'no-store'})

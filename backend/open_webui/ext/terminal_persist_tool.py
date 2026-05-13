import io
import os
from typing import Any, Optional
from urllib.parse import urlencode

import aiohttp
from fastapi import HTTPException, Request, UploadFile

from open_webui.env import (
    AIOHTTP_CLIENT_ALLOW_REDIRECTS,
    AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL,
    AIOHTTP_CLIENT_TIMEOUT_TOOL_SERVER,
)
from open_webui.models.users import UserModel
from open_webui.routers.files import upload_file_handler


def _safe_filename_from_path(path: str) -> str:
    filename = os.path.basename(path.rstrip('/\\'))
    return filename or 'upload.bin'


def _filename_from_disposition(content_disposition: str, fallback: str) -> str:
    if not content_disposition:
        return fallback

    for part in content_disposition.split(';'):
        part = part.strip()
        if not part.lower().startswith('filename='):
            continue
        value = part.split('=', 1)[1].strip().strip('"')
        return value or fallback

    return fallback


async def persist_terminal_file_to_platform(
    request: Request,
    user: UserModel,
    base_url: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    path: str,
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    if not isinstance(path, str) or not path.strip():
        raise HTTPException(status_code=400, detail='A file path is required.')

    normalized_path = path.strip()
    base = base_url.rstrip('/')
    query = urlencode({'directory': normalized_path})
    list_url = f'{base}/files/list?{query}'
    view_query = urlencode({'path': normalized_path})
    view_url = f'{base}/files/view?{view_query}'

    timeout = aiohttp.ClientTimeout(total=AIOHTTP_CLIENT_TIMEOUT_TOOL_SERVER)

    async with aiohttp.ClientSession(timeout=timeout, trust_env=True) as session:
        # Directory check: /files/list succeeds only for directories.
        async with session.get(
            list_url,
            headers=headers,
            cookies=cookies,
            ssl=AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL,
            allow_redirects=AIOHTTP_CLIENT_ALLOW_REDIRECTS,
        ) as list_response:
            if list_response.status == 200:
                raise HTTPException(
                    status_code=400,
                    detail='Directories are not supported. Zip first, then upload the .zip file.',
                )
            if list_response.status in (401, 403):
                body = await list_response.text()
                raise HTTPException(
                    status_code=502,
                    detail=f'Terminal authorization failed: HTTP {list_response.status}: {body[:300]}',
                )

        async with session.get(
            view_url,
            headers=headers,
            cookies=cookies,
            ssl=AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL,
            allow_redirects=AIOHTTP_CLIENT_ALLOW_REDIRECTS,
        ) as file_response:
            if file_response.status == 404:
                raise HTTPException(status_code=404, detail=f'File not found: {normalized_path}')
            if file_response.status >= 400:
                body = await file_response.text()
                raise HTTPException(
                    status_code=502,
                    detail=f'Failed to fetch file from terminal: HTTP {file_response.status}: {body[:300]}',
                )

            file_bytes = await file_response.read()
            if file_bytes is None:
                file_bytes = b''

            content_type = file_response.headers.get('Content-Type', 'application/octet-stream')
            fallback_name = _safe_filename_from_path(normalized_path)
            content_disposition = file_response.headers.get('Content-Disposition', '')
            filename = _filename_from_disposition(content_disposition, fallback_name)

    upload = UploadFile(
        file=io.BytesIO(file_bytes),
        filename=filename,
        headers={'content-type': content_type},
    )

    file_metadata = {
        'source': 'terminal',
        'terminal_path': normalized_path,
        **({'chat_id': metadata.get('chat_id')} if isinstance(metadata, dict) and metadata.get('chat_id') else {}),
    }

    file_item = await upload_file_handler(
        request,
        file=upload,
        metadata=file_metadata,
        process=False,
        process_in_background=False,
        user=user,
    )

    return {
        'message': 'file uploaded to ai platform',
        'file_id': file_item.id,
    }

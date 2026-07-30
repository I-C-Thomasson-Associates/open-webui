import asyncio
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
from open_webui.models.files import Files
from open_webui.models.config import Config
from open_webui.models.users import UserModel
from open_webui.routers.files import upload_file_handler
from open_webui.storage.provider import Storage
from open_webui.utils.access_control.files import has_access_to_file

DEFAULT_TERMINAL_FILE_MAX_BYTES = 25 * 1024 * 1024


async def _get_terminal_file_max_bytes() -> int:
    configured_max_mb = await Config.get('rag.file.max_size')
    try:
        max_bytes = int(configured_max_mb) * 1024 * 1024
    except (TypeError, ValueError):
        return DEFAULT_TERMINAL_FILE_MAX_BYTES
    return max_bytes if max_bytes > 0 else DEFAULT_TERMINAL_FILE_MAX_BYTES


def _read_bounded_file(path: str, max_bytes: int) -> bytes:
    if os.path.getsize(path) > max_bytes:
        raise HTTPException(status_code=413, detail='Platform file exceeds the configured upload size limit.')

    chunks: list[bytes] = []
    size = 0
    with open(path, 'rb') as file:
        while chunk := file.read(min(64 * 1024, max_bytes - size + 1)):
            size += len(chunk)
            if size > max_bytes:
                raise HTTPException(status_code=413, detail='Platform file exceeds the configured upload size limit.')
            chunks.append(chunk)
    return b''.join(chunks)


def _encode_bounded_text(content: Any, max_bytes: int) -> bytes:
    text = str(content or '')
    chunks: list[bytes] = []
    size = 0
    for offset in range(0, len(text), 64 * 1024):
        chunk = text[offset : offset + 64 * 1024].encode('utf-8')
        size += len(chunk)
        if size > max_bytes:
            raise HTTPException(status_code=413, detail='Platform file exceeds the configured upload size limit.')
        chunks.append(chunk)
    return b''.join(chunks)


async def _read_bounded_response(response: aiohttp.ClientResponse) -> bytes:
    max_bytes = await _get_terminal_file_max_bytes()
    content_length = response.content_length
    if content_length is not None and content_length > max_bytes:
        raise HTTPException(status_code=413, detail='Terminal file exceeds the configured upload size limit.')

    chunks: list[bytes] = []
    size = 0
    async for chunk in response.content.iter_chunked(64 * 1024):
        size += len(chunk)
        if size > max_bytes:
            raise HTTPException(status_code=413, detail='Terminal file exceeds the configured upload size limit.')
        chunks.append(chunk)
    return b''.join(chunks)


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


def _resolve_terminal_upload_target(path: str, fallback_filename: str) -> tuple[str, str]:
    normalized = path.strip()

    if normalized.endswith(('/', '\\')):
        directory = normalized.rstrip('/\\')
        if not directory:
            directory = '/'
        return directory, fallback_filename

    separator_index = max(normalized.rfind('/'), normalized.rfind('\\'))
    if separator_index < 0:
        return '.', normalized

    directory = normalized[:separator_index]
    filename = normalized[separator_index + 1 :]

    if not directory:
        directory = '/' if normalized.startswith(('/', '\\')) else '.'

    return directory, filename or fallback_filename


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

            file_bytes = await _read_bounded_response(file_response)

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
        'download_url': f'/api/v1/files/{file_item.id}/content',
        'download_markdown': f'[Download {file_item.filename}](/api/v1/files/{file_item.id}/content)',
    }


async def transfer_platform_file_to_terminal(
    request: Request,
    user: UserModel,
    base_url: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    file_id: str,
    path: str,
) -> dict[str, Any]:
    if not isinstance(file_id, str) or not file_id.strip():
        raise HTTPException(status_code=400, detail='A file_id is required.')
    if not isinstance(path, str) or not path.strip():
        raise HTTPException(status_code=400, detail='A destination path is required.')

    normalized_file_id = file_id.strip()
    source_file = await Files.get_file_by_id(normalized_file_id)
    if not source_file:
        raise HTTPException(status_code=404, detail='File not found.')

    can_read = source_file.user_id == user.id or user.role == 'admin' or await has_access_to_file(
        normalized_file_id,
        'read',
        user,
    )
    if not can_read:
        raise HTTPException(status_code=404, detail='File not found.')

    source_filename = source_file.filename or 'download.bin'
    content_type = 'application/octet-stream'
    if isinstance(source_file.meta, dict) and isinstance(source_file.meta.get('content_type'), str):
        content_type = source_file.meta.get('content_type')

    directory, target_filename = _resolve_terminal_upload_target(path, source_filename)
    max_bytes = await _get_terminal_file_max_bytes()

    if source_file.path:
        try:
            source_path = await asyncio.to_thread(Storage.get_file, source_file.path)
            file_bytes = await asyncio.to_thread(_read_bounded_file, source_path, max_bytes)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail='Stored file content not found.')
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f'Failed to read stored file: {str(e)}')
    else:
        content = ''
        if isinstance(source_file.data, dict):
            content = source_file.data.get('content', '')
        file_bytes = _encode_bounded_text(content, max_bytes)
        if content_type == 'application/octet-stream':
            content_type = 'text/plain'

    if len(file_bytes) > max_bytes:
        raise HTTPException(status_code=413, detail='Platform file exceeds the configured upload size limit.')

    base = base_url.rstrip('/')
    query = urlencode({'directory': directory})
    upload_url = f'{base}/files/upload?{query}'

    upload_headers = {
        key: value
        for key, value in headers.items()
        if key.lower() not in ('content-type', 'content-length')
    }

    form = aiohttp.FormData()
    form.add_field('file', file_bytes, filename=target_filename, content_type=content_type)

    timeout = aiohttp.ClientTimeout(total=AIOHTTP_CLIENT_TIMEOUT_TOOL_SERVER)

    async with aiohttp.ClientSession(timeout=timeout, trust_env=True) as session:
        async with session.post(
            upload_url,
            headers=upload_headers,
            cookies=cookies,
            data=form,
            ssl=AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL,
            allow_redirects=AIOHTTP_CLIENT_ALLOW_REDIRECTS,
        ) as upload_response:
            if upload_response.status in (401, 403):
                body = await upload_response.text()
                raise HTTPException(
                    status_code=502,
                    detail=f'Terminal authorization failed: HTTP {upload_response.status}: {body[:300]}',
                )
            if upload_response.status >= 400:
                body = await upload_response.text()
                raise HTTPException(
                    status_code=502,
                    detail=f'Failed to transfer file to terminal: HTTP {upload_response.status}: {body[:300]}',
                )

            try:
                response_data = await upload_response.json(content_type=None)
            except Exception:
                response_data = {}

    return {
        'message': 'file transferred to terminal',
        'file_id': normalized_file_id,
        'path': response_data.get('path', path),
        'filename': target_filename,
        'size': len(file_bytes),
    }

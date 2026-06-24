import base64
import io
import os
import re
from typing import Any
from urllib.parse import unquote, unquote_to_bytes

from fastapi import Request, UploadFile

from open_webui.models.chats import Chats
from open_webui.models.users import UserModel
from open_webui.routers.files import upload_file_handler

TOOL_RESULT_ATTACHMENT_MAX_BYTES = int(
    os.getenv('TOOL_RESULT_ATTACHMENT_MAX_BYTES', '26214400')
)
_DEFAULT_FILENAME = 'tool-result.bin'


def _get_header(headers: dict[str, Any] | None, name: str) -> str:
    if not isinstance(headers, dict):
        return ''
    name = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == name:
            return value if isinstance(value, str) else str(value)
    return ''


def _safe_filename(value: str | None) -> str:
    if not value:
        return _DEFAULT_FILENAME

    value = unquote(value).replace('\\', '/').rsplit('/', 1)[-1]
    value = re.sub(r'[\x00-\x1f\x7f]', '', value).strip().strip('.')
    return value or _DEFAULT_FILENAME


def _filename_from_content_disposition(content_disposition: str) -> str | None:
    if not content_disposition:
        return None

    match = re.search(r"filename\*\s*=\s*([^;]+)", content_disposition, flags=re.IGNORECASE)
    if match:
        value = match.group(1).strip().strip('"')
        charset = 'utf-8'
        encoded = value
        if "''" in value:
            charset, _, encoded = value.partition("''")
        try:
            raw = unquote_to_bytes(encoded)
            return raw.decode(charset or 'utf-8', errors='replace')
        except Exception:
            return unquote(encoded)

    match = re.search(r'filename\s*=\s*"?([^";]+)"?', content_disposition, flags=re.IGNORECASE)
    if match:
        return match.group(1).strip()

    return None


def is_attachment_response(headers: dict[str, Any] | None) -> bool:
    content_disposition = _get_header(headers, 'content-disposition')
    return 'attachment' in content_disposition.lower()


def _parse_base64_data_uri(data_uri: str) -> tuple[bytes, str | None] | None:
    if not isinstance(data_uri, str) or not data_uri.startswith('data:'):
        return None

    if ',' not in data_uri:
        return None

    header, payload = data_uri.split(',', 1)
    if ';base64' not in header.lower():
        return None

    mime_type = header[5:].split(';', 1)[0].strip() or None
    estimated_size = (len(payload) * 3) // 4
    if estimated_size > TOOL_RESULT_ATTACHMENT_MAX_BYTES:
        return None

    try:
        data = base64.b64decode(payload, validate=True)
    except Exception:
        return None

    if len(data) > TOOL_RESULT_ATTACHMENT_MAX_BYTES:
        return None

    return data, mime_type


async def handle_tool_result_attachment(
    request: Request,
    tool_result: Any,
    response_headers: dict[str, Any] | None,
    metadata: dict[str, Any] | None,
    user: UserModel | None,
) -> tuple[dict[str, Any] | str | None, list[dict[str, Any]]]:
    if user is None or not is_attachment_response(response_headers):
        return None, []

    if not isinstance(tool_result, str):
        return None, []

    parsed = _parse_base64_data_uri(tool_result)
    if not parsed:
        return None, []

    payload, data_uri_content_type = parsed

    content_disposition = _get_header(response_headers, 'content-disposition')
    filename = _safe_filename(_filename_from_content_disposition(content_disposition))

    desired_content_type = (
        _get_header(response_headers, 'x-openwebui-file-content-type')
        or _get_header(response_headers, 'content-type').split(';', 1)[0].strip()
        or data_uri_content_type
        or 'application/octet-stream'
    )

    upload = UploadFile(
        file=io.BytesIO(payload),
        filename=filename,
        headers={'content-type': desired_content_type},
    )

    file_metadata = {
        'source': 'tool_result_attachment',
    }

    file_item = await upload_file_handler(
        request,
        file=upload,
        metadata=file_metadata,
        process=False,
        process_in_background=False,
        user=user,
    )

    file_id = getattr(file_item, 'id', None)
    if not file_id:
        return None, []

    chat_id = metadata.get('chat_id') if isinstance(metadata, dict) else None
    message_id = metadata.get('message_id') if isinstance(metadata, dict) else None

    if chat_id and message_id:
        await Chats.insert_chat_files(
            chat_id=chat_id,
            message_id=message_id,
            file_ids=[file_id],
            user_id=user.id,
        )

    filename_out = getattr(file_item, 'filename', filename)
    content_type_out = desired_content_type
    size = len(payload)

    file_meta = getattr(file_item, 'meta', None)
    if isinstance(file_meta, dict):
        if isinstance(file_meta.get('name'), str):
            filename_out = file_meta.get('name')
        if isinstance(file_meta.get('content_type'), str) and file_meta.get('content_type'):
            content_type_out = file_meta.get('content_type')
        if isinstance(file_meta.get('size'), int):
            size = file_meta.get('size')

    file_event_item = {
        'type': 'file',
        'id': file_id,
        'url': f'/api/v1/files/{file_id}/content',
        'name': filename_out,
        'size': size,
        'content_type': content_type_out,
    }

    message = {
        'status': 'success',
        'message': f'Tool returned file {filename_out} and it was attached to this chat.',
        'file_id': file_id,
        'filename': filename_out,
    }

    return message, [file_event_item]

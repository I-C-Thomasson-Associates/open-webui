import base64
import io
import os
import re
from typing import Any
from urllib.parse import unquote, unquote_to_bytes

from fastapi import Request, UploadFile

from open_webui.models.chats import Chats
from open_webui.models.files import Files
from open_webui.models.users import UserModel
from open_webui.routers.files import upload_file_handler

TOOL_RESULT_ATTACHMENT_MAX_BYTES = int(
    os.getenv('TOOL_RESULT_ATTACHMENT_MAX_BYTES', '26214400')
)
TOOL_RESULT_ATTACHMENT_CITATION_MAX_CHARS = int(
    os.getenv('TOOL_RESULT_ATTACHMENT_CITATION_MAX_CHARS', '120000')
)
_DEFAULT_FILENAME = 'tool-result.bin'

_TEXT_ATTACHMENT_CONTENT_TYPES = (
    'text/',
    'application/json',
    'application/xml',
    'application/yaml',
    'application/x-yaml',
    'application/markdown',
)


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


def _is_textual_content_type(content_type: str | None) -> bool:
    if not isinstance(content_type, str):
        return False
    normalized = content_type.lower().strip()
    return any(normalized.startswith(prefix) for prefix in _TEXT_ATTACHMENT_CONTENT_TYPES)


def _decode_text_attachment(payload: bytes, content_type: str | None) -> str | None:
    if not _is_textual_content_type(content_type):
        return None

    text = payload.decode('utf-8', errors='replace').strip()
    if not text:
        return None

    if len(text) > TOOL_RESULT_ATTACHMENT_CITATION_MAX_CHARS:
        text = text[:TOOL_RESULT_ATTACHMENT_CITATION_MAX_CHARS]

    return text


def _file_id_from_upload_result(file_item: Any) -> str | None:
    if isinstance(file_item, dict):
        file_id = file_item.get('id')
        if isinstance(file_id, str) and file_id:
            return file_id
        nested = file_item.get('file')
        if isinstance(nested, dict):
            nested_id = nested.get('id')
            if isinstance(nested_id, str) and nested_id:
                return nested_id
        return None

    file_id = getattr(file_item, 'id', None)
    if isinstance(file_id, str) and file_id:
        return file_id
    return None


def _file_meta_from_upload_result(file_item: Any) -> dict[str, Any]:
    if isinstance(file_item, dict):
        meta = file_item.get('meta')
        return meta if isinstance(meta, dict) else {}

    meta = getattr(file_item, 'meta', None)
    return meta if isinstance(meta, dict) else {}


def _file_name_from_upload_result(file_item: Any) -> str | None:
    if isinstance(file_item, dict):
        value = file_item.get('filename')
        return value if isinstance(value, str) and value else None

    value = getattr(file_item, 'filename', None)
    return value if isinstance(value, str) and value else None


def _append_file_to_metadata(metadata: dict[str, Any] | None, file_event_item: dict[str, Any]) -> None:
    if not isinstance(metadata, dict):
        return

    files = metadata.setdefault('files', [])
    if not isinstance(files, list):
        metadata['files'] = []
        files = metadata['files']

    file_id = file_event_item.get('id')
    if not isinstance(file_id, str) or not file_id:
        return

    if any(isinstance(existing, dict) and existing.get('id') == file_id for existing in files):
        return

    files.append(
        {
            **file_event_item,
            'context': 'full',
        }
    )


async def _emit_attachment_source_event(
    metadata: dict[str, Any] | None,
    user: UserModel,
    file_id: str,
    filename: str,
    document: str,
) -> None:
    if not isinstance(metadata, dict):
        return

    chat_id = metadata.get('chat_id')
    message_id = metadata.get('message_id')
    if not isinstance(chat_id, str) or not chat_id or not isinstance(message_id, str) or not message_id:
        return

    try:
        from open_webui.socket.main import get_event_emitter

        emitter = await get_event_emitter(
            {
                'user_id': user.id,
                'chat_id': chat_id,
                'message_id': message_id,
            }
        )
    except Exception:
        return

    if emitter is None:
        return

    await emitter(
        {
            'type': 'source',
            'data': {
                'source': {
                    'id': file_id,
                    'name': filename,
                    'type': 'file',
                },
                'document': [document],
                'metadata': [
                    {
                        'file_id': file_id,
                        'name': filename,
                        'source': filename,
                    }
                ],
            },
        }
    )


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
        if tool_result.startswith('data:'):
            return {
                'status': 'error',
                'message': 'Tool attachment was invalid or exceeded the configured size limit.',
            }, []
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

    try:
        file_item = await upload_file_handler(
            request,
            file=upload,
            metadata=file_metadata,
            process=True,
            process_in_background=False,
            user=user,
        )
    except Exception:
        upload.file.seek(0)
        file_item = await upload_file_handler(
            request,
            file=upload,
            metadata=file_metadata,
            process=False,
            process_in_background=False,
            user=user,
        )

    file_id = _file_id_from_upload_result(file_item)
    if not file_id:
        return None, []

    chat_id = metadata.get('chat_id') if isinstance(metadata, dict) else None
    message_id = metadata.get('message_id') if isinstance(metadata, dict) else None

    if chat_id and message_id:
        owned_chat = await Chats.get_chat_by_id_and_user_id(chat_id, user.id)
        if owned_chat:
            await Chats.insert_chat_files(
                chat_id=chat_id,
                message_id=message_id,
                file_ids=[file_id],
                user_id=user.id,
            )

    filename_out = _file_name_from_upload_result(file_item) or filename
    content_type_out = desired_content_type
    size = len(payload)

    file_meta = _file_meta_from_upload_result(file_item)
    if file_meta:
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

    _append_file_to_metadata(metadata, file_event_item)

    attachment_text = None
    file_record = await Files.get_file_by_id(file_id)
    if file_record and isinstance(file_record.data, dict):
        attachment_text = _decode_text_attachment(
            (file_record.data.get('content') or '').encode('utf-8', errors='replace')
            if isinstance(file_record.data.get('content'), str)
            else b'',
            content_type_out,
        )

    if attachment_text:
        await _emit_attachment_source_event(
            metadata=metadata,
            user=user,
            file_id=file_id,
            filename=filename_out,
            document=attachment_text,
        )

    message = {
        'status': 'success',
        'message': f'Tool returned file {filename_out} and it was attached to this chat.',
        'file_id': file_id,
        'filename': filename_out,
    }

    return message, [file_event_item]

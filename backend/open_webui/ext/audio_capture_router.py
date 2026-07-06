"""Capture audio transcription endpoint isolated from core audio router."""

import asyncio
import json
import logging
import os
import uuid
from typing import Optional
from types import SimpleNamespace

import requests
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status

from open_webui.config import CACHE_DIR
from open_webui.constants import ERROR_MESSAGES
from open_webui.env import AIOHTTP_CLIENT_TIMEOUT
from open_webui.ext.audio_transcription import (
    build_azure_definition,
    format_azure_transcription_response,
    get_azure_max_speakers,
    post_azure_fast_transcription,
)
from open_webui.models.config import Config
from open_webui.routers import audio
from open_webui.utils.access_control import has_permission
from open_webui.utils.auth import get_verified_user
from open_webui.utils.misc import strict_match_mime_type

log = logging.getLogger(__name__)
router = APIRouter()

_AZURE_USER_FACING_CODES = {
    'EmptyAudioFile',
    'AudioLengthLimitExceeded',
    'NoLanguageIdentified',
    'MultipleLanguagesIdentified',
}

_AZURE_DEFAULT_LOCALES = ','.join(
    [
        'en-US',
        'es-ES',
        'es-MX',
        'fr-FR',
        'hi-IN',
        'it-IT',
        'de-DE',
        'en-GB',
        'en-IN',
        'ja-JP',
        'ko-KR',
        'pt-BR',
        'zh-CN',
    ]
)


def _build_azure_error_detail(response: Optional[requests.Response], exc: Exception) -> str:
    detail = None

    if response is not None:
        try:
            res = response.json()
            if 'code' in res and 'message' in res:
                azure_code = res.get('innerError', {}).get('code', res['code'])
                if azure_code in _AZURE_USER_FACING_CODES:
                    detail = res['message']
                else:
                    log.error(f'Azure STT error [{azure_code}]: {res["message"]}')
                    detail = 'An error occurred during transcription.'
            elif 'error' in res:
                detail = f'External: {res["error"].get("message", "")}'
        except Exception:
            detail = f'External: {exc}'

    return detail if detail else 'Open WebUI: Server Connection Error'


async def _transcribe_capture_azure(request: Request, file_path: str, metadata: dict):
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=400, detail='Audio file not found')

    audio_size = os.path.getsize(file_path)
    if audio_size > audio.AZURE_MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'File size ({audio_size // (1024 * 1024)}MB) exceeds Azure limit of {audio.AZURE_MAX_FILE_SIZE_MB}MB',
        )

    stt_config = await Config.get_many(
        'audio.stt.azure.api_key',
        'audio.stt.azure.region',
        'audio.stt.azure.locales',
        'audio.stt.azure.base_url',
        'audio.stt.azure.max_speakers',
    )

    api_key = stt_config.get('audio.stt.azure.api_key')
    if not api_key:
        raise HTTPException(status_code=400, detail='Azure API key is required for Azure STT')

    region = stt_config.get('audio.stt.azure.region') or 'eastus'
    locales = stt_config.get('audio.stt.azure.locales')
    if not locales or len(locales) < 2:
        locales = _AZURE_DEFAULT_LOCALES
    base_url = stt_config.get('audio.stt.azure.base_url')
    max_speakers = get_azure_max_speakers(
        SimpleNamespace(AUDIO_STT_AZURE_MAX_SPEAKERS=stt_config.get('audio.stt.azure.max_speakers'))
    )
    diarize = bool(metadata.get('diarize'))

    url = (base_url or f'https://{region}.api.cognitive.microsoft.com') + (
        '/speechtotext/transcriptions:transcribe?api-version=2024-11-15'
    )
    definition = build_azure_definition(locales, max_speakers, diarize=diarize)

    response = None
    try:
        response = await asyncio.to_thread(
            post_azure_fast_transcription,
            file_path=file_path,
            url=url,
            api_key=api_key,
            definition=definition,
            timeout=AIOHTTP_CLIENT_TIMEOUT,
            log=log,
        )

        response.raise_for_status()
        data = format_azure_transcription_response(response.json(), diarize=diarize)

        transcript_path = os.path.join(os.path.dirname(file_path), f'{os.path.splitext(os.path.basename(file_path))[0]}.json')
        with open(transcript_path, 'w') as f:
            json.dump(data, f)

        return data
    except (KeyError, IndexError, ValueError) as exc:
        log.exception('Error parsing Azure response')
        raise HTTPException(status_code=500, detail=f'Failed to parse Azure response: {str(exc)}')
    except requests.exceptions.RequestException as exc:
        log.exception(exc)
        status_code = response.status_code if response is not None else 500
        raise HTTPException(
            status_code=status_code,
            detail=_build_azure_error_detail(response, exc),
        )


@router.post('/capture/transcriptions')
async def capture_transcription(
    request: Request,
    file: UploadFile = File(...),
    language: Optional[str] = Form(None),
    diarize: Optional[bool] = Form(False),
    user=Depends(get_verified_user),
):
    user_permissions = await Config.get('user.permissions')
    if user.role != 'admin' and not await has_permission(user.id, 'chat.stt', user_permissions):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
        )

    stt_supported_content_types = await Config.get('audio.stt.supported_content_types', [])
    if not strict_match_mime_type(stt_supported_content_types, file.content_type):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.FILE_NOT_SUPPORTED,
        )

    try:
        safe_name = os.path.basename(file.filename) if file.filename else ''
        ext = safe_name.rsplit('.', 1)[-1].lower() if '.' in safe_name else ''

        allowed_extensions = await Config.get('audio.stt.allowed_extensions', [])
        if allowed_extensions and ext not in allowed_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Invalid audio file extension',
            )

        file_id = uuid.uuid4()
        filename = f'{file_id}.{ext}' if ext else str(file_id)
        contents = await file.read()

        file_dir = os.path.join(CACHE_DIR, 'audio', 'transcriptions')
        os.makedirs(file_dir, exist_ok=True)
        file_path = os.path.join(file_dir, filename)

        if not os.path.realpath(file_path).startswith(os.path.realpath(file_dir)):
            raise ValueError('Invalid file path detected')

        with open(file_path, 'wb') as f:
            f.write(contents)

        metadata = {}
        if language:
            metadata['language'] = language
        if diarize:
            metadata['diarize'] = True

        stt_engine = await Config.get('audio.stt.engine')
        if stt_engine == 'azure':
            result = await _transcribe_capture_azure(request, file_path, metadata)
        else:
            result = await audio.transcribe(request, file_path, metadata, user)

        return {
            **result,
            'filename': os.path.basename(file_path),
        }
    except HTTPException:
        raise
    except Exception as exc:
        log.exception(exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Transcription failed.',
        )

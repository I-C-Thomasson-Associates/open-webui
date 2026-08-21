"""Bounded streaming transport for browser-to-terminal file uploads.

``OPEN_WEBUI_TERMINAL_UPLOAD_MAX_BYTES`` defaults to 4 GiB and should match
the terminal orchestrator and runtime upload/request limits.
``OPEN_WEBUI_TERMINAL_UPLOAD_TIMEOUT_SECONDS`` defaults to one hour.
"""

import asyncio
import os
from collections.abc import AsyncIterator, Mapping

import aiohttp
from fastapi import Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from open_webui.config import TERMINAL_PROXY_HEADERS
from open_webui.env import AIOHTTP_CLIENT_SESSION_SSL


_DEFAULT_MAX_UPLOAD_BYTES = 4 * 1024 * 1024 * 1024
_DEFAULT_UPLOAD_TIMEOUT_SECONDS = 3600.0
_RESPONSE_STRIPPED_HEADERS = frozenset(
    ("transfer-encoding", "connection", "content-encoding", "content-length")
)


def _upload_max_bytes() -> int:
    """Return a positive, integer-safe upload cap without changing core config."""
    raw_value = os.getenv("OPEN_WEBUI_TERMINAL_UPLOAD_MAX_BYTES", str(_DEFAULT_MAX_UPLOAD_BYTES))
    try:
        value = int(raw_value)
    except ValueError:
        return _DEFAULT_MAX_UPLOAD_BYTES
    return value if value > 0 else _DEFAULT_MAX_UPLOAD_BYTES


def _upload_timeout_seconds() -> float:
    """Return a positive upload total timeout while keeping connects short."""
    raw_value = os.getenv(
        "OPEN_WEBUI_TERMINAL_UPLOAD_TIMEOUT_SECONDS",
        str(_DEFAULT_UPLOAD_TIMEOUT_SECONDS),
    )
    try:
        value = float(raw_value)
    except ValueError:
        return _DEFAULT_UPLOAD_TIMEOUT_SECONDS
    return value if value > 0 else _DEFAULT_UPLOAD_TIMEOUT_SECONDS


class UploadTooLargeError(ValueError):
    """Raised while passing an oversized request body upstream."""


def is_upload_too_large_error(exc: BaseException) -> bool:
    """Recognize wrapped body-producer errors without masking other failures."""
    seen: set[int] = set()
    pending = [exc]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        if isinstance(current, UploadTooLargeError):
            return True
        seen.add(id(current))
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return False


def _reject_oversized_content_length(request: Request, max_bytes: int) -> Response | None:
    raw_length = request.headers.get("content-length")
    if raw_length is None:
        return None
    try:
        content_length = int(raw_length)
    except ValueError:
        return JSONResponse({"error": "Invalid Content-Length header"}, status_code=400)
    if content_length < 0:
        return JSONResponse({"error": "Invalid Content-Length header"}, status_code=400)
    if content_length > max_bytes:
        return JSONResponse(
            {"error": f"Upload exceeds the {max_bytes}-byte limit"}, status_code=413
        )
    return None


async def _counted_stream(request: Request, max_bytes: int) -> AsyncIterator[bytes]:
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            raise UploadTooLargeError(f"Upload exceeds the {max_bytes}-byte limit")
        if chunk:
            yield chunk


async def proxy_terminal_upload(
    request: Request,
    target_url: str,
    headers: Mapping[str, str],
    cookies: Mapping[str, str],
) -> Response:
    """Stream one trusted terminal upload request to its already-resolved target."""
    max_bytes = _upload_max_bytes()
    invalid_or_oversized = _reject_oversized_content_length(request, max_bytes)
    if invalid_or_oversized is not None:
        return invalid_or_oversized

    session = aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=_upload_timeout_seconds(), connect=10),
        trust_env=True,
    )
    try:
        upstream_response = await session.request(
            method=request.method,
            url=target_url,
            headers=dict(headers),
            cookies=dict(cookies),
            data=_counted_stream(request, max_bytes),
            ssl=AIOHTTP_CLIENT_SESSION_SSL,
        )
    except asyncio.CancelledError:
        await session.close()
        raise
    except Exception as exc:
        await session.close()
        if is_upload_too_large_error(exc):
            return JSONResponse(
                {"error": f"Upload exceeds the {max_bytes}-byte limit"},
                status_code=413,
            )
        return JSONResponse({"error": f"Terminal proxy error: {exc}"}, status_code=502)

    filtered_headers = {
        key: value
        for key, value in upstream_response.headers.items()
        if key.lower() not in _RESPONSE_STRIPPED_HEADERS
    }
    if TERMINAL_PROXY_HEADERS:
        filtered_headers.update(TERMINAL_PROXY_HEADERS)

    async def stream_response():
        try:
            async for chunk in upstream_response.content.iter_any():
                yield chunk
        finally:
            upstream_response.release()
            await session.close()

    return StreamingResponse(
        stream_response(),
        status_code=upstream_response.status,
        headers=filtered_headers,
    )

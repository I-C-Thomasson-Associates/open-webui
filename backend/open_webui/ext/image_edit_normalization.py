"""Image edit normalization helpers isolated from core router logic."""

import asyncio
import base64
import io
import uuid

from PIL import Image, ImageOps, UnidentifiedImageError


def _has_alpha(image: Image.Image) -> bool:
    return image.mode in {"RGBA", "LA"} or (image.mode == "P" and "transparency" in image.info)


def _normalize_data_url_to_png_bytes(data_url: str) -> bytes:
    if "," not in data_url:
        raise ValueError("Invalid image data URL format")

    _, encoded = data_url.split(",", 1)

    try:
        source_bytes = base64.b64decode(encoded)
    except Exception as exc:
        raise ValueError("Invalid base64 image payload") from exc

    try:
        with Image.open(io.BytesIO(source_bytes)) as image:
            normalized = ImageOps.exif_transpose(image)
            target_mode = "RGBA" if _has_alpha(normalized) else "RGB"
            if normalized.mode != target_mode:
                normalized = normalized.convert(target_mode)

            output = io.BytesIO()
            normalized.save(output, format="PNG", optimize=True)
            return output.getvalue()
    except UnidentifiedImageError as exc:
        raise ValueError("Unsupported image format") from exc


async def build_normalized_png_image_file_item(base64_string: str, param_name: str = "image"):
    png_bytes = await asyncio.to_thread(_normalize_data_url_to_png_bytes, base64_string)

    return (
        param_name,
        (
            f"{uuid.uuid4()}.png",
            io.BytesIO(png_bytes),
            "image/png",
        ),
    )

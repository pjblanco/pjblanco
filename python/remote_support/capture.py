"""Best-effort screen capture. It never attempts to change desktop permissions."""

from __future__ import annotations

import io


def capture_jpeg(max_width: int = 1600, quality: int = 70) -> tuple[bytes | None, str | None]:
    """Capture the desktop as JPEG, returning an error instead of bypassing OS policy."""
    try:
        from PIL import ImageGrab
    except ImportError:
        return None, "Pillow is not installed"

    try:
        image = ImageGrab.grab(all_screens=True)
        if image.width > max_width:
            ratio = max_width / image.width
            image = image.resize(
                (max_width, max(1, int(image.height * ratio))),
                Image.Resampling.LANCZOS,
            )
        if image.mode not in ("RGB", "L"):
            image = image.convert("RGB")
        output = io.BytesIO()
        image.save(output, format="JPEG", quality=quality, optimize=True)
        return output.getvalue(), None
    except Exception as exc:  # platform screenshot APIs expose many exception types
        return None, f"screen capture unavailable: {exc}"

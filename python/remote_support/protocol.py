"""Small, bounded JSON-lines protocol used by the host and viewer."""

from __future__ import annotations

import asyncio
import json
from typing import Any

MAX_MESSAGE_BYTES = 8 * 1024 * 1024


class ProtocolError(ValueError):
    """Raised for malformed or oversized protocol messages."""


async def read_message(reader: asyncio.StreamReader) -> dict[str, Any]:
    line = await reader.readline()
    if not line:
        raise ConnectionError("peer closed the connection")
    if len(line) > MAX_MESSAGE_BYTES:
        raise ProtocolError("message is too large")
    try:
        message = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ProtocolError("message is not valid JSON") from exc
    if not isinstance(message, dict):
        raise ProtocolError("message must be a JSON object")
    return message


async def write_message(writer: asyncio.StreamWriter, message: dict[str, Any]) -> None:
    try:
        encoded = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtocolError("message cannot be encoded") from exc
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise ProtocolError("message is too large")
    writer.write(encoded)
    await writer.drain()

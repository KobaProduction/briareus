"""Bounded opaque MCP HTTP body transport, not a JSON-RPC interpreter.

Reject framing ambiguity, excess bytes, fragmentation and slow clients.
The destination Hand owns content-type, JSON-RPC validation and per-effect
Authorization/Cedar. Gateway never edits or interprets the application body.
"""

from __future__ import annotations

import asyncio

from starlette.requests import Request

_MAX_BYTES = 1024 * 1024
_MAX_CHUNKS = 1024
_READ_TIMEOUT_SECONDS = 8


class McpBodyRejected(Exception):
    def __init__(self, code: str, status_code: int) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


async def read_mcp_body(request: Request) -> bytes:
    """Read opaque original bytes with bounded transport framing only."""
    lengths = request.headers.getlist("content-length")
    declared_length: int | None = None
    if len(lengths) > 1:
        raise McpBodyRejected("MCP_CONTENT_LENGTH_INVALID", 400)
    if lengths:
        value = lengths[0]
        if (
            not value.isascii()
            or not value.isdecimal()
            or len(value) > 8
            or (len(value) > 1 and value.startswith("0"))
        ):
            raise McpBodyRejected("MCP_CONTENT_LENGTH_INVALID", 400)
        declared_length = int(value)
        if declared_length > _MAX_BYTES:
            raise McpBodyRejected("MCP_BODY_TOO_LARGE", 413)
    # A proxy must never reinterpret conflicting framing on behalf of MCP.
    encodings = request.headers.getlist("transfer-encoding")
    if len(encodings) > 1 or (
        encodings and (encodings[0].strip().casefold() != "chunked" or lengths)
    ):
        raise McpBodyRejected("MCP_TRANSFER_ENCODING_INVALID", 400)
    content_encodings = request.headers.getlist("content-encoding")
    if len(content_encodings) > 1 or (
        content_encodings and content_encodings[0].strip().casefold() != "identity"
    ):
        raise McpBodyRejected("MCP_CONTENT_ENCODING_INVALID", 415)

    payload = bytearray()
    try:
        async with asyncio.timeout(_READ_TIMEOUT_SECONDS):
            # Request.stream() suppresses empty body chunks. Count raw ASGI
            # messages instead, including zero-byte fragments from slow
            # senders, so the event bound actually limits request work.
            for _ in range(_MAX_CHUNKS):
                event = await request.receive()
                if event.get("type") == "http.disconnect":
                    raise McpBodyRejected("MCP_BODY_INTERRUPTED", 400)
                if event.get("type") != "http.request":
                    raise McpBodyRejected("MCP_BODY_UNAVAILABLE", 400)
                chunk = event.get("body", b"")
                if not isinstance(chunk, bytes) or len(chunk) > _MAX_BYTES - len(payload):
                    raise McpBodyRejected("MCP_BODY_TOO_LARGE", 413)
                payload.extend(chunk)
                if not event.get("more_body", False):
                    break
            else:
                raise McpBodyRejected("MCP_BODY_TOO_FRAGMENTED", 413)
    except TimeoutError as exc:
        raise McpBodyRejected("MCP_BODY_READ_TIMEOUT", 408) from exc

    # HTTP framing must be unambiguous even if an outer server was lenient.
    if declared_length is not None and len(payload) != declared_length:
        raise McpBodyRejected("MCP_CONTENT_LENGTH_INVALID", 400)

    return bytes(payload)

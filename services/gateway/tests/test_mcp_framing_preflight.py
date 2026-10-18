"""Gateway-only body framing checks; private Cedar/Hands are never contacted."""

from __future__ import annotations

import asyncio

from bridge._mcp_body import McpBodyRejected, read_mcp_body
from starlette.requests import Request

_BODY = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'


async def exercise(
    headers: list[tuple[bytes, bytes]],
    body: bytes = _BODY,
    chunks: tuple[bytes, ...] | None = None,
) -> tuple[str, int]:
    parts = iter(chunks or (body,))
    received = 0

    async def receive() -> dict[str, object]:
        nonlocal received
        received += 1
        try:
            part = next(parts)
        except StopIteration as exc:
            raise AssertionError("extra receive event beyond body") from exc
        return {
            "type": "http.request",
            "body": part,
            "more_body": received < len(chunks or (body,)),
        }

    request = Request(
        {
            "type": "http",
            "path": "/hands/files/mcp",
            "method": "POST",
            "headers": headers,
            "query_string": b"",
        },
        receive=receive,
    )
    try:
        payload = await read_mcp_body(request)
    except McpBodyRejected as exc:
        return exc.code, received
    assert payload == body
    return "ACCEPT", received


async def main() -> None:
    correct = (b"content-length", str(len(_BODY)).encode())
    assert await exercise([correct]) == ("ACCEPT", 1)
    assert await exercise([correct], chunks=(_BODY[:3], b"", _BODY[3:])) == ("ACCEPT", 3)
    assert await exercise([(b"transfer-encoding", b"chunked")]) == ("ACCEPT", 1)
    # Gateway must not parse application JSON-RPC. The Hand owns semantics,
    # duplicate-key rejection and unsupported protocol payloads.
    for opaque in (b"not-json", b"[]", b'{"method":"unknown","method":"duplicate"}'):
        assert await exercise([(b"content-length", str(len(opaque)).encode())], body=opaque) == (
            "ACCEPT",
            1,
        )

    for headers, error, reads in (
        ([(b"content-length", b"1")], "MCP_CONTENT_LENGTH_INVALID", 1),
        ([(b"content-length", b"0" + str(len(_BODY)).encode())], "MCP_CONTENT_LENGTH_INVALID", 0),
        ([(b"content-length", b"100")], "MCP_CONTENT_LENGTH_INVALID", 1),
        ([correct, correct], "MCP_CONTENT_LENGTH_INVALID", 0),
        ([(b"content-length", b"1048577")], "MCP_BODY_TOO_LARGE", 0),
        ([correct, (b"transfer-encoding", b"chunked")], "MCP_TRANSFER_ENCODING_INVALID", 0),
        ([(b"transfer-encoding", b"gzip")], "MCP_TRANSFER_ENCODING_INVALID", 0),
        ([(b"content-encoding", b"gzip")], "MCP_CONTENT_ENCODING_INVALID", 0),
    ):
        observed = await exercise(headers)
        assert observed == (error, reads), (headers, observed, error)

    print("GATEWAY_MCP_FRAMING_DENIED_BEFORE_PRIVATE_CEDAR_PASS")


if __name__ == "__main__":
    asyncio.run(main())

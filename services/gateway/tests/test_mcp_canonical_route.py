"""Exact public MCP route bytes; aliases never reach private Authorization.

No verified bearer, Project ownership, Cedar or live Hand invocation.
"""

from __future__ import annotations

import asyncio

import httpx
from bridge._mcp_admission import McpAdmissionRejected, parse_connection_admission
from starlette.requests import Request

from bridge.thin_gateway import build_app

_CANONICAL = "/hands/files/mcp"
_HEADERS: list[tuple[bytes, bytes]] = [
    (b"host", b"briareus.koba-nexus.ru"),
    (b"authorization", b"Bearer opaque_not_a_signed_resource_token"),
    (b"x-briareus-project-uuid", b"12345678-1234-4234-8234-123456789abc"),
    (b"x-briareus-agent-session-uuid", b"12345678-1234-4234-8234-123456789abd"),
    (b"x-briareus-grant-revision", b"7"),
]


def select(
    *,
    raw_path: bytes = b"/hands/files/mcp",
    path: str = _CANONICAL,
    query: bytes = b"",
) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "raw_path": raw_path,
            "query_string": query,
            "scheme": "https",
            "headers": _HEADERS,
            "server": ("briareus.koba-nexus.ru", 443),
        }
    )


async def main() -> None:
    allowed = parse_connection_admission(select())
    assert allowed.hand == "files"
    assert allowed.resource_audience == "https://briareus.koba-nexus.ru/hands/files/mcp"
    assert allowed.bearer.startswith("Bearer ")

    for raw in (
        b"/hands/%66iles/mcp",
        b"/hands/files%2fmcp",
        b"/hands/files/%6dcp",
        b"/hands/files/mcp/.",
        b"/hands/other/mcp",
        b"/hands/files//mcp",
        b"/hands/files/mcp%00",
        b"/hands/files%252fmcp",
    ):
        try:
            parse_connection_admission(select(raw_path=raw))
        except McpAdmissionRejected as exc:
            assert exc.status_code == 404 and exc.code == "MCP_MODULE_UNKNOWN", raw
        else:
            raise AssertionError(f"noncanonical MCP resource URI accepted: {raw!r}")

    for query in (b"token=ignored", b"project_uuid=fake", b"%00", b"?"):
        try:
            parse_connection_admission(select(query=query))
        except McpAdmissionRejected as exc:
            assert (exc.status_code, exc.code) == (400, "MCP_CONTEXT_INVALID")
        else:
            raise AssertionError("MCP query bypassed canonical route check")

    # ASGI integration: exact static route still resolves, but absent a
    # real authenticated private transport, default Gateway must deny.
    app = build_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://briareus.koba-nexus.ru",
        follow_redirects=False,
    ) as client:
        result = await client.post(
            _CANONICAL,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={name.decode(): value.decode() for name, value in _HEADERS},
        )
        assert (
            result.status_code == 503 and result.json()["code"] == "MCP_AUTHENTICATION_UNAVAILABLE"
        )
        rejected = await client.post(
            _CANONICAL + "?fake=selector",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={name.decode(): value.decode() for name, value in _HEADERS},
        )
        assert rejected.status_code == 400
        assert rejected.json()["code"] == "MCP_CONTEXT_INVALID"

    print("GATEWAY_MCP_CANONICAL_RAW_PATH_REJECTS_ALIASES_BEFORE_PRIVATE_PEER_PASS")


if __name__ == "__main__":
    asyncio.run(main())

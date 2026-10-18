"""Gateway checks signed-token evidence, not Cedar grants or Project rights."""

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta

from bridge._mcp_admission import (
    ConnectionAdmission,
    McpInvalidToken,
    VerifiedMcpAuthentication,
    authenticate_mcp_connection,
    parse_connection_admission,
)
from starlette.requests import Request


class Authenticator:
    def __init__(self, status: str) -> None:
        self.status = status
        self.calls = 0

    async def authenticate(
        self, *, bearer: str, resource_audience: str
    ) -> VerifiedMcpAuthentication:
        self.calls += 1
        if self.status == "invalid":
            raise McpInvalidToken
        if self.status == "unavailable":
            raise ConnectionError("unavailable")
        now = datetime.now(UTC)
        return VerifiedMcpAuthentication(
            issuer="https://briareus.koba-nexus.ru/auth/v1/",
            audience=resource_audience if self.status != "wrong_audience" else "invalid",
            bearer_sha256=hashlib.sha256(bearer.encode()).hexdigest(),
            authenticated_at=now,
            expires_at=now + timedelta(seconds=30),
        )


async def main() -> None:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/hands/files/mcp",
        "raw_path": b"/hands/files/mcp",
        "query_string": b"",
        "headers": [(b"authorization", b"Bearer example")],
    }
    admission = parse_connection_admission(Request(scope))
    assert admission == ConnectionAdmission("files", "Bearer example")
    assert admission.resource_audience.endswith("/hands/files/mcp")
    assert (await authenticate_mcp_connection(None, admission)).status_code == 503
    for kind, status in (("invalid", 401), ("unavailable", 503), ("wrong_audience", 401)):
        authenticator = Authenticator(kind)
        rejected = await authenticate_mcp_connection(authenticator, admission)
        assert rejected.status_code == status and authenticator.calls == 1
    verifier = Authenticator("verified")
    assert await authenticate_mcp_connection(verifier, admission) is None
    assert verifier.calls == 1
    print("GATEWAY_RESOURCE_AUTHN_ONLY_CONTRACT_PASS")


if __name__ == "__main__":
    asyncio.run(main())

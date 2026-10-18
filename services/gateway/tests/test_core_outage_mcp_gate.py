"""Authentication-only Gateway forwarding, without operation authorization."""

import asyncio
import hashlib
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
from bridge._mcp_admission import VerifiedMcpAuthentication

from bridge.thin_gateway import build_app

_BASE = "https://briareus.koba-nexus.ru"
_DATA = b'{"jsonrpc":"2.0","method":"tools/list","id":1}'


class FixtureStream(httpx.AsyncByteStream):
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.payload

    async def aclose(self) -> None:
        pass


class VerifiedFixture:
    async def authenticate(
        self, *, bearer: str, resource_audience: str
    ) -> VerifiedMcpAuthentication:
        now = datetime.now(UTC)
        return VerifiedMcpAuthentication(
            issuer=_BASE + "/auth/v1/",
            audience=resource_audience,
            bearer_sha256=hashlib.sha256(bearer.encode()).hexdigest(),
            authenticated_at=now,
            expires_at=now + timedelta(minutes=1),
        )


async def main() -> None:
    seen: list[httpx.Request] = []

    async def hand(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.url.host == "briareus-files"
        assert request.headers["authorization"] == "Bearer fixture-token"
        assert await request.aread() == _DATA
        return httpx.Response(
            403,
            headers={"content-type": "application/json"},
            stream=FixtureStream(b'{"code":"HAND_EFFECT_DENIED"}'),
        )

    app = build_app(authentication=VerifiedFixture())
    route = next(r for r in app.routes if getattr(r, "path", "") == "/hands/files/mcp")
    async with (
        httpx.AsyncClient(transport=httpx.MockTransport(hand)) as upstream,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=_BASE,
        ) as browser,
    ):
        route.endpoint.__self__._client = upstream
        response = await browser.post(
            "/hands/files/mcp",
            content=_DATA,
            headers={
                "authorization": "Bearer fixture-token",
                "content-type": "application/json",
                "accept": "application/json, text/event-stream",
            },
        )
        assert response.status_code == 403
        assert response.json()["code"] == "HAND_EFFECT_DENIED"
        assert len(seen) == 1
        assert "x-briareus-project-uuid" not in seen[0].headers
        assert route.endpoint.__self__._slots._value == 64
        no_verifier = build_app()
        absent = await httpx.AsyncClient(
            transport=httpx.ASGITransport(app=no_verifier),
            base_url=_BASE,
        ).post(
            "/hands/files/mcp",
            content=_DATA,
            headers={"authorization": "Bearer fixture-token"},
        )
        assert absent.status_code == 503
    print("GATEWAY_RESOURCE_IDENTITY_ONLY_HAND_EFFECT_DENIAL_INDEPENDENT_PASS")


if __name__ == "__main__":
    asyncio.run(main())

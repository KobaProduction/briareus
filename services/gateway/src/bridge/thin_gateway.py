"""Single-origin Panel, API, and upstream Rauthy OIDC reverse proxy.

Gateway only forwards fixed public namespaces; identity, JWT verification,
business permissions and authentication remain upstream responsibilities.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Literal

import httpx
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from ._api_contract import public_api_path, retired_auth_path
from ._mcp_admission import (
    McpAdmissionRejected,
    TrustedGatewayAuthenticationPort,
    admission_error,
    authenticate_mcp_connection,
    parse_connection_admission,
)
from ._mcp_body import McpBodyRejected, read_mcp_body
from ._proxy_start import PendingProxyStart
from ._proxy_stream import ProxyStreamingResponse
from ._rauthy_admin_privacy import classify_rauthy_public_path
from .route_telemetry import RouteTelemetry
from .single_origin import MCP_ENDPOINTS, PUBLIC_HOST, SingleOriginGuard, unavailable_routes

_PANEL_UPSTREAM = "http://briareus-control-panel-ui:8080"
_API_UPSTREAM = "http://briareus-control-panel-api:8000"
_RAUTHY_UPSTREAM = "http://briareus-rauthy:8080"
# Routing is defined by the fixed public namespace, not by a Vite
# asset-extension/MIME registry. Nginx owns every Panel asset and SPA route.
_PANEL_PUBLIC_FILES = frozenset({"/", "/robots.txt", "/sitemap.xml"})
_HOP_HEADERS = frozenset(
    {
        "host",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
    }
)
_PROXY_ASSERTIONS = frozenset(
    {
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
        "x-real-ip",
        "x-original-url",
        "x-rewrite-url",
    }
)
_TIMEOUT = httpx.Timeout(connect=3, read=60, write=30, pool=3)
_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


@dataclass(frozen=True, slots=True)
class RouteSpec:
    """Public route template and its fixed internal service destination."""

    template: str
    target: Literal["panel-ui", "panel-api", "rauthy"]


# Runtime routing policy contains no principal, permissions or Identity paths.
_ROUTE_TABLE: tuple[RouteSpec, ...] = (
    RouteSpec("/", "panel-ui"),
    RouteSpec("/robots.txt", "panel-ui"),
    RouteSpec("/sitemap.xml", "panel-ui"),
    RouteSpec("/panel", "panel-ui"),
    RouteSpec("/panel/{path:path}", "panel-ui"),
    RouteSpec("/api", "panel-api"),
    RouteSpec("/api/{path:path}", "panel-api"),
    RouteSpec("/auth/v1", "rauthy"),
    RouteSpec("/auth/v1/{path:path}", "rauthy"),
)


def _raw_path(request: Request) -> str | None:
    raw = request.scope.get("raw_path", b"")
    if not isinstance(raw, bytes):
        return None
    try:
        path = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not path.startswith("/") or any(c in path for c in ("#", "\\", "\r", "\n", "\x00")):
        return None
    return path


def _connection_tokens(headers: list[tuple[bytes, bytes]]) -> set[str]:
    return {
        token.strip().casefold()
        for name, value in headers
        if name.lower() == b"connection"
        for token in value.decode("latin1").split(",")
    }


def _api_headers(request: Request) -> list[tuple[bytes, bytes]]:
    """Forward end-to-end headers, never browser-originated proxy identity."""
    incoming = request.scope.get("headers", [])
    connection_tokens = _connection_tokens(incoming)
    result: list[tuple[bytes, bytes]] = []
    for name, value in incoming:
        key = name.decode("ascii").casefold()
        if (
            key in _HOP_HEADERS
            or key in _PROXY_ASSERTIONS
            or key.startswith("x-forwarded-")
            or key in connection_tokens
        ):
            continue
        result.append((name, value))
    return result


def _api_declared_length(request: Request, *, rauthy: bool) -> bytes | None:
    """Preserve a single bounded original BFF length, never ambiguous framing."""
    if rauthy:
        # Rauthy provider routes retain their existing streaming semantics.
        return None
    lengths = request.headers.getlist("content-length")
    if not lengths:
        return None
    value = lengths[0]
    if (
        len(lengths) != 1
        or not value.isascii()
        or not value.isdecimal()
        or len(value) > 19
        or (len(value) > 1 and value.startswith("0"))
        or int(value) > 2**63 - 1
        or request.headers.getlist("transfer-encoding")
    ):
        raise ValueError("ambiguous Control Panel API HTTP framing")
    return value.encode("ascii")


def _upstream_headers(
    request: Request, *, rauthy: bool, declared_length: bytes | None
) -> list[tuple[bytes, bytes]]:
    """Separate outbound origin claims from incoming browser request headers."""
    headers = _api_headers(request)
    if declared_length is not None:
        headers.append((b"content-length", declared_length))
    # After SingleOriginGuard has independently checked exactly one
    # accepted public Host, give the PRIVATE API owner exactly one stable
    # canonical authority. HTTPX otherwise synthesizes the container DNS
    # destination Host, which the Backend native credentials BFF correctly
    # rejects. Never forward client Host / :443 / X-Forwarded assertions.
    headers.append((b"host", PUBLIC_HOST.encode("ascii")))
    if rauthy:
        # Rauthy owner also requires trusted Gateway external-origin hints.
        headers.extend(
            (
                (b"x-forwarded-host", PUBLIC_HOST.encode("ascii")),
                (b"x-forwarded-proto", b"https"),
            )
        )
    return headers


# End-to-end MCP headers are original UNTRUSTED client inputs. Do not
# normalize Project/AgentSession/revision into an identity assertion; the
# Hand independently checks each selector against the signed actor and Cedar.
_MCP_FORWARD_HEADERS = frozenset(
    {
        b"authorization",
        b"accept",
        b"content-type",
        b"mcp-protocol-version",
        b"mcp-session-id",
        b"last-event-id",
        b"x-briareus-project-uuid",
        b"x-briareus-agent-session-uuid",
        b"x-briareus-grant-revision",
    }
)


def _mcp_forward_headers(request: Request) -> list[tuple[bytes, bytes]]:
    incoming = request.scope.get("headers", [])
    connection_tokens = _connection_tokens(incoming)
    return [
        (name, value)
        for name, value in incoming
        if name.lower() in _MCP_FORWARD_HEADERS
        and name.decode("ascii").casefold() not in connection_tokens
    ]


class ThinGateway:
    def __init__(self, authentication: TrustedGatewayAuthenticationPort | None = None) -> None:
        self._authentication = authentication
        self._client: httpx.AsyncClient | None = None
        self._slots = asyncio.Semaphore(64)
        self._draining = False
        self._open: set[httpx.Response] = set()
        self._streams: set[ProxyStreamingResponse] = set()
        self._pending: set[PendingProxyStart] = set()

    @asynccontextmanager
    async def lifespan(self, _app: Starlette) -> AsyncIterator[None]:
        self._draining = False
        async with httpx.AsyncClient(
            timeout=_TIMEOUT,
            limits=httpx.Limits(max_connections=64, max_keepalive_connections=24),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            self._client = client
            try:
                yield
            finally:
                self._draining = True
                self._client = None
                await self._drain_streams()

    async def _drain_streams(self) -> None:
        async def close_all() -> None:
            # Include requests still waiting for a client body or first
            # owner response; they have not become tracked streams yet.
            await asyncio.gather(
                *(pending.abort() for pending in tuple(self._pending)),
                return_exceptions=True,
            )
            # Each stream owns a three-second close deadline and frees its
            # own pool slot once. Parallel close avoids 64 sequential waits.
            await asyncio.gather(
                *(stream.aclose() for stream in tuple(self._streams)),
                return_exceptions=True,
            )

        cleanup = asyncio.create_task(close_all())
        cancelled = False
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                cancelled = True
        cleanup.result()
        if cancelled:
            raise asyncio.CancelledError

    async def _send_upstream(
        self, client: httpx.AsyncClient, request: httpx.Request
    ) -> httpx.Response:
        if self._draining:
            raise httpx.ReadError("gateway is draining")
        pending = PendingProxyStart(client, request)
        self._pending.add(pending)
        try:
            return await pending.take_response()
        finally:
            self._pending.discard(pending)

    def _stream_response(self, upstream: httpx.Response) -> ProxyStreamingResponse:
        self._open.add(upstream)
        response = ProxyStreamingResponse(
            upstream, slots=self._slots, open_responses=self._open, tracked_streams=self._streams
        )
        self._streams.add(response)
        return response

    @staticmethod
    def _unavailable() -> Response:
        return JSONResponse(
            {"code": "GATEWAY_UPSTREAM_UNAVAILABLE"},
            status_code=502,
            headers={"Cache-Control": "no-store"},
        )

    async def static(self, request: Request) -> Response:
        """Route the whole bounded Panel namespace to its owning UI server.

        No mime sniff, response-body parsing, WASM/JS/CSS filename allowlist,
        noindex inspection, or fabricated UI reply belongs in Gateway.
        """
        return await self._proxy(request, rauthy=False, panel_ui=True)

    async def api(self, request: Request) -> Response:
        """Preserve the Admin API's unmodified public /api/* contract."""
        return await self._proxy(request, rauthy=False)

    async def oidc(self, request: Request) -> Response:
        """Forward only the real upstream Rauthy /auth/v1/* namespace."""
        return await self._proxy(request, rauthy=True)

    async def mcp(self, request: Request) -> Response:
        """Coarse `mcp.connect` admission; Hand independently checks each effect."""
        try:
            admission = parse_connection_admission(request)
        except McpAdmissionRejected as exc:
            return admission_error(exc.code, exc.status_code)
        client = self._client
        if client is None or self._draining or self._authentication is None:
            # No real independent Rauthy authentication verifier, no route.
            # This never treats a Bearer string as identity or Permit.
            return admission_error("MCP_AUTHENTICATION_UNAVAILABLE", 503)
        try:
            await asyncio.wait_for(self._slots.acquire(), timeout=3)
        except TimeoutError:
            return admission_error("MCP_GATEWAY_BUSY", 503)
        try:
            # Gateway only authenticates the resource-specific Rauthy token.
            # Project, grant, resource and Cedar decisions belong to the Hand
            # and the independently authenticated Authorization service.
            blocked = await authenticate_mcp_connection(self._authentication, admission)
            if blocked is not None:
                self._slots.release()
                return blocked
            # Bounded HTTP framing only. JSON-RPC semantics, including tools
            # and notifications, are the selected Hand's responsibility.
            try:
                payload = await read_mcp_body(request)
            except McpBodyRejected as exc:
                self._slots.release()
                return admission_error(exc.code, exc.status_code)
            headers = _mcp_forward_headers(request)
            upstream_request = client.build_request(
                request.method, admission.target, headers=headers, content=payload
            )
            upstream = await self._send_upstream(client, upstream_request)
        except asyncio.CancelledError:
            self._slots.release()
            raise
        except (httpx.HTTPError, ValueError, TimeoutError):
            self._slots.release()
            return admission_error("MCP_UPSTREAM_UNAVAILABLE", 503)
        except BaseException:
            self._slots.release()
            raise
        # HTTP status and JSON-RPC error semantics are wholly Hand-owned;
        # the Gateway does not enumerate expected tool/protocol statuses.
        streamed = self._stream_response(upstream)
        if self._draining:
            await streamed.aclose()
            return admission_error("MCP_UPSTREAM_UNAVAILABLE", 503)
        # Only protocol framing metadata may cross the private Hand boundary.
        # Never forward a provider Set-Cookie, Location or internal server hint.
        streamed.raw_headers = [
            (key, value)
            for key, value in upstream.headers.raw
            if key.decode("ascii").casefold()
            in {"content-type", "mcp-session-id", "mcp-protocol-version"}
        ] + [(b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff")]
        return streamed

    async def _proxy(self, request: Request, *, rauthy: bool, panel_ui: bool = False) -> Response:
        path = _raw_path(request)
        if path is None:
            return Response(status_code=404)
        if panel_ui:
            if path == "/panel":
                return Response(
                    status_code=308, headers={"Location": "/panel/", "Cache-Control": "no-store"}
                )
            # Prevent path traversal escaping the fixed Panel route. Do not
            # define frontend URL semantics or inspect file extensions.
            decoded = request.scope.get("path")
            if (
                (path not in _PANEL_PUBLIC_FILES and not path.startswith("/panel/"))
                or not isinstance(decoded, str)
                or any(seg in {".", ".."} for seg in decoded.split("/"))
                or "//" in decoded
            ):
                return Response(status_code=404)
        else:
            prefix = "/auth/v1" if rauthy else "/api"
            if path != prefix and not path.startswith(prefix + "/"):
                return Response(status_code=404)
        if not rauthy and not panel_ui:
            decoded = request.scope.get("path")
            if retired_auth_path(raw_path=path, decoded_path=decoded, method=request.method):
                return JSONResponse(
                    {"code": "AUTH_API_ROUTE_RETIRED"},
                    status_code=404,
                    headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
                )
            if not public_api_path(raw_path=path, decoded_path=decoded, method=request.method):
                # No implicit /api/* access to future private API routes.
                # The public contract is /api/v1/* plus the registered
                # exact GET OAuth callback; neither is a trusted Permit.
                return JSONResponse(
                    {"code": "API_ROUTE_NOT_PUBLIC"},
                    status_code=404,
                    headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
                )
        if rauthy:
            # Rauthy 0.37.1 interleaves Admin APIs and essential login/
            # recovery/self-service handlers; use source-verified route and
            # method boundaries rather than a blanket /auth/v1 deny.
            route_disposition = classify_rauthy_public_path(path, request.method)
            if route_disposition == "bad_path":
                return Response(status_code=400)
            if route_disposition == "private_admin":
                return JSONResponse(
                    {"code": "RAUTHY_ADMIN_ROUTE_PRIVATE"},
                    status_code=404,
                    headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
                )
        query = request.scope.get("query_string", b"")
        if not isinstance(query, bytes):
            return Response(status_code=400)
        # Construct only a fixed private destination; the public Host is never a URL target.
        try:
            raw_url = path + ("?" + query.decode("ascii") if query else "")
            upstream = (
                _PANEL_UPSTREAM if panel_ui else _RAUTHY_UPSTREAM if rauthy else _API_UPSTREAM
            )
            target_url = httpx.URL(upstream + raw_url)
            expected_target = (
                ("briareus-control-panel-ui", 8080)
                if panel_ui
                else ("briareus-rauthy", 8080)
                if rauthy
                else ("briareus-control-panel-api", 8000)
            )
            if (target_url.host, target_url.port) != expected_target:
                return Response(status_code=400)
        except (UnicodeDecodeError, ValueError, httpx.InvalidURL):
            return Response(status_code=400)
        # The native Backend expects exact Content-Length: 2 for "{}"
        # Init/PoW, but Rauthy must keep its established stream behavior.
        try:
            declared_length = _api_declared_length(request, rauthy=rauthy or panel_ui)
        except ValueError:
            return Response(status_code=400)
        client = self._client
        if client is None or self._draining:
            return self._unavailable()
        try:
            await asyncio.wait_for(self._slots.acquire(), timeout=3)
        except TimeoutError:
            return self._unavailable()
        try:
            headers = _upstream_headers(request, rauthy=rauthy, declared_length=declared_length)
            upstream_request = client.build_request(
                request.method,
                target_url,
                headers=headers,
                content=request.stream(),
            )
            upstream = await self._send_upstream(client, upstream_request)
        except asyncio.CancelledError:
            self._slots.release()
            raise
        except (httpx.HTTPError, ValueError, UnicodeError):
            self._slots.release()
            return self._unavailable()
        except BaseException:
            self._slots.release()
            raise
        streamed = self._stream_response(upstream)
        if self._draining:
            await streamed.aclose()
            return self._unavailable()
        # Preserve duplicate Set-Cookie and other end-to-end response headers.
        # ASGI streaming manages framing; do not send hop-by-hop headers.
        excluded = _HOP_HEADERS | _connection_tokens(upstream.headers.raw)
        streamed.raw_headers = [
            (key, value)
            for key, value in upstream.headers.raw
            if key.decode("ascii").casefold() not in excluded
        ]
        return streamed


def build_app(*, authentication: TrustedGatewayAuthenticationPort | None = None) -> Starlette:
    transport = ThinGateway(authentication)
    handlers = {
        "panel-ui": transport.static,
        "panel-api": transport.api,
        "rauthy": transport.oidc,
    }
    return Starlette(
        routes=[
            *[
                Route(spec.template, handlers[spec.target], methods=_METHODS)
                for spec in _ROUTE_TABLE
            ],
            *[Route(path, transport.mcp, methods=["POST"]) for path in MCP_ENDPOINTS.values()],
            *unavailable_routes(),
        ],
        middleware=[Middleware(SingleOriginGuard), Middleware(RouteTelemetry)],
        lifespan=transport.lifespan,
    )

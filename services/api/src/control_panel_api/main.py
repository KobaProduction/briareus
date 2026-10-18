"""Control Panel API: stable BFF boundary, independent from Identity lifecycle."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import asdict

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, SecretStr

from ._api_paths import API_V1_PREFIX, AUTH_API_PREFIX, REGISTERED_RAUTHY_CALLBACK_PATH
from ._oidc import OidcProviderUnavailable, RauthyOidcAdapter
from ._oidc_approvals import ApprovalManagementPort
from ._oidc_browser import OidcBrowserSessionStore, oidc_browser_router
from ._oidc_catalog import TrustedCatalogReadPort
from ._oidc_files_content import TrustedFilesContentOwner
from ._oidc_membership import CurrentPlatformUserSource, platform_membership_router
from ._oidc_native_login import native_login_router
from ._oidc_native_start import native_login_start_router
from ._oidc_origin_policy import PUBLIC_ORIGIN
from ._platform_current_client import PrivatePlatformCurrentClient
from ._platform_unix_peer import UnixPlatformPeer
from ._rauthy_admin import RauthyAdminClient, RauthyAdminKeyRejected
from ._rauthy_native_init import PinnedNativeRauthyInit


class OidcBrowserConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer: str
    client_id: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None


def create_control_panel_api(
    *,
    provider: RauthyOidcAdapter | None = None,
    membership_source: CurrentPlatformUserSource | None = None,
    approval_source: ApprovalManagementPort | None = None,
    catalog_source: TrustedCatalogReadPort | None = None,
    files_content_source: TrustedFilesContentOwner | None = None,
    test_only_local_origin: str | None = None,
    native_init: PinnedNativeRauthyInit | None = None,
) -> FastAPI:
    platform_peer = None
    socket_path = os.environ.get("PLATFORM_PANEL_SOCKET", "")
    signing_key = os.environ.get("PLATFORM_PANEL_SIGNING_KEY_FILE", "")
    if membership_source is None and (socket_path or signing_key):
        if not socket_path or not signing_key:
            raise ValueError("Platform socket and service signing key must be configured together")
        platform_peer = UnixPlatformPeer(socket_path=socket_path, signing_key_file=signing_key)
        membership_source = PrivatePlatformCurrentClient(peer=platform_peer)
    if test_only_local_origin is not None and provider is None:
        # Test-only origin must be explicit and independently tied to a
        # disposable local provider; never enable through process ENV.
        raise ValueError("local test origin requires injected sandbox provider")
    if native_init is not None and (
        provider is None
        or (test_only_local_origin is None and native_init.issuer != PUBLIC_ORIGIN + "/auth/v1")
    ):
        raise ValueError("native Rauthy owner must be independently configured for its exact realm")
    # Human sign-in must not require a separately provisioned MCP resource.
    # When Files is explicitly enabled, bind its exact resource BEFORE code
    # issuance. Without it, the session proves identity only; Files stays closed.
    managed_provider = provider
    if managed_provider is None:
        issuer = os.environ.get("OIDC_ISSUER", "")
        client_id = os.environ.get("OIDC_CLIENT_ID", "")
        if issuer or client_id:
            if not issuer or not client_id:
                raise RuntimeError("both OIDC_ISSUER and OIDC_CLIENT_ID must be configured")
            approved = (
                issuer.rstrip("/") == PUBLIC_ORIGIN + "/auth/v1"
                and client_id == "briareus-control-panel"
            )
            resource_audience = os.environ.get("OIDC_RESOURCE_AUDIENCE") or None
            if resource_audience is not None and (
                not approved or resource_audience != PUBLIC_ORIGIN + "/hands/files/mcp"
            ):
                raise ValueError("OIDC resource must match the approved issuer/client/Files realm")
            managed_provider = RauthyOidcAdapter(
                issuer=issuer,
                client_id=client_id,
                resource_audience=resource_audience,
            )

    # No browser cookie or User token can provision an admin API credential.
    raw_api_key = os.environ.get("RAUTHY_ADMIN_API_KEY", "")
    service_admin = None
    admin_key_state = "unconfigured"
    if raw_api_key:
        try:
            service_admin = RauthyAdminClient(api_key=SecretStr(raw_api_key))
            admin_key_state = "configured_unverified"
        except RauthyAdminKeyRejected:
            # Invalid optional integration must never crash the independent
            # Control Panel API. Only this integration remains disabled.
            admin_key_state = "invalid_credential"

    # Private, short-lived browser transactions/sessions, NOT platform grants.
    # The Valkey credential is owned by the existing External Services stack.
    # Existing protected OAuth realm is the sole product activation switch.
    # No new operator ENV, no UI preview toggle, and no fallback to a foreign
    # provider. A missing provider/Valkey remains fail-closed HTTP503.
    if (
        native_init is None
        and test_only_local_origin is None
        and managed_provider is not None
        and managed_provider.issuer == PUBLIC_ORIGIN + "/auth/v1"
        and managed_provider.client_id == "briareus-control-panel"
    ):
        native_init = PinnedNativeRauthyInit.for_public_dev()

    raw_valkey_key = os.environ.get("OIDC_SESSION_VALKEY_PASSWORD", "")
    browser_sessions = None
    if raw_valkey_key:
        with suppress(ValueError):
            browser_sessions = OidcBrowserSessionStore(password=SecretStr(raw_valkey_key))

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        # No Identity proxy or legacy bearer: only Rauthy/OIDC BFF.
        _app.state.rauthy_admin = service_admin
        _app.state.rauthy_admin_state = admin_key_state
        try:
            yield
        finally:
            if platform_peer is not None:
                await platform_peer.close()
            _app.state.rauthy_admin = None
            _app.state.rauthy_admin_state = None
            if service_admin is not None:
                await service_admin.close()
            if browser_sessions is not None:
                await browser_sessions.close()
            if managed_provider is not None:
                await managed_provider.close()

    app = FastAPI(
        title="Briareus Control Panel API",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Stable fail-closed native endpoints even when Rauthy or private
    # Valkey has not been explicitly installed in the local BFF owner.
    # Frontend must never interpret a 404 as permission to use a hosted
    # identity UI or make credential requests to a different endpoint.
    if native_init is None or browser_sessions is None or managed_provider is None:

        async def native_unavailable() -> Response:
            return JSONResponse(
                {"error": {"code": "NATIVE_OWNER_UNAVAILABLE"}},
                status_code=503,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        for method, path in (
            ("POST", "start"),
            ("POST", "pow"),
            ("POST", "first-factor"),
            ("POST", "cancel"),
            ("GET", "capabilities"),
        ):
            app.add_api_route(
                AUTH_API_PREFIX + "/" + path,
                native_unavailable,
                methods=[method],
                include_in_schema=False,
            )

    @app.get("/health/live", include_in_schema=False)
    async def live() -> dict[str, str]:
        return {
            "state": "live",
            "service": "control-panel-api",
            "api": "rauthy-oidc-bff",
            "authorization": "fail-closed-platform-owners",
        }

    if managed_provider is not None and browser_sessions is not None:
        app.include_router(
            oidc_browser_router(
                managed_provider,
                browser_sessions,
                test_only_local_origin=test_only_local_origin,
            )
        )
        if native_init is not None:
            app.include_router(
                native_login_start_router(
                    provider=managed_provider,
                    transactions=browser_sessions,
                    native_init=native_init,
                    test_only_local_origin=test_only_local_origin,
                )
            )
            app.include_router(
                native_login_router(
                    provider=managed_provider,
                    transactions=browser_sessions,
                    native_provider=native_init,
                    test_only_local_origin=test_only_local_origin,
                )
            )
        app.include_router(
            platform_membership_router(
                browser_sessions,
                source=membership_source,
                approval_source=approval_source,
                catalog_source=catalog_source,
                files_content_source=files_content_source,
                resource_audience=managed_provider.resource_audience,
                test_only_local_origin=test_only_local_origin,
                expected_issuer=managed_provider.issuer,
                expected_client_id=managed_provider.client_id,
                management_peer=platform_peer,
            )
        )
    else:
        # Preserve a stable unconfigured API instead of a misleading 404.
        @app.get(AUTH_API_PREFIX + "/authorize")
        async def oidc_start_unavailable() -> Response:
            raise HTTPException(503, detail="OIDC login is not configured")

        @app.get(REGISTERED_RAUTHY_CALLBACK_PATH)
        async def oidc_callback_unavailable() -> Response:
            raise HTTPException(503, detail="OIDC login is not configured")

        @app.get(AUTH_API_PREFIX + "/session")
        async def oidc_session_unavailable() -> Response:
            raise HTTPException(503, detail="OIDC login is not configured")

        @app.get(AUTH_API_PREFIX + "/me")
        async def oidc_me_unavailable() -> Response:
            raise HTTPException(503, detail="OIDC login is not configured")

        @app.post(AUTH_API_PREFIX + "/logout")
        async def oidc_logout_unavailable() -> Response:
            raise HTTPException(503, detail="OIDC login is not configured")

        @app.post(API_V1_PREFIX + "/files/read", include_in_schema=False)
        async def oidc_files_read_unavailable() -> Response:
            return JSONResponse(
                {"error": {"code": "FILES_READ_OWNER_UNAVAILABLE"}},
                status_code=503,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        @app.get(API_V1_PREFIX + "/catalog")
        async def oidc_catalog_unavailable() -> Response:
            raise HTTPException(503, detail="OIDC Platform Catalog source is not configured")

        @app.get(API_V1_PREFIX + "/approvals")
        async def oidc_approvals_unavailable() -> Response:
            raise HTTPException(503, detail="OIDC Platform authority is not configured")

        @app.post(API_V1_PREFIX + "/approvals")
        async def oidc_approval_request_unavailable() -> Response:
            raise HTTPException(503, detail="OIDC Platform authority is not configured")

        @app.post(API_V1_PREFIX + "/approvals/{approval_uuid}/resolve")
        async def oidc_approval_resolve_unavailable(approval_uuid: str) -> Response:
            del approval_uuid
            raise HTTPException(503, detail="OIDC Platform authority is not configured")

        @app.get(API_V1_PREFIX + "/agent-sessions")
        async def oidc_session_list_unavailable() -> Response:
            raise HTTPException(503, detail="OIDC Platform authority is not configured")

        @app.get(API_V1_PREFIX + "/agent-sessions/{session_uuid}")
        async def oidc_session_get_unavailable(session_uuid: str) -> Response:
            del session_uuid
            raise HTTPException(503, detail="OIDC Platform authority is not configured")

        @app.post(API_V1_PREFIX + "/agent-sessions")
        async def oidc_session_open_unavailable() -> Response:
            raise HTTPException(503, detail="OIDC Platform authority is not configured")

        @app.post(API_V1_PREFIX + "/agent-sessions/{session_uuid}/revoke")
        async def oidc_session_revoke_unavailable(session_uuid: str) -> Response:
            del session_uuid
            raise HTTPException(503, detail="OIDC Platform authority is not configured")

    @app.get(AUTH_API_PREFIX + "/config", response_model=OidcBrowserConfiguration)
    async def oidc_config(response: Response) -> OidcBrowserConfiguration:
        response.headers["Cache-Control"] = "no-store"
        if managed_provider is None:
            raise HTTPException(status_code=503, detail="identity provider is not configured")
        try:
            configuration = await managed_provider.public_configuration()
        except OidcProviderUnavailable as exc:
            raise HTTPException(status_code=503, detail="identity provider unavailable") from exc
        return OidcBrowserConfiguration(**asdict(configuration))

    return app


app = create_control_panel_api()

"""Native Briareus first-factor start, without hosted Rauthy browser redirect.

A real Rauthy Init session is independently created on the pinned provider,
then bound with original PKCE/nonce/state to one private Valkey transaction.
Neither the browser nor this API endpoint receives Rauthy CSRF/cookie.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.requests import ClientDisconnect

from ._api_paths import AUTH_API_PREFIX
from ._oidc import OidcProviderUnavailable, RauthyOidcAdapter
from ._oidc_browser import (
    _NATIVE_TX_COOKIE,
    OidcBrowserSessionStore,
    OidcSessionStoreUnavailable,
    _cookie,
    _strict_browser_cookies,
)
from ._oidc_origin_policy import (
    PUBLIC_HOST,
    browser_callback_uri,
    local_browser_host,
    resolve_browser_origin,
)
from ._rauthy_native_init import PinnedNativeRauthyInit
from ._rauthy_native_protocol import NativeProviderProtocolUnavailable

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


async def _exact_empty_native_request(request: Request, *, origin: str, host: str) -> bool:
    """Bound pre-auth body reception without Request.body() buffering.

    Content-Length is a claim, never a safe receive limit. A forged length
    of 2 with a large ASGI body must deny before buffering the payload.
    """
    if (
        request.headers.getlist("origin") != [origin]
        or request.headers.getlist("host") != [host]
        or request.headers.getlist("content-type") != ["application/json"]
        or request.headers.getlist("content-length") != ["2"]
        or request.headers.getlist("transfer-encoding")
        or request.headers.getlist("authorization")
        or len(request.headers.getlist("cookie")) > 1
        or request.query_params
    ):
        return False
    result = bytearray()
    try:
        async with asyncio.timeout(5):
            async for part in request.stream():
                if len(part) > 2 - len(result):
                    return False
                result.extend(part)
    except (TimeoutError, RuntimeError, ClientDisconnect):
        return False
    return result == b"{}"


def native_login_start_router(
    *,
    provider: RauthyOidcAdapter,
    transactions: OidcBrowserSessionStore,
    native_init: PinnedNativeRauthyInit,
    test_only_local_origin: str | None,
) -> APIRouter:
    origin = resolve_browser_origin(
        test_origin=test_only_local_origin,
        provider_issuer=provider.issuer,
        provider_client=provider.client_id,
    )
    if (
        native_init.issuer != provider.issuer
        or native_init.client_id != provider.client_id
        or native_init.callback != browser_callback_uri(origin)
    ):
        raise ValueError("native Rauthy issuer/client/callback differs from signed OAuth provider")
    host = local_browser_host(test_only_local_origin) or PUBLIC_HOST
    callback = browser_callback_uri(origin)
    router = APIRouter()

    @router.post(AUTH_API_PREFIX + "/start")
    async def start(request: Request) -> JSONResponse:
        # Same-origin first-factor init is not an authenticated User,
        # but must not become a cross-origin provider-session allocation API.
        if not await _exact_empty_native_request(request, origin=origin, host=host):
            return JSONResponse(
                {"error": {"code": "NATIVE_ORIGIN_OR_REQUEST_DENIED"}},
                status_code=403,
                headers=_NO_STORE,
            )
        try:
            handles = _strict_browser_cookies(request)
            if handles is None:
                return JSONResponse(
                    {"error": {"code": "NATIVE_COOKIE_INVALID"}},
                    status_code=401,
                    headers=_NO_STORE,
                )
            prior = handles.get(_NATIVE_TX_COOKIE)
            if prior is not None:
                await transactions.delete_native_init(state=prior)
            attempt = await provider.prepare_authorization_code(redirect_uri=callback)
            native = await native_init.initialize()
            ttl = min(
                300,
                int((attempt.expires_at - datetime.now(UTC)).total_seconds()),
                int((native.expires_at - datetime.now(UTC)).total_seconds()),
            )
            if ttl < 1:
                raise NativeProviderProtocolUnavailable("Rauthy native Init expired")
            await transactions.save_native_init(
                state=attempt.state,
                nonce=attempt.nonce,
                verifier=attempt.code_verifier.get_secret_value(),
                issuer=provider.issuer,
                client_id=provider.client_id,
                csrf=native.csrf_token,
                provider_cookie=native.provider_cookie_header,
                seconds=ttl,
                resource_audience=attempt.resource_audience,
            )
        except (
            OidcProviderUnavailable,
            NativeProviderProtocolUnavailable,
            OidcSessionStoreUnavailable,
        ):
            return JSONResponse(
                {"error": {"code": "NATIVE_INIT_UNAVAILABLE"}},
                status_code=503,
                headers=_NO_STORE,
            )
        # This cookie is a pending transaction handle, NOT an identity.
        response = JSONResponse(
            {"stage": "first_factor_required", "authenticated": False, "expires_in": ttl},
            status_code=201,
            headers=_NO_STORE,
        )
        _cookie(response, _NATIVE_TX_COOKIE, attempt.state, ttl)
        return response

    @router.post(AUTH_API_PREFIX + "/pow")
    async def issue_pow(request: Request) -> JSONResponse:
        if not await _exact_empty_native_request(request, origin=origin, host=host):
            return JSONResponse(
                {"error": {"code": "NATIVE_ORIGIN_OR_REQUEST_DENIED"}},
                status_code=403,
                headers=_NO_STORE,
            )
        handles = _strict_browser_cookies(request)
        pending = handles.get(_NATIVE_TX_COOKIE) if handles is not None else None
        if pending is None:
            return JSONResponse(
                {"error": {"code": "NATIVE_INIT_REQUIRED"}},
                status_code=401,
                headers=_NO_STORE,
            )
        try:
            current = await transactions.native_init_is_current(
                state=pending, issuer=provider.issuer, client_id=provider.client_id
            )
            if not current:
                return JSONResponse(
                    {"error": {"code": "NATIVE_INIT_EXPIRED"}},
                    status_code=401,
                    headers=_NO_STORE,
                )
            reserved = await transactions.reserve_native_pow(
                state=pending, issuer=provider.issuer, client_id=provider.client_id
            )
            if not reserved:
                return JSONResponse(
                    {"error": {"code": "NATIVE_POW_ALREADY_RESERVED"}},
                    status_code=409,
                    headers=_NO_STORE,
                )
            challenge = await native_init.issue_pow()
            if not await transactions.confirm_native_pow(
                state=pending, issuer=provider.issuer, client_id=provider.client_id
            ):
                return JSONResponse(
                    {"error": {"code": "NATIVE_INIT_EXPIRED"}},
                    status_code=401,
                    headers=_NO_STORE,
                )
        except (OidcSessionStoreUnavailable, NativeProviderProtocolUnavailable):
            return JSONResponse(
                {"error": {"code": "NATIVE_POW_UNAVAILABLE"}},
                status_code=503,
                headers=_NO_STORE,
            )
        return JSONResponse(
            {"challenge": challenge, "authenticated": False},
            status_code=200,
            headers=_NO_STORE,
        )

    return router

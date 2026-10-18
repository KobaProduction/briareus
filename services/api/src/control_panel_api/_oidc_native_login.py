"""Native first factor with cancelable one-time state and real PKCE completion.

No provider credential, cookie, CSRF, MFA code or access bearer is returned.
Unsupported provider continuation states explicitly remain unauthenticated.
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import parse_qs, urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from ._api_paths import AUTH_API_PREFIX, REGISTERED_RAUTHY_CALLBACK_PATH
from ._native_credentials import NativeFirstFactorRequest
from ._oidc import OidcProviderUnavailable, RauthyOidcAdapter, _unique_oidc_fields
from ._oidc_browser import (
    _NATIVE_TX_COOKIE,
    _SID_COOKIE,
    OidcBrowserSessionStore,
    OidcSessionStoreUnavailable,
    PrivateNativePending,
    _clear,
    _cookie,
    _strict_browser_cookies,
)
from ._oidc_id_token import OidcIdentityKeysUnavailable, OidcIdentityRejected
from ._oidc_origin_policy import PUBLIC_ORIGIN, local_browser_host, resolve_browser_origin
from ._rauthy_native_init import PinnedNativeRauthyInit
from ._rauthy_native_protocol import NativeProviderProtocolUnavailable, PrivateNativeLoginStep

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_UNSUPPORTED = frozenset(
    {
        "webauthn_pending",
        "tos_pending",
        "account_update_required",
        "client_mfa_required",
    }
)


class NativeOtpMethodRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    method_index: int = Field(ge=0, le=9)


class NativeOtpFinishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    otp_code: SecretStr

    @field_validator("otp_code")
    @classmethod
    def validate_otp_value(cls, value: SecretStr) -> SecretStr:
        import re

        original = value.get_secret_value()
        compact = original.replace(" ", "")
        if re.fullmatch(r"[0-9]{6,8}", compact, re.ASCII) is None:
            raise ValueError("OTP verification code has unsupported shape")
        if original != compact and original != (
            compact[: len(compact) // 2] + " " + compact[len(compact) // 2 :]
        ):
            raise ValueError("OTP formatted code is ambiguous")
        # Rauthy emails codes in two groups separated by ONE ASCII space;
        # its actual v0.37.1 validate() expects the original digits only.
        return SecretStr(compact)


def _failure(status: int, code: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code}}, status_code=status, headers=_NO_STORE)


def native_login_router(
    *,
    provider: RauthyOidcAdapter,
    transactions: OidcBrowserSessionStore,
    native_provider: PinnedNativeRauthyInit,
    test_only_local_origin: str | None,
) -> APIRouter:
    origin = resolve_browser_origin(
        test_origin=test_only_local_origin,
        provider_issuer=provider.issuer,
        provider_client=provider.client_id,
    )
    host = local_browser_host(test_only_local_origin) or "briareus.koba-nexus.ru"
    if (
        native_provider.issuer != provider.issuer
        or native_provider.client_id != provider.client_id
        or native_provider.callback != origin + REGISTERED_RAUTHY_CALLBACK_PATH
        or (test_only_local_origin is None and origin != PUBLIC_ORIGIN)
    ):
        raise ValueError("native credentials require one fixed matching issuer/client/callback")
    router = APIRouter()

    async def read_body(request: Request, *, empty: bool) -> bytes | JSONResponse:
        if (
            request.headers.getlist("origin") != [origin]
            or request.headers.getlist("host") != [host]
            or request.headers.getlist("content-type") != ["application/json"]
            or request.headers.getlist("authorization")
            or request.headers.getlist("transfer-encoding")
            or len(request.headers.getlist("cookie")) > 1
            or request.query_params
        ):
            return _failure(403, "NATIVE_ORIGIN_OR_REQUEST_DENIED")
        lengths = request.headers.getlist("content-length")
        if (
            len(lengths) != 1
            or not 1 <= len(lengths[0]) <= 4
            or not lengths[0].isascii()
            or not lengths[0].isdecimal()
            or not 2 <= int(lengths[0]) <= 8192
        ):
            return _failure(422, "NATIVE_REQUEST_INVALID")
        content = bytearray()
        try:
            async with asyncio.timeout(5):
                async for block in request.stream():
                    if len(content) + len(block) > 8192:
                        return _failure(422, "NATIVE_REQUEST_INVALID")
                    content.extend(block)
        except (TimeoutError, RuntimeError):
            return _failure(422, "NATIVE_REQUEST_INVALID")
        if len(content) != int(lengths[0]) or (empty and bytes(content) != b"{}"):
            return _failure(422, "NATIVE_REQUEST_INVALID")
        return bytes(content)

    async def retire(state: str) -> bool:
        # Drain bounded cleanup even if downstream cancellation repeats.
        async def remove() -> None:
            async with asyncio.timeout(4):
                await transactions.delete_native_init(state=state)

        task = asyncio.create_task(remove())
        interrupted = False
        try:
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    interrupted = True
            task.result()
        except (OidcSessionStoreUnavailable, TimeoutError):
            if interrupted:
                raise asyncio.CancelledError from None
            return False
        if interrupted:
            raise asyncio.CancelledError
        return True

    @router.get(AUTH_API_PREFIX + "/capabilities")
    async def capabilities(request: Request) -> Response:
        if request.headers.getlist("host") != [host] or request.query_params:
            return _failure(403, "NATIVE_ORIGIN_OR_REQUEST_DENIED")
        # Configured API capability only, not provider health or a signed User.
        return JSONResponse(
            {
                "protocol": "rauthy-native-v1",
                "first_factor": "password",
                "pow": "client-solved",
                "cancel": True,
                # Capability describes the CURRENT public browser contract,
                # not a list of hidden backend-only routes. Deployed UI v1
                # accepts only []; advertising OTP without a coordinated OTP
                # form blocks ALL password-only login before /start. Retain
                # private OTP endpoints fail-closed, but publish the new
                # continuation only with a Frontend/Backend-compatible release.
                "continuations": [],
            },
            headers=_NO_STORE,
        )

    @router.post(AUTH_API_PREFIX + "/cancel")
    async def cancel(request: Request) -> Response:
        body = await read_body(request, empty=True)
        if isinstance(body, JSONResponse):
            return body
        handles = _strict_browser_cookies(request)
        if handles is None:
            return _failure(401, "NATIVE_COOKIE_INVALID")
        state = handles.get(_NATIVE_TX_COOKIE)
        if state is not None and not await retire(state):
            return _failure(503, "NATIVE_CANCEL_UNAVAILABLE")
        response = Response(status_code=204, headers=_NO_STORE)
        _clear(response, _NATIVE_TX_COOKIE)
        return response

    async def finish(
        request: Request, pending: PrivateNativePending, step: PrivateNativeLoginStep
    ) -> Response:
        if step.state in _UNSUPPORTED:
            return JSONResponse(
                {
                    "stage": step.state,
                    "authenticated": False,
                    "continuation_available": False,
                    "restart_required": True,
                },
                status_code=409,
                headers=_NO_STORE,
            )
        if step.state == "otp_pending":
            # Rauthy v0.37.1 one_time_password.rs implements validation for
            # OtpKind::Email only; Time and Phone return "unimplemented".
            # Never advertise a TOTP/phone method as a usable login factor.
            available = tuple(
                (kind, otp_id)
                for kind, otp_id in zip(step.challenge_kinds, step.private_otp_ids, strict=True)
                if kind == "email"
            )
            if not available:
                return JSONResponse(
                    {
                        "stage": "otp_pending",
                        "authenticated": False,
                        "continuation_available": False,
                        "restart_required": True,
                    },
                    status_code=409,
                    headers=_NO_STORE,
                )
            if (
                step.secret is None
                or step.provider_cookie is None
                or step.csrf_token is None
                or not step.private_otp_ids
                or len(step.private_otp_ids) != len(step.challenge_kinds)
            ):
                raise NativeProviderProtocolUnavailable("private OTP challenge unavailable")
            stored = await transactions.stage_native_otp(
                pending=pending,
                login_code=step.secret,
                methods=available,
                provider_cookie=step.provider_cookie,
                csrf_token=step.csrf_token,
            )
            if not stored or await request.is_disconnected():
                return _failure(401, "NATIVE_ATTEMPT_EXPIRED_OR_CANCELLED")
            return JSONResponse(
                {
                    "stage": "otp_pending",
                    "authenticated": False,
                    "continuation_available": True,
                    "methods": [
                        {"index": index, "kind": kind}
                        for index, (kind, _private_id) in enumerate(available)
                    ],
                },
                status_code=202,
                headers=_NO_STORE,
            )
        if step.state == "rate_limited":
            return JSONResponse(
                {
                    "error": {"code": "NATIVE_RATE_LIMITED"},
                    "retry_not_before": step.retry_not_before,
                },
                status_code=429,
                headers=_NO_STORE,
            )
        # Rauthy documents HTTP401 as credentials OR cookie/session/CSRF
        # failure. A provider HTTP400 is an invalid OIDC request; HTTP403
        # is an explicitly forbidden client/group. Neither proves an invalid
        # password. Preserve distinct, non-sensitive provider result codes.
        if step.state == "credentials_rejected":
            return _failure(401, "NATIVE_PROVIDER_AUTH_REJECTED")
        if step.state == "request_rejected":
            return _failure(400, "NATIVE_PROVIDER_REQUEST_REJECTED")
        if step.state == "provider_access_denied":
            return _failure(403, "NATIVE_PROVIDER_ACCESS_DENIED")
        if step.state != "oauth_callback_pending" or step.secret is None:
            raise NativeProviderProtocolUnavailable("native step cannot finish login")
        # The pinned decoder already verified exact callback/code/state/iss.
        args = parse_qs(urlsplit(step.secret.get_secret_value()).query, strict_parsing=True)
        login = await provider.authenticate_authorization_code(
            code=args["code"][0],
            redirect_uri=origin + REGISTERED_RAUTHY_CALLBACK_PATH,
            code_verifier=pending.verifier,
            expected_nonce=pending.nonce,
            expected_issuer=args["iss"][0],
            resource_audience=pending.resource_audience,
        )
        if await request.is_disconnected():
            return _failure(401, "NATIVE_ATTEMPT_DISCONNECTED")
        committed = await transactions.complete_native_login(
            pending=pending, identity=login.identity, resource=login.resource
        )
        if committed is None:
            return _failure(401, "NATIVE_ATTEMPT_EXPIRED_OR_CANCELLED")
        ticket, seconds = committed
        if await transactions.get_session(ticket) is None or await request.is_disconnected():
            return _failure(401, "NATIVE_ATTEMPT_EXPIRED_OR_CANCELLED")
        response = JSONResponse(
            {
                "stage": "authenticated",
                "authenticated": True,
                "authority": "rauthy",
                "platform_membership_verified": False,
                "permissions": [],
            },
            headers=_NO_STORE,
        )
        _cookie(response, _SID_COOKIE, ticket, seconds)
        # Retain the existing attempt cookie until its natural short expiry:
        # a concurrent cancel/logout can still invalidate a late cookie reply.
        return response

    @router.post(AUTH_API_PREFIX + "/first-factor")
    async def first_factor(request: Request) -> Response:
        body = await read_body(request, empty=False)
        if isinstance(body, JSONResponse):
            return body
        try:
            credentials = NativeFirstFactorRequest.model_validate(
                json.loads(body, object_pairs_hook=_unique_oidc_fields)
            )
        except (ValueError, TypeError, UnicodeError, RecursionError):
            return _failure(422, "NATIVE_REQUEST_INVALID")
        del body
        handles = _strict_browser_cookies(request)
        if handles is None:
            return _failure(401, "NATIVE_COOKIE_INVALID")
        state = handles.get(_NATIVE_TX_COOKIE)
        if state is None:
            return _failure(401, "NATIVE_INIT_REQUIRED")
        claimed = False
        success = False
        response: Response
        try:
            async with asyncio.timeout(30):
                pending = await transactions.consume_native_init(
                    state=state, issuer=provider.issuer, client_id=provider.client_id
                )
                if pending is None:
                    # Losing consumers must not cancel the winning request.
                    return _failure(401, "NATIVE_ATTEMPT_EXPIRED_OR_CLAIMED")
                claimed = True
                if (
                    pending.resource_audience != provider.resource_audience
                    or not await transactions.native_claim_is_current(pending)
                    or await request.is_disconnected()
                ):
                    response = _failure(401, "NATIVE_ATTEMPT_EXPIRED_OR_CANCELLED")
                else:
                    step = await native_provider.authorize(pending=pending, credentials=credentials)
                    if (
                        not await transactions.native_claim_is_current(pending)
                        or await request.is_disconnected()
                    ):
                        response = _failure(401, "NATIVE_ATTEMPT_EXPIRED_OR_CANCELLED")
                    else:
                        response = await finish(request, pending, step)
                        success = response.status_code in {200, 202}
        except asyncio.CancelledError:
            await retire(state)
            raise
        except OidcIdentityRejected:
            response = _failure(401, "NATIVE_IDENTITY_REJECTED")
        except (
            OidcProviderUnavailable,
            OidcIdentityKeysUnavailable,
            OidcSessionStoreUnavailable,
            NativeProviderProtocolUnavailable,
            TimeoutError,
        ):
            # A timed-out claim may have committed before its reply was lost.
            claimed = True
            response = _failure(503, "NATIVE_LOGIN_UNAVAILABLE")
        if claimed and not success and not await retire(state):
            return _failure(503, "NATIVE_CANCEL_UNAVAILABLE")
        return response

    async def otp_body(request: Request, model: type[BaseModel]) -> BaseModel | JSONResponse:
        raw = await read_body(request, empty=False)
        if isinstance(raw, JSONResponse):
            return raw
        try:
            return model.model_validate(json.loads(raw, object_pairs_hook=_unique_oidc_fields))
        except (ValueError, TypeError, UnicodeError, RecursionError):
            return _failure(422, "NATIVE_OTP_REQUEST_INVALID")

    @router.post(AUTH_API_PREFIX + "/otp/start")
    async def otp_start(request: Request) -> Response:
        body = await otp_body(request, NativeOtpMethodRequest)
        if isinstance(body, JSONResponse):
            return body
        assert isinstance(body, NativeOtpMethodRequest)
        handles = _strict_browser_cookies(request)
        if handles is None:
            return _failure(401, "NATIVE_COOKIE_INVALID")
        state = handles.get(_NATIVE_TX_COOKIE)
        if state is None:
            return _failure(401, "NATIVE_INIT_REQUIRED")
        try:
            challenge = await transactions.claim_native_otp_start(
                state=state,
                issuer=provider.issuer,
                client_id=provider.client_id,
                method_index=body.method_index,
            )
        except OidcSessionStoreUnavailable:
            return _failure(503, "NATIVE_OTP_START_UNAVAILABLE")
        if challenge is None:
            # Another one-use winner is in progress: never cancel its claim.
            return _failure(409, "NATIVE_OTP_START_ALREADY_CLAIMED")
        success = False
        response: Response
        try:
            async with asyncio.timeout(18):
                if await request.is_disconnected():
                    response = _failure(401, "NATIVE_ATTEMPT_EXPIRED_OR_CANCELLED")
                else:
                    result, private_cookie, private_csrf = await native_provider.otp_start(
                        pending=challenge
                    )
                    confirmed = await transactions.confirm_native_otp_start(
                        challenge=challenge,
                        otp_code=result.secret,
                        otp_expires_at=result.expires_at,
                        provider_cookie=private_cookie,
                        csrf_token=private_csrf,
                    )
                    if not confirmed or await request.is_disconnected():
                        response = _failure(401, "NATIVE_ATTEMPT_EXPIRED_OR_CANCELLED")
                    else:
                        success = True
                        response = JSONResponse(
                            {
                                "stage": "otp_code_pending",
                                "authenticated": False,
                                "expires_at": min(
                                    result.expires_at,
                                    int(challenge.original.expires_at.timestamp()),
                                ),
                            },
                            status_code=202,
                            headers=_NO_STORE,
                        )
        except asyncio.CancelledError:
            await retire(state)
            raise
        except (NativeProviderProtocolUnavailable, OidcSessionStoreUnavailable, TimeoutError):
            response = _failure(503, "NATIVE_OTP_START_UNAVAILABLE")
        if not success and not await retire(state):
            return _failure(503, "NATIVE_CANCEL_UNAVAILABLE")
        return response

    @router.post(AUTH_API_PREFIX + "/otp/finish")
    async def otp_finish(request: Request) -> Response:
        body = await otp_body(request, NativeOtpFinishRequest)
        if isinstance(body, JSONResponse):
            return body
        assert isinstance(body, NativeOtpFinishRequest)
        handles = _strict_browser_cookies(request)
        if handles is None:
            return _failure(401, "NATIVE_COOKIE_INVALID")
        state = handles.get(_NATIVE_TX_COOKIE)
        if state is None:
            return _failure(401, "NATIVE_INIT_REQUIRED")
        try:
            challenge = await transactions.claim_native_otp_finish(
                state=state, issuer=provider.issuer, client_id=provider.client_id
            )
        except OidcSessionStoreUnavailable:
            return _failure(503, "NATIVE_OTP_FINISH_UNAVAILABLE")
        if challenge is None:
            return _failure(409, "NATIVE_OTP_FINISH_ALREADY_CLAIMED")
        success = False
        response: Response
        try:
            async with asyncio.timeout(30):
                if await request.is_disconnected():
                    response = _failure(401, "NATIVE_ATTEMPT_EXPIRED_OR_CANCELLED")
                else:
                    step = await native_provider.otp_finish(
                        pending=challenge,
                        otp_value=body.otp_code.get_secret_value(),
                    )
                    if not await transactions.native_claim_is_current(challenge.original):
                        response = _failure(401, "NATIVE_ATTEMPT_EXPIRED_OR_CANCELLED")
                    else:
                        response = await finish(request, challenge.original, step)
                        success = response.status_code == 200
        except asyncio.CancelledError:
            await retire(state)
            raise
        except OidcIdentityRejected:
            response = _failure(401, "NATIVE_IDENTITY_REJECTED")
        except (
            NativeProviderProtocolUnavailable,
            OidcSessionStoreUnavailable,
            OidcProviderUnavailable,
            OidcIdentityKeysUnavailable,
            TimeoutError,
        ):
            response = _failure(503, "NATIVE_OTP_FINISH_UNAVAILABLE")
        if not success and not await retire(state):
            return _failure(503, "NATIVE_CANCEL_UNAVAILABLE")
        return response

    return router

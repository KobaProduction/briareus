"""Cookie-bound human Platform management; no owner SQL or provider grants here."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ._api_paths import API_V1_PREFIX
from ._oidc_membership import CurrentPlatformContext
from ._platform_unix_peer import UnixPlatformPeer

HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class PlatformCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation_uuid: UUID
    action: Literal[
        "team.create",
        "team.rename",
        "team.member.add",
        "team.member.remove",
        "project.create",
        "project.rename",
        "user.link",
    ]
    data: dict[str, object] = Field(max_length=6)

    @field_validator("operation_uuid")
    @classmethod
    def operation_v4(cls, value: UUID) -> UUID:
        if value.version != 4:
            raise ValueError("Operation must be UUIDv4")
        return value


def platform_management_router(
    *, current_context: CurrentPlatformContext, peer: UnixPlatformPeer | None, browser_origin: str
) -> APIRouter:
    router = APIRouter(prefix=API_V1_PREFIX + "/platform")

    def fail(status: int, code: str) -> JSONResponse:
        return JSONResponse({"error": {"code": code}}, status_code=status, headers=HEADERS)

    async def invoke(request: Request, command: dict[str, object]) -> JSONResponse:
        current = await current_context(request)
        if isinstance(current, JSONResponse):
            return current
        session, actor = current
        if actor.role != "operator":
            return fail(403, "PLATFORM_OPERATOR_REQUIRED")
        if peer is None:
            return fail(503, "PLATFORM_MANAGEMENT_UNAVAILABLE")
        deadline = min(session.expires_at, actor.expires_at)
        if deadline <= datetime.now(UTC):
            return fail(401, "OIDC_SESSION_EXPIRED")
        try:
            status, result = await peer.management(
                {"issuer": session.issuer, "subject": session.subject, **command},
                expires_at=deadline,
            )
            if deadline <= datetime.now(UTC):
                return fail(503, "OPERATION_OUTCOME_UNKNOWN")
            if status not in {200, 401, 403, 404, 409, 413, 422, 503}:
                return fail(503, "PLATFORM_MANAGEMENT_UNAVAILABLE")
            return JSONResponse(result, status_code=status, headers=HEADERS)
        except Exception:
            return fail(503, "OPERATION_OUTCOME_UNKNOWN")

    @router.get("/inventory")
    async def inventory(request: Request) -> JSONResponse:
        return await invoke(
            request, {"operation_uuid": str(uuid4()), "action": "inventory", "data": {}}
        )

    @router.post("/commands")
    async def command(request: Request) -> JSONResponse:
        if (
            request.headers.getlist("origin") != [browser_origin]
            or request.headers.getlist("content-type") != ["application/json"]
            or request.headers.get("sec-fetch-site") not in (None, "same-origin")
        ):
            return fail(403, "PLATFORM_ORIGIN_REQUIRED")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 8192:
                return fail(413, "COMMAND_TOO_LARGE")
        try:
            parsed = PlatformCommand.model_validate_json(body)
        except ValidationError:
            return fail(422, "COMMAND_INVALID")
        return await invoke(request, parsed.model_dump(mode="json"))

    return router

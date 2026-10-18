"""Browser-safe Files content facade; only an independently verified owner may read.

The BFF holds an opaque Rauthy browser cookie and scoped Platform proof. It
never resolves a Project root, turns a JWT into a Cedar Permit, or invokes a
Hand via browser-supplied service headers. Missing owner port always returns
503; a source-only fixture cannot activate the real Files dataplane.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from starlette.requests import ClientDisconnect

from ._api_paths import API_V1_PREFIX
from ._oidc import _unique_oidc_fields
from ._oidc_browser import (
    _SID_COOKIE,
    OidcBrowserSessionStore,
    OidcSessionStoreUnavailable,
    _strict_browser_cookies,
)
from ._oidc_membership import CurrentPlatformContext
from ._oidc_origin_policy import PUBLIC_HOST, PUBLIC_ORIGIN, local_browser_host

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_MAX_BODY = 8192
_MAX_READ = 262_144
_RESERVED = re.compile(r"\.upload-[0-9a-f]{32}\.tmp\Z", re.ASCII)


class BrowserFilesRead(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    project_uuid: UUID
    agent_session_uuid: UUID
    expected_grant_revision: int = Field(strict=True, ge=1, le=2**63 - 1)
    path: str = Field(min_length=1, max_length=4096)
    max_bytes: int = Field(strict=True, ge=1, le=_MAX_READ)

    @field_validator("project_uuid", "agent_session_uuid", mode="before")
    @classmethod
    def canonical_uuid(cls, value: object) -> UUID:
        if not isinstance(value, str):
            raise ValueError("canonical UUID string required")
        try:
            selected = UUID(value)
        except (TypeError, ValueError):
            raise ValueError("invalid UUID string") from None
        if selected.version != 4 or str(selected) != value:
            raise ValueError("canonical UUIDv4 required")
        return selected

    @field_validator("path")
    @classmethod
    def canonical_path(cls, path: str) -> str:
        if (
            not isinstance(path, str)
            or not path
            or path.startswith("/")
            or "\\" in path
            or not unicodedata.is_normalized("NFC", path)
        ):
            raise ValueError("relative NFC file path required")
        parts = path.split("/")
        try:
            if (
                len(path.encode("utf-8", errors="strict")) > 4096
                or len(parts) > 64
                or any(
                    part in {"", ".", ".."}
                    or len(part.encode("utf-8", errors="strict")) > 255
                    or any(ord(char) < 32 or ord(char) == 127 for char in part)
                    or _RESERVED.fullmatch(part) is not None
                    for part in parts
                )
            ):
                raise ValueError("noncanonical Files path")
        except UnicodeError:
            raise ValueError("non-UTF-8 Files path") from None
        return path


@dataclass(frozen=True, slots=True)
class PrivateFilesReadCommand:
    """Selectors bound to verified BFF state; not authorization or a tool call."""

    operation_uuid: UUID
    actor_uuid: UUID
    issuer: str
    subject: str
    project_uuid: UUID
    agent_session_uuid: UUID
    expected_grant_revision: int
    selector_id: str
    path: str
    max_bytes: int
    bearer: SecretStr = field(repr=False)
    proof_expires_at: datetime


@dataclass(frozen=True, slots=True)
class VerifiedPrivateFilesRead:
    """Owner-attested raw bytes, not a transferable receipt or Cedar grant."""

    operation_uuid: UUID
    actor_uuid: UUID
    project_uuid: UUID
    agent_session_uuid: UUID
    grant_revision: int
    selector_id: str
    path: str
    payload: bytes = field(repr=False)
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class FilesContentDenied(Exception):
    """Authenticated private Files/Access owner expressly denies this effect."""


class FilesContentUnavailable(Exception):
    """Signed caller, Project/Access/Cedar or Files mapping cannot be verified."""


class TrustedFilesContentOwner(Protocol):
    async def read(self, command: PrivateFilesReadCommand) -> VerifiedPrivateFilesRead:
        """Independently authenticate BFF peer, token, current Project, Access
        revision, resource selector/root and BOTH Files read-decision phases.

        Missing/stale proofs and filesystem failures MUST deny, never return
        success based solely on the BFF's cookie, JSON or saved JWT bearer.
        """
        ...


def _error(status: int, code: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code}}, status_code=status, headers=_NO_STORE)


def _session_cookie(request: Request) -> str | None:
    handles = _strict_browser_cookies(request)
    return handles.get(_SID_COOKIE) if handles is not None else None


async def _json_body(request: Request, *, origin: str, host: str) -> bytes | JSONResponse:
    if (
        request.headers.getlist("host") != [host]
        or request.headers.getlist("origin") != [origin]
        or request.headers.getlist("content-type") != ["application/json"]
        or request.headers.getlist("authorization")
        or request.headers.getlist("transfer-encoding")
        or request.query_params
    ):
        return _error(403, "FILES_READ_ORIGIN_DENIED")
    length = request.headers.getlist("content-length")
    if (
        len(length) != 1
        or not 1 <= len(length[0]) <= 4
        or not length[0].isascii()
        or not length[0].isdecimal()
        or not 2 <= int(length[0]) <= _MAX_BODY
    ):
        return _error(422, "FILES_READ_REQUEST_INVALID")
    received = bytearray()
    try:
        async with asyncio.timeout(5):
            async for part in request.stream():
                if len(part) > _MAX_BODY - len(received):
                    return _error(422, "FILES_READ_REQUEST_INVALID")
                received.extend(part)
    except (TimeoutError, RuntimeError, ClientDisconnect):
        return _error(422, "FILES_READ_REQUEST_INVALID")
    if len(received) != int(length[0]):
        return _error(422, "FILES_READ_REQUEST_INVALID")
    return bytes(received)


def _selector(project: UUID, path: str) -> str:
    digest = hashlib.sha256(b"files-project-relative-v1\0" + path.encode("utf-8")).hexdigest()
    return f"project-path-v1:{project}:{digest}"


def files_content_router(
    *,
    current_context: CurrentPlatformContext,
    sessions: OidcBrowserSessionStore,
    resource_audience: str | None,
    expected_client_id: str | None,
    owner: TrustedFilesContentOwner | None,
    test_only_local_origin: str | None,
) -> APIRouter:
    router = APIRouter()
    origin = test_only_local_origin or PUBLIC_ORIGIN
    host = local_browser_host(test_only_local_origin) or PUBLIC_HOST

    @router.post(API_V1_PREFIX + "/files/read", include_in_schema=False)
    async def read(request: Request) -> JSONResponse:
        data = await _json_body(request, origin=origin, host=host)
        if isinstance(data, JSONResponse):
            return data
        try:
            json.loads(data, object_pairs_hook=_unique_oidc_fields)
            body = BrowserFilesRead.model_validate_json(data)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            return _error(422, "FILES_READ_REQUEST_INVALID")
        sid = _session_cookie(request)
        if sid is None:
            return _error(401, "FILES_READ_SESSION_REQUIRED")
        current = await current_context(request, body.project_uuid)
        if isinstance(current, JSONResponse):
            return current
        identity, proof = current
        if (
            len(proof.projects) != 1
            or proof.projects[0].project_uuid != body.project_uuid
            or "use_resources" not in proof.projects[0].permissions
        ):
            return _error(403, "FILES_READ_PROJECT_DENIED")
        if resource_audience is None or expected_client_id is None:
            return _error(503, "FILES_READ_RESOURCE_AUTHORITY_UNAVAILABLE")
        if owner is None:
            return _error(503, "FILES_READ_OWNER_UNAVAILABLE")
        try:
            credential = await sessions.get_resource_credential(
                sid,
                issuer=identity.issuer,
                client_id=expected_client_id,
                audience=resource_audience,
            )
        except (OidcSessionStoreUnavailable, ValueError):
            return _error(503, "FILES_READ_RESOURCE_AUTHORITY_UNAVAILABLE")
        if credential is None or credential.subject != identity.subject:
            return _error(403, "FILES_READ_RESOURCE_CREDENTIAL_REQUIRED")
        expires = min(identity.expires_at, proof.expires_at, credential.expires_at)
        if expires <= datetime.now(UTC):
            return _error(401, "FILES_READ_PROOF_EXPIRED")
        if await request.is_disconnected():
            return _error(401, "FILES_READ_REQUEST_CANCELLED")
        command = PrivateFilesReadCommand(
            operation_uuid=uuid4(),
            actor_uuid=proof.user_uuid,
            issuer=identity.issuer,
            subject=identity.subject,
            project_uuid=body.project_uuid,
            agent_session_uuid=body.agent_session_uuid,
            expected_grant_revision=body.expected_grant_revision,
            selector_id=_selector(body.project_uuid, body.path),
            path=body.path,
            max_bytes=body.max_bytes,
            bearer=credential.bearer,
            proof_expires_at=expires,
        )
        try:
            async with asyncio.timeout(10):
                result = await owner.read(command)
        except FilesContentDenied:
            return _error(403, "FILES_READ_DENIED")
        except Exception:
            return _error(503, "FILES_READ_OWNER_UNAVAILABLE")
        now = datetime.now(UTC)
        if (
            not isinstance(result, VerifiedPrivateFilesRead)
            or result.operation_uuid != command.operation_uuid
            or result.actor_uuid != command.actor_uuid
            or result.project_uuid != command.project_uuid
            or result.agent_session_uuid != command.agent_session_uuid
            or type(result.grant_revision) is not int
            or result.grant_revision != command.expected_grant_revision
            or result.selector_id != command.selector_id
            or result.path != command.path
            or type(result.payload) is not bytes
            or len(result.payload) > command.max_bytes
            or not isinstance(result.checked_at, datetime)
            or result.checked_at.tzinfo is None
            or not isinstance(result.expires_at, datetime)
            or result.expires_at.tzinfo is None
            or not result.checked_at <= now < result.expires_at
            or result.expires_at > result.checked_at + timedelta(seconds=5)
            or expires <= now
        ):
            return _error(503, "FILES_READ_OWNER_INVALID_RESPONSE")
        if await request.is_disconnected():
            return _error(401, "FILES_READ_REQUEST_CANCELLED")
        # Encode the bounded bytes BEFORE the final revocation/expiry read.
        # Expensive Base64/hash work may not consume an already checked TTL.
        content = result.payload
        prepared = JSONResponse(
            {
                "path": body.path,
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "content_base64": base64.b64encode(content).decode("ascii"),
            },
            headers=_NO_STORE,
        )
        # A long-running Files owner may finish after Platform has revoked
        # membership or transferred this Project to another owner. Requery
        # the EXACT current Project, not a bounded general /me inventory.
        # Never promote the new proof's expiry beyond the original lease.
        latest = await current_context(request, body.project_uuid)
        if isinstance(latest, JSONResponse):
            return latest
        latest_session, latest_proof = latest
        if (
            latest_session.issuer != identity.issuer
            or latest_session.subject != identity.subject
            or latest_session.client_id != identity.client_id
            or latest_proof.user_uuid != proof.user_uuid
            or latest_proof.role != proof.role
            or len(latest_proof.projects) != 1
            or latest_proof.projects[0] != proof.projects[0]
            or "use_resources" not in latest_proof.projects[0].permissions
        ):
            return _error(403, "FILES_READ_PROJECT_CHANGED")
        # Platform IO itself may have awaited. Session+Files bearer are
        # intentionally the LAST private lookups before returning bytes, so
        # a logout in either owner call cannot resurrect the earlier session.
        try:
            refreshed = await sessions.get_session(sid)
            again = await sessions.get_resource_credential(
                sid,
                issuer=identity.issuer,
                client_id=expected_client_id,
                audience=resource_audience,
            )
        except (OidcSessionStoreUnavailable, ValueError):
            return _error(503, "FILES_READ_SESSION_RECHECK_UNAVAILABLE")
        now = datetime.now(UTC)
        if (
            refreshed is None
            or refreshed.issuer != identity.issuer
            or refreshed.subject != identity.subject
            or refreshed.client_id != identity.client_id
            or again is None
            or again.subject != identity.subject
            or not hmac.compare_digest(
                again.bearer.get_secret_value(), credential.bearer.get_secret_value()
            )
            or min(
                refreshed.expires_at,
                latest_session.expires_at,
                latest_proof.expires_at,
                again.expires_at,
                expires,
                result.expires_at,
            )
            <= now
        ):
            return _error(401, "FILES_READ_SESSION_EXPIRED_OR_REVOKED")
        return prepared

    return router

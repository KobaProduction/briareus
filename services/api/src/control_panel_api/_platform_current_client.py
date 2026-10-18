"""Private Rauthy subject → Platform projection over an authenticated peer.

The Panel BFF never opens Platform PostgreSQL or imports Platform SQL models.
A transport must be independently attested mTLS/Unix and a signed short-lived
subject delegation must accompany each query. Nothing is configured by default.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from ._oidc_membership import (
    PlatformMembershipUnavailable,
    PlatformProjectContext,
    PlatformTeamContext,
    ResolvedPlatformUser,
)

_OWNER_URL = "http://briareus-platform:8000/internal/v1/platform/oidc/current"
_MAX_JSON_BYTES = 32768


@dataclass(frozen=True, slots=True)
class VerifiedPlatformServiceTransport:
    client: httpx.AsyncClient
    mode: Literal["mtls", "unix-peer"]
    server_audience: Literal["briareus:platform"]
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class VerifiedPanelDelegation:
    bearer: SecretStr
    subject: str
    issuer: str
    recipient: Literal["briareus:platform"]
    expires_at: datetime
    project_uuid: UUID | None = None


class TrustedPlatformPeerPort(Protocol):
    async def current_transport(self) -> VerifiedPlatformServiceTransport:
        """Provide pre-authenticated private server peer, not raw Docker DNS."""
        ...

    async def signed_subject_delegation(
        self, *, issuer: str, subject: str
    ) -> VerifiedPanelDelegation:
        """Bind verified Panel session subject to short-lived audience scope."""
        ...

    async def signed_project_delegation(
        self, *, issuer: str, subject: str, project_uuid: UUID
    ) -> VerifiedPanelDelegation:
        """Independently bind the exact Project selector to this subject."""
        ...


class _Team(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    team_uuid: UUID
    owner: bool
    name: str | None = Field(default=None, max_length=255)


class _Project(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    project_uuid: UUID
    name: str | None = Field(default=None, max_length=255)
    owner_kind: Literal["user", "team"]
    owner_uuid: UUID
    permissions: tuple[Literal["use_resources", "approve_agent_session"], ...]


class _PlatformCurrent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    issuer: str
    subject: str
    name: str | None = Field(default=None, max_length=255)
    email: str | None = Field(default=None, max_length=255)
    user_uuid: UUID
    enabled: bool
    role: Literal["user", "operator"]
    expires_at: datetime
    teams: tuple[_Team, ...]
    projects: tuple[_Project, ...]


class PrivatePlatformCurrentClient:
    """Decode only an owner-authenticated response from a bounded private API."""

    def __init__(self, *, peer: TrustedPlatformPeerPort) -> None:
        if peer is None:
            raise ValueError("authenticated Platform peer required")
        self._peer = peer

    async def resolve(self, *, issuer: str, subject: str) -> ResolvedPlatformUser | None:
        return await self._resolve(issuer=issuer, subject=subject, project_uuid=None)

    async def resolve_project(
        self, *, issuer: str, subject: str, project_uuid: UUID
    ) -> ResolvedPlatformUser | None:
        if not isinstance(project_uuid, UUID) or project_uuid.version != 4:
            raise PlatformMembershipUnavailable("invalid exact Platform Project")
        return await self._resolve(issuer=issuer, subject=subject, project_uuid=project_uuid)

    async def _resolve(
        self, *, issuer: str, subject: str, project_uuid: UUID | None
    ) -> ResolvedPlatformUser | None:
        try:
            connection = await self._peer.current_transport()
            if project_uuid is None:
                delegation = await self._peer.signed_subject_delegation(
                    issuer=issuer, subject=subject
                )
            else:
                delegation = await self._peer.signed_project_delegation(
                    issuer=issuer, subject=subject, project_uuid=project_uuid
                )
        except Exception:
            raise PlatformMembershipUnavailable("private Platform peer unavailable") from None
        now = datetime.now(UTC)
        if (
            not isinstance(connection, VerifiedPlatformServiceTransport)
            or connection.mode not in {"mtls", "unix-peer"}
            or connection.server_audience != "briareus:platform"
            or not isinstance(connection.expires_at, datetime)
            or connection.expires_at.tzinfo is None
            or not now < connection.expires_at <= now + timedelta(seconds=30)
            or not isinstance(delegation, VerifiedPanelDelegation)
            or delegation.issuer != issuer
            or delegation.subject != subject
            or delegation.project_uuid != project_uuid
            or delegation.recipient != "briareus:platform"
            or not isinstance(delegation.expires_at, datetime)
            or delegation.expires_at.tzinfo is None
            or not now < delegation.expires_at <= connection.expires_at
        ):
            raise PlatformMembershipUnavailable("untrusted Platform peer delegation")
        credential = delegation.bearer.get_secret_value()
        if (
            not credential
            or len(credential) > 8192
            or not credential.isascii()
            or any(character.isspace() for character in credential)
        ):
            raise PlatformMembershipUnavailable("invalid private Platform bearer")

        try:
            async with connection.client.stream(
                "POST",
                _OWNER_URL,
                headers={
                    "Authorization": "Bearer " + credential,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json={
                    "issuer": issuer,
                    "subject": subject,
                    **({"project_uuid": str(project_uuid)} if project_uuid is not None else {}),
                },
                follow_redirects=False,
            ) as response:
                if response.status_code == 403:
                    return None
                if response.status_code != 200:
                    raise PlatformMembershipUnavailable("private Platform owner not available")
                if response.headers.get("content-type", "").split(";", 1)[0] != "application/json":
                    raise PlatformMembershipUnavailable("Platform owner returned non-JSON")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > _MAX_JSON_BYTES:
                        raise PlatformMembershipUnavailable("Platform owner response too large")
                    body.extend(chunk)
        except (httpx.HTTPError, TimeoutError):
            raise PlatformMembershipUnavailable("private Platform transport unavailable") from None
        try:
            current = _PlatformCurrent.model_validate_json(body)
        except (ValueError, ValidationError):
            raise PlatformMembershipUnavailable("Platform response invalid") from None
        now = datetime.now(UTC)
        if (
            current.issuer != issuer
            or current.subject != subject
            or not current.enabled
            or current.user_uuid.version != 4
            or current.expires_at.tzinfo is None
            or not now < current.expires_at <= delegation.expires_at
            or len(current.teams) > 100
            or len(current.projects) > 100
            or (
                project_uuid is not None
                and (
                    len(current.projects) != 1
                    or current.projects[0].project_uuid != project_uuid
                    or len(current.teams) > 1
                )
            )
            or any(item.team_uuid.version != 4 for item in current.teams)
            or any(
                item.project_uuid.version != 4 or item.owner_uuid.version != 4
                for item in current.projects
            )
        ):
            raise PlatformMembershipUnavailable("Platform response not current")
        return ResolvedPlatformUser(
            issuer=current.issuer,
            subject=current.subject,
            user_uuid=current.user_uuid,
            enabled=True,
            role=current.role,
            name=current.name,
            email=current.email,
            expires_at=current.expires_at,
            teams=tuple(
                PlatformTeamContext(item.team_uuid, item.owner, item.name)
                for item in current.teams
            ),
            projects=tuple(
                PlatformProjectContext(
                    item.project_uuid,
                    item.owner_kind,
                    item.owner_uuid,
                    item.permissions,
                    item.name,
                )
                for item in current.projects
            ),
        )

"""Authenticated local Platform peer; no database or membership authority in the BFF."""

from __future__ import annotations

import asyncio
import os
import socket
import stat
import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr

from ._platform_current_client import VerifiedPanelDelegation, VerifiedPlatformServiceTransport


class UnixPlatformPeer:
    def __init__(self, *, socket_path: str, signing_key_file: str) -> None:
        self._path = socket_path
        key = serialization.load_pem_private_key(Path(signing_key_file).read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Platform delegation requires an Ed25519 service key")
        self._key = key
        self._client = httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(uds=socket_path),
            timeout=3.0,
            trust_env=False,
            follow_redirects=False,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def current_transport(self) -> VerifiedPlatformServiceTransport:
        await asyncio.to_thread(self._verify_transport)
        return VerifiedPlatformServiceTransport(
            self._client,
            "unix-peer",
            "briareus:platform",
            datetime.now(UTC) + timedelta(seconds=30),
        )

    def _verify_transport(self) -> None:
        metadata = os.stat(self._path)
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != 1000
            or metadata.st_mode & 0o007
        ):
            raise ValueError("Platform socket ownership or permissions invalid")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(2.0)
            probe.connect(self._path)
            _, uid, _ = struct.unpack(
                "3i", probe.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if uid != 1000:
                raise ValueError("Platform process identity mismatch")

    async def signed_subject_delegation(
        self, *, issuer: str, subject: str
    ) -> VerifiedPanelDelegation:
        return self._delegate(issuer, subject, None)

    async def signed_project_delegation(
        self, *, issuer: str, subject: str, project_uuid: UUID
    ) -> VerifiedPanelDelegation:
        return self._delegate(issuer, subject, project_uuid)

    def _delegate(self, issuer: str, subject: str, project: UUID | None) -> VerifiedPanelDelegation:
        now = int(datetime.now(UTC).timestamp())
        expiry = now + 15
        token = jwt.encode(
            {
                "iss": "briareus:control-panel-api",
                "aud": "briareus:platform",
                "sub": subject,
                "rauthy_issuer": issuer,
                "project_uuid": str(project) if project else None,
                "purpose": "platform-current-v1",
                "iat": now,
                "nbf": now,
                "exp": expiry,
                "jti": str(uuid4()),
            },
            self._key,
            algorithm="EdDSA",
            headers={"typ": "briareus-panel-delegation+jwt"},
        )
        return VerifiedPanelDelegation(
            SecretStr(token),
            subject,
            issuer,
            "briareus:platform",
            datetime.fromtimestamp(expiry, UTC),
            project,
        )

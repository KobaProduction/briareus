"""Platform launcher with a peer-authenticated, owner-local Unix API listener.

TCP remains available for diagnostics; private context requests on TCP cannot
provide the kernel peer credentials required by the attestor.
"""

from __future__ import annotations

import asyncio
import os
import socket
import stat
import struct
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import jwt
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Request
from pydantic import SecretStr
from starlette.types import Receive, Scope, Send
from uvicorn.protocols.http.h11_impl import H11Protocol

from common.owner_runtime import VerifiedOwnerIngress

from ._oidc_context_api import (
    PanelContextNotAuthenticated,
    PlatformContextQuery,
    VerifiedPanelContextPeer,
)
from .control_runtime import create_platform_app


class UnixPanelAuthority:
    def __init__(self, socket_path: str, public_key_file: str) -> None:
        self.path = socket_path
        self.public_key_file = public_key_file
        self.key: Ed25519PublicKey | None = None

    def verification_key(self) -> Ed25519PublicKey:
        if self.key is not None:
            return self.key
        key = serialization.load_pem_public_key(Path(self.public_key_file).read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Panel service verification requires Ed25519")
        self.key = key
        return key

    async def verify_running_ingress(self) -> VerifiedOwnerIngress:
        await asyncio.to_thread(self.verification_key)
        info = os.stat(self.path)
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 1000 or info.st_mode & 0o007:
            raise ValueError("Private Platform socket unavailable")
        return VerifiedOwnerIngress(
            "platform", "unix-peer", True, datetime.now(UTC) + timedelta(seconds=15)
        )

    async def verify(
        self, request: Request, query: PlatformContextQuery
    ) -> VerifiedPanelContextPeer:
        if request.scope.get("briareus.unix_peer_uid") != 1001:
            raise PanelContextNotAuthenticated("Control Panel kernel peer required")
        bearer = request.headers.get("authorization", "")
        if not bearer.startswith("Bearer ") or len(bearer) > 8192:
            raise PanelContextNotAuthenticated("Signed Panel delegation required")
        try:
            token = bearer[7:]
            header = jwt.get_unverified_header(token)
            if header.get("typ") != "briareus-panel-delegation+jwt" or header.get("crit"):
                raise ValueError("Invalid delegation header")
            claims = jwt.decode(
                token,
                await asyncio.to_thread(self.verification_key),
                algorithms=["EdDSA"],
                issuer="briareus:control-panel-api",
                audience="briareus:platform",
                options={
                    "require": [
                        "iss",
                        "aud",
                        "sub",
                        "iat",
                        "nbf",
                        "exp",
                        "jti",
                        "purpose",
                        "rauthy_issuer",
                    ]
                },
            )
            project = str(query.project_uuid) if query.project_uuid else None
            if (
                claims["purpose"] != "platform-current-v1"
                or claims["sub"] != query.subject
                or claims["rauthy_issuer"] != query.issuer
                or claims["project_uuid"] != project
                or type(claims["iat"]) is not int
                or type(claims["exp"]) is not int
                or not 0 < claims["exp"] - claims["iat"] <= 15
                or UUID(claims["jti"]).version != 4
            ):
                raise ValueError("Delegation does not bind this exact query")
        except (jwt.PyJWTError, ValueError, TypeError, KeyError):
            raise PanelContextNotAuthenticated("Invalid Panel delegation") from None
        return VerifiedPanelContextPeer(
            "briareus:platform",
            "control-panel-api",
            query.issuer,
            query.subject,
            datetime.fromtimestamp(claims["exp"], UTC),
            query.project_uuid,
        )


class UnixPeerProtocol(H11Protocol):
    def connection_made(self, transport: asyncio.Transport) -> None:
        super().connection_made(transport)
        connection = transport.get_extra_info("socket")
        uid = None
        if connection is not None and connection.family == socket.AF_UNIX:
            _, uid, _ = struct.unpack(
                "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
        application = self.app

        async def with_peer(scope: Scope, receive: Receive, send: Send) -> None:
            scope = {**scope, "briareus.unix_peer_uid": uid}
            await application(scope, receive, send)

        self.app = with_peer


def serve() -> None:
    path = os.environ["PLATFORM_PANEL_SOCKET"]
    authority = UnixPanelAuthority(path, os.environ["PLATFORM_PANEL_VERIFY_KEY_FILE"])
    key_file = os.environ["RAUTHY_USERS_READ_KEY_FILE"]
    managed = os.environ.get("PLATFORM_MANAGED_PEER") == "1"
    key = None if managed else SecretStr(Path(key_file).read_text().strip())
    target = Path(path)
    # Independently deployed API init owns the shared public-key directory.
    # No cross-application depends_on or peer restart is performed here.
    deadline = time.monotonic() + 120
    while not target.parent.is_dir() and time.monotonic() < deadline:
        time.sleep(1)
    if target.exists():
        if not target.is_socket() or target.stat().st_uid != os.getuid():
            raise ValueError("Refusing to replace foreign Platform socket")
        target.unlink()
    unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        unix.bind(path)
        os.chmod(path, 0o660)
        unix.listen(128)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(("0.0.0.0", 8000))
        tcp.listen(128)
        app = create_platform_app(
            trusted_ingress=authority,
            panel_attestor=authority,
            users_read_api_key=key,
            users_read_key_file=key_file if managed else None,
        )
        uvicorn.Server(
            uvicorn.Config(app, http=UnixPeerProtocol, proxy_headers=False, access_log=False)
        ).run(sockets=[unix, tcp])
    finally:
        unix.close()
        tcp.close()


def main() -> None:
    if os.environ.get("PLATFORM_PANEL_SOCKET"):
        serve()
    else:
        uvicorn.run("projects.control_runtime:app", host="0.0.0.0", port=8000, proxy_headers=False)


if __name__ == "__main__":
    main()

"""Explicit owner-operated first-user enrollment; never exposed over HTTP.

Run with an offline operator key and --approve. The key is not mounted into
the running BFF or Platform service. Existing Platform data is never replaced.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import SecretStr

from common.owner_migrations import verify_owner
from common.platform_db import OwnerDatabaseSettings, PlatformDatabase

from ._rauthy_first_operator import FirstOperatorBootstrap, VerifiedFirstOperatorApproval
from ._rauthy_user_status import (
    _PUBLIC_ISSUER,
    CurrentRauthyUserStatusReader,
    FixedRauthyUsersTransport,
)

ISSUER = _PUBLIC_ISSUER


class OperatorApproval:
    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self.key = public_key

    async def verify(self, evidence: object) -> VerifiedFirstOperatorApproval:
        claims = jwt.decode(
            evidence,
            self.key,
            algorithms=["EdDSA"],
            issuer="briareus:offline-operator",
            audience="briareus:platform:first-operator",
            options={
                "require": [
                    "iss",
                    "aud",
                    "iat",
                    "exp",
                    "subject",
                    "user",
                    "project",
                    "operation",
                    "provider_admin_verified",
                    "owner_approved",
                ]
            },
        )
        if (
            claims["owner_approved"] is not True
            or claims["provider_admin_verified"] is not True
            or not 0 < claims["exp"] - claims["iat"] <= 30
        ):
            raise ValueError("Explicit current operator approval required")
        return VerifiedFirstOperatorApproval(
            UUID(claims["operation"]),
            UUID(claims["user"]),
            ISSUER,
            claims["subject"],
            "briareus:platform:first-operator",
            True,
            True,
            UUID(claims["project"]),
            claims["project_name"],
            datetime.fromtimestamp(claims["exp"], UTC),
        )


async def enroll(args: argparse.Namespace) -> None:
    material = await asyncio.to_thread(Path(args.operator_key).read_bytes)
    private = serialization.load_pem_private_key(material, password=None)
    if not args.approve or not isinstance(private, Ed25519PrivateKey):
        raise ValueError("Offline Ed25519 key and explicit --approve required")
    credential = await asyncio.to_thread(Path(os.environ["RAUTHY_USERS_READ_KEY_FILE"]).read_text)
    provider = FixedRauthyUsersTransport(users_read_api_key=SecretStr(credential.strip()))
    user = await provider.read_user(subject=args.subject)
    if user.status != 200:
        raise ValueError("Cannot verify existing Rauthy administrator")
    record = json.loads(user.body)
    roles = record.get("roles")
    if (
        record.get("id") != args.subject
        or record.get("enabled") is not True
        or not isinstance(roles, list)
        or "rauthy_admin" not in roles
    ):
        raise ValueError("Existing active Rauthy administrator required")
    now = int(datetime.now(UTC).timestamp())
    claims = {
        "iss": "briareus:offline-operator",
        "aud": "briareus:platform:first-operator",
        "iat": now,
        "exp": now + 25,
        "operation": str(uuid4()),
        "user": str(uuid4()),
        "project": str(uuid4()),
        "subject": args.subject,
        "project_name": args.project_name,
        "owner_approved": True,
        "provider_admin_verified": True,
    }
    evidence = jwt.encode(claims, private, algorithm="EdDSA")
    db = PlatformDatabase(OwnerDatabaseSettings(owner="platform"))
    try:
        await verify_owner(db, OwnerDatabaseSettings(owner="platform"))
        result = await FirstOperatorBootstrap(
            database=db,
            authority=OperatorApproval(private.public_key()),
            rauthy_status=CurrentRauthyUserStatusReader(private_transport=provider),
        ).enroll_once(signed_evidence=evidence)
        print(
            json.dumps(
                {
                    "user_uuid": str(result.user_id),
                    "project_uuid": claims["project"],
                    "role": result.role,
                }
            )
        )
    finally:
        await db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--project-name", default="Local workspace")
    parser.add_argument("--operator-key", required=True)
    parser.add_argument("--approve", action="store_true")
    asyncio.run(enroll(parser.parse_args()))


if __name__ == "__main__":
    main()

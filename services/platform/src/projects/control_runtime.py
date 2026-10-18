"""Platform owner: real, private Rauthy/SQL membership when trust is injected.

The default app has NO signer, privileged provider key or Project authority,
and remains unavailable/503. A trusted service launcher may supply
authenticated mTLS/Unix ingress, current signed actor attestors and only a
protected Users:read key. This lifecycle opens a Platform-ONLY read pool
AFTER the owner migration/schema verification, never a second DB owner.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import SecretStr

from common.owner_migrations import verify_owner
from common.owner_runtime import OwnerIngressVerifier, create_owner_app
from common.platform_db import OwnerDatabaseSettings, PlatformDatabase

from ._oidc_access_project_api import TrustedAccessProjectAttestor, oidc_access_project_router
from ._oidc_context_api import TrustedPanelContextAttestor, current_platform_context_router
from ._oidc_membership_projection import PlatformOidcMembershipProjection
from ._rauthy_user_status import platform_user_membership_with_rauthy


def create_platform_app(
    *,
    trusted_ingress: OwnerIngressVerifier | None = None,
    membership: PlatformOidcMembershipProjection | None = None,
    panel_attestor: TrustedPanelContextAttestor | None = None,
    access_attestor: TrustedAccessProjectAttestor | None = None,
    users_read_api_key: SecretStr | None = None,
    users_read_key_file: str | None = None,
    test_only_local_rauthy_ca_pem: str | None = None,
) -> FastAPI:
    if test_only_local_rauthy_ca_pem is not None and users_read_api_key is None:
        raise ValueError("disposable Rauthy status needs independently scoped local Users:read")
    if users_read_api_key is not None and users_read_key_file is not None:
        raise ValueError("Provider key sources are mutually exclusive")
    if (users_read_api_key is not None or users_read_key_file is not None) and (
        membership is not None
        or trusted_ingress is None
        or (panel_attestor is None and access_attestor is None)
    ):
        raise ValueError(
            "scoped Rauthy User reader requires exactly one trusted Platform source "
            "and authenticated private ingress/actor attestor"
        )

    app = create_owner_app("platform", trusted_ingress=trusted_ingress)
    owner_lifespan = app.router.lifespan_context
    # Never expose even an injected verified member-source before the owning
    # Platform schema and private ingress have passed startup verification.
    current_membership: PlatformOidcMembershipProjection | None = None

    @asynccontextmanager
    async def platform_membership_lifespan(current_app: FastAPI) -> AsyncIterator[None]:
        nonlocal current_membership
        # No independent SQL/issuer request before the owner migration and
        # authenticated ingress have succeeded. Failing any step aborts
        # startup instead of leaving a half-enabled current User endpoint.
        async with owner_lifespan(current_app):
            if users_read_api_key is None and users_read_key_file is None:
                current_membership = membership if trusted_ingress is not None else None
                try:
                    yield
                finally:
                    current_membership = None
                return
            settings = OwnerDatabaseSettings(owner="platform")
            reader_database = PlatformDatabase(settings)
            try:
                await verify_owner(reader_database, settings)
                current_membership = platform_user_membership_with_rauthy(
                    database=reader_database,
                    users_read_api_key=users_read_api_key,
                    users_read_key_file=users_read_key_file,
                    test_only_local_ca_pem=test_only_local_rauthy_ca_pem,
                )
                yield
            finally:
                current_membership = None
                await reader_database.close()

    app.router.lifespan_context = platform_membership_lifespan

    def verified_current_membership() -> PlatformOidcMembershipProjection | None:
        return current_membership

    app.include_router(
        current_platform_context_router(
            projection=membership,
            resolve_projection=verified_current_membership,
            attestor=panel_attestor if trusted_ingress is not None else None,
        )
    )
    app.include_router(
        oidc_access_project_router(
            projection=membership,
            resolve_projection=verified_current_membership,
            attestor=access_attestor if trusted_ingress is not None else None,
        )
    )
    return app


app = create_platform_app()

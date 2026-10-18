"""Fixed Dev and explicitly selected loopback realms; no request overrides."""

from __future__ import annotations

import os

# A deployment-owned opt-in selects one exact loopback realm. Browser Host,
# Origin and request data can never select another provider or destination.
LOCAL_RUNTIME = os.environ.get("BRIAREUS_LOCAL_TESTING") == "1"
PUBLIC_ORIGIN = "https://127.0.0.1" if LOCAL_RUNTIME else "https://briareus.koba-nexus.ru"
PUBLIC_HOST = PUBLIC_ORIGIN.removeprefix("https://")
BROWSER_ORIGIN = "http://127.0.0.1" if LOCAL_RUNTIME else PUBLIC_ORIGIN


def browser_callback_uri(origin: str) -> str:
    # Native login consumes the provider redirect server-side; the browser
    # stays on HTTP loopback. Provider discovery/code redemption retain TLS.
    from ._api_paths import REGISTERED_RAUTHY_CALLBACK_PATH

    return (PUBLIC_ORIGIN if LOCAL_RUNTIME else origin) + REGISTERED_RAUTHY_CALLBACK_PATH


LOCAL_TEST_ORIGIN = "https://127.0.0.1:18446"
LOCAL_TEST_HOST = "127.0.0.1:18446"
LOCAL_RAUTHY_ISSUER = "https://localhost:18444/auth/v1"
LOCAL_RAUTHY_CLIENT = "briareus-local-panel"


def validate_fixed_local_origin(test_origin: str | None) -> None:
    if test_origin not in (None, LOCAL_TEST_ORIGIN):
        raise ValueError("untrusted OIDC test-only browser origin")


def resolve_browser_origin(
    *, test_origin: str | None, provider_issuer: str, provider_client: str
) -> str:
    if test_origin is None:
        if LOCAL_RUNTIME and (
            provider_issuer != PUBLIC_ORIGIN + "/auth/v1"
            or provider_client != "briareus-control-panel"
        ):
            raise ValueError("local deployment requires the exact loopback provider")
        return BROWSER_ORIGIN
    if (
        test_origin == LOCAL_TEST_ORIGIN
        and provider_issuer == LOCAL_RAUTHY_ISSUER
        and provider_client == LOCAL_RAUTHY_CLIENT
    ):
        return LOCAL_TEST_ORIGIN
    raise ValueError("untrusted OIDC browser callback origin override")


def local_browser_host(test_origin: str | None) -> str | None:
    validate_fixed_local_origin(test_origin)
    return LOCAL_TEST_HOST if test_origin is not None else (PUBLIC_HOST if LOCAL_RUNTIME else None)


def validate_files_resource_intent(
    *, issuer: str, client_id: str, resource_audience: str | None
) -> None:
    """Only an explicitly configured first-Files audience in its original realm.

    This does not register the resource or prove provider consent. No request
    parameter may choose a provider, callback or a different Hand resource.
    """
    if resource_audience is None:
        return
    allowed = {
        (LOCAL_RAUTHY_ISSUER, LOCAL_RAUTHY_CLIENT, LOCAL_TEST_ORIGIN + "/hands/files/mcp"),
        (PUBLIC_ORIGIN + "/auth/v1", "briareus-control-panel", PUBLIC_ORIGIN + "/hands/files/mcp"),
    }
    if (issuer.rstrip("/"), client_id, resource_audience) not in allowed:
        raise ValueError("Files resource intent does not match the approved issuer/client")

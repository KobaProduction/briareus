"""Preserve loopback issuer/TLS identity across the local Docker network.

127.0.0.1 belongs to the browser host, whereas each container has its own
loopback. Only in the explicit local deployment, connect that exact issuer
to its Compose TLS service while still verifying the certificate for the IP.
"""

import ssl

import httpx

from ._oidc_origin_policy import LOCAL_RUNTIME


class LocalProviderTransport(httpx.AsyncHTTPTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if (
            request.url.scheme != "https"
            or request.url.host != "127.0.0.1"
            or request.url.port not in (None, 443)
        ):
            raise httpx.ConnectError("Local provider destination rejected", request=request)
        request.extensions["sni_hostname"] = "127.0.0.1"
        original_url = request.url
        request.url = request.url.copy_with(host="local-tls")
        try:
            return await super().handle_async_request(request)
        finally:
            request.url = original_url


def provider_http_client(
    *,
    verify: ssl.SSLContext | bool = True,
    timeout: float = 5.0,
    follow_redirects: bool = False,
    trust_env: bool = False,
) -> httpx.AsyncClient:
    if not LOCAL_RUNTIME:
        return httpx.AsyncClient(
            verify=verify,
            timeout=timeout,
            follow_redirects=follow_redirects,
            trust_env=trust_env,
        )
    transport = LocalProviderTransport(verify=verify, trust_env=False)
    return httpx.AsyncClient(
        verify=verify,
        timeout=timeout,
        follow_redirects=follow_redirects,
        trust_env=trust_env,
        transport=transport,
    )

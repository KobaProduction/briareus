"""Loopback deployment keeps provider TLS and rejects other destinations."""

import unittest
from unittest.mock import patch

import httpx
from control_panel_api import _oidc_origin_policy as origins
from control_panel_api._local_provider_transport import LocalProviderTransport


class LocalProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_loopback_connects_to_compose_with_ip_tls_identity(self) -> None:
        request = httpx.Request("GET", "https://127.0.0.1/auth/v1/oidc/certs")

        async def send(_transport: object, outgoing: httpx.Request) -> httpx.Response:
            self.assertEqual(outgoing.url.host, "local-tls")
            self.assertEqual(outgoing.headers["host"], "127.0.0.1")
            self.assertEqual(outgoing.extensions["sni_hostname"], "127.0.0.1")
            return httpx.Response(200)

        async with LocalProviderTransport() as transport:
            with patch.object(httpx.AsyncHTTPTransport, "handle_async_request", send):
                await transport.handle_async_request(request)
        self.assertEqual(request.url.host, "127.0.0.1")

    async def test_rejects_other_hosts_ports_and_plaintext_provider(self) -> None:
        async with LocalProviderTransport() as transport:
            for url in ("https://example.com/", "https://127.0.0.1:8443/", "http://127.0.0.1/"):
                with self.subTest(url=url), self.assertRaises(httpx.ConnectError):
                    await transport.handle_async_request(httpx.Request("GET", url))

    async def test_local_http_browser_is_bound_to_exact_https_provider(self) -> None:
        with patch.multiple(
            origins,
            LOCAL_RUNTIME=True,
            PUBLIC_ORIGIN="https://127.0.0.1",
            PUBLIC_HOST="127.0.0.1",
            BROWSER_ORIGIN="http://127.0.0.1",
        ):
            self.assertEqual(
                origins.resolve_browser_origin(
                    test_origin=None,
                    provider_issuer="https://127.0.0.1/auth/v1",
                    provider_client="briareus-control-panel",
                ),
                "http://127.0.0.1",
            )
            self.assertEqual(
                origins.browser_callback_uri("http://127.0.0.1"),
                "https://127.0.0.1/api/auth/oidc/callback",
            )
            self.assertEqual(origins.local_browser_host(None), "127.0.0.1")
            with self.assertRaises(ValueError):
                origins.resolve_browser_origin(
                    test_origin=None,
                    provider_issuer="https://foreign.example/auth/v1",
                    provider_client="client",
                )

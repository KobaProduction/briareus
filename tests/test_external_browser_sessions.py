from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastmcp import FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.providers.proxy import FastMCPProxy

from common.runtime_policy_contracts import BrowserRuntimePolicy
from modules.web.external_browser_proxy import (
    ExternalBrowserProxyRuntime,
    _PersistentPlaywrightProxyClient,
)


class _FakeLease:
    def __init__(
        self, *, failed_stage: str = "", tabs_error: bool = False,
        approval_gate: asyncio.Event | None = None,
    ) -> None:
        self.failed_stage = failed_stage
        self.tabs_error = tabs_error
        self.policy = BrowserRuntimePolicy()
        self.connected = True
        self.connect_count = 1
        self.last_activity_at = "2026-10-12T00:00:00Z"
        self.tab_calls = 0
        self.approval_gate = approval_gate
        self.shutdown_count = 0

    async def shutdown(self) -> None:
        self.shutdown_count += 1

    async def acquire(self) -> _FakeLease:
        if self.failed_stage == "mcp_initialize":
            raise TimeoutError("PRIVATE-SID-NOT-FOR-LOGGING")
        return self

    async def __aenter__(self) -> _FakeLease:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def list_tools(self) -> list[object]:
        if self.failed_stage == "tools_list":
            raise ConnectionError("PRIVATE-AUTH-HEADER")
        return ["browser_tabs"]

    async def call_tool(self, name: str, arguments: object, **_kwargs: object) -> object:
        assert name == "browser_tabs" and arguments == {"action": "list"}
        self.tab_calls += 1
        if self.approval_gate is not None:
            await self.approval_gate.wait()
        if self.failed_stage == "tabs_list":
            raise TimeoutError("PRIVATE-BROWSER-URL")
        return SimpleNamespace(is_error=self.tabs_error)


class ExternalBrowserSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = BrowserRuntimePolicy(
            external_enabled=True, external_mcp_url="http://localhost:8931/mcp"
        )

    def runtime(self, lease: _FakeLease | None = None) -> ExternalBrowserProxyRuntime:
        async def policy() -> BrowserRuntimePolicy:
            return self.policy

        runtime = ExternalBrowserProxyRuntime(policy)
        if lease is not None:
            lease.policy = self.policy
            runtime._client = lease  # type: ignore[assignment]
            runtime._client_policy = self.policy
        return runtime

    def test_disconnected_external_is_silent_during_internal_discovery(self) -> None:
        async def scenario() -> None:
            runtime = self.runtime()
            parent = FastMCP("internal-browser")
            parent.mount(runtime.server, namespace="external")
            with patch("fastmcp.server.providers.aggregate.logger.warning") as warnings:
                self.assertEqual(list(await parent.list_tools()), [])
                self.assertEqual(list(await parent.list_resources()), [])
                self.assertEqual(list(await parent.list_prompts()), [])
                self.assertIsNone(await parent.get_tool("external_browser_tabs"))
            warnings.assert_not_called()
        asyncio.run(scenario())

    def test_verified_external_session_exposes_proxy_again(self) -> None:
        async def scenario() -> None:
            runtime = self.runtime(_FakeLease())
            runtime._tab_probe_state = "responded"
            with patch.object(
                FastMCPProxy, "list_tools", new_callable=unittest.mock.AsyncMock
            ) as tools:
                tools.return_value = []
                self.assertEqual(await runtime.server.list_tools(), [])
                tools.assert_awaited_once()
        asyncio.run(scenario())

    def test_status_does_not_create_upstream_session(self) -> None:
        status = asyncio.run(self.runtime().status())
        self.assertFalse(status["connected"])
        self.assertEqual(status["other_client_sessions"], "not_observable")
        self.assertEqual(status["tab_access_state"], "not_checked")
        self.assertIsNone(status["browser_ready"])
        self.assertEqual(status["grant_state"], "unverified")

    def test_successful_tab_probe_not_equivalent_to_grant(self) -> None:
        async def scenario() -> None:
            lease = _FakeLease()
            runtime = self.runtime(lease)
            pending = await runtime.connect()
            self.assertIsNone(pending["ok"])
            self.assertTrue(pending["connecting"])
            assert runtime._connect_task is not None
            await runtime._connect_task
            result = await runtime.status()
            self.assertTrue(result["browser_ready"])
            self.assertEqual(result["connection_state"], "tab_list_responded")
            self.assertEqual(result["grant_state"], "unverified")
            self.assertEqual(lease.tab_calls, 1)
            self.assertEqual(result["tool_count"], 1)
            self.assertFalse(result["connecting"])
            self.assertEqual((await runtime.connect())["ok"], True)
            self.assertEqual(lease.tab_calls, 1)
        asyncio.run(scenario())

    def test_tabs_error_is_explicit_not_false_success(self) -> None:
        async def scenario() -> None:
            runtime = self.runtime(_FakeLease(tabs_error=True))
            await runtime.connect()
            assert runtime._connect_task is not None
            await runtime._connect_task
            status = await runtime.status()
            self.assertEqual(status["connection_state"], "tab_check_failed")
            self.assertEqual(status["last_error"]["code"], "BROWSER_TABS_FAILED")
            self.assertEqual(status["last_error"]["stage"], "tabs_list")
            self.assertTrue(status["connected"])
        asyncio.run(scenario())

    def test_staged_failures_are_actionable_without_secrets(self) -> None:
        async def scenario(stage: str, expected: str) -> None:
            runtime = self.runtime(_FakeLease(failed_stage=stage))
            await runtime.connect()
            assert runtime._connect_task is not None
            await runtime._connect_task
            status = await runtime.status()
            error = status["last_error"]
            self.assertEqual(error["stage"], stage)
            self.assertEqual(error["code"], expected)
            self.assertTrue(error["next_action"])
            self.assertNotIn("PRIVATE", str(error))
            self.assertNotIn("PRIVATE", str(status))
        for stage, expected in [
            ("mcp_initialize", "UPSTREAM_TIMEOUT"),
            ("tools_list", "UPSTREAM_UNREACHABLE"),
            ("tabs_list", "UPSTREAM_TIMEOUT"),
        ]:
            with self.subTest(stage=stage):
                asyncio.run(scenario(stage, expected))

    def test_pending_approval_is_reused_and_disconnect_cancels(self) -> None:
        async def scenario() -> None:
            gate = asyncio.Event()
            lease = _FakeLease(approval_gate=gate)
            runtime = self.runtime(lease)
            first = await runtime.connect()
            self.assertIsNone(first["ok"])
            await asyncio.sleep(0)
            self.assertEqual(lease.tab_calls, 1)
            second = await runtime.connect()
            self.assertIsNone(second["ok"])
            self.assertEqual(lease.tab_calls, 1)
            self.assertEqual((await runtime.status())["phase"], "tabs_list")
            self.assertEqual((await runtime.disconnect())["ok"], True)
            self.assertEqual(lease.shutdown_count, 1)
            self.assertEqual((await runtime.status())["connection_state"], "proxy_disconnected")
            self.assertIsNone(runtime._connect_task)
        asyncio.run(scenario())

    def test_approval_can_complete_after_initiating_request(self) -> None:
        async def scenario() -> None:
            gate = asyncio.Event()
            runtime = self.runtime(_FakeLease(approval_gate=gate))
            self.assertTrue((await runtime.connect())["connecting"])
            await asyncio.sleep(0)
            self.assertTrue((await runtime.status())["connecting"])
            gate.set()
            assert runtime._connect_task is not None
            await runtime._connect_task
            self.assertEqual((await runtime.status())["phase"], "tab_list_responded")
            self.assertTrue((await runtime.status())["browser_ready"])
        asyncio.run(scenario())

    def test_policy_change_cancels_only_the_old_proxy_probe(self) -> None:
        async def scenario() -> None:
            gate = asyncio.Event()
            lease = _FakeLease(approval_gate=gate)
            runtime = self.runtime(lease)
            await runtime.connect()
            await asyncio.sleep(0)
            self.assertEqual(lease.tab_calls, 1)
            self.policy = BrowserRuntimePolicy(
                external_enabled=True, external_mcp_url="http://localhost:8932/mcp",
            )
            replacement = await runtime._ensure_client()
            self.assertIsInstance(replacement, _PersistentPlaywrightProxyClient)
            self.assertEqual(lease.shutdown_count, 1)
            self.assertIsNone(runtime._connect_task)
            self.assertEqual((await runtime.status())["tab_access_state"], "not_checked")
        asyncio.run(scenario())

    def test_http_error_is_stage_scoped(self) -> None:
        error = RuntimeError("PRIVATE-SID")
        error.response = SimpleNamespace(status_code=404)  # type: ignore[attr-defined]
        diagnostic = ExternalBrowserProxyRuntime._diagnose("tools_list", error)
        self.assertEqual(diagnostic["http_status"], 404)
        self.assertEqual(diagnostic["stage"], "tools_list")
        self.assertNotIn("PRIVATE", str(diagnostic))

    def test_default_http_host_is_not_overridden(self) -> None:
        with patch(
            "modules.web.external_browser_proxy.StreamableHttpTransport",
            wraps=StreamableHttpTransport,
        ) as transport:
            _PersistentPlaywrightProxyClient(self.policy)
        transport.assert_called_once_with(self.policy.external_mcp_url)


if __name__ == "__main__":
    unittest.main()

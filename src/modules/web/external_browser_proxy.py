from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from types import TracebackType
from typing import Any
from urllib.parse import urlsplit

from fastmcp import FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.prompts import Prompt
from fastmcp.resources import Resource, ResourceTemplate
from fastmcp.server.providers.proxy import FastMCPProxy, ProxyClient
from fastmcp.tools import Tool
from fastmcp.utilities.versions import VersionSpec

from common.models import JsonObject
from common.runtime_policy_contracts import BrowserRuntimePolicy

logger = logging.getLogger("mcp_bridge.web.external_browser")

PolicyProvider = Callable[[], Awaitable[BrowserRuntimePolicy]]


class _PersistentPlaywrightProxyClient(ProxyClient[StreamableHttpTransport]):
    """One serialized persistent Playwright MCP session for the selected endpoint."""

    def __init__(self, policy: BrowserRuntimePolicy) -> None:
        self.policy = policy
        # Let the HTTP client construct Host (including non-default ports).
        transport = StreamableHttpTransport(policy.external_mcp_url)
        super().__init__(
            transport,
            timeout=float(policy.call_timeout_seconds),
            mode="auto",
            name="koba-external-playwright-upstream",
            cache=True,
        )
        self._lease_lock = asyncio.Lock()
        self._persistent_hold = False
        self._idle_task: asyncio.Task[None] | None = None
        self.connect_count = 0
        self.last_activity_at = ""

    @property
    def connected(self) -> bool:
        task = self._session_state.session_task
        return bool(self._persistent_hold and task is not None and not task.done())

    def _cancel_idle_task(self) -> None:
        task = self._idle_task
        self._idle_task = None
        if task is not None and not task.done():
            task.cancel()

    def _touch(self) -> None:
        self.last_activity_at = datetime.now(UTC).isoformat()

    def _schedule_idle_disconnect(self) -> None:
        self._cancel_idle_task()
        if not self.policy.auto_disconnect_enabled or not self.connected:
            return
        self._idle_task = asyncio.create_task(
            self._idle_disconnect(),
            name="external-browser-idle-disconnect",
        )

    async def _idle_disconnect(self) -> None:
        try:
            await asyncio.sleep(float(self.policy.idle_timeout_seconds))
            async with self._lease_lock:
                if self._persistent_hold:
                    await super()._disconnect(force=True)
                    self._persistent_hold = False
                    logger.info(
                        "External Playwright MCP session auto-disconnected after %ss idle",
                        self.policy.idle_timeout_seconds,
                    )
        except asyncio.CancelledError:
            raise
        finally:
            self._idle_task = None

    async def acquire(self) -> _PersistentPlaywrightProxyClient:
        await self._lease_lock.acquire()
        self._cancel_idle_task()
        return self

    async def __aenter__(self) -> _PersistentPlaywrightProxyClient:
        try:
            task = self._session_state.session_task
            if self._persistent_hold and task is not None and task.done():
                await super()._disconnect(force=True)
                self._persistent_hold = False
            new_session = not self._persistent_hold
            if new_session:
                await super()._connect()  # type: ignore[no-untyped-call]
                self._persistent_hold = True
                self.connect_count += 1
                logger.info("External Playwright MCP session connected")
            try:
                await super()._connect()  # type: ignore[no-untyped-call]
            except BaseException:
                if new_session:
                    await super()._disconnect(force=True)
                    self._persistent_hold = False
                raise
            self._touch()
            return self
        except BaseException:
            if self._lease_lock.locked():
                self._lease_lock.release()
            raise

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        try:
            await super()._disconnect()
            self._touch()
        finally:
            self._lease_lock.release()
            self._schedule_idle_disconnect()

    async def shutdown(self) -> None:
        self._cancel_idle_task()
        async with self._lease_lock:
            if self._persistent_hold:
                await super()._disconnect(force=True)
                self._persistent_hold = False
                logger.info("External Playwright MCP session disconnected")


class _OptionalExternalMCP(FastMCPProxy):
    """Hide an intentionally disconnected upstream from routine MCP discovery."""

    def __init__(self, *, ready: Callable[[], bool], **kwargs: object) -> None:
        self._ready = ready
        super().__init__(**kwargs)

    async def list_tools(self, *, run_middleware: bool = True) -> list[Tool]:
        if not self._ready():
            return []
        return list(await super().list_tools(run_middleware=run_middleware))

    async def get_tool(
        self, name: str, version: VersionSpec | None = None
    ) -> Tool | None:
        if not self._ready():
            return None
        return await super().get_tool(name, version)

    async def list_resources(self, *, run_middleware: bool = True) -> list[Resource]:
        if not self._ready():
            return []
        return list(await super().list_resources(run_middleware=run_middleware))

    async def list_resource_templates(
        self, *, run_middleware: bool = True
    ) -> list[ResourceTemplate]:
        if not self._ready():
            return []
        return list(await super().list_resource_templates(run_middleware=run_middleware))

    async def list_prompts(self, *, run_middleware: bool = True) -> list[Prompt]:
        if not self._ready():
            return []
        return list(await super().list_prompts(run_middleware=run_middleware))

    async def get_resource(
        self, uri: str, version: VersionSpec | None = None
    ) -> Resource | None:
        if not self._ready():
            return None
        return await super().get_resource(uri, version)

    async def get_resource_template(
        self, uri: str, version: VersionSpec | None = None
    ) -> ResourceTemplate | None:
        if not self._ready():
            return None
        return await super().get_resource_template(uri, version)

    async def get_prompt(
        self, name: str, version: VersionSpec | None = None
    ) -> Prompt | None:
        if not self._ready():
            return None
        return await super().get_prompt(name, version)


class ExternalBrowserProxyRuntime:
    """Dynamic proxy to the official Playwright MCP configured by Admin API policy."""

    def __init__(self, policy_provider: PolicyProvider) -> None:
        self._policy_provider = policy_provider
        self._client: _PersistentPlaywrightProxyClient | None = None
        self._client_policy: BrowserRuntimePolicy | None = None
        self._state_lock = asyncio.Lock()
        self._tab_probe_state = "not_checked"
        self._tab_probe_at = ""
        self._last_error: JsonObject | None = None
        self._connect_task: asyncio.Task[None] | None = None
        self._connection_phase = "idle"
        self._tool_count: int | None = None

        async def client_factory() -> ProxyClient[StreamableHttpTransport]:
            # Component discovery must never dial an unconnected external MCP.
            # Otherwise the remote timeout delays listing *internal* Chromium
            # tools whenever External Browser is enabled but unreachable.
            client = self._client
            if (
                client is None
                or not client.connected
                or self._tab_probe_state != "responded"
            ):
                raise RuntimeError(
                    "External Playwright MCP is not connected; use browser_external_connect"
                )
            return await client.acquire()

        self.server: FastMCP[Any] = _OptionalExternalMCP(
            ready=lambda: bool(
                self._client is not None
                and self._client.connected
                and self._tab_probe_state == "responded"
            ),
            client_factory=client_factory,
            name="external-playwright-upstream",
            provider_error_strategy="warn",
            identity="upstream",
            lifespan=self._lifespan,
        )

    async def _policy(self) -> BrowserRuntimePolicy:
        return await self._policy_provider()

    async def _ensure_client(self) -> _PersistentPlaywrightProxyClient:
        policy = await self._policy()
        if not policy.external_enabled:
            raise RuntimeError("external browser is disabled in Admin settings")
        async with self._state_lock:
            if self._client is not None and self._client_policy != policy:
                task = self._connect_task
                if task is not None and not task.done():
                    task.cancel()
                    with suppress(asyncio.CancelledError):
                        await task
                self._connect_task = None
                await self._client.shutdown()
                self._connection_phase = "idle"
                self._tool_count = None
                self._tab_probe_state = "not_checked"
                self._tab_probe_at = ""
                self._last_error = None
                self._client = None
                self._client_policy = None
            if self._client is None:
                self._client = _PersistentPlaywrightProxyClient(policy)
                self._client_policy = policy
            return self._client

    @staticmethod
    def _origin(url: str) -> str:
        if not url:
            return ""
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port is not None else ""
        return f"{parts.scheme}://{host}{port}"

    @staticmethod
    def _diagnose(stage: str, error: Exception) -> JsonObject:
        """Return safe, actionable diagnostics, never exception text or session credentials."""
        name = type(error).__name__
        response = getattr(error, "response", None)
        http_status = getattr(response, "status_code", None)
        if isinstance(error, (TimeoutError, asyncio.TimeoutError)) or "Timeout" in name:
            code, description, action, retryable = (
                "UPSTREAM_TIMEOUT",
                "The external Playwright MCP did not finish the requested stage in time.",
                ("Check the MCP server, browser prompt and network; "
                 "retry the same session rather than starting another."),
                True,
            )
        elif "ConnectError" in name or "Connection" in name or isinstance(error, OSError):
            code, description, action, retryable = (
                "UPSTREAM_UNREACHABLE",
                "The configured Playwright MCP endpoint could not be reached.",
                ("Start external Playwright MCP and verify the "
                 "configured HTTP address and port."),
                True,
            )
        elif isinstance(http_status, int):
            code, description, action, retryable = (
                "UPSTREAM_HTTP_ERROR",
                f"The Playwright MCP server returned HTTP {http_status} during {stage}.",
                (
                    "Verify the Streamable HTTP MCP endpoint and protocol. "
                    "If a session expired, reconnect deliberately; "
                    "do not reset Chrome."
                ),
                http_status >= 500,
            )
        else:
            code, description, action, retryable = (
                "UPSTREAM_PROTOCOL_ERROR",
                f"The Playwright MCP {stage} stage failed ({name}).",
                ("Inspect upstream MCP logs for this stage; "
                 "verify protocol compatibility."),
                False,
            )
        return {
            "code": code,
            "stage": stage,
            "message": description,
            "next_action": action,
            "retryable": retryable,
            **({"http_status": http_status} if isinstance(http_status, int) else {}),
        }

    async def status(self) -> JsonObject:
        policy = await self._policy()
        client = self._client if self._client_policy == policy else None
        connected = bool(client is not None and client.connected)
        if not policy.external_enabled:
            state = "disabled"
        elif not connected:
            state = "proxy_disconnected"
        elif self._tab_probe_state == "responded":
            state = "tab_list_responded"
        elif self._tab_probe_state == "failed":
            state = "tab_check_failed"
        else:
            state = "proxy_connected_unverified"
        pending = self._connect_task is not None and not self._connect_task.done()
        phase = (
            "disabled" if not policy.external_enabled
            else "not_configured" if not policy.external_mcp_url
            else self._connection_phase if pending
            else state
        )
        return {
            "phase": phase,
            "connecting": pending,
            "tool_count": self._tool_count,
            "configured": bool(policy.external_mcp_url),
            "enabled": policy.external_enabled,
            "provider": "playwright-mcp",
            "namespace": "external",
            "endpoint_origin": self._origin(policy.external_mcp_url),
            # Compatibility: this covers only the Koba Web-owned MCP session.
            "connected": connected,
            "proxy_connected": connected,
            "connection_state": state,
            "session_scope": "koba_web_proxy_only",
            "other_client_sessions": "not_observable",
            "grant_state": "unverified",  # A tab-list response is not a CDP/extension grant.
            "tab_access_state": (
                self._tab_probe_state if connected else
                "stale" if self._tab_probe_state == "responded" else "not_checked"
            ),
            "browser_ready": (
                self._tab_probe_state == "responded" if connected and
                self._tab_probe_state != "not_checked" else None
            ),
            "last_successful_tab_probe_at": self._tab_probe_at,
            "last_error": self._last_error,
            "next_action": (
                ("External browser access is being checked. Approve or deny the "
                 "existing Chrome prompt; do not reconnect.")
                if pending else
                self._last_error["next_action"] if self._last_error else
                ("Use Connect to check Web-owned tabs; "
                "other clients' approved sessions are not listed.")
                if not connected else
                ("Web-owned session is connected. Tab and debugger "
                "permissions must be checked separately.")
            ),
            "session_connect_count": client.connect_count if client is not None else 0,
            "last_activity_at": client.last_activity_at if client is not None else "",
            "call_timeout_seconds": policy.call_timeout_seconds,
            "auto_disconnect_enabled": policy.auto_disconnect_enabled,
            "idle_timeout_seconds": policy.idle_timeout_seconds,
            "profile_dir_name": policy.profile_dir_name,
            "extension_token_configured": policy.extension_token_configured,
        }

    async def _check_tabs(self, client: _PersistentPlaywrightProxyClient) -> None:
        # An operator approval may outlive the management HTTP request.
        stage = "mcp_initialize"
        try:
            lease = await client.acquire()
            async with lease:
                stage = "tools_list"
                self._connection_phase = stage
                tools = await lease.list_tools()
                self._tool_count = len(tools)
                stage = "tabs_list"
                self._connection_phase = stage
                tabs = await lease.call_tool(
                    "browser_tabs", {"action": "list"},
                    timeout=float(client.policy.call_timeout_seconds),
                    raise_on_error=False,
                )
                if tabs.is_error:
                    self._tab_probe_state = "failed"
                    self._last_error = {
                        "code": "BROWSER_TABS_FAILED",
                        "stage": stage,
                        "message": "Playwright MCP could not list permitted tabs.",
                        "next_action": (
                            "Inspect the existing Chrome prompt and upstream MCP logs. "
                            "Do not treat this as revocation or open another session."
                        ),
                        "retryable": False,
                    }
                    self._connection_phase = "failed"
                    return
        except asyncio.CancelledError:
            self._connection_phase = "idle"
            raise
        except Exception as error:
            self._last_error = self._diagnose(stage, error)
            self._tab_probe_state = "failed" if stage == "tabs_list" else "not_checked"
            self._connection_phase = "failed"
            logger.warning(
                "External browser connection failed: stage=%s type=%s",
                stage, type(error).__name__,
            )
            return
        self._last_error = None
        self._tab_probe_state = "responded"
        self._tab_probe_at = datetime.now(UTC).isoformat()
        self._connection_phase = "ready"

    async def connect(self) -> JsonObject:
        # A repeated Connect while approval is pending reuses the same task.
        async with self._state_lock:
            pending = self._connect_task is not None and not self._connect_task.done()
        if pending:
            return {**await self.status(), "ok": None}

        try:
            client = await self._ensure_client()
        except Exception as error:
            self._last_error = {
                "code": "CONFIGURATION_UNAVAILABLE",
                "stage": "configuration",
                "message": "External browser configuration is unavailable or disabled.",
                "next_action": "Check External Browser settings before connecting.",
                "retryable": False,
            }
            logger.warning("External browser configuration failed: type=%s", type(error).__name__)
            self._connection_phase = "failed"
            return {**await self.status(), "ok": False}

        async with self._state_lock:
            if (self._connect_task is None or self._connect_task.done()) and not (
                client.connected and self._tab_probe_state == "responded"
            ):
                self._last_error = None
                self._tab_probe_state = "not_checked"
                self._tool_count = None
                self._connection_phase = "mcp_initialize"
                self._connect_task = asyncio.create_task(
                    self._check_tabs(client), name="external-browser-tab-probe",
                )
        result = await self.status()
        return {**result, "ok": None if result["connecting"] else bool(result["browser_ready"])}

    async def disconnect(self) -> JsonObject:
        async with self._state_lock:
            task = self._connect_task
            if task is not None and not task.done():
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
            self._connect_task = None
            client = self._client
            self._client = None
            self._client_policy = None
            if client is not None:
                await client.shutdown()
            self._tab_probe_state = "not_checked"
            self._tab_probe_at = ""
            self._last_error = None
            self._tool_count = None
            self._connection_phase = "idle"
        return {**await self.status(), "ok": True}

    async def reset(self) -> JsonObject:
        await self.disconnect()
        policy = await self._policy()
        if not policy.external_enabled:
            return {**await self.status(), "ok": False}
        return await self.connect()

    @asynccontextmanager
    async def _lifespan(self, _server: FastMCP[Any]) -> AsyncIterator[None]:
        try:
            yield
        finally:
            with suppress(Exception):
                await self.disconnect()

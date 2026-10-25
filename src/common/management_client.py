from __future__ import annotations

import http.client
import json
import ssl
import urllib.parse

from opentelemetry import trace

from .account_contracts import (
    AccountList,
    GitHubAuthenticatedReaderSync,
    InvocationEvent,
    InvocationEventBatch,
    ResolvedAccount,
)
from .cache import CacheBackend, CacheKeys, SharedCache
from .http_transport import HttpTransportError, PooledHttpTransport
from .models import JsonObject, json_loads, json_object
from .oauth_session_contracts import OAuthSessionEvent
from .runtime_policy_contracts import (
    BrowserLauncherPolicy,
    BrowserRuntimePolicy,
    GitHubRuntimePolicy,
    GitLabRuntimePolicy,
    McpRuntimePolicy,
    TerminalRuntimePolicy,
)
from .settings import ManagementClientSettings, ValkeySettings


class ManagementClientError(RuntimeError):
    pass


_TRACER = trace.get_tracer("mcp-bridge.management-client")


class ManagementClient:
    def __init__(
        self,
        settings: ManagementClientSettings,
        *,
        cache: CacheBackend | None = None,
        cache_settings: ValkeySettings | None = None,
    ) -> None:
        self.url = settings.url.rstrip("/")
        self.service_token = settings.service_token
        self.timeout_seconds = settings.timeout_seconds
        if not self.url:
            raise ValueError("MANAGEMENT_URL is required")
        self.cache_settings = cache_settings or ValkeySettings()
        self.cache = cache or SharedCache(self.cache_settings)
        self.cache_keys = CacheKeys(self.cache)
        parsed = urllib.parse.urlsplit(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("MANAGEMENT_URL must be an absolute HTTP(S) URL")
        self._scheme = parsed.scheme
        self._hostname = parsed.hostname
        self._port = parsed.port
        self._base_path = parsed.path.rstrip("/")
        self._transport = PooledHttpTransport(
            self._new_connection,
            max_connections=8,
            acquire_timeout=self.timeout_seconds,
            span_name="management.http",
        )

    def _new_connection(self) -> http.client.HTTPConnection:
        if self._scheme == "https":
            return http.client.HTTPSConnection(
                self._hostname,
                self._port,
                timeout=self.timeout_seconds,
                context=ssl.create_default_context(),
            )
        return http.client.HTTPConnection(
            self._hostname,
            self._port,
            timeout=self.timeout_seconds,
        )

    def _target(self, path: str, query: dict[str, str] | None = None) -> str:
        if not path.startswith("/"):
            raise ValueError("management path must start with /")
        target = self._base_path + path
        if query:
            target += "?" + urllib.parse.urlencode(query)
        return target

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        payload: JsonObject | None = None,
        expect_body: bool = True,
        fresh_connection: bool = False,
    ) -> JsonObject:
        body = None
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.service_token}",
            "User-Agent": "mcp-bridge",
        }
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        normalized_method = method.upper()
        try:
            response = self._transport.request(
                normalized_method,
                self._target(path, query),
                body=body,
                headers=headers,
                reconnect_retries=1 if normalized_method in {"GET", "HEAD"} else 0,
                fresh_connection=fresh_connection,
            )
        except HttpTransportError as exc:
            raise ManagementClientError(f"management transport error: {exc}") from exc
        if response.status >= 400:
            detail = response.body[:2048].decode("utf-8", "replace")
            raise ManagementClientError(f"management HTTP {response.status}: {detail}")
        if not expect_body or not response.body:
            return {}
        return json_object(
            json_loads(response.body, context="management response"),
            context="management response",
        )

    def list_accounts(
        self,
        *,
        provider: str | None = None,
    ) -> AccountList:
        provider_key = (provider or "").strip().casefold()
        cache_key = self.cache_keys.account_list(provider_key)
        cached = self.cache.get_json(cache_key)
        if isinstance(cached, dict):
            return AccountList.model_validate(cached)

        query: dict[str, str] = {}
        if provider:
            query["provider"] = provider
        data = self._request("GET", "/internal/accounts", query=query)
        result = AccountList.model_validate(data)
        self.cache.set_json(
            cache_key,
            result.to_json(),
            ttl_seconds=self.cache_settings.account_list_ttl_seconds,
        )
        return result

    def resolve_account(
        self,
        selector: str,
        *,
        provider: str,
    ) -> ResolvedAccount:
        value = selector.strip()
        if not value:
            raise ValueError("account_id is required")
        provider_key = provider.strip().casefold()
        cache_key = self.cache_keys.account(provider_key, value)
        cached = self.cache.get_json(cache_key)
        if isinstance(cached, dict):
            return ResolvedAccount.model_validate(cached)

        query = {"provider": provider}
        path = "/internal/accounts/" + urllib.parse.quote(value, safe="") + "/resolve"
        try:
            data = self._request("GET", path, query=query)
        except ManagementClientError as exc:
            if "management HTTP 404:" not in str(exc):
                raise
            accounts = self.list_accounts(provider=provider)
            aliases = sorted(account.alias for account in accounts.accounts if account.alias)
            hint = f"; use stable account alias instead: {', '.join(aliases)}" if aliases else ""
            raise ManagementClientError(
                f"{provider} account selector not found: {value}{hint}"
            ) from exc

        account = ResolvedAccount.model_validate(data)
        payload = account.model_dump(mode="json")
        selectors = {value.casefold(), account.id.casefold(), account.alias.casefold()}
        for resolved_selector in selectors:
            self.cache.set_json(
                self.cache_keys.account(provider_key, resolved_selector),
                payload,
                ttl_seconds=self.cache_settings.account_ttl_seconds,
            )
        return account

    def sync_github_authenticated_reader(self, token: str, *, login: str) -> JsonObject:
        payload = GitHubAuthenticatedReaderSync(token=token, login=login)
        result = self._request(
            "PUT",
            "/internal/accounts/github/authenticated-reader",
            payload=json_object(
                payload.model_dump(mode="json"),
                context="GitHub authenticated reader sync",
            ),
        )
        self.cache.delete(
            self.cache_keys.account_list("github"),
            self.cache_keys.account("github", "authenticated"),
        )
        return result

    def record_invocation(self, event: InvocationEvent) -> None:
        self.record_invocations([event])

    def record_invocations(self, events: list[InvocationEvent]) -> None:
        if not events:
            return
        batch = InvocationEventBatch(events=events)
        trace.get_current_span().set_attribute("audit.batch.size", len(events))
        self._request(
            "POST",
            "/internal/events/batch",
            payload=json_object(batch.model_dump(mode="json"), context="invocation event batch"),
            expect_body=False,
            fresh_connection=True,
        )

    def terminal_runtime_policy(self) -> TerminalRuntimePolicy:
        cache_key = self.cache_keys.terminal_policy()
        cached = self.cache.get_json(cache_key)
        if isinstance(cached, dict):
            return TerminalRuntimePolicy.model_validate(cached)
        data = self._request("GET", "/internal/runtime-settings/terminal")
        result = TerminalRuntimePolicy.model_validate(data)
        self.cache.set_json(
            cache_key,
            result.to_json(),
            ttl_seconds=self.cache_settings.policy_ttl_seconds,
        )
        return result

    def mcp_runtime_policy(self) -> McpRuntimePolicy:
        cache_key = self.cache_keys.mcp_policy()
        cached = self.cache.get_json(cache_key)
        if isinstance(cached, dict):
            return McpRuntimePolicy.model_validate(cached)
        data = self._request("GET", "/internal/runtime-settings/mcp")
        result = McpRuntimePolicy.model_validate(data)
        self.cache.set_json(
            cache_key,
            result.to_json(),
            ttl_seconds=self.cache_settings.policy_ttl_seconds,
        )
        return result

    def github_runtime_policy(self) -> GitHubRuntimePolicy:
        cache_key = self.cache_keys.github_policy()
        cached = self.cache.get_json(cache_key)
        if isinstance(cached, dict):
            return GitHubRuntimePolicy.model_validate(cached)
        data = self._request("GET", "/internal/runtime-settings/github")
        result = GitHubRuntimePolicy.model_validate(data)
        self.cache.set_json(
            cache_key,
            result.to_json(),
            ttl_seconds=self.cache_settings.policy_ttl_seconds,
        )
        return result

    def gitlab_runtime_policy(self) -> GitLabRuntimePolicy:
        cache_key = self.cache_keys.gitlab_policy()
        cached = self.cache.get_json(cache_key)
        if isinstance(cached, dict):
            return GitLabRuntimePolicy.model_validate(cached)
        data = self._request("GET", "/internal/runtime-settings/gitlab")
        result = GitLabRuntimePolicy.model_validate(data)
        self.cache.set_json(
            cache_key,
            result.to_json(),
            ttl_seconds=self.cache_settings.policy_ttl_seconds,
        )
        return result


    def browser_runtime_policy(self) -> BrowserRuntimePolicy:
        cache_key = self.cache_keys.browser_policy()
        cached = self.cache.get_json(cache_key)
        if isinstance(cached, dict):
            return BrowserRuntimePolicy.model_validate(cached)
        data = self._request("GET", "/internal/runtime-settings/browser")
        result = BrowserRuntimePolicy.model_validate(data)
        self.cache.set_json(
            cache_key,
            result.to_json(),
            ttl_seconds=self.cache_settings.policy_ttl_seconds,
        )
        return result

    def browser_launcher_policy(self) -> BrowserLauncherPolicy:
        data = self._request("GET", "/internal/runtime-settings/browser-launcher")
        return BrowserLauncherPolicy.model_validate(data)

    def record_oauth_session(self, event: OAuthSessionEvent) -> None:
        self._request(
            "POST",
            "/internal/oauth-sessions/events",
            payload=json_object(event.model_dump(mode="json"), context="oauth session event"),
            expect_body=False,
        )

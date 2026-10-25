from __future__ import annotations

from os import getenv
from pathlib import Path
from typing import Annotated

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_DEFAULT_PRIVATE_HOSTS = (
    "localhost:*",
    "127.0.0.1:*",
    "[::1]:*",
    "github:*",
    "gitlab:*",
    "files:*",
    "web:*",
    "analysis:*",
    "ghidra:*",
    "terminal:*",
    "observability:*",
    "auth:*",
)
_DEFAULT_PRIVATE_ORIGINS = (
    "http://localhost:*",
    "http://127.0.0.1:*",
    "http://[::1]:*",
)
_DEFAULT_PUBLIC_HOSTS = ("localhost:*", "127.0.0.1:*", "[::1]:*")
_DEFAULT_PUBLIC_ORIGINS = (
    "http://localhost:*",
    "http://127.0.0.1:*",
    "http://[::1]:*",
)


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _tuple_value(value: object) -> object:
    return _csv(value) if isinstance(value, str) else value


def _frozenset_value(value: object) -> object:
    if isinstance(value, str):
        return frozenset(item.casefold() for item in _csv(value))
    if isinstance(value, (set, frozenset, tuple, list)):
        return frozenset(str(item).casefold() for item in value)
    return value


class FrozenSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HttpSurfaceSettings(FrozenSettings):
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]


class ProcessSettings(BaseSettings):
    """Immutable environment-backed configuration created only by composition roots."""

    model_config = SettingsConfigDict(
        extra="ignore",
        case_sensitive=True,
        env_file=None,
        validate_default=True,
        populate_by_name=True,
        frozen=True,
    )


class AsgiServerSettings(ProcessSettings):
    app: str = Field("bridge.server:app", validation_alias="ASGI_APP")
    host: str = Field("0.0.0.0", validation_alias="ASGI_HOST")
    port: int = Field(8000, ge=1, le=65535, validation_alias="ASGI_PORT")
    workers: int = Field(1, ge=1, le=8, validation_alias="ASGI_WORKERS")
    forwarded_allow_ips: str = Field(
        "127.0.0.1",
        validation_alias="ASGI_FORWARDED_ALLOW_IPS",
    )

    @field_validator("app", "host", "forwarded_allow_ips", mode="before")
    @classmethod
    def _strip_values(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


class PrivateRuntimeSettings(ProcessSettings):
    allowed_hosts: Annotated[tuple[str, ...], NoDecode] = Field(
        _DEFAULT_PRIVATE_HOSTS,
        validation_alias="PRIVATE_MCP_ALLOWED_HOSTS",
    )
    allowed_origins: Annotated[tuple[str, ...], NoDecode] = Field(
        _DEFAULT_PRIVATE_ORIGINS,
        validation_alias="PRIVATE_MCP_ALLOWED_ORIGINS",
    )

    @field_validator("allowed_hosts", "allowed_origins", mode="before")
    @classmethod
    def _parse_csv(cls, value: object) -> object:
        return _tuple_value(value)

    @property
    def http(self) -> HttpSurfaceSettings:
        return HttpSurfaceSettings(
            allowed_hosts=self.allowed_hosts,
            allowed_origins=self.allowed_origins,
        )


class ValkeySettings(ProcessSettings):
    url: str = Field("redis://valkey:6379/0", validation_alias="VALKEY_URL")
    namespace: str = Field("mcp-bridge:v1", validation_alias="VALKEY_NAMESPACE")
    socket_connect_timeout_seconds: float = Field(
        0.15,
        ge=0.01,
        le=5.0,
        validation_alias="VALKEY_CONNECT_TIMEOUT_SECONDS",
    )
    socket_timeout_seconds: float = Field(
        0.25,
        ge=0.01,
        le=5.0,
        validation_alias="VALKEY_SOCKET_TIMEOUT_SECONDS",
    )
    failure_backoff_seconds: float = Field(
        5.0,
        ge=0.1,
        le=60.0,
        validation_alias="VALKEY_FAILURE_BACKOFF_SECONDS",
    )
    account_ttl_seconds: int = Field(
        120, ge=1, le=3600, validation_alias="VALKEY_ACCOUNT_TTL_SECONDS"
    )
    account_list_ttl_seconds: int = Field(
        30, ge=1, le=600, validation_alias="VALKEY_ACCOUNT_LIST_TTL_SECONDS"
    )
    policy_ttl_seconds: int = Field(30, ge=1, le=600, validation_alias="VALKEY_POLICY_TTL_SECONDS")
    management_config_ttl_seconds: int = Field(
        30,
        ge=1,
        le=600,
        validation_alias="VALKEY_MANAGEMENT_CONFIG_TTL_SECONDS",
    )

    @field_validator("url", "namespace", mode="before")
    @classmethod
    def _strip_cache_strings(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


class BridgeSettings(ProcessSettings):
    github_url: str = Field("http://github:8000/mcp", validation_alias="GITHUB_URL")
    gitlab_url: str = Field("http://gitlab:8000/mcp", validation_alias="GITLAB_URL")
    files_url: str = Field("http://files:8000/mcp", validation_alias="FILES_URL")
    web_url: str = Field("http://web:8000/mcp", validation_alias="WEB_URL")
    analysis_url: str = Field(
        "http://analysis:8000/mcp",
        validation_alias="ANALYSIS_URL",
    )
    ghidra_url: str = Field(
        "http://ghidra:8000/mcp",
        validation_alias="GHIDRA_URL",
    )
    terminal_url: str = Field(
        "http://terminal:8000/mcp",
        validation_alias="TERMINAL_URL",
    )
    observability_url: str = Field(
        "http://observability:8000/mcp",
        validation_alias="OBSERVABILITY_URL",
    )
    build_sha: str = Field(
        "unknown",
        validation_alias=AliasChoices("BUILD_SHA", "SOURCE_COMMIT"),
    )
    build_time: str = Field("unknown", validation_alias="BUILD_TIME")
    allowed_hosts: Annotated[tuple[str, ...], NoDecode] = Field(
        _DEFAULT_PUBLIC_HOSTS,
        validation_alias="MCP_ALLOWED_HOSTS",
    )
    allowed_origins: Annotated[tuple[str, ...], NoDecode] = Field(
        _DEFAULT_PUBLIC_ORIGINS,
        validation_alias="MCP_ALLOWED_ORIGINS",
    )

    @field_validator(
        "github_url",
        "gitlab_url",
        "files_url",
        "web_url",
        "analysis_url",
        "ghidra_url",
        "terminal_url",
        "observability_url",
        "build_sha",
        "build_time",
        mode="before",
    )
    @classmethod
    def _strip_strings(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("allowed_hosts", "allowed_origins", mode="before")
    @classmethod
    def _parse_csv(cls, value: object) -> object:
        return _tuple_value(value)

    @property
    def backends(self) -> dict[str, str]:
        return {
            "github": self.github_url or "http://github:8000/mcp",
            "gitlab": self.gitlab_url or "http://gitlab:8000/mcp",
            "files": self.files_url or "http://files:8000/mcp",
            "web": self.web_url or "http://web:8000/mcp",
            "analysis": self.analysis_url or "http://analysis:8000/mcp",
            "ghidra": self.ghidra_url or "http://ghidra:8000/mcp",
            "terminal": self.terminal_url or "http://terminal:8000/mcp",
            "observability": self.observability_url or "http://observability:8000/mcp",
        }

    @property
    def http(self) -> HttpSurfaceSettings:
        return HttpSurfaceSettings(
            allowed_hosts=self.allowed_hosts,
            allowed_origins=self.allowed_origins,
        )


class ObservabilitySettings(ProcessSettings):
    service_name: str = Field("mcp-bridge", validation_alias="OTEL_SERVICE_NAME")
    service_version: str = Field("0.1.0", validation_alias="OTEL_SERVICE_VERSION")
    service_instance_id: str = Field("", validation_alias="OTEL_SERVICE_INSTANCE_ID")
    environment: str = Field("production", validation_alias="OTEL_ENVIRONMENT")
    endpoint: str = Field("", validation_alias="OTLP_ENDPOINT")
    bearer_token: str = Field("", validation_alias="OTLP_BEARER_TOKEN")
    resource_attributes: str = Field("", validation_alias="OTEL_RESOURCE_ATTRIBUTES")
    log_level: str = Field("INFO", validation_alias="OTEL_LOG_LEVEL")
    timeout_ms: int = Field(
        10_000,
        ge=100,
        le=120_000,
        validation_alias="OTEL_EXPORTER_OTLP_TIMEOUT",
    )
    metric_export_interval_ms: int = Field(
        30_000,
        ge=1_000,
        le=300_000,
        validation_alias="OTEL_METRIC_EXPORT_INTERVAL",
    )

    @field_validator(
        "service_name",
        "service_version",
        "service_instance_id",
        "environment",
        "endpoint",
        "bearer_token",
        "resource_attributes",
        "log_level",
        mode="before",
    )
    @classmethod
    def _strip_observability_strings(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @property
    def enabled(self) -> bool:
        return bool(self.endpoint)

    @property
    def resolved_instance_id(self) -> str:
        return self.service_instance_id or getenv("HOSTNAME") or "unknown"

    def signal_endpoint(self, signal: str) -> str:
        if signal not in {"logs", "traces", "metrics"}:
            raise ValueError(f"unsupported OTLP signal: {signal}")
        if not self.endpoint:
            return ""
        endpoint = self.endpoint.rstrip("/")
        for suffix in ("/v1/logs", "/v1/traces", "/v1/metrics"):
            if endpoint.endswith(suffix):
                endpoint = endpoint[: -len(suffix)]
                break
        return f"{endpoint}/v1/{signal}"

    @property
    def timeout_seconds(self) -> float:
        return self.timeout_ms / 1000


class AuthServiceSettings(ProcessSettings):
    public_base_url: str = Field("", validation_alias="MCP_PUBLIC_BASE_URL")
    oauth_client_id: str = Field("", validation_alias="GITHUB_OAUTH_CLIENT_ID")
    oauth_client_secret: str = Field("", validation_alias="GITHUB_OAUTH_CLIENT_SECRET")
    oauth_jwt_signing_key: str = Field("", validation_alias="GITHUB_OAUTH_JWT_SIGNING_KEY")
    oauth_allowed_users: Annotated[tuple[str, ...], NoDecode] = Field(
        (),
        validation_alias="GITHUB_OAUTH_ALLOWED_USERS",
    )
    github_token_cache_ttl_seconds: int = Field(
        300,
        ge=0,
        le=3600,
        validation_alias="AUTH_GITHUB_TOKEN_CACHE_TTL_SECONDS",
    )

    @field_validator(
        "public_base_url",
        "oauth_client_id",
        "oauth_client_secret",
        "oauth_jwt_signing_key",
        mode="before",
    )
    @classmethod
    def _strip_strings(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("oauth_allowed_users", mode="before")
    @classmethod
    def _parse_oauth_users(cls, value: object) -> object:
        parsed = _tuple_value(value)
        if isinstance(parsed, tuple):
            return tuple(item.casefold() for item in parsed)
        return parsed

    def validate_bootstrap(self) -> None:
        missing = [
            name
            for name, value in (
                ("MCP_PUBLIC_BASE_URL", self.public_base_url),
                ("GITHUB_OAUTH_CLIENT_ID", self.oauth_client_id),
                ("GITHUB_OAUTH_CLIENT_SECRET", self.oauth_client_secret),
                ("GITHUB_OAUTH_JWT_SIGNING_KEY", self.oauth_jwt_signing_key),
                ("GITHUB_OAUTH_ALLOWED_USERS", self.oauth_allowed_users),
            )
            if not value
        ]
        if missing:
            raise ValueError("missing auth bootstrap settings: " + ", ".join(missing))


class GatewayAuthSettings(ProcessSettings):
    enabled: bool = Field(False, validation_alias="OAUTH_ENABLED")
    public_base_url: str = Field("", validation_alias="MCP_PUBLIC_BASE_URL")
    oauth_jwt_signing_key: str = Field(
        "",
        validation_alias="GITHUB_OAUTH_JWT_SIGNING_KEY",
    )
    oauth_allowed_users: Annotated[tuple[str, ...], NoDecode] = Field(
        (),
        validation_alias="GITHUB_OAUTH_ALLOWED_USERS",
    )

    @field_validator("public_base_url", "oauth_jwt_signing_key", mode="before")
    @classmethod
    def _strip_strings(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("oauth_allowed_users", mode="before")
    @classmethod
    def _parse_oauth_users(cls, value: object) -> object:
        parsed = _tuple_value(value)
        if isinstance(parsed, tuple):
            return tuple(item.casefold() for item in parsed)
        return parsed

    def validate_bootstrap(self) -> None:
        if not self.enabled:
            return
        missing = [
            name
            for name, value in (
                ("GITHUB_OAUTH_JWT_SIGNING_KEY", self.oauth_jwt_signing_key),
                ("GITHUB_OAUTH_ALLOWED_USERS", self.oauth_allowed_users),
                ("MCP_PUBLIC_BASE_URL", self.public_base_url),
            )
            if not value
        ]
        if missing:
            raise ValueError("missing gateway auth settings: " + ", ".join(missing))


class ManagementClientSettings(ProcessSettings):
    url: str = Field("http://management:8000", validation_alias="MANAGEMENT_URL")
    service_token: str = Field("", validation_alias="MANAGEMENT_SERVICE_TOKEN")
    timeout_seconds: float = Field(
        10,
        gt=0,
        le=60,
        validation_alias="MANAGEMENT_TIMEOUT_SECONDS",
    )

    @field_validator("url", "service_token", mode="before")
    @classmethod
    def _strip_values(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


class ManagementSettings(ProcessSettings):
    database_path: Path = Field(
        Path("/management/management.sqlite3"),
        validation_alias="MANAGEMENT_DATABASE_PATH",
    )
    encryption_key: str = Field("", validation_alias="MANAGEMENT_ENCRYPTION_KEY")
    service_token: str = Field("", validation_alias="MANAGEMENT_SERVICE_TOKEN")
    admin_username: str = Field("admin", validation_alias="MANAGEMENT_ADMIN_USERNAME")
    admin_password: str = Field("", validation_alias="MANAGEMENT_ADMIN_PASSWORD")
    session_secret: str = Field("", validation_alias="MANAGEMENT_SESSION_SECRET")
    session_https_only: bool = Field(
        True,
        validation_alias="MANAGEMENT_SESSION_HTTPS_ONLY",
    )
    frontend_telemetry_upstream_url: str = Field(
        "https://telemetry.koba-nexus.ru",
        validation_alias="MANAGEMENT_FRONTEND_TELEMETRY_UPSTREAM_URL",
    )
    frontend_telemetry_bearer_token: str = Field(
        "",
        validation_alias="MANAGEMENT_FRONTEND_TELEMETRY_BEARER_TOKEN",
    )

    @field_validator(
        "encryption_key",
        "service_token",
        "admin_username",
        "admin_password",
        "session_secret",
        "frontend_telemetry_upstream_url",
        "frontend_telemetry_bearer_token",
        mode="before",
    )
    @classmethod
    def _strip_secrets(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("database_path")
    @classmethod
    def _absolute_database_path(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("MANAGEMENT_DATABASE_PATH must be absolute")
        return value.resolve(strict=False)

    @property
    def database_url(self) -> str:
        return f"sqlite:///{self.database_path}"

    def validate_bootstrap(self) -> None:
        missing = [
            name
            for name, value in (
                ("MANAGEMENT_ENCRYPTION_KEY", self.encryption_key),
                ("MANAGEMENT_SERVICE_TOKEN", self.service_token),
                ("MANAGEMENT_ADMIN_USERNAME", self.admin_username),
                ("MANAGEMENT_ADMIN_PASSWORD", self.admin_password),
                ("MANAGEMENT_SESSION_SECRET", self.session_secret),
            )
            if not value
        ]
        if missing:
            raise ValueError("missing management bootstrap settings: " + ", ".join(missing))


class AnalysisSettings(ProcessSettings):
    backend_url: str = Field(
        "http://ghidra:8000/mcp",
        validation_alias="GHIDRA_URL",
    )
    direct_upload_url: str = Field(
        "http://ghidra-mcp:8081/internal/artifacts/upload",
        validation_alias="GHIDRA_DIRECT_UPLOAD_URL",
    )
    direct_upload_timeout_seconds: float = Field(
        300,
        gt=0,
        le=3600,
        validation_alias="GHIDRA_DIRECT_UPLOAD_TIMEOUT_SECONDS",
    )
    schema_cache_ttl_seconds: float = Field(
        30,
        ge=0,
        le=3600,
        validation_alias="ANALYSIS_SCHEMA_CACHE_TTL_SECONDS",
    )

    @field_validator("backend_url", "direct_upload_url", mode="before")
    @classmethod
    def _strip_backend_url(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


class GhidraSettings(ProcessSettings):
    backend_url: str = Field(
        "http://bridge:8081/mcp",
        validation_alias="GHIDRA_MCP_URL",
    )

    @field_validator("backend_url", mode="before")
    @classmethod
    def _strip_backend_url(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


class GitHubPolicySettings(ProcessSettings):
    public_reader_account: str = Field(
        "",
        validation_alias="GITHUB_PUBLIC_READER_ACCOUNT",
    )
    public_allow_anonymous_fallback: bool = Field(
        False,
        validation_alias="GITHUB_PUBLIC_ALLOW_ANONYMOUS_FALLBACK",
    )
    protected_branches: Annotated[frozenset[str], NoDecode] = Field(
        frozenset(),
        validation_alias="GITHUB_AGENT_PROTECTED_BRANCHES",
    )
    required_checks: Annotated[tuple[str, ...], NoDecode] = Field(
        ("test", "docker"),
        validation_alias="GITHUB_AGENT_REQUIRED_CHECKS",
    )
    required_reviewers: Annotated[tuple[str, ...], NoDecode] = Field(
        (),
        validation_alias="GITHUB_AGENT_REQUIRED_REVIEWERS",
    )

    @field_validator("public_reader_account", mode="before")
    @classmethod
    def _strip_public_reader_account(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("protected_branches", mode="before")
    @classmethod
    def _parse_branches(cls, value: object) -> object:
        return _frozenset_value(value)

    @field_validator("required_checks", mode="before")
    @classmethod
    def _parse_checks(cls, value: object) -> object:
        return _tuple_value(value)

    @field_validator("required_reviewers", mode="before")
    @classmethod
    def _parse_reviewers(cls, value: object) -> object:
        parsed = _tuple_value(value)
        if isinstance(parsed, tuple):
            return tuple(item.casefold() for item in parsed)
        return parsed


class GitLabSettings(ProcessSettings):
    protected_branches: Annotated[frozenset[str], NoDecode] = Field(
        frozenset(),
        validation_alias="GITLAB_PROTECTED_BRANCHES",
    )
    registry_cache_ttl_seconds: float = Field(
        60,
        ge=0,
        le=3600,
        validation_alias="GITLAB_REGISTRY_CACHE_TTL_SECONDS",
    )

    @field_validator("protected_branches", mode="before")
    @classmethod
    def _parse_branches(cls, value: object) -> object:
        return _frozenset_value(value)


class FileSettings(ProcessSettings):
    workspace_root: Path = Field(
        Path("/workspace"),
        validation_alias="FILE_WORKSPACE_ROOT",
    )
    upload_max_bytes: int = Field(
        8 * 1024 * 1024 * 1024,
        ge=1024 * 1024,
        le=64 * 1024 * 1024 * 1024,
        validation_alias="FILE_UPLOAD_MAX_BYTES",
    )

    @field_validator("workspace_root")
    @classmethod
    def _absolute_root(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("FILE_WORKSPACE_ROOT must be absolute")
        return value.resolve(strict=False)


class TerminalSettings(ProcessSettings):
    workspace_root: Path = Field(
        Path("/workspace"),
        validation_alias="TERMINAL_WORKSPACE_ROOT",
    )
    home: Path = Field(
        Path("/home/agent"),
        validation_alias="TERMINAL_HOME",
    )
    shell: str = Field("/bin/bash", validation_alias="TERMINAL_SHELL")
    path: str = Field(
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        validation_alias="TERMINAL_PATH",
    )
    lang: str = Field("C.UTF-8", validation_alias="TERMINAL_LANG")
    term: str = Field("xterm-256color", validation_alias="TERMINAL_TERM")
    max_exec_output_bytes: int = Field(
        2 * 1024 * 1024,
        ge=1024,
        le=64 * 1024 * 1024,
        validation_alias="TERMINAL_MAX_EXEC_OUTPUT_BYTES",
    )
    max_job_read_bytes: int = Field(
        1024 * 1024,
        ge=1024,
        le=16 * 1024 * 1024,
        validation_alias="TERMINAL_MAX_JOB_READ_BYTES",
    )
    max_job_log_bytes: int = Field(
        256 * 1024 * 1024,
        ge=1024 * 1024,
        le=8 * 1024 * 1024 * 1024,
        validation_alias="TERMINAL_MAX_JOB_LOG_BYTES",
    )

    @field_validator("workspace_root", "home")
    @classmethod
    def _absolute_terminal_path(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("terminal paths must be absolute")
        return value.resolve(strict=False)

    @field_validator("shell", "path", "lang", "term", mode="before")
    @classmethod
    def _strip_terminal_strings(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


class BrowserSettings(ProcessSettings):
    profile_dir: Path = Field(
        Path("/browser/profile"),
        validation_alias="BROWSER_PROFILE_PATH",
    )
    executable_path: str = Field(
        "/usr/bin/chromium",
        validation_alias="BROWSER_EXECUTABLE_PATH",
    )
    timezone: str = Field("UTC", validation_alias="TZ")
    devtools_mcp_script_path: Path = Field(
        Path(
            "/opt/chrome-devtools-mcp/lib/node_modules/chrome-devtools-mcp/build/src/bin/chrome-devtools-mcp.js"
        ),
        validation_alias="BROWSER_DEVTOOLS_MCP_SCRIPT_PATH",
    )
    timeout_ms: int = Field(30_000, ge=1_000, le=120_000, validation_alias="BROWSER_TIMEOUT_MS")
    max_snapshot_text_chars: int = Field(
        30_000,
        ge=1_000,
        le=200_000,
        validation_alias="BROWSER_MAX_SNAPSHOT_TEXT_CHARS",
    )
    max_snapshot_elements: int = Field(
        250,
        ge=10,
        le=2_000,
        validation_alias="BROWSER_MAX_SNAPSHOT_ELEMENTS",
    )

    @field_validator("profile_dir", "devtools_mcp_script_path")
    @classmethod
    def _absolute_profile_dir(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("browser paths must be absolute")
        return value.resolve(strict=False)

    @field_validator("timezone", mode="before")
    @classmethod
    def _normalize_browser_timezone(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip() or "UTC"
        return value

    @field_validator("executable_path", mode="before")
    @classmethod
    def _strip_executable_path(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


class CurlSettings(ProcessSettings):
    binary: Path | None = Field(None, validation_alias="CURL_BINARY")

    @field_validator("binary", mode="before")
    @classmethod
    def _binary_file(cls, value: object) -> object:
        if value in {None, ""}:
            return None
        path = Path(str(value)).expanduser()
        if not path.is_file():
            raise ValueError("configured curl binary does not point to a file")
        return path

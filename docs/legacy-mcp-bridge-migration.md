# Legacy MCP Bridge: controlled Coolify migration

Deployment source: KobaProduction/briareus, branch legacy-mcp-bridge.
Coolify resource: mcp-bridge on tambov.

## Required external inputs

- OTLP_ENDPOINT: protected/shared collector base URL (do not append /v1/traces).
- OTLP_BEARER_TOKEN: protected/shared secret, not a preformatted header.
  Python constructs the Authorization: Bearer header for logs/traces/metrics.
- Existing Management secret material and OAuth identity remain unchanged.

The Python OTLP exporter no longer consumes OTEL_EXPORTER_OTLP_HEADERS,
old per-signal URLs, or ad hoc Authorization strings in Compose.
Do not deploy until the two new resource variables point to verified
Coolify Shared keys at their existing approved scopes.

## Limits controlled through Coolify

- WEB_MEMORY_LIMIT=1792m; WEB_MEMORY_SWAP_LIMIT=1792m; WEB_SHM_SIZE=1gb.
- ANALYSIS_MEMORY_LIMIT=2g; ANALYSIS_WORKERS=1.
- GHIDRA_MEMORY_LIMIT=2g; GHIDRA_WORKERS=1.
- Existing TERMINAL_MEMORY_LIMIT, TERMINAL_MEMORY_SWAP_LIMIT,
  TERMINAL_CPU_LIMIT and TERMINAL_PIDS_LIMIT remain supported.

Memory values limit Docker cgroups, rather than allocating RAM.
Worker counts govern proxy ASGI processes (1–8), not the separate
native ghidra-mcp application. Preserve defaults until measured.

## Authentication

The current publicly deployed Gateway responds 401 to anonymous
/mcp and /github/mcp, and serves GitHub OAuth metadata. Its auth
container and OAuth signing contract are still live. Do not remove
or disable them until a replacement public authentication gate
has been implemented and accepted.

## Safe rollout

1. Confirm only source branch changes, not any secret values or unrelated services.
2. Verify all required Shared references in Coolify without disclosing values.
3. Switch the existing resource source branch to legacy-mcp-bridge.
4. Roll out once during a maintenance window. Keep Management and
   web-browser named volumes unchanged; no secret rotation.
5. Verify health, unauthenticated 401, authenticated MCP requests,
   Web browser status/pages, Ghidra and Analysis backends, and
   logs/traces/metrics export. Retain rollback commit.

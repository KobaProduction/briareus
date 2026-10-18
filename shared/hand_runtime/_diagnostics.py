"""Real MCP transport with strictly non-authoritative diagnostic tools.

No provider implementation is imported and no executor, credential, workspace,
user data, or authenticated tool is exposed by this transport.
"""

from __future__ import annotations

from collections import Counter

from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import JWTVerifier

from ._effect_auth import EffectAuthorizationMiddleware


def diagnostic_mcp(
    hand: str,
    catalog: dict[str, object],
    *,
    resource_verifier: JWTVerifier | None = None,
) -> FastMCP:
    """Build diagnostic MCP; optional signed resource admission remains closed."""
    mcp = FastMCP(f"briareus-{hand}-diagnostics", auth=resource_verifier)
    if resource_verifier is not None:
        mcp.add_middleware(EffectAuthorizationMiddleware(hand))
    declared_count = int(catalog["declared_tool_count"])
    tools = catalog["declared_tools"]
    assert isinstance(tools, list)
    groups = Counter(
        str(item["module"]).split(".")[1]
        for item in tools
        if isinstance(item, dict) and isinstance(item.get("module"), str)
    )

    @mcp.tool(
        title="Hand runtime status",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
    )
    def hand_status() -> dict[str, object]:
        """Report process-level MCP diagnostics, not tool execution readiness."""
        return {
            "hand": hand,
            "transport": "diagnostic_only",
            "authorization": "not_configured",
            "protected_execution": "disabled",
            "declared_legacy_tool_count": declared_count,
            "registered_diagnostic_tools": 2,
            "ready": False,
        }

    @mcp.tool(
        title="Hand source tool summary",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
    )
    def hand_source_summary() -> dict[str, object]:
        """Summarize copied source declarations without activating them."""
        return {
            "hand": hand,
            "declared_legacy_tool_count": declared_count,
            "source_modules": dict(sorted(groups.items())),
            "source_declarations_are_callable": False,
        }

    if resource_verifier is not None:

        @mcp.tool(
            title="Current Hand permission proof",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        )
        def hand_permission_probe() -> dict[str, object]:
            """No effect: report the current, independently authorized action."""
            return {"hand": hand, "protected_effect": "none", "probe": "authorized"}

    return mcp

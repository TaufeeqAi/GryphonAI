"""FastMCP host adapter — the only module that imports a transport.

Exposes the seven tools as MCP tools that delegate to the transport-agnostic
:class:`ToolExecutionService`. The capability arrives as a JSON string argument
and is passed as bytes to force strict parsing. The host MUST be bound to an
authenticated, non-public transport (stdio / UDS / mTLS); a public bind is
prohibited and refused by deployment configuration, not offered here.
"""

from __future__ import annotations

from typing import Any

from gryphon.tooling.constants import ToolId
from gryphon.tooling.enforcement.service import ToolExecutionService
from gryphon.tooling.execution.aggregate import ToolExecutionResult


def serialize_result(result: ToolExecutionResult) -> dict[str, Any]:
    """Project an execution result into a JSON-safe structured output."""
    return {
        "scan_run_id": result.scan_run_id,
        "execution_id": result.execution_id,
        "tool_id": result.tool_id.value,
        "outcome": result.outcome.value,
        "reason_code": result.reason_code,
        "records": [
            record.model_dump() if hasattr(record, "model_dump") else record
            for record in result.records
        ],
        "per_target": [{"target": t.target, "state": t.state.value} for t in result.per_target],
        "truncated": result.truncated,
        "degraded": result.degraded,
        "audit_event_id": result.audit_event_id,
        "replayed": result.replayed,
    }


def build_tool_host(service: ToolExecutionService, *, name: str = "gryphon-tools") -> Any:
    """Build a FastMCP server exposing the seven capability-gated tools.

    FastMCP is imported lazily so the core package has no transport dependency.
    """
    from fastmcp import FastMCP  # lazy, transport-only

    mcp = FastMCP(name)

    async def _run(tool_id: ToolId, capability: str, target: str, requested_depth: str | None, path: str | None):
        result = await service.execute_with_capability(
            capability.encode("utf-8"), tool_id, target, path=path, requested_depth=requested_depth
        )
        return serialize_result(result)

    @mcp.tool
    async def subfinder_enumerate(capability: str, target: str, requested_depth: str | None = None) -> dict:
        """Passively enumerate subdomains for an authorized domain (capability-gated)."""
        return await _run(ToolId.SUBFINDER, capability, target, requested_depth, None)

    @mcp.tool
    async def httpx_probe(capability: str, target: str, requested_depth: str | None = None) -> dict:
        """Probe an authorized host over HTTP(S) (capability-gated, egress-contained)."""
        return await _run(ToolId.HTTPX, capability, target, requested_depth, None)

    @mcp.tool
    async def naabu_scan(capability: str, target: str, requested_depth: str | None = None) -> dict:
        """Scan ports on an authorized host (capability-gated, egress-contained)."""
        return await _run(ToolId.NAABU, capability, target, requested_depth, None)

    @mcp.tool
    async def katana_crawl(capability: str, target: str, requested_depth: str | None = None) -> dict:
        """Crawl an authorized web host (capability-gated, egress-contained)."""
        return await _run(ToolId.KATANA, capability, target, requested_depth, None)

    @mcp.tool
    async def dnsx_resolve(capability: str, target: str, requested_depth: str | None = None) -> dict:
        """Resolve DNS records for an authorized domain (capability-gated)."""
        return await _run(ToolId.DNSX, capability, target, requested_depth, None)

    @mcp.tool
    async def tlsx_inspect(capability: str, target: str, requested_depth: str | None = None) -> dict:
        """Inspect TLS configuration of an authorized host (capability-gated)."""
        return await _run(ToolId.TLSX, capability, target, requested_depth, None)

    @mcp.tool
    async def nuclei_scan(capability: str, target: str, requested_depth: str | None = None) -> dict:
        """Run template-based checks against an authorized host (capability-gated,
        host-code templates and out-of-band interaction disabled)."""
        return await _run(ToolId.NUCLEI, capability, target, requested_depth, None)

    return mcp

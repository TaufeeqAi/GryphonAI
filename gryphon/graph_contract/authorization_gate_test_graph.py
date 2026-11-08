"""Minimal compiled LangGraph gate + harmless sentinel (§30.4, INV-001/002/026).

Contract behaviour this graph proves:

    missing/expired/invalid/unknown-key/out-of-scope/excluded/db-fail
        -> DENY/UNKNOWN -> END -> sentinel_count == 0
    valid in-scope token
        -> committed ALLOW -> sentinel_count == 1

The graph consumes a trusted typed result from the Authorization Service and
only ROUTES it; it never re-checks or overrides policy (§12). The sentinel does
no network access, tool invocation or target interaction — it merely records
that the post-commit permit path was reached.
"""

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from gryphon.auth.results import AuthorizedPermit
from gryphon.auth.service import AuthorizationService, ScanAdmissionRequest


class GateState(TypedDict, total=False):
    request: ScanAdmissionRequest
    result: Any
    result_type: str
    scan_run_id: str | None
    sentinel_count: int


def build_gate_graph(service: AuthorizationService) -> Any:
    """Compile the Phase 1 conformance graph bound to ``service``."""

    async def authorization_gate(state: GateState) -> dict[str, Any]:
        result = await service.authorize_scan(state["request"])
        scan_run_id = getattr(result, "scan_run_id", None)
        return {
            "result": result,
            "result_type": type(result).__name__,
            "scan_run_id": scan_run_id,
            "sentinel_count": state.get("sentinel_count", 0),
        }

    async def sentinel(state: GateState) -> dict[str, Any]:
        # Harmless: no network, no tool, no target interaction. Proves the gate's
        # ALLOW control-flow only — NOT production scanner safety (§30.4).
        return {"sentinel_count": state.get("sentinel_count", 0) + 1}

    def route_after_gate(state: GateState) -> str:
        # Only a committed AuthorizedPermit may proceed. Every other outcome
        # (DENY, UNKNOWN, replay receipt) ends the graph.
        return "sentinel" if isinstance(state.get("result"), AuthorizedPermit) else END

    graph = StateGraph(GateState)
    graph.add_node("authorization_gate", authorization_gate)
    graph.add_node("sentinel", sentinel)
    graph.set_entry_point("authorization_gate")
    graph.add_conditional_edges(
        "authorization_gate", route_after_gate, {"sentinel": "sentinel", END: END}
    )
    graph.add_edge("sentinel", END)
    return graph.compile()


async def run_gate(
    compiled_graph: Any, request: ScanAdmissionRequest
) -> tuple[Any, int]:
    """Invoke the compiled graph once; return ``(result, sentinel_count)``."""
    final_state = await compiled_graph.ainvoke(
        {"request": request, "sentinel_count": 0}
    )
    return final_state.get("result"), final_state.get("sentinel_count", 0)

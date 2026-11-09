"""Graph construction — compiled deliberately **without** a checkpointer.

The framework here is a sequencer of node logic and nothing more. Every durable
fact lives in the work ledger, and that is what makes omitting persistence the
right choice rather than a limitation:

* **The gate is re-traversed on every entry.** A checkpointed graph resumes at
  its saved position, which is past the entry node — so the one path that most
  needs an authorization check is the one that skips it. With no checkpoint
  there is no saved position to resume to, and "gate first" becomes "gate
  always" by construction instead of by discipline.
* **Nothing can be pre-seeded.** A writable checkpoint keyed by the scan id is a
  store that decides where the pipeline believes it is. Planting a row that
  claims the pipeline is at the report step would produce a clean report for a
  scan that never ran, with no tool call to leave a trace. There is no such row.
* **A version bump stops being dangerous.** Changing the node set normally
  invalidates saved checkpoints and strands in-flight work — a routine deploy
  destroying running engagements. Here a re-invocation simply enters the new
  graph and re-walks covered ledger steps as no-ops.
* **No runtime DDL, no second driver.** The durable checkpointer would create
  its own tables at startup, which both contradicts migration-owned schema and
  requires a privilege the runtime role should not hold.
* **Authority cannot be persisted.** There is nowhere to persist it to. The
  state schema is closed to primitives, and nothing writes state to disk.

What this costs, stated plainly: no interrupt-based human-in-the-loop pause,
since that feature requires a checkpointer. Nothing in this pipeline needs one.
If a later stage wants operator approval mid-graph, a checkpointer can be
reintroduced as a **pure cache** — affordable precisely because the ledger, not
the checkpoint, is the authority.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from gryphon.orchestration.constants import GRAPH_VERSION, ScanStage
from gryphon.orchestration.nodes.gate import (
    ROUTE_ADMITTED,
    ROUTE_DENIED,
    build_gate_node,
    route_after_gate,
)
from gryphon.orchestration.nodes.report import build_report_node
from gryphon.orchestration.nodes.stage import build_stage_node, steps_for
from gryphon.orchestration.nodes.target_admit import (
    build_target_admit_node,
    route_after_admission,
)
from gryphon.orchestration.runtime import ScanRuntime
from gryphon.orchestration.state import ScanGraphState, assert_state_schema_is_closed

#: Node names. Stable identifiers: the topology version covers changes to them.
NODE_GATE = "authorization_gate"
NODE_RECON = "recon"
NODE_TARGET_ADMIT = "target_admit"
NODE_ENUMERATE = "enumerate"
NODE_FINGERPRINT = "fingerprint"
NODE_SCAN = "scan"
NODE_REPORT = "report"

#: The ordered active pipeline after admission.
_ACTIVE_SEQUENCE: tuple[tuple[str, ScanStage], ...] = (
    (NODE_ENUMERATE, ScanStage.ENUMERATE),
    (NODE_FINGERPRINT, ScanStage.FINGERPRINT),
    (NODE_SCAN, ScanStage.SCAN),
)


def build_graph(runtime: ScanRuntime, *, initiated_by: str) -> StateGraph:
    """Wire the pipeline. Nodes are closures over ``runtime``."""
    # Re-assert the state contract at build time as well as at import: a graph
    # must never be constructed around a state schema that could hold authority.
    assert_state_schema_is_closed()

    graph: StateGraph = StateGraph(ScanGraphState)

    graph.add_node(NODE_GATE, build_gate_node(runtime, initiated_by=initiated_by))
    graph.add_node(NODE_RECON, build_stage_node(runtime, ScanStage.RECON))
    graph.add_node(NODE_TARGET_ADMIT, build_target_admit_node(runtime))
    for node_name, stage in _ACTIVE_SEQUENCE:
        graph.add_node(node_name, build_stage_node(runtime, stage))
    graph.add_node(NODE_REPORT, build_report_node(runtime, initiated_by=initiated_by))

    graph.set_entry_point(NODE_GATE)

    # A denial ends the graph immediately: no side-effecting node is reachable.
    graph.add_conditional_edges(
        NODE_GATE,
        route_after_gate,
        {ROUTE_ADMITTED: NODE_RECON, ROUTE_DENIED: END},
    )
    graph.add_edge(NODE_RECON, NODE_TARGET_ADMIT)

    # Admission can halt for operator review. Active stages are unreachable
    # until discovered targets have been capped and address-attested.
    graph.add_conditional_edges(
        NODE_TARGET_ADMIT,
        route_after_admission,
        {ROUTE_ADMITTED: NODE_ENUMERATE, ROUTE_DENIED: END},
    )
    graph.add_edge(NODE_ENUMERATE, NODE_FINGERPRINT)
    graph.add_edge(NODE_FINGERPRINT, NODE_SCAN)
    graph.add_edge(NODE_SCAN, NODE_REPORT)
    graph.add_edge(NODE_REPORT, END)

    return graph


def compile_graph(runtime: ScanRuntime, *, initiated_by: str) -> Any:
    """Compile the pipeline with **no** checkpointer.

    The absence of a ``checkpointer=`` argument is the load-bearing part of this
    function; see the module docstring.
    """
    return build_graph(runtime, initiated_by=initiated_by).compile()


def topology() -> dict[str, Any]:
    """Describe the compiled topology for readiness checks and tests.

    Exposed so conformance tests assert the real shape rather than a comment,
    and so an operator can see which tool runs in which stage without reading
    the graph code.
    """
    return {
        "graph_version": GRAPH_VERSION,
        "entry_point": NODE_GATE,
        "nodes": [
            NODE_GATE,
            NODE_RECON,
            NODE_TARGET_ADMIT,
            NODE_ENUMERATE,
            NODE_FINGERPRINT,
            NODE_SCAN,
            NODE_REPORT,
        ],
        "stages": {
            stage.value: [
                {"step": spec.step, "tool_id": spec.tool_id.value}
                for spec in steps_for(stage)
            ]
            for stage in (
                ScanStage.RECON,
                ScanStage.ENUMERATE,
                ScanStage.FINGERPRINT,
                ScanStage.SCAN,
            )
        },
        "checkpointer": None,
    }

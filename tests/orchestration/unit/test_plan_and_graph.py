"""Plan construction and compiled-graph conformance.

The step table is data, so these tests assert the real pipeline shape rather
than trusting a comment — including the one correction this layer makes to the
stage/tool assignment it inherited.
"""

from __future__ import annotations

import pytest

from gryphon.constants import ScanDepth
from gryphon.orchestration.constants import (
    ACTIVE_STAGES,
    PLANNED_TOOLS,
    STEP_PLAN,
    PlanItemState,
    ScanStage,
    TargetSource,
)
from gryphon.orchestration.graph import topology
from gryphon.orchestration.nodes.stage import steps_for
from gryphon.orchestration.plan import PlannedTarget, build_plan, targets_for
from gryphon.tooling.constants import ToolId
from tests.orchestration.conftest import SCAN_RUN_ID, SEED_TARGET, TEST_SALT

pytestmark = pytest.mark.unit


# -- the step table -----------------------------------------------------------
def test_every_tool_is_planned_exactly_once() -> None:
    """A tool in the catalog but in no step would never run, silently."""
    assert PLANNED_TOOLS == {t for t in ToolId}
    assigned = [spec.tool_id for spec in STEP_PLAN]
    assert len(assigned) == len(set(assigned))


def test_port_discovery_precedes_the_http_probe() -> None:
    """The ordering correction this layer makes, asserted.

    The inherited stage assignment put the HTTP probe a whole stage *before*
    the port scan — the consumer of port data running ahead of its producer.
    Reordering costs nothing and removes the need to reorder later.
    """
    order = [spec.tool_id for spec in STEP_PLAN]
    assert order.index(ToolId.NAABU) < order.index(ToolId.HTTPX)


def test_passive_discovery_precedes_every_active_stage() -> None:
    """Nothing active may run before targets have been admitted."""
    for spec in STEP_PLAN:
        if spec.stage in ACTIVE_STAGES:
            assert spec.stage.order > ScanStage.TARGET_ADMIT.order
        else:
            assert spec.stage.order < ScanStage.TARGET_ADMIT.order


def test_active_steps_only_target_admitted_or_derived_hosts() -> None:
    """An active step must never plan straight from raw discovery output."""
    for spec in STEP_PLAN:
        if spec.stage in ACTIVE_STAGES:
            assert spec.target_source in (
                TargetSource.ADMITTED_HOSTS,
                TargetSource.LIVE_HTTP,
            )


def test_item_granularity_defaults_to_one_target_per_execution() -> None:
    """One execution, one target, one identity: the cleanest idempotency unit."""
    assert all(spec.max_targets_per_execution == 1 for spec in STEP_PLAN)


# -- the compiled graph -------------------------------------------------------
def test_graph_is_compiled_without_a_checkpointer() -> None:
    """The load-bearing absence.

    With no persisted position there is nothing to resume *into*, so every
    invocation re-enters at the gate; nothing can be pre-seeded to claim the
    pipeline already finished; and a topology change cannot strand in-flight
    work.
    """
    assert topology()["checkpointer"] is None


def test_the_gate_is_the_entry_point() -> None:
    assert topology()["entry_point"] == "authorization_gate"


def test_graph_stages_match_the_step_table() -> None:
    """The compiled topology and the data table cannot drift apart."""
    stages = topology()["stages"]
    for stage in (ScanStage.RECON, ScanStage.ENUMERATE, ScanStage.FINGERPRINT, ScanStage.SCAN):
        expected = [
            {"step": spec.step, "tool_id": spec.tool_id.value}
            for spec in steps_for(stage)
        ]
        assert stages[stage.value] == expected


def test_compiled_graph_exposes_the_expected_nodes() -> None:
    nodes = topology()["nodes"]
    assert nodes[0] == "authorization_gate"
    assert "target_admit" in nodes
    assert nodes[-1] == "report"
    # Deliberately absent: no inert enrichment or verification node occupies a
    # versioned topology slot. The data model reserves that extension instead.
    assert "enrich" not in nodes and "verify" not in nodes


# -- target resolution --------------------------------------------------------
def test_seed_target_is_planned_for_the_first_step() -> None:
    spec = STEP_PLAN[0]
    targets = targets_for(spec, admitted_target=SEED_TARGET)
    assert [t.canonical_target for t in targets] == [SEED_TARGET]


def test_admitted_hosts_always_include_the_seed() -> None:
    """The authorized target needs no attestation: it is what was granted."""
    spec = next(s for s in STEP_PLAN if s.target_source is TargetSource.ADMITTED_HOSTS)
    targets = targets_for(
        spec,
        admitted_target=SEED_TARGET,
        admitted_hosts=[
            PlannedTarget(canonical_target="a.example.com", provenance={})
        ],
    )
    assert SEED_TARGET in [t.canonical_target for t in targets]


def test_no_live_http_means_an_empty_plan_not_a_gap() -> None:
    """Nothing to crawl is a truthful empty plan, not missing coverage."""
    spec = next(s for s in STEP_PLAN if s.target_source is TargetSource.LIVE_HTTP)
    assert targets_for(spec, admitted_target=SEED_TARGET, evidence=[]) == []


# -- plan construction --------------------------------------------------------
def _build(targets: list[str], *, salt: str = TEST_SALT, generation: int = 1):
    spec = STEP_PLAN[0]
    return build_plan(
        spec,
        scan_run_id=SCAN_RUN_ID,
        targets=[PlannedTarget(canonical_target=t, provenance={}) for t in targets],
        execution_salt=salt,
        policy_version="1",
        effective_depth=ScanDepth.STANDARD,
        plan_generation=generation,
    )


def test_plan_stores_an_identity_per_item() -> None:
    plan = _build(["a.example.com", "b.example.com"])
    assert plan.item_count == 2
    ids = [item["execution_id"] for item in plan.items]
    assert len(set(ids)) == 2
    assert all(len(bytes.fromhex(i)) >= 16 for i in ids)
    assert all(item["state"] == PlanItemState.PLANNED.value for item in plan.items)


def test_rebuilding_the_same_plan_is_byte_identical() -> None:
    """The property a resumed step depends on."""
    first = _build(["a.example.com", "b.example.com"])
    second = _build(["a.example.com", "b.example.com"])
    assert first.plan_digest == second.plan_digest
    assert [i["execution_id"] for i in first.items] == [
        i["execution_id"] for i in second.items
    ]


def test_target_order_changes_identities() -> None:
    """Sequence feeds identity, which is why admitted ordering is stabilized."""
    forward = _build(["a.example.com", "b.example.com"])
    reverse = _build(["b.example.com", "a.example.com"])
    assert forward.plan_digest != reverse.plan_digest


def test_a_different_scan_cannot_reuse_another_scans_identities() -> None:
    """Per-scan salts isolate scans from each other's work queue."""
    plan_a = _build(["a.example.com"])
    plan_b = _build(["a.example.com"], salt="cc" * 32)
    assert plan_a.items[0]["execution_id"] != plan_b.items[0]["execution_id"]


def test_replan_generation_yields_new_identities() -> None:
    """A deliberate replan is new work and must not collide with the old plan."""
    first = _build(["a.example.com"], generation=1)
    second = _build(["a.example.com"], generation=2)
    assert first.plan_digest != second.plan_digest


def test_plan_items_carry_the_request_digest() -> None:
    plan = _build(["a.example.com"])
    assert len(plan.items[0]["request_digest"]) == 64


def test_oversized_plan_is_refused_rather_than_truncated() -> None:
    """Silently dropping planned work would be a coverage lie."""
    from gryphon.orchestration.constants import MAX_PLAN_ITEMS_PER_STEP

    too_many = [f"h{i}.example.com" for i in range(MAX_PLAN_ITEMS_PER_STEP + 1)]
    with pytest.raises(ValueError, match="above the ceiling"):
        _build(too_many)


def test_empty_target_list_builds_an_empty_plan() -> None:
    plan = _build([])
    assert plan.item_count == 0
    assert plan.plan_digest

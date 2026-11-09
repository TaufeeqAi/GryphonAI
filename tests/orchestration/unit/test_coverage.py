"""Coverage: the fold that stops a scan lying about what it did.

The scenario these tests exist for: every call is denied, the graph still
reaches its end, and the scan reports "completed" with zero findings. "Zero
findings" then reads as "clean target" rather than "we never looked". These
assertions make that outcome impossible to express.
"""

from __future__ import annotations

import pytest

from gryphon.orchestration.constants import CoverageClass, PlanItemState, ScanLifecycleState
from gryphon.orchestration.coverage import (
    ClassifiedItem,
    classify,
    fold,
    is_retryable,
    is_saturation,
    item_state_for,
)
from gryphon.orchestration.report import terminal_state_for
from gryphon.tooling.constants import ToolOutcome
from gryphon.tooling.reasons import ToolReasonCode

pytestmark = pytest.mark.unit


def _item(
    state: PlanItemState,
    outcome: ToolOutcome | None = None,
    reason: str | None = None,
    *,
    step: str = "vulnerability_scan",
) -> ClassifiedItem:
    return ClassifiedItem(
        stage="scan", step=step, tool_id="nuclei",
        state=state, outcome=outcome, reason_code=reason,
    )


# -- classification -----------------------------------------------------------
def test_completed_is_covered() -> None:
    assert (
        classify(
            outcome=ToolOutcome.COMPLETED,
            reason_code=ToolReasonCode.COMPLETED.value,
            item_state=PlanItemState.COMPLETED,
        )
        is CoverageClass.COVERED
    )


def test_a_negative_result_is_still_covered() -> None:
    """A reached target with nothing to report is covered, not a gap.

    Without this distinction the coverage signal fires on nearly every real
    scan — and a signal that always fires is indistinguishable from no signal,
    so the gap we actually care about gets lost in the noise.
    """
    covered = classify(
        outcome=ToolOutcome.COMPLETED,
        reason_code=ToolReasonCode.COMPLETED.value,
        item_state=PlanItemState.COMPLETED,
    )
    assert covered is CoverageClass.COVERED


@pytest.mark.parametrize(
    "outcome,reason",
    [
        (ToolOutcome.TIMED_OUT, ToolReasonCode.TOOL_TIMED_OUT.value),
        (ToolOutcome.FAILED, ToolReasonCode.TOOL_FAILED.value),
        (ToolOutcome.DENIED, ToolReasonCode.BUDGET_EXCEEDED.value),
        (ToolOutcome.DENIED, ToolReasonCode.BREAKER_OPEN.value),
        (ToolOutcome.DENIED, ToolReasonCode.EGRESS_UNAVAILABLE.value),
        (ToolOutcome.UNKNOWN, ToolReasonCode.COMMIT_OUTCOME_UNKNOWN.value),
    ],
)
def test_unaccounted_outcomes_are_gaps(outcome: ToolOutcome, reason: str) -> None:
    assert (
        classify(outcome=outcome, reason_code=reason, item_state=PlanItemState.FAILED)
        is CoverageClass.GAP
    )


@pytest.mark.parametrize(
    "reason",
    [
        ToolReasonCode.SCOPE_NO_MATCH.value,
        ToolReasonCode.SCOPE_EXCLUDED.value,
        ToolReasonCode.SCOPE_PROVENANCE_MISMATCH.value,
        ToolReasonCode.RECEIPT_MISMATCH.value,
    ],
)
def test_scope_denial_of_an_admitted_target_is_an_integrity_signal(reason: str) -> None:
    """Admission and the enforcement layer disagreeing is not routine noise.

    Admission only plans targets it believes are in scope. If the enforcement
    layer refuses one on scope grounds, one of the two is wrong — and averaging
    that into a coverage percentage would hide a correctness problem.
    """
    assert (
        classify(
            outcome=ToolOutcome.DENIED, reason_code=reason, item_state=PlanItemState.DENIED
        )
        is CoverageClass.INTEGRITY
    )


def test_excluded_items_are_classified_excluded() -> None:
    assert (
        classify(outcome=None, reason_code=None, item_state=PlanItemState.EXCLUDED)
        is CoverageClass.EXCLUDED
    )


def test_unresolved_possibly_contacted_is_a_gap_not_a_success() -> None:
    assert (
        classify(
            outcome=ToolOutcome.UNKNOWN,
            reason_code="UNRESOLVED_POSSIBLY_CONTACTED",
            item_state=PlanItemState.UNRESOLVED_POSSIBLY_CONTACTED,
        )
        is CoverageClass.GAP
    )


def test_pending_items_are_pending() -> None:
    for state in (PlanItemState.PLANNED, PlanItemState.DISPATCHED):
        assert (
            classify(outcome=None, reason_code=None, item_state=state)
            is CoverageClass.PENDING
        )


# -- retry / saturation policy ------------------------------------------------
def test_policy_denials_are_never_retried() -> None:
    assert not is_retryable(ToolOutcome.DENIED, ToolReasonCode.SCOPE_NO_MATCH.value)


def test_transient_failures_are_retryable() -> None:
    assert is_retryable(ToolOutcome.TIMED_OUT, ToolReasonCode.TOOL_TIMED_OUT.value)


def test_saturation_is_recognized_so_we_stop_asking() -> None:
    assert is_saturation(ToolReasonCode.BREAKER_OPEN.value)
    assert is_saturation(ToolReasonCode.BUDGET_EXCEEDED.value)
    assert not is_saturation(ToolReasonCode.TOOL_FAILED.value)


def test_indeterminate_outcome_stays_non_terminal() -> None:
    """Only the reconciler may give an UNKNOWN its terminal classification."""
    assert item_state_for(ToolOutcome.UNKNOWN, None) is PlanItemState.DISPATCHED


# -- the fold -----------------------------------------------------------------
def test_exclusions_are_not_in_the_denominator() -> None:
    """A target we never undertook to scan is not a gap in coverage."""
    coverage = fold(
        [
            _item(PlanItemState.COMPLETED, ToolOutcome.COMPLETED, "COMPLETED"),
            _item(PlanItemState.EXCLUDED),
        ]
    )
    assert coverage.planned == 2
    assert coverage.denominator == 1
    assert coverage.covered == 1
    assert coverage.covered_fraction == 1.0


def test_gap_reasons_are_histogrammed_by_cause() -> None:
    coverage = fold(
        [
            _item(PlanItemState.FAILED, ToolOutcome.FAILED, "TOOL_FAILED"),
            _item(PlanItemState.FAILED, ToolOutcome.FAILED, "TOOL_FAILED"),
            _item(PlanItemState.TIMED_OUT, ToolOutcome.TIMED_OUT, "TOOL_TIMED_OUT"),
        ]
    )
    assert coverage.gap_reasons == {"TOOL_FAILED": 2, "TOOL_TIMED_OUT": 1}


def test_fold_is_order_independent() -> None:
    items = [
        _item(PlanItemState.COMPLETED, ToolOutcome.COMPLETED, "COMPLETED"),
        _item(PlanItemState.FAILED, ToolOutcome.FAILED, "TOOL_FAILED"),
    ]
    assert fold(items).as_payload() == fold(list(reversed(items))).as_payload()


# -- the terminal decision ----------------------------------------------------
def test_a_fully_denied_scan_is_never_completed() -> None:
    """The headline scenario: nothing ran, so nothing may claim completion."""
    coverage = fold(
        [
            _item(PlanItemState.DENIED, ToolOutcome.DENIED, "BREAKER_OPEN")
            for _ in range(5)
        ]
    )
    state, _ = terminal_state_for(coverage, coverage_failure_floor=0.5)
    assert state is not ScanLifecycleState.COMPLETED
    assert coverage.covered == 0
    assert coverage.covered_fraction == 0.0


def test_full_coverage_completes() -> None:
    coverage = fold(
        [_item(PlanItemState.COMPLETED, ToolOutcome.COMPLETED, "COMPLETED")] * 3
    )
    state, _ = terminal_state_for(coverage, coverage_failure_floor=0.5)
    assert state is ScanLifecycleState.COMPLETED


def test_partial_coverage_above_the_floor_completes_with_gaps() -> None:
    items = [_item(PlanItemState.COMPLETED, ToolOutcome.COMPLETED, "COMPLETED")] * 8
    items += [_item(PlanItemState.FAILED, ToolOutcome.FAILED, "TOOL_FAILED")] * 2
    state, _ = terminal_state_for(fold(items), coverage_failure_floor=0.5)
    assert state is ScanLifecycleState.COMPLETED_WITH_GAPS


def test_coverage_below_the_floor_fails() -> None:
    items = [_item(PlanItemState.COMPLETED, ToolOutcome.COMPLETED, "COMPLETED")] * 2
    items += [_item(PlanItemState.FAILED, ToolOutcome.FAILED, "TOOL_FAILED")] * 8
    state, _ = terminal_state_for(fold(items), coverage_failure_floor=0.5)
    assert state is ScanLifecycleState.FAILED


def test_an_integrity_signal_fails_the_scan_regardless_of_coverage() -> None:
    items = [_item(PlanItemState.COMPLETED, ToolOutcome.COMPLETED, "COMPLETED")] * 99
    items += [_item(PlanItemState.DENIED, ToolOutcome.DENIED, "SCOPE_NO_MATCH")]
    state, reason = terminal_state_for(fold(items), coverage_failure_floor=0.5)
    assert state is ScanLifecycleState.FAILED
    assert reason == "SCOPE_DISAGREEMENT"


def test_nothing_planned_is_a_truthful_completion() -> None:
    """Discovery finding nothing in scope is a result, not a failure."""
    state, _ = terminal_state_for(fold([]), coverage_failure_floor=0.5)
    assert state is ScanLifecycleState.COMPLETED


# -- the reason the terminal state carries ------------------------------------
# A reason code is an instruction to an operator. "Reconcile this" when there is
# nothing to reconcile sends them to a command that reports "examined 0" and
# teaches them to stop reading reason codes.
def test_settled_denials_below_the_floor_do_not_ask_for_reconciliation() -> None:
    items = [
        _item(PlanItemState.DENIED, ToolOutcome.DENIED, "DESTINATION_UNRESOLVABLE")
    ] * 4
    state, reason = terminal_state_for(fold(items), coverage_failure_floor=0.5)
    assert state is ScanLifecycleState.FAILED
    assert reason == "COVERAGE_BELOW_FLOOR"


def test_settled_gaps_above_the_floor_do_not_ask_for_reconciliation() -> None:
    items = [_item(PlanItemState.COMPLETED, ToolOutcome.COMPLETED, "COMPLETED")] * 8
    items += [_item(PlanItemState.DENIED, ToolOutcome.DENIED, "EGRESS_UNAVAILABLE")] * 2
    state, reason = terminal_state_for(fold(items), coverage_failure_floor=0.5)
    assert state is ScanLifecycleState.COMPLETED_WITH_GAPS
    assert reason == "COVERAGE_INCOMPLETE"


def test_a_terminally_unresolved_gap_does_not_ask_for_reconciliation() -> None:
    """Reconciliation already ran and gave up; asking again resolves nothing."""
    items = [_item(PlanItemState.COMPLETED, ToolOutcome.COMPLETED, "COMPLETED")] * 8
    items += [
        _item(
            PlanItemState.UNRESOLVED_POSSIBLY_CONTACTED,
            ToolOutcome.UNKNOWN,
            "UNRESOLVED_POSSIBLY_CONTACTED",
        )
    ] * 2
    coverage = fold(items)
    assert coverage.pending == 0
    state, reason = terminal_state_for(coverage, coverage_failure_floor=0.5)
    assert state is ScanLifecycleState.COMPLETED_WITH_GAPS
    assert reason == "COVERAGE_INCOMPLETE"


def test_a_still_pending_item_asks_for_reconciliation() -> None:
    items = [_item(PlanItemState.COMPLETED, ToolOutcome.COMPLETED, "COMPLETED")] * 8
    items += [_item(PlanItemState.DISPATCHED)] * 2
    coverage = fold(items)
    assert coverage.pending == 2
    _, reason = terminal_state_for(coverage, coverage_failure_floor=0.5)
    assert reason == "RECONCILE_REQUIRED"


def test_the_budget_reason_still_wins_below_the_floor() -> None:
    items = [_item(PlanItemState.DENIED, ToolOutcome.DENIED, "BUDGET_EXCEEDED")] * 4
    _, reason = terminal_state_for(fold(items), coverage_failure_floor=0.5)
    assert reason == "DECISION_BUDGET_EXHAUSTED"

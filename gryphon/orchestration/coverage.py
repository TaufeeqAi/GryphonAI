"""Coverage — the classifier and fold that make "done" mean something.

A per-call outcome taxonomy that is faithful item-by-item still says nothing
about the scan as a whole. Without this module, a scan in which *every* call
was denied walks the graph to the end and terminates "completed", emitting a
schema-valid report with zero findings — and "zero findings" is then
indistinguishable from "we never looked". That is the most expensive confusion
a security product can ship, and it is silent.

So coverage is a first-class, persisted fact, and the terminal state is a
function of it:

    COMPLETED            every planned item is covered
    COMPLETED_WITH_GAPS  finished, gaps enumerated by cause
    FAILED               covered fell below the floor, or integrity is in doubt

The classifier is the load-bearing part, and the rule that earns its keep is
this: **a negative result is a result.** A target that was reached and had
nothing to say is *covered*, not a gap. Without that distinction the signal
fires on every real scan, and a signal that always fires is no signal at all.
Everything here is a pure function over recorded outcomes, so it is unit
testable without a database, a graph or a tool.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Final, Mapping

from gryphon.orchestration.constants import CoverageClass, PlanItemState
from gryphon.tooling.constants import ToolOutcome
from gryphon.tooling.reasons import ToolReasonCode

# -----------------------------------------------------------------------------
# Classification
# -----------------------------------------------------------------------------
#: Denials that mean "the system refused or could not proceed" — a gap in
#: coverage, by cause. These are operational or policy-throttling conditions,
#: not statements about the target.
_GAP_DENIAL_REASONS: Final[frozenset[str]] = frozenset(
    {
        ToolReasonCode.BUDGET_EXCEEDED.value,
        ToolReasonCode.BREAKER_OPEN.value,
        ToolReasonCode.EGRESS_UNAVAILABLE.value,
        ToolReasonCode.DB_UNAVAILABLE.value,
        ToolReasonCode.INTENT_COMMIT_FAILED.value,
        ToolReasonCode.READINESS_FAILED.value,
        ToolReasonCode.DESTINATION_UNRESOLVABLE.value,
        ToolReasonCode.DESTINATION_DENIED.value,
        ToolReasonCode.REDIRECT_ESCAPE.value,
        ToolReasonCode.DESCRIPTOR_MISSING.value,
        ToolReasonCode.INTERNAL_ERROR.value,
        ToolReasonCode.TOOL_UNKNOWN.value,
        ToolReasonCode.ARGS_INVALID.value,
        ToolReasonCode.REQUEST_MALFORMED.value,
        ToolReasonCode.REQUEST_TOO_LARGE.value,
        ToolReasonCode.EXECUTION_ID_INVALID.value,
        ToolReasonCode.DEPTH_INVALID.value,
        ToolReasonCode.DEPTH_EXCEEDED.value,
        ToolReasonCode.TAG_PROHIBITED.value,
        ToolReasonCode.PROTOCOL_PROHIBITED.value,
        ToolReasonCode.OUTPUT_DEGRADED.value,
    }
)

#: Denials that mean the enforcement layer and target admission **disagree**
#: about whether this target was authorized. Admission only ever plans targets
#: it believes are in scope, so a scope refusal is not routine noise: it is
#: evidence that one of the two is wrong, and that must surface as an integrity
#: failure rather than be averaged into a coverage percentage.
_INTEGRITY_DENIAL_REASONS: Final[frozenset[str]] = frozenset(
    {
        ToolReasonCode.SCOPE_NO_MATCH.value,
        ToolReasonCode.SCOPE_EXCLUDED.value,
        ToolReasonCode.SCOPE_INVALID_INPUT.value,
        ToolReasonCode.SCOPE_PROVENANCE_MISMATCH.value,
        ToolReasonCode.RECEIPT_MISSING.value,
        ToolReasonCode.RECEIPT_MISMATCH.value,
    }
)


def classify(
    *,
    outcome: ToolOutcome | None,
    reason_code: str | None,
    item_state: PlanItemState | None = None,
) -> CoverageClass:
    """Classify one recorded plan-item outcome for coverage.

    Pure. Takes only what the ledger records, so it can be exercised directly
    against captured tool outcomes with no infrastructure.
    """
    if item_state is PlanItemState.EXCLUDED:
        return CoverageClass.EXCLUDED
    if item_state is PlanItemState.UNRESOLVED_POSSIBLY_CONTACTED:
        return CoverageClass.GAP
    if item_state in (PlanItemState.PLANNED, PlanItemState.DISPATCHED) or outcome is None:
        return CoverageClass.PENDING

    if outcome is ToolOutcome.COMPLETED:
        # Reached and accounted for. An empty result set is a truthful negative
        # result, not a gap: the target had nothing to report.
        return CoverageClass.COVERED

    if outcome is ToolOutcome.DENIED:
        if reason_code in _INTEGRITY_DENIAL_REASONS:
            return CoverageClass.INTEGRITY
        return CoverageClass.GAP

    # TIMED_OUT, FAILED, UNKNOWN: attempted, not accounted for.
    return CoverageClass.GAP


def item_state_for(outcome: ToolOutcome, reason_code: str | None) -> PlanItemState:
    """Map an enforcement-layer outcome to the persisted plan-item state.

    An indeterminate outcome stays indeterminate here; only the reconciler may
    promote it to its terminal classification, and only after the configured
    window. Nothing in this layer ever maps a non-success outcome to success.
    """
    if outcome is ToolOutcome.COMPLETED:
        return PlanItemState.COMPLETED
    if outcome is ToolOutcome.DENIED:
        return PlanItemState.DENIED
    if outcome is ToolOutcome.TIMED_OUT:
        return PlanItemState.TIMED_OUT
    if outcome is ToolOutcome.FAILED:
        return PlanItemState.FAILED
    # UNKNOWN: a committed intent proves traffic may have occurred. The item is
    # left non-terminal and routed to reconciliation.
    return PlanItemState.DISPATCHED


def is_retryable(outcome: ToolOutcome, reason_code: str | None) -> bool:
    """Whether a bounded retry (reusing the stored identity) is permitted.

    A policy denial is never retryable — retrying it only burns budget and
    floods the append-only audit. Saturation is handled by a cool-down rather
    than a retry, because retrying into an open breaker is how a flapping target
    turns into thousands of signed audit rows.
    """
    if outcome in (ToolOutcome.TIMED_OUT, ToolOutcome.FAILED):
        return reason_code not in _INTEGRITY_DENIAL_REASONS
    return False


def is_saturation(reason_code: str | None) -> bool:
    """Whether a reason code means "stop asking for a while"."""
    return reason_code in {
        ToolReasonCode.BREAKER_OPEN.value,
        ToolReasonCode.BUDGET_EXCEEDED.value,
    }


# -----------------------------------------------------------------------------
# The fold
# -----------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class StepCoverage:
    """Coverage for one planned step."""

    stage: str
    step: str
    tool_id: str
    planned: int
    covered: int
    gap: int
    integrity: int
    excluded: int
    pending: int
    #: Gap counts keyed by the reason code that caused them.
    gap_reasons: Mapping[str, int] = field(default_factory=dict)

    @property
    def denominator(self) -> int:
        """Items that count toward coverage. Exclusions are never in it."""
        return self.planned - self.excluded

    @property
    def covered_fraction(self) -> float:
        """Covered share of the denominator; 1.0 when nothing was planned."""
        return 1.0 if self.denominator <= 0 else self.covered / self.denominator

    @property
    def is_complete(self) -> bool:
        return self.pending == 0 and self.covered == self.denominator


@dataclass(frozen=True, slots=True)
class ScanCoverage:
    """Coverage for a whole scan, and the terminal decision it implies."""

    steps: tuple[StepCoverage, ...]

    @property
    def planned(self) -> int:
        return sum(s.planned for s in self.steps)

    @property
    def denominator(self) -> int:
        return sum(s.denominator for s in self.steps)

    @property
    def covered(self) -> int:
        return sum(s.covered for s in self.steps)

    @property
    def gap(self) -> int:
        return sum(s.gap for s in self.steps)

    @property
    def integrity(self) -> int:
        return sum(s.integrity for s in self.steps)

    @property
    def excluded(self) -> int:
        return sum(s.excluded for s in self.steps)

    @property
    def pending(self) -> int:
        return sum(s.pending for s in self.steps)

    @property
    def covered_fraction(self) -> float:
        return 1.0 if self.denominator <= 0 else self.covered / self.denominator

    @property
    def gap_reasons(self) -> dict[str, int]:
        """Histogram of gap causes across the scan — the operator's first look."""
        counter: Counter[str] = Counter()
        for step in self.steps:
            counter.update(step.gap_reasons)
        return dict(counter)

    def as_payload(self) -> dict[str, object]:
        """Serializable coverage block. Required in every report."""
        return {
            "planned": self.planned,
            "denominator": self.denominator,
            "covered": self.covered,
            "gap": self.gap,
            "integrity": self.integrity,
            "excluded": self.excluded,
            "pending": self.pending,
            "covered_fraction": round(self.covered_fraction, 6),
            "gap_reasons": self.gap_reasons,
            "steps": [
                {
                    "stage": s.stage,
                    "step": s.step,
                    "tool_id": s.tool_id,
                    "planned": s.planned,
                    "denominator": s.denominator,
                    "covered": s.covered,
                    "gap": s.gap,
                    "integrity": s.integrity,
                    "excluded": s.excluded,
                    "pending": s.pending,
                    "covered_fraction": round(s.covered_fraction, 6),
                    "gap_reasons": dict(s.gap_reasons),
                }
                for s in self.steps
            ],
        }


@dataclass(frozen=True, slots=True)
class ClassifiedItem:
    """The minimal projection of a plan item that coverage needs."""

    stage: str
    step: str
    tool_id: str
    state: PlanItemState
    outcome: ToolOutcome | None
    reason_code: str | None


def fold(items: list[ClassifiedItem]) -> ScanCoverage:
    """Fold recorded plan items into per-step and scan coverage. Pure."""
    buckets: dict[tuple[str, str, str], list[ClassifiedItem]] = {}
    for item in items:
        buckets.setdefault((item.stage, item.step, item.tool_id), []).append(item)

    steps: list[StepCoverage] = []
    for (stage, step, tool_id), group in buckets.items():
        counts: Counter[CoverageClass] = Counter()
        gap_reasons: Counter[str] = Counter()
        for item in group:
            cls = classify(
                outcome=item.outcome, reason_code=item.reason_code, item_state=item.state
            )
            counts[cls] += 1
            if cls is CoverageClass.GAP:
                gap_reasons[item.reason_code or "UNSPECIFIED"] += 1
        steps.append(
            StepCoverage(
                stage=stage,
                step=step,
                tool_id=tool_id,
                planned=len(group),
                covered=counts[CoverageClass.COVERED],
                gap=counts[CoverageClass.GAP],
                integrity=counts[CoverageClass.INTEGRITY],
                excluded=counts[CoverageClass.EXCLUDED],
                pending=counts[CoverageClass.PENDING],
                gap_reasons=dict(gap_reasons),
            )
        )
    steps.sort(key=lambda s: (s.stage, s.step))
    return ScanCoverage(steps=tuple(steps))

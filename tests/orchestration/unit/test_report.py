"""Report assembly: corroborated, coverage-bearing, assurance-declaring.

The report is the only artifact a client sees. These tests cover the three ways
it could mislead: by including evidence nothing produced, by omitting how much
was actually covered, and by letting a reader assume verification happened.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from gryphon.orchestration.constants import PlanItemState, ScanLifecycleState
from gryphon.orchestration.coverage import ClassifiedItem, fold
from gryphon.orchestration.report import DECLARED_LIMITATIONS, assemble
from gryphon.tooling.constants import ToolOutcome
from tests.orchestration.conftest import NOW, SCAN_RUN_ID

pytestmark = pytest.mark.unit


@dataclass
class FakeItem:
    """Minimal plan-item shape the assembler reads."""

    execution_id: str
    stage: str = "scan"
    step: str = "vulnerability_scan"
    tool_id: str = "nuclei"
    state: str = PlanItemState.COMPLETED.value
    outcome: str | None = ToolOutcome.COMPLETED.value
    reason_code: str | None = "COMPLETED"
    audit_event_id: str | None = "audit-1"


@dataclass
class FakeFinding:
    """Minimal evidence shape the assembler reads."""

    execution_id: str
    finding_id: str = "f1"
    scan_run_id: str = SCAN_RUN_ID
    finding_key: str = "k1"
    stage: str = "scan"
    step: str = "vulnerability_scan"
    tool_id: str = "nuclei"
    observation_type: str = "vulnerability"
    canonical_target: str = "app.example.com"
    observation: dict | None = None
    severity: str | None = "HIGH"
    title: str | None = "Example finding"
    port: int | None = None
    url: str | None = "https://app.example.com/x"
    audit_event_id: str | None = "audit-1"
    verification_status: str = "NOT_VERIFIED"
    enrichment_status: str = "NOT_PERFORMED"

    def __post_init__(self) -> None:
        if self.observation is None:
            self.observation = {"template_id": "example"}


def _coverage(covered: int = 1, gap: int = 0, integrity: int = 0):
    items = [
        ClassifiedItem(
            stage="scan", step="vulnerability_scan", tool_id="nuclei",
            state=PlanItemState.COMPLETED, outcome=ToolOutcome.COMPLETED,
            reason_code="COMPLETED",
        )
    ] * covered
    items += [
        ClassifiedItem(
            stage="scan", step="vulnerability_scan", tool_id="nuclei",
            state=PlanItemState.FAILED, outcome=ToolOutcome.FAILED,
            reason_code="TOOL_FAILED",
        )
    ] * gap
    items += [
        ClassifiedItem(
            stage="scan", step="vulnerability_scan", tool_id="nuclei",
            state=PlanItemState.DENIED, outcome=ToolOutcome.DENIED,
            reason_code="SCOPE_NO_MATCH",
        )
    ] * integrity
    return fold(items)


def _assemble(*, findings, items, coverage=None, floor: float = 0.5):
    return assemble(
        scan_run_id=SCAN_RUN_ID,
        terminal_state=ScanLifecycleState.COMPLETED,
        reason_code="OK",
        coverage=coverage if coverage is not None else _coverage(),
        findings=findings,
        plan_items=items,
        generated_at=NOW,
        initiated_by="cli:uid:1000",
        policy_version="1",
        coverage_failure_floor=floor,
    )


# -- corroboration ------------------------------------------------------------
def test_corroborated_finding_is_included() -> None:
    report = _assemble(
        findings=[FakeFinding(execution_id="e1")], items=[FakeItem(execution_id="e1")]
    )
    assert report.finding_count == 1
    assert report.dropped_uncorroborated == 0
    assert not report.integrity_failure


def test_injected_finding_is_dropped_and_raises_integrity_failure() -> None:
    """Evidence with no producing execution is not evidence.

    Without this check, anything able to write the evidence table could author
    the deliverable — and a "deterministic report" test would pass while it did.
    """
    report = _assemble(
        findings=[FakeFinding(execution_id="never-ran")],
        items=[FakeItem(execution_id="e1")],
    )
    assert report.finding_count == 0
    assert report.dropped_uncorroborated == 1
    assert report.integrity_failure
    assert report.terminal_state is ScanLifecycleState.FAILED
    assert report.body["reason_code"] == "SCAN_INTEGRITY_FAILURE"


def test_finding_from_another_scan_is_dropped() -> None:
    """Cross-scan contamination must not reach a client's report."""
    report = _assemble(
        findings=[FakeFinding(execution_id="e1", scan_run_id="other-scan")],
        items=[FakeItem(execution_id="e1")],
    )
    assert report.finding_count == 0
    assert report.integrity_failure


def test_scope_disagreement_fails_the_report() -> None:
    report = _assemble(
        findings=[FakeFinding(execution_id="e1")],
        items=[FakeItem(execution_id="e1")],
        coverage=_coverage(covered=1, integrity=1),
    )
    assert report.integrity_failure
    assert report.terminal_state is ScanLifecycleState.FAILED


# -- coverage is mandatory ----------------------------------------------------
def test_coverage_block_is_always_present() -> None:
    report = _assemble(findings=[], items=[])
    assert "coverage" in report.body
    for key in ("planned", "denominator", "covered", "gap", "covered_fraction"):
        assert key in report.body["coverage"]


def test_gap_causes_are_itemized_for_the_operator() -> None:
    report = _assemble(
        findings=[], items=[], coverage=_coverage(covered=1, gap=2)
    )
    assert report.body["coverage"]["gap_reasons"] == {"TOOL_FAILED": 2}


def test_coverage_below_the_floor_downgrades_a_completion() -> None:
    """Most of the scan not happening must not be reported as completion."""
    report = _assemble(
        findings=[], items=[], coverage=_coverage(covered=1, gap=9), floor=0.5
    )
    assert report.terminal_state is ScanLifecycleState.FAILED


def test_identical_findings_with_different_coverage_differ() -> None:
    """Two reports with the same findings are not the same report."""
    findings = [FakeFinding(execution_id="e1")]
    items = [FakeItem(execution_id="e1")]
    full = _assemble(findings=findings, items=items, coverage=_coverage(covered=1))
    gapped = _assemble(
        findings=findings, items=items, coverage=_coverage(covered=1, gap=1)
    )
    assert full.report_digest != gapped.report_digest


# -- assurance ----------------------------------------------------------------
def test_every_finding_declares_it_is_unverified() -> None:
    """Being careful not to assert verification is not the same as denying it.

    A consumer defaults to the stronger reading unless told, so the absence is
    stated on every finding and at the top level.
    """
    report = _assemble(
        findings=[FakeFinding(execution_id="e1")], items=[FakeItem(execution_id="e1")]
    )
    assert report.body["assurance"]["verification"] == "NOT_VERIFIED"
    assert report.body["assurance"]["enrichment"] == "NOT_PERFORMED"
    for finding in report.body["findings"]:
        assert finding["verification_status"] == "NOT_VERIFIED"
        assert finding["enrichment_status"] == "NOT_PERFORMED"


def test_known_structural_limitations_are_declared() -> None:
    """The HTTP default-port gap is named in the deliverable, not discovered."""
    report = _assemble(findings=[], items=[])
    declared = {d["id"] for d in report.body["assurance"]["declared_limitations"]}
    assert "HTTP_DEFAULT_PORTS_ONLY" in declared
    assert "NO_VERIFICATION_OR_ENRICHMENT" in declared
    assert len(DECLARED_LIMITATIONS) == len(
        report.body["assurance"]["declared_limitations"]
    )


def test_findings_carry_provenance() -> None:
    report = _assemble(
        findings=[FakeFinding(execution_id="e1")], items=[FakeItem(execution_id="e1")]
    )
    provenance = report.body["findings"][0]["provenance"]
    assert provenance["execution_id"] == "e1"
    assert provenance["audit_event_id"] == "audit-1"
    assert provenance["tool_id"] == "nuclei"


def test_later_stage_seams_are_typed_and_empty() -> None:
    """Present so a consumer can tell "not performed" from "field absent"."""
    report = _assemble(findings=[], items=[])
    assert report.body["narrative"] is None
    assert report.body["compliance"] == []


# -- determinism --------------------------------------------------------------
def test_assembly_is_deterministic() -> None:
    findings = [FakeFinding(execution_id="e1"), FakeFinding(execution_id="e1", finding_id="f2", finding_key="k2")]
    items = [FakeItem(execution_id="e1")]
    first = _assemble(findings=findings, items=items)
    second = _assemble(findings=list(reversed(findings)), items=items)
    assert first.report_digest == second.report_digest
    assert first.report_id == second.report_id


def test_digest_changes_when_content_changes() -> None:
    """The digest is what a signed audit event attests, so it must be sensitive."""
    base = _assemble(
        findings=[FakeFinding(execution_id="e1")], items=[FakeItem(execution_id="e1")]
    )
    altered = _assemble(
        findings=[FakeFinding(execution_id="e1", severity="CRITICAL")],
        items=[FakeItem(execution_id="e1")],
    )
    assert base.report_digest != altered.report_digest


def test_summary_counts_observations_not_vulnerabilities() -> None:
    report = _assemble(
        findings=[FakeFinding(execution_id="e1")], items=[FakeItem(execution_id="e1")]
    )
    assert report.body["summary"]["observation_count"] == 1
    assert report.body["summary"]["observations_by_type"] == {"vulnerability": 1}
    assert report.body["summary"]["observations_by_severity"] == {"HIGH": 1}

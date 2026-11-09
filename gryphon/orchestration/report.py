"""Report assembly — a pure function over corroborated evidence.

The report is the only artifact a client ever sees, which makes it the thing
most worth attacking and the thing most worth proving. Three properties:

**Corroborated.** Every finding must trace to an enforcement-layer execution
that this scan actually recorded. Evidence whose ``execution_id`` has no
matching settled plan item is dropped and raises a scan-level integrity
failure. Without that check, a deliverable assembled from a table is a
deliverable that anything with write access to that table can author — and a
"deterministic report" test would pass happily while doing it.

**Coverage-bearing.** The coverage block is mandatory. A report that says
"completed" without saying *how much was covered* invites the reader to assume
the scan looked everywhere, and a zero-finding report for a target that was
never reached is the most expensive thing this system could say.

**Assurance-declaring.** Every finding carries ``NOT_VERIFIED`` and
``NOT_PERFORMED``, and the report carries a top-level assurance block naming
what was *not* done. Being careful never to assert something false is not the
same as denying it: a consumer — human or a later automated stage — defaults to
the stronger reading unless told otherwise, so the absence is stated explicitly.

The declared limitations block is where known, structural gaps are named rather
than left for a reader to discover. It currently records that HTTP probing
covers the enforcement layer's pinned default ports only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Sequence

from gryphon.clock import ensure_utc
from gryphon.db.models.raw_finding import RawFinding
from gryphon.db.models.scan_plan import PlanItem
from gryphon.orchestration.constants import (
    GRAPH_VERSION,
    REPORT_SCHEMA_VERSION,
    AssuranceStatus,
    ScanLifecycleState,
)
from gryphon.orchestration.coverage import ScanCoverage
from gryphon.orchestration.identity import content_digest
from gryphon.orchestration.reasons import OrchestrationReasonCode

#: Structural limitations this layer knows about and therefore declares. Named
#: here so they appear in the deliverable instead of being rediscovered by the
#: person reading it.
DECLARED_LIMITATIONS: tuple[dict[str, str], ...] = (
    {
        "id": "HTTP_DEFAULT_PORTS_ONLY",
        "statement": (
            "HTTP probing covered the default web ports only. Port discovery runs "
            "first and its results are recorded, but the enforcement layer pins "
            "each HTTP probe's destination allowlist to the ports declared by its "
            "tool descriptor, so a service discovered on a non-standard port was "
            "not probed."
        ),
        "consequence": (
            "A web service on a non-standard port may exist and not appear in this "
            "report. Discovered open ports are listed as evidence so the gap is "
            "visible and quantifiable."
        ),
    },
    {
        "id": "NO_VERIFICATION_OR_ENRICHMENT",
        "statement": (
            "Findings are raw tool observations. No false-positive filtering, "
            "exploit chaining, CVE correlation or severity adjustment was performed."
        ),
        "consequence": (
            "Every finding must be treated as unverified. Counts are observation "
            "counts, not confirmed-vulnerability counts."
        ),
    },
)


@dataclass(frozen=True, slots=True)
class AssembledReport:
    """A report body plus its content digest, ready to persist and attest."""

    report_id: str
    body: dict[str, Any]
    report_digest: str
    finding_count: int
    terminal_state: ScanLifecycleState
    integrity_failure: bool
    dropped_uncorroborated: int


def assemble(
    *,
    scan_run_id: str,
    terminal_state: ScanLifecycleState,
    reason_code: str | None,
    coverage: ScanCoverage,
    findings: Sequence[RawFinding],
    plan_items: Sequence[PlanItem],
    generated_at: datetime,
    initiated_by: str,
    policy_version: str,
    coverage_failure_floor: float,
) -> AssembledReport:
    """Assemble a report deterministically from recorded, corroborated facts.

    Pure: same inputs, same bytes. The digest is therefore stable and can be
    attested by a signed audit event rather than by signing the artifact with a
    key meant for another purpose.
    """
    # Corroboration: a finding is admissible only if its producing execution is
    # a settled item of THIS scan. This is what makes the report evidence
    # rather than an assertion about a table.
    settled: dict[str, PlanItem] = {
        item.execution_id: item for item in plan_items if item.audit_event_id or item.outcome
    }
    admissible: list[RawFinding] = []
    dropped = 0
    for finding in findings:
        if finding.execution_id in settled and finding.scan_run_id == scan_run_id:
            admissible.append(finding)
        else:
            dropped += 1

    integrity_failure = dropped > 0 or coverage.integrity > 0
    effective_state = terminal_state
    effective_reason = reason_code
    if integrity_failure:
        effective_state = ScanLifecycleState.FAILED
        effective_reason = OrchestrationReasonCode.SCAN_INTEGRITY_FAILURE.value
    elif (
        terminal_state
        in (ScanLifecycleState.COMPLETED, ScanLifecycleState.COMPLETED_WITH_GAPS)
        and coverage.denominator > 0
        and coverage.covered_fraction < coverage_failure_floor
    ):
        # Most of the scan did not happen. Reporting that as a completion —
        # even a gapped one — would overstate it.
        effective_state = ScanLifecycleState.FAILED
        effective_reason = OrchestrationReasonCode.SCAN_DEADLINE_EXCEEDED.value

    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for finding in admissible:
        by_type[finding.observation_type] = by_type.get(finding.observation_type, 0) + 1
        if finding.severity:
            key = finding.severity.upper()
            by_severity[key] = by_severity.get(key, 0) + 1

    body: dict[str, Any] = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "graph_version": GRAPH_VERSION,
        "scan_run_id": scan_run_id,
        "generated_at": ensure_utc(generated_at).isoformat(),
        "initiated_by": initiated_by,
        "policy_version": policy_version,
        "terminal_state": effective_state.value,
        "reason_code": effective_reason,
        # Mandatory. A report is not emitted without it.
        "coverage": coverage.as_payload(),
        "assurance": {
            "verification": AssuranceStatus.NOT_VERIFIED.value,
            "enrichment": AssuranceStatus.NOT_PERFORMED.value,
            "statement": (
                "Observations only. No verification, enrichment, exploit chaining "
                "or compliance mapping was performed by this layer."
            ),
            "declared_limitations": [dict(item) for item in DECLARED_LIMITATIONS],
        },
        "integrity": {
            "uncorroborated_findings_dropped": dropped,
            "scope_disagreements": coverage.integrity,
            "failed": integrity_failure,
        },
        "summary": {
            "observation_count": len(admissible),
            "observations_by_type": dict(sorted(by_type.items())),
            "observations_by_severity": dict(sorted(by_severity.items())),
        },
        "findings": [
            {
                "finding_id": f.finding_id,
                "observation_type": f.observation_type,
                "canonical_target": f.canonical_target,
                "title": f.title,
                "severity": f.severity,
                "port": f.port,
                "url": f.url,
                "observation": f.observation,
                "verification_status": f.verification_status,
                "enrichment_status": f.enrichment_status,
                "provenance": {
                    "execution_id": f.execution_id,
                    "audit_event_id": f.audit_event_id,
                    "stage": f.stage,
                    "step": f.step,
                    "tool_id": f.tool_id,
                },
            }
            for f in sorted(admissible, key=lambda r: (r.stage, r.step, r.finding_key))
        ],
        # Typed, empty seams for later stages. Present so a consumer can tell
        # "not performed" from "absent field".
        "narrative": None,
        "compliance": [],
    }

    digest = content_digest(body)
    report_id = f"{scan_run_id[:8]}-rpt-{digest[:16]}"
    return AssembledReport(
        report_id=report_id,
        body=body,
        report_digest=digest,
        finding_count=len(admissible),
        terminal_state=effective_state,
        integrity_failure=integrity_failure,
        dropped_uncorroborated=dropped,
    )


def _has_unsettled_coverage(coverage: ScanCoverage) -> bool:
    """Is there anything reconciliation could still resolve?

    The distinction is operational, not cosmetic: telling an operator to
    reconcile a scan whose every gap is already settled sends them to a command
    that will report "examined 0, resolved 0" and teaches them to stop reading
    reason codes.

    Only non-terminal items qualify, which is exactly what ``pending`` counts —
    an indeterminate outcome is deliberately left non-terminal so that it stays
    reconcilable. A deterministic denial is settled, and so, despite its name,
    is ``UNRESOLVED_POSSIBLY_CONTACTED``: that classification is what
    reconciliation produces when it gives up, so it is a declared gap, not
    pending work.
    """
    return coverage.pending > 0


def terminal_state_for(
    coverage: ScanCoverage, *, coverage_failure_floor: float
) -> tuple[ScanLifecycleState, str | None]:
    """Decide the terminal state from coverage alone.

    This is the fold that makes "done" mean something: reaching the end of the
    graph is not the criterion — accounting for the planned work is.
    """
    if coverage.integrity > 0:
        return (
            ScanLifecycleState.FAILED,
            OrchestrationReasonCode.SCOPE_DISAGREEMENT.value,
        )
    if coverage.denominator == 0:
        # Nothing was planned (e.g. discovery found nothing in scope). That is
        # a truthful completion, not a gap.
        return ScanLifecycleState.COMPLETED, OrchestrationReasonCode.OK.value
    unsettled = _has_unsettled_coverage(coverage)
    if coverage.covered_fraction < coverage_failure_floor:
        if coverage.gap_reasons.get("BUDGET_EXCEEDED"):
            reason = OrchestrationReasonCode.DECISION_BUDGET_EXHAUSTED.value
        elif unsettled:
            reason = OrchestrationReasonCode.RECONCILE_REQUIRED.value
        else:
            reason = OrchestrationReasonCode.COVERAGE_BELOW_FLOOR.value
        return ScanLifecycleState.FAILED, reason
    if coverage.covered == coverage.denominator:
        return ScanLifecycleState.COMPLETED, OrchestrationReasonCode.OK.value
    return (
        ScanLifecycleState.COMPLETED_WITH_GAPS,
        OrchestrationReasonCode.RECONCILE_REQUIRED.value
        if unsettled
        else OrchestrationReasonCode.COVERAGE_INCOMPLETE.value,
    )

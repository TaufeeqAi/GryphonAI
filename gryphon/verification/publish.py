"""The deliverable: what a client is actually told, and how it is attested.

The report is built once, digested over its canonical form, and attested by a
signed event in the same transaction that marks the pass COMPLETE. Readers
re-verify the digest before the report is served, so a row that was altered
after the fact cannot be handed to anyone as proof.

Two choices in the body shape are worth explaining, because both were made
against a more flattering alternative:

* **Nothing is deleted.** REFUTED findings are listed with their justification
  rather than silently dropped. A consumer that only ever sees the confirmed
  section cannot tell a finding that was never produced from one that was
  verified away, and that ambiguity is how a verification layer turns into a
  way of quietly removing inconvenient results.
* **The report says what it could not do.** Unverified findings carry the reason
  — a dependency that was down, a host that started answering protectively, a
  class nobody has reviewed — and the ordering basis is recorded, because when a
  budget runs out the ordering decides what was never looked at. A silent gap
  reads as a clean bill of health.

The report also names every verifier version it relied on. That is what makes a
later withdrawal actionable: when a predicate is found unsound, the affected
reports can be identified instead of guessed at.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from gryphon.auth.key_provider import TrustedKeyStore
from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.clock import ensure_utc
from gryphon.verification.constants import (
    VERIFICATION_CODE_VERSION,
    VERIFICATION_REPORT_SCHEMA_VERSION,
    EnrichmentContext,
    Justification,
    OrderingBasis,
    PassOutcome,
    VerdictStatus,
)
from gryphon.verification.evaluator import Verdict
from gryphon.verification.identity import report_id_for
from gryphon.verification.inputs import ReportRef

#: Report sections, in the order a reader meets them. "Confirmed" first because
#: it is the answer the client asked for; "unverified" last and never omitted.
_SECTIONS: tuple[tuple[str, tuple[VerdictStatus, ...]], ...] = (
    ("confirmed", (VerdictStatus.CONFIRMED,)),
    ("filtered_false_positives", (VerdictStatus.REFUTED,)),
    ("not_reproduced", (VerdictStatus.NOT_REPRODUCED,)),
    ("unverified", (VerdictStatus.INCONCLUSIVE, VerdictStatus.UNSUPPORTED)),
)


@dataclass(frozen=True, slots=True)
class VerdictRecord:
    """One finding's verdict, as it is stored and reported."""

    finding_id: str
    subject_key: str
    verdict: Verdict
    observed_at: datetime | None
    canonical_target: str
    url: str | None = None
    retracted: bool = False

    def as_report_entry(self) -> dict[str, Any]:
        verdict = self.verdict
        return {
            "finding_id": self.finding_id,
            "subject_key": self.subject_key,
            "canonical_target": self.canonical_target,
            "url": self.url,
            "status": verdict.status.value,
            "justification": verdict.justification.value if verdict.justification else None,
            "verifier_id": verdict.verifier_id,
            "rule": verdict.rule,
            "matched_predicates": list(verdict.matched_predicates),
            "control_summary": (
                verdict.control_summary.as_payload() if verdict.control_summary else None
            ),
            "evidence": verdict.projection,
            "possibly_applied": verdict.possibly_applied,
            "observed_at": (
                ensure_utc(self.observed_at).isoformat() if self.observed_at else None
            ),
            "retracted": self.retracted,
        }


@dataclass(frozen=True, slots=True)
class PublishedReport:
    report_id: str
    report_digest: str
    body: dict[str, Any]


def verdict_set_digest(records: Sequence[VerdictRecord]) -> str:
    """A digest over the verdicts themselves, independent of report prose.

    Derivation units (chains, advisory triage) key on this rather than on the
    report, so re-deriving them costs no traffic and produces a stable identity
    even if the report's presentation changes.
    """
    rows = sorted(
        (
            {
                "finding_id": r.finding_id,
                "subject_key": r.subject_key,
                "status": r.verdict.status.value,
                "justification": (
                    r.verdict.justification.value if r.verdict.justification else None
                ),
                "verifier_id": r.verdict.verifier_id,
            }
            for r in records
        ),
        key=lambda row: row["finding_id"],
    )
    return sha256_hex(canonical_json_bytes(rows))


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(dict(manifest)))


def report_digest(body: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(dict(body)))


def outcome_for(records: Sequence[VerdictRecord], *, degraded: bool) -> PassOutcome:
    """Summarize a pass honestly.

    ``degraded`` is set when a dependency or a host's protective response left
    the result shaped by our own limits rather than by the estate. It is kept
    separate from "there were gaps" so an operator does not read an outage as a
    finding about the client.
    """
    if not records:
        return PassOutcome.NOTHING_TO_VERIFY
    if degraded:
        return PassOutcome.VERIFICATION_DEGRADED
    undetermined = sum(
        1
        for r in records
        if r.verdict.status in (VerdictStatus.INCONCLUSIVE, VerdictStatus.UNSUPPORTED)
    )
    if undetermined:
        return PassOutcome.VERIFIED_WITH_GAPS
    return PassOutcome.VERIFIED


def build_report_body(
    *,
    scan_run_id: str,
    pass_id: str,
    records: Sequence[VerdictRecord],
    base: ReportRef,
    enrichment: ReportRef | None,
    enrichment_context: EnrichmentContext,
    ordering_basis: OrderingBasis,
    manifest: Mapping[str, Any],
    outcome: PassOutcome,
    scope: str | None,
    generated_at: datetime,
    limitations: Sequence[str],
) -> dict[str, Any]:
    """Assemble the report body. Deterministic for a given input set."""
    sections: dict[str, list[dict[str, Any]]] = {name: [] for name, _ in _SECTIONS}
    counts: dict[str, int] = {status.value: 0 for status in VerdictStatus}
    justifications: dict[str, int] = {}

    for record in sorted(records, key=lambda r: r.finding_id):
        counts[record.verdict.status.value] += 1
        if record.verdict.justification is not None:
            key = record.verdict.justification.value
            justifications[key] = justifications.get(key, 0) + 1
        for name, statuses in _SECTIONS:
            if record.verdict.status in statuses:
                sections[name].append(record.as_report_entry())
                break

    verifier_versions = {
        r.verdict.verifier_id: r.verdict.verifier_id
        for r in records
        if r.verdict.verifier_id
    }

    return {
        "verification_report_schema_version": VERIFICATION_REPORT_SCHEMA_VERSION,
        "code_version": VERIFICATION_CODE_VERSION,
        "scan_run_id": scan_run_id,
        "pass_id": pass_id,
        "generated_at": ensure_utc(generated_at).isoformat(),
        "outcome": outcome.value,
        "scope": scope,
        "ordering_basis": ordering_basis.value,
        "cites": {
            "base_report_id": base.report_id,
            "base_report_digest": base.report_digest,
            "enrichment_report_id": enrichment.report_id if enrichment else None,
            "enrichment_report_digest": enrichment.report_digest if enrichment else None,
            "enrichment_context": enrichment_context.value,
        },
        "counts": counts,
        "justification_counts": dict(sorted(justifications.items())),
        "verifier_versions": sorted(verifier_versions),
        "sections": sections,
        "manifest": dict(manifest),
        "limitations": list(limitations),
    }


def declared_limitations(
    *,
    enrichment_context: EnrichmentContext,
    ordering_basis: OrderingBasis,
    degraded_hosts: Sequence[str],
    blocked_seconds: float,
    unsupported_classes: Sequence[str],
) -> tuple[str, ...]:
    """What this report cannot tell you, stated in the report itself.

    Every entry here is a limit a reader would otherwise have to infer from an
    absence — and an absence reads as a clean result.
    """
    out: list[str] = [
        "Verification re-observes through the authorization gateway under authority "
        "established at the moment of contact. It is non-destructive within a reviewed "
        "endpoint class, and is not a proof about the target's own implementation.",
        "A secret's shape and count are reported; its value never left the process that "
        "read it and was never stored, logged or transmitted.",
    ]
    if ordering_basis is OrderingBasis.OBSERVED_SEVERITY:
        out.append(
            "No verified enrichment context was available, so findings were ordered by the "
            "severity observed during the scan rather than by exploitation intelligence. "
            "If a budget was reached, that ordering decided what was not re-observed."
        )
    if enrichment_context is EnrichmentContext.UNVERIFIED:
        out.append(
            "An enrichment report exists for this scan but could not be verified, so it was "
            "not used as context."
        )
    if enrichment_context is EnrichmentContext.SUPERSEDED:
        out.append(
            "The enrichment context used here has since been superseded by a newer report. "
            "It was valid and attested when this pass pinned it."
        )
    if degraded_hosts:
        out.append(
            f"{len(degraded_hosts)} host(s) began responding protectively during this pass and "
            "were paused. Findings on those hosts are reported as unverified because continuing "
            "would have measured our own effect rather than theirs."
        )
    if blocked_seconds > 0:
        out.append(
            f"This pass waited {blocked_seconds:.0f}s for a dependency of the verification "
            "platform. Findings it never observed carry no verdict rather than a misleading one."
        )
    if unsupported_classes:
        out.append(
            f"{len(unsupported_classes)} finding class(es) have no reviewed verifier and were "
            "reported as unsupported. An unsupported finding is not a refuted one."
        )
    return tuple(out)


def publish(
    *,
    scan_run_id: str,
    body: Mapping[str, Any],
) -> PublishedReport:
    """Freeze a report body into an identified, digested artifact."""
    frozen = dict(body)
    digest = report_digest(frozen)
    return PublishedReport(
        report_id=report_id_for(scan_run_id, digest),
        report_digest=digest,
        body=frozen,
    )


def verify_report(
    *,
    body: Mapping[str, Any],
    stored_digest: str,
    events: Sequence[tuple[dict[str, Any], str, str, str]],
    trust: TrustedKeyStore,
) -> bool:
    """Re-verify a stored report before serving it.

    Checks the digest against the body as stored and requires a signed event
    that attests exactly that digest. A report whose row was altered after
    publication fails here rather than being handed to a client as proof.
    """
    from gryphon.auth.audit_signer import verify_audit_event

    recomputed = report_digest(body)
    if recomputed != stored_digest:
        return False
    for payload, payload_digest, signer_kid, signature_b64 in events:
        if payload.get("report_digest") != recomputed:
            continue
        if sha256_hex(canonical_json_bytes(payload)) != payload_digest:
            continue
        if verify_audit_event(payload, signature_b64, signer_kid, trust):
            return True
    return False


def unsupported_classes_in(records: Sequence[VerdictRecord]) -> tuple[str, ...]:
    """Finding classes that had no reviewed verifier, for the limitations block."""
    out = {
        r.verdict.justification.value
        for r in records
        if r.verdict.status is VerdictStatus.UNSUPPORTED
        and r.verdict.justification
        in (Justification.NO_VERIFIER, Justification.UNREVIEWED_CLASS)
    }
    return tuple(sorted(out))

"""Pure derivation: assertions, priorities and the pass outcome.

No I/O, no clock, no network. Every input — the verified subjects, the pinned
snapshot views (with their ages), the reference data and the policy — is passed
in, so a pass can be re-derived offline from its manifest and produce the same
rows and the same digest.

Status algebra, per (finding, source):

* ``ENRICHED``        — a value from an accepted snapshot, a pinned dataset or
                        (CVSS only) the template, with its attribution.
* ``NOT_APPLICABLE``  — proven absent from an accepted, complete snapshot or a
                        pinned dataset, which the reason names.
* ``UNAVAILABLE``     — no accepted snapshot, an integrity hold, or a dataset
                        that does not verify. A *failed refresh* is never here:
                        it only makes the newest accepted snapshot older.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.enrichment.artifacts import KevEntry
from gryphon.enrichment.constants import (
    ALL_SOURCES,
    VALUE_SCHEMA_VERSION,
    AssertedBy,
    AssertionStatus,
    PassOutcome,
    RemediationClass,
    Source,
    UnavailableReason,
)
from gryphon.enrichment.cve import FindingSubjects
from gryphon.enrichment.policy import Policy, PriorityInputs, decide
from gryphon.enrichment.reference import DatasetUnavailable, ReferenceData


@dataclass(frozen=True)
class KevView:
    snapshot_id: str
    catalog_version: str
    age_s: int
    stale: bool
    listed: dict[str, KevEntry]
    integrity_hold: frozenset[str] = frozenset()


@dataclass(frozen=True)
class EpssView:
    snapshot_id: str
    score_date: str
    model_version: str
    age_s: int
    stale: bool
    scores: dict[str, tuple[float, float]]


@dataclass(frozen=True)
class DerivationInputs:
    subjects: tuple[FindingSubjects, ...]
    kev: KevView | None
    epss: EpssView | None
    reference: ReferenceData | DatasetUnavailable
    template_snapshot_id: str
    policy: Policy


@dataclass(frozen=True)
class AssertionRecord:
    finding_id: str
    source: str
    status: str
    reason: str | None
    remediation_class: str | None
    value: dict[str, Any]
    snapshot_id: str | None
    asserted_by: str
    snapshot_age_s: int | None
    value_schema_version: str = VALUE_SCHEMA_VERSION

    def as_payload(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "source": self.source,
            "status": self.status,
            "reason": self.reason,
            "remediation_class": self.remediation_class,
            "value": self.value,
            "value_schema_version": self.value_schema_version,
            "snapshot_id": self.snapshot_id,
            "asserted_by": self.asserted_by,
            "snapshot_age_s": self.snapshot_age_s,
        }


@dataclass(frozen=True)
class PriorityRecord:
    finding_id: str
    observed_severity: str
    priority: str
    rationale: tuple[dict[str, str], ...]
    policy_digest: str

    def as_payload(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "observed_severity": self.observed_severity,
            "priority": self.priority,
            "rationale": list(self.rationale),
            "policy_digest": self.policy_digest,
        }


@dataclass(frozen=True)
class Derivation:
    assertions: tuple[AssertionRecord, ...]
    priorities: tuple[PriorityRecord, ...]
    outcome: PassOutcome
    coverage: dict[str, dict[str, Any]] = field(default_factory=dict)
    digest: str = ""


def _unavailable(
    finding_id: str,
    source: Source,
    reason: UnavailableReason,
    remediation: RemediationClass,
    asserted_by: AssertedBy,
    *,
    snapshot_id: str | None = None,
    value: dict[str, Any] | None = None,
    age: int | None = None,
) -> AssertionRecord:
    return AssertionRecord(
        finding_id=finding_id,
        source=source.value,
        status=AssertionStatus.UNAVAILABLE.value,
        reason=reason.value,
        remediation_class=remediation.value,
        value=value or {},
        snapshot_id=snapshot_id,
        asserted_by=asserted_by.value,
        snapshot_age_s=age,
    )


def _kev_assertion(subject: FindingSubjects, kev: KevView | None) -> AssertionRecord:
    if kev is None:
        return _unavailable(
            subject.finding_id,
            Source.KEV,
            UnavailableReason.NO_ACCEPTED_SNAPSHOT,
            RemediationClass.TRANSIENT,
            AssertedBy.PROVIDER_SNAPSHOT,
        )
    listed = [kev.listed[c] for c in subject.cve_ids if c in kev.listed]
    held = sorted(c for c in subject.cve_ids if c in kev.integrity_hold)
    if listed:
        value: dict[str, Any] = {
            "catalog_version": kev.catalog_version,
            "listed": [
                {
                    "cve": e.cve,
                    "date_added": e.date_added,
                    "due_date": e.due_date,
                    "known_ransomware_campaign_use": e.known_ransomware_campaign_use,
                }
                for e in sorted(listed, key=lambda e: e.cve)
            ],
        }
        if held:
            value["integrity_hold"] = held
        return AssertionRecord(
            finding_id=subject.finding_id,
            source=Source.KEV.value,
            status=AssertionStatus.ENRICHED.value,
            reason=None,
            remediation_class=None,
            value=value,
            snapshot_id=kev.snapshot_id,
            asserted_by=AssertedBy.PROVIDER_SNAPSHOT.value,
            snapshot_age_s=kev.age_s,
        )
    if held:
        return _unavailable(
            subject.finding_id,
            Source.KEV,
            UnavailableReason.INTEGRITY_HOLD,
            RemediationClass.INTEGRITY,
            AssertedBy.PROVIDER_SNAPSHOT,
            snapshot_id=kev.snapshot_id,
            value={"catalog_version": kev.catalog_version, "integrity_hold": held},
            age=kev.age_s,
        )
    return AssertionRecord(
        finding_id=subject.finding_id,
        source=Source.KEV.value,
        status=AssertionStatus.NOT_APPLICABLE.value,
        reason=f"not_listed@{kev.snapshot_id}",
        remediation_class=None,
        value={"catalog_version": kev.catalog_version, "cves": sorted(subject.cve_ids)},
        snapshot_id=kev.snapshot_id,
        asserted_by=AssertedBy.PROVIDER_SNAPSHOT.value,
        snapshot_age_s=kev.age_s,
    )


def _epss_assertion(subject: FindingSubjects, epss: EpssView | None) -> AssertionRecord:
    if epss is None:
        return _unavailable(
            subject.finding_id,
            Source.EPSS,
            UnavailableReason.NO_ACCEPTED_SNAPSHOT,
            RemediationClass.TRANSIENT,
            AssertedBy.PROVIDER_SNAPSHOT,
        )
    scored = sorted((c, *epss.scores[c]) for c in subject.cve_ids if c in epss.scores)
    common = {"model_version": epss.model_version, "score_date": epss.score_date}
    if not scored:
        return AssertionRecord(
            finding_id=subject.finding_id,
            source=Source.EPSS.value,
            status=AssertionStatus.NOT_APPLICABLE.value,
            reason=f"not_scored@{epss.snapshot_id}",
            remediation_class=None,
            value={**common, "cves": sorted(subject.cve_ids)},
            snapshot_id=epss.snapshot_id,
            asserted_by=AssertedBy.PROVIDER_SNAPSHOT.value,
            snapshot_age_s=epss.age_s,
        )
    top = min(scored, key=lambda row: (-row[1], row[0]))
    return AssertionRecord(
        finding_id=subject.finding_id,
        source=Source.EPSS.value,
        status=AssertionStatus.ENRICHED.value,
        reason=None,
        remediation_class=None,
        value={
            **common,
            "scores": [{"cve": c, "epss": e, "percentile": p} for c, e, p in scored],
            "max": {"cve": top[0], "epss": top[1]},
        },
        snapshot_id=epss.snapshot_id,
        asserted_by=AssertedBy.PROVIDER_SNAPSHOT.value,
        snapshot_age_s=epss.age_s,
    )


def _cvss_assertion(subject: FindingSubjects, template_snapshot_id: str) -> AssertionRecord:
    raw = subject.cvss_score
    score: float | None = None
    if isinstance(raw, int | float) and not isinstance(raw, bool) and math.isfinite(raw):
        if 0.0 <= float(raw) <= 10.0:
            score = float(raw)
    if score is None:
        return AssertionRecord(
            finding_id=subject.finding_id,
            source=Source.CVSS_TEMPLATE.value,
            status=AssertionStatus.NOT_APPLICABLE.value,
            reason="no_score_in_template",
            remediation_class=None,
            value={},
            snapshot_id=template_snapshot_id,
            asserted_by=AssertedBy.TEMPLATE.value,
            snapshot_age_s=None,
        )
    return AssertionRecord(
        finding_id=subject.finding_id,
        source=Source.CVSS_TEMPLATE.value,
        status=AssertionStatus.ENRICHED.value,
        reason=None,
        remediation_class=None,
        value={"score": score, "template_id": subject.template_id},
        snapshot_id=template_snapshot_id,
        asserted_by=AssertedBy.TEMPLATE.value,
        snapshot_age_s=None,
    )


def _attack_assertion(
    subject: FindingSubjects, reference: ReferenceData | DatasetUnavailable
) -> AssertionRecord:
    if isinstance(reference, DatasetUnavailable):
        return _unavailable(
            subject.finding_id,
            Source.ATTACK_CTID,
            UnavailableReason.DATASET_UNAVAILABLE,
            RemediationClass.MISCONFIGURED,
            AssertedBy.REFERENCE_DATASET,
            value={"detail": reference.reason},
        )
    techniques: list[dict[str, Any]] = []
    for cve in sorted(subject.cve_ids):
        for ref in reference.techniques_for(cve) or ():
            techniques.append({"cve": cve, **ref.as_payload()})
    common = {
        "mapping_version": reference.mapping_version,
        "attack_version": reference.attack_version,
    }
    if not techniques:
        return AssertionRecord(
            finding_id=subject.finding_id,
            source=Source.ATTACK_CTID.value,
            status=AssertionStatus.NOT_APPLICABLE.value,
            reason=f"no_curated_mapping@{reference.mapping_version}",
            remediation_class=None,
            value={**common, "cves": sorted(subject.cve_ids)},
            snapshot_id=reference.snapshot_id,
            asserted_by=AssertedBy.REFERENCE_DATASET.value,
            snapshot_age_s=None,
        )
    return AssertionRecord(
        finding_id=subject.finding_id,
        source=Source.ATTACK_CTID.value,
        status=AssertionStatus.ENRICHED.value,
        reason=None,
        remediation_class=None,
        value={**common, "techniques": techniques},
        snapshot_id=reference.snapshot_id,
        asserted_by=AssertedBy.REFERENCE_DATASET.value,
        snapshot_age_s=None,
    )


def derivation_digest(
    assertions: tuple[AssertionRecord, ...], priorities: tuple[PriorityRecord, ...]
) -> str:
    """Canonical digest of a pass's output; part of its attested completion."""
    body = {
        "assertions": sorted(
            (a.as_payload() for a in assertions), key=lambda a: (a["finding_id"], a["source"])
        ),
        "priorities": sorted((p.as_payload() for p in priorities), key=lambda p: p["finding_id"]),
    }
    return sha256_hex(canonical_json_bytes(body))


def derive(inputs: DerivationInputs) -> Derivation:
    """Derive every (finding, source) assertion and every finding's priority."""
    assertions: list[AssertionRecord] = []
    priorities: list[PriorityRecord] = []
    for subject in sorted(inputs.subjects, key=lambda s: s.finding_id):
        kev = _kev_assertion(subject, inputs.kev)
        epss = _epss_assertion(subject, inputs.epss)
        cvss = _cvss_assertion(subject, inputs.template_snapshot_id)
        attack = _attack_assertion(subject, inputs.reference)
        row = (kev, epss, cvss, attack)
        assertions.extend(row)

        kev_listed: tuple[tuple[str, str], ...] = ()
        if kev.status == AssertionStatus.ENRICHED.value:
            kev_listed = tuple((e["cve"], e["due_date"]) for e in kev.value["listed"])
        epss_max = None
        if epss.status == AssertionStatus.ENRICHED.value:
            epss_max = (epss.value["max"]["cve"], float(epss.value["max"]["epss"]))
        decision = decide(
            inputs.policy,
            PriorityInputs(
                observed_severity=subject.observed_severity,
                kev_listed=kev_listed,
                kev_catalog_version=inputs.kev.catalog_version if inputs.kev else None,
                epss_max=epss_max,
                epss_model_version=inputs.epss.model_version if inputs.epss else None,
                epss_score_date=inputs.epss.score_date if inputs.epss else None,
                unavailable_sources=tuple(
                    a.source for a in row if a.status == AssertionStatus.UNAVAILABLE.value
                ),
            ),
        )
        priorities.append(
            PriorityRecord(
                finding_id=subject.finding_id,
                observed_severity=(subject.observed_severity or "").upper() or "UNKNOWN",
                priority=decision.priority.name,
                rationale=decision.rationale,
                policy_digest=inputs.policy.digest,
            )
        )

    coverage: dict[str, dict[str, Any]] = {}
    statuses: dict[str, Counter[str]] = defaultdict(Counter)
    reasons: dict[str, Counter[str]] = defaultdict(Counter)
    for a in assertions:
        statuses[a.source][a.status] += 1
        if a.status == AssertionStatus.UNAVAILABLE.value and a.reason:
            reasons[a.source][a.reason] += 1
    for source in ALL_SOURCES:
        coverage[source.value] = {
            "ENRICHED": statuses[source.value][AssertionStatus.ENRICHED.value],
            "NOT_APPLICABLE": statuses[source.value][AssertionStatus.NOT_APPLICABLE.value],
            "UNAVAILABLE": dict(sorted(reasons[source.value].items())),
        }

    if not inputs.subjects:
        outcome = PassOutcome.NOTHING_TO_ENRICH
    elif any(a.status == AssertionStatus.UNAVAILABLE.value for a in assertions):
        outcome = PassOutcome.ENRICHMENT_DEGRADED
    elif (inputs.kev is not None and inputs.kev.stale) or (
        inputs.epss is not None and inputs.epss.stale
    ):
        outcome = PassOutcome.ENRICHED_STALE
    else:
        outcome = PassOutcome.ENRICHED

    frozen_assertions, frozen_priorities = tuple(assertions), tuple(priorities)
    return Derivation(
        assertions=frozen_assertions,
        priorities=frozen_priorities,
        outcome=outcome,
        coverage=coverage,
        digest=derivation_digest(frozen_assertions, frozen_priorities),
    )

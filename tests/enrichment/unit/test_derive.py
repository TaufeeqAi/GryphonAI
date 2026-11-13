"""Pure derivation: the status algebra, attribution, outcomes and determinism."""

from __future__ import annotations

import pytest

from gryphon.enrichment.artifacts import KevEntry
from gryphon.enrichment.constants import SNAPSHOTLESS_REASONS, PassOutcome
from gryphon.enrichment.cve import extract_subjects
from gryphon.enrichment.derive import DerivationInputs, EpssView, KevView, derive
from gryphon.enrichment.reference import DatasetUnavailable
from tests.enrichment.conftest import nuclei_finding

pytestmark = pytest.mark.unit

KEV_ID = "KEV:2026.11.12@sha256:" + "a" * 64
EPSS_ID = "EPSS:2026-11-12@sha256:" + "b" * 64


def _kev(listed: tuple[str, ...] = ("CVE-2024-11111",), *, stale: bool = False,
         hold: frozenset[str] = frozenset()) -> KevView:
    return KevView(
        snapshot_id=KEV_ID,
        catalog_version="2026.11.12",
        age_s=600,
        stale=stale,
        listed={c: KevEntry(c, "2026-01-02", "2026-01-23", "Known") for c in listed},
        integrity_hold=hold,
    )


def _epss(scores: dict[str, tuple[float, float]] | None = None, *, stale: bool = False) -> EpssView:
    return EpssView(
        snapshot_id=EPSS_ID,
        score_date="2026-11-12",
        model_version="v2026.06.15",
        age_s=900,
        stale=stale,
        scores=scores if scores is not None else {"CVE-2024-22222": (0.75, 0.97)},
    )


def _inputs(findings, policy, reference, *, kev=..., epss=...) -> DerivationInputs:
    return DerivationInputs(
        subjects=tuple(extract_subjects(findings).subjects),
        kev=_kev() if kev is ... else kev,
        epss=_epss() if epss is ... else epss,
        reference=reference,
        template_snapshot_id="TEMPLATES:unpinned",
        policy=policy,
    )


def _by(derivation, finding_id: str, source: str):
    (row,) = [a for a in derivation.assertions if a.finding_id == finding_id and a.source == source]
    return row


FINDINGS = [
    nuclei_finding("f-kev", cves=["CVE-2024-11111"], severity="low", cvss=9.8),
    nuclei_finding("f-epss", cves=["CVE-2024-22222"], severity="medium"),
    nuclei_finding("f-none", cves=["CVE-2024-33333"], severity="high", cvss="9.8"),
]


def test_every_finding_gets_every_source(policy, reference) -> None:
    derivation = derive(_inputs(FINDINGS, policy, reference))
    assert len(derivation.assertions) == 3 * 4
    assert {p.finding_id for p in derivation.priorities} == {"f-kev", "f-epss", "f-none"}


def test_kev_listed_is_enriched_with_attribution(policy, reference) -> None:
    derivation = derive(_inputs(FINDINGS, policy, reference))
    row = _by(derivation, "f-kev", "KEV")
    assert row.status == "ENRICHED"
    assert row.snapshot_id == KEV_ID and row.asserted_by == "provider_snapshot"
    assert row.snapshot_age_s == 600
    assert row.value["listed"][0]["due_date"] == "2026-01-23"


def test_not_listed_names_the_snapshot_it_was_proven_against(policy, reference) -> None:
    derivation = derive(_inputs(FINDINGS, policy, reference))
    row = _by(derivation, "f-epss", "KEV")
    assert row.status == "NOT_APPLICABLE"
    assert row.reason == f"not_listed@{KEV_ID}"


def test_missing_snapshot_is_unavailable_never_not_applicable(policy, reference) -> None:
    derivation = derive(_inputs(FINDINGS, policy, reference, kev=None, epss=None))
    for finding in ("f-kev", "f-epss", "f-none"):
        for source in ("KEV", "EPSS"):
            row = _by(derivation, finding, source)
            assert row.status == "UNAVAILABLE"
            assert row.reason == "no_accepted_snapshot"
            assert row.snapshot_id is None
    assert derivation.outcome is PassOutcome.ENRICHMENT_DEGRADED
    # Priorities never drop below the observed severity when context is missing.
    assert {p.finding_id: p.priority for p in derivation.priorities}["f-none"] == "HIGH"


def test_integrity_hold_is_unavailable_with_integrity_remediation(policy, reference) -> None:
    held = _kev(listed=(), hold=frozenset({"CVE-2024-33333"}))
    derivation = derive(_inputs(FINDINGS, policy, reference, kev=held))
    row = _by(derivation, "f-none", "KEV")
    assert (row.status, row.reason, row.remediation_class) == (
        "UNAVAILABLE", "integrity_hold", "INTEGRITY",
    )
    assert row.snapshot_id == KEV_ID


def test_epss_reports_max_and_all_scores(policy, reference) -> None:
    findings = [nuclei_finding("f", cves=["CVE-2024-22222", "CVE-2024-22223"])]
    epss = _epss({"CVE-2024-22222": (0.2, 0.5), "CVE-2024-22223": (0.8, 0.99)})
    row = _by(derive(_inputs(findings, policy, reference, epss=epss)), "f", "EPSS")
    assert row.value["max"] == {"cve": "CVE-2024-22223", "epss": 0.8}
    assert len(row.value["scores"]) == 2


def test_cvss_is_template_asserted_and_only_numbers_count(policy, reference) -> None:
    derivation = derive(_inputs(FINDINGS, policy, reference))
    good = _by(derivation, "f-kev", "CVSS_TEMPLATE")
    assert good.status == "ENRICHED" and good.asserted_by == "template"
    assert good.value == {"score": 9.8, "template_id": "synthetic-f-kev"}
    # A string score is not a score.
    assert _by(derivation, "f-none", "CVSS_TEMPLATE").reason == "no_score_in_template"


@pytest.mark.parametrize("raw", [True, float("nan"), float("inf"), -1, 10.5, "7.5", None])
def test_non_scores_are_not_applicable(policy, reference, raw) -> None:
    findings = [nuclei_finding("f", cves=["CVE-2024-11111"], cvss=raw)]
    assert _by(derive(_inputs(findings, policy, reference)), "f", "CVSS_TEMPLATE").status == (
        "NOT_APPLICABLE"
    )


def test_attack_mapping_translates_revoked_techniques(policy, reference) -> None:
    row = _by(derive(_inputs(FINDINGS, policy, reference)), "f-kev", "ATTACK_CTID")
    assert row.status == "ENRICHED"
    techniques = {t["source_technique_id"]: t for t in row.value["techniques"]}
    assert techniques["T1190"]["technique_id"] == "T1190"
    assert techniques["T1001"]["technique_id"] == "T1002"
    assert techniques["T1001"]["translated"] is True


def test_unprovisioned_reference_is_unavailable(policy) -> None:
    derivation = derive(_inputs(FINDINGS, policy, DatasetUnavailable("not provisioned")))
    row = _by(derivation, "f-kev", "ATTACK_CTID")
    assert (row.status, row.reason, row.remediation_class) == (
        "UNAVAILABLE", "dataset_unavailable", "MISCONFIGURED",
    )


def test_snapshotless_rows_match_the_database_check(policy, reference) -> None:
    for kev, epss, ref in [(None, None, DatasetUnavailable("x")), (..., ..., reference)]:
        derivation = derive(_inputs(FINDINGS, policy, ref, kev=kev, epss=epss))
        for row in derivation.assertions:
            if row.snapshot_id is None:
                assert row.reason in SNAPSHOTLESS_REASONS


def test_outcomes(policy, reference) -> None:
    assert derive(_inputs([], policy, reference)).outcome is PassOutcome.NOTHING_TO_ENRICH
    assert derive(_inputs(FINDINGS, policy, reference)).outcome is PassOutcome.ENRICHED
    stale = derive(_inputs(FINDINGS, policy, reference, kev=_kev(stale=True)))
    assert stale.outcome is PassOutcome.ENRICHED_STALE
    degraded = derive(_inputs(FINDINGS, policy, reference, epss=None))
    assert degraded.outcome is PassOutcome.ENRICHMENT_DEGRADED


def test_priorities_follow_policy(policy, reference) -> None:
    priorities = {p.finding_id: p for p in derive(_inputs(FINDINGS, policy, reference)).priorities}
    assert priorities["f-kev"].priority == "CRITICAL"
    assert priorities["f-epss"].priority == "HIGH"
    assert priorities["f-none"].priority == "HIGH"
    assert priorities["f-kev"].policy_digest == policy.digest


def test_derivation_is_deterministic_and_order_independent(policy, reference) -> None:
    a = derive(_inputs(FINDINGS, policy, reference))
    b = derive(_inputs(list(reversed(FINDINGS)), policy, reference))
    assert a.digest == b.digest
    assert a.assertions == b.assertions


def test_coverage_counts(policy, reference) -> None:
    coverage = derive(_inputs(FINDINGS, policy, reference, epss=None)).coverage
    assert coverage["KEV"]["ENRICHED"] == 1 and coverage["KEV"]["NOT_APPLICABLE"] == 2
    assert coverage["EPSS"]["UNAVAILABLE"] == {"no_accepted_snapshot": 3}

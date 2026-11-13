"""Offline self-checks with deterministic synthetic data.

Used by ``scripts/verify_enrichment.py`` (and by the test suite) to answer
"does this build enforce what it claims?" without a network or a database:
acceptance proves completeness and rejects truncation and shrinkage, the
normalized grammar round-trips, the policy is monotone, derivation is
deterministic and ignores template tags, and attestations verify and detect
tampering. Every check names what it proves.

Synthetic data only: filler CVE ids use the far-future years 2098/2099, and the
handful of scenario ids are chosen per check. Nothing here is real intelligence
and nothing here is ever written to a database or the artifact store.
"""

from __future__ import annotations

import gzip
import io
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from gryphon.auth.key_provider import Ed25519SigningKey, TrustedKeyStore
from gryphon.enrichment.acquisition.acceptance import (
    AcceptanceRejected,
    LastAccepted,
    accept_epss,
    accept_kev,
)
from gryphon.enrichment.artifacts import parse_epss_normalized, parse_kev_normalized
from gryphon.enrichment.audit import EnrichmentAuditBuilder, verify_event
from gryphon.enrichment.constants import EPSS_MIN_ROWS, KEV_MIN_COUNT, PassOutcome
from gryphon.enrichment.cve import extract_subjects, normalize_cve_ids
from gryphon.enrichment.derive import DerivationInputs, EpssView, KevView, derive
from gryphon.enrichment.policy import Policy, PriorityInputs, decide, load_policy
from gryphon.enrichment.reference import ReferenceData

SYNTHETIC_MODEL = "v2026.06.15"


# -----------------------------------------------------------------------------
# Synthetic fixtures
# -----------------------------------------------------------------------------
def synthetic_kev_entry(
    cve: str, *, date_added: str = "2026-01-02", due: str = "2026-01-23"
) -> dict[str, Any]:
    return {
        "cveID": cve,
        "vendorProject": "Example",
        "product": "Example Product",
        "vulnerabilityName": f"Synthetic vulnerability {cve}",
        "dateAdded": date_added,
        "shortDescription": "Synthetic entry for self-verification.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": due,
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "",
        "cwes": [],
    }


def synthetic_kev_catalog(
    count: int = KEV_MIN_COUNT,
    *,
    catalog_version: str = "2026.11.12",
    date_released: str = "2026-11-12T15:00:00.000Z",
    include: tuple[str, ...] = (),
    declared_count: int | None = None,
) -> bytes:
    cves = list(include) + [f"CVE-2099-{n:05d}" for n in range(1, count - len(include) + 1)]
    document = {
        "title": "Synthetic Known Exploited Vulnerabilities Catalog",
        "catalogVersion": catalog_version,
        "dateReleased": date_released,
        "count": len(cves) if declared_count is None else declared_count,
        "vulnerabilities": [synthetic_kev_entry(c) for c in cves],
    }
    return json.dumps(document).encode("utf-8")


def synthetic_epss_file(
    rows: int = EPSS_MIN_ROWS,
    *,
    model_version: str = SYNTHETIC_MODEL,
    score_date: str = "2026-11-12",
    overrides: dict[str, tuple[float, float]] | None = None,
) -> bytes:
    overrides = dict(overrides or {})
    buffer = io.StringIO()
    buffer.write(f"#model_version:{model_version},score_date:{score_date}T12:00:25Z\n")
    buffer.write("cve,epss,percentile\n")
    for cve, (epss, pct) in sorted(overrides.items()):
        buffer.write(f"{cve},{epss:.5f},{pct:.5f}\n")
    for n in range(1, rows - len(overrides) + 1):
        buffer.write(f"CVE-2098-{n:06d},0.00043,0.12000\n")
    return gzip.compress(buffer.getvalue().encode("ascii"), mtime=0)


def ephemeral_signer(
    kid: str = "enrichment-selfcheck",
) -> tuple[Ed25519SigningKey, TrustedKeyStore]:
    private = ed25519.Ed25519PrivateKey.generate()
    signer = Ed25519SigningKey(kid=kid, _private=private)
    return signer, TrustedKeyStore({kid: private.public_key()})


def tiny_reference(mappings: dict[str, list[list[str]]] | None = None) -> ReferenceData:
    """A minimal in-memory reference with one revoked-by chain (T1001 → T1002)."""
    return ReferenceData(
        attack_version="20.1",
        mapping_version="selfcheck-map",
        kev_version="selfcheck",
        source_attack_version="16.1",
        snapshot_id="CTID_KEV_MAP:selfcheck-map@sha256:" + "0" * 64 + "+ATTACK_BUNDLE:20.1",
        attack_sha256="0" * 64,
        ctid_sha256="0" * 64,
        _techniques={
            "T1190": {"name": "Exploit Public-Facing Application", "stix_id": "attack-pattern--a",
                      "revoked": False, "deprecated": False},
            "T1001": {"name": "Old", "stix_id": "attack-pattern--old", "revoked": True,
                      "deprecated": False},
            "T1002": {"name": "New", "stix_id": "attack-pattern--new", "revoked": False,
                      "deprecated": False},
        },
        _stix_to_ext={"attack-pattern--a": "T1190", "attack-pattern--old": "T1001",
                      "attack-pattern--new": "T1002"},
        _revoked_by={"attack-pattern--old": "attack-pattern--new"},
        _mappings=mappings
        if mappings is not None
        else {"CVE-2024-11111": [["T1190", "exploitation_technique"], ["T1001", "primary_impact"]]},
    )


# -----------------------------------------------------------------------------
# Checks
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class SelfCheck:
    name: str
    proves: str
    passed: bool
    detail: str = ""
    #: A check that could not be performed here. Reported as SKIP, never as PASS.
    skipped: bool = False


def _expect_rejected(fn: Callable[[], object]) -> str | None:
    try:
        fn()
    except AcceptanceRejected as exc:
        return exc.reason
    return None


def check_kev_acceptance() -> list[SelfCheck]:
    catalog = synthetic_kev_catalog()
    accepted = accept_kev(catalog, None)
    entries = parse_kev_normalized(accepted.normalized)
    results = [
        SelfCheck(
            "kev_complete_catalog_accepted",
            "a complete catalog is accepted and its normalized form re-parses strictly",
            accepted.entry_count == KEV_MIN_COUNT and len(entries) == KEV_MIN_COUNT,
            accepted.label,
        )
    ]
    truncated = synthetic_kev_catalog(declared_count=KEV_MIN_COUNT + 5)
    reason = _expect_rejected(lambda: accept_kev(truncated, None))
    results.append(
        SelfCheck("kev_count_mismatch_rejected", "a catalog missing entries is rejected",
                  reason is not None, reason or "accepted!")
    )
    last = LastAccepted(label="2026.11.12", order_key=accepted.order_key,
                        entry_count=KEV_MIN_COUNT * 2, byte_size=len(catalog))
    reason = _expect_rejected(
        lambda: accept_kev(synthetic_kev_catalog(date_released="2026-11-13T00:00:00Z"), last)
    )
    results.append(
        SelfCheck("kev_shrinkage_rejected", "a catalog that shrank beyond the bound is rejected",
                  reason is not None, reason or "accepted!")
    )
    older = LastAccepted(label="2026.11.13", order_key="2026-11-13T00:00:00.000000Z|2026.11.13",
                         entry_count=KEV_MIN_COUNT, byte_size=len(catalog))
    reason = _expect_rejected(lambda: accept_kev(catalog, older))
    results.append(
        SelfCheck("kev_rollback_rejected", "a catalog older than the last accepted is rejected",
                  reason is not None, reason or "accepted!")
    )
    return results


def check_epss_acceptance() -> list[SelfCheck]:
    data = synthetic_epss_file(overrides={"CVE-2024-11111": (0.91234, 0.99)})
    accepted = accept_epss(data, None)
    scores = parse_epss_normalized(accepted.normalized, frozenset({"CVE-2024-11111"}))
    results = [
        SelfCheck(
            "epss_complete_file_accepted",
            "a complete daily file is accepted with its model version and score date",
            accepted.entry_count == EPSS_MIN_ROWS
            and accepted.meta["model_version"] == SYNTHETIC_MODEL
            and scores == {"CVE-2024-11111": (0.91234, 0.99)},
            accepted.order_key,
        )
    ]
    reason = _expect_rejected(lambda: accept_epss(data[: len(data) // 2], None))
    results.append(
        SelfCheck("epss_truncated_stream_rejected", "a truncated gzip stream is rejected",
                  reason is not None, reason or "accepted!")
    )
    short = synthetic_epss_file(rows=EPSS_MIN_ROWS - 1)
    reason = _expect_rejected(lambda: accept_epss(short, None))
    results.append(
        SelfCheck("epss_row_floor_enforced", "a file below the row floor is rejected",
                  reason is not None, reason or "accepted!")
    )
    return results


def check_policy(policy: Policy) -> list[SelfCheck]:
    def run(
        sev: str, *, kev: bool = False, epss: float | None = None,
        model: str = SYNTHETIC_MODEL,
    ) -> str:
        return decide(
            policy,
            PriorityInputs(
                observed_severity=sev,
                kev_listed=(("CVE-2024-11111", "2026-01-23"),) if kev else (),
                kev_catalog_version="2026.11.12",
                epss_max=("CVE-2024-11111", epss) if epss is not None else None,
                epss_model_version=model,
                epss_score_date="2026-11-12",
            ),
        ).priority.name

    cases = {
        "KEV-listed LOW becomes CRITICAL": (run("low", kev=True), "CRITICAL"),
        "EPSS 0.71 (calibrated) MEDIUM becomes HIGH": (run("medium", epss=0.71), "HIGH"),
        "EPSS 0.70 is not above the threshold": (run("medium", epss=0.70), "MEDIUM"),
        "an uncalibrated model never elevates": (run("medium", epss=0.99, model="v9999"), "MEDIUM"),
        "a low EPSS never lowers CRITICAL": (run("critical", epss=0.01), "CRITICAL"),
        "an unrecognized severity floors at LOW": (run("bogus"), "LOW"),
    }
    failed = [name for name, (got, want) in cases.items() if got != want]
    return [
        SelfCheck(
            "policy_golden_cases",
            "the priority policy elevates per the plan and never lowers",
            not failed,
            "all cases hold" if not failed else "failed: " + "; ".join(failed),
        )
    ]


def _report_findings() -> list[dict[str, Any]]:
    return [
        {
            "finding_id": "f-kev",
            "severity": "low",
            "observation": {
                "template_id": "synthetic-kev",
                "cve_ids": ["cve-2024-11111"],
                "cvss_score": 9.8,
                "tags": ["cve", "CVE-2024-99999"],
            },
        },
        {
            "finding_id": "f-split",
            "severity": "medium",
            # The upstream parser's list() of a scalar string.
            "observation": {"template_id": "synthetic-split", "cve_ids": list("CVE-2024-22222")},
        },
        {"finding_id": "f-port", "severity": None, "observation": {"port": 443}},
    ]


def check_derivation(policy: Policy) -> list[SelfCheck]:
    extraction = extract_subjects(_report_findings())
    kev_listed = parse_kev_normalized(
        accept_kev(synthetic_kev_catalog(include=("CVE-2024-11111",)), None).normalized,
        extraction.distinct_cves,
    )
    inputs = DerivationInputs(
        subjects=tuple(extraction.subjects),
        kev=KevView("KEV:2026.11.12@sha256:" + "a" * 64, "2026.11.12", 3600, False, kev_listed),
        epss=EpssView("EPSS:2026-11-12@sha256:" + "b" * 64, "2026-11-12", SYNTHETIC_MODEL, 3600,
                      False, {"CVE-2024-22222": (0.75, 0.97)}),
        reference=tiny_reference(),
        template_snapshot_id="TEMPLATES:unpinned",
        policy=policy,
    )
    first, second = derive(inputs), derive(inputs)
    priorities = {p.finding_id: p.priority for p in first.priorities}
    tags_ignored = "CVE-2024-99999" not in extraction.distinct_cves
    return [
        SelfCheck(
            "extraction_reads_only_cve_ids",
            "subjects come from observation.cve_ids only; template tags are never read",
            tags_ignored and extraction.distinct_cves == {"CVE-2024-11111", "CVE-2024-22222"},
            ", ".join(sorted(extraction.distinct_cves)),
        ),
        SelfCheck(
            "derivation_deterministic",
            "the same pinned inputs produce the same rows and digest",
            first.digest == second.digest and first.outcome is PassOutcome.ENRICHED,
            first.digest[:16],
        ),
        SelfCheck(
            "derivation_elevates_per_policy",
            "KEV-listed → CRITICAL, calibrated EPSS > 0.70 → HIGH",
            priorities == {"f-kev": "CRITICAL", "f-split": "HIGH"},
            json.dumps(priorities, sort_keys=True),
        ),
    ]


def check_extraction_normalization() -> list[SelfCheck]:
    valid, rejected = normalize_cve_ids(["cve-2021-44228", " CVE-2021-44228 ", "CVE-21-1", 7])
    return [
        SelfCheck(
            "extraction_normalizes_and_counts",
            "case and whitespace are normalized, duplicates collapse, rejects are counted",
            valid == ["CVE-2021-44228"]
            and rejected == {"invalid_cve_format": 1, "non_string_value": 1},
            json.dumps({"valid": valid, "rejected": dict(rejected)}, sort_keys=True),
        )
    ]


def check_attestation() -> list[SelfCheck]:
    signer, trust = ephemeral_signer()
    event = EnrichmentAuditBuilder(signer).report_emitted(
        scan_run_id="00000000-0000-4000-8000-000000000000",
        pass_id="selfcheck",  # noqa: S106 - an identifier, not a secret
        report_id="00000000-enr-selfcheck",
        report_digest="c" * 64,
        derivations_digest="d" * 64,
        manifest_digest="e" * 64,
        base_report_digest="f" * 64,
        outcome="ENRICHED",
        initiated_by="selfcheck",
        timestamp=datetime(2026, 11, 13, tzinfo=UTC),
    )
    ok = verify_event(payload=event.payload, payload_digest=event.payload_digest,
                      signer_kid=event.signer_kid, signature_b64=event.signature_b64, trust=trust)
    tampered = dict(event.payload, outcome="ENRICHMENT_DEGRADED")
    detected = not verify_event(payload=tampered, payload_digest=event.payload_digest,
                                signer_kid=event.signer_kid, signature_b64=event.signature_b64,
                                trust=trust)
    _, other_trust = ephemeral_signer()
    foreign = not verify_event(payload=event.payload, payload_digest=event.payload_digest,
                               signer_kid=event.signer_kid, signature_b64=event.signature_b64,
                               trust=other_trust)
    return [
        SelfCheck(
            "attestation_verifies_and_detects_tamper",
            "a signed report attestation verifies; an edit or an untrusted key does not",
            ok and detected and foreign,
            f"verify={ok} tamper_detected={detected} untrusted_rejected={foreign}",
        )
    ]


def run_selfchecks(policy: Policy | None = None) -> list[SelfCheck]:
    active = policy or load_policy()
    checks: list[SelfCheck] = []
    for fn in (
        check_kev_acceptance,
        check_epss_acceptance,
        check_extraction_normalization,
        check_attestation,
    ):
        checks.extend(fn())
    checks.extend(check_policy(active))
    checks.extend(check_derivation(active))
    return checks

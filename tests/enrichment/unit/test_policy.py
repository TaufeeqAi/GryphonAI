"""Policy v1: per-plan elevation, monotone, identified by its digest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.enrichment.constants import Severity
from gryphon.enrichment.policy import DEFAULT_POLICY_PATH, PriorityInputs, decide, load_policy
from gryphon.enrichment.reasons import EnrichmentConfigurationError

pytestmark = pytest.mark.unit

MODEL = "v2026.06.15"


def _inputs(sev: str | None, *, kev: bool = False, epss: float | None = None,
            model: str = MODEL, unavailable: tuple[str, ...] = ()) -> PriorityInputs:
    return PriorityInputs(
        observed_severity=sev,
        kev_listed=(("CVE-2021-44228", "2021-12-24"),) if kev else (),
        kev_catalog_version="2026.11.12",
        epss_max=("CVE-2021-44228", epss) if epss is not None else None,
        epss_model_version=model,
        epss_score_date="2026-11-12",
        unavailable_sources=unavailable,
    )


def test_policy_identity_is_the_canonical_digest(policy) -> None:
    document = json.loads(DEFAULT_POLICY_PATH.read_bytes())
    assert policy.digest == sha256_hex(canonical_json_bytes(document))
    assert policy.label == "v1"
    assert policy.epss_threshold == 0.70
    assert MODEL in policy.calibrated_models


def test_editing_the_file_is_a_new_policy(tmp_path: Path, policy) -> None:
    document = json.loads(DEFAULT_POLICY_PATH.read_bytes())
    document["rules"]["EPSS_HIGH"]["threshold_exclusive"] = 0.8
    edited = tmp_path / "policy.json"
    edited.write_text(json.dumps(document))
    assert load_policy(edited).digest != policy.digest


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["rules"]["KEV_LISTED"].update(set_priority="HIGH"),
        lambda d: d["rules"]["EPSS_HIGH"].update(threshold_exclusive=1.5),
        lambda d: d["rules"].pop("EPSS_HIGH"),
    ],
)
def test_invalid_policies_are_refused(tmp_path: Path, mutate) -> None:
    document = json.loads(DEFAULT_POLICY_PATH.read_bytes())
    mutate(document)
    bad = tmp_path / "policy.json"
    bad.write_text(json.dumps(document))
    with pytest.raises(EnrichmentConfigurationError):
        load_policy(bad)


def test_kev_listed_is_critical_with_named_reason(policy) -> None:
    decision = decide(policy, _inputs("low", kev=True))
    assert decision.priority is Severity.CRITICAL
    (kev,) = [r for r in decision.rationale if r["rule"] == "KEV_LISTED"]
    assert "CVE-2021-44228" in kev["text"] and "2026.11.12" in kev["text"]


def test_epss_above_threshold_is_at_least_high(policy) -> None:
    decision = decide(policy, _inputs("medium", epss=0.7001))
    assert decision.priority is Severity.HIGH
    assert decision.rationale[0]["rule"] == "EPSS_HIGH"
    assert "70.0%" in decision.rationale[0]["text"]


def test_threshold_is_exclusive(policy) -> None:
    assert decide(policy, _inputs("medium", epss=0.70)).priority is Severity.MEDIUM


def test_uncalibrated_model_is_recorded_and_never_elevates(policy) -> None:
    decision = decide(policy, _inputs("low", epss=0.99, model="v2099.01.01"))
    assert decision.priority is Severity.LOW
    assert decision.rationale[0]["rule"] == "EPSS_UNCALIBRATED"


def test_kev_takes_precedence_over_epss(policy) -> None:
    decision = decide(policy, _inputs("low", kev=True, epss=0.99))
    assert [r["rule"] for r in decision.rationale] == ["KEV_LISTED"]


def test_unavailable_context_is_named_but_never_lowers(policy) -> None:
    decision = decide(policy, _inputs("high", unavailable=("KEV", "EPSS")))
    assert decision.priority is Severity.HIGH
    assert [r["rule"] for r in decision.rationale] == [
        "CONTEXT_UNAVAILABLE", "CONTEXT_UNAVAILABLE", "FLOOR",
    ]


def test_unrecognized_severity_floors_at_low_and_says_so(policy) -> None:
    decision = decide(policy, _inputs("informational"))
    assert decision.priority is Severity.LOW
    assert decision.rationale[0]["rule"] == "FLOOR"
    assert "unrecognized" in decision.rationale[0]["text"]


@given(
    sev=st.sampled_from(["low", "medium", "high", "critical", "info", None, "HIGH "]),
    kev=st.booleans(),
    epss=st.one_of(st.none(), st.floats(min_value=0.0, max_value=1.0)),
    calibrated=st.booleans(),
)
def test_priority_is_monotone_never_below_observed(policy, sev, kev, epss, calibrated) -> None:
    observed, _ = Severity.parse(sev)
    decision = decide(policy, _inputs(sev, kev=kev, epss=epss,
                                      model=MODEL if calibrated else "v0"))
    assert decision.priority >= observed
    assert decision.priority <= Severity.CRITICAL
    assert decision.rationale, "every decision names at least one reason"
    # Raising an input never lowers the outcome.
    raised = decide(policy, _inputs(sev, kev=True, epss=epss, model=MODEL))
    assert raised.priority >= decision.priority

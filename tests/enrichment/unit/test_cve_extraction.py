"""CVE subject extraction: one source field, normalized, every reject counted."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gryphon.enrichment.constants import MAX_CVES_PER_FINDING, MAX_CVES_PER_PASS
from gryphon.enrichment.cve import extract_subjects, normalize_cve_ids
from tests.enrichment.conftest import nuclei_finding

pytestmark = pytest.mark.unit


def test_lowercase_and_whitespace_are_normalized() -> None:
    valid, rejected = normalize_cve_ids(["cve-2021-44228", "  CVE-2023-4863\t"])
    assert valid == ["CVE-2021-44228", "CVE-2023-4863"]
    assert not rejected


def test_list_of_single_characters_is_rejoined() -> None:
    # The upstream parser applies list() to a scalar ``cve-id``.
    valid, rejected = normalize_cve_ids(list("CVE-2021-44228"))
    assert valid == ["CVE-2021-44228"]
    assert not rejected


def test_scalar_string_is_accepted() -> None:
    assert normalize_cve_ids("CVE-2021-44228")[0] == ["CVE-2021-44228"]


@pytest.mark.parametrize(
    "value",
    [
        "CVE-21-1", "CVE-2021-123", "CVE-2021-12345678", "CVE-1998-1234", "GHSA-xxxx",
        "CVE-2021-44228x",
    ],
)
def test_malformed_ids_are_rejected_and_counted(value: str) -> None:
    valid, rejected = normalize_cve_ids([value])
    assert valid == []
    assert rejected["invalid_cve_format"] == 1


def test_non_strings_and_oversized_values_are_counted() -> None:
    valid, rejected = normalize_cve_ids([7, None, "CVE-2021-44228", "C" * 65])
    assert valid == ["CVE-2021-44228"]
    assert rejected == {"non_string_value": 2, "oversized_value": 1}


def test_duplicates_collapse_preserving_first_seen_order() -> None:
    valid, _ = normalize_cve_ids(["CVE-2022-0002", "cve-2022-0001", "CVE-2022-0002"])
    assert valid == ["CVE-2022-0002", "CVE-2022-0001"]


def test_per_finding_cap_is_enforced_and_counted() -> None:
    ids = [f"CVE-2020-{n:05d}" for n in range(MAX_CVES_PER_FINDING + 3)]
    valid, rejected = normalize_cve_ids(ids)
    assert len(valid) == MAX_CVES_PER_FINDING
    assert rejected["finding_cap_exceeded"] == 3


def test_only_cve_ids_is_a_source_never_tags_or_urls() -> None:
    finding = nuclei_finding("f1", cves=[], tags=("cve", "CVE-2021-44228"))
    finding["url"] = "https://app.example.com/?CVE-2021-44228"
    finding["observation"]["matched_url"] = finding["url"]
    result = extract_subjects([finding])
    assert result.subjects == []
    assert result.findings_without_cves == 1


def test_malformed_observation_is_counted_not_crashing() -> None:
    finding = nuclei_finding("f1", cves=["CVE-2021-44228"])
    finding["observation"] = ["not", "a", "dict"]
    result = extract_subjects([finding])
    assert result.subjects == []
    assert result.rejected["malformed_observation"] == 1


def test_subject_carries_severity_template_and_score() -> None:
    finding = nuclei_finding("f1", cves=["CVE-2021-44228"], severity="high", cvss=9.8)
    result = extract_subjects([finding])
    (subject,) = result.subjects
    assert subject.finding_id == "f1"
    assert subject.observed_severity == "high"
    assert subject.template_id == "synthetic-f1"
    assert subject.cvss_score == 9.8
    assert result.as_payload()["cve_subjects"] == 1


def test_pass_cap_counts_overflow() -> None:
    findings = [
        nuclei_finding(f"f{n}", cves=[f"CVE-2020-{n * 2:05d}", f"CVE-2020-{n * 2 + 1:05d}"])
        for n in range(MAX_CVES_PER_PASS // 2 + 2)
    ]
    result = extract_subjects(findings)
    assert len(result.distinct_cves) == MAX_CVES_PER_PASS
    assert result.rejected["pass_cap_exceeded"] == 4


@given(st.lists(st.one_of(st.text(max_size=80), st.integers(), st.none()), max_size=50))
def test_normalization_never_raises_and_outputs_are_canonical(raw: list) -> None:
    valid, rejected = normalize_cve_ids(raw)
    assert len(valid) <= MAX_CVES_PER_FINDING
    assert len(set(valid)) == len(valid)
    for cve in valid:
        assert cve == cve.strip().upper() and cve.startswith("CVE-")
    assert all(count > 0 for count in rejected.values())

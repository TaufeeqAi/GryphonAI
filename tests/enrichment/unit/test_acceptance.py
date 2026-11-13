"""Acceptance proves a snapshot complete — or rejects it and writes nothing."""

from __future__ import annotations

import gzip
import json

import pytest

from gryphon.enrichment.acquisition.acceptance import (
    AcceptanceRejected,
    LastAccepted,
    accept_epss,
    accept_kev,
)
from gryphon.enrichment.artifacts import parse_epss_normalized, parse_kev_normalized, parse_meta
from gryphon.enrichment.constants import EPSS_MIN_ROWS, KEV_MIN_COUNT
from gryphon.enrichment.selfcheck import (
    synthetic_epss_file,
    synthetic_kev_catalog,
    synthetic_kev_entry,
)

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def epss_file() -> bytes:
    return synthetic_epss_file(overrides={"CVE-2021-44228": (0.94358, 0.99961)})


def _kev_doc(**overrides) -> dict:
    document = json.loads(synthetic_kev_catalog())
    document.update(overrides)
    return document


# -- KEV ---------------------------------------------------------------------
def test_complete_catalog_is_accepted_and_normalized() -> None:
    accepted = accept_kev(synthetic_kev_catalog(include=("CVE-2021-44228",)), None)
    assert accepted.source == "KEV"
    assert accepted.label == "2026.11.12"
    assert accepted.order_key.startswith("2026-11-12T15:00:00.000000Z|")
    entries = parse_kev_normalized(accepted.normalized)
    assert len(entries) == KEV_MIN_COUNT
    assert entries["CVE-2021-44228"].due_date == "2026-01-23"
    meta = parse_meta(accepted.meta_bytes(), "KEV")
    assert meta["entry_count"] == KEV_MIN_COUNT


def test_gzip_catalog_is_accepted() -> None:
    raw = gzip.compress(synthetic_kev_catalog(), mtime=0)
    assert accept_kev(raw, None).entry_count == KEV_MIN_COUNT


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda d: d.update(count=d["count"] + 1), "does not match"),
        (lambda d: d.pop("catalogVersion"), "catalogVersion"),
        (lambda d: d.update(count="1000"), "count"),
        (
            lambda d: d.update(vulnerabilities=d["vulnerabilities"][:10], count=10),
            "below the floor",
        ),
        (lambda d: d["vulnerabilities"][3].pop("dueDate"), "dueDate"),
        (lambda d: d["vulnerabilities"][3].update(cveID="CVE-21-1"), "invalid cveID"),
        (lambda d: d["vulnerabilities"][3].update(dateAdded="03/04/2026"), "YYYY-MM-DD"),
        (
            lambda d: d["vulnerabilities"].__setitem__(5, dict(d["vulnerabilities"][4])),
            "duplicate cveID",
        ),
        (lambda d: d.update(dateReleased="yesterday"), "ISO-8601"),
    ],
)
def test_malformed_catalogs_are_rejected(mutate, reason: str) -> None:
    document = json.loads(synthetic_kev_catalog())
    mutate(document)
    with pytest.raises(AcceptanceRejected, match=reason):
        accept_kev(json.dumps(document).encode(), None)


def test_non_finite_constants_are_rejected() -> None:
    raw = synthetic_kev_catalog().replace(b'"count": 1000', b'"count": NaN')
    with pytest.raises(AcceptanceRejected):
        accept_kev(raw, None)


def test_shrinkage_beyond_bound_is_rejected() -> None:
    first = accept_kev(synthetic_kev_catalog(count=1100), None)
    last = LastAccepted(first.label, first.order_key, first.entry_count, first.byte_size)
    newer = synthetic_kev_catalog(count=1070, date_released="2026-11-13T15:00:00Z")
    with pytest.raises(AcceptanceRejected, match="shrank"):
        accept_kev(newer, last)
    # Within the 2% bound the newer catalog is fine.
    ok = synthetic_kev_catalog(count=1080, date_released="2026-11-13T15:00:00Z")
    assert accept_kev(ok, last).entry_count == 1080


def test_rollback_is_rejected() -> None:
    newer = accept_kev(synthetic_kev_catalog(date_released="2026-11-13T15:00:00Z"), None)
    last = LastAccepted(newer.label, newer.order_key, newer.entry_count, newer.byte_size)
    with pytest.raises(AcceptanceRejected, match="older"):
        accept_kev(synthetic_kev_catalog(), last)


def test_growth_beyond_bound_is_rejected() -> None:
    accepted = accept_kev(synthetic_kev_catalog(), None)
    last = LastAccepted(accepted.label, accepted.order_key, accepted.entry_count, 1000)
    with pytest.raises(AcceptanceRejected, match="grew"):
        accept_kev(synthetic_kev_catalog(), last)


def test_normalized_form_is_order_independent() -> None:
    document = json.loads(synthetic_kev_catalog())
    shuffled = dict(document, vulnerabilities=list(reversed(document["vulnerabilities"])))
    a = accept_kev(json.dumps(document).encode(), None)
    b = accept_kev(json.dumps(shuffled).encode(), None)
    assert a.normalized_sha256 == b.normalized_sha256
    assert a.content_sha256 != b.content_sha256


def test_oversized_ransomware_field_is_blanked_not_trusted() -> None:
    document = json.loads(synthetic_kev_catalog())
    document["vulnerabilities"][0] = dict(
        synthetic_kev_entry(document["vulnerabilities"][0]["cveID"]),
        knownRansomwareCampaignUse="x" * 500,
    )
    accepted = accept_kev(json.dumps(document).encode(), None)
    entry = parse_kev_normalized(accepted.normalized)[document["vulnerabilities"][0]["cveID"]]
    assert entry.known_ransomware_campaign_use == ""


# -- EPSS --------------------------------------------------------------------
def test_complete_epss_file_is_accepted(epss_file: bytes) -> None:
    accepted = accept_epss(epss_file, None)
    assert accepted.label == "2026-11-12"
    assert accepted.meta["model_version"] == "v2026.06.15"
    assert accepted.entry_count == EPSS_MIN_ROWS
    scores = parse_epss_normalized(accepted.normalized, frozenset({"CVE-2021-44228"}))
    assert scores == {"CVE-2021-44228": (0.94358, 0.99961)}


def test_epss_must_be_gzip() -> None:
    with pytest.raises(AcceptanceRejected, match="not gzip"):
        accept_epss(b"cve,epss,percentile\n", None)


def test_truncated_gzip_is_rejected(epss_file: bytes) -> None:
    with pytest.raises(AcceptanceRejected, match="truncated"):
        accept_epss(epss_file[:-20], None)


def test_trailing_data_is_rejected(epss_file: bytes) -> None:
    with pytest.raises(AcceptanceRejected, match="trailing"):
        accept_epss(epss_file + b"junk", None)


@pytest.mark.parametrize(
    ("header", "reason"),
    [
        ("#score_date:2026-11-12", "header"),
        ("#model_version:v2026.06.15,score_date:12/11/2026", "header"),
    ],
)
def test_bad_header_is_rejected(header: str, reason: str) -> None:
    raw = gzip.compress(f"{header}\ncve,epss,percentile\nCVE-2021-44228,0.9,0.9\n".encode())
    with pytest.raises(AcceptanceRejected, match=reason):
        accept_epss(raw, None)


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        ("CVE-2021-44228,1.5,0.9", "probability"),
        ("CVE-2021-44228,nan,0.9", "probability"),
        ("CVE-2021-44228,abc,0.9", "not a number"),
        ("CVE-2021-44228,0.1", "3 fields"),
        ("cve-2021-44228,0.1,0.2", "invalid cve"),
    ],
)
def test_bad_rows_are_rejected(row: str, reason: str) -> None:
    text = f"#model_version:v1,score_date:2026-11-12\ncve,epss,percentile\n{row}\n"
    with pytest.raises(AcceptanceRejected, match=reason):
        accept_epss(gzip.compress(text.encode()), None)


def test_wrong_columns_are_rejected() -> None:
    text = "#model_version:v1,score_date:2026-11-12\ncve,percentile,epss\n"
    with pytest.raises(AcceptanceRejected, match="columns"):
        accept_epss(gzip.compress(text.encode() + b"CVE-2021-44228,0.1,0.2\n"), None)


def test_epss_rollback_and_shrinkage_are_rejected(epss_file: bytes) -> None:
    accepted = accept_epss(epss_file, None)
    later = LastAccepted(
        "2026-11-13", "2026-11-13|v2026.06.15", accepted.entry_count, len(epss_file)
    )
    with pytest.raises(AcceptanceRejected, match="older"):
        accept_epss(epss_file, later)
    bigger = LastAccepted("2026-11-11", "x", accepted.entry_count * 2, len(epss_file))
    with pytest.raises(AcceptanceRejected, match="shrank"):
        accept_epss(epss_file, bigger)

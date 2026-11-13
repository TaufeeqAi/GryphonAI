"""Content-addressed artifact store and the strict normalized grammars."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from gryphon.enrichment.artifacts import (
    ArtifactStore,
    kev_cve_set,
    parse_epss_normalized,
    parse_kev_normalized,
    parse_meta,
)
from gryphon.enrichment.reasons import ArtifactIntegrityError

pytestmark = pytest.mark.unit


def _kev_line(cve: str, **overrides: str) -> str:
    row = {"cve": cve, "date_added": "2026-01-02", "due_date": "2026-01-23",
           "known_ransomware_campaign_use": "Unknown", **overrides}
    return json.dumps(row, sort_keys=True, separators=(",", ":"))


def _kev(*lines: str) -> bytes:
    return ("\n".join(lines) + "\n").encode("ascii")


# -- store ---------------------------------------------------------------------
def test_put_and_read_verified(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "store")
    source = tmp_path / "blob"
    source.write_bytes(b"hello")
    digest = hashlib.sha256(b"hello").hexdigest()
    target = store.put_file(source, digest)
    assert target == store.path_for(digest)
    assert store.read_verified(digest) == b"hello"
    # Idempotent.
    assert store.put_file(source, digest) == target


def test_put_rejects_wrong_digest(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    source = tmp_path / "blob"
    source.write_bytes(b"hello")
    with pytest.raises(ArtifactIntegrityError, match="mismatch"):
        store.put_file(source, "0" * 64)


def test_read_detects_corruption_and_absence(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    source = tmp_path / "blob"
    source.write_bytes(b"hello")
    digest = hashlib.sha256(b"hello").hexdigest()
    store.put_file(source, digest)
    store.path_for(digest).write_bytes(b"tampered")
    with pytest.raises(ArtifactIntegrityError, match="does not match"):
        store.read_verified(digest)
    with pytest.raises(ArtifactIntegrityError, match="missing"):
        store.read_verified("1" * 64)


@pytest.mark.parametrize("digest", ["../etc/passwd", "ABC", "0" * 63, "g" * 64])
def test_path_for_refuses_non_digests(tmp_path: Path, digest: str) -> None:
    with pytest.raises(ArtifactIntegrityError):
        ArtifactStore(tmp_path).path_for(digest)


def test_staging_dirs_are_unique(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    assert store.staging_dir() != store.staging_dir()


# -- KEV grammar -----------------------------------------------------------------
def test_kev_parse_filters_by_wanted() -> None:
    data = _kev(_kev_line("CVE-2020-0001"), _kev_line("CVE-2021-44228"))
    assert set(parse_kev_normalized(data)) == {"CVE-2020-0001", "CVE-2021-44228"}
    assert set(parse_kev_normalized(data, frozenset({"CVE-2021-44228"}))) == {"CVE-2021-44228"}
    assert kev_cve_set(data) == {"CVE-2020-0001", "CVE-2021-44228"}


@pytest.mark.parametrize(
    "data",
    [
        _kev(_kev_line("CVE-2021-44228"), _kev_line("CVE-2020-0001")),  # unsorted
        _kev(_kev_line("CVE-2021-44228"), _kev_line("CVE-2021-44228")),  # duplicate
        _kev(_kev_line("CVE-2021-44228"))[:-1],  # no trailing newline
        _kev(_kev_line("CVE-2021-44228", due_date="tomorrow")),
        _kev(_kev_line("cve-2021-44228")),
        _kev(json.dumps({"cve": "CVE-2021-44228"})),
        _kev(_kev_line("CVE-2021-44228", known_ransomware_campaign_use="x" * 33)),
        "é\n".encode(),
        b"not json\n",
    ],
)
def test_kev_grammar_is_strict(data: bytes) -> None:
    with pytest.raises(ArtifactIntegrityError):
        parse_kev_normalized(data)


# -- EPSS grammar ----------------------------------------------------------------
def test_epss_parse() -> None:
    data = b"cve,epss,percentile\nCVE-2020-0001,0.1,0.2\nCVE-2021-44228,0.9,0.99\n"
    assert parse_epss_normalized(data, frozenset({"CVE-2021-44228"})) == {
        "CVE-2021-44228": (0.9, 0.99)
    }


@pytest.mark.parametrize(
    "data",
    [
        b"cve,percentile,epss\n",
        b"cve,epss,percentile\nCVE-2021-44228,0.9,0.99",  # no newline at end
        b"cve,epss,percentile\nCVE-2021-44228,0.9,0.99\nCVE-2020-0001,0.1,0.2\n",
        b"cve,epss,percentile\nCVE-2021-44228,1.9,0.99\n",
        b"cve,epss,percentile\nCVE-2021-44228,inf,0.99\n",
        b"cve,epss,percentile\nCVE-2021-44228,0.9\n",
    ],
)
def test_epss_grammar_is_strict(data: bytes) -> None:
    with pytest.raises(ArtifactIntegrityError):
        parse_epss_normalized(data)


# -- meta --------------------------------------------------------------------------
def test_meta_requires_exact_keys() -> None:
    good = {"format_version": "1", "source": "EPSS", "label": "2026-11-12",
            "order_key": "2026-11-12|v1", "entry_count": 5, "model_version": "v1"}
    assert parse_meta(json.dumps(good).encode(), "EPSS")["entry_count"] == 5
    with pytest.raises(ArtifactIntegrityError):
        parse_meta(json.dumps({**good, "extra": "x"}).encode(), "EPSS")
    with pytest.raises(ArtifactIntegrityError):
        parse_meta(json.dumps({**good, "entry_count": True}).encode(), "EPSS")
    with pytest.raises(ArtifactIntegrityError):
        parse_meta(json.dumps(good).encode(), "KEV")

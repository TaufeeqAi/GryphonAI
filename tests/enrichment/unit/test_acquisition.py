"""The acquisition child: typed retries, request validation, whole-file sources.

``fetch`` is injected, so nothing here opens a socket.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gryphon.enrichment.acquisition import __main__ as child
from gryphon.enrichment.acquisition.connect import (
    FetchFailure,
    FetchOutcome,
    FetchRequest,
    RequestRecord,
    fetch_with_retry,
)
from gryphon.enrichment.constants import EPSS_HOST, KEV_HOST, KEV_PATH
from gryphon.enrichment.selfcheck import synthetic_epss_file, synthetic_kev_catalog

pytestmark = pytest.mark.unit

ADDRESS = "93.184.216.34"


def _request(**overrides) -> FetchRequest:
    values = dict(host=KEV_HOST, path=KEV_PATH, addresses=(ADDRESS,), max_bytes=1 << 20,
                  connect_timeout=1.0, request_timeout=1.0)
    values.update(overrides)
    return FetchRequest(**values)


@pytest.mark.parametrize(
    "overrides",
    [
        {"host": "attacker.example.com"},
        {"path": "relative"},
        {"path": "/x?cve=CVE-2021-44228"},
        {"addresses": ()},
        {"addresses": ("2001:db8::1",)},
    ],
)
def test_fetch_request_refuses_anything_off_the_allowlist(overrides) -> None:
    with pytest.raises(ValueError):
        _request(**overrides)


def test_success_on_first_attempt() -> None:
    outcome = fetch_with_retry(_request(), fetch=lambda r, a: (200, b"body"), sleep=lambda s: None)
    assert outcome.body == b"body" and outcome.failure is None
    assert [r.outcome_class for r in outcome.records] == ["OK"]


def test_transient_failures_retry_with_backoff_then_succeed() -> None:
    calls: list[str] = []
    sleeps: list[float] = []

    def flaky(request, address):
        calls.append(address)
        if len(calls) < 3:
            raise FetchFailure("TRANSIENT", "http 503", retryable=True, status=503)
        return 200, b"ok"

    outcome = fetch_with_retry(_request(), attempts=3, fetch=flaky, sleep=sleeps.append,
                               jitter=lambda: 0.5)
    assert outcome.body == b"ok"
    assert sleeps == [2.0, 4.0]
    assert [r.outcome_class for r in outcome.records] == ["TRANSIENT", "TRANSIENT", "OK"]


def test_retry_after_is_honoured_up_to_a_ceiling() -> None:
    sleeps: list[float] = []

    def limited(request, address):
        raise FetchFailure("TRANSIENT", "http 429", retryable=True, status=429, retry_after=500)

    outcome = fetch_with_retry(_request(), attempts=2, fetch=limited, sleep=sleeps.append,
                               jitter=lambda: 0.0)
    assert outcome.body is None and outcome.failure.status == 429
    assert sleeps == [60.0]


def test_non_retryable_failures_stop_immediately() -> None:
    def redirect(request, address):
        raise FetchFailure("MISCONFIGURED", "redirect 302 refused", retryable=False, status=302)

    outcome = fetch_with_retry(_request(), attempts=3, fetch=redirect, sleep=lambda s: None)
    assert len(outcome.records) == 1
    assert outcome.failure.remediation_class == "MISCONFIGURED"


def test_attempts_rotate_across_pinned_addresses() -> None:
    seen: list[str] = []

    def failing(request, address):
        seen.append(address)
        raise FetchFailure("TRANSIENT", "timeout", retryable=True)

    fetch_with_retry(_request(addresses=("93.184.216.34", "93.184.216.35")), attempts=3,
                     fetch=failing, sleep=lambda s: None)
    assert seen == ["93.184.216.34", "93.184.216.35", "93.184.216.34"]


# -- request validation -----------------------------------------------------------
def _write_request(tmp_path: Path, **overrides) -> Path:
    request = {
        "format_version": "1",
        "sources": ["KEV"],
        "addresses": {KEV_HOST: [ADDRESS]},
        "epss_dates": ["2026-11-13"],
        "out_dir": str(tmp_path),
    }
    request.update(overrides)
    path = tmp_path / "request.json"
    path.write_text(json.dumps(request))
    return path


@pytest.mark.parametrize(
    "overrides",
    [
        {"format_version": "2"},
        {"sources": ["NVD"]},
        {"sources": []},
        {"addresses": {"evil.example.com": [ADDRESS]}},
        {"epss_dates": ["13/11/2026x"]},
        {"out_dir": "/definitely/not/here"},
    ],
)
def test_child_refuses_invalid_requests(tmp_path: Path, overrides) -> None:
    assert child.main([str(_write_request(tmp_path, **overrides))]) == 2


def _fake_fetch(responses: dict[str, tuple[int, bytes] | FetchFailure]):
    def fake(request: FetchRequest, *, attempts: int = 3) -> FetchOutcome:
        value = responses[request.path]
        record = RequestRecord(host=request.host, path=request.path, address=ADDRESS,
                               started_at="t0", finished_at="t1")
        if isinstance(value, FetchFailure):
            record.outcome_class, record.status = value.remediation_class, value.status
            return FetchOutcome(body=None, failure=value, records=[record])
        record.status, record.outcome_class, record.bytes_received = value[0], "OK", len(value[1])
        return FetchOutcome(body=value[1], failure=None, records=[record])

    return fake


def test_kev_source_writes_verified_artifacts(tmp_path: Path, monkeypatch) -> None:
    fake = _fake_fetch({KEV_PATH: (200, synthetic_kev_catalog())})
    monkeypatch.setattr(child, "fetch_with_retry", fake)
    request = json.loads(_write_request(tmp_path).read_text())
    result = child._acquire_source(request, "KEV", tmp_path)
    assert result["status"] == "accepted"
    assert (tmp_path / result["normalized_file"]).is_file()
    assert result["requests"][0]["path"] == KEV_PATH


@pytest.mark.parametrize("status", [403, 404])
def test_epss_falls_back_to_the_previous_dated_file(tmp_path: Path, monkeypatch, status) -> None:
    # The S3 origin answers 403 (not 404) for a file that is not published yet.
    today, yesterday = "/epss_scores-2026-11-13.csv.gz", "/epss_scores-2026-11-12.csv.gz"
    monkeypatch.setattr(child, "fetch_with_retry", _fake_fetch({
        today: FetchFailure("MISCONFIGURED", f"http {status}", retryable=False, status=status),
        yesterday: (200, synthetic_epss_file()),
    }))
    request = json.loads(_write_request(
        tmp_path, sources=["EPSS"], addresses={EPSS_HOST: [ADDRESS]},
        epss_dates=["2026-11-13", "2026-11-12"],
    ).read_text())
    result = child._acquire_source(request, "EPSS", tmp_path)
    assert result["status"] == "accepted"
    assert [r["path"] for r in result["requests"]] == [today, yesterday]


def test_rejected_download_writes_nothing(tmp_path: Path, monkeypatch) -> None:
    truncated = synthetic_kev_catalog()[:5000]
    monkeypatch.setattr(child, "fetch_with_retry", _fake_fetch({KEV_PATH: (200, truncated)}))
    request = json.loads(_write_request(tmp_path).read_text())
    result = child._acquire_source(request, "KEV", tmp_path)
    assert result["status"] == "rejected" and result["remediation_class"] == "INTEGRITY"
    assert not list(tmp_path.glob("KEV.*"))


def test_outbound_requests_never_depend_on_engagement_data(tmp_path: Path, monkeypatch) -> None:
    """Every path the child can request is a code constant or a date."""
    paths: list[str] = []

    def record(request: FetchRequest, *, attempts: int = 3) -> FetchOutcome:
        paths.append(request.path)
        return FetchOutcome(body=None, failure=FetchFailure("TRANSIENT", "x", retryable=True))

    monkeypatch.setattr(child, "fetch_with_retry", record)
    request = json.loads(_write_request(
        tmp_path, sources=["KEV", "EPSS"],
        addresses={KEV_HOST: [ADDRESS], EPSS_HOST: [ADDRESS]},
        epss_dates=["2026-11-13", "2026-11-12"],
    ).read_text())
    for source in ("KEV", "EPSS"):
        child._acquire_source(request, source, tmp_path)
    assert paths == [KEV_PATH, "/epss_scores-2026-11-13.csv.gz"]

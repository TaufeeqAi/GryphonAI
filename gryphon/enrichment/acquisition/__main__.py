"""Acquisition subprocess entry point.

    python -m gryphon.enrichment.acquisition <request.json>

Reads a request written by the enrichment process, fetches each requested source
as a whole published file, runs acceptance, writes raw / normalized / meta
artifacts into the staging directory named by the request, and prints a JSON
report on stdout. It exits 0 whenever it could produce a report — rejections are
results, not crashes — and 2 for a malformed request.

The request carries no engagement data: only source names, pinned addresses for
the allowlisted hosts, the dates of the EPSS files to try, and the metadata of
the last accepted snapshot of each source.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from gryphon.enrichment.acquisition.acceptance import (
    AcceptanceRejected,
    Accepted,
    LastAccepted,
    accept_epss,
    accept_kev,
)
from gryphon.enrichment.acquisition.connect import FetchRequest, fetch_with_retry
from gryphon.enrichment.constants import (
    ALLOWED_HOSTS,
    EPSS_HOST,
    EPSS_MAX_COMPRESSED_BYTES,
    EPSS_PATH_TEMPLATE,
    KEV_HOST,
    KEV_MAX_BYTES,
    KEV_PATH,
)

REQUEST_FORMAT_VERSION = "1"
_MAX_REQUEST_BYTES = 64 * 1024
_SOURCES = ("KEV", "EPSS")
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
#: Statuses meaning "this dated file is not published (yet)".
_NOT_PUBLISHED = frozenset({403, 404})


class RequestInvalid(Exception):
    pass


def _load_request(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > _MAX_REQUEST_BYTES:
        raise RequestInvalid("request too large")
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get("format_version") != REQUEST_FORMAT_VERSION:
        raise RequestInvalid("unsupported request format")
    sources = request.get("sources")
    if not isinstance(sources, list) or not sources or any(s not in _SOURCES for s in sources):
        raise RequestInvalid("sources must be a non-empty subset of KEV, EPSS")
    addresses = request.get("addresses")
    if not isinstance(addresses, dict) or any(h not in ALLOWED_HOSTS for h in addresses):
        raise RequestInvalid("addresses may only name allowlisted hosts")
    dates = request.get("epss_dates", [])
    if not isinstance(dates, list) or len(dates) > 4 or any(
        not isinstance(d, str) or not _DATE_RE.fullmatch(d) for d in dates
    ):
        raise RequestInvalid("epss_dates must be YYYY-MM-DD strings")
    out_dir = Path(str(request.get("out_dir", "")))
    if not out_dir.is_dir():
        raise RequestInvalid("out_dir must be an existing directory")
    return request


def _write(out_dir: Path, accepted: Accepted, raw: bytes) -> dict[str, str]:
    files = {
        "raw_file": out_dir / f"{accepted.source}.raw",
        "normalized_file": out_dir / f"{accepted.source}.normalized",
        "meta_file": out_dir / f"{accepted.source}.meta.json",
    }
    files["raw_file"].write_bytes(raw)
    files["normalized_file"].write_bytes(accepted.normalized)
    files["meta_file"].write_bytes(accepted.meta_bytes())
    return {key: path.name for key, path in files.items()}


def _fetch_request(request: dict[str, Any], host: str, path: str, cap: int) -> FetchRequest:
    return FetchRequest(
        host=host,
        path=path,
        addresses=tuple(request["addresses"].get(host, ())),
        max_bytes=cap,
        connect_timeout=float(request.get("connect_timeout", 10.0)),
        request_timeout=float(request.get("request_timeout", 120.0)),
    )


def _acquire_source(request: dict[str, Any], source: str, out_dir: Path) -> dict[str, Any]:
    last = LastAccepted.from_payload((request.get("last") or {}).get(source))
    attempts = int(request.get("attempts", 3))
    records: list[dict[str, Any]] = []
    if source == "KEV":
        targets = [(KEV_HOST, KEV_PATH, KEV_MAX_BYTES)]
    else:
        targets = [
            (EPSS_HOST, EPSS_PATH_TEMPLATE.format(date=d), EPSS_MAX_COMPRESSED_BYTES)
            for d in request.get("epss_dates", [])
        ]
    if not targets:
        return {"status": "rejected", "reason": "no file to request", "remediation_class":
                "MISCONFIGURED", "requests": records}

    failure_reason, failure_class = "no request made", "MISCONFIGURED"
    for host, path, cap in targets:
        try:
            fetch_request = _fetch_request(request, host, path, cap)
        except ValueError as exc:
            return {"status": "rejected", "reason": str(exc), "remediation_class":
                    "MISCONFIGURED", "requests": records}
        outcome = fetch_with_retry(fetch_request, attempts=attempts)
        records.extend(r.as_payload() for r in outcome.records)
        if outcome.body is None:
            failure = outcome.failure
            failure_reason = failure.reason if failure else "unknown failure"
            failure_class = failure.remediation_class if failure else "TRANSIENT"
            # A dated EPSS file that is not published yet answers 403 from its
            # S3 origin (AccessDenied for a missing key; 404 if listing were
            # allowed): try the previous date rather than failing the source.
            if source == "EPSS" and failure is not None and failure.status in _NOT_PUBLISHED:
                continue
            break
        try:
            accepted = accept_kev(outcome.body, last) if source == "KEV" else accept_epss(
                outcome.body, last
            )
        except AcceptanceRejected as rejected:
            return {"status": "rejected", "reason": rejected.reason,
                    "remediation_class": rejected.remediation_class, "requests": records}
        files = _write(out_dir, accepted, outcome.body)
        return {
            "status": "accepted",
            "label": accepted.label,
            "order_key": accepted.order_key,
            "entry_count": accepted.entry_count,
            "byte_size": accepted.byte_size,
            "content_sha256": accepted.content_sha256,
            "normalized_sha256": accepted.normalized_sha256,
            "fetched_from": host,
            "requests": records,
            **files,
        }
    return {"status": "rejected", "reason": failure_reason,
            "remediation_class": failure_class, "requests": records}


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m gryphon.enrichment.acquisition <request.json>", file=sys.stderr)
        return 2
    try:
        request = _load_request(Path(args[0]))
    except (OSError, ValueError, RequestInvalid) as exc:
        print(f"invalid request: {exc}", file=sys.stderr)
        return 2
    out_dir = Path(request["out_dir"])
    results = {source: _acquire_source(request, source, out_dir) for source in request["sources"]}
    print(json.dumps({"format_version": REQUEST_FORMAT_VERSION, "results": results},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

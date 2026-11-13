"""Acceptance: proving a downloaded snapshot complete before anything uses it.

A negative answer — "not on KEV", "not scored by EPSS" — is only as good as the
completeness of the snapshot it is inferred from. Every check below exists so
that a truncated, stale, drifted or tampered file is *rejected* (and nothing is
written) rather than accepted as a catalog that happens to be missing entries.

Normalized artifacts are what the privileged parent process reads. They have a
fixed, minimal grammar so the parent can parse them strictly without ever
touching the provider's raw bytes.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import math
import re
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from gryphon.enrichment.constants import (
    EPSS_COLUMNS,
    EPSS_MAX_COMPRESSED_BYTES,
    EPSS_MAX_DECOMPRESSED_BYTES,
    EPSS_MIN_ROW_RATIO,
    EPSS_MIN_ROWS,
    KEV_CVE_PATTERN,
    KEV_MAX_BYTES,
    KEV_MAX_GROWTH_FACTOR,
    KEV_MIN_COUNT,
    KEV_MIN_COUNT_RATIO,
    NORMALIZED_FORMAT_VERSION,
)

_CVE_RE = re.compile(KEV_CVE_PATTERN)
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_EPSS_HEADER_RE = re.compile(
    r"^#model_version:(?P<model>[A-Za-z0-9._-]{1,32}),"
    r"score_date:(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})(?:T[0-9:.]{1,20}(?:Z|[+-][0-9:]{2,5})?)?$"
)
_KEV_REQUIRED = (
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
)
_RANSOMWARE_MAX = 32


class AcceptanceRejected(Exception):
    def __init__(self, reason: str, remediation_class: str = "INTEGRITY") -> None:
        super().__init__(reason)
        self.reason = reason
        self.remediation_class = remediation_class


@dataclass(frozen=True)
class LastAccepted:
    """What the parent last accepted for a source — the comparison baseline."""

    label: str
    order_key: str
    entry_count: int
    byte_size: int

    @classmethod
    def from_payload(cls, payload: dict[str, Any] | None) -> LastAccepted | None:
        if not payload:
            return None
        return cls(
            label=str(payload["label"]),
            order_key=str(payload["order_key"]),
            entry_count=int(payload["entry_count"]),
            byte_size=int(payload["byte_size"]),
        )


@dataclass
class Accepted:
    source: str
    label: str
    order_key: str
    entry_count: int
    byte_size: int
    content_sha256: str
    normalized: bytes
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def normalized_sha256(self) -> str:
        return hashlib.sha256(self.normalized).hexdigest()

    def meta_bytes(self) -> bytes:
        return (json.dumps(self.meta, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _reject_constant(token: str) -> Any:
    raise AcceptanceRejected(f"non-finite JSON constant {token!r}")


def _bounded_gunzip(data: bytes, limit: int) -> bytes:
    """Decompress a complete gzip stream, refusing truncation and bombs."""
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = bytearray()
    view = memoryview(data)
    step = 1 << 16
    for offset in range(0, len(data), step):
        out += decompressor.decompress(view[offset : offset + step], limit + 1 - len(out))
        if len(out) > limit:
            raise AcceptanceRejected("decompressed size exceeds cap")
        if decompressor.unconsumed_tail:
            raise AcceptanceRejected("decompressed size exceeds cap")
    out += decompressor.flush()
    if len(out) > limit:
        raise AcceptanceRejected("decompressed size exceeds cap")
    if not decompressor.eof:
        raise AcceptanceRejected("truncated gzip stream")
    if decompressor.unused_data:
        raise AcceptanceRejected("trailing data after gzip stream")
    return bytes(out)


def _order_key_from_release(date_released: str, catalog_version: str) -> str:
    try:
        released = datetime.fromisoformat(date_released.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AcceptanceRejected("dateReleased is not an ISO-8601 timestamp") from exc
    if released.tzinfo is None:
        released = released.replace(tzinfo=UTC)
    stamp = released.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return f"{stamp}|{catalog_version}"


# -----------------------------------------------------------------------------
# CISA KEV catalog
# -----------------------------------------------------------------------------
def accept_kev(raw: bytes, last: LastAccepted | None) -> Accepted:
    """Accept the KEV catalog, or raise :class:`AcceptanceRejected`."""
    if len(raw) > KEV_MAX_BYTES:
        raise AcceptanceRejected("catalog exceeds size cap")
    if last is not None and len(raw) > KEV_MAX_GROWTH_FACTOR * max(last.byte_size, 1):
        raise AcceptanceRejected("catalog grew beyond the bound against the last accepted")
    body = _bounded_gunzip(raw, KEV_MAX_BYTES) if raw[:2] == b"\x1f\x8b" else raw
    try:
        document = json.loads(body.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcceptanceRejected(f"catalog is not valid JSON: {type(exc).__name__}") from exc
    if not isinstance(document, dict):
        raise AcceptanceRejected("catalog root is not an object")
    for key, kind in (
        ("catalogVersion", str),
        ("dateReleased", str),
        ("count", int),
        ("vulnerabilities", list),
    ):
        value = document.get(key)
        if not isinstance(value, kind) or isinstance(value, bool):
            raise AcceptanceRejected(f"catalog field {key!r} missing or mistyped")
    catalog_version: str = document["catalogVersion"]
    if not catalog_version or len(catalog_version) > 32:
        raise AcceptanceRejected("catalogVersion is empty or oversized")
    entries: list[Any] = document["vulnerabilities"]
    count: int = document["count"]
    if count != len(entries):
        raise AcceptanceRejected(f"count {count} does not match {len(entries)} entries")
    if count < KEV_MIN_COUNT:
        raise AcceptanceRejected(f"catalog has {count} entries, below the floor {KEV_MIN_COUNT}")
    if last is not None and count < math.ceil(KEV_MIN_COUNT_RATIO * last.entry_count):
        raise AcceptanceRejected(
            f"catalog shrank from {last.entry_count} to {count} entries (beyond the bound)"
        )
    order_key = _order_key_from_release(document["dateReleased"], catalog_version)
    if last is not None and order_key < last.order_key:
        raise AcceptanceRejected("catalog is older than the last accepted catalog")

    normalized_rows: dict[str, dict[str, str]] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise AcceptanceRejected(f"entry {index} is not an object")
        for key in _KEV_REQUIRED:
            if not isinstance(entry.get(key), str):
                raise AcceptanceRejected(f"entry {index} field {key!r} missing or mistyped")
        cve = entry["cveID"]
        if not _CVE_RE.fullmatch(cve):
            raise AcceptanceRejected(f"entry {index} has an invalid cveID")
        if cve in normalized_rows:
            raise AcceptanceRejected(f"duplicate cveID {cve}")
        for key in ("dateAdded", "dueDate"):
            if not _DATE_RE.fullmatch(entry[key]):
                raise AcceptanceRejected(f"entry {index} field {key!r} is not YYYY-MM-DD")
        ransomware = entry.get("knownRansomwareCampaignUse", "")
        if not isinstance(ransomware, str) or len(ransomware) > _RANSOMWARE_MAX:
            ransomware = ""
        normalized_rows[cve] = {
            "cve": cve,
            "date_added": entry["dateAdded"],
            "due_date": entry["dueDate"],
            "known_ransomware_campaign_use": ransomware,
        }

    lines = [
        json.dumps(normalized_rows[cve], sort_keys=True, separators=(",", ":"))
        for cve in sorted(normalized_rows)
    ]
    normalized = ("\n".join(lines) + "\n").encode("ascii")
    return Accepted(
        source="KEV",
        label=catalog_version,
        order_key=order_key,
        entry_count=count,
        byte_size=len(raw),
        content_sha256=hashlib.sha256(raw).hexdigest(),
        normalized=normalized,
        meta={
            "format_version": NORMALIZED_FORMAT_VERSION,
            "source": "KEV",
            "label": catalog_version,
            "order_key": order_key,
            "entry_count": count,
            "date_released": document["dateReleased"],
        },
    )


# -----------------------------------------------------------------------------
# FIRST EPSS daily file
# -----------------------------------------------------------------------------
def _probability(token: str, field_name: str, line_no: int) -> str:
    try:
        value = float(token)
    except ValueError as exc:
        raise AcceptanceRejected(f"line {line_no}: {field_name} is not a number") from exc
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise AcceptanceRejected(f"line {line_no}: {field_name} is not a probability")
    return token


def accept_epss(raw: bytes, last: LastAccepted | None) -> Accepted:
    """Accept an EPSS daily file (gzip CSV), or raise :class:`AcceptanceRejected`."""
    if len(raw) > EPSS_MAX_COMPRESSED_BYTES:
        raise AcceptanceRejected("compressed file exceeds size cap")
    if raw[:2] != b"\x1f\x8b":
        raise AcceptanceRejected("file is not gzip")
    try:
        text = _bounded_gunzip(raw, EPSS_MAX_DECOMPRESSED_BYTES).decode("utf-8")
    except (UnicodeDecodeError, zlib.error, gzip.BadGzipFile) as exc:
        raise AcceptanceRejected(f"file cannot be decoded: {type(exc).__name__}") from exc
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) < 2:
        raise AcceptanceRejected("file has no header")
    header = _EPSS_HEADER_RE.fullmatch(lines[0].strip())
    if header is None:
        raise AcceptanceRejected("missing or malformed model_version/score_date header")
    if tuple(lines[1].strip().split(",")) != EPSS_COLUMNS:
        raise AcceptanceRejected("unexpected columns (expected cve,epss,percentile)")
    model_version = header.group("model")
    score_date = header.group("date")

    rows: dict[str, str] = {}
    for offset, line in enumerate(lines[2:], start=3):
        parts = line.strip().split(",")
        if len(parts) != 3:
            raise AcceptanceRejected(f"line {offset}: expected 3 fields")
        cve, epss, percentile = parts
        if not _CVE_RE.fullmatch(cve):
            raise AcceptanceRejected(f"line {offset}: invalid cve")
        if cve in rows:
            raise AcceptanceRejected(f"line {offset}: duplicate cve {cve}")
        rows[cve] = (
            f"{cve},{_probability(epss, 'epss', offset)},"
            f"{_probability(percentile, 'percentile', offset)}"
        )
    count = len(rows)
    if count < EPSS_MIN_ROWS:
        raise AcceptanceRejected(f"file has {count} rows, below the floor {EPSS_MIN_ROWS}")
    if last is not None and count < math.ceil(EPSS_MIN_ROW_RATIO * last.entry_count):
        raise AcceptanceRejected(f"file shrank from {last.entry_count} to {count} rows")
    order_key = f"{score_date}|{model_version}"
    if last is not None and score_date < last.label:
        raise AcceptanceRejected("score_date is older than the last accepted file")

    body = "cve,epss,percentile\n" + "".join(rows[cve] + "\n" for cve in sorted(rows))
    return Accepted(
        source="EPSS",
        label=score_date,
        order_key=order_key,
        entry_count=count,
        byte_size=len(raw),
        content_sha256=hashlib.sha256(raw).hexdigest(),
        normalized=body.encode("ascii"),
        meta={
            "format_version": NORMALIZED_FORMAT_VERSION,
            "source": "EPSS",
            "label": score_date,
            "order_key": order_key,
            "entry_count": count,
            "model_version": model_version,
        },
    )

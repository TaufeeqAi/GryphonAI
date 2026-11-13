"""Content-addressed artifact store and strict normalized-format parsers.

Accepted snapshots are stored by the SHA-256 of their bytes, so a file is its own
identity: the same bytes accepted twice are one artifact, and a stored file that
no longer hashes to its name is detected on every read.

The enrichment process never parses a provider's raw bytes. It parses only the
*normalized* artifacts the acquisition subprocess produced, and it does so with a
deliberately small grammar: exact keys, exact columns, canonical order, no
duplicates, finite numbers. Anything else is an :class:`ArtifactIntegrityError`.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gryphon.enrichment.constants import EPSS_COLUMNS, KEV_CVE_PATTERN, NORMALIZED_FORMAT_VERSION
from gryphon.enrichment.reasons import ArtifactIntegrityError

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_CVE_RE = re.compile(KEV_CVE_PATTERN)
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_KEV_KEYS = frozenset({"cve", "date_added", "due_date", "known_ransomware_campaign_use"})
_META_KEYS = {
    "KEV": frozenset(
        {"format_version", "source", "label", "order_key", "entry_count", "date_released"}
    ),
    "EPSS": frozenset(
        {"format_version", "source", "label", "order_key", "entry_count", "model_version"}
    ),
}
_CHUNK = 1 << 20


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ArtifactStore:
    """Files keyed by SHA-256 under ``<root>/sha256/<aa>/<digest>``."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    @property
    def root(self) -> Path:
        return self._root

    def staging_dir(self) -> Path:
        base = self._root / "staging"
        base.mkdir(parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix="acq-", dir=base))

    def path_for(self, digest: str) -> Path:
        if not _DIGEST_RE.fullmatch(digest):
            raise ArtifactIntegrityError(f"not a sha256 digest: {digest!r}")
        return self._root / "sha256" / digest[:2] / digest

    def has(self, digest: str) -> bool:
        return self.path_for(digest).is_file()

    def put_file(self, source: Path, expected_digest: str) -> Path:
        """Store ``source`` under its digest after verifying it. Idempotent."""
        actual = sha256_file(source)
        if actual != expected_digest:
            raise ArtifactIntegrityError(
                f"artifact digest mismatch: expected {expected_digest[:12]}…, got {actual[:12]}…"
            )
        target = self.path_for(expected_digest)
        if target.is_file():
            if sha256_file(target) != expected_digest:
                raise ArtifactIntegrityError(f"stored artifact {expected_digest[:12]}… is corrupt")
            return target
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=".incoming-")
        os.close(fd)
        tmp = Path(tmp_name)
        try:
            shutil.copyfile(source, tmp)
            os.replace(tmp, target)
        finally:
            if tmp.exists():
                tmp.unlink()
        return target

    def read_verified(self, digest: str) -> bytes:
        path = self.path_for(digest)
        if not path.is_file():
            raise ArtifactIntegrityError(f"artifact {digest[:12]}… is missing")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ArtifactIntegrityError(f"artifact {digest[:12]}… does not match its digest")
        return data


@dataclass(frozen=True)
class KevEntry:
    cve: str
    date_added: str
    due_date: str
    known_ransomware_campaign_use: str


def _reject_constant(token: str) -> Any:
    raise ArtifactIntegrityError(f"non-finite constant {token!r}")


def parse_meta(data: bytes, source: str) -> dict[str, Any]:
    """Parse a snapshot's metadata strictly."""
    try:
        meta = json.loads(data.decode("ascii"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactIntegrityError(f"{source} metadata is not valid JSON") from exc
    expected = _META_KEYS.get(source)
    if expected is None or not isinstance(meta, dict) or set(meta) != expected:
        raise ArtifactIntegrityError(f"{source} metadata has unexpected keys")
    if meta["format_version"] != NORMALIZED_FORMAT_VERSION or meta["source"] != source:
        raise ArtifactIntegrityError(f"{source} metadata has an unsupported format")
    if not isinstance(meta["entry_count"], int) or isinstance(meta["entry_count"], bool):
        raise ArtifactIntegrityError(f"{source} metadata entry_count is not an integer")
    for key in expected - {"entry_count"}:
        if not isinstance(meta[key], str) or not meta[key] or len(meta[key]) > 96:
            raise ArtifactIntegrityError(f"{source} metadata field {key!r} is invalid")
    return meta


def parse_kev_normalized(data: bytes, wanted: frozenset[str] | None = None) -> dict[str, KevEntry]:
    """Parse normalized KEV lines. Returns entries for ``wanted`` (or all)."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ArtifactIntegrityError("KEV normalized artifact is not ASCII") from exc
    if not text.endswith("\n"):
        raise ArtifactIntegrityError("KEV normalized artifact is not newline-terminated")
    entries: dict[str, KevEntry] = {}
    previous = ""
    for number, line in enumerate(text[:-1].split("\n"), start=1):
        try:
            row = json.loads(line, parse_constant=_reject_constant)
        except json.JSONDecodeError as exc:
            raise ArtifactIntegrityError(f"KEV normalized line {number} is not JSON") from exc
        if not isinstance(row, dict) or set(row) != _KEV_KEYS:
            raise ArtifactIntegrityError(f"KEV normalized line {number} has unexpected keys")
        if not all(isinstance(row[k], str) for k in _KEV_KEYS):
            raise ArtifactIntegrityError(f"KEV normalized line {number} has a non-string field")
        cve = row["cve"]
        if not _CVE_RE.fullmatch(cve):
            raise ArtifactIntegrityError(f"KEV normalized line {number} has an invalid cve")
        if not _DATE_RE.fullmatch(row["date_added"]) or not _DATE_RE.fullmatch(row["due_date"]):
            raise ArtifactIntegrityError(f"KEV normalized line {number} has an invalid date")
        if len(row["known_ransomware_campaign_use"]) > 32:
            raise ArtifactIntegrityError(f"KEV normalized line {number} has an oversized field")
        if cve <= previous:
            raise ArtifactIntegrityError("KEV normalized artifact is not sorted and unique")
        previous = cve
        if wanted is None or cve in wanted:
            entries[cve] = KevEntry(
                cve=cve,
                date_added=row["date_added"],
                due_date=row["due_date"],
                known_ransomware_campaign_use=row["known_ransomware_campaign_use"],
            )
    return entries


def parse_epss_normalized(
    data: bytes, wanted: frozenset[str] | None = None
) -> dict[str, tuple[float, float]]:
    """Parse normalized EPSS rows. Returns ``cve -> (epss, percentile)`` for ``wanted``."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ArtifactIntegrityError("EPSS normalized artifact is not ASCII") from exc
    lines = text.split("\n")
    if not lines or lines[0] != ",".join(EPSS_COLUMNS) or lines[-1] != "":
        raise ArtifactIntegrityError("EPSS normalized artifact has an unexpected header")
    scores: dict[str, tuple[float, float]] = {}
    previous = ""
    for number, line in enumerate(lines[1:-1], start=2):
        parts = line.split(",")
        if len(parts) != 3:
            raise ArtifactIntegrityError(f"EPSS normalized line {number} is malformed")
        cve, epss_text, pct_text = parts
        if not _CVE_RE.fullmatch(cve) or cve <= previous:
            raise ArtifactIntegrityError(f"EPSS normalized line {number} is invalid or unsorted")
        previous = cve
        if wanted is not None and cve not in wanted:
            continue
        try:
            epss, pct = float(epss_text), float(pct_text)
        except ValueError as exc:
            raise ArtifactIntegrityError(f"EPSS normalized line {number} is not numeric") from exc
        if not (math.isfinite(epss) and math.isfinite(pct) and 0 <= epss <= 1 and 0 <= pct <= 1):
            raise ArtifactIntegrityError(f"EPSS normalized line {number} is out of range")
        scores[cve] = (epss, pct)
    return scores


def kev_cve_set(data: bytes) -> frozenset[str]:
    """All CVEs in a normalized KEV artifact (validated)."""
    return frozenset(parse_kev_normalized(data))

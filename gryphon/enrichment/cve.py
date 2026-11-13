"""CVE subject extraction from verified evidence.

Subjects come from exactly one place: the ``cve_ids`` field of a finding's
observation, which the producing tool copies from the template's own
classification. No other field is ever a source — in particular not the matched
URL, which the scanned target controls, and not the template's tags.

The upstream parser builds the list with ``list(classification["cve-id"])``. A
template that writes ``cve-id`` as a scalar would, through that call, arrive as a
list of single characters; and nuclei may emit lower-case identifiers. Both are
normalized here *before* validation, and every value that is still rejected is
counted, so an extraction failure is visible rather than a silent "no CVE".
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from gryphon.enrichment.constants import (
    EXTRACTED_CVE_PATTERN,
    MAX_CVES_PER_FINDING,
    MAX_CVES_PER_PASS,
)

_CVE_RE = re.compile(EXTRACTED_CVE_PATTERN)
#: Longest string worth examining at all; anything longer is rejected unread.
_MAX_RAW_LENGTH = 64


@dataclass(frozen=True)
class FindingSubjects:
    """One admissible finding and the CVE subjects extracted from it."""

    finding_id: str
    observed_severity: str | None
    template_id: str | None
    cve_ids: tuple[str, ...]
    cvss_score: Any


@dataclass
class ExtractionResult:
    subjects: list[FindingSubjects] = field(default_factory=list)
    findings_total: int = 0
    findings_without_cves: int = 0
    rejected: Counter[str] = field(default_factory=Counter)

    @property
    def distinct_cves(self) -> frozenset[str]:
        return frozenset(c for s in self.subjects for c in s.cve_ids)

    def as_payload(self) -> dict[str, Any]:
        return {
            "findings_total": self.findings_total,
            "findings_with_cves": len(self.subjects),
            "findings_without_cves": self.findings_without_cves,
            "cve_subjects": len(self.distinct_cves),
            "rejected": dict(sorted(self.rejected.items())),
        }


def _flatten(raw: Any) -> tuple[list[str], int]:
    """Normalize the many shapes ``cve_ids`` can arrive in.

    Returns (candidate strings, number of non-string items). A list made only of
    single characters is the signature of ``list()`` applied to a scalar string,
    so it is re-joined rather than rejected thirteen times.
    """
    if raw is None:
        return [], 0
    if isinstance(raw, str):
        return [raw], 0
    if isinstance(raw, list | tuple):
        if raw and all(isinstance(x, str) and len(x) == 1 for x in raw):
            return ["".join(raw)], 0
        strings = [x for x in raw if isinstance(x, str)]
        return strings, len(raw) - len(strings)
    return [], 1


def normalize_cve_ids(raw: Any) -> tuple[list[str], Counter[str]]:
    """Return (valid canonical CVE ids in first-seen order, rejection counts)."""
    rejected: Counter[str] = Counter()
    candidates, non_strings = _flatten(raw)
    if non_strings:
        rejected["non_string_value"] += non_strings
    seen: dict[str, None] = {}
    for value in candidates:
        if len(value) > _MAX_RAW_LENGTH:
            rejected["oversized_value"] += 1
            continue
        canonical = value.strip().upper()
        if not _CVE_RE.fullmatch(canonical):
            rejected["invalid_cve_format"] += 1
            continue
        seen.setdefault(canonical, None)
    valid = list(seen)
    if len(valid) > MAX_CVES_PER_FINDING:
        rejected["finding_cap_exceeded"] += len(valid) - MAX_CVES_PER_FINDING
        valid = valid[:MAX_CVES_PER_FINDING]
    return valid, rejected


def extract_subjects(findings: Iterable[dict[str, Any]]) -> ExtractionResult:
    """Extract CVE subjects from the admissible findings of a verified report.

    ``findings`` are the per-finding entries of the report body. Only
    ``observation.cve_ids`` is read for subjects; ``severity``, ``template_id``
    and ``cvss_score`` are carried as evidence about the finding and template.
    """
    result = ExtractionResult()
    pass_cves: dict[str, None] = {}
    for finding in findings:
        result.findings_total += 1
        observation = finding.get("observation") or {}
        if not isinstance(observation, dict):
            result.rejected["malformed_observation"] += 1
            result.findings_without_cves += 1
            continue
        cves, rejected = normalize_cve_ids(observation.get("cve_ids"))
        result.rejected.update(rejected)
        kept: list[str] = []
        for cve in cves:
            if cve in pass_cves:
                kept.append(cve)
            elif len(pass_cves) < MAX_CVES_PER_PASS:
                pass_cves[cve] = None
                kept.append(cve)
            else:
                result.rejected["pass_cap_exceeded"] += 1
        if not kept:
            result.findings_without_cves += 1
            continue
        result.subjects.append(
            FindingSubjects(
                finding_id=str(finding["finding_id"]),
                observed_severity=finding.get("severity"),
                template_id=observation.get("template_id"),
                cve_ids=tuple(kept),
                cvss_score=observation.get("cvss_score"),
            )
        )
    return result

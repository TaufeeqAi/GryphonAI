"""Project enforcement-layer results into durable evidence rows.

Two jobs, and the second is the one that matters architecturally.

**Record what was observed.** Each tool's typed result becomes append-only
``raw_finding`` rows carrying the producing ``execution_id`` and the signed
audit event that recorded the outcome. Evidence with provenance is what lets
the report corroborate itself later instead of trusting whatever is in a table.

**Carry targets between stages durably.** The next stage's targets come from
these persisted rows, never from the previous stage's in-memory result objects.
That is deliberate: a result object does not survive a crash, so a resumed scan
that recomputed its target list from live tool output would produce a
*different* list — different ordering, different membership — and therefore
different execution identities. Different identities mean the enforcement
layer sees brand-new work and runs it, which is exactly the second real scan
the whole design exists to prevent. Reading rows is deterministic; re-running
discovery is not.

Every row is assurance-tagged ``NOT_VERIFIED`` / ``NOT_PERFORMED``. This layer
observes; it does not decide what a finding means or whether it is real.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable

from gryphon.orchestration.constants import AssuranceStatus
from gryphon.tooling.constants import ToolId
from gryphon.tooling.tools.models import (
    CrawlResult,
    DnsResolveResult,
    HttpProbeResult,
    NucleiScanResult,
    PortScanResult,
    SubdomainResult,
    TlsInspectResult,
)


class ObservationType:
    """Stable observation kinds. Additive; a value is never repurposed."""

    SUBDOMAIN = "subdomain"
    DNS_RECORD = "dns_record"
    OPEN_PORT = "open_port"
    HTTP_SERVICE = "http_service"
    TLS_CERTIFICATE = "tls_certificate"
    ENDPOINT = "endpoint"
    VULNERABILITY = "vulnerability"


@dataclass(frozen=True, slots=True)
class Observation:
    """One observed fact, before it is given an identity and persisted."""

    observation_type: str
    canonical_target: str
    observation: dict[str, Any]
    title: str | None = None
    severity: str | None = None
    port: int | None = None
    url: str | None = None

    def finding_key(self) -> str:
        """A stable key within one execution, so re-folding cannot duplicate.

        Derived from the identifying fields rather than from position, because
        a re-walked step may emit the same observations in a different order.
        """
        material = "|".join(
            (
                self.observation_type,
                self.canonical_target,
                self.url or "",
                str(self.port or ""),
                self.title or "",
            )
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:48]


def observations_from(tool_id: ToolId, records: Iterable[Any]) -> list[Observation]:
    """Flatten one execution's typed results into observations.

    Unknown or empty results yield an empty list — a truthful negative result,
    which the coverage classifier counts as *covered*. Nothing here invents an
    observation to fill a gap.
    """
    out: list[Observation] = []
    for record in records:
        if tool_id is ToolId.SUBFINDER and isinstance(record, SubdomainResult):
            for host in record.subdomains:
                out.append(
                    Observation(
                        observation_type=ObservationType.SUBDOMAIN,
                        canonical_target=host,
                        observation={"domain": record.domain, "host": host},
                        title=host,
                    )
                )
        elif tool_id is ToolId.DNSX and isinstance(record, DnsResolveResult):
            for dns in record.records:
                out.append(
                    Observation(
                        observation_type=ObservationType.DNS_RECORD,
                        canonical_target=dns.host,
                        observation={
                            "host": dns.host,
                            "a": list(dns.a),
                            "aaaa": list(dns.aaaa),
                            "cname": list(dns.cname),
                        },
                        title=dns.host,
                    )
                )
        elif tool_id is ToolId.NAABU and isinstance(record, PortScanResult):
            for port in record.records:
                out.append(
                    Observation(
                        observation_type=ObservationType.OPEN_PORT,
                        canonical_target=port.host,
                        observation={"host": port.host, "ip": port.ip, "port": port.port},
                        port=port.port,
                        title=f"{port.host}:{port.port}",
                    )
                )
        elif tool_id is ToolId.HTTPX and isinstance(record, HttpProbeResult):
            for http in record.records:
                out.append(
                    Observation(
                        observation_type=ObservationType.HTTP_SERVICE,
                        canonical_target=record.target,
                        observation={
                            "url": http.url,
                            "status_code": http.status_code,
                            "title": http.title,
                            "webserver": http.webserver,
                            "technologies": list(http.technologies),
                            "content_length": http.content_length,
                        },
                        url=http.url,
                        title=http.title or http.url,
                    )
                )
        elif tool_id is ToolId.TLSX and isinstance(record, TlsInspectResult):
            for tls in record.records:
                out.append(
                    Observation(
                        observation_type=ObservationType.TLS_CERTIFICATE,
                        canonical_target=tls.host,
                        observation={
                            "host": tls.host,
                            "port": tls.port,
                            "subject_cn": tls.subject_cn,
                            "issuer": tls.issuer,
                            "not_after": tls.not_after,
                            "tls_versions": list(tls.tls_versions),
                        },
                        port=tls.port,
                        title=tls.subject_cn or tls.host,
                    )
                )
        elif tool_id is ToolId.KATANA and isinstance(record, CrawlResult):
            for url in record.urls:
                out.append(
                    Observation(
                        observation_type=ObservationType.ENDPOINT,
                        canonical_target=record.target,
                        observation={"url": url},
                        url=url,
                        title=url,
                    )
                )
        elif tool_id is ToolId.NUCLEI and isinstance(record, NucleiScanResult):
            for finding in record.findings:
                out.append(
                    Observation(
                        observation_type=ObservationType.VULNERABILITY,
                        canonical_target=record.target,
                        observation={
                            "template_id": finding.template_id,
                            "name": finding.name,
                            "severity": finding.severity,
                            "matched_url": finding.matched_url,
                            "description": finding.description,
                            "cve_ids": list(finding.cve_ids),
                            "cvss_score": finding.cvss_score,
                            "tags": list(finding.tags),
                            "reference": list(finding.reference),
                        },
                        severity=finding.severity,
                        url=finding.matched_url or None,
                        title=finding.name or finding.template_id,
                    )
                )
    return out


def rows_for(
    *,
    observations: list[Observation],
    scan_run_id: str,
    plan_item_id: str,
    execution_id: str,
    audit_event_id: str | None,
    stage: str,
    step: str,
    tool_id: ToolId,
) -> list[dict[str, Any]]:
    """Build insertable evidence rows with mandatory provenance."""
    rows: list[dict[str, Any]] = []
    for obs in observations:
        key = obs.finding_key()
        rows.append(
            {
                # Deterministic id: re-folding the same observation from the
                # same execution yields the same row, so the insert is a no-op
                # rather than a duplicate.
                "finding_id": hashlib.sha256(
                    f"{execution_id}|{key}".encode("utf-8")
                ).hexdigest()[:48],
                "scan_run_id": scan_run_id,
                "execution_id": execution_id,
                "audit_event_id": audit_event_id,
                "plan_item_id": plan_item_id,
                "stage": stage,
                "step": step,
                "tool_id": tool_id.value,
                "finding_key": key,
                "canonical_target": obs.canonical_target,
                "observation_type": obs.observation_type,
                "observation": obs.observation,
                "severity": obs.severity,
                "title": obs.title,
                "port": obs.port,
                "url": obs.url,
                "verification_status": AssuranceStatus.NOT_VERIFIED.value,
                "enrichment_status": AssuranceStatus.NOT_PERFORMED.value,
            }
        )
    return rows

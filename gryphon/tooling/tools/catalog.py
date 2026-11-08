"""Tool catalog — maps a tool id to its descriptor, arg builder and result parser.

A closed, enumerable surface. Adding a tool is a MINOR change requiring its own
descriptor, builder, model and tests.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from gryphon.tooling.constants import ToolId
from gryphon.tooling.tools.descriptors import ToolDescriptor, get_descriptor
from gryphon.tooling.tools.models import (
    CrawlResult,
    DnsRecord,
    DnsResolveResult,
    HttpProbeResult,
    HttpxRecord,
    NucleiFinding,
    NucleiScanResult,
    PortRecord,
    PortScanResult,
    SubdomainResult,
    TlsInspectResult,
    TlsRecord,
)
from gryphon.tooling.tools.sanitize import ParsedJsonl


def descriptor_for(tool_id: ToolId) -> ToolDescriptor:
    return get_descriptor(tool_id)


def _s(value: Any) -> str | None:
    return str(value) if value is not None else None


def build_result(tool_id: ToolId, target: str, parsed: ParsedJsonl) -> BaseModel:
    """Project parsed JSONL records into the tool's structured result model."""
    rows = parsed.records
    if tool_id is ToolId.SUBFINDER:
        subs = sorted({r.get("host", "") for r in rows if r.get("host")})
        sources = sorted({r.get("source", "") for r in rows if r.get("source")})[:10]
        return SubdomainResult(
            domain=target, subdomains=subs, total_found=len(subs), sources_used=sources
        )
    if tool_id is ToolId.HTTPX:
        recs = [
            HttpxRecord(
                url=r.get("url") or r.get("input") or "",
                status_code=r.get("status_code") or r.get("status-code"),
                title=r.get("title"),
                webserver=r.get("webserver") or r.get("web_server"),
                technologies=list(r.get("tech") or r.get("technologies") or []),
                content_length=r.get("content_length") or r.get("content-length"),
            )
            for r in rows
        ]
        return HttpProbeResult(target=target, records=recs, total=len(recs))
    if tool_id is ToolId.NAABU:
        recs = [
            PortRecord(host=r.get("host") or target, ip=_s(r.get("ip")), port=int(r.get("port", 0)))
            for r in rows
            if r.get("port") is not None
        ]
        return PortScanResult(target=target, records=recs, total=len(recs))
    if tool_id is ToolId.KATANA:
        # katana nests the crawled endpoint under "request" (verified v1.8.0);
        # the flat forms are kept as fallbacks for other versions.
        urls: set[str] = set()
        for r in rows:
            request = r.get("request") if isinstance(r.get("request"), dict) else {}
            endpoint = (
                request.get("endpoint")
                or request.get("url")
                or r.get("endpoint")
                or r.get("url")
            )
            if endpoint:
                urls.add(str(endpoint))
        return CrawlResult(target=target, urls=sorted(urls), total=len(urls))
    if tool_id is ToolId.DNSX:
        recs = [
            DnsRecord(
                host=r.get("host") or target,
                a=list(r.get("a") or []),
                aaaa=list(r.get("aaaa") or []),
                cname=list(r.get("cname") or []),
            )
            for r in rows
        ]
        return DnsResolveResult(target=target, records=recs, total=len(recs))
    if tool_id is ToolId.TLSX:
        recs = [
            TlsRecord(
                host=r.get("host") or target,
                port=r.get("port"),
                subject_cn=r.get("subject_cn") or r.get("subject_an_cn"),
                issuer=r.get("issuer_cn") or r.get("issuer"),
                not_after=_s(r.get("not_after")),
                tls_versions=list(r.get("tls_version") or r.get("version") or []) if isinstance(
                    r.get("tls_version") or r.get("version"), list
                ) else ([str(r.get("tls_version"))] if r.get("tls_version") else []),
            )
            for r in rows
        ]
        return TlsInspectResult(target=target, records=recs, total=len(recs))
    if tool_id is ToolId.NUCLEI:
        findings = []
        for r in rows:
            info = r.get("info", {}) if isinstance(r.get("info"), dict) else {}
            classification = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}
            findings.append(
                NucleiFinding(
                    template_id=r.get("template-id") or r.get("template_id") or "",
                    name=info.get("name", ""),
                    severity=str(info.get("severity", "info")).upper(),
                    matched_url=r.get("matched-at") or r.get("matched_at") or "",
                    description=info.get("description", ""),
                    cve_ids=list(classification.get("cve-id") or classification.get("cve_id") or []),
                    cvss_score=classification.get("cvss-score") or classification.get("cvss_score"),
                    tags=list(info.get("tags") or []),
                    reference=list(info.get("reference") or []),
                )
            )
        critical = sum(1 for f in findings if f.severity == "CRITICAL")
        high = sum(1 for f in findings if f.severity == "HIGH")
        return NucleiScanResult(
            target=target,
            findings=findings,
            total_findings=len(findings),
            critical_count=critical,
            high_count=high,
        )
    raise ValueError(f"no result builder for tool {tool_id}")  # pragma: no cover

"""Structured, bounded result models for each tool (one schema per tool).

These are output projections of the tools' JSONL, validated by Pydantic. The
sanitizer bounds collection sizes and redacts secrets before records leave the
execution boundary.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class _Record(BaseModel):
    model_config = ConfigDict(extra="ignore")


# ---- subfinder --------------------------------------------------------------
class SubdomainResult(_Record):
    domain: str
    subdomains: list[str] = Field(default_factory=list)
    total_found: int = 0
    sources_used: list[str] = Field(default_factory=list)


# ---- httpx ------------------------------------------------------------------
class HttpxRecord(_Record):
    url: str
    status_code: int | None = None
    title: str | None = None
    webserver: str | None = None
    technologies: list[str] = Field(default_factory=list)
    content_length: int | None = None


class HttpProbeResult(_Record):
    target: str
    records: list[HttpxRecord] = Field(default_factory=list)
    total: int = 0


# ---- naabu ------------------------------------------------------------------
class PortRecord(_Record):
    host: str
    ip: str | None = None
    port: int


class PortScanResult(_Record):
    target: str
    records: list[PortRecord] = Field(default_factory=list)
    total: int = 0


# ---- katana -----------------------------------------------------------------
class CrawlResult(_Record):
    target: str
    urls: list[str] = Field(default_factory=list)
    total: int = 0


# ---- dnsx -------------------------------------------------------------------
class DnsRecord(_Record):
    host: str
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)


class DnsResolveResult(_Record):
    target: str
    records: list[DnsRecord] = Field(default_factory=list)
    total: int = 0


# ---- tlsx -------------------------------------------------------------------
class TlsRecord(_Record):
    host: str
    port: int | None = None
    subject_cn: str | None = None
    issuer: str | None = None
    not_after: str | None = None
    tls_versions: list[str] = Field(default_factory=list)


class TlsInspectResult(_Record):
    target: str
    records: list[TlsRecord] = Field(default_factory=list)
    total: int = 0


# ---- nuclei -----------------------------------------------------------------
class NucleiFinding(_Record):
    template_id: str
    name: str = ""
    severity: str = "INFO"
    matched_url: str = ""
    description: str = ""
    cve_ids: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    tags: list[str] = Field(default_factory=list)
    reference: list[str] = Field(default_factory=list)


class NucleiScanResult(_Record):
    target: str
    findings: list[NucleiFinding] = Field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0


__all__ = [
    "SubdomainResult",
    "HttpxRecord",
    "HttpProbeResult",
    "PortRecord",
    "PortScanResult",
    "CrawlResult",
    "DnsRecord",
    "DnsResolveResult",
    "TlsRecord",
    "TlsInspectResult",
    "NucleiFinding",
    "NucleiScanResult",
]

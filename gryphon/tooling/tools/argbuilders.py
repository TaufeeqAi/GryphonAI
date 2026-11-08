"""Per-tool argument-vector builders (pure, data-driven, no shell).

Each builder returns a list of arguments (never a shell string). Safe defaults
are always applied: structured JSONL output, conservative rate limits, bounded
timeouts, and — for nuclei — destructive-tag exclusion, template-protocol
exclusion of host code execution, and disabled out-of-band interaction. Depth
controls which tag classes are additionally excluded.
"""

from __future__ import annotations

from gryphon.constants import ScanDepth
from gryphon.tooling.tools.descriptors import ToolDescriptor
from gryphon.tooling.tools.models import (
    CrawlResult,
    DnsResolveResult,
    HttpProbeResult,
    NucleiScanResult,
    PortScanResult,
    SubdomainResult,
    TlsInspectResult,
)
from gryphon.tooling.constants import ToolId


def _depth_excluded_tags(descriptor: ToolDescriptor, depth: ScanDepth) -> list[str]:
    tags = list(descriptor.destructive_tag_classes)  # always-excluded (dos, fuzz)
    if depth is ScanDepth.PASSIVE:
        tags += ["intrusive", "network", "exposure"]
    elif depth is ScanDepth.STANDARD:
        tags += ["intrusive"]
    # aggressive: only the always-excluded destructive classes
    # de-duplicate while preserving order
    seen: set[str] = set()
    ordered: list[str] = []
    for tag in tags:
        if tag not in seen:
            seen.add(tag)
            ordered.append(tag)
    return ordered


def build_subfinder(d: ToolDescriptor, target: str, depth: ScanDepth) -> list[str]:
    return ["-d", target, "-json", "-silent", "-max-time", "60", "-rate-limit", str(d.rate_limit_floor)]


def build_httpx(d: ToolDescriptor, target: str, depth: ScanDepth) -> list[str]:
    return [
        "-u", target, "-json", "-silent", "-no-color",
        "-rate-limit", str(d.rate_limit_floor), "-timeout", "10",
        "-title", "-tech-detect", "-status-code", "-web-server", "-content-length",
    ]


def build_naabu(d: ToolDescriptor, target: str, depth: ScanDepth) -> list[str]:
    return [
        "-host", target, "-json", "-silent", "-no-color",
        "-rate", str(d.rate_limit_floor), "-top-ports", "100",
    ]


def build_katana(d: ToolDescriptor, target: str, depth: ScanDepth) -> list[str]:
    depth_flag = "1" if depth is ScanDepth.PASSIVE else ("2" if depth is ScanDepth.STANDARD else "3")
    # katana emits `-jsonl`; it has no `-json` flag (verified against v1.8.0).
    # `-omit-raw`/`-omit-body` keep raw requests and response bodies out of the
    # captured output: smaller, and nothing sensitive is retained from a target.
    return [
        "-u", target, "-jsonl", "-silent", "-no-color", "-omit-raw", "-omit-body",
        "-rate-limit", str(d.rate_limit_floor), "-depth", depth_flag, "-timeout", "10",
    ]


def build_dnsx(d: ToolDescriptor, target: str, depth: ScanDepth) -> list[str]:
    return [
        "-d", target, "-json", "-silent", "-no-color",
        "-rate-limit", str(d.rate_limit_floor), "-a", "-aaaa", "-cname",
    ]


def build_tlsx(d: ToolDescriptor, target: str, depth: ScanDepth) -> list[str]:
    # tlsx has no rate limiter (verified against v1.4.0): `-c` caps concurrency,
    # which is the only throttle it offers. The gateway's aggregate budgets and
    # the per-run token bucket remain the primary rate control.
    # Its `-json` record already carries subject_cn, subject_an, issuer_cn,
    # not_after and tls_version, and `-cn`/`-san` are refused in combination with
    # other probes, so no display probes are passed.
    return [
        "-u", target, "-json", "-silent", "-no-color",
        "-c", str(d.rate_limit_floor),
    ]


def build_nuclei(d: ToolDescriptor, target: str, depth: ScanDepth) -> list[str]:
    severity = "critical,high,medium" if depth is ScanDepth.PASSIVE else "critical,high,medium,low"
    args = [
        "-target", target, "-jsonl", "-silent", "-no-color",
        "-rate-limit", str(d.rate_limit_floor), "-timeout", "10",
        "-severity", severity,
        "-exclude-tags", ",".join(_depth_excluded_tags(d, depth)),
        # Containment: never execute host-code template protocols; never OOB.
        "-exclude-type", ",".join(d.prohibited_template_protocols) or "code",
        "-no-interactsh",
        "-disable-update-check",
    ]
    return args


_BUILDERS = {
    ToolId.SUBFINDER: build_subfinder,
    ToolId.HTTPX: build_httpx,
    ToolId.NAABU: build_naabu,
    ToolId.KATANA: build_katana,
    ToolId.DNSX: build_dnsx,
    ToolId.TLSX: build_tlsx,
    ToolId.NUCLEI: build_nuclei,
}

_RESULT_MODELS = {
    ToolId.SUBFINDER: SubdomainResult,
    ToolId.HTTPX: HttpProbeResult,
    ToolId.NAABU: PortScanResult,
    ToolId.KATANA: CrawlResult,
    ToolId.DNSX: DnsResolveResult,
    ToolId.TLSX: TlsInspectResult,
    ToolId.NUCLEI: NucleiScanResult,
}


def build_argv(tool_id: ToolId, descriptor: ToolDescriptor, target: str, depth: ScanDepth) -> list[str]:
    return _BUILDERS[tool_id](descriptor, target, depth)


def result_model_for(tool_id: ToolId):  # noqa: ANN201 - returns a pydantic model class
    return _RESULT_MODELS[tool_id]

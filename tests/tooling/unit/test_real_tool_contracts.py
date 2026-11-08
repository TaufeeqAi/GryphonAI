"""Facts verified against the pinned binaries, locked in so they cannot regress.

Every assertion here was established by running the real tool
(``python -m scripts.verify_tool_binaries`` against the pinned manifest on
2026-11-08) and the fixtures are that run's actual output. These tests need no
binaries, so the contract is enforced on every platform and in CI.

If a version bump changes any of this, these fail first -- which is the point:
a silently rejected flag is a control that is not applied, and a silently
unparsed field is a finding that is never reported.
"""

from __future__ import annotations

import json

import pytest

from gryphon.constants import ScanDepth
from gryphon.tooling.constants import MAX_RESULT_RECORDS, ToolId
from gryphon.tooling.tools.argbuilders import build_argv
from gryphon.tooling.tools.catalog import build_result
from gryphon.tooling.tools.descriptors import get_descriptor
from gryphon.tooling.tools.sanitize import parse_jsonl

pytestmark = pytest.mark.unit

TARGET = "app.example.com"


def _argv(tool_id: ToolId, depth: ScanDepth = ScanDepth.STANDARD) -> list[str]:
    return build_argv(tool_id, get_descriptor(tool_id), TARGET, depth)


def _projected(tool_id: ToolId, lines: list[dict]) -> object:
    stdout = "\n".join(json.dumps(line) for line in lines)
    parsed = parse_jsonl(stdout, max_records=MAX_RESULT_RECORDS)
    return build_result(tool_id, TARGET, parsed)


# =============================================================================
# Flags the binaries actually accept
# =============================================================================
def test_katana_uses_jsonl_because_json_does_not_exist() -> None:
    argv = _argv(ToolId.KATANA)
    assert "-jsonl" in argv
    assert "-json" not in argv, "katana v1.8.0 rejects -json: 'flag provided but not defined'"


def test_katana_does_not_retain_raw_requests_or_bodies() -> None:
    argv = _argv(ToolId.KATANA)
    assert "-omit-raw" in argv and "-omit-body" in argv


def test_tlsx_throttles_with_concurrency_and_passes_no_display_probes() -> None:
    argv = _argv(ToolId.TLSX)
    assert "-c" in argv, "tlsx has no rate limiter; -c is its only throttle"
    assert "-rate-limit" not in argv, "tlsx v1.4.0 has no -rate-limit flag"
    # tlsx refuses: "san or cn flag cannot be used with other probes".
    assert "-cn" not in argv and "-san" not in argv


def test_nuclei_containment_flags_are_passed() -> None:
    argv = _argv(ToolId.NUCLEI)
    assert "-no-interactsh" in argv, "out-of-band interaction must be disabled"
    assert "-disable-update-check" in argv
    exclude_type = argv[argv.index("-exclude-type") + 1]
    assert "code" in exclude_type, "host-code template protocols must be excluded"
    excluded_tags = argv[argv.index("-exclude-tags") + 1]
    assert "dos" in excluded_tags and "fuzz" in excluded_tags


def test_every_tool_requests_machine_readable_output() -> None:
    for tool_id in ToolId:
        argv = _argv(tool_id)
        assert any(flag in argv for flag in ("-json", "-jsonl")), tool_id


# =============================================================================
# Projections against real captured output
# =============================================================================
def test_katana_projection_reads_the_nested_endpoint() -> None:
    """katana nests the crawled URL under "request" -- flat lookups find nothing."""
    row = {
        "timestamp": "2026-11-08T20:04:46.424869415Z",
        "request": {"method": "GET", "endpoint": "http://127.0.0.1:44849/linked"},
        "response": {"status_code": 200},
    }
    result = _projected(ToolId.KATANA, [row])
    assert result.urls == ["http://127.0.0.1:44849/linked"]
    assert result.total == 1


def test_katana_projection_still_accepts_a_flat_endpoint() -> None:
    result = _projected(ToolId.KATANA, [{"endpoint": "http://a.example/x"}])
    assert result.urls == ["http://a.example/x"]


def test_httpx_projection_against_real_output() -> None:
    row = {
        "timestamp": "2026-11-08T20:02:27.666189969Z",
        "port": "18099",
        "url": "http://127.0.0.1:18099",
        "input": "http://127.0.0.1:18099",
        "title": "Directory listing for /",
        "scheme": "http",
        "webserver": "SimpleHTTP/0.6 Python/3.12.3",
        "host": "127.0.0.1",
        "tech": ["Python:3.12.3", "SimpleHTTP:0.6"],
        "status_code": 200,
        "content_length": 1246,
        "failed": False,
    }
    result = _projected(ToolId.HTTPX, [row])
    assert result.total == 1
    record = result.records[0]
    assert record.url == "http://127.0.0.1:18099"
    assert record.status_code == 200
    assert record.title == "Directory listing for /"
    assert record.webserver.startswith("SimpleHTTP/")
    assert "Python:3.12.3" in record.technologies
    assert record.content_length == 1246


def test_tlsx_projection_against_real_output() -> None:
    row = {
        "host": "127.0.0.1",
        "ip": "127.0.0.1",
        "port": "42107",  # tlsx emits the port as a string
        "probe_status": True,
        "tls_version": "tls13",  # a scalar, not a list
        "cipher": "TLS_AES_256_GCM_SHA384",
        "self_signed": True,
        "not_before": "2026-11-08T19:59:57Z",
        "not_after": "2026-11-08T21:04:57Z",
        "subject_cn": "gryphon-conformance.local",
        "subject_an": ["gryphon-conformance.local"],
        "issuer_cn": "gryphon-conformance.local",
    }
    result = _projected(ToolId.TLSX, [row])
    assert result.total == 1
    record = result.records[0]
    assert record.port == 42107, "the string port must coerce to an int"
    assert record.subject_cn == "gryphon-conformance.local"
    assert record.issuer == "gryphon-conformance.local"
    assert record.not_after == "2026-11-08T21:04:57Z"
    assert record.tls_versions == ["tls13"], "a scalar version must become a list"


def test_naabu_projection_against_real_output() -> None:
    result = _projected(
        ToolId.NAABU, [{"ip": "127.0.0.1", "port": 8099, "host": "127.0.0.1"}]
    )
    assert result.total == 1
    assert result.records[0].port == 8099


def test_subfinder_projection_deduplicates_hosts() -> None:
    result = _projected(
        ToolId.SUBFINDER,
        [
            {"host": "a.app.example.com", "source": "crtsh"},
            {"host": "a.app.example.com", "source": "hackertarget"},
            {"host": "b.app.example.com", "source": "crtsh"},
        ],
    )
    assert result.total_found == 2
    assert result.subdomains == ["a.app.example.com", "b.app.example.com"]
    assert set(result.sources_used) == {"crtsh", "hackertarget"}

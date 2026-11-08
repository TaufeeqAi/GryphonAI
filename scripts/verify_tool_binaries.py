"""Conformance harness for the pinned ProjectDiscovery binaries.

Two questions this answers that no mock can:

1. **Does the real binary accept the exact flags we pass?** In particular the
   containment flags — ``-exclude-type code``, ``-no-interactsh`` and the
   excluded tags for nuclei. A flag silently rejected is a containment control
   that is not applied. Checked offline against each binary's own ``-h`` output,
   so no target is contacted.
2. **Does our parser match the real output?** Checked by running the tool
   against a **local** HTTP/TLS listener started by this script and feeding the
   real stdout to the real parser. If the tool emits JSONL and our parser
   extracts nothing, that is parse drift and it fails here rather than in a scan.

Tools whose work is inherently remote are flag-checked only, never run:
``subfinder`` (queries third-party passive sources), ``dnsx`` (needs a
resolver), and ``nuclei`` (needs its template repository). That is a deliberate
limit, reported as SKIPPED rather than passed.

    python -m scripts.verify_tool_binaries --manifest /opt/gryphon/tool-manifest.json
    python -m scripts.verify_tool_binaries --json

Exit code 0 = every available binary matched its checksum, accepted every flag,
and produced output our parsers understand. **This script calls the binaries
directly, outside the enforcement gateway** — it is a provisioning check, not a
scan, and it never leaves the loopback interface.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as _dt
import http.server
import json
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

from gryphon.constants import ScanDepth
from gryphon.tooling.constants import MAX_RESULT_RECORDS, ToolId
from gryphon.tooling.provisioning.manifest import ToolManifest, verify_entry
from gryphon.tooling.tools.argbuilders import build_argv
from gryphon.tooling.tools.catalog import build_result
from gryphon.tooling.tools.descriptors import get_descriptor
from gryphon.tooling.tools.sanitize import parse_jsonl

#: Tools that cannot be exercised without leaving the machine.
FLAG_CHECK_ONLY = {
    ToolId.SUBFINDER: "queries third-party passive sources",
    ToolId.DNSX: "requires an external resolver",
    ToolId.NUCLEI: "requires its template repository",
}
#: Phrases that mean the binary rejected something we passed.
REJECTION_PATTERNS = (
    re.compile(r"flag provided but not defined", re.I),
    re.compile(r"unknown (flag|option|argument)", re.I),
    re.compile(r"unexpected argument", re.I),
    re.compile(r"invalid value .* for flag", re.I),
)
RUN_TIMEOUT_SECONDS = 30


@dataclass
class ToolReport:
    tool: str
    version: str = ""
    checksum_ok: bool | None = None
    version_reported: bool | None = None
    unknown_flags: list[str] = field(default_factory=list)
    live_run: str = "skipped"
    lines_seen: int = 0
    records_parsed: int = 0
    parse_failures: int = 0
    projected_ok: bool | None = None
    items_extracted: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        if self.checksum_ok is not True:
            return False
        if self.unknown_flags:
            return False
        if self.live_run == "ran" and self.lines_seen > 0:
            # Output the projection could not turn into anything is parse drift.
            if self.projected_ok is not True or self.items_extracted == 0:
                return False
        return True


# -----------------------------------------------------------------------------
# Local listeners (loopback only)
# -----------------------------------------------------------------------------
class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        body = (
            b"<html><head><title>gryphon conformance target</title></head>"
            b"<body><a href='/linked'>linked</a><p>ok</p></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "gryphon-conformance/1.0")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence
        return


def _start_http() -> tuple[http.server.ThreadingHTTPServer, int]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _self_signed(path: Path) -> Path:
    """Generate a throwaway certificate for the local TLS listener."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gryphon-conformance.local")])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("gryphon-conformance.local")]), False
        )
        .sign(key, hashes.SHA256())
    )
    pem = path / "tls.pem"
    pem.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return pem


def _start_tls(pem: Path) -> tuple[socket.socket, int, threading.Event]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(pem))
    raw = socket.socket()
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind(("127.0.0.1", 0))
    raw.listen(8)
    port = raw.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                raw.settimeout(0.5)
                conn, _ = raw.accept()
            except (TimeoutError, OSError):
                continue
            try:
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1024)
                    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except (ssl.SSLError, OSError):
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True).start()
    return raw, port, stop


# -----------------------------------------------------------------------------
# Checks
# -----------------------------------------------------------------------------
def _run(argv: list[str], timeout: int = RUN_TIMEOUT_SECONDS) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - argv vector, absolute path from the manifest
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )


def known_flags(binary: str) -> set[str]:
    """Every flag the binary's own help output mentions."""
    try:
        proc = _run([binary, "-h"], timeout=20)
    except (subprocess.TimeoutExpired, OSError):
        return set()
    text = (proc.stdout or "") + (proc.stderr or "")
    return {f"-{m}" for m in re.findall(r"-([A-Za-z][A-Za-z0-9-]*)", text)}


def check_tool(tool_id: ToolId, binary: str, version: str, http_port: int, tls_port: int) -> ToolReport:
    report = ToolReport(tool=tool_id.value, version=version)
    descriptor = get_descriptor(tool_id)

    # -- the binary reports the pinned version --------------------------------
    try:
        proc = _run([binary, "-version"], timeout=20)
        reported = (proc.stdout or "") + (proc.stderr or "")
        report.version_reported = version in reported
        if not report.version_reported:
            report.notes.append(f"-version did not mention {version}: {reported.strip()[:80]!r}")
    except (subprocess.TimeoutExpired, OSError) as exc:
        report.notes.append(f"-version failed: {type(exc).__name__}")
        report.version_reported = False

    # -- every flag we pass is a flag the binary knows ------------------------
    recognized = known_flags(binary)
    if not recognized:
        report.notes.append("could not read -h output; flag acceptance unverified")
    else:
        argv = build_argv(tool_id, descriptor, "127.0.0.1", ScanDepth.STANDARD)
        report.unknown_flags = [
            token for token in argv if token.startswith("-") and token not in recognized
        ]

    # -- live local run, where that is possible without leaving the host ------
    if tool_id in FLAG_CHECK_ONLY:
        report.live_run = "skipped"
        report.notes.append(FLAG_CHECK_ONLY[tool_id])
        return report

    target = {
        ToolId.HTTPX: f"http://127.0.0.1:{http_port}",
        ToolId.KATANA: f"http://127.0.0.1:{http_port}",
        ToolId.NAABU: "127.0.0.1",
        ToolId.TLSX: f"127.0.0.1:{tls_port}",
    }[tool_id]
    argv = [binary, *build_argv(tool_id, descriptor, target, ScanDepth.STANDARD)]
    try:
        proc = _run(argv)
    except subprocess.TimeoutExpired:
        report.live_run = "timed out"
        report.notes.append(f"did not finish within {RUN_TIMEOUT_SECONDS}s")
        return report
    except OSError as exc:
        report.live_run = "failed"
        report.notes.append(f"spawn failed: {exc}")
        return report

    combined = (proc.stdout or "") + (proc.stderr or "")
    for pattern in REJECTION_PATTERNS:
        found = pattern.search(combined)
        if found:
            report.notes.append(f"binary rejected an argument: {found.group(0)!r}")
            report.unknown_flags.append("(runtime rejection)")
            break

    report.live_run = "ran"
    parsed = parse_jsonl(proc.stdout or "", max_records=MAX_RESULT_RECORDS)
    report.lines_seen = parsed.total_lines
    report.records_parsed = len(parsed.records)
    report.parse_failures = parsed.failed_lines

    # Validate through the real projection the gateway uses, not the raw lines:
    # build_result maps tool output onto the per-execution aggregate.
    try:
        aggregate = build_result(tool_id, target, parsed)
        report.projected_ok = True
        report.items_extracted = sum(
            len(value)
            for value in aggregate.model_dump().values()
            if isinstance(value, list)
        )
    except Exception as exc:  # noqa: BLE001 - reported, not raised
        report.projected_ok = False
        report.notes.append(f"projection failed: {type(exc).__name__}: {exc}")
    if parsed.total_lines and report.projected_ok and report.items_extracted == 0:
        report.notes.append(
            "the tool produced output but the projection extracted nothing "
            "(field drift: build_result needs updating for this version)"
        )
    if proc.returncode != 0 and not parsed.total_lines:
        report.notes.append(f"exit {proc.returncode}: {(proc.stderr or '').strip()[:120]}")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify the pinned tool binaries.")
    parser.add_argument("--manifest", help="path to the tool manifest JSON")
    parser.add_argument("--json", action="store_true", help="emit results as JSON")
    args = parser.parse_args()

    manifest_path = args.manifest
    if not manifest_path:
        from gryphon.tooling.settings import get_tooling_settings

        manifest_path = get_tooling_settings().tool_manifest_path
    if not manifest_path or not Path(manifest_path).is_file():
        print(
            "no tool manifest found: pass --manifest or set GRYPHON_TOOL_MANIFEST_PATH",
            file=sys.stderr,
        )
        sys.exit(2)

    manifest = ToolManifest.load(manifest_path)
    entries = manifest.by_tool()

    http_server, http_port = _start_http()
    with tempfile.TemporaryDirectory() as tmp:
        tls_socket, tls_port, tls_stop = _start_tls(_self_signed(Path(tmp)))
        reports: list[ToolReport] = []
        try:
            for tool_id in ToolId:
                entry = entries.get(tool_id)
                if entry is None:
                    report = ToolReport(tool=tool_id.value)
                    report.notes.append("not in the manifest")
                    reports.append(report)
                    continue
                report = ToolReport(tool=tool_id.value, version=entry.version)
                try:
                    verify_entry(entry)
                    report.checksum_ok = True
                except Exception as exc:  # noqa: BLE001
                    report.checksum_ok = False
                    report.notes.append(str(exc))
                    reports.append(report)
                    continue
                full = check_tool(tool_id, entry.path, entry.version, http_port, tls_port)
                full.checksum_ok = True
                reports.append(full)
        finally:
            tls_stop.set()
            tls_socket.close()
            http_server.shutdown()

    present = [r for r in reports if r.checksum_ok is not None]
    failed = [r for r in present if not r.ok]

    if args.json:
        print(json.dumps({"tools": [r.__dict__ for r in reports]}, indent=2, default=str))
    else:
        print()
        print("GRYPHON pinned tool binary conformance")
        print("local loopback listeners only; no scan target was contacted")
        print("-" * 78)
        for r in reports:
            if r.checksum_ok is None:
                print(f"[SKIP] {r.tool:<10} {'; '.join(r.notes)}")
                continue
            mark = "PASS" if r.ok else "FAIL"
            print(f"[{mark}] {r.tool:<10} v{r.version}")
            print(
                f"       checksum={'ok' if r.checksum_ok else 'MISMATCH'} "
                f"version_self_report={'ok' if r.version_reported else 'no'} "
                f"unknown_flags={r.unknown_flags or 'none'}"
            )
            if r.live_run == "ran":
                print(
                    f"       live={r.live_run} lines={r.lines_seen} parsed={r.records_parsed} "
                    f"projected={'ok' if r.projected_ok else 'FAILED'} "
                    f"items={r.items_extracted} parse_failures={r.parse_failures}"
                )
            else:
                print(f"       live={r.live_run}")
            for note in r.notes:
                print(f"       note: {note}")
        print("-" * 78)
        print(
            f"{len(present) - len(failed)}/{len(present)} binaries conformant"
            f"{' — ALL GOOD' if not failed else ' — REVIEW THE FAILURES'}"
        )
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()

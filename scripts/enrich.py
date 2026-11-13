"""Operator CLI for the enrichment layer.

Every command identifies its caller by the process's real uid (enforced against
``GRYPHON_ENRICHMENT_ALLOWED_UIDS``) and records it as ``initiated_by`` on every
pass, attempt and signed event.

    python -m scripts.enrich start <scan_run_id> [--refresh] [--json]
    python -m scripts.enrich status [<scan_run_id>] [--json]
    python -m scripts.enrich report <scan_run_id> [--out enrichment.json]
    python -m scripts.enrich refresh [--source KEV|EPSS] [--json]
    python -m scripts.enrich abort <scan_run_id> [--detail TEXT]
    python -m scripts.enrich revoke <snapshot_id> --reason TEXT

``start`` is also resume: an interrupted pass for the scan is adopted and
finished from its recorded pins. ``report`` re-verifies the report's digest and
signed attestation and refuses to print one that does not verify.

Exit codes: 0 ok · 1 unexpected error · 2 usage or invalid id · 3 configuration
refused · 4 slot busy · 5 pass refused · 6 pass abandoned · 7 no report or
report failed verification · 8 caller rejected.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from gryphon.enrichment.bootstrap import build_enrichment_services
from gryphon.enrichment.constants import NETWORK_SOURCES, PassState, Source
from gryphon.enrichment.identity import local_cli_identity
from gryphon.enrichment.reasons import (
    CallerRejected,
    EnrichmentConfigurationError,
    InvalidScanId,
    SlotBusy,
)
from gryphon.logging_config import configure_logging

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_BUSY = 4
EXIT_REFUSED = 5
EXIT_ABANDONED = 6
EXIT_NO_REPORT = 7
EXIT_CALLER = 8


def _print(payload: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return
    for key, value in payload.items():
        if isinstance(value, dict | list):
            value = json.dumps(value, sort_keys=True, default=str)
        print(f"{key:<16} {value}")


async def _dispatch(args: argparse.Namespace) -> int:
    try:
        services = build_enrichment_services()
    except EnrichmentConfigurationError as exc:
        print(f"refusing to start: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    try:
        try:
            caller = local_cli_identity(allowed_uids=services.settings.allowed_uids)
        except CallerRejected as exc:
            print(f"caller rejected: {exc}", file=sys.stderr)
            return EXIT_CALLER
        engine = services.engine

        if args.command == "start":
            result = await engine.run_pass(args.scan_run_id, caller=caller, refresh=args.refresh)
            _print(result.as_payload(), as_json=args.json)
            if result.state == PassState.REFUSED.value:
                return EXIT_REFUSED
            if result.state == PassState.ABANDONED.value:
                return EXIT_ABANDONED
            return EXIT_OK

        if args.command == "status":
            status = await engine.status(args.scan_run_id)
            _print(status, as_json=args.json)
            return EXIT_OK

        if args.command == "report":
            served = await engine.report(args.scan_run_id)
            if served is None:
                print("no completed enrichment pass for that scan", file=sys.stderr)
                return EXIT_NO_REPORT
            if not served.verification.verified:
                print(
                    f"report {served.report_id} FAILED verification: "
                    f"{served.verification.reason}; refusing to serve it",
                    file=sys.stderr,
                )
                return EXIT_NO_REPORT
            body = json.dumps(served.body, indent=2, sort_keys=True, default=str)
            if args.out:
                await asyncio.to_thread(
                    Path(args.out).write_text, body + "\n", encoding="utf-8"
                )
                print(f"wrote {args.out} ({served.report_id}, verified)")
            else:
                print(body)
            return EXIT_OK

        if args.command == "refresh":
            sources = (Source(args.source),) if args.source else NETWORK_SOURCES
            summary = await engine.refresh(caller=caller, sources=sources)
            payload: dict[str, Any] = {
                k: {"snapshot_id": v.snapshot_id, "acquired": v.acquired, "reason": v.reason}
                for k, v in summary.statuses.items()
            } or {"note": "no source was due or permitted"}
            _print(payload, as_json=args.json)
            failed = any(v.acquired == "REJECTED" for v in summary.statuses.values())
            return EXIT_ERROR if failed else EXIT_OK

        if args.command == "abort":
            aborted = await engine.abort(args.scan_run_id, caller=caller, detail=args.detail)
            if aborted is None:
                print("no unfinished pass for that scan", file=sys.stderr)
                return EXIT_ERROR
            _print(aborted.as_payload(), as_json=False)
            return EXIT_OK

        if args.command == "revoke":
            revoked = await engine.revoke_snapshot(
                args.snapshot_id, reason=args.reason, caller=caller
            )
            print("revoked" if revoked else "not revoked (unknown or already revoked)")
            return EXIT_OK if revoked else EXIT_ERROR

        print(f"unknown command: {args.command}", file=sys.stderr)
        return EXIT_USAGE
    except InvalidScanId as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE
    except SlotBusy as exc:
        print(f"busy: {exc}", file=sys.stderr)
        return EXIT_BUSY
    finally:
        await services.dispose()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="GRYPHON enrichment layer operator commands",
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="run or resume the enrichment pass for a scan")
    start.add_argument("scan_run_id")
    start.add_argument(
        "--refresh", action="store_true", help="force acquisition before pinning"
    )
    start.add_argument("--json", action="store_true")

    status = sub.add_parser("status", help="slot, snapshot freshness, a scan's passes")
    status.add_argument("scan_run_id", nargs="?")
    status.add_argument("--json", action="store_true")

    report = sub.add_parser("report", help="print the verified enrichment report")
    report.add_argument("scan_run_id")
    report.add_argument("--out", help="write to a file instead of stdout")

    refresh = sub.add_parser("refresh", help="force acquisition of public snapshots")
    refresh.add_argument("--source", choices=[s.value for s in NETWORK_SOURCES])
    refresh.add_argument("--json", action="store_true")

    abort = sub.add_parser("abort", help="abandon an unfinished pass whose process is gone")
    abort.add_argument("scan_run_id")
    abort.add_argument("--detail")

    revoke = sub.add_parser("revoke", help="revoke an accepted snapshot")
    revoke.add_argument("snapshot_id")
    revoke.add_argument("--reason", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    # Diagnostics go to stderr so stdout carries only the command's result.
    configure_logging(json_output=False, stream=sys.stderr)
    args = build_parser().parse_args(argv)
    try:
        return asyncio.run(_dispatch(args))
    except KeyboardInterrupt:
        print("interrupted; an unfinished pass resumes on the next start", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

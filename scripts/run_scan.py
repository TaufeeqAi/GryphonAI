"""Operator CLI for the scan orchestrator.

Every command authenticates its caller and is audited. The caller identity is
the process's real uid, not a value it supplies, and it is recorded as the
initiator of whatever it starts — "who started this scan?" is the first
question in any incident review, and it needs an answer that does not depend on
logs having survived.

    python -m scripts.run_scan start <scan_run_id>
    python -m scripts.run_scan status <scan_run_id> [--json]
    python -m scripts.run_scan abort <scan_run_id>
    python -m scripts.run_scan reconcile <scan_run_id>
    python -m scripts.run_scan sweep
    python -m scripts.run_scan report <scan_run_id> [--out report.json]

``start`` is also resume: invoking an interrupted scan continues it, and
invoking a finished one returns the recorded result rather than scanning again.

A ``scan_run_id`` comes from ``scripts.admit_scan``: it exists only because
the authorization core admitted a request, and this layer cannot create one.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from gryphon.logging_config import configure_logging
from gryphon.orchestration.bootstrap import build_orchestration_services
from gryphon.orchestration.commands import CallerRejected, local_cli_identity
from gryphon.orchestration.ledger import ReportRepository
from gryphon.orchestration.reasons import OrchestrationConfigurationError


async def _dispatch(args: argparse.Namespace) -> int:
    try:
        services = build_orchestration_services()
    except OrchestrationConfigurationError as exc:
        print(f"refusing to start: {exc}", file=sys.stderr)
        return 2

    try:
        try:
            caller = local_cli_identity(
                allowed_uids=services.settings.control_allowed_uids
            )
        except CallerRejected as exc:
            print(f"caller rejected: {exc}", file=sys.stderr)
            return 3

        commands = services.commands

        if args.command == "start":
            outcome = await commands.start(args.scan_run_id, caller=caller)
            print(f"scan      : {outcome.scan_run_id}")
            print(f"state     : {outcome.terminal_state.value}")
            print(f"reason    : {outcome.reason_code}")
            print(f"coverage  : {outcome.covered}/{outcome.planned}")
            if outcome.gaps:
                print(f"gaps      : {outcome.gaps}")
            if outcome.integrity:
                print(f"integrity : {outcome.integrity} (scan failed on integrity)")
            print(f"report    : {outcome.report_id or '(none)'}")
            if outcome.replayed:
                # Idempotency and "tell me about now" are different questions;
                # saying so prevents an old result being read as a fresh one.
                print(
                    f"replayed  : yes - recorded result from "
                    f"{outcome.completed_at or 'an earlier run'}; nothing was re-scanned"
                )
            return 0 if outcome.is_clean_completion or outcome.replayed else 1

        if args.command == "status":
            status = await commands.status(args.scan_run_id)
            if status is None:
                # An admitted scan has no ledger entry until `start` claims it.
                # Saying "no such scan" would blame the operator for an id that
                # is in fact valid and simply not started here yet.
                print(
                    "not started: no ledger entry for that scan "
                    "(admitted scans appear here only once `start` claims them)",
                    file=sys.stderr,
                )
                return 1
            if args.json:
                print(json.dumps(status.as_payload(), indent=2, default=str))
            else:
                for key, value in status.as_payload().items():
                    print(f"{key:<22} {value}")
            return 0

        if args.command in ("abort", "cancel"):
            ok = await commands.abort(args.scan_run_id, caller=caller)
            print("aborted" if ok else "could not abort (stale claim or no such scan)")
            return 0 if ok else 1

        if args.command == "reconcile":
            counts = await commands.reconcile(args.scan_run_id, caller=caller)
            print(
                f"examined {counts['examined']}, resolved {counts['resolved']}, "
                f"unresolved-possibly-contacted {counts['unresolved']}"
            )
            return 0

        if args.command == "sweep":
            report = await services.sweeper.sweep_once()
            print(
                f"reclaimed {report.reclaimed} abandoned, "
                f"retired {report.aborted_overdue} overdue"
            )
            return 0

        if args.command == "report":
            async with services.database.session() as session:
                row = await ReportRepository(session).latest_for_scan(args.scan_run_id)
            if row is None:
                print("no report for that scan", file=sys.stderr)
                return 1
            body = json.dumps(row.body, indent=2, default=str)
            if args.out:
                Path(args.out).write_text(body, encoding="utf-8")
                print(f"wrote {args.out} (digest {row.report_digest})")
            else:
                print(body)
            return 0

        print(f"unknown command: {args.command}", file=sys.stderr)
        return 2
    finally:
        await services.dispose()


def main() -> None:
    # Diagnostics go to stderr so that stdout carries only this command's
    # result, and the redaction processor is active for this process.
    configure_logging(json_output=False, stream=sys.stderr)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("start", "run or resume a scan"),
        ("abort", "force a scan to a terminal state without scanning further"),
        ("cancel", "alias for abort"),
        ("reconcile", "resolve indeterminate outcomes from recorded evidence"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("scan_run_id")

    p_status = sub.add_parser("status", help="read the versioned scan view")
    p_status.add_argument("scan_run_id")
    p_status.add_argument("--json", action="store_true")

    p_report = sub.add_parser("report", help="print or save the emitted report")
    p_report.add_argument("scan_run_id")
    p_report.add_argument("--out", help="write the report body to this path")

    sub.add_parser("sweep", help="reclaim abandoned scans and retire overdue ones")

    args = parser.parse_args()
    sys.exit(asyncio.run(_dispatch(args)))


if __name__ == "__main__":
    main()

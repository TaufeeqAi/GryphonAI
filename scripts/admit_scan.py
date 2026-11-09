"""Operator CLI to admit one scan against an issued grant (§11.4).

This is the missing step between ``issue_grant`` and ``run_scan``: a grant
authorizes a *scope*, a scan run is one admitted request *within* that scope,
and only the authorization core may create one. It prints the ``scan_run_id``
that the orchestrator's ``start`` command takes.

    python -m scripts.admit_scan --target staging.acme.example --token "$TOKEN"

Admission is idempotent on ``--idempotency-key``: re-running with the same key
and the same request returns a receipt for the original scan run instead of
admitting a second one. Omit the flag to admit a new scan each time.

A DENY is a committed, audited decision, not an error — it exits non-zero and
names the reason code. The permit minted here lives and dies inside this
process; what persists is the admission record the orchestrator re-resolves.
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import sys

from gryphon.auth.results import (
    AdmissionReplayReceipt,
    AuthorizedPermit,
    DeniedDecision,
    UnknownOutcome,
)
from gryphon.auth.service import ScanAdmissionRequest
from gryphon.bootstrap import build_services
from gryphon.clock import SystemClock
from gryphon.constants import ScanDepth
from gryphon.logging_config import configure_logging


async def _run(args: argparse.Namespace) -> int:
    services = build_services(clock=SystemClock())
    try:
        result = await services.authorization_service.authorize_scan(
            ScanAdmissionRequest(
                target=args.target,
                token=args.token,
                requested_depth=args.depth,
                idempotency_key=args.idempotency_key or secrets.token_hex(16),
                path=args.path,
            )
        )
    finally:
        await services.dispose()

    if isinstance(result, AuthorizedPermit):
        print(result.scan_run_id)
        print(
            f"# ADMITTED target={result.canonical_target} "
            f"depth={result.effective_scan_depth.value} grant={result.grant_id}",
            file=sys.stderr,
        )
        print(
            f"# next: python -m scripts.run_scan start {result.scan_run_id}",
            file=sys.stderr,
        )
        return 0

    if isinstance(result, AdmissionReplayReceipt):
        # Not a fresh admission. Printing the id still lets the operator act on
        # the original scan, but calling it new would be a lie.
        print(result.scan_run_id)
        print(
            f"# REPLAY of an earlier admission (stored status "
            f"{result.stored_status}); nothing new was admitted",
            file=sys.stderr,
        )
        return 0

    if isinstance(result, DeniedDecision):
        print(
            f"DENIED {result.reason_code.value} (scan_run {result.scan_run_id})",
            file=sys.stderr,
        )
        return 1

    if isinstance(result, UnknownOutcome):
        # Uncertain is not permitted. Say so plainly: no scan may start.
        print(
            f"UNKNOWN {result.reason_code.value} — no permit, no scan. "
            f"retry_after_reconciliation={result.retry_after_reconciliation}",
            file=sys.stderr,
        )
        return 2

    print(f"unexpected admission result: {type(result).__name__}", file=sys.stderr)
    return 2


def main() -> None:
    # Diagnostics go to stderr so that stdout carries only this command's
    # result, and the redaction processor is active for this process.
    configure_logging(json_output=False, stream=sys.stderr)
    parser = argparse.ArgumentParser(
        description="Admit one scan against an issued grant (local operator)."
    )
    parser.add_argument("--target", required=True, help="the single target to admit")
    parser.add_argument(
        "--token",
        required=True,
        help="the compact JWS grant token printed by scripts.issue_grant",
    )
    parser.add_argument(
        "--path",
        help="optional origin-form path, checked against the grant's exclusions",
    )
    parser.add_argument(
        "--depth",
        choices=[d.value for d in ScanDepth],
        default=ScanDepth.STANDARD.value,
        help="requested depth; the grant's maximum still wins",
    )
    parser.add_argument(
        "--idempotency-key",
        help="reuse to replay a prior admission instead of admitting a new scan",
    )
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()

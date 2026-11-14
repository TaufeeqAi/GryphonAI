"""Readiness probe for the verification layer.

Checks facts, not revision numbers: tables, views and monthly partitions,
enabled triggers and their function bodies, the dedicated role's exact
privileges *including every privilege that must be absent*, key and database
custody (one role, one key, non-owner, non-superuser, a restricted search path),
the signed registry and its pinned digests, the gateway's protocol and feature
set, this process's own import graph, and the observed egress posture. It also
prints the redacted effective configuration, so an operator sees what the
process loaded rather than what the deployment template says. Exit 0 means ready.

    python -m scripts.verification_readiness
    python -m scripts.verification_readiness --json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from gryphon.logging_config import configure_logging
from gryphon.verification.bootstrap import build_verification_services
from gryphon.verification.readiness import check_verification_readiness
from gryphon.verification.reasons import VerificationConfigurationError


async def _run(as_json: bool) -> int:
    try:
        services = build_verification_services()
    except VerificationConfigurationError as exc:
        # A startup refusal is itself the readiness answer: there is nothing to
        # probe, because the process that would do the probing declined to exist.
        payload = {"ready": False, "error": str(exc), "checks": []}
        print(json.dumps(payload, indent=2) if as_json else f"NOT READY\n  {exc}")
        return 1
    try:
        report = await check_verification_readiness(services)
    finally:
        await services.dispose()

    if as_json:
        print(json.dumps(report.as_payload(), indent=2, default=str))
    else:
        print(f"verification readiness ({report.environment}): "
              f"{'READY' if report.ready else 'NOT READY'}")
        for check in report.checks:
            mark = "PASS" if check.passed else ("FAIL" if check.fatal else "WARN")
            print(f"  [{mark}] {check.name:<32} {check.detail}")
    return 0 if report.ready else 1


def main(argv: list[str] | None = None) -> int:
    configure_logging(json_output=False, stream=sys.stderr)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    return asyncio.run(_run(args.json))


if __name__ == "__main__":
    sys.exit(main())

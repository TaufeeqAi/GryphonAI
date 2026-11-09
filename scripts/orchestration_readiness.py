"""Readiness probe for the orchestration layer.

Answers one question before a scan is attempted: *would this deployment enforce
what it claims to enforce?* Exit code 0 means ready, 1 means not.

    python -m scripts.orchestration_readiness
    python -m scripts.orchestration_readiness --json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from gryphon.orchestration.bootstrap import build_orchestration_services
from gryphon.orchestration.graph import topology
from gryphon.orchestration.readiness import check_orchestration_readiness
from gryphon.orchestration.reasons import OrchestrationConfigurationError

_PASS = "PASS"
_FAIL = "FAIL"


async def _run(as_json: bool) -> int:
    try:
        services = build_orchestration_services()
    except OrchestrationConfigurationError as exc:
        # A configuration refusal is itself the answer: the process would not
        # start, so reporting it here is more useful than a traceback.
        payload = {"ready": False, "error": str(exc), "checks": []}
        print(json.dumps(payload, indent=2) if as_json else f"NOT READY\n  {exc}")
        return 1

    try:
        report = await check_orchestration_readiness(
            database=services.database, settings=services.settings
        )
        topo = topology()

        if as_json:
            print(
                json.dumps(
                    {
                        "ready": report.ready,
                        "environment": report.environment,
                        "graph_version": topo["graph_version"],
                        "checkpointer": topo["checkpointer"],
                        "stages": topo["stages"],
                        "checks": [
                            {
                                "name": c.name,
                                "passed": c.passed,
                                "fatal": c.fatal,
                                "detail": c.detail,
                                "details": c.details,
                            }
                            for c in report.checks
                        ],
                    },
                    indent=2,
                    default=str,
                )
            )
        else:
            print("GRYPHON scan orchestration — readiness")
            print(f"  environment     : {report.environment}")
            print(f"  graph version   : {topo['graph_version']}")
            print(f"  checkpointer    : {topo['checkpointer'] or 'none (by design)'}")
            print(f"  owner id        : {services.orchestrator.owner_id}")
            print(f"  lease / beat    : {services.settings.scan_lease_seconds:g}s / "
                  f"{services.settings.scan_heartbeat_seconds:g}s")
            print(f"  sweeper every   : {services.settings.sweeper_interval_seconds:g}s")
            print(f"  target cap      : {services.settings.discovered_target_cap}")
            print(f"  coverage floor  : {services.settings.coverage_failure_floor:g}")
            print("\n  pipeline:")
            for stage, steps in topo["stages"].items():
                chain = " -> ".join(f"{s['tool_id']}" for s in steps) or "(none)"
                print(f"    {stage:<12} {chain}")
            print("\n  checks:")
            for check in report.checks:
                status = _PASS if check.passed else (_FAIL if check.fatal else "WARN")
                print(f"    [{status:<4}] {check.name}")
                if check.detail:
                    print(f"             {check.detail}")
            print(f"\n{'READY' if report.ready else 'NOT READY'}")
        return 0 if report.ready else 1
    finally:
        await services.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()
    sys.exit(asyncio.run(_run(args.json)))


if __name__ == "__main__":
    main()

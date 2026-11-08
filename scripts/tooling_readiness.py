"""Operator CLI: report readiness of the capability-gated tool execution layer.

A partially-provisioned or mixed-schema deployment MUST NOT admit executions.
This command wires the real services from your configuration and prints the
readiness report; it writes nothing and contacts no target.

    python -m scripts.tooling_readiness          # human-readable
    python -m scripts.tooling_readiness --json   # machine-readable

Exit code 0 = READY, 1 = NOT READY (safe for a container readiness probe).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from gryphon.tooling.bootstrap import build_tooling_services
from gryphon.tooling.provisioning.readiness import check_tooling_readiness


async def _run(as_json: bool) -> int:
    services = build_tooling_services()
    try:
        report = await check_tooling_readiness(
            settings=services.tooling_settings,
            database=services.database,
            has_capability_signer=services.has_capability_signer,
            manifest=services.manifest,
        )
    finally:
        await services.dispose()

    settings = services.tooling_settings
    payload = {
        "ready": report.ready,
        "environment": settings.environment,
        "egress_mode": settings.egress_mode.value,
        "egress_enforced": settings.egress_mode.value == "enforced",
        "capability_kid": settings.capability_kid,
        "capability_ttl_seconds": settings.capability_ttl_seconds,
        "manifest_configured": services.manifest is not None,
        "checks": report.checks,
        "details": report.details,
    }

    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"tool execution layer readiness: {'READY' if report.ready else 'NOT READY'}")
        print(f"  environment        : {payload['environment']}")
        print(f"  egress posture     : {payload['egress_mode']}")
        print(f"  capability kid     : {payload['capability_kid']}")
        print(f"  capability ttl (s) : {payload['capability_ttl_seconds']}")
        print(f"  binary manifest    : {'configured' if payload['manifest_configured'] else 'none'}")
        print("  checks:")
        for name, ok in sorted(report.checks.items()):
            detail = report.details.get(name, "")
            print(f"    [{'PASS' if ok else 'FAIL'}] {name}{f'  ({detail})' if detail else ''}")
    return 0 if report.ready else 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args()
    sys.exit(asyncio.run(_run(args.json)))


if __name__ == "__main__":
    main()

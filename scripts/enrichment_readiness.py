"""Readiness probe for the enrichment layer.

Checks facts, not revision numbers: tables and view, enabled triggers, trigger
function bodies, the dedicated role's exact privileges, the seeded slot,
verified reference data, the policy, the signing key, the egress posture, the
artifact store and the process's own import graph. Exit 0 means ready.

    python -m scripts.enrichment_readiness
    python -m scripts.enrichment_readiness --json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from gryphon.enrichment.bootstrap import build_enrichment_services
from gryphon.enrichment.readiness import check_enrichment_readiness
from gryphon.enrichment.reasons import EnrichmentConfigurationError
from gryphon.logging_config import configure_logging


async def _run(as_json: bool) -> int:
    try:
        services = build_enrichment_services()
    except EnrichmentConfigurationError as exc:
        payload = {"ready": False, "error": str(exc), "checks": []}
        print(json.dumps(payload, indent=2) if as_json else f"NOT READY\n  {exc}")
        return 1
    try:
        report = await check_enrichment_readiness(services)
    finally:
        await services.dispose()

    if as_json:
        print(json.dumps(report.as_payload(), indent=2, default=str))
    else:
        print(f"enrichment readiness ({report.environment}): "
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

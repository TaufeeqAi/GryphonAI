"""Deployment self-verification for the enrichment layer.

Offline by default — no network, no database writes. It answers "does this
build enforce what it claims?" with checks that each state what they prove:

* the key-holding process's import graph contains no HTTP client and no
  orchestration module (probed in a *fresh* interpreter, so this script's own
  imports cannot hide or cause a failure);
* the acquisition child imports no database driver, settings or key code;
* acceptance proves completeness and rejects truncation, shrinkage, rollback;
* the normalized grammar round-trips; the policy is monotone and per plan;
* derivation is deterministic and reads CVE subjects only from ``cve_ids``;
* report attestations verify and detect tampering;
* the provisioned reference data (if any) verifies against its pins.

``--db`` additionally runs the readiness checks against the configured database.

    python -m scripts.verify_enrichment
    python -m scripts.verify_enrichment --db
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

from gryphon.enrichment.readiness import FORBIDDEN_PARENT_MODULES
from gryphon.enrichment.reference import DatasetUnavailable, load_reference
from gryphon.enrichment.selfcheck import SelfCheck, run_selfchecks
from gryphon.enrichment.settings import get_enrichment_settings

_REPO_ROOT = Path(__file__).resolve().parents[1]

_PARENT_PROBE = """
import json, sys
import gryphon.enrichment.bootstrap, gryphon.enrichment.engine, gryphon.enrichment.readiness
forbidden = {forbidden!r}
loaded = [m for m in forbidden
          if m in sys.modules or any(k.startswith(m + '.') for k in sys.modules)]
print(json.dumps(loaded))
"""

_CHILD_PROBE = """
import importlib, json, sys
importlib.import_module('gryphon.enrichment.acquisition.__main__')
forbidden = ('sqlalchemy', 'asyncpg', 'pydantic', 'pydantic_settings', 'cryptography',
             'gryphon.settings', 'gryphon.db', 'gryphon.auth', 'gryphon.enrichment.settings')
loaded = [m for m in forbidden
          if m in sys.modules or any(k.startswith(m + '.') for k in sys.modules)]
print(json.dumps(loaded))
"""


def _probe(code: str) -> list[str] | str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GRYPHON_")}
    env["PYTHONPATH"] = str(_REPO_ROOT)
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and fixed code
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(_REPO_ROOT),
        timeout=120,
        check=False,
    )
    if completed.returncode != 0:
        return completed.stderr.strip().splitlines()[-1] if completed.stderr else "probe failed"
    loaded = json.loads(completed.stdout.strip().splitlines()[-1])
    return [str(name) for name in loaded] if isinstance(loaded, list) else str(loaded)


def import_checks() -> list[SelfCheck]:
    parent = _probe(_PARENT_PROBE.format(forbidden=FORBIDDEN_PARENT_MODULES))
    child = _probe(_CHILD_PROBE)
    return [
        SelfCheck(
            "parent_imports_no_http_client",
            "the process holding keys and engagement data cannot speak HTTP",
            parent == [],
            "clean" if parent == [] else str(parent),
        ),
        SelfCheck(
            "child_imports_no_database_or_keys",
            "the acquisition subprocess cannot reach the database or key material",
            child == [],
            "clean" if child == [] else str(child),
        ),
    ]


def reference_check() -> SelfCheck:
    reference = load_reference(get_enrichment_settings().reference_dir)
    if isinstance(reference, DatasetUnavailable):
        return SelfCheck(
            "reference_data_verified",
            "provisioned ATT&CK data matches its pins",
            True,
            reference.reason,
            skipped=True,
        )
    return SelfCheck(
        "reference_data_verified",
        "provisioned ATT&CK data matches its pins",
        True,
        reference.snapshot_id,
    )


async def _db_checks() -> list[SelfCheck]:
    from gryphon.enrichment.bootstrap import build_enrichment_services
    from gryphon.enrichment.readiness import check_enrichment_readiness

    services = build_enrichment_services()
    try:
        report = await check_enrichment_readiness(services)
    finally:
        await services.dispose()
    return [
        SelfCheck(f"readiness:{c.name}", c.detail or c.name, c.passed or not c.fatal,
                  ("" if c.passed else "WARN " if not c.fatal else "FAIL ") + c.detail)
        for c in report.checks
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--db", action="store_true", help="also run database readiness checks")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    checks = [*import_checks(), *run_selfchecks(), reference_check()]
    if args.db:
        checks.extend(asyncio.run(_db_checks()))

    if args.json:
        print(json.dumps([c.__dict__ for c in checks], indent=2))
    else:
        for c in checks:
            mark = "SKIP" if c.skipped else ("PASS" if c.passed else "FAIL")
            print(f"[{mark}] {c.name:<44} {c.detail}")
            print(f"       proves: {c.proves}")
    failed = [c for c in checks if not c.passed]
    skipped = [c for c in checks if c.skipped]
    performed = len(checks) - len(skipped)
    print(
        f"\n{performed - len(failed)}/{performed} checks passed, {len(skipped)} skipped",
        file=sys.stderr,
    )
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())

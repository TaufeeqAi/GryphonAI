"""Accepted snapshots: acquisition orchestration on the parent side.

The parent decides *when* a source is acquired (missing, older than its maximum
age, breaker closed — or an operator ``intel refresh``), resolves and pins the
allowlisted hosts' IPv4 addresses, and launches the acquisition subprocess
inside the OS egress enforcer with a scrubbed environment: no database URL, no
keys, nothing from the engagement. It then trusts nothing the child says:

* every returned artifact is re-hashed and must match the digest the child
  reported;
* the *normalized* artifact and its metadata are re-parsed with the strict
  grammar of :mod:`gryphon.enrichment.artifacts`;
* only then is the snapshot recorded (content-addressed, append-only) and a
  ``snapshot_accepted`` event signed.

A failed acquisition writes no snapshot. It is recorded as an attempt with a
remediation class and in the egress ledger, and passes simply derive against the
newest accepted snapshot — older, and saying so.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from gryphon.clock import Clock
from gryphon.db.models import IntelSnapshot
from gryphon.db.session import Database
from gryphon.enrichment.artifacts import (
    ArtifactStore,
    parse_epss_normalized,
    parse_kev_normalized,
    parse_meta,
    sha256_file,
)
from gryphon.enrichment.audit import EnrichmentAuditBuilder
from gryphon.enrichment.constants import (
    HOST_FOR_SOURCE,
    NETWORK_SOURCES,
    AttemptResult,
    RemediationClass,
    Source,
)
from gryphon.enrichment.reasons import ArtifactIntegrityError
from gryphon.enrichment.repository import EnrichmentRepository
from gryphon.enrichment.settings import EnrichmentSettings
from gryphon.logging_config import get_logger

logger = get_logger(__name__)

_REQUEST_FORMAT_VERSION = "1"
#: Environment passed to the child. Nothing else is inherited: no GRYPHON_*,
#: no proxy variables, no credentials of any kind.
_CHILD_ENV_KEYS = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
_REPO_ROOT = Path(__file__).resolve().parents[2]


class Resolver(Protocol):
    async def resolve(self, host: str) -> list[Any]: ...


class Enforcer(Protocol):
    @property
    def enforcing(self) -> bool: ...

    async def establish(self, allowlist: list[str], ports: list[int]) -> Any: ...

    async def teardown(self, handle: Any) -> None: ...


class AcquisitionLauncher(Protocol):
    async def run(self, request: dict[str, Any], staging: Path) -> dict[str, Any]: ...


@dataclass(frozen=True)
class SourceStatus:
    """What a caller needs to know about one source after ensure_fresh()."""

    source: str
    snapshot_id: str | None
    acquired: str | None = None
    reason: str | None = None


@dataclass
class AcquisitionSummary:
    statuses: dict[str, SourceStatus] = field(default_factory=dict)


def child_environment() -> dict[str, str]:
    env = {k: os.environ[k] for k in _CHILD_ENV_KEYS if k in os.environ}
    env.update(
        {
            "PYTHONPATH": str(_REPO_ROOT),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
            "LC_ALL": "C.UTF-8",
        }
    )
    return env


class SubprocessAcquisitionLauncher:
    """Runs ``python -m gryphon.enrichment.acquisition`` inside the enforcer."""

    def __init__(
        self,
        *,
        enforcer: Enforcer,
        timeout_seconds: float,
        max_report_bytes: int,
        python: str | None = None,
    ) -> None:
        self._enforcer = enforcer
        self._timeout = timeout_seconds
        self._max_report = max_report_bytes
        self._python = python or sys.executable

    @property
    def posture(self) -> str:
        return "ENFORCED" if self._enforcer.enforcing else "UNENFORCED"

    async def run(self, request: dict[str, Any], staging: Path) -> dict[str, Any]:
        addresses = sorted({a for values in request["addresses"].values() for a in values})
        request_path = staging / "request.json"
        request_path.write_text(json.dumps(request, sort_keys=True), encoding="utf-8")
        handle = await self._enforcer.establish(addresses, [443])
        try:
            argv = handle.wrap_argv(
                [self._python, "-s", "-B", "-m", "gryphon.enrichment.acquisition",
                 str(request_path)]
            )
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=str(staging),
                env=child_environment(),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self._timeout)
            except TimeoutError:
                proc.kill()
                await proc.wait()
                raise
        finally:
            await self._enforcer.teardown(handle)
        if proc.returncode != 0:
            raise RuntimeError(
                f"acquisition exited {proc.returncode}: {stderr[:300].decode(errors='replace')}"
            )
        if len(stdout) > self._max_report:
            raise RuntimeError("acquisition report exceeds its size cap")
        report = json.loads(stdout)
        if not isinstance(report, dict) or report.get("format_version") != _REQUEST_FORMAT_VERSION:
            raise RuntimeError("acquisition report has an unsupported format")
        return dict(report)


def snapshot_id_for(source: str, label: str, content_sha256: str) -> str:
    return f"{source}:{label}@sha256:{content_sha256}"


class SnapshotService:
    def __init__(
        self,
        *,
        database: Database,
        artifacts: ArtifactStore,
        launcher: AcquisitionLauncher,
        resolver: Resolver,
        audit: EnrichmentAuditBuilder,
        settings: EnrichmentSettings,
        clock: Clock,
        posture: str,
    ) -> None:
        self._db = database
        self._artifacts = artifacts
        self._launcher = launcher
        self._resolver = resolver
        self._audit = audit
        self._settings = settings
        self._clock = clock
        self._posture = posture

    @property
    def posture(self) -> str:
        return self._posture

    # -- freshness and breaker -------------------------------------------------
    async def age_seconds(self, repo: EnrichmentRepository, snapshot: IntelSnapshot) -> int:
        confirmed = await repo.last_confirmed_at(snapshot)
        return max(0, int((await repo.db_now() - confirmed).total_seconds()))

    async def breaker_open(self, repo: EnrichmentRepository, source: str) -> bool:
        attempts = await repo.recent_attempts(source, self._settings.breaker_failures)
        if len(attempts) < self._settings.breaker_failures:
            return False
        if any(a.result != AttemptResult.REJECTED.value for a in attempts):
            return False
        cooldown = timedelta(seconds=self._settings.breaker_cooldown_seconds)
        return attempts[0].finished_at + cooldown > await repo.db_now()

    async def sources_needing_acquisition(
        self, sources: tuple[Source, ...], *, force: bool
    ) -> list[Source]:
        due: list[Source] = []
        async with self._db.session() as session:
            repo = EnrichmentRepository(session)
            for source in sources:
                if HOST_FOR_SOURCE[source] not in self._settings.allowed_hosts:
                    continue
                if not force and await self.breaker_open(repo, source.value):
                    logger.warning("acquisition_breaker_open", source=source.value)
                    continue
                newest = await repo.newest_snapshot(source.value)
                if force or newest is None:
                    due.append(source)
                    continue
                if await self.age_seconds(repo, newest) > self._settings.max_age_seconds(
                    source.value
                ):
                    due.append(source)
        return due

    async def ensure_fresh(
        self, *, initiated_by: str, pass_id: str | None = None, force: bool = False,
        sources: tuple[Source, ...] = NETWORK_SOURCES,
    ) -> AcquisitionSummary:
        due = await self.sources_needing_acquisition(sources, force=force)
        summary = AcquisitionSummary()
        if due:
            summary = await self.acquire(due, initiated_by=initiated_by, pass_id=pass_id)
        return summary

    # -- acquisition -----------------------------------------------------------
    async def _pin_addresses(
        self, sources: list[Source]
    ) -> tuple[dict[str, list[str]], dict[str, str]]:
        pins: dict[str, list[str]] = {}
        failures: dict[str, str] = {}
        for source in sources:
            host = HOST_FOR_SOURCE[source]
            try:
                resolved = await self._resolver.resolve(host)
            except (OSError, TimeoutError) as exc:
                failures[source.value] = f"dns resolution failed: {type(exc).__name__}"
                continue
            v4 = sorted(
                {str(a) for a in resolved if isinstance(ipaddress.ip_address(str(a)),
                                                       ipaddress.IPv4Address)}
            )
            if not v4:
                failures[source.value] = "no IPv4 address for host"
                continue
            pins[host] = v4
        return pins, failures

    async def _last_accepted(self, sources: list[Source]) -> dict[str, dict[str, Any]]:
        last: dict[str, dict[str, Any]] = {}
        async with self._db.session() as session:
            repo = EnrichmentRepository(session)
            for source in sources:
                newest = await repo.newest_snapshot(source.value)
                if newest is not None:
                    last[source.value] = {
                        "label": newest.label,
                        "order_key": newest.order_key,
                        "entry_count": newest.entry_count,
                        "byte_size": newest.byte_size,
                    }
        return last

    def _epss_dates(self, now: datetime) -> list[str]:
        """Newest first: today's file may not be published yet (UTC)."""
        today = now.astimezone(UTC).date() if now.tzinfo else now.date()
        return [(today - timedelta(days=d)).isoformat() for d in (0, 1, 2)]

    async def acquire(
        self, sources: list[Source], *, initiated_by: str, pass_id: str | None
    ) -> AcquisitionSummary:
        summary = AcquisitionSummary()
        started = self._clock.now()
        pins, failures = await self._pin_addresses(sources)
        runnable = [s for s in sources if s.value not in failures]
        report: dict[str, Any] = {"results": {}}
        staging: Path | None = None
        if runnable:
            staging = self._artifacts.staging_dir()
            request = {
                "format_version": _REQUEST_FORMAT_VERSION,
                "sources": [s.value for s in runnable],
                "addresses": pins,
                "last": await self._last_accepted(runnable),
                "epss_dates": self._epss_dates(started),
                "out_dir": str(staging),
                "connect_timeout": self._settings.connect_timeout_seconds,
                "request_timeout": self._settings.request_timeout_seconds,
                "attempts": self._settings.fetch_attempts,
            }
            try:
                report = await self._launcher.run(request, staging)
            except Exception as exc:
                reason = f"acquisition process failed: {type(exc).__name__}: {exc}"[:400]
                logger.error("acquisition_failed", error=type(exc).__name__)
                for source in runnable:
                    failures[source.value] = reason
        try:
            for source in sources:
                result = report.get("results", {}).get(source.value)
                status = await self._record(
                    source,
                    result,
                    failure=failures.get(source.value),
                    staging=staging,
                    started=started,
                    initiated_by=initiated_by,
                    pass_id=pass_id,
                )
                summary.statuses[source.value] = status
        finally:
            if staging is not None:
                shutil.rmtree(staging, ignore_errors=True)
        return summary

    async def _verified_artifacts(
        self, source: Source, result: dict[str, Any], staging: Path
    ) -> tuple[dict[str, Any], str, str]:
        """Re-verify the child's artifacts and store them. Returns (meta, digests)."""
        names = {key: Path(str(result[key])).name for key in ("raw_file", "normalized_file",
                                                              "meta_file")}
        raw_path, norm_path, meta_path = (staging / names[k] for k in
                                          ("raw_file", "normalized_file", "meta_file"))
        meta = parse_meta(meta_path.read_bytes(), source.value)
        normalized = norm_path.read_bytes()
        if source is Source.KEV:
            count = len(parse_kev_normalized(normalized))
        else:
            count = len(parse_epss_normalized(normalized))
        if count != meta["entry_count"] or count != int(result["entry_count"]):
            raise ArtifactIntegrityError("normalized entry count disagrees with the report")
        if meta["label"] != result["label"] or meta["order_key"] != result["order_key"]:
            raise ArtifactIntegrityError("snapshot metadata disagrees with the report")
        self._artifacts.put_file(raw_path, str(result["content_sha256"]))
        self._artifacts.put_file(norm_path, str(result["normalized_sha256"]))
        meta_sha = sha256_file(meta_path)
        self._artifacts.put_file(meta_path, meta_sha)
        return meta, meta_sha, str(result["normalized_sha256"])

    async def _record(
        self,
        source: Source,
        result: dict[str, Any] | None,
        *,
        failure: str | None,
        staging: Path | None,
        started: datetime,
        initiated_by: str,
        pass_id: str | None,
    ) -> SourceStatus:
        attempt_id = uuid4().hex
        attempt: dict[str, Any] = {
            "attempt_id": attempt_id,
            "source": source.value,
            "pass_id": pass_id,
            "egress_posture": self._posture,
            "initiated_by": initiated_by,
            "started_at": started,
        }
        ledger_rows = [
            {
                "request_id": uuid4().hex,
                "attempt_id": attempt_id,
                "source": source.value,
                "host": str(r.get("host", ""))[:128],
                "path": str(r.get("path", ""))[:512],
                "address": str(r.get("address", ""))[:64] or None,
                "status_code": r.get("status") if isinstance(r.get("status"), int) else None,
                "bytes_received": int(r.get("bytes_received") or 0),
                "outcome_class": str(r.get("outcome_class", "UNKNOWN"))[:16],
                "detail": (str(r["detail"])[:400] if r.get("detail") else None),
                "started_at": str(r.get("started_at", ""))[:40] or None,
                "finished_at": str(r.get("finished_at", ""))[:40] or None,
            }
            for r in (result or {}).get("requests", [])
            if isinstance(r, dict)
        ]

        snapshot_id: str | None = None
        outcome = AttemptResult.REJECTED
        reason = failure
        remediation: str | None = RemediationClass.TRANSIENT.value if failure else None
        meta: dict[str, Any] = {}
        meta_sha = normalized_sha = ""
        if failure is None and result is not None:
            if result.get("status") == "accepted" and staging is not None:
                try:
                    meta, meta_sha, normalized_sha = await self._verified_artifacts(
                        source, result, staging
                    )
                    snapshot_id = snapshot_id_for(
                        source.value, str(result["label"]), str(result["content_sha256"])
                    )
                except (ArtifactIntegrityError, KeyError, OSError, ValueError) as exc:
                    reason = f"artifact verification failed: {exc}"[:400]
                    remediation = RemediationClass.INTEGRITY.value
            else:
                reason = str(result.get("reason", "rejected"))[:400]
                remediation = str(result.get("remediation_class") or "INTEGRITY")[:16]
        elif result is None and failure is None:
            reason, remediation = "no result for source", RemediationClass.MISCONFIGURED.value

        async with self._db.session() as session, session.begin():
            repo = EnrichmentRepository(session)
            if snapshot_id is not None and result is not None:
                inserted = await repo.insert_snapshot(
                    {
                        "snapshot_id": snapshot_id,
                        "source": source.value,
                        "label": str(result["label"]),
                        "order_key": str(result["order_key"]),
                        "content_sha256": str(result["content_sha256"]),
                        "normalized_sha256": normalized_sha,
                        "meta_sha256": meta_sha,
                        "entry_count": int(result["entry_count"]),
                        "byte_size": int(result["byte_size"]),
                        "model_version": meta.get("model_version"),
                        "fetched_from": str(result.get("fetched_from", ""))[:128],
                        "acceptance": {"checks": "passed", "meta": meta},
                    }
                )
                outcome = AttemptResult.ACCEPTED if inserted else AttemptResult.UNCHANGED
                reason = None
                remediation = None
                if inserted:
                    event = self._audit.snapshot_accepted(
                        snapshot_id=snapshot_id,
                        source=source.value,
                        label=str(result["label"]),
                        entry_count=int(result["entry_count"]),
                        model_version=meta.get("model_version"),
                        initiated_by=initiated_by,
                        timestamp=self._clock.now(),
                    )
                    repo.add_event(event, initiated_by=initiated_by, pass_id=pass_id)
            await repo.insert_attempt(
                {**attempt, "result": outcome.value, "reason": reason,
                 "remediation_class": remediation, "snapshot_id": snapshot_id}
            )
            if ledger_rows:
                await repo.insert_ledger(ledger_rows)
        logger.info(
            "acquisition_recorded",
            source=source.value,
            result=outcome.value,
            remediation_class=remediation,
        )
        return SourceStatus(
            source=source.value, snapshot_id=snapshot_id, acquired=outcome.value, reason=reason
        )

    async def revoke(self, snapshot_id: str, *, reason: str, initiated_by: str) -> bool:
        async with self._db.session() as session, session.begin():
            repo = EnrichmentRepository(session)
            if await repo.get_snapshot(snapshot_id) is None or await repo.is_revoked(snapshot_id):
                return False
            await repo.insert_revocation(
                {
                    "revocation_id": uuid4().hex,
                    "snapshot_id": snapshot_id,
                    "reason": reason[:2000],
                    "revoked_by": initiated_by,
                }
            )
            repo.add_event(
                self._audit.snapshot_revoked(
                    snapshot_id=snapshot_id, reason=reason[:2000], initiated_by=initiated_by,
                    timestamp=self._clock.now(),
                ),
                initiated_by=initiated_by,
            )
        return True

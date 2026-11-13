"""The enrichment pass: one fenced, pinned, attested unit of work.

Lifecycle of ``enrichment_pass.state``::

    PLANNED ──pin──▶ RUNNING ──publish──▶ COMPLETE
       │                │
       ├──▶ REFUSED     └──▶ ABANDONED (pins_unavailable | operator_abort)
       └──▶ ABANDONED

* **Fenced.** A pass runs only while its process holds the system-wide slot — a
  lease evaluated on the *database* clock and renewed by :class:`LeaseKeeper`.
  Every lifecycle write first re-asserts the lease inside its own transaction
  (which also row-locks the slot until commit) and then compare-and-sets the
  pass on its ``claim_epoch``. A process whose lease lapsed is fenced out and
  its writes roll back.
* **Pinned.** Inputs are chosen once, when the pass leaves PLANNED: the newest
  accepted, non-revoked snapshot of each source with its age and staleness, the
  KEV removal hold, the reference dataset, the policy digest and the template
  set. A resumed pass re-derives from the same pins and produces the same rows.
* **Atomic.** Publishing is one transaction — the COMPLETE compare-and-set,
  every assertion and priority, the report and its signed attestation. Readers
  see all of a pass or none of it.
* **Verified input only.** The base report is verified (digest, signature,
  terminal state, integrity, consent) before anything is derived; a report that
  fails is a REFUSED pass with a signed reason, never a partial result.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import func

from gryphon.auth.key_provider import TrustedKeyStore
from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.clock import Clock
from gryphon.db.models import EnrichmentPass, IntelSnapshot
from gryphon.db.session import Database
from gryphon.enrichment.artifacts import (
    ArtifactStore,
    kev_cve_set,
    parse_epss_normalized,
    parse_kev_normalized,
)
from gryphon.enrichment.audit import EnrichmentAuditBuilder
from gryphon.enrichment.constants import (
    ENRICHMENT_CODE_VERSION,
    EXTRACTION_RULES_VERSION,
    KEV_REMOVAL_HOLD_DAYS,
    NETWORK_SOURCES,
    VALUE_SCHEMA_VERSION,
    AbandonReason,
    PassState,
    RefusalReason,
    Source,
)
from gryphon.enrichment.cve import ExtractionResult, extract_subjects
from gryphon.enrichment.derive import Derivation, DerivationInputs, EpssView, KevView, derive
from gryphon.enrichment.identity import CallerIdentity
from gryphon.enrichment.policy import Policy
from gryphon.enrichment.publish import (
    ReportVerification,
    build_report_body,
    declared_limitations,
    manifest_digest,
    report_digest,
    report_id_for,
    verify_report,
)
from gryphon.enrichment.reader import Refusal, ReportReader, VerifiedReport
from gryphon.enrichment.reasons import (
    ArtifactIntegrityError,
    EnrichmentConfigurationError,
    FencedOut,
    InvalidScanId,
    SlotBusy,
)
from gryphon.enrichment.reference import DatasetUnavailable, ReferenceData
from gryphon.enrichment.repository import EnrichmentRepository
from gryphon.enrichment.settings import EnrichmentSettings
from gryphon.enrichment.snapshots import AcquisitionSummary, SnapshotService
from gryphon.logging_config import get_logger

logger = get_logger(__name__)

PINS_FORMAT_VERSION = "1"
MANIFEST_FORMAT_VERSION = "1"
_OPEN_STATES = (PassState.PLANNED, PassState.RUNNING)


def canonical_scan_id(raw: str) -> str:
    """Canonical UUID text, as the orchestration layer generates it."""
    try:
        return str(uuid.UUID(str(raw).strip()))
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidScanId(f"{raw!r} is not a scan run id") from exc


def template_snapshot_id(templates_digest: str | None) -> str:
    return f"TEMPLATES:{templates_digest}" if templates_digest else "TEMPLATES:unpinned"


# -----------------------------------------------------------------------------
# Lease
# -----------------------------------------------------------------------------
class LeaseKeeper:
    """Renews the slot lease in the background and reports loss — never hides it.

    ``lost`` turns true when a renewal is refused (another holder owns the slot)
    or when no renewal has succeeded within ``lease - heartbeat`` seconds of the
    local monotonic clock: past that point the lease may already have lapsed on
    the database clock, so the holder must assume it has.
    """

    def __init__(
        self,
        database: Database,
        *,
        holder: str,
        epoch: int,
        lease_seconds: float,
        heartbeat_seconds: float,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._db = database
        self._holder = holder
        self._epoch = epoch
        self._lease = lease_seconds
        self._heartbeat = heartbeat_seconds
        self._monotonic = monotonic
        # Taken *before* the claim statement, so the database-side expiry is
        # never earlier than this local bound.
        self._last_renewal_started = monotonic()
        self._lost_reason: str | None = None
        self._task: asyncio.Task[None] | None = None

    async def __aenter__(self) -> LeaseKeeper:
        self._task = asyncio.create_task(self._run(), name="enrichment-lease-keeper")
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task

    @property
    def holder(self) -> str:
        return self._holder

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def lost(self) -> bool:
        if self._lost_reason is not None:
            return True
        return self._monotonic() - self._last_renewal_started >= self._lease - self._heartbeat

    def ensure_held(self) -> None:
        if self.lost:
            raise FencedOut(
                self._lost_reason or "the slot lease was not renewed within its validity"
            )

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self._heartbeat)
            started = self._monotonic()
            try:
                async with self._db.session() as session, session.begin():
                    renewed = await EnrichmentRepository(session).renew_slot(
                        self._holder, self._epoch, self._lease
                    )
            except Exception as exc:
                logger.warning("enrichment_lease_renew_failed", error=type(exc).__name__)
                continue
            if not renewed:
                self._lost_reason = "the slot was claimed by another holder"
                logger.error("enrichment_lease_lost", holder=self._holder, epoch=self._epoch)
                return
            self._last_renewal_started = started


# -----------------------------------------------------------------------------
# Results
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class PassResult:
    scan_run_id: str
    pass_id: str | None
    state: str
    outcome: str | None = None
    reason: str | None = None
    detail: str | None = None
    report_id: str | None = None
    report_digest: str | None = None
    resumed: bool = False
    acquisitions: dict[str, dict[str, Any]] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ServedReport:
    report_id: str
    pass_id: str
    scan_run_id: str
    body: dict[str, Any]
    verification: ReportVerification


@dataclass(frozen=True)
class _OpenedPass:
    pass_id: str
    verified: VerifiedReport
    state: PassState
    resumed: bool
    pins: dict[str, Any]


@dataclass(frozen=True)
class _Pinned:
    pins: dict[str, Any]
    plan_digest: str
    kev: KevView | None
    epss: EpssView | None
    reference: ReferenceData | DatasetUnavailable


class _PinsUnavailable(Exception):
    """A pinned input can no longer be loaded and verified."""


# -----------------------------------------------------------------------------
# Engine
# -----------------------------------------------------------------------------
class EnrichmentEngine:
    def __init__(
        self,
        *,
        database: Database,
        reader: ReportReader,
        snapshots: SnapshotService,
        artifacts: ArtifactStore,
        audit: EnrichmentAuditBuilder,
        trust: TrustedKeyStore,
        policy: Policy,
        settings: EnrichmentSettings,
        clock: Clock,
        reference_loader: Callable[[], ReferenceData | DatasetUnavailable],
    ) -> None:
        self._db = database
        self._reader = reader
        self._snapshots = snapshots
        self._artifacts = artifacts
        self._audit = audit
        self._trust = trust
        self._policy = policy
        self._settings = settings
        self._clock = clock
        self._load_reference = reference_loader

    @property
    def policy(self) -> Policy:
        return self._policy

    # -- the slot ------------------------------------------------------------
    @asynccontextmanager
    async def _holding_slot(self, caller: CallerIdentity) -> AsyncIterator[LeaseKeeper]:
        holder = f"{caller.label}/pid:{os.getpid()}/{uuid.uuid4().hex[:8]}"[:80]
        lease = self._settings.pass_lease_seconds
        async with self._db.session() as session, session.begin():
            repo = EnrichmentRepository(session)
            epoch = await repo.claim_slot(holder, lease)
            if epoch is None:
                state = await repo.slot_state()
                if state is None:
                    raise EnrichmentConfigurationError(
                        "the enrichment slot is not seeded; apply the database migrations"
                    )
                raise SlotBusy(state.holder, state.lease_expires_at)
        keeper = LeaseKeeper(
            self._db,
            holder=holder,
            epoch=epoch,
            lease_seconds=lease,
            heartbeat_seconds=self._settings.pass_heartbeat_seconds,
        )
        try:
            async with keeper:
                yield keeper
        finally:
            try:
                async with self._db.session() as session, session.begin():
                    await EnrichmentRepository(session).release_slot(holder, epoch)
            except Exception as exc:
                logger.warning("enrichment_slot_release_failed", error=type(exc).__name__)

    async def _assert_holding(self, repo: EnrichmentRepository, keeper: LeaseKeeper) -> None:
        """Re-assert the lease inside the caller's transaction.

        The UPDATE row-locks the slot until commit, so no other process can claim
        it between this check and the transaction's writes.
        """
        keeper.ensure_held()
        renewed = await repo.renew_slot(
            keeper.holder, keeper.epoch, self._settings.pass_lease_seconds
        )
        if not renewed:
            raise FencedOut("the enrichment slot is no longer held by this process")

    # -- public operations ---------------------------------------------------
    async def run_pass(
        self, scan_run_id: str, *, caller: CallerIdentity, refresh: bool = False
    ) -> PassResult:
        """Run (or resume) the enrichment pass for one scan."""
        scan_run_id = canonical_scan_id(scan_run_id)
        async with self._holding_slot(caller) as keeper:
            opened = await self._open(scan_run_id, keeper=keeper, caller=caller)
            if isinstance(opened, PassResult):
                return opened
            logger.info(
                "enrichment_pass_started",
                scan_run_id=scan_run_id,
                pass_id=opened.pass_id,
                resumed=opened.resumed,
                state=opened.state.value,
            )
            extraction = extract_subjects(opened.verified.findings)

            acquisitions: dict[str, dict[str, Any]] = {}
            if opened.state is PassState.PLANNED and extraction.subjects:
                keeper.ensure_held()
                summary = await self._snapshots.ensure_fresh(
                    initiated_by=caller.label, pass_id=opened.pass_id, force=refresh
                )
                acquisitions = {k: asdict(v) for k, v in summary.statuses.items()}

            try:
                if opened.state is PassState.PLANNED:
                    pinned = await self._pin(opened, extraction, keeper=keeper)
                else:
                    pinned = await self._repin(opened, extraction)
            except _PinsUnavailable as exc:
                return await self._abandon_now(
                    opened.pass_id,
                    scan_run_id=scan_run_id,
                    keeper=keeper,
                    caller=caller,
                    reason=AbandonReason.PINS_UNAVAILABLE,
                    detail=str(exc),
                    acquisitions=acquisitions,
                )

            derivation = derive(
                DerivationInputs(
                    subjects=tuple(extraction.subjects),
                    kev=pinned.kev,
                    epss=pinned.epss,
                    reference=pinned.reference,
                    template_snapshot_id=pinned.pins["CVSS_TEMPLATE"]["snapshot_id"],
                    policy=self._policy,
                )
            )
            return await self._publish(
                opened,
                pinned,
                derivation,
                extraction,
                keeper=keeper,
                caller=caller,
                acquisitions=acquisitions,
            )

    async def refresh(
        self, *, caller: CallerIdentity, sources: tuple[Source, ...] = NETWORK_SOURCES
    ) -> AcquisitionSummary:
        """Operator-forced acquisition of the network sources, under the slot."""
        async with self._holding_slot(caller):
            return await self._snapshots.ensure_fresh(
                initiated_by=caller.label, force=True, sources=sources
            )

    async def abort(
        self, scan_run_id: str, *, caller: CallerIdentity, detail: str | None = None
    ) -> PassResult | None:
        """Abandon a scan's unfinished pass whose holder is gone.

        A live pass holds the slot, so this succeeds only once its lease has
        lapsed (its process stopped); against a live pass it raises
        :class:`SlotBusy`.
        """
        scan_run_id = canonical_scan_id(scan_run_id)
        async with self._holding_slot(caller) as keeper:
            async with self._db.session() as session, session.begin():
                repo = EnrichmentRepository(session)
                await self._assert_holding(repo, keeper)
                open_row = await repo.open_pass(scan_run_id)
                if open_row is None:
                    return None
                await self._adopt(repo, open_row, keeper)
                return await self._abandon(
                    repo,
                    pass_id=open_row.pass_id,
                    scan_run_id=scan_run_id,
                    keeper=keeper,
                    caller=caller,
                    reason=AbandonReason.OPERATOR_ABORT,
                    detail=(detail or "abandoned by operator")[:2000],
                )

    async def revoke_snapshot(
        self, snapshot_id: str, *, reason: str, caller: CallerIdentity
    ) -> bool:
        """Revoke an accepted snapshot (an appended row and a signed event)."""
        return await self._snapshots.revoke(snapshot_id, reason=reason, initiated_by=caller.label)

    async def report(self, scan_run_id: str) -> ServedReport | None:
        """The newest COMPLETE pass's report, re-verified before it is served."""
        scan_run_id = canonical_scan_id(scan_run_id)
        async with self._db.session() as session:
            repo = EnrichmentRepository(session)
            row = await repo.latest_report(scan_run_id)
            if row is None:
                return None
            event = await repo.report_event(row)
            verification = verify_report(
                body=dict(row.body),
                stored_digest=row.report_digest,
                event_payload=dict(event.payload) if event else None,
                event_payload_digest=event.payload_digest if event else None,
                signer_kid=event.signer_kid if event else None,
                signature=event.signature if event else None,
                trust=self._trust,
            )
            return ServedReport(
                report_id=row.report_id,
                pass_id=row.pass_id,
                scan_run_id=row.scan_run_id,
                body=dict(row.body),
                verification=verification,
            )

    async def status(self, scan_run_id: str | None = None) -> dict[str, Any]:
        """Slot, source freshness and (optionally) one scan's passes."""
        if scan_run_id is not None:
            scan_run_id = canonical_scan_id(scan_run_id)
        async with self._db.session() as session:
            repo = EnrichmentRepository(session)
            now = await repo.db_now()
            slot = await repo.slot_state()
            held = bool(
                slot
                and slot.holder
                and slot.lease_expires_at is not None
                and slot.lease_expires_at > now
            )
            sources: dict[str, Any] = {}
            for source in NETWORK_SOURCES:
                newest = await repo.newest_snapshot(source.value)
                attempts = await repo.recent_attempts(source.value, 1)
                last = attempts[0] if attempts else None
                entry: dict[str, Any] = {
                    "snapshot_id": None,
                    "max_age_s": int(self._settings.max_age_seconds(source.value)),
                    "breaker_open": await self._snapshots.breaker_open(repo, source.value),
                    "last_attempt": (
                        {
                            "result": last.result,
                            "reason": last.reason,
                            "remediation_class": last.remediation_class,
                            "finished_at": last.finished_at.isoformat(),
                            "egress_posture": last.egress_posture,
                        }
                        if last
                        else None
                    ),
                }
                if newest is not None:
                    age = await self._snapshots.age_seconds(repo, newest)
                    entry.update(
                        {
                            "snapshot_id": newest.snapshot_id,
                            "label": newest.label,
                            "entry_count": newest.entry_count,
                            "accepted_at": newest.accepted_at.isoformat(),
                            "age_s": age,
                            "stale": age > entry["max_age_s"],
                        }
                    )
                sources[source.value] = entry
            result: dict[str, Any] = {
                "slot": {
                    "held": held,
                    "holder": slot.holder if slot and held else None,
                    "claim_epoch": slot.claim_epoch if slot else None,
                    "lease_expires_at": (
                        slot.lease_expires_at.isoformat()
                        if slot and held and slot.lease_expires_at
                        else None
                    ),
                },
                "egress_posture": self._snapshots.posture,
                "policy": {"digest": self._policy.digest, "label": self._policy.label},
                "sources": sources,
            }
            if scan_run_id is not None:
                passes = await repo.passes_for_scan(scan_run_id)
                latest = await repo.latest_report(scan_run_id)
                result["scan"] = {
                    "scan_run_id": scan_run_id,
                    "passes": [_pass_summary(p) for p in passes],
                    "latest_report": (
                        {
                            "report_id": latest.report_id,
                            "pass_id": latest.pass_id,
                            "report_digest": latest.report_digest,
                            "outcome": latest.body.get("outcome"),
                            "generated_at": latest.generated_at.isoformat(),
                        }
                        if latest
                        else None
                    ),
                }
            return result

    # -- opening -------------------------------------------------------------
    async def _open(
        self, scan_run_id: str, *, keeper: LeaseKeeper, caller: CallerIdentity
    ) -> _OpenedPass | PassResult:
        """Verify the base report, then refuse, resume or create the pass."""
        async with self._db.session() as session, session.begin():
            repo = EnrichmentRepository(session)
            await self._assert_holding(repo, keeper)
            if not await repo.scan_exists(scan_run_id):
                return PassResult(
                    scan_run_id=scan_run_id,
                    pass_id=None,
                    state=PassState.REFUSED.value,
                    reason=RefusalReason.REPORT_UNVERIFIED.value,
                    detail="no such scan",
                )
            verified = await self._reader.verify(session, scan_run_id)
            if not isinstance(verified, Refusal):
                missing = await repo.missing_evidence(
                    scan_run_id, [str(f["finding_id"]) for f in verified.findings]
                )
                if missing:
                    verified = Refusal(
                        RefusalReason.REPORT_UNVERIFIED,
                        f"{len(missing)} reported finding(s) have no evidence row in this scan",
                    )
            open_row = await repo.open_pass(scan_run_id)

            if isinstance(verified, Refusal):
                return await self._refuse(
                    repo, scan_run_id=scan_run_id, open_row=open_row, keeper=keeper,
                    caller=caller, refusal=verified,
                )

            if open_row is not None:
                await self._adopt(repo, open_row, keeper)
                if open_row.base_report_digest == verified.report_digest:
                    return _OpenedPass(
                        pass_id=open_row.pass_id,
                        verified=verified,
                        state=PassState(open_row.state),
                        resumed=True,
                        pins=dict(open_row.pins or {}),
                    )
                # The scan's report was superseded after this pass pinned it.
                await self._abandon(
                    repo,
                    pass_id=open_row.pass_id,
                    scan_run_id=scan_run_id,
                    keeper=keeper,
                    caller=caller,
                    reason=AbandonReason.PINS_UNAVAILABLE,
                    detail=(
                        "the pinned base report was superseded by "
                        f"{verified.report_id} ({verified.report_digest[:12]})"
                    ),
                )

            pass_id = uuid.uuid4().hex
            await repo.insert_pass(
                {
                    "pass_id": pass_id,
                    "scan_run_id": scan_run_id,
                    "state": PassState.PLANNED.value,
                    "initiated_by": caller.label,
                    "base_report_id": verified.report_id,
                    "base_report_digest": verified.report_digest,
                    "claim_epoch": keeper.epoch,
                }
            )
            return _OpenedPass(
                pass_id=pass_id, verified=verified, state=PassState.PLANNED, resumed=False, pins={}
            )

    async def _adopt(
        self, repo: EnrichmentRepository, row: EnrichmentPass, keeper: LeaseKeeper
    ) -> None:
        if row.claim_epoch == keeper.epoch:
            return
        if not await repo.adopt_pass(row.pass_id, new_epoch=keeper.epoch):
            raise FencedOut(f"pass {row.pass_id} could not be adopted at epoch {keeper.epoch}")

    async def _refuse(
        self,
        repo: EnrichmentRepository,
        *,
        scan_run_id: str,
        open_row: EnrichmentPass | None,
        keeper: LeaseKeeper,
        caller: CallerIdentity,
        refusal: Refusal,
    ) -> PassResult:
        detail = refusal.detail[:2000]
        if open_row is not None:
            await self._adopt(repo, open_row, keeper)
            changed = await repo.transition_pass(
                open_row.pass_id,
                epoch=keeper.epoch,
                expected_states=_OPEN_STATES,
                state=PassState.REFUSED.value,
                reason=refusal.reason.value,
                detail=detail,
                completed_at=func.now(),
            )
            if not changed:
                raise FencedOut(f"pass {open_row.pass_id} changed underneath this process")
            pass_id = open_row.pass_id
        else:
            pass_id = uuid.uuid4().hex
            await repo.insert_pass(
                {
                    "pass_id": pass_id,
                    "scan_run_id": scan_run_id,
                    "state": PassState.REFUSED.value,
                    "reason": refusal.reason.value,
                    "detail": detail,
                    "initiated_by": caller.label,
                    "claim_epoch": keeper.epoch,
                    "completed_at": func.now(),
                }
            )
        repo.add_event(
            self._audit.pass_refused(
                scan_run_id=scan_run_id,
                pass_id=pass_id,
                reason=refusal.reason.value,
                detail=detail,
                initiated_by=caller.label,
                timestamp=self._clock.now(),
            ),
            initiated_by=caller.label,
            scan_run_id=scan_run_id,
            pass_id=pass_id,
        )
        logger.warning(
            "enrichment_pass_refused",
            scan_run_id=scan_run_id,
            pass_id=pass_id,
            reason=refusal.reason.value,
        )
        return PassResult(
            scan_run_id=scan_run_id,
            pass_id=pass_id,
            state=PassState.REFUSED.value,
            reason=refusal.reason.value,
            detail=detail,
        )

    async def _abandon(
        self,
        repo: EnrichmentRepository,
        *,
        pass_id: str,
        scan_run_id: str,
        keeper: LeaseKeeper,
        caller: CallerIdentity,
        reason: AbandonReason,
        detail: str,
        acquisitions: dict[str, dict[str, Any]] | None = None,
    ) -> PassResult:
        changed = await repo.transition_pass(
            pass_id,
            epoch=keeper.epoch,
            expected_states=_OPEN_STATES,
            state=PassState.ABANDONED.value,
            reason=reason.value,
            detail=detail,
            completed_at=func.now(),
        )
        if not changed:
            raise FencedOut(f"pass {pass_id} changed underneath this process")
        repo.add_event(
            self._audit.pass_abandoned(
                scan_run_id=scan_run_id,
                pass_id=pass_id,
                reason=reason.value,
                detail=detail,
                initiated_by=caller.label,
                timestamp=self._clock.now(),
            ),
            initiated_by=caller.label,
            scan_run_id=scan_run_id,
            pass_id=pass_id,
        )
        logger.warning(
            "enrichment_pass_abandoned", scan_run_id=scan_run_id, pass_id=pass_id,
            reason=reason.value,
        )
        return PassResult(
            scan_run_id=scan_run_id,
            pass_id=pass_id,
            state=PassState.ABANDONED.value,
            reason=reason.value,
            detail=detail,
            acquisitions=acquisitions or {},
        )

    async def _abandon_now(
        self,
        pass_id: str,
        *,
        scan_run_id: str,
        keeper: LeaseKeeper,
        caller: CallerIdentity,
        reason: AbandonReason,
        detail: str,
        acquisitions: dict[str, dict[str, Any]],
    ) -> PassResult:
        async with self._db.session() as session, session.begin():
            repo = EnrichmentRepository(session)
            await self._assert_holding(repo, keeper)
            return await self._abandon(
                repo, pass_id=pass_id, scan_run_id=scan_run_id, keeper=keeper, caller=caller,
                reason=reason, detail=detail[:2000], acquisitions=acquisitions,
            )

    # -- pinning -------------------------------------------------------------
    async def _source_pin(
        self, repo: EnrichmentRepository, row: IntelSnapshot | None
    ) -> dict[str, Any] | None:
        if row is None:
            return None
        age = await self._snapshots.age_seconds(repo, row)
        max_age = int(self._settings.max_age_seconds(row.source))
        return {
            "snapshot_id": row.snapshot_id,
            "label": row.label,
            "order_key": row.order_key,
            "normalized_sha256": row.normalized_sha256,
            "model_version": row.model_version,
            "age_s": age,
            "max_age_s": max_age,
            "stale": age > max_age,
        }

    def _reference_pin(self, reference: ReferenceData | DatasetUnavailable) -> dict[str, Any]:
        if isinstance(reference, DatasetUnavailable):
            return {"snapshot_id": None, "unavailable": reference.reason}
        return {
            "snapshot_id": reference.snapshot_id,
            "mapping_version": reference.mapping_version,
            "attack_version": reference.attack_version,
            "source_attack_version": reference.source_attack_version,
        }

    def _read_views(
        self, pins: dict[str, Any], wanted: frozenset[str]
    ) -> tuple[KevView | None, EpssView | None]:
        """Load the pinned snapshots' entries for this pass's CVEs (verified reads)."""
        kev: KevView | None = None
        epss: EpssView | None = None
        try:
            if pins.get("KEV"):
                p = pins["KEV"]
                listed = parse_kev_normalized(
                    self._artifacts.read_verified(p["normalized_sha256"]), wanted
                )
                kev = KevView(
                    snapshot_id=p["snapshot_id"],
                    catalog_version=p["label"],
                    age_s=int(p["age_s"]),
                    stale=bool(p["stale"]),
                    listed=listed,
                    integrity_hold=frozenset(p.get("integrity_hold", ())),
                )
            if pins.get("EPSS"):
                p = pins["EPSS"]
                scores = parse_epss_normalized(
                    self._artifacts.read_verified(p["normalized_sha256"]), wanted
                )
                epss = EpssView(
                    snapshot_id=p["snapshot_id"],
                    score_date=p["label"],
                    model_version=p.get("model_version") or "",
                    age_s=int(p["age_s"]),
                    stale=bool(p["stale"]),
                    scores=scores,
                )
        except (ArtifactIntegrityError, OSError, ValueError, KeyError) as exc:
            raise _PinsUnavailable(f"a pinned snapshot cannot be loaded: {exc}") from exc
        return kev, epss

    def _removed_from_kev(
        self, older: list[tuple[str, str]], pinned_listed: frozenset[str], wanted: frozenset[str]
    ) -> list[str]:
        """CVEs of this pass listed by a recent catalog but absent from the pinned one."""
        seen: set[str] = set()
        for snapshot_id, normalized_sha256 in older:
            try:
                data = self._artifacts.read_verified(normalized_sha256)
            except (ArtifactIntegrityError, OSError) as exc:
                raise _PinsUnavailable(
                    f"KEV snapshot {snapshot_id} (inside the removal hold window) cannot be "
                    f"loaded: {exc}"
                ) from exc
            seen |= kev_cve_set(data) & wanted
        return sorted(seen - pinned_listed)

    def _plan_digest(
        self, scan_run_id: str, verified: VerifiedReport, extraction: ExtractionResult,
        pins: dict[str, Any],
    ) -> str:
        plan = {
            "scan_run_id": scan_run_id,
            "base_report_digest": verified.report_digest,
            "subjects": sorted([s.finding_id, list(s.cve_ids)] for s in extraction.subjects),
            "pins": pins,
        }
        return sha256_hex(canonical_json_bytes(plan))

    async def _pin(
        self, opened: _OpenedPass, extraction: ExtractionResult, *, keeper: LeaseKeeper
    ) -> _Pinned:
        """Choose and record the pass's inputs (PLANNED → RUNNING)."""
        wanted = extraction.distinct_cves
        async with self._db.session() as session:
            repo = EnrichmentRepository(session)
            kev_row = await repo.newest_snapshot(Source.KEV.value)
            epss_row = await repo.newest_snapshot(Source.EPSS.value)
            kev_pin = await self._source_pin(repo, kev_row)
            epss_pin = await self._source_pin(repo, epss_row)
            older: list[tuple[str, str]] = []
            if kev_row is not None:
                since = await repo.db_now() - timedelta(days=KEV_REMOVAL_HOLD_DAYS)
                older = [
                    (s.snapshot_id, s.normalized_sha256)
                    for s in await repo.kev_snapshots_since(since, kev_row.order_key)
                ]
        reference = self._load_reference()
        pins: dict[str, Any] = {
            "pins_format_version": PINS_FORMAT_VERSION,
            Source.KEV.value: kev_pin,
            Source.EPSS.value: epss_pin,
            Source.ATTACK_CTID.value: self._reference_pin(reference),
            Source.CVSS_TEMPLATE.value: {
                "snapshot_id": template_snapshot_id(self._settings.templates_digest)
            },
            "policy": {"digest": self._policy.digest, "label": self._policy.label},
            "extraction_rules_version": EXTRACTION_RULES_VERSION,
            "value_schema_version": VALUE_SCHEMA_VERSION,
            "code_version": ENRICHMENT_CODE_VERSION,
        }

        kev, epss = await asyncio.to_thread(self._read_views, pins, wanted)
        if kev is not None and kev_pin is not None:
            hold = await asyncio.to_thread(
                self._removed_from_kev, older, frozenset(kev.listed), wanted
            )
            kev_pin["integrity_hold"] = hold
            kev = KevView(
                snapshot_id=kev.snapshot_id,
                catalog_version=kev.catalog_version,
                age_s=kev.age_s,
                stale=kev.stale,
                listed=kev.listed,
                integrity_hold=frozenset(hold),
            )
        plan_digest = self._plan_digest(
            opened.verified.scan_run_id, opened.verified, extraction, pins
        )

        async with self._db.session() as session, session.begin():
            repo = EnrichmentRepository(session)
            await self._assert_holding(repo, keeper)
            changed = await repo.transition_pass(
                opened.pass_id,
                epoch=keeper.epoch,
                expected_states=(PassState.PLANNED,),
                state=PassState.RUNNING.value,
                pins=pins,
                plan_digest=plan_digest,
            )
            if not changed:
                raise FencedOut(f"pass {opened.pass_id} could not be pinned at this epoch")
        return _Pinned(pins=pins, plan_digest=plan_digest, kev=kev, epss=epss, reference=reference)

    async def _repin(self, opened: _OpenedPass, extraction: ExtractionResult) -> _Pinned:
        """Reload a RUNNING pass's recorded pins; refuse to substitute anything."""
        pins = opened.pins
        if pins.get("pins_format_version") != PINS_FORMAT_VERSION:
            raise _PinsUnavailable("the pass's pins were recorded in an unsupported format")
        if pins.get("policy", {}).get("digest") != self._policy.digest:
            raise _PinsUnavailable("the policy changed since this pass was pinned")
        reference_pin = pins.get(Source.ATTACK_CTID.value) or {}
        reference: ReferenceData | DatasetUnavailable
        if reference_pin.get("snapshot_id") is None:
            reference = DatasetUnavailable(str(reference_pin.get("unavailable", "unavailable")))
        else:
            reference = self._load_reference()
            if (
                isinstance(reference, DatasetUnavailable)
                or reference.snapshot_id != reference_pin["snapshot_id"]
            ):
                raise _PinsUnavailable("the pinned reference dataset is no longer loadable")
        wanted = extraction.distinct_cves
        kev, epss = await asyncio.to_thread(self._read_views, pins, wanted)
        plan_digest = self._plan_digest(
            opened.verified.scan_run_id, opened.verified, extraction, pins
        )
        return _Pinned(pins=pins, plan_digest=plan_digest, kev=kev, epss=epss, reference=reference)

    # -- publishing ----------------------------------------------------------
    def _sources_meta(self, pins: dict[str, Any]) -> dict[str, Any]:
        meta: dict[str, Any] = {}
        kev = pins.get(Source.KEV.value)
        meta[Source.KEV.value] = (
            {
                "snapshot_id": kev["snapshot_id"],
                "catalog_version": kev["label"],
                "age_s": kev["age_s"],
                "max_age_s": kev["max_age_s"],
                "stale": kev["stale"],
                "integrity_hold": kev.get("integrity_hold", []),
                "asserted_by": "provider_snapshot",
            }
            if kev
            else {"snapshot_id": None, "status": "no_accepted_snapshot"}
        )
        epss = pins.get(Source.EPSS.value)
        meta[Source.EPSS.value] = (
            {
                "snapshot_id": epss["snapshot_id"],
                "score_date": epss["label"],
                "model_version": epss.get("model_version"),
                "calibrated_for_policy": epss.get("model_version")
                in self._policy.calibrated_models,
                "age_s": epss["age_s"],
                "max_age_s": epss["max_age_s"],
                "stale": epss["stale"],
                "asserted_by": "provider_snapshot",
            }
            if epss
            else {"snapshot_id": None, "status": "no_accepted_snapshot"}
        )
        meta[Source.CVSS_TEMPLATE.value] = {
            "snapshot_id": pins[Source.CVSS_TEMPLATE.value]["snapshot_id"],
            "asserted_by": "template",
            "note": "template-asserted score; not provider truth",
        }
        reference = pins.get(Source.ATTACK_CTID.value) or {}
        meta[Source.ATTACK_CTID.value] = (
            {**reference, "asserted_by": "reference_dataset"}
            if reference.get("snapshot_id")
            else {"snapshot_id": None, "status": "dataset_unavailable",
                  "detail": reference.get("unavailable")}
        )
        return meta

    def _pinned_snapshot_ids(self, pins: dict[str, Any]) -> list[str]:
        return [
            pins[s.value]["snapshot_id"]
            for s in NETWORK_SOURCES
            if pins.get(s.value) and pins[s.value].get("snapshot_id")
        ]

    async def _publish(
        self,
        opened: _OpenedPass,
        pinned: _Pinned,
        derivation: Derivation,
        extraction: ExtractionResult,
        *,
        keeper: LeaseKeeper,
        caller: CallerIdentity,
        acquisitions: dict[str, dict[str, Any]],
    ) -> PassResult:
        scan_run_id = opened.verified.scan_run_id
        manifest = {
            "manifest_format_version": MANIFEST_FORMAT_VERSION,
            "plan_digest": pinned.plan_digest,
            "base_report": opened.verified.as_reference(),
            "pins": pinned.pins,
            "egress_posture": self._snapshots.posture,
        }
        body = build_report_body(
            scan_run_id=scan_run_id,
            pass_id=opened.pass_id,
            initiated_by=caller.label,
            generated_at=self._clock.now(),
            verified=opened.verified,
            derivation=derivation,
            extraction=extraction,
            policy=self._policy,
            sources_meta=self._sources_meta(pinned.pins),
            manifest=manifest,
            limitations=declared_limitations(
                templates_pinned=bool(self._settings.templates_digest),
                posture=self._snapshots.posture,
                reference=pinned.reference,
            ),
        )
        digest = report_digest(body)
        report_id = report_id_for(scan_run_id, digest)
        event = self._audit.report_emitted(
            scan_run_id=scan_run_id,
            pass_id=opened.pass_id,
            report_id=report_id,
            report_digest=digest,
            derivations_digest=derivation.digest,
            manifest_digest=manifest_digest(manifest),
            base_report_digest=opened.verified.report_digest,
            outcome=derivation.outcome.value,
            initiated_by=caller.label,
            timestamp=self._clock.now(),
        )

        async with self._db.session() as session, session.begin():
            repo = EnrichmentRepository(session)
            await self._assert_holding(repo, keeper)
            revoked = [
                sid for sid in self._pinned_snapshot_ids(pinned.pins) if await repo.is_revoked(sid)
            ]
            if revoked:
                return await self._abandon(
                    repo,
                    pass_id=opened.pass_id,
                    scan_run_id=scan_run_id,
                    keeper=keeper,
                    caller=caller,
                    reason=AbandonReason.PINS_UNAVAILABLE,
                    detail=f"pinned snapshot revoked: {', '.join(revoked)}"[:2000],
                    acquisitions=acquisitions,
                )
            # The compare-and-set comes first: it row-locks the pass, so a second
            # publisher blocks here and then fails the state predicate.
            completed = await repo.transition_pass(
                opened.pass_id,
                epoch=keeper.epoch,
                expected_states=(PassState.RUNNING,),
                state=PassState.COMPLETE.value,
                outcome=derivation.outcome.value,
                manifest=manifest,
                completed_at=func.now(),
            )
            if not completed:
                raise FencedOut(f"pass {opened.pass_id} could not be completed at this epoch")
            await repo.insert_assertions(opened.pass_id, scan_run_id, derivation.assertions)
            await repo.insert_priorities(opened.pass_id, scan_run_id, derivation.priorities)
            repo.add_event(
                event, initiated_by=caller.label, scan_run_id=scan_run_id, pass_id=opened.pass_id
            )
            await repo.insert_report(
                {
                    "report_id": report_id,
                    "pass_id": opened.pass_id,
                    "scan_run_id": scan_run_id,
                    "kind": "ENRICHMENT",
                    "base_report_id": opened.verified.report_id,
                    "base_report_digest": opened.verified.report_digest,
                    "report_schema_version": body["enrichment_report_schema_version"],
                    "body": body,
                    "report_digest": digest,
                    "audit_event_id": event.event_id,
                }
            )
        logger.info(
            "enrichment_pass_completed",
            scan_run_id=scan_run_id,
            pass_id=opened.pass_id,
            outcome=derivation.outcome.value,
            findings=len(derivation.priorities),
            report_id=report_id,
        )
        return PassResult(
            scan_run_id=scan_run_id,
            pass_id=opened.pass_id,
            state=PassState.COMPLETE.value,
            outcome=derivation.outcome.value,
            report_id=report_id,
            report_digest=digest,
            resumed=opened.resumed,
            acquisitions=acquisitions,
        )


def _pass_summary(row: EnrichmentPass) -> dict[str, Any]:
    return {
        "pass_id": row.pass_id,
        "state": row.state,
        "outcome": row.outcome,
        "reason": row.reason,
        "detail": row.detail,
        "initiated_by": row.initiated_by,
        "base_report_id": row.base_report_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
    }

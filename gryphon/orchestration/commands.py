"""The operator command boundary and the versioned read view.

Two problems this closes.

**An unauthenticated invocation surface.** This component turns a bare scan id
into live scanning authority, so "a local trusted caller" is an assumption, not
a control. The enforcement layer already learned this and answers it with a peer
credential check on a Unix socket; the same standard applies here, and every
accepted command records *who* issued it. "Who started this scan?" is the first
question in any incident review, and it needs an answer that does not depend on
logs having survived.

**Consumers coupling to tables.** A return type too narrow to express the
system's states forces callers to query the ledger directly, and then the
schema becomes the public interface — unversioned, unguarded, and impossible to
change. The read view here is the supported surface, versioned so it can evolve
without breaking a later stage's scheduler or dashboard.

Commands are deliberately few: start, status, cancel, abort, reconcile, drain.
Those are exactly the operations a long-running stateful workload needs and the
ones whose absence makes an incident unrecoverable.
"""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Sequence

from sqlalchemy.exc import DBAPIError, OperationalError

from gryphon.logging_config import get_logger
from gryphon.orchestration.audit import OrchestrationAuditBuilder
from gryphon.orchestration.constants import READ_VIEW_VERSION, ScanLifecycleState
from gryphon.orchestration.ledger import (
    OrchestrationAuditRepository,
    PlanRepository,
    RawFindingRepository,
    ReportRepository,
    ScanLifecycleRepository,
)
from gryphon.orchestration.orchestrator import ScanOrchestrator, ScanOutcome
from gryphon.orchestration.reasons import OrchestrationReasonCode, StaleClaimError
from gryphon.orchestration.runtime import ScanRuntime

logger = get_logger(__name__)


class Command(str, Enum):
    """The supported operator commands."""

    START = "start"
    STATUS = "status"
    CANCEL = "cancel"
    ABORT = "abort"
    RECONCILE = "reconcile"
    DRAIN = "drain"


@dataclass(frozen=True, slots=True)
class CallerIdentity:
    """An authenticated local caller."""

    uid: int
    label: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.label


class CallerRejected(Exception):
    """The caller could not be authenticated or is not allowed."""


def peer_identity(sock: socket.socket, *, allowed_uids: Sequence[int]) -> CallerIdentity:
    """Authenticate a Unix-socket peer by its kernel-reported credentials.

    ``SO_PEERCRED`` is supplied by the kernel, not by the client, so it cannot
    be forged by the caller the way a self-asserted identity in a payload could.
    """
    if not hasattr(socket, "SO_PEERCRED"):  # pragma: no cover - non-Linux
        raise CallerRejected("peer credentials are unavailable on this platform")
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, _gid = struct.unpack("3i", raw)
    if allowed_uids and uid not in allowed_uids:
        raise CallerRejected(f"uid {uid} is not permitted to invoke scans")
    return CallerIdentity(uid=uid, label=f"uid:{uid}/pid:{pid}")


def local_cli_identity(*, allowed_uids: Sequence[int] = ()) -> CallerIdentity:
    """Identify a direct CLI caller by its own uid.

    Permitted outside production, where the socket path is required. The uid is
    the process's real identity, not a value it supplied.
    """
    uid = os.getuid() if hasattr(os, "getuid") else -1
    if allowed_uids and uid not in allowed_uids:
        raise CallerRejected(f"uid {uid} is not permitted to invoke scans")
    return CallerIdentity(uid=uid, label=f"cli:uid:{uid}")


@dataclass(frozen=True, slots=True)
class ScanStatus:
    """The versioned read view of one scan. The supported consumer surface."""

    read_view_version: str
    scan_run_id: str
    state: str
    reason_code: str | None
    phase_reached: int
    owner_id: str | None
    claim_epoch: int
    lease_expires_at: datetime | None
    deadline_at: datetime | None
    initiated_by: str
    planned: int
    covered: int
    pending: int
    finding_count: int
    report_id: str | None
    report_digest: str | None
    started_at: datetime | None
    terminal_at: datetime | None

    def as_payload(self) -> dict[str, Any]:
        return {
            "read_view_version": self.read_view_version,
            "scan_run_id": self.scan_run_id,
            "state": self.state,
            "reason_code": self.reason_code,
            "phase_reached": self.phase_reached,
            "owner_id": self.owner_id,
            "claim_epoch": self.claim_epoch,
            "lease_expires_at": _iso(self.lease_expires_at),
            "deadline_at": _iso(self.deadline_at),
            "initiated_by": self.initiated_by,
            "planned": self.planned,
            "covered": self.covered,
            "pending": self.pending,
            "finding_count": self.finding_count,
            "report_id": self.report_id,
            "report_digest": self.report_digest,
            "started_at": _iso(self.started_at),
            "terminal_at": _iso(self.terminal_at),
        }


class OperatorCommands:
    """Authenticated, audited operator operations."""

    def __init__(
        self,
        *,
        runtime: ScanRuntime,
        orchestrator: ScanOrchestrator,
        audit: OrchestrationAuditBuilder | None = None,
    ) -> None:
        self._runtime = runtime
        self._orchestrator = orchestrator
        self._audit = audit or runtime.audit
        self._draining = False

    @property
    def draining(self) -> bool:
        """Whether new claims are being refused.

        Drain is what makes a deploy survivable: in-flight scans finish while
        nothing new starts, instead of a restart stranding running engagements.
        """
        return self._draining

    async def start(self, scan_run_id: str, *, caller: CallerIdentity) -> ScanOutcome:
        """Run or resume a scan as an authenticated caller."""
        if self._draining:
            await self._audit_command(
                Command.START, scan_run_id, caller, accepted=False,
                reason=OrchestrationReasonCode.ALREADY_RUNNING,
            )
            return ScanOutcome(
                scan_run_id=scan_run_id,
                terminal_state=ScanLifecycleState.RUNNING,
                reason_code=OrchestrationReasonCode.ALREADY_RUNNING.value,
                claim_epoch=0,
            )
        await self._audit_command(Command.START, scan_run_id, caller, accepted=True)
        return await self._orchestrator.invoke(scan_run_id, initiated_by=caller.label)

    async def status(self, scan_run_id: str) -> ScanStatus | None:
        """Read the versioned view. No authority required; no side effects."""
        async with self._runtime.database.session() as session:
            lifecycle = await ScanLifecycleRepository(session).get(scan_run_id)
            if lifecycle is None:
                return None
            items = await PlanRepository(session).items_for_scan(scan_run_id)
            findings = await RawFindingRepository(session).count_for_scan(scan_run_id)
            report = await ReportRepository(session).latest_for_scan(scan_run_id)

        from gryphon.orchestration.constants import PlanItemState

        planned = len(items)
        covered = sum(1 for i in items if i.state == PlanItemState.COMPLETED.value)
        pending = sum(
            1
            for i in items
            if i.state in (PlanItemState.PLANNED.value, PlanItemState.DISPATCHED.value)
        )
        return ScanStatus(
            read_view_version=READ_VIEW_VERSION,
            scan_run_id=scan_run_id,
            state=lifecycle.state,
            reason_code=lifecycle.reason_code,
            phase_reached=lifecycle.phase_reached,
            owner_id=lifecycle.owner_id,
            claim_epoch=lifecycle.claim_epoch,
            lease_expires_at=lifecycle.lease_expires_at,
            deadline_at=lifecycle.deadline_at,
            initiated_by=lifecycle.initiated_by,
            planned=planned,
            covered=covered,
            pending=pending,
            finding_count=findings,
            report_id=report.report_id if report else None,
            report_digest=report.report_digest if report else None,
            started_at=lifecycle.started_at,
            terminal_at=lifecycle.terminal_at,
        )

    async def abort(
        self, scan_run_id: str, *, caller: CallerIdentity
    ) -> bool:
        """Force a scan to a terminal state without scanning anything further.

        The escape hatch for a scan that cannot make progress. Without it, a
        scan stuck behind an unresolvable condition would occupy its
        authorization indefinitely with no supported way out.
        """
        async with self._runtime.database.session() as session:
            lifecycle = await ScanLifecycleRepository(session).get(scan_run_id)
        if lifecycle is None:
            await self._audit_command(
                Command.ABORT, scan_run_id, caller, accepted=False,
                reason=OrchestrationReasonCode.NO_ADMISSION,
            )
            return False

        try:
            async with self._runtime.database.session() as session:
                async with session.begin():
                    await ScanLifecycleRepository(session).transition(
                        scan_run_id=scan_run_id,
                        claim_epoch=lifecycle.claim_epoch,
                        state=ScanLifecycleState.ABORTED_OPERATOR,
                        reason_code=OrchestrationReasonCode.OPERATOR_ABORT.value,
                    )
        except (StaleClaimError, OperationalError, DBAPIError):
            await self._audit_command(
                Command.ABORT, scan_run_id, caller, accepted=False,
                reason=OrchestrationReasonCode.STALE_CLAIM_EPOCH,
            )
            return False

        await self._audit_command(Command.ABORT, scan_run_id, caller, accepted=True)
        logger.warning(
            "scan_aborted_by_operator", scan_run_id=scan_run_id, caller=caller.label
        )
        return True

    #: ``cancel`` is an alias for ``abort`` at this layer: there is no
    #: cooperative cancellation to request, because work is dispatched one
    #: bounded call at a time and the next call simply does not happen.
    cancel = abort

    async def reconcile(
        self, scan_run_id: str, *, caller: CallerIdentity
    ) -> dict[str, int]:
        """Run a reconciliation pass on demand."""
        async with self._runtime.database.session() as session:
            lifecycle = await ScanLifecycleRepository(session).get(scan_run_id)
        if lifecycle is None:
            await self._audit_command(
                Command.RECONCILE, scan_run_id, caller, accepted=False,
                reason=OrchestrationReasonCode.NO_ADMISSION,
            )
            return {"examined": 0, "resolved": 0, "unresolved": 0}

        await self._audit_command(Command.RECONCILE, scan_run_id, caller, accepted=True)
        report = await self._runtime.reconciler.reconcile(
            scan_run_id=scan_run_id, claim_epoch=lifecycle.claim_epoch
        )
        return {
            "examined": report.examined,
            "resolved": report.resolved,
            "unresolved": report.unresolved,
        }

    async def drain(self, *, caller: CallerIdentity, enabled: bool = True) -> bool:
        """Refuse new claims while in-flight scans finish."""
        self._draining = enabled
        await self._audit_command(Command.DRAIN, None, caller, accepted=True)
        logger.info("drain_mode", enabled=enabled, caller=caller.label)
        return self._draining

    async def _audit_command(
        self,
        command: Command,
        scan_run_id: str | None,
        caller: CallerIdentity,
        *,
        accepted: bool,
        reason: OrchestrationReasonCode | None = None,
    ) -> None:
        event = self._audit.operator_command(
            scan_run_id=scan_run_id,
            command=command.value,
            initiated_by=caller.label,
            accepted=accepted,
            reason_code=reason.value if reason else None,
            timestamp=self._runtime.clock.now(),
        )
        try:
            async with self._runtime.database.session() as session:
                async with session.begin():
                    OrchestrationAuditRepository(session).append(
                        event_id=event.event_id,
                        event_type=event.event_type,
                        event_schema_version=event.payload["event_schema_version"],
                        scan_run_id=scan_run_id,
                        decision="ACCEPT" if accepted else "REJECT",
                        reason_code=reason.value if reason else None,
                        initiated_by=caller.label,
                        payload=event.payload,
                        payload_digest=event.payload_digest,
                        signer_kid=event.signer_kid,
                        signature=event.signature_b64,
                    )
        except (OperationalError, DBAPIError):
            logger.warning("operator_command_audit_unavailable", command=command.value)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None

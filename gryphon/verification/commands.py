"""The operator commands: one pass, assembled from parts that stay separable.

This module is the composition that turns the layer's pure pieces — the planner,
the evaluator, the publisher — and its two effectful ones — the repository and
the gateway client — into the six things an operator can ask for. It holds no
policy of its own. Every refusal here is a value some other module returned.

Four properties are the reason it exists as its own unit rather than inside the
engine:

* **The engine never learns what a session is.** It talks to two narrow ports.
  Keeping the database and the socket behind adapters is what makes the engine
  testable without either, and what stopped the gateway from being constructed
  in this process — the single most load-bearing custody rule in the layer.
* **Ownership and identity are decided before anything is spent.** The request
  key resolves to exactly one pass, and a pass that already reached a terminal
  state is *returned*, not re-run. A retried command after a dropped connection
  costs a client's estate nothing.
* **The lease is claimed by the same statement that creates the pass.** Claiming
  in two steps would leave a window where a pass exists that nobody owns, and
  recovery from that window is indistinguishable from a crash. The keeper that
  heartbeats afterwards is anchored at a reading taken *before* that statement,
  because the claim's own round trip counts against the lease.
* **Publication is one transaction.** The report row, the signed attestation and
  the move to COMPLETE commit together, guarded by the claim epoch. A deliverable
  that existed without its attestation would be a conclusion nobody vouched for.

The two ``VerdictRecord`` types are deliberate and are reconciled here. The
engine produces :class:`gryphon.verification.publish.VerdictRecord`, which holds
the evaluator's verdict whole because the report is rendered from it. The row
needs :class:`gryphon.verification.repository.VerdictRecord`, which is flat
because a column is not a nested document. This module is the only place that
knows both, which is why the translation is written out rather than hidden in a
constructor on either side.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from gryphon.auth.key_provider import KeyMaterial, build_key_material
from gryphon.clock import Clock
from gryphon.db.session import Database
from gryphon.logging_config import get_logger
from gryphon.passkernel.lease import LeaseKeeper, LeaseLost, new_holder_id
from gryphon.passkernel.ports import LeaseState
from gryphon.tooling.gateway.client import GatewayClient
from gryphon.tooling.gateway.protocol import ObserveRequest, Welcome
from gryphon.tooling.observation.envelope import RequestEnvelope
from gryphon.tooling.observation.facts import ObservationFacts
from gryphon.verification.constants import (
    EVIDENCE_OUTCOMES,
    EXECUTION_PURPOSE,
    AbandonReason,
    BlockedReason,
    EnrichmentContext,
    ObservationRole,
    OrderingBasis,
    OutcomeClass,
    PassOutcome,
    PassState,
    RefusalReason,
    VerdictStatus,
    VerificationEventType,
)
from gryphon.verification.engine import Budget, CampaignResult, VerificationCampaign
from gryphon.verification.inputs import (
    AttestedEvent,
    BaseReportMaterial,
    EnrichmentMaterial,
    Refusal,
    VerifiedInput,
    findings_from,
    verify_base_report,
    verify_enrichment,
)
from gryphon.verification.observation import Observation
from gryphon.verification.planner import ObservationPlanner, Plan
from gryphon.verification.publish import (
    VerdictRecord as ReportVerdict,
)
from gryphon.verification.publish import (
    build_report_body,
    declared_limitations,
    manifest_digest,
    outcome_for,
    publish,
    verdict_set_digest,
    verify_report,
)
from gryphon.verification.reasons import (
    GatewayProtocolError,
    GatewayUnavailable,
    PassBusy,
    RequestKeyConflict,
    VerificationConfigurationError,
)
from gryphon.verification.repository import (
    Busy,
    KeyConflict,
    ObservationRecord,
    PassClaim,
    PinRecord,
    VerificationRepository,
)
from gryphon.verification.repository import (
    VerdictRecord as RowVerdict,
)

logger = get_logger(__name__)

#: What this layer calls itself to the gateway. The gateway binds a purpose to
#: the destination classes it will serve, so presenting the wrong one is refused
#: rather than quietly widened.
CLIENT_NAME = "gryphon-verification"

#: The report schema this layer emits.
REPORT_SCHEMA_VERSION = "1"

#: Selectors ``--only`` accepts, resolved against the scan's last complete pass.
SELECTOR_INCONCLUSIVE = "inconclusive"
SELECTOR_UNKNOWN = "unknown"

#: Pass states that still hold the scan's one open slot.
_OPEN_STATE_VALUES = frozenset(
    {PassState.PLANNED.value, PassState.RUNNING.value, PassState.BLOCKED.value}
)


# =============================================================================
# Results
# =============================================================================


@dataclass(frozen=True, slots=True)
class PassResult:
    """What one command did, in the shape the CLI prints.

    ``state`` is the field the exit code is derived from, so it is always the
    pass's state as committed — never a local opinion about how things went.
    """

    pass_id: str
    scan_run_id: str
    state: PassState
    outcome: PassOutcome | None = None
    reason: str | None = None
    detail: str | None = None
    report_id: str | None = None
    findings_planned: int = 0
    observations: int = 0
    verdicts: int = 0
    resumed: bool = False
    adopted: bool = False
    returned: bool = False
    degraded: bool = False
    stopped: bool = False
    paused_hosts: tuple[str, ...] = ()
    counts: dict[str, int] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        return {
            "pass_id": self.pass_id,
            "scan_run_id": self.scan_run_id,
            "state": self.state.value,
            "outcome": self.outcome.value if self.outcome else None,
            "reason": self.reason,
            "detail": self.detail,
            "report_id": self.report_id,
            "findings_planned": self.findings_planned,
            "observations": self.observations,
            "verdicts": self.verdicts,
            "resumed": self.resumed,
            "adopted": self.adopted,
            # True when this command returned an existing pass untouched: the
            # request key did its job and no traffic was sent.
            "returned": self.returned,
            "degraded": self.degraded,
            "stopped": self.stopped,
            "paused_hosts": list(self.paused_hosts),
            "counts": dict(self.counts),
        }


@dataclass(frozen=True, slots=True)
class ReportVerification:
    """Whether a stored report still verifies, and why not when it does not."""

    verified: bool
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class ServedReport:
    """A deliverable, re-verified at the moment it is served."""

    report_id: str
    pass_id: str
    body: dict[str, Any]
    verification: ReportVerification


@dataclass(frozen=True, slots=True)
class StatusResult:
    """Open passes and, when a scan is named, that scan's pass history."""

    open_passes: tuple[dict[str, Any], ...]
    scan_run_id: str | None = None
    history: tuple[dict[str, Any], ...] = ()

    def as_payload(self) -> dict[str, Any]:
        return {
            "open_passes": [dict(p) for p in self.open_passes],
            "scan_run_id": self.scan_run_id,
            "history": [dict(h) for h in self.history],
        }


# =============================================================================
# Adapters
# =============================================================================


class _PassLeaseStore:
    """A :class:`LeaseStore` bound to one pass.

    ``claim`` is deliberately absent from the path this module uses: the pass is
    claimed by ``claim_pass``, which creates the row and takes the lease in one
    statement. Offering a second way to claim would invite a caller to create an
    unowned pass and then race to own it.
    """

    def __init__(self, database: Database, pass_id: str) -> None:
        self._database = database
        self._pass_id = pass_id

    async def claim(self, holder: str, lease_seconds: float) -> int | None:
        raise VerificationConfigurationError(
            "a verification pass is claimed by claim_pass, which creates the row and "
            "takes the lease together"
        )

    async def renew(self, holder: str, epoch: int, lease_seconds: float) -> bool:
        async with self._database.session() as session:
            repo = VerificationRepository(session)
            held = await repo.renew_lease(holder, epoch, lease_seconds)
            await session.commit()
            return held

    async def release(self, holder: str, epoch: int) -> None:
        async with self._database.session() as session:
            repo = VerificationRepository(session)
            await repo.release_lease(holder, epoch)
            await session.commit()

    async def describe(self) -> LeaseState | None:
        async with self._database.session() as session:
            return await VerificationRepository(session).lease_state(self._pass_id)


class _PassStore:
    """The engine's :class:`PassPort`, over short, committed sessions.

    Each write commits on its own. Batching them would be faster and wrong: the
    engine's recovery story is that an observation already on the wire has a
    durable row before the next one is dispatched, and a transaction held open
    across dispatches is exactly the window that story denies.
    """

    def __init__(
        self,
        database: Database,
        *,
        claim: PassClaim,
        registry_digest: str,
        envelope_digests: Mapping[str, str],
        subjects: Mapping[str, str],
    ) -> None:
        self._database = database
        self._claim = claim
        self._registry_digest = registry_digest
        self._envelope_digests = dict(envelope_digests)
        self._subjects = dict(subjects)

    async def record_observation(
        self, observation: Observation, *, finding_id: str, verifier_id: str
    ) -> None:
        digest = self._envelope_digests.get(observation.observation_id, "")
        record = ObservationRecord.settled(
            observation,
            finding_id=finding_id,
            verifier_id=verifier_id,
            envelope_digest=digest,
        )
        async with self._database.session() as session:
            repo = VerificationRepository(session)
            await repo.record_observation(self._claim, record)
            await session.commit()

    async def record_verdict(self, record: ReportVerdict) -> None:
        row = row_verdict(record, registry_digest=self._registry_digest)
        async with self._database.session() as session:
            repo = VerificationRepository(session)
            await repo.record_verdict(self._claim, row)
            await session.commit()

    async def settled_observations(self, pass_id: str) -> Mapping[str, Observation]:
        """Only the observations this layer can reconstruct truthfully.

        The row keeps a *digest* of the typed facts, never the facts: they stay
        with the gateway, which is the only component that ever held them. So a
        row for a contact that produced evidence cannot be rebuilt here, and
        returning one with ``facts=None`` would hand the evaluator an absence
        where there was a measurement — turning a resumed CONFIRMED into an
        INCONCLUSIVE without anything in the system saying why.

        Rows with no facts — refusals, transport failures, anything the gateway
        declined — *are* faithfully reconstructable, because for those the
        absence is the truth, and reusing them saves a pointless round trip.

        The rest is not lost: a resumed pass re-presents the same deterministic
        ``execution_id``, and the gateway answers a repeated execution from its
        own durable record, facts included, without contacting the target. The
        de-duplication that matters lives with the component that would
        otherwise send the packet, which is the only place it can be enforced.
        """
        async with self._database.session() as session:
            rows = await VerificationRepository(session).observations_for(pass_id)
        settled: dict[str, Observation] = {}
        for row in rows:
            rebuilt = reconstructed_observation(row)
            if rebuilt is not None:
                settled[rebuilt.observation_id] = rebuilt
        return settled

    async def possibly_applied_subjects(self, scan_run_id: str) -> set[str]:
        async with self._database.session() as session:
            return await VerificationRepository(session).possibly_applied_subjects(scan_run_id)

    async def cancellation_epoch(self, pass_id: str) -> int:
        async with self._database.session() as session:
            row = await VerificationRepository(session).get_pass(pass_id)
        return int(row.cancellation_epoch) if row is not None else self._claim.cancellation_epoch


class _GatewayObservations:
    """The engine's :class:`ObservationPort`, over one gateway connection.

    Every field the gateway needs to decide whether to dispatch — the pass, the
    claim epoch, the cancellation epoch — is carried on each request rather than
    established once at connect time. The gateway is the component that puts
    packets on someone else's network, so it re-decides per request instead of
    trusting a session it opened earlier.
    """

    def __init__(
        self,
        client: GatewayClient,
        *,
        pinned_digest: str,
        observation_ids: Mapping[str, str],
    ) -> None:
        self._client = client
        self._pinned = pinned_digest
        # execution id -> the planned observation id it answers for. The port
        # does not carry the observation id, and the reply must not invent one:
        # which planned contact an answer belongs to is this layer's knowledge,
        # not something the far side should be able to assert.
        self._observation_ids = dict(observation_ids)

    async def observe(
        self,
        *,
        execution_id: str,
        envelope: RequestEnvelope,
        pass_id: str,
        claim_epoch: int,
        cancellation_epoch: int,
        deadline_seconds: float,
        scan_run_id: str,
        finding_id: str,
        role: ObservationRole,
        control_index: int,
    ) -> Observation:
        # Re-asserted per request: a gateway redeployed mid-pass would otherwise
        # keep answering, and the later verdicts would rest on different
        # evidence from the earlier ones without anything saying so.
        self._client.assert_pin(self._pinned)

        reply = await self._client.observe(
            ObserveRequest(
                purpose=EXECUTION_PURPOSE,
                pass_id=pass_id,
                claim_epoch=claim_epoch,
                cancellation_epoch=cancellation_epoch,
                execution_id=execution_id,
                envelope=envelope.as_canonical(),
                deadline_seconds=deadline_seconds,
                scan_run_id=scan_run_id,
                finding_id=finding_id,
                role=role,
                control_index=control_index,
            )
        )
        facts = ObservationFacts.from_payload(reply.facts) if reply.facts else None
        if facts is None and reply.outcome in EVIDENCE_OUTCOMES:
            # An evidence outcome with nothing to evidence it. Refused here as a
            # protocol failure rather than allowed through as an observation
            # with no facts: the evaluator reads an absence of facts as an
            # absence in the world, so this would become a verdict about the
            # target instead of a complaint about the reply.
            raise GatewayProtocolError(
                f"the gateway answered {reply.outcome.value} for execution "
                f"{reply.execution_id!r} but carried no facts"
            )
        return Observation(
            observation_id=self._observation_ids[execution_id],
            execution_id=reply.execution_id,
            role=role,
            control_index=control_index,
            outcome=reply.outcome,
            reason_code=reply.reason_code,
            facts=facts,
            peer_address=reply.peer_address,
        )


# =============================================================================
# Commands
# =============================================================================


class VerificationCommands:
    """What an operator can ask for. One instance per process.

    Every method takes the caller explicitly. The identity is established once,
    in the composition root, and threaded through rather than re-read, so a
    command cannot be recorded against a different caller from the one the
    process was admitted as.
    """

    def __init__(
        self,
        *,
        database: Database,
        settings: Any,
        clock: Clock,
        registry: Any,
        evaluator: Any,
        audit: Any,
        attestation_trust: Any,
        enrichment_trust: Any,
        gateway_socket: Any,
        keys: KeyMaterial,
        gateway_factory: Any | None = None,
    ) -> None:
        self._database = database
        self._settings = settings
        self._clock = clock
        self._registry = registry
        self._evaluator = evaluator
        self._audit = audit
        self._attestation_trust = attestation_trust
        self._enrichment_trust = enrichment_trust
        self._socket = gateway_socket
        self._keys = keys
        # How a connected gateway client is obtained. Overridden only by tests,
        # which cannot open a Unix socket on every platform this is developed on
        # — and, more to the point, should be able to drive a whole pass without
        # one. The default is the only thing production ever uses.
        self._gateway_factory = gateway_factory or self._connect_over_socket

    # -- start -----------------------------------------------------------------
    async def start(
        self,
        scan_run_id: str,
        *,
        request_key: str | None,
        caller: Any,
        only: str | Sequence[str] | None = None,
    ) -> PassResult:
        """Run, resume or re-return the pass this request key names."""
        scope = {"only": list(only)} if isinstance(only, tuple | list) else (
            {"only": only} if only else None
        )
        return await self._run_pass(
            scan_run_id,
            request_key=request_key,
            caller=caller,
            only=only,
            scope=scope,
            supersedes=None,
            supersession_reason=None,
        )

    # -- reverify --------------------------------------------------------------
    async def reverify(
        self,
        scan_run_id: str,
        *,
        request_key: str,
        supersedes_pass_id: str,
        reason: str,
        caller: Any,
        only: str | Sequence[str] | None = None,
    ) -> PassResult:
        """Verify again, superseding a named earlier pass.

        A distinct command rather than a flag on ``start`` because superseding a
        published conclusion is a decision someone must state a reason for. The
        superseded pass is named explicitly so the scope of the supersession is
        recorded rather than inferred from timing.
        """
        async with self._database.session() as session:
            earlier = await VerificationRepository(session).get_pass(supersedes_pass_id)
        if earlier is None or earlier.scan_run_id != scan_run_id:
            raise VerificationConfigurationError(
                f"pass {supersedes_pass_id!r} is not a pass of scan {scan_run_id!r}"
            )

        scope = {
            "supersedes": supersedes_pass_id,
            "reason": reason,
            "only": list(only) if isinstance(only, tuple | list) else only,
        }
        return await self._run_pass(
            scan_run_id,
            request_key=request_key,
            caller=caller,
            only=only,
            scope=scope,
            supersedes=supersedes_pass_id,
            supersession_reason=reason,
        )

    # -- status ----------------------------------------------------------------
    async def status(self, scan_run_id: str | None = None) -> StatusResult:
        """Open passes, and one scan's history when a scan is named."""
        from sqlalchemy import select

        from gryphon.db.models.verification import VerificationPass

        async with self._database.session() as session:
            repo = VerificationRepository(session)

            if scan_run_id is None:
                rows = (
                    (
                        await session.execute(
                            select(VerificationPass)
                            .where(VerificationPass.state.in_(_OPEN_STATE_VALUES))
                            .order_by(VerificationPass.started_at.desc())
                        )
                    )
                    .scalars()
                    .all()
                )
                return StatusResult(
                    open_passes=tuple([await self._describe_pass(repo, r) for r in rows])
                )

            rows = (
                (
                    await session.execute(
                        select(VerificationPass)
                        .where(VerificationPass.scan_run_id == scan_run_id)
                        .order_by(VerificationPass.started_at.desc())
                    )
                )
                .scalars()
                .all()
            )
            described = [await self._describe_pass(repo, r) for r in rows]
            return StatusResult(
                open_passes=tuple(d for d in described if d["state"] in _OPEN_STATE_VALUES),
                scan_run_id=scan_run_id,
                history=tuple(described),
            )

    async def _describe_pass(self, repo: VerificationRepository, row: Any) -> dict[str, Any]:
        lease = await repo.lease_state(row.pass_id)
        return {
            "pass_id": row.pass_id,
            "scan_run_id": row.scan_run_id,
            "state": row.state,
            "claim_epoch": row.claim_epoch,
            "cancellation_epoch": row.cancellation_epoch,
            "adoption_count": row.adoption_count,
            "holder": lease.holder if lease else row.holder,
            "lease_expires_at": lease.lease_expires_at if lease else row.lease_expires_at,
            "outcome": getattr(row, "outcome", None),
            "reason": getattr(row, "reason", None),
        }

    # -- report ----------------------------------------------------------------
    async def report(self, scan_run_id: str) -> ServedReport | None:
        """The deliverable, re-verified before it is handed over.

        A stored report is checked against its own digest *and* against a signed
        event that attests exactly that digest. A row altered after publication
        fails here rather than being served as proof — which is the only moment
        at which that alteration could still be caught.
        """
        from sqlalchemy import select

        from gryphon.db.models.verification import VerificationAudit

        async with self._database.session() as session:
            repo = VerificationRepository(session)
            row = await repo.latest_report(scan_run_id)
            if row is None:
                return None
            audit_rows = (
                (
                    await session.execute(
                        select(VerificationAudit).where(
                            VerificationAudit.pass_id == row.pass_id,
                            VerificationAudit.event_type
                            == VerificationEventType.REPORT_EMITTED.value,
                        )
                    )
                )
                .scalars()
                .all()
            )
        events = tuple(
            (dict(e.payload), e.payload_digest, e.signer_kid, e.signature) for e in audit_rows
        )

        verified = verify_report(
            body=dict(row.body),
            stored_digest=row.digest,
            events=events,
            trust=self._attestation_trust,
        )
        return ServedReport(
            report_id=row.report_id,
            pass_id=row.pass_id,
            body=dict(row.body),
            verification=ReportVerification(
                verified=verified,
                reason=None if verified else "no trusted attestation vouches for this digest",
            ),
        )

    # -- stop ------------------------------------------------------------------
    async def stop(self, scan_run_id: str, *, caller: Any, detail: str | None = None) -> (
        PassResult | None
    ):
        """Cease new traffic now. Deliberately not gated on the lease.

        For a component that sends requests to someone else's systems, "stop" is
        a safety control. Requiring the lease would mean an operator could not
        stop a pass whose process is wedged — precisely the case where stopping
        matters most. The epoch advance is what the gateway checks, so traffic
        ceases within one request whether or not this process owns anything.
        """
        async with self._database.session() as session:
            repo = VerificationRepository(session)
            row = await repo.open_pass_for(scan_run_id)
            if row is None:
                return None
            epoch = await repo.advance_cancellation(row.pass_id)
            event = self._audit.pass_abandoned(
                scan_run_id=scan_run_id,
                pass_id=row.pass_id,
                reason=AbandonReason.OPERATOR_STOP.value,
                detail=detail or "operator stop",
                at=await repo.db_now(),
            )
            repo.add_event(_event_values(event))
            await session.commit()

        logger.info(
            "verification_pass_stopped",
            pass_id=row.pass_id,
            cancellation_epoch=epoch,
            initiated_by=getattr(caller, "label", None),
        )
        return PassResult(
            pass_id=row.pass_id,
            scan_run_id=scan_run_id,
            state=PassState(row.state),
            reason=AbandonReason.OPERATOR_STOP.value,
            detail=detail,
            stopped=True,
        )

    # -- abort -----------------------------------------------------------------
    async def abort(self, scan_run_id: str, *, caller: Any, detail: str | None = None) -> (
        PassResult | None
    ):
        """Finish off a pass whose process is gone and whose lease has lapsed.

        Narrower than ``stop`` on purpose: this writes a terminal state, and a
        terminal state written while another process still believes it owns the
        pass would let two writers disagree about what happened.
        """
        holder = new_holder_id("abort")
        async with self._database.session() as session:
            repo = VerificationRepository(session)
            row = await repo.open_pass_for(scan_run_id)
            if row is None:
                return None
            claim = await repo.claim_pass(
                scan_run_id,
                None,
                holder=holder,
                lease_seconds=self._settings.pass_lease_seconds,
                initiated_by=getattr(caller, "label", "unknown"),
            )
            if isinstance(claim, Busy):
                # Abort is for a pass whose lease has lapsed. A live holder is
                # still working, and two writers on one terminal state is the
                # thing the epoch exists to prevent.
                raise PassBusy(claim.scan_run_id, claim.holder, claim.lease_expires_at)
            if isinstance(claim, KeyConflict):  # pragma: no cover - no key was presented
                raise RequestKeyConflict(claim.request_key, claim.detail)

            moved = await repo.transition(
                claim,
                {PassState.PLANNED, PassState.RUNNING, PassState.BLOCKED},
                PassState.ABANDONED,
                reason=AbandonReason.OPERATOR_ABORT.value,
                detail=detail or "operator abort",
            )
            event = self._audit.pass_abandoned(
                scan_run_id=scan_run_id,
                pass_id=claim.pass_id,
                reason=AbandonReason.OPERATOR_ABORT.value,
                detail=detail or "operator abort",
                at=await repo.db_now(),
            )
            repo.add_event(_event_values(event))
            await session.commit()

        return PassResult(
            pass_id=claim.pass_id,
            scan_run_id=scan_run_id,
            state=PassState.ABANDONED if moved else PassState(row.state),
            reason=AbandonReason.OPERATOR_ABORT.value,
            detail=detail,
            adopted=claim.adopted,
        )

    # =========================================================================
    # The pass itself
    # =========================================================================

    async def _run_pass(
        self,
        scan_run_id: str,
        *,
        request_key: str | None,
        caller: Any,
        only: str | Sequence[str] | None,
        scope: Mapping[str, Any] | None,
        supersedes: str | None,
        supersession_reason: str | None,
    ) -> PassResult:
        holder = new_holder_id(CLIENT_NAME)
        initiated_by = getattr(caller, "label", "unknown")

        # Read before the claim statement: the claim's own round trip counts
        # against the lease, so the staleness bound starts here, not after.
        claimed_at = time.monotonic()
        async with self._database.session() as session:
            repo = VerificationRepository(session)
            claim = await repo.claim_pass(
                scan_run_id,
                request_key,
                holder=holder,
                lease_seconds=self._settings.pass_lease_seconds,
                initiated_by=initiated_by,
                scope=scope,
            )
            await session.commit()

        if isinstance(claim, KeyConflict):
            raise RequestKeyConflict(claim.request_key, claim.detail)
        if isinstance(claim, Busy):
            raise PassBusy(claim.scan_run_id, claim.holder, claim.lease_expires_at)

        if not claim.owned:
            # The key resolved to a pass that already finished. That is the key
            # doing its job: return what it produced, send nothing.
            return await self._return_existing(claim)

        keeper = LeaseKeeper(
            _PassLeaseStore(self._database, claim.pass_id),
            holder=holder,
            epoch=claim.claim_epoch,
            lease_seconds=self._settings.pass_lease_seconds,
            heartbeat_seconds=self._settings.pass_heartbeat_seconds,
            claimed_at=claimed_at,
        )
        try:
            async with keeper:
                return await self._execute(
                    claim,
                    keeper=keeper,
                    caller=caller,
                    only=only,
                    request_key=request_key,
                    supersedes=supersedes,
                    supersession_reason=supersession_reason,
                )
        except LeaseLost as exc:
            logger.warning(
                "verification_pass_fenced", pass_id=claim.pass_id, reason=str(exc)
            )
            return PassResult(
                pass_id=claim.pass_id,
                scan_run_id=claim.scan_run_id,
                state=PassState.BLOCKED,
                reason=BlockedReason.DATABASE_UNAVAILABLE.value,
                detail=str(exc),
            )
        finally:
            # Give the lease up rather than letting it lapse. The keeper's exit
            # only stops the heartbeat; the release is what the kernel's own
            # ``hold_lease`` does after the body, and this composition claims
            # through ``claim_pass`` instead, so it owes the same courtesy.
            #
            # It matters most for a pass that did not finish: a BLOCKED pass
            # still holds the scan's one slot, so without this the operator who
            # restarts the dependency and retries is told the scan is busy until
            # the lease expires. Allowed to fail — recovery rests on expiry, so
            # a release that does not happen costs time, never correctness.
            try:
                await _PassLeaseStore(self._database, claim.pass_id).release(
                    holder, claim.claim_epoch
                )
            except Exception as exc:  # pragma: no cover - best effort by design
                logger.warning(
                    "verification_lease_release_failed",
                    pass_id=claim.pass_id,
                    error=type(exc).__name__,
                )

    async def _return_existing(self, claim: PassClaim) -> PassResult:
        async with self._database.session() as session:
            repo = VerificationRepository(session)
            row = await repo.get_pass(claim.pass_id)
            report = await repo.report_for_pass(claim.pass_id)
        outcome = getattr(row, "outcome", None)
        return PassResult(
            pass_id=claim.pass_id,
            scan_run_id=claim.scan_run_id,
            state=claim.state,
            outcome=PassOutcome(outcome) if outcome else None,
            reason=getattr(row, "reason", None),
            report_id=report.report_id if report else None,
            resumed=True,
            returned=True,
        )

    async def _execute(
        self,
        claim: PassClaim,
        *,
        keeper: LeaseKeeper,
        caller: Any,
        only: str | Sequence[str] | None,
        request_key: str | None,
        supersedes: str | None,
        supersession_reason: str | None,
    ) -> PassResult:
        # 1. The gateway, before anything is read or planned. Its welcome is
        #    what the pass pins, so a pass that cannot reach it has nothing to
        #    pin and must block rather than proceed on last-known values.
        try:
            async with self._connected() as client:
                welcome = client.welcome
                return await self._with_gateway(
                    claim,
                    client=client,
                    welcome=welcome,
                    keeper=keeper,
                    caller=caller,
                    only=only,
                    supersedes=supersedes,
                    supersession_reason=supersession_reason,
                )
        except GatewayUnavailable as exc:
            return await self._block(claim, BlockedReason.GATEWAY_UNAVAILABLE, str(exc), caller)

    def _connected(self) -> Any:
        return self._gateway_factory()

    @asynccontextmanager
    async def _connect_over_socket(self) -> AsyncIterator[GatewayClient]:
        client = GatewayClient.over_unix_socket(
            self._socket,
            client_name=CLIENT_NAME,
            connect_timeout_seconds=self._settings.gateway_connect_timeout_seconds,
        )
        await client.connect()
        try:
            yield client
        finally:
            await client.close()

    async def _with_gateway(
        self,
        claim: PassClaim,
        *,
        client: GatewayClient,
        welcome: Welcome,
        keeper: LeaseKeeper,
        caller: Any,
        only: str | Sequence[str] | None,
        supersedes: str | None,
        supersession_reason: str | None,
    ) -> PassResult:
        # 2. Inputs. A refusal here is a statement about the scan, not about us,
        #    and it is recorded against the pass so a repeat of the command
        #    returns the same refusal instead of re-deriving it.
        verified = await self._verified_input(claim.scan_run_id)
        if isinstance(verified, Refusal):
            return await self._refuse(claim, verified, caller)

        # 3. Pins. Written once; a resumed pass reads back what it pinned and
        #    holds the gateway to it.
        pins = await self._pin(claim, verified=verified, welcome=welcome)
        client.assert_pin(pins.feature_set_digest)

        # 4. Plan, from the gateway's own descriptor versions.
        salt = await self._salt(claim.pass_id)
        plan = self._plan(
            verified,
            welcome=welcome,
            pass_id=claim.pass_id,
            salt=salt,
            only=only,
        )

        await self._mark_running(claim)

        # 5. Run.
        store = _PassStore(
            self._database,
            claim=claim,
            registry_digest=self._registry.digest,
            envelope_digests={
                o.observation_id: o.envelope.digest
                for f in plan.findings
                for o in f.observations
            },
            subjects={f.finding.finding_id: f.subject_key for f in plan.findings},
        )
        campaign = VerificationCampaign(
            gateway=_GatewayObservations(
                client,
                pinned_digest=pins.feature_set_digest,
                observation_ids={
                    o.execution_id: o.observation_id
                    for f in plan.findings
                    for o in f.observations
                },
            ),
            store=store,
            evaluator=self._evaluator,
            clock=self._clock,
            budget=Budget(
                max_findings=self._settings.findings_per_pass,
                max_observations=self._settings.observations_per_pass,
                concurrency=self._settings.concurrency,
                deadline_seconds=self._settings.pass_deadline_seconds,
                controls_per_host=self._settings.controls_per_host,
            ),
            lease_check=keeper,
        )
        result = await campaign.run(
            plan,
            pass_id=claim.pass_id,
            scan_run_id=claim.scan_run_id,
            claim_epoch=claim.claim_epoch,
            deadline_seconds=self._settings.pass_deadline_seconds,
        )

        if result.stopped:
            return await self._abandon(
                claim, AbandonReason.OPERATOR_STOP, "stopped by an operator", caller
            )

        # 6. Publish.
        return await self._publish(
            claim,
            verified=verified,
            pins=pins,
            plan=plan,
            result=result,
            caller=caller,
            supersedes=supersedes,
            supersession_reason=supersession_reason,
        )

    # -- inputs ----------------------------------------------------------------
    async def _verified_input(self, scan_run_id: str) -> VerifiedInput | Refusal:
        """Load and verify the base report and the optional enrichment context."""
        base_material, enrichment_material = await self._load_materials(scan_run_id)
        if base_material is None:
            return Refusal(
                RefusalReason.EVIDENCE_MISSING,
                "no scan report exists for this scan run",
            )

        outcome = verify_base_report(base_material, self._keys.audit_trust)
        if isinstance(outcome, Refusal):
            return outcome
        base_ref, terminal_state, raw_findings = outcome

        enrichment_ref, priorities, context = verify_enrichment(
            enrichment_material if self._settings.use_enrichment_context else None,
            self._enrichment_trust,
            scan_run_id,
        )
        if (
            context is EnrichmentContext.SUPERSEDED
            and not self._settings.use_superseded_enrichment
        ):
            enrichment_ref, priorities, context = None, {}, EnrichmentContext.ABSENT

        return VerifiedInput(
            base=base_ref,
            findings=findings_from(list(raw_findings)),
            enrichment=enrichment_ref,
            priorities=priorities,
            enrichment_context=context,
            terminal_state=terminal_state,
        )

    async def _load_materials(
        self, scan_run_id: str
    ) -> tuple[BaseReportMaterial | None, EnrichmentMaterial | None]:
        from sqlalchemy import select

        from gryphon.db.models.enrichment import EnrichmentAudit, EnrichmentReport
        from gryphon.db.models.scan_report import OrchestrationAudit, ScanReport

        async with self._database.session() as session:
            report = (
                await session.execute(
                    select(ScanReport)
                    .where(ScanReport.scan_run_id == scan_run_id)
                    .order_by(ScanReport.generated_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            base: BaseReportMaterial | None = None
            if report is not None:
                events = (
                    (
                        await session.execute(
                            select(OrchestrationAudit).where(
                                OrchestrationAudit.scan_run_id == scan_run_id,
                                OrchestrationAudit.event_type == "report_emitted",
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                base = BaseReportMaterial(
                    scan_run_id=scan_run_id,
                    report_id=report.report_id,
                    report_digest=report.report_digest,
                    report_schema_version=report.report_schema_version,
                    body=dict(report.body),
                    events=tuple(_attested_events(events)),
                )

            enrichment_rows = (
                (
                    await session.execute(
                        select(EnrichmentReport)
                        .where(EnrichmentReport.scan_run_id == scan_run_id)
                        .order_by(EnrichmentReport.generated_at.desc())
                    )
                )
                .scalars()
                .all()
            )
            enrichment: EnrichmentMaterial | None = None
            if enrichment_rows:
                newest = enrichment_rows[0]
                e_events = (
                    (
                        await session.execute(
                            select(EnrichmentAudit).where(
                                EnrichmentAudit.scan_run_id == scan_run_id,
                                EnrichmentAudit.event_type == "enrichment_report_emitted",
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                enrichment = EnrichmentMaterial(
                    report_id=newest.report_id,
                    report_digest=newest.report_digest,
                    report_schema_version=newest.report_schema_version,
                    body=dict(newest.body),
                    events=tuple(_attested_events(e_events)),
                    superseded=False,
                )
        return base, enrichment

    # -- pins ------------------------------------------------------------------
    async def _pin(
        self, claim: PassClaim, *, verified: VerifiedInput, welcome: Welcome
    ) -> PinRecord:
        record = PinRecord(
            registry_digest=self._registry.digest,
            extractor_set_digest=welcome.extractor_set_digest,
            estate_digest=self._settings.estate_digest or "unpinned",
            resolver_set_digest=self._settings.resolver_set_digest,
            feature_set_digest=welcome.digest,
            base_report_id=verified.base.report_id,
            base_report_digest=verified.base.report_digest,
            enrichment_report_id=(
                verified.enrichment.report_id if verified.enrichment else None
            ),
            enrichment_report_digest=(
                verified.enrichment.report_digest if verified.enrichment else None
            ),
            manifest={
                "finding_count": len(verified.findings),
                "enrichment_context": verified.enrichment_context.value,
            },
        )
        async with self._database.session() as session:
            repo = VerificationRepository(session)
            written = await repo.write_pins_once(claim, record)
            await session.commit()
            if written:
                return record
            # Already pinned: the pass is being resumed, and what it pinned is
            # what it must keep using. A second pass over different inputs under
            # the same pass id would publish one conclusion over two estates.
            existing = await repo.read_pins(claim.pass_id)
        if existing is None:  # pragma: no cover - write said no, read says gone
            raise VerificationConfigurationError(
                f"pass {claim.pass_id} reports pinned inputs that cannot be read back"
            )
        return PinRecord(
            registry_digest=existing.registry_digest,
            extractor_set_digest=existing.extractor_set_digest,
            estate_digest=existing.estate_digest,
            resolver_set_digest=existing.resolver_set_digest,
            feature_set_digest=existing.feature_set_digest,
            base_report_id=existing.base_report_id,
            base_report_digest=existing.base_report_digest,
            enrichment_report_id=existing.enrichment_report_id,
            enrichment_report_digest=existing.enrichment_report_digest,
            manifest=dict(existing.manifest or {}),
        )

    async def _salt(self, pass_id: str) -> bytes:
        async with self._database.session() as session:
            salt = await VerificationRepository(session).pass_salt(pass_id)
        if salt is None:  # pragma: no cover - the row is created with its salt
            raise VerificationConfigurationError(f"pass {pass_id} has no salt")
        return salt

    # -- plan ------------------------------------------------------------------
    def _plan(
        self,
        verified: VerifiedInput,
        *,
        welcome: Welcome,
        pass_id: str,
        salt: bytes,
        only: str | Sequence[str] | None,
    ) -> Plan:
        planner = ObservationPlanner(
            registry=self._registry,
            descriptor_versions=dict(welcome.descriptor_versions),
            extractor_set_digest=welcome.extractor_set_digest,
            resolver_set_digest=self._settings.resolver_set_digest,
        )
        findings = verified.findings
        if isinstance(only, tuple | list):
            wanted = set(only)
            findings = tuple(f for f in findings if f.finding_id in wanted)
        return planner.plan(
            findings,
            pass_salt=salt,
            pass_id=pass_id,
            priorities=verified.priorities or None,
        )

    # -- terminal states -------------------------------------------------------
    async def _mark_running(self, claim: PassClaim) -> None:
        async with self._database.session() as session:
            repo = VerificationRepository(session)
            await repo.transition(claim, {PassState.PLANNED, PassState.BLOCKED}, PassState.RUNNING)
            await session.commit()

    async def _refuse(self, claim: PassClaim, refusal: Refusal, caller: Any) -> PassResult:
        async with self._database.session() as session:
            repo = VerificationRepository(session)
            await repo.transition(
                claim,
                {PassState.PLANNED, PassState.RUNNING, PassState.BLOCKED},
                PassState.REFUSED,
                reason=refusal.reason.value,
                detail=refusal.detail,
            )
            event = self._audit.pass_refused(
                scan_run_id=claim.scan_run_id,
                pass_id=claim.pass_id,
                reason=refusal.reason.value,
                detail=refusal.detail,
                at=await repo.db_now(),
            )
            repo.add_event(_event_values(event))
            await session.commit()
        return PassResult(
            pass_id=claim.pass_id,
            scan_run_id=claim.scan_run_id,
            state=PassState.REFUSED,
            reason=refusal.reason.value,
            detail=refusal.detail,
        )

    async def _block(
        self, claim: PassClaim, reason: BlockedReason, detail: str, caller: Any
    ) -> PassResult:
        """Wait, rather than publish our own outage as the client's ambiguity."""
        async with self._database.session() as session:
            repo = VerificationRepository(session)
            await repo.transition(
                claim,
                # BLOCKED is included: a pass resuming from BLOCKED into a
                # dependency that is still down must be able to record *this*
                # attempt's reason. Omitting it would leave the row describing
                # the first outage while the signed event described the latest,
                # and a reader would have no way to tell which was current.
                {PassState.PLANNED, PassState.RUNNING, PassState.BLOCKED},
                PassState.BLOCKED,
                reason=reason.value,
                detail=detail,
            )
            event = self._audit.pass_blocked(
                scan_run_id=claim.scan_run_id,
                pass_id=claim.pass_id,
                dependency=reason.value,
                at=await repo.db_now(),
            )
            repo.add_event(_event_values(event))
            await session.commit()
        return PassResult(
            pass_id=claim.pass_id,
            scan_run_id=claim.scan_run_id,
            state=PassState.BLOCKED,
            reason=reason.value,
            detail=detail,
        )

    async def _abandon(
        self, claim: PassClaim, reason: AbandonReason, detail: str, caller: Any
    ) -> PassResult:
        async with self._database.session() as session:
            repo = VerificationRepository(session)
            await repo.transition(
                claim,
                {PassState.PLANNED, PassState.RUNNING, PassState.BLOCKED},
                PassState.ABANDONED,
                reason=reason.value,
                detail=detail,
            )
            event = self._audit.pass_abandoned(
                scan_run_id=claim.scan_run_id,
                pass_id=claim.pass_id,
                reason=reason.value,
                detail=detail,
                at=await repo.db_now(),
            )
            repo.add_event(_event_values(event))
            await session.commit()
        return PassResult(
            pass_id=claim.pass_id,
            scan_run_id=claim.scan_run_id,
            state=PassState.ABANDONED,
            reason=reason.value,
            detail=detail,
        )

    # -- publication -----------------------------------------------------------
    async def _publish(
        self,
        claim: PassClaim,
        *,
        verified: VerifiedInput,
        pins: PinRecord,
        plan: Plan,
        result: CampaignResult,
        caller: Any,
        supersedes: str | None,
        supersession_reason: str | None,
    ) -> PassResult:
        records = list(result.records)
        outcome = outcome_for(records, degraded=result.degraded)
        ordering = (
            OrderingBasis.ENRICHMENT_PRIORITY
            if verified.priorities
            else OrderingBasis.OBSERVED_SEVERITY
        )
        unsupported = sorted(
            {
                r.verdict.verifier_id or "unregistered"
                for r in records
                if r.verdict.status is VerdictStatus.UNSUPPORTED
            }
        )
        limitations = declared_limitations(
            enrichment_context=verified.enrichment_context,
            ordering_basis=ordering,
            degraded_hosts=result.paused_hosts,
            blocked_seconds=result.blocked_seconds,
            unsupported_classes=unsupported,
        )

        async with self._database.session() as session:
            repo = VerificationRepository(session)
            generated_at = await repo.db_now()

            body = build_report_body(
                scan_run_id=claim.scan_run_id,
                pass_id=claim.pass_id,
                records=records,
                base=verified.base,
                enrichment=verified.enrichment,
                enrichment_context=verified.enrichment_context,
                ordering_basis=ordering,
                manifest=dict(pins.manifest),
                outcome=outcome,
                scope=supersession_reason,
                generated_at=generated_at,
                limitations=limitations,
            )
            published = publish(scan_run_id=claim.scan_run_id, body=body)

            verifier_versions = {
                r.verdict.verifier_id: self._registry.digest
                for r in records
                if r.verdict.verifier_id
            }
            event = self._audit.report_emitted(
                scan_run_id=claim.scan_run_id,
                pass_id=claim.pass_id,
                report_id=published.report_id,
                report_digest=published.report_digest,
                verdict_set_digest=verdict_set_digest(records),
                manifest_digest=manifest_digest(pins.manifest),
                base_report_digest=verified.base.report_digest,
                enrichment_report_digest=(
                    verified.enrichment.report_digest if verified.enrichment else None
                ),
                verifier_versions=verifier_versions,
                ordering_basis=ordering.value,
                at=generated_at,
            )

            await repo.insert_report(
                {
                    "report_id": published.report_id,
                    "pass_id": claim.pass_id,
                    "scan_run_id": claim.scan_run_id,
                    "body": published.body,
                    "digest": published.report_digest,
                    "schema_version": REPORT_SCHEMA_VERSION,
                    "base_report_id": verified.base.report_id,
                    "base_report_digest": verified.base.report_digest,
                    "enrichment_report_id": (
                        verified.enrichment.report_id if verified.enrichment else None
                    ),
                    "enrichment_report_digest": (
                        verified.enrichment.report_digest if verified.enrichment else None
                    ),
                    "verifier_versions": verifier_versions,
                    "ordering_basis": ordering.value,
                }
            )
            repo.add_event(_event_values(event))

            moved = await repo.transition(
                claim,
                {PassState.RUNNING, PassState.PLANNED},
                PassState.COMPLETE,
                outcome=outcome.value,
            )
            if not moved:
                # Fenced between the last write and this one. Roll the whole
                # publication back: another process owns this pass now, and two
                # reports for one pass is the one outcome the unique key on
                # ``pass_id`` exists to make impossible.
                await session.rollback()
                return PassResult(
                    pass_id=claim.pass_id,
                    scan_run_id=claim.scan_run_id,
                    state=PassState.BLOCKED,
                    reason=BlockedReason.DATABASE_UNAVAILABLE.value,
                    detail="the pass was claimed by another process before publication",
                )
            await session.commit()

        counts: dict[str, int] = {}
        for record in records:
            key = record.verdict.status.value
            counts[key] = counts.get(key, 0) + 1

        logger.info(
            "verification_pass_complete",
            pass_id=claim.pass_id,
            report_id=published.report_id,
            outcome=outcome.value,
            observations=result.observations,
            supersedes=supersedes,
        )
        return PassResult(
            pass_id=claim.pass_id,
            scan_run_id=claim.scan_run_id,
            state=PassState.COMPLETE,
            outcome=outcome,
            report_id=published.report_id,
            findings_planned=len(plan.findings),
            observations=result.observations,
            verdicts=len(records),
            resumed=claim.resumed,
            adopted=claim.adopted,
            degraded=result.degraded,
            paused_hosts=result.paused_hosts,
            counts=counts,
        )


# =============================================================================
# Helpers
# =============================================================================


def row_verdict(record: ReportVerdict, *, registry_digest: str) -> RowVerdict:
    """Carry the engine's verdict into the flat shape a row needs.

    The two types are not redundant. The engine's holds the evaluator's verdict
    whole because the report is rendered from it; the row's is flat because a
    column is not a nested document. Written out here, in the one module that
    knows both, rather than as a constructor on either — which would make each
    side depend on the other's reason for existing.
    """
    return RowVerdict.from_verdict(
        record.verdict,
        finding_id=record.finding_id,
        subject_key=record.subject_key,
        registry_digest=registry_digest,
    )


def reconstructed_observation(row: Any) -> Observation | None:
    """Rebuild an observation from its row, or decline to.

    ``None`` for any row that carried evidence: the facts are not in the row,
    only their digest, so rebuilding one would produce an observation that
    claims to have measured nothing. That claim would be read by the evaluator
    as an absence — and an absence is exactly what some verdicts rest on.
    """
    if row.facts_digest is not None:
        return None
    return Observation(
        observation_id=row.observation_id,
        execution_id=row.execution_id,
        role=ObservationRole(row.role),
        control_index=row.control_index,
        outcome=OutcomeClass(row.outcome_class),
        reason_code=row.reason_code,
        facts=None,
        peer_address=row.peer_address,
    )


def _attested_events(rows: Sequence[Any]) -> tuple[AttestedEvent, ...]:
    """Project audit rows into the shape the input verifier checks.

    Only the four fields that participate in the signature check are carried.
    A verifier that could see the rest of the row might come to depend on it,
    and what a signature covers must be exactly what is checked.
    """
    return tuple(
        AttestedEvent(
            payload=dict(row.payload),
            payload_digest=row.payload_digest,
            signer_kid=row.signer_kid,
            signature_b64=row.signature,
        )
        for row in rows
    )


def _event_values(event: Any) -> dict[str, Any]:
    """The audit row for a signed event: the signed payload, unaltered.

    The caller is deliberately *not* a column here. It is recorded on the pass
    row, which is where it is covered by the lifecycle's own append-only
    guarantees; copying it beside a signed payload that does not contain it
    would create a second, unsigned claim about who acted, and a reader finding
    the two disagreeing would have no way to decide which one to believe.
    """
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "event_schema_version": "1",
        "scan_run_id": event.scan_run_id,
        "pass_id": event.pass_id,
        "payload": dict(event.payload),
        "payload_digest": event.payload_digest,
        "signer_kid": event.signer_kid,
        "signature": event.signature_b64,
    }


def build_commands(services: Any, *, gateway_factory: Any | None = None) -> VerificationCommands:
    """Assemble the commands from an already-proved-safe services object.

    Takes the whole services value rather than its parts so that a new custody
    assertion added to the composition root is automatically upstream of every
    command, instead of being something this constructor could be called around.
    """
    return VerificationCommands(
        database=services.database,
        settings=services.settings,
        clock=services.clock,
        registry=services.registry,
        evaluator=services.evaluator,
        audit=services.audit,
        attestation_trust=services.attestation_trust,
        enrichment_trust=services.enrichment_trust,
        gateway_socket=services.gateway_socket,
        keys=build_key_material(services.core),
        gateway_factory=gateway_factory,
    )


__all__ = [
    "CLIENT_NAME",
    "PassResult",
    "ReportVerification",
    "ServedReport",
    "StatusResult",
    "VerificationCommands",
    "build_commands",
    "reconstructed_observation",
    "row_verdict",
]

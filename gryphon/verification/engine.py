"""The verification pass: one fenced, pinned, stoppable unit of traffic.

The engine is the only component here that causes anything to happen in the
world, so almost every rule it enforces is about restraint rather than progress.

* **It asks; it does not act.** Every contact is a request to the gateway
  service, which establishes authority at the moment of contact, pins the
  destination and performs the measurement. This process holds no permit, no
  resolver and no socket to any target — so a defect here cannot become
  unauthorized traffic, only a refused request.
* **A repeated command is not a second pass.** The caller's request key maps to
  exactly one pass, forever. An operator whose terminal died after publication
  gets the original result back; without that, a retry of a command that had
  already succeeded would re-observe every finding, against a client's estate,
  to learn something the system already knew.
* **A resumed pass does not re-contact.** Identities are derived from the pinned
  envelope and the pass salt, so a resumed pass presents the same identity and
  receives the recorded measurement.
* **A dependency of ours is not an answer about them.** When the gateway or the
  database is unavailable the pass blocks and waits. Publishing thousands of
  INCONCLUSIVE verdicts because our own service was down would report our outage
  as the client's ambiguity, and a reader cannot tell those apart afterwards.
* **It stops when told.** The cancellation epoch is checked before every
  dispatch and is not gated on lease ownership, because "stop now" is a safety
  control and waiting for a lease to lapse is not stopping.
* **It notices when it is the problem.** A host that starts answering
  protectively is paused: past that point the controls are measuring our own
  effect, and more requests would only produce more confident nonsense.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from gryphon.clock import Clock
from gryphon.logging_config import get_logger
from gryphon.tooling.observation.envelope import RequestEnvelope
from gryphon.verification.constants import (
    HOST_PROTECTIVE_THRESHOLD,
    PROTECTIVE_STATUS_CODES,
    AbandonReason,
    BlockedReason,
    EnrichmentContext,
    Justification,
    ObservationRole,
    OrderingBasis,
    OutcomeClass,
    PassState,
    VerdictStatus,
)
from gryphon.verification.evaluator import ProofEvaluator, Verdict
from gryphon.verification.identity import request_key_digest
from gryphon.verification.observation import Observation
from gryphon.verification.planner import Plan, PlannedFinding, PlannedObservation
from gryphon.verification.publish import VerdictRecord
from gryphon.verification.reasons import FencedOut, GatewayUnavailable

logger = get_logger(__name__)


# =============================================================================
# Ports
# =============================================================================


class ObservationPort(Protocol):
    """What the engine needs from the gateway. Deliberately narrow."""

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
    ) -> Observation: ...


class PassPort(Protocol):
    """What the engine needs from its own storage."""

    async def record_observation(self, observation: Observation, *, finding_id: str,
                                 verifier_id: str) -> None: ...

    async def record_verdict(self, record: VerdictRecord) -> None: ...

    async def settled_observations(self, pass_id: str) -> Mapping[str, Observation]: ...

    async def possibly_applied_subjects(self, scan_run_id: str) -> set[str]: ...

    async def cancellation_epoch(self, pass_id: str) -> int: ...


# =============================================================================
# Budget
# =============================================================================


@dataclass(slots=True)
class Budget:
    """What a pass may spend. Exhaustion is reported, never hidden."""

    max_findings: int
    max_observations: int
    concurrency: int
    deadline_seconds: float
    controls_per_host: int

    observations_used: int = 0
    findings_used: int = 0

    def may_observe(self, count: int) -> bool:
        return (
            self.observations_used + count <= self.max_observations
            and self.findings_used < self.max_findings
        )

    def spend(self, count: int) -> None:
        self.observations_used += count
        self.findings_used += 1


@dataclass(slots=True)
class HostHealth:
    """Per-host protective-response tracking.

    Controls are requests. Tripling request volume with deliberate requests for
    things that do not exist is exactly the pattern that trips rate limiters, and
    a pass that pushed through it would be measuring its own footprint.
    """

    protective_hits: dict[str, int] = field(default_factory=dict)
    paused: set[str] = field(default_factory=set)

    def observe(self, host: str, observation: Observation) -> None:
        http = observation.facts.http if observation.facts else None
        protective = (
            observation.outcome is OutcomeClass.REFUSED_CAPACITY
            or (http is not None and http.status_code in PROTECTIVE_STATUS_CODES)
        )
        if protective:
            hits = self.protective_hits.get(host, 0) + 1
            self.protective_hits[host] = hits
            if hits >= HOST_PROTECTIVE_THRESHOLD:
                self.paused.add(host)
                logger.warning("verification_host_paused", host_digest=request_key_digest(host))
        else:
            self.protective_hits[host] = 0

    def is_paused(self, host: str) -> bool:
        return host in self.paused


# =============================================================================
# Result
# =============================================================================


@dataclass(frozen=True, slots=True)
class CampaignResult:
    """What one traffic-bearing campaign produced."""

    records: tuple[VerdictRecord, ...]
    observations: int
    degraded: bool
    paused_hosts: tuple[str, ...]
    blocked_seconds: float
    stopped: bool


# =============================================================================
# Campaign
# =============================================================================


class VerificationCampaign:
    """Runs the traffic-bearing half of a pass.

    Kept separate from derivation (evaluation is pure; chains and advisory
    triage, when they exist, are their own units keyed by digest) so that a
    model provider's outage can never extend a lease that holds the right to
    send packets, and so that re-deriving costs no traffic.
    """

    def __init__(
        self,
        *,
        gateway: ObservationPort,
        store: PassPort,
        evaluator: ProofEvaluator,
        clock: Clock,
        budget: Budget,
        lease_check: Any,
    ) -> None:
        self._gateway = gateway
        self._store = store
        self._evaluator = evaluator
        self._clock = clock
        self._budget = budget
        self._lease = lease_check
        self._health = HostHealth()

    async def run(
        self,
        plan: Plan,
        *,
        pass_id: str,
        scan_run_id: str,
        claim_epoch: int,
        deadline_seconds: float,
    ) -> CampaignResult:
        """Observe what the plan asks for, within budget, and judge it."""
        settled = await self._store.settled_observations(pass_id)
        applied_subjects = await self._store.possibly_applied_subjects(scan_run_id)
        cancellation = await self._store.cancellation_epoch(pass_id)

        records: list[VerdictRecord] = []
        blocked_seconds = 0.0
        degraded = False
        stopped = False
        started = self._clock.monotonic()
        semaphore = asyncio.Semaphore(max(1, self._budget.concurrency))

        for planned in plan.findings:
            # The lease is re-asserted before each finding, not merely before
            # each write: a fenced process should stop asking, even though the
            # gateway would refuse it anyway.
            self._lease.ensure_held()

            if self._clock.monotonic() - started > deadline_seconds:
                records.extend(self._unobserved(plan, records, Justification.BUDGET_EXHAUSTED))
                break

            current_cancellation = await self._store.cancellation_epoch(pass_id)
            if current_cancellation != cancellation:
                stopped = True
                break

            record, blocked, was_degraded = await self._verify_one(
                planned,
                pass_id=pass_id,
                scan_run_id=scan_run_id,
                claim_epoch=claim_epoch,
                cancellation_epoch=current_cancellation,
                settled=settled,
                applied_subjects=applied_subjects,
                semaphore=semaphore,
            )
            blocked_seconds += blocked
            degraded = degraded or was_degraded
            if record is not None:
                records.append(record)
                await self._store.record_verdict(record)

        return CampaignResult(
            records=tuple(records),
            observations=self._budget.observations_used,
            degraded=degraded or bool(self._health.paused),
            paused_hosts=tuple(sorted(self._health.paused)),
            blocked_seconds=blocked_seconds,
            stopped=stopped,
        )

    # -- one finding ----------------------------------------------------------
    async def _verify_one(
        self,
        planned: PlannedFinding,
        *,
        pass_id: str,
        scan_run_id: str,
        claim_epoch: int,
        cancellation_epoch: int,
        settled: Mapping[str, Observation],
        applied_subjects: set[str],
        semaphore: asyncio.Semaphore,
    ) -> tuple[VerdictRecord | None, float, bool]:
        now = self._clock.now()

        # The registry declined: say why, and spend nothing.
        if planned.spec is None or planned.primary is None:
            unsupported = planned.unsupported
            verdict = self._evaluator.evaluate(
                None,
                None,
                unsupported=unsupported.justification if unsupported else None,
            )
            return self._record(planned, verdict, now), 0.0, False

        host = planned.primary.envelope.host
        if self._health.is_paused(host):
            return (
                self._record(
                    planned,
                    _inconclusive(Justification.HOST_PROTECTIVE_RESPONSE, planned),
                    now,
                ),
                0.0,
                True,
            )

        needed = len(planned.observations)
        if not self._budget.may_observe(needed):
            return (
                self._record(planned, _inconclusive(Justification.BUDGET_EXHAUSTED, planned), now),
                0.0,
                False,
            )

        # The replay gate precedes any request: a subject whose earlier contact
        # may have been applied is not re-observed on our own initiative.
        subject_applied = planned.subject_key in applied_subjects

        blocked_seconds = 0.0
        try:
            observations = await self._observe_all(
                planned,
                pass_id=pass_id,
                scan_run_id=scan_run_id,
                claim_epoch=claim_epoch,
                cancellation_epoch=cancellation_epoch,
                settled=settled,
                semaphore=semaphore,
                skip=subject_applied and not planned.spec.repeat_safe,
            )
        except GatewayUnavailable:
            # Not a verdict. The caller suspends the pass and resumes; a finding
            # we never looked at carries no claim at all.
            raise

        self._budget.spend(needed)
        for observation in observations.values():
            self._health.observe(host, observation)

        primary = observations.get(planned.primary.observation_id)
        controls = tuple(
            observations[c.observation_id]
            for c in planned.controls
            if c.observation_id in observations
        )

        verdict = self._evaluator.evaluate(
            planned.spec,
            primary,
            controls,
            subject_possibly_applied=subject_applied,
        )
        degraded = verdict.status is VerdictStatus.INCONCLUSIVE and verdict.justification in (
            Justification.DEPENDENCY_UNAVAILABLE,
            Justification.HOST_PROTECTIVE_RESPONSE,
        )
        return self._record(planned, verdict, now), blocked_seconds, degraded

    async def _observe_all(
        self,
        planned: PlannedFinding,
        *,
        pass_id: str,
        scan_run_id: str,
        claim_epoch: int,
        cancellation_epoch: int,
        settled: Mapping[str, Observation],
        semaphore: asyncio.Semaphore,
        skip: bool,
    ) -> dict[str, Observation]:
        """Observe the primary and its controls, reusing anything already settled."""
        if skip:
            return {}

        async def one(target: PlannedObservation) -> tuple[str, Observation]:
            previous = settled.get(target.observation_id)
            if previous is not None:
                # Resume: this identity already has a recorded outcome, so the
                # target is not contacted again.
                return target.observation_id, previous
            async with semaphore:
                observation = await self._gateway.observe(
                    execution_id=target.execution_id,
                    envelope=target.envelope,
                    pass_id=pass_id,
                    claim_epoch=claim_epoch,
                    cancellation_epoch=cancellation_epoch,
                    deadline_seconds=self._budget.deadline_seconds,
                    scan_run_id=scan_run_id,
                    finding_id=target.finding_id,
                    role=target.role,
                    control_index=target.control_index,
                )
            await self._store.record_observation(
                observation, finding_id=target.finding_id, verifier_id=target.verifier_id
            )
            return target.observation_id, observation

        results = await asyncio.gather(*(one(t) for t in planned.observations))
        return dict(results)

    # -- helpers --------------------------------------------------------------
    def _record(
        self, planned: PlannedFinding, verdict: Verdict, now: datetime
    ) -> VerdictRecord:
        return VerdictRecord(
            finding_id=planned.finding.finding_id,
            subject_key=planned.subject_key,
            verdict=verdict,
            observed_at=now,
            canonical_target=planned.finding.canonical_target,
            url=planned.finding.url,
        )

    def _unobserved(
        self,
        plan: Plan,
        done: Sequence[VerdictRecord],
        justification: Justification,
    ) -> list[VerdictRecord]:
        """Findings the budget or deadline never reached.

        They get a verdict with an honest reason rather than silence: a finding
        absent from the report reads as one that was never produced.
        """
        seen = {r.finding_id for r in done}
        now = self._clock.now()
        return [
            self._record(planned, _inconclusive(justification, planned), now)
            for planned in plan.findings
            if planned.finding.finding_id not in seen
        ]


def _inconclusive(justification: Justification, planned: PlannedFinding) -> Verdict:
    return Verdict(
        status=VerdictStatus.INCONCLUSIVE,
        justification=justification,
        verifier_id=planned.spec.verifier_id if planned.spec else None,
        rule=2,
    )


# =============================================================================
# Blocked-state helper
# =============================================================================


@dataclass(slots=True)
class BlockRecorder:
    """Tracks how long a pass waited on a dependency of ours.

    Surfaced in the report because a reader otherwise cannot tell an estate that
    was hard to measure from a platform that was unavailable, and only one of
    those is a statement about the client.
    """

    clock: Clock
    total_seconds: float = 0.0
    reason: BlockedReason | None = None
    _since: float | None = None

    def enter(self, reason: BlockedReason) -> None:
        if self._since is None:
            self._since = self.clock.monotonic()
            self.reason = reason

    def leave(self) -> None:
        if self._since is not None:
            self.total_seconds += self.clock.monotonic() - self._since
            self._since = None
            self.reason = None


__all__ = [
    "AbandonReason",
    "BlockRecorder",
    "Budget",
    "CampaignResult",
    "EnrichmentContext",
    "FencedOut",
    "HostHealth",
    "ObservationPort",
    "OrderingBasis",
    "PassPort",
    "PassState",
    "VerificationCampaign",
]

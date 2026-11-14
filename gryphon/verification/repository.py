"""Database access for the verification layer.

Every write here is one of four shapes, and nothing else:

* a **keyed write** — look for the identity, insert it if absent, then read it
  back and compare. A retried write is a no-op; a *different* write under the
  same identity is an :class:`IdentityConflictError`, never a silent
  keep-first;
* a **compare-and-set** on the pass row, fenced by ``claim_epoch`` and
  evaluated against the **database clock**;
* a **write-once insert** for the pin manifest, whose second attempt is a
  returned ``False`` rather than an exception, because a resumed pass finding
  its own manifest and a re-planned pass finding someone else's are different
  events and only the caller can tell them apart;
* an **append** of a retraction, a report or a signed event.

There are no deletes and no updates of append-only rows.

Three rules shape every statement below.

**The clock is the database's.** Lease expiry, lease liveness and every
``*_at`` column are computed inside the statement from ``func.now()`` or left to
a server default. A deadline built in this process would be compared against a
different clock by the next holder, and two hosts that disagree about who owns a
pass are two hosts that both put packets on someone else's estate.
:meth:`VerificationRepository.transition` therefore refuses a Python
``datetime`` outright rather than writing a wall-clock reading that looks
plausible in a row and is wrong by whatever the skew happens to be.

**A refusal is a value.** ``Busy``, ``KeyConflict`` and a ``False`` from a
compare-and-set are returned, not raised: each has a legitimate reading that
only the caller can choose between. Exceptions are reserved for the one
condition that must stop the process — two writers disagreeing about a single
identity.

**Keyed inserts are not ``ON CONFLICT`` here.** ``verification_observation`` and
``finding_verification`` are range-partitioned, so their primary keys contain a
server-generated partition column. A retry would therefore arrive with a
*different* ``settled_at`` and collide with nothing, which is exactly the case
``ON CONFLICT`` cannot see. Those two tables are written by read-insert-compare
under the pass's lease instead, and a second row for one identity is reported as
the integrity failure it is rather than quietly becoming two verdicts.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Final

from sqlalchemy import and_, func, literal, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.db.models.verification import (
    FindingVerification,
    VerificationAudit,
    VerificationObservation,
    VerificationPass,
    VerificationPassPin,
    VerificationReport,
    VerificationRetraction,
)
from gryphon.passkernel.ports import LeaseState
from gryphon.verification.constants import (
    EVIDENCE_OUTCOMES,
    OPEN_PASS_STATES,
    TERMINAL_PASS_STATES,
    AssertedBy,
    Justification,
    ObservationRole,
    OutcomeClass,
    PassState,
    VerdictStatus,
)
from gryphon.verification.evaluator import Verdict
from gryphon.verification.identity import new_pass_id, new_pass_salt
from gryphon.verification.observation import NotDispatched, Observation
from gryphon.verification.reasons import (
    IdentityConflictError,
    VerificationConfigurationError,
)

#: Digest domain for the bound request behind a request key. A fresh label:
#: reusing one of the identity module's domains would make two unrelated
#: derivations collide-able by construction.
_SCOPE_DOMAIN: Final[bytes] = b"gryphon/verification/request-scope/v1"

#: Digest domain for the pinned input set.
_PINS_DOMAIN: Final[bytes] = b"gryphon/verification/pins/v1"

#: The first epoch of a freshly inserted pass. Zero is reserved for "never
#: claimed", so a fencing comparison can tell an unclaimed row from a claimed
#: one without a second nullable column.
_FIRST_EPOCH: Final[int] = 1

#: Observation fields whose stored value must equal what the caller meant to
#: store. A differing read-back under one ``observation_id`` means two writers
#: disagree about one contact, which no retry can resolve.
_COMPARED_OBSERVATION_FIELDS: Final[tuple[str, ...]] = (
    "pass_id",
    "finding_id",
    "verifier_id",
    "execution_id",
    "envelope_digest",
    "role",
    "control_index",
    "outcome_class",
    "reason_code",
    "possibly_applied",
    "completeness",
    "facts_digest",
)

#: Verdict fields compared on read-back. The projection is compared by digest
#: rather than by value: the digest is what the report cites, so two
#: projections that digest alike are the same evidence by the definition the
#: deliverable already uses.
_COMPARED_VERDICT_FIELDS: Final[tuple[str, ...]] = (
    "subject_key",
    "status",
    "justification",
    "verifier_id",
    "registry_digest",
    "asserted_by",
    "rule",
    "projection_digest",
)


# =============================================================================
# Typed outcomes of a claim
# =============================================================================


def scope_digest(scope: Mapping[str, Any] | None) -> str:
    """Identify the request a key was used for, over its canonical form.

    A re-serialized command is the same command, so the comparison cannot be
    textual. The digest is what a refusal message and a log line carry: the
    scope itself may name internal hosts and paths, and a bounded digest answers
    "is this the same command?" without putting a second copy of the
    engagement's addresses somewhere nobody audits.
    """
    return sha256_hex(_SCOPE_DOMAIN + canonical_json_bytes(dict(scope or {})))


@dataclass(frozen=True, slots=True)
class PassRef:
    """What a request key resolves to: one pass, permanently.

    Carries the bound scope so a caller can say *why* a reused key was refused
    without re-reading the row.
    """

    pass_id: str
    scan_run_id: str
    request_key: str | None
    state: PassState
    claim_epoch: int
    scope: dict[str, Any] | None

    @property
    def is_open(self) -> bool:
        return self.state in OPEN_PASS_STATES

    @property
    def scope_digest(self) -> str:
        return scope_digest(self.scope)


@dataclass(frozen=True, slots=True)
class PassClaim:
    """The pass this process may act on, and on what terms.

    ``owned`` is the field that matters. A repeated command whose pass already
    reached a terminal state resolves to that pass — that is the whole point of
    the request key — but this process is *not* its owner and must publish
    nothing: it returns the original deliverable instead. Collapsing "here is
    your pass" and "you may write to it" into one value is how a second runner
    would re-publish a finished engagement.
    """

    pass_id: str
    scan_run_id: str
    state: PassState
    claim_epoch: int
    cancellation_epoch: int
    holder: str | None
    adoption_count: int
    #: Whether this process holds the lease and may write as the owner.
    owned: bool
    #: Whether the pass row already existed when this claim was made.
    resumed: bool
    #: Whether this claim took the pass over from a holder whose lease lapsed.
    adopted: bool


@dataclass(frozen=True, slots=True)
class Busy:
    """An open pass owns this scan and its lease is still live.

    Reported rather than raised because waiting is a legitimate response and so
    is giving up; the caller turns this into ``PassBusy`` when it has decided
    which.
    """

    scan_run_id: str
    pass_id: str
    holder: str | None
    lease_expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class KeyConflict:
    """The same request key was presented with a different request.

    A repeated command is safe and returns its original pass. A *changed*
    command under a reused key is ambiguous — the caller may believe either
    request ran — so it is refused rather than guessed at.
    """

    request_key: str
    pass_id: str
    stored_digest: str
    presented_digest: str
    detail: str


# =============================================================================
# Persisted records
# =============================================================================


@dataclass(frozen=True, slots=True)
class PinRecord:
    """The pinned inputs of one pass, written once and never moved.

    ``pins`` is derived from the columns rather than supplied beside them. Two
    copies of one provenance root can disagree, and a reader that found them
    disagreeing would have to decide which copy the published work actually
    rested on — a question with no answer. One value, projected two ways.
    """

    registry_digest: str
    extractor_set_digest: str
    estate_digest: str
    resolver_set_digest: str
    feature_set_digest: str
    base_report_id: str
    base_report_digest: str
    enrichment_report_id: str | None = None
    enrichment_report_digest: str | None = None
    #: The plan this pass will execute: counts, ordering and per-finding
    #: identities. Distinct from the pins, which are what the plan was derived
    #: *from*.
    manifest: dict[str, Any] = field(default_factory=dict)

    @property
    def pins(self) -> dict[str, Any]:
        """Every pinned input as one canonical value."""
        return {
            "registry_digest": self.registry_digest,
            "extractor_set_digest": self.extractor_set_digest,
            "estate_digest": self.estate_digest,
            "resolver_set_digest": self.resolver_set_digest,
            "feature_set_digest": self.feature_set_digest,
            "base_report_id": self.base_report_id,
            "base_report_digest": self.base_report_digest,
            "enrichment_report_id": self.enrichment_report_id,
            "enrichment_report_digest": self.enrichment_report_digest,
        }

    @property
    def digest(self) -> str:
        """Identity of the pinned set, for a log line or a resume comparison."""
        return sha256_hex(_PINS_DOMAIN + canonical_json_bytes(self.pins))

    def as_payload(self) -> dict[str, Any]:
        return {**self.pins, "pins": self.pins, "manifest": dict(self.manifest)}


def facts_digest_for(observation: Observation) -> str | None:
    """Digest of the typed facts an observation carried, or ``None``.

    The facts themselves stay with the gateway. What a verdict needs is proof
    that the document it was evaluated against is the document still on record,
    and a digest is that proof without this layer holding a second copy of
    target-derived content.
    """
    if observation.facts is None:
        return None
    return sha256_hex(canonical_json_bytes(observation.facts.as_payload()))


@dataclass(frozen=True, slots=True)
class ObservationRecord:
    """One observation as it is persisted: identity, outcome, completeness.

    Completeness travels as its own value rather than being folded into the
    outcome, because the question a later reader asks is not "did it work" but
    "may a negative claim rest on this?" — and only transport and body
    completeness answer that.

    There is no row before the contact. The table is append-only, so a
    pre-dispatch row could never be completed with its outcome; an identity
    with no row is the normal pre-dispatch state, which is what lets a resumed
    pass tell "not yet asked" from "asked and lost".
    """

    observation_id: str
    finding_id: str
    verifier_id: str
    execution_id: str
    envelope_digest: str
    role: ObservationRole
    control_index: int
    outcome_class: OutcomeClass
    reason_code: str
    possibly_applied: bool
    completeness: dict[str, Any]
    facts_digest: str | None = None
    peer_address: str | None = None

    def __post_init__(self) -> None:
        if self.outcome_class in EVIDENCE_OUTCOMES and self.facts_digest is None:
            raise ValueError(f"{self.outcome_class.value} requires a facts digest")

    def as_payload(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "finding_id": self.finding_id,
            "verifier_id": self.verifier_id,
            "execution_id": self.execution_id,
            "envelope_digest": self.envelope_digest,
            "role": self.role.value,
            "control_index": self.control_index,
            "outcome_class": self.outcome_class.value,
            "reason_code": self.reason_code,
            "possibly_applied": self.possibly_applied,
            "completeness": dict(self.completeness),
            "facts_digest": self.facts_digest,
            "peer_address": self.peer_address,
        }

    @classmethod
    def settled(
        cls,
        observation: Observation,
        *,
        finding_id: str,
        verifier_id: str,
        envelope_digest: str,
    ) -> ObservationRecord:
        """Build the row for an observation the gateway carried out.

        ``possibly_applied`` is taken from the outcome class rather than from a
        caller's flag. A transport failure is not a rollback, and the one place
        that decides whether the target may have processed the request should be
        the closed table in ``constants``, not each call site.
        """
        return cls(
            observation_id=observation.observation_id,
            finding_id=finding_id,
            verifier_id=verifier_id,
            execution_id=observation.execution_id,
            envelope_digest=envelope_digest,
            role=observation.role,
            control_index=observation.control_index,
            outcome_class=observation.outcome,
            reason_code=observation.reason_code,
            possibly_applied=observation.possibly_applied,
            completeness=observation.completeness.as_payload(),
            facts_digest=facts_digest_for(observation),
            peer_address=observation.peer_address,
        )

    @classmethod
    def refused(
        cls,
        refusal: NotDispatched,
        *,
        finding_id: str,
        verifier_id: str,
        envelope_digest: str,
    ) -> ObservationRecord:
        """Build the row for a planned observation that never reached the wire.

        Zero traffic occurred, so the subject carries no possibly-applied fact.
        That is the whole difference between this row and a dispatched-then-
        failed one, and it is the difference that decides whether a later pass
        may look again.
        """
        return cls(
            observation_id=refusal.observation_id,
            finding_id=finding_id,
            verifier_id=verifier_id,
            execution_id=refusal.execution_id,
            envelope_digest=envelope_digest,
            role=refusal.role,
            control_index=refusal.control_index,
            outcome_class=refusal.outcome,
            reason_code=refusal.reason_code,
            possibly_applied=False,
            completeness=refusal.to_observation().completeness.as_payload(),
        )


@dataclass(frozen=True, slots=True)
class VerdictRecord:
    """One finding's verdict as it is persisted.

    ``asserted_by`` is fixed rather than parameterized. Every row this layer
    writes is a deterministic verifier's claim; a model's label and a human's
    disposition occupy their own columns in the read view precisely so that
    neither can ever be mistaken for a proof.

    ``registry_digest`` is required even where no verifier was found, because
    "nothing was registered for this class" is itself a statement about a
    particular registry, and an operator reading UNSUPPORTED next year needs to
    know which one.
    """

    finding_id: str
    subject_key: str
    status: VerdictStatus
    justification: Justification | None
    verifier_id: str | None
    registry_digest: str
    rule: int
    matched_predicates: tuple[str, ...] = ()
    control_summary: dict[str, Any] | None = None
    projection: dict[str, Any] = field(default_factory=dict)
    asserted_by: AssertedBy = AssertedBy.DETERMINISTIC_VERIFIER

    def __post_init__(self) -> None:
        if self.status is VerdictStatus.CONFIRMED and self.justification is not None:
            raise ValueError("CONFIRMED carries no justification")
        if self.status is not VerdictStatus.CONFIRMED and self.justification is None:
            raise ValueError(f"{self.status.value} requires a justification")
        if self.asserted_by is not AssertedBy.DETERMINISTIC_VERIFIER:
            raise ValueError(
                "only a deterministic verifier writes this table; a model label and a "
                "human disposition have their own columns"
            )

    @property
    def projection_digest(self) -> str:
        """Digest of the stored evidence, over its canonical form."""
        return sha256_hex(canonical_json_bytes(self.projection))

    def as_payload(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "subject_key": self.subject_key,
            "status": self.status.value,
            "justification": self.justification.value if self.justification else None,
            "verifier_id": self.verifier_id,
            "registry_digest": self.registry_digest,
            "rule": self.rule,
            "matched_predicates": list(self.matched_predicates),
            "control_summary": self.control_summary,
            "projection": dict(self.projection),
            "projection_digest": self.projection_digest,
            "asserted_by": self.asserted_by.value,
        }

    @classmethod
    def from_verdict(
        cls,
        verdict: Verdict,
        *,
        finding_id: str,
        subject_key: str,
        registry_digest: str,
    ) -> VerdictRecord:
        """Carry the evaluator's pure result into the persisted shape."""
        return cls(
            finding_id=finding_id,
            subject_key=subject_key,
            status=verdict.status,
            justification=verdict.justification,
            verifier_id=verdict.verifier_id,
            registry_digest=registry_digest,
            rule=verdict.rule,
            matched_predicates=verdict.matched_predicates,
            control_summary=(
                verdict.control_summary.as_payload() if verdict.control_summary else None
            ),
            projection=dict(verdict.projection),
        )


# =============================================================================
# Read-back comparison
# =============================================================================


def observation_mismatch(stored: object, record: ObservationRecord) -> tuple[str, ...]:
    """Fields on which the stored observation differs from this record.

    Empty means the retry is a no-op. Non-empty means two writers disagree about
    one contact, and no amount of retrying will make them agree.
    """
    return _mismatch(stored, record.as_payload(), _COMPARED_OBSERVATION_FIELDS)


def verdict_mismatch(stored: object, record: VerdictRecord) -> tuple[str, ...]:
    """Fields on which the stored verdict differs from this record."""
    return _mismatch(stored, record.as_payload(), _COMPARED_VERDICT_FIELDS)


def _mismatch(
    stored: object, payload: Mapping[str, Any], fields: Sequence[str]
) -> tuple[str, ...]:
    return tuple(
        name
        for name in fields
        if name in payload
        and _normalize(getattr(stored, name, None)) != _normalize(payload[name])
    )


def _normalize(value: object) -> object:
    """Compare an enum and its stored text as the same value."""
    return value.value if isinstance(value, Enum) else value


def _scalar(value: Any) -> Any:
    """Store a closed enum as the text the CHECK constraints are written over."""
    return value.value if isinstance(value, Enum) else value


def _reject_process_clock(values: Mapping[str, Any]) -> None:
    """Refuse a timestamp this process read from its own clock.

    Wall-clock-at-construction is the defect this layer is built to avoid: the
    lease, the grant window and the supersession order in the read view are all
    compared against the database's clock, and a column written from a host
    clock is wrong by whatever the skew is on the day someone has to
    reconstruct what happened.
    """
    offenders = sorted(name for name, value in values.items() if isinstance(value, datetime))
    if offenders:
        raise VerificationConfigurationError(
            "timestamps are written by the database clock, never by this process: "
            + ", ".join(offenders)
        )


# =============================================================================
# The repository
# =============================================================================


class VerificationRepository:
    """All SQL for the verification layer, over one :class:`AsyncSession`."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @property
    def session(self) -> AsyncSession:
        return self._session

    async def db_now(self) -> datetime:
        """The database's clock, for a log line or a refusal message.

        Never for building a deadline: a value read here and written back has
        already left the statement that would have kept it consistent.
        """
        return (await self._session.execute(select(func.now()))).scalar_one()

    # -- command idempotency ---------------------------------------------------
    async def resolve_request_key(self, scan_run_id: str, request_key: str) -> PassRef | None:
        """The one pass this key names, or ``None`` if the key is unused.

        The mapping is permanent. A lost response must not re-send traffic, so a
        repeat of the same command has to find its way back to the pass it
        already created rather than starting a second one.
        """
        row = await self._pass_for_key(scan_run_id, request_key)
        if row is None:
            return None
        return PassRef(
            pass_id=row.pass_id,
            scan_run_id=row.scan_run_id,
            request_key=row.request_key,
            state=PassState(row.state),
            claim_epoch=row.claim_epoch,
            scope=row.scope,
        )

    async def claim_pass(
        self,
        scan_run_id: str,
        request_key: str | None,
        *,
        holder: str,
        lease_seconds: float,
        initiated_by: str,
        scope: Mapping[str, Any] | None = None,
    ) -> PassClaim | Busy | KeyConflict:
        """Take ownership of this scan's verification, or say why not.

        Four answers, and each exists because collapsing it into another one
        loses something a caller must act on:

        * the key is unused and the scan is free — a new PLANNED pass;
        * the key is known and names the same request — that pass, resumed,
          adopted when its lease has lapsed and merely returned when it is
          already finished;
        * the key is known and names a *different* request — refused, because
          the caller may believe either request ran;
        * an open pass holds the scan on a live lease — busy, because taking it
          would put two processes on one client's estate.

        A ``None`` key is a caller declining idempotency: it binds nothing, so a
        repeat of that command is a new command. The one-open-pass rule still
        applies, which is what keeps "no key" from meaning "no limit".
        """
        presented = scope_digest(scope)
        if request_key is not None:
            existing = await self._pass_for_key(scan_run_id, request_key)
            if existing is not None:
                stored = scope_digest(existing.scope)
                if stored != presented:
                    return KeyConflict(
                        request_key=request_key,
                        pass_id=existing.pass_id,
                        stored_digest=stored,
                        presented_digest=presented,
                        detail="the request bound to this key has a different scope",
                    )
                return await self._resume(
                    existing, holder=holder, lease_seconds=lease_seconds
                )

        open_row = await self.open_pass_for(scan_run_id)
        if open_row is not None:
            # A pass started under another key still owns the scan. Adopting it
            # rather than refusing is what makes recovery driven by the next
            # start: the alternative is a crashed pass that nobody may continue.
            return await self._resume(open_row, holder=holder, lease_seconds=lease_seconds)

        return await self._insert_pass(
            scan_run_id,
            request_key,
            scope=scope,
            presented=presented,
            holder=holder,
            lease_seconds=lease_seconds,
            initiated_by=initiated_by,
        )

    # -- the lease -------------------------------------------------------------
    async def renew_lease(self, holder: str, epoch: int, lease_seconds: float) -> bool:
        """Extend this holder's lease, computing the new expiry in the database.

        ``False`` is not a failure to retry: it means the pass was claimed by
        someone else, so this process must stop writing *and* stop dispatching.
        The statement row-locks the pass until the caller's transaction commits,
        which is what makes a fenced write safe rather than merely ordered.
        """
        stmt = (
            update(VerificationPass)
            .where(
                VerificationPass.holder == holder,
                VerificationPass.claim_epoch == epoch,
                VerificationPass.state.in_(_state_values(OPEN_PASS_STATES)),
            )
            .values(lease_expires_at=func.now() + timedelta(seconds=lease_seconds))
            .returning(VerificationPass.pass_id)
        )
        return (await self._session.execute(stmt)).first() is not None

    async def release_lease(self, holder: str, epoch: int) -> None:
        """Give the lease up early. A courtesy that shortens the next recovery."""
        await self._session.execute(
            update(VerificationPass)
            .where(
                VerificationPass.holder == holder,
                VerificationPass.claim_epoch == epoch,
                VerificationPass.state.in_(_state_values(OPEN_PASS_STATES)),
            )
            .values(holder=None, lease_expires_at=None)
        )

    async def lease_state(self, pass_id: str) -> LeaseState | None:
        """Report the lease without taking it, for a refusal message or status.

        ``held`` is decided by the database, inside the statement. Recomputing it
        here from an expiry and a local instant would reintroduce exactly the
        skew question the lease exists to answer.
        """
        stmt = select(
            VerificationPass.holder,
            VerificationPass.claim_epoch,
            VerificationPass.lease_expires_at,
            VerificationPass.lease_expires_at > func.now(),
        ).where(VerificationPass.pass_id == pass_id)
        row = (await self._session.execute(stmt)).first()
        if row is None:
            return None
        return LeaseState(
            holder=row[0], claim_epoch=row[1], lease_expires_at=row[2], held=bool(row[3])
        )

    # -- lifecycle -------------------------------------------------------------
    async def transition(
        self,
        claim: PassClaim,
        expected: set[PassState],
        to: PassState,
        **values: Any,
    ) -> bool:
        """Compare-and-set the pass's lifecycle row; ``False`` means fenced out.

        Returned rather than raised because the two callers differ: a publisher
        treats it as a rollback, a sweeper treats it as "someone else got there
        first", and only one of those is an error. A terminal state gets its
        ``completed_at`` from the database unless the caller already named the
        column, so the published time cannot come from a host clock.
        """
        if not expected:
            raise VerificationConfigurationError("a transition needs at least one expected state")
        leaving_terminal = set(expected) & TERMINAL_PASS_STATES
        if leaving_terminal:
            raise VerificationConfigurationError(
                "a terminal state is never left: "
                + ", ".join(sorted(s.value for s in leaving_terminal))
            )
        _reject_process_clock(values)
        payload: dict[str, Any] = {name: _scalar(v) for name, v in values.items()}
        payload["state"] = to.value
        if to in TERMINAL_PASS_STATES and "completed_at" not in payload:
            payload["completed_at"] = func.now()
        stmt = (
            update(VerificationPass)
            .where(
                VerificationPass.pass_id == claim.pass_id,
                VerificationPass.claim_epoch == claim.claim_epoch,
                VerificationPass.state.in_(_state_values(expected)),
            )
            .values(**payload)
            .returning(VerificationPass.pass_id)
        )
        return (await self._session.execute(stmt)).first() is not None

    async def advance_cancellation(self, pass_id: str) -> int | None:
        """Advance the cancellation epoch; returns its new value.

        A stop control has to be enforceable by the component that puts packets
        on the wire, not by the one being stopped. Advancing this counter is what
        the gateway checks, so a pass whose process is wedged still stops
        dispatching within one request.
        """
        stmt = (
            update(VerificationPass)
            .where(
                VerificationPass.pass_id == pass_id,
                VerificationPass.state.in_(_state_values(OPEN_PASS_STATES)),
            )
            .values(cancellation_epoch=VerificationPass.cancellation_epoch + 1)
            .returning(VerificationPass.cancellation_epoch)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    # -- pins (write-once) -----------------------------------------------------
    async def write_pins_once(self, claim: PassClaim, pins: PinRecord) -> bool:
        """Write the pin manifest if this pass has none. ``False`` if it has.

        Write-once is what makes every append-only row of the pass explainable:
        the pins are the provenance root those rows were derived from, so if the
        manifest could move, work already published would no longer be traceable
        to the inputs that produced it. The pin table's primary key *is* that
        guarantee — the insert collides rather than overwriting — so a ``False``
        here means a manifest already exists, not that this writer lost a race
        it should retry.

        The epoch is checked first so a superseded holder does not plant pins for
        a pass it no longer owns. ``False`` covers both readings, which is
        correct: either way this process must stop and compare what is stored
        against what it intended.
        """
        owns = await self._session.execute(
            select(VerificationPass.pass_id).where(
                VerificationPass.pass_id == claim.pass_id,
                VerificationPass.claim_epoch == claim.claim_epoch,
            )
        )
        if owns.first() is None:
            return False
        stmt = (
            pg_insert(VerificationPassPin)
            .values(pass_id=claim.pass_id, **pins.as_payload())
            .on_conflict_do_nothing(index_elements=["pass_id"])
            .returning(VerificationPassPin.pass_id)
        )
        return (await self._session.execute(stmt)).first() is not None

    async def read_pins(self, pass_id: str) -> VerificationPassPin | None:
        """The stored manifest a resumed pass must re-derive from.

        A resumed pass finding its own manifest is the normal path. A re-planned
        pass finding a manifest it did not write is an integrity conflict, which
        only the caller can recognize — so the row is returned rather than
        compared here.
        """
        return await self._session.get(VerificationPassPin, pass_id)

    async def pass_salt(self, pass_id: str) -> bytes | None:
        """The pass's secret salt, read one row at a time and never logged.

        Deliberately not a field on :class:`PassClaim`: a value that appears in a
        dataclass is a value that appears in a repr, and this one must never
        reach a view, a report, a log line or telemetry. It is what makes
        observation identities and control locators unpredictable from outside
        the system, which a host that wanted to look clean would otherwise be
        able to anticipate.
        """
        stmt = select(VerificationPass.salt).where(VerificationPass.pass_id == pass_id)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    # -- observations ----------------------------------------------------------
    async def record_observation(self, claim: PassClaim, record: ObservationRecord) -> None:
        """Record one observation, keyed by ``observation_id``.

        Read, insert if absent, read back and compare. A retry is a no-op; a
        differing row under the same identity is an integrity failure, because
        the only way two writers disagree about one contact is that one of them
        is describing a different contact — and that is a question for a person,
        not a retry loop.
        """
        values = {
            "pass_id": claim.pass_id,
            "scan_run_id": claim.scan_run_id,
            **record.as_payload(),
        }
        stored = await self._observation_row(record.observation_id)
        if stored is None:
            try:
                async with self._session.begin_nested():
                    await self._session.execute(
                        VerificationObservation.__table__.insert().values(**values)
                    )
            except IntegrityError as exc:
                raise IdentityConflictError(
                    f"observation {record.observation_id} could not be recorded: execution "
                    f"{record.execution_id} is already held by another identity"
                ) from exc
            stored = await self._observation_row(record.observation_id)
        if stored is None:
            raise IdentityConflictError(
                f"observation {record.observation_id} vanished between insert and read-back"
            )
        differing = observation_mismatch(stored, record)
        if differing:
            raise IdentityConflictError(
                f"observation {record.observation_id} differs from the stored row on "
                + ", ".join(differing)
            )

    async def observations_for(self, pass_id: str) -> list[VerificationObservation]:
        """Every observation already recorded for this pass, primaries first.

        This is the resume surface: an identity with a row has settled and must
        not be contacted again, and an identity without one is the normal
        pre-dispatch state rather than an integrity failure.
        """
        stmt = (
            select(VerificationObservation)
            .where(VerificationObservation.pass_id == pass_id)
            .order_by(
                VerificationObservation.finding_id,
                VerificationObservation.control_index,
                VerificationObservation.observation_id,
            )
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def possibly_applied_subjects(
        self, scan_run_id: str, *, before_pass_id: str | None = None
    ) -> set[str]:
        """Subjects carrying a possibly-applied fact from an earlier observation.

        This is what makes the replay gate work across passes. A request that
        timed out may have been processed by the target, and a new pass generates
        new identities — so without a durable record keyed on something that
        outlives the scan's findings, the uncertainty would be silently erased
        the moment someone ran verification again.

        The subject identity lives on the verdict, not on the observation, so the
        join is through the verdict that pass wrote for the same finding. A pass
        that recorded an observation and was abandoned before publishing its
        verdicts therefore contributes nothing here;
        :meth:`possibly_applied_findings` exposes those rows so a caller holding
        the findings can derive their subjects itself rather than concluding
        there was no uncertainty.
        """
        stmt = (
            select(FindingVerification.subject_key)
            .join(
                VerificationObservation,
                and_(
                    VerificationObservation.pass_id == FindingVerification.pass_id,
                    VerificationObservation.finding_id == FindingVerification.finding_id,
                ),
            )
            .where(
                FindingVerification.scan_run_id == scan_run_id,
                VerificationObservation.possibly_applied.is_(True),
            )
        )
        if before_pass_id is not None:
            stmt = stmt.where(VerificationObservation.pass_id != before_pass_id)
        return set((await self._session.execute(stmt.distinct())).scalars().all())

    async def possibly_applied_findings(
        self, scan_run_id: str, *, before_pass_id: str | None = None
    ) -> set[str]:
        """Findings whose earlier observation may have been applied.

        The same fact as :meth:`possibly_applied_subjects`, read without the
        verdict join so that a pass abandoned before publication still counts.
        A finding id is unique per scan, so this is usable within one scan only
        — which is why the subject-keyed form exists for everything else.
        """
        stmt = select(VerificationObservation.finding_id).where(
            VerificationObservation.scan_run_id == scan_run_id,
            VerificationObservation.possibly_applied.is_(True),
        )
        if before_pass_id is not None:
            stmt = stmt.where(VerificationObservation.pass_id != before_pass_id)
        return set((await self._session.execute(stmt.distinct())).scalars().all())

    # -- verdicts --------------------------------------------------------------
    async def record_verdict(self, claim: PassClaim, record: VerdictRecord) -> None:
        """Record one verdict, keyed by ``(pass_id, finding_id)``.

        Read, insert if absent, read back and compare — the same discipline as an
        observation, and for the same reason: a verdict is an immutable
        statement, so two writers disagreeing about one is an integrity failure
        rather than a lost update. ``observed_at`` is left to the database, which
        is also the partition key and therefore the one value a resumed writer
        must not try to reproduce.
        """
        values = {
            "pass_id": claim.pass_id,
            "scan_run_id": claim.scan_run_id,
            **record.as_payload(),
        }
        stored = await self._verdict_row(claim.pass_id, record.finding_id)
        if stored is None:
            try:
                async with self._session.begin_nested():
                    await self._session.execute(
                        FindingVerification.__table__.insert().values(**values)
                    )
            except IntegrityError as exc:
                raise IdentityConflictError(
                    f"verdict for {record.finding_id} could not be recorded: {exc.orig}"
                ) from exc
            stored = await self._verdict_row(claim.pass_id, record.finding_id)
        if stored is None:
            raise IdentityConflictError(
                f"verdict for {record.finding_id} vanished between insert and read-back"
            )
        differing = verdict_mismatch(stored, record)
        if differing:
            raise IdentityConflictError(
                f"verdict for {record.finding_id} differs from the stored row on "
                + ", ".join(differing)
            )

    async def record_verdicts(
        self, claim: PassClaim, records: Sequence[VerdictRecord]
    ) -> None:
        """Record a pass's verdicts in a stable order.

        Ordered by finding id so that a crash part-way through leaves the same
        prefix written every time, which is what makes a resumed publication
        comparable with the one it is continuing.
        """
        for record in sorted(records, key=lambda r: r.finding_id):
            await self.record_verdict(claim, record)

    async def verdicts_for(self, pass_id: str) -> list[FindingVerification]:
        stmt = (
            select(FindingVerification)
            .where(FindingVerification.pass_id == pass_id)
            .order_by(FindingVerification.finding_id)
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def record_retraction(self, verifier_id: str, reason: str, approved_by: str) -> int:
        """Retract every verdict a withdrawn verifier produced; return the count.

        A withdrawal never edits a verdict. For a layer that sells proof, "what
        happens to the proofs we already issued when the prover turns out to be
        wrong?" cannot be undefined — so the claim stays exactly as it was
        published and a retraction row says, separately and visibly, that it can
        no longer be relied on.

        The count reported is the total number of retracted verdicts for this
        verifier, not the number of rows this call happened to insert. A
        withdrawal repeated after a lost response must report the same effect
        rather than zero.
        """
        source = select(
            FindingVerification.verifier_id,
            FindingVerification.pass_id,
            FindingVerification.finding_id,
            literal(reason),
            literal(approved_by),
        ).where(FindingVerification.verifier_id == verifier_id)
        await self._session.execute(
            pg_insert(VerificationRetraction)
            .from_select(
                ["verifier_id", "pass_id", "finding_id", "reason", "approved_by"], source
            )
            .on_conflict_do_nothing(
                index_elements=["verifier_id", "pass_id", "finding_id"]
            )
        )
        total = (
            select(func.count())
            .select_from(VerificationRetraction)
            .where(VerificationRetraction.verifier_id == verifier_id)
        )
        return int((await self._session.execute(total)).scalar_one())

    async def retractions_for(self, pass_id: str) -> list[VerificationRetraction]:
        stmt = (
            select(VerificationRetraction)
            .where(VerificationRetraction.pass_id == pass_id)
            .order_by(VerificationRetraction.finding_id)
        )
        return list((await self._session.execute(stmt)).scalars().all())

    # -- passes ----------------------------------------------------------------
    async def open_pass_for(self, scan_run_id: str) -> VerificationPass | None:
        """The pass that currently owns this scan, if any.

        One open pass per scan is a partial unique index, so this read is for the
        refusal message and for recovery — never for the decision, which the
        database makes.
        """
        stmt = (
            select(VerificationPass)
            .where(
                VerificationPass.scan_run_id == scan_run_id,
                VerificationPass.state.in_(_state_values(OPEN_PASS_STATES)),
            )
            .order_by(VerificationPass.started_at.desc())
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_pass(self, pass_id: str) -> VerificationPass | None:
        return await self._session.get(VerificationPass, pass_id, populate_existing=True)

    async def latest_complete_pass(self, scan_run_id: str) -> VerificationPass | None:
        stmt = (
            select(VerificationPass)
            .where(
                VerificationPass.scan_run_id == scan_run_id,
                VerificationPass.state == PassState.COMPLETE.value,
            )
            .order_by(VerificationPass.completed_at.desc(), VerificationPass.pass_id.desc())
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    # -- deliverable and audit -------------------------------------------------
    async def insert_report(self, values: Mapping[str, Any]) -> None:
        """Append the deliverable. Written in the same transaction as COMPLETE."""
        self._session.add(VerificationReport(**dict(values)))

    async def latest_report(self, scan_run_id: str) -> VerificationReport | None:
        """The newest report from a COMPLETE pass of this scan.

        Joined through the pass rather than read by time alone: a report row
        whose pass did not reach COMPLETE is not a deliverable, and serving one
        would publish a conclusion the pass never committed to.
        """
        stmt = (
            select(VerificationReport)
            .join(VerificationPass, VerificationPass.pass_id == VerificationReport.pass_id)
            .where(
                VerificationReport.scan_run_id == scan_run_id,
                VerificationPass.state == PassState.COMPLETE.value,
            )
            .order_by(VerificationPass.completed_at.desc(), VerificationPass.pass_id.desc())
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def report_for_pass(self, pass_id: str) -> VerificationReport | None:
        stmt = select(VerificationReport).where(VerificationReport.pass_id == pass_id)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    def add_event(self, values: Mapping[str, Any]) -> None:
        """Append a signed event.

        Takes the already-signed row as a mapping rather than an event object:
        the signing surface belongs to the audit module, and a repository that
        reached into it would be a second place where the payload that gets
        digested could differ from the payload that gets stored.
        """
        self._session.add(VerificationAudit(**dict(values)))

    # -- internals -------------------------------------------------------------
    async def _pass_for_key(self, scan_run_id: str, request_key: str) -> VerificationPass | None:
        stmt = select(VerificationPass).where(
            VerificationPass.scan_run_id == scan_run_id,
            VerificationPass.request_key == request_key,
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def _observation_row(self, observation_id: str) -> VerificationObservation | None:
        """The one row for this identity, or the integrity failure of two.

        The table's key carries its partition column, so nothing in the parent
        table stops a second row for one ``observation_id``. Reporting that as a
        conflict is the point: silently taking the first would make a duplicated
        contact look like a retry.
        """
        stmt = (
            select(VerificationObservation)
            .where(VerificationObservation.observation_id == observation_id)
            .order_by(VerificationObservation.settled_at)
        )
        rows = list((await self._session.execute(stmt)).scalars().all())
        if len(rows) > 1:
            raise IdentityConflictError(
                f"observation {observation_id} has {len(rows)} rows; one identity is one contact"
            )
        return rows[0] if rows else None

    async def _verdict_row(self, pass_id: str, finding_id: str) -> FindingVerification | None:
        stmt = (
            select(FindingVerification)
            .where(
                FindingVerification.pass_id == pass_id,
                FindingVerification.finding_id == finding_id,
            )
            .order_by(FindingVerification.observed_at)
        )
        rows = list((await self._session.execute(stmt)).scalars().all())
        if len(rows) > 1:
            raise IdentityConflictError(
                f"finding {finding_id} has {len(rows)} verdicts in pass {pass_id}; "
                "one finding is one verdict per pass"
            )
        return rows[0] if rows else None

    async def _resume(
        self, row: VerificationPass, *, holder: str, lease_seconds: float
    ) -> PassClaim | Busy:
        state = PassState(row.state)
        if state in TERMINAL_PASS_STATES:
            return PassClaim(
                pass_id=row.pass_id,
                scan_run_id=row.scan_run_id,
                state=state,
                claim_epoch=row.claim_epoch,
                cancellation_epoch=row.cancellation_epoch,
                holder=row.holder,
                adoption_count=row.adoption_count,
                owned=False,
                resumed=True,
                adopted=False,
            )
        adopted = await self._adopt(row.pass_id, holder=holder, lease_seconds=lease_seconds)
        if adopted is not None:
            return adopted
        lease = await self.lease_state(row.pass_id)
        return Busy(
            scan_run_id=row.scan_run_id,
            pass_id=row.pass_id,
            holder=lease.holder if lease else row.holder,
            lease_expires_at=lease.lease_expires_at if lease else row.lease_expires_at,
        )

    async def _adopt(
        self, pass_id: str, *, holder: str, lease_seconds: float
    ) -> PassClaim | None:
        """Re-fence an open pass whose lease has lapsed; ``None`` if it is live.

        The epoch advance and the adoption count move in one statement. Counting
        in a second statement would let a process that dies between them adopt
        without being counted, which is precisely the loop the bound in the pass
        kernel exists to stop.
        """
        stmt = (
            update(VerificationPass)
            .where(
                VerificationPass.pass_id == pass_id,
                VerificationPass.state.in_(_state_values(OPEN_PASS_STATES)),
                or_(
                    VerificationPass.holder.is_(None),
                    VerificationPass.holder == holder,
                    VerificationPass.lease_expires_at.is_(None),
                    VerificationPass.lease_expires_at <= func.now(),
                ),
            )
            .values(
                holder=holder,
                claim_epoch=VerificationPass.claim_epoch + 1,
                adoption_count=VerificationPass.adoption_count + 1,
                lease_expires_at=func.now() + timedelta(seconds=lease_seconds),
            )
            .returning(
                VerificationPass.pass_id,
                VerificationPass.scan_run_id,
                VerificationPass.state,
                VerificationPass.claim_epoch,
                VerificationPass.cancellation_epoch,
                VerificationPass.adoption_count,
            )
        )
        row = (await self._session.execute(stmt)).first()
        if row is None:
            return None
        return PassClaim(
            pass_id=row[0],
            scan_run_id=row[1],
            state=PassState(row[2]),
            claim_epoch=row[3],
            cancellation_epoch=row[4],
            holder=holder,
            adoption_count=row[5],
            owned=True,
            resumed=True,
            adopted=True,
        )

    async def _insert_pass(
        self,
        scan_run_id: str,
        request_key: str | None,
        *,
        scope: Mapping[str, Any] | None,
        presented: str,
        holder: str,
        lease_seconds: float,
        initiated_by: str,
    ) -> PassClaim | Busy | KeyConflict:
        """Insert a PLANNED pass, or lose the race and resolve what won.

        Both uniqueness rules can reject this insert — the key map and the
        one-open-pass-per-scan index — and both rejections mean another process
        got there first. The savepoint keeps the caller's transaction usable so
        the answer can be read from the row that won rather than from an
        exception.
        """
        stmt = (
            pg_insert(VerificationPass)
            .values(
                pass_id=new_pass_id(),
                scan_run_id=scan_run_id,
                request_key=request_key,
                scope=dict(scope) if scope else None,
                state=PassState.PLANNED.value,
                initiated_by=initiated_by,
                holder=holder,
                claim_epoch=_FIRST_EPOCH,
                cancellation_epoch=0,
                adoption_count=0,
                salt=new_pass_salt(),
                lease_expires_at=func.now() + timedelta(seconds=lease_seconds),
            )
            .on_conflict_do_nothing(index_elements=["scan_run_id", "request_key"])
            .returning(VerificationPass.pass_id, VerificationPass.claim_epoch)
        )
        row = None
        try:
            async with self._session.begin_nested():
                row = (await self._session.execute(stmt)).first()
        except IntegrityError:
            row = None
        if row is not None:
            return PassClaim(
                pass_id=row[0],
                scan_run_id=scan_run_id,
                state=PassState.PLANNED,
                claim_epoch=row[1],
                cancellation_epoch=0,
                holder=holder,
                adoption_count=0,
                owned=True,
                resumed=False,
                adopted=False,
            )

        if request_key is not None:
            winner = await self._pass_for_key(scan_run_id, request_key)
            if winner is not None:
                stored = scope_digest(winner.scope)
                if stored != presented:
                    return KeyConflict(
                        request_key=request_key,
                        pass_id=winner.pass_id,
                        stored_digest=stored,
                        presented_digest=presented,
                        detail="the request bound to this key has a different scope",
                    )
                return await self._resume(winner, holder=holder, lease_seconds=lease_seconds)

        open_row = await self.open_pass_for(scan_run_id)
        if open_row is not None:
            return await self._resume(open_row, holder=holder, lease_seconds=lease_seconds)
        raise IdentityConflictError(
            f"the pass for scan {scan_run_id} was rejected on insert but no owning row exists"
        )


def _state_values(states: set[PassState] | frozenset[PassState]) -> tuple[str, ...]:
    """Closed-enum members as the text the CHECK constraints compare."""
    return tuple(sorted(state.value for state in states))

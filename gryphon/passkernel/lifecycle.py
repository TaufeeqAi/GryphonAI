"""The pass lifecycle: compare-and-set on the epoch, pins written once.

Every durable move a pass makes is a compare-and-set on its claim epoch. A
statement that matches no row is not a lost update to retry — it means this
process no longer owns the pass and must stop. Leases alone cannot give that
guarantee, because they infer death from silence, and a lease shorter than the
work silently produces two owners.

The kernel keeps only the parts of a lifecycle that every layer has, and takes
the rest as configuration:

* **The state enum belongs to the host.** :class:`StateModel` says which of its
  members are open, terminal, and suspended. The kernel never learns that a
  state means "the gateway is down"; it only needs to know that a suspended
  state can be entered and left again without the pass ending, so that waiting
  for a dependency is not mistaken for finishing.
* **Pins are written once and the second attempt is a *result*.** A resumed pass
  finding its own manifest is the normal path; a re-planned pass finding a
  manifest it did not write is an integrity conflict. Only the caller can tell
  those apart, so the kernel reports the fact and refuses to guess.
* **Adoption is bounded.** Taking over an expired pass is how recovery works,
  but a pass whose own work kills the process that adopts it would be adopted
  forever by a queue of identical workers, each one re-contacting the same
  targets. Past the bound the kernel returns ``RECOVERY_BLOCKED`` and the pass
  waits for a person.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from gryphon.logging_config import get_logger
from gryphon.passkernel.lease import LeaseKeeper
from gryphon.passkernel.ports import (
    KernelConfigurationError,
    KernelLogger,
    LifecycleStore,
    PassSnapshot,
    StateT,
)

__all__ = [
    "DEFAULT_ADOPTION_POLICY",
    "RECOVERY_BLOCKED_SIGNAL",
    "Adoption",
    "AdoptionOutcome",
    "AdoptionPolicy",
    "PassLifecycle",
    "StateModel",
]

_LOGGER: KernelLogger = get_logger(__name__)

#: The reason text a host records when adoption is exhausted. It is one shared
#: string so that "this pass stopped being recoverable" reads the same in every
#: layer's rows, events and dashboards.
RECOVERY_BLOCKED_SIGNAL: Final[str] = "recovery_blocked"

#: Three takeovers is a crash loop, not bad luck. Deliberately small: the cost of
#: stopping early is an operator decision, and the cost of not stopping is
#: repeated traffic to someone else's estate.
DEFAULT_MAX_ADOPTIONS: Final[int] = 3


class AdoptionOutcome(StrEnum):
    """What happened when this holder tried to take over an unfinished pass."""

    #: The epoch was advanced; this holder now owns the pass.
    ADOPTED = "ADOPTED"
    #: The pass was already at this holder's epoch — nothing to do.
    ALREADY_HELD = "ALREADY_HELD"
    #: A newer holder owns it, or it moved underneath this process.
    FENCED = "FENCED"
    #: The pass reached a terminal state; there is nothing left to adopt.
    CLOSED = "CLOSED"
    #: The adoption bound is exhausted. Terminal for recovery: no further
    #: holder may take this pass without a person deciding why it keeps dying.
    RECOVERY_BLOCKED = "RECOVERY_BLOCKED"


@dataclass(frozen=True, slots=True)
class AdoptionPolicy:
    """How many times one pass may be taken over before recovery stops."""

    max_adoptions: int = DEFAULT_MAX_ADOPTIONS

    def __post_init__(self) -> None:
        if self.max_adoptions < 0:
            raise KernelConfigurationError("max_adoptions cannot be negative")

    def exhausted(self, adoption_count: int) -> bool:
        """Whether a pass with this many adoptions behind it may be taken again."""
        return adoption_count >= self.max_adoptions


DEFAULT_ADOPTION_POLICY: Final[AdoptionPolicy] = AdoptionPolicy()


@dataclass(frozen=True, slots=True)
class Adoption:
    """The result of one adoption attempt, with the count that produced it."""

    outcome: AdoptionOutcome
    epoch: int
    adoption_count: int

    @property
    def owned(self) -> bool:
        """Whether this holder may now write as the owner of the pass."""
        return self.outcome in (AdoptionOutcome.ADOPTED, AdoptionOutcome.ALREADY_HELD)

    @property
    def recovery_blocked(self) -> bool:
        return self.outcome is AdoptionOutcome.RECOVERY_BLOCKED


@dataclass(frozen=True, slots=True)
class StateModel[StateT]:
    """Which of a host's states are open, suspended and terminal.

    This is the whole of what the kernel knows about a layer's lifecycle. The
    sets are checked once, when services are built, because a model in which a
    terminal state is also open would let a published pass be re-opened — and
    that is not something a runtime check at transition time could undo.
    """

    initial: StateT
    running: StateT
    open_states: frozenset[StateT]
    terminal_states: frozenset[StateT]
    #: States the pass can enter and leave without terminating — waiting for a
    #: dependency rather than concluding about it.
    suspended_states: frozenset[StateT] = frozenset()

    def __post_init__(self) -> None:
        if not self.terminal_states:
            raise KernelConfigurationError("a lifecycle needs at least one terminal state")
        overlap = self.open_states & self.terminal_states
        if overlap:
            raise KernelConfigurationError(
                "states cannot be both open and terminal: "
                + ", ".join(sorted(s.name for s in overlap))
            )
        for role, state in (("initial", self.initial), ("running", self.running)):
            if state not in self.open_states:
                raise KernelConfigurationError(f"the {role} state must be an open state")
        stray = self.suspended_states - self.open_states
        if stray:
            raise KernelConfigurationError(
                "a suspended state must also be open: "
                + ", ".join(sorted(s.name for s in stray))
            )

    def is_open(self, state: StateT) -> bool:
        return state in self.open_states

    def is_terminal(self, state: StateT) -> bool:
        return state in self.terminal_states

    def is_suspended(self, state: StateT) -> bool:
        return state in self.suspended_states


class PassLifecycle[StateT]:
    """One pass's fenced lifecycle, over whatever storage the host supplies."""

    def __init__(
        self,
        store: LifecycleStore[StateT],
        *,
        pass_id: str,
        keeper: LeaseKeeper,
        model: StateModel[StateT],
        policy: AdoptionPolicy = DEFAULT_ADOPTION_POLICY,
        logger: KernelLogger | None = None,
    ) -> None:
        self._store = store
        self._pass_id = pass_id
        self._keeper = keeper
        self._model = model
        self._policy = policy
        self._log = logger if logger is not None else _LOGGER

    @property
    def pass_id(self) -> str:
        return self._pass_id

    @property
    def epoch(self) -> int:
        return self._keeper.epoch

    @property
    def model(self) -> StateModel[StateT]:
        return self._model

    async def read(self) -> PassSnapshot[StateT] | None:
        """The pass's current row, unfenced — a read decides nothing."""
        return await self._store.read(self._pass_id)

    # -- the compare-and-set --------------------------------------------------
    async def transition(
        self, *, expected: Collection[StateT], to: StateT, **values: object
    ) -> bool:
        """Move the pass to ``to`` if it is in ``expected`` at this epoch.

        ``False`` means this process is no longer the owner, or the pass is no
        longer where it was. It is returned rather than raised because the two
        callers differ: a publisher treats it as a rollback, while a sweeper
        treats it as "somebody else got there first", and only one of those is
        an error.
        """
        expected_states = frozenset(expected)
        if not expected_states:
            raise KernelConfigurationError("a transition needs at least one expected state")
        leaving_terminal = expected_states & self._model.terminal_states
        if leaving_terminal:
            raise KernelConfigurationError(
                "a terminal state is never left: "
                + ", ".join(sorted(s.name for s in leaving_terminal))
            )
        self._keeper.ensure_held()
        changed = await self._store.compare_and_set(
            pass_id=self._pass_id,
            epoch=self._keeper.epoch,
            expected=expected_states,
            to=to,
            values=dict(values),
        )
        if not changed:
            # Deliberately *not* reported to the keeper as a lost lease. Under
            # one epoch there is one holder, so a statement that matched no row
            # may simply mean the pass is not where the caller believed it was.
            # Poisoning the lease on that reading would abandon a run that is
            # still perfectly owned.
            self._log.warning(
                "pass_transition_fenced",
                pass_id=self._pass_id,
                epoch=self._keeper.epoch,
                to=to.name,
            )
        return changed

    async def suspend(self, *, to: StateT, **values: object) -> bool:
        """Enter a suspended state from the running state.

        Suspension is how a pass waits for a dependency without concluding
        anything about the work it has not done. A layer that terminated here
        would be publishing its own outage as a result.
        """
        if not self._model.is_suspended(to):
            raise KernelConfigurationError(f"{to.name} is not a suspended state")
        return await self.transition(expected={self._model.running}, to=to, **values)

    async def resume(self, **values: object) -> bool:
        """Leave any suspended state and continue running.

        The expected set is every suspended state rather than the one that was
        entered, so a caller that resumes after a restart does not have to have
        remembered which dependency it was waiting on.
        """
        if not self._model.suspended_states:
            raise KernelConfigurationError("this lifecycle declares no suspended states")
        return await self.transition(
            expected=self._model.suspended_states, to=self._model.running, **values
        )

    # -- pins ------------------------------------------------------------------
    async def write_pins_once(self, pins: Mapping[str, object]) -> bool:
        """Write the pin manifest; ``False`` means one was already written.

        Not an exception, because the second attempt has two readings and the
        kernel cannot choose between them. A pass resuming after a crash expects
        to find its own manifest and re-derive from it. A pass being *re-planned*
        finds a manifest it did not write, which means two planners disagree
        about one pass and nothing it publishes could be explained.
        """
        self._keeper.ensure_held()
        written = await self._store.write_pins(
            pass_id=self._pass_id, epoch=self._keeper.epoch, pins=dict(pins)
        )
        if not written:
            self._log.info("pass_pins_already_written", pass_id=self._pass_id)
        return written

    async def read_pins(self) -> Mapping[str, object] | None:
        """The stored manifest a resumed pass must re-derive from."""
        return await self._store.read_pins(self._pass_id)

    # -- bounded adoption ------------------------------------------------------
    async def adopt(self) -> Adoption:
        """Take over an unfinished pass at this holder's epoch, within the bound.

        Recovery after a crash is an adoption: the next holder re-fences the pass
        and continues from the rows already recorded, which is what keeps a
        resumed pass from re-contacting anything it already observed. The bound
        is what stops that from becoming a loop — if the work itself is what
        kills the holder, every new worker would adopt, die, and hand the same
        pass to the next one.
        """
        self._keeper.ensure_held()
        snapshot = await self._store.read(self._pass_id)
        if snapshot is None:
            self._log.warning("pass_adopt_missing", pass_id=self._pass_id)
            return Adoption(AdoptionOutcome.CLOSED, epoch=self._keeper.epoch, adoption_count=0)
        if self._model.is_terminal(snapshot.state):
            return Adoption(
                AdoptionOutcome.CLOSED,
                epoch=snapshot.claim_epoch,
                adoption_count=snapshot.adoption_count,
            )
        if snapshot.claim_epoch == self._keeper.epoch:
            return Adoption(
                AdoptionOutcome.ALREADY_HELD,
                epoch=snapshot.claim_epoch,
                adoption_count=snapshot.adoption_count,
            )
        if snapshot.claim_epoch > self._keeper.epoch:
            self._keeper.mark_lost(
                f"pass {self._pass_id} is held at epoch {snapshot.claim_epoch}"
            )
            return Adoption(
                AdoptionOutcome.FENCED,
                epoch=snapshot.claim_epoch,
                adoption_count=snapshot.adoption_count,
            )
        if self._policy.exhausted(snapshot.adoption_count):
            self._log.error(
                "pass_recovery_blocked",
                pass_id=self._pass_id,
                signal=RECOVERY_BLOCKED_SIGNAL,
                adoption_count=snapshot.adoption_count,
                max_adoptions=self._policy.max_adoptions,
            )
            return Adoption(
                AdoptionOutcome.RECOVERY_BLOCKED,
                epoch=snapshot.claim_epoch,
                adoption_count=snapshot.adoption_count,
            )
        adopted = await self._store.adopt(
            pass_id=self._pass_id,
            new_epoch=self._keeper.epoch,
            open_states=self._model.open_states,
        )
        if adopted is None:
            self._log.warning(
                "pass_adopt_fenced", pass_id=self._pass_id, epoch=self._keeper.epoch
            )
            return Adoption(
                AdoptionOutcome.FENCED,
                epoch=snapshot.claim_epoch,
                adoption_count=snapshot.adoption_count,
            )
        self._log.info(
            "pass_adopted",
            pass_id=self._pass_id,
            epoch=self._keeper.epoch,
            adoption_count=adopted,
        )
        return Adoption(
            AdoptionOutcome.ADOPTED, epoch=self._keeper.epoch, adoption_count=adopted
        )

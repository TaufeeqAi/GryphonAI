"""What a host layer must supply, and what it must be ready to handle.

The kernel owns the *rules* of a fenced pass — when a lease is lost, which
transitions are legal, how often a pass may be adopted. It owns none of the
storage. Every statement is executed by an adapter the host layer writes, so the
kernel imports no model, no session and no SQL, and one copy of the rules serves
layers whose tables have nothing in common.

Two obligations sit on the adapter rather than on the kernel, and both are here
because getting them wrong is silent:

* **Expiry is computed by the database, inside the statement.** An adapter
  receives ``lease_seconds``, never a deadline. It must build the deadline from
  the database's own ``now()`` so that every participant compares against one
  clock. A host whose clock runs fast would otherwise believe a live lease had
  lapsed and take work away from a holder that is still running.
* **A fenced write re-asserts the lease in its own transaction.** The renewal
  statement row-locks the lease until commit, so nothing can claim it between
  the check and the writes that follow. A ``compare_and_set`` whose adapter only
  compares the epoch is still correct against a *newer* holder, but it leaves a
  window in which a holder whose lease has quietly lapsed commits anyway.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Protocol, TypeVar, runtime_checkable

__all__ = [
    "KernelConfigurationError",
    "KernelLogger",
    "LeaseState",
    "LeaseStore",
    "LifecycleStore",
    "PassKernelError",
    "PassSnapshot",
    "StateT",
]

#: A host layer's closed lifecycle enum. Bound to :class:`enum.Enum` rather than
#: :class:`enum.StrEnum` because the layers that exist today use both forms; the
#: kernel only ever compares members and logs ``.name``.
StateT = TypeVar("StateT", bound=Enum)


class PassKernelError(Exception):
    """Base class for the kernel's own failures.

    The kernel raises for two conditions only: a composition that cannot be made
    safe, and a lease it can no longer vouch for. Everything else — an adoption
    refused, a pin already written, a transition that matched no row — is
    returned as a typed value, because each of those has a legitimate reading
    that only the caller can choose between.
    """


class KernelConfigurationError(PassKernelError):
    """A composition the kernel refuses to run with.

    Raised while services are being built, never during a pass: a heartbeat that
    cannot cover its lease, a state model whose terminal states are also open, a
    transition asked to leave a terminal state. Each would produce two owners or
    an unexplainable row, and each is a property of the code rather than of the
    run, so it fails at startup where a human is watching.
    """


class KernelLogger(Protocol):
    """The logging surface the kernel uses.

    Declared structurally so the kernel binds to no layer's logger. The
    enrichment copy of this code logged under an enrichment event name, which is
    exactly the kind of detail that stops shared code from being shared.
    """

    def debug(self, event: str, **fields: object) -> None: ...

    def info(self, event: str, **fields: object) -> None: ...

    def warning(self, event: str, **fields: object) -> None: ...

    def error(self, event: str, **fields: object) -> None: ...


@dataclass(frozen=True, slots=True)
class LeaseState:
    """What the store can say about a lease without claiming it.

    ``held`` is decided by the adapter against the database clock. The kernel
    never recomputes it from ``lease_expires_at`` and a local instant: that
    comparison is the skew question the lease exists to answer.
    """

    holder: str | None
    claim_epoch: int
    lease_expires_at: datetime | None
    held: bool


@dataclass(frozen=True, slots=True)
class PassSnapshot[StateT]:
    """The fields of a pass row the kernel reasons about. Nothing else."""

    pass_id: str
    state: StateT
    claim_epoch: int
    #: How many times this pass has already been taken over by a later holder.
    #: Bounded, because a pass that crashes the process which adopts it would
    #: otherwise be adopted forever by a queue of identical workers.
    adoption_count: int = 0
    pins_present: bool = False


@runtime_checkable
class LeaseStore(Protocol):
    """One lease, on the database clock.

    An adapter is bound to a single lease resource when it is constructed — the
    enrichment layer's system-wide slot, one scan's open pass, one scheduler
    shard — so the kernel never names a resource and never builds a key.
    """

    async def claim(self, holder: str, lease_seconds: float) -> int | None:
        """Take the lease if it is free or lapsed; return the new claim epoch.

        ``None`` means someone else holds it. The epoch must increase on every
        claim: it is the fencing token every later write is checked against, and
        a reused epoch would let a superseded holder's writes land.
        """
        ...

    async def renew(self, holder: str, epoch: int, lease_seconds: float) -> bool:
        """Extend the lease, if this holder still owns it at this epoch.

        ``False`` is not a failure to retry. It means the lease was claimed by
        someone else, so this process must stop writing *and* stop acting.
        """
        ...

    async def release(self, holder: str, epoch: int) -> None:
        """Give the lease up early, if this holder still owns it at this epoch.

        Releasing is a courtesy that shortens recovery, never a correctness
        requirement: a holder that dies without releasing is recovered by expiry.
        """
        ...

    async def describe(self) -> LeaseState | None:
        """Report the lease without taking it, for a refusal message or status.

        ``None`` means the lease row does not exist, which is a deployment fault
        — the migration that seeds it has not been applied — rather than a free
        lease to claim.
        """
        ...


@runtime_checkable
class LifecycleStore[StateT](Protocol):
    """One pass row's state, epoch, adoption count and write-once pins."""

    async def read(self, pass_id: str) -> PassSnapshot[StateT] | None:
        """Return the pass's current snapshot, or ``None`` if there is no row."""
        ...

    async def compare_and_set(
        self,
        *,
        pass_id: str,
        epoch: int,
        expected: frozenset[StateT],
        to: StateT,
        values: Mapping[str, object],
    ) -> bool:
        """Move the pass to ``to``, fenced on ``epoch`` and on ``expected``.

        The statement must match on the epoch *and* the current state, and must
        report whether exactly one row changed. ``False`` therefore carries two
        readings — a newer holder, or a state that moved underneath this process
        — and both mean the same thing to the caller: stop.
        """
        ...

    async def adopt(
        self, *, pass_id: str, new_epoch: int, open_states: frozenset[StateT]
    ) -> int | None:
        """Re-fence an unfinished pass to ``new_epoch``; return its adoption count.

        The statement must advance the epoch only from a strictly lower one and
        only while the pass is open, and must increment the adoption count in the
        same statement. Counting in a second statement would let a process that
        dies between them adopt without being counted, which is precisely the
        loop the bound exists to stop.
        """
        ...

    async def write_pins(
        self, *, pass_id: str, epoch: int, pins: Mapping[str, object]
    ) -> bool:
        """Write the pin manifest if this pass has none. ``False`` if it has.

        Write-once is what makes every append-only row of the pass explainable:
        the pins are the provenance root those rows were derived from, so if the
        manifest could move, work already published would no longer be traceable
        to the inputs that produced it.
        """
        ...

    async def read_pins(self, pass_id: str) -> Mapping[str, object] | None:
        """Return the stored pin manifest, or ``None`` when none was written."""
        ...

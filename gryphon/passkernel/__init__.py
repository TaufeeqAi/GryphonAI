"""The shared fenced-pass kernel: one implementation of a pattern we had twice.

A *fenced pass* is a unit of work that exactly one process may own at a time: it
claims a lease, every durable write it makes is compare-and-set against the
claim epoch that lease produced, it pins its inputs once, and if its process
dies the next holder adopts the work rather than starting it again.

That pattern was already implemented independently in the orchestration ledger
and in the enrichment engine. The verification layer would have been the third
copy and a scheduler the fourth, which means a correction to adoption, sweeping
or recovery would have to be made — correctly, and the same way — in four
places. This package is the one implementation those layers share.

It is deliberately storage-agnostic. The kernel defines the protocols in
:mod:`gryphon.passkernel.ports` and nothing else: no model, no session, no SQL,
no layer's state enum. A host layer writes small adapters over its own tables
and supplies its own fencing exception, so the rules live in one place while the
rows stay where they belong.

What the kernel holds:

* :class:`~gryphon.passkernel.lease.LeaseKeeper` — background renewal on the
  **database** clock, with a conservative local bound on staleness, so that two
  hosts whose clocks differ cannot disagree about who owns the work.
* :class:`~gryphon.passkernel.lifecycle.PassLifecycle` — epoch compare-and-set
  over a host's own state enum, a suspended state that can be entered and left
  without terminating, write-once pins reported as a value, and adoption bounded
  by a policy whose exhaustion is ``RECOVERY_BLOCKED``.
"""

from __future__ import annotations

from gryphon.passkernel.lease import LeaseKeeper, LeaseLost, hold_lease, new_holder_id
from gryphon.passkernel.lifecycle import (
    DEFAULT_ADOPTION_POLICY,
    RECOVERY_BLOCKED_SIGNAL,
    Adoption,
    AdoptionOutcome,
    AdoptionPolicy,
    PassLifecycle,
    StateModel,
)
from gryphon.passkernel.ports import (
    KernelConfigurationError,
    KernelLogger,
    LeaseState,
    LeaseStore,
    LifecycleStore,
    PassKernelError,
    PassSnapshot,
)

__all__ = [
    "DEFAULT_ADOPTION_POLICY",
    "RECOVERY_BLOCKED_SIGNAL",
    "Adoption",
    "AdoptionOutcome",
    "AdoptionPolicy",
    "KernelConfigurationError",
    "KernelLogger",
    "LeaseKeeper",
    "LeaseLost",
    "LeaseState",
    "LeaseStore",
    "LifecycleStore",
    "PassKernelError",
    "PassLifecycle",
    "PassSnapshot",
    "StateModel",
    "hold_lease",
    "new_holder_id",
]

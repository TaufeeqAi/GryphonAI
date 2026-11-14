"""The shared fenced-pass kernel: lease loss, epoch CAS, pins and adoption.

No database and no real clock. The lease store answers from a script and the
monotonic reading is a value the test moves by hand, because the properties
under test are all about *when* the holder stops trusting itself — and a test
that had to wait out a real lease could only ever check the fast paths.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import replace

import pytest

from gryphon.passkernel.lease import LeaseKeeper, hold_lease, new_holder_id
from gryphon.passkernel.lifecycle import (
    AdoptionOutcome,
    AdoptionPolicy,
    PassLifecycle,
    StateModel,
)
from gryphon.passkernel.ports import (
    KernelConfigurationError,
    LeaseState,
    PassSnapshot,
)
from gryphon.verification.constants import (
    OPEN_PASS_STATES,
    TERMINAL_PASS_STATES,
    PassState,
)

pytestmark = pytest.mark.unit


class HostFencedOut(Exception):
    """Stands in for a host layer's own fencing error."""


class HostBusy(Exception):
    """Stands in for a host layer's own "someone else holds it" refusal."""

    def __init__(self, state: LeaseState | None) -> None:
        self.state = state
        super().__init__("the lease is held elsewhere")


class Ticks:
    """A monotonic reading the test moves, never the machine."""

    def __init__(self, now: float = 0.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeLeaseStore:
    """A lease store with no database behind it."""

    def __init__(self, *, epoch: int | None = 1, renew: Callable[[], bool] | None = None) -> None:
        self.epoch = epoch
        self.renew_calls = 0
        self.released: list[tuple[str, int]] = []
        self.renewed = asyncio.Event()
        self._renew = renew if renew is not None else (lambda: True)
        self.state = LeaseState(
            holder="someone-else", claim_epoch=7, lease_expires_at=None, held=True
        )

    async def claim(self, holder: str, lease_seconds: float) -> int | None:
        return self.epoch

    async def renew(self, holder: str, epoch: int, lease_seconds: float) -> bool:
        self.renew_calls += 1
        try:
            return self._renew()
        finally:
            self.renewed.set()

    async def release(self, holder: str, epoch: int) -> None:
        self.released.append((holder, epoch))

    async def describe(self) -> LeaseState | None:
        return self.state


class FakeLifecycleStore:
    """One pass row in memory, with the same fencing the SQL has to have."""

    def __init__(
        self,
        *,
        pass_id: str = "pass-1",
        state: PassState = PassState.PLANNED,
        epoch: int = 1,
        adoption_count: int = 0,
    ) -> None:
        self.row: PassSnapshot[PassState] = PassSnapshot(
            pass_id=pass_id, state=state, claim_epoch=epoch, adoption_count=adoption_count
        )
        self.pins: dict[str, object] | None = None
        self.written: dict[str, object] = {}

    async def read(self, pass_id: str) -> PassSnapshot[PassState] | None:
        return self.row if pass_id == self.row.pass_id else None

    async def compare_and_set(
        self,
        *,
        pass_id: str,
        epoch: int,
        expected: frozenset[PassState],
        to: PassState,
        values: dict[str, object],
    ) -> bool:
        row = self.row
        if pass_id != row.pass_id or epoch != row.claim_epoch or row.state not in expected:
            return False
        self.row = replace(row, state=to)
        self.written.update(values)
        return True

    async def adopt(
        self, *, pass_id: str, new_epoch: int, open_states: frozenset[PassState]
    ) -> int | None:
        row = self.row
        if pass_id != row.pass_id or row.state not in open_states or row.claim_epoch >= new_epoch:
            return None
        self.row = replace(row, claim_epoch=new_epoch, adoption_count=row.adoption_count + 1)
        return self.row.adoption_count

    async def write_pins(self, *, pass_id: str, epoch: int, pins: dict[str, object]) -> bool:
        if self.pins is not None:
            return False
        self.pins = dict(pins)
        return True

    async def read_pins(self, pass_id: str) -> dict[str, object] | None:
        return self.pins


MODEL: StateModel[PassState] = StateModel(
    initial=PassState.PLANNED,
    running=PassState.RUNNING,
    open_states=frozenset(OPEN_PASS_STATES),
    terminal_states=frozenset(TERMINAL_PASS_STATES),
    suspended_states=frozenset({PassState.BLOCKED}),
)


async def _settle(times: int = 8) -> None:
    """Give the keeper's loop the event-loop turns it needs to finish."""
    for _ in range(times):
        await asyncio.sleep(0)


def _keeper(
    store: FakeLeaseStore,
    *,
    epoch: int = 1,
    lease: float = 60.0,
    heartbeat: float = 15.0,
    ticks: Ticks | None = None,
    claimed_at: float | None = None,
) -> LeaseKeeper:
    return LeaseKeeper(
        store,
        holder="holder-a",
        epoch=epoch,
        lease_seconds=lease,
        heartbeat_seconds=heartbeat,
        fenced_error=HostFencedOut,
        monotonic=ticks if ticks is not None else Ticks(),
        claimed_at=claimed_at,
    )


def _lifecycle(
    store: FakeLifecycleStore,
    keeper: LeaseKeeper,
    *,
    policy: AdoptionPolicy | None = None,
) -> PassLifecycle[PassState]:
    return PassLifecycle(
        store,
        pass_id="pass-1",
        keeper=keeper,
        model=MODEL,
        policy=policy if policy is not None else AdoptionPolicy(),
    )


# -- the lease ----------------------------------------------------------------
async def test_lease_is_lost_when_a_renewal_is_refused() -> None:
    ticks = Ticks()
    store = FakeLeaseStore(renew=lambda: False)
    keeper = _keeper(store, heartbeat=0.001, ticks=ticks)

    async with keeper:
        await asyncio.wait_for(store.renewed.wait(), timeout=1.0)
        await _settle()

    assert keeper.lost
    assert keeper.lost_reason is not None
    assert "another holder" in keeper.lost_reason


async def test_lease_is_lost_when_a_renewal_succeeds_too_late() -> None:
    """A statement that returns True after the lease has lapsed proves nothing.

    The renewal below succeeds, but the call itself outlasts the lease. The
    holder is told by the local bound — measured from *before* the statement —
    that it can no longer vouch for ownership.
    """
    ticks = Ticks()

    def renew_slowly() -> bool:
        ticks.advance(120.0)
        return True

    store = FakeLeaseStore(renew=renew_slowly)
    keeper = _keeper(store, lease=60.0, heartbeat=0.001, ticks=ticks)

    async with keeper:
        await asyncio.wait_for(store.renewed.wait(), timeout=1.0)
        await _settle()

    assert store.renew_calls >= 1
    assert keeper.lost_reason is None  # nothing refused it
    assert keeper.lost  # and yet the holder must assume it is gone


async def test_ensure_held_raises_the_hosts_own_error_at_the_bound() -> None:
    ticks = Ticks()
    keeper = _keeper(FakeLeaseStore(), lease=60.0, heartbeat=15.0, ticks=ticks)

    keeper.ensure_held()
    ticks.advance(44.9)  # still inside lease - heartbeat
    assert not keeper.lost
    keeper.ensure_held()

    ticks.advance(0.2)
    assert keeper.lost
    with pytest.raises(HostFencedOut):
        keeper.ensure_held()


async def test_reassert_raises_when_the_store_refuses_the_renewal() -> None:
    store = FakeLeaseStore(renew=lambda: False)
    keeper = _keeper(store)

    with pytest.raises(HostFencedOut):
        await keeper.reassert()
    assert keeper.lost


async def test_a_transport_failure_is_not_a_lost_lease() -> None:
    ticks = Ticks()

    def explode() -> bool:
        raise RuntimeError("connection reset")

    store = FakeLeaseStore(renew=explode)
    keeper = _keeper(store, lease=60.0, heartbeat=0.05, ticks=ticks)

    async with keeper:
        await asyncio.wait_for(store.renewed.wait(), timeout=1.0)
        await _settle()
        assert not keeper.lost  # the local bound has not elapsed yet
    ticks.advance(60.0)
    assert keeper.lost  # and it decides once the outage outlasts the lease


async def test_keeper_cancellation_is_clean() -> None:
    store = FakeLeaseStore()
    keeper = _keeper(store, heartbeat=0.001)

    async with keeper:
        assert keeper.running
        await asyncio.wait_for(store.renewed.wait(), timeout=1.0)

    assert not keeper.running
    await _settle()
    await keeper.aclose()  # closing twice is harmless


async def test_cancelling_the_holder_stops_the_keeper() -> None:
    store = FakeLeaseStore()
    keeper = _keeper(store, heartbeat=0.001)
    started = asyncio.Event()

    async def hold() -> None:
        async with keeper:
            started.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(hold())
    await asyncio.wait_for(started.wait(), timeout=1.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await _settle()
    assert not keeper.running


async def test_hold_lease_claims_and_releases() -> None:
    store = FakeLeaseStore(epoch=4)

    async with hold_lease(
        store,
        holder="holder-a",
        lease_seconds=60.0,
        heartbeat_seconds=15.0,
        busy_error=HostBusy,
        fenced_error=HostFencedOut,
        monotonic=Ticks(),
    ) as keeper:
        assert keeper.epoch == 4

    assert store.released == [("holder-a", 4)]


async def test_hold_lease_refuses_with_the_hosts_own_busy_error() -> None:
    store = FakeLeaseStore(epoch=None)

    with pytest.raises(HostBusy) as caught:
        async with hold_lease(
            store,
            holder="holder-a",
            lease_seconds=60.0,
            heartbeat_seconds=15.0,
            busy_error=HostBusy,
            monotonic=Ticks(),
        ):
            pass  # pragma: no cover - the claim refuses before the body runs

    assert caught.value.state is not None
    assert caught.value.state.holder == "someone-else"


async def test_a_lease_must_leave_room_for_one_renewal_round_trip() -> None:
    """Twice the heartbeat is not enough, and the boundary is the interesting case.

    At exactly twice, the staleness bound (``lease - heartbeat``) equals the
    sleep before the first renewal, so the keeper declares itself lost at the
    very instant that renewal becomes due — before any renewal could refresh
    the anchor. Three heartbeats leave room for one round trip.
    """
    with pytest.raises(KernelConfigurationError, match="three times"):
        _keeper(FakeLeaseStore(), lease=30.0, heartbeat=15.0)
    with pytest.raises(KernelConfigurationError, match="three times"):
        _keeper(FakeLeaseStore(), lease=44.0, heartbeat=15.0)
    # Exactly three is admissible.
    _keeper(FakeLeaseStore(), lease=45.0, heartbeat=15.0)


async def test_the_staleness_anchor_is_taken_before_the_claim_statement() -> None:
    """The claim's own round trip counts against the lease.

    Anchoring after the statement returns would have the keeper vouch for a
    lease that had already partly elapsed, which is the one thing this bound
    exists to prevent.
    """
    keeper = _keeper(FakeLeaseStore(), lease=45.0, heartbeat=15.0, claimed_at=100.0)
    assert keeper._last_renewal_started == 100.0


def test_holder_ids_are_unique_per_attempt() -> None:
    assert new_holder_id("cli:uid:1000") != new_holder_id("cli:uid:1000")
    assert new_holder_id("x" * 200).startswith("x")
    assert len(new_holder_id("x" * 200)) <= 80


# -- the state model ----------------------------------------------------------
def test_a_state_cannot_be_both_open_and_terminal() -> None:
    with pytest.raises(KernelConfigurationError, match="open and terminal"):
        StateModel(
            initial=PassState.PLANNED,
            running=PassState.RUNNING,
            open_states=frozenset({PassState.PLANNED, PassState.RUNNING, PassState.COMPLETE}),
            terminal_states=frozenset({PassState.COMPLETE}),
        )


def test_a_suspended_state_must_also_be_open() -> None:
    with pytest.raises(KernelConfigurationError, match="suspended"):
        StateModel(
            initial=PassState.PLANNED,
            running=PassState.RUNNING,
            open_states=frozenset({PassState.PLANNED, PassState.RUNNING}),
            terminal_states=frozenset(TERMINAL_PASS_STATES),
            suspended_states=frozenset({PassState.BLOCKED}),
        )


# -- the compare-and-set ------------------------------------------------------
async def test_cas_rejects_a_stale_epoch() -> None:
    store = FakeLifecycleStore(state=PassState.PLANNED, epoch=2)
    stale = _lifecycle(store, _keeper(FakeLeaseStore(), epoch=1))

    assert not await stale.transition(expected={PassState.PLANNED}, to=PassState.RUNNING)
    assert store.row.state is PassState.PLANNED

    current = _lifecycle(store, _keeper(FakeLeaseStore(), epoch=2))
    assert await current.transition(expected={PassState.PLANNED}, to=PassState.RUNNING)
    assert store.row.state is PassState.RUNNING


async def test_cas_rejects_a_state_that_moved() -> None:
    store = FakeLifecycleStore(state=PassState.RUNNING, epoch=1)
    lifecycle = _lifecycle(store, _keeper(FakeLeaseStore()))

    assert not await lifecycle.transition(expected={PassState.PLANNED}, to=PassState.RUNNING)


async def test_a_terminal_state_is_never_left() -> None:
    store = FakeLifecycleStore(state=PassState.COMPLETE, epoch=1)
    lifecycle = _lifecycle(store, _keeper(FakeLeaseStore()))

    with pytest.raises(KernelConfigurationError, match="terminal"):
        await lifecycle.transition(expected={PassState.COMPLETE}, to=PassState.RUNNING)


async def test_a_fenced_holder_writes_nothing() -> None:
    ticks = Ticks()
    store = FakeLifecycleStore(state=PassState.RUNNING, epoch=1)
    keeper = _keeper(FakeLeaseStore(), lease=60.0, heartbeat=15.0, ticks=ticks)
    lifecycle = _lifecycle(store, keeper)
    ticks.advance(50.0)

    with pytest.raises(HostFencedOut):
        await lifecycle.transition(expected={PassState.RUNNING}, to=PassState.COMPLETE)
    with pytest.raises(HostFencedOut):
        await lifecycle.write_pins_once({"registry": "abc"})
    assert store.row.state is PassState.RUNNING
    assert store.pins is None


async def test_a_pass_enters_and_leaves_a_suspended_state() -> None:
    store = FakeLifecycleStore(state=PassState.RUNNING, epoch=1)
    lifecycle = _lifecycle(store, _keeper(FakeLeaseStore()))

    assert await lifecycle.suspend(to=PassState.BLOCKED, reason="gateway_unavailable")
    assert store.row.state is PassState.BLOCKED
    assert not MODEL.is_terminal(store.row.state)
    assert store.written["reason"] == "gateway_unavailable"

    assert await lifecycle.resume(reason=None)
    assert store.row.state is PassState.RUNNING


async def test_suspending_to_a_state_that_is_not_suspended_is_refused() -> None:
    store = FakeLifecycleStore(state=PassState.RUNNING, epoch=1)
    lifecycle = _lifecycle(store, _keeper(FakeLeaseStore()))

    with pytest.raises(KernelConfigurationError, match="suspended"):
        await lifecycle.suspend(to=PassState.COMPLETE)


# -- pins ---------------------------------------------------------------------
async def test_pins_are_written_once_and_the_second_attempt_is_a_result() -> None:
    store = FakeLifecycleStore(state=PassState.PLANNED, epoch=1)
    lifecycle = _lifecycle(store, _keeper(FakeLeaseStore()))

    assert await lifecycle.write_pins_once({"registry_digest": "aaa"})
    assert not await lifecycle.write_pins_once({"registry_digest": "bbb"})
    assert await lifecycle.read_pins() == {"registry_digest": "aaa"}


# -- bounded adoption ---------------------------------------------------------
async def test_adoption_advances_the_epoch_and_counts() -> None:
    store = FakeLifecycleStore(state=PassState.RUNNING, epoch=1)
    lifecycle = _lifecycle(store, _keeper(FakeLeaseStore(), epoch=2))

    adoption = await lifecycle.adopt()
    assert adoption.outcome is AdoptionOutcome.ADOPTED
    assert adoption.owned
    assert adoption.adoption_count == 1
    assert store.row.claim_epoch == 2


async def test_adoption_of_a_pass_already_at_this_epoch_is_a_no_op() -> None:
    store = FakeLifecycleStore(state=PassState.RUNNING, epoch=3)
    lifecycle = _lifecycle(store, _keeper(FakeLeaseStore(), epoch=3))

    adoption = await lifecycle.adopt()
    assert adoption.outcome is AdoptionOutcome.ALREADY_HELD
    assert adoption.owned
    assert store.row.adoption_count == 0


async def test_a_newer_holder_fences_adoption() -> None:
    store = FakeLifecycleStore(state=PassState.RUNNING, epoch=9)
    keeper = _keeper(FakeLeaseStore(), epoch=4)
    lifecycle = _lifecycle(store, keeper)

    adoption = await lifecycle.adopt()
    assert adoption.outcome is AdoptionOutcome.FENCED
    assert not adoption.owned
    assert keeper.lost  # a higher epoch exists, so this holder's claim is stale


async def test_a_terminal_pass_has_nothing_to_adopt() -> None:
    store = FakeLifecycleStore(state=PassState.COMPLETE, epoch=1)
    lifecycle = _lifecycle(store, _keeper(FakeLeaseStore(), epoch=2))

    assert (await lifecycle.adopt()).outcome is AdoptionOutcome.CLOSED


async def test_the_adoption_bound_ends_in_recovery_blocked() -> None:
    """A pass that keeps killing its holder stops being recoverable.

    Without the bound, each new worker would adopt the same pass, die on the
    same work, and hand it to the next one — re-contacting the same estate every
    time. Past the bound the kernel refuses and the pass waits for a person.
    """
    policy = AdoptionPolicy(max_adoptions=2)
    store = FakeLifecycleStore(state=PassState.RUNNING, epoch=1)

    first = _lifecycle(store, _keeper(FakeLeaseStore(), epoch=2), policy=policy)
    assert (await first.adopt()).adoption_count == 1
    second = _lifecycle(store, _keeper(FakeLeaseStore(), epoch=3), policy=policy)
    assert (await second.adopt()).adoption_count == 2

    third = _lifecycle(store, _keeper(FakeLeaseStore(), epoch=4), policy=policy)
    blocked = await third.adopt()
    assert blocked.outcome is AdoptionOutcome.RECOVERY_BLOCKED
    assert blocked.recovery_blocked
    assert not blocked.owned
    assert store.row.claim_epoch == 3  # the refused holder took nothing
    assert store.row.adoption_count == 2


def test_a_negative_adoption_bound_is_refused() -> None:
    with pytest.raises(KernelConfigurationError, match="negative"):
        AdoptionPolicy(max_adoptions=-1)

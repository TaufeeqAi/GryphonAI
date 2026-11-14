"""The lease: one holder at a time, decided by the database clock.

A lease answers one question — *is this process still the owner?* — and the
answer has to be the same for every participant. It is therefore evaluated
against the database's clock inside the statement that renews it, never against
a process clock. Two hosts whose clocks differ by a minute must not disagree
about who owns a pass; if they did, the layer's fencing would protect writes
while two processes were both still *acting*, which for a layer that puts
packets on the wire is the failure that matters.

:class:`LeaseKeeper` adds the one thing the database cannot provide: a local,
conservative bound on how stale the holder's knowledge is. The keeper renews in
the background and reports loss; it never hides it, and it never decides that a
lease is still good because the last renewal returned quickly.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress

from gryphon.logging_config import get_logger
from gryphon.passkernel.ports import (
    KernelConfigurationError,
    KernelLogger,
    LeaseState,
    LeaseStore,
    PassKernelError,
)

__all__ = [
    "LeaseKeeper",
    "LeaseLost",
    "hold_lease",
    "new_holder_id",
]

_LOGGER: KernelLogger = get_logger(__name__)

#: Holder labels are stored in a bounded column and read by operators; the
#: identity only has to be unique, not long.
_MAX_HOLDER_CHARS = 80


class LeaseLost(PassKernelError):
    """This process can no longer vouch for the lease and must stop.

    The default for a host layer that has no fencing error of its own. Layers
    that do — the enrichment and verification ``FencedOut`` — pass theirs in, so
    their callers keep catching the one exception their own contract names.
    """


def new_holder_id(label: str) -> str:
    """Build a holder identity that is unique per process *and* per attempt.

    The process id alone is not unique enough: pids are recycled, and two
    attempts from one long-lived process must not be mistaken for each other
    when a stale claim is being diagnosed from the row alone.
    """
    return f"{label}/pid:{os.getpid()}/{uuid.uuid4().hex[:8]}"[:_MAX_HOLDER_CHARS]


class LeaseKeeper:
    """Renews a lease in the background and reports loss — never hides it.

    ``lost`` turns true in two ways. A renewal that the store *refuses* means
    another holder owns the lease. A renewal that has not *succeeded* within
    ``lease - heartbeat`` seconds of the local monotonic clock means the holder
    no longer knows: past that point the database-side lease may already have
    lapsed, so the only safe assumption is that it has. The second case is the
    one that catches a renewal which succeeds *late* — a store call that blocked
    for longer than the lease is a successful statement against a lease that had
    already been taken.

    The monotonic reading is taken *before* the claim statement, so the local
    bound is never later than the database-side expiry it stands in for.
    """

    def __init__(
        self,
        store: LeaseStore,
        *,
        holder: str,
        epoch: int,
        lease_seconds: float,
        heartbeat_seconds: float,
        fenced_error: type[Exception] = LeaseLost,
        monotonic: Callable[[], float] = time.monotonic,
        logger: KernelLogger | None = None,
        task_name: str = "pass-lease-keeper",
        claimed_at: float | None = None,
    ) -> None:
        if lease_seconds <= 0 or heartbeat_seconds <= 0:
            raise KernelConfigurationError("lease and heartbeat must both be positive")
        if lease_seconds < 3 * heartbeat_seconds:
            # At exactly twice the heartbeat, `lost` turns true at the same
            # instant the first renewal becomes due: the staleness bound is
            # `lease - heartbeat` and renewals are attempted after sleeping
            # `heartbeat`, so the holder fences itself before any renewal can
            # refresh the anchor. Three leaves room for one full round trip.
            raise KernelConfigurationError(
                "a lease must cover at least three times its heartbeat, so one renewal "
                "round trip fits inside the staleness bound"
            )
        self._store = store
        self._holder = holder
        self._epoch = epoch
        self._lease = lease_seconds
        self._heartbeat = heartbeat_seconds
        self._fenced = fenced_error
        self._monotonic = monotonic
        self._log = logger if logger is not None else _LOGGER
        self._task_name = task_name
        # Anchored *before* the claim statement, so the database-side expiry is
        # never earlier than this local bound. Reading the clock here instead
        # would start the window after the statement already took time to run,
        # and the keeper would then vouch for a lease that had partly elapsed —
        # which is the one thing this bound exists to prevent.
        self._last_renewal_started = monotonic() if claimed_at is None else claimed_at
        self._lost_reason: str | None = None
        self._task: asyncio.Task[None] | None = None

    # -- lifecycle ------------------------------------------------------------
    async def __aenter__(self) -> LeaseKeeper:
        self.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    def start(self) -> None:
        """Begin renewing. Idempotent; a second call is ignored."""
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name=self._task_name)

    async def aclose(self) -> None:
        """Stop renewing, and wait for the loop to actually be gone.

        Cancellation is suppressed here and only here: the caller is leaving the
        lease, so a cancelled renewal is the expected end of the loop and not a
        condition anyone upstream should have to handle. Awaiting the task
        matters — returning while a renewal is still in flight would let a
        statement commit after the holder believed it had stopped.
        """
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    # -- what the holder asks --------------------------------------------------
    @property
    def holder(self) -> str:
        return self._holder

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def running(self) -> bool:
        """Whether the renewal loop is still alive."""
        return self._task is not None and not self._task.done()

    @property
    def lost_reason(self) -> str | None:
        return self._lost_reason

    @property
    def lost(self) -> bool:
        if self._lost_reason is not None:
            return True
        return self._monotonic() - self._last_renewal_started >= self._lease - self._heartbeat

    def ensure_held(self) -> None:
        """Raise the host's fencing error unless the lease is still vouched for."""
        if self.lost:
            raise self._fenced(
                self._lost_reason or "the lease was not renewed within its validity"
            )

    def mark_lost(self, reason: str) -> None:
        """Record a loss observed elsewhere — a fenced write, a cancelled claim.

        A lifecycle statement that matches no row has already proved the lease is
        gone. Telling the keeper stops it from renewing a lease this process no
        longer owns, which would otherwise keep a dead holder's row alive and
        delay the next holder's recovery by a full lease.
        """
        if self._lost_reason is None:
            self._lost_reason = reason

    async def reassert(self) -> None:
        """Renew inside the caller's transaction, or raise the fencing error.

        This is the renewal that makes a fenced write safe rather than merely
        ordered: the statement row-locks the lease until the caller's transaction
        commits, so no other process can claim it between this check and the
        writes that follow it.
        """
        self.ensure_held()
        started = self._monotonic()
        renewed = await self._store.renew(self._holder, self._epoch, self._lease)
        if not renewed:
            self.mark_lost("the lease is no longer held by this process")
            raise self._fenced(f"lease {self._holder}/{self._epoch} is held by another process")
        self._last_renewal_started = started

    # -- the loop --------------------------------------------------------------
    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self._heartbeat)
            started = self._monotonic()
            try:
                renewed = await self._store.renew(self._holder, self._epoch, self._lease)
            except Exception as exc:
                # A transport failure is not evidence that the lease was taken.
                # It is left to the local bound to decide, which it will as soon
                # as the outage outlasts `lease - heartbeat`.
                self._log.warning(
                    "pass_lease_renew_failed",
                    holder=self._holder,
                    epoch=self._epoch,
                    error=type(exc).__name__,
                )
                continue
            if not renewed:
                self._lost_reason = "the lease was claimed by another holder"
                self._log.error("pass_lease_lost", holder=self._holder, epoch=self._epoch)
                return
            self._last_renewal_started = started


@asynccontextmanager
async def hold_lease(
    store: LeaseStore,
    *,
    holder: str,
    lease_seconds: float,
    heartbeat_seconds: float,
    busy_error: Callable[[LeaseState | None], Exception],
    fenced_error: type[Exception] = LeaseLost,
    monotonic: Callable[[], float] = time.monotonic,
    logger: KernelLogger | None = None,
    task_name: str = "pass-lease-keeper",
) -> AsyncIterator[LeaseKeeper]:
    """Claim the lease, keep it renewed for the body, and give it up after.

    ``busy_error`` builds the host's own refusal from whatever the store can say
    about the current holder, because "who has it, and until when" is the only
    part of that message an operator can act on. The release at the end is a
    courtesy and is allowed to fail: recovery rests on expiry, so a release that
    does not happen costs time, never correctness.
    """
    log = logger if logger is not None else _LOGGER
    # Read before the statement: the claim's own round trip counts against the
    # lease, so the bound has to start before it, not after.
    claimed_at = monotonic()
    epoch = await store.claim(holder, lease_seconds)
    if epoch is None:
        raise busy_error(await store.describe())
    keeper = LeaseKeeper(
        store,
        holder=holder,
        epoch=epoch,
        lease_seconds=lease_seconds,
        heartbeat_seconds=heartbeat_seconds,
        fenced_error=fenced_error,
        monotonic=monotonic,
        logger=logger,
        task_name=task_name,
        claimed_at=claimed_at,
    )
    try:
        async with keeper:
            yield keeper
    finally:
        try:
            await store.release(holder, epoch)
        except Exception as exc:
            log.warning("pass_lease_release_failed", holder=holder, error=type(exc).__name__)

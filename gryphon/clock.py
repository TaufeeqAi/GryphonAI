"""Injectable UTC clock.

Time is a source of truth supplied by the trusted runtime (§13). Tests inject a
fixed clock to exercise ``iat``/``nbf``/``exp`` and the ``now == exp`` boundary
(SEC-005 / INV-006). A monotonic reading is provided separately for elapsed
deadline measurement; wall-clock instants are never used to measure elapsed
time.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """A source of the current UTC instant and a monotonic reading."""

    def now(self) -> datetime:
        """Return the current timezone-aware UTC instant."""
        ...

    def monotonic(self) -> float:
        """Return a monotonic seconds reading for elapsed-time measurement."""
        ...


class SystemClock:
    """Production clock backed by the OS."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def monotonic(self) -> float:
        return time.monotonic()


@dataclass(frozen=True)
class FixedClock:
    """Deterministic clock for tests. ``monotonic`` advances only when asked."""

    instant: datetime
    mono: float = 0.0

    def __post_init__(self) -> None:
        if self.instant.tzinfo is None:
            raise ValueError("FixedClock requires a timezone-aware instant")

    def now(self) -> datetime:
        return self.instant.astimezone(timezone.utc)

    def monotonic(self) -> float:
        return self.mono


def ensure_utc(value: datetime) -> datetime:
    """Return ``value`` as UTC, rejecting naive timestamps at the boundary (§11.2)."""
    if value.tzinfo is None:
        raise ValueError("naive datetime is not permitted; timezone-aware UTC required")
    return value.astimezone(timezone.utc)

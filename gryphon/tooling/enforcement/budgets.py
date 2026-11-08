"""Aggregate budgets and a circuit breaker (CHG-010, CHG-011).

Single-process, single-gateway budgets: a host-wide concurrency ceiling, a
per-``scan_run_id`` concurrency ceiling and token-bucket request rate, and a
per-dependency circuit breaker. Over-budget fails fast (DENY), never exhausts.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from gryphon.clock import Clock
from gryphon.tooling.reasons import EnforcementDenied, ToolReasonCode
from gryphon.tooling.settings import ToolingSettings


class TokenBucket:
    def __init__(self, *, rate_per_second: float, burst: int, clock: Clock) -> None:
        self._rate = rate_per_second
        self._capacity = float(burst)
        self._tokens = float(burst)
        self._clock = clock
        self._last = clock.monotonic()

    def try_acquire(self, amount: float = 1.0) -> bool:
        now = self._clock.monotonic()
        elapsed = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        if self._tokens >= amount:
            self._tokens -= amount
            return True
        return False


class CircuitBreaker:
    def __init__(self, *, failure_threshold: int, reset_seconds: float, clock: Clock) -> None:
        self._threshold = failure_threshold
        self._reset = reset_seconds
        self._clock = clock
        self._failures: dict[str, int] = {}
        self._open_until: dict[str, float] = {}

    def allow(self, key: str) -> bool:
        until = self._open_until.get(key)
        if until is None:
            return True
        if self._clock.monotonic() >= until:
            # Half-open: clear and allow one probe.
            self._open_until.pop(key, None)
            self._failures[key] = 0
            return True
        return False

    def record_success(self, key: str) -> None:
        self._failures[key] = 0
        self._open_until.pop(key, None)

    def record_failure(self, key: str) -> None:
        count = self._failures.get(key, 0) + 1
        self._failures[key] = count
        if count >= self._threshold:
            self._open_until[key] = self._clock.monotonic() + self._reset


class BudgetManager:
    """Aggregate concurrency + rate budgets, enforced in the gateway process."""

    def __init__(self, settings: ToolingSettings, clock: Clock) -> None:
        self._clock = clock
        self._host_max = settings.max_host_concurrent_executions
        self._run_max = settings.per_run_max_concurrent
        self._rate = settings.per_run_rate_per_second
        self._burst = settings.per_run_burst
        self._host_count = 0
        self._run_counts: dict[str, int] = {}
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()
        self.breaker = CircuitBreaker(
            failure_threshold=settings.breaker_failure_threshold,
            reset_seconds=settings.breaker_reset_seconds,
            clock=clock,
        )

    @asynccontextmanager
    async def lease(self, scan_run_id: str) -> AsyncIterator[None]:
        """Acquire an aggregate budget lease or raise ``EnforcementDenied``."""
        async with self._lock:
            if self._host_count >= self._host_max:
                raise EnforcementDenied(ToolReasonCode.BUDGET_EXCEEDED, "host concurrency ceiling")
            if self._run_counts.get(scan_run_id, 0) >= self._run_max:
                raise EnforcementDenied(ToolReasonCode.BUDGET_EXCEEDED, "scan concurrency ceiling")
            bucket = self._buckets.setdefault(
                scan_run_id,
                TokenBucket(rate_per_second=self._rate, burst=self._burst, clock=self._clock),
            )
            if not bucket.try_acquire():
                raise EnforcementDenied(ToolReasonCode.BUDGET_EXCEEDED, "scan request-rate budget")
            self._host_count += 1
            self._run_counts[scan_run_id] = self._run_counts.get(scan_run_id, 0) + 1
        try:
            yield
        finally:
            async with self._lock:
                self._host_count = max(0, self._host_count - 1)
                remaining = self._run_counts.get(scan_run_id, 1) - 1
                if remaining <= 0:
                    self._run_counts.pop(scan_run_id, None)
                else:
                    self._run_counts[scan_run_id] = remaining

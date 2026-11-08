"""Aggregate concurrency/rate budgets and the circuit breaker."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from gryphon.tooling.enforcement.budgets import BudgetManager, CircuitBreaker, TokenBucket
from gryphon.tooling.reasons import EnforcementDenied, ToolReasonCode
from gryphon.tooling.settings import ToolingSettings

pytestmark = pytest.mark.unit
_NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


class MutableClock:
    def __init__(self) -> None:
        self._mono = 0.0

    def now(self) -> datetime:
        return _NOW

    def monotonic(self) -> float:
        return self._mono

    def advance(self, seconds: float) -> None:
        self._mono += seconds


def _settings(**over) -> ToolingSettings:
    base = dict(_env_file=None, environment="test")
    base.update(over)
    return ToolingSettings(**base)


def test_token_bucket_refills() -> None:
    clock = MutableClock()
    bucket = TokenBucket(rate_per_second=1.0, burst=2, clock=clock)
    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is False  # burst exhausted
    clock.advance(1.0)
    assert bucket.try_acquire() is True  # one token refilled


def test_breaker_opens_and_resets() -> None:
    clock = MutableClock()
    breaker = CircuitBreaker(failure_threshold=2, reset_seconds=10, clock=clock)
    assert breaker.allow("dep") is True
    breaker.record_failure("dep")
    breaker.record_failure("dep")
    assert breaker.allow("dep") is False  # open
    clock.advance(11.0)
    assert breaker.allow("dep") is True  # half-open after reset


@pytest.mark.asyncio
async def test_host_concurrency_ceiling() -> None:
    clock = MutableClock()
    mgr = BudgetManager(
        _settings(max_host_concurrent_executions=2, per_run_max_concurrent=10,
                  per_run_rate_per_second=1000, per_run_burst=1000),
        clock,
    )
    async with mgr.lease("run-a"):
        async with mgr.lease("run-b"):
            with pytest.raises(EnforcementDenied) as exc:
                async with mgr.lease("run-c"):
                    pass
            assert exc.value.reason_code is ToolReasonCode.BUDGET_EXCEEDED


@pytest.mark.asyncio
async def test_per_run_concurrency_ceiling() -> None:
    clock = MutableClock()
    mgr = BudgetManager(
        _settings(max_host_concurrent_executions=10, per_run_max_concurrent=1,
                  per_run_rate_per_second=1000, per_run_burst=1000),
        clock,
    )
    async with mgr.lease("run-a"):
        with pytest.raises(EnforcementDenied):
            async with mgr.lease("run-a"):
                pass


@pytest.mark.asyncio
async def test_per_run_rate_budget() -> None:
    clock = MutableClock()
    mgr = BudgetManager(
        _settings(max_host_concurrent_executions=100, per_run_max_concurrent=100,
                  per_run_rate_per_second=1.0, per_run_burst=1),
        clock,
    )
    async with mgr.lease("run-a"):
        pass
    with pytest.raises(EnforcementDenied) as exc:
        async with mgr.lease("run-a"):
            pass
    assert exc.value.reason_code is ToolReasonCode.BUDGET_EXCEEDED

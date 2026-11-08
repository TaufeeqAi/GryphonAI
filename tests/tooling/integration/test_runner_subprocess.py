"""Safe runner against a harmless local fake binary (no network).

Exercises the real subprocess path: argument-vector exec, bounded capture,
COMPLETED parsing and timeout → process-group kill. No ProjectDiscovery binary
and no target traffic are involved.
"""

from __future__ import annotations

import sys

import pytest

from gryphon.tooling.constants import ToolOutcome
from gryphon.tooling.destination.egress import EgressHandle
from gryphon.tooling.tools.runner import SafeSubprocessRunner

pytestmark = pytest.mark.integration

_IDENTITY_HANDLE = EgressHandle(context_id="t", allowlist=(), ports=(), enforcing=True)


def _write(tmp_path, name: str, body: str) -> str:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return str(path.resolve())


@pytest.mark.asyncio
async def test_completed_emits_jsonl(tmp_path) -> None:
    script = _write(
        tmp_path,
        "emit.py",
        "import json\n[print(json.dumps({'host': f'h{i}.example'})) for i in range(3)]\n",
    )
    runner = SafeSubprocessRunner(max_stdout_bytes=1 << 20)
    result = await runner.run(
        binary_path=sys.executable, argv=[script], timeout_seconds=30, egress_handle=_IDENTITY_HANDLE
    )
    assert result.outcome is ToolOutcome.COMPLETED
    assert result.exit_code == 0
    assert result.stdout.count("\n") >= 3


@pytest.mark.asyncio
async def test_nonzero_exit_is_failed(tmp_path) -> None:
    script = _write(tmp_path, "fail.py", "import sys\nsys.exit(2)\n")
    runner = SafeSubprocessRunner(max_stdout_bytes=1 << 20)
    result = await runner.run(
        binary_path=sys.executable, argv=[script], timeout_seconds=30, egress_handle=_IDENTITY_HANDLE
    )
    assert result.outcome is ToolOutcome.FAILED
    assert result.exit_code == 2


@pytest.mark.asyncio
async def test_timeout_kills_process(tmp_path) -> None:
    script = _write(tmp_path, "sleep.py", "import time\ntime.sleep(30)\n")
    runner = SafeSubprocessRunner(max_stdout_bytes=1 << 20)
    result = await runner.run(
        binary_path=sys.executable, argv=[script], timeout_seconds=1.0, egress_handle=_IDENTITY_HANDLE
    )
    assert result.outcome is ToolOutcome.TIMED_OUT


@pytest.mark.asyncio
async def test_missing_binary_is_failed() -> None:
    runner = SafeSubprocessRunner(max_stdout_bytes=1 << 20)
    result = await runner.run(
        binary_path="/nonexistent/abs/path/bin",
        argv=[],
        timeout_seconds=5,
        egress_handle=_IDENTITY_HANDLE,
    )
    assert result.outcome is ToolOutcome.FAILED

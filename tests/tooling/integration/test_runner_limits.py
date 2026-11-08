"""Child-process resource bounds: memory ceiling and process-tree kill.

Both controls are POSIX-only and are skipped elsewhere. They use harmless local
Python stubs — no ProjectDiscovery binary and no network traffic.
"""

from __future__ import annotations

import asyncio
import os
import sys

import pytest

from gryphon.tooling.constants import ToolOutcome
from gryphon.tooling.destination.egress import EgressHandle
from gryphon.tooling.tools.runner import SafeSubprocessRunner

pytestmark = pytest.mark.integration

requires_posix = pytest.mark.skipif(
    os.name != "posix", reason="rlimit and process-group kill are POSIX-only"
)

_IDENTITY_HANDLE = EgressHandle(context_id="t", allowlist=(), ports=(), enforcing=True)


def _write(tmp_path, name: str, body: str) -> str:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return str(path.resolve())


def test_memory_limit_is_only_claimed_when_it_can_be_applied() -> None:
    runner = SafeSubprocessRunner(max_stdout_bytes=1 << 20, memory_limit_mb=64)
    assert runner.memory_limit_enforced is (os.name == "posix")
    # No configured limit must never report as enforced.
    assert SafeSubprocessRunner(max_stdout_bytes=1 << 20).memory_limit_enforced is False


@requires_posix
@pytest.mark.asyncio
async def test_memory_hog_is_killed_by_the_rlimit(tmp_path) -> None:
    script = _write(
        tmp_path,
        "hog.py",
        # Well above the 64 MiB ceiling below; allocation must fail.
        "buf = bytearray(512 * 1024 * 1024)\nprint(len(buf))\n",
    )
    runner = SafeSubprocessRunner(max_stdout_bytes=1 << 20, memory_limit_mb=64)
    result = await runner.run(
        binary_path=sys.executable,
        argv=[script],
        timeout_seconds=30,
        egress_handle=_IDENTITY_HANDLE,
    )
    assert result.outcome is ToolOutcome.FAILED
    assert result.exit_code not in (0, None)
    assert "512" not in result.stdout


@requires_posix
@pytest.mark.asyncio
async def test_a_generous_limit_does_not_break_a_normal_tool(tmp_path) -> None:
    script = _write(tmp_path, "ok.py", "buf = bytearray(8 * 1024 * 1024)\nprint('ok')\n")
    runner = SafeSubprocessRunner(max_stdout_bytes=1 << 20, memory_limit_mb=512)
    result = await runner.run(
        binary_path=sys.executable,
        argv=[script],
        timeout_seconds=30,
        egress_handle=_IDENTITY_HANDLE,
    )
    assert result.outcome is ToolOutcome.COMPLETED
    assert "ok" in result.stdout


@requires_posix
@pytest.mark.asyncio
async def test_timeout_kills_the_whole_process_tree(tmp_path) -> None:
    """A tool that spawns helpers must not leave them running after a timeout."""
    pidfile = tmp_path / "grandchild.pid"
    script = _write(
        tmp_path,
        "spawner.py",
        "import subprocess, sys, time, pathlib\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
        f"pathlib.Path({str(pidfile)!r}).write_text(str(child.pid))\n"
        "time.sleep(120)\n",
    )
    runner = SafeSubprocessRunner(max_stdout_bytes=1 << 20)
    result = await runner.run(
        binary_path=sys.executable,
        argv=[script],
        timeout_seconds=2.5,
        egress_handle=_IDENTITY_HANDLE,
    )
    assert result.outcome is ToolOutcome.TIMED_OUT

    grandchild = int(pidfile.read_text())
    for _ in range(50):  # the group signal is asynchronous; allow it to land
        try:
            os.kill(grandchild, 0)
        except (ProcessLookupError, PermissionError):
            break
        await asyncio.sleep(0.1)
    else:
        pytest.fail(f"grandchild {grandchild} survived the timeout kill")

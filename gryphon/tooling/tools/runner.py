"""Safe subprocess runner.

Executes a pinned binary with an argument vector (never a shell), inside the
egress context, under a hard deadline, in its own process group so timeouts kill
the whole tree, with bounded streaming capture. The binary is resolved from an
absolute manifest path, never ambient ``PATH``.
"""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
from dataclasses import dataclass
from functools import partial
from pathlib import Path

try:  # POSIX only; absent on Windows, where these limits cannot be applied.
    import resource
except ImportError:  # pragma: no cover - Windows
    resource = None  # type: ignore[assignment]

from gryphon.logging_config import get_logger
from gryphon.tooling.constants import ToolOutcome
from gryphon.tooling.destination.egress import EgressHandle

logger = get_logger(__name__)

_IS_POSIX = os.name == "posix"


@dataclass(frozen=True)
class RunResult:
    outcome: ToolOutcome  # COMPLETED | TIMED_OUT | FAILED
    exit_code: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool


async def _read_capped(stream: asyncio.StreamReader | None, cap: int) -> tuple[bytes, bool]:
    if stream is None:
        return b"", False
    buf = bytearray()
    truncated = False
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        if len(buf) < cap:
            buf.extend(chunk[: cap - len(buf)])
            if len(buf) >= cap:
                truncated = True
        else:
            truncated = True
    return bytes(buf), truncated


def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    try:
        if _IS_POSIX:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:  # pragma: no cover - Windows path
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _preexec(memory_limit_bytes: int | None) -> None:  # pragma: no cover - POSIX child
    """Child-side hardening, applied between fork and exec.

    * New session/process group, so a timeout kills the whole tree rather than
      only the tool and leaves its helpers running.
    * Address-space ceiling, so a runaway tool cannot exhaust host memory. Time,
      stdout and record count are already bounded by the caller.
    * No core dumps: a core of a scanner may contain target data and secrets.
    """
    os.setsid()
    if resource is None:
        return
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if memory_limit_bytes:
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit_bytes, memory_limit_bytes))
    except (ValueError, OSError):
        # A limit we cannot set must not silently become "no limit": the parent
        # treats a failed exec as a FAILED outcome.
        os._exit(126)


class SafeSubprocessRunner:
    def __init__(self, *, max_stdout_bytes: int, memory_limit_mb: int | None = None) -> None:
        self._max_stdout = max_stdout_bytes
        self._memory_limit_bytes = (memory_limit_mb * 1024 * 1024) if memory_limit_mb else None

    @property
    def memory_limit_enforced(self) -> bool:
        """True when a memory ceiling will actually be applied to children."""
        return bool(_IS_POSIX and resource is not None and self._memory_limit_bytes)

    async def run(
        self,
        *,
        binary_path: str,
        argv: list[str],
        timeout_seconds: float,
        egress_handle: EgressHandle,
    ) -> RunResult:
        path = Path(binary_path)
        if not path.is_absolute() or not path.exists():
            logger.error("binary_not_resolved", binary_path=binary_path)
            return RunResult(ToolOutcome.FAILED, None, "", "binary not found at manifest path", False)

        full_argv = egress_handle.wrap_argv([str(path), *argv])

        popen_kwargs: dict = {
            "stdout": asyncio.subprocess.PIPE,
            "stderr": asyncio.subprocess.PIPE,
            "stdin": asyncio.subprocess.DEVNULL,
        }
        if _IS_POSIX:
            popen_kwargs["preexec_fn"] = partial(_preexec, self._memory_limit_bytes)
        else:  # pragma: no cover - Windows path
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            proc = await asyncio.create_subprocess_exec(*full_argv, **popen_kwargs)
        except (OSError, ValueError) as exc:
            logger.error("subprocess_spawn_failed", error=str(exc))
            return RunResult(ToolOutcome.FAILED, None, "", f"spawn failed: {exc}", False)

        stdout_task = asyncio.ensure_future(_read_capped(proc.stdout, self._max_stdout))
        stderr_task = asyncio.ensure_future(_read_capped(proc.stderr, 64 * 1024))
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            _kill_tree(proc)
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:  # pragma: no cover
                pass
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            logger.warning("subprocess_timeout", binary=path.name, timeout=timeout_seconds)
            return RunResult(ToolOutcome.TIMED_OUT, None, "", "timed out", False)

        stdout_bytes, truncated = await stdout_task
        stderr_bytes, _ = await stderr_task
        exit_code = proc.returncode
        outcome = ToolOutcome.COMPLETED if exit_code == 0 else ToolOutcome.FAILED
        return RunResult(
            outcome=outcome,
            exit_code=exit_code,
            stdout=stdout_bytes.decode("utf-8", errors="ignore"),
            stderr=stderr_bytes.decode("utf-8", errors="ignore")[:4096],
            stdout_truncated=truncated,
        )

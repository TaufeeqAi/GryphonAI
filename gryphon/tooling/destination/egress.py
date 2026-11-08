"""OS egress containment.

An execution runs inside a context whose egress is **default-deny** with an
allowlist of exactly the pinned addresses. If a real enforcing context cannot be
established, execution MUST NOT proceed (fail closed).

Three implementers:

* ``LinuxNamespaceEgressEnforcer`` — the production control. Creates a
  per-execution Linux network namespace and programs an nftables default-deny
  egress allowlist (see :mod:`gryphon.tooling.destination.netns`). Requires
  Linux plus either ``CAP_NET_ADMIN`` in this process or a configured privileged
  helper. If prerequisites are absent, or if any step of the setup fails, or if
  the ruleset does not read back with a drop policy, it raises
  ``EgressUnavailableError`` — it never silently degrades.
* ``NullEgressEnforcer`` — enforces nothing. Permitted only under the explicit
  ``unenforced`` posture (single-tenant/dev); never selected in production.
* a test ``FakeEgressEnforcer`` (in the test suite) establishes successfully to
  exercise the allow path without privileges.

The handle wraps the child argument vector so the subprocess launches inside the
context; it never manipulates the parent process network state.
"""

from __future__ import annotations

import os
import platform
import uuid
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from gryphon.logging_config import get_logger
from gryphon.tooling.constants import EgressMode
from gryphon.tooling.destination.netns import (
    COUNTER_DROPPED,
    NETNS_PREFIX,
    AddressPool,
    DirectNetnsProvisioner,
    HelperNetnsProvisioner,
    NamespacePlan,
    NetnsProvisioner,
    plan_for,
    reap_stale_namespaces,
    split_allowlist,
    tooling_available,
)
from gryphon.tooling.reasons import EgressUnavailableError
from gryphon.tooling.settings import ToolingSettings

logger = get_logger(__name__)


@dataclass(frozen=True)
class EgressHandle:
    """A live egress context. ``wrap_argv`` prefixes the child command."""

    context_id: str
    allowlist: tuple[str, ...]
    ports: tuple[int, ...]
    enforcing: bool
    _argv_prefix: tuple[str, ...] = ()
    _teardown: tuple[str, ...] | None = field(default=None, repr=False)

    def wrap_argv(self, argv: list[str]) -> list[str]:
        return [*self._argv_prefix, *argv]


@runtime_checkable
class EgressEnforcer(Protocol):
    @property
    def enforcing(self) -> bool: ...

    async def establish(self, allowlist: list[str], ports: list[int]) -> EgressHandle: ...

    async def teardown(self, handle: EgressHandle) -> None: ...


class NullEgressEnforcer:
    """Enforces nothing. Only valid under the ``unenforced`` posture."""

    enforcing = False

    async def establish(self, allowlist: list[str], ports: list[int]) -> EgressHandle:
        logger.warning("egress_unenforced", allowlist=allowlist[:4])
        return EgressHandle(
            context_id=f"null-{uuid.uuid4().hex[:8]}",
            allowlist=tuple(allowlist),
            ports=tuple(ports),
            enforcing=False,
        )

    async def teardown(self, handle: EgressHandle) -> None:
        return None


class LinuxNamespaceEgressEnforcer:
    """Production egress control via a per-execution network namespace + nftables.

    Capability-gated and fail-closed. The privileged work is delegated to a
    :class:`~gryphon.tooling.destination.netns.NetnsProvisioner`: in-process when
    this process holds ``CAP_NET_ADMIN``, otherwise to a narrow external helper.
    """

    enforcing = True

    def __init__(
        self,
        provisioner: NetnsProvisioner | None = None,
        *,
        helper_path: str | None = None,
        pool: AddressPool | None = None,
    ) -> None:
        self._helper_path = helper_path
        self._capable, self._incapable_reason = self._probe_capability(helper_path)
        self._pool = pool or AddressPool()
        self._live: dict[str, tuple[NamespacePlan, int]] = {}
        if provisioner is not None:
            self._provisioner: NetnsProvisioner | None = provisioner
        elif not self._capable:
            self._provisioner = None
        elif helper_path:
            self._provisioner = HelperNetnsProvisioner(helper_path)
        else:
            self._provisioner = DirectNetnsProvisioner()

    @staticmethod
    def _probe_capability(helper_path: str | None) -> tuple[bool, str]:
        """Return (capable, reason-if-not). Checks the host, never the ruleset."""
        if platform.system() != "Linux":
            return False, f"{platform.system()} has no network namespaces or nftables"
        if helper_path:
            if not os.path.isfile(helper_path):
                return False, f"egress helper not found at {helper_path}"
            if not os.access(helper_path, os.X_OK):
                return False, f"egress helper at {helper_path} is not executable"
            return True, ""
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            return False, "process lacks CAP_NET_ADMIN and no egress helper is configured"
        if not tooling_available():
            return False, "the ip and/or nft binaries are not on PATH"
        return True, ""

    @property
    def capable(self) -> bool:
        """Whether this host can establish a context at all (no side effects)."""
        return self._capable

    async def reap(self) -> list[str]:
        """Delete namespaces leaked by an earlier crash. Safe at startup."""
        if not self._capable or self._provisioner is None:
            return []
        return await reap_stale_namespaces(self._provisioner)

    async def establish(self, allowlist: list[str], ports: list[int]) -> EgressHandle:
        if not self._capable or self._provisioner is None:
            raise EgressUnavailableError(self._incapable_reason or "egress context unavailable")

        allowlist_v4, unsupported = split_allowlist(allowlist)
        if not allowlist_v4:
            # Never establish a context that cannot reach the pinned destination:
            # that would be an execution contained into a dead end.
            raise EgressUnavailableError(
                "no IPv4 destination among the pinned addresses "
                f"({len(unsupported)} non-IPv4 cannot be contained)"
            )

        index = await self._pool.acquire()
        namespace = f"{NETNS_PREFIX}{uuid.uuid4().hex[:12]}"
        plan = plan_for(index, namespace)
        try:
            await self._provisioner.prepare_host()
            await self._provisioner.setup(plan, allowlist_v4, ports)
        except EgressUnavailableError:
            await self._provisioner.teardown(plan)
            await self._pool.release(index)
            raise
        except Exception as exc:  # pragma: no cover - defensive: still fail closed
            await self._provisioner.teardown(plan)
            await self._pool.release(index)
            raise EgressUnavailableError(f"egress setup failed: {type(exc).__name__}") from exc

        self._live[namespace] = (plan, index)
        logger.info(
            "egress_context_established",
            context_id=namespace,
            allowlisted=len(allowlist_v4),
            uncontainable_skipped=len(unsupported),
            ports=sorted(set(ports)) or "any",
        )
        return EgressHandle(
            context_id=namespace,
            allowlist=tuple(allowlist_v4),
            ports=tuple(ports),
            enforcing=True,
            _argv_prefix=plan.argv_prefix,
            _teardown=("ip", "netns", "delete", namespace),
        )

    async def counters(self, handle: EgressHandle) -> dict[str, int]:
        """Packets accepted and dropped by this context's ruleset.

        A rising ``dropped`` count is a tool attempting to reach something
        outside its pinned destinations — worth surfacing, not just blocking.
        """
        entry = self._live.get(handle.context_id)
        if entry is None or self._provisioner is None:
            return {}
        plan, _ = entry
        try:
            return await self._provisioner.counters(plan)
        except EgressUnavailableError:
            return {}

    async def teardown(self, handle: EgressHandle) -> None:
        entry = self._live.pop(handle.context_id, None)
        if entry is None or self._provisioner is None:
            return
        plan, index = entry
        dropped = 0
        try:
            dropped = (await self._provisioner.counters(plan)).get(COUNTER_DROPPED, 0)
        except EgressUnavailableError:  # pragma: no cover - best effort
            pass
        try:
            await self._provisioner.teardown(plan)
        finally:
            await self._pool.release(index)
        logger.info(
            "egress_context_torn_down",
            context_id=handle.context_id,
            packets_dropped=dropped,
        )


def build_egress_enforcer(settings: ToolingSettings) -> EgressEnforcer:
    """Select the egress enforcer for the configured posture (fail closed)."""
    if settings.egress_mode is EgressMode.UNENFORCED:
        # Validated by settings: only reachable outside prod with explicit opt-in.
        return NullEgressEnforcer()
    return LinuxNamespaceEgressEnforcer(helper_path=settings.egress_helper_path)

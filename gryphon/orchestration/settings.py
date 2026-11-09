"""Fail-closed configuration for the orchestration layer.

Every bound here is finite and tested. Where a value needs measurement before
it can be defended, the default is marked `TO BE MEASURED` in the comment and
the rationale for the starting point is stated — rather than a magic constant
appearing in code with no provenance.

Security rules enforced at startup (not at scan time):

* Third-party tracing/telemetry is refused. The orchestrator holds the live
  authorization in memory and its dependency closure contains an HTTP/WebSocket
  telemetry client, so an inherited environment variable must not be able to
  export scan state. Startup fails if one is set.
* A non-loopback control socket is refused; the invocation surface is local.
* In ``prod`` the control socket must be a Unix domain socket with a peer-uid
  allowlist, and egress containment must be enforced.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Final, Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from gryphon.orchestration.constants import (
    MAX_DISCOVERED_TARGETS,
    MAX_GRAPH_STATE_BYTES,
)
from gryphon.orchestration.reasons import OrchestrationConfigurationError

#: Environment variables that enable third-party tracing in this dependency
#: closure. Any of these being set is a startup failure: the traced payloads are
#: node inputs and outputs, i.e. client hostnames, discovered attack surface and
#: findings, leaving the process that holds the permit.
TELEMETRY_ENV_VARS: Final[tuple[str, ...]] = (
    "LANGSMITH_TRACING",
    "LANGSMITH_TRACING_V2",
    "LANGSMITH_API_KEY",
    "LANGSMITH_ENDPOINT",
    "LANGCHAIN_TRACING",
    "LANGCHAIN_TRACING_V2",
    "LANGCHAIN_API_KEY",
    "LANGCHAIN_ENDPOINT",
)

#: Values of a tracing variable that we treat as "off" and therefore tolerate.
_TELEMETRY_OFF_VALUES: Final[frozenset[str]] = frozenset({"", "0", "false", "no", "off"})


def assert_telemetry_disabled(env: dict[str, str] | None = None) -> None:
    """Refuse to start if third-party tracing could be active.

    A key variable set to a falsy value is tolerated; an endpoint or API key is
    not, because those are only meaningful when exporting.
    """
    source = os.environ if env is None else env
    offenders: list[str] = []
    for name in TELEMETRY_ENV_VARS:
        if name not in source:
            continue
        value = str(source[name]).strip().lower()
        if name.endswith(("_API_KEY", "_ENDPOINT")):
            if value:
                offenders.append(name)
        elif value not in _TELEMETRY_OFF_VALUES:
            offenders.append(name)
    if offenders:
        raise OrchestrationConfigurationError(
            "third-party tracing must be disabled in the orchestration process; "
            f"unset: {', '.join(sorted(offenders))}"
        )


def neutralize_telemetry() -> None:
    """Disable the tracing client programmatically, before the graph is built.

    Belt-and-braces with :func:`assert_telemetry_disabled`: the assertion
    catches an inherited environment, this prevents a library default from
    opting in. Safe to call repeatedly.
    """
    os.environ["LANGSMITH_TRACING"] = "false"
    os.environ["LANGCHAIN_TRACING_V2"] = "false"
    # The SDK consults this before any network path.
    os.environ.setdefault("LANGCHAIN_TRACING", "false")


class OrchestrationSettings(BaseSettings):
    """Typed, frozen configuration for the orchestration layer."""

    model_config = SettingsConfigDict(
        env_prefix="GRYPHON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    environment: Literal["dev", "test", "prod"] = "dev"

    # -- lease / recovery -----------------------------------------------------
    # TO BE MEASURED. Starting point: a lease an order of magnitude longer than
    # the heartbeat tolerates a stalled event loop without a false takeover,
    # while keeping the worst-case reclaim delay under a minute.
    scan_lease_seconds: float = Field(default=60.0, gt=0, le=3600.0)
    scan_heartbeat_seconds: float = Field(default=15.0, gt=0, le=600.0)
    #: How often the recovery sweeper looks for abandoned or stale work.
    sweeper_interval_seconds: float = Field(default=30.0, gt=0, le=3600.0)
    #: Bound on how long an indeterminate outcome may stay indeterminate before
    #: it is terminally classified as possibly-contacted. TO BE MEASURED against
    #: the longest tool hard deadline (currently 300s for the scan step).
    reconciliation_window_seconds: float = Field(default=900.0, gt=0, le=86_400.0)

    # -- deadlines ------------------------------------------------------------
    #: Operator-configured ceiling on total scan wall time. The *effective*
    #: deadline is min(this, grant expiry - per-item tool deadline); the grant
    #: always wins.
    scan_deadline_seconds: float = Field(default=6 * 3600.0, gt=0, le=30 * 86_400.0)

    # -- budgets --------------------------------------------------------------
    #: Bounded retries of one plan item. A retry reuses the stored execution id.
    max_attempts_per_item: int = Field(default=2, ge=1, le=10)
    #: Global ceiling on enforcement-layer decisions (each one costs a signed
    #: audit row), so a flapping target cannot flood the append-only audit.
    max_decisions_per_scan: int = Field(default=20_000, ge=1)
    #: After a saturation or breaker-open outcome, stop issuing calls for this
    #: long rather than retrying into a wall.
    breaker_cooldown_seconds: float = Field(default=60.0, gt=0, le=3600.0)
    #: Concurrent in-flight dispatches within one step. Subordinate to the
    #: enforcement layer's own aggregate budgets, which remain authoritative.
    max_step_concurrency: int = Field(default=4, ge=1, le=64)

    # -- target admission -----------------------------------------------------
    #: Above this many discovered targets the scan halts for operator review
    #: instead of fanning out silently.
    discovered_target_cap: int = Field(default=2_000, ge=1, le=MAX_DISCOVERED_TARGETS)
    #: Operator-confirmed estate: CIDRs/addresses a discovered name may resolve
    #: into and still be actively scanned. Empty means "attestation
    #: unconfigured": discovered targets are then admitted for passive stages
    #: only, and active scanning of them is refused.
    attested_estate_cidrs: tuple[str, ...] = ()
    #: When true, a discovered name that resolves outside the attested estate is
    #: excluded rather than passively scanned. Never relaxed in ``prod``.
    strict_address_attestation: bool = True

    # -- state bounds ---------------------------------------------------------
    max_graph_state_bytes: int = Field(default=MAX_GRAPH_STATE_BYTES, ge=1024)

    # -- coverage -------------------------------------------------------------
    #: Covered-fraction below which a finished scan is FAILED rather than
    #: COMPLETED_WITH_GAPS. TO BE MEASURED; 0.5 is a deliberately conservative
    #: starting point that treats "most of the scan did not happen" as failure.
    coverage_failure_floor: float = Field(default=0.5, ge=0.0, le=1.0)

    # -- invocation surface ---------------------------------------------------
    #: Unix-domain control socket for the operator command boundary. Required in
    #: ``prod``; the CLI path is permitted elsewhere.
    control_socket_path: str | None = None
    #: Peer uids permitted to invoke. Empty with a socket configured is a
    #: configuration error: an unauthenticated caller must never be admitted.
    control_allowed_uids: tuple[int, ...] = ()

    # -- egress ---------------------------------------------------------------
    #: Require that the control plane itself runs under a default-deny egress
    #: policy (database only). Enforced by deployment; asserted at readiness.
    require_control_plane_egress_deny: bool = True

    @model_validator(mode="after")
    def _validate(self) -> "OrchestrationSettings":
        if self.scan_heartbeat_seconds >= self.scan_lease_seconds:
            raise OrchestrationConfigurationError(
                "scan_heartbeat_seconds must be shorter than scan_lease_seconds, "
                "or a live owner will lose its own lease"
            )
        # A lease must outlive at least two heartbeats, else a single missed
        # beat hands the scan to a second owner while the first is still live.
        if self.scan_lease_seconds < 2 * self.scan_heartbeat_seconds:
            raise OrchestrationConfigurationError(
                "scan_lease_seconds must be at least twice scan_heartbeat_seconds"
            )
        if self.sweeper_interval_seconds > self.scan_lease_seconds:
            raise OrchestrationConfigurationError(
                "sweeper_interval_seconds must not exceed scan_lease_seconds, "
                "or abandoned work outlives its lease unobserved"
            )
        prod = self.environment == "prod"
        if prod:
            if not self.control_socket_path:
                raise OrchestrationConfigurationError(
                    "control_socket_path is required in prod: the invocation "
                    "surface must authenticate its caller"
                )
            if not self.strict_address_attestation:
                raise OrchestrationConfigurationError(
                    "strict_address_attestation cannot be disabled in prod"
                )
            if not self.attested_estate_cidrs:
                raise OrchestrationConfigurationError(
                    "attested_estate_cidrs is required in prod: active scanning "
                    "of a discovered target requires an attested address"
                )
        if self.control_socket_path and not self.control_allowed_uids:
            raise OrchestrationConfigurationError(
                "control_allowed_uids must be non-empty when a control socket is "
                "configured; an unauthenticated caller is never admitted"
            )
        return self


@lru_cache(maxsize=1)
def get_orchestration_settings() -> OrchestrationSettings:
    """Load and cache settings, refusing to start with telemetry enabled."""
    assert_telemetry_disabled()
    return OrchestrationSettings()

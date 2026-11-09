"""Target admission — attestation between name scope and address containment.

This step exists because of a seam only this layer spans. Authorization is
granted over **names** (often a wildcard like ``*.client.example``), while
containment is enforced over **addresses** (the destination guard resolves and
pins, and the egress allowlist is an address list). Those are different things,
and a hostile or merely neglected DNS record is where they come apart:

    A dangling or hijacked subdomain under an authorized wildcard is in scope
    *by name* while resolving to an address somebody else owns. Every control
    behaves exactly as specified — the name matches the grant, the destination
    is pinned, the intent is committed, the audit is signed — and the traffic
    goes to a stranger.

So admitted-by-name is not sufficient for active scanning: the resolved address
must also attest to the estate the client actually agreed to. This is
*attestation*, not policy. It never widens what the grant allows and it never
re-decides scope — it only refuses to act on a name whose address cannot be
accounted for.

Admission also runs **before** planning the active stages, which matters for
honesty as much as safety: if out-of-scope discoveries were planned and then
denied call-by-call, they would sit in the coverage denominator and make every
real scan look full of gaps. Excluded targets are reported separately and are
never counted against coverage.

The count cap is the other half. Discovery output is attacker-influenceable: a
wildcard DNS record can return tens of thousands of names. Above the configured
cap the scan halts for an operator decision rather than quietly fanning out and
burning the authorization window.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime

from gryphon.auth.scope import ScopeEntry, ScopeResult, canonicalize_target, evaluate
from gryphon.clock import ensure_utc
from gryphon.errors import ScopeEvaluationError
from gryphon.logging_config import get_logger
from gryphon.orchestration.constants import ExclusionReason
from gryphon.tooling.destination.resolver import Resolver

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class AdmittedTarget:
    """A discovered target cleared for active scanning, with its provenance."""

    canonical_target: str
    addresses: tuple[str, ...]
    #: Why this target is being scanned: which tool found it, from which seed,
    #: when, and what its address was attested against. The chain of custody.
    provenance: dict[str, object]


@dataclass(frozen=True, slots=True)
class ExcludedTarget:
    """A discovered target refused, and why."""

    canonical_target: str
    reason: ExclusionReason
    detail: str = ""


@dataclass(frozen=True, slots=True)
class AdmissionResult:
    """The outcome of one admission pass."""

    admitted: tuple[AdmittedTarget, ...]
    excluded: tuple[ExcludedTarget, ...]
    #: True when the discovered count exceeded the cap: the scan must stop for
    #: an operator decision rather than proceed with an arbitrary subset.
    halted_for_review: bool = False
    discovered_count: int = 0
    attestation_configured: bool = True

    @property
    def exclusion_histogram(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.excluded:
            counts[item.reason.value] = counts.get(item.reason.value, 0) + 1
        return counts


class TargetAdmission:
    """Caps, attests and records provenance for discovered targets."""

    def __init__(
        self,
        *,
        resolver: Resolver,
        attested_estate_cidrs: tuple[str, ...],
        discovered_target_cap: int,
        strict_address_attestation: bool,
    ) -> None:
        self._resolver = resolver
        self._cap = discovered_target_cap
        self._strict = strict_address_attestation
        self._estate = _parse_estate(attested_estate_cidrs)

    @property
    def attestation_configured(self) -> bool:
        """Whether an estate was configured to attest against.

        With no estate configured there is nothing to check an address against,
        so in strict mode every discovered target is refused for active
        scanning. Failing closed here is deliberate: silently admitting
        everything would make the control look present while doing nothing.
        """
        return bool(self._estate)

    async def admit(
        self,
        *,
        discovered: list[str],
        seed_target: str,
        discovered_by: str,
        scope_entries: tuple[ScopeEntry, ...],
        now: datetime,
    ) -> AdmissionResult:
        """Admit discovered targets for active scanning, or refuse them."""
        instant = ensure_utc(now)
        unique = _dedupe(discovered)
        discovered_count = len(unique)

        if discovered_count > self._cap:
            logger.warning(
                "target_admission_cap_exceeded",
                discovered=discovered_count,
                cap=self._cap,
                seed_target=seed_target,
            )
            return AdmissionResult(
                admitted=(),
                excluded=(),
                halted_for_review=True,
                discovered_count=discovered_count,
                attestation_configured=self.attestation_configured,
            )

        admitted: list[AdmittedTarget] = []
        excluded: list[ExcludedTarget] = []

        for raw in unique:
            # 1. Canonicalize with the authorization layer's own policy. Reused,
            #    never reimplemented: a second canonicalizer would be a second
            #    opinion about what a target *is*.
            try:
                canonical = canonicalize_target(raw)
            except ScopeEvaluationError as exc:
                excluded.append(
                    ExcludedTarget(raw, ExclusionReason.INVALID, exc.reason_code.value)
                )
                continue

            # 2. Must still be inside the granted scope by name. Discovery can
            #    return anything; a wildcard grant does not cover the internet.
            decision = evaluate(scope_entries, canonical, None)
            if decision.result is not ScopeResult.MATCH:
                excluded.append(
                    ExcludedTarget(
                        canonical.text,
                        ExclusionReason.INVALID,
                        f"scope {decision.result.value}",
                    )
                )
                continue

            # 3. Resolve, then attest the ADDRESS against the agreed estate.
            try:
                resolved = await self._resolver.resolve(canonical.text)
            except Exception as exc:  # resolution failure is not a scan result
                excluded.append(
                    ExcludedTarget(
                        canonical.text,
                        ExclusionReason.UNRESOLVABLE,
                        type(exc).__name__,
                    )
                )
                continue
            if not resolved:
                excluded.append(
                    ExcludedTarget(
                        canonical.text, ExclusionReason.UNRESOLVABLE, "no address"
                    )
                )
                continue

            addresses = tuple(str(addr) for addr in resolved)
            attested, unattested = self._partition_by_estate(resolved)

            if self._strict and unattested:
                # Any address outside the estate disqualifies the name: a
                # round-robin record that mixes an in-estate and an out-of-estate
                # address would otherwise let traffic reach the stranger.
                excluded.append(
                    ExcludedTarget(
                        canonical.text,
                        ExclusionReason.ADDRESS_UNATTESTED,
                        f"outside estate: {','.join(unattested)}",
                    )
                )
                continue

            admitted.append(
                AdmittedTarget(
                    canonical_target=canonical.text,
                    addresses=addresses,
                    provenance={
                        "discovered_by": discovered_by,
                        "seed_target": seed_target,
                        "discovered_at": instant.isoformat(),
                        "resolved_addresses": list(addresses),
                        "attested_addresses": attested,
                        "attested_against": [str(net) for net in self._estate],
                        "attestation_configured": self.attestation_configured,
                    },
                )
            )

        logger.info(
            "target_admission_complete",
            seed_target=seed_target,
            discovered=discovered_count,
            admitted=len(admitted),
            excluded=len(excluded),
        )
        return AdmissionResult(
            admitted=tuple(admitted),
            excluded=tuple(excluded),
            halted_for_review=False,
            discovered_count=discovered_count,
            attestation_configured=self.attestation_configured,
        )

    def _partition_by_estate(
        self, addresses: list[ipaddress._BaseAddress]
    ) -> tuple[list[str], list[str]]:
        """Split resolved addresses into attested and unattested."""
        if not self._estate:
            # Nothing to attest against: every address is unattested, which in
            # strict mode refuses the target rather than pretending to check.
            return [], [str(a) for a in addresses]
        attested: list[str] = []
        unattested: list[str] = []
        for addr in addresses:
            if any(addr in net for net in self._estate):
                attested.append(str(addr))
            else:
                unattested.append(str(addr))
        return attested, unattested


def _parse_estate(cidrs: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse the operator-confirmed estate, rejecting malformed entries loudly."""
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in cidrs:
        text = raw.strip()
        if not text:
            continue
        nets.append(ipaddress.ip_network(text, strict=False))
    return tuple(nets)


def _dedupe(values: list[str]) -> list[str]:
    """Stable de-duplication. Order is preserved so planning is deterministic.

    Deterministic ordering is not cosmetic here: plan item sequence numbers feed
    the execution identity, so an unstable order would change identities between
    runs and turn a re-walked step into a second real scan.
    """
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        key = value.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(value.strip())
    return out

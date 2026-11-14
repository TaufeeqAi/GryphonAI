"""Planning observations: pure, deterministic, and identical on resume.

The planner turns verified findings plus a pinned registry into the exact set of
requests a pass will make. It performs no I/O and reaches no authorization
decision — the gateway owns that — so the whole plan can be computed, inspected
and tested before anything touches a network.

Determinism is a safety property here, not a convenience. A resumed pass must
produce byte-identical envelopes and therefore identical ``execution_id`` values;
that is what lets it present the same identity and receive the recorded
observation instead of contacting the target a second time. Any nondeterminism
in this module — a set iteration order, a timestamp, an unsorted mapping —
becomes duplicate traffic against a client's estate.

Control locators are derived from the pass's secret salt rather than chosen at
random for the same reason, and for one more: a control asks for something that
should not exist, and a predictable locator is one a host could special-case to
look clean.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

from gryphon.tooling.observation.envelope import (
    EnvelopeError,
    RequestEnvelope,
    dns_envelope,
    http_envelope,
)
from gryphon.verification.constants import (
    SELF_CONTROLLING_STRATEGIES,
    ClaimScope,
    ControlStrategy,
    Justification,
    ObservationKind,
    ObservationRole,
    Severity,
)
from gryphon.verification.identity import (
    control_locator,
    execution_id,
    observation_id,
    subject_key,
)
from gryphon.verification.registry import Finding, Unsupported, VerifierRegistry
from gryphon.verification.spec import VerifierSpec

#: Extensions a sibling control keeps, so the control asks for the same *kind*
#: of thing as the subject. A host that serves .env differently from .txt is
#: common; comparing across that difference would measure the wrong thing.
_KEEP_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {".env", ".json", ".yml", ".yaml", ".ini", ".conf", ".cfg", ".xml", ".txt", ".bak"}
)
_MAX_PATH_BYTES: Final[int] = 1024


@dataclass(frozen=True, slots=True)
class PlannedObservation:
    """One request the pass intends to make."""

    observation_id: str
    execution_id: str
    envelope: RequestEnvelope
    role: ObservationRole
    control_index: int
    finding_id: str
    verifier_id: str


@dataclass(frozen=True, slots=True)
class PlannedFinding:
    """A finding with its verifier and the requests it needs — or why not."""

    finding: Finding
    subject_key: str
    spec: VerifierSpec | None
    unsupported: Unsupported | None
    primary: PlannedObservation | None
    controls: tuple[PlannedObservation, ...]
    #: Ordering weight; higher is observed first when a budget is tight.
    rank: tuple[int, str]

    @property
    def observations(self) -> tuple[PlannedObservation, ...]:
        if self.primary is None:
            return ()
        return (self.primary, *self.controls)


@dataclass(frozen=True, slots=True)
class Plan:
    """Everything a pass will do, decided before it does any of it."""

    findings: tuple[PlannedFinding, ...]

    @property
    def observation_count(self) -> int:
        return sum(len(f.observations) for f in self.findings)

    @property
    def dispatchable(self) -> tuple[PlannedFinding, ...]:
        return tuple(f for f in self.findings if f.primary is not None)


class ObservationPlanner:
    """Builds the plan. Pure; every input is explicit."""

    def __init__(
        self,
        *,
        registry: VerifierRegistry,
        descriptor_versions: dict[str, str],
        extractor_set_digest: str,
        resolver_set_digest: str,
    ) -> None:
        self._registry = registry
        self._descriptors = descriptor_versions
        self._extractor_digest = extractor_set_digest
        self._resolver_digest = resolver_set_digest

    def plan(
        self,
        findings: Iterable[Finding],
        *,
        pass_salt: bytes,
        pass_id: str,
        priorities: dict[str, str] | None = None,
    ) -> Plan:
        """Plan every finding, in a deterministic order.

        ``priorities`` is the enrichment layer's view when a verified enrichment
        report exists. When it does not, ordering falls back to the severity the
        scan observed — which is a materially different ordering, and is why the
        pass records which basis it used: budget exhaustion truncates the tail,
        so the ordering decides what never gets looked at.
        """
        planned: list[PlannedFinding] = []
        for finding in sorted(findings, key=lambda f: f.finding_id):
            planned.append(
                self._plan_one(
                    finding,
                    pass_salt=pass_salt,
                    pass_id=pass_id,
                    priority=(priorities or {}).get(finding.finding_id),
                )
            )
        planned.sort(key=lambda p: (-p.rank[0], p.rank[1]))
        return Plan(findings=tuple(planned))

    # -- one finding ----------------------------------------------------------
    def _plan_one(
        self,
        finding: Finding,
        *,
        pass_salt: bytes,
        pass_id: str,
        priority: str | None,
    ) -> PlannedFinding:
        resolved = self._registry.resolve(finding)
        rank = _rank_for(finding, priority)

        if isinstance(resolved, Unsupported):
            return PlannedFinding(
                finding=finding,
                subject_key=self._subject_key(finding, None),
                spec=None,
                unsupported=resolved,
                primary=None,
                controls=(),
                rank=rank,
            )

        spec = resolved
        try:
            primary_envelope = self._primary_envelope(finding, spec)
        except EnvelopeError as exc:
            # The registry validated the spec, but this particular finding's
            # observed locator is not representable. Saying so is honest; a
            # scope denial at dispatch would blame the grant.
            return PlannedFinding(
                finding=finding,
                subject_key=self._subject_key(finding, spec),
                spec=None,
                unsupported=Unsupported(
                    justification=Justification.UNREPRESENTABLE_TARGET,
                    registry_digest=self._registry.digest,
                    detail=str(exc),
                ),
                primary=None,
                controls=(),
                rank=rank,
            )

        primary = self._observation(
            envelope=primary_envelope,
            pass_salt=pass_salt,
            pass_id=pass_id,
            finding=finding,
            spec=spec,
            role=ObservationRole.PRIMARY,
            control_index=0,
        )
        controls = self._controls(
            primary_envelope,
            pass_salt=pass_salt,
            pass_id=pass_id,
            finding=finding,
            spec=spec,
        )
        return PlannedFinding(
            finding=finding,
            subject_key=self._subject_key(finding, spec),
            spec=spec,
            unsupported=None,
            primary=primary,
            controls=controls,
            rank=rank,
        )

    # -- envelopes ------------------------------------------------------------
    def _primary_envelope(self, finding: Finding, spec: VerifierSpec) -> RequestEnvelope:
        descriptor = self._descriptor_for(spec.kind)
        if spec.kind is ObservationKind.DNS_ANSWER:
            return dns_envelope(
                host=finding.canonical_target,
                record_types=spec.record_types,
                descriptor_version=descriptor,
                extractor_set_digest=self._extractor_digest,
                resolver_set_digest=self._resolver_digest,
            )
        scheme, host, port, path = _split_url(finding)
        return http_envelope(
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            method=spec.method,
            descriptor_version=descriptor,
            extractor_set_digest=self._extractor_digest,
        )

    def _controls(
        self,
        primary: RequestEnvelope,
        *,
        pass_salt: bytes,
        pass_id: str,
        finding: Finding,
        spec: VerifierSpec,
    ) -> tuple[PlannedObservation, ...]:
        if spec.controls.strategy in SELF_CONTROLLING_STRATEGIES:
            # An authoritative negative answer is its own control; asking again
            # for a name that does not exist would only cost the client traffic.
            return ()
        if spec.controls.strategy is ControlStrategy.NONE:
            return ()
        if spec.controls.strategy is not ControlStrategy.SIBLING_PATHS:
            # Reserved strategies (differential SNI, closed port) belong to kinds
            # this catalog does not yet contain. The registry rejects a spec that
            # names one, so reaching here means a hand-built spec.
            return ()
        if spec.claim_scope is not ClaimScope.RESOURCE_SPECIFIC:
            return ()

        out: list[PlannedObservation] = []
        for index in range(1, spec.controls.count + 1):
            locator = control_locator(
                pass_salt=pass_salt, finding_id=finding.finding_id, control_index=index
            )
            path = _sibling_path(primary.path or "/", locator, index)
            out.append(
                self._observation(
                    envelope=primary.with_path(path),
                    pass_salt=pass_salt,
                    pass_id=pass_id,
                    finding=finding,
                    spec=spec,
                    role=ObservationRole.CONTROL,
                    control_index=index,
                )
            )
        return tuple(out)

    def _observation(
        self,
        *,
        envelope: RequestEnvelope,
        pass_salt: bytes,
        pass_id: str,
        finding: Finding,
        spec: VerifierSpec,
        role: ObservationRole,
        control_index: int,
    ) -> PlannedObservation:
        return PlannedObservation(
            observation_id=observation_id(
                pass_id=pass_id,
                finding_id=finding.finding_id,
                verifier_id=spec.verifier_id,
                role=role,
                control_index=control_index,
            ),
            execution_id=execution_id(
                pass_salt=pass_salt,
                envelope=envelope,
                finding_id=finding.finding_id,
                role=role,
                control_index=control_index,
            ),
            envelope=envelope,
            role=role,
            control_index=control_index,
            finding_id=finding.finding_id,
            verifier_id=spec.verifier_id,
        )

    # -- helpers --------------------------------------------------------------
    def _descriptor_for(self, kind: ObservationKind) -> str:
        descriptor = self._descriptors.get(kind.value)
        if not descriptor:
            raise EnvelopeError(f"no pinned descriptor for observation kind {kind.value}")
        return descriptor

    def _subject_key(self, finding: Finding, spec: VerifierSpec | None) -> str:
        locator: str | None = None
        if finding.url:
            try:
                locator = urlsplit(finding.url).path or "/"
            except ValueError:
                locator = None
        kind = spec.kind.value if spec else finding.observation_type
        return subject_key(
            kind=kind,
            canonical_target=finding.canonical_target,
            locator=locator,
            finding_class=finding.template_id or finding.observation_type,
        )


# =============================================================================
# Pure helpers
# =============================================================================


def _split_url(finding: Finding) -> tuple[str, str, int | None, str]:
    """Pull scheme, host, port and path out of an observed URL.

    The host is compared against the finding's canonical target by the caller;
    a mismatch is a destination mismatch rather than a quiet substitution,
    because a matched URL can reflect a redirect the scan followed.
    """
    raw = finding.url or ""
    if not raw:
        raise EnvelopeError("the finding carries no URL to re-observe")
    parts = urlsplit(raw)
    if parts.scheme not in {"http", "https"}:
        raise EnvelopeError(f"scheme {parts.scheme!r} is not an HTTP scheme")
    if not parts.hostname:
        raise EnvelopeError("the observed URL has no host")
    if parts.query or parts.fragment:
        raise EnvelopeError("the observed URL carries a query or fragment")
    path = parts.path or "/"
    if len(path.encode("utf-8")) > _MAX_PATH_BYTES:
        raise EnvelopeError("the observed path is too long to re-observe")
    return parts.scheme, parts.hostname.lower(), parts.port, path


def _sibling_path(path: str, locator: str, index: int) -> str:
    """A path that should not exist, next to one that does.

    Two shapes, so the controls differ from each other in structure as well as
    in name: a sibling file in the same directory, and a sibling directory. A
    host whose behaviour for missing things is not stable will show it as
    disagreement between the two, which is a reason to refuse to judge rather
    than to pick one.
    """
    head, _, tail = path.rpartition("/")
    directory = head or ""
    extension = ""
    if "." in tail:
        candidate = tail[tail.rindex(".") :].lower()
        if candidate in _KEEP_EXTENSIONS:
            extension = candidate
    if index % 2 == 1:
        return f"{directory}/{locator}{extension}"
    return f"{directory}/{locator}/{tail or 'index'}"


def _rank_for(finding: Finding, priority: str | None) -> tuple[int, str]:
    """Ordering weight. Higher is observed first."""
    label = priority if priority else finding.severity
    severity, _ = Severity.parse(label)
    return (int(severity), finding.finding_id)


def sibling_paths_for(path: str, locators: Sequence[str]) -> tuple[str, ...]:
    """Exposed for tests and for explaining a verdict to an operator."""
    return tuple(_sibling_path(path, locator, i + 1) for i, locator in enumerate(locators))

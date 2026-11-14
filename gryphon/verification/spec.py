"""Verifier specifications: declarative, closed, and evaluated over typed facts.

A verifier says four things and nothing more:

1. **What to observe** — a kind from the closed catalog, and how to derive the
   subject from the finding.
2. **How to control it** — a strategy from the closed catalog, because a control
   is *a request whose expected answer is known independently of the finding*
   and different protocols know that in different ways.
3. **What would make the predicate hold** — a conjunction of clauses over typed
   facts, never over a body, because no body exists on this side.
4. **What would make the original match spurious** — the refutation predicate,
   evaluated against controls.

The clause set is deliberately small and fixed. It is not a language: there is no
grammar to version, no interpreter to harden, and no expressiveness to be
tempted by. The eight verifiers this set is designed for are all of one shape —
*is this response structurally the artifact we think it is, and does the same
structure appear where it should not?* — and a clause that cannot express a new
predicate is a signal to review the predicate, not to grow a DSL.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from gryphon.tooling.observation.facts import ObservationFacts
from gryphon.verification.constants import (
    ClaimScope,
    ControlStrategy,
    ObservationKind,
    SafeReadClass,
    SecretClass,
    VerifierLifecycle,
)


class SpecError(ValueError):
    """A verifier specification is not admissible.

    Raised at registry load, never at dispatch. A spec that could derive an
    unrepresentable target, that omits a control strategy for a claim that needs
    one, or that names an unreviewed endpoint class is a registry problem; the
    operator should hear about it when the registry loads, not as a scope denial
    on a finding that was perfectly in scope.
    """


# =============================================================================
# Predicate clauses (closed set)
# =============================================================================


@dataclass(frozen=True, slots=True)
class StatusIn:
    """The response status is one of these codes."""

    codes: tuple[int, ...]

    def holds(self, facts: ObservationFacts) -> bool:
        return facts.http is not None and facts.http.status_code in self.codes


@dataclass(frozen=True, slots=True)
class StatusClassIn:
    """The response status class (2, 3, 4, 5) is one of these."""

    classes: tuple[int, ...]

    def holds(self, facts: ObservationFacts) -> bool:
        return facts.http is not None and facts.http.status_class in self.classes


@dataclass(frozen=True, slots=True)
class ContentTypeNotIn:
    """The normalized content type is not one of these.

    Used to separate a served configuration file from an HTML error page that
    happens to answer 200 — the single most common catch-all shape.
    """

    types: tuple[str, ...]

    def holds(self, facts: ObservationFacts) -> bool:
        if facts.http is None:
            return False
        actual = (facts.http.content_type or "").lower()
        return not any(actual.startswith(t) for t in self.types)


@dataclass(frozen=True, slots=True)
class DotenvShape:
    """The body parses as a configuration file by its own grammar.

    Independent of whatever regex the original detection template used: that
    independence is the entire reason a second look is worth anything.
    """

    min_non_empty_lines: int = 3
    min_assignment_ratio: float = 0.5

    def holds(self, facts: ObservationFacts) -> bool:
        dotenv = facts.http.dotenv if facts.http else None
        if dotenv is None:
            return False
        return (
            dotenv.non_empty_lines >= self.min_non_empty_lines
            and dotenv.assignment_ratio >= self.min_assignment_ratio
        )


@dataclass(frozen=True, slots=True)
class SecretClassPresent:
    """At least ``minimum`` values of this shape were counted in the body.

    The count crosses the boundary; the values do not, and never did.
    """

    secret_class: SecretClass
    minimum: int = 1

    def holds(self, facts: ObservationFacts) -> bool:
        if facts.http is None:
            return False
        return facts.http.secret_class_counts.get(self.secret_class.value, 0) >= self.minimum


@dataclass(frozen=True, slots=True)
class TokenPresent:
    """A pinned signal token appeared.

    The token is copied into the registry rather than read from a template, so
    an unpinned template update cannot silently change what a pass refutes.
    """

    token: str

    def holds(self, facts: ObservationFacts) -> bool:
        if facts.http is None:
            return False
        return self.token in facts.http.tokens_present


@dataclass(frozen=True, slots=True)
class HeaderPresent:
    """An allowlisted header name was present. Names only; never values."""

    name: str

    def holds(self, facts: ObservationFacts) -> bool:
        if facts.http is None:
            return False
        return self.name.lower() in facts.http.header_names


@dataclass(frozen=True, slots=True)
class RcodeIs:
    """The resolver returned this response code.

    ``NXDOMAIN`` is the positive case for a dangling record, which is why it
    travels as a fact rather than as a refusal.
    """

    rcode: str

    def holds(self, facts: ObservationFacts) -> bool:
        return facts.dns is not None and facts.dns.rcode == self.rcode.upper()


@dataclass(frozen=True, slots=True)
class CnameTerminatesInProvider:
    """The CNAME chain ends in a domain on the pinned provider list.

    The list is pinned by digest and entered only by review: community
    fingerprint sets change, carry no correctness guarantee, and a stale entry
    would confirm a takeover against a provider that long since fixed it.
    """

    providers: tuple[str, ...]

    def holds(self, facts: ObservationFacts) -> bool:
        if facts.dns is None or not facts.dns.cname_chain:
            return False
        terminal = facts.dns.cname_chain[-1]
        return any(terminal == p or terminal.endswith("." + p) for p in self.providers)

    def provider_for(self, facts: ObservationFacts) -> str | None:
        if not self.holds(facts) or facts.dns is None:
            return None
        terminal = facts.dns.cname_chain[-1]
        for provider in self.providers:
            if terminal == provider or terminal.endswith("." + provider):
                return provider
        return None


#: The closed clause union. Adding a member is a MINOR catalog change and a
#: review item; it is not a language extension.
Clause = (
    StatusIn
    | StatusClassIn
    | ContentTypeNotIn
    | DotenvShape
    | SecretClassPresent
    | TokenPresent
    | HeaderPresent
    | RcodeIs
    | CnameTerminatesInProvider
)

_CLAUSE_TAGS: Final[dict[str, type]] = {
    "status_in": StatusIn,
    "status_class_in": StatusClassIn,
    "content_type_not_in": ContentTypeNotIn,
    "dotenv_shape": DotenvShape,
    "secret_class_present": SecretClassPresent,
    "token_present": TokenPresent,
    "header_present": HeaderPresent,
    "rcode_is": RcodeIs,
    "cname_terminates_in_provider": CnameTerminatesInProvider,
}


@dataclass(frozen=True, slots=True)
class Predicate:
    """A conjunction of clauses. Every clause must hold.

    Only AND is supported. Disjunction invites a predicate that is true for
    several unrelated reasons, which is precisely the looseness a verification
    layer exists to remove.
    """

    clauses: tuple[Clause, ...]

    def __post_init__(self) -> None:
        if not self.clauses:
            raise SpecError("a predicate needs at least one clause")

    def holds(self, facts: ObservationFacts | None) -> bool:
        if facts is None:
            return False
        return all(clause.holds(facts) for clause in self.clauses)

    def matched(self, facts: ObservationFacts | None) -> tuple[str, ...]:
        """Which clause tags held — recorded on the verdict for explainability."""
        if facts is None:
            return ()
        tags = []
        for clause in self.clauses:
            if clause.holds(facts):
                tags.append(_tag_for(clause))
        return tuple(tags)

    @classmethod
    def from_payload(cls, raw: Sequence[Mapping[str, Any]]) -> Predicate:
        return cls(tuple(_clause_from_payload(item) for item in raw))


def _tag_for(clause: Clause) -> str:
    for tag, kind in _CLAUSE_TAGS.items():
        if isinstance(clause, kind):
            return tag
    raise SpecError(f"{type(clause).__name__} is not a registered clause")


def _clause_from_payload(raw: Mapping[str, Any]) -> Clause:
    tag = str(raw.get("clause", ""))
    kind = _CLAUSE_TAGS.get(tag)
    if kind is None:
        raise SpecError(f"{tag!r} is not a clause in the closed set")
    args = {k: v for k, v in raw.items() if k != "clause"}
    try:
        if kind is StatusIn:
            return StatusIn(codes=tuple(int(c) for c in args["codes"]))
        if kind is StatusClassIn:
            return StatusClassIn(classes=tuple(int(c) for c in args["classes"]))
        if kind is ContentTypeNotIn:
            return ContentTypeNotIn(types=tuple(str(t).lower() for t in args["types"]))
        if kind is DotenvShape:
            return DotenvShape(
                min_non_empty_lines=int(args.get("min_non_empty_lines", 3)),
                min_assignment_ratio=float(args.get("min_assignment_ratio", 0.5)),
            )
        if kind is SecretClassPresent:
            return SecretClassPresent(
                secret_class=SecretClass(args["secret_class"]),
                minimum=int(args.get("minimum", 1)),
            )
        if kind is TokenPresent:
            return TokenPresent(token=str(args["token"]))
        if kind is HeaderPresent:
            return HeaderPresent(name=str(args["name"]).lower())
        if kind is RcodeIs:
            return RcodeIs(rcode=str(args["rcode"]).upper())
        if kind is CnameTerminatesInProvider:
            return CnameTerminatesInProvider(
                providers=tuple(str(p).lower().rstrip(".") for p in args["providers"])
            )
    except (KeyError, TypeError, ValueError) as exc:
        raise SpecError(f"clause {tag!r} is malformed: {exc}") from exc
    raise SpecError(f"{tag!r} is not a clause in the closed set")


# =============================================================================
# Control strategy
# =============================================================================


@dataclass(frozen=True, slots=True)
class ControlPlan:
    """How this verifier produces an expectation it can compare against."""

    strategy: ControlStrategy
    #: Number of control observations to make. Zero for self-controlling
    #: strategies, which produce their expectation without extra requests.
    count: int = 0
    #: Required when the strategy is ``none``: a control exemption must say why.
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.strategy is ControlStrategy.NONE and not self.reason:
            raise SpecError("a control exemption must state its reason")
        if self.strategy is ControlStrategy.SIBLING_PATHS and self.count < 2:
            raise SpecError("sibling_paths needs at least two controls to detect disagreement")


# =============================================================================
# Projection
# =============================================================================


@dataclass(frozen=True, slots=True)
class ProjectionSpec:
    """What may be persisted as evidence for this verifier.

    An allowlist rather than a redaction list: anything not named here does not
    reach storage. The difference matters because a redaction list has to be
    right about every shape it has never seen.
    """

    include_dotenv_keys: bool = False
    include_secret_counts: bool = True
    include_tokens: bool = False
    include_header_names: bool = True
    include_dns_chain: bool = False
    #: Cap on dotenv key names retained, so a huge file cannot bloat a row.
    max_keys: int = 200


# =============================================================================
# Verifier
# =============================================================================


@dataclass(frozen=True, slots=True)
class VerifierSpec:
    """One registered way to verify one class of finding."""

    verifier_id: str
    lifecycle: VerifierLifecycle
    kind: ObservationKind
    claim_scope: ClaimScope
    can_confirm: bool
    can_refute: bool
    safe_read_class: SafeReadClass
    repeat_safe: bool
    method: str
    predicate: Predicate | None
    refutation: Predicate | None
    controls: ControlPlan
    projection: ProjectionSpec = field(default_factory=ProjectionSpec)
    #: Signal tokens handed to the observer's token_presence extractor. Copied
    #: into the registry so a template update cannot change what a pass refutes.
    signal_tokens: tuple[str, ...] = ()
    #: DNS record types for resolver-mediated kinds.
    record_types: tuple[str, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        if self.can_confirm and self.predicate is None:
            raise SpecError(f"{self.verifier_id}: can_confirm requires a predicate")
        if self.can_refute and self.refutation is None and self.predicate is None:
            raise SpecError(f"{self.verifier_id}: can_refute requires a predicate to compare")
        if not self.can_confirm and not self.can_refute:
            raise SpecError(f"{self.verifier_id}: a verifier that can do neither is not a verifier")
        if self.safe_read_class is SafeReadClass.UNREVIEWED:
            raise SpecError(
                f"{self.verifier_id}: an unreviewed endpoint class is never dispatched; "
                "review it or leave the class unsupported"
            )
        if (
            self.claim_scope is ClaimScope.RESOURCE_SPECIFIC
            and self.can_refute
            and self.controls.strategy is ControlStrategy.NONE
        ):
            raise SpecError(
                f"{self.verifier_id}: a resource-specific claim that can be refuted needs a "
                "control strategy — without one, 'the server says yes' is not evidence"
            )
        if self.kind is ObservationKind.DNS_ANSWER and not self.record_types:
            raise SpecError(f"{self.verifier_id}: a resolver-mediated verifier needs record types")

    @property
    def is_dispatchable(self) -> bool:
        """Whether this verifier may currently cause traffic."""
        return self.lifecycle is not VerifierLifecycle.WITHDRAWN

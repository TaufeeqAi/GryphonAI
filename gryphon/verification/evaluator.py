"""The decision table: observations in, exactly one verdict out.

This module is pure. It performs no I/O, holds no state, and reaches no
conclusion that is not a function of its arguments — which is what makes the
layer's most consequential rules exhaustively testable without a database, a
socket or a network namespace.

The ordering of the rules is the contract, not an implementation detail. Three
properties are tested against it directly, and every rule below exists to keep
one of them true:

* **CONFIRMED requires proof.** A complete primary observation on which the
  predicate held, and complete, mutually agreeing controls that did *not* match
  and from which the primary differs. A server that answers the same way for
  things that do not exist proves nothing by answering.
* **REFUTED requires evidence.** A complete control that positively matched.
  "We could not reach it" is never a false positive — that conflation is how a
  verification layer becomes a way of quietly deleting findings.
* **Incomplete proves nothing negative.** A truncated body missing a token says
  nothing about whether the token was there, so a measurement that stopped early
  can never produce REFUTED or NOT_REPRODUCED.

The fourth property has no row of its own because it precedes the table: a
subject whose earlier observation may have been applied is not re-observed
automatically unless its verifier is declared repeat-safe. Transport failure is
not a rollback, and a new identity in a later pass would otherwise erase that
uncertainty silently.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from gryphon.tooling.observation.facts import ObservationFacts
from gryphon.verification.constants import (
    ABSENT_STATUS_CODES,
    ACCESS_REFUSED_STATUS_CODES,
    JUSTIFICATIONS_BY_STATUS,
    SELF_CONTROLLING_STRATEGIES,
    ControlStrategy,
    Justification,
    ObservationKind,
    OutcomeClass,
    VerdictStatus,
)
from gryphon.verification.observation import Observation
from gryphon.verification.spec import VerifierSpec

#: Gateway reason codes mapped to the justification that explains them to an
#: operator. Anything unmapped falls back to a generic denial rather than being
#: guessed at: a wrong-but-specific reason is worse than an honest generic one.
_REASON_TO_JUSTIFICATION: Final[dict[str, Justification]] = {
    # Authority
    "RECEIPT_MISSING": Justification.AUTHORIZATION_UNAVAILABLE,
    "RECEIPT_MISMATCH": Justification.AUTHORIZATION_UNAVAILABLE,
    "CAPABILITY_EXPIRED": Justification.AUTHORIZATION_UNAVAILABLE,
    "CAPABILITY_NOT_YET_VALID": Justification.AUTHORIZATION_UNAVAILABLE,
    "GRANT_EXPIRED": Justification.AUTHORIZATION_UNAVAILABLE,
    "GRANT_SIGNER_UNTRUSTED": Justification.AUTHORIZATION_UNAVAILABLE,
    "AUTHORIZATION_UNAVAILABLE": Justification.AUTHORIZATION_UNAVAILABLE,
    "DEADLINE_EXCEEDS_GRANT": Justification.DEADLINE_EXCEEDS_GRANT,
    # Scope and destination
    "SCOPE_EXCLUDED": Justification.SCOPE_EXCLUDED,
    "SCOPE_NO_MATCH": Justification.SCOPE_EXCLUDED,
    "SCOPE_INVALID_INPUT": Justification.SCOPE_EXCLUDED,
    "SCOPE_PROVENANCE_MISMATCH": Justification.SCOPE_EXCLUDED,
    "DESTINATION_UNATTESTED": Justification.DESTINATION_UNATTESTED,
    "DESTINATION_DENIED": Justification.DESTINATION_UNATTESTED,
    "DESTINATION_MISMATCH": Justification.DESTINATION_MISMATCH,
    "DESTINATION_UNRESOLVABLE": Justification.UNREACHABLE,
    "REDIRECT_ESCAPE": Justification.DESTINATION_MISMATCH,
    # Capacity
    "BUDGET_EXCEEDED": Justification.BUDGET_EXHAUSTED,
    "BREAKER_OPEN": Justification.DEPENDENCY_UNAVAILABLE,
    "RATE_LIMITED": Justification.RATE_LIMITED,
    "DB_UNAVAILABLE": Justification.DEPENDENCY_UNAVAILABLE,
    "EGRESS_UNAVAILABLE": Justification.DEPENDENCY_UNAVAILABLE,
    "READINESS_FAILED": Justification.DEPENDENCY_UNAVAILABLE,
    "HOST_PROTECTIVE_RESPONSE": Justification.HOST_PROTECTIVE_RESPONSE,
    # Transport
    "TOOL_TIMED_OUT": Justification.TIMEOUT,
    "TOOL_FAILED": Justification.PROBE_FAILED,
}

_OUTCOME_FALLBACK: Final[dict[OutcomeClass, Justification]] = {
    OutcomeClass.REFUSED_POLICY: Justification.PROBE_DENIED,
    OutcomeClass.REFUSED_CAPACITY: Justification.DEPENDENCY_UNAVAILABLE,
    OutcomeClass.TIMED_OUT: Justification.TIMEOUT,
    OutcomeClass.FAILED: Justification.PROBE_FAILED,
    OutcomeClass.OBSERVATION_LOST: Justification.EVIDENCE_UNAVAILABLE,
}


def justification_for(observation: Observation) -> Justification:
    """Explain a non-evidential outcome in the operator's vocabulary."""
    mapped = _REASON_TO_JUSTIFICATION.get(observation.reason_code.upper())
    if mapped is not None:
        return mapped
    return _OUTCOME_FALLBACK.get(observation.outcome, Justification.PROBE_DENIED)


# =============================================================================
# Verdict
# =============================================================================


@dataclass(frozen=True, slots=True)
class ControlSummary:
    """What the controls said, recorded so a verdict can be re-read later."""

    requested: int
    observed: int
    complete: int
    agreeing: bool
    any_matched_predicate: bool
    any_matched_refutation: bool
    primary_indistinguishable: bool

    def as_payload(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "observed": self.observed,
            "complete": self.complete,
            "agreeing": self.agreeing,
            "any_matched_predicate": self.any_matched_predicate,
            "any_matched_refutation": self.any_matched_refutation,
            "primary_indistinguishable": self.primary_indistinguishable,
        }


@dataclass(frozen=True, slots=True)
class Verdict:
    """One finding's outcome in one pass."""

    status: VerdictStatus
    justification: Justification | None
    verifier_id: str | None
    rule: int
    matched_predicates: tuple[str, ...] = ()
    control_summary: ControlSummary | None = None
    projection: dict[str, Any] = field(default_factory=dict)
    #: True when the subject may have been acted on by an earlier observation.
    possibly_applied: bool = False

    def __post_init__(self) -> None:
        allowed = JUSTIFICATIONS_BY_STATUS[self.status]
        if self.status is VerdictStatus.CONFIRMED:
            if self.justification is not None:
                raise ValueError("CONFIRMED carries no justification")
        elif self.justification is None:
            raise ValueError(f"{self.status.value} requires a justification")
        elif self.justification not in allowed:
            raise ValueError(
                f"{self.justification.value} is not a justification for {self.status.value}"
            )

    def as_payload(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "justification": self.justification.value if self.justification else None,
            "verifier_id": self.verifier_id,
            "rule": self.rule,
            "matched_predicates": list(self.matched_predicates),
            "control_summary": self.control_summary.as_payload() if self.control_summary else None,
            "possibly_applied": self.possibly_applied,
        }


# =============================================================================
# Comparison helpers
# =============================================================================


def _fingerprint(facts: ObservationFacts | None) -> tuple[Any, ...] | None:
    """A comparable shape for "did these two answers look the same?".

    Status class rather than exact status, because a host that returns 200 for
    everything and one that returns 203 for everything are the same problem. The
    body digest is exact, because that is the part a catch-all repeats.
    """
    if facts is None:
        return None
    if facts.kind is ObservationKind.HTTP_RESPONSE_SUMMARY and facts.http is not None:
        return (facts.http.status_class, facts.http.body_sha256)
    if facts.kind is ObservationKind.DNS_ANSWER and facts.dns is not None:
        return (facts.dns.rcode, facts.dns.cname_chain)
    return None


def _controls_agree(controls: Sequence[Observation]) -> bool:
    """Whether the controls told a consistent story.

    Controls that disagree with each other mean the host's behaviour for
    non-existent things is not stable, so comparing the primary against them
    proves nothing either way. That is a reason to refuse to judge, not a reason
    to pick one.
    """
    prints = {_fingerprint(c.facts) for c in controls}
    return len(prints) <= 1


# =============================================================================
# The table
# =============================================================================


class ProofEvaluator:
    """Applies the decision table. Stateless and deterministic."""

    def evaluate(
        self,
        spec: VerifierSpec | None,
        primary: Observation | None,
        controls: Sequence[Observation] = (),
        *,
        unsupported: Justification | None = None,
        subject_possibly_applied: bool = False,
    ) -> Verdict:
        """Return the single verdict these observations support.

        ``unsupported`` is supplied by the registry when it declined to produce a
        spec at all — no verifier, an unrepresentable target, or an unreviewed
        endpoint class — so the reason reaches the deliverable instead of
        becoming a silent gap.
        """
        # -- Rule 0: the registry declined ------------------------------------
        if spec is None:
            return Verdict(
                status=VerdictStatus.UNSUPPORTED,
                justification=unsupported or Justification.NO_VERIFIER,
                verifier_id=None,
                rule=0,
            )

        # -- Rule 1: an earlier contact may already have been applied ---------
        # Checked before anything else because it decides whether we should have
        # looked at all. A new identity in a later pass would otherwise quietly
        # erase the uncertainty that made the question worth asking.
        if subject_possibly_applied and not spec.repeat_safe:
            return Verdict(
                status=VerdictStatus.INCONCLUSIVE,
                justification=Justification.REPLAY_REQUIRES_DECISION,
                verifier_id=spec.verifier_id,
                rule=1,
                possibly_applied=True,
            )

        requested = spec.controls.count
        self_controlling = spec.controls.strategy in SELF_CONTROLLING_STRATEGIES
        exempt = spec.controls.strategy is ControlStrategy.NONE or self_controlling

        # -- Rule 2: no usable primary ----------------------------------------
        if primary is None or not primary.has_evidence:
            return Verdict(
                status=VerdictStatus.INCONCLUSIVE,
                justification=(
                    justification_for(primary) if primary else Justification.PROBE_DENIED
                ),
                verifier_id=spec.verifier_id,
                rule=2,
                possibly_applied=bool(primary and primary.possibly_applied),
            )

        # -- Rule 3: the primary measurement stopped early --------------------
        if not primary.is_whole:
            return Verdict(
                status=VerdictStatus.INCONCLUSIVE,
                justification=Justification.INCOMPLETE_OBSERVATION,
                verifier_id=spec.verifier_id,
                rule=3,
                possibly_applied=primary.possibly_applied,
            )

        usable_controls = [c for c in controls if c.has_evidence]
        summary = ControlSummary(
            requested=requested,
            observed=len(usable_controls),
            complete=sum(1 for c in usable_controls if c.is_whole),
            agreeing=_controls_agree(usable_controls) if usable_controls else True,
            any_matched_predicate=False,
            any_matched_refutation=False,
            primary_indistinguishable=False,
        )

        if not exempt:
            # -- Rule 4: a required control never produced evidence -----------
            if len(usable_controls) < requested:
                missing = next((c for c in controls if not c.has_evidence), None)
                return Verdict(
                    status=VerdictStatus.INCONCLUSIVE,
                    justification=(
                        justification_for(missing) if missing else Justification.CONTROLS_DISAGREE
                    ),
                    verifier_id=spec.verifier_id,
                    rule=4,
                    control_summary=summary,
                )

            # -- Rule 5: a required control stopped early ---------------------
            if any(not c.is_whole for c in usable_controls):
                return Verdict(
                    status=VerdictStatus.INCONCLUSIVE,
                    justification=Justification.INCOMPLETE_OBSERVATION,
                    verifier_id=spec.verifier_id,
                    rule=5,
                    control_summary=summary,
                )

            # -- Rule 6: the controls disagree with each other ----------------
            if not summary.agreeing:
                return Verdict(
                    status=VerdictStatus.INCONCLUSIVE,
                    justification=Justification.CONTROLS_DISAGREE,
                    verifier_id=spec.verifier_id,
                    rule=6,
                    control_summary=summary,
                )

            matched_predicate = bool(
                spec.predicate and any(spec.predicate.holds(c.facts) for c in usable_controls)
            )
            matched_refutation = bool(
                spec.refutation and any(spec.refutation.holds(c.facts) for c in usable_controls)
            )
            primary_print = _fingerprint(primary.facts)
            indistinguishable = any(
                _fingerprint(c.facts) == primary_print for c in usable_controls
            )
            summary = ControlSummary(
                requested=summary.requested,
                observed=summary.observed,
                complete=summary.complete,
                agreeing=True,
                any_matched_predicate=matched_predicate,
                any_matched_refutation=matched_refutation,
                primary_indistinguishable=indistinguishable,
            )

            # -- Rule 7: the server answers the same way for things that do
            #            not exist, so its answer here says nothing -----------
            if spec.can_refute and matched_predicate:
                return Verdict(
                    status=VerdictStatus.REFUTED,
                    justification=Justification.CONTROL_MATCHED,
                    verifier_id=spec.verifier_id,
                    rule=7,
                    control_summary=summary,
                )

            # -- Rule 8: the matched signal is everywhere ----------------------
            if spec.can_refute and matched_refutation:
                return Verdict(
                    status=VerdictStatus.REFUTED,
                    justification=Justification.SIGNAL_UBIQUITOUS,
                    verifier_id=spec.verifier_id,
                    rule=8,
                    control_summary=summary,
                )

            # -- Rule 9: the subject looks exactly like a thing that is not
            #            there ------------------------------------------------
            if indistinguishable:
                return Verdict(
                    status=VerdictStatus.NOT_REPRODUCED,
                    justification=Justification.SUBJECT_ABSENT,
                    verifier_id=spec.verifier_id,
                    rule=9,
                    control_summary=summary,
                )

        # -- Rule 10: the predicate held --------------------------------------
        if spec.can_confirm and spec.predicate is not None and spec.predicate.holds(primary.facts):
            return Verdict(
                status=VerdictStatus.CONFIRMED,
                justification=None,
                verifier_id=spec.verifier_id,
                rule=10,
                matched_predicates=spec.predicate.matched(primary.facts),
                control_summary=summary,
                projection=build_projection(spec, primary.facts),
            )

        if spec.can_confirm:
            http = primary.facts.http if primary.facts else None
            # -- Rule 11: the subject is gone ---------------------------------
            if http is not None and http.status_code in ABSENT_STATUS_CODES:
                return Verdict(
                    status=VerdictStatus.NOT_REPRODUCED,
                    justification=Justification.SUBJECT_ABSENT,
                    verifier_id=spec.verifier_id,
                    rule=11,
                    control_summary=summary,
                )
            # -- Rule 12: access is now refused -------------------------------
            if http is not None and http.status_code in ACCESS_REFUSED_STATUS_CODES:
                return Verdict(
                    status=VerdictStatus.NOT_REPRODUCED,
                    justification=Justification.ACCESS_REFUSED,
                    verifier_id=spec.verifier_id,
                    rule=12,
                    control_summary=summary,
                )
            # -- Rule 13: present, but the condition is not --------------------
            return Verdict(
                status=VerdictStatus.NOT_REPRODUCED,
                justification=Justification.PREDICATE_FALSE,
                verifier_id=spec.verifier_id,
                rule=13,
                control_summary=summary,
            )

        # -- Rule 14: a refute-only verifier that refuted nothing -------------
        # It cannot confirm by construction, so the absence of a refutation is
        # not evidence for the finding. Saying so plainly is the honest answer.
        return Verdict(
            status=VerdictStatus.INCONCLUSIVE,
            justification=Justification.NO_CONFIRMING_PREDICATE,
            verifier_id=spec.verifier_id,
            rule=14,
            control_summary=summary,
        )


def build_projection(spec: VerifierSpec, facts: ObservationFacts | None) -> dict[str, Any]:
    """Persisted evidence for one verdict, by allowlist.

    An allowlist rather than a redaction pass: anything this function does not
    name does not reach storage. A redaction list has to be right about every
    shape it has never seen, and the shapes here were chosen by someone else.
    """
    if facts is None:
        return {}
    out: dict[str, Any] = {
        "kind": facts.kind.value,
        "completeness": facts.completeness.as_payload(),
    }
    http = facts.http
    if http is not None:
        out["status_code"] = http.status_code
        out["content_type"] = http.content_type
        out["body_sha256"] = http.body_sha256
        if spec.projection.include_secret_counts:
            out["secret_class_counts"] = dict(http.secret_class_counts)
        if spec.projection.include_header_names:
            out["header_names"] = list(http.header_names)
        if spec.projection.include_tokens:
            out["tokens_present"] = list(http.tokens_present)
        if spec.projection.include_dotenv_keys and http.dotenv is not None:
            keys = list(http.dotenv.key_names)[: spec.projection.max_keys]
            classes = list(http.dotenv.value_classes)[: spec.projection.max_keys]
            out["dotenv"] = {
                "non_empty_lines": http.dotenv.non_empty_lines,
                "assignment_lines": http.dotenv.assignment_lines,
                "key_names": keys,
                "value_classes": classes,
                "keys_truncated": len(http.dotenv.key_names) > spec.projection.max_keys,
            }
    dns = facts.dns
    if dns is not None and spec.projection.include_dns_chain:
        out["dns"] = {
            "rcode": dns.rcode,
            "cname_chain": list(dns.cname_chain),
            "resolver_set_digest": dns.resolver_set_digest,
        }
    return out

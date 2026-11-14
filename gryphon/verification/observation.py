"""The layer-internal view of one observation.

This is deliberately *not* the gateway's wire type. The evaluator is a pure
function and must not depend on a transport: an observation that arrived over a
socket, one replayed from the gateway's durable record, and one built from a
fixture in a test are the same thing to the decision table. The engine adapts
whatever the gateway returned into this value, and from that point the question
"how did we get this?" stops mattering.

What does matter, and is carried here explicitly:

* the **outcome class**, because a policy refusal, a capacity refusal and a fact
  about the world lead to different operator actions and must not collapse;
* **completeness**, because a measurement that stopped early cannot support a
  negative claim — a token missing from a truncated body says nothing;
* **possibly_applied**, because a transport failure is not a rollback. The
  target may have processed the request before the response failed, and that
  uncertainty has to survive into the next pass rather than being forgotten the
  moment a new identity is generated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gryphon.tooling.observation.facts import Completeness, ObservationFacts
from gryphon.verification.constants import (
    EVIDENCE_OUTCOMES,
    POSSIBLY_APPLIED_OUTCOMES,
    ObservationRole,
    OutcomeClass,
    TruncationReason,
)


@dataclass(frozen=True, slots=True)
class Observation:
    """One settled observation, as the evaluator sees it."""

    observation_id: str
    execution_id: str
    role: ObservationRole
    control_index: int
    outcome: OutcomeClass
    #: Gateway reason code. Stable, safe to persist, never free text.
    reason_code: str
    facts: ObservationFacts | None = None
    peer_address: str | None = None

    def __post_init__(self) -> None:
        if self.outcome in EVIDENCE_OUTCOMES and self.facts is None:
            raise ValueError(f"{self.outcome.value} requires facts")

    @property
    def completeness(self) -> Completeness:
        """Completeness of this measurement.

        An outcome that carries no facts is not complete by definition: there is
        nothing to have been whole.
        """
        if self.facts is None:
            return Completeness.incomplete(TruncationReason.NONE)
        return self.facts.completeness

    @property
    def has_evidence(self) -> bool:
        """Whether this observation can be reasoned over at all."""
        return self.outcome in EVIDENCE_OUTCOMES and self.facts is not None

    @property
    def is_whole(self) -> bool:
        """Whether a *negative* claim may rest on this observation."""
        return self.has_evidence and self.completeness.is_whole

    @property
    def possibly_applied(self) -> bool:
        """Whether the target may have processed the request regardless."""
        return self.outcome in POSSIBLY_APPLIED_OUTCOMES

    def as_payload(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "execution_id": self.execution_id,
            "role": self.role.value,
            "control_index": self.control_index,
            "outcome": self.outcome.value,
            "reason_code": self.reason_code,
            "completeness": self.completeness.as_payload(),
            "peer_address": self.peer_address,
        }


@dataclass(frozen=True, slots=True)
class NotDispatched:
    """A planned observation the gateway refused before committing intent.

    Kept as a distinct shape from a dispatched-then-failed observation because
    the difference is exactly the one that decides whether a subject carries a
    possibly-applied fact. Zero traffic occurred.
    """

    observation_id: str
    execution_id: str
    role: ObservationRole
    control_index: int
    outcome: OutcomeClass
    reason_code: str

    def to_observation(self) -> Observation:
        return Observation(
            observation_id=self.observation_id,
            execution_id=self.execution_id,
            role=self.role,
            control_index=self.control_index,
            outcome=self.outcome,
            reason_code=self.reason_code,
            facts=None,
        )

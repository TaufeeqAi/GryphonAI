"""The verification layer: proof, not theory.

Verification is an attributed, time-stamped claim that a finding's proof
predicate held — or demonstrably did not — on a fresh, authorized,
non-destructive re-observation performed by a principal that is not the
verifier, and measured by a process that keeps the bytes and returns only the
answer.

Four properties shape every module here:

* **This layer never contacts a target.** It asks the tool execution gateway,
  which is a separate process with its own database role and its own signing
  key. It holds no permit, no resolver and no socket beyond the gateway and the
  database — so it cannot write the evidence it judges, and cannot sign the
  attestation it verifies.
* **Nothing a target wrote crosses into it.** Measurement happens in an
  unprivileged, keyless observer; only typed facts leave. The secret guarantee
  is therefore a property of the architecture rather than of a recognizer's
  coverage.
* **Only deterministic code decides.** The decision table in
  :mod:`gryphon.verification.evaluator` is a pure function. A model may annotate
  what is already unverified; it can neither confirm, refute, nor cause traffic.
* **Negatives are honest.** Five statuses, each non-confirmed one carrying a
  closed justification. "Could not tell" is an answer this layer is willing to
  publish, and an incomplete measurement never proves absence.
"""

from __future__ import annotations

from gryphon.verification.constants import (
    DETERMINATE_STATUSES,
    Justification,
    ObservationKind,
    OutcomeClass,
    PassState,
    VerdictStatus,
)
from gryphon.verification.evaluator import ProofEvaluator, Verdict
from gryphon.verification.observation import Observation
from gryphon.verification.spec import VerifierSpec

__all__ = [
    "DETERMINATE_STATUSES",
    "Justification",
    "Observation",
    "ObservationKind",
    "OutcomeClass",
    "PassState",
    "ProofEvaluator",
    "Verdict",
    "VerdictStatus",
    "VerifierSpec",
]

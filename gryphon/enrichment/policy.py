"""Priority policy: the master plan's elevation rules, as versioned data.

* **KEV_LISTED** — any of the finding's CVEs is on the pinned CISA KEV catalog
  → CRITICAL, with the reason "actively exploited (CISA KEV …, due …)".
* **EPSS_HIGH** — otherwise, the finding's highest EPSS probability is above the
  threshold *and* the pinned EPSS model is one the policy declares calibrated
  → at least HIGH. An uncalibrated model is recorded and never elevates.

The floor is the finding's observed severity and inputs can only *raise*
priority: a low EPSS score, a NOT_APPLICABLE answer or an unavailable source
never lowers anything. CVSS (template-asserted) and ATT&CK techniques are
context only.

The policy's identity is the SHA-256 of its canonical JSON (RFC 8785): editing
the file — even without changing its human label — is a new policy, and every
priority records the digest of the policy that produced it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.enrichment.constants import Severity
from gryphon.enrichment.reasons import EnrichmentConfigurationError

DEFAULT_POLICY_PATH = Path(__file__).with_name("policy_v1.json")


@dataclass(frozen=True)
class Policy:
    document: dict[str, Any]
    digest: str
    label: str
    epss_threshold: float
    calibrated_models: frozenset[str]
    kev_reason: str
    epss_reason: str
    epss_uncalibrated_reason: str

    @property
    def short_digest(self) -> str:
        return self.digest[:12]


@dataclass(frozen=True)
class PriorityInputs:
    """What the policy may look at for one finding."""

    observed_severity: str | None
    #: KEV-listed CVEs of this finding: (cve, due_date), sorted by cve.
    kev_listed: tuple[tuple[str, str], ...]
    kev_catalog_version: str | None
    #: Highest EPSS of this finding's CVEs: (cve, epss) or None.
    epss_max: tuple[str, float] | None
    epss_model_version: str | None
    epss_score_date: str | None
    unavailable_sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class PriorityDecision:
    observed: Severity
    priority: Severity
    rationale: tuple[dict[str, str], ...]


def load_policy(path: Path | None = None) -> Policy:
    """Load and validate a policy document; its digest is its identity."""
    source = path or DEFAULT_POLICY_PATH
    try:
        document = json.loads(source.read_bytes())
        rules = document["rules"]
        kev, epss = rules["KEV_LISTED"], rules["EPSS_HIGH"]
        threshold = float(epss["threshold_exclusive"])
        models = frozenset(str(m) for m in epss["calibrated_models"])
        if kev["set_priority"] != "CRITICAL" or epss["set_min_priority"] != "HIGH":
            raise EnrichmentConfigurationError("policy v1 rules must keep their plan targets")
        if not 0.0 < threshold < 1.0:
            raise EnrichmentConfigurationError("EPSS threshold must be a probability")
        policy = Policy(
            document=document,
            digest=sha256_hex(canonical_json_bytes(document)),
            label=str(document.get("label", "")),
            epss_threshold=threshold,
            calibrated_models=models,
            kev_reason=str(kev["reason"]),
            epss_reason=str(epss["reason"]),
            epss_uncalibrated_reason=str(epss["uncalibrated_reason"]),
        )
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise EnrichmentConfigurationError(f"policy {source} is invalid: {exc}") from exc
    return policy


def decide(policy: Policy, inputs: PriorityInputs) -> PriorityDecision:
    """Pure, monotone priority decision with named reasons."""
    observed, recognized = Severity.parse(inputs.observed_severity)
    priority = observed
    rationale: list[dict[str, str]] = []
    if not recognized:
        rationale.append(
            {
                "rule": "FLOOR",
                "text": (
                    f"unrecognized observed severity {inputs.observed_severity!r} "
                    "ordered as LOW"
                ),
            }
        )

    if inputs.kev_listed:
        priority = max(priority, Severity.CRITICAL)
        for cve, due_date in inputs.kev_listed:
            rationale.append(
                {
                    "rule": "KEV_LISTED",
                    "text": policy.kev_reason.format(
                        cve=cve,
                        catalog_version=inputs.kev_catalog_version or "?",
                        due_date=due_date,
                    ),
                }
            )
    elif inputs.epss_max is not None:
        cve, score = inputs.epss_max
        model = inputs.epss_model_version or "?"
        if model not in policy.calibrated_models:
            rationale.append(
                {
                    "rule": "EPSS_UNCALIBRATED",
                    "text": policy.epss_uncalibrated_reason.format(model_version=model),
                }
            )
        elif score > policy.epss_threshold:
            priority = max(priority, Severity.HIGH)
            rationale.append(
                {
                    "rule": "EPSS_HIGH",
                    "text": policy.epss_reason.format(
                        cve=cve,
                        pct=f"{score * 100:.1f}",
                        model_version=model,
                        score_date=inputs.epss_score_date or "?",
                    ),
                }
            )

    for source in inputs.unavailable_sources:
        rationale.append({"rule": "CONTEXT_UNAVAILABLE", "text": f"{source} context unavailable"})
    if priority == observed:
        rationale.append({"rule": "FLOOR", "text": f"observed severity {observed.name} retained"})
    return PriorityDecision(observed=observed, priority=priority, rationale=tuple(rationale))

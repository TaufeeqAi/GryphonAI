"""The planner — pure construction of a step's intended work.

Everything here is a pure function over recorded facts: the authorization
context, the step specification, and the evidence rows earlier steps persisted.
No database, no graph, no tool. That is the point — the properties that matter
most in this layer (identity stability, coverage arithmetic, target provenance)
become unit-testable with fixtures instead of needing a live stack, a crash
harness and a packet capture.

A step's plan is built **once**, committed, and then read back forever. The
identities are computed here, at build time, and stored. Rebuilding the same
plan from the same recorded inputs must produce byte-identical identities, so
every input is explicit and every ordering is stable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from gryphon.constants import ScanDepth
from gryphon.orchestration.constants import (
    LEDGER_SCHEMA_VERSION,
    MAX_PLAN_ITEMS_PER_STEP,
    PlanItemState,
    StepSpec,
    TargetSource,
)
from gryphon.orchestration.identity import derive_execution_id, plan_digest, request_digest
from gryphon.orchestration.projection import ObservationType
from gryphon.tooling.tools.argbuilders import build_argv
from gryphon.tooling.tools.descriptors import get_descriptor


@dataclass(frozen=True, slots=True)
class PlannedTarget:
    """One target to plan, with the provenance that justifies scanning it."""

    canonical_target: str
    provenance: dict[str, Any]


@dataclass(frozen=True, slots=True)
class BuiltPlan:
    """A plan ready to commit atomically with its items."""

    plan_id: str
    scan_run_id: str
    stage: str
    step: str
    tool_id: str
    plan_generation: int
    plan_digest: str
    policy_version: str
    min_coverage_to_proceed: float
    items: list[dict[str, Any]]

    @property
    def item_count(self) -> int:
        return len(self.items)


def targets_for(
    spec: StepSpec,
    *,
    admitted_target: str,
    admitted_hosts: Sequence[PlannedTarget] = (),
    evidence: Iterable[Any] = (),
) -> list[PlannedTarget]:
    """Resolve a step's targets from recorded facts.

    ``evidence`` is the scan's persisted ``raw_finding`` rows. Reading them —
    rather than a previous step's return value — is what makes a re-planned step
    produce the same plan after a crash.
    """
    if spec.target_source is TargetSource.ADMITTED_TARGET:
        return [
            PlannedTarget(
                canonical_target=admitted_target,
                provenance={"source": "admission", "seed_target": admitted_target},
            )
        ]

    if spec.target_source is TargetSource.ADMITTED_HOSTS:
        # Admitted discoveries, plus the seed itself: the authorized target is
        # always in scope for the active stages and needs no attestation, since
        # it is the name the grant was issued for.
        seeded = [
            PlannedTarget(
                canonical_target=admitted_target,
                provenance={"source": "admission", "seed_target": admitted_target},
            )
        ]
        return _dedupe_targets(seeded + list(admitted_hosts))

    if spec.target_source is TargetSource.DISCOVERED_HOSTS:
        hosts = [
            PlannedTarget(
                canonical_target=row.canonical_target,
                provenance={
                    "source": ObservationType.SUBDOMAIN,
                    "discovered_by": row.tool_id,
                    "execution_id": row.execution_id,
                },
            )
            for row in evidence
            if row.observation_type == ObservationType.SUBDOMAIN
        ]
        return _dedupe_targets(hosts)

    if spec.target_source is TargetSource.LIVE_HTTP:
        live = [
            PlannedTarget(
                canonical_target=row.canonical_target,
                provenance={
                    "source": ObservationType.HTTP_SERVICE,
                    "discovered_by": row.tool_id,
                    "execution_id": row.execution_id,
                    "url": row.url,
                },
            )
            for row in evidence
            if row.observation_type == ObservationType.HTTP_SERVICE
        ]
        # A target with no live HTTP service is not a gap: there was simply
        # nothing to crawl or scan. An empty plan is a truthful empty plan.
        return _dedupe_targets(live)

    return []


def build_plan(
    spec: StepSpec,
    *,
    scan_run_id: str,
    targets: Sequence[PlannedTarget],
    execution_salt: str,
    policy_version: str,
    effective_depth: ScanDepth,
    plan_generation: int = 1,
    attempt_epoch: int = 0,
) -> BuiltPlan:
    """Build (but do not commit) a step plan with stored identities.

    Raises if the target set exceeds the hard per-step ceiling: a plan that
    large is a symptom, not a workload, and truncating it silently would be a
    coverage lie.
    """
    if len(targets) > MAX_PLAN_ITEMS_PER_STEP:
        raise ValueError(
            f"step {spec.stage.value}/{spec.step} would plan {len(targets)} items, "
            f"above the ceiling of {MAX_PLAN_ITEMS_PER_STEP}"
        )

    descriptor = get_descriptor(spec.tool_id)
    stage = spec.stage.value
    items: list[dict[str, Any]] = []
    digest_input: list[dict[str, Any]] = []

    for seq, target in enumerate(targets):
        # The exact argument vector the enforcement layer will construct, so the
        # digest covers depth clamping, rate floors, template tags and
        # containment flags. Two calls that differ in ANY of these get different
        # identities, which is what stops one silently deduplicating the other.
        argv = build_argv(spec.tool_id, descriptor, target.canonical_target, effective_depth)
        req_digest = request_digest(
            tool_id=spec.tool_id.value,
            canonical_target=target.canonical_target,
            effective_depth=effective_depth.value,
            descriptor_version=descriptor.descriptor_version,
            argv=tuple(argv),
        )
        execution_id = derive_execution_id(
            execution_salt=execution_salt,
            scan_run_id=scan_run_id,
            stage=stage,
            step=spec.step,
            seq=seq,
            tool_id=spec.tool_id.value,
            canonical_target=target.canonical_target,
            request_digest_hex=req_digest,
            policy_version=policy_version,
            attempt_epoch=attempt_epoch,
        )
        plan_item_id = f"{execution_id[:40]}"
        items.append(
            {
                "plan_item_id": plan_item_id,
                "plan_id": "",  # set below, once the plan id is known
                "scan_run_id": scan_run_id,
                "stage": stage,
                "step": spec.step,
                "seq": seq,
                "tool_id": spec.tool_id.value,
                "execution_id": execution_id,
                "request_digest": req_digest,
                "attempt_epoch": attempt_epoch,
                "attempts": 0,
                "canonical_target": target.canonical_target,
                "target_path": None,
                "effective_depth": effective_depth.value,
                "provenance": target.provenance,
                "state": PlanItemState.PLANNED.value,
                "claim_epoch": 0,
            }
        )
        digest_input.append(
            {
                "seq": seq,
                "canonical_target": target.canonical_target,
                "execution_id": execution_id,
                "request_digest": req_digest,
            }
        )

    digest = plan_digest(
        scan_run_id=scan_run_id,
        stage=stage,
        step=spec.step,
        plan_generation=plan_generation,
        policy_version=policy_version,
        items=digest_input,
    )
    plan_id = f"{scan_run_id[:8]}-{stage[:6]}-{spec.step[:16]}-g{plan_generation}-{digest[:12]}"
    for item in items:
        item["plan_id"] = plan_id

    return BuiltPlan(
        plan_id=plan_id,
        scan_run_id=scan_run_id,
        stage=stage,
        step=spec.step,
        tool_id=spec.tool_id.value,
        plan_generation=plan_generation,
        plan_digest=digest,
        policy_version=policy_version,
        min_coverage_to_proceed=spec.min_coverage_to_proceed,
        items=items,
    )


def ledger_schema_version() -> str:
    """The ledger schema version recorded with every committed plan."""
    return LEDGER_SCHEMA_VERSION


def _dedupe_targets(targets: Iterable[PlannedTarget]) -> list[PlannedTarget]:
    """Stable de-duplication by canonical target, first provenance wins.

    Stability is load-bearing: a plan item's sequence number is an input to its
    execution identity, so an unstable order would silently change identities
    between an original run and a resumed one.
    """
    seen: set[str] = set()
    out: list[PlannedTarget] = []
    for target in targets:
        key = target.canonical_target.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(target)
    return out

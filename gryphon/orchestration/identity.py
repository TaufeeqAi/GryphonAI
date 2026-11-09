"""Execution identity — pure, keyed, and computed exactly once.

The reliability core of this layer. An execution identity is derived with a
keyed KDF over the **full canonical request** and then **stored on the plan
item**; it is never recomputed at dispatch. Three properties follow, and each
closes a concrete failure:

* **Covers the request.** The tool arguments are inside the digest, so two
  genuinely different calls against the same target cannot collide and silently
  deduplicate into one — which would drop a real scan and report success.
* **Stable across a crash.** Nothing is recomputed, so a re-entered node
  re-reads the same identity and the enforcement layer returns the recorded
  outcome instead of launching a second subprocess. Determinism is a storage
  property here, not a hope about pure functions.
* **Unpredictable to anyone else.** The inputs are all public (the scan id
  appears in logs and the report), so an unkeyed hash would let any local
  process precompute the identities a scan will use and pre-register them at
  the enforcement layer, whose first-writer-wins idempotency would then
  deduplicate the real calls into silence. The per-scan salt — held only on the
  lifecycle row, never logged, reported or placed in graph state — removes that.

The canonicalizer version is an input, so a policy bump cannot silently
re-identify an in-flight scan's work.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any, Final

import rfc8785
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from gryphon.orchestration.constants import (
    EXECUTION_ID_BYTES,
    EXECUTION_ID_KDF_INFO_LABEL,
    EXECUTION_SALT_BYTES,
)

#: Domain-separation prefix for the request digest, so a digest computed here
#: can never be confused with a digest computed for another purpose.
_REQUEST_DIGEST_PREFIX: Final[bytes] = b"gryphon/orchestration/request/v1\x00"
#: Domain-separation prefix for a committed plan's digest.
_PLAN_DIGEST_PREFIX: Final[bytes] = b"gryphon/orchestration/plan/v1\x00"


def new_execution_salt() -> str:
    """Mint a per-scan execution salt.

    Stored once on the lifecycle row at claim time. It is a secret: excluded
    from graph state, logs, telemetry and the report.
    """
    return secrets.token_hex(EXECUTION_SALT_BYTES)


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Canonicalize ``payload`` with RFC 8785 JCS.

    One canonical form means a digest is reproducible across processes and
    library versions — the same discipline the authorization and enforcement
    layers already use for signed material.
    """
    return rfc8785.dumps(payload)


def request_digest(
    *,
    tool_id: str,
    canonical_target: str,
    effective_depth: str,
    descriptor_version: str,
    argv: tuple[str, ...] | list[str],
    path: str | None = None,
) -> str:
    """Digest the canonical request: what the tool will actually do.

    ``argv`` is the enforcement layer's constructed argument vector, so depth
    clamping, rate floors, template tags and containment flags are all covered.
    Change any of them and the identity changes, which is the point: the
    enforcement layer's deduplication contract is conditioned on the request
    being the same, and this is what makes that true by construction.
    """
    payload = {
        "tool_id": tool_id,
        "canonical_target": canonical_target,
        "effective_depth": effective_depth,
        "descriptor_version": descriptor_version,
        "argv": list(argv),
        "path": path,
    }
    digest = hashlib.sha256(_REQUEST_DIGEST_PREFIX + canonical_bytes(payload)).hexdigest()
    return digest


def derive_execution_id(
    *,
    execution_salt: str,
    scan_run_id: str,
    stage: str,
    step: str,
    seq: int,
    tool_id: str,
    canonical_target: str,
    request_digest_hex: str,
    policy_version: str,
    attempt_epoch: int,
) -> str:
    """Derive the stored execution identity for one planned item.

    Called **once**, at plan commit. The result is persisted on the plan item
    and read back on every dispatch, retry and resume.

    ``attempt_epoch`` advances only through an explicit, audited replan of an
    item proven not to have contacted its target — never on an indeterminate
    outcome, which routes to reconciliation instead.
    """
    if not execution_salt:
        raise ValueError("execution_salt is required: an unkeyed identity is predictable")
    info = canonical_bytes(
        {
            "label": EXECUTION_ID_KDF_INFO_LABEL,
            "scan_run_id": scan_run_id,
            "stage": stage,
            "step": step,
            "seq": seq,
            "tool_id": tool_id,
            "canonical_target": canonical_target,
            "request_digest": request_digest_hex,
            "policy_version": policy_version,
            "attempt_epoch": attempt_epoch,
        }
    )
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=EXECUTION_ID_BYTES,
        salt=bytes.fromhex(execution_salt),
        info=info,
    )
    return kdf.derive(b"gryphon-execution-identity").hex()


def plan_digest(
    *,
    scan_run_id: str,
    stage: str,
    step: str,
    plan_generation: int,
    policy_version: str,
    items: list[dict[str, Any]],
) -> str:
    """Digest a committed step plan so it can be proven stable across a resume.

    ``items`` carries each item's ordering, target and execution identity. A
    stable digest is what lets a re-invocation assert it is continuing the same
    plan rather than a recomputed one.
    """
    payload = {
        "scan_run_id": scan_run_id,
        "stage": stage,
        "step": step,
        "plan_generation": plan_generation,
        "policy_version": policy_version,
        "items": items,
    }
    return hashlib.sha256(_PLAN_DIGEST_PREFIX + canonical_bytes(payload)).hexdigest()


def content_digest(payload: dict[str, Any]) -> str:
    """Digest an artifact's content (used for the report attestation).

    The report itself is not signed with the audit key — that key has a
    different purpose and mixing purposes erodes the key separation the
    upstream layers established. Instead a signed audit event carries this
    digest, which gives the same tamper evidence through the existing key and
    the existing verifier.
    """
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()

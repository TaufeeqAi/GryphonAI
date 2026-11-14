"""Identities: who asked, what was observed, and what the claim is about.

Four distinct identity problems live here, and conflating any two of them has
already been the cause of a defect somewhere in this platform:

* **Who asked.** The caller is the process's *real* uid, never a value it
  supplies. The label carries an explicit scheme (``cli:uid:<n>``) so a future
  transport can add a principal form without the old labels in signed history
  becoming ambiguous.

* **What one contact is.** ``execution_id`` is derived from the *whole* canonical
  request envelope, so one id can mean exactly one request. The derivation is
  keyed by a per-pass secret salt, which makes identities unpredictable to a
  target while staying stable across a resume — that is what lets a resumed pass
  present the same id and get the recorded outcome instead of sending traffic.

* **Which control.** A control locator must be a path the target cannot predict
  in advance, or a host that wants to look clean could special-case it. It comes
  from the same keyed derivation, so it is also identical on resume.

* **What the claim is about.** ``subject_key`` is the identity that outlives a
  scan. A ``raw_finding``'s id is unique per scan by construction, so two scans
  of the same unchanged exposure share nothing — and "is Monday's confirmed
  exposure still there after Tuesday's deploy?" has nothing to join on. The
  subject key is that join, and it is written from the first migration because
  retrofitting an identity underneath append-only signed rows is the expensive
  path.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.tooling.observation.envelope import RequestEnvelope
from gryphon.verification.constants import (
    CONTROL_LOCATOR_BYTES,
    CONTROL_LOCATOR_DOMAIN,
    EXECUTION_ID_DOMAIN,
    PROBE_ID_DOMAIN,
    SUBJECT_KEY_DOMAIN,
    SUBJECT_KEY_VERSION,
    ObservationRole,
)
from gryphon.verification.reasons import CallerRejected, InvalidScanId

#: Identity-label scheme for a direct CLI caller. A future socket or API
#: transport adds its own scheme rather than reusing this one, so signed history
#: stays unambiguous about which kind of principal acted.
CLI_IDENTITY_SCHEME: Final[str] = "cli:uid"

#: Pass salt length. 32 bytes is well beyond the 128-bit floor the execution-id
#: contract requires and costs nothing.
PASS_SALT_BYTES: Final[int] = 32

_EXECUTION_ID_BYTES: Final[int] = 32


@dataclass(frozen=True, slots=True)
class CallerIdentity:
    uid: int
    label: str


def local_cli_identity(*, allowed_uids: Sequence[int] = ()) -> CallerIdentity:
    """Identify a direct CLI caller by its own uid; enforce the allowlist.

    An empty allowlist permits any local user outside production. Production
    requires a non-empty list, which the settings refuse to start without.
    """
    uid = os.getuid() if hasattr(os, "getuid") else -1
    if allowed_uids and uid not in allowed_uids:
        raise CallerRejected(f"uid {uid} is not permitted to run verification")
    return CallerIdentity(uid=uid, label=f"{CLI_IDENTITY_SCHEME}:{uid}")


def canonical_scan_id(raw: str) -> str:
    """Canonical UUID text, as the orchestration layer generates it."""
    try:
        return str(uuid.UUID(str(raw).strip()))
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidScanId(f"{raw!r} is not a scan run id") from exc


def new_pass_id() -> str:
    """A fresh pass identifier."""
    return uuid.uuid4().hex


def new_pass_salt() -> bytes:
    """A per-pass secret salt.

    Stored only on the pass row — never in a view, a report, a log line or
    telemetry. It is what makes observation identities and control locators
    unpredictable from outside the system while remaining reproducible inside it.
    """
    return os.urandom(PASS_SALT_BYTES)


def observation_id(
    *,
    pass_id: str,
    finding_id: str,
    verifier_id: str,
    role: ObservationRole,
    control_index: int,
) -> str:
    """The identity of one planned observation within a pass.

    Deliberately *not* keyed: this is a local bookkeeping identity that appears
    in our own rows and logs. The unpredictable one is ``execution_id``, which is
    what reaches the gateway and therefore what a target could otherwise try to
    anticipate.
    """
    digest = hashlib.sha256()
    digest.update(PROBE_ID_DOMAIN)
    for part in (pass_id, finding_id, verifier_id, role.value, str(control_index)):
        digest.update(b"\x00")
        digest.update(part.encode("utf-8"))
    return digest.hexdigest()


def execution_id(
    *,
    pass_salt: bytes,
    envelope: RequestEnvelope,
    finding_id: str,
    role: ObservationRole,
    control_index: int,
) -> str:
    """The gateway-facing identity of one contact, bound to its whole envelope.

    Binding the envelope digest is what makes "same id, different request" a
    detectable conflict rather than an article of faith: the gateway stores the
    digest and refuses a mismatch before any traffic. Scheme and port are inside
    the envelope, so a probe answered over a different scheme is a different
    identity rather than a silent substitution.
    """
    info = canonical_json_bytes(
        {
            "envelope_digest": envelope.digest,
            "finding_id": finding_id,
            "role": role.value,
            "control_index": control_index,
        }
    )
    return hmac.new(pass_salt, EXECUTION_ID_DOMAIN + info, hashlib.sha256).hexdigest()[
        : _EXECUTION_ID_BYTES * 2
    ]


def control_locator(
    *,
    pass_salt: bytes,
    finding_id: str,
    control_index: int,
    suffix: str = "",
) -> str:
    """An unpredictable path segment for a control request.

    A control asks for something that should not exist. If the segment were
    predictable, a host that wanted to look clean could answer it differently
    from everything else and defeat the comparison.
    """
    info = canonical_json_bytes(
        {"finding_id": finding_id, "control_index": control_index, "suffix": suffix}
    )
    raw = hmac.new(pass_salt, CONTROL_LOCATOR_DOMAIN + info, hashlib.sha256).digest()
    return raw[:CONTROL_LOCATOR_BYTES].hex()


def subject_key(
    *,
    kind: str,
    canonical_target: str,
    locator: str | None,
    finding_class: str,
) -> str:
    """The identity of the thing a claim is about, stable across scans.

    ``locator`` is the within-target address of the subject: a normalized path
    for an HTTP exposure, a record type for a DNS one, ``None`` where the claim
    is about the host as a whole. ``finding_class`` is the registry's class key,
    not a template id, so a template rename does not split a subject's history.
    """
    payload = {
        "subject_key_version": SUBJECT_KEY_VERSION,
        "kind": kind,
        "canonical_target": canonical_target.strip().lower(),
        "locator": locator,
        "class": finding_class,
    }
    return sha256_hex(SUBJECT_KEY_DOMAIN + canonical_json_bytes(payload))


def report_id_for(scan_run_id: str, report_digest: str) -> str:
    """Human-readable report identity: scan prefix, purpose, content prefix."""
    return f"{scan_run_id[:8]}-ver-{report_digest[:16]}"


def request_key_digest(request_key: str) -> str:
    """A digest of the caller's request key, for logs.

    The key itself can be anything the caller chose, including something they
    consider sensitive. Logs carry the digest so a repeated command is still
    traceable without recording the operator's chosen string.
    """
    return sha256_hex(request_key.encode("utf-8"))

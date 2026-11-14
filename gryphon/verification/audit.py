"""Signed verification events, under this layer's own key.

Every event here is signed with the dedicated verification key and with nothing
else. That is a custody rule rather than a naming rule: this process must not be
able to produce a signature it is also required to verify, or a compromise of it
would be enough to fabricate an input and mint the attestation that makes the
fabrication look genuine.

The event set is deliberately small and covers the moments where the layer
either refuses to act, stops acting, or publishes a claim — the points at which
an operator or an auditor needs to know what happened without taking the
layer's word for it afterwards.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from gryphon.auth.key_provider import Ed25519SigningKey
from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.clock import ensure_utc
from gryphon.verification.constants import (
    VERIFICATION_AUDIT_EVENT_SCHEMA_VERSION,
    VerificationEventType,
)


@dataclass(frozen=True, slots=True)
class SignedVerificationEvent:
    """A canonical payload plus the signature that vouches for it."""

    event_id: str
    event_type: str
    scan_run_id: str
    pass_id: str | None
    payload: dict[str, Any]
    payload_digest: str
    signer_kid: str
    signature_b64: str

    @property
    def signature_bytes(self) -> bytes:
        return base64.standard_b64decode(self.signature_b64)


class VerificationAuditBuilder:
    """Builds and signs canonical verification events."""

    def __init__(self, signing_key: Ed25519SigningKey) -> None:
        self._key = signing_key

    @property
    def kid(self) -> str:
        return self._key.kid

    # -- lifecycle ------------------------------------------------------------
    def pass_refused(
        self, *, scan_run_id: str, pass_id: str, reason: str, detail: str, at: datetime
    ) -> SignedVerificationEvent:
        return self._sign(
            VerificationEventType.PASS_REFUSED,
            scan_run_id=scan_run_id,
            pass_id=pass_id,
            body={"reason": reason, "detail": detail},
            at=at,
        )

    def pass_blocked(
        self, *, scan_run_id: str, pass_id: str, dependency: str, at: datetime
    ) -> SignedVerificationEvent:
        """Recorded because a blocked pass is a statement about *us*.

        An operator reading a report full of INCONCLUSIVE verdicts deserves to
        know whether the client's estate was ambiguous or our own dependency was
        down. The second is not the client's problem and must not read as if it
        were.
        """
        return self._sign(
            VerificationEventType.PASS_BLOCKED,
            scan_run_id=scan_run_id,
            pass_id=pass_id,
            body={"dependency": dependency},
            at=at,
        )

    def pass_abandoned(
        self, *, scan_run_id: str, pass_id: str, reason: str, detail: str, at: datetime
    ) -> SignedVerificationEvent:
        return self._sign(
            VerificationEventType.PASS_ABANDONED,
            scan_run_id=scan_run_id,
            pass_id=pass_id,
            body={"reason": reason, "detail": detail},
            at=at,
        )

    # -- deliverable ----------------------------------------------------------
    def report_emitted(
        self,
        *,
        scan_run_id: str,
        pass_id: str,
        report_id: str,
        report_digest: str,
        verdict_set_digest: str,
        manifest_digest: str,
        base_report_digest: str,
        enrichment_report_digest: str | None,
        verifier_versions: dict[str, str],
        ordering_basis: str,
        at: datetime,
    ) -> SignedVerificationEvent:
        """Attests the deliverable, and names the verifiers it rested on.

        The verifier versions are part of the attestation so a later withdrawal
        can find exactly which reports relied on an unsound predicate. Without
        them, retracting a proof would mean guessing at its provenance.
        """
        return self._sign(
            VerificationEventType.REPORT_EMITTED,
            scan_run_id=scan_run_id,
            pass_id=pass_id,
            body={
                "report_id": report_id,
                "report_digest": report_digest,
                "verdict_set_digest": verdict_set_digest,
                "manifest_digest": manifest_digest,
                "base_report_digest": base_report_digest,
                "enrichment_report_digest": enrichment_report_digest,
                "verifier_versions": dict(sorted(verifier_versions.items())),
                "ordering_basis": ordering_basis,
            },
            at=at,
        )

    def verifier_withdrawn(
        self,
        *,
        scan_run_id: str,
        verifier_id: str,
        reason: str,
        approved_by: str,
        retractions: int,
        at: datetime,
    ) -> SignedVerificationEvent:
        """A proof taken back, said out loud.

        Withdrawal never edits a verdict. It records that the predicate behind a
        set of verdicts was found unsound, who approved saying so, and how many
        claims are affected — so a client can be told, which is the part that
        cannot be done at all if nobody wrote it down.
        """
        return self._sign(
            VerificationEventType.VERIFIER_WITHDRAWN,
            scan_run_id=scan_run_id,
            pass_id=None,
            body={
                "verifier_id": verifier_id,
                "reason": reason,
                "approved_by": approved_by,
                "retractions": retractions,
            },
            at=at,
        )

    # -- internals ------------------------------------------------------------
    def _sign(
        self,
        event_type: VerificationEventType,
        *,
        scan_run_id: str,
        pass_id: str | None,
        body: dict[str, Any],
        at: datetime,
    ) -> SignedVerificationEvent:
        event_id = uuid.uuid4().hex
        payload: dict[str, Any] = {
            "event_schema_version": VERIFICATION_AUDIT_EVENT_SCHEMA_VERSION,
            "event_id": event_id,
            "event_type": event_type.value,
            "scan_run_id": scan_run_id,
            "pass_id": pass_id,
            "occurred_at": ensure_utc(at).isoformat(),
            "signer_kid": self._key.kid,
            **body,
        }
        canonical = canonical_json_bytes(payload)
        signature = self._key.sign(canonical)
        return SignedVerificationEvent(
            event_id=event_id,
            event_type=event_type.value,
            scan_run_id=scan_run_id,
            pass_id=pass_id,
            payload=payload,
            payload_digest=sha256_hex(canonical),
            signer_kid=self._key.kid,
            signature_b64=base64.standard_b64encode(signature).decode("ascii"),
        )

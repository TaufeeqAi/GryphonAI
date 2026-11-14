"""Errors raised by the verification layer.

Refusals, blocks and abandonments are *outcomes*: they are recorded, audited and
reported, not raised. A verdict of INCONCLUSIVE is a result, not a failure — the
whole point of the layer is that "we could not tell" is an answer it is willing
to publish.

The exceptions here are for conditions that must stop the process instead:
configuration that would weaken a control, a fenced-out writer, an identity that
two writers disagree about, or a dependency whose absence makes the next step
unsafe rather than merely unknown.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from gryphon.verification.constants import BlockedReason


class VerificationError(Exception):
    """Base class for verification errors."""


class VerificationConfigurationError(VerificationError):
    """Configuration that would weaken a control. Refused at startup.

    Includes the custody refusals: a second database identity, or any signing
    key other than the verification key being loadable in this process.
    """


class FencedOut(VerificationError):
    """A newer holder owns the pass; this process must stop writing.

    Raised when a lifecycle compare-and-set fails on ``claim_epoch`` or when the
    lease keeper has not renewed within its validity. The engine must also stop
    *dispatching*, not merely stop writing: the gateway enforces that
    independently, but a fenced process should not be asking.
    """


class PassBusy(VerificationError):
    """Another open pass owns this scan."""

    def __init__(
        self, scan_run_id: str, holder: str | None, lease_expires_at: object | None
    ) -> None:
        self.scan_run_id = scan_run_id
        self.holder = holder
        self.lease_expires_at = lease_expires_at
        super().__init__(
            f"scan {scan_run_id} has an open verification pass held by "
            f"{holder or 'another process'}"
            + (f" until {lease_expires_at}" if lease_expires_at else "")
        )


class RequestKeyConflict(VerificationError):
    """The same request key was presented with a different request.

    A repeated command is safe and returns its original pass. A *changed*
    command under a reused key is ambiguous — the caller may believe either
    request ran — so it is refused rather than guessed at.
    """

    def __init__(self, request_key: str, detail: str) -> None:
        self.request_key = request_key
        super().__init__(f"request key {request_key!r} was used for a different request: {detail}")


class InvalidScanId(VerificationError):
    """The scan identifier is not a well-formed scan run id."""


class IdentityConflictError(VerificationError):
    """A keyed row already exists with different content.

    Two writers disagree about one identity. That is an integrity failure, not a
    retry: the pass stops and an operator decides.
    """


class PinAlreadyWritten(VerificationError):
    """Pins are write-once; a second attempt means the pass was re-planned.

    The pin row is the provenance root for every append-only verdict in the
    pass. If it could move, earlier work would become unexplainable.
    """


class ProjectionIntegrityError(VerificationError):
    """A stored evidence projection does not match its recorded digest."""


class CallerRejected(VerificationError):
    """The invoking user is not permitted to run verification."""


class RegistryError(VerificationError):
    """The verifier registry is unusable.

    Covers an invalid document, an unsigned one in production, a spec whose
    observation kind is outside the closed catalog, a resource-specific claim
    with no control strategy and no stated reason, and a spec that can derive a
    target the gateway cannot express.
    """


class GatewayUnavailable(VerificationError):
    """The tool execution gateway service could not be reached.

    This is deliberately *not* mapped to a verdict. A pass that published
    thousands of INCONCLUSIVE verdicts because its own dependency was down would
    be reporting our outage as the client's ambiguity. The pass blocks instead.
    """

    def __init__(self, reason: BlockedReason, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)


class GatewayProtocolError(VerificationError):
    """The gateway speaks a protocol or feature set this layer cannot trust.

    Refused before any dispatch. Mapping an unknown schema to INCONCLUSIVE would
    protect verdict correctness while still permitting traffic from a gateway
    that is missing an enforcement feature the invariants rest on.
    """


class ObservationSchemaError(VerificationError):
    """A returned observation does not satisfy its kind's closed schema.

    The observer is unprivileged and its output is untrusted. A document that
    does not validate is a failure of that boundary, never a partially-trusted
    result.
    """

"""The gateway wire protocol: framing, typed messages and the feature handshake.

The tool execution gateway is a service with its own uid, its own database role
and its own audit key, so everything the verification layer asks of it crosses a
socket. This module is the whole of that boundary: the frame format, the four
messages, and the compatibility check that decides whether a dispatch may happen
at all.

**Framing is length-prefixed, not newline-delimited.** These documents carry no
body and no target-controlled text, but a typed document can still contain a
newline in principle — a reason string, a header name, a CNAME label — and a
framing scheme that depends on content is a framing scheme that content can
break. A four-byte big-endian length states how many bytes the next document
occupies before any of it is parsed, so an oversized or malformed frame is
refused by the reader instead of being resynchronized by hunting for a
delimiter. Framing must not depend on what is framed.

**The handshake is a gate, not a label.** The service advertises its protocol
version and the enforcement features it implements. A missing security-critical
feature refuses every dispatch: mapping it to INCONCLUSIVE would protect the
verdict while still permitting traffic from a gateway that is not enforcing the
properties the invariants rest on (CHG-P5-034).

**Reason codes are a closed vocabulary with exactly one outcome class each.**
Collapsing policy, capacity and world facts into one "denied" is how a two-second
dependency blip reads as a scope violation, and how NXDOMAIN — the positive case
for takeover verification — reads as a refusal (CHG-P5-013).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final, Protocol

from gryphon.canonical import canonical_json_bytes, sha256_hex, strict_json_loads
from gryphon.errors import ValidationError
from gryphon.tooling.observation.facts import Completeness, ObservationFacts
from gryphon.verification.constants import (
    GATEWAY_PROTOCOL_VERSION,
    REQUIRED_GATEWAY_FEATURES,
    ObservationRole,
    OutcomeClass,
)
from gryphon.verification.reasons import GatewayProtocolError, ObservationSchemaError

__all__ = [
    "FRAME_HEADER_BYTES",
    "HANDSHAKE_DEADLINE_SECONDS",
    "MAX_FRAME_BYTES",
    "OUTCOME_FOR_REASON",
    "ByteReader",
    "ByteWriter",
    "FeatureSet",
    "GatewayReason",
    "Hello",
    "MessageType",
    "ObserveReply",
    "ObserveRequest",
    "Welcome",
    "assert_compatible",
    "encode_frame",
    "read_frame",
    "write_frame",
]

#: Big-endian unsigned length prefix. Four bytes is the smallest width that can
#: express the cap below without the cap itself becoming the parser's business.
FRAME_HEADER_BYTES: Final[int] = 4

#: Caps on the caller-supplied signal-token list. Bounded at the frame
#: boundary because an unbounded list would already have cost the gateway the
#: memory to parse it; the observer caps them again on its own side.
_MAX_SIGNAL_TOKENS: Final[int] = 32
_MAX_SIGNAL_TOKEN_CHARS: Final[int] = 128

#: Hard ceiling on one frame. A frame carries typed facts and counts, never a
#: body, so this is far above any legitimate document: anything larger is a
#: boundary failure to refuse, not a large response to accommodate.
MAX_FRAME_BYTES: Final[int] = 262_144

#: How long a peer may take to complete the handshake. A connection that has not
#: identified itself is holding a slot on a privileged socket.
HANDSHAKE_DEADLINE_SECONDS: Final[float] = 5.0


class MessageType(StrEnum):
    """Every frame names itself.

    A frame read in the wrong order is then a diagnosable protocol error rather
    than a document that happens to parse because two messages share a field.
    """

    HELLO = "hello"
    WELCOME = "welcome"
    OBSERVE_REQUEST = "observe_request"
    OBSERVE_REPLY = "observe_reply"


class GatewayReason(StrEnum):
    """Why the gateway answered as it did.

    The values deliberately match the verification layer's justification names
    where one exists, so the mapping from a refusal to a verdict is an identity
    rather than a translation table that can drift.
    """

    # -- the request was carried out ------------------------------------------
    OBSERVED = "observed"

    # -- permanent policy refusals (zero traffic) ------------------------------
    PURPOSE_FORBIDDEN = "purpose_forbidden"
    KIND_FORBIDDEN = "kind_forbidden"
    ENVELOPE_MALFORMED = "envelope_malformed"
    DESCRIPTOR_MISMATCH = "descriptor_mismatch"
    PEER_REFUSED = "peer_refused"
    EPOCH_STALE = "epoch_stale"
    CANCELLED = "cancelled"
    ENVELOPE_CONFLICT = "envelope_conflict"
    AUTHORIZATION_UNAVAILABLE = "authorization_unavailable"
    DEADLINE_EXCEEDS_GRANT = "deadline_exceeds_grant"
    SCOPE_EXCLUDED = "scope_excluded"
    SCOPE_NO_MATCH = "scope_no_match"
    DESTINATION_UNATTESTED = "destination_unattested"
    DESTINATION_MISMATCH = "destination_mismatch"

    # -- transient capacity refusals (retryable before intent) -----------------
    BUDGET_EXHAUSTED = "budget_exhausted"
    RATE_LIMITED = "rate_limited"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"

    # -- facts about the world, routed to the verifier as evidence -------------
    NXDOMAIN = "nxdomain"
    NO_ANSWER = "no_answer"
    DESTINATION_UNRESOLVABLE = "destination_unresolvable"

    # -- the attempt happened and did not produce usable facts -----------------
    TIMEOUT = "timeout"
    UNREACHABLE = "unreachable"
    PROBE_FAILED = "probe_failed"
    OBSERVATION_LOST = "observation_lost"


#: Each reason belongs to exactly one outcome class. The gateway builds every
#: reply through this table so a reason cannot be emitted under two classes.
OUTCOME_FOR_REASON: Final[dict[GatewayReason, OutcomeClass]] = {
    GatewayReason.OBSERVED: OutcomeClass.OBSERVED,
    GatewayReason.PURPOSE_FORBIDDEN: OutcomeClass.REFUSED_POLICY,
    GatewayReason.KIND_FORBIDDEN: OutcomeClass.REFUSED_POLICY,
    GatewayReason.ENVELOPE_MALFORMED: OutcomeClass.REFUSED_POLICY,
    GatewayReason.DESCRIPTOR_MISMATCH: OutcomeClass.REFUSED_POLICY,
    GatewayReason.PEER_REFUSED: OutcomeClass.REFUSED_POLICY,
    GatewayReason.EPOCH_STALE: OutcomeClass.REFUSED_POLICY,
    GatewayReason.CANCELLED: OutcomeClass.REFUSED_POLICY,
    GatewayReason.ENVELOPE_CONFLICT: OutcomeClass.REFUSED_POLICY,
    GatewayReason.AUTHORIZATION_UNAVAILABLE: OutcomeClass.REFUSED_POLICY,
    GatewayReason.DEADLINE_EXCEEDS_GRANT: OutcomeClass.REFUSED_POLICY,
    GatewayReason.SCOPE_EXCLUDED: OutcomeClass.REFUSED_POLICY,
    GatewayReason.SCOPE_NO_MATCH: OutcomeClass.REFUSED_POLICY,
    GatewayReason.DESTINATION_UNATTESTED: OutcomeClass.REFUSED_POLICY,
    GatewayReason.DESTINATION_MISMATCH: OutcomeClass.REFUSED_POLICY,
    GatewayReason.BUDGET_EXHAUSTED: OutcomeClass.REFUSED_CAPACITY,
    GatewayReason.RATE_LIMITED: OutcomeClass.REFUSED_CAPACITY,
    GatewayReason.DEPENDENCY_UNAVAILABLE: OutcomeClass.REFUSED_CAPACITY,
    GatewayReason.NXDOMAIN: OutcomeClass.WORLD_FACT,
    GatewayReason.NO_ANSWER: OutcomeClass.WORLD_FACT,
    GatewayReason.DESTINATION_UNRESOLVABLE: OutcomeClass.WORLD_FACT,
    GatewayReason.TIMEOUT: OutcomeClass.TIMED_OUT,
    GatewayReason.UNREACHABLE: OutcomeClass.FAILED,
    GatewayReason.PROBE_FAILED: OutcomeClass.FAILED,
    GatewayReason.OBSERVATION_LOST: OutcomeClass.OBSERVATION_LOST,
}


# =============================================================================
# Streams
# =============================================================================


class ByteReader(Protocol):
    """The read half of a duplex stream.

    Narrowed to ``readexactly`` on purpose: a length-prefixed reader never needs
    to search for a delimiter, and a reader that cannot scan cannot be steered
    by content.
    """

    async def readexactly(self, n: int, /) -> bytes: ...


class ByteWriter(Protocol):
    """The write half of a duplex stream, satisfied by ``asyncio.StreamWriter``."""

    def write(self, data: bytes, /) -> None: ...

    async def drain(self) -> None: ...

    def close(self) -> None: ...

    async def wait_closed(self) -> None: ...


# =============================================================================
# Framing
# =============================================================================


def encode_frame(payload: dict[str, Any]) -> bytes:
    """Serialize one message to a length-prefixed canonical JSON frame.

    Canonical (RFC 8785) rather than merely valid JSON: the same message must
    produce the same bytes in every process, because a frame's contents are
    hashed into the digest a pass pins and into the envelope identity the
    gateway compares.
    """
    body = canonical_json_bytes(payload)
    if len(body) > MAX_FRAME_BYTES:
        raise GatewayProtocolError(
            f"refusing to send a {len(body)}-byte frame; the cap is {MAX_FRAME_BYTES}"
        )
    return len(body).to_bytes(FRAME_HEADER_BYTES, "big") + body


async def write_frame(writer: ByteWriter, payload: dict[str, Any]) -> None:
    """Write one frame and wait for it to leave the buffer."""
    writer.write(encode_frame(payload))
    await writer.drain()


async def read_frame(reader: ByteReader) -> dict[str, Any]:
    """Read exactly one frame, or refuse.

    The length is checked against the cap *before* the body is read, so an
    oversize claim costs nothing: a peer cannot make this process allocate a
    buffer by asserting a size. A short or truncated stream is left to propagate
    as the transport error it is — the caller distinguishes "the gateway went
    away" (which blocks a pass) from "the gateway said something invalid" (which
    refuses one).
    """
    header = await reader.readexactly(FRAME_HEADER_BYTES)
    length = int.from_bytes(header, "big")
    if length == 0:
        raise GatewayProtocolError("empty frame")
    if length > MAX_FRAME_BYTES:
        raise GatewayProtocolError(f"frame of {length} bytes exceeds the {MAX_FRAME_BYTES} cap")
    body = await reader.readexactly(length)
    try:
        return strict_json_loads(body)
    except ValidationError as exc:
        raise GatewayProtocolError(
            f"frame is not a well-formed document: {exc.reason_code.value}"
        ) from exc


# -- payload accessors --------------------------------------------------------
# JSON arrives as `Any`; these narrow it once, at the boundary, so no message
# constructor has to.


def _expect(payload: dict[str, Any], message: MessageType) -> None:
    kind = payload.get("message")
    if kind != message.value:
        raise GatewayProtocolError(f"expected a {message.value} frame, received {kind!r}")


def _text(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise GatewayProtocolError(f"{key} must be a string")
    return value


def _whole(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GatewayProtocolError(f"{key} must be a non-negative integer")
    return value


def _number(payload: dict[str, Any], key: str) -> float:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise GatewayProtocolError(f"{key} must be a number")
    return float(value)


def _tokens(payload: dict[str, Any], key: str) -> tuple[str, ...]:
    """Read a bounded list of signal tokens.

    Caller-supplied, so bounded here rather than downstream: the observer caps
    them again on its own side, but a frame that could carry an unbounded list
    would already have cost the gateway the memory to parse it.
    """
    raw = payload.get(key)
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > _MAX_SIGNAL_TOKENS:
        raise GatewayProtocolError(f"{key} must be a list of at most {_MAX_SIGNAL_TOKENS} tokens")
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item or len(item) > _MAX_SIGNAL_TOKEN_CHARS:
            raise GatewayProtocolError(f"{key} contains a token that is empty or too long")
        out.append(item)
    return tuple(out)


def _mapping(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise GatewayProtocolError(f"{key} must be an object")
    return value


def _string_map(payload: dict[str, Any], key: str) -> dict[str, str]:
    return {str(k): str(v) for k, v in _mapping(payload, key).items()}


# =============================================================================
# Messages
# =============================================================================


@dataclass(frozen=True, slots=True)
class Hello:
    """Client to server, first frame on every connection."""

    protocol_version: str
    client_name: str

    def as_payload(self) -> dict[str, Any]:
        return {
            "message": MessageType.HELLO.value,
            "protocol_version": self.protocol_version,
            "client_name": self.client_name,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> Hello:
        _expect(payload, MessageType.HELLO)
        name = _text(payload, "client_name")
        if not name or len(name) > 128:
            raise GatewayProtocolError("client_name must be 1..128 characters")
        return cls(protocol_version=_text(payload, "protocol_version"), client_name=name)


@dataclass(frozen=True, slots=True)
class Welcome:
    """Server to client: what this gateway is and what it enforces.

    ``digest`` is the value a pass pins. Every field below changes what a
    dispatch means — which binary runs, which extractors evaluate its bytes,
    which enforcement steps are present — so a mid-pass change to any of them
    invalidates the pin rather than silently altering the evidence behind
    verdicts already written.
    """

    protocol_version: str
    feature_set: frozenset[str]
    descriptor_versions: dict[str, str] = field(default_factory=dict)
    extractor_set_digest: str = ""
    sanitizer_ruleset_digest: str = ""
    binary_digests: dict[str, str] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        return {
            "message": MessageType.WELCOME.value,
            "protocol_version": self.protocol_version,
            "feature_set": sorted(self.feature_set),
            "descriptor_versions": dict(sorted(self.descriptor_versions.items())),
            "extractor_set_digest": self.extractor_set_digest,
            "sanitizer_ruleset_digest": self.sanitizer_ruleset_digest,
            "binary_digests": dict(sorted(self.binary_digests.items())),
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> Welcome:
        _expect(payload, MessageType.WELCOME)
        features = payload.get("feature_set")
        if not isinstance(features, list) or not all(isinstance(f, str) for f in features):
            raise GatewayProtocolError("feature_set must be a list of strings")
        return cls(
            protocol_version=_text(payload, "protocol_version"),
            feature_set=frozenset(str(f) for f in features),
            descriptor_versions=_string_map(payload, "descriptor_versions"),
            extractor_set_digest=_text(payload, "extractor_set_digest"),
            sanitizer_ruleset_digest=_text(payload, "sanitizer_ruleset_digest"),
            binary_digests=_string_map(payload, "binary_digests"),
        )

    @property
    def features(self) -> FeatureSet:
        return FeatureSet(self.feature_set)

    @property
    def digest(self) -> str:
        """SHA-256 over the canonical form — the per-pass capability pin."""
        return sha256_hex(canonical_json_bytes(self.as_payload()))


@dataclass(frozen=True, slots=True)
class ObserveRequest:
    """Client to server: one contact, described exactly once.

    The request names no tool. The observation kind inside the envelope selects
    the binary and its descriptor, and the kind catalog is closed — which is what
    stops a verification purpose from reaching a scan tool by naming one.
    """

    purpose: str
    pass_id: str
    claim_epoch: int
    cancellation_epoch: int
    execution_id: str
    #: ``RequestEnvelope.as_canonical()``. Carried as the mapping it was
    #: digested over, never re-derived here: re-deriving it would mean the
    #: identity the gateway compares is not the identity the caller sent.
    envelope: dict[str, Any]
    deadline_seconds: float
    scan_run_id: str
    finding_id: str
    role: ObservationRole
    #: Which control this is, for a control observation; ``None`` for a primary.
    control_index: int | None = None
    #: Signal tokens the observer's ``token_presence`` extractor looks for.
    #: They travel with the request because they are the verifier's own copy of
    #: a detection template's signal — pinned in the registry so an unpinned
    #: template update cannot silently change what a pass refutes. They are
    #: NOT part of the envelope digest: they change what is *measured*, not
    #: what is *contacted*, and the identity describes the contact.
    signal_tokens: tuple[str, ...] = ()

    def as_payload(self) -> dict[str, Any]:
        return {
            "message": MessageType.OBSERVE_REQUEST.value,
            "purpose": self.purpose,
            "pass_id": self.pass_id,
            "claim_epoch": self.claim_epoch,
            "cancellation_epoch": self.cancellation_epoch,
            "execution_id": self.execution_id,
            "envelope": dict(self.envelope),
            "deadline_seconds": self.deadline_seconds,
            "scan_run_id": self.scan_run_id,
            "finding_id": self.finding_id,
            "role": self.role.value,
            "control_index": self.control_index,
            "signal_tokens": list(self.signal_tokens),
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> ObserveRequest:
        _expect(payload, MessageType.OBSERVE_REQUEST)
        control_index = payload.get("control_index")
        if control_index is not None and (
            not isinstance(control_index, int)
            or isinstance(control_index, bool)
            or control_index < 0
        ):
            raise GatewayProtocolError("control_index must be a non-negative integer or null")
        try:
            role = ObservationRole(_text(payload, "role"))
        except ValueError as exc:
            raise GatewayProtocolError(
                f"{payload.get('role')!r} is not an observation role"
            ) from exc
        # `purpose` is read as free text: presenting the wrong purpose is a
        # policy refusal the service records, not a malformed frame to drop.
        return cls(
            purpose=_text(payload, "purpose"),
            pass_id=_text(payload, "pass_id"),
            claim_epoch=_whole(payload, "claim_epoch"),
            cancellation_epoch=_whole(payload, "cancellation_epoch"),
            execution_id=_text(payload, "execution_id"),
            envelope=_mapping(payload, "envelope"),
            deadline_seconds=_number(payload, "deadline_seconds"),
            scan_run_id=_text(payload, "scan_run_id"),
            finding_id=_text(payload, "finding_id"),
            role=role,
            control_index=control_index,
            signal_tokens=_tokens(payload, "signal_tokens"),
        )

    @property
    def envelope_digest(self) -> str:
        """The identity the gateway stores and compares (CHG-P5-008)."""
        return sha256_hex(canonical_json_bytes(self.envelope))


@dataclass(frozen=True, slots=True)
class ObserveReply:
    """Server to client: the outcome of one contact, or the refusal instead of it.

    ``facts`` stays a payload across this boundary. The observer is unprivileged
    and its output is untrusted, so the document is schema-validated by whoever
    is about to rely on it rather than being handed over as an already-trusted
    object.
    """

    outcome: OutcomeClass
    reason_code: str
    execution_id: str
    facts: dict[str, Any] | None = None
    completeness: Completeness | None = None
    peer_address: str | None = None
    #: The target may have processed the request. Durable on the subject, so a
    #: later pass knows re-observation is a decision and not a free retry.
    possibly_applied: bool = False

    def as_payload(self) -> dict[str, Any]:
        return {
            "message": MessageType.OBSERVE_REPLY.value,
            "outcome": self.outcome.value,
            "reason_code": self.reason_code,
            "execution_id": self.execution_id,
            "facts": dict(self.facts) if self.facts is not None else None,
            "completeness": self.completeness.as_payload() if self.completeness else None,
            "peer_address": self.peer_address,
            "possibly_applied": self.possibly_applied,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> ObserveReply:
        _expect(payload, MessageType.OBSERVE_REPLY)
        try:
            outcome = OutcomeClass(_text(payload, "outcome"))
        except ValueError as exc:
            raise GatewayProtocolError(
                f"{payload.get('outcome')!r} is not an outcome class this layer knows"
            ) from exc
        facts = payload.get("facts")
        if facts is not None and not isinstance(facts, dict):
            raise GatewayProtocolError("facts must be an object or null")
        raw_completeness = payload.get("completeness")
        if raw_completeness is not None and not isinstance(raw_completeness, dict):
            raise GatewayProtocolError("completeness must be an object or null")
        peer = payload.get("peer_address")
        if peer is not None and not isinstance(peer, str):
            raise GatewayProtocolError("peer_address must be a string or null")
        try:
            completeness = (
                Completeness.from_payload(raw_completeness) if raw_completeness else None
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GatewayProtocolError("completeness does not satisfy its schema") from exc
        return cls(
            outcome=outcome,
            reason_code=_text(payload, "reason_code"),
            execution_id=_text(payload, "execution_id"),
            facts=facts,
            completeness=completeness,
            peer_address=peer,
            possibly_applied=bool(payload.get("possibly_applied", False)),
        )

    def typed_facts(self) -> ObservationFacts | None:
        """Validate the facts document strictly, or refuse it.

        A document that does not validate is a failure of the observer boundary,
        never a partially-trusted result: there is no "most of the facts".
        """
        if self.facts is None:
            return None
        try:
            return ObservationFacts.from_payload(self.facts)
        except (KeyError, TypeError, ValueError) as exc:
            raise ObservationSchemaError(f"observation document rejected: {exc}") from exc


# =============================================================================
# Feature set
# =============================================================================


@dataclass(frozen=True, slots=True)
class FeatureSet:
    """What a gateway claims to enforce, measured against what is required.

    The check names the missing features rather than returning a bare false,
    because the operator's next action is to look at one deployment and one
    flag — and "the gateway refused to be used" with no name attached is a
    support ticket rather than a diagnosis.
    """

    advertised: frozenset[str]

    @property
    def missing(self) -> tuple[str, ...]:
        return tuple(sorted(REQUIRED_GATEWAY_FEATURES - self.advertised))

    @property
    def satisfied(self) -> bool:
        return not self.missing

    def describe_missing(self) -> str:
        return ", ".join(self.missing)


def assert_compatible(welcome: Welcome) -> None:
    """Raise unless a dispatch through this gateway is permitted at all.

    Both conditions are refusals rather than degradations. A protocol mismatch
    means the two sides disagree about what the fields mean; a missing feature
    means one of the enforcement steps an invariant names is simply not there.
    Either way the correct number of requests to send is zero.
    """
    if welcome.protocol_version != GATEWAY_PROTOCOL_VERSION:
        raise GatewayProtocolError(
            f"gateway speaks protocol {welcome.protocol_version!r}; "
            f"this layer speaks {GATEWAY_PROTOCOL_VERSION!r}"
        )
    features = welcome.features
    if not features.satisfied:
        raise GatewayProtocolError(
            f"gateway does not enforce {features.describe_missing()}; refusing to dispatch"
        )

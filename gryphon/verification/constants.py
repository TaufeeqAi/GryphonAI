"""Closed enumerations and fixed bounds for the verification layer.

Every set here is *closed*: the decision table, the persistence CHECK
constraints, the report schema and the read views all agree with these members,
and a value outside them is an error rather than an unknown. Values that carry
security meaning — the observation kinds, the method allowlists, the caps — are
code constants. A setting may only *narrow* them.

Three groups deserve their own note:

* **Statuses and justifications.** A verdict is one status plus, unless it is
  CONFIRMED, exactly one justification. The justification names are grouped by
  the category the evaluator reached, not by the protocol that produced it, so a
  new observation kind needs no new category.
* **Outcome classes.** A refusal is permanent policy, transient capacity, or a
  fact about the world. Collapsing those three is how a two-second blip reads as
  a scope violation and how NXDOMAIN reads as a denial.
* **Completeness.** An observation that is not transport- *and* body-complete
  can never support a negative claim. The bound that stopped a read is recorded
  so the deliverable can say *why* it could not tell.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum
from typing import Final

# =============================================================================
# Verdicts
# =============================================================================


class VerdictStatus(StrEnum):
    """The five answers verification can give. There is no sixth."""

    #: The predicate held on a complete primary observation and every control
    #: failed to satisfy it.
    CONFIRMED = "CONFIRMED"
    #: Positive evidence explains the original match as spurious.
    REFUTED = "REFUTED"
    #: Observation complete, controls clean, predicate false *now*. Not a false
    #: positive: possibly remediated, possibly transient.
    NOT_REPRODUCED = "NOT_REPRODUCED"
    #: No determination was possible.
    INCONCLUSIVE = "INCONCLUSIVE"
    #: No verifier is registered, or the class is unreviewed or unrepresentable.
    UNSUPPORTED = "UNSUPPORTED"


#: Statuses that settle the question. Only these supersede in the read views; an
#: INCONCLUSIVE from a later pass never hides an earlier CONFIRMED.
DETERMINATE_STATUSES: Final[frozenset[VerdictStatus]] = frozenset(
    {VerdictStatus.CONFIRMED, VerdictStatus.REFUTED, VerdictStatus.NOT_REPRODUCED}
)

#: Statuses excluded from the confirmed deliverable but never deleted.
FILTERED_STATUSES: Final[frozenset[VerdictStatus]] = frozenset({VerdictStatus.REFUTED})


class Justification(StrEnum):
    """Why a verdict is not CONFIRMED. Closed per report schema version.

    Grouped by category rather than by protocol: ``control_matched`` means the
    same thing whether the control was an HTTP sibling path or an authoritative
    NXDOMAIN, so adding an observation kind adds no category.
    """

    # -- REFUTED: positive evidence that the original match was spurious ------
    #: A control request satisfied the predicate too — the server answers the
    #: same way for things that do not exist.
    CONTROL_MATCHED = "control_matched"
    #: The matched signal appears on non-existent siblings as well, so it says
    #: nothing about this resource.
    SIGNAL_UBIQUITOUS = "signal_ubiquitous"

    # -- NOT_REPRODUCED: the condition is not there now -----------------------
    SUBJECT_ABSENT = "subject_absent"
    PREDICATE_FALSE = "predicate_false"
    ACCESS_REFUSED = "access_refused"

    # -- INCONCLUSIVE: we could not tell --------------------------------------
    AUTHORIZATION_UNAVAILABLE = "authorization_unavailable"
    DEADLINE_EXCEEDS_GRANT = "deadline_exceeds_grant"
    SCOPE_EXCLUDED = "scope_excluded"
    DESTINATION_UNATTESTED = "destination_unattested"
    DESTINATION_MISMATCH = "destination_mismatch"
    PROBE_DENIED = "probe_denied"
    BUDGET_EXHAUSTED = "budget_exhausted"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    UNREACHABLE = "unreachable"
    PROBE_FAILED = "probe_failed"
    CONTROLS_DISAGREE = "controls_disagree"
    NO_CONFIRMING_PREDICATE = "no_confirming_predicate"
    EVIDENCE_UNAVAILABLE = "evidence_unavailable"
    #: The observation was truncated, failed to decode, or hit a bound. It can
    #: never prove absence.
    INCOMPLETE_OBSERVATION = "incomplete_observation"
    #: The gateway refused for capacity reasons — a breaker, a budget, or a
    #: dependency it needs. Distinct from a policy refusal on purpose.
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    #: The subject carries a possibly-applied fact and its verifier is not
    #: declared repeat-safe, so re-observation needs an explicit decision.
    REPLAY_REQUIRES_DECISION = "replay_requires_decision"
    #: The host began answering protectively (429/403/latency) while controls
    #: were running; continuing would measure our own effect.
    HOST_PROTECTIVE_RESPONSE = "host_protective_response"

    # -- UNSUPPORTED: we will not try -----------------------------------------
    NO_VERIFIER = "no_verifier"
    UNREPRESENTABLE_TARGET = "unrepresentable_target"
    UNREVIEWED_CLASS = "unreviewed_class"


#: Which justifications may accompany which status. The evaluator and the
#: database CHECK both consult this, so they cannot drift apart.
JUSTIFICATIONS_BY_STATUS: Final[dict[VerdictStatus, frozenset[Justification]]] = {
    VerdictStatus.CONFIRMED: frozenset(),
    VerdictStatus.REFUTED: frozenset(
        {Justification.CONTROL_MATCHED, Justification.SIGNAL_UBIQUITOUS}
    ),
    VerdictStatus.NOT_REPRODUCED: frozenset(
        {
            Justification.SUBJECT_ABSENT,
            Justification.PREDICATE_FALSE,
            Justification.ACCESS_REFUSED,
        }
    ),
    VerdictStatus.INCONCLUSIVE: frozenset(
        {
            Justification.AUTHORIZATION_UNAVAILABLE,
            Justification.DEADLINE_EXCEEDS_GRANT,
            Justification.SCOPE_EXCLUDED,
            Justification.DESTINATION_UNATTESTED,
            Justification.DESTINATION_MISMATCH,
            Justification.PROBE_DENIED,
            Justification.BUDGET_EXHAUSTED,
            Justification.RATE_LIMITED,
            Justification.TIMEOUT,
            Justification.UNREACHABLE,
            Justification.PROBE_FAILED,
            Justification.CONTROLS_DISAGREE,
            Justification.NO_CONFIRMING_PREDICATE,
            Justification.EVIDENCE_UNAVAILABLE,
            Justification.INCOMPLETE_OBSERVATION,
            Justification.DEPENDENCY_UNAVAILABLE,
            Justification.REPLAY_REQUIRES_DECISION,
            Justification.HOST_PROTECTIVE_RESPONSE,
        }
    ),
    VerdictStatus.UNSUPPORTED: frozenset(
        {
            Justification.NO_VERIFIER,
            Justification.UNREPRESENTABLE_TARGET,
            Justification.UNREVIEWED_CLASS,
        }
    ),
}

#: Justifications that name a registry decision rather than an observation; the
#: verdict records the registry digest alongside them.
REGISTRY_SCOPED_JUSTIFICATIONS: Final[frozenset[Justification]] = frozenset(
    {
        Justification.NO_VERIFIER,
        Justification.UNREPRESENTABLE_TARGET,
        Justification.UNREVIEWED_CLASS,
    }
)


class AssertedBy(StrEnum):
    """Who made a claim. Authors never overwrite each other (one lane each)."""

    DETERMINISTIC_VERIFIER = "deterministic_verifier"
    MODEL = "model"
    HUMAN_REVIEWER = "human_reviewer"


# =============================================================================
# Observation
# =============================================================================


class ObservationKind(StrEnum):
    """The closed catalog of non-destructive observation kinds.

    A kind declares its own envelope shape, method allowlist, fact vocabulary
    and completeness semantics. Adding one is a MINOR change whose safety review
    is the catalog gate; it is *not* a change to the verdict algebra.
    """

    HTTP_RESPONSE_SUMMARY = "http.response.summary"
    DNS_ANSWER = "dns.answer"


#: Methods each kind may put on the wire. Nothing outside these is representable.
METHODS_BY_KIND: Final[dict[ObservationKind, tuple[str, ...]]] = {
    ObservationKind.HTTP_RESPONSE_SUMMARY: ("GET", "HEAD"),
    ObservationKind.DNS_ANSWER: ("DNS",),
}

#: Whether a kind's destination is the subject itself or a mediator. A
#: resolver-mediated kind does not require the subject to resolve, and its
#: egress allowlist is the resolver set.
MEDIATED_KINDS: Final[frozenset[ObservationKind]] = frozenset({ObservationKind.DNS_ANSWER})


class ObservationRole(StrEnum):
    """Why this observation was made."""

    PRIMARY = "primary"
    CONTROL = "control"


class OutcomeClass(StrEnum):
    """What kind of answer the gateway gave.

    The three refusal classes exist because collapsing them loses the operator's
    next action: a policy refusal is final, a capacity refusal is worth retrying
    before intent, and a world fact is evidence rather than a refusal at all.
    """

    #: Typed facts are available.
    OBSERVED = "OBSERVED"
    #: Permanent: scope, exclusion, depth, purpose, unattested destination,
    #: stale epoch, cancellation, envelope conflict.
    REFUSED_POLICY = "REFUSED_POLICY"
    #: Transient: budget, breaker, egress or database unavailable at the
    #: gateway. Retryable *before intent* only.
    REFUSED_CAPACITY = "REFUSED_CAPACITY"
    #: A fact about the world, routed to the verifier as evidence — NXDOMAIN,
    #: NOERROR with no answer.
    WORLD_FACT = "WORLD_FACT"
    TIMED_OUT = "TIMED_OUT"
    FAILED = "FAILED"
    #: The execution completed but its facts are gone. Never success.
    OBSERVATION_LOST = "OBSERVATION_LOST"


#: Outcomes after which the target may have processed the request, so the
#: subject carries a durable possibly-applied fact.
POSSIBLY_APPLIED_OUTCOMES: Final[frozenset[OutcomeClass]] = frozenset(
    {OutcomeClass.TIMED_OUT, OutcomeClass.FAILED, OutcomeClass.OBSERVATION_LOST}
)

#: Outcomes that carry usable facts.
EVIDENCE_OUTCOMES: Final[frozenset[OutcomeClass]] = frozenset(
    {OutcomeClass.OBSERVED, OutcomeClass.WORLD_FACT}
)


class ObservationState(StrEnum):
    """Persisted lifecycle of one planned observation."""

    PLANNED = "PLANNED"
    #: Derived from the gateway's record; this layer never writes it.
    DISPATCHED = "DISPATCHED"
    SETTLED = "SETTLED"
    #: The gateway refused before committing intent: zero traffic.
    NOT_DISPATCHED = "NOT_DISPATCHED"


class TruncationReason(StrEnum):
    """Which bound stopped a read. Recorded so a report can say why."""

    NONE = "none"
    WIRE_BYTES = "wire_bytes"
    DECODED_BYTES = "decoded_bytes"
    HEADER_BYTES = "header_bytes"
    ANSWER_COUNT = "answer_count"
    CNAME_DEPTH = "cname_depth"
    DEADLINE = "deadline"
    DECODE_FAILED = "decode_failed"


# =============================================================================
# Verifiers and controls
# =============================================================================


class ClaimScope(StrEnum):
    """Whether a finding class asserts something about a specific resource or
    about the host as a whole. Controls refute only resource-specific claims."""

    RESOURCE_SPECIFIC = "resource_specific"
    HOST_WIDE = "host_wide"


class SafeReadClass(StrEnum):
    """Whether this endpoint class has been reviewed as observational.

    Method restriction is necessary and not sufficient: a GET can mutate state
    on someone else's application. An unreviewed class is never dispatched.
    """

    REVIEWED_SAFE_READ = "reviewed_safe_read"
    UNREVIEWED = "unreviewed"


class ControlStrategy(StrEnum):
    """A control is a request whose expected answer is known independently of
    the finding. The strategy says how that expectation is produced."""

    #: N non-existent siblings of the subject path, locators keyed per pass.
    SIBLING_PATHS = "sibling_paths"
    #: An authoritative NXDOMAIN is its own control; a resolver cannot catch-all
    #: an authoritative negative answer.
    AUTHORITATIVE_NXDOMAIN = "authoritative_nxdomain"
    #: Reserved for TLS kinds: a handshake to a name the host does not serve.
    DIFFERENTIAL_SNI = "differential_sni"
    #: Reserved for TCP kinds: a port known to be closed.
    CLOSED_PORT = "closed_port"
    #: No control, with a stated reason. Registry validation requires the reason.
    NONE = "none"


#: Strategies that produce their own expectation without extra requests.
SELF_CONTROLLING_STRATEGIES: Final[frozenset[ControlStrategy]] = frozenset(
    {ControlStrategy.AUTHORITATIVE_NXDOMAIN}
)


class Extractor(StrEnum):
    """The fixed extractor set, evaluated inside the observer.

    These are named functions versioned with the observer image — deliberately
    not a language. Adding one is a MINOR catalog change; the set is small
    because the verifiers it serves are all of one shape: *is this response
    structurally the artifact we think it is, and does the same structure appear
    on a control?*
    """

    DOTENV_GRAMMAR = "dotenv_grammar"
    TOKEN_PRESENCE = "token_presence"  # noqa: S105 - an extractor name, not a secret
    HEADER_PRESENCE = "header_presence"
    CNAME_CHAIN = "cname_chain"
    STATUS_CLASS = "status_class"
    BODY_DIGEST = "body_digest"
    SIZE_FACTS = "size_facts"


EXTRACTORS_BY_KIND: Final[dict[ObservationKind, frozenset[Extractor]]] = {
    ObservationKind.HTTP_RESPONSE_SUMMARY: frozenset(
        {
            Extractor.DOTENV_GRAMMAR,
            Extractor.TOKEN_PRESENCE,
            Extractor.HEADER_PRESENCE,
            Extractor.STATUS_CLASS,
            Extractor.BODY_DIGEST,
            Extractor.SIZE_FACTS,
        }
    ),
    ObservationKind.DNS_ANSWER: frozenset({Extractor.CNAME_CHAIN}),
}


class VerifierLifecycle(StrEnum):
    """A verifier version's standing.

    ``withdrawn`` never edits a verdict: it emits a retraction, so a proof that
    rested on an unsound predicate can be taken back and said so.
    """

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    WITHDRAWN = "withdrawn"


class SecretClass(StrEnum):
    """Shapes the observer recognizes. Only the class and a count ever leave it."""

    AWS_ACCESS_KEY_ID = "aws_access_key_id"
    CREDENTIAL_ASSIGNMENT = "credential_assignment"
    PRIVATE_KEY_BLOCK = "private_key_block"
    JWT = "jwt"
    URL_CREDENTIAL = "url_credential"


class ValueClass(StrEnum):
    """What a dotenv-style key's value looks like. The value never leaves."""

    EMPTY = "empty"
    SECRET_SHAPED = "secret_shaped"  # noqa: S105 - a value CLASS, never a value
    OTHER = "other"


# =============================================================================
# Pass lifecycle
# =============================================================================


class PassState(StrEnum):
    PLANNED = "PLANNED"
    RUNNING = "RUNNING"
    #: A dependency the pass needs is absent. The pass waits; it does not
    #: manufacture verdicts for findings it never observed.
    BLOCKED = "BLOCKED"
    COMPLETE = "COMPLETE"
    REFUSED = "REFUSED"
    ABANDONED = "ABANDONED"


TERMINAL_PASS_STATES: Final[frozenset[PassState]] = frozenset(
    {PassState.COMPLETE, PassState.REFUSED, PassState.ABANDONED}
)
#: States in which a pass still owns the scan. A second `start` is PassBusy.
OPEN_PASS_STATES: Final[frozenset[PassState]] = frozenset(
    {PassState.PLANNED, PassState.RUNNING, PassState.BLOCKED}
)


class PassOutcome(StrEnum):
    """Outcome of a COMPLETE pass."""

    VERIFIED = "VERIFIED"
    #: Completed, but at least one finding could not be determined.
    VERIFIED_WITH_GAPS = "VERIFIED_WITH_GAPS"
    #: A dependency or a host's protective response left most of the set
    #: undetermined. Distinguished so an operator does not read it as signal.
    VERIFICATION_DEGRADED = "VERIFICATION_DEGRADED"
    NOTHING_TO_VERIFY = "NOTHING_TO_VERIFY"


class RefusalReason(StrEnum):
    """Why a pass never started. Recorded in a signed event."""

    REPORT_UNVERIFIED = "report_unverified"
    REPORT_SCHEMA_UNSUPPORTED = "report_schema_unsupported"
    SCAN_NOT_TERMINAL = "scan_not_terminal"
    SCAN_INTEGRITY_FAILED = "scan_integrity_failed"
    GRANT_SIGNER_UNTRUSTED = "grant_signer_untrusted"
    EVIDENCE_MISSING = "evidence_missing"
    CALLER_REJECTED = "caller_rejected"


class BlockedReason(StrEnum):
    """Why a pass is waiting rather than concluding."""

    GATEWAY_UNAVAILABLE = "gateway_unavailable"
    DATABASE_UNAVAILABLE = "database_unavailable"


class AbandonReason(StrEnum):
    PINS_UNAVAILABLE = "pins_unavailable"
    OPERATOR_STOP = "operator_stop"
    OPERATOR_ABORT = "operator_abort"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"


class OrderingBasis(StrEnum):
    """Which ordering a pass used, recorded because it changes what gets dropped
    when a budget runs out."""

    ENRICHMENT_PRIORITY = "enrichment_priority"
    OBSERVED_SEVERITY = "observed_severity"


class EnrichmentContext(StrEnum):
    """How the optional enrichment report was used."""

    VERIFIED = "verified"
    ABSENT = "absent"
    UNVERIFIED = "unverified"
    #: Still valid and attested, but a newer report exists. Not a failure, and
    #: never a reason to abandon traffic-bearing work.
    SUPERSEDED = "superseded"


class VerificationEventType(StrEnum):
    PASS_REFUSED = "verification_pass_refused"  # noqa: S105 - an event name
    PASS_BLOCKED = "verification_pass_blocked"  # noqa: S105 - an event name
    PASS_ABANDONED = "verification_pass_abandoned"  # noqa: S105 - an event name
    REPORT_EMITTED = "verification_report_emitted"
    VERIFIER_WITHDRAWN = "verifier_withdrawn"


class Severity(IntEnum):
    """Ordinal fallback ordering. An unrecognized label orders as LOW."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, raw: str | None) -> tuple[Severity, bool]:
        """Return (severity, recognized). Never raises."""
        if raw is None:
            return cls.LOW, False
        try:
            return cls[str(raw).strip().upper()], True
        except KeyError:
            return cls.LOW, False


# =============================================================================
# Bounds (code constants; settings may only narrow)
# =============================================================================

#: HTTP observation bounds, enforced by the observer and the gateway service —
#: never by the probed tool's own flags alone.
HTTP_MAX_WIRE_BYTES: Final[int] = 65_536
HTTP_MAX_DECODED_BYTES: Final[int] = 262_144
HTTP_MAX_HEADER_BYTES: Final[int] = 16_384
HTTP_DEADLINE_SECONDS: Final[float] = 20.0

#: DNS observation bounds.
DNS_MAX_ANSWERS: Final[int] = 64
DNS_MAX_CNAME_DEPTH: Final[int] = 16
DNS_DEADLINE_SECONDS: Final[float] = 10.0

#: Per-finding observation cap: one primary plus at most this many controls.
MAX_CONTROLS_PER_FINDING: Final[int] = 2

#: Headers whose *names* may be reported. No header value ever crosses the
#: observer boundary except the normalized content type.
HEADER_NAME_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        "content-type",
        "content-length",
        "server",
        "location",
        "www-authenticate",
        "retry-after",
        "x-powered-by",
    }
)

#: Status classes the evaluator reasons about, independent of protocol.
ABSENT_STATUS_CODES: Final[frozenset[int]] = frozenset({404, 410})
ACCESS_REFUSED_STATUS_CODES: Final[frozenset[int]] = frozenset({401, 403})
PROTECTIVE_STATUS_CODES: Final[frozenset[int]] = frozenset({429, 403, 503})

#: Consecutive protective responses from one host before the pass pauses it.
HOST_PROTECTIVE_THRESHOLD: Final[int] = 3

#: Control locator shape: a keyed-random segment the target cannot predict.
CONTROL_LOCATOR_BYTES: Final[int] = 8

# -- versions -----------------------------------------------------------------
VERIFICATION_REPORT_SCHEMA_VERSION: Final[str] = "1"
VERIFICATION_AUDIT_EVENT_SCHEMA_VERSION: Final[str] = "1"
VERDICT_VALUE_SCHEMA_VERSION: Final[str] = "1"
OBSERVATION_SCHEMA_VERSION: Final[str] = "1"
SUBJECT_KEY_VERSION: Final[str] = "1"
VERIFICATION_CODE_VERSION: Final[str] = "1.1.0"
#: Gateway wire protocol this layer speaks. A mismatch refuses dispatch.
GATEWAY_PROTOCOL_VERSION: Final[str] = "1"

#: Security-critical gateway features. Absence of any one refuses every
#: dispatch: these are the properties the contract's invariants rest on.
REQUIRED_GATEWAY_FEATURES: Final[frozenset[str]] = frozenset(
    {
        "authority_at_contact",
        "estate_at_pin_time",
        "envelope_conflict_refusal",
        "epoch_fencing",
        "purpose_binding",
        "enforced_bounds",
        "durable_observations",
        "sealed_observer",
    }
)

# -- upstream contracts this layer consumes (read-only) -----------------------
BASE_REPORT_EVENT_TYPE: Final[str] = "report_emitted"
SUPPORTED_BASE_REPORT_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({"1"})
SUPPORTED_ENRICHMENT_REPORT_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({"1"})
INTEGRITY_FAILURE_REASONS: Final[frozenset[str]] = frozenset(
    {"SCAN_INTEGRITY_FAILURE", "SCOPE_DISAGREEMENT"}
)
NON_TERMINAL_SCAN_STATES: Final[frozenset[str]] = frozenset(
    {"RUNNING", "RECONCILING", "HALTED_FOR_REVIEW"}
)

# -- identity -----------------------------------------------------------------
DATABASE_ROLE: Final[str] = "gryphon_verification"
#: HKDF / digest domain separation. Never reuse a label.
PROBE_ID_DOMAIN: Final[bytes] = b"gryphon/verification/observation/v1"
CONTROL_LOCATOR_DOMAIN: Final[bytes] = b"gryphon/verification/control-locator/v1"
EXECUTION_ID_DOMAIN: Final[bytes] = b"gryphon/verification/execution/v1"
SUBJECT_KEY_DOMAIN: Final[bytes] = b"gryphon/verification/subject/v1"
#: The only purpose this layer may present to the gateway.
EXECUTION_PURPOSE: Final[str] = "verification"

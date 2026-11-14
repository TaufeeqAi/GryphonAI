"""Repository contracts: typed outcomes, conflict semantics, and the clock.

No database here. What these tests hold still is the part of the repository a
live PostgreSQL would not tell us about anyway: which typed value a claim
resolves to, whether a read-back is judged identical, and whether any statement
could ever write a timestamp this process read from its own clock. The real
schema, the triggers, the partitions and the privilege matrix belong to the
integration suite.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from gryphon.tooling.observation.facts import Completeness, HttpFacts, ObservationFacts
from gryphon.verification.constants import (
    AssertedBy,
    Justification,
    ObservationKind,
    ObservationRole,
    OutcomeClass,
    PassState,
    TruncationReason,
    VerdictStatus,
)
from gryphon.verification.evaluator import ControlSummary, Verdict
from gryphon.verification.observation import NotDispatched, Observation
from gryphon.verification.reasons import VerificationConfigurationError
from gryphon.verification.repository import (
    Busy,
    KeyConflict,
    ObservationRecord,
    PassClaim,
    PinRecord,
    VerdictRecord,
    VerificationRepository,
    observation_mismatch,
    scope_digest,
    verdict_mismatch,
)

pytestmark = pytest.mark.unit

SCAN = "11111111-2222-3333-4444-555555555555"
PASS_ID = "a" * 32
HOLDER = "verify/pid:1/abcd1234"
OTHER_HOLDER = "verify/pid:2/beef0000"
DIGEST = "d" * 64


# =============================================================================
# Stubs
# =============================================================================


class _Result:
    """Just enough of a SQLAlchemy result for the statements under test."""

    def __init__(self, row: Any = None) -> None:
        self._row = row

    def first(self) -> Any:
        return self._row

    def scalar_one_or_none(self) -> Any:
        return self._row

    def scalar_one(self) -> Any:
        return self._row


class _RecordingSession:
    """Captures the statements a repository emits without executing them."""

    def __init__(self, result: Any = None) -> None:
        self.statements: list[Any] = []
        self._result = result

    async def execute(self, statement: Any) -> _Result:
        self.statements.append(statement)
        return _Result(self._result)

    @property
    def last(self) -> Any:
        return self.statements[-1]


def _repository(result: Any = None) -> tuple[VerificationRepository, _RecordingSession]:
    session = _RecordingSession(result)
    return VerificationRepository(cast(AsyncSession, session)), session


def _compiled(statement: Any) -> tuple[str, dict[str, Any]]:
    compiled = statement.compile(dialect=postgresql.dialect())
    return str(compiled), dict(compiled.params)


def _bound(params: dict[str, Any]) -> list[Any]:
    """Every bound value, with expanding IN parameters flattened out."""
    flat: list[Any] = []
    for value in params.values():
        if isinstance(value, list | tuple):
            flat.extend(value)
        else:
            flat.append(value)
    return flat


def _pass_row(
    *,
    state: PassState = PassState.RUNNING,
    scope: dict[str, Any] | None = None,
    claim_epoch: int = 1,
    holder: str | None = OTHER_HOLDER,
    adoption_count: int = 0,
) -> Any:
    return SimpleNamespace(
        pass_id=PASS_ID,
        scan_run_id=SCAN,
        request_key="key-1",
        scope=scope if scope is not None else {"all": True},
        state=state.value,
        claim_epoch=claim_epoch,
        cancellation_epoch=0,
        adoption_count=adoption_count,
        holder=holder,
        lease_expires_at=datetime(2026, 11, 14, 12, 0, tzinfo=UTC),
    )


def _claim(*, epoch: int = 3, state: PassState = PassState.RUNNING) -> PassClaim:
    return PassClaim(
        pass_id=PASS_ID,
        scan_run_id=SCAN,
        state=state,
        claim_epoch=epoch,
        cancellation_epoch=0,
        holder=HOLDER,
        adoption_count=0,
        owned=True,
        resumed=False,
        adopted=False,
    )


def _facts(*, whole: bool = True, status: int = 200) -> ObservationFacts:
    completeness = (
        Completeness(transport_complete=True, body_complete=True, bytes_read=120)
        if whole
        else Completeness.incomplete(TruncationReason.WIRE_BYTES)
    )
    return ObservationFacts(
        kind=ObservationKind.HTTP_RESPONSE_SUMMARY,
        completeness=completeness,
        http=HttpFacts(
            status_code=status,
            status_class=status // 100,
            content_type="text/plain",
            content_length_header=120,
            body_sha256="c" * 64,
            header_names=("content-type",),
            location_class="none",
        ),
    )


def _observation(
    *,
    outcome: OutcomeClass = OutcomeClass.OBSERVED,
    whole: bool = True,
    with_facts: bool = True,
) -> Observation:
    return Observation(
        observation_id="o" * 64,
        execution_id="e" * 64,
        role=ObservationRole.PRIMARY,
        control_index=0,
        outcome=outcome,
        reason_code="observed",
        facts=_facts(whole=whole) if with_facts else None,
        peer_address="203.0.113.7",
    )


def _record(**overrides: Any) -> ObservationRecord:
    base = ObservationRecord.settled(
        _observation(),
        finding_id="f-1",
        verifier_id="exposed-config@1.0.0",
        envelope_digest=DIGEST,
    )
    if not overrides:
        return base
    payload: dict[str, Any] = {
        "observation_id": base.observation_id,
        "finding_id": base.finding_id,
        "verifier_id": base.verifier_id,
        "execution_id": base.execution_id,
        "envelope_digest": base.envelope_digest,
        "role": base.role,
        "control_index": base.control_index,
        "outcome_class": base.outcome_class,
        "reason_code": base.reason_code,
        "possibly_applied": base.possibly_applied,
        "completeness": base.completeness,
        "facts_digest": base.facts_digest,
        "peer_address": base.peer_address,
    }
    payload.update(overrides)
    return ObservationRecord(**payload)


def _verdict_record(**overrides: Any) -> VerdictRecord:
    defaults: dict[str, Any] = {
        "finding_id": "f-1",
        "subject_key": "s" * 64,
        "status": VerdictStatus.CONFIRMED,
        "justification": None,
        "verifier_id": "exposed-config@1.0.0",
        "registry_digest": "r" * 64,
        "rule": 10,
        "projection": {"kind": "http.response.summary", "status_code": 200},
    }
    defaults.update(overrides)
    return VerdictRecord(**defaults)


def _pins(**overrides: Any) -> PinRecord:
    defaults: dict[str, Any] = {
        "registry_digest": "1" * 64,
        "extractor_set_digest": "2" * 64,
        "estate_digest": "3" * 64,
        "resolver_set_digest": "4" * 64,
        "feature_set_digest": "5" * 64,
        "base_report_id": "base-1",
        "base_report_digest": "6" * 64,
    }
    defaults.update(overrides)
    return PinRecord(**defaults)


# =============================================================================
# Identities
# =============================================================================


def test_scope_digest_is_canonical_not_textual() -> None:
    """A re-serialized command is the same command."""
    one = scope_digest({"findings": ["b", "a"], "limit": 10})
    two = scope_digest({"limit": 10, "findings": ["b", "a"]})
    assert one == two


def test_an_absent_scope_and_an_empty_one_both_mean_the_whole_scan() -> None:
    assert scope_digest(None) == scope_digest({})


def test_a_changed_scope_is_a_different_request() -> None:
    assert scope_digest({"limit": 10}) != scope_digest({"limit": 11})


# =============================================================================
# Pin records
# =============================================================================


def test_the_pin_json_is_derived_from_its_columns() -> None:
    """One provenance root, projected two ways — never two copies to reconcile."""
    record = _pins()
    payload = record.as_payload()
    assert payload["pins"] == record.pins
    for name, value in record.pins.items():
        assert payload[name] == value


def test_the_pin_digest_moves_with_any_pinned_input() -> None:
    base = _pins().digest
    assert _pins(estate_digest="9" * 64).digest != base
    assert _pins(enrichment_report_id="enr-1").digest != base
    # The plan manifest is what was derived, not what it was derived from.
    assert _pins(manifest={"observations": 12}).digest == base


# =============================================================================
# Observation records
# =============================================================================


def test_a_settled_record_carries_completeness_and_a_facts_digest() -> None:
    record = _record()
    assert record.completeness["transport_complete"] is True
    assert record.completeness["body_complete"] is True
    assert record.completeness["truncation_reason"] == TruncationReason.NONE.value
    assert record.facts_digest is not None and len(record.facts_digest) == 64
    assert record.possibly_applied is False


def test_a_truncated_observation_is_stored_as_incomplete_with_its_bound() -> None:
    record = ObservationRecord.settled(
        _observation(whole=False),
        finding_id="f-1",
        verifier_id="v@1",
        envelope_digest=DIGEST,
    )
    assert record.completeness["body_complete"] is False
    assert record.completeness["truncation_reason"] == TruncationReason.WIRE_BYTES.value


@pytest.mark.parametrize(
    "outcome",
    [OutcomeClass.TIMED_OUT, OutcomeClass.FAILED, OutcomeClass.OBSERVATION_LOST],
)
def test_possibly_applied_comes_from_the_outcome_class_not_a_caller_flag(
    outcome: OutcomeClass,
) -> None:
    """A transport failure is not a rollback, whatever the call site believes."""
    record = ObservationRecord.settled(
        _observation(outcome=outcome, with_facts=False),
        finding_id="f-1",
        verifier_id="v@1",
        envelope_digest=DIGEST,
    )
    assert record.possibly_applied is True


def test_a_refusal_before_intent_carries_no_possibly_applied_fact() -> None:
    record = ObservationRecord.refused(
        NotDispatched(
            observation_id="o" * 64,
            execution_id="e" * 64,
            role=ObservationRole.CONTROL,
            control_index=1,
            outcome=OutcomeClass.REFUSED_POLICY,
            reason_code="scope_excluded",
        ),
        finding_id="f-1",
        verifier_id="v@1",
        envelope_digest=DIGEST,
    )
    assert record.possibly_applied is False
    assert record.facts_digest is None
    assert record.completeness["transport_complete"] is False


def test_an_evidence_outcome_without_facts_is_refused() -> None:
    with pytest.raises(ValueError, match="requires a facts digest"):
        _record(facts_digest=None)


# =============================================================================
# Verdict records
# =============================================================================


def test_only_a_deterministic_verifier_writes_the_verdict_table() -> None:
    with pytest.raises(ValueError, match="deterministic verifier"):
        _verdict_record(asserted_by=AssertedBy.MODEL)


def test_confirmed_carries_no_justification_and_others_require_one() -> None:
    with pytest.raises(ValueError, match="carries no justification"):
        _verdict_record(justification=Justification.PREDICATE_FALSE)
    with pytest.raises(ValueError, match="requires a justification"):
        _verdict_record(status=VerdictStatus.INCONCLUSIVE, justification=None)


def test_projection_digest_is_canonical_over_the_stored_evidence() -> None:
    one = _verdict_record(projection={"a": 1, "b": [2, 3]})
    two = _verdict_record(projection={"b": [2, 3], "a": 1})
    assert one.projection_digest == two.projection_digest
    assert _verdict_record(projection={}).projection_digest != one.projection_digest


def test_from_verdict_preserves_the_evaluators_reasoning() -> None:
    summary = ControlSummary(
        requested=2,
        observed=2,
        complete=2,
        agreeing=True,
        any_matched_predicate=False,
        any_matched_refutation=False,
        primary_indistinguishable=False,
    )
    verdict = Verdict(
        status=VerdictStatus.CONFIRMED,
        justification=None,
        verifier_id="exposed-config@1.0.0",
        rule=10,
        matched_predicates=("dotenv_shape", "secret_class_present"),
        control_summary=summary,
        projection={"kind": "http.response.summary"},
    )
    record = VerdictRecord.from_verdict(
        verdict, finding_id="f-1", subject_key="s" * 64, registry_digest="r" * 64
    )
    assert record.status is VerdictStatus.CONFIRMED
    assert record.matched_predicates == ("dotenv_shape", "secret_class_present")
    assert record.control_summary == summary.as_payload()
    assert record.asserted_by is AssertedBy.DETERMINISTIC_VERIFIER
    assert record.registry_digest == "r" * 64


def test_an_unsupported_verdict_still_names_the_registry_that_declined() -> None:
    """"Nothing was registered" is a statement about one particular registry."""
    record = VerdictRecord.from_verdict(
        Verdict(
            status=VerdictStatus.UNSUPPORTED,
            justification=Justification.NO_VERIFIER,
            verifier_id=None,
            rule=0,
        ),
        finding_id="f-9",
        subject_key="s" * 64,
        registry_digest="r" * 64,
    )
    assert record.verifier_id is None
    assert record.as_payload()["registry_digest"] == "r" * 64


# =============================================================================
# Read-back comparison
# =============================================================================


def test_an_identical_stored_row_is_not_a_conflict() -> None:
    record = _record()
    stored = SimpleNamespace(pass_id=PASS_ID, **record.as_payload())
    assert observation_mismatch(stored, record) == ()


def test_a_stored_enum_and_its_text_are_the_same_value() -> None:
    """The row holds text; the record holds closed-enum members."""
    record = _record()
    stored = SimpleNamespace(
        pass_id=PASS_ID,
        **{
            **record.as_payload(),
            "role": record.role,
            "outcome_class": record.outcome_class,
        },
    )
    assert observation_mismatch(stored, record) == ()


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("execution_id", "f" * 64),
        ("envelope_digest", "9" * 64),
        ("facts_digest", "0" * 64),
        ("finding_id", "f-2"),
        ("outcome_class", "FAILED"),
        ("possibly_applied", True),
    ],
)
def test_a_differing_read_back_names_the_field(field_name: str, value: Any) -> None:
    """Never a silent keep-first: the caller is told what disagrees."""
    record = _record()
    stored = SimpleNamespace(
        pass_id=PASS_ID, **{**record.as_payload(), field_name: value}
    )
    assert observation_mismatch(stored, record) == (field_name,)


def test_an_incomplete_read_back_is_a_conflict_not_a_match() -> None:
    """A truncated stored measurement cannot stand in for a whole one."""
    record = _record()
    stored = SimpleNamespace(
        pass_id=PASS_ID,
        **{
            **record.as_payload(),
            "completeness": Completeness.incomplete(
                TruncationReason.DECODED_BYTES
            ).as_payload(),
        },
    )
    assert observation_mismatch(stored, record) == ("completeness",)


def test_a_missing_column_reads_as_a_mismatch_rather_than_a_match() -> None:
    record = _record()
    payload = record.as_payload()
    del payload["execution_id"]
    stored = SimpleNamespace(pass_id=PASS_ID, **payload)
    assert "execution_id" in observation_mismatch(stored, record)


def test_verdict_read_back_compares_the_projection_by_digest() -> None:
    record = _verdict_record()
    stored = SimpleNamespace(**record.as_payload())
    assert verdict_mismatch(stored, record) == ()
    # A re-ordered projection digests alike, so it is the same evidence.
    reordered = SimpleNamespace(
        **{**record.as_payload(), "projection": {"status_code": 200, "kind": "x"}}
    )
    assert verdict_mismatch(reordered, record) == ()


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("status", "REFUTED"),
        ("justification", "control_matched"),
        ("verifier_id", "other@1"),
        ("registry_digest", "8" * 64),
        ("rule", 7),
        ("projection_digest", "1" * 64),
        ("subject_key", "other"),
    ],
)
def test_a_differing_verdict_read_back_names_the_field(field_name: str, value: Any) -> None:
    record = _verdict_record()
    stored = SimpleNamespace(**{**record.as_payload(), field_name: value})
    assert verdict_mismatch(stored, record) == (field_name,)


# =============================================================================
# The database clock
# =============================================================================


async def test_transition_refuses_a_timestamp_from_this_process() -> None:
    """Wall-clock-at-construction is the defect, not a convenience."""
    repository, _ = _repository()
    with pytest.raises(VerificationConfigurationError, match="database clock"):
        await repository.transition(
            _claim(),
            {PassState.RUNNING},
            PassState.COMPLETE,
            completed_at=datetime.now(UTC),
        )


async def test_a_terminal_transition_takes_its_time_from_the_database() -> None:
    repository, session = _repository()
    await repository.transition(_claim(), {PassState.RUNNING}, PassState.COMPLETE)
    sql, params = _compiled(session.last)
    assert "now()" in sql
    assert not any(isinstance(value, datetime) for value in _bound(params))


async def test_a_non_terminal_transition_writes_no_completion_time() -> None:
    repository, session = _repository()
    await repository.transition(_claim(), {PassState.RUNNING}, PassState.BLOCKED)
    sql, _ = _compiled(session.last)
    assert "completed_at" not in sql


async def test_a_transition_is_fenced_on_the_epoch_and_the_expected_states() -> None:
    repository, session = _repository()
    await repository.transition(
        _claim(epoch=7), {PassState.PLANNED, PassState.RUNNING}, PassState.RUNNING
    )
    sql, params = _compiled(session.last)
    bound = _bound(params)
    assert "claim_epoch" in sql
    assert 7 in bound
    assert {"PLANNED", "RUNNING"} <= {str(value) for value in bound}


async def test_a_terminal_state_is_never_left() -> None:
    repository, _ = _repository()
    with pytest.raises(VerificationConfigurationError, match="never left"):
        await repository.transition(_claim(), {PassState.COMPLETE}, PassState.RUNNING)


async def test_a_transition_needs_an_expected_state() -> None:
    repository, _ = _repository()
    with pytest.raises(VerificationConfigurationError, match="at least one expected state"):
        await repository.transition(_claim(), set(), PassState.RUNNING)


async def test_lease_arithmetic_happens_in_the_database() -> None:
    repository, session = _repository()
    await repository.renew_lease(HOLDER, 4, 60.0)
    sql, params = _compiled(session.last)
    bound = _bound(params)
    assert "now()" in sql
    assert timedelta(seconds=60.0) in bound
    assert not any(isinstance(value, datetime) for value in bound)


async def test_lease_liveness_is_decided_by_the_database() -> None:
    repository, session = _repository()
    await repository.lease_state(PASS_ID)
    sql, _ = _compiled(session.last)
    assert "now()" in sql


async def test_closed_enums_are_stored_as_the_text_the_checks_compare() -> None:
    repository, session = _repository()
    await repository.transition(
        _claim(), {PassState.RUNNING}, PassState.ABANDONED, reason=Justification.TIMEOUT
    )
    bound = _bound(_compiled(session.last)[1])
    assert "timeout" in bound
    assert not any(isinstance(value, Justification) for value in bound)


async def test_adoption_only_takes_a_pass_the_database_calls_expired() -> None:
    repository, session = _repository(result=None)
    await repository._adopt(PASS_ID, holder=HOLDER, lease_seconds=30.0)
    sql, params = _compiled(session.last)
    bound = _bound(params)
    assert "now()" in sql
    assert "adoption_count" in sql
    assert timedelta(seconds=30.0) in bound
    assert not any(isinstance(value, datetime) for value in bound)


# =============================================================================
# Claim semantics
# =============================================================================


class _ClaimRepository(VerificationRepository):
    """A repository whose storage seams are supplied by the test.

    The conflict semantics are the contract: which typed value a claim resolves
    to is decided here, and nothing about that decision needs a real schema.
    """

    def __init__(
        self,
        *,
        keyed: Any = None,
        open_row: Any = None,
        adopt_to: PassClaim | None = None,
        lease: Any = None,
    ) -> None:
        super().__init__(cast(AsyncSession, _RecordingSession()))
        self._keyed = keyed
        self._open = open_row
        self._adopt_to = adopt_to
        self._lease = lease
        self.inserted = False

    async def _pass_for_key(self, scan_run_id: str, request_key: str) -> Any:
        return self._keyed

    async def open_pass_for(self, scan_run_id: str) -> Any:
        return self._open

    async def _adopt(
        self, pass_id: str, *, holder: str, lease_seconds: float
    ) -> PassClaim | None:
        return self._adopt_to

    async def lease_state(self, pass_id: str) -> Any:
        return self._lease

    async def _insert_pass(self, *args: Any, **kwargs: Any) -> Any:
        self.inserted = True
        return _claim(epoch=1, state=PassState.PLANNED)


def _adopted(epoch: int = 2, adoption_count: int = 1) -> PassClaim:
    return PassClaim(
        pass_id=PASS_ID,
        scan_run_id=SCAN,
        state=PassState.RUNNING,
        claim_epoch=epoch,
        cancellation_epoch=0,
        holder=HOLDER,
        adoption_count=adoption_count,
        owned=True,
        resumed=True,
        adopted=True,
    )


async def _claim_pass(
    repository: VerificationRepository,
    *,
    scope: Any = None,
    request_key: str | None = "key-1",
) -> Any:
    return await repository.claim_pass(
        SCAN,
        request_key,
        holder=HOLDER,
        lease_seconds=60.0,
        initiated_by="cli:uid:1000",
        scope=scope if scope is not None else {"all": True},
    )


async def test_an_unused_key_on_a_free_scan_starts_a_pass() -> None:
    repository = _ClaimRepository()
    claim = await _claim_pass(repository)
    assert repository.inserted is True
    assert isinstance(claim, PassClaim)
    assert (claim.owned, claim.resumed, claim.adopted) == (True, False, False)


async def test_the_same_key_with_a_different_request_is_refused() -> None:
    """The caller may believe either request ran, so neither is assumed."""
    repository = _ClaimRepository(keyed=_pass_row())
    conflict = await _claim_pass(repository, scope={"all": False})
    assert isinstance(conflict, KeyConflict)
    assert conflict.pass_id == PASS_ID
    assert conflict.stored_digest != conflict.presented_digest
    assert repository.inserted is False


async def test_the_same_key_with_the_same_request_returns_the_same_pass() -> None:
    adopted = _adopted()
    repository = _ClaimRepository(keyed=_pass_row(), adopt_to=adopted)
    claim = await _claim_pass(repository)
    assert claim is adopted
    assert repository.inserted is False


async def test_a_re_serialized_scope_is_still_the_same_request() -> None:
    repository = _ClaimRepository(
        keyed=_pass_row(scope={"limit": 10, "findings": ["b", "a"]}), adopt_to=_adopted()
    )
    claim = await _claim_pass(repository, scope={"findings": ["b", "a"], "limit": 10})
    assert isinstance(claim, PassClaim)


async def test_a_finished_pass_is_returned_but_not_owned() -> None:
    """A repeat must serve the original deliverable, never publish a second."""
    repository = _ClaimRepository(keyed=_pass_row(state=PassState.COMPLETE, claim_epoch=4))
    claim = await _claim_pass(repository)
    assert isinstance(claim, PassClaim)
    assert claim.state is PassState.COMPLETE
    assert (claim.owned, claim.resumed, claim.adopted) == (False, True, False)
    assert claim.holder == OTHER_HOLDER


@pytest.mark.parametrize("terminal", [PassState.REFUSED, PassState.ABANDONED])
async def test_every_terminal_state_resolves_without_ownership(terminal: PassState) -> None:
    repository = _ClaimRepository(keyed=_pass_row(state=terminal))
    claim = await _claim_pass(repository)
    assert isinstance(claim, PassClaim) and claim.owned is False


async def test_a_live_lease_on_the_keyed_pass_is_busy() -> None:
    lease = SimpleNamespace(
        holder=OTHER_HOLDER,
        claim_epoch=1,
        lease_expires_at=datetime(2026, 11, 14, 12, 0, tzinfo=UTC),
        held=True,
    )
    repository = _ClaimRepository(keyed=_pass_row(), adopt_to=None, lease=lease)
    busy = await _claim_pass(repository)
    assert isinstance(busy, Busy)
    assert busy.holder == OTHER_HOLDER
    assert busy.lease_expires_at == lease.lease_expires_at


async def test_an_open_pass_under_another_key_still_owns_the_scan() -> None:
    """One open pass per scan: a second command adopts it or waits for it."""
    repository = _ClaimRepository(open_row=_pass_row(), adopt_to=None, lease=None)
    busy = await _claim_pass(repository)
    assert isinstance(busy, Busy)
    assert busy.pass_id == PASS_ID
    assert repository.inserted is False


async def test_an_open_pass_whose_lease_lapsed_is_adopted_with_a_higher_epoch() -> None:
    repository = _ClaimRepository(open_row=_pass_row(claim_epoch=1), adopt_to=_adopted())
    claim = await _claim_pass(repository)
    assert isinstance(claim, PassClaim)
    assert claim.adopted is True
    assert claim.claim_epoch > 1
    assert claim.adoption_count == 1


async def test_declining_idempotency_binds_nothing_but_still_respects_the_scan() -> None:
    """No key is not no limit: the one-open-pass rule is unaffected."""
    free = _ClaimRepository(keyed=_pass_row())
    claim = await _claim_pass(free, request_key=None)
    assert free.inserted is True
    assert isinstance(claim, PassClaim)

    taken = _ClaimRepository(open_row=_pass_row(), adopt_to=None)
    busy = await _claim_pass(taken, request_key=None)
    assert isinstance(busy, Busy)
    assert taken.inserted is False

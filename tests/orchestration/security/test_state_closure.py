"""The graph state must not be able to hold authority.

This codebase already contains the opposite precedent: the authorization
gate-conformance graph places the live permit into graph state. That graph
persists nothing today, so it leaks nothing — but it is also the most likely
file someone copies when building a pipeline graph, and a long-running pipeline
plus any persistence layer would write bearer authority to disk.

So the rule is mechanical rather than advisory: the state schema is validated
against an allowlist of primitives at import time, and a violation fails the
build rather than a scan.
"""

from __future__ import annotations

from typing import Any, TypedDict

import pytest

from gryphon.auth.results import AuthorizedPermit
from gryphon.orchestration.reasons import StateSchemaViolation
from gryphon.orchestration.state import (
    ScanGraphState,
    assert_state_schema_is_closed,
    initial_state,
    serialized_size,
)

pytestmark = pytest.mark.security


def test_the_shipped_schema_is_closed() -> None:
    assert_state_schema_is_closed()


def test_a_permit_field_fails_the_build() -> None:
    """The exact mistake the precedent invites."""

    class Leaky(TypedDict, total=False):
        scan_run_id: str
        permit: AuthorizedPermit

    with pytest.raises(StateSchemaViolation, match="names authority material"):
        assert_state_schema_is_closed(Leaky)


@pytest.mark.parametrize(
    "field_name",
    [
        "authorization_token",
        "capability_wire",
        "grant_jws",
        "execution_salt",
        "signing_key",
        "api_secret",
        "credential_blob",
        "signature",
    ],
)
def test_authority_named_fields_are_refused_whatever_their_type(field_name: str) -> None:
    """A plain ``str`` named like a credential is still refused.

    Type checking alone would pass ``authorization_token: str`` — which is
    precisely the shape that persists a bearer token. The name check is what
    catches it.
    """
    leaky = TypedDict("leaky", {"scan_run_id": str, field_name: str}, total=False)
    with pytest.raises(StateSchemaViolation, match="names authority material"):
        assert_state_schema_is_closed(leaky)


@pytest.mark.parametrize("annotation", [Any, dict, "dict[str, Any]", object])
def test_non_primitive_types_are_refused(annotation: object) -> None:
    """An allowlist, not a denylist: ``Any`` or a mapping could carry anything."""
    leaky = TypedDict("leaky", {"scan_run_id": str, "payload": annotation}, total=False)
    with pytest.raises(StateSchemaViolation, match="non-primitive type"):
        assert_state_schema_is_closed(leaky)


def test_primitives_and_optional_primitives_are_allowed() -> None:
    class Fine(TypedDict, total=False):
        scan_run_id: str
        count: int
        ratio: float
        halted: bool
        maybe: str | None
        names: list[str]

    assert_state_schema_is_closed(Fine)


def test_initial_state_carries_only_references_and_counters() -> None:
    state = initial_state("abc", 1)
    assert set(state) <= set(ScanGraphState.__annotations__)
    for value in state.values():
        assert isinstance(value, (str, int, float, bool))


def test_state_stays_tiny() -> None:
    """Growth here means something is accumulating that belongs in the ledger."""
    assert serialized_size(initial_state("a" * 36, 99)) < 512

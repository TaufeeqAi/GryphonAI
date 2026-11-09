"""The closed graph-state schema.

The graph carries **references and counters only**. It is compiled without a
checkpointer, so nothing here is persisted — but the schema is still closed by
an *allowlist* of primitive types, validated at import time, because the
codebase already contains the opposite precedent: the authorization
gate-conformance graph places the live permit into graph state. Copying that
shape into a long-running pipeline and later adding any persistence layer would
write bearer authority to disk.

The rule this module enforces mechanically:

    graph state may contain only primitives — no permit, capability, token,
    key, salt, secret or arbitrary object.

An offending annotation raises :class:`StateSchemaViolation` on import, so a
non-conforming schema fails the build rather than a scan. Authority is reached
only through the authority touchpoint, which holds it in a local variable for
the life of one call.
"""

from __future__ import annotations

import json
import types
import typing
from typing import Any, Final, TypedDict

from gryphon.orchestration.constants import SCAN_STATE_SCHEMA_VERSION
from gryphon.orchestration.reasons import StateSchemaViolation

# -----------------------------------------------------------------------------
# The schema
# -----------------------------------------------------------------------------


class ScanGraphState(TypedDict, total=False):
    """In-flight graph state: references and counters, nothing more.

    Durable truth lives in the work ledger. This dict exists only to route the
    compiled graph and to carry cheap counters between nodes within one
    invocation. Rebuilding it from the ledger is always legitimate.
    """

    #: The single admission identity. The only identifier the graph needs.
    scan_run_id: str
    #: The fenced claim epoch this invocation owns. Stamped on every ledger
    #: write so a superseded owner cannot mutate the scan.
    claim_epoch: int
    #: The stage the graph is entering, for routing and observability.
    stage: str
    #: Set when the gate denies: the graph routes straight to the end.
    halted: bool
    #: Terminal lifecycle state, once decided.
    terminal_state: str
    #: Stable reason code for the terminal state or the halt.
    reason_code: str
    #: Reference to the emitted report row, once assembled.
    report_id: str
    #: Cheap progress counters (authoritative counts come from the ledger).
    planned_count: int
    covered_count: int
    gap_count: int
    integrity_count: int
    #: Schema version, so a rebuilt state is never silently mixed with another.
    scan_state_version: str


#: Field names that must never appear, whatever their declared type.
_FORBIDDEN_NAME_FRAGMENTS: Final[tuple[str, ...]] = (
    "permit",
    "capability",
    "credential",
    "token",
    "secret",
    "salt",
    "key",
    "signature",
    "password",
    "grant_jws",
    "authorization",
)

#: The only types a graph-state field may be built from.
_ALLOWED_PRIMITIVES: Final[tuple[type, ...]] = (str, int, float, bool)


def _flatten(annotation: Any) -> list[Any]:
    """Return every concrete type mentioned by an annotation."""
    origin = typing.get_origin(annotation)
    if origin is None:
        return [annotation]
    # Unions (including `X | None`) and containers: inspect every argument.
    if origin in (typing.Union, types.UnionType):
        out: list[Any] = []
        for arg in typing.get_args(annotation):
            out.extend(_flatten(arg))
        return out
    if origin in (list, tuple, set, frozenset):
        out = [origin]
        for arg in typing.get_args(annotation):
            if arg is Ellipsis:
                continue
            out.extend(_flatten(arg))
        return out
    # Anything else (Mapping, a dataclass, a Protocol, Any) is not primitive.
    return [annotation]


def assert_state_schema_is_closed(schema: type = ScanGraphState) -> None:
    """Raise if the graph-state schema could carry authority.

    Uses an allowlist: a field must resolve to the declared primitives (or
    homogeneous containers of them). ``Any``, mappings and arbitrary classes are
    all rejected, so a future "convenience" field cannot smuggle an object in.
    """
    hints = typing.get_type_hints(schema)
    for name, annotation in hints.items():
        lowered = name.lower()
        for fragment in _FORBIDDEN_NAME_FRAGMENTS:
            if fragment in lowered:
                raise StateSchemaViolation(
                    f"graph-state field {name!r} names authority material; "
                    "authority is reached through the touchpoint, never state"
                )
        for part in _flatten(annotation):
            if part is type(None):
                continue
            if part in _ALLOWED_PRIMITIVES:
                continue
            if part in (list, tuple, set, frozenset):
                continue
            raise StateSchemaViolation(
                f"graph-state field {name!r} declares non-primitive type {part!r}; "
                "graph state may carry only references and counters"
            )


# Fail the build, not a scan.
assert_state_schema_is_closed()


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def initial_state(scan_run_id: str, claim_epoch: int) -> ScanGraphState:
    """Build the entry state for one invocation."""
    return ScanGraphState(
        scan_run_id=scan_run_id,
        claim_epoch=claim_epoch,
        stage="gate",
        halted=False,
        planned_count=0,
        covered_count=0,
        gap_count=0,
        integrity_count=0,
        scan_state_version=SCAN_STATE_SCHEMA_VERSION,
    )


def serialized_size(state: ScanGraphState) -> int:
    """Return the serialized size of ``state`` in bytes.

    Used to assert the state stays a references-and-counters object. Growth here
    means something is accumulating in the graph that belongs in the ledger.
    """
    return len(json.dumps(dict(state), sort_keys=True, separators=(",", ":")).encode())

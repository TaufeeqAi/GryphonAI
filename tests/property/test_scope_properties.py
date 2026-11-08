"""Property / fuzz tests for scope policy (§30.5, SEC-006/007)."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gryphon.auth.scope import (
    ScopeEntry,
    ScopeResult,
    canonicalize_domain,
    canonicalize_target,
    evaluate,
)
from gryphon.constants import TargetType

pytestmark = pytest.mark.property

_labels = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=12)
_domains = st.builds(lambda a, b: f"{a}.{b}.example", _labels, _labels)


@given(target=_domains)
def test_target_outside_all_entries_is_never_match(target: str) -> None:
    # Scope authorizes a disjoint domain; the random target must never match.
    scope = (ScopeEntry(target_type=TargetType.DOMAIN, target="authorized.example.test"),)
    decision = evaluate(scope, canonicalize_target(target), None)
    assert decision.result in (ScopeResult.NO_MATCH, ScopeResult.EXCLUDED)
    assert decision.result is not ScopeResult.MATCH


@given(sub=_labels)
def test_adding_exclusion_cannot_turn_deny_into_allow(sub: str) -> None:
    target = canonicalize_target("app.example.com")
    path = f"/{sub}"
    open_scope = (ScopeEntry(target_type=TargetType.DOMAIN, target="app.example.com"),)
    excluded_scope = (
        ScopeEntry(target_type=TargetType.DOMAIN, target="app.example.com", excluded_paths=[path]),
    )
    open_result = evaluate(open_scope, target, path).result
    excluded_result = evaluate(excluded_scope, target, path).result
    # Adding the exclusion can only make access equal-or-less permissive.
    assert not (open_result is ScopeResult.EXCLUDED and excluded_result is ScopeResult.MATCH)
    assert excluded_result is ScopeResult.EXCLUDED


@given(domain=_domains)
def test_domain_canonicalization_is_idempotent(domain: str) -> None:
    once = canonicalize_domain(domain)
    assert canonicalize_domain(once) == once

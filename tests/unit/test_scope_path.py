"""Path canonicalization + exclusion precedence (§11.3, SEC-007)."""

from __future__ import annotations

import pytest

from gryphon.auth.scope import (
    ScopeEntry,
    ScopeResult,
    canonicalize_path,
    canonicalize_target,
    evaluate,
)
from gryphon.constants import TargetType
from gryphon.errors import ScopeEvaluationError

pytestmark = pytest.mark.unit


def _scope_with_exclusion(exclusion: str) -> tuple[ScopeEntry, ...]:
    return (
        ScopeEntry(
            target_type=TargetType.DOMAIN, target="app.example.com", excluded_paths=[exclusion]
        ),
    )


def test_path_percent_decoded_once() -> None:
    assert canonicalize_path("/a%20b") == "/a b"


@pytest.mark.parametrize(
    "raw",
    [
        "/a%2fb",   # encoded slash
        "/a%5cb",   # encoded backslash
        "/a\\b",    # raw backslash
        "/a//b",    # repeated separator
        "/a/../b",  # dot segment
        "/a/./b",   # single dot segment
        "/a%00b",   # encoded NUL
        "relative", # not origin-form
        "/a?b=1",   # query not part of path
        "/a#frag",  # fragment not part of path
    ],
)
def test_path_rejects_ambiguous_forms(raw: str) -> None:
    with pytest.raises(ScopeEvaluationError):
        canonicalize_path(raw)


def test_path_is_case_sensitive() -> None:
    assert canonicalize_path("/Admin") == "/Admin"
    assert canonicalize_path("/Admin") != canonicalize_path("/admin")


def test_exclusion_matches_prefix_and_descendants_not_sibling() -> None:
    scope = _scope_with_exclusion("/admin")
    target = canonicalize_target("app.example.com")
    # /admin itself and descendants are excluded.
    assert evaluate(scope, target, "/admin").result is ScopeResult.EXCLUDED
    assert evaluate(scope, target, "/admin/users").result is ScopeResult.EXCLUDED
    # Sibling with shared prefix is NOT excluded.
    assert evaluate(scope, target, "/administrator").result is ScopeResult.MATCH
    # Unrelated path matches.
    assert evaluate(scope, target, "/public").result is ScopeResult.MATCH


def test_exclusion_overrides_positive_match() -> None:
    scope = _scope_with_exclusion("/admin")
    target = canonicalize_target("app.example.com")
    assert evaluate(scope, target, "/admin").result is ScopeResult.EXCLUDED

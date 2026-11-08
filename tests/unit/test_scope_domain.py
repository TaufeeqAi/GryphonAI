"""Domain + wildcard scope policy v1 (§11.3, SEC-006)."""

from __future__ import annotations

import pytest

from gryphon.auth.scope import (
    ScopeEntry,
    ScopeResult,
    canonicalize_domain,
    canonicalize_target,
    evaluate,
)
from gryphon.constants import TargetType
from gryphon.errors import ScopeEvaluationError

pytestmark = pytest.mark.unit


def _domain_scope(target: str, **kw) -> tuple[ScopeEntry, ...]:
    return (ScopeEntry(target_type=TargetType.DOMAIN, target=target, **kw),)


def _wildcard_scope(target: str) -> tuple[ScopeEntry, ...]:
    return (ScopeEntry(target_type=TargetType.DOMAIN_WILDCARD, target=target),)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("App.Example.COM", "app.example.com"),
        ("example.com.", "example.com"),
        ("xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai"),
    ],
)
def test_canonicalize_domain_normalizes(raw: str, expected: str) -> None:
    assert canonicalize_domain(raw) == expected


def test_canonicalize_domain_idna_a_label() -> None:
    # Internationalized labels are converted to A-label (IDNA 2008 / UTS-46).
    result = canonicalize_domain("бумага.рф")
    assert result.startswith("xn--") and result.endswith(".xn--p1ai")
    # Idempotent: canonicalizing the A-label yields the same value.
    assert canonicalize_domain(result) == result


@pytest.mark.parametrize(
    "raw",
    [
        "http://example.com",
        "example.com:443",
        "user@example.com",
        "exa mple.com",
        "example.com/path",
        "exam%70le.com",
        "",
        ".",
    ],
)
def test_canonicalize_domain_rejects_non_dns(raw: str) -> None:
    with pytest.raises(ScopeEvaluationError):
        canonicalize_domain(raw)


def test_exact_domain_matches_only_identical_fqdn() -> None:
    scope = _domain_scope("app.example.com")
    assert evaluate(scope, canonicalize_target("app.example.com"), None).result is ScopeResult.MATCH
    # No implicit parent/subdomain expansion (suffix confusion).
    assert evaluate(scope, canonicalize_target("evil-app.example.com"), None).result is ScopeResult.NO_MATCH
    assert evaluate(scope, canonicalize_target("example.com"), None).result is ScopeResult.NO_MATCH
    assert evaluate(scope, canonicalize_target("app.example.com.attacker.test"), None).result is ScopeResult.NO_MATCH


def test_wildcard_matches_exactly_one_label_not_apex_not_multilabel() -> None:
    scope = _wildcard_scope("*.example.com")
    assert evaluate(scope, canonicalize_target("api.example.com"), None).result is ScopeResult.MATCH
    # Apex excluded.
    assert evaluate(scope, canonicalize_target("example.com"), None).result is ScopeResult.NO_MATCH
    # Two labels excluded.
    assert evaluate(scope, canonicalize_target("a.b.example.com"), None).result is ScopeResult.NO_MATCH


def test_wildcard_grammar_rejects_double_star_and_mid_wildcard() -> None:
    with pytest.raises(ScopeEvaluationError):
        ScopeEntry(target_type=TargetType.DOMAIN_WILDCARD, target="*.*.example.com")
    with pytest.raises(ScopeEvaluationError):
        ScopeEntry(target_type=TargetType.DOMAIN_WILDCARD, target="api.example.com")

"""Execution identity: covers the request, stable, keyed, unpredictable.

These are the highest-consequence assertions in the layer. An identity that
collides across different requests silently drops a real scan; an identity that
changes across a restart silently runs a second one; an identity anyone can
compute lets a local process pre-register it and suppress the real call.
"""

from __future__ import annotations

import pytest

from gryphon.orchestration.identity import (
    derive_execution_id,
    new_execution_salt,
    plan_digest,
    request_digest,
)
from tests.orchestration.conftest import SCAN_RUN_ID, TEST_SALT

pytestmark = pytest.mark.unit


def _derive(**overrides) -> str:
    base = dict(
        execution_salt=TEST_SALT,
        scan_run_id=SCAN_RUN_ID,
        stage="scan",
        step="vulnerability_scan",
        seq=0,
        tool_id="nuclei",
        canonical_target="app.example.com",
        request_digest_hex="deadbeef" * 8,
        policy_version="1",
        attempt_epoch=0,
    )
    base.update(overrides)
    return derive_execution_id(**base)


# -- determinism --------------------------------------------------------------
def test_identical_inputs_yield_identical_identity() -> None:
    """The property crash-resume safety rests on."""
    assert _derive() == _derive()


def test_identity_is_128_bits_or_more() -> None:
    assert len(bytes.fromhex(_derive())) >= 16


# -- the request is covered ---------------------------------------------------
@pytest.mark.parametrize(
    "field,value",
    [
        ("request_digest_hex", "feedface" * 8),
        ("canonical_target", "other.example.com"),
        ("tool_id", "httpx"),
        ("step", "http_probe"),
        ("stage", "enumerate"),
        ("seq", 1),
        ("attempt_epoch", 1),
        ("policy_version", "2"),
        ("scan_run_id", "99999999-2222-3333-4444-555555555555"),
    ],
)
def test_every_tuple_element_changes_the_identity(field: str, value: object) -> None:
    """No input is decorative: changing any of them must change the identity."""
    assert _derive() != _derive(**{field: value})


def test_argv_difference_changes_the_request_digest() -> None:
    """Two calls that will DO different things get different identities.

    This is what stops the enforcement layer deduplicating a misconfiguration
    scan against an earlier CVE scan of the same host and reporting success for
    a scan that never ran.
    """
    common = dict(
        tool_id="nuclei",
        canonical_target="app.example.com",
        effective_depth="standard",
        descriptor_version="1",
    )
    cve = request_digest(argv=("-u", "app.example.com", "-tags", "cve"), **common)
    misconfig = request_digest(
        argv=("-u", "app.example.com", "-tags", "misconfig"), **common
    )
    assert cve != misconfig
    assert _derive(request_digest_hex=cve) != _derive(request_digest_hex=misconfig)


def test_request_digest_is_order_sensitive_in_argv() -> None:
    """An argument vector is a sequence; reordering it can change behaviour."""
    common = dict(
        tool_id="httpx",
        canonical_target="app.example.com",
        effective_depth="standard",
        descriptor_version="1",
    )
    assert request_digest(argv=("-a", "-b"), **common) != request_digest(
        argv=("-b", "-a"), **common
    )


# -- unpredictability ---------------------------------------------------------
def test_identity_depends_on_the_secret_salt() -> None:
    """Full knowledge of the public tuple must not yield the identity.

    Every other input is public — the scan id appears in logs and the report,
    the tool and step are fixed by the step table, the target is the client's
    hostname. Only the salt stops an id being precomputable.
    """
    other_salt = "b2" * 32
    assert _derive() != _derive(execution_salt=other_salt)


def test_unkeyed_derivation_is_refused() -> None:
    with pytest.raises(ValueError, match="execution_salt is required"):
        _derive(execution_salt="")


def test_salts_are_unique_and_long_enough() -> None:
    salts = {new_execution_salt() for _ in range(32)}
    assert len(salts) == 32
    assert all(len(bytes.fromhex(s)) >= 32 for s in salts)


# -- plan digest --------------------------------------------------------------
def test_plan_digest_is_stable_and_order_sensitive() -> None:
    """A plan digest proves a resumed plan is the same plan."""
    items = [
        {"seq": 0, "canonical_target": "a.example.com", "execution_id": "aa"},
        {"seq": 1, "canonical_target": "b.example.com", "execution_id": "bb"},
    ]
    base = dict(
        scan_run_id=SCAN_RUN_ID,
        stage="recon",
        step="subdomain_discovery",
        plan_generation=1,
        policy_version="1",
    )
    assert plan_digest(items=items, **base) == plan_digest(items=items, **base)
    assert plan_digest(items=list(reversed(items)), **base) != plan_digest(
        items=items, **base
    )


def test_plan_generation_changes_the_digest() -> None:
    items = [{"seq": 0, "canonical_target": "a.example.com", "execution_id": "aa"}]
    base = dict(
        scan_run_id=SCAN_RUN_ID,
        stage="recon",
        step="subdomain_discovery",
        policy_version="1",
    )
    assert plan_digest(items=items, plan_generation=1, **base) != plan_digest(
        items=items, plan_generation=2, **base
    )

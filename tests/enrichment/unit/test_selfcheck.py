"""The offline self-verification suite passes on this build."""

from __future__ import annotations

import pytest

from gryphon.enrichment.selfcheck import run_selfchecks

pytestmark = pytest.mark.unit


def test_all_selfchecks_pass(policy) -> None:
    results = run_selfchecks(policy)
    failed = [f"{c.name}: {c.detail}" for c in results if not c.passed]
    assert not failed, failed
    assert len(results) >= 13

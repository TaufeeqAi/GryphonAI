"""Descriptors drive policy; nuclei containment flags are always present."""

from __future__ import annotations

import pytest

from gryphon.constants import ScanDepth
from gryphon.tooling.constants import ToolId
from gryphon.tooling.tools.argbuilders import build_argv
from gryphon.tooling.tools.descriptors import all_descriptors, get_descriptor

pytestmark = pytest.mark.unit


def test_all_seven_descriptors_present() -> None:
    ids = {d.tool_id for d in all_descriptors()}
    assert ids == set(ToolId)


def test_passive_and_rawpacket_declared() -> None:
    assert get_descriptor(ToolId.SUBFINDER).is_passive is True
    assert get_descriptor(ToolId.SUBFINDER).touches_target is False
    # naabu uses raw packets — a proxy cannot contain it; the descriptor says so.
    assert get_descriptor(ToolId.NAABU).raw_packets is True
    assert get_descriptor(ToolId.NUCLEI).emits_oob is True


def test_nuclei_containment_flags() -> None:
    d = get_descriptor(ToolId.NUCLEI)
    argv = build_argv(ToolId.NUCLEI, d, "app.example.com", ScanDepth.AGGRESSIVE)
    joined = " ".join(argv)
    # Host-code template protocol excluded, OOB disabled, destructive tags excluded.
    assert "-exclude-type" in argv and "code" in joined
    assert "-no-interactsh" in argv
    assert "-exclude-tags" in argv
    exclude_tags = argv[argv.index("-exclude-tags") + 1]
    assert "dos" in exclude_tags and "fuzz" in exclude_tags
    # The target is a single argument, never interpolated into a shell string.
    assert "app.example.com" in argv


def test_depth_controls_tag_exclusions() -> None:
    d = get_descriptor(ToolId.NUCLEI)
    passive = build_argv(ToolId.NUCLEI, d, "app.example.com", ScanDepth.PASSIVE)
    standard = build_argv(ToolId.NUCLEI, d, "app.example.com", ScanDepth.STANDARD)
    aggressive = build_argv(ToolId.NUCLEI, d, "app.example.com", ScanDepth.AGGRESSIVE)
    passive_tags = passive[passive.index("-exclude-tags") + 1]
    standard_tags = standard[standard.index("-exclude-tags") + 1]
    aggressive_tags = aggressive[aggressive.index("-exclude-tags") + 1]
    assert "intrusive" in passive_tags and "intrusive" in standard_tags
    assert "intrusive" not in aggressive_tags  # aggressive: only dos/fuzz
    assert "dos" in aggressive_tags

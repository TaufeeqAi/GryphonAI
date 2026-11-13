"""Pinned reference data: provisioning, verification, translation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from gryphon.enrichment.reasons import ArtifactIntegrityError
from gryphon.enrichment.reference import (
    MANIFEST_NAME,
    PINNED_ATTACK_BUNDLE,
    PINNED_CTID_KEV_MAP,
    DatasetUnavailable,
    PinnedDataset,
    build_attack_index,
    build_ctid_index,
    load_reference,
    provision,
)
from gryphon.enrichment.selfcheck import tiny_reference

pytestmark = pytest.mark.unit


def _technique(stix_id: str, ext: str, *, revoked: bool = False, deprecated: bool = False) -> dict:
    obj = {
        "type": "attack-pattern",
        "id": stix_id,
        "name": ext,
        "external_references": [{"source_name": "mitre-attack", "external_id": ext}],
    }
    if revoked:
        obj["revoked"] = True
    if deprecated:
        obj["x_mitre_deprecated"] = True
    return obj


BUNDLE = {
    "type": "bundle",
    "objects": [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "20.1"},
        _technique("attack-pattern--a", "T1190"),
        _technique("attack-pattern--old", "T1001", revoked=True),
        _technique("attack-pattern--new", "T1002"),
        _technique("attack-pattern--dep", "T1003", deprecated=True),
        {"type": "relationship", "id": "relationship--1", "relationship_type": "revoked-by",
         "source_ref": "attack-pattern--old", "target_ref": "attack-pattern--new"},
    ],
}

CTID = {
    "metadata": {"attack_version": "16.1", "mapping_framework": "kev",
                 "mapping_framework_version": "07/28/2025", "technology_domain": "enterprise"},
    "mapping_objects": [
        {"capability_id": "CVE-2024-11111", "mapping_type": "exploitation_technique",
         "attack_object_id": "T1190", "status": "complete"},
        {"capability_id": "CVE-2024-11111", "mapping_type": "primary_impact",
         "attack_object_id": "T1001", "status": "complete"},
        {"capability_id": "CVE-2024-22222", "mapping_type": "secondary_impact",
         "attack_object_id": "T1003", "status": "complete"},
        {"capability_id": "CVE-2024-33333", "mapping_type": "non_mappable",
         "attack_object_id": None, "status": "complete"},
    ],
}


def _write(tmp_path: Path) -> tuple[Path, Path, tuple[PinnedDataset, PinnedDataset]]:
    bundle_path = tmp_path / "bundle.json"
    ctid_path = tmp_path / "ctid.json"
    bundle_path.write_text(json.dumps(BUNDLE))
    ctid_path.write_text(json.dumps(CTID))
    pins = (
        PinnedDataset("ATTACK_BUNDLE", "20.1", hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
                      bundle_path.stat().st_size, "https://example.invalid/b", "test"),
        PinnedDataset("CTID_KEV_MAP", "test", hashlib.sha256(ctid_path.read_bytes()).hexdigest(),
                      ctid_path.stat().st_size, "https://example.invalid/c", "test"),
    )
    return bundle_path, ctid_path, pins


def test_attack_index_records_revocation_and_deprecation() -> None:
    index = build_attack_index(BUNDLE, "0" * 64)
    assert index["attack_version"] == "20.1"
    assert index["techniques"]["T1001"]["revoked"] is True
    assert index["techniques"]["T1003"]["deprecated"] is True
    assert index["revoked_by"] == {"attack-pattern--old": "attack-pattern--new"}


def test_ctid_index_keeps_only_typed_technique_mappings() -> None:
    index = build_ctid_index(CTID, "0" * 64)
    assert sorted(index["mappings"]) == ["CVE-2024-11111", "CVE-2024-22222"]
    assert index["source_attack_version"] == "16.1"


def test_provision_verifies_pins(tmp_path: Path) -> None:
    bundle_path, ctid_path, pins = _write(tmp_path)
    manifest = provision(attack_bundle_path=bundle_path, ctid_map_path=ctid_path,
                         out_dir=tmp_path / "out", pins=pins)
    assert set(manifest["datasets"]) == {"ATTACK_BUNDLE", "CTID_KEV_MAP"}
    tampered = (pins[0], PinnedDataset("CTID_KEV_MAP", "test", "0" * 64, 1, "x", "x"))
    with pytest.raises(ArtifactIntegrityError):
        provision(attack_bundle_path=bundle_path, ctid_map_path=ctid_path,
                  out_dir=tmp_path / "out2", pins=tampered)


def test_runtime_loader_rejects_data_not_matching_the_code_pins(tmp_path: Path) -> None:
    bundle_path, ctid_path, pins = _write(tmp_path)
    provision(attack_bundle_path=bundle_path, ctid_map_path=ctid_path,
              out_dir=tmp_path / "out", pins=pins)
    # Provisioned with test pins, so the code-constant pins do not match.
    loaded = load_reference(tmp_path / "out")
    assert isinstance(loaded, DatasetUnavailable)
    assert "pin" in loaded.reason


def test_missing_and_corrupt_reference_is_unavailable(tmp_path: Path) -> None:
    assert isinstance(load_reference(tmp_path / "nowhere"), DatasetUnavailable)
    (tmp_path / MANIFEST_NAME).write_text("{not json")
    assert isinstance(load_reference(tmp_path), DatasetUnavailable)


def test_pins_are_commit_addressed_https() -> None:
    for pin in (PINNED_ATTACK_BUNDLE, PINNED_CTID_KEV_MAP):
        assert pin.url.startswith("https://raw.githubusercontent.com/")
        assert len(pin.sha256) == 64 and pin.size > 0
        # A 40-hex commit id in the path, never a branch name.
        assert any(len(part) == 40 and all(c in "0123456789abcdef" for c in part)
                   for part in pin.url.split("/"))


def test_translation_rules() -> None:
    reference = tiny_reference(
        {"CVE-2024-11111": [["T1001", "primary_impact"], ["T9999", "exploitation_technique"]]}
    )
    refs = {r.source_technique_id: r for r in reference.techniques_for("CVE-2024-11111")}
    assert (refs["T1001"].technique_id, refs["T1001"].translated) == ("T1002", True)
    assert refs["T9999"].technique_id is None
    assert refs["T9999"].untranslatable_reason == "unknown_in_bundle"
    assert reference.techniques_for("CVE-2000-0001") is None


def test_revocation_cycles_are_refused() -> None:
    reference = tiny_reference({"CVE-2024-11111": [["T1001", "primary_impact"]]})
    object.__setattr__(reference, "_revoked_by", {
        "attack-pattern--old": "attack-pattern--new",
        "attack-pattern--new": "attack-pattern--old",
    })
    reference._techniques["T1002"] = {**reference._techniques["T1002"], "revoked": True}
    (ref,) = reference.techniques_for("CVE-2024-11111")
    assert ref.technique_id is None
    assert ref.untranslatable_reason == "revoked_without_replacement"

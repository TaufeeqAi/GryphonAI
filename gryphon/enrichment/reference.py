"""Pinned, offline ATT&CK reference data.

Two datasets, both provisioned with the deployment and pinned by SHA-256 to an
immutable commit URL:

* **ATTACK_BUNDLE** — MITRE ATT&CK Enterprise STIX 2.1 bundle (v20.1). Used to
  validate technique ids and to translate ids from the mapping's older ATT&CK
  version through ``revoked-by`` relationships and deprecation flags.
* **CTID_KEV_MAP** — MITRE Center for Threat-Informed Defense mappings from
  CISA KEV CVEs to ATT&CK techniques (typed: ``exploitation_technique``,
  ``primary_impact``, ``secondary_impact``). Apache-2.0.

Provisioning (``scripts/provision_reference_data.py``) verifies each source file
against its pin, builds a compact index, and writes a manifest recording both
digests. At runtime nothing is fetched: the loader verifies the indexes against
the manifest and the manifest against the pins. A dataset that is missing or does
not verify is *unavailable* — reported as such, never as "no techniques".
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from gryphon.enrichment.artifacts import sha256_file
from gryphon.enrichment.reasons import ArtifactIntegrityError

MANIFEST_NAME: Final[str] = "manifest.json"
ATTACK_INDEX_NAME: Final[str] = "attack_index.json"
CTID_INDEX_NAME: Final[str] = "ctid_kev_map.json"
MANIFEST_FORMAT_VERSION: Final[str] = "1"
#: Hops allowed when following ``revoked-by`` chains (cycles are refused).
_MAX_REVOCATION_HOPS: Final[int] = 10
_MAPPING_TYPES: Final[frozenset[str]] = frozenset(
    {"exploitation_technique", "primary_impact", "secondary_impact", "uncategorized"}
)


@dataclass(frozen=True)
class PinnedDataset:
    name: str
    version: str
    sha256: str
    size: int
    url: str
    license: str
    detail: str = ""


#: MITRE ATT&CK Enterprise v20.1 (released 2026-11-05), pinned to commit f59b03ec.
PINNED_ATTACK_BUNDLE: Final[PinnedDataset] = PinnedDataset(
    name="ATTACK_BUNDLE",
    version="20.1",
    sha256="539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5",
    size=55_277_605,
    url=(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "f59b03ecf828579d5f9e93683ce25b7e2e5fd9d7/enterprise-attack/enterprise-attack-20.1.json"
    ),
    license="MITRE ATT&CK Terms of Use",
    detail="enterprise-attack",
)

#: CTID KEV → ATT&CK mappings (KEV 07.28.2025, ATT&CK 16.1, enterprise), commit e51d7f59.
PINNED_CTID_KEV_MAP: Final[PinnedDataset] = PinnedDataset(
    name="CTID_KEV_MAP",
    version="kev-07.28.2025_attack-16.1-enterprise",
    sha256="b57b3d382809d9159fdda6701d21f0e67a2d655444d89301caab2c39ad54bdc7",
    size=1_210_128,
    url=(
        "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/"
        "e51d7f595db675df064ffc2b5c35c88f98eb3688/mappings/kev/attack-16.1/kev-07.28.2025/"
        "enterprise/kev-07.28.2025_attack-16.1-enterprise.json"
    ),
    license="Apache-2.0",
    detail="source ATT&CK 16.1",
)

PINNED_DATASETS: Final[tuple[PinnedDataset, ...]] = (PINNED_ATTACK_BUNDLE, PINNED_CTID_KEV_MAP)


# -----------------------------------------------------------------------------
# Provisioning: source files → compact indexes + manifest
# -----------------------------------------------------------------------------
def _canonical_json(obj: Any) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _mitre_external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            ext = ref.get("external_id")
            if isinstance(ext, str) and ext.startswith("T"):
                return ext
    return None


def build_attack_index(bundle: dict[str, Any], source_sha256: str) -> dict[str, Any]:
    """Compact technique index from an ATT&CK STIX 2.1 bundle."""
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ArtifactIntegrityError("ATT&CK file is not a STIX bundle")
    version = None
    techniques: dict[str, dict[str, Any]] = {}
    stix_to_ext: dict[str, str] = {}
    revoked_by: dict[str, str] = {}
    for obj in bundle["objects"]:
        if not isinstance(obj, dict):
            continue
        kind = obj.get("type")
        if kind == "x-mitre-collection":
            version = obj.get("x_mitre_version")
        elif kind == "attack-pattern":
            ext = _mitre_external_id(obj)
            stix_id = obj.get("id")
            if not ext or not isinstance(stix_id, str):
                continue
            stix_to_ext[stix_id] = ext
            current = techniques.get(ext)
            entry = {
                "name": str(obj.get("name", ""))[:200],
                "stix_id": stix_id,
                "revoked": bool(obj.get("revoked", False)),
                "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            }
            # Prefer the live object if an id appears more than once.
            if current is None or (current["revoked"] or current["deprecated"]):
                techniques[ext] = entry
        elif kind == "relationship" and obj.get("relationship_type") == "revoked-by":
            source_ref, target_ref = obj.get("source_ref"), obj.get("target_ref")
            if isinstance(source_ref, str) and isinstance(target_ref, str):
                revoked_by[source_ref] = target_ref
    if not version:
        raise ArtifactIntegrityError("ATT&CK bundle has no collection version")
    return {
        "format_version": MANIFEST_FORMAT_VERSION,
        "attack_version": str(version),
        "source_sha256": source_sha256,
        "techniques": dict(sorted(techniques.items())),
        "stix_to_ext": dict(sorted(stix_to_ext.items())),
        "revoked_by": dict(sorted(revoked_by.items())),
    }


def build_ctid_index(document: dict[str, Any], source_sha256: str) -> dict[str, Any]:
    """Compact CVE → techniques index from a CTID KEV mapping file."""
    metadata = document.get("metadata")
    objects = document.get("mapping_objects")
    if not isinstance(metadata, dict) or not isinstance(objects, list):
        raise ArtifactIntegrityError("CTID file lacks metadata or mapping_objects")
    if metadata.get("mapping_framework") != "kev":
        raise ArtifactIntegrityError("CTID file is not a KEV mapping")
    mappings: dict[str, set[tuple[str, str]]] = defaultdict(set)
    skipped = 0
    for obj in objects:
        if not isinstance(obj, dict):
            skipped += 1
            continue
        cve = obj.get("capability_id")
        technique = obj.get("attack_object_id")
        mapping_type = obj.get("mapping_type")
        if (
            not isinstance(cve, str)
            or not cve.startswith("CVE-")
            or not isinstance(technique, str)
            or not technique.startswith("T")
            or mapping_type not in _MAPPING_TYPES
            or obj.get("status") not in (None, "complete")
        ):
            skipped += 1
            continue
        mappings[cve.upper()].add((technique, mapping_type))
    return {
        "format_version": MANIFEST_FORMAT_VERSION,
        "source_sha256": source_sha256,
        "source_attack_version": str(metadata.get("attack_version", "")),
        "kev_version": str(metadata.get("mapping_framework_version", "")),
        "technology_domain": str(metadata.get("technology_domain", "")),
        "skipped_objects": skipped,
        "mappings": {cve: sorted(pairs) for cve, pairs in sorted(mappings.items())},
    }


def provision(
    *,
    attack_bundle_path: Path,
    ctid_map_path: Path,
    out_dir: Path,
    pins: tuple[PinnedDataset, PinnedDataset] = (PINNED_ATTACK_BUNDLE, PINNED_CTID_KEV_MAP),
) -> dict[str, Any]:
    """Verify both source files against their pins and write indexes + manifest."""
    attack_pin, ctid_pin = pins
    attack_sha = sha256_file(attack_bundle_path)
    if attack_sha != attack_pin.sha256:
        raise ArtifactIntegrityError(
            f"ATT&CK bundle digest {attack_sha[:12]}… does not match the pin "
            f"{attack_pin.sha256[:12]}…"
        )
    ctid_sha = sha256_file(ctid_map_path)
    if ctid_sha != ctid_pin.sha256:
        raise ArtifactIntegrityError(
            f"CTID mapping digest {ctid_sha[:12]}… does not match the pin {ctid_pin.sha256[:12]}…"
        )
    attack_index = build_attack_index(json.loads(attack_bundle_path.read_bytes()), attack_sha)
    if attack_index["attack_version"] != attack_pin.version:
        raise ArtifactIntegrityError("ATT&CK bundle version does not match the pin")
    ctid_index = build_ctid_index(json.loads(ctid_map_path.read_bytes()), ctid_sha)

    out_dir.mkdir(parents=True, exist_ok=True)
    attack_bytes = _canonical_json(attack_index)
    ctid_bytes = _canonical_json(ctid_index)
    (out_dir / ATTACK_INDEX_NAME).write_bytes(attack_bytes)
    (out_dir / CTID_INDEX_NAME).write_bytes(ctid_bytes)
    manifest = {
        "format_version": MANIFEST_FORMAT_VERSION,
        "provisioned_at": datetime.now(UTC).isoformat(),
        "datasets": {
            attack_pin.name: {
                "version": attack_pin.version,
                "source_sha256": attack_sha,
                "index_sha256": hashlib.sha256(attack_bytes).hexdigest(),
                "index_file": ATTACK_INDEX_NAME,
                "url": attack_pin.url,
                "license": attack_pin.license,
            },
            ctid_pin.name: {
                "version": ctid_pin.version,
                "source_sha256": ctid_sha,
                "index_sha256": hashlib.sha256(ctid_bytes).hexdigest(),
                "index_file": CTID_INDEX_NAME,
                "url": ctid_pin.url,
                "license": ctid_pin.license,
            },
        },
    }
    (out_dir / MANIFEST_NAME).write_bytes(_canonical_json(manifest))
    return manifest


# -----------------------------------------------------------------------------
# Runtime: verified loading and translation
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class TechniqueRef:
    technique_id: str | None
    source_technique_id: str
    mapping_type: str
    source_attack_version: str
    translated: bool
    untranslatable_reason: str | None = None

    def as_payload(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "source_technique_id": self.source_technique_id,
            "mapping_type": self.mapping_type,
            "source_attack_version": self.source_attack_version,
            "translated": self.translated,
            "untranslatable_reason": self.untranslatable_reason,
        }


@dataclass(frozen=True)
class ReferenceData:
    attack_version: str
    mapping_version: str
    kev_version: str
    source_attack_version: str
    snapshot_id: str
    attack_sha256: str
    ctid_sha256: str
    _techniques: dict[str, dict[str, Any]] = field(repr=False)
    _stix_to_ext: dict[str, str] = field(repr=False)
    _revoked_by: dict[str, str] = field(repr=False)
    _mappings: dict[str, list[list[str]]] = field(repr=False)

    def _translate(self, technique_id: str) -> tuple[str | None, bool, str | None]:
        """Follow ``revoked-by`` to the live technique at the pinned version.

        Returns (technique id or None, translated?, reason when untranslatable).
        """
        current_id = technique_id
        current = self._techniques.get(current_id)
        if current is None:
            return None, False, "unknown_in_bundle"
        seen = {current["stix_id"]}
        hops = 0
        while current["revoked"]:
            target_stix = self._revoked_by.get(current["stix_id"])
            target_id = self._stix_to_ext.get(target_stix) if target_stix else None
            target = self._techniques.get(target_id) if target_id else None
            if (
                target is None
                or target_id is None
                or target_stix is None
                or target_stix in seen
                or hops >= _MAX_REVOCATION_HOPS
            ):
                return None, hops > 0, "revoked_without_replacement"
            seen.add(target_stix)
            hops += 1
            current_id, current = target_id, target
        if current["deprecated"]:
            return None, hops > 0, "deprecated"
        return current_id, hops > 0, None

    def techniques_for(self, cve: str) -> list[TechniqueRef] | None:
        """Techniques mapped to ``cve`` at the pinned ATT&CK version, or None."""
        pairs = self._mappings.get(cve)
        if not pairs:
            return None
        refs: list[TechniqueRef] = []
        for source_id, mapping_type in pairs:
            technique_id, translated, reason = self._translate(source_id)
            refs.append(
                TechniqueRef(
                    technique_id=technique_id,
                    source_technique_id=source_id,
                    mapping_type=mapping_type,
                    source_attack_version=self.source_attack_version,
                    translated=translated,
                    untranslatable_reason=reason,
                )
            )
        return refs


@dataclass(frozen=True)
class DatasetUnavailable:
    reason: str


def load_reference(reference_dir: Path) -> ReferenceData | DatasetUnavailable:
    """Load the provisioned indexes, verifying them against manifest and pins."""
    manifest_path = Path(reference_dir) / MANIFEST_NAME
    if not manifest_path.is_file():
        return DatasetUnavailable("reference data is not provisioned (no manifest)")
    try:
        manifest = json.loads(manifest_path.read_bytes())
        datasets = manifest["datasets"]
        loaded: dict[str, dict[str, Any]] = {}
        for pin in PINNED_DATASETS:
            entry = datasets[pin.name]
            if entry["source_sha256"] != pin.sha256:
                return DatasetUnavailable(f"{pin.name} source digest does not match the pin")
            index_path = Path(reference_dir) / entry["index_file"]
            if not index_path.is_file():
                return DatasetUnavailable(f"{pin.name} index file is missing")
            index_bytes = index_path.read_bytes()
            if hashlib.sha256(index_bytes).hexdigest() != entry["index_sha256"]:
                return DatasetUnavailable(f"{pin.name} index does not match the manifest")
            loaded[pin.name] = json.loads(index_bytes)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        return DatasetUnavailable(f"reference manifest is unreadable: {type(exc).__name__}")

    attack = loaded[PINNED_ATTACK_BUNDLE.name]
    ctid = loaded[PINNED_CTID_KEV_MAP.name]
    if attack.get("source_sha256") != PINNED_ATTACK_BUNDLE.sha256:
        return DatasetUnavailable("ATT&CK index was built from an unpinned bundle")
    if ctid.get("source_sha256") != PINNED_CTID_KEV_MAP.sha256:
        return DatasetUnavailable("CTID index was built from an unpinned mapping file")
    snapshot_id = (
        f"{PINNED_CTID_KEV_MAP.name}:{PINNED_CTID_KEV_MAP.version}"
        f"@sha256:{PINNED_CTID_KEV_MAP.sha256}"
        f"+{PINNED_ATTACK_BUNDLE.name}:{PINNED_ATTACK_BUNDLE.version}"
    )
    return ReferenceData(
        attack_version=str(attack["attack_version"]),
        mapping_version=PINNED_CTID_KEV_MAP.version,
        kev_version=str(ctid.get("kev_version", "")),
        source_attack_version=str(ctid.get("source_attack_version", "")),
        snapshot_id=snapshot_id,
        attack_sha256=PINNED_ATTACK_BUNDLE.sha256,
        ctid_sha256=PINNED_CTID_KEV_MAP.sha256,
        _techniques=attack["techniques"],
        _stix_to_ext=attack["stix_to_ext"],
        _revoked_by=attack["revoked_by"],
        _mappings=ctid["mappings"],
    )

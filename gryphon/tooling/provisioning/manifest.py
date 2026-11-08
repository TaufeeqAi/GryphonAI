"""Tool provisioning manifest and binary resolvers.

The manifest records, per tool, the pinned version, absolute binary path and
expected SHA-256. ``ManifestBinaryResolver`` resolves and (lazily) integrity-
checks binaries from it. ``StaticBinaryResolver`` is a simple map used in tests
and single-binary setups.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from gryphon.tooling.constants import ToolId
from gryphon.tooling.reasons import ProvisioningError


class ToolBinaryEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_id: ToolId
    version: str = Field(min_length=1)
    path: str = Field(min_length=1)
    sha256: str = Field(min_length=64, max_length=64)


class ToolManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    entries: tuple[ToolBinaryEntry, ...]

    def by_tool(self) -> dict[ToolId, ToolBinaryEntry]:
        return {e.tool_id: e for e in self.entries}

    @classmethod
    def load(cls, path: str | Path) -> "ToolManifest":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(entries=tuple(ToolBinaryEntry(**e) for e in data["entries"]))


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_entry(entry: ToolBinaryEntry) -> None:
    """Raise if the binary is missing or its checksum does not match."""
    p = Path(entry.path)
    if not p.is_absolute() or not p.exists():
        raise ProvisioningError(f"{entry.tool_id.value} binary missing at {entry.path}")
    actual = sha256_file(p)
    if actual.lower() != entry.sha256.lower():
        raise ProvisioningError(f"{entry.tool_id.value} checksum mismatch")


class ManifestBinaryResolver:
    """Resolves binaries from a verified manifest (integrity-checked once)."""

    def __init__(self, manifest: ToolManifest, *, verify: bool = True) -> None:
        self._entries = manifest.by_tool()
        if verify:
            for entry in self._entries.values():
                verify_entry(entry)

    def resolve(self, tool_id: ToolId) -> str | None:
        entry = self._entries.get(tool_id)
        return entry.path if entry else None


@dataclass(frozen=True)
class StaticBinaryResolver:
    """A simple tool_id → absolute path map (tests / single-host setups)."""

    paths: dict[ToolId, str]

    def resolve(self, tool_id: ToolId) -> str | None:
        return self.paths.get(tool_id)

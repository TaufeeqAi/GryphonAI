"""Export the tool execution layer into a single bundled markdown file.

Bundles ONLY this layer's files (the ``gryphon/tooling`` package, its three
sibling DB tables + repositories + migration, and its tests), the directory
structure, and the codebase guide. Additive edits to shared authorization-core
files are noted but not re-exported.

    python -m scripts.export_tooling_bundle
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = REPO_ROOT / "GRYPHON_Tool_Execution_Layer_Bundle.md"
GUIDE = REPO_ROOT / "docs" / "TOOL_EXECUTION_CODEBASE_GUIDE.md"

# Explicit, scoped file set for this layer.
_GLOBS = ["gryphon/tooling/**/*.py", "tests/tooling/**/*.py"]
_EXPLICIT = [
    "gryphon/db/models/tool_execution.py",
    "gryphon/db/models/capability_consumption.py",
    "gryphon/db/models/tool_invocation_audit.py",
    "gryphon/db/repositories/tool_execution.py",
    "gryphon/db/repositories/capability_consumption.py",
    "gryphon/db/repositories/tool_audit.py",
    "gryphon/db/migrations/versions/0002_tool_execution_layer.py",
    "docs/TOOL_EXECUTION_LAYER.md",
    "docs/TOOL_EXECUTION_CODEBASE_GUIDE.md",
    "docs/TOOL_EXECUTION_RUNBOOK.md",
    "scripts/tooling_readiness.py",
    "scripts/verify_tooling.py",
    "scripts/verify_tool_binaries.py",
    "scripts/gryphon_egress_helper.py",
    "scripts/provision_tool_binaries.sh",
]

_LANG = {
    ".py": "python",
    ".md": "markdown",
    ".sql": "sql",
    ".toml": "toml",
    ".txt": "text",
    ".sh": "bash",
}

_SHARED_EDITS = """\
This layer also makes small **additive** edits to shared authorization-core files
(not re-exported here):

* `gryphon/db/models/__init__.py` — registers the three new sibling tables on the
  shared metadata.
* `requirements.txt` — adds `fastmcp==4.1.6` (the transport adapter).
* `scripts/generate_keys.py` / `.env.example` — emit/declare the capability key
  and the layer's settings.
* `Makefile` — adds the `tooling-*` developer targets (test / ready / verify / bundle).
"""


def _collect() -> list[Path]:
    files: set[Path] = set()
    for glob in _GLOBS:
        files.update(p for p in REPO_ROOT.glob(glob) if p.is_file())
    for rel in _EXPLICIT:
        p = REPO_ROOT / rel
        if p.is_file():
            files.add(p)
    return sorted(files, key=lambda p: p.relative_to(REPO_ROOT).as_posix())


def _tree(files: list[Path]) -> str:
    root: dict = {}
    for path in files:
        node = root
        for part in path.relative_to(REPO_ROOT).parts:
            node = node.setdefault(part, {})
    lines = ["GRYPHON/  (tool execution layer — scoped view)"]

    def walk(node: dict, prefix: str) -> None:
        entries = sorted(node.items(), key=lambda kv: (not bool(kv[1]), kv[0]))
        for i, (name, child) in enumerate(entries):
            last = i == len(entries) - 1
            lines.append(f"{prefix}{'└── ' if last else '├── '}{name}{'/' if child else ''}")
            if child:
                walk(child, prefix + ("    " if last else "│   "))

    walk(root, "")
    return "\n".join(lines)


def _fence(content: str) -> str:
    longest = run = 0
    for ch in content:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    return "`" * max(3, longest + 1)


def build() -> str:
    files = _collect()
    today = _dt.date.today().isoformat()
    parts: list[str] = [
        f"""# GRYPHON — Capability-Gated Tool Execution Layer — Codebase Bundle

> **Contract:** v1.1.0  ·  **Generated:** {today}  ·  **Files bundled:** {len(files)}
> **Runtime:** CPython 3.12+  ·  new dependency: `fastmcp==4.1.6` (transport adapter only)

This single file bundles the complete tool execution layer: directory structure,
codebase guide, and every source and test file inlined below.

{_SHARED_EDITS}

## Table of contents
1. [Directory structure](#1-directory-structure)
2. [Codebase guide](#2-codebase-guide)
3. [Source files](#3-source-files)
""",
        "## 1. Directory structure\n\n```text\n" + _tree(files) + "\n```\n",
        "## 2. Codebase guide\n\n"
        + (GUIDE.read_text(encoding="utf-8") if GUIDE.exists() else "_guide missing_")
        + "\n",
        "## 3. Source files\n",
    ]
    for path in files:
        rel = path.relative_to(REPO_ROOT).as_posix()
        content = path.read_text(encoding="utf-8")
        fence = _fence(content)
        lang = _LANG.get(path.suffix, "text")
        parts.append(f"\n### `{rel}`\n\n{fence}{lang}\n{content}\n{fence}\n")
    return "\n".join(parts)


def main() -> None:
    OUTPUT.write_text(build(), encoding="utf-8")
    print(f"Wrote {OUTPUT.name} ({OUTPUT.stat().st_size / 1024:.1f} KiB)")


if __name__ == "__main__":
    main()

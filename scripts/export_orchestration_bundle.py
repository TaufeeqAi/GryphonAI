"""Export the scan orchestration layer into a single bundled markdown file.

Bundles ONLY this layer's files: the ``gryphon/orchestration`` package, its
sibling DB models and migration, its scripts, docs and tests — plus the
directory structure and the codebase guide. Additive edits to shared files are
noted rather than re-exported, so the bundle stays a scoped view rather than a
copy of the repository.

    python -m scripts.export_orchestration_bundle
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = REPO_ROOT / "GRYPHON_Scan_Orchestration_Layer_Bundle.md"
GUIDE = REPO_ROOT / "docs" / "SCAN_ORCHESTRATION_CODEBASE_GUIDE.md"

_GLOBS = ["gryphon/orchestration/**/*.py", "tests/orchestration/**/*.py"]
_EXPLICIT = [
    "gryphon/db/models/scan_lifecycle.py",
    "gryphon/db/models/scan_plan.py",
    "gryphon/db/models/raw_finding.py",
    "gryphon/db/models/scan_report.py",
    "gryphon/db/migrations/versions/0003_orchestration_layer.py",
    "gryphon/auth/permit_resolver.py",
    "docs/SCAN_ORCHESTRATION.md",
    "docs/SCAN_ORCHESTRATION_CODEBASE_GUIDE.md",
    "docs/SCAN_ORCHESTRATION_RUNBOOK.md",
    "scripts/orchestration_readiness.py",
    "scripts/verify_orchestration.py",
    "scripts/run_scan.py",
    "scripts/export_orchestration_bundle.py",
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
This layer makes small **additive** edits to shared files (not re-exported here):

* `gryphon/db/models/__init__.py` — registers the seven new sibling tables on the
  shared metadata.
* `gryphon/auth/permit_resolver.py` — **new**, and bundled above: re-resolving an
  in-process permit from committed admission records belongs to the
  authorization layer, because minting authority is that layer's privilege and
  "is this authorization still live?" is its question to answer.
* `Makefile` — adds the `scan-*` developer targets (test / ready / verify / bundle).
* `.env.example` — declares this layer's settings.
* `scripts/admit_scan.py` — **new**, and NOT bundled: admitting a scan creates the
  `scan_run_id` this layer consumes, which only the authorization core may do.
  It is the missing operator step between issuing a grant and starting a scan.
* `gryphon/logging_config.py` — gains a `stream` argument so an operator CLI can
  send diagnostics to stderr and keep stdout for its one machine-readable value.
  The CLIs now call `configure_logging`, which also activates the redaction
  processor that was previously defined but never invoked by any process.

It adds **no new third-party dependency**: the graph runtime was already a
runtime dependency of the project.
"""


def _collect() -> list[Path]:
    files: set[Path] = set()
    for glob in _GLOBS:
        files.update(p for p in REPO_ROOT.glob(glob) if p.is_file())
    for rel in _EXPLICIT:
        path = REPO_ROOT / rel
        if path.is_file():
            files.add(path)
    return sorted(files, key=lambda p: p.relative_to(REPO_ROOT).as_posix())


def _tree(files: list[Path]) -> str:
    root: dict = {}
    for path in files:
        node = root
        for part in path.relative_to(REPO_ROOT).parts:
            node = node.setdefault(part, {})
    lines = ["GRYPHON/  (scan orchestration layer — scoped view)"]

    def walk(node: dict, prefix: str) -> None:
        entries = sorted(node.items(), key=lambda kv: (not bool(kv[1]), kv[0]))
        for i, (name, child) in enumerate(entries):
            last = i == len(entries) - 1
            lines.append(
                f"{prefix}{'└── ' if last else '├── '}{name}{'/' if child else ''}"
            )
            if child:
                walk(child, prefix + ("    " if last else "│   "))

    walk(root, "")
    return "\n".join(lines)


def _fence(content: str) -> str:
    """Pick a fence longer than any backtick run inside the content."""
    longest = run = 0
    for ch in content:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    return "`" * max(3, longest + 1)


def build() -> str:
    files = _collect()
    today = _dt.date.today().isoformat()
    parts: list[str] = [
        f"""# GRYPHON — Scan Orchestration Layer — Codebase Bundle

> **Contract:** v1.1.0  ·  **Generated:** {today}  ·  **Files bundled:** {len(files)}
> **Runtime:** CPython 3.12+  ·  **New dependencies:** none

This single file bundles the complete scan orchestration layer: directory
structure, codebase guide, and every source and test file inlined below.

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

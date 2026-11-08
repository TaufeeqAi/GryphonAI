"""Export the entire Phase 1 codebase into one bundled markdown file.

Produces ``GRYPHON_Phase1_Codebase_Bundle.md`` at the repository root, containing:

1. a header with provenance,
2. the complete Phase 1 directory structure,
3. the full codebase guide (docs/CODEBASE_GUIDE.md), and
4. every source/config/test file inlined with a correctly-sized code fence.

Deterministic output (sorted paths) so diffs are meaningful.

    python -m scripts.export_bundle
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = REPO_ROOT / "GRYPHON_Phase1_Codebase_Bundle.md"
GUIDE = REPO_ROOT / "docs" / "CODEBASE_GUIDE.md"

EXCLUDE_DIRS = {
    ".venv", ".git", "__pycache__", ".pytest_cache", ".hypothesis",
    ".ruff_cache", ".mypy_cache", "artifacts", ".idea", ".vscode", "node_modules",
}
EXCLUDE_NAMES = {OUTPUT.name, "CODEBASE_GUIDE.md"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo"}

LANG_BY_SUFFIX = {
    ".py": "python", ".toml": "toml", ".md": "markdown", ".yml": "yaml",
    ".yaml": "yaml", ".sql": "sql", ".ini": "ini", ".mako": "mako",
    ".txt": "text", ".cfg": "ini", ".sh": "bash",
}
LANG_BY_NAME = {
    "Makefile": "makefile", ".gitignore": "text", ".env.example": "bash",
    "docker-compose.yml": "yaml", "alembic.ini": "ini",
}


def _iter_files() -> list[Path]:
    files: list[Path] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(REPO_ROOT)
        if any(part in EXCLUDE_DIRS for part in rel.parts):
            continue
        if path.name in EXCLUDE_NAMES or path.suffix in EXCLUDE_SUFFIXES:
            continue
        if path.name.endswith(".egg-info"):
            continue
        files.append(path)
    return sorted(files, key=lambda p: p.relative_to(REPO_ROOT).as_posix())


def _render_tree(files: list[Path]) -> str:
    tree: dict = {}
    for path in files:
        node = tree
        for part in path.relative_to(REPO_ROOT).parts:
            node = node.setdefault(part, {})

    lines: list[str] = ["gryphon/  (repository root)"]

    def walk(node: dict, prefix: str) -> None:
        entries = sorted(node.items(), key=lambda kv: (not bool(kv[1]), kv[0]))
        for i, (name, child) in enumerate(entries):
            last = i == len(entries) - 1
            connector = "└── " if last else "├── "
            suffix = "/" if child else ""
            lines.append(f"{prefix}{connector}{name}{suffix}")
            if child:
                walk(child, prefix + ("    " if last else "│   "))

    walk(tree, "")
    return "\n".join(lines)


def _lang(path: Path) -> str:
    return LANG_BY_NAME.get(path.name) or LANG_BY_SUFFIX.get(path.suffix, "text")


def _fence_for(content: str) -> str:
    longest = 0
    run = 0
    for ch in content:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    return "`" * max(3, longest + 1)


def build() -> str:
    files = _iter_files()
    today = _dt.date.today().isoformat()
    parts: list[str] = []

    parts.append(
        f"""# GRYPHON — Phase 1 Codebase Bundle

> **Phase:** 1 — Authorization Gate + Core Database
> **Contract:** v1.1.0
> **Generated:** {today}
> **Files bundled:** {len(files)}
> **Target runtime:** CPython 3.12+  ·  dependency pins confirmed live from PyPI 2026-11-08

This single file bundles the complete Phase 1 implementation: the directory
structure, the codebase guide for senior/staff engineers and principal
architects, and every source, configuration and test file inlined below.

---

## Table of contents

1. [Directory structure](#1-directory-structure)
2. [Codebase guide](#2-codebase-guide)
3. [Source files](#3-source-files)
"""
    )

    parts.append("## 1. Directory structure\n\n```text\n" + _render_tree(files) + "\n```\n")

    guide_text = GUIDE.read_text(encoding="utf-8") if GUIDE.exists() else "_guide missing_"
    parts.append("## 2. Codebase guide\n\n" + guide_text + "\n")

    parts.append("## 3. Source files\n")
    for path in files:
        rel = path.relative_to(REPO_ROOT).as_posix()
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = "<binary file omitted>"
        fence = _fence_for(content)
        parts.append(f"\n### `{rel}`\n\n{fence}{_lang(path)}\n{content}\n{fence}\n")

    return "\n".join(parts)


def main() -> None:
    OUTPUT.write_text(build(), encoding="utf-8")
    size_kb = OUTPUT.stat().st_size / 1024
    print(f"Wrote {OUTPUT.name} ({size_kb:.1f} KiB)")


if __name__ == "__main__":
    main()

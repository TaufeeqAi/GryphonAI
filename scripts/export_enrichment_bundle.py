"""Export the enrichment layer into a single bundled markdown file.

Bundles ONLY this layer's files: the ``gryphon/enrichment`` package (code and
the packaged policy), its sibling DB models and migration, its scripts, docs and
tests — plus the directory structure and the codebase guide. Additive edits to
shared files are listed rather than re-exported, so the bundle stays a scoped
view rather than a copy of the repository.

    python -m scripts.export_enrichment_bundle
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = REPO_ROOT / "GRYPHON_Enrichment_Layer_Bundle.md"
GUIDE = REPO_ROOT / "docs" / "ENRICHMENT_CODEBASE_GUIDE.md"

type _Tree = dict[str, _Tree]

_GLOBS = [
    "gryphon/enrichment/**/*.py",
    "gryphon/enrichment/*.json",
    "tests/enrichment/**/*.py",
]
_EXPLICIT = [
    "gryphon/db/models/enrichment.py",
    "gryphon/db/migrations/versions/0004_enrichment.py",
    "docs/ENRICHMENT.md",
    "docs/ENRICHMENT_CODEBASE_GUIDE.md",
    "docs/ENRICHMENT_RUNBOOK.md",
    "scripts/enrich.py",
    "scripts/enrichment_readiness.py",
    "scripts/verify_enrichment.py",
    "scripts/provision_reference_data.py",
    "scripts/export_enrichment_bundle.py",
]

_LANG = {
    ".py": "python",
    ".md": "markdown",
    ".json": "json",
    ".sql": "sql",
    ".toml": "toml",
    ".txt": "text",
    ".sh": "bash",
}

_SHARED_EDITS = """\
This layer makes small **additive** edits to shared files (not re-exported here):

* `gryphon/db/models/__init__.py` — registers the ten sibling tables on the
  shared metadata.
* `gryphon/db/models/raw_finding.py` — declares
  `UNIQUE (scan_run_id, finding_id)` (trivially true: `finding_id` is the key).
  The first migration builds every ORM table on a fresh database, so the
  composite foreign key that binds each derived row to its own scan's evidence
  needs the uniqueness in the model; this layer's migration adds it idempotently
  to databases migrated from the previous revision.
* `scripts/generate_keys.py` — also prints a dedicated enrichment keypair.
* `scripts/init_db_roles.sql` — creates the `gryphon_enrichment` login role on
  fresh development volumes (the migration creates it `NOLOGIN` elsewhere).
* `Makefile` — adds the `enrich-*` developer targets.
* `.env.example` — declares this layer's `GRYPHON_ENRICHMENT_*` settings.
* `.gitignore` — ignores `var/` (artifact store, reference data) and this bundle.
* `pyproject.toml` — scopes ruff's S608 off for `gryphon/enrichment/schema.py`
  (DDL composed only of code constants).
* `README.md` — a feature entry, quick-start step and test/readiness targets.

It adds **no new third-party dependency**: network code is stdlib and runs only
in the acquisition subprocess.
"""


def _collect() -> list[Path]:
    files: set[Path] = set()
    for glob in _GLOBS:
        files.update(
            p for p in REPO_ROOT.glob(glob) if p.is_file() and "__pycache__" not in p.parts
        )
    for rel in _EXPLICIT:
        path = REPO_ROOT / rel
        if path.is_file():
            files.add(path)
    return sorted(files, key=lambda p: p.relative_to(REPO_ROOT).as_posix())


def _tree(files: list[Path]) -> str:
    root: _Tree = {}
    for path in files:
        node = root
        for part in path.relative_to(REPO_ROOT).parts:
            node = node.setdefault(part, {})
    lines = ["GRYPHON/  (enrichment layer — scoped view)"]

    def walk(node: _Tree, prefix: str) -> None:
        entries = sorted(node.items(), key=lambda kv: (not bool(kv[1]), kv[0]))
        for i, (name, child) in enumerate(entries):
            last = i == len(entries) - 1
            lines.append(f"{prefix}{'└── ' if last else '├── '}{name}{'/' if child else ''}")
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


def _line_count(files: list[Path]) -> int:
    return sum(len(p.read_text(encoding="utf-8").splitlines()) for p in files)


def build() -> str:
    files = _collect()
    today = _dt.date.today().isoformat()
    code = [p for p in files if p.suffix == ".py" and "tests" not in p.parts]
    tests = [p for p in files if "tests" in p.parts]
    parts: list[str] = [
        f"""# GRYPHON — Enrichment Layer — Codebase Bundle

> **Contract:** v1.1.0  ·  **Generated:** {today}  ·  **Files bundled:** {len(files)}
> **Source lines:** {_line_count(code):,} (code) · {_line_count(tests):,} (tests)
> **Runtime:** CPython 3.12+  ·  **New dependencies:** none

This single file bundles the complete enrichment layer: directory structure,
codebase guide for senior staff engineers and principal architects, and every
source, test, policy and doc file inlined below.

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
    OUTPUT.write_text(build(), encoding="utf-8", newline="\n")
    print(f"Wrote {OUTPUT.name} ({OUTPUT.stat().st_size / 1024:.1f} KiB)")


if __name__ == "__main__":
    main()

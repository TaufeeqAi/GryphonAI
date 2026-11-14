"""Export the verification layer into a single bundled markdown file.

Bundles ONLY this layer's files: the ``gryphon/verification`` package (code and
the packaged registry), the shared fenced-pass kernel, the gateway boundary it
speaks across, its sibling DB models and migration, its scripts, docs and tests
— plus the directory structure and the codebase guide. Additive edits to shared
files are listed rather than re-exported, so the bundle stays a scoped view
rather than a copy of the repository.

    python -m scripts.export_verification_bundle
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = REPO_ROOT / "GRYPHON_Verification_Layer_Bundle.md"
GUIDE = REPO_ROOT / "docs" / "VERIFICATION_CODEBASE_GUIDE.md"

type _Tree = dict[str, _Tree]

_GLOBS = [
    "gryphon/verification/**/*.py",
    "gryphon/verification/*.json",
    "gryphon/passkernel/**/*.py",
    "gryphon/tooling/gateway/**/*.py",
    "gryphon/tooling/observation/**/*.py",
    "tests/verification/**/*.py",
]
_EXPLICIT = [
    "gryphon/db/models/verification.py",
    "gryphon/db/migrations/versions/0005_verification.py",
    "docs/VERIFICATION.md",
    "docs/VERIFICATION_CODEBASE_GUIDE.md",
    "docs/VERIFICATION_RUNBOOK.md",
    "scripts/verify_findings.py",
    "scripts/verification_readiness.py",
    "scripts/export_verification_bundle.py",
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
Two packages outside `gryphon/verification/` are bundled because they *are* this
layer's boundary rather than context for it:

* `gryphon/passkernel/` — the shared fenced-pass kernel (lease, epoch CAS,
  lifecycle, write-once pins). One copy of those rules serves every layer that
  runs a leased pass; a second implementation is the thing it exists to prevent.
* `gryphon/tooling/gateway/` and `gryphon/tooling/observation/` — the client
  half of the gateway socket, the wire protocol and feature handshake, the typed
  fact schema and the observer's extractors. The gateway *service* runs under its
  own uid, its own database role and its own signing key, so everything this
  layer can ask of it crosses this boundary and nothing else.

This layer makes small **additive** edits to shared files (not re-exported here):

* `gryphon/db/models/__init__.py` — registers this layer's sibling tables on the
  shared metadata.
* `scripts/generate_keys.py` — also prints a dedicated verification keypair.
* `scripts/init_db_roles.sql` — creates the `gryphon_verification` login role on
  fresh development volumes (the migration creates it `NOLOGIN` elsewhere).
* `Makefile` — adds the `verify-*` developer targets.
* `.env.example` — declares this layer's `GRYPHON_VERIFICATION_*` settings.
* `.gitignore` — ignores this bundle.
* `pyproject.toml` — scopes ruff's S608 off for the DDL-facts module (statements
  composed only of code constants).
* `README.md` — a feature entry, quick-start step and test/readiness targets.

It adds **no new third-party dependency**. This layer holds no HTTP client, no
resolver and no socket to any target: its only sockets are the database and the
gateway, and the gateway client is stdlib asyncio.
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
    lines = ["GRYPHON/  (verification layer — scoped view)"]

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
        f"""# GRYPHON — Verification Layer — Codebase Bundle

> **Contract:** v1.1.0  ·  **Generated:** {today}  ·  **Files bundled:** {len(files)}
> **Source lines:** {_line_count(code):,} (code) · {_line_count(tests):,} (tests)
> **Runtime:** CPython 3.12+  ·  **New dependencies:** none

This single file bundles the complete verification layer: directory structure,
codebase guide for senior staff engineers and principal architects, and every
source, test, registry and doc file inlined below.

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

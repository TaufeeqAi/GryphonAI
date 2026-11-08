# ==============================================================================
# GRYPHON Phase 1 — developer tasks
# ==============================================================================
# POSIX make. On Windows, run the underlying commands directly or use Git Bash.
PY ?= python

.PHONY: help venv install lint test test-db up down migrate keys bundle clean tooling-test tooling-test-db tooling-ready tooling-verify tooling-bundle tooling-verify-binaries

help:
	@echo "targets: install | test | test-db | up | down | migrate | keys | bundle | clean"
	@echo "tool execution layer: tooling-test | tooling-test-db | tooling-ready | tooling-verify | tooling-verify-binaries | tooling-bundle"

install:
	$(PY) -m pip install -r requirements.txt -r requirements-dev.txt
	$(PY) -m pip install -e .

# Pure suite (no database required).
test:
	$(PY) -m pytest tests/unit tests/contract tests/security tests/property tests/graph

# Full suite incl. PostgreSQL integration (requires GRYPHON_TEST_DATABASE_URL).
test-db:
	$(PY) -m pytest

up:
	docker compose up -d

down:
	docker compose down

# Apply the schema (runs as the migration/owner role via GRYPHON_MIGRATION_DATABASE_URL).
migrate:
	alembic upgrade head

# Generate a distinct grant + audit Ed25519 key set.
keys:
	$(PY) -m scripts.generate_keys

# Export the entire Phase 1 codebase into a single bundled markdown file.
bundle:
	$(PY) -m scripts.export_bundle

clean:
	rm -rf .pytest_cache .hypothesis .ruff_cache .mypy_cache **/__pycache__

# ------------------------------------------------------------------------------
# Tool execution layer
# ------------------------------------------------------------------------------
# Tests that need no database (capability crypto, destination, descriptors,
# sanitization, budgets, egress config, real subprocess runner).
tooling-test:
	$(PY) -m pytest tests/tooling/unit tests/tooling/security tests/tooling/integration/test_runner_subprocess.py

# Full suite incl. the execution saga. WARNING: resets GRYPHON_TEST_DATABASE_URL.
tooling-test-db:
	$(PY) -m pytest

# Readiness probe: key material, egress posture, descriptors, schema, triggers.
tooling-ready:
	$(PY) -m scripts.tooling_readiness

# Deployment self-verification: the real pipeline, dry-run runner and resolver,
# no tool process and no target traffic.
tooling-verify:
	$(PY) -m scripts.verify_tooling

# Single-file markdown export of this layer only.
tooling-bundle:
	$(PY) -m scripts.export_tooling_bundle

# Conformance of the pinned binaries: checksums, flag acceptance, parser match.
# Loopback listeners only; no scan target is contacted. Needs the manifest.
tooling-verify-binaries:
	$(PY) -m scripts.verify_tool_binaries

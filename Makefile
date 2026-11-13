# ==============================================================================
# GRYPHON Phase 1 — developer tasks
# ==============================================================================
# POSIX make. On Windows, run the underlying commands directly or use Git Bash.
PY ?= python

.PHONY: help venv install lint test test-db up down migrate keys bundle clean tooling-test tooling-test-db tooling-ready tooling-verify tooling-bundle tooling-verify-binaries scan-test scan-test-db scan-ready scan-ready-json scan-verify scan-bundle enrich-test enrich-test-db enrich-ready enrich-ready-json enrich-verify enrich-reference enrich-bundle

help:
	@echo "targets: install | test | test-db | up | down | migrate | keys | bundle | clean"
	@echo "tool execution layer: tooling-test | tooling-test-db | tooling-ready | tooling-verify | tooling-verify-binaries | tooling-bundle"
	@echo "scan orchestration:   scan-test | scan-test-db | scan-ready | scan-verify | scan-bundle"
	@echo "enrichment:           enrich-test | enrich-test-db | enrich-ready | enrich-verify | enrich-reference | enrich-bundle"

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

# ------------------------------------------------------------------------------
# Scan orchestration layer
# ------------------------------------------------------------------------------
# Pure tests: identity, coverage, planning, state closure, attestation, report.
# The load-bearing logic is pure, so these need no database.
scan-test:
	$(PY) -m pytest tests/orchestration/unit tests/orchestration/security

# Full suite incl. the fenced lease and an end-to-end scan.
# Needs GRYPHON_TEST_DATABASE_URL. WARNING: resets that database's schema.
scan-test-db:
	$(PY) -m pytest tests/orchestration

# Readiness: would this deployment enforce what it claims? exit 0/1.
scan-ready:
	$(PY) -m scripts.orchestration_readiness

scan-ready-json:
	$(PY) -m scripts.orchestration_readiness --json

# Self-verification: the real pipeline with a dry-run runner and pinned
# resolver. No tool process is started and no target is contacted.
scan-verify:
	$(PY) -m scripts.verify_orchestration

# Single-file markdown export of this layer only.
scan-bundle:
	$(PY) -m scripts.export_orchestration_bundle

# ------------------------------------------------------------------------------
# Enrichment layer
# ------------------------------------------------------------------------------
# Pure tests: acceptance, extraction, policy, derivation, verification, isolation.
enrich-test:
	$(PY) -m pytest tests/enrichment/unit tests/enrichment/security

# Incl. migration, privileges, fenced passes and the read view against PostgreSQL.
# Needs GRYPHON_TEST_DATABASE_URL. WARNING: resets that database's schema.
enrich-test-db:
	$(PY) -m pytest tests/enrichment

# Readiness by facts (tables, enabled triggers, function bodies, role privileges,
# reference data, signing key, egress posture). exit 0/1.
enrich-ready:
	$(PY) -m scripts.enrichment_readiness

enrich-ready-json:
	$(PY) -m scripts.enrichment_readiness --json

# Offline self-verification: import isolation, acceptance, policy, derivation,
# attestation. No network, no database writes.
enrich-verify:
	$(PY) -m scripts.verify_enrichment

# Download (pinned URL, verified digest and size) and index the ATT&CK reference data.
enrich-reference:
	$(PY) -m scripts.provision_reference_data --download

# Single-file markdown export of this layer only.
enrich-bundle:
	$(PY) -m scripts.export_enrichment_bundle

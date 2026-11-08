# ==============================================================================
# GRYPHON Phase 1 — developer tasks
# ==============================================================================
# POSIX make. On Windows, run the underlying commands directly or use Git Bash.
PY ?= python

.PHONY: help venv install lint test test-db up down migrate keys bundle clean

help:
	@echo "targets: install | test | test-db | up | down | migrate | keys | bundle | clean"

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

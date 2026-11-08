# GRYPHON — The guardian that never sleeps

> *The guardian that never sleeps.* Phase 1 is the **authorization root of trust**
> and core database foundation for GRYPHON's continuous autonomous pentesting platform. 

---

## ⚠️ Legal

GRYPHON must ONLY be used against infrastructure you own or have explicit written
authorization to test. It is the architecturally-unbypassable gate that
enforces this: no protected scanning operation may execute unless a valid,
signed, in-scope, unexpired grant covers the canonical target **and** the ALLOW
decision plus its signed audit record have durably committed. It 
authenticates *grants*, not *presenters* — do not expose it as a multi-user
remote service.

---

## What it does

1. **Ed25519-signed, scope-bound, time-limited grants** issued through a local
   operator path (compact JWS, EdDSA pinned, 90-day maximum lifetime).
2. **Deterministic Scope Policy v1** — exact domains (IDNA 2008), explicit
   `*.`-wildcards (one label, never apex), IPs, strict CIDR (no host-bit
   widening), and path exclusions that override every positive match.
3. **One admission identity** — `scan_runs` records every ALLOW/DENY attempt.
4. **Independently-signed, append-only audit** — a *separate* Ed25519 key; the
   runtime DB role cannot UPDATE/DELETE/TRUNCATE audit or grant rows.
5. **Atomic admission** — the `scan_runs` row and its signed audit event commit
   in one transaction, or neither does. UNKNOWN is never success.
6. **A real compiled LangGraph gate** proving DENY→END (sentinel never runs) and
   ALLOW→sentinel-once.

What deliberately does **not** do: run scanners, build the full
RECON→REPORT graph, implement revocation / presenter-auth / multi-tenancy, or
treat Redis as authorization truth. Those are later (contract §34).

---

## Quick start

```bash
# 1. Bring up PostgreSQL 16 + Redis 7 (Redis is provisioned-only, never auth truth)
docker compose up -d

# 2. Create a Python 3.12+ environment and install
python -m venv .venv && . .venv/Scripts/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt && pip install -e .

# 3. Generate a DISTINCT grant + audit key set and paste into .env
cp .env.example .env
python -m scripts.generate_keys        # copy output into .env

# 4. Apply the schema as the migration/owner role
alembic upgrade head

# 5. Issue a grant (local operator; you assert out-of-band written authority)
python -m scripts.issue_grant \
  --organization "Acme" --granted-by you@acme.example --granted-to team@acme.example \
  --domain staging.acme.example --exclude-path /admin \
  --days 30 --max-depth standard --written-auth-ref SOW-2026-0042
```

## Tests

```bash
# Pure suite — no database needed (87 tests)
pytest tests/unit tests/contract tests/security tests/property tests/graph

# Full suite incl. PostgreSQL integration (migration, atomic commit, privileges)
export GRYPHON_TEST_DATABASE_URL=postgresql+asyncpg://gryphon_owner:owner_pw@localhost:5432/gryphon
pytest
```

## Dependencies

Exact pins, confirmed live from PyPI on **2026-11-08** (see `requirements.txt`).
Target runtime **CPython 3.12+**. Key libraries: `cryptography 50.0.2`,
`PyJWT 2.15.1`, `pydantic 2.14.3`, `pydantic-settings 2.16.2`,
`SQLAlchemy 2.1.8`, `alembic 1.20.1`, `asyncpg 0.32.0`, `rfc8785 0.1.4`
(RFC 8785 JCS), `idna 3.20` (IDNA 2008/UTS-46), `structlog 26.1.0`,
`langgraph 1.2.20`.



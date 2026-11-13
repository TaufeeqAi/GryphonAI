# GRYPHON — The guardian that never sleeps

> *The guardian that never sleeps.* is the **authorization root of trust**
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

7. **Capability-gated tool execution** — seven ProjectDiscovery wrappers behind
   one enforcement gateway: grant-rooted credentials, OS-enforced per-execution
   egress containment, a durable intent record before any target traffic, and
   `execution_id` idempotency. See
   [docs/TOOL_EXECUTION_LAYER.md](docs/TOOL_EXECUTION_LAYER.md).
8. **Scan orchestration** — composes those enforced calls into one authorized
   scan: a gate re-traversed on every entry, a durable work ledger as the only
   source of truth, a fenced lease so a crash cannot wedge a scan, stored
   execution identities so replay never re-scans, and a **coverage** fold so
   "completed" means the planned work was accounted for rather than "the graph
   finished". See [docs/SCAN_ORCHESTRATION.md](docs/SCAN_ORCHESTRATION.md).
9. **Finding intelligence enrichment** — turns a finished scan's *verified*
   evidence into an explainable priority using public intelligence acquired
   **whole** (CISA KEV catalog, FIRST EPSS daily file) and pinned, offline
   MITRE ATT&CK data. The base report is re-digested and its signature checked
   before use; acquisition runs in a key-less, egress-contained subprocess and
   no outbound request depends on what was scanned; a failed download only
   makes knowledge older; every assertion is attributed and every priority is
   a pure, versioned, monotone policy decision with named reasons. The
   deliverable is a separate, signed enrichment report. See
   [docs/ENRICHMENT.md](docs/ENRICHMENT.md).

What it deliberately does **not** do: verify findings, schedule re-scans,
expose a network API, or support multi-tenancy. Those are later, and
the seams for them are data-model seams rather than placeholder code.

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
TOKEN=$(python -m scripts.issue_grant \
  --organization "Acme" --granted-by you@acme.example --granted-to team@acme.example \
  --domain staging.acme.example --exclude-path /admin \
  --days 30 --max-depth standard --written-auth-ref SOW-2026-0042)

# 6. Admit ONE scan within that grant's scope; prints a scan_run_id
SCAN=$(python -m scripts.admit_scan --target staging.acme.example --token "$TOKEN")

# 7. Run it (start is also resume)
python -m scripts.run_scan start "$SCAN"
python -m scripts.run_scan report "$SCAN" --out report.json

# 8. Enrich the finished scan (one-time: provision ATT&CK reference data)
python -m scripts.provision_reference_data --download
python -m scripts.enrich refresh                     # acquire KEV + EPSS whole
python -m scripts.enrich start "$SCAN"               # verified, pinned, attested
python -m scripts.enrich report "$SCAN" --out enrichment.json
```

Each script prints its one machine-readable value on stdout and its
diagnostics on stderr, so the captures above hold the token and the id and
nothing else.

## Tests

```bash
# Pure suites — no database needed
make test            # authorization core
make tooling-test    # tool execution layer
make scan-test       # scan orchestration
make enrich-test     # enrichment

# Full suite incl. PostgreSQL integration (migration, atomic commit, privileges)
export GRYPHON_TEST_DATABASE_URL=postgresql+asyncpg://gryphon_owner:owner_pw@localhost:5432/gryphon
pytest               # 555 passed, 14 skipped (skips are Linux-only) on 2026-11-13
```

Readiness and self-verification probes, per layer:

```bash
make tooling-ready && make tooling-verify   # tool execution
make scan-ready    && make scan-verify      # scan orchestration
make enrich-ready  && make enrich-verify    # enrichment
```

> Run one suite at a time against a given database: each resets the schema.





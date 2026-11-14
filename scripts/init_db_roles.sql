-- ============================================================================
-- GRYPHON Phase 1 — database role bootstrap (§22.3)
-- ============================================================================
-- Runs once at first PostgreSQL boot (mounted into docker-entrypoint-initdb.d).
-- Creates the least-privilege RUNTIME login role. Table-level privileges are
-- granted by the Alembic migration AFTER the tables exist.
--
-- The schema owner / migration role is the container's POSTGRES_USER
-- (gryphon_owner) — a DISTINCT identity from the runtime role (§22.3).
--
-- NOTE: the password here is a development default matching docker-compose.yml
-- and .env.example. In production, provision this role via your secret manager
-- and do NOT use a static password in source control.
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gryphon_runtime') THEN
        CREATE ROLE gryphon_runtime LOGIN PASSWORD 'runtime_pw';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE gryphon TO gryphon_runtime;

-- Runtime must not own or create schema objects (§22.3). (PostgreSQL 15+ already
-- removes the implicit CREATE grant on the public schema for non-owners; this is
-- belt-and-braces.)
REVOKE CREATE ON SCHEMA public FROM gryphon_runtime;
REVOKE ALL ON DATABASE gryphon FROM PUBLIC;
GRANT CONNECT ON DATABASE gryphon TO gryphon_runtime;

-- ----------------------------------------------------------------------------
-- Enrichment layer: a DEDICATED login role. It can read the evidence and the
-- attested report, and write only enrichment tables (privileges are granted by
-- the enrichment migration, which also creates this role NOLOGIN on databases
-- initialized before it existed). Development password only — in production,
-- provision it from your secret manager.
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gryphon_enrichment') THEN
        CREATE ROLE gryphon_enrichment LOGIN PASSWORD 'enrichment_pw';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE gryphon TO gryphon_enrichment;
REVOKE CREATE ON SCHEMA public FROM gryphon_enrichment;

-- ----------------------------------------------------------------------------
-- Verification layer: a DEDICATED login role, and the separation matters more
-- here than anywhere else. The verification layer judges evidence the runtime
-- role wrote; were it to connect AS that role it would hold write access to the
-- very rows it is deciding about, and a verdict is only worth something if the
-- process reaching it could not have authored its inputs. Its privileges are
-- granted by the verification migration (read on evidence and attested reports,
-- write only on verification tables), which also creates this role NOLOGIN on
-- databases initialized before it existed. Development password only — in
-- production, provision it from your secret manager.
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gryphon_verification') THEN
        CREATE ROLE gryphon_verification LOGIN PASSWORD 'verification_pw';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE gryphon TO gryphon_verification;
REVOKE CREATE ON SCHEMA public FROM gryphon_verification;

-- Pin the search path. PostgreSQL's default is "$user", public — and a
-- per-user schema is a place where a table or function can be shadowed without
-- one line of this layer's SQL changing. A verifier reading a shadowed table
-- would reach real conclusions about fake evidence, so readiness refuses a
-- search_path naming anything but public and pg_catalog.
ALTER ROLE gryphon_verification SET search_path = public, pg_catalog;

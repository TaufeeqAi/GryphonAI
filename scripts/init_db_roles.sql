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

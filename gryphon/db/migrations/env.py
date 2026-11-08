"""Alembic environment (async) for GRYPHON Phase 1.

The migration DSN is resolved from ``GRYPHON_MIGRATION_DATABASE_URL`` (the
owner/deploy role) so credentials never live in ``alembic.ini`` (§22.3). The
ORM ``Base.metadata`` is the single source of truth for table shape; this env
layers the append-only triggers and least-privilege grants on top.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

from gryphon.db import models  # noqa: F401  (registers tables on Base.metadata)
from gryphon.db.base import Base
from gryphon.settings import get_settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _resolve_url() -> str:
    settings = get_settings()
    return settings.migration_database_url or settings.database_url


def run_migrations_offline() -> None:
    context.configure(
        url=_resolve_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection) -> None:  # type: ignore[no-untyped-def]
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = create_async_engine(_resolve_url(), poolclass=pool.NullPool)
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())

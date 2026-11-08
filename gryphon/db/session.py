"""Async engine, session factory and unit-of-work (BND-07, §18).

One :class:`~sqlalchemy.ext.asyncio.AsyncSession` per concurrent task/request
(INV-016). Sessions are never shared across tasks. Connection, statement and
request deadlines are finite, bounded deployment configuration (§16).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from gryphon.settings import Settings


def create_engine(settings: Settings, *, use_migration_role: bool = False) -> AsyncEngine:
    """Create an async engine with bounded timeouts.

    ``use_migration_role`` selects the owner/deploy DSN (Alembic only); the
    application always runs under the restricted runtime DSN (§22.3).
    """
    url = settings.database_url
    if use_migration_role:
        if not settings.migration_database_url:
            raise ValueError("migration_database_url is not configured")
        url = settings.migration_database_url

    statement_timeout_ms = int(settings.db_statement_timeout_seconds * 1000)
    return create_async_engine(
        url,
        pool_pre_ping=True,
        connect_args={
            "timeout": settings.db_connect_timeout_seconds,
            "command_timeout": settings.db_statement_timeout_seconds,
            # Server-side statement timeout: defence-in-depth against runaway SQL.
            "server_settings": {"statement_timeout": str(statement_timeout_ms)},
        },
    )


class Database:
    """Owns the engine and session factory for one deployment."""

    def __init__(self, settings: Settings, *, use_migration_role: bool = False) -> None:
        self._settings = settings
        self._engine = create_engine(settings, use_migration_role=use_migration_role)
        self._sessionmaker = async_sessionmaker(
            self._engine, expire_on_commit=False, autoflush=False
        )

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    @property
    def sessionmaker(self) -> async_sessionmaker[AsyncSession]:
        return self._sessionmaker

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Yield a fresh session (one per task). The caller owns the transaction."""
        async with self._sessionmaker() as session:
            yield session

    async def dispose(self) -> None:
        await self._engine.dispose()

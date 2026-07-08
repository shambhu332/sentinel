"""Alembic environment for SENTINEL.

The URL is resolved at runtime from `SENTINEL_POSTGRES_URL` /
`POSTGRES_URL` env vars so CI, local dev, and production all use the
same config file. Autogenerate is not wired to any metadata object —
this project uses hand-written migrations for tables (RLS, partitions,
BRIN, PG RULEs cannot be autogen-derived reliably).
"""
from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _resolve_url() -> str:
    return (
        os.getenv("SENTINEL_POSTGRES_URL")
        or os.getenv("POSTGRES_URL")
        or config.get_main_option("sqlalchemy.url")
        or "postgresql://sentinel_service:sentineldev@localhost:5432/sentinel"
    )


def run_migrations_offline() -> None:
    context.configure(
        url=_resolve_url(),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(_resolve_url(), poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

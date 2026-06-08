"""Fallback boot-audit writer for the daemon boot path (#174 PR-S4-1).

sec-001 closure: the daemon's ``load_settings_or_die()`` constructs an
:class:`AuditWriter` BEFORE the environment-missing check, so the most
common misconfiguration path (no ``ALFRED_ENVIRONMENT``) still emits a
``DAEMON_BOOT_FAILED_FIELDS`` row instead of silently exiting. Because
``Settings`` cannot construct without a resolved ``environment``, the
fallback writer is built directly from ``ALFRED_DATABASE_URL`` (or the
shipped default DSN) rather than from a fully-validated ``Settings``.

If Postgres is unreachable the writer's ``append_schema`` raises — the
caller catches that and exits 3 (``audit_log_unwritable``) per sec-003,
so the failure is loud, not silent (CLAUDE.md hard rule 7).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Final

from sqlalchemy.ext.asyncio import AsyncSession

from alfred.audit.log import AuditWriter
from alfred.memory.db import _engine_for_url, session_scope

# The shipped default DSN, mirrored from ``Settings.database_url``'s default
# so the fallback writer can reach the same Postgres a normally-configured
# install uses when ``ALFRED_DATABASE_URL`` is unset.
_DEFAULT_DATABASE_URL: Final[str] = "postgresql+asyncpg://alfred:alfred@localhost:5432/alfred"

type SessionScope = Callable[[], AbstractAsyncContextManager[AsyncSession]]


def fallback_database_url() -> str:
    """Return ``ALFRED_DATABASE_URL`` or the shipped default DSN."""
    return os.environ.get("ALFRED_DATABASE_URL", _DEFAULT_DATABASE_URL)


def build_fallback_session_scope() -> SessionScope:
    """Build a session-scope factory independent of a validated ``Settings``.

    Reads ``ALFRED_DATABASE_URL`` directly (the env-missing refusal path
    has no ``Settings`` instance) and binds an async session scope to the
    cached engine for that DSN.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker

    engine = _engine_for_url(fallback_database_url())
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)

    def _scope() -> AbstractAsyncContextManager[AsyncSession]:
        return session_scope(factory)

    return _scope


def build_boot_audit_writer(*, session_scope_factory: SessionScope | None = None) -> AuditWriter:
    """Construct the boot-time :class:`AuditWriter`.

    Args:
        session_scope_factory: An explicit session-scope factory. When
            ``None`` the fallback DSN-derived scope is used (sec-001 — the
            env-missing path has no validated ``Settings``).
    """
    scope = (
        session_scope_factory
        if session_scope_factory is not None
        else build_fallback_session_scope()
    )
    return AuditWriter(session_factory=scope)

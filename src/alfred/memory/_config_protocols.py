"""Narrow read-only config Protocols for the memory subsystem (#351).

Design: docs/superpowers/specs/2026-07-02-config-protocol-dip-design.md. Consumers
depend on exactly the config fields they read; the real ``Settings`` satisfies these
structurally (PEP 544), so a test double is a trivial stub rather than a full
``Settings``. See docs/python-conventions.md "Config consumers depend on narrow
read-only Protocols".
"""

from __future__ import annotations

from typing import Protocol

from pydantic import PostgresDsn


class MemoryDbConfig(Protocol):
    """The config surface the memory engine / session factory reads: just the DSN.

    Producer invariant: ``Settings.database_url`` is a validated ``PostgresDsn`` with a
    default and **no** normalizer, so a stub may supply any ``PostgresDsn`` directly
    without reproducing a validator.
    """

    @property
    def database_url(self) -> PostgresDsn: ...

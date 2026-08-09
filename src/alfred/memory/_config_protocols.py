"""Narrow read-only config Protocols for the memory subsystem (#351).

Design: docs/superpowers/specs/2026-07-02-config-protocol-dip-design.md. Consumers
depend on exactly the config fields they read; the real ``Settings`` satisfies these
structurally (PEP 544), so a test double is a trivial stub rather than a full
``Settings``. See docs/python-conventions.md "Config consumers depend on narrow
read-only Protocols".
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import PostgresDsn


class MemoryDbConfig(Protocol):
    """The config surface the memory engine / session factory reads: just the DSN.

    Producer invariant: ``Settings.database_url`` is a validated ``PostgresDsn`` with a
    default and **no** normalizer, so a stub may supply any ``PostgresDsn`` directly
    without reproducing a validator.
    """

    @property
    def database_url(self) -> PostgresDsn: ...


@runtime_checkable
class MemoryDbTuningConfig(Protocol):
    """Optional pool-tuning surface a db config MAY carry (#410 PR1 / ADR-0062).

    The real ``Settings`` satisfies this structurally (Task 2 adds the four
    fields); narrow test stubs that only carry ``database_url`` simply don't
    match, and ``make_engine`` falls back to ``DbPoolTuning()`` defaults —
    which are the same values as the Settings field defaults, so the two
    sources can never disagree silently.
    """

    @property
    def db_turn_pool_max_connections(self) -> int: ...

    @property
    def db_side_pool_max_connections(self) -> int: ...

    @property
    def db_pool_checkout_timeout_seconds(self) -> float: ...

    @property
    def db_idle_in_transaction_timeout_seconds(self) -> float: ...

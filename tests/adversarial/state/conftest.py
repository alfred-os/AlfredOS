"""Per-subdir conftest for ``tests/adversarial/state/`` — provides Postgres.

The dispatch adversarial suite needs a real Postgres testcontainer to
exercise the at-most-once ledger contract through the production engine.
The shared ``tests/integration/conftest.py`` already declares the
``postgres_url`` fixture; this conftest re-exports it via a thin
``@pytest.fixture`` that proxies to a fresh container per test (matching
the integration-tier discipline — per-test isolation prevents row
bleeding between adversarial cases).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from testcontainers.postgres import PostgresContainer


@pytest.fixture
def postgres_url() -> Iterator[str]:
    """Yield a fresh Postgres container's asyncpg-driver URL for one test.

    Same shape as ``tests/integration/conftest.py::postgres_url`` —
    rewrites the testcontainers default psycopg2 driver token to asyncpg
    so the dispatcher's ``create_async_engine`` accepts the URL
    verbatim.
    """
    with PostgresContainer("postgres:18") as pg:
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        yield url

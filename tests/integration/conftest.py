"""Integration-test fixtures shared across ``tests/integration/``.

Spins up a single Postgres testcontainer per test function (cheap enough at
~5s startup; isolates each migration scenario from siblings) and yields the
URL + a sync ``Engine``.

Sync because Alembic's command-line helpers (``alembic.command.upgrade`` etc.)
operate on a sync connection. The production ``env.py`` runs async via
``async_engine_from_config`` + ``run_sync``, which means ``command.upgrade``
*itself* uses asyncpg under the hood — but the tests want plain
``with engine.begin() as conn: conn.execute(text(...))`` to assert
post-migration state, which is sync-shaped and natural with a sync engine.
``psycopg2-binary`` is dev-only; the runtime never sees it.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine
from testcontainers.postgres import PostgresContainer


@pytest.fixture
def postgres_url() -> Iterator[str]:
    """Yield a fresh Postgres container's connection URL for one test.

    testcontainers' default URL is ``postgresql+psycopg2://…``. We rewrite
    to ``postgresql+asyncpg://…`` because that's what the migration
    ``env.py`` expects to consume from ``ALFRED_DATABASE_URL`` (it builds an
    async engine). Tests that need a sync handle use ``postgres_engine``
    below, which builds its own psycopg2-backed engine from the raw URL.
    """
    with PostgresContainer("postgres:18") as pg:
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        yield url


# The unreachable-by-construction placeholder proxy every boot-graph integration
# fixture points the egress plane at. RFC 6761 reserves `.invalid` as guaranteed
# non-resolvable, so if a test ever DID dial it the failure is loud and immediate
# rather than a silent escape to a real network. Mirrors the value the unit daemon
# harness (`tests/unit/cli/daemon/conftest.py`) and the smoke tests already use.
_PLACEHOLDER_EGRESS_PROXY_URL = "http://proxy.invalid:3128"


@pytest.fixture
def egress_proxy_url_env(monkeypatch: pytest.MonkeyPatch) -> str:
    """Point the boot graph's egress plane at an unreachable placeholder proxy.

    **Why every comms-enabled boot-graph test needs this (#340 PR2b-golive).**
    ``_build_comms_boot_graph`` now resolves the quarantine child's egress config
    SYNCHRONOUSLY pre-spawn (``daemon_runtime._resolve_egress_config``), which raises
    :class:`alfred.egress.errors.IOPlaneUnavailableError` fail-closed on an unset or
    blank ``ALFRED_EGRESS_PROXY_URL``. That demand is CORRECT — the golive child
    genuinely brokers its provider socket through the gateway L7 CONNECT proxy — so the
    harness supplies the config rather than the code relaxing the check.

    It supersedes the previous per-file assumption that a ``router_override`` made the
    variable unnecessary: the override bypasses ``build_router``, but the quarantine
    egress resolve happens regardless, so overriding the router no longer avoids it.

    **An unreachable URL is the right value, not a shortcut.** These tests double the
    quarantine child (no real spawn) and override the provider router, so nothing dials
    the proxy — boot only has to CONSTRUCT the config. Because the host is
    non-resolvable, a regression that started making real provider calls would fail
    loudly here instead of silently reaching the network.

    EXPLICIT, never autouse: a test that wants to drive the unset/blank refuse path
    simply does not request this fixture (and so cannot have the value slipped under it),
    which keeps the fail-closed boot refusal genuinely reachable from the test suite.
    """
    monkeypatch.setenv("ALFRED_EGRESS_PROXY_URL", _PLACEHOLDER_EGRESS_PROXY_URL)
    return _PLACEHOLDER_EGRESS_PROXY_URL


@pytest.fixture
def postgres_engine(postgres_url: str) -> Iterator[Engine]:
    """Yield a sync SQLAlchemy Engine bound to the per-test Postgres container.

    Rewrites the asyncpg URL back to psycopg2 for the sync engine — the
    migration env consumes ``postgres_url`` (asyncpg), the tests use this
    sync engine for inspecting / inserting rows around the migration calls.
    """
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = create_engine(sync_url, future=True)
    try:
        yield engine
    finally:
        engine.dispose()

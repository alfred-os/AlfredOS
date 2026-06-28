"""Per-subdir conftest for ``tests/adversarial/dlp_egress/`` — provides Postgres.

The #173 corpus entries (``de-2026-005`` / ``de-2026-006``) drive the real
``_record_failure`` DLP boundary against a Postgres testcontainer so the
ledger insert + the in-session redacted audit twin (and the refusal /
scan-failed abort paths) are exercised against the production engine.

Mirrors ``tests/adversarial/state/conftest.py`` — a thin per-test
``postgres_url`` fixture (per-test isolation prevents row bleeding between
adversarial cases). The Redis-backed entries in this directory
(``de-2026-004``) bring their own container fixtures and are unaffected.

The C5 corpus entries (``de-2026-007`` through ``de-2026-010``) also need
the ``fake_external_world`` fixture from the G7-2c-2 integration suite.
pytest fixtures are scoped to conftest directory subtrees, so we provide
the fixture here rather than importing from ``tests/integration/egress/conftest.py``
(a sibling tree).  The implementation delegates to the shared
``tests.helpers.egress_doubles.make_fake_external_world`` factory, keeping
the adversarial and integration suites in sync without duplication.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from testcontainers.postgres import PostgresContainer

from tests.helpers.egress_doubles import (
    _CannedResponse,
    _FakeClient,
    make_fake_external_world,
)


@pytest.fixture
def postgres_url() -> Any:
    """Yield a fresh Postgres container's asyncpg-driver URL for one test.

    Same shape as ``tests/integration/conftest.py::postgres_url`` — rewrites
    the testcontainers default psycopg2 driver token to asyncpg so
    ``create_async_engine`` accepts the URL verbatim.
    """
    with PostgresContainer("postgres:16") as pg:
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        yield url


@pytest.fixture
def fake_external_world() -> tuple[
    Callable[[], _FakeClient],
    Any,
    _CannedResponse,
]:
    """Yield ``(open_client_factory, fire_counter, canned_response)``.

    Delegates to ``tests.helpers.egress_doubles.make_fake_external_world``.
    Inject ``open_client_factory`` as the relay's ``open_client`` seam.
    """
    return make_fake_external_world()

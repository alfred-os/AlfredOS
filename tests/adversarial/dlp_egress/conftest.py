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
pytest fixtures are scoped to conftest directory subtrees, so we duplicate
the fixture here rather than importing from ``tests/integration/egress/conftest.py``
(a sibling tree).  The implementation is identical — the same three-tuple
``(open_client_factory, _FireCounter, _CannedResponse)`` so tests are
structurally identical to the integration counterparts.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from testcontainers.postgres import PostgresContainer


@pytest.fixture
def postgres_url() -> Iterator[str]:
    """Yield a fresh Postgres container's asyncpg-driver URL for one test.

    Same shape as ``tests/integration/conftest.py::postgres_url`` — rewrites
    the testcontainers default psycopg2 driver token to asyncpg so
    ``create_async_engine`` accepts the URL verbatim.
    """
    with PostgresContainer("postgres:16") as pg:
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        yield url


# ---------------------------------------------------------------------------
# fake_external_world — mirrors tests/integration/egress/conftest.py
#
# The G7-2c-2 integration conftest owns the canonical definition; we duplicate
# it here because pytest conftest fixtures are directory-scoped and the
# adversarial suite lives in a sibling tree.  Keep in sync with the
# integration counterpart when either is modified.
# ---------------------------------------------------------------------------


class _FireCounter:
    """Shareable mutable fire counter."""

    def __init__(self) -> None:
        self.value: int = 0


@dataclass
class _CannedResponse:
    """Holder for the upstream response the fake client will return."""

    status_code: int = 200
    headers: dict[str, str] = field(default_factory=lambda: {"content-type": "text/plain"})
    body: bytes = b"fake-upstream-body"


class _FakeResponse:
    def __init__(self, canned: _CannedResponse) -> None:
        self.status_code = canned.status_code
        self.headers = canned.headers
        self._body = canned.body
        self.is_redirect = False

    async def aiter_bytes(self) -> Any:
        yield self._body

    async def aclose(self) -> None:
        return None


class _FakeClient:
    def __init__(self, fire_counter: _FireCounter, canned: _CannedResponse) -> None:
        self._fire_counter = fire_counter
        self._canned = canned

    def build_request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        content: Any,
    ) -> httpx.Request:
        return httpx.Request(method, url, headers=headers, content=content)  # type: ignore[arg-type]

    async def send(
        self,
        request: httpx.Request,
        *,
        follow_redirects: bool,
        stream: bool = False,
    ) -> _FakeResponse:
        self._fire_counter.value += 1
        return _FakeResponse(self._canned)

    async def aclose(self) -> None:
        return None


@pytest.fixture
def fake_external_world() -> tuple[
    Callable[[], _FakeClient],
    _FireCounter,
    _CannedResponse,
]:
    """Yield ``(open_client_factory, fire_counter, canned_response)``.

    Mirrors ``tests/integration/egress/conftest.py::fake_external_world``.
    Inject ``open_client_factory`` as the relay's ``open_client`` seam.
    """
    fire_counter = _FireCounter()
    canned = _CannedResponse()

    def _factory() -> _FakeClient:
        return _FakeClient(fire_counter, canned)

    return _factory, fire_counter, canned

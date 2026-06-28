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
the ``fake_external_world`` and ``authorized_t3_nonce`` fixtures from the
G7-2c-2 integration suite.  pytest fixtures are scoped to conftest directory
subtrees, so we provide them here rather than importing from
``tests/integration/egress/conftest.py`` (a sibling tree).  The
implementations delegate to the shared helpers in
``tests.helpers.egress_doubles``, keeping the adversarial and integration
suites in sync without duplication.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest
from testcontainers.postgres import PostgresContainer

from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.security import tiers as _tiers
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.egress_doubles import (
    _CannedResponse,
    _FakeClient,
    _FireCounter,
    make_fake_external_world,
)


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


@pytest.fixture
def authorized_t3_nonce() -> Iterator[CapabilityGateNonce]:
    """Install a fresh ``CapabilityGateNonce`` as the authorised slot.

    Yields the nonce object so adversarial tests can pass it as
    ``caller_token`` when exercising the legitimate-path branch. Saves
    and restores the previous slot value on teardown.

    Both the install and the restore happen under ``_NONCE_LOCK`` (the
    same module-level lock that guards ``create_and_register_t3_nonce``)
    so concurrent test workers cannot race the slot mutation — spec §3.2
    "one live nonce per process" stays sound under same-process
    parallelism (pytest-xdist with ``--dist loadgroup``, etc.).

    Mirrors the canonical fixture in
    ``tests/adversarial/tier_laundering/conftest.py``.
    """
    with _NONCE_LOCK:
        previous = _tiers._AUTHORIZED_T3_NONCE
        nonce = CapabilityGateNonce()
        _tiers._set_authorized_t3_nonce(nonce)
    try:
        yield nonce
    finally:
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(previous)


@pytest.fixture
def fake_external_world() -> tuple[
    Callable[[], _FakeClient],
    _FireCounter,
    _CannedResponse,
]:
    """Yield ``(open_client_factory, fire_counter, canned_response)``.

    * ``open_client_factory`` — a zero-argument callable returning a fresh
      ``_FakeClient`` bound to the shared ``fire_counter`` and
      ``canned_response``; inject it as the relay's ``open_client`` seam.
    * ``fire_counter`` — a ``_FireCounter`` whose ``.value`` increments each
      time the relay's ``send`` is called; tests assert on this to prove the
      upstream was (or was not) hit.
    * ``canned_response`` — a ``_CannedResponse`` whose fields can be mutated
      between test rounds (e.g. a TTL-prune scenario sets a new body after the
      sweep, proving re-fire uses the new canned response, not the old ledger
      replay).

    Delegates to ``tests.helpers.egress_doubles.make_fake_external_world``.
    The fixture itself stays directory-scoped (pytest constraint); only the
    construction logic is shared with the integration conftest.
    """
    return make_fake_external_world()

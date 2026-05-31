"""Shared fixtures for ``tests/unit/security``.

The fixtures defined here are the single legitimate path for tests to
control the module-level ``_AUTHORIZED_T3_NONCE`` slot on
``alfred.security.tiers``. CR-138 findings #7 and #10 removed the per-
call ``_authorized_nonce=`` test-injection seam on ``tag_t3_with_nonce``
and the ad-hoc mutation pattern that left global state changed across
tests; both lived in test code as a workaround for not having a fixture.

CR-138 round-2 finding #4: the runtime helper
``reset_authorized_t3_nonce_for_tests`` was removed from
``src/alfred/bootstrap/nonce_factory.py`` because any code under
``src/`` could call it to clear the live slot and mint its own
authorised nonce. The reset is now performed inline by
``clean_t3_nonce_slot`` under the same lock the bootstrap factory uses,
so the fixture remains race-safe against concurrent bootstrap.

Use ``authorized_t3_nonce`` whenever you need ``tag_t3_with_nonce`` to
accept a specific nonce object. Save/restore happens in the fixture so
the slot value the *next* test sees is whatever the *previous* test saw.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.security import tiers as _tiers
from alfred.security.tiers import CapabilityGateNonce


@pytest.fixture
def authorized_t3_nonce() -> Iterator[CapabilityGateNonce]:
    """Install a fresh ``CapabilityGateNonce`` as the authorised slot.

    Yields the nonce object so tests can pass it as ``caller_token``.
    The previous slot value (typically ``None`` or the bootstrap-set
    nonce) is restored on teardown — no leaked global state between
    tests. CR-138 finding #10.

    Acquires :data:`alfred.bootstrap.nonce_factory._NONCE_LOCK` for the
    save/install and the restore so the fixture stays race-safe against
    a parallel bootstrap path that might run in the same process during
    multi-threaded test scenarios (CR-138 round-2 finding #3).
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
def clean_t3_nonce_slot() -> Iterator[None]:
    """Force ``_AUTHORIZED_T3_NONCE`` to ``None`` for the duration of the test.

    Used by tests that exercise the bootstrap factory path (which
    refuses to run if a nonce is already registered — see
    ``T3NonceAlreadyRegisteredError``). The previous value is restored on
    teardown.

    This fixture is the only legitimate "reset to None" path. The prior
    runtime helper ``reset_authorized_t3_nonce_for_tests`` was removed
    from ``src/`` in CR-138 round-2 finding #4 — exposing a reset seam
    under ``src/`` would let any production code clear the live slot
    and then call the bootstrap factory to mint its own authorised
    nonce. By keeping the reset here (and acquiring
    :data:`alfred.bootstrap.nonce_factory._NONCE_LOCK`) the seam stays
    inside the test tree and remains race-safe against concurrent
    bootstrap.
    """
    with _NONCE_LOCK:
        previous = _tiers._AUTHORIZED_T3_NONCE
        _tiers._set_authorized_t3_nonce(None)
    try:
        yield
    finally:
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(previous)

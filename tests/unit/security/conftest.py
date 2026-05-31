"""Shared fixtures for ``tests/unit/security``.

The fixtures defined here are the single legitimate path for tests to
control the module-level ``_AUTHORIZED_T3_NONCE`` slot on
``alfred.security.tiers``. CR-138 findings #7 and #10 removed the per-
call ``_authorized_nonce=`` test-injection seam on ``tag_t3_with_nonce``
and the ad-hoc mutation pattern that left global state changed across
tests; both lived in test code as a workaround for not having a fixture.

Use ``authorized_t3_nonce`` whenever you need ``tag_t3_with_nonce`` to
accept a specific nonce object. Save/restore happens in the fixture so
the slot value the *next* test sees is whatever the *previous* test saw.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from alfred.security import tiers as _tiers
from alfred.security.tiers import CapabilityGateNonce


@pytest.fixture
def authorized_t3_nonce() -> Iterator[CapabilityGateNonce]:
    """Install a fresh ``CapabilityGateNonce`` as the authorised slot.

    Yields the nonce object so tests can pass it as ``caller_token``.
    The previous slot value (typically ``None`` or the bootstrap-set
    nonce) is restored on teardown — no leaked global state between
    tests. CR-138 finding #10.
    """
    previous = _tiers._AUTHORIZED_T3_NONCE
    nonce = CapabilityGateNonce()
    _tiers._set_authorized_t3_nonce(nonce)
    try:
        yield nonce
    finally:
        _tiers._set_authorized_t3_nonce(previous)


@pytest.fixture
def clean_t3_nonce_slot() -> Iterator[None]:
    """Force ``_AUTHORIZED_T3_NONCE`` to ``None`` for the duration of the test.

    Used by tests that exercise the bootstrap factory path (which
    refuses to run if a nonce is already registered — see
    ``T3NonceAlreadyRegistered``). The previous value is restored on
    teardown.
    """
    previous = _tiers._AUTHORIZED_T3_NONCE
    _tiers._set_authorized_t3_nonce(None)
    try:
        yield
    finally:
        _tiers._set_authorized_t3_nonce(previous)

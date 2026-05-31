"""Pytest fixtures for the tier_laundering adversarial category.

Mirrors the ``authorized_t3_nonce`` fixture in
``tests/unit/security/conftest.py`` so adversarial tests have the same
single legitimate way to install a known nonce in the module-level slot.
CR-138 finding #7 removed the per-call ``_authorized_nonce=`` override
seam; tests now go through this fixture.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from alfred.security import tiers as _tiers
from alfred.security.tiers import CapabilityGateNonce


@pytest.fixture
def authorized_t3_nonce() -> Iterator[CapabilityGateNonce]:
    """Install a fresh ``CapabilityGateNonce`` as the authorised slot.

    Yields the nonce object so adversarial tests can pass it as
    ``caller_token`` when exercising the legitimate-path branch. Saves
    and restores the previous slot value on teardown.
    """
    previous = _tiers._AUTHORIZED_T3_NONCE
    nonce = CapabilityGateNonce()
    _tiers._set_authorized_t3_nonce(nonce)
    try:
        yield nonce
    finally:
        _tiers._set_authorized_t3_nonce(previous)

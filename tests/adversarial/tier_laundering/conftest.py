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

from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.security import tiers as _tiers
from alfred.security.tiers import CapabilityGateNonce


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

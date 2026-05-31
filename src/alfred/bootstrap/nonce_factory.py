"""Bootstrap factory for the T3 capability-gate nonce.

Called once at process start to create the per-process
``CapabilityGateNonce`` and register it as the module-level authorised
slot in ``alfred.security.tiers``. The returned nonce is then
distributed via dependency injection to the two authorised T3-tagging
call sites:

- ``StdioTransport`` (``src/alfred/plugins/stdio_transport.py``, lands
  in PR-S3-3a).
- ``quarantine_host`` (``src/alfred/plugins/quarantine_host.py``, lands
  in PR-S3-4).

This module is the ONLY legitimate caller of
``alfred.security.tiers._set_authorized_t3_nonce`` outside of tests. The
gate compares by identity (Python ``is``); see spec §3.2 and ADR-0017.

CR-138 round-2 finding #3: registration is locked under a module-level
:class:`threading.Lock` so two concurrent bootstrap paths cannot both
observe ``None``, mint different nonces, and race to install — the
losing caller would otherwise return a stale (now-orphaned) nonce that
fails the gate's identity check.

CR-138 round-2 finding #4: the test-only reset seam
(``reset_authorized_t3_nonce_for_tests``) was REMOVED from this module
because any code under ``src/`` could call it to clear the live slot
and then mint its own authorised nonce — a runtime-callable bypass of
the bootstrap DI invariant. Tests now poke the slot inline through the
``clean_t3_nonce_slot`` / ``authorized_t3_nonce`` fixtures in
``tests/unit/security/conftest.py``; the fixtures acquire
:data:`_NONCE_LOCK` so they remain race-safe against concurrent
bootstrap.
"""

from __future__ import annotations

from threading import Lock

from alfred.security import tiers as _tiers
from alfred.security.tiers import CapabilityGateNonce, _set_authorized_t3_nonce

# Module-level lock guarding every read+write of the authorised nonce
# slot. The test fixtures acquire the same lock when they poke the slot
# for setup/teardown — see ``tests/unit/security/conftest.py``. The
# lock is exposed (no underscore-only access) because the test fixtures
# legitimately need to coordinate with production bootstrap in
# pathological multi-thread test runs.
_NONCE_LOCK: Lock = Lock()


class T3NonceAlreadyRegisteredError(RuntimeError):
    """Raised when ``create_and_register_t3_nonce`` is called a second time.

    Re-running bootstrap after the process has already distributed its
    nonce silently invalidates every authorised holder — the nonce
    identity check (``caller_token is _AUTHORIZED_T3_NONCE``) suddenly
    starts failing for callers that hold the old reference. That
    failure mode is hard to diagnose because the surface symptom is
    "T3 tagging refuses a call that worked five minutes ago" with no
    log entry pointing at the rotation.

    Tests that legitimately need to reset the slot do so via the
    ``clean_t3_nonce_slot`` fixture in
    ``tests/unit/security/conftest.py``. There is no production
    runtime API for clearing the slot. CR-138 finding #3 + round-2
    finding #4.
    """


def create_and_register_t3_nonce() -> CapabilityGateNonce:
    """Create the per-process T3 nonce and register it as the authorised
    nonce in ``alfred.security.tiers``.

    Returns the nonce so the bootstrap caller can distribute it via DI
    to the two authorised call sites (``StdioTransport``,
    ``quarantine_host``). The nonce object must be passed directly —
    never serialised, never put in a module global outside the two
    authorised modules. Doing either would defeat the identity check
    that backs the gate.

    Idempotent ONLY via the test-only fixture path. Calling this a
    second time after a previous call has registered a nonce raises
    :class:`T3NonceAlreadyRegisteredError`. The silent-rotation failure
    mode (an authorised holder's ``is`` check suddenly failing because
    bootstrap ran again) is far worse than a loud refusal — CR-138
    finding #3.

    Concurrency: the check + create + register sequence runs inside
    :data:`_NONCE_LOCK`. Two concurrent callers each observing
    ``_AUTHORIZED_T3_NONCE is None`` and both racing to install would
    otherwise leave the loser holding a now-orphaned nonce that fails
    the gate's identity check — CR-138 round-2 finding #3.

    Raises:
        T3NonceAlreadyRegisteredError: if a nonce is already registered.
            Tests reset the slot via the ``clean_t3_nonce_slot`` fixture
            (``tests/unit/security/conftest.py``).
    """
    with _NONCE_LOCK:
        if _tiers._AUTHORIZED_T3_NONCE is not None:
            raise T3NonceAlreadyRegisteredError(
                "create_and_register_t3_nonce() called a second time. "
                "Production code calls this exactly once at process start. "
                "Tests reset the slot via the clean_t3_nonce_slot fixture "
                "in tests/unit/security/conftest.py."
            )
        nonce = CapabilityGateNonce()
        _set_authorized_t3_nonce(nonce)
        return nonce

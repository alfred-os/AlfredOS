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
"""

from __future__ import annotations

from alfred.security import tiers as _tiers
from alfred.security.tiers import CapabilityGateNonce, _set_authorized_t3_nonce


class T3NonceAlreadyRegisteredError(RuntimeError):
    """Raised when ``create_and_register_t3_nonce`` is called a second time.

    Re-running bootstrap after the process has already distributed its
    nonce silently invalidates every authorised holder — the nonce
    identity check (``caller_token is _AUTHORIZED_T3_NONCE``) suddenly
    starts failing for callers that hold the old reference. That
    failure mode is hard to diagnose because the surface symptom is
    "T3 tagging refuses a call that worked five minutes ago" with no
    log entry pointing at the rotation.

    Tests that legitimately need to reset the slot call
    :func:`reset_authorized_t3_nonce_for_tests` explicitly; production
    code never does. CR-138 finding #3.
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

    Idempotent ONLY via the explicit test-only reset path. Calling this
    a second time after a previous call has registered a nonce raises
    :class:`T3NonceAlreadyRegisteredError`. The silent-rotation failure mode
    (an authorised holder's ``is`` check suddenly failing because
    bootstrap ran again) is far worse than a loud refusal — CR-138
    finding #3.

    Raises:
        T3NonceAlreadyRegisteredError: if a nonce is already registered. Tests
            must call :func:`reset_authorized_t3_nonce_for_tests` first.
    """
    if _tiers._AUTHORIZED_T3_NONCE is not None:
        raise T3NonceAlreadyRegisteredError(
            "create_and_register_t3_nonce() called a second time. "
            "Production code calls this exactly once at process start. "
            "Tests that need to reset must call "
            "reset_authorized_t3_nonce_for_tests() explicitly."
        )
    nonce = CapabilityGateNonce()
    _set_authorized_t3_nonce(nonce)
    return nonce


def reset_authorized_t3_nonce_for_tests() -> None:
    """Test-only seam: clear the authorised T3 nonce slot.

    Production code must NEVER call this — silently rotating the nonce
    mid-process invalidates every authorised holder (see
    :class:`T3NonceAlreadyRegisteredError`). Tests that exercise the
    bootstrap path use this to return to a fresh state between runs.

    Prefer the ``authorized_t3_nonce`` pytest fixture (declared in
    ``tests/unit/security/conftest.py``) over calling this directly:
    the fixture handles save/restore so subsequent tests observe the
    correct slot value.
    """
    _set_authorized_t3_nonce(None)

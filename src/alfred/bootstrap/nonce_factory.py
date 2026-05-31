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

from alfred.security.tiers import CapabilityGateNonce, _set_authorized_t3_nonce


def create_and_register_t3_nonce() -> CapabilityGateNonce:
    """Create the per-process T3 nonce and register it as the authorised
    nonce in ``alfred.security.tiers``.

    Returns the nonce so the bootstrap caller can distribute it via DI
    to the two authorised call sites (``StdioTransport``,
    ``quarantine_host``). The nonce object must be passed directly —
    never serialised, never put in a module global outside the two
    authorised modules. Doing either would defeat the identity check
    that backs the gate.

    Idempotent only for testing: calling this twice within the same
    process replaces the registered nonce, which invalidates any
    previously-distributed reference (those holders will fail the
    ``is`` check). In production this is called exactly once at
    process start.
    """
    nonce = CapabilityGateNonce()
    _set_authorized_t3_nonce(nonce)
    return nonce

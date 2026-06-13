"""Per-boot, non-secret lifecycle epoch (Spec A G1 / ADR-0033).

The epoch is a per-process, serialisable, NON-secret value minted once at
boot and carried in the ``core.lifecycle.ready`` notification (and reserved
for the comms handshake). The gateway (G3) rejects a ``ready``/handshake
whose epoch mismatches the one it retained, and binds the last-acked
exchange to it, so a fresh core's ``seq=0`` reconciles against the gateway's
retained high-water mark (spec §4).

It deliberately mirrors the SHAPE of
``alfred.bootstrap.nonce_factory.create_and_register_t3_nonce`` (module slot
+ lock + once-per-process guard) but is its OPPOSITE in trust: the
``CapabilityGateNonce`` is identity-only and MUST NEVER be serialised
(``alfred.security.tiers``), whereas the epoch EXISTS to be serialised onto
the wire. They are distinct values for distinct purposes; do not conflate
them.
"""

from __future__ import annotations

from threading import Lock
from uuid import uuid4

_EPOCH_LOCK: Lock = Lock()
_BOOT_EPOCH: str | None = None


class BootEpochAlreadyMintedError(RuntimeError):
    """Raised when ``mint_boot_epoch`` is called a second time in a process.

    Re-minting would hand out a new epoch while consumers (the ``ready``
    frame already sent, the handshake) still hold the old one — a silent
    reconciliation break. A loud refusal beats a silent rotation
    (mirrors ``T3NonceAlreadyRegisteredError``).
    """


def mint_boot_epoch() -> str:
    """Mint + register the per-process boot epoch; return it.

    Idempotent ONLY via the test reset seam. A second call in the same
    process raises :class:`BootEpochAlreadyMintedError`.
    """
    global _BOOT_EPOCH
    with _EPOCH_LOCK:
        if _BOOT_EPOCH is not None:
            raise BootEpochAlreadyMintedError(
                "mint_boot_epoch() called a second time. Production code mints "
                "exactly once at process start. Tests reset via "
                "reset_boot_epoch_for_tests()."
            )
        _BOOT_EPOCH = uuid4().hex
        return _BOOT_EPOCH


def current_boot_epoch() -> str | None:
    """Return the registered boot epoch, or ``None`` before it is minted."""
    with _EPOCH_LOCK:
        return _BOOT_EPOCH


def reset_boot_epoch_for_tests() -> None:
    """Test-only: clear the slot so a sibling test starts clean.

    Unlike the T3 nonce (whose runtime reset seam was deliberately removed
    because any ``src/`` caller clearing it could forge an authorised
    identity), the epoch is non-secret, so a reset seam grants no privilege —
    a forged epoch only fails the gateway's reconciliation check, it cannot
    cross a trust boundary. Named ``*_for_tests`` so its intent is loud.
    """
    global _BOOT_EPOCH
    with _EPOCH_LOCK:
        _BOOT_EPOCH = None

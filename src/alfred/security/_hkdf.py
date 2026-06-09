"""RFC 5869 HKDF-Expand over stdlib ``hmac`` + ``hashlib`` (SHA-256).

AlfredOS does NOT depend on ``cryptography`` (CLAUDE.md forbids new
fourth-party deps without justification). HKDF-Expand is the only HKDF
stage PR-S4-5 needs — the ``audit.hash_pepper`` broker secret is already
a high-entropy 256-bit master key, so the HKDF-Extract stage (which
condenses low-entropy input keying material into a PRK) is unnecessary;
the pepper IS the PRK. We expose only ``hkdf_expand`` so callers cannot
accidentally skip Extract when their input is NOT already a uniform PRK.

Reference: RFC 5869 §2.3 (HKDF-Expand). Pinned against the published
test vectors in ``tests/unit/security/test_hkdf.py``.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Final

_HASH_LEN: Final = hashlib.sha256().digest_size  # 32 bytes for SHA-256
_MAX_LENGTH: Final = 255 * _HASH_LEN  # RFC 5869 §2.3 hard ceiling


def hkdf_expand(*, prk: bytes, info: bytes, length: int) -> bytes:
    """Derive ``length`` bytes of output keying material from a PRK.

    Implements RFC 5869 §2.3 HKDF-Expand with SHA-256:

        T(0) = empty
        T(n) = HMAC-SHA256(PRK, T(n-1) || info || byte(n))
        OKM  = first ``length`` bytes of T(1) || T(2) || ...

    ``prk`` MUST already be a uniformly-random pseudorandom key of at
    least ``_HASH_LEN`` bytes — for AlfredOS this is the 256-bit
    ``audit.hash_pepper``. ``info`` is the per-purpose domain-separation
    label (e.g. ``b"operator_session.token_hash.v1"``).

    The ``prk``-length floor is ENFORCED, not merely documented (sec-13):
    a short/misconfigured/rotated pepper would otherwise silently yield
    weak subkeys for both the token-hash and machine-id-hash derivations.
    This is the chokepoint both derivations route through, so the check
    here is defense-in-depth covering every subkey.

    Raises:
        ValueError: if ``prk`` is shorter than ``_HASH_LEN`` bytes, if
            ``length`` is negative, or if ``length`` exceeds ``255 * HashLen``
            (the RFC ceiling — beyond it the single-byte block counter
            would overflow).
    """
    if len(prk) < _HASH_LEN:
        msg = f"hkdf_expand prk must be at least {_HASH_LEN} bytes, got {len(prk)}"
        raise ValueError(msg)
    if length < 0:
        msg = f"hkdf_expand length must be non-negative, got {length}"
        raise ValueError(msg)
    if length > _MAX_LENGTH:
        msg = f"hkdf_expand length {length} exceeds RFC 5869 ceiling {_MAX_LENGTH}"
        raise ValueError(msg)

    okm = bytearray()
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(
            key=prk,
            msg=block + info + bytes([counter]),
            digestmod=hashlib.sha256,
        ).digest()
        okm.extend(block)
        counter += 1
    return bytes(okm[:length])


__all__ = ["hkdf_expand"]

"""RFC 5869 HKDF-Expand verification (PR-S4-5 foundation gap).

``cryptography`` is not a fourth-party dependency in AlfredOS (CLAUDE.md
forbids new deps without justification) and HKDF-Expand is ~10 lines of
stdlib ``hmac`` + ``hashlib``. This test pins the implementation against
the published RFC 5869 test vectors so a future refactor cannot silently
diverge from the standard.
"""

from __future__ import annotations

import pytest

from alfred.security._hkdf import hkdf_expand


def test_rfc5869_test_case_1_expand() -> None:
    """RFC 5869 Appendix A.1 (SHA-256) — the OKM output is pinned.

    PRK and L are taken verbatim from the RFC; the expected OKM is the
    42-byte output the RFC publishes for Test Case 1.
    """
    prk = bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )

    okm = hkdf_expand(prk=prk, info=info, length=42)

    assert okm == expected_okm


def test_rfc5869_test_case_3_expand_empty_info() -> None:
    """RFC 5869 Appendix A.3 (SHA-256, zero-length info)."""
    prk = bytes.fromhex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
    expected_okm = bytes.fromhex(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    )

    okm = hkdf_expand(prk=prk, info=b"", length=42)

    assert okm == expected_okm


def test_length_zero_returns_empty() -> None:
    """A zero-length request is a no-op returning empty bytes."""
    assert hkdf_expand(prk=b"\x00" * 32, info=b"x", length=0) == b""


def test_length_above_255_blocks_refused() -> None:
    """RFC 5869 caps the output at 255 * HashLen; we refuse beyond it."""
    with pytest.raises(ValueError, match="length"):
        hkdf_expand(prk=b"\x00" * 32, info=b"x", length=255 * 32 + 1)


def test_negative_length_refused() -> None:
    """A negative length is a caller bug; refuse it loudly."""
    with pytest.raises(ValueError, match="non-negative"):
        hkdf_expand(prk=b"\x00" * 32, info=b"x", length=-1)


def test_single_block_boundary() -> None:
    """A request of exactly HashLen (32) bytes uses a single T(1) block."""
    okm = hkdf_expand(prk=b"\x01" * 32, info=b"ctx", length=32)
    assert len(okm) == 32

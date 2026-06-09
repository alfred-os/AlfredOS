"""HKDF domain-separation subkeys for the operator session (sec-3 closure).

``audit.hash_pepper`` is the master pepper. PR-S4-5 derives two distinct
subkeys from it via HKDF-Expand so a leaked token-hash cannot be replayed
as a machine-id-hash (cross-purpose attack). This test pins that the two
subkeys are deterministic, 32 bytes, and — critically — DIFFER.
"""

from __future__ import annotations

from alfred.identity.operator_session import (
    derive_machine_id_hash_subkey,
    derive_token_hash_subkey,
)

_PEPPER = b"0" * 64  # mirrors `openssl rand -hex 32` → 64-char hex string


def test_subkeys_are_32_bytes() -> None:
    assert len(derive_token_hash_subkey(_PEPPER)) == 32
    assert len(derive_machine_id_hash_subkey(_PEPPER)) == 32


def test_subkeys_differ() -> None:
    """Domain separation: the two info-labels MUST yield distinct keys."""
    assert derive_token_hash_subkey(_PEPPER) != derive_machine_id_hash_subkey(_PEPPER)


def test_subkeys_are_deterministic() -> None:
    assert derive_token_hash_subkey(_PEPPER) == derive_token_hash_subkey(_PEPPER)
    assert derive_machine_id_hash_subkey(_PEPPER) == derive_machine_id_hash_subkey(_PEPPER)


def test_subkeys_differ_from_master_pepper() -> None:
    assert derive_token_hash_subkey(_PEPPER) != _PEPPER
    assert derive_machine_id_hash_subkey(_PEPPER) != _PEPPER

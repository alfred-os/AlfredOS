"""Comms audit rows hash identity values via the authoritative ``audit_hash`` recipe.

H1 unified the comms identity-hash recipe onto ``alfred.comms_mcp.audit_hash``
(closure comms-1): an HKDF-Expand-derived comms subkey over the broker's
``audit.hash_pepper``, plus a PER-FIELD domain-separation prefix so the same
plaintext under two different fields (platform user id vs verification phrase)
yields two DIFFERENT digests. The legacy plain ``HMAC(pepper, raw)[:32]``
``_peppered_hash`` (no per-field separation) is deleted; these tests pin the
properties of the recipe that actually ships.
"""

from __future__ import annotations

import re

import pytest

from alfred.comms_mcp import audit_hash
from alfred.security.secrets import UnknownSecretError

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_PEPPER = "test-pepper-32-bytes-long-enough!"


class _StubBroker:
    def __init__(self, pepper: str | None = _PEPPER) -> None:
        self._pepper = pepper

    def get(self, name: str) -> str:
        if name != "audit.hash_pepper":  # pragma: no cover - defensive
            raise AssertionError(f"unexpected secret {name!r}")
        if self._pepper is None:
            raise UnknownSecretError(name)
        return self._pepper


@pytest.fixture(autouse=True)
def _reset_audit_hash_cache() -> object:
    audit_hash.reset_for_test()
    yield
    audit_hash.reset_for_test()


def test_platform_user_id_hash_is_32_hex_and_hides_the_raw_value() -> None:
    audit_hash.set_broker_for_test(_StubBroker())
    h = audit_hash.hash_platform_user_id("discord:123")
    assert _HEX32.match(h)
    assert "discord:123" not in h


def test_hash_differs_per_input() -> None:
    audit_hash.set_broker_for_test(_StubBroker())
    assert audit_hash.hash_platform_user_id("a") != audit_hash.hash_platform_user_id("b")


def test_hash_differs_per_pepper() -> None:
    audit_hash.set_broker_for_test(_StubBroker(pepper="p" * 40))
    first = audit_hash.hash_platform_user_id("discord:123")
    audit_hash.reset_for_test()
    audit_hash.set_broker_for_test(_StubBroker(pepper="q" * 40))
    second = audit_hash.hash_platform_user_id("discord:123")
    assert first != second


def test_per_field_domain_separation_prevents_cross_field_collision() -> None:
    # comms-1: the SAME plaintext hashed as a platform user id vs a verification
    # phrase MUST produce different digests — so an audit row's user-id hash can
    # never be confused with (or replayed as) a phrase hash. The deleted
    # _peppered_hash had no per-field separation and would collide here.
    audit_hash.set_broker_for_test(_StubBroker())
    same = "collision-probe"
    assert audit_hash.hash_platform_user_id(same) != audit_hash.hash_verification_phrase(same)
    assert audit_hash.hash_channel_id(same) != audit_hash.hash_guild_id(same)

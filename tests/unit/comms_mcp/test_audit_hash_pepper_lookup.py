"""``audit_hash`` HKDF-derived comms hashing helpers (PR-S4-9 Task A2, #206).

Reconciled with round-2 closure **comms-1**: four per-field helpers
(``hash_platform_user_id`` / ``hash_channel_id`` / ``hash_guild_id`` /
``hash_verification_phrase``) keyed on a single HKDF-Expand-derived comms subkey
(``info=b"comms.audit_hash.v1"``) over the master ``audit.hash_pepper`` broker
secret, each with a PER-FIELD domain-separation suffix so cross-field rainbow
tables cannot compose. The pepper is fetched ONCE per process (cached); a missing
pepper raises the typed :class:`MissingAuditHashPepperError`.
"""

from __future__ import annotations

import re

import pytest

from alfred.comms_mcp import audit_hash
from alfred.comms_mcp.audit_hash import (
    AuditHashBrokerNotWiredError,
    MissingAuditHashPepperError,
    hash_channel_id,
    hash_guild_id,
    hash_platform_user_id,
    hash_verification_phrase,
)
from alfred.security.secrets import UnknownSecretError

_HEX32 = re.compile(r"^[0-9a-f]{32}$")

# 32 bytes minimum — the HKDF PRK floor (SHA-256 digest size). A real
# ``audit.hash_pepper`` is a 256-bit master key.
_PEPPER_1 = "p" * 40
_PEPPER_2 = "q" * 40


class _StubBroker:
    """SecretBroker stand-in returning a fixed pepper; counts ``get`` calls."""

    def __init__(self, pepper: str | None) -> None:
        self._pepper = pepper
        self.get_calls = 0

    def get(self, name: str) -> str:
        self.get_calls += 1
        if name != "audit.hash_pepper":  # pragma: no cover - defensive
            raise AssertionError(f"unexpected secret {name!r}")
        if self._pepper is None:
            raise UnknownSecretError(name)
        return self._pepper


@pytest.fixture(autouse=True)
def _reset_audit_hash_cache() -> object:
    """Reset the module-level pepper/subkey cache around every test."""
    audit_hash.reset_for_test()
    yield
    audit_hash.reset_for_test()


def test_hash_platform_user_id_returns_32_char_hex() -> None:
    audit_hash.set_broker_for_test(_StubBroker(_PEPPER_1))
    digest = hash_platform_user_id("123456789")
    assert _HEX32.match(digest)


def test_pepper_change_changes_digest() -> None:
    audit_hash.set_broker_for_test(_StubBroker(_PEPPER_1))
    first = hash_platform_user_id("123456789")

    audit_hash.reset_for_test()
    audit_hash.set_broker_for_test(_StubBroker(_PEPPER_2))
    second = hash_platform_user_id("123456789")

    assert first != second


def test_pepper_fetched_exactly_once_per_process() -> None:
    broker = _StubBroker(_PEPPER_1)
    audit_hash.set_broker_for_test(broker)
    hash_platform_user_id("a")
    hash_channel_id("a")
    hash_guild_id("a")
    hash_verification_phrase("a")
    assert broker.get_calls == 1  # cached after the first derive


def test_missing_pepper_raises_typed_error() -> None:
    audit_hash.set_broker_for_test(_StubBroker(None))
    with pytest.raises(MissingAuditHashPepperError):
        hash_platform_user_id("123456789")


def test_unwired_broker_raises_typed_error() -> None:
    # reset_for_test (autouse) leaves no broker wired; hashing before boot-wiring
    # is a boot-ordering bug surfaced loud, not a silent unsalted hash.
    with pytest.raises(AuditHashBrokerNotWiredError):
        hash_platform_user_id("123456789")


def test_four_helpers_produce_distinct_digests_for_same_input() -> None:
    audit_hash.set_broker_for_test(_StubBroker(_PEPPER_1))
    same = "collision-bait"
    digests = {
        hash_platform_user_id(same),
        hash_channel_id(same),
        hash_guild_id(same),
        hash_verification_phrase(same),
    }
    # Per-field domain separation: four distinct outputs for one plaintext.
    assert len(digests) == 4


def test_each_helper_is_deterministic_under_a_fixed_pepper() -> None:
    audit_hash.set_broker_for_test(_StubBroker(_PEPPER_1))
    assert hash_platform_user_id("x") == hash_platform_user_id("x")
    assert hash_channel_id("x") == hash_channel_id("x")
    assert hash_guild_id("x") == hash_guild_id("x")
    assert hash_verification_phrase("x") == hash_verification_phrase("x")


def test_set_broker_for_test_always_rederives_even_on_same_object() -> None:
    """The test seam must NEVER leak a stale subkey across a re-set.

    ``set_broker`` short-circuits when re-wired with the SAME broker object (so the
    inbound hot-path can call it per message without thrashing the cache). The TEST
    seam must not inherit that short-circuit: a test that mutates a reused stub's
    pepper and re-injects the SAME object must observe the new pepper, else a stale
    subkey derived from the prior pepper silently produces wrong hashes.
    """
    broker = _StubBroker(_PEPPER_1)
    audit_hash.set_broker_for_test(broker)
    first = hash_platform_user_id("123456789")

    # Mutate the SAME broker object's pepper, then re-inject it via the test seam.
    broker._pepper = _PEPPER_2
    audit_hash.set_broker_for_test(broker)
    second = hash_platform_user_id("123456789")

    assert first != second, "set_broker_for_test must drop the stale derived subkey"

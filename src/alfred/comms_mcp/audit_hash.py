"""Comms-MCP audit-hash helpers (PR-S4-9 Task A2, #206 — closure comms-1).

Every Discord identity value that lands in an audit row — the platform user id,
the channel id, the guild id, the binding verification phrase — is stored as a
keyed hash, never in the clear. An operator browsing the audit log sees a stable
correlation token, not the raw Discord snowflake or the secret phrase, so the
audit store cannot become a deanonymisation or replay oracle.

**Keying (round-2 closure comms-1).** The master key is the ``audit.hash_pepper``
broker secret (a 256-bit key bootstrapped in PR-S4-0b). This module derives a
single *comms subkey* from it via HKDF-Expand with
``info=b"comms.audit_hash.v1"`` (the comms-domain separator that keeps comms
hashes from colliding with the operator-session subkeys derived from the same
pepper). Each of the four helpers then HMACs its input under that comms subkey
with a PER-FIELD domain-separation prefix (``platform_user_id:`` / ``channel:`` /
``guild:`` / ``verification_phrase:``) so the same plaintext under two different
fields yields two different digests — a cross-field rainbow table built for one
field cannot be reused against another.

**Pepper lifecycle.** The pepper is fetched from the broker exactly ONCE per
process and the derived comms subkey is cached for the daemon lifetime (rotating
the pepper requires a restart, matching the operator-session resolver). A missing
pepper raises the typed :class:`MissingAuditHashPepperError` at first use — loud,
not silent — so a misconfigured deployment fails closed rather than writing
unsalted identity values.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Final, Protocol, runtime_checkable

from alfred.errors import AlfredError
from alfred.i18n import t
from alfred.security._hkdf import hkdf_expand
from alfred.security.secrets import UnknownSecretError


@runtime_checkable
class _BrokerLike(Protocol):
    """Structural view of the secret broker: ``get("audit.hash_pepper")``.

    The comms host wires the real :class:`alfred.security.secrets.SecretBroker`;
    the inbound unit tests wire a structural stub. The module only ever requests
    the ``audit.hash_pepper`` secret, so this minimal surface is the whole
    dependency.
    """

    def get(self, name: str) -> str: ...


# HKDF-Expand domain separator for the comms subkey (closure comms-1). Distinct
# from operator_session's ``operator_session.*`` infos so the two subsystems
# derive non-overlapping subkeys from the shared master pepper.
_COMMS_SUBKEY_INFO: Final = b"comms.audit_hash.v1"
_SUBKEY_LEN: Final = 32
# Truncated hex width of every comms audit hash (spec §8.10).
_HEX_WIDTH: Final = 32

# Per-field HMAC domain-separation prefixes. The same plaintext under two fields
# hashes differently because the HMAC message is prefixed by the field label.
_PLATFORM_USER_PREFIX: Final = b"platform_user_id:"
_CHANNEL_PREFIX: Final = b"channel:"
_GUILD_PREFIX: Final = b"guild:"
_VERIFICATION_PHRASE_PREFIX: Final = b"verification_phrase:"


class AuditHashBrokerNotWiredError(AlfredError):
    """:func:`set_broker` was never called before a comms identity was hashed.

    The daemon boot path MUST wire the process :class:`SecretBroker` via
    :func:`set_broker` before any inbound flows through the comms-MCP audit path.
    Reaching a hashing helper with no broker is a boot-ordering bug, surfaced
    loud rather than papered over with an implicitly-constructed broker (which
    would hide a misconfigured boot and violate the no-hidden-global-state rule).
    """


class MissingAuditHashPepperError(AlfredError):
    """The ``audit.hash_pepper`` broker secret is unset.

    Raised at first hashing call rather than at import so a process that never
    hashes a comms identity value is not forced to have the pepper configured,
    while any process that DOES hash fails loud and closed on a missing pepper —
    no unsalted identity value can reach an audit row.
    """

    def __init__(self) -> None:
        # closure i18n-2: reuse the PR-S4-0b daemon-boot key (already in the
        # catalog + reserved in alfred.i18n._slice_4_reserve) rather than mint a
        # parallel one — one operator-facing message for one root cause.
        super().__init__(t("daemon.boot.audit_hash_pepper_missing"))


# Module-level injection seam + cache. ``set_broker`` is called once at daemon
# boot with the process broker; the derived subkey is memoised on first use.
# This is deliberately NOT a global singleton SecretBroker — the broker is
# passed in explicitly (no hidden construction), and the cache holds only the
# derived 32-byte subkey, never the raw pepper beyond the single derive call.
_broker: _BrokerLike | None = None
_comms_subkey: bytes | None = None


def set_broker(broker: _BrokerLike) -> None:
    """Wire the process secret broker (called at the comms host construction seam).

    Idempotent on the SAME broker object: re-wiring the identical broker is a
    no-op so the inbound hot-path can call this every message (keeping the wiring
    explicit, no hidden global construction) without thrashing the derived-subkey
    cache. Wiring a DIFFERENT broker resets the cache so the fresh broker
    re-derives on next use (the rotation / test path).

    Accepts any object exposing ``get(name) -> str`` (the comms host passes the
    real :class:`SecretBroker`; the inbound unit tests pass a structural stub) —
    the module only ever calls ``get("audit.hash_pepper")``.
    """
    global _broker, _comms_subkey
    if broker is _broker:
        return
    _broker = broker
    _comms_subkey = None


def _resolve_subkey() -> bytes:
    """Return the cached comms subkey, deriving it from the pepper on first use.

    Raises:
        AuditHashBrokerNotWiredError: if :func:`set_broker` was never called.
        MissingAuditHashPepperError: if no pepper is configured in the broker.
    """
    global _comms_subkey
    if _comms_subkey is not None:
        return _comms_subkey
    if _broker is None:
        raise AuditHashBrokerNotWiredError
    try:
        pepper = _broker.get("audit.hash_pepper").encode("utf-8")
    except UnknownSecretError as exc:
        raise MissingAuditHashPepperError from exc
    _comms_subkey = hkdf_expand(prk=pepper, info=_COMMS_SUBKEY_INFO, length=_SUBKEY_LEN)
    return _comms_subkey


def _hash(prefix: bytes, raw: str) -> str:
    """HMAC ``raw`` under the comms subkey with a per-field prefix; hex-truncate."""
    subkey = _resolve_subkey()
    return hmac.new(subkey, prefix + raw.encode("utf-8"), hashlib.sha256).hexdigest()[:_HEX_WIDTH]


def hash_platform_user_id(raw: str) -> str:
    """Keyed hash of a platform user id (Discord snowflake) for audit rows."""
    return _hash(_PLATFORM_USER_PREFIX, raw)


def hash_channel_id(raw: str) -> str:
    """Keyed hash of a platform channel id for audit rows."""
    return _hash(_CHANNEL_PREFIX, raw)


def hash_guild_id(raw: str) -> str:
    """Keyed hash of a platform guild id for audit rows."""
    return _hash(_GUILD_PREFIX, raw)


def hash_verification_phrase(raw: str) -> str:
    """Keyed hash of a binding verification phrase for audit rows."""
    return _hash(_VERIFICATION_PHRASE_PREFIX, raw)


def set_broker_for_test(broker: _BrokerLike) -> None:
    """Test seam: inject a stub broker and clear the cache.

    Distinct public name from :func:`set_broker` so a grep for production
    boot-wiring versus test wiring stays unambiguous; both reset the cache.
    """
    set_broker(broker)


def reset_for_test() -> None:
    """Test seam: drop the injected broker + cached subkey."""
    global _broker, _comms_subkey
    _broker = None
    _comms_subkey = None


__all__ = [
    "AuditHashBrokerNotWiredError",
    "MissingAuditHashPepperError",
    "hash_channel_id",
    "hash_guild_id",
    "hash_platform_user_id",
    "hash_verification_phrase",
    "reset_for_test",
    "set_broker",
    "set_broker_for_test",
]

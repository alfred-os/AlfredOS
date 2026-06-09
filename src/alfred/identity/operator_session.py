"""Operator-session model, file persistence, machine-id, and resolver (#153).

This module is the trust boundary for CLI operator attribution. An
operator runs ``alfred login`` to mint a session token persisted at
``~/.config/alfred/session`` (mode 0600); every operator-attributed CLI
command thereafter resolves that file -> a canonical ``User.id`` and
stamps it onto the audit row. The defences layered here:

* **HKDF domain separation** (sec-3): the master ``audit.hash_pepper``
  is expanded into two distinct subkeys so a leaked token-hash cannot be
  replayed as a machine-id-hash.
* **TOCTOU-safe load** (sec-2): parent-dir-fd fstat + ``openat`` +
  ``O_NOFOLLOW`` so a rename-into-dir or symlink swap is refused.
* **SecretStr persistence** (sec-1): the in-memory model redacts the
  token in logs; explicit serialise/deserialise helpers round-trip the
  raw value so the next load's HMAC lookup hits the DB row.
* **Log-injection defence** (sec-4): the self-claimed ``user_id`` in a
  planted file is validated against a strict character class BEFORE any
  audit emit.

Naming: the Pydantic FILE model here is ``OperatorSessionFile``. The
SQLAlchemy ORM row (``operator_sessions`` table) is
``alfred.memory.models.OperatorSession`` — referenced as
``models.OperatorSession`` to keep the distinction unambiguous.

The ``OperatorResolverProtocol`` (``alfred.supervisor.protocols``,
async ``resolve() -> str``) is THE operator-session resolver — it was
shipped + consumed in PR-S4-1 and is reused verbatim here (lower-churn
than introducing a competing ``OperatorSessionResolver`` name).
``DefaultOperatorSessionResolver`` below is the production implementation.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from alfred.errors import AlfredError
from alfred.security._hkdf import hkdf_expand

# ---------------------------------------------------------------------------
# Constants (lifetime-pin closure 13)
# ---------------------------------------------------------------------------

_TOKEN_BYTES: Final = 32  # 32 random bytes; base64url-encoded -> ~43 chars
_HASH_LEN: Final = 64  # full HMAC-SHA256 hex output (256 bits) — no truncation

_DEFAULT_EXPIRES_IN: Final = timedelta(hours=12)
_MIN_EXPIRES_IN: Final = timedelta(hours=1)
_MAX_EXPIRES_IN: Final = timedelta(days=7)

# HKDF domain-separation labels (sec-3). Versioned so a future rotation of
# the derivation scheme can coexist with v1 sessions during migration.
_TOKEN_HASH_INFO: Final = b"operator_session.token_hash.v1"
_MACHINE_ID_HASH_INFO: Final = b"operator_session.machine_id_hash.v1"
_SUBKEY_LEN: Final = 32


def derive_token_hash_subkey(pepper: bytes) -> bytes:
    """HKDF-Expand the master pepper into the token-hash subkey (sec-3)."""
    return hkdf_expand(prk=pepper, info=_TOKEN_HASH_INFO, length=_SUBKEY_LEN)


def derive_machine_id_hash_subkey(pepper: bytes) -> bytes:
    """HKDF-Expand the master pepper into the machine-id-hash subkey (sec-3)."""
    return hkdf_expand(prk=pepper, info=_MACHINE_ID_HASH_INFO, length=_SUBKEY_LEN)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class OperatorSessionError(AlfredError):
    """Root of the operator-session refusal hierarchy.

    Every refusal path raises a concrete subclass so the CLI top-level
    dispatch can map each to a localised stderr message + a typed audit
    ``reason`` without string-matching.
    """


class OperatorSessionMissing(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """No session file at the expected path."""


class OperatorSessionMalformed(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The session file exists but did not parse as an OperatorSessionFile."""


class OperatorSessionBadFileMode(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The session file's mode is broader than 0600 (or open was refused)."""


class OperatorSessionBadFileOwner(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The session file is not owned by the calling uid/gid."""


class OperatorSessionParentDirInsecure(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The parent directory is group/other-accessible (mode & 0o077)."""


class OperatorSessionParentDirNotOwned(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The parent directory is not owned by the calling euid."""


class OperatorSessionExpired(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The session's expires_at is in the past."""


class OperatorSessionRevoked(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The session row carries a non-null revoked_at."""


class OperatorSessionHostMismatch(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The session was created on a different host (hostname changed)."""


class OperatorSessionMachineIdMismatch(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The live machine-id hash does not match the session's (replay)."""


class OperatorSessionTokenUnknown(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """No matching, non-revoked operator_sessions row for the token hash."""


class OperatorSessionTokenUserMismatch(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """Valid token, but the file's user_id disagrees with the DB row.

    Token is authoritative (closure 11); a planted file claiming a
    different operator than the token's DB owner is refused.
    """


class OperatorSessionUserRevoked(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The bound User row is soft-deleted (deleted_at set)."""


class OperatorSessionTimeout(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The resolver exceeded its 250ms hard timeout (err-008)."""


class OperatorSessionNoMachineId(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The per-OS machine-id source was unreadable."""


# ---------------------------------------------------------------------------
# §5.1 OperatorSessionFile Pydantic model
# ---------------------------------------------------------------------------


class OperatorSessionFile(BaseModel):
    """Persisted operator-session record (the on-disk file body).

    The token field is the verbatim base64url token minted at login. The
    file's 0600 mode is the host-side defence; the daemon-side defence is
    the matching ``token_hash`` row in ``operator_sessions`` on the
    ``uq_operator_sessions_token_hash`` unique index.

    ``machine_id_hash`` is ``HMAC-SHA256(machine_id_subkey, raw_machine_id)``
    as full 64-char hex. The raw machine-id is NEVER serialised.

    ``user_id`` is the canonical autoincrement ``User.id`` (int) — the FK
    target of ``operator_sessions.user_id``.
    """

    schema_version: Literal[1]
    user_id: int
    token: SecretStr
    issued_at: datetime
    expires_at: datetime
    host: str
    machine_id_hash: str = Field(min_length=_HASH_LEN, max_length=_HASH_LEN)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def _expiry_after_issue(self) -> OperatorSessionFile:
        if self.expires_at <= self.issued_at:
            msg = "expires_at must be strictly after issued_at"
            raise ValueError(msg)
        return self


__all__ = [
    "OperatorSessionBadFileMode",
    "OperatorSessionBadFileOwner",
    "OperatorSessionError",
    "OperatorSessionExpired",
    "OperatorSessionFile",
    "OperatorSessionHostMismatch",
    "OperatorSessionMachineIdMismatch",
    "OperatorSessionMalformed",
    "OperatorSessionMissing",
    "OperatorSessionNoMachineId",
    "OperatorSessionParentDirInsecure",
    "OperatorSessionParentDirNotOwned",
    "OperatorSessionRevoked",
    "OperatorSessionTimeout",
    "OperatorSessionTokenUnknown",
    "OperatorSessionTokenUserMismatch",
    "OperatorSessionUserRevoked",
    "derive_machine_id_hash_subkey",
    "derive_token_hash_subkey",
]

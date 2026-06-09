"""``DefaultOperatorSessionResolver`` — happy path + every refusal (Tasks 10-13).

The resolver is the trust boundary: session file -> DB lookup -> canonical
User.id. Unit tests inject a fake async session scope (no aiosqlite in the
unit env) plus a fake audit writer + hook dispatcher so every branch is
exercised deterministically. 100% line + branch coverage is merge-blocking
on this file (test-3 closure).
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from alfred.identity._resolver import DefaultOperatorSessionResolver
from alfred.identity.operator_session import (
    OperatorSessionBadFileMode,
    OperatorSessionExpired,
    OperatorSessionFile,
    OperatorSessionHostMismatch,
    OperatorSessionMachineIdMismatch,
    OperatorSessionMalformed,
    OperatorSessionMissing,
    OperatorSessionNoMachineId,
    OperatorSessionParentDirInsecure,
    OperatorSessionPepperMisconfigured,
    OperatorSessionTimeout,
    OperatorSessionTokenUnknown,
    OperatorSessionTokenUserMismatch,
    OperatorSessionUserRevoked,
    compute_machine_id_hash,
    compute_token_hash,
    write_session_file,
)

_PEPPER = "0" * 64
_HOST = "alfred-host"
_TOKEN = "the-token"  # noqa: S105 -- test fixture token, not a real credential


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


@dataclass
class _FakeBroker:
    pepper: str = _PEPPER

    def get(self, name: str) -> str:
        assert name == "audit.hash_pepper"
        return self.pepper


@dataclass
class _StubMachineId:
    raw: bytes = b"machine-raw"

    async def read_raw(self) -> bytes:
        return self.raw


class _NoMachineId:
    async def read_raw(self) -> bytes:
        raise OperatorSessionNoMachineId("no machine id source")


@dataclass
class _Row:
    token_hash: str
    user_id: int
    revoked_at: datetime | None = None
    user_deleted_at: datetime | None = None


@dataclass
class _FakeResult:
    row: tuple[int, datetime | None] | None

    def first(self) -> tuple[int, datetime | None] | None:
        return self.row


def _bound_token_hash(statement: Any) -> str | None:
    """Extract the bound ``token_hash`` from the resolver's compiled SELECT.

    The resolver filters ``OperatorSessionRow.token_hash == token_hash``; the
    literal lives in the statement's bind params. Pulling it out lets the fake
    DB honour the unique-index lookup instead of blindly returning row[0].
    """
    params = statement.compile().params
    for key, value in params.items():
        if "token_hash" in key:
            return None if value is None else str(value)
    return None


@dataclass
class _FakeSession:
    rows: Sequence[_Row]
    sleep_s: float = 0.0

    async def execute(self, statement: Any, *_args: Any, **_kwargs: Any) -> _FakeResult:
        if self.sleep_s:
            await asyncio.sleep(self.sleep_s)
        # CR-227 round-2 finding 7: honour the queried ``token_hash`` so the
        # fake actually exercises the ``uq_operator_sessions_token_hash``
        # unique-index lookup. The previous fake returned the first
        # non-revoked row regardless of which token was queried, so a
        # resolver regression that looked up the wrong hash would pass
        # unnoticed. The bound value lives in the compiled statement's
        # params; we filter the seeded rows by it (returning None on no
        # match, mirroring ``Result.first()`` over an empty result set).
        queried = _bound_token_hash(statement)
        for row in self.rows:
            if row.revoked_at is None and row.token_hash == queried:
                return _FakeResult((row.user_id, row.user_deleted_at))
        return _FakeResult(None)


@dataclass
class _AuditCall:
    schema_name: str
    subject: dict[str, Any]


@dataclass
class _FakeAudit:
    calls: list[_AuditCall] = field(default_factory=list)

    async def append_schema(self, **kwargs: Any) -> None:
        self.calls.append(_AuditCall(kwargs["schema_name"], kwargs["subject"]))


@dataclass
class _HookCall:
    name: str
    payload: dict[str, Any]


@dataclass
class _FakeHooks:
    calls: list[_HookCall] = field(default_factory=list)

    async def __call__(self, name: str, payload: dict[str, Any]) -> None:
        self.calls.append(_HookCall(name, payload))


def _scope_for(session: _FakeSession) -> Any:
    @asynccontextmanager
    async def _scope() -> Any:
        yield session

    return _scope


def _expected_machine_hash() -> str:
    import hashlib
    import hmac

    from alfred.identity.operator_session import derive_machine_id_hash_subkey

    sub = derive_machine_id_hash_subkey(_PEPPER.encode())
    return hmac.new(sub, b"machine-raw", hashlib.sha256).hexdigest()


def _write_session(
    tmp_path: Path,
    *,
    user_id: int = 7,
    host: str = _HOST,
    machine_hash: str | None = None,
    expires_delta: timedelta = timedelta(hours=12),
    token: str = _TOKEN,
) -> Path:
    parent = tmp_path / ".config" / "alfred"
    parent.mkdir(parents=True, exist_ok=True)
    parent.chmod(0o700)
    path = parent / "session"
    now = datetime.now(UTC)
    expires_at = now + expires_delta
    session = OperatorSessionFile(
        schema_version=1,
        user_id=user_id,
        token=SecretStr(token),
        # issued_at is always strictly before expires_at (model invariant),
        # even for the expired-session case where expires_at is in the past.
        issued_at=expires_at - timedelta(minutes=1),
        expires_at=expires_at,
        host=host,
        machine_id_hash=machine_hash or _expected_machine_hash(),
    )
    write_session_file(path, session)
    return path


def _make_resolver(
    path: Path,
    session: _FakeSession,
    *,
    audit: _FakeAudit | None = None,
    hooks: _FakeHooks | None = None,
    host: str = _HOST,
    broker: _FakeBroker | None = None,
) -> DefaultOperatorSessionResolver:
    return DefaultOperatorSessionResolver(
        session_scope=_scope_for(session),
        secret_broker=broker or _FakeBroker(),
        machine_id_provider=_StubMachineId(),
        audit_writer=audit or _FakeAudit(),
        hook_dispatcher=hooks or _FakeHooks(),
        host=host,
        session_file_path=path,
    )


def _refused_calls(audit: _FakeAudit) -> list[_AuditCall]:
    """All ``OPERATOR_SESSION_REFUSED`` rows the resolver emitted.

    hard rule #7: each refusal path lands EXACTLY one row — assertions over
    this helper count, never just "at least one".
    """
    return [c for c in audit.calls if c.schema_name == "OPERATOR_SESSION_REFUSED_FIELDS"]


def _refused_hooks(hooks: _FakeHooks) -> list[_HookCall]:
    """All ``operator.session.refused`` hookpoint emissions."""
    return [c for c in hooks.calls if c.name == "operator.session.refused"]


def _token_hash() -> str:
    return compute_token_hash(token=_TOKEN, pepper=_PEPPER.encode())


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


async def test_happy_path_returns_canonical_user_id(tmp_path: Path) -> None:
    path = _write_session(tmp_path, user_id=7)
    session = _FakeSession(rows=[_Row(token_hash=_token_hash(), user_id=7)])
    resolver = _make_resolver(path, session)
    assert await resolver.resolve() == "7"


async def test_expired_refuses_and_audits(tmp_path: Path) -> None:
    path = _write_session(tmp_path, expires_delta=timedelta(hours=-1))
    audit = _FakeAudit()
    hooks = _FakeHooks()
    resolver = _make_resolver(path, _FakeSession(rows=[]), audit=audit, hooks=hooks)
    with pytest.raises(OperatorSessionExpired):
        await resolver.resolve()
    refused = _refused_calls(audit)
    assert len(refused) == 1
    assert refused[0].subject["reason"] == "expired"
    assert len(_refused_hooks(hooks)) == 1


async def test_host_mismatch_refuses(tmp_path: Path) -> None:
    path = _write_session(tmp_path, host="other-host")
    audit = _FakeAudit()
    hooks = _FakeHooks()
    resolver = _make_resolver(path, _FakeSession(rows=[]), audit=audit, hooks=hooks)
    with pytest.raises(OperatorSessionHostMismatch):
        await resolver.resolve()
    refused = _refused_calls(audit)
    assert len(refused) == 1
    assert refused[0].subject["reason"] == "host_mismatch"
    assert len(_refused_hooks(hooks)) == 1


async def test_machine_mismatch_refuses(tmp_path: Path) -> None:
    path = _write_session(tmp_path, machine_hash="f" * 64)
    audit = _FakeAudit()
    hooks = _FakeHooks()
    resolver = _make_resolver(path, _FakeSession(rows=[]), audit=audit, hooks=hooks)
    with pytest.raises(OperatorSessionMachineIdMismatch):
        await resolver.resolve()
    refused = _refused_calls(audit)
    assert len(refused) == 1
    assert refused[0].subject["reason"] == "machine_mismatch"
    assert len(_refused_hooks(hooks)) == 1


async def test_token_unknown_refuses(tmp_path: Path) -> None:
    path = _write_session(tmp_path)
    audit = _FakeAudit()
    hooks = _FakeHooks()
    resolver = _make_resolver(path, _FakeSession(rows=[]), audit=audit, hooks=hooks)
    with pytest.raises(OperatorSessionTokenUnknown):
        await resolver.resolve()
    refused = _refused_calls(audit)
    assert len(refused) == 1
    assert refused[0].subject["reason"] == "token_unknown"
    assert len(_refused_hooks(hooks)) == 1


async def test_token_hash_mismatch_is_token_unknown(tmp_path: Path) -> None:
    """A seeded row whose token_hash differs from the queried hash is invisible.

    CR-227 round-2 finding 7: proves the resolver looks up by the unique-index
    ``token_hash`` (not just "first non-revoked row"). The fake honours the
    bound hash, so a row keyed on a DIFFERENT token resolves to ``token_unknown``.
    """
    path = _write_session(tmp_path, user_id=7)
    session = _FakeSession(rows=[_Row(token_hash="deadbeef" * 8, user_id=7)])
    audit = _FakeAudit()
    hooks = _FakeHooks()
    resolver = _make_resolver(path, session, audit=audit, hooks=hooks)
    with pytest.raises(OperatorSessionTokenUnknown):
        await resolver.resolve()
    refused = _refused_calls(audit)
    assert len(refused) == 1
    assert refused[0].subject["reason"] == "token_unknown"
    assert len(_refused_hooks(hooks)) == 1


async def test_token_user_mismatch_refuses(tmp_path: Path) -> None:
    """Valid token, but file user_id != DB row user_id -> token authoritative."""
    path = _write_session(tmp_path, user_id=7)
    # DB row owns the token but is bound to a DIFFERENT user (9).
    session = _FakeSession(rows=[_Row(token_hash=_token_hash(), user_id=9)])
    audit = _FakeAudit()
    hooks = _FakeHooks()
    resolver = _make_resolver(path, session, audit=audit, hooks=hooks)
    with pytest.raises(OperatorSessionTokenUserMismatch):
        await resolver.resolve()
    refused = _refused_calls(audit)
    assert len(refused) == 1
    assert refused[0].subject["reason"] == "token_user_mismatch"
    assert len(_refused_hooks(hooks)) == 1


async def test_user_revoked_refuses(tmp_path: Path) -> None:
    path = _write_session(tmp_path, user_id=7)
    session = _FakeSession(
        rows=[_Row(token_hash=_token_hash(), user_id=7, user_deleted_at=datetime.now(UTC))]
    )
    audit = _FakeAudit()
    hooks = _FakeHooks()
    resolver = _make_resolver(path, session, audit=audit, hooks=hooks)
    with pytest.raises(OperatorSessionUserRevoked):
        await resolver.resolve()
    refused = _refused_calls(audit)
    assert len(refused) == 1
    assert refused[0].subject["reason"] == "user_revoked"
    assert len(_refused_hooks(hooks)) == 1


async def test_timeout_refuses(tmp_path: Path) -> None:
    path = _write_session(tmp_path, user_id=7)
    session = _FakeSession(rows=[_Row(token_hash=_token_hash(), user_id=7)], sleep_s=5.0)
    resolver = _make_resolver(path, session)
    # Shrink the hard timeout so the test is fast.
    resolver._hard_timeout_s = 0.05  # type: ignore[attr-defined]
    with pytest.raises(OperatorSessionTimeout):
        await resolver.resolve()


async def test_missing_file_emits_fileless_session_missing(tmp_path: Path) -> None:
    """No file -> file-less ``session_missing`` row (attempted_user_id None).

    hard rule #7: the load refusal fires before any session exists, so the
    resolver MUST still land exactly one refused row + hookpoint.
    """
    parent = tmp_path / ".config" / "alfred"
    parent.mkdir(parents=True)
    parent.chmod(0o700)
    path = parent / "session"  # never written
    audit = _FakeAudit()
    hooks = _FakeHooks()
    resolver = _make_resolver(path, _FakeSession(rows=[]), audit=audit, hooks=hooks)
    with pytest.raises(OperatorSessionMissing):
        await resolver.resolve()
    # hard rule #7: EXACTLY one refused row + one refused hookpoint — no
    # duplicates, no zero (CR-227 round-3 finding 3 tightens "at least one").
    refused = _refused_calls(audit)
    assert len(refused) == 1
    assert refused[0].subject["reason"] == "session_missing"
    assert refused[0].subject["attempted_user_id"] is None
    assert refused[0].subject["host"] is None
    assert refused[0].subject["machine_id_hash"] is None
    assert len(_refused_hooks(hooks)) == 1


async def test_malformed_file_emits_fileless_planted_file_invalid(tmp_path: Path) -> None:
    parent = tmp_path / ".config" / "alfred"
    parent.mkdir(parents=True)
    parent.chmod(0o700)
    path = parent / "session"
    path.write_bytes(b'{"not":"a session"}')
    path.chmod(0o600)
    audit = _FakeAudit()
    hooks = _FakeHooks()
    resolver = _make_resolver(path, _FakeSession(rows=[]), audit=audit, hooks=hooks)
    with pytest.raises(OperatorSessionMalformed):
        await resolver.resolve()
    refused = _refused_calls(audit)
    assert len(refused) == 1
    assert refused[0].subject["reason"] == "planted_file_invalid"
    assert len(_refused_hooks(hooks)) == 1


async def test_non_hex_machine_id_hash_refused_as_planted_file_invalid(tmp_path: Path) -> None:
    """A planted file with a non-hex ``machine_id_hash`` is refused at PARSE.

    CR-227 round-3 finding 2: the field used to accept ANY 64-char string, so
    a planted file could splice arbitrary bytes (newlines, control chars, a
    log-injection payload) into the ``machine_mismatch`` forensic row. Pinning
    the field to the HMAC-SHA256 hex shape turns a non-hex value into a
    malformed file → ``planted_file_invalid`` file-less row, so NO attacker
    bytes ever reach the audit log.
    """
    parent = tmp_path / ".config" / "alfred"
    parent.mkdir(parents=True)
    parent.chmod(0o700)
    path = parent / "session"
    now = datetime.now(UTC)
    # 64 chars but NOT lowercase hex — the exact log-injection shape the
    # length-only constraint used to wave through.
    poison = "Z" * 63 + "\n"
    body = {
        "schema_version": 1,
        "user_id": 7,
        "token": _TOKEN,
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=12)).isoformat(),
        "host": _HOST,
        "machine_id_hash": poison,
    }
    import json

    path.write_text(json.dumps(body))
    path.chmod(0o600)
    audit = _FakeAudit()
    hooks = _FakeHooks()
    resolver = _make_resolver(path, _FakeSession(rows=[]), audit=audit, hooks=hooks)
    with pytest.raises(OperatorSessionMalformed):
        await resolver.resolve()
    refused = _refused_calls(audit)
    assert len(refused) == 1
    assert refused[0].subject["reason"] == "planted_file_invalid"
    # The poison never reaches the row: every self-claimed field is None.
    assert refused[0].subject["machine_id_hash"] is None
    assert len(_refused_hooks(hooks)) == 1


async def test_bad_file_mode_emits_fileless_bad_file_mode(tmp_path: Path) -> None:
    path = _write_session(tmp_path)
    path.chmod(0o644)  # broaden beyond 0600 -> BadFileMode on load
    audit = _FakeAudit()
    hooks = _FakeHooks()
    resolver = _make_resolver(path, _FakeSession(rows=[]), audit=audit, hooks=hooks)
    with pytest.raises(OperatorSessionBadFileMode):
        await resolver.resolve()
    refused = _refused_calls(audit)
    assert len(refused) == 1
    assert refused[0].subject["reason"] == "bad_file_mode"
    assert len(_refused_hooks(hooks)) == 1


async def test_parent_dir_insecure_emits_fileless_row(tmp_path: Path) -> None:
    path = _write_session(tmp_path)
    path.parent.chmod(0o755)  # group/other-accessible parent -> ParentDirInsecure
    audit = _FakeAudit()
    hooks = _FakeHooks()
    resolver = _make_resolver(path, _FakeSession(rows=[]), audit=audit, hooks=hooks)
    with pytest.raises(OperatorSessionParentDirInsecure):
        await resolver.resolve()
    refused = _refused_calls(audit)
    assert len(refused) == 1
    assert refused[0].subject["reason"] == "parent_dir_insecure"
    assert len(_refused_hooks(hooks)) == 1


async def test_no_machine_id_emits_fileless_machine_id_unavailable(tmp_path: Path) -> None:
    """A machine-id source read failure lands a ``machine_id_unavailable`` row.

    The machine-id is not session-derived, so the row stays file-less rather
    than echoing the (untrusted) session's self-claimed machine_id_hash.
    """
    path = _write_session(tmp_path, user_id=7)
    audit = _FakeAudit()
    hooks = _FakeHooks()
    resolver = DefaultOperatorSessionResolver(
        session_scope=_scope_for(_FakeSession(rows=[])),
        secret_broker=_FakeBroker(),
        machine_id_provider=_NoMachineId(),
        audit_writer=audit,
        hook_dispatcher=hooks,
        host=_HOST,
        session_file_path=path,
    )
    with pytest.raises(OperatorSessionNoMachineId):
        await resolver.resolve()
    refused = _refused_calls(audit)
    assert len(refused) == 1
    assert refused[0].subject["reason"] == "machine_id_unavailable"
    assert refused[0].subject["machine_id_hash"] is None
    assert len(_refused_hooks(hooks)) == 1


async def test_short_pepper_refused_as_pepper_misconfigured(tmp_path: Path) -> None:
    """A short/misconfigured pepper is a TYPED refusal, not a raw ValueError.

    CR-227 round-3 finding 1 (KEYSTONE audit-gap): ``hkdf_expand`` raises a
    bare ``ValueError`` for a pepper below the 32-byte HKDF PRK floor. Before
    this fix that error escaped ``resolve()`` UNTYPED — skipping BOTH the
    ``OPERATOR_SESSION_REFUSED`` audit row AND the CLI refusal UX (raw
    traceback). The resolver now reads the pepper, refuses below-floor lengths
    with the closed-vocab reason ``pepper_misconfigured``, emits EXACTLY one
    file-less refused row + hookpoint, then raises the typed
    ``OperatorSessionPepperMisconfigured``.
    """
    path = _write_session(tmp_path, user_id=7)
    audit = _FakeAudit()
    hooks = _FakeHooks()
    # 31 bytes — one short of the SHA-256 PRK floor.
    short_broker = _FakeBroker(pepper="0" * 31)
    resolver = _make_resolver(
        path, _FakeSession(rows=[]), audit=audit, hooks=hooks, broker=short_broker
    )
    with pytest.raises(OperatorSessionPepperMisconfigured):
        await resolver.resolve()
    refused = _refused_calls(audit)
    assert len(refused) == 1
    assert refused[0].subject["reason"] == "pepper_misconfigured"
    # File-less row: no self-claimed file bytes reach the log.
    assert refused[0].subject["attempted_user_id"] is None
    assert refused[0].subject["machine_id_hash"] is None
    assert len(_refused_hooks(hooks)) == 1


async def test_happy_path_fires_no_refused_hook(tmp_path: Path) -> None:
    path = _write_session(tmp_path, user_id=7)
    session = _FakeSession(rows=[_Row(token_hash=_token_hash(), user_id=7)])
    hooks = _FakeHooks()
    resolver = _make_resolver(path, session, hooks=hooks)
    await resolver.resolve()
    assert not [c for c in hooks.calls if c.name == "operator.session.refused"]


async def test_refusal_fires_refused_hook(tmp_path: Path) -> None:
    path = _write_session(tmp_path, expires_delta=timedelta(hours=-1))
    hooks = _FakeHooks()
    resolver = _make_resolver(path, _FakeSession(rows=[]), hooks=hooks)
    with pytest.raises(OperatorSessionExpired):
        await resolver.resolve()
    assert [c for c in hooks.calls if c.name == "operator.session.refused"]


def test_resolver_satisfies_operator_resolver_protocol(tmp_path: Path) -> None:
    """arch-2 reconcile: DefaultOperatorSessionResolver IS the operator resolver.

    The shipped ``OperatorResolverProtocol`` (PR-S4-1, consumed by the
    Supervisor + daemon stub) is reused verbatim; this asserts structural
    conformance so the wiring in Component F type-checks at runtime too.
    """
    from alfred.supervisor.protocols import OperatorResolverProtocol

    resolver = _make_resolver(tmp_path / "x", _FakeSession(rows=[]))
    assert isinstance(resolver, OperatorResolverProtocol)


def test_compute_machine_id_hash_matches_helper() -> None:
    """Sanity: the test's expected-hash helper matches the production helper."""
    import asyncio as _aio

    digest = _aio.run(compute_machine_id_hash(provider=_StubMachineId(), pepper=_PEPPER.encode()))
    assert digest == _expected_machine_hash()

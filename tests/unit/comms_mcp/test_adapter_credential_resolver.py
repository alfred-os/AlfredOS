"""Tests for the ``CoreAdapterCredentialResolver`` (G6-3, #288).

The resolver is the ONLY component that decrypts a platform credential. It maps
``adapter_id -> secret_id`` via a CLOSED allowlist (``discord -> discord_bot_token``;
an unknown id is a typed refusal, never a ``broker.get(adapter_id)`` passthrough —
the confused-deputy defence), binds the grant to the request's epoch, and dedups on
``(adapter_id, host_restart_seq, epoch)`` (a true replay returns the SAME grant
with ``broker.get`` called EXACTLY ONCE — no decrypt-storm/oracle).

Fail-closed: an unknown adapter / a missing secret / a stale-or-foreign epoch is a
loud, audited refusal, not a grant. NO row ever carries the credential (the
``_FakeAudit`` captures full subjects; a sweep asserts the sentinel value is absent).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import SQLAlchemyError

from alfred.comms_mcp.adapter_credential_protocol import SpawnGrant, SpawnRequest
from alfred.comms_mcp.adapter_credential_resolver import (
    _MAX_GRANTED_CREDENTIALS,
    AdapterCredentialAuditWriteError,
    AdapterCredentialError,
    CoreAdapterCredentialResolver,
)
from alfred.security.secrets import UnknownSecretError

pytestmark = pytest.mark.asyncio

_EPOCH = "0123456789abcdef0123456789abcdef"
_OTHER_EPOCH = "fedcba9876543210fedcba9876543210"
_REQ_ID = "11111111111111111111111111111111"
_REQ_ID2 = "22222222222222222222222222222222"
_FIXED_NOW = datetime(2026, 6, 20, 12, 0, 0, tzinfo=UTC)
_SENTINEL_CRED = "SENTINEL-CREDENTIAL-DO-NOT-LEAK-7f3a"


class _FakeAudit:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    async def append_schema(self, **kwargs: object) -> None:
        self.rows.append(dict(kwargs))


class _FakeBroker:
    """Counts ``get`` calls so the exactly-once-on-replay property is assertable."""

    def __init__(self, *, values: dict[str, str] | None = None) -> None:
        self._values = values if values is not None else {"discord_bot_token": _SENTINEL_CRED}
        self.calls: list[str] = []

    def get(self, name: str) -> str:
        self.calls.append(name)
        try:
            return self._values[name]
        except KeyError as exc:
            raise UnknownSecretError(name) from exc


def _resolver(
    *, broker: _FakeBroker | None = None, audit: _FakeAudit | None = None
) -> tuple[CoreAdapterCredentialResolver, _FakeBroker, _FakeAudit]:
    b = broker if broker is not None else _FakeBroker()
    a = audit if audit is not None else _FakeAudit()
    resolver = CoreAdapterCredentialResolver(
        broker=b,  # structural _SecretBrokerLike
        audit=a,  # structural _AuditWriterLike
        now=lambda: _FIXED_NOW,
    )
    return resolver, b, a


def _request(
    *,
    adapter_id: str = "discord",
    host_restart_seq: int = 0,
    epoch: str = _EPOCH,
    req_id: str = _REQ_ID,
) -> SpawnRequest:
    return SpawnRequest(
        request_id=req_id, adapter_id=adapter_id, host_restart_seq=host_restart_seq, epoch=epoch
    )


# --- Happy path ---------------------------------------------------------------


async def test_resolve_returns_grant_echoing_the_request() -> None:
    resolver, broker, _audit = _resolver()
    grant = await resolver.resolve(_request())
    assert isinstance(grant, SpawnGrant)
    assert grant.request_id == _REQ_ID
    assert grant.adapter_id == "discord"
    assert grant.host_restart_seq == 0
    assert grant.epoch == _EPOCH
    assert grant.credential_material == _SENTINEL_CRED
    assert broker.calls == ["discord_bot_token"]


async def test_resolve_audits_granted_with_no_credential() -> None:
    resolver, _broker, audit = _resolver()
    await resolver.resolve(_request())
    assert len(audit.rows) == 1
    row = audit.rows[0]
    assert row["result"] == "granted"
    assert row["schema_name"] == "CORE_ADAPTER_SPAWN_GRANT_FIELDS"
    subject = row["subject"]
    assert isinstance(subject, dict)
    assert subject["adapter_id"] == "discord"
    assert subject["duplicate"] is False
    assert "credential_material" not in subject
    # The credential never appears in ANY captured audit field.
    assert _SENTINEL_CRED not in repr(audit.rows)


# --- Confused-deputy defence (L4 / adversarial a) -----------------------------


async def test_unknown_adapter_is_refused_without_broker_passthrough() -> None:
    # An adapter kind with no allowlist entry: the resolver MUST NOT call
    # broker.get(adapter_id). ``tui`` is a known adapter_kind but has no credential.
    resolver, broker, audit = _resolver()
    with pytest.raises(AdapterCredentialError):
        await resolver.resolve(_request(adapter_id="tui"))
    assert broker.calls == []  # never reached the broker
    assert audit.rows[-1]["result"] == "refused"


# --- Fail-closed branches -----------------------------------------------------


async def test_missing_secret_is_refused() -> None:
    broker = _FakeBroker(values={})  # discord_bot_token absent
    resolver, _b, audit = _resolver(broker=broker)
    with pytest.raises(AdapterCredentialError):
        await resolver.resolve(_request())
    assert broker.calls == ["discord_bot_token"]
    assert audit.rows[-1]["result"] == "refused"


# --- Dedup / replay (H3 / H4) -------------------------------------------------


async def test_replayed_request_returns_same_grant_broker_called_once() -> None:
    resolver, broker, audit = _resolver()
    first = await resolver.resolve(_request())
    second = await resolver.resolve(_request(req_id=_REQ_ID2))  # same dedup key, new req id
    # Same credential, decrypt happened ONCE (no decrypt-storm/oracle).
    assert second.credential_material == first.credential_material
    assert broker.calls == ["discord_bot_token"]
    # The replay echoes the NEW request's request_id (correlation) but is flagged dup.
    assert second.request_id == _REQ_ID2
    dup_rows = [r for r in audit.rows if r["subject"]["duplicate"] is True]  # type: ignore[index]
    assert len(dup_rows) == 1


async def test_different_host_restart_seq_is_not_a_replay() -> None:
    resolver, broker, _audit = _resolver()
    await resolver.resolve(_request(host_restart_seq=0))
    await resolver.resolve(_request(host_restart_seq=1))
    # A new incarnation is a fresh grant: broker decrypted twice.
    assert broker.calls == ["discord_bot_token", "discord_bot_token"]


async def test_different_epoch_is_not_a_replay() -> None:
    resolver, broker, _audit = _resolver()
    await resolver.resolve(_request(epoch=_EPOCH))
    await resolver.resolve(_request(epoch=_OTHER_EPOCH))
    assert broker.calls == ["discord_bot_token", "discord_bot_token"]


# --- The error never carries raw input (correction C3) ------------------------


async def test_refusal_error_does_not_carry_credential_or_frame() -> None:
    broker = _FakeBroker(values={})
    resolver, _b, _audit = _resolver(broker=broker)
    try:
        await resolver.resolve(_request())
    except AdapterCredentialError as exc:
        assert _SENTINEL_CRED not in str(exc)
        assert _SENTINEL_CRED not in repr(exc)
    else:  # pragma: no cover - the refusal must raise
        pytest.fail("expected AdapterCredentialError")


# --- ERR-G63-01: a failed signed-audit write is a typed, escalatable marker -----


class _RaisingAudit:
    """Audit whose write fails (a signed-audit-write backend fault)."""

    def __init__(self, *, exc: BaseException) -> None:
        self._exc = exc
        self.calls = 0

    async def append_schema(self, **kwargs: object) -> None:
        self.calls += 1
        raise self._exc


async def test_grant_audit_write_failure_raises_typed_marker() -> None:
    # ERR-G63-01: a SQLAlchemyError from the GRANT audit write is wrapped as the
    # DISTINCT AdapterCredentialAuditWriteError (so the runner can ESCALATE it) — never
    # a silent swallow, never the raw backend error escaping unrecognised.
    audit = _RaisingAudit(exc=SQLAlchemyError("db down"))
    resolver = CoreAdapterCredentialResolver(
        broker=_FakeBroker(), audit=audit, now=lambda: _FIXED_NOW
    )
    with pytest.raises(AdapterCredentialAuditWriteError):
        await resolver.resolve(_request())


async def test_audit_write_failure_does_not_leak_credential() -> None:
    audit = _RaisingAudit(exc=SQLAlchemyError("db down"))
    resolver = CoreAdapterCredentialResolver(
        broker=_FakeBroker(), audit=audit, now=lambda: _FIXED_NOW
    )
    try:
        await resolver.resolve(_request())
    except AdapterCredentialAuditWriteError as exc:
        assert _SENTINEL_CRED not in str(exc)
        assert _SENTINEL_CRED not in repr(exc)
    else:  # pragma: no cover - the audit failure must raise
        pytest.fail("expected AdapterCredentialAuditWriteError")


# --- ERR-G63-02: cache only AFTER a successful grant+audit; bounded ------------


async def test_audit_failure_does_not_poison_the_dedup_cache() -> None:
    # ERR-G63-02 ordering: if the GRANT audit fails, the credential is NOT cached —
    # a subsequent legit identical request RE-RESOLVES (broker called again) + re-audits,
    # rather than serving an unaudited/undelivered credential from a poisoned cache.
    broker = _FakeBroker()
    failing_audit = _RaisingAudit(exc=SQLAlchemyError("db down"))
    resolver = CoreAdapterCredentialResolver(
        broker=broker, audit=failing_audit, now=lambda: _FIXED_NOW
    )
    with pytest.raises(AdapterCredentialAuditWriteError):
        await resolver.resolve(_request())
    assert broker.calls == ["discord_bot_token"]  # decrypted once, but NOT cached

    # The leg recovers (a healthy audit). The SAME dedup key must re-resolve, NOT serve
    # a poisoned-cache entry — the broker is called a SECOND time + the row is audited.
    healthy_audit = _FakeAudit()
    resolver._audit = healthy_audit  # the audit backend recovered
    grant = await resolver.resolve(_request())
    assert isinstance(grant, SpawnGrant)
    assert broker.calls == ["discord_bot_token", "discord_bot_token"]  # re-resolved
    assert healthy_audit.rows[-1]["result"] == "granted"
    assert healthy_audit.rows[-1]["subject"]["duplicate"] is False  # type: ignore[index]


async def test_dedup_cache_is_bounded_evicting_oldest() -> None:
    # ERR-G63-02: a restart-storm of distinct (adapter_id, host_restart_seq, epoch)
    # triples cannot grow the cache without limit — it is FIFO-capped.
    resolver, broker, _audit = _resolver()
    total = _MAX_GRANTED_CREDENTIALS + 5
    for seq in range(total):
        await resolver.resolve(_request(host_restart_seq=seq))
    assert broker.calls == ["discord_bot_token"] * total  # each distinct -> a decrypt
    assert len(resolver._granted) == _MAX_GRANTED_CREDENTIALS

    # The OLDEST entries were evicted: re-requesting seq=0 re-resolves (a decrypt), the
    # most-recent entry is still cached (no decrypt).
    before = len(broker.calls)
    await resolver.resolve(_request(host_restart_seq=0))  # evicted -> re-resolve
    assert len(broker.calls) == before + 1
    await resolver.resolve(_request(host_restart_seq=total - 1))  # cached -> NO decrypt
    assert len(broker.calls) == before + 1

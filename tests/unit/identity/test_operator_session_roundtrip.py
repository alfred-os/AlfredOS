"""sec-1 closure: SecretStr file persistence round-trip.

``SecretStr.model_dump_json()`` writes ``"**********"`` for the token, so
a naive dump would make every login produce a file whose next load misses
the DB row (the HMAC of ``"**********"`` is not the HMAC of the real
token). The explicit ``_serialize_to_file_bytes`` /
``_deserialize_from_file_bytes`` helpers call ``get_secret_value()`` so
the raw token survives the write->read cycle. This test pins that.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import SecretStr

from alfred.identity.operator_session import (
    OperatorSessionFile,
    _deserialize_from_file_bytes,
    _serialize_to_file_bytes,
)


def _make() -> OperatorSessionFile:
    issued = datetime(2026, 6, 8, tzinfo=UTC)
    return OperatorSessionFile(
        schema_version=1,
        user_id=42,
        token=SecretStr("the-real-secret-token-value"),
        issued_at=issued,
        expires_at=issued + timedelta(hours=12),
        host="alfred-host",
        machine_id_hash="b" * 64,
    )


def test_roundtrip_preserves_raw_token() -> None:
    original = _make()

    raw_bytes = _serialize_to_file_bytes(original)
    restored = _deserialize_from_file_bytes(raw_bytes)

    assert restored == original
    assert (
        restored.token.get_secret_value()
        == original.token.get_secret_value()
        == "the-real-secret-token-value"
    )


def test_serialized_bytes_contain_raw_token_not_redaction() -> None:
    """The persisted bytes carry the real token, never the redaction mask."""
    raw_bytes = _serialize_to_file_bytes(_make())
    assert b"the-real-secret-token-value" in raw_bytes
    assert b"**********" not in raw_bytes


def test_naive_model_dump_json_redacts_token() -> None:
    """Guards the premise: the default dump WOULD redact (hence the helpers)."""
    dumped = _make().model_dump_json()
    assert "**********" in dumped
    assert "the-real-secret-token-value" not in dumped

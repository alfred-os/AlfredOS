"""``OperatorSessionFile`` Pydantic-model invariants (PR-S4-5 Task 2).

The file-persistence model is named ``OperatorSessionFile`` to
disambiguate from the SQLAlchemy ORM ``OperatorSession`` at
``alfred.memory.models`` (the DB row). The in-memory model keeps the
token in ``SecretStr`` so it redacts in logs; the explicit
serialise/deserialise helpers (sec-1 closure) round-trip the raw value.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr, ValidationError

from alfred.identity.operator_session import OperatorSessionFile

_HASH = "a" * 64


def _make(**overrides: object) -> OperatorSessionFile:
    base: dict[str, object] = {
        "schema_version": 1,
        "user_id": 7,
        "token": SecretStr("tok-raw-value"),
        "issued_at": datetime(2026, 6, 8, tzinfo=UTC),
        "expires_at": datetime(2026, 6, 8, tzinfo=UTC) + timedelta(hours=12),
        "host": "alfred-host",
        "machine_id_hash": _HASH,
    }
    base.update(overrides)
    return OperatorSessionFile(**base)  # type: ignore[arg-type]


def test_schema_version_one_happy_path() -> None:
    assert _make().schema_version == 1


def test_schema_version_two_refused() -> None:
    with pytest.raises(ValidationError):
        _make(schema_version=2)


def test_token_is_secretstr_redacted() -> None:
    session = _make()
    assert str(session.token) == "**********"
    assert session.token.get_secret_value() == "tok-raw-value"


def test_frozen_model_refuses_mutation() -> None:
    session = _make()
    with pytest.raises(ValidationError):
        session.host = "other"  # type: ignore[misc]


def test_extra_field_forbidden() -> None:
    with pytest.raises(ValidationError):
        _make(unexpected="x")


def test_expires_at_not_after_issued_at_refused() -> None:
    issued = datetime(2026, 6, 8, tzinfo=UTC)
    with pytest.raises(ValidationError, match="expires_at"):
        _make(issued_at=issued, expires_at=issued)


def test_machine_id_hash_length_validator() -> None:
    with pytest.raises(ValidationError):
        _make(machine_id_hash="a" * 63)
    with pytest.raises(ValidationError):
        _make(machine_id_hash="a" * 65)

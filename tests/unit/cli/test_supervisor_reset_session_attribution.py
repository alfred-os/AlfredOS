"""``alfred supervisor reset`` session attribution (#153, Task 22).

The Slice-3 ``_resolve_operator_user_id`` env/getlogin/getpwuid fallback is
replaced by the session-backed resolver. When no session is present the
command refuses with ``t("supervisor.breaker.reset.refused.not_logged_in")``
and emits ``SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS(reason=...)``. With a
valid session the proposal payload carries the canonical ``User.id``.
"""

from __future__ import annotations

from typing import Any

import pytest
import typer

from alfred.cli import supervisor as sup
from alfred.identity.operator_session import (
    OperatorSessionExpired,
    OperatorSessionMissing,
    OperatorSessionTimeout,
)


class _OkResolver:
    async def resolve(self) -> str:
        return "42"


class _RaisingResolver:
    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    async def resolve(self) -> str:
        raise self._exc


def test_slice3_fallback_deleted() -> None:
    """The OS-account fallback function is gone (Task 23 grep verification)."""
    assert not hasattr(sup, "_resolve_operator_user_id")


def test_reset_with_session_carries_canonical_user_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sup, "_build_operator_resolver", lambda: _OkResolver())
    assert sup._resolve_operator_session_or_refuse(component_id="c") == "42"


@pytest.mark.parametrize(
    ("exc", "reason", "exit_code"),
    [
        (OperatorSessionMissing("x"), "operator_session_missing", 1),
        (OperatorSessionExpired("x"), "operator_session_expired", 1),
        (OperatorSessionTimeout("x"), "operator_session_resolver_timeout", 1),
    ],
)
def test_reset_refuses_when_resolver_raises(
    monkeypatch: pytest.MonkeyPatch,
    exc: Exception,
    reason: str,
    exit_code: int,
) -> None:
    monkeypatch.setattr(sup, "_build_operator_resolver", lambda: _RaisingResolver(exc))
    events: list[dict[str, Any]] = []

    class _FakeLog:
        def warning(self, _event: str, **kwargs: Any) -> None:
            events.append(kwargs)

    monkeypatch.setattr(sup, "_log", _FakeLog())
    with pytest.raises(typer.Exit) as got:
        sup._resolve_operator_session_or_refuse(component_id="c")
    assert got.value.exit_code == exit_code
    refused = [
        e for e in events if e.get("schema_name") == "SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS"
    ]
    assert refused and refused[-1]["reason"] == reason

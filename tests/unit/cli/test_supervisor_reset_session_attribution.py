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
    OperatorSessionBadFileMode,
    OperatorSessionBadFileOwner,
    OperatorSessionError,
    OperatorSessionExpired,
    OperatorSessionHostMismatch,
    OperatorSessionMachineIdMismatch,
    OperatorSessionMalformed,
    OperatorSessionMissing,
    OperatorSessionNoMachineId,
    OperatorSessionParentDirInsecure,
    OperatorSessionParentDirNotOwned,
    OperatorSessionPepperMisconfigured,
    OperatorSessionRevoked,
    OperatorSessionTimeout,
    OperatorSessionTokenUnknown,
    OperatorSessionTokenUserMismatch,
    OperatorSessionUserRevoked,
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


# CR-227 round-2 finding 1: every concrete ``OperatorSessionError`` subclass
# maps to its OWN audit reason — coercing host_mismatch / machine_mismatch /
# token_unknown / token_user_mismatch / user_revoked / bad_file_mode / etc. to
# ``operator_session_missing`` mislabels the forensic trail and weakens hard
# rule #7. The full subclass matrix is asserted here.
@pytest.mark.parametrize(
    ("exc", "reason", "exit_code"),
    [
        (OperatorSessionMissing("x"), "operator_session_missing", 1),
        (OperatorSessionExpired("x"), "operator_session_expired", 1),
        (OperatorSessionTimeout("x"), "operator_session_resolver_timeout", 1),
        (OperatorSessionHostMismatch("x"), "operator_session_host_mismatch", 1),
        (OperatorSessionMachineIdMismatch("x"), "operator_session_machine_mismatch", 1),
        (OperatorSessionTokenUnknown("x"), "operator_session_token_unknown", 1),
        (OperatorSessionTokenUserMismatch("x"), "operator_session_token_user_mismatch", 1),
        (OperatorSessionUserRevoked("x"), "operator_session_user_revoked", 1),
        (OperatorSessionRevoked("x"), "operator_session_revoked", 1),
        (OperatorSessionBadFileMode("x"), "operator_session_bad_file_mode", 1),
        (OperatorSessionBadFileOwner("x"), "operator_session_bad_file_owner", 1),
        (OperatorSessionMalformed("x"), "operator_session_malformed", 1),
        (OperatorSessionParentDirInsecure("x"), "operator_session_parent_dir_insecure", 1),
        (OperatorSessionParentDirNotOwned("x"), "operator_session_parent_dir_not_owned", 1),
        (OperatorSessionNoMachineId("x"), "operator_session_no_machine_id", 1),
        # CR-227 round-3 finding 1: the short/misconfigured-pepper KEYSTONE
        # audit-gap subclass maps to its OWN reason, never silently to missing.
        (
            OperatorSessionPepperMisconfigured("x"),
            "operator_session_pepper_misconfigured",
            1,
        ),
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


def test_reset_unknown_subclass_does_not_coerce_to_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A future/unmapped ``OperatorSessionError`` must NOT be labelled 'missing'.

    CR-227 round-2 finding 1: defaulting unknown subclasses to
    ``operator_session_missing`` ("not logged in") drifts forensics. An
    unmapped subclass gets a distinct ``operator_session_unknown`` reason
    instead of impersonating the missing-session disposition.
    """

    class _FutureRefusal(OperatorSessionError):  # noqa: N818 -- test-only subclass
        """An OperatorSessionError subclass the supervisor map has not seen."""

    monkeypatch.setattr(
        sup, "_build_operator_resolver", lambda: _RaisingResolver(_FutureRefusal("x"))
    )
    events: list[dict[str, Any]] = []

    class _FakeLog:
        def warning(self, _event: str, **kwargs: Any) -> None:
            events.append(kwargs)

    monkeypatch.setattr(sup, "_log", _FakeLog())
    with pytest.raises(typer.Exit):
        sup._resolve_operator_session_or_refuse(component_id="c")
    refused = [
        e for e in events if e.get("schema_name") == "SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS"
    ]
    assert refused and refused[-1]["reason"] == "operator_session_unknown"

"""``alfred login`` / ``logout`` / ``whoami`` impl coroutines (Tasks 14-19).

The ``_impl`` coroutines take an ``OperatorSessionDeps`` bundle so every
collaborator (broker, audit, hooks, machine-id, DB ops) is a fake — no
Postgres, no real ``HOME``. Output and exit codes are asserted directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import typer
from pydantic import SecretStr

from alfred.cli.operator_session import (
    OperatorSessionDeps,
    login_impl,
    logout_impl,
    parse_expires_in,
    whoami_impl,
)
from alfred.cli.operator_session import (
    _PickerUser as PickerUser,
)
from alfred.identity.operator_session import (
    OperatorSessionFile,
    compute_machine_id_hash,
    write_session_file,
)

_PEPPER = "0" * 64
_HOST = "alfred-host"


@dataclass
class _Broker:
    def get(self, name: str) -> str:
        assert name == "audit.hash_pepper"
        return _PEPPER


@dataclass
class _MachineId:
    raw: bytes = b"machine-raw"

    async def read_raw(self) -> bytes:
        return self.raw


class _NoMachineId:
    async def read_raw(self) -> bytes:
        from alfred.identity.operator_session import OperatorSessionNoMachineId

        raise OperatorSessionNoMachineId("no machine id")


@dataclass
class _Audit:
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def append_schema(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


@dataclass
class _Hooks:
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    async def __call__(self, name: str, payload: dict[str, Any]) -> None:
        self.calls.append((name, payload))


@dataclass
class _DB:
    users_by_slug: dict[str, PickerUser] = field(default_factory=dict)
    users_by_id: dict[int, PickerUser] = field(default_factory=dict)
    inserted: list[dict[str, Any]] = field(default_factory=list)
    revoked: list[str] = field(default_factory=list)

    async def list_users(self) -> list[PickerUser]:
        return list(self.users_by_id.values())

    async def lookup_by_slug(self, slug: str) -> PickerUser | None:
        return self.users_by_slug.get(slug)

    async def lookup_by_id(self, uid: int) -> PickerUser | None:
        return self.users_by_id.get(uid)

    async def insert(self, **kwargs: Any) -> None:
        self.inserted.append(kwargs)

    async def revoke(self, token_hash: str) -> None:
        self.revoked.append(token_hash)


def _user(uid: int = 7, slug: str = "alice") -> PickerUser:
    return PickerUser(user_id=uid, slug=slug, display_name=f"User {uid}", language="en")


def _deps(
    tmp_path: Path,
    *,
    db: _DB | None = None,
    audit: _Audit | None = None,
    hooks: _Hooks | None = None,
    machine: Any = None,
) -> OperatorSessionDeps:
    db = db or _DB(users_by_slug={"alice": _user()}, users_by_id={7: _user()})
    return OperatorSessionDeps(
        secret_broker=_Broker(),
        audit_writer=audit or _Audit(),
        hook_dispatcher=hooks or _Hooks(),
        machine_id_provider=machine or _MachineId(),
        host=_HOST,
        session_file_path=tmp_path / ".config" / "alfred" / "session",
        list_users=db.list_users,
        lookup_user_by_slug=db.lookup_by_slug,
        lookup_user_by_id=db.lookup_by_id,
        insert_session_row=db.insert,
        revoke_session_row=db.revoke,
        now_fn=lambda: datetime(2026, 6, 8, 12, 0, tzinfo=UTC),
    )


async def _seed_session_file(deps: OperatorSessionDeps, *, user_id: int = 7) -> None:
    pepper = _PEPPER.encode()
    machine_hash = await compute_machine_id_hash(provider=_MachineId(), pepper=pepper)
    now = deps.now_fn()
    write_session_file(
        deps.session_file_path,
        OperatorSessionFile(
            schema_version=1,
            user_id=user_id,
            token=SecretStr("tok"),
            issued_at=now,
            expires_at=now + timedelta(hours=12),
            host=_HOST,
            machine_id_hash=machine_hash,
        ),
    )


# --------------------------------------------------------------------------- #
# parse_expires_in
# --------------------------------------------------------------------------- #


def test_parse_expires_in_default() -> None:
    assert parse_expires_in(None) == timedelta(hours=12)


@pytest.mark.parametrize("raw", ["1h", "24h", "7d"])
def test_parse_expires_in_in_range(raw: str) -> None:
    parse_expires_in(raw)  # no raise


@pytest.mark.parametrize("raw", ["30m", "8d", "0h", "garbage", "10"])
def test_parse_expires_in_out_of_range_raises(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_expires_in(raw)


# --------------------------------------------------------------------------- #
# login
# --------------------------------------------------------------------------- #


async def test_login_happy_path(tmp_path: Path) -> None:
    db = _DB(users_by_slug={"alice": _user()}, users_by_id={7: _user()})
    audit = _Audit()
    hooks = _Hooks()
    deps = _deps(tmp_path, db=db, audit=audit, hooks=hooks)
    await login_impl(deps, as_user="alice", expires_in=None, refresh=False)

    assert (deps.session_file_path.stat().st_mode & 0o777) == 0o600
    assert len(db.inserted) == 1
    created = next(c for c in audit.calls if c["schema_name"] == "OPERATOR_SESSION_CREATED_FIELDS")
    assert created["subject"]["via"] == "login"
    assert [n for n, _ in hooks.calls] == ["operator.session.created"]


async def test_login_user_not_found(tmp_path: Path) -> None:
    deps = _deps(tmp_path, db=_DB())
    with pytest.raises(typer.Exit) as exc:
        await login_impl(deps, as_user="ghost", expires_in=None, refresh=False)
    assert exc.value.exit_code == 1


async def test_login_expires_in_out_of_range(tmp_path: Path) -> None:
    deps = _deps(tmp_path)
    with pytest.raises(typer.Exit) as exc:
        await login_impl(deps, as_user="alice", expires_in="30m", refresh=False)
    assert exc.value.exit_code == 2


async def test_login_no_machine_id(tmp_path: Path) -> None:
    deps = _deps(tmp_path, machine=_NoMachineId())
    with pytest.raises(typer.Exit) as exc:
        await login_impl(deps, as_user="alice", expires_in=None, refresh=False)
    assert exc.value.exit_code == 1


async def test_login_refresh_no_session(tmp_path: Path) -> None:
    deps = _deps(tmp_path)
    with pytest.raises(typer.Exit) as exc:
        await login_impl(deps, as_user=None, expires_in=None, refresh=True)
    assert exc.value.exit_code == 1


async def test_login_refresh_rotates(tmp_path: Path) -> None:
    deps = _deps(tmp_path)
    await _seed_session_file(deps)
    audit = _Audit()
    deps2 = _deps(tmp_path, audit=audit)
    await login_impl(deps2, as_user=None, expires_in=None, refresh=True)
    created = next(c for c in audit.calls if c["schema_name"] == "OPERATOR_SESSION_CREATED_FIELDS")
    assert created["subject"]["via"] == "refresh"


async def test_login_bare_zero_users(tmp_path: Path) -> None:
    deps = _deps(tmp_path, db=_DB())
    with pytest.raises(typer.Exit) as exc:
        await login_impl(deps, as_user=None, expires_in=None, refresh=False)
    assert exc.value.exit_code == 1


async def test_login_bare_single_user_autoselect(tmp_path: Path) -> None:
    db = _DB(users_by_slug={"alice": _user()}, users_by_id={7: _user()})
    deps = _deps(tmp_path, db=db)
    await login_impl(deps, as_user=None, expires_in=None, refresh=False)
    assert len(db.inserted) == 1


async def test_login_bare_multi_user_non_tty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = _DB(
        users_by_slug={"a": _user(7, "a"), "b": _user(8, "b")},
        users_by_id={7: _user(7, "a"), 8: _user(8, "b")},
    )
    deps = _deps(tmp_path, db=db)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(typer.Exit) as exc:
        await login_impl(deps, as_user=None, expires_in=None, refresh=False)
    assert exc.value.exit_code == 2


async def test_login_bare_multi_user_tty_picker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = _DB(
        users_by_slug={"a": _user(7, "a"), "b": _user(8, "b")},
        users_by_id={7: _user(7, "a"), 8: _user(8, "b")},
    )
    deps = _deps(tmp_path, db=db)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.prompt", lambda *_a, **_k: 2)
    await login_impl(deps, as_user=None, expires_in=None, refresh=False)
    assert db.inserted[0]["user_id"] == 8


async def test_login_bare_multi_user_tty_picker_out_of_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = _DB(
        users_by_slug={"a": _user(7, "a"), "b": _user(8, "b")},
        users_by_id={7: _user(7, "a"), 8: _user(8, "b")},
    )
    deps = _deps(tmp_path, db=db)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.prompt", lambda *_a, **_k: 99)
    with pytest.raises(typer.Exit) as exc:
        await login_impl(deps, as_user=None, expires_in=None, refresh=False)
    assert exc.value.exit_code == 2


async def test_login_refresh_user_gone(tmp_path: Path) -> None:
    """Refresh when the session's user was removed -> user_not_found."""
    deps = _deps(tmp_path)
    await _seed_session_file(deps, user_id=7)
    deps2 = _deps(tmp_path, db=_DB())  # empty registry
    with pytest.raises(typer.Exit) as exc:
        await login_impl(deps2, as_user=None, expires_in=None, refresh=True)
    assert exc.value.exit_code == 1


async def test_login_overwrite_declined(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    deps = _deps(tmp_path)
    await _seed_session_file(deps, user_id=7)
    db = _DB(users_by_slug={"bob": _user(9, "bob")}, users_by_id={9: _user(9, "bob")})
    deps2 = _deps(tmp_path, db=db)
    monkeypatch.setattr("typer.confirm", lambda *_a, **_k: False)
    with pytest.raises(typer.Exit) as exc:
        await login_impl(deps2, as_user="bob", expires_in=None, refresh=False)
    assert exc.value.exit_code == 1


# --------------------------------------------------------------------------- #
# logout
# --------------------------------------------------------------------------- #


async def test_logout_happy_path(tmp_path: Path) -> None:
    deps = _deps(tmp_path)
    await _seed_session_file(deps)
    db = _DB()
    audit = _Audit()
    hooks = _Hooks()
    deps2 = _deps(tmp_path, db=db, audit=audit, hooks=hooks)
    await logout_impl(deps2)
    assert not deps2.session_file_path.exists()
    assert len(db.revoked) == 1
    revoked = next(c for c in audit.calls if c["schema_name"] == "OPERATOR_SESSION_REVOKED_FIELDS")
    assert revoked["subject"]["via"] == "logout"
    assert [n for n, _ in hooks.calls] == ["operator.session.revoked"]


async def test_logout_no_session(tmp_path: Path) -> None:
    deps = _deps(tmp_path)
    with pytest.raises(typer.Exit) as exc:
        await logout_impl(deps)
    assert exc.value.exit_code == 1


async def test_logout_bad_file_cleanup(tmp_path: Path) -> None:
    """A session file present but unloadable (bad mode) is removed + refused."""
    deps = _deps(tmp_path)
    await _seed_session_file(deps)
    deps.session_file_path.chmod(0o644)  # break the mode -> BadFileMode on load
    with pytest.raises(typer.Exit) as exc:
        await logout_impl(deps)
    assert exc.value.exit_code == 1
    assert not deps.session_file_path.exists()


def test_session_file_path_under_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from alfred.cli.operator_session import _session_file_path

    monkeypatch.setenv("HOME", str(tmp_path))
    path = _session_file_path()
    assert path.name == "session"
    assert path.parent.name == "alfred"


# --------------------------------------------------------------------------- #
# whoami
# --------------------------------------------------------------------------- #


async def test_whoami_happy_path(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    deps = _deps(tmp_path)
    await _seed_session_file(deps)
    await whoami_impl(deps)
    out = capsys.readouterr().out
    assert "User 7" in out
    assert "tok" not in out  # raw token never printed


async def test_whoami_no_session(tmp_path: Path) -> None:
    deps = _deps(tmp_path)
    with pytest.raises(typer.Exit) as exc:
        await whoami_impl(deps)
    assert exc.value.exit_code == 1


def test_resolve_operator_user_id_or_refuse_happy(monkeypatch: pytest.MonkeyPatch) -> None:
    from alfred.cli import operator_session as mod

    class _Ok:
        async def resolve(self) -> str:
            return "9"

    monkeypatch.setattr(mod, "_build_operator_resolver", lambda: _Ok())
    assert (
        mod.resolve_operator_user_id_or_refuse(refusal_key="cli.config.set.refused.not_logged_in")
        == "9"
    )


def test_resolve_operator_user_id_or_refuse_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    from alfred.cli import operator_session as mod
    from alfred.identity.operator_session import OperatorSessionMissing

    class _Missing:
        async def resolve(self) -> str:
            raise OperatorSessionMissing("no file")

    monkeypatch.setattr(mod, "_build_operator_resolver", lambda: _Missing())
    with pytest.raises(typer.Exit) as exc:
        mod.resolve_operator_user_id_or_refuse(refusal_key="cli.config.set.refused.not_logged_in")
    assert exc.value.exit_code == 1


def test_resolve_operator_user_id_or_refuse_no_recovery_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refusal key without a ``.recovery`` companion still refuses cleanly."""
    from alfred.cli import operator_session as mod
    from alfred.identity.operator_session import OperatorSessionMissing

    class _Missing:
        async def resolve(self) -> str:
            raise OperatorSessionMissing("no file")

    monkeypatch.setattr(mod, "_build_operator_resolver", lambda: _Missing())
    with pytest.raises(typer.Exit) as exc:
        mod.resolve_operator_user_id_or_refuse(refusal_key="some.key.without.recovery.companion")
    assert exc.value.exit_code == 1


async def test_whoami_expired(tmp_path: Path) -> None:
    deps = _deps(tmp_path)
    pepper = _PEPPER.encode()
    machine_hash = await compute_machine_id_hash(provider=_MachineId(), pepper=pepper)
    past = deps.now_fn() - timedelta(hours=2)
    write_session_file(
        deps.session_file_path,
        OperatorSessionFile(
            schema_version=1,
            user_id=7,
            token=SecretStr("tok"),
            issued_at=past - timedelta(minutes=1),
            expires_at=past,
            host=_HOST,
            machine_id_hash=machine_hash,
        ),
    )
    with pytest.raises(typer.Exit) as exc:
        await whoami_impl(deps)
    assert exc.value.exit_code == 1

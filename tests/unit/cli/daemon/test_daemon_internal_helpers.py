"""Coverage for the daemon's internal helpers (#174 Task H.3).

These exercise the small adapter + fallback helpers that the boot path
relies on but that the higher-level command tests monkeypatch away.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from alfred.cli.daemon import _audit_fallback, _commands, _gate_boot
from alfred.cli.daemon._daemon_pidfile import DaemonPidFileError, load_pidfile

# --- _audit_fallback -------------------------------------------------------


def test_fallback_database_url_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALFRED_DATABASE_URL", raising=False)
    assert _audit_fallback.fallback_database_url() == _audit_fallback._DEFAULT_DATABASE_URL


def test_fallback_database_url_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DATABASE_URL", "postgresql+asyncpg://x:y@h:5432/db")
    assert _audit_fallback.fallback_database_url() == "postgresql+asyncpg://x:y@h:5432/db"


def test_build_fallback_session_scope_returns_callable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ALFRED_DATABASE_URL", "postgresql+asyncpg://x:y@h:5432/db")
    scope = _audit_fallback.build_fallback_session_scope()
    assert callable(scope)
    # Invoking the factory builds the async context manager (no connect yet),
    # covering the inner _scope closure.
    cm = scope()
    assert hasattr(cm, "__aenter__")


def test_build_boot_audit_writer_uses_explicit_scope() -> None:
    sentinel = object()
    writer = _audit_fallback.build_boot_audit_writer(
        session_scope_factory=lambda: sentinel  # type: ignore[arg-type,return-value]
    )
    assert writer is not None


def test_build_boot_audit_writer_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ALFRED_DATABASE_URL", "postgresql+asyncpg://x:y@h:5432/db")
    writer = _audit_fallback.build_boot_audit_writer()
    assert writer is not None


# --- _daemon_pidfile malformed-shape arm -----------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.O_NOFOLLOW (not exposed by CPython on Windows)",
)
def test_load_pidfile_refuses_missing_json_field(tmp_path: Path) -> None:
    """A JSON object missing a required field → DaemonPidFileError."""
    pf = tmp_path / "daemon.pid"
    pf.write_text('{"pid": 1}', encoding="utf-8")  # missing boot_id/started_at/hostname
    pf.chmod(0o600)
    with pytest.raises(DaemonPidFileError):
        load_pidfile(pf)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.O_NOFOLLOW (not exposed by CPython on Windows)",
)
def test_load_pidfile_refuses_non_int_pid(tmp_path: Path) -> None:
    pf = tmp_path / "daemon.pid"
    pf.write_text(
        '{"pid": "notanint", "boot_id": "x", "started_at": "t", "hostname": "h"}',
        encoding="utf-8",
    )
    pf.chmod(0o600)
    with pytest.raises(DaemonPidFileError):
        load_pidfile(pf)


# --- _commands small adapters ----------------------------------------------


async def test_stub_operator_resolver_returns_synthetic_id() -> None:
    resolver = _commands._StubOperatorResolver()
    assert await resolver.resolve() == _commands._STUB_OPERATOR_ID


def test_current_pid_is_our_pid() -> None:
    assert _commands._current_pid() == os.getpid()


def test_supervisor_boot_gate_available_delegates_to_public_method() -> None:
    """The adapter re-exports the wrapped gate's PUBLIC availability method."""

    class _Gate:
        def is_backing_store_available(self) -> bool:
            return True

    adapter = _gate_boot._SupervisorBootGate(_Gate())
    assert adapter.is_backing_store_available() is True


def test_supervisor_boot_gate_unavailable_delegates_to_public_method() -> None:
    class _Gate:
        def is_backing_store_available(self) -> bool:
            return False

    adapter = _gate_boot._SupervisorBootGate(_Gate())
    assert adapter.is_backing_store_available() is False


def test_supervisor_boot_gate_fails_loud_when_method_absent() -> None:
    """A wrapped gate WITHOUT the public method raises — never fails OPEN.

    arch-222-1 / err-001 / test-engineer Critical coverage gap: the previous
    ``getattr(gate, "_fail_closed", False)`` shape silently reported
    "available" when the attribute was absent (a fail-OPEN trust-boundary
    default). Delegating to the public method makes a missing contract a
    loud ``AttributeError`` instead.
    """

    class _GateMissingMethod:
        pass

    adapter = _gate_boot._SupervisorBootGate(_GateMissingMethod())  # type: ignore[arg-type]
    with pytest.raises(AttributeError):
        adapter.is_backing_store_available()


async def test_boot_handshake_runs_healthcheck(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []

    async def _fake_healthcheck(scope: Any) -> None:
        calls.append(scope)

    monkeypatch.setattr("alfred.memory.db.healthcheck", _fake_healthcheck)
    sentinel_scope = object()
    handshake = _gate_boot._BootHandshake(sentinel_scope)  # type: ignore[arg-type]
    assert await handshake.is_backing_store_available() is True
    assert calls == [sentinel_scope]


def test_build_boot_handshake_returns_handshake() -> None:
    h = _gate_boot.build_boot_handshake(lambda: None)  # type: ignore[arg-type, return-value]
    assert isinstance(h, _gate_boot._BootHandshake)


def test_snapshot_failure_helper() -> None:
    failure = _commands._snapshot_failure()
    assert failure.failure_reason == "snapshot_ref_init_failed"


# --- read_state_git_head_sha against a real temp git repo ------------------


def test_read_state_git_head_sha_empty_repo(tmp_path: Path) -> None:
    """A bare repo with no commits → the unknown sentinel."""
    repo = tmp_path / "state.git"
    subprocess.run(["git", "init", "--bare", str(repo)], check=True)
    assert _commands.read_state_git_head_sha(repo) == _commands._STATE_GIT_HEAD_UNKNOWN


def test_read_state_git_head_sha_missing_path(tmp_path: Path) -> None:
    assert (
        _commands.read_state_git_head_sha(tmp_path / "absent") == _commands._STATE_GIT_HEAD_UNKNOWN
    )


def test_read_state_git_head_sha_with_commit(tmp_path: Path) -> None:
    """A repo with a commit → the real 40-char SHA."""
    repo = tmp_path / "work"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
    (repo / "f").write_text("x", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "c"], check=True)
    sha = _commands.read_state_git_head_sha(repo)
    assert sha != _commands._STATE_GIT_HEAD_UNKNOWN
    assert len(sha) == 40


def test_read_state_git_head_sha_oserror(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """An OSError launching git → the unknown sentinel."""

    def _raise(*_args: object, **_kwargs: object) -> object:
        raise OSError("no git")

    monkeypatch.setattr(subprocess, "run", _raise)
    assert _commands.read_state_git_head_sha(tmp_path) == _commands._STATE_GIT_HEAD_UNKNOWN


def test_snapshot_detail_falls_back_when_the_failure_is_another_member() -> None:
    """The ``isinstance`` narrowing in ``_snapshot_detail`` is documented as a device rather
    than a real branch — the probe only ever hands it a ``SnapshotRefInitFailedFailure``. But
    it deliberately fails SOFT (``"unknown"``) instead of raising, because a boot refusal must
    never be preempted by a formatting error on the refusal message itself. Pin the soft arm so
    that guarantee survives the union growing a 21st member.
    """
    from alfred.cli.daemon._failures import CapabilityGateHandshakeFailedFailure

    other = CapabilityGateHandshakeFailedFailure(backing_store_kind="postgres")
    assert _commands._snapshot_detail(other) == "unknown"


def test_handshake_detail_falls_back_when_the_failure_is_another_member() -> None:
    """Twin of the above for ``_handshake_detail`` — same soft-fail contract, opposite member."""
    from alfred.cli.daemon._failures import SnapshotRefInitFailedFailure

    other = SnapshotRefInitFailedFailure(detail_redacted="FileNotFoundError")
    assert _commands._handshake_detail(other) == "unknown"

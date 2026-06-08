"""Shared fixtures for the daemon CLI unit tests (#174).

The success-path tests need every external dependency of ``start_daemon``
(audit writer, capability gate, session scope, state.git head reader,
operator resolver, Supervisor) replaced with in-memory fakes so the boot
sequence runs without Postgres / state.git / an event-loop-bound
supervisor.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest


class FakeAuditWriter:
    """Records every ``append_schema`` call for assertion."""

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def append_schema(self, **kw: Any) -> None:
        self.rows.append(kw)

    def rows_for(self, schema_name: str) -> list[dict[str, Any]]:
        return [r for r in self.rows if r.get("schema_name") == schema_name]


class FakeSupervisor:
    """No-op Supervisor double — records construction + lifecycle calls."""

    last_instance: FakeSupervisor | None = None

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.started = False
        self.stopped = False
        FakeSupervisor.last_instance = self

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True


@pytest.fixture
def fake_audit_writer() -> FakeAuditWriter:
    return FakeAuditWriter()


@pytest.fixture
def boot_success_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fake_audit_writer: FakeAuditWriter,
) -> FakeAuditWriter:
    """Patch every external builder so the boot success path runs in-memory.

    Returns the recording audit writer so tests can assert on the rows.
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.delenv("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", raising=False)
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent-etc",
    )
    # CR #6: the snapshot-ref probe reads ``Settings.policies_path`` (anchored
    # at /etc/alfred), NOT a CWD-relative ``config/policies.yaml``. Point it at
    # a real file under tmp so the boot-success path passes regardless of the
    # test runner's CWD — including the production-environment success tests
    # that would otherwise refuse on an absent /etc/alfred/policies.yaml.
    policies_file = tmp_path / "policies.yaml"
    policies_file.write_text("schema_version: 1\n", encoding="utf-8")
    monkeypatch.setenv("ALFRED_POLICIES_PATH", str(policies_file))

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: fake_audit_writer,
    )
    # sec-004 (INTENTIONAL launcher-probe bypass): the shipped PR-S4-1
    # launcher stub returns ``_STUB_SIGNATURE`` and so REFUSES the boot in
    # production — that production refusal is the real, security-required
    # behaviour and is asserted directly by
    # ``test_probe_launcher_not_policy_resolving.py`` (the prod-refusal
    # test). It must NOT be weakened. Boot-SUCCESS tests that run with
    # ALFRED_ENVIRONMENT=production (e.g. the source-conflict test) only need
    # to isolate their assertion from that refusal, so this fixture pins the
    # launcher probe to "passing" (standing in for a genuine
    # policy-resolving launcher PR-S4-6 will ship). Probe-refusal tests
    # monkeypatch this back to the failure they exercise.
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.probe_launcher_policy_resolving",
        _make_async(lambda **_kw: None),
    )
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_session_scope",
        lambda _settings: lambda: None,
    )
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_handshake",
        lambda _scope: _HealthyGate(),
    )
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_gate",
        _make_async(lambda _settings: _SyncGate()),
    )
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.read_state_git_head_sha",
        lambda _path: "deadbeefcafe",
    )
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.Supervisor",
        FakeSupervisor,
    )
    # Park-for-shutdown returns immediately so the command does not block.
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.wait_for_shutdown",
        _make_async_noop(),
    )
    # PID file goes under tmp so the test never touches ~/.run.
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.default_pidfile_path",
        lambda: tmp_path / "daemon.pid",
    )
    return fake_audit_writer


class _HealthyGate:
    """Async handshake double for probe (c)."""

    async def is_backing_store_available(self) -> bool:
        return True


class _SyncGate:
    """Sync supervisor-gate double."""

    def is_backing_store_available(self) -> bool:
        return True


def _make_async(fn: Any) -> Any:
    async def _f(*args: Any, **kwargs: Any) -> Any:
        return fn(*args, **kwargs)

    return _f


def _make_async_noop() -> Any:
    async def _f(*_args: Any, **_kwargs: Any) -> None:
        return None

    return _f

"""Each probe refusal arm of ``alfred daemon start`` (#174 coverage).

arch-001 closure: every refusal invokes the daemon.boot.failed hookpoint
before the audit emit + exit.
"""

from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.cli.daemon._failures import (
    CapabilityGateHandshakeFailedFailure,
    LauncherNotPolicyResolvingFailure,
    SnapshotRefInitFailedFailure,
)

from .conftest import FakeAuditWriter


def _async_return(value: Any):  # type: ignore[no-untyped-def]
    async def _f(*_args: Any, **_kwargs: Any) -> Any:
        return value

    return _f


def test_launcher_refusal(
    monkeypatch: pytest.MonkeyPatch, boot_success_env: FakeAuditWriter
) -> None:
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.probe_launcher_policy_resolving",
        _async_return(LauncherNotPolicyResolvingFailure(probe_response="stub")),
    )
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert _reason(boot_success_env) == "launcher_not_policy_resolving"


def test_snapshot_refusal(
    monkeypatch: pytest.MonkeyPatch, boot_success_env: FakeAuditWriter
) -> None:
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.probe_snapshot_ref_init",
        _async_return((SnapshotRefInitFailedFailure(detail_redacted="ScannerError"), None)),
    )
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert _reason(boot_success_env) == "snapshot_ref_init_failed"


def test_capability_gate_refusal(
    monkeypatch: pytest.MonkeyPatch, boot_success_env: FakeAuditWriter
) -> None:
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.probe_capability_gate_handshake",
        _async_return(CapabilityGateHandshakeFailedFailure(backing_store_kind="postgres")),
    )
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert _reason(boot_success_env) == "capability_gate_handshake_failed"


def test_refusal_exits_3_when_audit_unwritable(
    monkeypatch: pytest.MonkeyPatch, boot_success_env: FakeAuditWriter
) -> None:
    """sec-003 on a probe refusal: audit-write failure → exit 3."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.probe_capability_gate_handshake",
        _async_return(CapabilityGateHandshakeFailedFailure(backing_store_kind="postgres")),
    )

    async def _boom(**_kw: object) -> None:
        raise RuntimeError("pg down")

    monkeypatch.setattr(boot_success_env, "append_schema", _boom)
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 3


def _reason(writer: FakeAuditWriter) -> str | None:
    for r in writer.rows_for("DAEMON_BOOT_FAILED_FIELDS"):
        subject = r["subject"]
        if isinstance(subject, dict):
            return subject["failure_reason"]
    return None

"""Each probe refusal arm of ``alfred daemon start`` (#174 coverage).

arch-001 closure: every refusal invokes the daemon.boot.failed hookpoint
before the audit emit + exit.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy.exc import OperationalError
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


def test_snapshot_refusal_when_ref_is_none(
    monkeypatch: pytest.MonkeyPatch, boot_success_env: FakeAuditWriter
) -> None:
    """test-engineer LOW: probe returns ``(None, None)`` → _snapshot_failure refuses.

    Drives the ``or snapshot_ref is None`` disjunct of the boot
    orchestration's snapshot guard through the command path (previously only
    ``_snapshot_failure()`` was unit-tested in isolation).
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.probe_snapshot_ref_init",
        _async_return((None, None)),
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
    """sec-003 on a probe refusal: a persistence-family failure → exit 3."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.probe_capability_gate_handshake",
        _async_return(CapabilityGateHandshakeFailedFailure(backing_store_kind="postgres")),
    )

    async def _boom(**_kw: object) -> None:
        # err-002: a DB-write failure (SQLAlchemyError) is the genuine
        # "audit log unwritable" case → quarantine exit 3.
        raise OperationalError("pg down", None, Exception("conn refused"))

    monkeypatch.setattr(boot_success_env, "append_schema", _boom)
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 3


def test_refusal_propagates_non_persistence_bug(
    monkeypatch: pytest.MonkeyPatch, boot_success_env: FakeAuditWriter
) -> None:
    """err-002: a non-persistence bug in append_schema is NOT masked as exit 3.

    A ``TypeError`` (e.g. a schema/field mismatch) is a real code defect — it
    must crash loudly rather than be relabelled "audit log unwritable".
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.probe_capability_gate_handshake",
        _async_return(CapabilityGateHandshakeFailedFailure(backing_store_kind="postgres")),
    )

    async def _bug(**_kw: object) -> None:
        raise TypeError("append_schema() got an unexpected field")

    monkeypatch.setattr(boot_success_env, "append_schema", _bug)
    result = CliRunner().invoke(daemon_app, ["start"])
    # Typer surfaces an uncaught exception as a non-2/non-3 failure exit.
    assert result.exit_code not in (0, 2, 3)
    assert isinstance(result.exception, TypeError)


def _reason(writer: FakeAuditWriter) -> str | None:
    for r in writer.rows_for("DAEMON_BOOT_FAILED_FIELDS"):
        subject = r["subject"]
        if isinstance(subject, dict):
            return subject["failure_reason"]
    return None

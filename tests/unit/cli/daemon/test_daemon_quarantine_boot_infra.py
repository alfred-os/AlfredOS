"""Daemon quarantine boot infra wiring (PR-S4-11b0 / ADR-0026).

The daemon, after probe (c), builds a RAW seeded :class:`RealGate`,
installs the boot :class:`HookRegistry` over it (so a production
:class:`QuarantinedExtractor` can register its DLP subscriber), and
ASSERTS the seeded first-party grant is live — refusing boot fail-closed
(exit 2 + audit row) if it is not.

These tests drive the small pure helpers that make the wiring testable
without Postgres, plus the refusal arm through the CLI command path.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy.exc import OperationalError
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.hooks.errors import HookError
from tests.helpers.gates import make_deny_all_gate, make_quarantined_extract_chain_gate

from .conftest import FakeAuditWriter


def test_first_party_grant_live_true_when_seeded() -> None:
    """A gate carrying the first-party DLP grant reports it live."""
    from alfred.cli.daemon._commands import _first_party_grant_live

    gate = make_quarantined_extract_chain_gate()
    assert _first_party_grant_live(gate) is True


def test_first_party_grant_live_false_on_empty_grant_gate() -> None:
    """A deny-all RealGate (no first-party grant) reports it NOT live —
    the fail-closed posture the boot assertion turns into a refusal.

    Uses ``make_deny_all_gate`` (a RealGate with empty grants), NEVER a
    permissive always-allow shim — CLAUDE.md hard rule #2."""
    from alfred.cli.daemon._commands import _first_party_grant_live

    gate = make_deny_all_gate()
    assert _first_party_grant_live(gate) is False


def test_first_party_grant_live_false_on_empty_grant_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An EMPTY ``FIRST_PARTY_SYSTEM_GRANTS`` reports NOT live — fail-closed.

    ``all(())`` is vacuously True, which would let the boot assertion pass with
    nothing asserted. The explicit empty-set guard refuses instead. Even a
    permissive chain gate must report False when there is no grant to verify, so
    the result cannot depend on the gate."""
    from alfred.cli.daemon._commands import _first_party_grant_live

    monkeypatch.setattr(
        "alfred.security.capability_gate._bootstrap_grants.FIRST_PARTY_SYSTEM_GRANTS",
        (),
    )
    assert _first_party_grant_live(make_quarantined_extract_chain_gate()) is False


def test_install_quarantine_boot_registry_admits_extractor() -> None:
    """After install over a granted gate, a QuarantinedExtractor-style
    DLP-subscriber registration lands exactly one subscriber."""
    from alfred.cli.daemon._commands import _install_quarantine_boot_registry
    from alfred.hooks import get_registry, set_registry
    from alfred.security._extract_dlp_subscriber import register_extract_dlp_subscriber

    prior = get_registry()
    try:
        gate = make_quarantined_extract_chain_gate()
        _install_quarantine_boot_registry(gate, audit=FakeAuditWriter())
        register_extract_dlp_subscriber(outbound_dlp=object())
        subs = get_registry().subscribers_for("security.quarantined.extract", "post")
        assert len(subs) == 1
    finally:
        set_registry(prior)


def test_boot_refuses_when_first_party_grant_missing(
    monkeypatch: pytest.MonkeyPatch, boot_success_env: FakeAuditWriter
) -> None:
    """The grant-assertion arm: an empty-grant RealGate installed → boot
    refuses (exit 2) with a ``quarantine_grant_missing`` failed row.

    Drives the RAW-gate builder to a deny-all RealGate; the assertion in
    ``_start_async`` then refuses. Uses a FIXTURE deny gate, never a
    permissive shim (CLAUDE.md hard rule #2)."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_real_gate_for_daemon",
        _async_return(make_deny_all_gate()),
    )
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert _reason(boot_success_env) == "quarantine_grant_missing"


def test_boot_proceeds_when_first_party_grant_live(
    monkeypatch: pytest.MonkeyPatch, boot_success_env: FakeAuditWriter
) -> None:
    """The happy arm: a seeded RealGate passes the assertion and boot
    reaches the completion row."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_real_gate_for_daemon",
        _async_return(make_quarantined_extract_chain_gate()),
    )
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS")


def test_boot_refuses_audited_when_seed_raises_sqlalchemy_error(
    monkeypatch: pytest.MonkeyPatch, boot_success_env: FakeAuditWriter
) -> None:
    """FIX 1: a SQLAlchemyError from the seed-gate build must NOT crash
    uncaught out of ``_start_async``. It must run the audited refusal path:
    exit 2 + a ``daemon.boot.failed`` row with the ``boot_infra_install_failed``
    reason (distinct from ``quarantine_grant_missing``)."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")

    async def _raise_seed_error(*_args: Any, **_kwargs: Any) -> Any:
        raise OperationalError("pg down", None, Exception("conn refused"))

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_real_gate_for_daemon",
        _raise_seed_error,
    )
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert _reason(boot_success_env) == "boot_infra_install_failed"


def test_boot_refuses_audited_when_install_raises_hook_error(
    monkeypatch: pytest.MonkeyPatch, boot_success_env: FakeAuditWriter
) -> None:
    """FIX 1: a HookError from the registry install must NOT crash uncaught.
    It runs the audited refusal: exit 2 + ``boot_infra_install_failed`` row."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    # Build succeeds (granted gate); the install is what fails.
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_real_gate_for_daemon",
        _async_return(make_quarantined_extract_chain_gate()),
    )

    def _raise_install_error(*_args: Any, **_kwargs: Any) -> None:
        raise HookError("hookpoint metadata drift at boot")

    monkeypatch.setattr(
        "alfred.cli.daemon._commands._install_quarantine_boot_registry",
        _raise_install_error,
    )
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert _reason(boot_success_env) == "boot_infra_install_failed"


def test_boot_refuses_audited_when_grants_builder_raises_manifest_error(
    monkeypatch: pytest.MonkeyPatch, boot_success_env: FakeAuditWriter
) -> None:
    """FIX 2: a ``ManifestError`` from the comms-adapter grants-builder
    (corrupt manifest for an enabled adapter, OR a ``system``-tier manifest)
    must NOT crash uncaught out of ``_start_async`` with a raw traceback /
    exit 1. The builder runs INSIDE ``build_boot_real_gate_for_daemon``; its
    ``ManifestError`` must hit the boot ``except`` and map to the audited
    refusal: exit 2 + a ``daemon.boot.failed`` row with
    ``boot_infra_install_failed``.

    ``CommsAdapterSystemTierError`` is a ``ManifestError`` subclass, so this
    arm also covers the FIX 1 self-escalation refusal reaching the audited
    boot path rather than a traceback."""
    from alfred.plugins.errors import ManifestError

    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")

    async def _raise_manifest_error(*_args: Any, **_kwargs: Any) -> Any:
        raise ManifestError("corrupt enabled-adapter manifest")

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_real_gate_for_daemon",
        _raise_manifest_error,
    )
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert _reason(boot_success_env) == "boot_infra_install_failed"


def test_boot_refuses_audited_when_grants_builder_raises_os_error(
    monkeypatch: pytest.MonkeyPatch, boot_success_env: FakeAuditWriter
) -> None:
    """FIX 2: a missing manifest FILE at the grants-builder raises
    ``FileNotFoundError`` (an ``OSError``). It must reach the audited refusal
    (exit 2 + ``boot_infra_install_failed``), never a raw traceback/exit 1."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")

    async def _raise_os_error(*_args: Any, **_kwargs: Any) -> Any:
        raise FileNotFoundError("enabled adapter manifest vanished")

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_real_gate_for_daemon",
        _raise_os_error,
    )
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert _reason(boot_success_env) == "boot_infra_install_failed"


def test_boot_refuses_audited_when_outbound_dlp_broker_config_error(
    monkeypatch: pytest.MonkeyPatch, boot_success_env: FakeAuditWriter
) -> None:
    """#368: a SecretBrokerConfigError from the boot-DLP broker build must NOT
    crash uncaught out of ``_start_async`` as a raw traceback / exit 1. It must
    run the audited refusal: exit 2 + a ``daemon.boot.failed`` row with the
    ``boot_infra_install_failed`` reason (same path as a broken seed/install)."""
    from pathlib import Path

    from alfred.security.secrets import SecretBrokerNotAFileError

    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_real_gate_for_daemon",
        _async_return(make_quarantined_extract_chain_gate()),
    )

    def _raise_broker_config_error(*_args: Any, **_kwargs: Any) -> Any:
        raise SecretBrokerNotAFileError(
            "secrets path is a directory", path=Path("/etc/alfred/secrets.toml")
        )

    monkeypatch.setattr(
        "alfred.cli.daemon._commands._build_boot_outbound_dlp",
        _raise_broker_config_error,
    )
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert _reason(boot_success_env) == "boot_infra_install_failed"


def _async_return(value: Any):  # type: ignore[no-untyped-def]
    async def _f(*_args: Any, **_kwargs: Any) -> Any:
        return value

    return _f


def _reason(writer: FakeAuditWriter) -> str | None:
    for r in writer.rows_for("DAEMON_BOOT_FAILED_FIELDS"):
        subject = r["subject"]
        if isinstance(subject, dict):
            return subject["failure_reason"]
    return None

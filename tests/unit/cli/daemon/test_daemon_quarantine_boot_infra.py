"""Daemon quarantine boot infra wiring (PR-S4-11b0 / ADR-0026 / #339 PR3).

The daemon, after probe (c), builds a RAW seeded :class:`RealGate`,
installs the boot :class:`HookRegistry` over it (so a production
:class:`QuarantinedExtractor` can register its DLP subscriber), and
ASSERTS every seeded first-party grant is live — refusing boot fail-closed
(exit 2 + audit row) if any is not. #339 PR3 grew
:data:`FIRST_PARTY_SYSTEM_GRANTS` from the one DLP-subscriber row to four
(+ tool.dispatch, quarantine.dereference, t3.downgrade_to_orchestrator);
the assertion now verifies each row on its OWN axis — subscriber-tier rows
via ``check``, content-tier rows via ``check_content_clearance``.

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
from alfred.security.capability_gate._bootstrap_grants import FIRST_PARTY_SYSTEM_GRANTS
from tests.helpers.gates import (
    make_comms_adapter_load_gate,
    make_deny_all_gate,
    make_quarantined_extract_chain_gate,
)

from .conftest import FakeAuditWriter


def test_first_party_grant_live_true_when_seeded() -> None:
    """A gate carrying ALL FOUR first-party grants reports live.

    #339 PR3: :data:`FIRST_PARTY_SYSTEM_GRANTS` grew from one row (the DLP
    subscriber) to four (+ tool.dispatch, quarantine.dereference,
    t3.downgrade_to_orchestrator). ``make_comms_adapter_load_gate`` seeds a
    real :class:`RealGate` with EXACTLY the production constant's rows — not
    a permissive shim (CLAUDE.md hard rule #2) — so this proves
    ``_first_party_grant_live`` verifies every row, on its own axis, against
    the real grant-policy evaluator.
    """
    from alfred.cli.daemon._commands import _first_party_grant_live

    gate = make_comms_adapter_load_gate(FIRST_PARTY_SYSTEM_GRANTS)
    assert _first_party_grant_live(gate) is True


def test_first_party_grant_live_false_when_missing_one_content_grant() -> None:
    """A gate missing ONE content-tier grant reports NOT live.

    FIX-13: proves the content-clearance axis is ACTUALLY consulted, not
    vacuously satisfied. Seeds every first-party grant EXCEPT
    ``quarantine.dereference`` (a ``content_tier="T3"`` row) — the
    subscriber-tier rows (DLP subscriber, ``tool.dispatch``) are still live,
    so a version of ``_first_party_grant_live`` that only exercised the
    ``check`` branch (ignoring ``content_tier``) would wrongly report
    ``True`` here. The dependency on ``check_content_clearance`` for
    content-bearing rows is exactly what fails this gate to ``False``.
    """
    from alfred.cli.daemon._commands import _first_party_grant_live

    partial = tuple(
        grant for grant in FIRST_PARTY_SYSTEM_GRANTS if grant.hookpoint != "quarantine.dereference"
    )
    # Sanity: the omission actually dropped a row (guards against a future
    # hookpoint rename silently turning this into a no-op tautology).
    assert len(partial) == len(FIRST_PARTY_SYSTEM_GRANTS) - 1

    gate = make_comms_adapter_load_gate(partial)
    assert _first_party_grant_live(gate) is False


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
    """The happy arm: a gate seeded with every first-party grant passes the
    assertion and boot reaches the completion row.

    #339 PR3: the boot-success env's default (``boot_success_env`` fixture)
    already seeds this same full set; this test re-patches it explicitly so
    the "boot proceeds" property stays visible without relying on the
    conftest default."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_real_gate_for_daemon",
        _async_return(make_comms_adapter_load_gate(FIRST_PARTY_SYSTEM_GRANTS)),
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
    DEDICATED ``secrets_config_failed`` reason (#370 item 2 — so ``alfred audit
    log`` can tell a secrets misconfig apart from a capability-gate seed/install
    fault), and NO boot-completed row. The operator-facing message is the
    exception's own ``str(exc)`` (the actionable secrets remedy — devex dx-001),
    not the generic capability-gate/hook-registry boot-infra text."""
    from pathlib import Path

    from alfred.security.secrets import SecretBrokerNotAFileError

    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    # The seed-gate build + the grant-assertion must BOTH succeed here so the
    # SecretBrokerConfigError raised further down the boot path is what
    # actually trips the refusal — a gate missing any of the four #339 PR3
    # first-party grants would refuse EARLIER with quarantine_grant_missing,
    # never reaching _build_boot_outbound_dlp.
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_real_gate_for_daemon",
        _async_return(make_comms_adapter_load_gate(FIRST_PARTY_SYSTEM_GRANTS)),
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
    assert _reason(boot_success_env) == "secrets_config_failed"
    # The refusal short-circuits boot cleanly — no boot-completed row (CR).
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []
    # The operator sees the actionable secrets message, not the generic
    # boot-infra text that would misdirect them (devex dx-001).
    assert "secrets path is a directory" in result.output


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

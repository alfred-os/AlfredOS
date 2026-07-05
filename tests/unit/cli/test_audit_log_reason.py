"""Spec B G6-7-5 Task 8 — ``alfred audit log`` forwarded-drop reason triage.

Covers the render + ``--reason`` filter logic at the CLI layer (the backend
stub stays unwired — these tests patch :func:`_query_audit_log` with fixture
rows). Two reason shapes exist:

* Receiver terminal drops (``event="comms.forwarded_inbound.dropped"``) carry
  the reason in ``subject.reason``.
* The poison dead-letter (``event="comms.inbound.poisoned"``,
  ``result="poisoned"``) carries NO ``subject.reason`` — its reason IS the
  ``poisoned`` result.

:func:`_row_reason` must also be robust to rows without a ``subject`` (or whose
``subject`` is not a dict) — those render an empty reason cell.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from alfred.cli.audit import _row_reason, audit_app


@pytest.fixture()
def runner() -> CliRunner:
    """Typer runner — Click 8.2 separates stdout/stderr by default."""
    return CliRunner()


@pytest.fixture()
def dropped_row() -> dict[str, object]:
    """A forwarded-inbound terminal drop carrying ``subject.reason``."""
    return {
        "event": "comms.forwarded_inbound.dropped",
        "result": "dropped",
        "actor_user_id": "operator",
        "timestamp": "2026-06-22T10:00:00Z",
        "subject": {"reason": "body_malformed", "adapter_id": "discord"},
    }


@pytest.fixture()
def unknown_adapter_row() -> dict[str, object]:
    """A second forwarded-inbound drop with a different reason."""
    return {
        "event": "comms.forwarded_inbound.dropped",
        "result": "dropped",
        "actor_user_id": "operator",
        "timestamp": "2026-06-22T10:01:00Z",
        "subject": {"reason": "unknown_adapter", "adapter_id": "telegram"},
    }


@pytest.fixture()
def poisoned_row() -> dict[str, object]:
    """The poison dead-letter — no ``subject.reason``; reason IS the result."""
    return {
        "event": "comms.inbound.poisoned",
        "result": "poisoned",
        "actor_user_id": "operator",
        "timestamp": "2026-06-22T10:02:00Z",
        "subject": {
            "adapter_id": "discord",
            "inbound_id_hash": "abc123",
            "attempt_count": 3,
            "observed_at": "2026-06-22T10:02:00Z",
        },
    }


@pytest.fixture()
def boot_failed_row() -> dict[str, object]:
    """A ``daemon.boot.failed`` row — carries ``subject.failure_reason``, NOT
    ``subject.reason`` (the ``_refuse_boot`` fixed-subject shape)."""
    return {
        "event": "daemon.boot.failed",
        "result": "refused",
        "actor_user_id": "daemon",
        "timestamp": "2026-07-05T10:00:00Z",
        "subject": {
            "boot_id": "b1",
            "attempted_at": "2026-07-05T10:00:00Z",
            "failure_reason": "secrets_config_failed",
            "environment_source": "env",
        },
    }


def test_dropped_reason_renders_in_output(
    runner: CliRunner, dropped_row: dict[str, object]
) -> None:
    """(a) A ``subject.reason`` drop renders its reason in the row line."""
    with patch("alfred.cli.audit._query_audit_log", return_value=[dropped_row]):
        result = runner.invoke(audit_app, ["log", "--since", "24h"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "body_malformed" in result.output


def test_boot_failure_reason_renders_in_output(
    runner: CliRunner, boot_failed_row: dict[str, object]
) -> None:
    """#381: a ``daemon.boot.failed`` row renders its ``failure_reason``.

    Was blank — ``_row_reason`` read ``subject.reason`` only, but boot rows carry
    the discriminator in ``subject.failure_reason``, so ``alfred audit log`` could
    not show WHAT broke at boot. The fallback closes that gap.
    """
    with patch("alfred.cli.audit._query_audit_log", return_value=[boot_failed_row]):
        result = runner.invoke(audit_app, ["log", "--since", "24h"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "secrets_config_failed" in result.output


def test_row_reason_prefers_subject_reason_over_failure_reason() -> None:
    """The forwarded-drop contract is unchanged: ``subject.reason`` wins when
    both keys are present (only boot rows, which lack ``reason``, hit the fallback)."""
    row = {"subject": {"reason": "body_malformed", "failure_reason": "secrets_config_failed"}}
    assert _row_reason(row) == "body_malformed"


def test_row_reason_falls_back_to_failure_reason() -> None:
    """A row with only ``failure_reason`` returns it."""
    assert _row_reason({"subject": {"failure_reason": "boot_infra_install_failed"}}) == (
        "boot_infra_install_failed"
    )


def test_row_reason_empty_reason_falls_through_to_failure_reason() -> None:
    """An empty ``subject.reason`` must NOT short-circuit to a blank cell — it
    falls through to ``failure_reason`` (CR #381: the truthiness guard)."""
    assert _row_reason({"subject": {"reason": "", "failure_reason": "secrets_config_failed"}}) == (
        "secrets_config_failed"
    )


def test_row_reason_empty_when_dict_subject_has_neither_reason_key() -> None:
    """A dict subject with neither ``reason`` nor ``failure_reason`` on a
    non-poisoned row falls through to ``""`` (the honest reason-less signal)."""
    assert _row_reason({"subject": {"boot_id": "x"}, "result": "refused"}) == ""


def test_reason_filter_keeps_only_matching_row(
    runner: CliRunner,
    dropped_row: dict[str, object],
    unknown_adapter_row: dict[str, object],
) -> None:
    """(b) ``--reason body_malformed`` excludes the unknown_adapter row."""
    rows = [dropped_row, unknown_adapter_row]
    with patch("alfred.cli.audit._query_audit_log", return_value=rows):
        result = runner.invoke(audit_app, ["log", "--since", "24h", "--reason", "body_malformed"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "body_malformed" in result.output
    # The unknown_adapter drop must be filtered out entirely.
    assert "unknown_adapter" not in result.output
    assert "telegram" not in result.output


def test_reason_filter_matches_poisoned_via_result_fallback(
    runner: CliRunner,
    dropped_row: dict[str, object],
    poisoned_row: dict[str, object],
) -> None:
    """(c) ``--reason poisoned`` matches the no-subject.reason dead-letter."""
    rows = [dropped_row, poisoned_row]
    with patch("alfred.cli.audit._query_audit_log", return_value=rows):
        result = runner.invoke(audit_app, ["log", "--since", "24h", "--reason", "poisoned"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "comms.inbound.poisoned" in result.output
    # The body_malformed drop must be filtered out — it is not poisoned.
    assert "body_malformed" not in result.output


def test_reason_filter_no_match_renders_reason_aware_message(
    runner: CliRunner, dropped_row: dict[str, object]
) -> None:
    """(d) ``--reason`` with no match prints the REASON-AWARE empty body.

    devex MEDIUM: a filtered miss must read differently from a global
    empty (``cli.audit.log.reason_empty`` → "No audit rows with reason
    '<reason>' in the last ..."), naming the reason so the operator can
    tell "no row with THIS reason" apart from "no rows at all". Exits 0,
    exactly as the no-rows case does.
    """
    with patch("alfred.cli.audit._query_audit_log", return_value=[dropped_row]):
        result = runner.invoke(audit_app, ["log", "--since", "24h", "--reason", "receive_fault"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "receive_fault" in result.output
    assert "body_malformed" not in result.output


def test_reason_invalid_value_rejected(runner: CliRunner) -> None:
    """An unknown ``--reason`` value fails loud (closed ``_ReasonChoice``).

    A typo like ``--reason poisned`` must raise :class:`typer.BadParameter`
    (Typer exit code 2), not silently render an empty result -- the
    silent-failure pattern CLAUDE.md hard rule #7 forbids. Mirrors the
    ``--tier`` invalid-value coverage.
    """
    result = runner.invoke(audit_app, ["log", "--since", "24h", "--reason", "poisned"])
    assert result.exit_code == 2
    combined = (result.output or "") + (result.stderr or "")
    assert "poisned" in combined or "invalid" in combined.lower()


def test_row_without_subject_renders_without_crash(runner: CliRunner) -> None:
    """(e) A row with no ``subject`` renders (empty reason cell), no crash."""
    rows = [
        {
            "event": "tool.web.fetch",
            "result": "success",
            "actor_user_id": "operator",
            "timestamp": "2026-06-22T10:00:00Z",
        }
    ]
    with patch("alfred.cli.audit._query_audit_log", return_value=rows):
        result = runner.invoke(audit_app, ["log", "--since", "24h"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "tool.web.fetch" in result.output


def test_row_reason_helper_branches() -> None:
    """:func:`_row_reason` returns the right discriminator for each shape."""
    assert (
        _row_reason({"subject": {"reason": "envelope_body_mismatch"}, "result": "dropped"})
        == "envelope_body_mismatch"
    )
    # No subject.reason but poisoned result → the result fallback.
    assert _row_reason({"subject": {"adapter_id": "x"}, "result": "poisoned"}) == ("poisoned")
    # Subject is not a dict → robust empty.
    assert _row_reason({"subject": "nope", "result": "success"}) == ""
    # No subject at all, non-poisoned → empty.
    assert _row_reason({"event": "tool.web.fetch", "result": "success"}) == ""

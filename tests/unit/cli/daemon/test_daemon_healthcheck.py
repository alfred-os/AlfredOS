"""`alfred daemon healthcheck` — core /metrics endpoint liveness probe (#470 Task 5).

Scope: liveness of the /metrics endpoint ONLY, not full data-plane readiness (spec §5.4) —
see the `alfred.cli.daemon._healthcheck` module docstring. Unlike `healthcheck_gateway`
(which imports `fetch_metrics_text`/`resolve_metrics_port` LAZILY inside the function body,
perf-001), `_healthcheck.py` imports them at module top — the module itself is only reached
via the lazy `from alfred.cli.daemon._healthcheck import healthcheck_daemon` inside the
`healthcheck` typer command body, so `alfred --help` still never pays this import. That means
the patch target here is the local module attribute (`alfred.cli.daemon._healthcheck.
fetch_metrics_text`), not the `alfred.observability.metrics_server` source module.

Content assertions capture `typer.echo`'s argument directly (NOT `capsys`/stdout) — this
module also logs via `structlog`, which by this repo's config renders to stdout too and
happens to interpolate the SAME `port=` kwarg the message text carries. A stdout-blob
assertion would pass on the log line's noise alone even if `t()` fell back to the raw
catalog key (a vacuous oracle — see memory domain_a_test_that_asks_the_code_if_the_code_
is_right.md). Spying on `typer.echo` isolates the operator-facing string the catalog is
actually responsible for.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.cli.daemon._healthcheck import healthcheck_daemon
from alfred.observability.metrics_server import CORE_METRICS_DEFAULT_PORT


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")


def _capture_echo(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Spy on `typer.echo` as called FROM `_healthcheck.py`, recording every message."""
    calls: list[str] = []
    monkeypatch.setattr(
        "alfred.cli.daemon._healthcheck.typer.echo",
        lambda message=None, *_a, **_kw: calls.append(message),
    )
    return calls


def test_healthcheck_registered() -> None:
    result = CliRunner().invoke(daemon_app, ["--help"])
    assert result.exit_code == 0
    assert "healthcheck" in result.stdout


def test_cli_invocation_healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercises the actual Typer dispatch (`daemon_app` → `healthcheck()` wrapper →
    `healthcheck_daemon()`), not just the function body directly — the thin wrapper
    registered in `alfred.cli.daemon.__init__` is otherwise never invoked by a test."""
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "9465")
    with patch("alfred.cli.daemon._healthcheck.fetch_metrics_text", return_value="# ok\n"):
        result = CliRunner().invoke(daemon_app, ["healthcheck"])
    assert result.exit_code == 0


def test_cli_invocation_unhealthy_is_not_a_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "9465")
    with patch("alfred.cli.daemon._healthcheck.fetch_metrics_text", side_effect=OSError("refused")):
        result = CliRunner().invoke(daemon_app, ["healthcheck"])
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_healthy_when_metrics_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "9465")
    with patch("alfred.cli.daemon._healthcheck.fetch_metrics_text", return_value="# ok\n"):
        healthcheck_daemon()  # no raise == exit 0


def test_probes_the_shared_default_port_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """rev-001 / sec-003: with NO env set, the probe dials the same default the boot binds.

    Every other test in this module ``setenv``s the port, so the DEFAULT half of the
    (env var, default) pair was never exercised here — and the boot seam and the probe used
    to re-declare that pair independently. If they drift, the healthcheck goes permanently
    red and the only mechanism that surfaces a metrics bind failure dies with it. The port
    is read off the ACTUAL call, not asserted against a re-typed literal.
    """
    monkeypatch.delenv("ALFRED_CORE_METRICS_PORT", raising=False)
    with patch("alfred.cli.daemon._healthcheck.fetch_metrics_text", return_value="# ok\n") as fetch:
        healthcheck_daemon()
    assert fetch.call_args.args == (CORE_METRICS_DEFAULT_PORT,)
    assert CORE_METRICS_DEFAULT_PORT == 9465  # the value compose + the runbook publish


def test_unhealthy_when_metrics_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "9465")
    echoed = _capture_echo(monkeypatch)
    with (
        patch("alfred.cli.daemon._healthcheck.fetch_metrics_text", side_effect=OSError("refused")),
        pytest.raises(typer.Exit) as exc_info,
    ):
        healthcheck_daemon()
    assert exc_info.value.exit_code == 1
    assert len(echoed) == 1
    # i18n-001/003: the catalog msgstr must actually resolve (not fall back to the raw
    # dotted key) and must retain the {port} placeholder substitution.
    assert echoed[0] != "daemon.healthcheck.metrics_unreachable"
    assert "9465" in echoed[0]


def test_unhealthy_on_bad_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "70000")
    echoed = _capture_echo(monkeypatch)
    with pytest.raises(typer.Exit) as exc_info:
        healthcheck_daemon()
    assert exc_info.value.exit_code == 1
    assert len(echoed) == 1
    assert echoed[0] != "daemon.healthcheck.bad_port"


@pytest.mark.parametrize("bad_value", ["70000", "notaport"])
def test_bad_port_message_carries_the_actionable_detail(
    monkeypatch: pytest.MonkeyPatch, bad_value: str
) -> None:
    """dx-001: the refusal must name the env var, the accepted range AND the operator's value.

    ``resolve_metrics_port`` already composes exactly that sentence; the message previously
    threw it away and echoed a generic "is invalid" line, so an operator was told something
    was wrong but not what they had typed or what would be accepted. Both refusal arms
    (out-of-range and non-integer) are checked — the non-integer arm used to surface a bare
    ``int()`` message naming neither.
    """
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", bad_value)
    echoed = _capture_echo(monkeypatch)
    with pytest.raises(typer.Exit):
        healthcheck_daemon()
    message = echoed[0]
    assert "ALFRED_CORE_METRICS_PORT" in message
    assert "1..65535" in message
    assert bad_value in message
    # i18n-003: the placeholder must have been SUBSTITUTED, not echoed literally.
    assert "{detail}" not in message


def test_bad_port_detail_is_length_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """An operator-supplied env value reaches the terminal — bounded, so it cannot BE the message.

    The value is operator config (T1), not untrusted content, but a pathological
    multi-kilobyte ``ALFRED_CORE_METRICS_PORT`` must not scroll the actionable remediation
    off the screen.
    """
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "z" * 5000)
    echoed = _capture_echo(monkeypatch)
    with pytest.raises(typer.Exit):
        healthcheck_daemon()
    assert len(echoed[0]) < 1000


def test_bad_port_and_unreachable_messages_are_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    """i18n-004: the bad-port config error must NOT reuse the metrics-unreachable copy.

    A shared message would tell the operator "the data plane may still be serving" for a
    config typo it can never actually probe — the wrong remediation.
    """
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "70000")
    bad_port_echoed = _capture_echo(monkeypatch)
    with pytest.raises(typer.Exit):
        healthcheck_daemon()

    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "9465")
    unreachable_echoed = _capture_echo(monkeypatch)
    with (
        patch("alfred.cli.daemon._healthcheck.fetch_metrics_text", side_effect=OSError("refused")),
        pytest.raises(typer.Exit),
    ):
        healthcheck_daemon()

    assert bad_port_echoed != unreachable_echoed
    assert bad_port_echoed[0].strip() != ""
    assert unreachable_echoed[0].strip() != ""

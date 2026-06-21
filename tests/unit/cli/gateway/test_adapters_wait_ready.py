"""``alfred gateway adapters [--wait-ready]`` verify command (Spec B G6-5 Task 8, #288).

The command READS the live per-adapter status via the ADR-0038 daemon-control
``status.query`` client (GAP-3 ruling: REUSE the daemon-control poll; there is NO
gateway-side socket read — the gateway's own socket is single-accept-for-life). The
gateway-reported status reaches the daemon's :class:`AdapterStatusObserver`; readiness
is ``state == "up"``.

These tests drive a FAKE ``query_daemon_control`` (monkeypatched on the command module,
mirroring ``_render_live_adapter_status``) + a FAKE inter-poll sleep, so the bounded poll
loop is exercised WITHOUT real wall-clock time. Assertions key on ``t()`` catalog values /
canonical adapter ids — never raw English literals (i18n hard rule).

Exit-code contract (mirrors the deleted ``alfred discord verify`` 0/1/2/3):
* 0 — ready
* 1 — not-ready-by-timeout (loud)
* 2 — daemon / control unavailable
* 3 — unknown adapter
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon._daemon_control_client import DaemonControlUnavailableError
from alfred.cli.daemon._daemon_control_protocol import (
    AdapterStatusLine,
    ControlResponse,
    DaemonStatusResult,
)
from alfred.cli.gateway import gateway_app
from alfred.i18n import t


def _response(adapters: dict[str, str]) -> ControlResponse:
    """Build a control response whose result carries one status line per adapter id."""
    lines = {
        adapter_id: AdapterStatusLine(adapter_id=adapter_id, state=state)  # type: ignore[arg-type]
        for adapter_id, state in adapters.items()
    }
    result = DaemonStatusResult(adapters=lines)
    return ControlResponse(id="1", result=result.model_dump())


class _SeqQuery:
    """A fake ``query_daemon_control`` that returns a scripted response per call.

    Each ``__call__`` pops the next scripted item: a :class:`ControlResponse` is
    returned, an ``Exception`` instance is raised (to simulate a control fault). The
    last item repeats once the script is exhausted, so a poll loop that overshoots the
    script does not ``IndexError``.
    """

    def __init__(self, script: list[ControlResponse | Exception]) -> None:
        self._script = script
        self.calls = 0

    async def __call__(self, method: str, **_kwargs: object) -> ControlResponse:
        self.calls += 1
        item = self._script[min(self.calls - 1, len(self._script) - 1)]
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[float]]:
    """Replace the command's inter-poll sleep with a no-op recorder.

    The poll loop must NOT busy-spin (a bounded ``await`` between polls). Faking the
    sleep keeps the test deterministic AND lets it assert the loop sleeps between polls
    (never a tight CPU spin).
    """
    from alfred.cli.gateway import _adapters

    slept: list[float] = []

    async def _fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(_adapters, "_poll_sleep", _fake_sleep)
    yield slept


def _patch_query(monkeypatch: pytest.MonkeyPatch, fake: _SeqQuery) -> None:
    from alfred.cli.gateway import _adapters

    monkeypatch.setattr(_adapters, "query_daemon_control", fake)


def test_ready_on_first_poll_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _SeqQuery([_response({"discord": "up"})])
    _patch_query(monkeypatch, fake)
    result = CliRunner().invoke(gateway_app, ["adapters", "--wait-ready", "discord"])
    assert result.exit_code == 0, result.output
    assert t("gateway.adapters.wait_ready.ready", adapter="discord") in result.output
    assert fake.calls == 1


def test_becomes_ready_after_n_polls_exits_zero(
    monkeypatch: pytest.MonkeyPatch, _no_real_sleep: list[float]
) -> None:
    fake = _SeqQuery(
        [
            _response({"discord": "down"}),
            _response({"discord": "down"}),
            _response({"discord": "up"}),
        ]
    )
    _patch_query(monkeypatch, fake)
    result = CliRunner().invoke(
        gateway_app, ["adapters", "--wait-ready", "discord", "--timeout", "30"]
    )
    assert result.exit_code == 0, result.output
    assert fake.calls == 3
    # The loop slept BETWEEN polls (bounded, never a busy-spin) — two waits for three polls.
    assert _no_real_sleep == [pytest.approx(_no_real_sleep[0])] * 2
    assert all(s > 0 for s in _no_real_sleep)


def test_timeout_not_ready_exits_one_and_is_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _SeqQuery([_response({"discord": "down"})])
    _patch_query(monkeypatch, fake)
    # A zero timeout takes the single-shot poll then the bounded loop expires immediately.
    result = CliRunner().invoke(
        gateway_app, ["adapters", "--wait-ready", "discord", "--timeout", "0"]
    )
    assert result.exit_code == 1, result.output
    assert t("gateway.adapters.wait_ready.timeout", adapter="discord", timeout=0) in result.output


def test_unavailable_exits_two(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _SeqQuery([DaemonControlUnavailableError("/no/socket")])
    _patch_query(monkeypatch, fake)
    result = CliRunner().invoke(gateway_app, ["adapters", "--wait-ready", "discord"])
    assert result.exit_code == 2, result.output
    assert t("gateway.adapters.unavailable") in result.output


def _patch_known(monkeypatch: pytest.MonkeyPatch, known: list[str]) -> None:
    """Pin the closed configured/hosted adapter set the up-front validation reads.

    The real resolution reads Settings + manifests; faking it keeps these unit
    tests from constructing Settings / touching the filesystem.
    """
    from alfred.cli.gateway import _adapters

    monkeypatch.setattr(_adapters, "_resolve_known_adapter_ids", lambda: set(known))


def test_unknown_adapter_exits_three(monkeypatch: pytest.MonkeyPatch) -> None:
    """A GENUINELY-unknown id (absent from the configured set) → exit-3 immediately."""
    fake = _SeqQuery([_response({"discord": "up"})])
    _patch_query(monkeypatch, fake)
    _patch_known(monkeypatch, ["discord"])
    result = CliRunner().invoke(gateway_app, ["adapters", "--wait-ready", "telegram"])
    assert result.exit_code == 3, result.output
    assert t("gateway.adapters.unknown_adapter", adapter="telegram") in result.output
    # An unknown id is resolved up front: it never reaches the poll loop.
    assert fake.calls == 0


def test_known_but_not_yet_reported_adapter_waits_then_times_out(
    monkeypatch: pytest.MonkeyPatch, _no_real_sleep: list[float]
) -> None:
    """A KNOWN adapter still BOOTING (absent from the observer map) waits, then exit-1.

    The observer omits a not-yet-reported adapter; that absence must be treated as
    NOT-READY (fall through to the deadline → loud exit-1 on timeout), NOT the
    instant exit-3 a genuinely-unknown id gets.
    """
    # The status map NEVER lists ``discord`` (still booting), but it IS configured.
    fake = _SeqQuery([_response({"tui": "up"})])
    _patch_query(monkeypatch, fake)
    _patch_known(monkeypatch, ["discord", "tui"])
    result = CliRunner().invoke(
        gateway_app, ["adapters", "--wait-ready", "discord", "--timeout", "0"]
    )
    assert result.exit_code == 1, result.output
    assert t("gateway.adapters.wait_ready.timeout", adapter="discord", timeout=0) in result.output
    # It POLLED (did not short-circuit to exit-3): the loop ran at least once.
    assert fake.calls >= 1


def test_resolve_known_adapter_ids_returns_configured_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real resolver returns the configured/hosted set from the boot seam."""
    from alfred.cli.gateway import _adapters, _commands

    monkeypatch.setattr(_commands, "_resolve_hosted_adapter_ids", lambda: ["discord"])
    assert _adapters._resolve_known_adapter_ids() == {"discord"}


def test_resolve_known_adapter_ids_empty_set_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty configured set resolves to ``None`` (skip validation; nothing to reject)."""
    from alfred.cli.gateway import _adapters, _commands

    monkeypatch.setattr(_commands, "_resolve_hosted_adapter_ids", list)
    assert _adapters._resolve_known_adapter_ids() is None


def test_resolve_known_adapter_ids_degrades_to_none_on_fault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resolution fault degrades to ``None`` (fail-safe; never a false refusal)."""
    from alfred.cli.gateway import _adapters, _commands

    def _boom() -> list[str]:
        raise RuntimeError("settings unreadable")

    monkeypatch.setattr(_commands, "_resolve_hosted_adapter_ids", _boom)
    assert _adapters._resolve_known_adapter_ids() is None


def test_known_but_booting_then_reports_up_exits_zero(
    monkeypatch: pytest.MonkeyPatch, _no_real_sleep: list[float]
) -> None:
    """A KNOWN adapter absent on the first poll then reported ``up`` → exit-0.

    Proves in-loop absence is NOT-READY (keep waiting), not a terminal unknown.
    """
    fake = _SeqQuery(
        [
            _response({"tui": "up"}),  # discord not yet reported
            _response({"discord": "up", "tui": "up"}),  # now booted
        ]
    )
    _patch_query(monkeypatch, fake)
    _patch_known(monkeypatch, ["discord", "tui"])
    result = CliRunner().invoke(
        gateway_app, ["adapters", "--wait-ready", "discord", "--timeout", "30"]
    )
    assert result.exit_code == 0, result.output
    assert t("gateway.adapters.wait_ready.ready", adapter="discord") in result.output
    assert fake.calls == 2


def test_one_shot_renders_status(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _SeqQuery([_response({"discord": "up", "tui": "down"})])
    _patch_query(monkeypatch, fake)
    result = CliRunner().invoke(gateway_app, ["adapters"])
    assert result.exit_code == 0, result.output
    assert "discord" in result.output
    assert "tui" in result.output
    # The ready/not-ready render uses localized state tokens, never the raw wire token.
    assert t("gateway.adapters.state.up") in result.output
    assert fake.calls == 1


def test_one_shot_unavailable_exits_two(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _SeqQuery([DaemonControlUnavailableError("/no/socket")])
    _patch_query(monkeypatch, fake)
    result = CliRunner().invoke(gateway_app, ["adapters"])
    assert result.exit_code == 2, result.output
    assert t("gateway.adapters.unavailable") in result.output


def test_one_shot_filtered_by_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _SeqQuery([_response({"discord": "up", "tui": "down"})])
    _patch_query(monkeypatch, fake)
    result = CliRunner().invoke(gateway_app, ["adapters", "discord"])
    assert result.exit_code == 0, result.output
    assert "discord" in result.output
    assert "tui" not in result.output


def test_one_shot_unknown_adapter_exits_three(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _SeqQuery([_response({"discord": "up"})])
    _patch_query(monkeypatch, fake)
    result = CliRunner().invoke(gateway_app, ["adapters", "telegram"])
    assert result.exit_code == 3, result.output
    assert t("gateway.adapters.unknown_adapter", adapter="telegram") in result.output


def test_control_fault_does_not_crash_render(monkeypatch: pytest.MonkeyPatch) -> None:
    """A control auth/protocol fault degrades to exit 2 + a friendly line, never a traceback."""
    from alfred.cli.daemon._daemon_control_client import DaemonControlProtocolError

    fake = _SeqQuery([DaemonControlProtocolError("malformed")])
    _patch_query(monkeypatch, fake)
    result = CliRunner().invoke(gateway_app, ["adapters"])
    assert result.exit_code == 2, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert t("gateway.adapters.unavailable") in result.output

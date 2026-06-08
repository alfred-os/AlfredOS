"""ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED truthy + production → refusal (#174).

sec-002 closure: the env var is parsed via the truthy-vocabulary helper,
NOT == "1". Production + any truthy value refuses + exits 2.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app


class _FakeWriter:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    async def append_schema(self, **kw: object) -> None:
        self.rows.append(kw)


@pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "yes", "on", " On "])
def test_unsandboxed_in_production_refuses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, truthy: str
) -> None:
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", truthy)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent",
    )
    writer = _FakeWriter()
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: writer,
    )

    runner = CliRunner()
    result = runner.invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert any(
        isinstance(r["subject"], dict)
        and r["subject"]["failure_reason"] == "unsandboxed_env_in_production"
        for r in writer.rows
    )


def test_unsandboxed_falsey_value_does_not_refuse_on_that_arm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A non-truthy value must NOT trip the unsandboxed refusal arm."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", "0")
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent",
    )
    writer = _FakeWriter()
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: writer,
    )
    # Force the launcher probe (next arm) to refuse so the command still
    # exits — proving the unsandboxed arm was NOT the one that fired.
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.probe_launcher_policy_resolving",
        _make_async_return(_launcher_failure()),
    )

    runner = CliRunner()
    result = runner.invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    reasons = [
        r["subject"]["failure_reason"] for r in writer.rows if isinstance(r["subject"], dict)
    ]
    assert "unsandboxed_env_in_production" not in reasons
    assert "launcher_not_policy_resolving" in reasons


def _launcher_failure() -> object:
    from alfred.cli.daemon._failures import LauncherNotPolicyResolvingFailure

    return LauncherNotPolicyResolvingFailure(probe_response="stub")


def _make_async_return(value: object):  # type: ignore[no-untyped-def]
    async def _f(**_kw: object) -> object:
        return value

    return _f

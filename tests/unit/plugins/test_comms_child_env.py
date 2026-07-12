"""Child-env builder for the daemon-hosted comms transport (PR-S4-11a Wave 1).

:func:`alfred.plugins._comms_child_env.comms_child_env` is the SHARED,
SCRUBBED, allowlisted env builder both the foreground ``alfred chat`` launcher
(:mod:`alfred.cli._launcher_spawn`) and the daemon-hosted
:class:`alfred.plugins.comms_stdio_transport.CommsStdioTransport` use.

Unlike the foreground ``kind="none"`` TUI path (which keeps full passthrough so
the operator's session env reaches their own Textual app), the daemon-hosted
comms path uses the SCRUBBED allowlist for ALL sandbox kinds — a deliberate
security tightening (#237): the daemon may spawn an adversary-facing relay (the
Discord adapter, ``kind="full"``, open egress per #230) and an operator's
exported ``DISCORD_BOT_TOKEN`` / ``ANTHROPIC_API_KEY`` must never cross into it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from alfred.cli._launcher_spawn import PluginLaunchSpec
from alfred.plugins._comms_child_env import _SCRUBBED_ENV_ALLOWLIST, comms_child_env


def _spec(*, sandbox_kind: str = "full") -> PluginLaunchSpec:
    return PluginLaunchSpec(
        plugin_id="alfred_comms_test",
        manifest_path=Path("/opt/alfred/plugins/alfred_comms_test/manifest.toml"),
        module="alfred_comms_test.main",
        adapter_id="alfred_comms_test",
        import_roots=(Path("/opt/alfred/plugins"), Path("/opt/alfred/src")),
        inherit_stdio=False,
        sandbox_kind=sandbox_kind,
    )


_SECRET_NAMES = ("DISCORD_BOT_TOKEN", "ANTHROPIC_API_KEY", "OPENAI_API_KEY")


def test_allowlist_is_exactly_the_expected_key_set() -> None:
    """The scrubbed allowlist is pinned to the launcher control + locale surface.

    No secret-bearing key is on the list — a regression that adds one is a
    release-blocking leak into an adversary-facing relay.
    """
    assert _SCRUBBED_ENV_ALLOWLIST == (
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "ALFRED_ENVIRONMENT",
        "ALFRED_SANDBOX_POLICY_DIR",
        "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED",
        "ALFRED_PLUGIN_UID",
        "FAKE_UNAME",
    )
    for secret in _SECRET_NAMES:
        assert secret not in _SCRUBBED_ENV_ALLOWLIST


def test_secret_bearing_vars_do_not_reach_the_child(monkeypatch: pytest.MonkeyPatch) -> None:
    """An operator's exported secrets never appear in the comms child env."""
    for name in _SECRET_NAMES:
        monkeypatch.setenv(name, "super-secret-value")

    env = comms_child_env(_spec())

    for name in _SECRET_NAMES:
        assert name not in env, f"{name} leaked into the comms child env"
    assert "super-secret-value" not in env.values()


def test_scrubbed_even_for_kind_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """The daemon comms path scrubs for ALL kinds — including ``none`` (#237).

    The foreground launcher's ``kind="none"`` full passthrough is the
    operator-local TUI exception; the daemon-hosted path has no operator at the
    keyboard, so it tightens to the scrubbed allowlist regardless of kind.
    """
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "leak-me")

    env = comms_child_env(_spec(sandbox_kind="none"))

    assert "DISCORD_BOT_TOKEN" not in env


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: hardcoded Linux container path (#246 review)",
)
def test_pythonpath_is_import_roots_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """PYTHONPATH is the spec's import roots, in order.

    PYTHONPATH is NOT on :data:`_SCRUBBED_ENV_ALLOWLIST`, so the parent's
    PYTHONPATH is deliberately dropped (a daemon-hosted relay must not inherit
    the host's import path); the child's PYTHONPATH is built fresh from the
    spec's import roots alone.
    """
    monkeypatch.setenv("PYTHONPATH", "/pre-existing-host-path")

    env = comms_child_env(_spec())

    assert env["PYTHONPATH"].split(":") == ["/opt/alfred/plugins", "/opt/alfred/src"]
    assert "/pre-existing-host-path" not in env["PYTHONPATH"]


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: hardcoded Linux container path (#246 review)",
)
def test_manifest_and_adapter_keys_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """The spec-derived manifest path + adapter id land on the child env."""
    env = comms_child_env(_spec())

    assert (
        env["ALFRED_PLUGIN_MANIFEST_PATH"] == "/opt/alfred/plugins/alfred_comms_test/manifest.toml"
    )
    assert env["ALFRED_PLUGIN_ADAPTER_ID"] == "alfred_comms_test"


def test_launcher_control_vars_pass_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """The launcher's own control surface (ALFRED_ENVIRONMENT, PATH) survives."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")

    env = comms_child_env(_spec())

    assert env["ALFRED_ENVIRONMENT"] == "test"
    assert "PATH" in env

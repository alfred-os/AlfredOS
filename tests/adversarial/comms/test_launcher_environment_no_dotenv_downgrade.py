"""Adversarial test (RELEASE-BLOCKING, #469 Blocker 1 Task 5, sec-001 Critical).

``bin/alfred-plugin-launcher.sh`` gates the bwrap sandbox refusals + the dev
escape hatch (``ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED``) + the FAKE_UNAME keystone
on ``IS_PRODUCTION``, which it derives from
``python3 -m alfred.plugins.manifest_reader --read-environment``'s stdout. That
helper resolves ``Settings.environment`` via
:func:`alfred.config._environment_loader.resolve_environment`, whose lowest
layer is a ``.env`` file resolved relative to the **process CWD** — writable by
anything with CWD access (an app-writable location, not a trusted root-owned
source like ``/etc/alfred/environment`` or the process's own env vars).

The vulnerability: on the ``.env``-only path (``ALFRED_ENVIRONMENT`` unset,
``/etc/alfred/environment`` absent/unreadable), the launcher child used to
happily consult that CWD ``.env`` and could resolve
``ALFRED_ENVIRONMENT=development`` purely from it — silently downgrading an
otherwise-unresolved (should-fail-closed) environment to "development" and
un-gating the sandbox / dev escape hatch on what may actually be a production
host. The fix (Task 5) makes ``_cmd_read_environment`` resolve
**trusted-sources-only** (env var + ``/etc``, never ``.env``) by calling
``resolve_environment(consult_dotenv=False)`` — the stdout->bash interface
carries the VALUE but not the SOURCE, so source-EXCLUSION is the only way to
express the trust floor across that boundary.

Two properties are proven end-to-end:

1. The Python helper's ``--read-environment`` stdout never contains
   "development" when a CWD ``.env`` is the ONLY source claiming it — it
   emits the closed-vocabulary "no value" refusal instead
   (``daemon.boot.environment_not_set``).
2. The REAL bash launcher, driven with the maximally dangerous adjacent
   env (the dev escape hatch ``ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1``
   already set), still refuses outright and never execs the plugin — a
   canary file the stub would touch on exec is asserted absent.

Matches the invocation style of ``tests/unit/plugins/test_manifest_reader_cli.py``
(subprocess + explicit minimal env, since ``ALFRED_ETC_ENV_FILE`` is the test
seam for the ``/etc`` source) and ``tests/unit/launcher/test_launcher_sandbox_flow.py``
(the launcher needs the REAL ``PATH`` so its embedded ``python3 -m
alfred.plugins.manifest_reader`` subprocess resolves the venv interpreter, not
just ``/usr/bin:/bin``).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_LAUNCHER = _REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"
_LAUNCHER_TIMEOUT_S = 30.0

_DOTENV_BODY = "ALFRED_ENVIRONMENT=development\n"


def _manifest_reader_cli_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Minimal env for direct ``python3 -m alfred.plugins.manifest_reader`` invocation.

    ``sys.executable`` is an absolute path (matches
    ``test_manifest_reader_cli.py::_run``), so PATH hermeticity doesn't need to
    resolve ``python3`` — only ``PYTHONPATH`` matters for the import.
    """
    env = {"PYTHONPATH": str(_REPO_ROOT / "src"), "PATH": "/usr/bin:/bin"}
    if extra:
        env.update(extra)
    return env


def _launcher_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Env for the REAL bash launcher, which internally shells out to ``python3``.

    Inherits the REAL ``PATH`` (matches ``tests/unit/launcher/conftest.py``) so
    the venv interpreter — with this repo's dependencies installed — resolves,
    rather than falling back to a bare system ``/usr/bin/python3``.
    """
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": str(_REPO_ROOT / "src")}
    if extra:
        env.update(extra)
    return env


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: subprocess PATH hermeticity (/usr/bin:/bin) breaks child launch on Windows",
)
def test_read_environment_ignores_cwd_dotenv_only_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A CWD ``.env=development`` alone must NOT make --read-environment report it.

    ``ALFRED_ENVIRONMENT`` is unset (the explicit env dict below never sets
    it) and ``/etc`` is absent (``ALFRED_ETC_ENV_FILE`` points at a
    nonexistent path — hermetic against a real ``/etc/alfred/environment`` on
    the test host). The ONLY signal claiming "development" is the CWD
    ``.env`` this test plants — trusted-sources-only resolution must ignore
    it and fall through to the closed-vocabulary "no value" refusal.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(_DOTENV_BODY, encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-m", "alfred.plugins.manifest_reader", "--read-environment"],
        capture_output=True,
        text=True,
        env=_manifest_reader_cli_env({"ALFRED_ETC_ENV_FILE": str(tmp_path / "absent")}),
        check=False,
    )

    assert "development" not in result.stdout
    assert result.stdout.strip() == ""
    assert result.returncode != 0
    assert "daemon.boot.environment_not_set" in result.stderr


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: bash launcher + runuser/bwrap semantics are POSIX-only",
)
def test_launcher_refuses_to_spawn_when_only_cwd_dotenv_claims_development(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """End-to-end: a CWD ``.env`` cannot unlock the dev escape hatch on a production host.

    The dev escape hatch (``ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1``) is set —
    the concrete danger a pre-fix downgrade would have unlocked: had the
    launcher resolved "development" from the CWD ``.env``, ``IS_PRODUCTION``
    would go false and the escape-hatch refusal
    (``supervisor.sandbox.unsandboxed_refused_in_production``, gated on
    ``IS_PRODUCTION=true``) would never fire, letting the stub "plugin" exec
    unsandboxed on what is really an unresolved-environment host. With the
    fix, the environment read itself refuses BEFORE the escape-hatch check —
    or any manifest/sandbox-kind branch — is ever reached, so the stub is
    never exec'd regardless of the escape hatch.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(_DOTENV_BODY, encoding="utf-8")

    canary = tmp_path / "spawned.canary"
    stub = tmp_path / "stub.sh"
    stub.write_text(f'#!/bin/sh\ntouch "{canary}"\nexit 0\n')
    stub.chmod(0o755)

    result = subprocess.run(  # noqa: S603 — repo-owned launcher script path
        [str(_LAUNCHER), "alfred.example", str(stub)],
        capture_output=True,
        text=True,
        env=_launcher_env(
            {
                "ALFRED_ETC_ENV_FILE": str(tmp_path / "absent"),
                "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED": "1",
            }
        ),
        check=False,
        timeout=_LAUNCHER_TIMEOUT_S,
    )

    assert result.returncode != 0
    assert not canary.exists(), "the stub plugin executed despite the unresolved environment"
    assert "development" not in result.stdout
    assert "development" not in result.stderr
    assert "daemon.boot.environment_not_set" in result.stderr

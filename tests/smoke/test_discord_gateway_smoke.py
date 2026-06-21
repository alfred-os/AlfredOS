"""Smoke test for the gateway-hosted Discord adapter: ``alfred gateway adapters --wait-ready``.

Module-level skip: this test only runs when ``ALFRED_SMOKE_DISCORD_TOKEN``
is set in the environment. The variable carries a throwaway bot token for
a private Discord application the operator/CI owns. Without it the test
reports ``SKIPPED`` rather than ``ERROR`` or ``PASSED`` — same skip-vs-pass
discipline as the rest of the smoke layer.

G6-5 flag-day re-point (#288)
-----------------------------

PRE-G6-5 this smoke drove the now-retired standalone ``alfred discord
verify`` subprocess (a self-contained 30s gateway probe). Under the
flag-day, Discord is GATEWAY-HOSTED: the ``alfred-gateway`` process
bwrap-spawns the Discord adapter child, delivers its bot token over fd-3
from the core vault, and REPORTS each lifecycle transition to the core
(ADR-0036 inversion). The operator-facing readiness probe is therefore the
Task-8 command ``alfred gateway adapters --wait-ready discord``, which polls
the daemon-control ``status.query`` until the gateway reports Discord ``up``
(exit 0) or a bounded ``--timeout`` elapses (loud non-zero). This smoke
invokes THAT command, not the deleted verify path.

What the test asserts
---------------------

The test invokes ``python -m alfred gateway adapters --wait-ready discord``
as a subprocess (so the Typer entrypoint, structlog JSON renderer, and the
daemon-control client all boot the same way an operator's shell would) and
asserts the readiness exit-code contract:

* Exit code ``0`` within the bounded ``--timeout`` window + a harness slack
  window — the gateway brought the Discord child to ``up``.
* The localized ``gateway.adapters.wait_ready.ready`` line is rendered (the
  command's success surface), so a future i18n-key rename is caught here too.

PRE-CONDITION: a live ``alfred daemon start`` + ``alfred gateway start`` with
``ALFRED_COMMS_ENABLED_ADAPTERS`` listing the Discord plugin-package id, so
the gateway is actually hosting the adapter. The smoke is a wiring proof, not
a unit — the harness assumes the operator stood the stack up (the same posture
as the rest of ``tests/smoke/``).

The bot token + DB/provider credentials are written into a ``tmp_path``
``secrets.toml`` at 0600 perms under a 0700 parent so the
``SecretBroker._validate_secrets_file_security`` fail-closed check passes;
``ALFRED_SECRETS_FILE`` overrides the broker's path resolution into that
fixture for the subprocess. (G6-5 Task 12 — NOT this task — relocates the
Discord token to the core vault + deletes the standalone secrets bind-mount;
the secret-path lines stay here until then.)

CLAUDE.md hard-rule alignment
-----------------------------

* Never logs the bot token — the value lives only in the ``tmp_path`` TOML
  file (and, in the real flow, crosses to the child over fd-3, never env) and
  is redacted by the structlog redactor. The harness reads stdout but does
  not assert on token bytes.
* Skip-vs-pass discipline: unset env var → ``SKIPPED``, never ``PASSED``.
* The ``tmp_path`` lives under ``/tmp`` (or ``$TMPDIR``) so the broker's
  ``.git`` worktree walk completes without finding a worktree.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from alfred.i18n import t

_TOKEN_ENV = "ALFRED_SMOKE_DISCORD_TOKEN"  # noqa: S105 — env-var name, not a secret value
# The gateway-hosted readiness probe is a daemon-control poll; give it a bounded
# wait plus harness slack for process startup + asyncio loop creation + uv import cost.
_WAIT_READY_TIMEOUT_S = 30
_HARNESS_SLACK_S = 15.0
# The canonical adapter id the gateway hosts Discord under ([comms_mcp] adapter_kind).
_DISCORD_ADAPTER_ID = "discord"


def _token_present() -> bool:
    # GitHub Actions resolves an unset / fork-PR-inaccessible
    # ``${{ secrets.X }}`` to the empty string, NOT undefined, so a plain
    # ``is None`` check would still try to run the smoke against an empty
    # token. Treat unset, empty, and whitespace-only as "skip".
    raw = os.getenv(_TOKEN_ENV)
    return raw is not None and raw.strip() != ""


pytestmark = pytest.mark.skipif(
    not _token_present(),
    reason=(
        f"{_TOKEN_ENV} is unset, empty, or whitespace-only; this smoke "
        "targets a real Discord bot hosted by a live gateway and is skipped "
        "on fork PRs / unconfigured local boxes (GitHub Actions resolves "
        "missing secrets to '', not undefined)."
    ),
)


@pytest.fixture
def smoke_secrets_file(tmp_path: Path) -> Path:
    """Write the operator's throwaway bot token into a 0600 secrets.toml.

    Mirrors the production layout: ``~/.config/alfred/secrets.toml`` is a
    flat TOML map with ``discord_bot_token`` as one of its keys. The fixture
    lives under ``tmp_path`` so the broker's ``.git``-in-parent walk lands on
    the filesystem root without hitting the worktree's ``.git`` dir.

    The parent dir is created at 0700 and the file at 0600 so
    ``_validate_secrets_file_security`` passes — fail-closed. (G6-5 Task 12
    relocates this to the core vault; the lines stay until then.)
    """
    token = os.environ[_TOKEN_ENV]
    parent = tmp_path / "alfred"
    parent.mkdir(mode=0o700)
    path = parent / "secrets.toml"
    # Smoke-only: the token comes from the harness's env, never hardcoded.
    # The TOML file lives in tmp_path that the OS cleans up at process exit.
    path.write_text(f'discord_bot_token = "{token}"\n')
    path.chmod(0o600)
    return path


@pytest.mark.smoke
def test_discord_gateway_reports_ready(smoke_secrets_file: Path) -> None:
    """End-to-end: ``alfred gateway adapters --wait-ready discord`` returns 0 + ready line.

    Subprocess invocation mirrors what an operator's shell does:
    ``python -m alfred gateway adapters --wait-ready discord``. The command
    polls the daemon-control ``status.query`` until the gateway-hosted Discord
    child reaches ``up``, then exits 0 with the localized ready line.

    Outer timeout = the command's ``--timeout`` + harness slack. A gateway that
    never brings Discord up hits the inner ``--timeout`` first and exits 1
    (not-ready); the outer timeout only fires if the subprocess itself stalls —
    a harness bug worth surfacing loudly.
    """
    env = {
        **os.environ,
        "ALFRED_SECRETS_FILE": str(smoke_secrets_file),
        # Settings requires deepseek_api_key + database_url to construct. The
        # control client only reads adapter status, but Settings.model_validate
        # runs first and rejects unset required fields; stuff sane placeholders.
        "ALFRED_DEEPSEEK_API_KEY": env_or_placeholder("ALFRED_DEEPSEEK_API_KEY"),
        "ALFRED_DATABASE_URL": env_or_placeholder(
            "ALFRED_DATABASE_URL",
            default="postgresql+asyncpg://smoke:smoke@127.0.0.1:5432/smoke",
        ),
    }
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "alfred",
            "gateway",
            "adapters",
            "--wait-ready",
            _DISCORD_ADAPTER_ID,
            "--timeout",
            str(_WAIT_READY_TIMEOUT_S),
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=_WAIT_READY_TIMEOUT_S + _HARNESS_SLACK_S,
        check=False,
    )

    assert result.returncode == 0, (
        f"`gateway adapters --wait-ready {_DISCORD_ADAPTER_ID}` returned "
        f"{result.returncode}; stdout={result.stdout!r} stderr={result.stderr!r}"
    )

    # The success surface is the localized ready line. Asserting on the rendered
    # t() string (not a raw English literal) catches a key-rename regression too.
    ready_line = t("gateway.adapters.wait_ready.ready", adapter=_DISCORD_ADAPTER_ID)
    assert ready_line in result.stdout, (
        f"expected the ready line {ready_line!r} on stdout; got {result.stdout!r}"
    )


def env_or_placeholder(name: str, *, default: str = "smoke-placeholder-value") -> str:
    """Return the existing env var or a smoke-safe placeholder.

    Used for Settings fields the status-read path doesn't actually exercise
    (deepseek key + database URL). If the operator's box already has real
    values, pass them through unchanged so a smoke run doesn't clobber a
    working setup.
    """
    existing = os.environ.get(name)
    if existing:
        return existing
    return default

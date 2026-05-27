"""Smoke test for the live Discord gateway: ``alfred discord verify``.

Module-level skip: this test only runs when ``ALFRED_SMOKE_DISCORD_TOKEN``
is set in the environment. The variable carries a throwaway bot token for
a private Discord application the operator/CI owns. Without it the test
reports ``SKIPPED`` rather than ``ERROR`` or ``PASSED`` — same skip-vs-pass
discipline as the rest of the smoke layer.

What the test asserts
---------------------

The test invokes ``python -m alfred discord verify`` as a subprocess (so
the Typer entrypoint, structlog JSON renderer, and Slice-2 dependency
graph all boot the same way an operator's shell would invoke them) and
asserts:

* Exit code is ``0`` within the 30-second verify deadline + a 15s harness
  slack window (so a hung CI runner doesn't loop forever).
* The ``discord.verify.ok`` structlog event appears on stdout, JSON-parsed.
* The captured intents tuple on that event includes ``dm_messages`` AND
  ``message_content`` — the two intents the spec requires for the DM-only
  ingestion path (per ``_compute_intents`` in ``alfred.comms.discord``).

The bot token + DB/provider credentials are written into a ``tmp_path``
``secrets.toml`` at 0600 perms under a 0700 parent so the
``SecretBroker._validate_secrets_file_security`` fail-closed check passes.
``ALFRED_SECRETS_FILE`` overrides the broker's path resolution into that
fixture path for the duration of the subprocess.

CLAUDE.md hard-rule alignment
-----------------------------

* Never logs the bot token — the value lives only in the ``tmp_path``
  TOML file and is redacted by the structlog redactor in the subprocess.
  The harness reads stdout but does not assert on token bytes.
* Skip-vs-pass discipline matches Task 1's spec verbatim (see
  ``docs/superpowers/plans/2026-05-26-slice-2-pr-E-smoke-corpus-docs.md``
  §Task 1 Step 2): unset env var → ``SKIPPED``, never ``PASSED``.
* The DLP layer's ``allow_inside_git_worktree=False`` default would reject
  a secrets file inside the worktree; the ``tmp_path`` lives under
  ``/tmp`` (or ``$TMPDIR`` on macOS) so the ``.git`` walk completes
  without finding a worktree — no override needed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_TOKEN_ENV = "ALFRED_SMOKE_DISCORD_TOKEN"  # noqa: S105 — env-var name, not a secret value
_VERIFY_DEADLINE_S = 30.0
_HARNESS_SLACK_S = 15.0


pytestmark = pytest.mark.skipif(
    os.getenv(_TOKEN_ENV) is None,
    reason=(
        f"{_TOKEN_ENV} is unset; this smoke targets a real Discord bot and "
        "is skipped on fork PRs / unconfigured local boxes."
    ),
)


@pytest.fixture
def smoke_secrets_file(tmp_path: Path) -> Path:
    """Write the operator's throwaway bot token into a 0600 secrets.toml.

    Mirrors the production layout: ``~/.config/alfred/secrets.toml`` is a
    flat TOML map with ``discord_bot_token`` as one of its keys. The
    fixture lives under ``tmp_path`` so the broker's ``.git``-in-parent
    walk lands on the filesystem root without hitting the worktree's
    ``.git`` dir (avoiding the need for ``allow_inside_git_worktree``).

    The parent dir is created at 0700 and the file at 0600 so
    ``_validate_secrets_file_security`` passes — fail-closed.
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
def test_discord_verify_reports_ok(smoke_secrets_file: Path) -> None:
    """End-to-end: ``alfred discord verify`` returns 0 and logs intents.

    Subprocess invocation mirrors what an operator's shell does:
    ``python -m alfred discord verify``. The verify subcommand reads
    ``ALFRED_SECRETS_FILE`` to find the throwaway token, opens a 30s
    gateway probe, fires ``on_ready``, and exits 0 with a
    ``discord.verify.ok`` structlog event on stdout.

    Outer timeout of 45s = the spec's 30s verify deadline + 15s harness
    slack for process startup + asyncio loop creation + uv import cost.
    A hung gateway should hit the inner 30s deadline first and exit 4
    (``TIMEOUT``); the outer 45s only fires if the subprocess itself
    stalls — that's a harness bug worth surfacing loudly.
    """
    env = {
        **os.environ,
        "ALFRED_SECRETS_FILE": str(smoke_secrets_file),
        # Settings requires deepseek_api_key + database_url to construct.
        # The verify path only reads discord_bot_token from the broker,
        # but Settings.model_validate runs first and will reject unset
        # required fields. Stuff sane placeholders so construction
        # succeeds; verify never touches them.
        "ALFRED_DEEPSEEK_API_KEY": env_or_placeholder("ALFRED_DEEPSEEK_API_KEY"),
        "ALFRED_DATABASE_URL": env_or_placeholder(
            "ALFRED_DATABASE_URL",
            default="postgresql+asyncpg://smoke:smoke@127.0.0.1:5432/smoke",
        ),
    }
    result = subprocess.run(
        [sys.executable, "-m", "alfred", "discord", "verify"],
        env=env,
        capture_output=True,
        text=True,
        timeout=_VERIFY_DEADLINE_S + _HARNESS_SLACK_S,
        check=False,
    )

    assert result.returncode == 0, (
        f"verify subcommand returned {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )

    ok_event = _find_structlog_event(result.stdout, "discord.verify.ok")
    assert ok_event is not None, (
        "expected a structlog event with event='discord.verify.ok' on stdout; "
        f"got stdout={result.stdout!r}"
    )

    intents = ok_event.get("intents")
    assert isinstance(intents, list), (
        f"expected intents tuple on the verify-ok event; got {ok_event!r}"
    )
    intents_set = set(intents)
    # Spec §3: DM-only path requires message_content + dm_messages.
    # ``_intents_summary`` in alfred.comms.discord serialises the
    # enabled intents alphabetically; both flags must appear.
    assert "message_content" in intents_set, (
        f"DM-only intents must include message_content; got {intents_set!r}"
    )
    assert "dm_messages" in intents_set, (
        f"DM-only intents must include dm_messages; got {intents_set!r}"
    )


def env_or_placeholder(name: str, *, default: str = "smoke-placeholder-value") -> str:
    """Return the existing env var or a smoke-safe placeholder.

    Used for Settings fields the verify path doesn't actually exercise
    (deepseek key + database URL). If the operator's box already has
    real values, pass them through unchanged so a smoke run doesn't
    clobber a working setup.
    """
    existing = os.environ.get(name)
    if existing:
        return existing
    return default


def _find_structlog_event(stdout: str, event_name: str) -> dict[str, object] | None:
    """Locate the first JSON line on ``stdout`` whose ``event`` matches.

    Structlog's JSONRenderer emits one JSON object per log call on its
    own line. The verify subcommand's first ``_log.info(event_key, ...)``
    is the ``discord.verify.ok`` event when probe returns 0. We scan
    every line (not just the first) because import-time logs from
    ``configure_logging`` or downstream subsystems may precede it.
    """
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("event") == event_name:
            return obj
    return None

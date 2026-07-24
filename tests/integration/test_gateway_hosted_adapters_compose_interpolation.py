"""#469 Blocker 2 devops-003 / test-p-003: proves the REAL ``docker compose config``
interpolation of the gateway's hosted-adapter env var — not just the lexical YAML string
the pure ``tests/unit/test_compose_invariants.py`` fixture checks.

The unit-level invariant test asserts the compose SOURCE TEXT carries the
``ALFRED_GATEWAY_HOSTED_ADAPTERS:-[]`` fallback syntax. It cannot prove Compose actually
resolves that fallback to the empty-list *value* an operator's stack boots with, nor that
the override path an operator would set in ``.env`` still round-trips. This module runs
the real ``docker compose config`` client against the shipped file for both arms.

``docker compose config`` is a **client-only** command — it never talks to a daemon, so
this gates on ``shutil.which("docker")`` (mirrors
``tests/integration/egress/test_core_network_isolation_kernel.py``), NOT the
``pytest.mark.docker`` marker (that marker exists for real-daemon / Testcontainers tests
and would skip this needlessly on a docker-CLI-present-but-daemonless runner).

**Hermetic**: ``docker compose config`` auto-loads an ambient ``.env`` from the invocation
cwd, which would let a developer's own ``.env`` silently change what this test observes.
``--env-file /dev/null`` suppresses that; ``-f docker-compose.yaml`` pins the file
explicitly regardless of cwd.

**Environment shape, measured against docker compose v5.1.2 (2026-07-24)**: ``config
--format json``'s ``services.<name>.environment`` is a ``dict[str, str]`` for this compose
version (unlike the ``KEY=VALUE`` list shape older Compose releases used) — every value
comes back as a STRING, so the empty-list default and the JSON-list override are both
compared as their literal string forms below, never as parsed Python lists.
"""

from __future__ import annotations

# ruff: noqa: S603, S607
# Test-controlled `docker compose` invocations from the integration suite. Every argv is a
# literal authored in this module; nothing crosses an untrusted boundary.
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="docker CLI required for the real `docker compose config` interpolation proof",
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE_FILE = _REPO_ROOT / "docker-compose.yaml"


def _config_env(extra_env: dict[str, str]) -> dict[str, Any]:
    """Return the resolved ``alfred-gateway`` ``environment`` mapping from a real
    ``docker compose config`` run, hermetic against any ambient ``.env`` OR shell env.

    CodeRabbit finding 4 (#469 Blocker 2 PR review): ``--env-file /dev/null`` below only
    blocks an ambient ``.env`` FILE — the child process still inherits ``os.environ``,
    so an ``ALFRED_GATEWAY_HOSTED_ADAPTERS`` already exported in a developer's or CI
    runner's shell would silently shadow the shipped default and the default-case test
    would never actually exercise the ``[]`` fallback it claims to prove. Strip that one
    key out of the inherited base environment unconditionally, THEN layer ``extra_env``
    on top — so the default-case call (``extra_env={}``) is hermetic regardless of the
    ambient shell, while the override-case call still sets it explicitly.
    """
    base_env = {k: v for k, v in os.environ.items() if k != "ALFRED_GATEWAY_HOSTED_ADAPTERS"}
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            "/dev/null",
            "-f",
            str(_COMPOSE_FILE),
            "config",
            "--format",
            "json",
        ],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
        env={**base_env, **extra_env},
    )
    config = json.loads(result.stdout)
    env = config["services"]["alfred-gateway"]["environment"]
    assert isinstance(env, dict), (
        f"expected a dict[str, str] environment shape from this Compose version, got "
        f"{type(env)!r} — see the module docstring's measured-shape note; the accessor "
        f"below needs updating for a KEY=VALUE-list Compose release"
    )
    return env


def test_hosted_adapters_default_is_empty_list() -> None:
    """No ``ALFRED_GATEWAY_HOSTED_ADAPTERS`` override -> the stock default, ``[]``."""
    assert _config_env({})["ALFRED_COMMS_ENABLED_ADAPTERS"] == "[]"


def test_hosted_adapters_override_interpolates() -> None:
    """An operator's ``.env`` override still round-trips through Compose interpolation."""
    env = _config_env({"ALFRED_GATEWAY_HOSTED_ADAPTERS": '["alfred_discord"]'})
    assert env["ALFRED_COMMS_ENABLED_ADAPTERS"] == '["alfred_discord"]'


def test_default_case_is_hermetic_against_ambient_shell_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CodeRabbit finding 4: the default-case test must not be shadowed by an ambient
    shell env var.

    ``--env-file /dev/null`` blocks an ambient ``.env`` FILE, but ``_config_env`` still
    passed ``{**os.environ, **extra_env}`` as the child process environment — so an
    ``ALFRED_GATEWAY_HOSTED_ADAPTERS`` already exported in a developer's or CI runner's
    shell would silently override the shipped ``[]`` default, and
    ``test_hosted_adapters_default_is_empty_list`` would never actually exercise the
    fallback it claims to prove. Simulate that ambient shell state directly (rather
    than relying on the test runner's own environment happening to be clean) so this
    regression is provable without depending on the outer shell's state.
    """
    monkeypatch.setenv("ALFRED_GATEWAY_HOSTED_ADAPTERS", '["alfred_discord"]')
    assert _config_env({})["ALFRED_COMMS_ENABLED_ADAPTERS"] == "[]"

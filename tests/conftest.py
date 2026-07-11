"""Root pytest fixtures shared across the suite.

Exports ``launcher_chain_fixture`` (arch-1 cross-PR contract): a callable
factory that spawns ``bin/alfred-plugin-launcher.sh`` against a per-test
temporary policy directory. PR-S4-7's policy-translation tests import this
fixture; without it they don't compile. The signature is pinned:

    def launcher_chain_fixture(tmp_path: Path) -> Callable[[str], LauncherResult]

Calling the returned callable with a manifest TOML body writes a fixture
manifest under ``tmp_path``, invokes the launcher with a no-op stub binary
under a fake bwrap, and returns the :class:`LauncherResult`.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests._docker_probe import docker_available, docker_unavailable_reason
from tests.support.discord_mocks import DiscordMockFactory

# Enable the built-in ``pytester`` plugin (inert unless the ``pytester`` fixture
# is requested) so the docker auto-skip hook can be exercised end-to-end. Must
# live in the top-most conftest — there is no repo-root conftest.py.
pytest_plugins = ["pytester"]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_LAUNCHER = _REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"

# CR #229 R2 finding-6 (must-fix): a hung launcher must fail THIS test fast
# rather than stall the whole job. ``subprocess.run`` kills the child on
# timeout and re-raises ``TimeoutExpired``, surfacing as a test error.
_LAUNCHER_TIMEOUT_S = 30.0


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip ``docker``-marked tests when no Docker daemon is reachable.

    The Docker-backed unit modules (the Testcontainers web_fetch files, each
    module-marked ``pytest.mark.docker``) would ERROR at fixture setup on a
    daemon-less runner. On the macOS / Windows CI legs — which have no Docker
    daemon — this hook turns that error into a clean SKIP, which is what lets
    ``tests/unit`` run there. On Linux CI and dev boxes with Docker the probe
    returns ``True`` and this is a no-op.

    The skip reason carries the specific probe reason (PATH-absent / hung /
    OSError / nonzero-exit) so the integration fixture's flaky-vs-absent
    diagnostic (PR #217) is preserved uniformly across all docker skips.
    """
    docker_items = [item for item in items if item.get_closest_marker("docker") is not None]
    if not docker_items:
        return  # no docker-marked items collected — don't pay the probe at all
    if docker_available():
        return
    skip_docker = pytest.mark.skip(
        reason=f"docker daemon unavailable: {docker_unavailable_reason()}"
    )
    for item in docker_items:
        item.add_marker(skip_docker)


@dataclass(frozen=True)
class LauncherResult:
    """The outcome of one ``alfred-plugin-launcher.sh`` invocation."""

    returncode: int
    stdout: str
    stderr: str


def _launcher_env(repo_root: Path, extra: dict[str, str]) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(repo_root / "src"),
    }
    env.update(extra)
    return env


@pytest.fixture
def launcher_chain_fixture(
    tmp_path: Path,
) -> Callable[[str], LauncherResult]:
    """Return a callable that runs the launcher against a per-test manifest.

    The callable accepts a manifest TOML body, writes it under ``tmp_path``,
    spawns the launcher with a no-op stub plugin binary + a fake bwrap that
    echoes its args, and returns the :class:`LauncherResult`. Defaults:
    ``ALFRED_ENVIRONMENT=test`` + ``FAKE_UNAME=Linux`` so the Linux policy-
    resolving branch runs on any host. Callers override via ``env_extra``.
    """
    stub = tmp_path / "stub.sh"
    stub.write_text("#!/bin/sh\nexit 0\n")
    stub.chmod(0o755)

    fake_bwrap = tmp_path / "echo-bwrap.sh"
    fake_bwrap.write_text('#!/bin/sh\nprintf "BWRAP_ARGS: %s\\n" "$*"\nexit 0\n')
    fake_bwrap.chmod(0o755)

    def _run(
        manifest_body: str,
        *,
        plugin_id: str = "alfred.example",
        env_extra: dict[str, str] | None = None,
    ) -> LauncherResult:
        manifest = tmp_path / "manifest.toml"
        manifest.write_text(manifest_body)
        extra = {
            "ALFRED_ENVIRONMENT": "test",
            "FAKE_UNAME": "Linux",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
            "BWRAP": str(fake_bwrap),
        }
        if env_extra:
            extra.update(env_extra)
        proc = subprocess.run(  # noqa: S603 — repo-owned launcher script path
            [str(_LAUNCHER), plugin_id, str(stub)],
            capture_output=True,
            text=True,
            env=_launcher_env(_REPO_ROOT, extra),
            check=False,
            timeout=_LAUNCHER_TIMEOUT_S,
        )
        return LauncherResult(proc.returncode, proc.stdout, proc.stderr)

    return _run


@pytest.fixture
def discord_mock_factory() -> DiscordMockFactory:
    """Return the typed Discord double factory (closure test-1).

    The single sanctioned construction site for Discord-shaped test inputs.
    Every ``DiscordMock*`` instance in the suite is built through this factory;
    the AST guard ``tests/unit/discord/test_no_ad_hoc_mocks.py`` forbids ad-hoc
    ``Mock(spec=discord.Message)`` patterns elsewhere.
    """
    return DiscordMockFactory()

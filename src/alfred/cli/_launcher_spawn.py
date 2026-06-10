"""Shared launcher-spawn seam for the ``alfred`` CLI comms surfaces (PR-S4-10, #206).

The Slice-4 comms-MCP flag-day inverts the CLI model: instead of building the
in-process orchestrator graph + comms adapter, an operator-facing comms command
(``alfred chat``, ``alfred discord``) spawns the matching MCP plugin through
``bin/alfred-plugin-launcher.sh`` (the PR-S4-6 policy-resolving launcher) and
lets the already-running daemon own the orchestrator graph.

Both call sites share the same launch shape — build the launcher argv, hand the
child a manifest path + import roots, spawn, and treat a launcher failure within
a short probe window as "the daemon is not running". This module owns that shape
once (DRY) so the per-command modules only supply the plugin-specific inputs and
map the outcome to their own operator-facing ``t()`` string + exit code.

Why a probe window rather than an unconditional wait: a launcher still alive
after the window has handed a live, foreground plugin (the TUI's Textual app)
the operator's terminal — the command should then block on the session. A
launcher that exits *within* the window failed to hand off (absent or
mid-restart daemon, sandbox refusal, bad token). The caller distinguishes the
two via :class:`LaunchOutcome`.

The launcher contract is the REAL PR-S4-6 one: positional
``<plugin_id> <executable> [args...]`` with the manifest path delivered on the
``ALFRED_PLUGIN_MANIFEST_PATH`` environment variable. There are no
``--manifest``/``--adapter-id`` flags (an earlier plan draft assumed them; the
launcher exposes none).
"""

from __future__ import annotations

import asyncio
import os
import shlex
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path

#: Handshake-probe window (seconds). A launcher that exits non-zero within this
#: window means the plugin never reached a live handshake (spec §8.7 /
#: core-005); a launcher still alive after it has handed off a live session.
LAUNCHER_PROBE_TIMEOUT_S = 2.5

#: Default launcher path, overridable via ``ALFRED_PLUGIN_LAUNCHER`` (tests +
#: bespoke deployments point this elsewhere).
_LAUNCHER_ENV_VAR = "ALFRED_PLUGIN_LAUNCHER"


def repo_root() -> Path:
    """Resolve the in-tree repo root that ships ``bin/`` and ``plugins/``.

    The CLI module lives at ``src/alfred/cli/`` so the repo root is three
    parents up. An operator running from the repo root (or with the package
    installed alongside ``bin/``/``plugins/``) gets the right launcher,
    manifest, and plugin-source paths.
    """
    return Path(__file__).resolve().parents[3]


def _launcher_path() -> str:
    return os.environ.get(_LAUNCHER_ENV_VAR, str(repo_root() / "bin" / "alfred-plugin-launcher.sh"))


class LaunchResult(Enum):
    """Coarse outcome of a launcher spawn, mapped by the caller to UX."""

    #: The launcher exited zero after handing off / running to completion.
    COMPLETED = auto()
    #: The launcher failed (non-zero exit in the probe window, missing binary,
    #: or OS spawn error). The daemon contract is unmet.
    FAILED = auto()
    #: The launcher was still alive after the probe window — it handed off a
    #: live, long-running session. Only surfaced to a caller that opted out of
    #: blocking (``block_on_handoff=False``, the ``alfred discord verify``
    #: readiness probe): the seam terminates the child and reports this so the
    #: probe returns promptly instead of awaiting an exit that never comes
    #: (review F3). A blocking caller (``alfred chat`` / boot) never sees it —
    #: it waits for the session to end and gets COMPLETED/FAILED.
    HANDED_OFF = auto()


@dataclass(frozen=True, slots=True)
class LaunchOutcome:
    """Result of :func:`spawn_plugin_via_launcher`.

    ``returncode`` is ``None`` when the spawn itself failed (missing launcher
    binary / OS error) — there was no process to collect a code from.
    """

    result: LaunchResult
    returncode: int | None


@dataclass(frozen=True, slots=True)
class PluginLaunchSpec:
    """Immutable inputs for one plugin launch.

    Attributes:
        plugin_id: The launcher's first positional arg + sandbox-policy key
            (charset ``[A-Za-z0-9._-]+``; the launcher refuses anything else).
        manifest_path: Absolute path to the plugin's ``manifest.toml``,
            delivered on ``ALFRED_PLUGIN_MANIFEST_PATH``.
        module: The ``python -m`` module the launcher executes.
        adapter_id: The per-instance comms-MCP adapter id, delivered on
            ``ALFRED_PLUGIN_ADAPTER_ID``. The plugin binds it as its log self-id
            for the lines it emits BEFORE ``lifecycle.start`` arrives (the TUI
            server's :func:`alfred_tui.server.bind_self_id_from_env`); the
            daemon then re-asserts the AUTHORITATIVE id over the
            ``lifecycle.start`` wire request.
        import_roots: Directories prepended to the child ``PYTHONPATH`` so the
            plugin's package + the core ``alfred.comms_mcp`` protocol resolve.
        inherit_stdio: When true, the child inherits the CLI's stdio (the TUI
            needs the PTY); when false, stdio is piped.
        sandbox_kind: The plugin's manifest ``sandbox.kind`` (``"none"`` |
            ``"full"`` | ...). Drives the child-env posture (review F2): a
            non-``"none"`` plugin is adversary-facing (e.g. the Discord relay,
            ``kind="full"``, open egress per #230) and gets a SCRUBBED,
            allowlisted env so an operator's exported secrets never cross into
            it; ``"none"`` is the operator-local TUI and keeps full passthrough.
    """

    plugin_id: str
    manifest_path: Path
    module: str
    adapter_id: str
    import_roots: tuple[Path, ...]
    inherit_stdio: bool
    sandbox_kind: str


#: Env keys forwarded verbatim into a scrubbed (adversary-facing) child. These
#: are the launcher's OWN operational controls (it reads them from the env we
#: hand it to resolve the per-OS sandbox policy + UID drop — see
#: ``bin/alfred-plugin-launcher.sh`` ``ENVIRONMENT``) plus the locale + PATH the
#: child interpreter needs. NO secret-bearing key (``ANTHROPIC_API_KEY``,
#: ``DISCORD_BOT_TOKEN``, ...) is on this list — that is the whole point of F2.
_SCRUBBED_ENV_ALLOWLIST: tuple[str, ...] = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    # Launcher control surface (parent env -> launcher).
    "ALFRED_ENVIRONMENT",
    "ALFRED_SANDBOX_POLICY_DIR",
    "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED",
    "ALFRED_PLUGIN_UID",
    "FAKE_UNAME",
)


def _spec_env(spec: PluginLaunchSpec, base: dict[str, str]) -> dict[str, str]:
    """Overlay the spec-derived keys (manifest, adapter id, import roots) onto ``base``."""
    base["ALFRED_PLUGIN_MANIFEST_PATH"] = str(spec.manifest_path)
    base["ALFRED_PLUGIN_ADAPTER_ID"] = spec.adapter_id
    existing = base.get("PYTHONPATH", "")
    roots = [str(p) for p in spec.import_roots]
    base["PYTHONPATH"] = os.pathsep.join(p for p in (*roots, existing) if p)
    return base


def _minimal_child_env(spec: PluginLaunchSpec) -> dict[str, str]:
    """Build a SCRUBBED, allowlisted env for an adversary-facing child (review F2).

    Mirrors :mod:`alfred.plugins.stdio_transport`'s minimal-env discipline:
    the env is assembled from an explicit allowlist
    (:data:`_SCRUBBED_ENV_ALLOWLIST`) — never a blanket ``dict(os.environ)`` —
    so the operator's secret-bearing variables cannot leak into a
    ``kind="full"`` plugin (the Discord relay opens egress per #230). The
    AST guard in ``tests/unit/cli/test_launcher_spawn_env_scrub.py`` is the
    release-blocker against any future patch that re-introduces a full-env
    read here.
    """
    base = {name: os.environ[name] for name in _SCRUBBED_ENV_ALLOWLIST if name in os.environ}
    return _spec_env(spec, base)


def _full_child_env(spec: PluginLaunchSpec) -> dict[str, str]:
    """Build a full-passthrough env for the operator-local TUI (``kind="none"``).

    The ``kind="none"`` launcher path ``exec``s the executable directly and the
    child inherits this env; the operator IS the trusted user (no adversary
    ingress) and the foreground Textual app needs the inherited session env, so
    a full ``dict(os.environ)`` passthrough is correct here. NOT used for any
    adversary-facing plugin — :func:`_child_env` routes those to
    :func:`_minimal_child_env`.
    """
    return _spec_env(spec, dict(os.environ))


def _child_env(spec: PluginLaunchSpec) -> dict[str, str]:
    """Build the child environment, scrubbing secrets for adversary-facing plugins.

    Review F2: full ``os.environ`` passthrough is reserved for the
    operator-local TUI (``sandbox_kind="none"``). Every other kind is
    adversary-facing and gets a scrubbed, allowlisted env.
    """
    if spec.sandbox_kind == "none":
        return _full_child_env(spec)
    return _minimal_child_env(spec)


async def spawn_plugin_via_launcher(
    spec: PluginLaunchSpec,
    *,
    block_on_handoff: bool = True,
    probe_timeout_s: float | None = None,
) -> LaunchOutcome:
    """Spawn the plugin through the launcher and resolve the probe-window outcome.

    Returns a :class:`LaunchOutcome` rather than emitting any operator-facing
    text or raising ``typer.Exit`` — the caller owns the ``t()`` string and the
    exit code so each command keeps its own UX contract. A missing launcher
    binary or OS spawn error is reported as :data:`LaunchResult.FAILED` (not
    re-raised) because, from the operator's perspective, it is the same
    "daemon/launcher unavailable" condition as a non-zero exit.

    ``block_on_handoff`` governs what happens when the launcher is STILL ALIVE
    after the probe window — i.e. it handed off a live, long-running session:

    * ``True`` (default — ``alfred chat`` / ``alfred discord`` boot) — re-await
      the child without a deadline so the foreground TUI / long-running relay
      runs to completion; the eventual exit maps to COMPLETED/FAILED.
    * ``False`` (the ``alfred discord verify`` readiness probe) — the hand-off
      itself IS the success signal; awaiting a healthy relay's exit would hang
      forever (review F3). Terminate the child and report
      :data:`LaunchResult.HANDED_OFF`.

    ``probe_timeout_s`` overrides the probe-window length (default
    :data:`LAUNCHER_PROBE_TIMEOUT_S`). ``alfred discord verify`` threads its
    operator-supplied ``--timeout`` here (review F7) so the readiness probe can
    wait longer for a slow-handshaking relay before declaring a hand-off.
    """
    import sys

    timeout = LAUNCHER_PROBE_TIMEOUT_S if probe_timeout_s is None else probe_timeout_s
    cmd = [
        *shlex.split(_launcher_path()),
        spec.plugin_id,
        sys.executable,
        "-m",
        spec.module,
    ]
    stdio = None if spec.inherit_stdio else asyncio.subprocess.PIPE

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=stdio,
            stdout=stdio,
            stderr=stdio,
            env=_child_env(spec),
        )
    except (FileNotFoundError, OSError):
        return LaunchOutcome(result=LaunchResult.FAILED, returncode=None)

    # A launcher that exits within the probe window never handed off — map its
    # code to COMPLETED/FAILED. A launcher still alive after the window handed
    # off a live session.
    try:
        returncode = await asyncio.wait_for(proc.wait(), timeout=timeout)
    except TimeoutError:
        if not block_on_handoff:
            # Readiness probe: alive past the window IS healthy. Terminate the
            # child so the probe returns promptly rather than awaiting an exit
            # a long-running relay never reaches.
            await _terminate(proc)
            return LaunchOutcome(result=LaunchResult.HANDED_OFF, returncode=proc.returncode)
        # Blocking caller (foreground TUI / boot): run the session to
        # completion.
        returncode = await proc.wait()

    result = LaunchResult.COMPLETED if returncode == 0 else LaunchResult.FAILED
    return LaunchOutcome(result=result, returncode=returncode)


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    """Terminate a handed-off child and reap it, escalating to kill on stall.

    SIGTERM first (lets the relay close its gateway cleanly); a child that does
    not exit within a short grace window is SIGKILL'd so the readiness probe
    never blocks on an unresponsive plugin.
    """
    if proc.returncode is not None:
        return
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=_TERMINATE_GRACE_S)
    except TimeoutError:  # pragma: no cover - defensive kill on a wedged child
        proc.kill()
        await proc.wait()


#: Grace window (seconds) between SIGTERM and SIGKILL when terminating a
#: handed-off child during a readiness probe.
_TERMINATE_GRACE_S = 2.0


__all__ = [
    "LAUNCHER_PROBE_TIMEOUT_S",
    "LaunchOutcome",
    "LaunchResult",
    "PluginLaunchSpec",
    "repo_root",
    "spawn_plugin_via_launcher",
]

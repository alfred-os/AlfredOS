"""``alfred daemon`` CLI — boot / stop / status for the AlfredOS daemon (#174).

Spec §3 (issue #174). The daemon entrypoint constructs
``Supervisor(state_git_path=Settings.state_git_path, ...)`` so the
merged-proposal dispatch loop (ADR-0021 / Slice-3 ``_proposal_dispatch_loop``)
runs in deployed installs for the first time.

Probes run at the CLI layer pre-TaskGroup (core-007 closure): the Slice-3
``Supervisor.start()`` is TaskGroup-first, so a pre-flight phase belongs
above the construction site, not inside it.

Three hookpoints are declared by :func:`declare_hookpoints`, called at
module import:

* ``daemon.boot.completed`` (T0, fail_closed=True) — emitted once per
  successful boot.
* ``daemon.boot.failed`` (T0, fail_closed=True) — emitted on every typed
  refusal mode in :data:`alfred.cli.daemon._failures.DaemonBootFailure`.
* ``proposal.dispatch.failed`` (T0, fail_closed=True) — emitted by the
  dispatch loop when a single proposal blob fails. PR-S4-2 subscribes an
  OutboundDlp-scan handler; this PR only declares the hookpoint.

The hookpoints carry ``carrier_tier=T0`` (system-internal — none of these
paths carries operator or untrusted content) and ``fail_closed=True`` (a
crashing subscriber on a boot/dispatch fault is a security-relevant
signal, not observability noise).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from alfred.i18n import t

if TYPE_CHECKING:
    from alfred.hooks.registry import HookRegistry

# The three daemon hookpoint names this PR owns. Module-level tuple so the
# manifest (``alfred.hooks._known_hookpoints.KNOWN_HOOKPOINTS``) and the
# declaration loop share one source of truth (no string duplication that
# could drift). Pinned by ``tests/unit/hooks/test_known_hookpoints_sync.py``.
_DAEMON_HOOKPOINTS: tuple[str, ...] = (
    "daemon.boot.completed",
    "daemon.boot.failed",
    "proposal.dispatch.failed",
)


def declare_hookpoints(registry: HookRegistry | None = None) -> None:
    """Register the three daemon hookpoints this PR owns.

    Mirrors the ``declare_hookpoints`` pattern used by
    :mod:`alfred.memory.episodic` and :mod:`alfred.identity._ingest`: a
    standalone function the drift detector
    (``tests/unit/hooks/test_known_hookpoints_sync.py``) can call, plus a
    module-level invocation at the bottom of this module so a plain
    ``import alfred.cli.daemon`` fires it. Idempotent on equal metadata
    (the registry's standard re-declaration guard).

    Args:
        registry: The :class:`HookRegistry` to declare against. ``None``
            uses the process singleton via
            :func:`alfred.hooks.get_registry`.
    """
    from alfred.hooks import SYSTEM_ONLY_TIERS, get_registry
    from alfred.security.tiers import T0

    target = registry if registry is not None else get_registry()
    for name in _DAEMON_HOOKPOINTS:
        target.register_hookpoint(
            name=name,
            subscribable_tiers=SYSTEM_ONLY_TIERS,
            refusable_tiers=frozenset(),
            fail_closed=True,
            carrier_tier=T0,
        )


daemon_app = typer.Typer(help=t("daemon.help.root"), no_args_is_help=True)


@daemon_app.command("start", help=t("daemon.help.start"))
def start() -> None:
    from alfred.cli.daemon._commands import start_daemon

    start_daemon()


@daemon_app.command("stop", help=t("daemon.help.stop"))
def stop() -> None:
    from alfred.cli.daemon._commands import stop_daemon

    stop_daemon()


@daemon_app.command("status", help=t("daemon.status.help"))
def status() -> None:
    from alfred.cli.daemon._commands import status_daemon

    status_daemon()


@daemon_app.command("healthcheck", help=t("daemon.help.healthcheck"))
def healthcheck() -> None:
    from alfred.cli.daemon._healthcheck import healthcheck_daemon

    healthcheck_daemon()


# Module-import-time declaration — mirrors alfred.identity._ingest's
# bottom-of-module declare_hookpoints() call so a plain import wires the
# hookpoints. The sync test's importlib.import_module("alfred.cli.daemon")
# relies on this firing.
declare_hookpoints()


__all__ = ["daemon_app", "declare_hookpoints"]

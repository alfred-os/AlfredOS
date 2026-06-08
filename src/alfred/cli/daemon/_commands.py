"""Daemon command bodies (#174 PR-S4-1).

Component D ships placeholder bodies; Component E fills in the real boot
sequence (probes → Supervisor construction → audit → TaskGroup), the
SIGTERM-via-PID-file stop, and the PID-file status renderer.
"""

from __future__ import annotations

import typer


def start_daemon() -> None:
    """Placeholder — Component E ships the probe + boot sequence."""
    typer.echo("start TBD")


def stop_daemon() -> None:
    """Placeholder — Component E ships the SIGTERM-via-PID-file body."""
    typer.echo("stop TBD")


def status_daemon() -> None:
    """Placeholder — Component E ships the PID-file status renderer."""
    typer.echo("status TBD")

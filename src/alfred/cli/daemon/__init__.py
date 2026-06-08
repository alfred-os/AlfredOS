"""``alfred daemon`` CLI package (#174 PR-S4-1).

Component D populates this module with the three Slice-4 hookpoint
declarations (``daemon.boot.completed`` / ``daemon.boot.failed`` /
``proposal.dispatch.failed``) and the ``daemon_app`` Typer group with its
``start`` / ``stop`` / ``status`` subcommands. Until then the package
exists only as the home for the CLI-layer helper modules (``_failures``,
``_daemon_probes``, ``_daemon_pidfile``, ``_audit_fallback``).
"""

from __future__ import annotations

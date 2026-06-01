"""Top-level CLI sub-app registration (PR-S3-6 Component G — Task 13).

Pins the wiring contract for ``src/alfred/cli/main.py``:

* The five Slice-3 sub-apps (``plugin``, ``web``, ``config``,
  ``supervisor``, ``audit``) are each reachable from ``alfred --help``
  and surface their own help text when invoked with ``--help``.
* ``alfred audit graph --tier`` (the swimlane filter shipped in
  ed9bb69) is reachable through the registered ``audit`` sub-app —
  not just through direct import of ``audit_app``.

These tests are intentionally smoke-thin. The per-sub-app behaviour
(grants, allowlist mutations, config set/get, supervisor reset, graph
queries) is covered exhaustively in the dedicated test modules
alongside each sub-app. What this file verifies is that an operator
who runs ``alfred <subcmd>`` actually reaches those commands — i.e.
that the registration call in ``main.py`` hasn't been accidentally
removed or shadowed.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from alfred.cli.main import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Top-level: every Slice-3 sub-app appears in ``alfred --help``.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "subcommand",
    [
        "plugin",
        "web",
        "config",
        "supervisor",
        "audit",
    ],
)
def test_subapp_appears_in_root_help(subcommand: str) -> None:
    """Each registered sub-app must show in the root ``--help`` listing.

    Regression target: a missing ``app.add_typer(...)`` call would still
    let direct imports of ``plugin_app`` etc. work, but operators
    invoking ``alfred plugin`` would hit "no such command". The root
    help is the operator's discovery surface.
    """
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0, result.stdout
    assert subcommand in result.stdout, (
        f"Expected ``{subcommand}`` in ``alfred --help`` output; got:\n{result.stdout}"
    )


# ---------------------------------------------------------------------------
# Per-sub-app: invoking ``alfred <subcmd> --help`` succeeds and shows
# the sub-app's own help text. This is the reachability check — a
# registration error would surface here as exit_code != 0.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("subcommand", "expected_help_fragment"),
    [
        ("plugin", "plugin"),
        ("web", "web-fetch"),
        ("config", "configuration"),
        ("supervisor", "supervised"),
        ("audit", "audit"),
    ],
)
def test_subapp_help_is_reachable(subcommand: str, expected_help_fragment: str) -> None:
    """``alfred <subcmd> --help`` exits zero and surfaces sub-app help text.

    The fragments asserted here are drawn from each sub-app's own
    ``Typer(help=...)`` string (see locale/en/LC_MESSAGES/alfred.po).
    If the wiring in ``main.py`` ever shadows a sub-app with a stub
    Typer instance, the help string would diverge from the source —
    this catches that.
    """
    result = runner.invoke(app, [subcommand, "--help"])
    assert result.exit_code == 0, (
        f"``alfred {subcommand} --help`` exited {result.exit_code}; stdout:\n{result.stdout}"
    )
    assert expected_help_fragment.lower() in result.stdout.lower(), (
        f"Expected ``{expected_help_fragment}`` in ``alfred {subcommand} "
        f"--help`` output; got:\n{result.stdout}"
    )


# ---------------------------------------------------------------------------
# Audit-specific: the ``--tier`` swimlane filter (ed9bb69) must be
# reachable through the registered sub-app, not just via direct
# import. ``--help`` is enough — actually running the query requires
# Postgres; that path is covered by test_audit_graph_tier_swimlanes.
# ---------------------------------------------------------------------------


def test_audit_graph_tier_flag_is_reachable_through_registration() -> None:
    """``alfred audit graph --help`` must list the ``--tier`` option.

    The graph + tier filter ship in audit_app; this asserts the
    registration in main.py exposes the flag end-to-end so an
    operator invoking ``alfred audit graph --tier T3`` can actually
    reach the swimlane query.
    """
    result = runner.invoke(app, ["audit", "graph", "--help"])
    assert result.exit_code == 0, result.stdout
    assert "--tier" in result.stdout, (
        f"Expected ``--tier`` option in ``alfred audit graph --help``; got:\n{result.stdout}"
    )

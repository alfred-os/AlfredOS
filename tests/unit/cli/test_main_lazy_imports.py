"""Module-load discipline for ``alfred.cli.main`` (PR-S3-6 perf-001).

The CLI entry point is the bootstrap for the full slice-1/2 dependency
graph — :class:`Orchestrator`, :class:`BudgetGuard`, :class:`WorkingMemoryPool`,
:class:`EpisodicMemory`, :class:`AuditWriter`, :class:`OutboundDlp`, the
provider adapters, the SQLAlchemy engine + sessionmaker. Pre-perf-001 the
entire chain was imported at module-top so every ``alfred --help`` (and
every ``alfred <subcmd> --help`` rendered through it) paid the full
import cost just to render the typer surface. Measured ~0.98 s on the
dev mac before the fix; the typer surface itself is sub-300 ms once the
heavy chain is excluded.

The fix pushes every chat-graph import inside :func:`alfred.cli.main._chat_main`
(plus tighter scope-local imports inside ``status`` and ``migrate``).
This file pins the invariant by booting a **fresh** Python interpreter
(via :mod:`subprocess`) so the assertion is not polluted by other test
modules that may legitimately have imported the heavy chain into the
shared pytest process's ``sys.modules``. The child process imports
``alfred.cli.main`` and prints a JSON list of every loaded ``alfred.*``
module — we then assert that the chat-graph prefixes are absent.

The forbidden-prefix list is intentionally conservative:

* ``alfred.providers`` — DeepSeek / Anthropic adapter chains, each
  drag a provider SDK + HTTP layer.
* ``alfred.memory.db`` — the async session-scope factory + the
  SQLAlchemy async engine.
* ``alfred.memory.episodic`` — :class:`EpisodicMemory`, used only by
  the chat-graph and the proposal queue.
* ``alfred.memory.working_pool`` — :class:`WorkingMemoryPool`, the
  per-user buffer manager for the orchestrator.
* ``alfred.orchestrator`` — pulls in supervisor + plugin chain.
* ``alfred.budget`` — :class:`BudgetGuard` is a chat-graph-only seam.
* ``alfred.comms.adapter`` — the in-process comms adapter chain.
  **Deleted in PR-S4-10 (#206)** by the comms-MCP flag-day; ``_chat_main``
  now spawns the TUI plugin via the launcher and imports nothing under
  ``alfred.comms``. Kept here as a PERMANENT FLOOR — a regression that
  resurrects the in-process adapter on the ``--help`` path fails loudly
  rather than silently re-adding the import cost.
* ``alfred.gateway.process`` / ``alfred.gateway.relay`` — the
  ``alfred gateway start`` relay graph (client listener + core link +
  the two-direction pump). PR-S4-G3-3b-2b (#237) registers the
  ``gateway`` Typer group at module-top but imports the process /
  relay chain LAZILY inside the ``start`` command body, so
  ``alfred --help`` never pays the relay import cost. Pinned here so a
  refactor that hoists the relay import back to module-top fails loudly.

``alfred.memory.models`` is **deliberately not in the list** because
:class:`alfred.identity.models` (which the ``alfred user`` Typer surface
needs at registration time) imports :class:`Base` from it. Excluding
``alfred.memory.models`` would require a separate refactor of the
identity ORM (split ``Base`` into its own module). Tracked as a Slice-4
follow-up; the heavier sub-paths under ``alfred.memory`` that are
chat-graph-only are still pinned here.

If a future refactor needs one of these at module-top for a legitimate
reason, the fix is to update this list **and** document why in the
``_chat_main`` deferred-import block — not to silently weaken the
invariant.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Final

import pytest

# The chat-graph dependency prefixes that MUST stay out of the
# import graph of ``alfred.cli.main`` at module load. See module
# docstring for the rationale per entry. Each entry is the dotted
# prefix; the membership check matches the exact name or any deeper
# submodule (``alfred.providers`` matches both ``alfred.providers``
# and ``alfred.providers.deepseek``).
_FORBIDDEN_PREFIXES: Final[tuple[str, ...]] = (
    "alfred.providers",
    "alfred.memory.db",
    "alfred.memory.episodic",
    "alfred.memory.working_pool",
    "alfred.orchestrator",
    "alfred.budget",
    "alfred.comms.adapter",
    "alfred.gateway.process",
    "alfred.gateway.relay",
)


def _modules_loaded_after_importing_main() -> list[str]:
    """Return every ``alfred.*`` module loaded after a fresh ``import alfred.cli.main``.

    Uses a child interpreter via :mod:`subprocess` so the pytest parent's
    pre-existing ``sys.modules`` cannot mask a regression: another test
    in this run may legitimately have imported ``alfred.orchestrator``
    minutes before this test runs, so a same-process ``sys.modules``
    snapshot would always show the forbidden modules even if
    ``alfred.cli.main`` itself had not pulled them in.

    The child writes its ``sys.modules`` keys as JSON to stdout so the
    parent decodes a typed ``list[str]`` rather than parsing repr
    output.

    Failure mode: a non-zero child exit (e.g. an ImportError introduced
    elsewhere) re-raises through ``check_returncode``. The captured
    stderr is propagated in the assertion message so the failure is
    self-describing.
    """
    # ``-I`` (isolated mode) avoids inheriting site-customisations or
    # ``PYTHONPATH`` shenanigans that could mask a real regression.
    # Cannot use ``-S`` because we need ``alfred`` on ``sys.path``,
    # which the parent's ``.venv`` provides via ``site``.
    # CR-149: the docstring above promises ``-I`` but the previous
    # argv omitted it, letting the child inherit the ambient user /
    # site environment. A real lazy-import regression could hide
    # behind a customisation hook that preloads ``alfred.*`` before
    # ``import alfred.cli.main`` runs in the child. Adding the flag
    # makes the snapshot honest.
    child = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import alfred.cli.main; "
                "import json, sys; "
                "print(json.dumps(sorted("
                "k for k in sys.modules if k.startswith('alfred.')"
                ")))"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if child.returncode != 0:
        msg = (
            f"Child interpreter exited {child.returncode} while importing "
            f"alfred.cli.main.\n--- stdout ---\n{child.stdout}\n"
            f"--- stderr ---\n{child.stderr}"
        )
        raise AssertionError(msg)
    return list(json.loads(child.stdout))


def test_alfred_cli_main_does_not_import_chat_graph_at_module_load() -> None:
    """``import alfred.cli.main`` must not pull in the chat-graph chain.

    Regression target: pre-perf-001 the module-top imports of
    :class:`Orchestrator`, :class:`BudgetGuard`, :class:`WorkingMemoryPool`,
    :class:`EpisodicMemory`, :class:`AuditWriter`, :class:`OutboundDlp`,
    the providers, and the SQLAlchemy engine cost ~0.7 s at import time
    and made every ``alfred --help`` invocation pay the full bootstrap
    even though the typer surface never invokes ``_chat_main``.

    The fix pushed every heavy import inside the functions that need
    them. This test pins the contract: any future refactor that re-
    surfaces a chat-graph module at module-top (deliberately or via a
    transitive ``alfred.audit`` / ``alfred.config`` chain that the
    sub-app modules pull in eagerly) fails here with a clear message
    naming the forbidden prefix that leaked.
    """
    loaded = _modules_loaded_after_importing_main()
    leaks: list[str] = [
        m for m in loaded if any(m == p or m.startswith(p + ".") for p in _FORBIDDEN_PREFIXES)
    ]
    assert not leaks, (
        "alfred.cli.main pulled chat-graph modules at module load. "
        "perf-001 invariant violated. Leaked modules: "
        f"{leaks}\n"
        "Move the offending import inside the function body that needs "
        "it (mirror the ``_chat_main`` pattern in src/alfred/cli/main.py)."
    )


@pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "POSIX-only: rich/typer --help console-detection under CliRunner's "
        "captured stream (#246 review)"
    ),
)
def test_alfred_cli_main_lazy_load_keeps_help_surface_intact() -> None:
    """The lazy-load refactor must not break the ``alfred --help`` surface.

    Complements the discipline test above: pruning module-top imports
    risks breaking the Typer surface itself (a missing ``Typer(...)``
    registration would surface as a missing subcommand in ``--help``).
    Booting a child interpreter that imports the module + invokes the
    typer app with ``["--help"]`` keeps the contract end-to-end.

    Asserts the seven registered sub-apps appear in the help output —
    the same set ``tests/unit/cli/test_cli_registration.py`` pins, but
    asserted here as a sanity backstop against a refactor that silently
    deletes a registration call alongside the lazy-import work.
    """
    # CR-149 round-3: ``-I`` mirrors the earlier probe in this
    # module. Without it the child inherits the developer's
    # ``sitecustomize`` / ``PYTHONPATH``, so a hostile sitecustomize
    # could keep ``alfred --help`` green while the isolated-import
    # path is genuinely broken. The lazy-load discipline this test
    # guards depends on a clean import environment — isolated mode
    # delivers it.
    child = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "from typer.testing import CliRunner; "
                "from alfred.cli.main import app; "
                "result = CliRunner().invoke(app, ['--help']); "
                "import sys; "
                "sys.stdout.write(result.stdout); "
                "sys.exit(result.exit_code)"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert child.returncode == 0, (
        f"alfred --help exited {child.returncode} after lazy-import refactor.\n"
        f"stdout:\n{child.stdout}\nstderr:\n{child.stderr}"
    )
    expected_subcommands = (
        "status",
        "chat",
        "user",
        "plugin",
        "web",
        "config",
        "supervisor",
        "audit",
        "gateway",
    )
    for subcommand in expected_subcommands:
        assert subcommand in child.stdout, (
            f"Sub-command ``{subcommand}`` missing from ``alfred --help`` "
            f"output after lazy-import refactor; got:\n{child.stdout}"
        )

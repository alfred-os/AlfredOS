"""#410 PR1 final review (I-3): the comms boot graph's ONE `role=TURN` wiring is covered.

``_build_comms_boot_graph`` (``_comms_boot.py``) passes ``role=ConnectionRole.TURN``
to ``build_boot_session_scope`` for the orchestrator's ``session_scope`` kwarg — the
production wiring that keeps the orchestrator's Phase A/C transactions on the
budgeted TURN pool and the ADR-0062 nesting guard armed. Every OTHER
``build_boot_session_scope`` call the comms graph makes (``audit_session_scope``,
the working-memory pool, the forwarded-dispatch-attempt store, the inbound
idempotency store) stays on the default SIDE_EFFECT role.

Before this test, no test asserted the ``role=`` kwarg at all:
``test_build_orchestrator_wiring.py`` only covers ``build_orchestrator``'s
DEFAULT-path role sequence (``_bootstrap.build_session_scope``), not the
production injected-scopes path ``_comms_boot.py`` actually drives (it calls
``build_orchestrator`` with ``session_scope=``/``audit_session_scope=`` already
built). And this package's own ``boot_success_env`` fixture
(``conftest.py``) monkeypatches ``_commands.build_boot_session_scope`` with an
inert double — ``lambda _settings, *, role=None: lambda: None`` — that accepts
and DISCARDS the role entirely. So deleting ``role=ConnectionRole.TURN`` from
``_comms_boot.py`` would silently put the orchestrator's phase transactions on
the SIDE_EFFECT pool and disarm the nesting guard in production, with a fully
green test suite. This test upgrades that inert double to a RECORDING one
(mirroring the pattern in ``test_build_orchestrator_wiring.py``) so a real
daemon boot's role sequence is observable and asserted.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from alfred.cli import _bootstrap
from alfred.cli.daemon import daemon_app
from alfred.hooks.registry import HookRegistry
from alfred.memory.db import ConnectionRole

from .conftest import FakeAuditWriter
from .test_daemon_comms_spawn import _ENABLED_ADAPTER, _patch_comms_seams, quarantine_registry

__all__ = ["quarantine_registry"]  # re-exported fixture; silence the unused-import lint


@pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "POSIX-only: real daemon-boot pipeline touches os.O_NOFOLLOW "
        "(pidfile write) not exposed on Windows"
    ),
)
def test_comms_boot_graph_wires_exactly_one_turn_scope(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """A real comms-enabled boot passes ``role=TURN`` exactly once, never CONTROL.

    #410 PR1 review (CodeRabbit, round 2): the aggregate role counts below
    are necessary but not sufficient — they cannot distinguish "TURN went to
    the orchestrator's ``session_scope``" from "TURN went to some OTHER
    boot-graph call and the orchestrator got a SIDE_EFFECT scope instead",
    since both shapes produce the same (1 TURN, N SIDE_EFFECT) tally. Each
    recorded scope is now a DISTINCT sentinel object, and a spy on
    ``build_orchestrator`` captures its actual ``session_scope=`` argument
    by identity — the test fails if the orchestrator's scope is ever NOT
    the specific sentinel returned for the ``role=ConnectionRole.TURN`` call,
    even if the aggregate counts still happen to line up.
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    recorded_roles: list[ConnectionRole] = []
    turn_sentinels: list[Any] = []

    def _recording_build_boot_session_scope(
        _settings: Any,
        *,
        role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
    ) -> Any:
        recorded_roles.append(role)

        # A fresh, distinctly-identified no-op scope per call — identity
        # (`is`), not equality, is what proves WHICH call's return value
        # reached the orchestrator.
        def _scope() -> None:
            return None

        if role is ConnectionRole.TURN:
            turn_sentinels.append(_scope)
        return _scope

    # Overrides boot_success_env's own inert double (set during ITS fixture
    # setup, which runs before this test body) — same monkeypatch instance,
    # so this later setattr wins for the remainder of the test.
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_session_scope",
        _recording_build_boot_session_scope,
    )

    real_build_orchestrator = _bootstrap.build_orchestrator
    captured_session_scopes: list[Any] = []

    def _spy_build_orchestrator(*args: Any, **kwargs: Any) -> Any:
        captured_session_scopes.append(kwargs.get("session_scope"))
        return real_build_orchestrator(*args, **kwargs)

    # `_build_comms_boot_graph` imports `build_orchestrator` from this module
    # AT CALL TIME (module-load-cycle break, #256 PR-3), so patching the
    # module attribute here — not a re-exported name — is what the lazy
    # import actually picks up.
    monkeypatch.setattr(_bootstrap, "build_orchestrator", _spy_build_orchestrator)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    # Never CONTROL over this seam — CONTROL is reserved for CLI/Alembic/
    # gate-backend/identity-resolver traffic (ADR-0062), never the boot graph.
    assert ConnectionRole.CONTROL not in recorded_roles

    # `_build_comms_boot_graph` is the ONLY call site in this boot that can
    # ever request TURN (`_commands.py`'s own two calls — the probe-(c)
    # capability-gate handshake and the post-Settings audit-writer rebuild,
    # #410 PR1 final review I-1 — are both unconditionally SIDE_EFFECT, and
    # both run BEFORE `_build_comms_boot_graph` is invoked). So exactly one
    # TURN call, over the whole boot, IS the assertion that
    # `session_scope=build_boot_session_scope(settings, role=ConnectionRole.TURN)`
    # survived at `_comms_boot.py`'s orchestrator construction — deleting
    # that kwarg (defaulting to SIDE_EFFECT) would drop this to zero.
    assert recorded_roles.count(ConnectionRole.TURN) == 1

    # The comms graph's four OTHER `build_boot_session_scope` calls
    # (audit_session_scope, the working-memory pool, the forwarded-dispatch-
    # attempt store, the inbound idempotency store) plus `_commands.py`'s own
    # two SIDE_EFFECT calls named above account for every remaining entry.
    assert recorded_roles.count(ConnectionRole.SIDE_EFFECT) == len(recorded_roles) - 1
    assert recorded_roles.count(ConnectionRole.SIDE_EFFECT) >= 6

    # The identity check CodeRabbit's finding asked for: the orchestrator's
    # OWN session_scope= argument must BE the sentinel minted for the TURN
    # call — not merely "some TURN call happened somewhere in the boot".
    assert len(captured_session_scopes) == 1
    assert len(turn_sentinels) == 1
    assert captured_session_scopes[0] is turn_sentinels[0]

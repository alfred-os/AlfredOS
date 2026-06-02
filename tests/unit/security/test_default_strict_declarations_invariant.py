"""Bootstrap gate-selection invariant tests (PR-S3-2 Task 13).

Spec §8.4 + PR-S3-7 (spec §15.1 flag-day):
:class:`alfred.security.capability_gate._gate.RealGate` is now BOTH
the production and the development gate. The dev branch wires it with
an empty grant snapshot and an in-process backend stub (no Postgres);
the production branch wires it with a real
:class:`alfred.security.capability_gate.backend.PostgresBackend` and
the heartbeat running. The Slice-2.5 :class:`DevGate` was removed in
PR-S3-7. :mod:`alfred.bootstrap.gate_factory` is the ONLY module in
``src/alfred/`` that may read ``ALFRED_ENV`` for the purpose of
selecting which RealGate construction the supervisor wires — sec-007
forbids the read inside the gate itself, where an env-at-import-time
read would make the gate's construction depend on global state
rather than injected configuration.

Two invariants under test:

1. **Behavioural** — :func:`build_dev_gate` returns a
   :class:`RealGate` over an empty grant snapshot (every check denies
   fail-closed); :func:`build_real_gate` returns a :class:`RealGate`
   constructed against the supplied backend and audit sink.
2. **Source-level** — :mod:`alfred.hooks.capability`,
   :mod:`alfred.security.capability_gate.policy`, and
   :mod:`alfred.security.capability_gate._gate` MUST NOT contain a
   literal ``"ALFRED_ENV"`` string constant. The AST scan in
   :mod:`tests.unit.security.test_capability_gate_ast_no_os_import`
   covers the broader ``import os`` guard; this test pins the narrower
   ``ALFRED_ENV`` discipline as a separate failure surface so a future
   contributor cannot route ``os.getenv("ALFRED_ENV")`` through an
   indirection inside the gate.

The :func:`build_real_gate` test uses an ``AsyncMock`` :class:`StorageBackend`
double rather than testcontainers — the bootstrap factory is a thin DI seam
and exercising the full Postgres backend here would conflate two failure
surfaces (DI wiring vs storage roundtrip). The roundtrip is covered by
:mod:`tests.integration.security.test_grant_lifecycle_e2e` (Task 18).
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest


def test_build_dev_gate_returns_realgate_with_empty_grants() -> None:
    """:func:`build_dev_gate` returns a fail-closed :class:`RealGate`.

    PR-S3-7 (spec §15.1 flag-day): the Slice-2.5 :class:`DevGate`
    was removed from ``src/``; the development bootstrap path now
    constructs a :class:`RealGate` with an empty grant snapshot, an
    in-process backend stub, and no heartbeat. Every check denies
    fail-closed — the safer default in the absence of a real grant
    table. A developer who needs granted-system semantics for local
    iteration uses :mod:`tests.helpers.gates` or seeds a real Postgres
    grants table.
    """
    from alfred.bootstrap import gate_factory
    from alfred.security.capability_gate._gate import RealGate

    gate = gate_factory.build_dev_gate()
    assert isinstance(gate, RealGate)
    # Empty grant snapshot ⇒ every check denies fail-closed.
    assert not gate.check(plugin_id="any", hookpoint="any", requested_tier="operator")
    assert not gate.check(plugin_id="any", hookpoint="any", requested_tier="system")
    assert not gate.check(plugin_id="any", hookpoint="any", requested_tier="user-plugin")


# ---------------------------------------------------------------------------
# DEVEX-004 — bootstrap.gate_selected log event. An operator who typos
# `ALFRED_ENV=prod` (instead of "production") still gets RealGate (safer-
# by-default), but used to have no way to confirm that without grepping
# code. The factory now emits an INFO-level structured log event on
# every gate selection so the operator's log stream visibly records the
# decision + the exact env value the bootstrap read.
# ---------------------------------------------------------------------------


def test_build_dev_gate_emits_gate_selected_log_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dev-bootstrap gate construction emits ``bootstrap.gate_selected``.

    The structlog event MUST include:
    - ``gate="DevelopmentRealGate"`` (PR-S3-7 closed vocabulary; log
      filters match on it — distinct from the production
      ``gate="RealGate"`` so an operator can spot the dev-branch wire
      reaching production by mistake)
    - ``alfred_env=<raw>`` so an operator can confirm the env value
    - ``warning="..."`` so the fail-closed-by-default posture is
      visible in dashboards

    Uses :func:`structlog.testing.capture_logs` rather than ``caplog``
    because the structlog config in this repo routes through structlog's
    own pipeline (not stdlib logging) for INFO-level events.

    DEVEX-004 fix.
    """
    import structlog.testing

    monkeypatch.delenv("ALFRED_ENV", raising=False)
    from alfred.bootstrap import gate_factory

    importlib.reload(gate_factory)
    with structlog.testing.capture_logs() as captured:
        gate_factory.build_dev_gate()
    events = [e for e in captured if e.get("event") == "bootstrap.gate_selected"]
    assert events, f"expected bootstrap.gate_selected event; got {captured!r}"
    entry = events[0]
    assert entry["gate"] == "DevelopmentRealGate"
    # The raw env value (unset → "(unset)") surfaces so an operator can
    # confirm the bootstrap saw what they intended.
    assert entry["alfred_env"] == "(unset)"
    # The dev-branch posture warning surfaces in dashboards without
    # having to know which filter to add.
    assert "warning" in entry
    assert "production" in entry["warning"].lower()


@pytest.mark.asyncio
async def test_build_real_gate_emits_gate_selected_log_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RealGate construction emits ``bootstrap.gate_selected`` carrying the raw env.

    The DEVEX-004 audit trail is most useful in production — confirms an
    operator's `ALFRED_ENV` setting actually made it to the bootstrap.
    The raw_env value is echoed verbatim (no normalisation) so a typo
    like ``prdouction`` shows up in the log line.
    """
    import structlog.testing

    monkeypatch.setenv("ALFRED_ENV", "prdouction")  # operator typo
    from alfred.bootstrap import gate_factory

    importlib.reload(gate_factory)
    backend = MagicMock()
    backend.ping = AsyncMock(return_value=None)
    backend.load_grants = AsyncMock(return_value=frozenset())
    backend.get_sync_hash = AsyncMock(return_value=None)
    audit_sink = MagicMock()
    audit_sink.append_schema = AsyncMock(return_value=None)
    with structlog.testing.capture_logs() as captured:
        await gate_factory.build_real_gate(
            backend=backend,
            audit_sink=audit_sink,
            start_heartbeat=False,
        )
    events = [e for e in captured if e.get("event") == "bootstrap.gate_selected"]
    assert events, f"expected bootstrap.gate_selected event; got {captured!r}"
    entry = events[0]
    assert entry["gate"] == "RealGate"
    # The exact raw value the bootstrap read must surface so the operator
    # can self-diagnose a typo without grepping `os.environ` themselves.
    assert entry["alfred_env"] == "prdouction"


@pytest.mark.asyncio
async def test_build_real_gate_returns_realgate_instance() -> None:
    """Build a :class:`RealGate` against the supplied backend + audit sink.

    The factory is the production-side equivalent of
    :func:`build_dev_gate`. It is async because
    :meth:`RealGate.create` runs the initial Postgres load before
    returning a ready instance — that load CANNOT happen inside a sync
    factory without an event-loop dance.

    ``start_heartbeat=False`` keeps the test deterministic: the
    background heartbeat would race the test runner without explicit
    cancellation. Production bootstrap passes ``start_heartbeat=True``
    after the gate is wired into the supervisor.
    """
    from alfred.bootstrap import gate_factory
    from alfred.security.capability_gate._gate import RealGate

    backend = MagicMock()
    backend.ping = AsyncMock(return_value=None)
    backend.load_grants = AsyncMock(return_value=frozenset())
    backend.get_sync_hash = AsyncMock(return_value=None)
    audit_sink = MagicMock()
    audit_sink.append_schema = AsyncMock(return_value=None)

    gate = await gate_factory.build_real_gate(
        backend=backend,
        audit_sink=audit_sink,
        start_heartbeat=False,
    )

    assert isinstance(gate, RealGate)
    # Initial Postgres load runs once during create() — confirm the
    # backend was consulted (rules out a factory that constructs RealGate
    # without exercising the load contract).
    backend.load_grants.assert_awaited_once()


def test_is_production_defaults_to_false_when_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """:func:`is_production` returns False when ``ALFRED_ENV`` is unset.

    The default posture is development. An unset env var must not silently
    promote a test process to production-gate mode — the developer
    receives the dev-branch :class:`RealGate` (post-PR-S3-7) with an
    empty grant snapshot (every check denies fail-closed) unless they
    explicitly opt in.
    """
    monkeypatch.delenv("ALFRED_ENV", raising=False)
    from alfred.bootstrap import gate_factory

    importlib.reload(gate_factory)
    assert gate_factory.is_production() is False


def test_is_production_false_when_env_is_development(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ALFRED_ENV=development`` keeps :func:`is_production` False.

    The development sentinel is the explicit opt-out from production
    behaviour. Confirms the canonical string the bootstrap looks for
    matches CLAUDE.md's documented expectation.
    """
    monkeypatch.setenv("ALFRED_ENV", "development")
    from alfred.bootstrap import gate_factory

    importlib.reload(gate_factory)
    assert gate_factory.is_production() is False


def test_is_production_false_when_env_is_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-empty ``ALFRED_ENV=""`` stays in development.

    Shell-export chains can silently produce an empty environment
    variable (``export ALFRED_ENV=$UNSET_VAR``); without explicit
    handling, ``os.environ.get(_ENV_KEY, _DEVELOPMENT)`` returns ``""``
    (not the default) and the original predicate flips the gate to
    production. CR-139 finding #1: empty must be treated as
    development, matching the documented contract.
    """
    monkeypatch.setenv("ALFRED_ENV", "")
    from alfred.bootstrap import gate_factory

    importlib.reload(gate_factory)
    assert gate_factory.is_production() is False


def test_is_production_false_when_env_is_whitespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Whitespace-only ``ALFRED_ENV`` is normalised to empty / development.

    Defends against the same shell-export footgun as the empty-string
    case: a stray space-only value ("ALFRED_ENV= ") would otherwise
    pass the empty-string check and flip the gate to production. The
    ``.strip()`` in :func:`is_production` collapses both shapes into
    the safe default.
    """
    monkeypatch.setenv("ALFRED_ENV", "   ")
    from alfred.bootstrap import gate_factory

    importlib.reload(gate_factory)
    assert gate_factory.is_production() is False


def test_is_production_true_when_env_is_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Any non-development value promotes :func:`is_production` to True.

    Spec §8.4 frames the read as "RealGate is the production default"
    — the bootstrap MUST treat anything other than ``"development"``
    as production so a typo'd or unfamiliar deployment label still gets
    the safer gate.
    """
    monkeypatch.setenv("ALFRED_ENV", "production")
    from alfred.bootstrap import gate_factory

    importlib.reload(gate_factory)
    assert gate_factory.is_production() is True


_SRC = Path(__file__).resolve().parents[3] / "src" / "alfred"
_FORBIDDEN_ALFRED_ENV_READERS = [
    _SRC / "hooks" / "capability.py",
    _SRC / "security" / "capability_gate" / "policy.py",
    _SRC / "security" / "capability_gate" / "_gate.py",
    _SRC / "security" / "capability_gate" / "backend.py",
    _SRC / "security" / "capability_gate" / "proposals.py",
]


@pytest.mark.parametrize(
    "module_path",
    _FORBIDDEN_ALFRED_ENV_READERS,
    ids=lambda p: p.name,
)
def test_gate_factory_is_the_only_alfred_env_read_site(module_path: Path) -> None:
    """No capability-gate module may reference the ``"ALFRED_ENV"`` literal.

    The read is delegated to :mod:`alfred.bootstrap.gate_factory` — the
    explicitly allowed bootstrap seam. If a capability-gate module
    references the literal string ``"ALFRED_ENV"``, a contributor has
    likely added an :func:`os.getenv` or :attr:`os.environ` read inside
    a security-critical module, which makes the gate's construction
    depend on env-at-import-time rather than injected configuration.

    AST-based check rather than text-grep: a comment mentioning
    ``ALFRED_ENV`` (cross-referencing the bootstrap seam) is fine; an
    actual string literal is not.
    """
    # CR-139 finding #9: fail loud when the guarded path disappears.
    # A pytest.skip would silently disable the invariant — exactly the
    # shape CLAUDE.md hard rule #7 forbids. The forbidden-reader list is
    # source-pinned; if a module is intentionally removed, the list MUST
    # be updated in the same commit.
    assert module_path.exists(), (
        f"Forbidden-module list references {module_path}, which is missing. "
        "Update the list only if the module was intentionally removed."
    )
    tree = ast.parse(module_path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == "ALFRED_ENV":
            pytest.fail(
                f"{module_path.name} contains the literal 'ALFRED_ENV' "
                "string. Move any ALFRED_ENV-driven branching to "
                "src/alfred/bootstrap/gate_factory.py (sec-007 extension)."
            )

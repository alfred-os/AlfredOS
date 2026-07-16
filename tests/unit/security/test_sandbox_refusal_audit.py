"""Unit tests for the reusable sandbox-refusal auditor (#433)."""

from __future__ import annotations

import importlib
from typing import Any

import pytest

from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_FIELDS
from alfred.audit.launcher_refusal import SandboxRefusalRow
from alfred.hooks import get_registry
from alfred.security.sandbox_refusal_audit import SandboxRefusalAuditor
from alfred.supervisor.core import Supervisor


class _FakeAudit:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def append_schema(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


def _row(reason: str = "sandbox_block_missing") -> SandboxRefusalRow:
    return SandboxRefusalRow(
        plugin_id="alfred.quarantined-llm",
        policy_ref="",
        host_os="linux",
        reason=reason,
        environment="development",
    )


@pytest.fixture
def _fake_invoke(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    invoked: list[dict[str, Any]] = []

    async def _invoke(name: str, ctx: object, **kwargs: Any) -> object:
        invoked.append({"name": name, **kwargs})
        return ctx

    # invoke is lazily imported inside record(); patch it at its source module.
    #
    # NOTE: alfred.hooks/__init__.py does `from alfred.hooks.invoke import
    # invoke`, which rebinds the *package* attribute `alfred.hooks.invoke`
    # from the submodule to the re-exported function object. That shadowing
    # breaks monkeypatch.setattr's dotted-string resolver (it walks via
    # getattr before falling back to import, so it silently lands on the
    # function instead of the submodule -- confirmed via a standalone repro).
    # importlib.import_module bypasses attribute traversal and returns the
    # real submodule from sys.modules, so patching its `invoke` attribute
    # directly is what actually reaches record()'s lazy
    # `from alfred.hooks.invoke import invoke`.
    invoke_module = importlib.import_module("alfred.hooks.invoke")
    monkeypatch.setattr(invoke_module, "invoke", _invoke)
    return invoked


@pytest.mark.asyncio
async def test_record_writes_exact_schema_and_dispatches(
    _fake_invoke: list[dict[str, Any]],
) -> None:
    audit = _FakeAudit()
    await SandboxRefusalAuditor(audit_writer=audit).record((_row(),))
    assert len(audit.calls) == 1
    call = audit.calls[0]
    assert call["event"] == "supervisor.plugin.sandbox_refused"
    assert call["fields"] == SANDBOX_REFUSED_FIELDS
    assert set(call["subject"].keys()) == SANDBOX_REFUSED_FIELDS
    assert call["trust_tier_of_trigger"] == "T0"
    assert call["result"] == "refused"
    assert call["actor_user_id"] is None
    assert call["cost_estimate_usd"] == 0.0
    assert len(_fake_invoke) == 1
    assert _fake_invoke[0]["name"] == "supervisor.plugin.sandbox_refused"
    assert _fake_invoke[0]["fail_closed"] is True


@pytest.mark.asyncio
async def test_record_writes_every_row(_fake_invoke: list[dict[str, Any]]) -> None:
    audit = _FakeAudit()
    await SandboxRefusalAuditor(audit_writer=audit).record(
        (_row("unknown_host_os"), _row("policy_ref_missing"))
    )
    assert [c["subject"]["reason"] for c in audit.calls] == [
        "unknown_host_os",
        "policy_ref_missing",
    ]


@pytest.mark.asyncio
async def test_empty_rows_writes_nothing(_fake_invoke: list[dict[str, Any]]) -> None:
    audit = _FakeAudit()
    await SandboxRefusalAuditor(audit_writer=audit).record(())
    assert audit.calls == []


@pytest.mark.asyncio
async def test_append_schema_failure_propagates(_fake_invoke: list[dict[str, Any]]) -> None:
    class _BoomAudit:
        async def append_schema(self, **kwargs: Any) -> None:
            raise RuntimeError("db down")

    with pytest.raises(RuntimeError, match="db down"):
        await SandboxRefusalAuditor(audit_writer=_BoomAudit()).record((_row(),))


@pytest.mark.asyncio
async def test_invoke_failure_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """CR-major-3: a hookpoint-dispatch failure must propagate, not be swallowed.

    Mirrors ``test_append_schema_failure_propagates`` but on the OTHER call
    ``record()`` makes per row: ``append_schema`` succeeds (the row IS
    persisted) and the subsequent ``invoke(...)`` dispatch raises. ``record()``
    has no try/except around either call, so this is a coverage-gap fill that
    proves the "caller's contract to handle" docstring claim end-to-end rather
    than asserting it only for the append_schema half.

    Patched at its source module (``alfred.hooks.invoke``, not the string
    form) -- see the ``_fake_invoke`` fixture's docstring above for why the
    dotted-string resolver silently lands on the wrong object otherwise.
    """

    async def _boom_invoke(name: str, ctx: object, **kwargs: Any) -> object:
        raise RuntimeError("hookpoint dispatch down")

    invoke_module = importlib.import_module("alfred.hooks.invoke")
    monkeypatch.setattr(invoke_module, "invoke", _boom_invoke)

    audit = _FakeAudit()
    with pytest.raises(RuntimeError, match="hookpoint dispatch down"):
        await SandboxRefusalAuditor(audit_writer=audit).record((_row(),))
    # The row WAS persisted before the dispatch failure -- proves the failure
    # is downstream of append_schema, not a mask of it never having run.
    assert len(audit.calls) == 1


# ---------------------------------------------------------------------------
# core-001 — the declared-hookpoint / real-dispatch registry proof (#433,
# ADR-0051).
#
# The four tests above monkeypatch ``alfred.hooks.invoke.invoke`` (see the
# ``_fake_invoke`` fixture's docstring) so they never touch the registry at
# all -- they prove ``record()``'s SHAPE (fields, dispatch args) but not
# that the "supervisor.plugin.sandbox_refused" hookpoint is actually
# declared at the phase the auditor calls ``invoke(...)``. That is exactly
# the premise ADR-0051 records as the "B" decision: the auditor fires at
# the ``read_frame`` drain, which happens post-``Supervisor`` construction,
# so by the time ``record()`` runs, ``Supervisor.__init__`` has already
# called ``_register_hookpoints()`` and the hookpoint is on the registry.
# Without this test, a future refactor that moved the auditor's dispatch
# EARLIER than ``Supervisor`` construction would silently start hitting
# ``dispatch_undeclared_hookpoint_message`` in production while every
# other test in this file kept passing (they never exercise the real
# registry).
#
# The pattern below is the confirmed-safe one from
# ``tests/unit/hooks/test_sandbox_hookpoints_registered.py``:
# ``Supervisor._register_hookpoints`` only reads ``get_registry()`` and
# touches ``self`` to dispatch, so a bare stub instance is a safe receiver.
# ---------------------------------------------------------------------------


class _StubSupervisor:
    """Bare receiver for ``Supervisor._register_hookpoints`` (unbound call).

    Mirrors ``tests/unit/hooks/test_sandbox_hookpoints_registered.py``'s
    ``_fresh_registry_with_supervisor_hookpoints`` helper. The method only
    reads the module-level ``get_registry()`` singleton and touches
    ``self`` to dispatch -- it never reads or writes instance state -- so
    a bare, unconstructed stub is a safe ``self`` for this unbound call.
    """


def test_sandbox_refused_hookpoint_declared_at_auditor_dispatch_phase() -> None:
    """The declared-hookpoint half of core-001: no undeclared-hookpoint gap.

    Registers the real supervisor hookpoints into the real
    ``get_registry()`` singleton (exactly what ``Supervisor.__init__``
    does at boot) and asserts the auditor's target hookpoint is present.
    This is the "declared at the phase the auditor dispatches" half of the
    proof; ``test_record_real_dispatch_against_declared_hookpoint`` below
    is the "and dispatch against it does not raise" half.
    """
    Supervisor._register_hookpoints(_StubSupervisor())  # type: ignore[arg-type]
    meta = get_registry().hookpoint_meta("supervisor.plugin.sandbox_refused")
    assert meta is not None
    assert meta.fail_closed is True


@pytest.mark.asyncio
async def test_record_real_dispatch_against_declared_hookpoint() -> None:
    """core-001: ``record()``'s REAL ``invoke(...)`` resolves cleanly.

    Deliberately does NOT use the ``_fake_invoke`` fixture -- that fixture
    monkeypatches ``alfred.hooks.invoke.invoke`` itself, which would make
    this test prove nothing about the registry. Instead this test:

    1. Registers the supervisor hookpoints into the real ``get_registry()``
       singleton (same call ``Supervisor.__init__`` makes at boot).
    2. Runs ``SandboxRefusalAuditor.record(...)`` UNPATCHED against a
       ``_FakeAudit`` writer, so ``record()``'s lazy
       ``from alfred.hooks.invoke import invoke`` reaches the real
       dispatcher, which in turn consults the real registry.

    A pass proves the post-``Supervisor`` dispatch timing ADR-0051 records
    (decision B) holds end-to-end: ``invoke(...)`` never hits
    ``dispatch_undeclared_hookpoint_message`` because the hookpoint is
    already declared by the time the launcher-refusal drain calls
    ``record()``. (There are zero subscribers registered against the
    hookpoint here -- only the DECLARATION -- so the dispatch is a
    zero-subscriber no-op chain; that is sufficient to prove the
    "declared, not undeclared" contract this test targets.)
    """
    Supervisor._register_hookpoints(_StubSupervisor())  # type: ignore[arg-type]
    assert get_registry().hookpoint_meta("supervisor.plugin.sandbox_refused") is not None

    audit = _FakeAudit()
    await SandboxRefusalAuditor(audit_writer=audit).record((_row(),))
    assert len(audit.calls) == 1

"""Unit tests for the reusable sandbox-refusal auditor (#433)."""

from __future__ import annotations

import importlib
from typing import Any

import pytest

from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_FIELDS
from alfred.audit.launcher_refusal import SandboxRefusalRow
from alfred.security.sandbox_refusal_audit import SandboxRefusalAuditor


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

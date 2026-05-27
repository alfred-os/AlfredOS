"""Bridge between the structlog redactor and ``OutboundDlp.scan``.

sec-003 regression: the slice-1 redactor called ``broker.redact`` on each
leaf string, missing the generic-API-key shape. PR D1 routes the leaf
through :meth:`OutboundDlp.scan` so the stage-2 regex covers log
emissions too. These tests assert the bridge end-to-end through the
real CLI module ``_redact_value`` / ``_redact``.
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from alfred.cli import main as cli_main
from alfred.security.dlp import OutboundDlp


class _StubBroker:
    """Replaces literal known-secret values."""

    def __init__(self, mapping: dict[str, str] | None = None) -> None:
        self._mapping = mapping or {}

    def redact(self, text: str) -> str:
        for value, name in self._mapping.items():
            text = text.replace(value, f"[REDACTED:{name}]")
        return text


def _install_dlp(
    monkeypatch: pytest.MonkeyPatch,
    *,
    broker_mapping: dict[str, str] | None = None,
) -> list[tuple[str, Mapping[str, object]]]:
    """Install a DLP instance on the cli module and return the audit log."""
    audit_log: list[tuple[str, Mapping[str, object]]] = []

    def _sink(*, event: str, subject: Mapping[str, object]) -> None:
        audit_log.append((event, subject))

    dlp = OutboundDlp(broker=_StubBroker(broker_mapping), audit=_sink)
    monkeypatch.setattr(cli_main, "_outbound_dlp_for_redact", dlp)
    return audit_log


def test_generic_api_key_redacted_in_log_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stage 2 generic-API-key regex now catches values in log dicts."""
    _install_dlp(monkeypatch)
    event_dict = {"event": "test", "token": "sk-AAAAAAAAAAAAAAAAAAAA"}
    out = cli_main._redact(None, "warning", event_dict)
    assert out["token"] == "[REDACTED:api-key-shape]"  # noqa: S105 — sentinel, not a real secret


def test_live_secret_in_log_message_still_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Backwards-compat: stage 1 broker redaction still works (sec-003)."""
    _install_dlp(monkeypatch, broker_mapping={"hunter2": "deepseek_api_key"})
    event_dict = {"event": "test", "msg": "logged hunter2 leak"}
    out = cli_main._redact(None, "warning", event_dict)
    assert "[REDACTED:deepseek_api_key]" in out["msg"]


def test_nested_redaction_through_list_of_dicts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Leaf-string recursion preserved; every nested string runs through DLP."""
    _install_dlp(monkeypatch)
    event_dict = {
        "event": "test",
        "rows": [
            {"token": "sk-AAAAAAAAAAAAAAAAAAAA", "ok": "no secret here"},
            {"token": "pk_BBBBBBBBBBBBBBBBBBBB", "ok": "still fine"},
        ],
    }
    out = cli_main._redact(None, "warning", event_dict)
    assert out["rows"][0]["token"] == "[REDACTED:api-key-shape]"  # noqa: S105 — sentinel
    assert out["rows"][0]["ok"] == "no secret here"
    assert out["rows"][1]["token"] == "[REDACTED:api-key-shape]"  # noqa: S105 — sentinel


def test_no_double_audit_on_single_log_emission(monkeypatch: pytest.MonkeyPatch) -> None:
    """The structlog bridge's sink is the no-op (zero audit calls expected).

    The default sink wired in ``_configure_logging`` is
    ``_structlog_audit_sink`` (no-op). This test instead injects a
    recording sink and confirms the COUNT of calls per redaction event
    matches what the code emits — exactly one per modified leaf.
    """
    audit_log = _install_dlp(monkeypatch)
    event_dict = {
        "event": "test",
        "a": "sk-AAAAAAAAAAAAAAAAAAAA",
        "b": "sk-BBBBBBBBBBBBBBBBBBBB",
    }
    cli_main._redact(None, "warning", event_dict)
    # Two leaf strings each carrying an api-key shape — two audit rows.
    assert len(audit_log) == 2


def test_non_string_values_pass_through_untouched(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_dlp(monkeypatch)
    event_dict = {"event": "test", "count": 5, "ok": True, "tuple_field": (1, 2)}
    out = cli_main._redact(None, "warning", event_dict)
    assert out["count"] == 5
    assert out["ok"] is True
    assert out["tuple_field"] == (1, 2)


def test_redactor_inactive_when_dlp_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before ``_configure_logging`` runs, the redactor is a pass-through."""
    monkeypatch.setattr(cli_main, "_outbound_dlp_for_redact", None)
    event_dict = {"event": "test", "token": "sk-AAAAAAAAAAAAAAAAAAAA"}
    out = cli_main._redact(None, "warning", event_dict)
    # Pass-through: no redaction happens.
    assert out["token"] == "sk-AAAAAAAAAAAAAAAAAAAA"  # noqa: S105 — fabricated test token


def test_no_other_broker_redact_callers_in_codebase() -> None:
    """AST-assert: the only ``broker.redact`` caller is OutboundDlp.scan.

    Catches the regression where someone re-introduces a direct
    ``.redact(...)`` call outside the DLP module, bypassing stages 2
    and 3. AST-based so references in docstrings / comments don't
    trigger false positives.

    The visitor flags **every** attribute-form call to a method named
    ``redact`` — variable-name suffix matching (the prior
    ``endswith("broker")`` heuristic) was bypassable by trivial renames
    like ``sb.redact(...)``. Since the only legitimate ``.redact``
    method belongs to :class:`SecretBroker` (caller-wise: only
    :class:`OutboundDlp`), flagging every call-site outside
    ``dlp.py``/``secrets.py`` is both sound and tight. If a future
    module legitimately needs to expose a different ``redact`` method,
    add an explicit allowlist entry rather than weakening the gate.
    """
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[3] / "src" / "alfred"
    offenders: list[str] = []

    class _Visitor(ast.NodeVisitor):
        def __init__(self, file: pathlib.Path) -> None:
            self.file = file

        def visit_Call(self, node: ast.Call) -> None:
            # Flag every ``*.redact(...)`` invocation site. The call form
            # (vs. the attribute access in isolation) means docstrings
            # mentioning ``.redact`` and bare attribute references that
            # never invoke don't trip the guard.
            fn = node.func
            if isinstance(fn, ast.Attribute) and fn.attr == "redact":
                offenders.append(f"{self.file}:{node.lineno}")
            self.generic_visit(node)

    for path in root.rglob("*.py"):
        if path.name == "dlp.py":
            continue
        # ``secrets.py`` legitimately implements ``redact`` as a method
        # on :class:`SecretBroker` and may call ``self`` variants
        # internally; the definition itself is not a "caller bypass".
        if path.name == "secrets.py":
            continue
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            continue
        _Visitor(path).visit(tree)
    assert not offenders, (
        f"`.redact(...)` must only be called from OutboundDlp.scan after PR D1; "
        f"found: {offenders}"
    )


def test_structlog_audit_sink_is_a_noop() -> None:
    """Smoke-test the default sink: never raises.

    The sink's signature is ``-> None`` so the call itself returning
    cleanly is the whole contract. We deliberately don't assert on the
    return value because CodeQL flags assignments from declared-None
    callables (``py/use-of-none``).
    """
    cli_main._structlog_audit_sink(event="ignored", subject={"k": "v"})

"""Tests for ``alfred.hooks.audit_sink`` — the AuditSink Protocol seam,
the StructlogAuditSink default, and the six hook event-name constants.

Pins the load-bearing invariants of Slice-2.5 PR-A Task 5:

* :class:`alfred.hooks.audit_sink.AuditSink` is ``@runtime_checkable`` and
  its ``emit`` signature is fully keyword-only — calling
  ``sink.emit("hooks.refusal", ...)`` positionally is a ``TypeError`` at
  runtime (the static checkers reject it too). The keyword-only seam is
  load-bearing because PR-B's dispatcher will pass ``event=…,
  correlation_id=…, fields=…`` by name and a future change to a positional
  signature would silently re-order audit-row attribution.
* :class:`alfred.hooks.audit_sink.StructlogAuditSink` honours the
  Protocol structurally (``isinstance(...)`` returns ``True``) and writes
  exactly one row per ``emit`` call onto an injected structlog logger.
  The logger is INJECTED — the sink holds no module-global — so PR-B can
  swap in the real ``AuditWriter``-backed logger without monkeypatching.
* The structlog redactor chain wired in ``cli/_bootstrap.configure_logging``
  is on the path — a secret-shaped value in ``fields`` is masked to the
  DLP sentinel before the row is logged. CLAUDE.md hard rules #1 + #2 +
  sec-003.
* No DB import / no DB call. arch-001 — PR-B brings the persistent
  audit-backed sink; PR-A's default is structlog-only. Asserted both by
  reading the source-level imports (AST) and by the absence of a real
  audit dependency in the sink's constructor surface.
* All six ``hooks.*`` event identifiers are exported as ``Final[str]``
  module constants and each constant equals its expected string
  identifier (``HOOKS_REFUSAL == "hooks.refusal"`` etc.). These are
  audit-row event IDENTIFIERS, NOT operator-facing display strings — so
  no catalog key, no ``t()`` here.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
from collections.abc import Mapping
from dataclasses import FrozenInstanceError
from typing import Any
from unittest.mock import MagicMock

import pytest
import structlog

from alfred.cli import _bootstrap as cli_bootstrap
from alfred.hooks.audit_sink import (
    HOOKS_CHAIN_TIMEOUT,
    HOOKS_ERROR_SUPPRESSED,
    HOOKS_REENTRY_BYPASS,
    HOOKS_REFUSAL,
    HOOKS_SUBSCRIBER_ERROR,
    HOOKS_UNAUTHORIZED_REFUSAL,
    AuditSink,
    StructlogAuditSink,
)
from alfred.security.dlp import OutboundDlp

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


class _StubBroker:
    """Replaces known-secret values with ``[REDACTED:<name>]`` sentinels.

    Mirrors the shape of :class:`alfred.security.secrets.SecretBroker`'s
    ``redact`` surface so we can install a deterministic redactor on the
    CLI module's ``_outbound_dlp_for_redact`` slot.
    """

    def __init__(self, mapping: dict[str, str] | None = None) -> None:
        self._mapping = mapping or {}

    def redact(self, text: str) -> str:
        for value, name in self._mapping.items():
            text = text.replace(value, f"[REDACTED:{name}]")
        return text


@pytest.fixture
def _install_redactor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install a real :class:`OutboundDlp` on the CLI module so the
    leaf-redactor processor (``_redact``) recognises ``sk-…`` shapes and
    masks them to the project's ``[REDACTED:api-key-shape]`` sentinel.

    The structlog processor chain in
    :func:`alfred.cli._bootstrap.configure_logging` reads
    ``cli_bootstrap._outbound_dlp_for_redact`` at every log emission;
    setting it here without calling ``configure_logging`` keeps the test
    surface narrow — we exercise the redactor that the default sink's
    logger configuration will go through, not the global structlog state.
    """

    def _sink_noop(*, event: str, subject: Mapping[str, object]) -> None:
        del event, subject

    dlp = OutboundDlp(broker=_StubBroker(), audit=_sink_noop)
    monkeypatch.setattr(cli_bootstrap, "_outbound_dlp_for_redact", dlp)


# ──────────────────────────────────────────────────────────────────────
# 1. Protocol structural check (@runtime_checkable)
# ──────────────────────────────────────────────────────────────────────


def test_audit_sink_protocol_is_runtime_checkable() -> None:
    """``AuditSink`` is decorated ``@runtime_checkable`` so dispatchers
    can :func:`isinstance`-narrow against it without a concrete base.
    """
    # The Protocol's ``_is_runtime_protocol`` attribute is the public-ish
    # marker the typing machinery flips when ``@runtime_checkable`` runs.
    assert getattr(AuditSink, "_is_runtime_protocol", False) is True


def test_structlog_audit_sink_satisfies_audit_sink_protocol() -> None:
    """``isinstance(StructlogAuditSink(...), AuditSink)`` holds — the
    default sink honours the Protocol structurally so PR-B's dispatcher
    can type-narrow uniformly.
    """
    sink = StructlogAuditSink(logger=structlog.get_logger("alfred.hooks.test"))
    assert isinstance(sink, AuditSink)


# ──────────────────────────────────────────────────────────────────────
# 2. emit is awaitable
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_emit_is_awaitable_and_returns_none() -> None:
    """``await sink.emit(...)`` completes without error and returns
    ``None``. The whole sink contract is ``-> None``; a non-None return
    is a contract break.
    """
    sink = StructlogAuditSink(logger=structlog.get_logger("alfred.hooks.test"))
    result = await sink.emit(
        event=HOOKS_REFUSAL,
        correlation_id="abc",
        fields={"hookpoint": "before_validate"},
    )
    assert result is None


def test_emit_method_is_coroutine_function() -> None:
    """:meth:`StructlogAuditSink.emit` is an ``async def`` (a coroutine
    function) — the Protocol's signature is async and the default sink
    honours that shape even if the body has no ``await``.
    """
    assert inspect.iscoroutinefunction(StructlogAuditSink.emit)


# ──────────────────────────────────────────────────────────────────────
# 3. One structlog row written per emit, carrying event + correlation_id
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_emit_writes_one_row_with_event_correlation_id_and_fields() -> None:
    """Exactly one log row is written per ``emit`` call, carrying
    ``event``, ``correlation_id``, and the ``fields`` mapping. We inject
    a :class:`unittest.mock.MagicMock` standing in for a structlog logger
    so we can assert the call shape exactly without depending on global
    structlog state.
    """
    spy_logger = MagicMock()
    sink = StructlogAuditSink(logger=spy_logger)
    await sink.emit(
        event=HOOKS_REFUSAL,
        correlation_id="corr-1",
        fields={"hookpoint": "before_validate", "user_id": "u42"},
    )

    # Exactly one structlog ``.info(...)`` call.
    assert spy_logger.info.call_count == 1

    args, kwargs = spy_logger.info.call_args
    # First positional arg is the log event identifier — by convention
    # the hook-trace row keys off ``event``. Either the event string is
    # the first positional or it's a ``event=`` kwarg; we accept either
    # but pin that the value flows through.
    if args:
        assert args[0] == HOOKS_REFUSAL
    else:
        assert kwargs.get("event") == HOOKS_REFUSAL
    # ``correlation_id`` and the ``fields`` keys are bound as kwargs on
    # the structlog event so the renderer surfaces them in the row.
    assert kwargs.get("correlation_id") == "corr-1"
    assert kwargs.get("hookpoint") == "before_validate"
    assert kwargs.get("user_id") == "u42"


# ──────────────────────────────────────────────────────────────────────
# 4. Secret-shaped fields are redacted before the row is logged
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_emit_redacts_secret_shaped_fields(
    _install_redactor: None,
) -> None:
    """A secret-shaped value (``sk-…`` + 20 chars) inside ``fields`` is
    masked to the DLP sentinel ``[REDACTED:api-key-shape]`` before the
    row is logged. Pins CLAUDE.md hard rule #1 + #2 — the redactor is on
    the path.

    The default sink resolves its logger via ``structlog.get_logger(...)``
    which inherits the leaf-redactor processor chain configured by
    :func:`alfred.cli._bootstrap.configure_logging`. We install the
    redactor's DLP slot via the ``_install_redactor`` fixture and call
    ``structlog.configure`` with the leaf redactor + a list-capturing
    renderer so we can assert against the final emitted row.
    """
    captured: list[dict[str, Any]] = []

    def _capture_renderer(_logger: object, _name: str, event_dict: dict[str, Any]) -> str:
        captured.append(dict(event_dict))
        return ""

    structlog.configure(
        processors=[cli_bootstrap._redact, _capture_renderer],
        wrapper_class=structlog.make_filtering_bound_logger(20),  # INFO
        cache_logger_on_first_use=False,
    )
    try:
        sink = StructlogAuditSink(logger=structlog.get_logger("alfred.hooks.test_redact"))
        await sink.emit(
            event=HOOKS_REFUSAL,
            correlation_id="corr-2",
            # ``sk-`` + 20 chars triggers the stage-2 api-key-shape regex.
            fields={
                "content": "sk-AAAAAAAAAAAAAAAAAAAA",
                "user_id": "u42",
            },
        )
    finally:
        structlog.reset_defaults()

    assert len(captured) == 1
    row = captured[0]
    # The raw secret value MUST NOT appear anywhere in the rendered row.
    rendered = repr(row)
    assert "sk-AAAAAAAAAAAAAAAAAAAA" not in rendered
    # The DLP sentinel IS present (proves the redactor ran end-to-end).
    assert "[REDACTED:api-key-shape]" in rendered
    # The non-secret field passes through untouched.
    assert row.get("user_id") == "u42"


# ──────────────────────────────────────────────────────────────────────
# 5. Six event-name constants importable and equal their identifiers
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("constant", "expected"),
    [
        (HOOKS_REFUSAL, "hooks.refusal"),
        (HOOKS_CHAIN_TIMEOUT, "hooks.chain_timeout"),
        (HOOKS_SUBSCRIBER_ERROR, "hooks.subscriber_error"),
        (HOOKS_ERROR_SUPPRESSED, "hooks.error_suppressed"),
        (HOOKS_UNAUTHORIZED_REFUSAL, "hooks.unauthorized_refusal"),
        (HOOKS_REENTRY_BYPASS, "hooks.reentry_bypass"),
    ],
)
def test_event_name_constants_equal_their_identifiers(constant: str, expected: str) -> None:
    """Each ``HOOKS_*`` module constant equals its canonical
    ``hooks.<kind>`` identifier — these strings are audit-row event IDs,
    NOT catalog keys, so they live as plain ``Final[str]`` constants the
    dispatcher and tests share by import.
    """
    assert constant == expected


# ──────────────────────────────────────────────────────────────────────
# 6. emit signature is fully keyword-only
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_emit_rejects_positional_args() -> None:
    """``sink.emit("hooks.refusal", "corr-1", {})`` raises ``TypeError``
    — the Protocol's keyword-only seam (verbatim spec §0) prevents
    silently re-ordered attribution at the call site.
    """
    sink = StructlogAuditSink(logger=MagicMock())
    with pytest.raises(TypeError):
        await sink.emit(  # type: ignore[misc, call-arg]
            HOOKS_REFUSAL,
            "corr-1",
            {},
        )


@pytest.mark.asyncio
async def test_emit_rejects_positional_event_only() -> None:
    """Even a single positional ``event`` (with kwargs for the rest) is
    rejected — the ``*`` after ``self`` makes the entire signature
    keyword-only.
    """
    sink = StructlogAuditSink(logger=MagicMock())
    with pytest.raises(TypeError):
        await sink.emit(  # type: ignore[misc, call-arg]
            HOOKS_REFUSAL,
            correlation_id="corr-1",
            fields={},
        )


# ──────────────────────────────────────────────────────────────────────
# 7. Injected logger — no module-global side door
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_emit_uses_injected_logger_not_a_module_global() -> None:
    """When the caller injects a spy logger, every ``emit`` call hits
    the spy — proving the sink holds NO module-global logger handle.
    PR-B's dispatcher injects an ``AuditWriter``-backed logger here.
    """
    spy_a = MagicMock()
    spy_b = MagicMock()
    sink_a = StructlogAuditSink(logger=spy_a)
    sink_b = StructlogAuditSink(logger=spy_b)
    await sink_a.emit(event=HOOKS_REFUSAL, correlation_id="c1", fields={})
    await sink_b.emit(event=HOOKS_CHAIN_TIMEOUT, correlation_id="c2", fields={})
    assert spy_a.info.call_count == 1
    assert spy_b.info.call_count == 1
    # No cross-talk: each spy saw exactly its own ``emit``.
    assert spy_a.info.call_args.kwargs.get("correlation_id") == "c1"
    assert spy_b.info.call_args.kwargs.get("correlation_id") == "c2"


# ──────────────────────────────────────────────────────────────────────
# 8. Frozen + slots dataclass (no mutation)
# ──────────────────────────────────────────────────────────────────────


def test_structlog_audit_sink_is_frozen() -> None:
    """``StructlogAuditSink`` is ``frozen=True`` — reassigning the
    injected logger raises ``FrozenInstanceError``. Locks the
    "constructor is the only configuration surface" invariant.
    """
    sink = StructlogAuditSink(logger=MagicMock())
    with pytest.raises(FrozenInstanceError):
        sink.logger = MagicMock()  # type: ignore[misc]


def test_structlog_audit_sink_has_no_instance_dict() -> None:
    """``slots=True`` means instances have no ``__dict__`` — keeps the
    sink lightweight on the dispatcher's hot path.
    """
    sink = StructlogAuditSink(logger=MagicMock())
    assert not hasattr(sink, "__dict__")


# ──────────────────────────────────────────────────────────────────────
# 9. arch-001 — no DB / SQL / audit-writer import
# ──────────────────────────────────────────────────────────────────────


def test_audit_sink_module_has_no_db_or_audit_writer_imports() -> None:
    """arch-001: the PR-A default sink must NOT import
    ``alfred.audit.log``, ``AuditWriter``, ``sqlalchemy``, or
    ``asyncpg``. PR-B owns the DB-backed sink; PR-A's coverage runs
    entirely against this structlog-only default.

    AST-based source scan so docstring mentions and inline-comment
    references can't trip the guard.
    """
    src_path = (
        pathlib.Path(__file__).resolve().parents[3] / "src" / "alfred" / "hooks" / "audit_sink.py"
    )
    tree = ast.parse(src_path.read_text(encoding="utf-8"), filename=str(src_path))

    forbidden_modules = {
        "alfred.audit",
        "alfred.audit.log",
        "sqlalchemy",
        "asyncpg",
    }
    forbidden_names = {"AuditWriter"}

    offenders: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in forbidden_modules:
                    offenders.append(f"import {alias.name}")
                if any(alias.name.startswith(f"{m}.") for m in forbidden_modules):
                    offenders.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod in forbidden_modules or any(mod.startswith(f"{m}.") for m in forbidden_modules):
                offenders.append(f"from {mod} import ...")
            for alias in node.names:
                if alias.name in forbidden_names:
                    offenders.append(f"from {mod} import {alias.name}")

    assert not offenders, (
        f"arch-001: audit_sink.py must not import DB / audit-writer modules. Offenders: {offenders}"
    )


# ──────────────────────────────────────────────────────────────────────
# 10. Smoke: many emit calls in sequence — no shared mutable state
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_repeated_emit_calls_do_not_share_state() -> None:
    """Two ``emit`` calls in sequence on the same sink instance each
    produce a distinct ``.info(...)`` invocation with independent
    fields. Pins the "no shared mutable state between calls" invariant.
    """
    spy = MagicMock()
    sink = StructlogAuditSink(logger=spy)
    await sink.emit(
        event=HOOKS_REFUSAL,
        correlation_id="c1",
        fields={"a": 1},
    )
    await sink.emit(
        event=HOOKS_CHAIN_TIMEOUT,
        correlation_id="c2",
        fields={"b": 2},
    )
    assert spy.info.call_count == 2
    first_kwargs = spy.info.call_args_list[0].kwargs
    second_kwargs = spy.info.call_args_list[1].kwargs
    assert first_kwargs.get("correlation_id") == "c1"
    assert first_kwargs.get("a") == 1
    assert "b" not in first_kwargs
    assert second_kwargs.get("correlation_id") == "c2"
    assert second_kwargs.get("b") == 2
    assert "a" not in second_kwargs

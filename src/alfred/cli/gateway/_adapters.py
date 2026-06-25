"""``alfred gateway adapters [--wait-ready]`` command body (Spec B G6-5 Task 8, #288).

The operator verify surface for the gateway-hosted comms adapters. Ergonomically it
sits under ``alfred gateway`` (it is about the gateway's children), but it READS the live
per-adapter status via the ADR-0038 DAEMON-control ``status.query`` client — NOT a
gateway-side socket read.

GAP-3 ruling (plan-review, 2026-06-21): REUSE the daemon-control poll; STRIKE any
gateway-side read fallback. The gateway is the adapter child's supervising parent and
REPORTS each lifecycle transition to the core as a ``gateway.adapter.*`` notification
(ADR-0036 inversion); the core's ``AdapterStatusObserver``
(:mod:`alfred.comms_mcp.adapter_status_observer`)
holds the latest per-adapter status, which the control plane folds into the
``status.query`` result. The gateway's OWN client socket is single-accept-for-life
(undiallable for a probe), so the daemon-control client is the only correct read path.

Readiness is ``state == "up"`` — the observer's status record already expresses per-adapter
readiness through its :data:`RenderedAdapterState` field (``up`` / ``down`` / ``crashed`` /
``breaker_open`` / ``unknown``), so NO new observer field is needed (GAP-3 verification).

Two modes:

* ``--wait-ready [adapter]`` — a bounded client-side POLL LOOP: repeated ``status.query``
  reads until the named adapter is ``up`` OR a ``--timeout`` (seconds, monotonic-clock
  bounded) elapses, with a short bounded inter-poll ``await`` (NEVER a busy-spin).
* one-shot (no flag) — a single ``status.query`` render of the per-adapter state.

Exit-code contract (mirrors the now-retired ``alfred discord verify`` 0/1/2/3 that
operator scripts branched on; the verify subcommand was retired in #309 — Discord is
gateway-hosted since Spec B G6-7-8):

* 0 — ready (``--wait-ready``) / rendered (one-shot)
* 1 — not-ready-by-timeout (``--wait-ready`` only; LOUD)
* 2 — daemon / control unavailable (a :class:`DaemonControlError` of ANY arm — CLAUDE.md
  hard rule #7: the render layer NEVER crashes on a control fault)
* 3 — the named adapter cannot be RESOLVED — dual meaning: either a genuinely-unknown
  id (absent from the closed configured / hosted adapter set, validated up front) OR a
  ``--wait-ready`` invocation with no adapter at all (a usage error). A known-but-still-
  booting id (absent only from the live status map) is NOT exit-3 — it WAITS to the
  deadline (exit-1 on timeout). The friendly stderr line disambiguates the two exit-3 cases.

i18n: every operator string flows through :func:`alfred.i18n.t`; the localized state
token is dict-dereferenced via :data:`_STATE_KEYS` (reserved in ``_spec_b_reserve``).
"""

from __future__ import annotations

import asyncio
import time
from typing import Final

import structlog
import typer

from alfred.cli.daemon._daemon_control_client import (
    DaemonControlError,
    DaemonControlProtocolError,
    DaemonControlUnavailableError,
    query_daemon_control,
)
from alfred.cli.daemon._daemon_control_protocol import (
    STATUS_QUERY_METHOD,
    DaemonStatusResult,
)
from alfred.i18n import t

log = structlog.get_logger(__name__)

__all__ = ["adapters_verify"]

# Exit codes (mirrors the now-retired ``alfred discord verify`` 0/1/2/3 contract;
# the verify subcommand was retired in #309 — Discord is gateway-hosted since Spec B G6-7-8).
_EXIT_READY: Final[int] = 0
_EXIT_NOT_READY: Final[int] = 1
_EXIT_UNAVAILABLE: Final[int] = 2
_EXIT_UNKNOWN_ADAPTER: Final[int] = 3

# The readiness state. Spec B / ADR-0036: ``up`` is the only liveness-asserting,
# epoch-bound transition — so "ready" is exactly ``state == "up"``.
_READY_STATE: Final[str] = "up"

# Bounded inter-poll wait. Indirected through a module-level ``_poll_sleep`` so a test
# can fake it (the loop is then exercised without real wall-clock time) AND so the loop
# can never become a tight CPU busy-spin (a positive, bounded ``await`` every iteration).
_POLL_INTERVAL_S: Final[float] = 1.0
_DEFAULT_TIMEOUT_S: Final[int] = 30

# Render-layer map from a wire ``RenderedAdapterState`` to its localized catalog key (the
# state token is localized through ``t()``, never raw-interpolated — i18n hard rule). The
# literals are reserved in ``_spec_b_reserve._register`` (dict-dereferenced here, so
# pybabel cannot see them at the call site).
_STATE_KEYS: Final[dict[str, str]] = {
    "up": "gateway.adapters.state.up",
    "down": "gateway.adapters.state.down",
    "crashed": "gateway.adapters.state.crashed",
    "breaker_open": "gateway.adapters.state.breaker_open",
    "unknown": "gateway.adapters.state.unknown",
}


async def _poll_sleep(seconds: float) -> None:
    """The bounded inter-poll wait (indirected so tests can fake it; never a busy-spin)."""
    await asyncio.sleep(seconds)


def _resolve_known_adapter_ids() -> set[str] | None:
    """The CLOSED configured/hosted adapter-id set, for up-front ``--wait-ready`` validation.

    Reuses the gateway-boot reconciliation seam
    (:func:`alfred.cli.gateway._commands._resolve_hosted_adapter_ids`) so the set is the
    SAME canonical ``adapter_id`` strings the gateway actually supervises. Used ONLY to
    distinguish a genuinely-unknown id (refuse fast, exit-3) from a known-but-still-booting
    id (the observer omits a not-yet-reported adapter — that must WAIT to the deadline,
    not short-circuit to exit-3).

    FAIL-SAFE (degrade to waiting, never to a false refusal): if the set cannot be resolved
    — Settings cannot construct, a manifest is unreadable, or the resolved set is empty —
    return ``None`` so the caller SKIPS up-front validation and falls through to the bounded
    poll. A resolution fault must never turn a real, booting adapter into a spurious exit-3;
    the poll's own timeout remains the bound (CLAUDE.md hard rule #7 — loud-and-continue).
    """
    try:
        from alfred.cli.gateway._commands import _resolve_hosted_adapter_ids

        resolved = set(_resolve_hosted_adapter_ids())
    except Exception as exc:  # degrade to waiting — never a false refusal
        log.warning("gateway.adapters.known_set_unresolved", error=type(exc).__name__)
        return None
    return resolved or None


async def _query_status() -> DaemonStatusResult:
    """One ``status.query`` round-trip, validated into the typed result.

    Raises :class:`DaemonControlError` (any arm) on a control fault — the caller maps
    EVERY such fault to the unavailable exit code so the render never crashes (hard rule
    #7). A control response carrying a structured ``error`` (or an empty result) is the
    SAME unusable-answer contract, surfaced as :class:`DaemonControlUnavailableError`.
    """
    # Resolve through the module-level name so a test monkeypatching
    # ``_adapters.query_daemon_control`` is honoured (mirrors the daemon-status render).
    response = await query_daemon_control(STATUS_QUERY_METHOD)
    if response.error is not None or response.result is None:
        raise DaemonControlUnavailableError("control response error")
    try:
        return DaemonStatusResult.model_validate(response.result)
    except ValueError as exc:
        # A response that DECODED (no transport / structured-error fault) but whose payload
        # fails DaemonStatusResult validation is the unusable-answer contract.
        # ``ValidationError`` is a ``ValueError`` subclass; map it to a control PROTOCOL
        # fault (a ``DaemonControlError`` arm) so the caller's exit-2 handlers degrade it
        # rather than letting a raw traceback escape (CLAUDE.md hard rule #7).
        raise DaemonControlProtocolError("malformed status payload") from exc


def _render_line(line_state: str, adapter_id: str) -> str:
    """One localized per-adapter status line (state token localized through ``t()``)."""
    state_key = _STATE_KEYS.get(line_state, _STATE_KEYS["unknown"])
    return t("gateway.adapters.line", adapter=adapter_id, state=t(state_key))


def _emit_status(result: DaemonStatusResult, adapter: str | None) -> int:
    """Render the one-shot status; return the process exit code.

    A named ``adapter`` absent from the live status map is an UNKNOWN adapter (exit 3);
    otherwise every (or the one named) per-adapter line is echoed and the command exits 0.
    """
    if adapter is not None and adapter not in result.adapters:
        typer.echo(t("gateway.adapters.unknown_adapter", adapter=adapter))
        return _EXIT_UNKNOWN_ADAPTER
    ids = [adapter] if adapter is not None else sorted(result.adapters)
    if not ids:
        typer.echo(t("gateway.adapters.none"))
        return _EXIT_READY
    typer.echo(t("gateway.adapters.header"))
    for adapter_id in ids:
        typer.echo(_render_line(result.adapters[adapter_id].state, adapter_id))
    return _EXIT_READY


async def _wait_ready(adapter: str, timeout: int) -> int:
    """Bounded poll loop: return the exit code once ready / timed-out / faulted.

    UP-FRONT VALIDATION: a genuinely-unknown id (absent from the closed configured /
    hosted adapter set) is resolved authoritatively to exit-3 BEFORE the loop, so an
    operator typo fails fast. A KNOWN id that is merely still booting — the observer
    omits a not-yet-reported adapter — is NOT unknown: its in-loop absence from the
    status map is treated as NOT-READY (fall through to the deadline → loud exit-1 on
    timeout), never the instant exit-3 a typo gets. When the configured set cannot be
    resolved, validation is skipped (fail-safe — see :func:`_resolve_known_adapter_ids`).

    The deadline is a MONOTONIC-clock bound (immune to wall-clock steps). Each iteration
    is one ``status.query`` + (if not yet ready and time remains) one bounded
    ``_poll_sleep`` — so the loop can never busy-spin. A control fault on ANY poll
    degrades to the unavailable exit code (never a traceback — hard rule #7).
    """
    known = _resolve_known_adapter_ids()
    if known is not None and adapter not in known:
        # Authoritatively unknown (a typo / un-configured id): refuse fast.
        typer.echo(t("gateway.adapters.unknown_adapter", adapter=adapter))
        return _EXIT_UNKNOWN_ADAPTER
    deadline = time.monotonic() + timeout
    while True:
        try:
            result = await _query_status()
        except DaemonControlError as exc:
            log.warning("gateway.adapters.control_query_failed", error=type(exc).__name__)
            typer.echo(t("gateway.adapters.unavailable"))
            return _EXIT_UNAVAILABLE
        # A KNOWN adapter absent from the live status map is still BOOTING (the observer
        # omits a not-yet-reported adapter), NOT unknown — fall through to the deadline.
        if adapter in result.adapters and result.adapters[adapter].state == _READY_STATE:
            typer.echo(t("gateway.adapters.wait_ready.ready", adapter=adapter))
            return _EXIT_READY
        if time.monotonic() >= deadline:
            # LOUD timeout: the adapter never reached ``up`` within the bound.
            log.warning("gateway.adapters.wait_ready_timeout", adapter=adapter, timeout=timeout)
            typer.echo(t("gateway.adapters.wait_ready.timeout", adapter=adapter, timeout=timeout))
            return _EXIT_NOT_READY
        typer.echo(t("gateway.adapters.wait_ready.waiting", adapter=adapter))
        await _poll_sleep(_POLL_INTERVAL_S)


def adapters_verify(
    adapter: str | None,
    *,
    wait_ready: bool,
    timeout: int,
) -> None:
    """Render / verify the gateway-hosted adapter status; raise ``typer.Exit`` per the contract.

    ``--wait-ready`` requires a NAMED adapter (which one to wait for); without it the
    command renders the one-shot status of all (or the named) adapter(s). EVERY control
    fault is caught and mapped to the unavailable exit code — the command never crashes on
    a control-plane fault (CLAUDE.md hard rule #7).
    """
    if wait_ready and adapter is None:
        # DUAL MEANING of exit-3 (documented): ``--wait-ready`` with NO adapter is a
        # USAGE error (which adapter to wait for is unspecified). It shares the exit-3
        # code with "unknown adapter" because both are "the named adapter cannot be
        # resolved" — an unrunnable request, distinct from the runtime not-ready (1) /
        # unavailable (2) outcomes. The friendly ``needs_adapter`` line disambiguates
        # the two exit-3 cases for an operator reading stderr.
        typer.echo(t("gateway.adapters.wait_ready.needs_adapter"))
        raise typer.Exit(code=_EXIT_UNKNOWN_ADAPTER)

    if wait_ready:
        assert adapter is not None  # guarded above; narrows for the type checker
        code = asyncio.run(_wait_ready(adapter, timeout))
        raise typer.Exit(code=code)

    try:
        result = asyncio.run(_query_status())
    except DaemonControlError as exc:
        log.warning("gateway.adapters.control_query_failed", error=type(exc).__name__)
        typer.echo(t("gateway.adapters.unavailable"))
        raise typer.Exit(code=_EXIT_UNAVAILABLE) from exc
    raise typer.Exit(code=_emit_status(result, adapter))

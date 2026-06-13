#!/usr/bin/env python3
"""Alfred comms-test MCP stdio plugin — full-lifecycle reference adapter (PR-S4-8).

Upgraded from the Slice-3 one-shot echo stub into a full-lifecycle comms adapter
exercising the ADR-0024 eight-method wire contract host-side (#152, Task 50):

Host -> plugin requests (the plugin answers):

* ``lifecycle.start``  -> :func:`handle_lifecycle_start`  -> ``{"ok": true}``
* ``lifecycle.stop``   -> :func:`handle_lifecycle_stop`   -> ``{"ok", "flushed_messages"}``
* ``adapter.health``   -> :func:`handle_adapter_health`   -> ``HealthReport`` shape
* ``outbound.message`` -> :func:`handle_outbound_message` -> ``_OutboundDelivered`` shape

Plugin -> host notifications (emitted on internal test triggers):

* ``inbound.message``          (``alfred_comms_test/inject_inbound``)
* ``adapter.binding_request``  (``alfred_comms_test/inject_binding_request``)
* ``adapter.rate_limit_signal``(``alfred_comms_test/inject_rate_limit``)
* ``adapter.crashed``          (``alfred_comms_test/inject_crash``)

The internal ``alfred_comms_test/*`` triggers are NOT part of the ADR-0024 wire
contract — they are the test harness's lever to make the plugin manufacture a
host-bound notification on demand. The most dangerous of these,
``inject_inbound``, fabricates an inbound platform message; it is therefore
gated on the dev/test ``ALFRED_ENV`` allowlist (``development`` / ``test``) and
refuses in production (and on any unset / empty / unknown ``ALFRED_ENV``) with a
``comms.test_injection_refused`` refusal frame + a raised
:class:`TestInjectionRefusedError` (plan §10 risk row / Task 51). The plugin process
has no DB, so "audit row + raise" is realised as a structured refusal frame the
host records plus a hard raise that crashes the subprocess loudly.

This plugin is for TEST USE ONLY — no production functionality. The host
transport speaks line-delimited JSON-RPC (matching ``alfred_web_fetch`` /
``alfred_quarantined_llm``); JSON-RPC method names appear LITERALLY on the wire.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from typing import Any, Final

# ADR-0024 wire method names — host -> plugin requests.
_METHOD_LIFECYCLE_START: Final[str] = "lifecycle.start"
_METHOD_LIFECYCLE_STOP: Final[str] = "lifecycle.stop"
_METHOD_ADAPTER_HEALTH: Final[str] = "adapter.health"
_METHOD_OUTBOUND_MESSAGE: Final[str] = "outbound.message"

# Plugin -> host notification method names.
_NOTIFY_INBOUND: Final[str] = "inbound.message"
_NOTIFY_BINDING: Final[str] = "adapter.binding_request"
_NOTIFY_RATE_LIMIT: Final[str] = "adapter.rate_limit_signal"
_NOTIFY_CRASHED: Final[str] = "adapter.crashed"

# Internal test-trigger method names (NOT part of the wire contract).
_TRIGGER_INJECT_INBOUND: Final[str] = "alfred_comms_test/inject_inbound"
_TRIGGER_INJECT_BINDING: Final[str] = "alfred_comms_test/inject_binding_request"
_TRIGGER_INJECT_RATE_LIMIT: Final[str] = "alfred_comms_test/inject_rate_limit"
_TRIGGER_INJECT_CRASH: Final[str] = "alfred_comms_test/inject_crash"

_ADAPTER_ID: Final[str] = "alfred_comms_test"
_PLUGIN_VERSION: Final[str] = "0.1.0"

# Env values under which fabricated-inbound injection is permitted.
# FAIL-CLOSED: the empty string is deliberately NOT a member — an unset or empty
# signal (the common production default) must REFUSE, never default-allow.
# Only an explicit ``development``/``test`` signal opens the gate.
_INJECTION_ALLOWED_ENVS: Final[frozenset[str]] = frozenset({"development", "test"})

# Env var names the injection gate consults, in precedence order. ``ALFRED_ENV``
# is the plugin's own historical dev/test signal; ``ALFRED_ENVIRONMENT`` is the
# daemon's launcher control surface — the ONLY env-tier signal that survives the
# daemon's SCRUBBED comms-child allowlist (alfred.plugins._comms_child_env), so a
# daemon-spawned reference adapter is gated on it. A test process that exports
# neither (or exports an empty / production value in both) still REFUSES.
_INJECTION_ENV_VARS: Final[tuple[str, ...]] = ("ALFRED_ENV", "ALFRED_ENVIRONMENT")

# Event name the host records when an injection is refused in production.
_REFUSAL_EVENT: Final[str] = "comms.test_injection_refused"


class TestInjectionRefusedError(RuntimeError):
    """Raised when ``inject_inbound`` runs outside the dev/test env allowlist.

    Fail-closed: only an explicit ``ALFRED_ENV`` of ``development`` or ``test``
    opens the gate (:data:`_INJECTION_ALLOWED_ENVS`); an unset / empty value (the
    common production default) and any other value REFUSE. Carries
    :attr:`event` = ``comms.test_injection_refused`` so the refusal frame + the
    host's audit row name the same closed-vocabulary event.
    """

    event: Final[str] = _REFUSAL_EVENT


# ---------------------------------------------------------------------------
# Adapter state (one subprocess lifetime). Pure functions mutate it via the
# module-level dict so the unit tests can ``reset_state()`` between cases.
# ---------------------------------------------------------------------------

_state: dict[str, Any] = {"running": False, "outbound": [], "last_inbound_at": None}


def reset_state() -> None:
    """Reset adapter state — test-only helper for hermetic unit cases."""
    _state["running"] = False
    _state["outbound"] = []
    _state["last_inbound_at"] = None


def outbound_buffer_depth() -> int:
    """Number of outbound messages buffered this lifetime."""
    return len(_state["outbound"])


# ---------------------------------------------------------------------------
# Host -> plugin request handlers (the 8-method wire contract, answer half)
# ---------------------------------------------------------------------------


def handle_lifecycle_start(_params: dict[str, Any]) -> dict[str, Any]:
    """Mark the adapter running; report the plugin version.

    Spec A G2 (#237): this reference adapter does NOT advertise the seq/ack
    capability, even though the host may advertise it on ``lifecycle.start``.
    seq/ack is the resumable core<->gateway leg (G3); a daemon-SPAWNED plugin is
    not the seq/ack peer — it dies with the core, so there is no resume benefit —
    and it never deframes the out-of-band ``A1`` header in its plain ``json.loads``
    serve loop. Echoing the capability would flip the host's version-gate ON and
    every subsequent host->plugin frame would arrive ``A1``-wrapped, which this
    plugin cannot parse. So the echo is deliberately ABSENT: the gate stays OFF
    and the wire stays plain ADR-0025. The gateway (G3) is the peer that both
    echoes the capability and deframes the header (ADR-0032).
    """
    _state["running"] = True
    return {"ok": True, "plugin_version": _PLUGIN_VERSION}


def handle_lifecycle_stop(_params: dict[str, Any]) -> dict[str, Any]:
    """Stop the adapter, flushing any buffered outbound; report flushed count."""
    flushed = len(_state["outbound"])
    _state["outbound"] = []
    _state["running"] = False
    return {"ok": True, "flushed_messages": flushed}


def handle_adapter_health(_params: dict[str, Any]) -> dict[str, Any]:
    """Return a ``HealthReport``-shaped snapshot.

    ``queue_depth`` reports the REAL pending-outbound buffer depth (the same
    buffer ``lifecycle.stop`` drains and reports as ``flushed_messages``), not a
    hardcoded ``0`` — so ``adapter.health`` stays truthful after the first send.
    """
    return {
        "ok": bool(_state["running"]),
        "last_inbound_at": _state["last_inbound_at"],
        "queue_depth": outbound_buffer_depth(),
        "error_count": 0,
    }


def handle_outbound_message(params: dict[str, Any]) -> dict[str, Any]:
    """Buffer the outbound message + report ``_OutboundDelivered``.

    The reference adapter never touches a real platform — it records the
    delivery in an in-memory buffer (drained by ``lifecycle.stop``) and reports a
    synthetic ``delivered`` outcome with a fabricated platform message id.
    """
    _state["outbound"].append(params)
    return {
        "outcome": "delivered",
        "platform_message_id": f"msg-{len(_state['outbound'])}",
    }


# ---------------------------------------------------------------------------
# Plugin -> host notification builders + the production-gated injector
# ---------------------------------------------------------------------------


def build_inbound_notification(body: dict[str, Any]) -> dict[str, Any]:
    """Build an ``inbound.message`` notification frame for ``body``.

    Matches the host-side ``InboundMessageNotification`` wire schema:
    ``adapter_id``, ``platform_user_id``, ``body``, ``sub_payload_refs``,
    ``received_at`` (tz-aware), ``addressing_signal``. ``platform_metadata`` is
    threaded through verbatim from the injection payload so the adversarial
    corpus can plant a forged ``canonical_user_id`` there and assert the host
    ignores it. No ``id`` member — this is a JSON-RPC notification.
    """
    _state["last_inbound_at"] = datetime.now(UTC).isoformat()
    params: dict[str, Any] = {
        "adapter_id": _ADAPTER_ID,
        # Spec A decision 4 (G0): the durable wire dedup key. This reference
        # plugin emits a genuinely new frame per inject, so a fresh uuid4 per
        # build is the correct opaque id. The host validates it through
        # ``InboundMessageNotification.model_validate(raw)``, so a missing
        # inbound_id would fail validation host-side, not here.
        "inbound_id": uuid.uuid4().hex,
        "platform_user_id": body.get("platform_user_id", "discord:reference"),
        "body": {"content": body.get("content", "")},
        "sub_payload_refs": [],
        "received_at": datetime.now(UTC).isoformat(),
        "addressing_signal": body.get("addressing_signal", "dm"),
    }
    if "platform_metadata" in body:
        params["platform_metadata"] = body["platform_metadata"]
    return {"jsonrpc": "2.0", "method": _NOTIFY_INBOUND, "params": params}


def build_binding_request_notification(payload: dict[str, Any]) -> dict[str, Any]:
    """Build an ``adapter.binding_request`` notification frame."""
    return {
        "jsonrpc": "2.0",
        "method": _NOTIFY_BINDING,
        "params": {
            "adapter_id": _ADAPTER_ID,
            "platform_user_id": payload.get("platform_user_id", "discord:newcomer"),
            "verification_phrase": payload.get("verification_phrase", "blue-otter-42"),
            "platform_metadata": payload.get("platform_metadata", {}),
        },
    }


def build_rate_limit_notification(payload: dict[str, Any]) -> dict[str, Any]:
    """Build an ``adapter.rate_limit_signal`` notification frame."""
    return {
        "jsonrpc": "2.0",
        "method": _NOTIFY_RATE_LIMIT,
        "params": {
            "adapter_id": _ADAPTER_ID,
            "retry_after_seconds": int(payload.get("retry_after_seconds", 5)),
            "platform_endpoint": payload.get("platform_endpoint", "POST /messages"),
        },
    }


def build_crashed_notification(payload: dict[str, Any]) -> dict[str, Any]:
    """Build an ``adapter.crashed`` notification frame."""
    return {
        "jsonrpc": "2.0",
        "method": _NOTIFY_CRASHED,
        "params": {
            "adapter_id": _ADAPTER_ID,
            "error_class": payload.get("error_class", "AdapterRuntimeError"),
            "detail": payload.get("detail", "self-reported crash (test trigger)"),
        },
    }


def inject_inbound(body: dict[str, Any]) -> dict[str, Any]:
    """Manufacture an ``inbound.message`` notification — gated on ``ALFRED_ENV``.

    The highest-risk test trigger: it fabricates an inbound platform message.
    Outside the dev/test allowlist it refuses with :class:`TestInjectionRefusedError`
    (event ``comms.test_injection_refused``) so a production deployment can never
    be coerced into injecting synthetic inbound traffic (plan §10 risk row).

    The gate accepts a dev/test signal from EITHER ``ALFRED_ENV`` (the plugin's own
    historical control) or ``ALFRED_ENVIRONMENT`` (the daemon's launcher control
    surface, the only env-tier signal that survives the scrubbed comms-child
    allowlist). Fail-closed is preserved: the gate opens ONLY if at least one var
    carries an explicit ``development`` / ``test`` value; unset / empty / production
    on every var REFUSES.
    """
    resolved_env = _resolve_injection_env()
    if resolved_env not in _INJECTION_ALLOWED_ENVS:
        raise TestInjectionRefusedError(
            f"inject_inbound refused: env={resolved_env!r} is not a test environment "
            f"(event={_REFUSAL_EVENT})"
        )
    return build_inbound_notification(body)


def _resolve_injection_env() -> str:
    """Return the first explicit dev/test env signal, or ``""`` if none.

    Reads :data:`_INJECTION_ENV_VARS` in precedence order and returns the first
    value that is in the dev/test allowlist; otherwise returns the (possibly
    empty) first var's value for the refusal message. Fail-closed: an
    all-unset / all-empty / production-only set resolves to a non-allowlisted
    value and the caller refuses.
    """
    for name in _INJECTION_ENV_VARS:
        value = os.environ.get(name, "").strip()
        if value in _INJECTION_ALLOWED_ENVS:
            return value
    return os.environ.get(_INJECTION_ENV_VARS[0], "").strip()


def build_test_injection_refused_frame(env: str) -> dict[str, Any]:
    """Build the structured refusal frame the host records for a refused inject."""
    return {
        "jsonrpc": "2.0",
        "method": _REFUSAL_EVENT,
        "params": {"adapter_id": _ADAPTER_ID, "alfred_env": env},
    }


# ---------------------------------------------------------------------------
# JSON-RPC envelope helpers
# ---------------------------------------------------------------------------


def _build_method_not_found(method: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def _build_parse_error(detail: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32700, "message": "Parse error", "data": {"detail": detail}},
    }


def _build_invalid_request(req_id: object) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32600, "message": "Invalid Request"}}


# Request methods that produce a synchronous result.
_REQUEST_HANDLERS: Final[dict[str, Any]] = {
    _METHOD_LIFECYCLE_START: handle_lifecycle_start,
    _METHOD_LIFECYCLE_STOP: handle_lifecycle_stop,
    _METHOD_ADAPTER_HEALTH: handle_adapter_health,
    _METHOD_OUTBOUND_MESSAGE: handle_outbound_message,
}

# Trigger methods that emit a host-bound notification (no request result).
_NOTIFY_TRIGGERS: Final[dict[str, Any]] = {
    _TRIGGER_INJECT_BINDING: build_binding_request_notification,
    _TRIGGER_INJECT_RATE_LIMIT: build_rate_limit_notification,
    _TRIGGER_INJECT_CRASH: build_crashed_notification,
}


async def _serve_stdin_stdout() -> None:  # pragma: no cover - exercised via subprocess
    """MCP stdio loop: read JSON-RPC, answer requests, emit notifications.

    Covered end-to-end by the integration tests (which spawn this module as a
    subprocess); the pure handlers above carry the unit coverage.
    """
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_event_loop()
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    writer_transport, _writer_protocol = await loop.connect_write_pipe(
        asyncio.BaseProtocol, sys.stdout.buffer
    )

    def _emit(frame: dict[str, Any]) -> None:
        writer_transport.write((json.dumps(frame) + "\n").encode())

    while True:
        line = await reader.readline()
        if not line:
            break
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            _emit(_build_parse_error(str(exc)))
            continue
        if not isinstance(request, dict):
            _emit(_build_invalid_request(None))
            continue

        has_response_id = "id" in request
        req_id = request.get("id")
        params = request.get("params") or {}
        method = request.get("method")
        if not isinstance(method, str) or not method:
            _emit(_build_invalid_request(req_id if has_response_id else None))
            continue

        # The inbound injector is production-gated. A refusal emits the structured
        # refusal frame then crashes the subprocess (loud, never silent).
        if method == _TRIGGER_INJECT_INBOUND:
            try:
                _emit(inject_inbound(params))
            except TestInjectionRefusedError:
                _emit(build_test_injection_refused_frame(os.environ.get("ALFRED_ENV", "").strip()))
                raise
            continue

        if method in _NOTIFY_TRIGGERS:
            _emit(_NOTIFY_TRIGGERS[method](params))
            continue

        handler = _REQUEST_HANDLERS.get(method)
        if handler is None:
            response = _build_method_not_found(method)
        else:
            response = {"jsonrpc": "2.0", "result": handler(params)}

        if has_response_id:
            response["id"] = req_id
            _emit(response)


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    asyncio.run(_serve_stdin_stdout())

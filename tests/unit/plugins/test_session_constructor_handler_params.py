"""``AlfredPluginSession`` comms-handler constructor params + factory (Task 35).

The Slice-3 ``__init__`` gains six optional, keyword-only comms params
(``inbound_handler`` / ``binding_handler`` / ``rate_limit_handler`` /
``crash_handler`` / ``supervisor`` / ``adapter_id``) plus a ``dispatch_semaphore``
and ``error_counter``, all defaulting so every Slice-3 caller still constructs
unchanged. The enforcing ``for_comms_adapter`` factory (comms-004) makes the
four handlers REQUIRED and allocates a fresh per-session semaphore + counter.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.comms_mcp.handlers import (
    BindingHandler,
    CrashHandler,
    InboundHandler,
    RateLimitHandler,
)
from alfred.plugins.manifest import parse_manifest
from alfred.plugins.session import AlfredPluginSession
from alfred.utils.sliding_window_counter import SlidingWindowCounter

_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred_comms_test"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"

[sandbox]
kind = "none"
"""


def _manifest() -> object:
    return parse_manifest(_MANIFEST)


def _audit() -> MagicMock:
    writer = MagicMock()
    writer.append_schema = AsyncMock()
    return writer


def _gate() -> MagicMock:
    gate = MagicMock()
    gate.check_plugin_load = MagicMock(return_value=True)
    return gate


# ---------------------------------------------------------------------------
# Constructor: new params accepted + backwards-compatible
# ---------------------------------------------------------------------------


def test_constructor_accepts_new_comms_params() -> None:
    session = AlfredPluginSession(
        manifest=_manifest(),
        audit_writer=_audit(),
        gate=_gate(),
        adapter_id="alfred_comms_test",
        inbound_handler=MagicMock(spec=InboundHandler),
        binding_handler=MagicMock(spec=BindingHandler),
        rate_limit_handler=MagicMock(spec=RateLimitHandler),
        crash_handler=MagicMock(spec=CrashHandler),
        dispatch_semaphore=asyncio.BoundedSemaphore(value=32),
        error_counter=SlidingWindowCounter(),
        supervisor=MagicMock(),
    )
    assert session._dispatch_semaphore is not None
    assert session._inbound_handler is not None
    assert session._adapter_id == "alfred_comms_test"


def test_constructor_backwards_compatible_without_comms_params() -> None:
    # Slice-3 callers pass no comms args; the session still constructs.
    session = AlfredPluginSession(
        manifest=_manifest(),
        audit_writer=_audit(),
        gate=_gate(),
    )
    assert session._inbound_handler is None
    assert session._adapter_id is None
    # A no-op semaphore is provisioned so the Slice-3 disallowed-method path
    # (which never enters the dispatch arm) constructs without a real one.
    assert session._dispatch_semaphore is not None


# ---------------------------------------------------------------------------
# Enforcing factory (comms-004)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_for_comms_adapter_requires_all_four_handlers() -> None:
    session = await AlfredPluginSession.for_comms_adapter(
        adapter_id="alfred_comms_test",
        manifest_raw=_MANIFEST,
        audit_writer=_audit(),
        gate=_gate(),
        supervisor=MagicMock(),
        inbound_handler=MagicMock(spec=InboundHandler),
        binding_handler=MagicMock(spec=BindingHandler),
        rate_limit_handler=MagicMock(spec=RateLimitHandler),
        crash_handler=MagicMock(spec=CrashHandler),
    )
    assert session._adapter_id == "alfred_comms_test"
    assert session._inbound_handler is not None
    assert session._binding_handler is not None
    assert session._rate_limit_handler is not None
    assert session._crash_handler is not None


@pytest.mark.asyncio
async def test_for_comms_adapter_allocates_fresh_per_session_state() -> None:
    common = {
        "manifest_raw": _MANIFEST,
        "audit_writer": _audit(),
        "gate": _gate(),
        "supervisor": MagicMock(),
        "inbound_handler": MagicMock(spec=InboundHandler),
        "binding_handler": MagicMock(spec=BindingHandler),
        "rate_limit_handler": MagicMock(spec=RateLimitHandler),
        "crash_handler": MagicMock(spec=CrashHandler),
    }
    session_a = await AlfredPluginSession.for_comms_adapter(
        adapter_id="alfred_comms_test", **common
    )
    session_b = await AlfredPluginSession.for_comms_adapter(
        adapter_id="alfred_comms_test", **common
    )
    # perf-003: per-adapter semaphore — two sessions hold distinct instances.
    assert session_a._dispatch_semaphore is not session_b._dispatch_semaphore
    assert session_a._error_counter is not session_b._error_counter


def test_for_comms_adapter_handlers_are_required_kwargs() -> None:
    # All four handlers are REQUIRED kwargs (comms-004): omitting one is a
    # TypeError at call time, not an Optional-defaulted None.
    with pytest.raises(TypeError):
        AlfredPluginSession.for_comms_adapter(  # type: ignore[call-arg]
            adapter_id="alfred_comms_test",
            manifest_raw=_MANIFEST,
            audit_writer=_audit(),
            gate=_gate(),
            supervisor=MagicMock(),
            inbound_handler=MagicMock(spec=InboundHandler),
        )

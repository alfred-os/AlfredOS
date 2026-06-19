"""G6-2b-2a (#288): the core-side session arm routing gateway.adapter.* to the observer.

Proves the prefix-routing arm in :meth:`AlfredPluginSession._on_post_handshake_method`
(correction #2): the WHOLE ``gateway.adapter.*`` namespace is intercepted and handed to
the injected :class:`AdapterStatusObserver`, BEFORE the ``_is_comms_session`` early
return — so a forged ``gateway.adapter.bogus`` reaches the observer's ``unknown_method``
refusal rather than the generic unknown-method handler that would restart the leg. Also
proves SEC-1: a typed audit-write failure from the observer propagates LOUDLY from the
arm (so the live runner can re-raise it past its catch-and-continue).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.comms_mcp.adapter_status_observer import AdapterStatusAuditWriteError
from alfred.comms_mcp.handlers import (
    BindingHandler,
    CrashHandler,
    InboundHandler,
    RateLimitHandler,
)
from alfred.comms_mcp.protocol import GATEWAY_ADAPTER_UP
from alfred.plugins.session import AlfredPluginSession

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


def _audit() -> MagicMock:
    writer = MagicMock()
    writer.append_schema = AsyncMock()
    return writer


def _gate() -> MagicMock:
    gate = MagicMock()
    gate.check_plugin_load = MagicMock(return_value=True)
    return gate


class _RecordingObserver:
    def __init__(self) -> None:
        self.observed: list[tuple[object, object]] = []

    async def observe(self, method: object, params: object) -> None:
        self.observed.append((method, params))


class _AuditFailingObserver:
    """An observer whose observe() raises the typed audit-write marker (SEC-1)."""

    async def observe(self, method: object, params: object) -> None:
        raise AdapterStatusAuditWriteError("status audit write failed")


class _RecordingSupervisor:
    def __init__(self) -> None:
        self.restart_requests: list[dict[str, str]] = []

    async def trip_breaker(
        self, *, component_id: str, reason: str
    ) -> None:  # pragma: no cover - unused
        raise AssertionError("trip_breaker not expected on the status arm")

    async def request_plugin_restart(self, *, adapter_id: str, reason: str) -> None:
        self.restart_requests.append({"adapter_id": adapter_id, "reason": reason})


async def _make_comms_session(
    *, status_observer: object, supervisor: object | None = None
) -> AlfredPluginSession:
    return await AlfredPluginSession.for_comms_adapter(
        adapter_id="alfred_comms_test",
        manifest_raw=_MANIFEST,
        audit_writer=_audit(),
        gate=_gate(),
        supervisor=supervisor if supervisor is not None else _RecordingSupervisor(),
        inbound_handler=MagicMock(spec=InboundHandler),
        binding_handler=MagicMock(spec=BindingHandler),
        rate_limit_handler=MagicMock(spec=RateLimitHandler),
        crash_handler=MagicMock(spec=CrashHandler),
        status_observer=status_observer,
    )


async def test_gateway_adapter_method_routes_to_observer() -> None:
    observer = _RecordingObserver()
    session = await _make_comms_session(status_observer=observer)
    params = {"adapter_id": "discord", "epoch": "a" * 32}
    await session._on_post_handshake_method(GATEWAY_ADAPTER_UP, params)
    assert observer.observed == [(GATEWAY_ADAPTER_UP, params)]


async def test_unknown_gateway_adapter_prefix_method_still_routes_to_observer() -> None:
    """Prefix routing (correction #2): a forged gateway.adapter.bogus reaches the observer.

    NOT only the four known constants — the observer is the SOLE authority over the
    whole ``gateway.adapter.*`` space, so its own ``unknown_method`` refusal fires
    (audited ``status_rejected``) rather than the generic unknown-method handler.
    """
    observer = _RecordingObserver()
    session = await _make_comms_session(status_observer=observer)
    await session._on_post_handshake_method("gateway.adapter.bogus", {"adapter_id": "discord"})
    assert observer.observed == [("gateway.adapter.bogus", {"adapter_id": "discord"})]


async def test_gateway_adapter_method_does_not_request_restart() -> None:
    """A gateway.adapter.* method is NOT an unknown method — no restart request."""
    observer = _RecordingObserver()
    supervisor = _RecordingSupervisor()
    session = await _make_comms_session(status_observer=observer, supervisor=supervisor)
    await session._on_post_handshake_method(
        GATEWAY_ADAPTER_UP, {"adapter_id": "discord", "epoch": "a" * 32}
    )
    assert supervisor.restart_requests == []


async def test_gateway_adapter_routes_before_is_comms_session_guard() -> None:
    """SEC-2: the arm is LIVE even on a NON-comms session (no adapter_id).

    The loud-refusal branch must not sit AFTER the ``not _is_comms_session`` early
    return (where it would be dead on Slice-3 sessions). A bare ``create()`` session
    has no adapter_id, yet a ``gateway.adapter.*`` frame still reaches the observer.
    """
    observer = _RecordingObserver()
    session = await AlfredPluginSession.create(
        manifest_raw=_MANIFEST,
        audit_writer=_audit(),
        gate=_gate(),
    )
    session._status_observer = observer  # type: ignore[attr-defined]
    assert session._is_comms_session is False
    await session._on_post_handshake_method(
        GATEWAY_ADAPTER_UP, {"adapter_id": "discord", "epoch": "a" * 32}
    )
    assert observer.observed == [(GATEWAY_ADAPTER_UP, {"adapter_id": "discord", "epoch": "a" * 32})]


async def test_no_observer_wired_treats_gateway_adapter_as_unknown() -> None:
    """A status frame with NO observer wired is loud+audited+restart (never dropped).

    Documents correction #8: in production the observer is injected into EVERY comms
    session, so this else-branch is defensive — but it must stay LOUD (hard rule #7).
    """
    supervisor = _RecordingSupervisor()
    session = await _make_comms_session(status_observer=None, supervisor=supervisor)
    await session._on_post_handshake_method(
        GATEWAY_ADAPTER_UP, {"adapter_id": "discord", "epoch": "a" * 32}
    )
    assert supervisor.restart_requests == [
        {"adapter_id": "alfred_comms_test", "reason": "unknown_notification"}
    ]


async def test_no_observer_non_comms_session_is_a_noop_not_a_crash() -> None:
    """A NON-comms session with no observer that somehow receives a ``gateway.adapter.*``
    frame falls through (``_route_gateway_adapter_status`` returns ``False``) to the
    Slice-3 no-op tail (the ``not _is_comms_session`` early return) — NOT the
    ``_emit_unknown_notification`` path, which would assert on the absent ``adapter_id``.

    The return-bool + shared-tail refactor removed both that latent assert-crash AND the
    duplicated unknown tail's unreachable restart-guard branch.
    """
    session = await AlfredPluginSession.create(
        manifest_raw=_MANIFEST,
        audit_writer=_audit(),
        gate=_gate(),
    )
    assert session._is_comms_session is False
    assert session._status_observer is None
    # No exception (under the pre-refactor duplicated tail this asserted at
    # _effective_adapter_id); the frame is a clean Slice-3 no-op.
    await session._on_post_handshake_method(
        GATEWAY_ADAPTER_UP, {"adapter_id": "discord", "epoch": "a" * 32}
    )


async def test_audit_write_failure_propagates_from_the_arm() -> None:
    """SEC-1: a typed audit-write failure from the observer propagates out of the arm.

    The arm does NOT swallow it (so the live runner can re-raise it past its blanket
    catch-and-continue) — fail-loud (CLAUDE.md hard rules #5/#7).
    """
    session = await _make_comms_session(status_observer=_AuditFailingObserver())
    with pytest.raises(AdapterStatusAuditWriteError):
        await session._on_post_handshake_method(
            GATEWAY_ADAPTER_UP, {"adapter_id": "discord", "epoch": "a" * 32}
        )

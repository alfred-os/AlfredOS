"""Daemon-side comms runtime adapters (PR-S4-11b Wave 2, #237).

The three host-side surfaces the daemon wires (Wave 4) between the inbound
trust-boundary path (:func:`alfred.comms_mcp.inbound.process_inbound_message`),
the comms-plugin runner (:class:`alfred.plugins.comms_runner.CommsPluginRunner`),
and the hook registry. They are deliberately additive and isolated-testable —
none of them is constructed by the daemon yet (that is Wave 4's
``_start_async`` wiring).

* :class:`CommsInboundOrchestratorAdapter` satisfies the inbound path's
  ``_OrchestratorLike`` Protocol. ``quarantined_extract`` delegates to the
  injected :class:`CommsExtractorBridge` (raw body -> handle -> structured
  ``ExtractionResult``); ``ingest`` records the inbound + builds the ack
  envelope; ``dispatch`` emits a FIXED-SHAPE ack outbound via a LATE-BOUND
  :class:`OutboundSenderLike` seam. 11b's dispatch does NOT call any privileged
  ``handle_user_message`` — it produces a deterministic ack so the round-trip is
  observable end to end while the privileged turn machinery stays out of scope.

  The sender is late-bound because the runner that satisfies it
  (:meth:`CommsPluginRunner.send_request`) is constructed AFTER the orchestrator
  adapter in the daemon boot order (the runner needs the session, which needs the
  handlers, which need this adapter). Calling ``ingest`` / ``dispatch`` before
  :meth:`bind_outbound_sender` is a wiring error and raises a loud
  :class:`RuntimeError` (CLAUDE.md hard rule #7 — never a silent miss).

* :class:`CommsAdapterCrashedHookInvoker` satisfies the crash handler's
  ``_HookInvokerLike`` seam by firing the ``comms.adapter.crashed`` hookpoint
  through the real :func:`alfred.hooks.invoke.invoke` API,
  ``subscribable_tiers=SYSTEM_OPERATOR_TIERS`` (the tier set the hookpoint was
  declared with — system + operator may observe a crash, never ``user-plugin``).

* :func:`_build_comms_inbound_extractor` constructs a REAL
  :class:`QuarantinedExtractor` over a recorded-fixture LLM transport (the
  recorded-response pattern CLAUDE.md sanctions outside smoke tests), wired with
  the REAL ``outbound_dlp`` the daemon owns — only the LLM transport is a
  fixture, so the genuine ``extract(handle, schema)`` + post-stage DLP scan path
  is exercised.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol, runtime_checkable

import structlog

from alfred.comms_mcp.hookpoints import ADAPTER_CRASHED_HOOKPOINT
from alfred.hooks.context import HookContext
from alfred.hooks.registry import SYSTEM_OPERATOR_TIERS
from alfred.i18n import t
from alfred.security.quarantine import QuarantinedExtractor

if TYPE_CHECKING:
    from alfred.audit.log import AuditWriter
    from alfred.comms_mcp.bootstrap import CommsExtractorBridge
    from alfred.plugins.transport import DispatchResult
    from alfred.security.dlp import OutboundDlp
    from alfred.security.quarantine import ExtractionResult

_log = structlog.get_logger(__name__)

# The fixed ack body the 11b dispatch emits. A deterministic, content-free
# acknowledgement so the inbound -> extract -> ingest -> dispatch -> outbound
# round-trip is observable end to end without invoking the (out-of-scope)
# privileged per-turn machinery.
_ACK_BODY: Mapping[str, object] = {"content": "ack"}

# The hook-invoke seam shape (:func:`alfred.hooks.invoke.invoke`). Injected so the
# crash invoker can be unit-tested without standing up a full registry + dispatch
# chain; the daemon wires the real ``invoke``.
type _InvokeFn = Callable[..., Awaitable[HookContext[Any]]]

# The recorded ``quarantine.extract`` response the fixture transport replays. A
# ``CommsBodyExtraction``-valid ``extracted`` payload so the real extractor lift
# is exercised against a deterministic response (recorded-LLM-response pattern).
_RECORDED_EXTRACT_PAYLOAD: Final[Mapping[str, object]] = {
    "kind": "extracted",
    "data": {"text": "hello", "intent": "greeting"},
    "extraction_mode": "native_constrained",
}


@runtime_checkable
class OutboundSenderLike(Protocol):
    """The narrow host -> plugin outbound seam the dispatch ack uses.

    :meth:`alfred.plugins.comms_runner.CommsPluginRunner.send_request` satisfies
    this via a thin wrapper (Wave 4) that maps ``send_outbound`` onto an
    ``outbound.message`` JSON-RPC request. Kept as a structural Protocol so this
    module never imports the runner (one-directional import graph) and tests can
    drive it with a recording double.
    """

    async def send_outbound(
        self,
        *,
        adapter_id: str,
        target_platform_id: str,
        body: Mapping[str, object],
    ) -> Mapping[str, object]: ...


class CommsInboundOrchestratorAdapter:
    """The ``_OrchestratorLike`` the inbound trust-boundary path drives.

    Holds the body-shaped :class:`CommsExtractorBridge` for ``quarantined_extract``
    and a LATE-BOUND :class:`OutboundSenderLike` for the ack ``dispatch`` emits.
    See the module docstring for why the sender is bound after construction and
    why a pre-bind ``ingest`` / ``dispatch`` fails loudly.
    """

    def __init__(self, *, extractor_bridge: CommsExtractorBridge) -> None:
        self._extractor_bridge = extractor_bridge
        self._outbound_sender: OutboundSenderLike | None = None

    def bind_outbound_sender(self, sender: OutboundSenderLike) -> None:
        """Wire the outbound seam the dispatch ack flows through (Wave-4 boot)."""
        self._outbound_sender = sender

    async def quarantined_extract(
        self,
        body: bytes | str | Mapping[str, object],
        *,
        canonical_user_id: str,
        source_tier: Literal["T3"],
    ) -> ExtractionResult:
        """Delegate to the bridge — raw T3 body -> structured ``ExtractionResult``.

        ``canonical_user_id`` is accepted by the seam but never crosses the
        quarantine wire (the bridge drops it — spec §8.2 identity invariant);
        ``source_tier`` is pinned ``"T3"`` by the inbound caller.
        """
        return await self._extractor_bridge.extract(
            body=body, canonical_user_id=canonical_user_id, source_tier=source_tier
        )

    async def ingest(self, **kwargs: Any) -> object:
        """Record the inbound + build the ack envelope the dispatch will send.

        The privileged per-turn machinery is out of 11b scope, so ingest produces
        a deterministic ack descriptor carrying ONLY the platform-facing
        identifiers (``adapter_id`` + ``target_platform_id``) — the canonical user
        id arrives as a discrete kwarg and is intentionally NOT folded into the
        outbound, preserving the identity invariant (spec §8.2).
        """
        sender = self._require_sender()
        del sender  # presence-checked here so a pre-bind ingest fails loudly too
        notification = kwargs["notification"]
        return {
            "adapter_id": notification.adapter_id,
            "target_platform_id": notification.platform_user_id,
        }

    async def dispatch(self, ingested: object) -> None:
        """Emit the fixed-shape ack outbound through the late-bound sender."""
        sender = self._require_sender()
        if not isinstance(ingested, Mapping):
            raise RuntimeError(t("comms.daemon_runtime.dispatch_bad_ingested"))
        await sender.send_outbound(
            adapter_id=str(ingested["adapter_id"]),
            target_platform_id=str(ingested["target_platform_id"]),
            body=_ACK_BODY,
        )

    def _require_sender(self) -> OutboundSenderLike:
        """Return the bound sender or raise loudly (no silent failure)."""
        if self._outbound_sender is None:
            _log.error("comms.daemon_runtime.sender_unbound")
            raise RuntimeError(t("comms.daemon_runtime.sender_unbound"))
        return self._outbound_sender


class CommsAdapterCrashedHookInvoker:
    """Fires ``comms.adapter.crashed`` through the real ``invoke`` API.

    Satisfies the crash handler's ``_HookInvokerLike`` seam. The injected
    ``invoke`` defaults to :func:`alfred.hooks.invoke.invoke`; tests pass a double
    so the contract is exercised without a full registry + dispatch chain. The
    crash payload carries only the closed-vocab ``adapter_id`` + ``error_class``
    — never raw plugin bytes.
    """

    def __init__(self, *, invoke: _InvokeFn | None = None) -> None:
        if invoke is None:
            from alfred.hooks.invoke import invoke as real_invoke

            invoke = real_invoke
        self._invoke = invoke

    async def fire_adapter_crashed(self, *, adapter_id: str, error_class: str) -> None:
        ctx: HookContext[dict[str, object]] = HookContext(
            action_id=ADAPTER_CRASHED_HOOKPOINT,
            hookpoint=ADAPTER_CRASHED_HOOKPOINT,
            input={"adapter_id": adapter_id, "error_class": error_class},
            correlation_id=adapter_id,
            kind="post",
        )
        await self._invoke(
            ADAPTER_CRASHED_HOOKPOINT,
            ctx,
            kind="post",
            subscribable_tiers=SYSTEM_OPERATOR_TIERS,
        )


class _RecordedExtractTransport:
    """A :class:`PluginTransport` that replays one recorded extract response.

    The recorded-LLM-response substitute the daemon uses until a real quarantined
    LLM is co-hosted (11b is the fixture cut). It implements the production
    ``PluginTransport`` Protocol so the real :class:`QuarantinedExtractor` drives
    it exactly as it would the stdio transport — every dispatch returns the same
    ``CommsBodyExtraction``-valid ``ControlResult``. ``close`` is an idempotent
    no-op (there is no subprocess behind this transport).
    """

    async def dispatch(self, method: str, params: dict[str, object]) -> DispatchResult:
        del method, params  # the recorded response is independent of the request
        from alfred.plugins.transport import ControlResult

        return ControlResult(
            method="quarantine.extract",
            payload=dict(_RECORDED_EXTRACT_PAYLOAD),
        )

    async def close(self) -> None:
        return None


def _build_comms_inbound_extractor(
    *, audit_writer: AuditWriter, outbound_dlp: OutboundDlp
) -> QuarantinedExtractor:
    """Construct a REAL :class:`QuarantinedExtractor` over a recorded transport.

    Mirrors ``tests/integration/_comms_mcp_harness._build_fixture_extractor`` in
    spirit but threads the REAL ``outbound_dlp`` the daemon owns (not a stub) so
    the post-stage DLP scan registered at extractor construction is the
    production scanner. Only the LLM transport is recorded
    (:class:`_RecordedExtractTransport`) — the genuine ``extract(handle, schema)``
    lift runs against a deterministic ``extracted`` response.
    """
    return QuarantinedExtractor(
        transport=_RecordedExtractTransport(),
        audit_writer=audit_writer,
        outbound_dlp=outbound_dlp,
    )


# ``_build_comms_inbound_extractor`` is deliberately omitted from ``__all__``:
# its leading underscore marks it module-private. The daemon boot wiring imports
# it by its private name (``from ...daemon_runtime import _build_comms_inbound_extractor``)
# rather than through the public surface, so it stays out of the star-export.
__all__ = [
    "CommsAdapterCrashedHookInvoker",
    "CommsInboundOrchestratorAdapter",
    "OutboundSenderLike",
]

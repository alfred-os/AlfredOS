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
  :class:`QuarantinedExtractor` over the REAL
  :class:`alfred.security.quarantine_transport.QuarantineStdioTransport`, driven
  by a LIVE bwrap-sandboxed quarantined child spawned via
  :func:`alfred.security.quarantine_child_io.spawn_quarantine_child_io`
  (PR-S4-11c-2b, the daemon go-live flip — ADR-0027 amended). It is ``async``
  because the spawn is async, and FAIL-CLOSED: on a non-Linux / unprovisioned
  host the spawn raises :class:`QuarantineChildSpawnError`, which propagates so
  the daemon refuses to boot with a clear operator message rather than running a
  fixture extractor in production. The 2b child runs a DETERMINISTIC ECHO loop
  (no real LLM, no egress); the real provider client + its egress allowlist land
  in PR-S4-11c-2c behind release-blocker #230.
"""

from __future__ import annotations

import platform
from collections.abc import Awaitable, Callable, Mapping
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable
from uuid import uuid4

import structlog

from alfred.comms_mcp.hookpoints import ADAPTER_CRASHED_HOOKPOINT
from alfred.comms_mcp.protocol import OutboundMessageRequest
from alfred.errors import AlfredError
from alfred.hooks.context import HookContext
from alfred.hooks.registry import SYSTEM_OPERATOR_TIERS
from alfred.i18n import t
from alfred.security.quarantine import QuarantinedExtractor

if TYPE_CHECKING:
    from alfred.audit.log import AuditWriter
    from alfred.comms_mcp.bootstrap import CommsExtractorBridge
    from alfred.security.dlp import OutboundDlp
    from alfred.security.quarantine import ExtractionResult
    from alfred.security.quarantine_transport import QuarantineStagingMap, QuarantineStdioTransport
    from alfred.security.secrets import SecretBroker

# The secret-broker id the quarantined child's provider key is resolved by
# (config/routing.yaml ``[quarantine] secret_id`` — pinned by
# test_routing_yaml_quarantine_block). Resolved at boot and delivered over fd 3
# to the bwrap child; NEVER read from the child's own env.
_PROVIDER_KEY_SECRET_ID = "quarantine_provider_api_key"  # noqa: S105 - broker lookup id, not a credential

_log = structlog.get_logger(__name__)

# The fixed ack *content text* the 11b dispatch emits. A deterministic,
# content-free acknowledgement so the inbound -> extract -> ingest -> dispatch ->
# outbound round-trip is observable end to end without invoking the (out-of-scope)
# privileged per-turn machinery. This is the RAW body string the outbound DLP
# chokepoint scans (:meth:`OutboundDlp.scan_for_outbound`) before the ack is
# wrapped in an :class:`OutboundMessageRequest` — the ack does NOT bypass DLP
# (CLAUDE.md hard rule #4: no outbound, not even a stubbed ack, skips the redactor).
_ACK_CONTENT: str = "ack"

# The ack is a direct reply, so it addresses the recipient in DM mode. The TUI
# handler refuses anything other than ``"dm"`` (it is 1:1); a stubbed ack to any
# adapter is conceptually a direct reply to the originating user.
_ACK_ADDRESSING_MODE: Literal["dm"] = "dm"

# The hook-invoke seam shape (:func:`alfred.hooks.invoke.invoke`). Injected so the
# crash invoker can be unit-tested without standing up a full registry + dispatch
# chain; the daemon wires the real ``invoke``.
type _InvokeFn = Callable[..., Awaitable[HookContext[Any]]]


@runtime_checkable
class OutboundSenderLike(Protocol):
    """The narrow host -> plugin outbound seam the dispatch ack uses.

    :meth:`alfred.plugins.comms_runner.CommsPluginRunner.send_request` satisfies
    this via a thin wrapper (Wave 4) that maps ``send_outbound`` onto an
    ``outbound.message`` JSON-RPC request. Kept as a structural Protocol so this
    module never imports the runner (one-directional import graph) and tests can
    drive it with a recording double.

    The seam takes a fully-validated :class:`OutboundMessageRequest` (G5 #237) —
    NOT a loose ``(adapter_id, target_platform_id, body)`` triple. Passing the
    typed request makes the wire contract type-safe at the construction site AND
    means the DLP-minted :data:`ScannedOutboundBody` body cannot be bypassed: the
    request is unconstructable without first routing the body through the outbound
    DLP chokepoint (CLAUDE.md hard rule #4). The sender serialises it onto the wire.
    """

    async def send_outbound(self, request: OutboundMessageRequest) -> Mapping[str, object]: ...


class CommsInboundOrchestratorAdapter:
    """The ``_OrchestratorLike`` the inbound trust-boundary path drives.

    Holds the body-shaped :class:`CommsExtractorBridge` for ``quarantined_extract``
    and a LATE-BOUND :class:`OutboundSenderLike` for the ack ``dispatch`` emits.
    See the module docstring for why the sender is bound after construction and
    why a pre-bind ``ingest`` / ``dispatch`` fails loudly.
    """

    def __init__(
        self, *, extractor_bridge: CommsExtractorBridge, outbound_dlp: OutboundDlp
    ) -> None:
        self._extractor_bridge = extractor_bridge
        # The outbound DLP chokepoint the stubbed ack is routed through before it
        # crosses the wire (CLAUDE.md hard rule #4 — no outbound, not even an ack,
        # bypasses the redactor). ``scan_for_outbound`` is the ONLY minter of the
        # ``ScannedOutboundBody`` the ``OutboundMessageRequest`` body field accepts.
        self._outbound_dlp = outbound_dlp
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
        """Emit the fixed-shape ack outbound through the late-bound sender.

        The ack body is routed through the outbound DLP chokepoint
        (:meth:`OutboundDlp.scan_for_outbound`) and wrapped in a fully-validated
        :class:`OutboundMessageRequest`. The DLP-minted :data:`ScannedOutboundBody`
        is the body — never a raw dict — so the ack cannot bypass the redactor
        (CLAUDE.md hard rule #4) and the wire frame satisfies
        ``OutboundMessageRequest`` on the consumer's ``model_validate``.

        ``addressing_mode`` is pinned :data:`_ACK_ADDRESSING_MODE` (``"dm"``), which
        is correct for the TODAY-shipped path: the 1:1 TUI reply leg (the TUI handler
        is dm-only). It is NOT yet derived from the ingested inbound — for a future
        GROUP-addressed Discord inbound a hard ``"dm"`` ack would be a behavioral
        mismatch. Deriving ``addressing_mode`` from the ingested inbound is a
        follow-up for when the Discord outbound path lands (G5 #237 scopes this to the
        TUI 1:1 reply path).
        """
        sender = self._require_sender()
        if not isinstance(ingested, Mapping):
            raise RuntimeError(t("comms.daemon_runtime.dispatch_bad_ingested"))
        # MANDATORY DLP chokepoint: mint the ScannedOutboundBody from the raw ack
        # content text. This is the ONLY way to obtain the body type the request
        # requires, so the ack physically cannot skip the scan.
        scanned_body = self._outbound_dlp.scan_for_outbound(_ACK_CONTENT)
        request = OutboundMessageRequest(
            adapter_id=self._require_ingested_key(ingested, "adapter_id"),
            idempotency_key=uuid4(),
            target_platform_id=self._require_ingested_key(ingested, "target_platform_id"),
            body=scanned_body,
            attachments_refs=(),
            addressing_mode=_ACK_ADDRESSING_MODE,
        )
        await sender.send_outbound(request)

    @staticmethod
    def _require_ingested_key(ingested: Mapping[str, object], key: str) -> str:
        """Return ``str(ingested[key])`` or raise a CONTEXTUAL error on a missing key.

        Symmetry with the ``dispatch_bad_ingested`` guard above: a malformed ingest
        result missing a required key surfaces the same operator-facing ``t()`` string
        (``comms.daemon_runtime.dispatch_missing_ingested_key``) rather than a bare,
        contextless ``KeyError`` (CLAUDE.md hard rule #7 — loud AND clear).
        """
        if key not in ingested:
            _log.error("comms.daemon_runtime.dispatch_missing_ingested_key", missing_key=key)
            raise RuntimeError(t("comms.daemon_runtime.dispatch_missing_ingested_key"))
        return str(ingested[key])

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


def _resolve_host_os() -> str:
    """Normalise the parent host OS to the launcher's {linux, macos, windows, unknown}.

    Mirrors ``bin/alfred-plugin-launcher.sh``'s ``_host_os()`` so a host-authored
    ``provider_key_delivery_failed`` row (#444) renders uniformly beside the
    launcher-authored ``sandbox_refused`` rows in ``alfred audit graph``.
    """
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    if system == "darwin":
        return "macos"
    if system == "windows":
        return "windows"
    return "unknown"


class QuarantineProviderKeyUnsetError(AlfredError):
    """No ``quarantine_provider_api_key`` is configured — refuse boot.

    The §20.2 PRIMARY refuse-boot (#340 golive): the quarantined child now makes
    a REAL provider call, so an unset key must fail LOUD at boot (CLAUDE.md hard
    rule #7) rather than resolve to a fallback placeholder — a real client built
    on a bogus key would be a SILENT dead-LLM (§20.3.1 must-not-regress). Rooted
    at :class:`AlfredError` so the CLI boot path's ``except`` arm can pattern-match
    it into an audited ``daemon.boot.failed`` refusal (exit 2).
    """


def _resolve_provider_key(secret_broker: SecretBroker) -> str:
    """Resolve the quarantined child's provider key; refuse boot if unset.

    Returns the broker-held ``quarantine_provider_api_key`` when configured. When
    unset, emits a LOUD structlog error and raises
    :class:`QuarantineProviderKeyUnsetError` — the §20.2 PRIMARY refuse-boot
    defense (#340 golive). The go-live child makes a REAL provider call, so an
    unset key is a fail-closed boot refusal, NOT a silent placeholder fallback
    that would build a real client on a bogus key (§20.3.1 must-not-regress,
    CLAUDE.md hard rule #7).

    SYNCHRONOUS by design (no ``await``): the caller
    (:func:`_build_comms_inbound_extractor`) invokes this BEFORE the single
    ``await spawn_quarantine_child_io(...)``, so a refuse here raises pre-spawn —
    the fd-3 clobber window never opens on the refuse path. Adding an ``await``
    would reopen that window; do not.
    """
    # ``has`` returns False (never raises) for a registered-but-unset secret, so
    # this branch is the clean "operator has not configured a quarantine provider
    # key yet" path — distinct from a broker construction failure (which raised
    # earlier at ``build_broker``).
    if secret_broker.has(_PROVIDER_KEY_SECRET_ID):
        return secret_broker.get(_PROVIDER_KEY_SECRET_ID)
    # Fail LOUD + fail CLOSED: a real provider client built on a bogus placeholder
    # key would be a silent dead-LLM (§20.3.1). The secret id is a closed
    # broker-lookup token (never a secret value), safe to log + carry in the error.
    _log.error(
        "comms.daemon_runtime.quarantine_provider_key_unset",
        secret_id=_PROVIDER_KEY_SECRET_ID,
    )
    raise QuarantineProviderKeyUnsetError(_PROVIDER_KEY_SECRET_ID)


async def _build_comms_inbound_extractor(
    *,
    audit_writer: AuditWriter,
    outbound_dlp: OutboundDlp,
    secret_broker: SecretBroker,
    staging: QuarantineStagingMap,
    environment: str,
) -> tuple[QuarantinedExtractor, QuarantineStdioTransport]:
    """Construct a REAL :class:`QuarantinedExtractor` over a LIVE quarantined child.

    The PR-S4-11c-2b go-live flip (ADR-0027 amended): replaces the prior
    recorded-fixture transport with the production
    :class:`alfred.security.quarantine_transport.QuarantineStdioTransport` driving
    a REAL bwrap-sandboxed quarantined child spawned via
    :func:`alfred.security.quarantine_child_io.spawn_quarantine_child_io`. The
    spawn delivers the provider key over fd 3; the ``staging`` map is the SAME
    single-use store the host's :class:`T3BodyRecorder` writes to, so the inline-
    over-wire content path (ADR-0029) is exercised end to end in production.

    FAIL-CLOSED (CLAUDE.md hard rule #7): on a non-Linux / unprovisioned host the
    spawn raises :class:`QuarantineChildSpawnError`, which propagates out of this
    builder so the daemon refuses to boot rather than silently degrading. There is
    NO dev fixture fallback.

    fd-3-clobber discipline: the provider key is resolved SYNCHRONOUSLY before the
    spawn, so the single ``await spawn_quarantine_child_io(...)`` is the only
    await that runs before or during the spawn's dup2 window — nothing
    interleaves in it. (Two further awaits exist in this builder, but only in the
    ``except`` cleanup arm below, and only AFTER the spawn has returned — by which
    point ``spawn_quarantine_child_io``'s own ``finally`` has already closed that
    window, so they do not reopen it.)
    """
    from alfred.security.quarantine_child_io import spawn_quarantine_child_io
    from alfred.security.quarantine_transport import QuarantineStdioTransport
    from alfred.security.sandbox_refusal_audit import SandboxRefusalAuditor

    provider_key = _resolve_provider_key(secret_broker)
    # SandboxRefusalAuditor construction is SYNCHRONOUS — it does NOT add an await
    # to the fd-3-clobber window; the await below remains the only one that touches it.
    refusal_recorder = SandboxRefusalAuditor(
        audit_writer=audit_writer,
        host_os=_resolve_host_os(),
        environment=environment,
    )
    # SINGLE await — the spawn owns the process-wide fd-3 clobber window and must
    # not race any other coroutine. Do not interleave awaits here.
    child_io = await spawn_quarantine_child_io(
        provider_key=provider_key, refusal_recorder=refusal_recorder
    )
    # Reap the just-spawned child if the (synchronous) transport/extractor
    # construction raises: this builder hasn't returned the transport yet, so the
    # daemon's exit-path teardown can't see it — without this the bwrap child would
    # leak on a post-spawn construction failure (CR #255 round-4).
    transport: QuarantineStdioTransport | None = None
    try:
        transport = QuarantineStdioTransport(child_io=child_io, staging=staging)
        extractor = QuarantinedExtractor(
            transport=transport,
            audit_writer=audit_writer,
            outbound_dlp=outbound_dlp,
        )
    except Exception:
        if transport is not None:
            await transport.close()
        else:
            await child_io.aclose()
        raise
    # Return the transport alongside the extractor so the daemon boot graph can
    # reap the LIVE bwrap child on every exit path (`transport.close()` ->
    # `child_io.aclose()`); the extractor alone exposes no teardown seam, so a
    # boot failure after the spawn — or a normal shutdown — would otherwise leak
    # the child (CR #255). The caller owns calling `transport.close()`.
    return extractor, transport


# ``_build_comms_inbound_extractor`` + ``_resolve_provider_key`` are deliberately
# omitted from ``__all__``: their leading underscore marks them module-private. The
# daemon boot wiring imports the builder by its private name (``from
# ...daemon_runtime import _build_comms_inbound_extractor``) rather than through the
# public surface, so it stays out of the star-export.
__all__ = [
    "CommsAdapterCrashedHookInvoker",
    "CommsInboundOrchestratorAdapter",
    "OutboundSenderLike",
    "QuarantineProviderKeyUnsetError",
]

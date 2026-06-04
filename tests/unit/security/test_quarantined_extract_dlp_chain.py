"""End-to-end: :meth:`QuarantinedExtractor.extract` dispatches through
the ``security.quarantined.extract`` hookpoint chain (issue #158).

The hookpoint dispatch is ADDITIVE to the existing audit-row family:

* :meth:`extract` continues to emit the
  ``quarantine.extract`` / ``quarantine.protocol_violation`` /
  ``quarantine.transport_failed`` rows the existing tests pin.
* AND it now dispatches through the
  ``security.quarantined.extract`` hookpoint's pre / post / error
  chains. A system-tier post subscriber
  (:class:`OutboundDlpExtractSubscriber`) refuses on canary trip;
  refusal propagates out of :meth:`extract` as :class:`HookRefusal`;
  the validated payload never returns.

Three scenarios pin the chain:

1. Clean extract with DLP subscriber registered — happy path;
   ``Extracted`` returned; audit rows emitted; no refusal.
2. Canary in the response — DLP subscriber raises
   :class:`HookRefusal`; :meth:`extract` propagates; the validated
   payload never reaches the caller.
3. Constructor wires the injected DLP into the post chain — pins
   that the DLP handed to :class:`QuarantinedExtractor.__init__`
   IS the one the ``security.quarantined.extract`` post chain
   dispatches at extract time (no implicit fallback, no swap).
   Post CR-156 round 7 / CR-158 T1 the constructor auto-registers,
   so the empty-bucket scenario is no longer reachable through the
   public API; the contract worth pinning is the inverse.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any, ClassVar, Literal
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.hooks import HookRefusal
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.plugins.transport import ControlResult
from alfred.security._extract_dlp_subscriber import register_extract_dlp_subscriber
from alfred.security.quarantine import (
    ContentHandle,
    Extracted,
    ExtractionSchema,
    QuarantinedExtractor,
    declare_hookpoints,
)
from tests.helpers.gates import make_quarantined_extract_chain_gate

# ---------------------------------------------------------------------------
# Local fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_registry_allow_system() -> Iterator[HookRegistry]:
    """Yield a brand-new :class:`HookRegistry` with the ``system`` tier
    granted, installed as the module singleton for the test.

    Mirrors ``tests/unit/hooks/conftest.py::fresh_registry_allow_system``
    — conftest is dir-scoped so we keep a local copy. Critical: the
    fixture must declare the ``security.quarantined.extract``
    hookpoint on the FRESH registry because the module-bottom
    :func:`declare_hookpoints` call only fires at the FIRST import of
    :mod:`alfred.security.quarantine`; the singleton swap-and-restore
    means the fresh registry starts empty.
    """
    prior = get_registry()
    # CR-156 round-7 / CR-158 T4 (CLAUDE.md hard rule #2): scoped
    # :class:`RealGate` — production gate code, no
    # ``make_permissive_fixture_gate(allow_system=True)`` shim. The
    # quarantined-extract chain is a PRD §7.1 trust-boundary path;
    # an always-allow stub would hide a regression in the registry's
    # grant-policy check. The scoped gate seeds exactly the
    # system-tier grant the DLP subscriber needs to register against
    # the security.quarantined.extract chain, plus system+operator
    # grants for THIS test module so tests that register ad-hoc
    # pre/error-stage observers under their own ``__module__``
    # attribution land cleanly.
    registry = HookRegistry(
        gate=make_quarantined_extract_chain_gate(
            extra_system_plugin_ids=(__name__,),
            extra_operator_plugin_ids=(__name__,),
        ),
        strict_declarations=False,
    )
    try:
        # Install + declare INSIDE the try so any failure in
        # :func:`declare_hookpoints` cannot leak the half-installed
        # singleton (CR-158 round 2). The earlier ordering called
        # :func:`set_registry` outside the try, so a raise from
        # :func:`declare_hookpoints` would never reach the
        # ``finally`` restore.
        set_registry(registry)
        # Re-run the publisher declaration against the freshly-installed
        # registry — the module-bottom declare_hookpoints() at first import
        # landed on the PRIOR registry; the fresh one is empty until we
        # explicitly re-declare.
        declare_hookpoints(registry)
        yield registry
    finally:
        set_registry(prior)


@pytest.fixture
def fake_audit_writer() -> MagicMock:
    """Capture every ``append_schema`` call on ``.calls``."""
    writer = MagicMock()
    writer.calls = []

    async def _capture(**kwargs: Any) -> None:
        writer.calls.append(kwargs)

    writer.append_schema = AsyncMock(side_effect=_capture)
    return writer


class _Schema(ExtractionSchema):
    """Schema with a free-text ``summary`` field — the spec's primary
    exfil-channel shape.
    """

    schema_version: ClassVar[Literal[1]] = 1
    summary: str = ""


def _make_handle() -> ContentHandle:
    return ContentHandle(
        id="handle-uuid-dlp",
        source_url="https://example.test/article",
        fetch_timestamp=datetime.now(UTC),
    )


def _clean_transport() -> MagicMock:
    """Transport whose extract response has a clean (no-canary)
    ``summary``.
    """
    transport = MagicMock()
    transport.dispatch = AsyncMock(
        return_value=ControlResult(
            method="quarantine.extract",
            payload={
                "kind": "extracted",
                "data": {"summary": "all clear"},
                "extraction_mode": "native_constrained",
            },
        ),
    )
    return transport


def _canary_transport() -> MagicMock:
    """Transport whose extract response carries a canary in the
    ``summary`` field.
    """
    transport = MagicMock()
    transport.dispatch = AsyncMock(
        return_value=ControlResult(
            method="quarantine.extract",
            payload={
                "kind": "extracted",
                "data": {"summary": "embedded CANARY-DLP-XYZ secret"},
                "extraction_mode": "native_constrained",
            },
        ),
    )
    return transport


def _redacting_dlp() -> MagicMock:
    """:class:`OutboundDlp` stub that redacts the canary token."""
    dlp = MagicMock()
    dlp.scan = MagicMock(
        side_effect=lambda x: re.sub(r"CANARY-DLP-XYZ", "[REDACTED]", x),
    )
    return dlp


def _identity_dlp() -> MagicMock:
    """:class:`OutboundDlp` stub that returns its input unchanged —
    clean scan, no trigger.
    """
    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda x: x)
    return dlp


# ---------------------------------------------------------------------------
# Scenario 1: clean extract with DLP subscriber registered.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_clean_extract_succeeds_with_dlp_subscriber_registered(
    fresh_registry_allow_system: HookRegistry,
    fake_audit_writer: MagicMock,
) -> None:
    """Happy path: clean model_dump passes the DLP subscriber, the
    chain returns the validated payload, the existing
    ``quarantine.extract`` audit row still emits.
    """
    dlp = _identity_dlp()
    register_extract_dlp_subscriber(
        registry=fresh_registry_allow_system,
        outbound_dlp=dlp,
    )

    transport = _clean_transport()
    extractor = QuarantinedExtractor(
        transport=transport,
        audit_writer=fake_audit_writer,
        outbound_dlp=dlp,
    )

    result = await extractor.extract(_make_handle(), _Schema)

    assert isinstance(result, Extracted)
    assert dict(result.data) == {"summary": "all clear"}
    # DLP scanned exactly once (post stage runs the subscriber once).
    dlp.scan.assert_called_once()
    # Existing audit-row family still emits the success row.
    events = [call["event"] for call in fake_audit_writer.calls]
    assert "quarantine.extract" in events


# ---------------------------------------------------------------------------
# Scenario 2: canary in extracted payload refused by DLP subscriber.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_extract_with_canary_in_response_is_refused_by_dlp_subscriber(
    fresh_registry_allow_system: HookRegistry,
    fake_audit_writer: MagicMock,
) -> None:
    """A canary in the extracted payload trips the post-stage DLP
    subscriber; :meth:`extract` propagates :class:`HookRefusal`; the
    validated payload never reaches the caller.
    """
    dlp = _redacting_dlp()
    register_extract_dlp_subscriber(
        registry=fresh_registry_allow_system,
        outbound_dlp=dlp,
    )

    transport = _canary_transport()
    extractor = QuarantinedExtractor(
        transport=transport,
        audit_writer=fake_audit_writer,
        outbound_dlp=dlp,
    )

    with pytest.raises(HookRefusal) as excinfo:
        await extractor.extract(_make_handle(), _Schema)

    # Refusal carries the canonical SCAN_ID hook_id.
    assert excinfo.value.hook_id == "security.quarantined.extract.post.dlp"
    # The DLP scan ran exactly once and was the source of the
    # refusal (the redaction delta).
    dlp.scan.assert_called_once()
    # The transport was hit exactly once — the body ran and produced
    # the result the DLP subscriber then refused. The post-stage
    # refusal does NOT retry the transport.
    transport.dispatch.assert_called_once()


@pytest.mark.asyncio
async def test_dlp_refusal_does_not_leave_misleading_success_audit_row(
    fresh_registry_allow_system: HookRegistry,
    fake_audit_writer: MagicMock,
) -> None:
    """Pin BLOCKER #2 (CR-158): the ``quarantine.extract`` audit row
    MUST reflect the post-stage DLP refusal — NOT the pre-refusal
    "extracted" classification.

    Before the fix the audit row landed inside :meth:`_extract_body`
    with ``result="extracted"`` BEFORE the post chain ran; on canary
    refusal the misleading "successful extraction" record stayed in
    the audit log forever. The fix DEFERS the audit emission to
    :meth:`extract` and rewrites the ``result`` value to
    ``"post_stage_refused"`` when the post chain raises
    :class:`HookRefusal`. The refusing subscriber's identity surfaces
    in the row's ``refusing_hook_id`` field — the only forensic
    surface for that attribution because ``invoke._run_post`` does
    NOT emit ``HOOKS_REFUSAL`` for post-stage refusals (§6.5 is
    pre-only by design).

    Asserts:

    * The ``quarantine.extract`` row exists.
    * Its ``result`` field is ``"post_stage_refused"`` (the generic
      closed-vocab :data:`TypedRefusalReason` value).
    * Its ``subject["refusing_hook_id"]`` is the DLP subscriber's
      canonical ``_SCAN_ID`` — i.e. ``"security.quarantined.extract.post.dlp"``.
    * Its ``extraction_mode`` is ``"refused"`` — matches the
      :class:`TypedRefusal` audit shape so the audit graph treats
      canary-blocked outcomes the same as typed-refusal outcomes.
    * The audit log carries NO row with ``result="extracted"`` — the
      audit log MUST NOT lie about the trust boundary's behaviour.

    CLAUDE.md hard rule #7 — no silent failures in security paths;
    the audit log IS the source of truth.
    """
    from alfred.security._extract_dlp_subscriber import OutboundDlpExtractSubscriber

    dlp = _redacting_dlp()
    register_extract_dlp_subscriber(
        registry=fresh_registry_allow_system,
        outbound_dlp=dlp,
    )
    transport = _canary_transport()
    extractor = QuarantinedExtractor(
        transport=transport,
        audit_writer=fake_audit_writer,
        outbound_dlp=dlp,
    )

    with pytest.raises(HookRefusal):
        await extractor.extract(_make_handle(), _Schema)

    extract_rows = [
        call for call in fake_audit_writer.calls if call["event"] == "quarantine.extract"
    ]
    assert len(extract_rows) == 1, (
        f"Expected exactly one quarantine.extract row; got "
        f"{[c['event'] for c in fake_audit_writer.calls]!r}"
    )
    row = extract_rows[0]
    # The row's outer ``result`` AND its ``subject.result`` are the
    # two attribution fields audit-graph consumers read; both must
    # reflect the refusal.
    assert row["result"] == "post_stage_refused", (
        f"Misleading audit row — expected result='post_stage_refused', "
        f"got {row['result']!r}. CLAUDE.md hard rule #7."
    )
    subject = row["subject"]
    assert subject["result"] == "post_stage_refused"
    assert subject["extraction_mode"] == "refused"
    # The refusing-subscriber identity is on the row's
    # ``refusing_hook_id`` — the ONLY forensic surface because
    # ``invoke._run_post`` is silent on post-stage refusals.
    assert subject["refusing_hook_id"] == OutboundDlpExtractSubscriber._SCAN_ID

    # And NO row anywhere classifies the canary-blocked outcome as
    # "extracted" — the regression the BLOCKER #2 fix exists to
    # prevent.
    extracted_rows = [
        call
        for call in fake_audit_writer.calls
        if call["event"] == "quarantine.extract" and call.get("result") == "extracted"
    ]
    assert extracted_rows == [], (
        f"Misleading 'extracted' audit row landed for a canary-refused outcome: {extracted_rows!r}"
    )


# ---------------------------------------------------------------------------
# Scenario 2.5: trace-key consistency across body + chain audit rows.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_quarantine_extract_audit_row_trace_id_matches_chain_correlation_id(
    fresh_registry_allow_system: HookRegistry,
    fake_audit_writer: MagicMock,
) -> None:
    """Pin the CR-158 round-4 audit-trace-key contract.

    Every ``quarantine.*`` audit row this extractor emits MUST carry the
    SAME ``trace_id`` value within a single call — that value is
    ``chain_correlation_id``, the UUID minted at chain entry. The body-
    local per-invocation ``correlation_id`` lives BELOW, inside the
    row's ``subject`` payload, and is a DISTINCT UUID. Forensic queries
    joining on ``trace_id`` see a single coherent trace covering the
    chain + body; ``subject["correlation_id"]`` narrows further to a
    specific body invocation.

    Pre-fix, ``trace_id`` was set to the body-local ``correlation_id``,
    splitting the hook-chain rows (keyed on ``chain_correlation_id``)
    from the ``quarantine.*`` rows. This test pins the join key model
    so a regression that re-introduces the split fails loudly.

    We exercise the post-stage refusal path because it emits a single
    ``quarantine.extract`` audit row at the post-chain boundary AND
    that row's ``subject`` carries the body-local ``correlation_id`` —
    so the test asserts the trace/subject distinction explicitly. The
    transport-failed / protocol-violation rows follow the same
    contract (they share the helper that threads
    ``chain_correlation_id``); their own pins live in the
    :mod:`tests.unit.security.test_quarantined_extractor` module's
    failure-path tests once those tests adopt the same trace-key
    assertion.
    """
    dlp = _redacting_dlp()
    register_extract_dlp_subscriber(
        registry=fresh_registry_allow_system,
        outbound_dlp=dlp,
    )
    transport = _canary_transport()
    extractor = QuarantinedExtractor(
        transport=transport,
        audit_writer=fake_audit_writer,
        outbound_dlp=dlp,
    )

    with pytest.raises(HookRefusal):
        await extractor.extract(_make_handle(), _Schema)

    extract_rows = [
        call for call in fake_audit_writer.calls if call["event"] == "quarantine.extract"
    ]
    assert len(extract_rows) == 1
    row = extract_rows[0]

    # The chain-shared trace key — a 32-char hex (uuid4().hex shape).
    trace_id = row["trace_id"]
    assert isinstance(trace_id, str)
    assert len(trace_id) == 32, (
        f"Expected uuid4().hex (32 chars) for chain_correlation_id-backed "
        f"trace_id; got {trace_id!r}"
    )

    # The body-local per-invocation correlation id — a UUID string
    # (str(uuid.uuid4()), 36 chars including hyphens). DISTINCT from
    # ``trace_id`` because the two are minted by separate uuid.uuid4()
    # calls — sharing would collapse two deliberately-distinct concepts.
    subject = row["subject"]
    body_correlation_id = subject["correlation_id"]
    assert isinstance(body_correlation_id, str)
    assert len(body_correlation_id) == 36, (
        f"Expected str(uuid4()) (36 chars) for body-local correlation_id; "
        f"got {body_correlation_id!r}"
    )

    # The deliberate split: trace_id is the chain id; subject.correlation_id
    # is the body id; sharing the same UUID value across both would
    # conflate the chain-wide trace key with the body-local correlation
    # token.
    assert trace_id != body_correlation_id, (
        "trace_id and subject.correlation_id MUST be distinct values — "
        "trace_id is the chain id (shared with the pre/post/error "
        "hook-dispatch rows), subject.correlation_id is the body-local "
        "per-invocation id (CR-158 round 4 trace-key model)."
    )


# ---------------------------------------------------------------------------
# Scenario 3: pre-stage refusal propagates and dispatches error chain.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_extract_propagates_pre_stage_refusal_and_runs_error_chain(
    fresh_registry_allow_system: HookRegistry,
    fake_audit_writer: MagicMock,
) -> None:
    """A system-tier ``pre`` subscriber that refuses MUST propagate as
    :class:`HookRefusal` out of :meth:`extract`, and the error chain
    MUST dispatch so subscribers can observe the failure.

    Pins the pre-stage exception → error-chain dispatch branch in
    :meth:`QuarantinedExtractor.extract` (and the
    :meth:`_dispatch_error_chain` BaseException arm — the error chain
    re-raises the original :class:`HookRefusal` because no error
    subscriber suppressed; we observe the dispatcher walked the
    chain by counting subscriber invocations).
    """
    from alfred.hooks import HookContext

    pre_calls: list[str] = []
    error_calls: list[str] = []

    async def _refusing_pre(_ctx: HookContext[Any]) -> HookContext[Any]:
        pre_calls.append("ran")
        # Pin the pre-carrier T3-absence invariant (NIT #12 — CR-158):
        # the pre stage MUST carry closed-vocabulary attribution only
        # (``schema_name`` + opaque ``handle_id``). NO ``data`` /
        # ``payload`` / ``model_dump`` / ``handle.content`` keys —
        # those would surface T3-derived content on a pre subscriber's
        # audit attribution. A refactor that widened the pre carrier
        # would trip this assertion.
        assert set(_ctx.input.keys()) == {"schema_name", "handle_id"}, (
            f"Pre-stage carrier MUST only carry schema_name + handle_id "
            f"(closed-vocab attribution); got {set(_ctx.input.keys())!r}"
        )
        raise HookRefusal(
            hook_id="test.pre.refuser",
            action_id="security.quarantined.extract",
            reason="test_refusal",
            correlation_id=_ctx.correlation_id,
        )

    async def _observing_error(_ctx: HookContext[Any]) -> None:
        error_calls.append("ran")
        return  # no suppression — original exc re-raises

    fresh_registry_allow_system.register(
        hook_fn=_refusing_pre,
        hookpoint="security.quarantined.extract",
        kind="pre",
        tier="system",
    )
    fresh_registry_allow_system.register(
        hook_fn=_observing_error,
        hookpoint="security.quarantined.extract",
        kind="error",
        tier="system",
    )

    dlp = _identity_dlp()
    transport = _clean_transport()
    extractor = QuarantinedExtractor(
        transport=transport,
        audit_writer=fake_audit_writer,
        outbound_dlp=dlp,
    )

    with pytest.raises(HookRefusal):
        await extractor.extract(_make_handle(), _Schema)

    # Pre subscriber ran and refused; error subscriber observed.
    assert pre_calls == ["ran"]
    assert error_calls == ["ran"]
    # The body never ran (no transport dispatch, no DLP scan).
    transport.dispatch.assert_not_called()
    dlp.scan.assert_not_called()


# ---------------------------------------------------------------------------
# Scenario 5: error chain runs when body raises (transport failure).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_extract_body_exception_dispatches_error_chain(
    fresh_registry_allow_system: HookRegistry,
    fake_audit_writer: MagicMock,
) -> None:
    """A transport-layer crash inside the extract body propagates AND
    the error chain dispatches before the propagation surfaces.

    Pins the body-exception → error-chain dispatch branch. The error
    chain runs the registered error subscriber; no subscriber
    suppresses; the original transport exception re-raises with
    identity preserved.
    """
    from alfred.hooks import HookContext

    error_calls: list[BaseException] = []

    from alfred.hooks.invoke import ERROR_EXC_METADATA_KEY

    async def _observing_error(ctx: HookContext[Any]) -> None:
        # The dispatcher stashes the original exc on ctx.metadata
        # under :data:`ERROR_EXC_METADATA_KEY` — surface it to assert
        # identity preservation. Importing the constant rather than
        # spelling the literal pins the assertion against the
        # canonical key — a drift in :func:`alfred.hooks.invoke.invoke`
        # would break THIS import, not silently land the wrong value.
        exc_obj = ctx.metadata.get(ERROR_EXC_METADATA_KEY)
        if isinstance(exc_obj, BaseException):
            error_calls.append(exc_obj)
        return

    fresh_registry_allow_system.register(
        hook_fn=_observing_error,
        hookpoint="security.quarantined.extract",
        kind="error",
        tier="system",
    )

    dlp = _identity_dlp()
    transport = MagicMock()
    transport.dispatch = AsyncMock(side_effect=RuntimeError("transport pipe broken"))
    extractor = QuarantinedExtractor(
        transport=transport,
        audit_writer=fake_audit_writer,
        outbound_dlp=dlp,
    )

    with pytest.raises(RuntimeError, match="transport pipe broken"):
        await extractor.extract(_make_handle(), _Schema)

    # Error subscriber ran AND saw the original exception.
    assert len(error_calls) == 1
    assert isinstance(error_calls[0], RuntimeError)
    assert "transport pipe broken" in str(error_calls[0])
    # The transport_failed audit row still landed (existing audit
    # family is additive to the hookpoint chain).
    events = [call["event"] for call in fake_audit_writer.calls]
    assert "quarantine.transport_failed" in events


# ---------------------------------------------------------------------------
# Scenario 6: error-chain subscriber crash does not displace original exc.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_error_chain_subscriber_crash_does_not_displace_original_exc(
    fresh_registry_allow_system: HookRegistry,
    fake_audit_writer: MagicMock,
) -> None:
    """An error-stage subscriber that crashes MUST NOT displace the
    upstream exception on the caller's traceback.

    Pins the :meth:`_dispatch_error_chain` HookError arm: when an
    error subscriber raises, the dispatcher emits HOOKS_SUBSCRIBER_ERROR
    and (with fail_closed=False) wraps in HookSubscriberError; the
    helper swallows that wrap so the ORIGINAL exception is what
    propagates from :meth:`extract`.

    The error chain is invoked with ``fail_closed=False`` (this
    slice's policy) so a subscriber crash is logged via the audit
    sink but does not raise to the caller. The caller's
    ``raise`` outside the helper is what surfaces.
    """
    from alfred.hooks import HookContext

    # Observer that records execution of the crashing error
    # subscriber. Without this we cannot distinguish "the
    # error-chain swallow branch ran and re-raised the original
    # body exception" from "the error chain was never dispatched
    # at all and the body exception just bubbled up unhandled" —
    # both produce an identical RuntimeError("body crash") at the
    # caller. The assertion below pins that ``_dispatch_error_chain``
    # really executes the crashing subscriber, exercising the
    # ``HookError`` swallow arm.
    error_calls: list[str] = []

    async def _crashing_error(_ctx: HookContext[Any]) -> None:
        error_calls.append("ran")
        raise RuntimeError("error subscriber blew up")

    fresh_registry_allow_system.register(
        hook_fn=_crashing_error,
        hookpoint="security.quarantined.extract",
        kind="error",
        tier="system",
    )

    dlp = _identity_dlp()
    transport = MagicMock()
    transport.dispatch = AsyncMock(side_effect=RuntimeError("body crash"))
    extractor = QuarantinedExtractor(
        transport=transport,
        audit_writer=fake_audit_writer,
        outbound_dlp=dlp,
    )

    # Body exception ("body crash"), NOT the subscriber's exception
    # ("error subscriber blew up"), is what reaches the caller.
    with pytest.raises(RuntimeError, match="body crash"):
        await extractor.extract(_make_handle(), _Schema)

    # The error-chain dispatch ACTUALLY ran. If the dispatcher
    # were short-circuited the test would still pass on the
    # ``raises`` clause above, masking a real regression in the
    # error-chain wiring.
    assert error_calls == ["ran"]


# ---------------------------------------------------------------------------
# Scenario 7: error-chain narrow catch (HIGH #3 — CR-158).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_error_chain_propagates_cancelled_error_from_subscriber(
    fresh_registry_allow_system: HookRegistry,
    fake_audit_writer: MagicMock,
) -> None:
    """Pin HIGH #3 (CR-158): a :class:`asyncio.CancelledError` raised
    inside an error-stage subscriber MUST propagate — it is a
    :class:`BaseException`, NOT an :class:`Exception`, and the
    narrowed catch in :meth:`_dispatch_error_chain` MUST honour it.

    Pre-fix the helper caught ``BaseException`` which silently
    swallowed cooperative cancellation. That regression would let a
    cancelled task in the error stage outlive its caller and leak a
    never-completing coroutine. CLAUDE.md hard rule #7 — no silent
    failures in security paths; cancellation propagation IS a
    security guarantee.
    """
    import asyncio

    from alfred.hooks import HookContext

    async def _cancelling_error(_ctx: HookContext[Any]) -> None:
        raise asyncio.CancelledError()

    fresh_registry_allow_system.register(
        hook_fn=_cancelling_error,
        hookpoint="security.quarantined.extract",
        kind="error",
        tier="system",
    )

    dlp = _identity_dlp()
    transport = MagicMock()
    transport.dispatch = AsyncMock(side_effect=RuntimeError("body crash"))
    extractor = QuarantinedExtractor(
        transport=transport,
        audit_writer=fake_audit_writer,
        outbound_dlp=dlp,
    )

    # CancelledError MUST propagate (it's a BaseException, NOT an
    # Exception; the narrowed except-Exception arm intentionally lets
    # it through).
    with pytest.raises(asyncio.CancelledError):
        await extractor.extract(_make_handle(), _Schema)


# ---------------------------------------------------------------------------
# Scenario 9: post-stage HookRefusal dispatches the error chain (HIGH #5).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dlp_post_refusal_runs_error_chain(
    fresh_registry_allow_system: HookRegistry,
    fake_audit_writer: MagicMock,
) -> None:
    """Pin HIGH #5 (CR-158): a post-stage :class:`HookRefusal` (the
    DLP subscriber tripping on a canary) MUST invoke the error chain
    so error-stage subscribers can observe the refusal.

    Before this test the post-stage exception → error-chain dispatch
    branch was un-pinned; a refactor that broke the ``except`` arm
    in :meth:`extract` would silently disarm every error-stage
    subscriber on a DLP refusal — a regression hard to spot without
    a dedicated assertion.

    The error subscriber observes the refusal via
    ``ctx.metadata[ERROR_EXC_METADATA_KEY]`` — the constant import
    is the structural pin against a string-literal drift in
    :func:`alfred.hooks.invoke` (NIT #12 alignment).
    """
    from alfred.hooks import HookContext
    from alfred.hooks.invoke import ERROR_EXC_METADATA_KEY

    error_observed: list[BaseException] = []

    async def _observing_error(ctx: HookContext[Any]) -> None:
        exc_obj = ctx.metadata.get(ERROR_EXC_METADATA_KEY)
        if isinstance(exc_obj, BaseException):
            error_observed.append(exc_obj)
        return

    dlp = _redacting_dlp()
    # Register BOTH the DLP subscriber AND the error-stage observer.
    # The DLP subscriber raises HookRefusal on the canary; the post
    # chain's catch arm in :meth:`extract` dispatches the error chain;
    # the observer reads ERROR_EXC_METADATA_KEY off ctx.metadata.
    register_extract_dlp_subscriber(
        registry=fresh_registry_allow_system,
        outbound_dlp=dlp,
    )
    fresh_registry_allow_system.register(
        hook_fn=_observing_error,
        hookpoint="security.quarantined.extract",
        kind="error",
        tier="system",
    )

    transport = _canary_transport()
    extractor = QuarantinedExtractor(
        transport=transport,
        audit_writer=fake_audit_writer,
        outbound_dlp=dlp,
    )

    with pytest.raises(HookRefusal):
        await extractor.extract(_make_handle(), _Schema)

    # The error subscriber ran AND observed the DLP refusal —
    # confirming the post-stage exception branch in :meth:`extract`
    # invokes the error chain before re-raising.
    assert len(error_observed) == 1
    assert isinstance(error_observed[0], HookRefusal)
    assert error_observed[0].hook_id == "security.quarantined.extract.post.dlp"


@pytest.mark.asyncio
async def test_error_chain_does_not_displace_body_exc_when_invoke_reraises(
    fresh_registry_allow_system: HookRegistry,
    fake_audit_writer: MagicMock,
) -> None:
    """Pin HIGH #3 (CR-158) "identity match" arm: when
    :func:`alfred.hooks.invoke.invoke` re-raises the original ``exc``
    via the no-suppression-completed path, the helper MUST swallow
    via identity (``raised is exc``) so the caller's outer ``raise``
    is the visible propagation site.

    The test registers a non-suppressing error subscriber and a
    body crash; ``invoke`` runs the subscriber, gets no suppression,
    then re-raises the body's :class:`RuntimeError` (same identity
    as ``exc``). The helper's identity check swallows the
    re-raise; :meth:`extract`'s outer ``raise`` is what surfaces.

    The exception that propagates MUST be the BODY's exception
    (identity preserved), NOT any new exception the subscriber or
    dispatcher synthesised.
    """
    from alfred.hooks import HookContext

    async def _observing_error(_ctx: HookContext[Any]) -> None:
        # No suppression, no raise — let invoke walk to the
        # re-raise-exc arm.
        return None

    fresh_registry_allow_system.register(
        hook_fn=_observing_error,
        hookpoint="security.quarantined.extract",
        kind="error",
        tier="system",
    )

    body_exc = RuntimeError("body identity-preserved")
    dlp = _identity_dlp()
    transport = MagicMock()
    transport.dispatch = AsyncMock(side_effect=body_exc)
    extractor = QuarantinedExtractor(
        transport=transport,
        audit_writer=fake_audit_writer,
        outbound_dlp=dlp,
    )

    with pytest.raises(RuntimeError) as excinfo:
        await extractor.extract(_make_handle(), _Schema)
    # Identity preserved — NOT a new RuntimeError synthesised by
    # the dispatcher or the helper.
    assert excinfo.value is body_exc


# ---------------------------------------------------------------------------
# Scenario 7b: post-stage non-refusal crash dispatches error chain + re-raises.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_stage_subscriber_crash_dispatches_error_chain_and_reraises(
    fresh_registry_allow_system: HookRegistry,
    fake_audit_writer: MagicMock,
) -> None:
    """A post-stage subscriber that raises a non-:class:`HookRefusal`
    exception MUST dispatch the error chain AND propagate the failure.

    Pins the ``except Exception as post_exc`` arm in :meth:`extract`
    (BLOCKER #2 sibling path): when ``fail_closed=True`` (the
    hookpoint's policy) and a post-stage subscriber crashes,
    :func:`invoke` wraps the crash as a :class:`HookSubscriberError`.
    The post-chain ``except`` arm dispatches the error chain so
    error-stage subscribers can observe the failure, then re-raises
    so the caller sees the loud failure.

    The :data:`quarantine.extract` audit row is intentionally NOT
    emitted on this arm — the upstream
    :data:`HOOKS_SUBSCRIBER_ERROR` row :func:`invoke` already emitted
    is the forensic anchor; a second ``quarantine.extract`` row
    would imply the extract completed cleanly, which it didn't.
    """
    from alfred.hooks import HookContext

    async def _crashing_post(_ctx: HookContext[Any]) -> HookContext[Any]:
        raise RuntimeError("post-stage subscriber blew up")

    # Register a crashing post subscriber — system-tier so it
    # qualifies for the SYSTEM_OPERATOR_TIERS subscribable allow-list.
    fresh_registry_allow_system.register(
        hook_fn=_crashing_post,
        hookpoint="security.quarantined.extract",
        kind="post",
        tier="system",
    )

    dlp = _identity_dlp()
    transport = _clean_transport()
    extractor = QuarantinedExtractor(
        transport=transport,
        audit_writer=fake_audit_writer,
        outbound_dlp=dlp,
    )

    # invoke() with fail_closed=True wraps the non-HookError crash as
    # a HookSubscriberError (which is a HookError → AlfredError).
    # The exception type is the WRAP, not the raw RuntimeError; we
    # assert the wrap propagates.
    from alfred.hooks import HookError as _HookError

    with pytest.raises(_HookError):
        await extractor.extract(_make_handle(), _Schema)

    # No quarantine.extract row landed — the post-chain crash
    # short-circuited the success-arm emission AND did NOT trigger
    # the post_stage_refused arm (which is only for HookRefusal).
    extract_rows = [
        call for call in fake_audit_writer.calls if call["event"] == "quarantine.extract"
    ]
    assert extract_rows == [], (
        f"No quarantine.extract row should land on a post-stage subscriber "
        f"crash; got {extract_rows!r}"
    )


# ---------------------------------------------------------------------------
# Scenario 7c: error-chain re-raises NEW exception → helper propagates it.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_error_chain_propagates_new_exceptions_distinct_from_upstream_exc(
    fresh_registry_allow_system: HookRegistry,
    fake_audit_writer: MagicMock,
) -> None:
    """Pin HIGH #3 (CR-158) "new exception" arm: when the error-stage
    dispatch raises a :class:`Exception` whose IDENTITY differs from
    the upstream ``exc``, the helper MUST re-raise it (not swallow).

    The shape exercises the ``raised is not exc`` branch in
    :meth:`_dispatch_error_chain`. ``invoke``'s standard error-stage
    paths don't synthesise a non-identity, non-HookError exception
    (a subscriber crash with ``fail_closed=True`` wraps as
    :class:`HookSubscriberError` which IS a :class:`HookError`; the
    no-suppression-completed path re-raises ``exc`` with identity
    preserved). The defensive ``raise`` exists for the hypothetical
    case where a future invoke refactor surfaces a distinct
    exception — we exercise it by monkey-patching ``invoke`` to
    raise a synthesised :class:`RuntimeError` whose identity differs
    from the body's exception.

    Without this pin the defensive ``raise`` would silently rot — a
    future regression that turned it into ``pass`` would not be
    caught by any test.
    """
    from unittest.mock import patch

    from alfred.hooks import HookContext

    body_exc = RuntimeError("body crash")
    sentinel_exc = RuntimeError("error-chain synthetic crash")

    async def _real_invoke_replacement(*args: Any, **kwargs: Any) -> HookContext[Any]:
        # Only the error-stage invoke call inside _dispatch_error_chain
        # should fire this — the pre/post invokes happen BEFORE the
        # body raises. The error chain runs once, after the body
        # exception, so this synthesises the "invoke raises a new
        # exception" shape the defensive line guards against.
        if kwargs.get("kind") == "error":
            raise sentinel_exc
        # Pre/post stages — call through to the real invoke.
        from alfred.hooks import invoke as _real_invoke

        return await _real_invoke(*args, **kwargs)

    dlp = _identity_dlp()
    transport = MagicMock()
    transport.dispatch = AsyncMock(side_effect=body_exc)
    extractor = QuarantinedExtractor(
        transport=transport,
        audit_writer=fake_audit_writer,
        outbound_dlp=dlp,
    )

    # CR-156 round-7 / CR-158 T5: patch the symbol where it is
    # BOUND (used) — :mod:`alfred.security.quarantine` does
    # ``from alfred.hooks import (..., invoke)``, which binds the
    # name into the quarantine module's namespace at import time.
    # Patching ``alfred.hooks.invoke`` would only replace the
    # upstream module attribute; the quarantine-side bound symbol
    # would still call the real :func:`invoke`. Patching
    # ``alfred.security.quarantine.invoke`` swaps the actually-used
    # reference and the defensive ``if raised is not exc: raise``
    # branch in :meth:`_dispatch_error_chain` actually executes.
    with (
        patch("alfred.security.quarantine.invoke", _real_invoke_replacement),
        pytest.raises(RuntimeError) as excinfo,
    ):
        await extractor.extract(_make_handle(), _Schema)

    # The propagating exception is the SYNTHESISED one (identity
    # differs from ``exc``), NOT the body crash. The helper's
    # defensive ``raise`` is what surfaces it; without that
    # ``raise``, the synthetic exception would be silently swallowed
    # and the caller's outer ``raise exc`` would surface the body
    # exception — a silent failure CLAUDE.md hard rule #7 forbids.
    assert excinfo.value is sentinel_exc


# ---------------------------------------------------------------------------
# Scenario 8: constructor wires the injected DLP into the post chain.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_constructor_wires_injected_dlp_into_post_chain(
    fresh_registry_allow_system: HookRegistry,
    fake_audit_writer: MagicMock,
) -> None:
    """Post-CR-156 round 7 / CR-158 T1, :class:`QuarantinedExtractor`'s
    constructor auto-registers the injected DLP via
    :func:`register_extract_dlp_subscriber` — there is no "no
    subscriber" path from inside :meth:`extract`. This test pins
    that contract: the DLP we hand the constructor is the one the
    post-chain dispatches, evidenced by the scanner being called
    against the validated payload exactly once.

    Earlier this test asserted "extract still succeeds without a
    DLP subscriber registered" — a premise that became false when
    the constructor switched to fail-loud auto-registration. CR-158
    round-2 (#168) flagged the gap: the empty-bucket scenario is
    no longer reachable through the public API, so the contract
    worth pinning is the inverse — *the injected DLP IS what the
    post chain runs.*
    """
    # NOTE: no register_extract_dlp_subscriber call here — the
    # constructor below makes that call internally.
    dlp = _identity_dlp()
    transport = _clean_transport()
    extractor = QuarantinedExtractor(
        transport=transport,
        audit_writer=fake_audit_writer,
        outbound_dlp=dlp,
    )

    result = await extractor.extract(_make_handle(), _Schema)

    assert isinstance(result, Extracted)
    assert dict(result.data) == {"summary": "all clear"}
    # The DLP the constructor wired IS the one the post chain
    # invoked. One call per extract — the validated payload's
    # ``model_dump()``.
    assert dlp.scan.call_count == 1
    # Existing audit emit-path still ran.
    events = [call["event"] for call in fake_audit_writer.calls]
    assert "quarantine.extract" in events


# ---------------------------------------------------------------------------
# Scenario 9: future-proofing — a NON-DLP post-stage subscriber refusal
# surfaces ITS hook_id on ``refusing_hook_id``, not the DLP _SCAN_ID.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_dlp_post_subscriber_refusal_records_post_stage_refused_and_refusing_hook_id(
    fresh_registry_allow_system: HookRegistry,
    fake_audit_writer: MagicMock,
) -> None:
    """A NON-DLP post-stage subscriber that refuses MUST land a
    ``post_stage_refused`` row whose ``refusing_hook_id`` carries
    the alternate subscriber's identity — NOT the DLP ``_SCAN_ID``.

    This is the load-bearing future-proofing pin: the
    ``post_stage_refused`` token is generic by design. Any future
    post-stage subscriber that refuses will attribute through the
    same row family without DLP-specific code paths. The forensic
    surface for "which subscriber refused?" is the row's
    ``refusing_hook_id`` field — the only such surface because
    ``alfred.hooks.invoke._run_post`` does NOT emit ``HOOKS_REFUSAL``
    for post-stage refusals (§6.5 is pre-only).

    The DLP subscriber is registered (the constructor auto-registers
    it) AND a second, alternate post-stage subscriber is registered
    that refuses BEFORE the DLP one runs (it sits earlier in the
    bucket because it registers first — the bucket is sorted by
    (tier-rank, registration-seq)). The alternate's ``hook_id``
    surfaces on the audit row.
    """
    from alfred.hooks import HookContext

    alternate_hook_id = "test.alternate_post_subscriber"

    async def _alternate_post_refuser(_ctx: HookContext[Any]) -> HookContext[Any]:
        # HookRefusal constructor shape matches production sites — the
        # four kwargs are keyword-only (see HookRefusal.__init__).
        raise HookRefusal(
            hook_id=alternate_hook_id,
            action_id="security.quarantined.extract",
            reason="test_refusal",
            correlation_id=_ctx.correlation_id,
        )

    # Register the alternate subscriber FIRST so it sits earlier in
    # the bucket and runs before the constructor-auto-registered DLP
    # subscriber. Both are system-tier and pass the
    # SYSTEM_OPERATOR_TIERS subscribable allow-list.
    fresh_registry_allow_system.register(
        hook_fn=_alternate_post_refuser,
        hookpoint="security.quarantined.extract",
        kind="post",
        tier="system",
    )

    # Clean DLP — when the post chain runs, the alternate refuses
    # FIRST so the DLP scan never executes. (If the DLP somehow ran
    # later it would be a no-op anyway; we use a clean transport to
    # avoid any canary trip altogether.)
    dlp = _identity_dlp()
    transport = _clean_transport()
    extractor = QuarantinedExtractor(
        transport=transport,
        audit_writer=fake_audit_writer,
        outbound_dlp=dlp,
    )

    with pytest.raises(HookRefusal) as excinfo:
        await extractor.extract(_make_handle(), _Schema)

    # The propagating refusal is the alternate's — NOT the DLP's.
    assert excinfo.value.hook_id == alternate_hook_id

    extract_rows = [
        call for call in fake_audit_writer.calls if call["event"] == "quarantine.extract"
    ]
    assert len(extract_rows) == 1, (
        f"Expected exactly one quarantine.extract row; got "
        f"{[c['event'] for c in fake_audit_writer.calls]!r}"
    )
    row = extract_rows[0]
    subject = row["subject"]

    # Generic closed-vocab token — same as the DLP arm; the
    # attribution is on ``refusing_hook_id``.
    assert row["result"] == "post_stage_refused"
    assert subject["result"] == "post_stage_refused"
    assert subject["extraction_mode"] == "refused"

    # THE LOAD-BEARING ASSERTION: the alternate's hook_id surfaces,
    # NOT the DLP _SCAN_ID. A regression that hard-codes the DLP id
    # on this path will fail here.
    assert subject["refusing_hook_id"] == alternate_hook_id

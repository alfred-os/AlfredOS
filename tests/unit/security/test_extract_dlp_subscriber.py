"""Unit tests for :class:`OutboundDlpExtractSubscriber` (issue #158).

The subscriber sits on the post-stage of the
``security.quarantined.extract`` hookpoint chain (spec §6.5 line 476).
It receives a :class:`alfred.hooks.HookContext` whose ``input`` is the
:meth:`pydantic.BaseModel.model_dump` of the validated
:class:`alfred.security.quarantine.ExtractionResult` and runs
:meth:`alfred.security.dlp.OutboundDlp.scan` on the serialised JSON of
that dump. Any redaction (broker / API-key regex / canary) means a
DLP trigger fired and the subscriber raises :class:`HookRefusal` so
the dispatch chain aborts and the validated payload never reaches the
privileged orchestrator.

Four cases pin the contract:

* Clean payload — the scan output equals the input; the subscriber
  returns the carrier unchanged. The dispatch chain proceeds.
* Canary in the top-level summary field — the scan redacts; the
  subscriber raises :class:`HookRefusal`. This is the spec's primary
  exfil channel (a free-text str field in the schema).
* Canary in a nested-dict field — :meth:`model_dump` produces nested
  dicts; the JSON serialisation still surfaces the canary string and
  the scan trips. Defence against an attacker hiding the payload one
  level deeper in the schema.
* :class:`alfred.security.dlp.OutboundDlp` outage — a crash inside the
  scan propagates loud. The hookpoint's ``fail_closed=True`` policy
  treats the propagation as a refusal at the chain level. We assert
  the subscriber does NOT swallow.

The tests use :class:`unittest.mock.MagicMock` for the
:class:`OutboundDlp` seam so the subscriber's contract is exercised
without spinning up the real DLP pipeline (broker + secret store +
audit sink). The :class:`HookContext` is constructed verbatim — the
subscriber is a pure async callable; no dispatcher needed for the unit
test.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import pytest

from alfred.hooks import HookContext, HookError, HookRefusal
from alfred.hooks.audit_sink import HOOKS_DLP_SUBSCRIBER_NOT_REGISTERED
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.security._extract_dlp_subscriber import (
    OutboundDlpExtractSubscriber,
    RegistrationOutcome,
    register_extract_dlp_subscriber,
)
from tests.helpers.gates import (
    make_deny_all_gate,
    make_quarantined_extract_chain_gate,
)


@dataclass(frozen=True, slots=True)
class _SpyAuditSink:
    """Capturing :class:`AuditSink` that records every emit.

    Local copy of ``tests/unit/hooks/conftest.py::SpyAuditSink`` —
    conftest is dir-scoped; the hooks-tree fixture is invisible here.
    Frozen + slots so the spy honours the same hot-path discipline as
    the real :class:`StructlogAuditSink`.
    """

    calls: list[dict[str, object]] = field(default_factory=list)

    async def emit(
        self,
        *,
        event: str,
        correlation_id: str,
        fields: Mapping[str, object],
    ) -> None:
        self.calls.append(
            {
                "event": event,
                "correlation_id": correlation_id,
                "fields": dict(fields),
            }
        )


# ---------------------------------------------------------------------------
# Local fixtures.
#
# A copy of ``fresh_registry_allow_system`` from
# ``tests/unit/hooks/conftest.py`` — pytest conftests are dir-scoped, so
# the hooks-tree fixture is invisible here. Keeping a local copy is
# cheaper than promoting the fixture to a shared root conftest, and the
# fixture body is the canonical "swap registry, restore on teardown"
# pattern (spec §0 + alfred-core-engineer-1 hardening).
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_registry_allow_system() -> Iterator[HookRegistry]:
    """Install a brand-new :class:`HookRegistry` scoped to the
    ``security.quarantined.extract`` chain as the module singleton.

    Captures the pre-test registry and restores it on teardown —
    cross-test contamination via the module-level singleton is
    impossible. ``strict_declarations=False`` matches the canonical
    ``tests/unit/hooks/conftest.py::fresh_registry_allow_system``
    fixture so test bodies can register against ad-hoc hookpoint
    names; the production posture (strict=True) is exercised by
    the canonical hookpoint registration tests in Task 1.

    CR-156 round-7 / CR-158 T4 (CLAUDE.md hard rule #2): the gate
    is a scoped :class:`RealGate` (via
    :func:`make_quarantined_extract_chain_gate`) — NOT
    :func:`make_permissive_fixture_gate(allow_system=True)`. The
    permissive shim ignores ``plugin_id`` / ``hookpoint`` so a
    regression in the registry's grant-policy check would be
    invisible at test time. The scoped gate seeds exactly the
    grants the chain needs: system-tier for the DLP subscriber's
    plugin_id + operator-tier for the sibling-observer test. Any
    request outside this scope denies fail-closed.
    """
    prior = get_registry()
    # The sibling-observer test registers an operator-tier subscriber
    # whose ``__module__`` resolves to THIS test module. The scoped
    # gate seeds an operator grant against that plugin_id so the
    # sibling registration lands cleanly without the fixture leaning
    # on a permissive shim.
    registry = HookRegistry(
        gate=make_quarantined_extract_chain_gate(
            allow_sibling_operator=True,
            sibling_operator_plugin_id=__name__,
        ),
        strict_declarations=False,
    )
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)


def _build_ctx(payload: dict[str, Any]) -> HookContext[dict[str, Any]]:
    """Build a minimal :class:`HookContext` carrying ``payload`` as
    :attr:`HookContext.input`.

    Mirrors the shape :class:`alfred.hooks.invoke.Flow.post` would hand
    a subscriber at dispatch time: the carrier is freshly-minted with
    a placeholder ``correlation_id`` so a test can assert it surfaces
    on the refusal exception (CLAUDE.md hard rule #7 — refusal audit
    rows MUST carry the correlation id).
    """
    return HookContext(
        action_id="security.quarantined.extract",
        hookpoint="security.quarantined.extract",
        input=payload,
        correlation_id="test-correlation-id",
        kind="post",
    )


# ---------------------------------------------------------------------------
# Subscriber contract.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_clean_payload_returns_ctx_unchanged() -> None:
    """A scan that returns its input unchanged means no DLP trigger
    fired; the subscriber returns the carrier verbatim so the chain
    continues with the validated payload.
    """
    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda x: x)  # identity — no redaction
    sub = OutboundDlpExtractSubscriber(outbound_dlp=dlp)
    ctx = _build_ctx({"summary": "all clear", "score": 42})

    result = await sub(ctx)

    assert result is ctx
    dlp.scan.assert_called_once()


@pytest.mark.asyncio
async def test_canary_in_summary_field_raises_refusal() -> None:
    """A canary token in a top-level str field MUST trip DLP and the
    subscriber MUST raise :class:`HookRefusal`.

    The canary is the spec's primary exfil-channel pin (free-text str
    field in the schema). The mock DLP redacts the canary so the scan
    output differs from the input; the subscriber detects the delta
    and refuses.
    """
    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda x: x.replace("CANARY-XYZ", "[REDACTED]"))
    sub = OutboundDlpExtractSubscriber(outbound_dlp=dlp)
    ctx = _build_ctx({"summary": "embedded CANARY-XYZ in text"})

    with pytest.raises(HookRefusal) as excinfo:
        await sub(ctx)

    # The refusal's attribution fields are part of the structural
    # contract — the post-stage audit row (downstream) reads them.
    assert excinfo.value.hook_id == "security.quarantined.extract.post.dlp"
    assert excinfo.value.action_id == "security.quarantined.extract"
    assert excinfo.value.correlation_id == "test-correlation-id"
    # CR-156 round-7 / CR-158 T3: ``reason`` is the closed-vocabulary
    # tag the audit-row consumer branches on. Pin it next to the
    # other attribution fields so a drift in the subscriber's raise
    # site (e.g. someone renaming the constant) trips this test
    # alongside the adversarial corpus pin in
    # tests/adversarial/prompt_injection/test_pi_direct_injection_into_extracted_data.py.
    assert excinfo.value.reason == "canary_or_secret_in_extracted_payload"


@pytest.mark.asyncio
async def test_canary_in_nested_dict_field_raises_refusal() -> None:
    """A canary buried inside a nested dict still surfaces in the
    :func:`json.dumps` serialisation and trips the scan.

    ``model_dump()`` produces nested dicts whenever a schema has a
    sub-model field; the JSON serialisation flattens the structure
    into a single string the regex can match against. Defence against
    an attacker hiding the canary one level deeper.
    """
    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda x: x.replace("CANARY-XYZ", "[REDACTED]"))
    sub = OutboundDlpExtractSubscriber(outbound_dlp=dlp)
    ctx = _build_ctx({"meta": {"reason": "saw CANARY-XYZ in body"}})

    with pytest.raises(HookRefusal):
        await sub(ctx)


@pytest.mark.asyncio
async def test_dlp_outage_propagates_loud() -> None:
    """:meth:`OutboundDlp.scan` raising MUST propagate — the subscriber
    does NOT swallow.

    The hookpoint's ``fail_closed=True`` policy turns a propagating
    exception into a chain-level :class:`alfred.hooks.HookError` at
    the dispatcher (Task 10's subscriber-error arm). Swallowing here
    would silently disarm DLP — the very failure CLAUDE.md hard rule
    #7 forbids.
    """
    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=RuntimeError("DLP broker outage"))
    sub = OutboundDlpExtractSubscriber(outbound_dlp=dlp)
    ctx = _build_ctx({"summary": "clean"})

    with pytest.raises(RuntimeError, match="DLP broker outage"):
        await sub(ctx)


@pytest.mark.asyncio
async def test_subscriber_serialises_dict_with_default_str_for_non_json_types() -> None:
    """The serialisation MUST tolerate :meth:`model_dump` outputs that
    contain non-JSON-native types (e.g. :class:`datetime.datetime`,
    :class:`uuid.UUID`).

    A schema with a datetime field — common for forensic
    extraction — would otherwise raise :class:`TypeError` on
    :func:`json.dumps`. The :func:`json.dumps` ``default=str`` arm
    coerces unknown types to their ``str()`` form so the scan still
    runs.
    """
    import uuid as _uuid
    from datetime import UTC, datetime

    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda x: x)  # identity
    sub = OutboundDlpExtractSubscriber(outbound_dlp=dlp)
    ctx = _build_ctx(
        {
            "summary": "clean",
            "extracted_at": datetime.now(UTC),
            "request_id": _uuid.uuid4(),
        }
    )

    result = await sub(ctx)
    assert result is ctx


# ---------------------------------------------------------------------------
# Registration helper — idempotency + tier pin.
# ---------------------------------------------------------------------------


def test_register_extract_dlp_subscriber_idempotent(
    fresh_registry_allow_system: Any,
) -> None:
    """Calling :func:`register_extract_dlp_subscriber` twice with the
    same :class:`OutboundDlp` MUST result in ONE subscriber registered.

    The hookpoint's subscriber bucket is :class:`list`-backed
    (:meth:`HookRegistry.register` appends), so a naive
    re-registration would double-run the scan at dispatch. The helper
    short-circuits on the second call by consulting the registry for
    an existing subscriber bound to the SCAN_ID.

    Subscriber lifecycle is anchored to extractor lifecycle (the
    extractor's ``__init__`` calls this helper), and multiple
    extractor instances per process MUST NOT double-register.
    """
    # Need the hookpoint declared first — the registry is fresh and
    # strict-declarations=False per the fixture, so the publisher
    # declaration is not strictly required, but we run the canonical
    # path to mirror production.
    from alfred.security.quarantine import declare_hookpoints

    declare_hookpoints(fresh_registry_allow_system)

    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda x: x)

    first = register_extract_dlp_subscriber(registry=fresh_registry_allow_system, outbound_dlp=dlp)
    second = register_extract_dlp_subscriber(registry=fresh_registry_allow_system, outbound_dlp=dlp)

    # Pin both return values — the behavioral contract (one subscriber
    # registered) AND the idempotency-path API (second call signals
    # ALREADY_REGISTERED so callers can distinguish a no-op from a
    # successful register without re-querying the registry).
    assert first is RegistrationOutcome.REGISTERED
    assert second is RegistrationOutcome.ALREADY_REGISTERED

    subs = fresh_registry_allow_system.subscribers_for("security.quarantined.extract", "post")
    assert len(subs) == 1


def test_register_extract_dlp_subscriber_skips_past_non_dlp_subscribers(
    fresh_registry_allow_system: Any,
) -> None:
    """The idempotency check MUST skip past unrelated subscribers
    registered against the same hookpoint and still register the DLP
    scan.

    A future operator-tier subscriber (telemetry / observability)
    landing on the same post chain is legal — spec §6.5's
    :data:`SYSTEM_OPERATOR_TIERS` permits both ``system`` and
    ``operator`` registrations. The DLP helper's idempotency check
    MUST distinguish "an existing DLP subscriber is already
    registered" from "an unrelated sibling subscriber is registered";
    a naive ``existing`` truthy check would refuse the legitimate DLP
    registration when a telemetry subscriber arrived first.
    """
    from alfred.security.quarantine import declare_hookpoints

    declare_hookpoints(fresh_registry_allow_system)

    # Register a sibling operator-tier observer that is NOT a DLP
    # subscriber — mirrors a future telemetry / span-emit subscriber
    # on the same post stage.
    async def _sibling_observer(_ctx: HookContext[Any]) -> HookContext[Any]:
        return _ctx

    fresh_registry_allow_system.register(
        hook_fn=_sibling_observer,
        hookpoint="security.quarantined.extract",
        kind="post",
        tier="operator",
    )

    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda x: x)
    register_extract_dlp_subscriber(registry=fresh_registry_allow_system, outbound_dlp=dlp)

    subs = fresh_registry_allow_system.subscribers_for("security.quarantined.extract", "post")
    assert len(subs) == 2
    # The DLP subscriber MUST end up registered as ``system`` tier
    # — the sort key in :meth:`HookRegistry.register` orders system
    # before operator, so the DLP scan runs first.
    assert any(s.tier == "system" for s in subs)


def test_register_extract_dlp_subscriber_registers_as_system_tier(
    fresh_registry_allow_system: Any,
) -> None:
    """The subscriber MUST register as ``system`` tier — spec §6.5
    pins the post-stage DLP scan as a system-tier defence.

    A user-plugin or operator tier registration would be refused at
    declaration time (the hookpoint's ``subscribable_tiers`` is
    :data:`SYSTEM_OPERATOR_TIERS` — operator is allowed but
    user-plugin is not; spec mandates ``system`` for the canonical
    DLP scan). Pin the tier here so a future refactor that drifts to
    ``operator`` (a tempting "less privileged" choice) trips this
    test.
    """
    from alfred.security.quarantine import declare_hookpoints

    declare_hookpoints(fresh_registry_allow_system)

    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda x: x)

    register_extract_dlp_subscriber(registry=fresh_registry_allow_system, outbound_dlp=dlp)

    subs = fresh_registry_allow_system.subscribers_for("security.quarantined.extract", "post")
    assert len(subs) == 1
    assert subs[0].tier == "system"


# ---------------------------------------------------------------------------
# BLOCKER #1 — gate-deny path MUST emit structlog WARN + audit row.
# ---------------------------------------------------------------------------


def test_register_extract_dlp_subscriber_emits_audit_and_raises_on_gate_deny() -> None:
    """A registry whose gate denies system-tier MUST land an audit row
    AND raise :class:`HookError` — no silent skip, no fail-soft return.

    Pin the CR-156 round-7 / CR-158 T1 contract: the helper previously
    returned :data:`False` on gate-deny, leaving a half-wired
    :class:`QuarantinedExtractor` (no post-stage DLP scan) as a legal
    state. That posture is an active trust-boundary violation (PRD
    §7.1, CLAUDE.md hard rule #7). The helper now RAISES on the deny
    path so a half-wired extractor cannot construct.

    Observability is preserved BEFORE the raise — the structlog WARN
    and the audit row still emit, so an operator (or audit-log
    consumer) sees the failure even if a caller swallows the
    exception. CLAUDE.md hard rule #7 — every security-boundary
    refusal is auditable.

    Asserts:

    1. The helper raises :class:`HookError`.
    2. The post-stage subscriber bucket is empty (no registration
       landed).
    3. The audit sink received a :data:`HOOKS_DLP_SUBSCRIBER_NOT_REGISTERED`
       row carrying ``plugin_id``, ``hookpoint``, and
       ``requested_tier`` BEFORE the raise.

    The :class:`_DenyAllGate`-backed registry mirrors the bootstrap-
    incomplete posture (pre-:func:`set_registry` runtime, test
    fixtures that don't install a permissive gate) — the exact
    posture this hard-fail exists to render observable.
    """
    prior = get_registry()
    sink = _SpyAuditSink()
    registry = HookRegistry(
        gate=make_deny_all_gate(),
        sink=sink,
        strict_declarations=False,
    )
    set_registry(registry)
    try:
        # Declare the hookpoint so the helper's idempotency check sees
        # a declared post bucket. The deny-all gate refuses the
        # subscriber registration; the hookpoint declaration itself is
        # gate-agnostic.
        from alfred.security.quarantine import declare_hookpoints

        declare_hookpoints(registry)

        dlp = MagicMock()
        dlp.scan = MagicMock(side_effect=lambda x: x)

        with pytest.raises(HookError, match="DLP subscriber registration denied"):
            register_extract_dlp_subscriber(registry=registry, outbound_dlp=dlp)

        subs = registry.subscribers_for("security.quarantined.extract", "post")
        assert subs == (), (
            "No subscriber should be registered on a gate-deny — the helper "
            "short-circuits BEFORE registry.register() touches the bucket."
        )

        deny_rows = [
            call for call in sink.calls if call["event"] == HOOKS_DLP_SUBSCRIBER_NOT_REGISTERED
        ]
        assert len(deny_rows) == 1, (
            f"Expected exactly one HOOKS_DLP_SUBSCRIBER_NOT_REGISTERED row; "
            f"got {[call['event'] for call in sink.calls]!r}"
        )
        fields = deny_rows[0]["fields"]
        assert isinstance(fields, dict)
        assert fields["hookpoint"] == "security.quarantined.extract"
        assert fields["requested_tier"] == "system"
        # plugin_id matches HookRegistry.register's default attribution
        # (hook_fn.__module__) so the gate sees the same key whether
        # the helper's pre-check fires or the internal register-time
        # check does.
        assert "plugin_id" in fields
        # The closed-vocab deny reason ties the row to the specific
        # arm — operators can grep on it without re-reading the
        # message column.
        assert fields["deny_reason"] == "capability_gate_check_returned_false"
    finally:
        set_registry(prior)


def test_register_extract_dlp_subscriber_emits_structlog_warning_on_gate_deny() -> None:
    """The structlog WARN MUST land on the gate-deny path so the
    operator sees the silent-disarm risk in the live log stream.

    CLAUDE.md hard rule #7 — every security-boundary refusal is loud.
    The audit row is the durable forensic record; the structlog WARN
    is the real-time signal. Both must fire.

    Uses :func:`structlog.testing.capture_logs` rather than pytest's
    ``caplog`` fixture because structlog's default configuration in
    this project writes through its own ConsoleRenderer pipeline
    rather than through stdlib :mod:`logging` — ``caplog`` would
    therefore miss the message even though it lands on stdout. See
    ``tests/unit/memory/test_hooks_audit_sink.py`` for the precedent.
    """
    import structlog.testing

    prior = get_registry()
    registry = HookRegistry(
        gate=make_deny_all_gate(),
        strict_declarations=False,
    )
    set_registry(registry)
    try:
        from alfred.security.quarantine import declare_hookpoints

        declare_hookpoints(registry)

        dlp = MagicMock()
        dlp.scan = MagicMock(side_effect=lambda x: x)

        # Per T1: helper raises on gate-deny, but the structlog WARN
        # MUST land BEFORE the raise. ``capture_logs`` snapshots the
        # WARN even though the call propagates an exception.
        with structlog.testing.capture_logs() as captured, pytest.raises(HookError):
            register_extract_dlp_subscriber(registry=registry, outbound_dlp=dlp)

        warnings = [
            c
            for c in captured
            if c.get("event") == HOOKS_DLP_SUBSCRIBER_NOT_REGISTERED
            and c.get("log_level") == "warning"
        ]
        assert len(warnings) == 1, (
            f"Expected one structlog WARN tagged "
            f"{HOOKS_DLP_SUBSCRIBER_NOT_REGISTERED!r}; got {captured!r}"
        )
        assert warnings[0]["plugin_id"] == "alfred.security._extract_dlp_subscriber"
        assert warnings[0]["hookpoint"] == "security.quarantined.extract"
        assert warnings[0]["requested_tier"] == "system"
    finally:
        set_registry(prior)


# ---------------------------------------------------------------------------
# MEDIUM #8 — idempotency arm MUST raise on different OutboundDlp instance.
# ---------------------------------------------------------------------------


def test_register_with_different_outbound_dlp_raises(
    fresh_registry_allow_system: Any,
) -> None:
    """A second :func:`register_extract_dlp_subscriber` call carrying a
    DIFFERENT :class:`OutboundDlp` instance MUST raise :class:`HookError`.

    Pin the MEDIUM #8 fix (CR-158): the prior behaviour silently
    no-op'd the second call, leaving the FIRST scanner as the active
    DLP defence while the caller's intent was "use *my* scanner".
    That drift silently disarms the orchestrator's DLP singleton
    wiring whenever the orchestrator constructs a second
    :class:`QuarantinedExtractor` with a fresh scanner (a
    bootstrap-mistake shape).

    The FIRST registration MUST stay intact — the raise is the loud
    signal to the caller; rolling back the first registration would
    confuse the forensic trail.
    """
    from alfred.security.quarantine import declare_hookpoints

    declare_hookpoints(fresh_registry_allow_system)

    dlp_a = MagicMock()
    dlp_a.scan = MagicMock(side_effect=lambda x: x)
    dlp_b = MagicMock()
    dlp_b.scan = MagicMock(side_effect=lambda x: x)

    first = register_extract_dlp_subscriber(
        registry=fresh_registry_allow_system,
        outbound_dlp=dlp_a,
    )
    assert first is RegistrationOutcome.REGISTERED

    with pytest.raises(HookError, match="different OutboundDlp"):
        register_extract_dlp_subscriber(
            registry=fresh_registry_allow_system,
            outbound_dlp=dlp_b,
        )

    # First registration intact.
    subs = fresh_registry_allow_system.subscribers_for("security.quarantined.extract", "post")
    assert len(subs) == 1
    bound_self = getattr(subs[0].hook_fn, "__self__", None)
    assert isinstance(bound_self, OutboundDlpExtractSubscriber)
    assert bound_self._dlp is dlp_a


# ---------------------------------------------------------------------------
# LOW #10 — non-ASCII canary detected under ``ensure_ascii=False``.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_ascii_canary_is_detected_under_ensure_ascii_false() -> None:
    """A multi-byte canary character MUST surface verbatim in the
    :func:`json.dumps` serialisation so the DLP regex sees the exact
    UTF-8 byte sequence the scanner expects.

    Pin the LOW #10 fix (CR-158): the subscriber's ``json.dumps`` call
    passes ``ensure_ascii=False`` so multi-byte canaries (Cyrillic,
    CJK, emoji-encoded markers) are emitted as the literal
    code-point string. A regression to ``ensure_ascii=True`` would
    re-encode the canary as ``\\uXXXX`` escapes — the DLP regex
    matching against the literal UTF-8 bytes would miss them and
    silently disarm the boundary for non-ASCII canaries.

    The mock DLP redacts only when the canary character sequence is
    present in the literal form. A regression to ``ensure_ascii=True``
    would NOT trip the redaction because ``"канарейка-XYZ"`` would
    appear in the serialised JSON as
    ``"\\u043a\\u0430\\u043d..."`` — different bytes, regex misses.
    """
    canary = "канарейка-XYZ"  # Cyrillic + ASCII

    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda x: x.replace(canary, "[REDACTED]"))
    sub = OutboundDlpExtractSubscriber(outbound_dlp=dlp)
    ctx = _build_ctx({"summary": f"observed {canary} in body"})

    with pytest.raises(HookRefusal):
        await sub(ctx)

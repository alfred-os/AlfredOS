"""Concrete seam bridges that wire the Wave-2/3 Protocols (Task 52 prep, #152).

Wave 2 shipped three injected Protocol seams the inbound path consumes:

* ``_OrchestratorLike.quarantined_extract`` (body-shaped) — the
  :class:`CommsExtractorBridge` adapts the real Slice-3
  :class:`alfred.security.quarantine.QuarantinedExtractor` (handle-shaped
  ``extract(handle, schema)``) onto it: raw body -> ``ContentHandle`` ->
  ``extract``. The canonical ``user_id`` is NEVER threaded into the extractor
  call — structurally, the extractor surface has no user-id parameter.
* ``_IdentityResolverLike.resolve`` (async) — the
  :class:`SyncIdentityResolverBridge` adapts the real sync
  :meth:`IdentityResolver.resolve(platform, platform_id)` and maps the
  ``alfred_comms_test`` adapter kind onto a :class:`Platform` member.
* the breaker seam — :class:`SupervisorBreakerTripper` adapts
  :meth:`Supervisor.trip_breaker` onto the handlers' ``trip_comms_breaker``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.comms_mcp.bootstrap import (
    CommsBodyExtraction,
    CommsExtractorBridge,
    SupervisorBreakerTripper,
    SyncIdentityResolverBridge,
    build_supervisor_breaker_tripper,
)
from alfred.comms_mcp.errors import UnknownAdapterKindError
from alfred.identity.models import Platform

# ---------------------------------------------------------------------------
# CommsExtractorBridge
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_extractor_bridge_mints_handle_and_delegates() -> None:
    """The bridge calls the real ``extract(handle, schema)`` surface."""
    extractor = MagicMock()
    extractor.extract = AsyncMock(return_value="EXTRACTION_RESULT")
    bridge = CommsExtractorBridge(extractor=extractor)

    result = await bridge.extract(
        body={"content": "hello"},
        canonical_user_id="u_alice",
        source_tier="T3",
    )

    assert result == "EXTRACTION_RESULT"
    extractor.extract.assert_awaited_once()
    call = extractor.extract.await_args
    handle = call.kwargs.get("handle") if call.kwargs else call.args[0]
    schema = call.kwargs.get("schema") if "schema" in (call.kwargs or {}) else call.args[1]
    assert schema is CommsBodyExtraction
    # The handle is opaque + carries a tz-aware fetch timestamp.
    assert handle.fetch_timestamp.tzinfo is not None


@pytest.mark.asyncio
async def test_extractor_bridge_records_body_under_handle() -> None:
    """When a recorder is wired, the body is recorded under the minted handle."""
    extractor = MagicMock()
    extractor.extract = AsyncMock(return_value="R")
    recorded: list[dict[str, Any]] = []

    def _recorder(*, handle: Any, body: Any) -> None:
        recorded.append({"handle_id": handle.id, "body": body})

    bridge = CommsExtractorBridge(extractor=extractor, record_body=_recorder)
    await bridge.extract(body={"content": "x"}, canonical_user_id="u", source_tier="T3")

    assert len(recorded) == 1
    assert recorded[0]["body"] == {"content": "x"}
    # The recorded handle id matches the one passed to the extractor.
    handle = extractor.extract.await_args.args[0]
    assert recorded[0]["handle_id"] == handle.id


@pytest.mark.asyncio
async def test_extractor_bridge_never_threads_canonical_user_id_to_extractor() -> None:
    """#152 identity invariant: canonical_user_id never reaches the extractor call.

    The bridge accepts ``canonical_user_id`` (the inbound seam passes it) but the
    real extractor surface is ``extract(handle, schema)`` — there is no parameter
    by which the canonical id could cross into the quarantine wire. This test
    pins that no extractor-call argument is, or contains, the canonical id.
    """
    extractor = MagicMock()
    extractor.extract = AsyncMock(return_value="R")
    bridge = CommsExtractorBridge(extractor=extractor)

    await bridge.extract(
        body={"content": "x"},
        canonical_user_id="u_secret_canonical",
        source_tier="T3",
    )

    call = extractor.extract.await_args
    blob = repr(call.args) + repr(call.kwargs)
    assert "u_secret_canonical" not in blob


# ---------------------------------------------------------------------------
# SyncIdentityResolverBridge
# ---------------------------------------------------------------------------


def _fake_user(*, slug: str, language: str) -> Any:
    user = MagicMock()
    user.slug = slug
    user.language = language
    return user


@pytest.mark.asyncio
async def test_resolver_bridge_maps_adapter_kind_and_wraps_user() -> None:
    resolver = MagicMock()
    resolver.resolve = MagicMock(return_value=_fake_user(slug="u_alice", language="en-GB"))
    bridge = SyncIdentityResolverBridge(resolver=resolver)

    resolved = await bridge.resolve(adapter_id="alfred_comms_test", platform_user_id="discord:123")

    assert resolved is not None
    assert resolved.canonical_user_id == "u_alice"
    assert resolved.language == "en-GB"
    assert resolved.adapter_id == "alfred_comms_test"
    # alfred_comms_test maps onto a real Platform member for the sync call.
    resolver.resolve.assert_called_once()
    platform_arg = resolver.resolve.call_args.args[0]
    assert isinstance(platform_arg, Platform)
    assert resolver.resolve.call_args.args[1] == "discord:123"


@pytest.mark.asyncio
async def test_resolver_bridge_returns_none_on_unbound_user() -> None:
    resolver = MagicMock()
    resolver.resolve = MagicMock(return_value=None)
    bridge = SyncIdentityResolverBridge(resolver=resolver)

    resolved = await bridge.resolve(
        adapter_id="alfred_comms_test", platform_user_id="discord:nobody"
    )

    assert resolved is None


@pytest.mark.asyncio
async def test_resolver_bridge_raises_on_unknown_adapter_kind() -> None:
    """A truly unknown adapter_id must NOT silently map onto DISCORD.

    The ``alfred_comms_test -> DISCORD`` placeholder is intentional, but an
    unmapped adapter kind is a contract violation — fail loud with the
    closed-vocab error naming the offending kind, never resolve it against the
    wrong platform's binding table.
    """
    resolver = MagicMock()
    resolver.resolve = MagicMock()
    bridge = SyncIdentityResolverBridge(resolver=resolver)

    with pytest.raises(UnknownAdapterKindError) as excinfo:
        await bridge.resolve(adapter_id="totally_unknown", platform_user_id="x:1")

    assert "totally_unknown" in str(excinfo.value)
    # The resolver is never consulted for an unmapped kind.
    resolver.resolve.assert_not_called()


# ---------------------------------------------------------------------------
# SupervisorBreakerTripper
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_breaker_tripper_maps_open_vocab_reason_onto_supervisor_facade() -> None:
    """The open-vocab seam reason maps onto the closed supervisor vocabulary.

    Foundation gap: the handlers' ``trip_comms_breaker`` carries an open-vocab
    reason but ``Supervisor.trip_breaker`` accepts only ``TripBreakerReason``.
    The bridge keys the breaker on ``comms.<adapter_id>`` and maps any non-
    dispatcher trip onto ``plugin_lifecycle_crash``.
    """
    supervisor = AsyncMock()
    tripper = SupervisorBreakerTripper(supervisor=supervisor)

    await tripper.trip_comms_breaker(
        adapter_id="alfred_comms_test", reason="comms.rate_limit.exhausted"
    )

    supervisor.trip_breaker.assert_awaited_once()
    kwargs = supervisor.trip_breaker.await_args.kwargs
    assert kwargs["component_id"] == "comms.alfred_comms_test"
    assert kwargs["reason"] == "plugin_lifecycle_crash"


def test_build_supervisor_breaker_tripper_factory() -> None:
    supervisor = AsyncMock()
    tripper = build_supervisor_breaker_tripper(supervisor=supervisor)
    assert isinstance(tripper, SupervisorBreakerTripper)

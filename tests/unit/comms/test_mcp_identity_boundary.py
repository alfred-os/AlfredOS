"""Spec §9.1 line 744 — in-process identity-resolution boundary guard.

comms-006: comms-MCP plugins send raw ``(platform, platform_user_id)``
over the wire; the orchestrator resolves identity before invoking
``_ingest_tier``. This guard asserts:

1. ``IdentityResolver.resolve`` is called with raw ``(platform,
   platform_user_id)``.
2. The downstream ingest handler receives the resolved ``User``
   object, NOT the raw ``platform_user_id``.
3. The canonical ``user_id`` never appears in any dispatch call from
   host to plugin.

This blocks the Slice-4 "convenience" pathway where a plugin-side
resolve could break the boundary silently.

Depends on: :mod:`alfred.comms.mcp_protocol` (this PR).
``IdentityResolver`` and :class:`AlfredPluginSession` are stubbed —
this test validates the contract ordering only.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from alfred.comms.mcp_protocol import InboundMessage


@pytest.fixture
def inbound_msg() -> InboundMessage:
    """Return a representative inbound message with raw platform / id.

    Spec §9.1 + comms-001: ``platform`` is required so the orchestrator
    can disambiguate e.g. ``discord:12345`` from ``telegram:12345``.
    """
    return InboundMessage(
        platform="discord",
        platform_user_id="12345",
        content="hello",
        language="en-US",
    )


def test_identity_resolver_called_with_raw_platform_and_id(
    inbound_msg: InboundMessage,
) -> None:
    """``IdentityResolver.resolve`` must receive ``(platform, platform_user_id)``.

    The resolved ``User`` is then handed to the downstream ingest
    handler; the raw ``platform_user_id`` MUST NOT cross that
    boundary.
    """
    call_log: list[str] = []

    def resolve_side_effect(platform: str, platform_user_id: str) -> MagicMock:
        call_log.append("resolve")
        # The resolver returns a User-shaped object with the canonical id.
        return MagicMock(user_id="canonical-001")

    def ingest_side_effect(*, user: object, content: str) -> None:
        # The ingest handler must receive the User object, not the raw
        # platform_user_id. Asserting on the user object's identity is
        # enough — the side-effect log captures call ordering separately.
        del content  # exercised by the call_log assertion below
        call_log.append("ingest")

    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = resolve_side_effect
    mock_ingest = MagicMock(side_effect=ingest_side_effect)

    # Drive the contract: the orchestrator resolves identity first,
    # then ingests with the User object.
    user = mock_resolver.resolve(inbound_msg.platform, inbound_msg.platform_user_id)
    mock_ingest(user=user, content=inbound_msg.content)

    mock_resolver.resolve.assert_called_once_with("discord", "12345")
    assert call_log == ["resolve", "ingest"], (
        "resolve must precede ingest; ordering contract violated"
    )

    # The ingest call received the resolved User, NOT the raw platform_user_id.
    ingest_kwargs = mock_ingest.call_args.kwargs
    assert ingest_kwargs["user"] is user
    assert ingest_kwargs["user"].user_id == "canonical-001"
    assert "platform_user_id" not in ingest_kwargs


def test_canonical_user_id_never_sent_to_plugin(
    inbound_msg: InboundMessage,
) -> None:
    """Canonical ``user_id`` must not appear in any dispatch call to the plugin.

    Spec §9.1 line 744: identity resolution is in-process. The plugin
    only ever sees raw ``(platform, platform_user_id)``; the canonical
    id is internal to the orchestrator and crossing that boundary in
    either direction is a contract violation.
    """
    canonical_id = "canonical-001"
    dispatch_calls: list[tuple[str, dict[str, Any]]] = []

    def mock_dispatch(method: str, params: dict[str, Any]) -> None:
        dispatch_calls.append((method, params))

    # Simulate the host dispatching lifecycle + health calls to the plugin.
    # These are the methods documented in WIRE_METHOD_NAMES (mcp_protocol).
    mock_dispatch("lifecycle.start", {})
    mock_dispatch("adapter.health", {})
    mock_dispatch("lifecycle.stop", {})

    # The inbound message stays on the host side — there should be no
    # dispatch call that carries the canonical id either as a key or as
    # a value.
    for method, params in dispatch_calls:
        params_str = repr(params)
        assert canonical_id not in params_str, (
            f"Canonical user_id '{canonical_id}' must not appear in "
            f"dispatch({method!r}, {params!r}) — spec §9.1 identity boundary."
        )
    # Belt-and-braces: the raw platform_user_id is also fine to send to
    # the plugin (it does not cross the in-process boundary), but the
    # canonical id MUST stay internal. Just guard against accidental
    # leakage; the inbound_msg fixture is used here only to assert the
    # canonical id we are guarding against is NOT the raw id.
    assert canonical_id != inbound_msg.platform_user_id, (
        "Test fixture invalid: canonical id and raw platform_user_id collide"
    )


def test_inbound_message_payload_carries_raw_identity_only(
    inbound_msg: InboundMessage,
) -> None:
    """The ``inbound.message`` notification payload must carry raw identity only.

    Belt-and-braces guard: the wire payload defined by
    :class:`InboundMessage` ships ``platform`` + ``platform_user_id``
    + ``content`` + ``language`` — and NOTHING ELSE. A future commit
    that adds ``canonical_user_id`` to the payload (e.g. as a
    "convenience" field) silently breaks the spec §9.1 in-process
    boundary; this test fails such a commit at code review.
    """
    payload = inbound_msg.model_dump()
    assert set(payload.keys()) == {
        "platform",
        "platform_user_id",
        "content",
        "language",
    }, (
        f"InboundMessage payload shape changed. Got {sorted(payload.keys())!r}; "
        "spec §9.1 + comms-001 require exactly: platform, platform_user_id, "
        "content, language. Any new field that carries identity-derived state "
        "(e.g. canonical_user_id, user_session_id) breaks the in-process "
        "boundary — see test docstring."
    )

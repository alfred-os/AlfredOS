"""PluginTransport Protocol + DispatchResult union — PR-S3-3a Task 2 (spec §4.1, §4.2).

PluginTransport is the structural Protocol every transport implementation
honours. Slice 3 ships ``StdioTransport`` as the sole implementation; the
Protocol exists so HTTP transport (Slice 5+) drops in without touching the
orchestrator.

DispatchResult is a plain union of three shapes — one per call type:

* ``ContentHandle`` — content-bearing tools (web.fetch). T3 bytes are held
  in the content store and the orchestrator only sees the opaque handle.
* ``ExtractionResult`` (= ``Extracted | TypedRefusal``) — quarantine.extract
  calls. Pre-validated by the quarantined LLM plugin.
* ``ControlResult`` — lifecycle, config, and health-check calls. No T3
  tagging, no content store write.

core-011 fix: DispatchResult is a plain union — no ``Annotated[…,
Field(discriminator=None)]`` wrapper. Pydantic's discriminator machinery is
unnecessary here because dispatch sites branch by ``isinstance``.
"""

from __future__ import annotations

import typing

import pydantic
import pytest

from alfred.plugins.transport import ControlResult, DispatchResult, PluginTransport
from alfred.security.quarantine import ContentHandle, Extracted, TypedRefusal

# ---------------------------------------------------------------------------
# ControlResult — frozen Pydantic model. Mutating after construction is a
# programming bug; the freeze flag turns it into a Pydantic validation error.
# ---------------------------------------------------------------------------


def test_control_result_is_frozen() -> None:
    cr = ControlResult(method="lifecycle.start", payload={"status": "ok"})
    with pytest.raises(pydantic.ValidationError):
        cr.method = "changed"  # type: ignore[misc]


def test_control_result_carries_method_and_payload() -> None:
    cr = ControlResult(method="lifecycle.start", payload={"status": "ok"})
    assert cr.method == "lifecycle.start"
    assert cr.payload == {"status": "ok"}


def test_control_result_payload_accepts_empty_dict() -> None:
    cr = ControlResult(method="ping", payload={})
    assert cr.payload == {}


# ---------------------------------------------------------------------------
# DispatchResult union shape — three concrete shapes, plain union (core-011).
# ---------------------------------------------------------------------------


def test_dispatch_result_is_plain_union_of_three_shapes() -> None:
    args = typing.get_args(DispatchResult)
    # Sanity-check the union has exactly three concrete members. The
    # extraction branch is itself a union (Extracted | TypedRefusal) so the
    # member count depends on how the type alias is composed; either form
    # (three shapes flattened, or ContentHandle + ControlResult + the
    # extraction union) must include each shape.
    flat: list[type] = []
    for arg in args:
        flat.extend(typing.get_args(arg) or [arg])
    assert ContentHandle in flat
    assert ControlResult in flat
    assert Extracted in flat
    assert TypedRefusal in flat


# ---------------------------------------------------------------------------
# PluginTransport Protocol surface.
# ---------------------------------------------------------------------------


def test_plugin_transport_protocol_has_dispatch() -> None:
    assert hasattr(PluginTransport, "dispatch")


def test_plugin_transport_protocol_has_close() -> None:
    assert hasattr(PluginTransport, "close")


def test_plugin_transport_is_runtime_checkable() -> None:
    # Slice-3 wiring uses ``isinstance(obj, PluginTransport)`` in supervisor
    # bootstrap; runtime_checkable is the contract.
    class _DummyTransport:
        async def dispatch(self, method: str, params: dict[str, object]) -> DispatchResult:
            return ControlResult(method=method, payload=params)

        async def close(self) -> None:
            return None

    assert isinstance(_DummyTransport(), PluginTransport)


def test_plugin_transport_rejects_object_missing_required_method() -> None:
    class _IncompleteTransport:
        async def dispatch(self, method: str, params: dict[str, object]) -> DispatchResult:
            return ControlResult(method=method, payload=params)

        # no `close` method

    assert not isinstance(_IncompleteTransport(), PluginTransport)

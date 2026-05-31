"""PluginTransport Protocol and DispatchResult type (spec §4.1, §4.2).

Slice 3 ships :class:`alfred.plugins.stdio_transport.StdioTransport` as the
sole implementation of this Protocol. HTTP transport is deferred to
Slice 5+. In-process ``MemoryTransport`` is deliberately never shipped:
process-boundary isolation is load-bearing per PRD §5 and ADR-0017, and
any in-process implementation would collapse it.

The Protocol exists so the supervisor + orchestrator do not import the
concrete transport — they hold a ``PluginTransport`` reference. When the
HTTP transport lands, it implements this Protocol and the supervisor
swaps the constructor without code-path changes.

``DispatchResult`` is a plain ``X | Y | Z`` union (core-011 fix — no
``Annotated`` discriminator wrapper). Call sites branch by ``isinstance``;
each shape carries enough type information that mypy narrows correctly.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from alfred.security.quarantine import ContentHandle, ExtractionResult


class ControlResult(BaseModel):
    """Plain JSON-deserialisable result from a control-plane RPC call.

    Returned for lifecycle, config, and health-check methods (every method
    whose response is *not* T3-tagged user-visible content and *not* a
    structured extraction).

    NEVER carries T3 content — that path returns
    :class:`alfred.security.quarantine.ContentHandle`.
    NEVER carries structured extraction — that path returns
    :class:`alfred.security.quarantine.ExtractionResult`.

    Frozen so dispatch sites cannot mutate the response between
    construction and audit-log emission.
    """

    model_config = ConfigDict(frozen=True)

    method: str
    payload: dict[str, object]


# DispatchResult: discriminated by ``isinstance`` in dispatch sites — three
# shapes, no Pydantic discriminator field (core-011 fix).
#
#   * ContentHandle      — content-bearing tools (web.fetch); T3 bytes held
#     in the content store, the orchestrator only sees the opaque handle.
#   * ExtractionResult   — quarantine.extract calls. This is itself a
#     union (``Extracted | TypedRefusal``); when flattened, DispatchResult
#     resolves to four concrete shapes.
#   * ControlResult      — lifecycle, config, health-check methods. No T3
#     tagging, no content store write.
#
# Removed the ``Annotated[..., Field(discriminator=None)]`` wrapper that
# earlier spec drafts mentioned — the discriminator was meaningless because
# the three shapes do not share a tag field.
DispatchResult = ContentHandle | ExtractionResult | ControlResult


@runtime_checkable
class PluginTransport(Protocol):
    """Structural Protocol every plugin transport implementation honours.

    Slice 3 ships :class:`alfred.plugins.stdio_transport.StdioTransport` as
    the sole implementation (spec §4.2). HTTP is deferred to Slice 5+.
    In-process ``MemoryTransport`` is deliberately never shipped — it
    would collapse process-boundary isolation.

    DLP wraps ``dispatch()``: callers receive the post-DLP result. The
    intermediate ``TaggedContent[T3]`` value is plugin-host-internal — it
    exists between the subprocess boundary and the content store write
    and never exits ``dispatch()`` to the caller.

    ``runtime_checkable`` so supervisor bootstrap can
    ``isinstance(obj, PluginTransport)`` check without importing the
    concrete class.
    """

    async def dispatch(
        self,
        method: str,
        params: dict[str, object],
    ) -> DispatchResult:
        """Dispatch a JSON-RPC call to the plugin subprocess.

        Returns one of the three :data:`DispatchResult` shapes based on
        the method type. T3 bytes never exit this call — content-bearing
        methods return a :class:`ContentHandle` referencing the content
        store.
        """
        ...

    async def close(self) -> None:
        """Gracefully close the plugin transport connection.

        Idempotent: a second ``close()`` is a no-op. Releases subprocess
        resources, drains pending writes, and emits the
        ``plugin.lifecycle.closed`` audit row.
        """
        ...


__all__ = [
    "ControlResult",
    "DispatchResult",
    "PluginTransport",
]

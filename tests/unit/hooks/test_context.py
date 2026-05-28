"""Tests for ``alfred.hooks.context`` — the ``HookContext[T]`` carrier.

The carrier is the immutable per-stage object that every hook sees. The
invariants this file pins are the load-bearing ones the rest of the
subsystem will rely on:

* Frozen — no attribute set after construction (``FrozenInstanceError``).
* Copy helpers (``with_input``, ``with_metadata``, ``for_stage``) return a
  **new** instance; the original is never mutated.
* ``with_metadata`` merges into a **fresh** dict, not into the original's
  mapping — proven by mutating the returned metadata and asserting the
  original is unchanged.
* No shared mutable default — two contexts built with no ``metadata=``
  kwarg have distinct dict objects (the spec's
  "never a shared mutable default" assertion).
* ``for_stage`` round-trip: the hookpoint/kind that go in come out.

Hypothesis covers the round-trip with a one-sentence property. The other
cases are deterministic examples — they pin specific shapes the carrier
must hold, which a property-based generator could in principle miss.
"""

from __future__ import annotations

import dataclasses

import pytest
from hypothesis import given
from hypothesis import strategies as st

from alfred.hooks.context import HookContext, HookKind

# A representative context used as the starting point for the copy-helper
# tests. Strings are intentionally distinct ("orig-*") so an accidental
# alias in the implementation surfaces as a value mismatch rather than a
# silently-passing identity check.
_BASE_KWARGS: dict[str, object] = {
    "action_id": "orig-action",
    "hookpoint": "orig.hookpoint",
    "input": "orig-input",
    "correlation_id": "orig-corr",
    "kind": "pre",
}


def _make_ctx(**overrides: object) -> HookContext[str]:
    """Build a context with the base kwargs, applying any overrides."""
    kwargs: dict[str, object] = {**_BASE_KWARGS, **overrides}
    return HookContext[str](**kwargs)  # type: ignore[arg-type]


# ──────────────────────────────────────────────────────────────────────
# 1. Frozen-ness
# ──────────────────────────────────────────────────────────────────────


def test_hookcontext_is_frozen() -> None:
    """Setting any attribute on a constructed context raises
    ``FrozenInstanceError`` — the dataclass is ``frozen=True``.
    """
    ctx = _make_ctx()
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.action_id = "mutated"  # type: ignore[misc]


# ──────────────────────────────────────────────────────────────────────
# 2. with_input
# ──────────────────────────────────────────────────────────────────────


def test_with_input_returns_new_instance_with_replaced_input() -> None:
    """``with_input`` produces a fresh context whose ``input`` is the new
    value; the original instance is unchanged.
    """
    ctx = _make_ctx()
    new_ctx = ctx.with_input("replaced-input")

    assert new_ctx is not ctx
    assert new_ctx.input == "replaced-input"
    # Original untouched — the carrier is value-typed.
    assert ctx.input == "orig-input"
    # Other fields carry through verbatim.
    assert new_ctx.action_id == ctx.action_id
    assert new_ctx.hookpoint == ctx.hookpoint
    assert new_ctx.correlation_id == ctx.correlation_id
    assert new_ctx.kind == ctx.kind


# ──────────────────────────────────────────────────────────────────────
# 3. with_metadata — merge into a FRESH dict
# ──────────────────────────────────────────────────────────────────────


def test_with_metadata_merges_into_fresh_dict() -> None:
    """``with_metadata`` returns a new context whose metadata mapping is a
    distinct object containing both the original keys and the new kv
    pairs. Mutating the returned metadata MUST NOT mutate the original
    — proving the merge is a copy, not an alias.
    """
    original_metadata: dict[str, object] = {"trace_id": "trace-orig"}
    ctx = _make_ctx(metadata=original_metadata)

    new_ctx = ctx.with_metadata(span_id="span-new", trace_id="trace-overridden")

    # The two contexts are distinct instances.
    assert new_ctx is not ctx
    # The merged map contains both the original key (overridden) and the new one.
    assert new_ctx.metadata == {"trace_id": "trace-overridden", "span_id": "span-new"}
    # And it is a different object from both the original kwarg dict and from
    # the original context's metadata.
    assert new_ctx.metadata is not original_metadata
    assert new_ctx.metadata is not ctx.metadata
    # The original context's metadata is unchanged — no mutation through alias.
    assert ctx.metadata == {"trace_id": "trace-orig"}
    # And mutating the new metadata in-place (it is a dict in practice) leaves
    # the original alone — the load-bearing "fresh dict" assertion.
    assert isinstance(new_ctx.metadata, dict)
    new_ctx.metadata["scratch"] = "value"
    assert "scratch" not in ctx.metadata
    assert "scratch" not in original_metadata


# ──────────────────────────────────────────────────────────────────────
# 4. for_stage
# ──────────────────────────────────────────────────────────────────────


def test_for_stage_returns_new_instance_retargeted() -> None:
    """``for_stage`` produces a new context with the supplied
    ``hookpoint`` / ``kind``; the original is unchanged.
    """
    ctx = _make_ctx()
    new_ctx = ctx.for_stage(hookpoint="other.hookpoint", kind="post")

    assert new_ctx is not ctx
    assert new_ctx.hookpoint == "other.hookpoint"
    assert new_ctx.kind == "post"
    # The original retains its stage.
    assert ctx.hookpoint == "orig.hookpoint"
    assert ctx.kind == "pre"
    # And everything else carries through.
    assert new_ctx.action_id == ctx.action_id
    assert new_ctx.input == ctx.input
    assert new_ctx.correlation_id == ctx.correlation_id
    assert new_ctx.metadata == ctx.metadata


# ──────────────────────────────────────────────────────────────────────
# 5. Hypothesis property — for_stage round-trip
# ──────────────────────────────────────────────────────────────────────


_KIND_STRATEGY = st.sampled_from(("pre", "post", "error", "cancel"))


@given(hookpoint=st.text(), kind=_KIND_STRATEGY)
def test_for_stage_round_trip(hookpoint: str, kind: HookKind) -> None:
    """Property: whatever ``hookpoint`` / ``kind`` go into ``for_stage``
    come back out of the returned context. Pins the retarget semantics
    against accidental field swaps.
    """
    ctx = _make_ctx()
    staged = ctx.for_stage(hookpoint=hookpoint, kind=kind)
    assert staged.hookpoint == hookpoint
    assert staged.kind == kind


# ──────────────────────────────────────────────────────────────────────
# 6. Distinct default metadata (no shared mutable default)
# ──────────────────────────────────────────────────────────────────────


def test_default_metadata_is_not_shared_across_instances() -> None:
    """Two freshly-built contexts (no ``metadata=`` kwarg) hold distinct
    metadata mappings — the spec's "never a shared mutable default"
    assertion. ``field(default_factory=dict)`` is the implementation
    contract that satisfies this; this test pins it.
    """
    a = _make_ctx()
    b = _make_ctx()
    assert a.metadata is not b.metadata


def test_metadata_defensive_copy_protects_against_external_mutation() -> None:
    """Constructor seals the metadata mapping against alias mutation.

    A caller that passes a mutable dict and then mutates it post-init
    MUST NOT see the mutation reach back into the frozen carrier — the
    dataclass's ``__post_init__`` defensive-copies the metadata mapping
    so the stored attribute is a fresh dict, not the caller's original.
    The ``with_metadata`` merge already produced fresh dicts on the
    *update* path; this pins the *construct* path too so both ingress
    seams honour the same isolation contract.
    """
    original_metadata: dict[str, object] = {"key": "value"}
    ctx = _make_ctx(metadata=original_metadata)

    # Mutate the original AFTER constructing the context.
    original_metadata["key"] = "mutated"
    original_metadata["new_key"] = "injected"

    # The carrier is unchanged — the constructor copied on ingress.
    assert ctx.metadata == {"key": "value"}
    assert ctx.metadata is not original_metadata


# ──────────────────────────────────────────────────────────────────────
# Bonus: HookKind exposes exactly the four stage names. Pins the alias
# so a Task-2/3 author wiring decorators can rely on the set.
# ──────────────────────────────────────────────────────────────────────


def test_hookkind_alias_covers_the_four_stages() -> None:
    """``HookKind`` is the type alias every decorator / dispatcher uses.
    Sanity-check the four literal values it carries.
    """
    # This is a typing-only alias, so we cannot iterate it at runtime
    # without ``typing.get_args``. The test is light — it confirms the
    # four canonical stage names are present, in any order.
    from typing import get_args

    # ``HookKind`` is a PEP 695 type alias for ``Literal["pre","post","error","cancel"]``.
    # ``get_args`` over the underlying ``Literal`` returns the value tuple.
    underlying = HookKind.__value__  # PEP 695 type-alias underlying form
    assert set(get_args(underlying)) == {"pre", "post", "error", "cancel"}
    # And the four named values are themselves assignable to ``HookKind``-
    # typed parameters via ``Literal`` (mypy/pyright check this at static
    # time; this assertion is a runtime smoke test for the matching set).
    for kind in ("pre", "post", "error", "cancel"):
        assert kind in get_args(underlying)

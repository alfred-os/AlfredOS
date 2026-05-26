"""Trust-tier types for AlfredOS. Slice 1 ships T0 and T2 only.

See PRD §7.1. T1 (operator) and T3 (untrusted) markers land alongside the
dual-LLM split in Slice 2/3 when AlfredOS first ingests untrusted content.
"""

from __future__ import annotations

from typing import Any, overload

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TrustTier:
    """Marker base for trust tiers. Subclasses set `name` as a class attribute
    so the trust-tier label survives into runtime use (audit log, DB row)
    without losing the static-type-parameter benefits of `TaggedContent`."""

    name: str = ""


class T0(TrustTier):
    """System tier: AlfredOS internals (highest trust)."""

    name = "T0"


class T2(TrustTier):
    """Authenticated tier: known users."""

    name = "T2"


class TaggedContent[TierT: TrustTier](BaseModel):
    """Content tagged with a trust tier.

    The tier is BOTH a type parameter (so mypy can distinguish T0/T2 statically)
    AND a runtime field (so the orchestrator + audit log can read it). Slice 1
    uses this to keep system prompts (T0) and user input (T2) distinguishable;
    Slice 2 adds T1/T3 plus the dual-LLM split.
    """

    # `arbitrary_types_allowed=True` is required because `tier` is a runtime
    # `type` object (a TrustTier subclass), which Pydantic doesn't recognise
    # as a native schema type. The `tier` field_validator below enforces the
    # invariant Pydantic can't: that the class is a TrustTier subclass with a
    # non-empty `name`. Slice 5 plans to replace this with `tier_name: str`
    # backed by the persona registry — at which point this flag goes away.
    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    content: str
    source: str
    tier: type[TrustTier]
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tier")
    @classmethod
    def _validate_tier(cls, value: type[TrustTier]) -> type[TrustTier]:
        """Reject any tier outside the slice-1 allowlist.

        Defence in depth at the data-class boundary, matching the runtime
        guard in ``tag()``. Three checks:

        1. Pydantic's ``is_subclass_of`` check (driven by the
           ``type[TrustTier]`` annotation) already rejects non-TrustTier
           classes and non-class values — the static half of the gate.
        2. Empty ``name`` would persist "" into the audit log — reject it.
        3. The class must be one of ``_APPROVED_TIERS``. This is the trust-
           boundary policy: even a properly-named TrustTier subclass that
           isn't in this slice's enabled set must not be constructable. CR
           (#89) tightened this against the prior "any-named-subclass"
           pass-through; PRD §7.1 only enables T0/T2 in slice 1.
        """
        if not value.name:
            raise ValueError(
                f"TrustTier subclass {value.__name__} must set a non-empty `name`",
            )
        if value not in _APPROVED_TIERS:
            approved = sorted(t.name for t in _APPROVED_TIERS)
            raise ValueError(
                f"unsupported trust tier for this build: {value.name!r} (approved: {approved})"
            )
        return value


# Slice 1 admits only T0 and T2 at the `tag()` boundary. Slice 2 will add T1
# (operator) and T3 (untrusted ingestion) here alongside the dual-LLM split —
# a one-line change. Keeping the allowlist as a module-level frozenset (rather
# than literals inline in `tag()`) makes the Slice-2 migration mechanical and
# keeps the rejection branch a single, testable predicate.
_APPROVED_TIERS: frozenset[type[TrustTier]] = frozenset({T0, T2})


@overload
def tag(
    tier: type[T0], content: str, *, source: str = "unspecified", **metadata: Any
) -> TaggedContent[T0]: ...


@overload
def tag(
    tier: type[T2], content: str, *, source: str = "unspecified", **metadata: Any
) -> TaggedContent[T2]: ...


def tag(
    tier: type[TrustTier], content: str, *, source: str = "unspecified", **metadata: Any
) -> TaggedContent[Any]:
    """Tag content with a trust tier at an ingestion boundary.

    `content` is positional so call sites read naturally:
        tag(T2, user_text, source="comms.tui.input")
    `source` is optional; supply it at every real ingestion site (the
    audit log records it) but defaults exist so quick test fixtures don't
    have to repeat it.

    Runtime-rejects any tier outside the slice-1 allowlist (T0, T2). The
    `@overload` signatures and the Pydantic `_validate_tier` already close
    the static + empty-name halves of the gate; this guard closes the
    runtime "looks like a TrustTier but isn't on the slice's list" hole.
    """
    if tier not in _APPROVED_TIERS:
        approved = sorted(t.name for t in _APPROVED_TIERS)
        raise ValueError(
            f"unsupported trust tier for this build: "
            f"{getattr(tier, 'name', tier)!r} (approved: {approved})"
        )
    return TaggedContent[tier](  # type: ignore[valid-type]
        content=content, source=source, tier=tier, metadata=dict(metadata)
    )

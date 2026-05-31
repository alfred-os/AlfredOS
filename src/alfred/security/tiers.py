"""Trust-tier types for AlfredOS.

The closed tier model (PRD §7.1 / ADR-0017): {T0, T1, T2, T3}.

Slice 3 adds T1 (operator) and T3 (untrusted ingestion) alongside the
dual-LLM split. The ``tag(T3, ...)`` factory is capability-gated by a
per-process nonce token — see ``CapabilityGateNonce`` and spec §3.2.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, overload, runtime_checkable

import structlog
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_serializer,
    model_validator,
)

from alfred.i18n import t


class TrustTier:
    """Marker base for trust tiers. Subclasses set `name` as a class attribute
    so the trust-tier label survives into runtime use (audit log, DB row)
    without losing the static-type-parameter benefits of `TaggedContent`."""

    name: str = ""


class T0(TrustTier):
    """System tier: AlfredOS internals (highest trust)."""

    name = "T0"


class T1(TrustTier):
    """Operator tier: TUI ingress + operator-attributable outbound.

    T1 ingress path: TUI adapter + operator role via _ingest_tier()
    (src/alfred/identity/_ingest.py). T1 outbound is TUI stdout only
    in Slice 3. Discord is broadcast-shaped and never reaches T1.
    See spec §3.1 and §3.6.
    """

    name = "T1"


class T2(TrustTier):
    """Authenticated tier: known users."""

    name = "T2"


class T3(TrustTier):
    """Untrusted ingestion tier: web fetch, email, file, MCP tool output.

    tag(T3, ...) is capability-gated via a per-process nonce token
    (spec §3.2). The quarantined LLM is the only legitimate T3 producer
    in Slice 3. T3 bytes never reach the privileged orchestrator directly;
    the orchestrator holds ContentHandle references only.
    See spec §3.1, §3.2, and §7.3.
    """

    name = "T3"


# ---------------------------------------------------------------------------
# CapabilityGateNonce — per-process opaque token for the tag(T3) gate.
# ---------------------------------------------------------------------------


class CapabilityGateNonce:
    """Per-process opaque nonce token for the tag(T3, ...) capability gate.

    Constructed once by ``src/alfred/bootstrap/nonce_factory.py`` and
    distributed via dependency injection to exactly two authorised call
    sites: ``StdioTransport`` (PR-S3-3a) and ``quarantine_host`` (PR-S3-4).

    The gate compares by identity (Python ``is``, not ``==``). Constructing
    your own ``CapabilityGateNonce`` yields a different object that fails
    the ``is`` check — this closes the import-copy-and-call attack.

    The ``gc.get_objects()`` traversal attack (locating the live nonce in
    the GC heap and passing it) is acknowledged as out-of-scope: an
    adversary with that capability already has full process compromise.
    The adversarial corpus labels this ``tl_gc_traversal_out_of_scope``.
    See spec §3.2.
    """

    __slots__ = ()  # no attributes; identity is the only meaningful property


# Module-level "authorised" nonce slot — set once at bootstrap by
# alfred.bootstrap.nonce_factory.create_and_register_t3_nonce(). Tests
# install fixture state via the ``authorized_t3_nonce`` pytest fixture
# in tests/unit/security/conftest.py; the per-call ``_authorized_nonce=``
# seam was removed in CR-138 finding #7 because it codified a bypass
# of the bootstrap-registered capability into the public function
# signature.
_AUTHORIZED_T3_NONCE: CapabilityGateNonce | None = None

_log_t3 = structlog.get_logger(__name__)


def _set_authorized_t3_nonce(nonce: CapabilityGateNonce | None) -> None:
    """Bootstrap seam: called once by ``alfred.bootstrap.nonce_factory``.

    Sets the module-level authorised nonce. Tests call this to reset to
    ``None`` between runs (the test fixture pattern); the production caller
    is the bootstrap factory.
    """
    # Module-level bootstrap seam — the ONE legitimate `global` in this
    # module. The pattern is locked by spec §3.2; ruff's PLW0603 rule is
    # not enabled in this project so no noqa needed.
    global _AUTHORIZED_T3_NONCE
    _AUTHORIZED_T3_NONCE = nonce


@runtime_checkable
class AnyTaggedContent(Protocol):
    """Read-only view of any TaggedContent regardless of tier parameter.

    Observer code — audit writers, logging, DLP scanners — takes
    AnyTaggedContent rather than a concrete TaggedContent[T] to avoid
    cast() proliferation that the generic variance gap would otherwise
    force. Mutators take the concrete TaggedContent[T].

    A ruff/grep CI rule (scripts/check_tag_t3.py — lands in a follow-up
    task) rejects ``cast(TaggedContent[`` in non-test src/ files to
    prevent observers from re-acquiring a concrete generic type and
    discarding provenance. See spec §3.3.

    All four members are declared as read-only ``@property`` in the
    Protocol so type checkers refuse observer code that tries to
    rebind ``c.content = "..."`` or similar. ``metadata`` returns
    ``Mapping[str, Any]`` (not ``dict[str, Any]``) so observers cannot
    statically mutate the metadata dict either — the static surface
    is the contract. NOTE: Python's runtime ``isinstance`` against a
    ``runtime_checkable`` Protocol only checks attribute presence, not
    descriptor shape, so a class with mutating attributes still passes
    ``isinstance``. The Mapping return type is the load-bearing
    static-typing fix; the property declarations document intent.
    CR-138 finding #6.
    """

    @property
    def content(self) -> str: ...

    @property
    def source(self) -> str: ...

    @property
    def tier(self) -> type[TrustTier]: ...

    @property
    def metadata(self) -> Mapping[str, Any]: ...


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
        """Reject any tier outside the Slice-3 closed allowlist.

        Defence in depth at the data-class boundary, matching the runtime
        guard in ``tag()``. Four checks (the fourth is cross-tier):

        1. Pydantic's ``is_subclass_of`` check (driven by the
           ``type[TrustTier]`` annotation) already rejects non-TrustTier
           classes and non-class values — the static half of the gate.
        2. Empty ``name`` would persist "" into the audit log — reject it.
        3. The class must be one of ``_APPROVED_TIERS``. The closed PRD §7.1
           tier model is {T0, T1, T2, T3}; any other subclass — even a
           properly-named one — is rejected.
        4. If this class was parameterised (``TaggedContent[T2]``) the
           generic argument must match the resolved tier. Closes the wire
           "tier-laundering" attack (spec §3.5) where a payload claims
           ``tier="T3"`` against a consumer expecting ``TaggedContent[T2]``.
           Pydantic v2 preserves the generic args on the parameterised
           class via ``__pydantic_generic_metadata__["args"]``; the
           non-parameterised base form leaves ``args`` empty, so the
           check is skipped for legacy untyped construction sites.
        """
        if not value.name:
            raise ValueError(
                f"TrustTier subclass {value.__name__} must set a non-empty `name`",
            )
        if value not in _APPROVED_TIERS:
            approved = sorted(t_cls.name for t_cls in _APPROVED_TIERS)
            raise ValueError(
                f"unsupported trust tier for this build: {value.name!r} (approved: {approved})"
            )
        # Cross-tier guard: the generic argument (when present) MUST match.
        # __pydantic_generic_metadata__["args"] is a tuple of the type
        # parameters supplied to the parameterised class; for the
        # unparameterised base TaggedContent it is empty. Pydantic v2 always
        # populates this attribute on BaseModel subclasses — accessed directly
        # without a None guard.
        args = cls.__pydantic_generic_metadata__.get("args", ()) or ()
        if args:
            expected_tier = args[0]
            # ``expected_tier`` may be a TypeVar on the unparameterised base
            # (which we already short-circuit via the empty-args branch);
            # only enforce when it is a concrete TrustTier subclass.
            if (
                isinstance(expected_tier, type)
                and issubclass(expected_tier, TrustTier)
                and value is not expected_tier
            ):
                raise ValueError(
                    "cross-tier wire payload rejected: declared "
                    f"{value.name!r} but parser expects "
                    f"{expected_tier.name!r} (spec §3.5)"
                )
        return value

    @model_serializer(mode="plain")
    def _serialize_with_tier_name(self) -> dict[str, Any]:
        """Emit ``tier`` as ``tier.name`` (string) for wire transport (spec §3.5).

        Mode is ``plain`` (not ``wrap``) because the default field
        serialiser cannot encode ``type[TrustTier]`` into JSON — the
        ``arbitrary_types_allowed=True`` flag lets the class object live
        on the model but excludes it from any wire format. A ``plain``
        serializer fully owns the output shape, which is what the wire
        contract needs anyway.

        Cross-tier confusion — a Python ``TaggedContent[T3]`` serialised
        with ``tier="T2"`` — is impossible here because we read
        ``self.tier.name`` directly off the instance. The cross-tier attack
        lands at deserialisation: a wire payload claiming ``T2`` but whose
        content was T3-derived. The ``_validate_tier`` field validator
        (above) and the ``_resolve_tier_from_wire`` model validator (below)
        together close that path.
        """
        return {
            "content": self.content,
            "source": self.source,
            "tier": self.tier.name,
            "metadata": dict(self.metadata),
        }

    @model_validator(mode="before")
    @classmethod
    def _resolve_tier_from_wire(cls, data: Any) -> Any:
        """Resolve a wire-format tier string to a TrustTier subclass on parse.

        Two-stage rejection (spec §3.5):

        - Unknown tier string (``"TX_UNKNOWN"``) → ``ValueError`` here.
        - Known-but-mismatched-with-generic-parameter → caught by
          ``_validate_tier`` after the string resolves.

        Inputs that already supply a TrustTier subclass (the in-process
        ``TaggedContent[T2](..., tier=T2)`` form) pass through unchanged.
        """
        if isinstance(data, dict) and isinstance(data.get("tier"), str):
            tier_name = data["tier"]
            resolved = _tier_by_name(tier_name)
            if resolved is None:
                approved = sorted(t_cls.name for t_cls in _APPROVED_TIERS)
                raise ValueError(
                    f"unknown trust tier on wire: {tier_name!r} (approved: {approved})"
                )
            data = {**data, "tier": resolved}
        return data


# Slice 3 adds T1 (operator) and T3 (untrusted ingestion) alongside the
# dual-LLM split. The closed T0..T3 tier model in PRD §7.1 / ADR-0017 is
# now fully populated; any TrustTier subclass outside this frozenset is
# rejected at both the `tag()` boundary and the `_validate_tier` field
# validator. See spec §3.1.
_APPROVED_TIERS: frozenset[type[TrustTier]] = frozenset({T0, T1, T2, T3})


def _tier_by_name(name: str) -> type[TrustTier] | None:
    """Look up an approved TrustTier subclass by its wire-format name.

    Returns ``None`` for any name not in ``_APPROVED_TIERS`` so the caller
    can raise a context-aware ``ValueError`` (spec §3.5 cross-tier
    rejection). The linear scan is fine — ``_APPROVED_TIERS`` is bounded
    at four entries by the closed PRD §7.1 tier model.
    """
    for tier in _APPROVED_TIERS:
        if tier.name == name:
            return tier
    return None


@overload
def tag(
    tier: type[T0], content: str, *, source: str = "unspecified", **metadata: Any
) -> TaggedContent[T0]: ...


@overload
def tag(
    tier: type[T1], content: str, *, source: str = "unspecified", **metadata: Any
) -> TaggedContent[T1]: ...


@overload
def tag(
    tier: type[T2], content: str, *, source: str = "unspecified", **metadata: Any
) -> TaggedContent[T2]: ...


@overload
def tag(
    tier: type[T3], content: str, *, source: str = "unspecified", **metadata: Any
) -> TaggedContent[T3]: ...


def tag(
    tier: type[TrustTier], content: str, *, source: str = "unspecified", **metadata: Any
) -> TaggedContent[Any]:
    """Tag content with a trust tier at an ingestion boundary.

    ``content`` is positional so call sites read naturally::

        tag(T2, user_text, source="comms.tui.input")

    ``source`` is optional; supply it at every real ingestion site (the
    audit log records it) but defaults exist so quick test fixtures don't
    have to repeat it.

    Routing:

    - ``tag(T0, ...)`` / ``tag(T1, ...)`` / ``tag(T2, ...)`` go through
      the open construction path below.
    - ``tag(T3, ...)`` routes through ``tag_t3_with_nonce`` with
      ``caller_token=None``, which always raises. Authorised call sites
      bypass ``tag()`` and call ``tag_t3_with_nonce`` directly with their
      injected ``CapabilityGateNonce``. This makes ``tag(T3, ...)`` an
      always-loud refusal — direct callers cannot accidentally produce
      T3 content. Spec §3.2.
    """
    if tier is T3:
        # Route through the capability gate. Direct callers without a
        # nonce receive ValueError. Authorised call sites use
        # tag_t3_with_nonce() with their injected token.
        return tag_t3_with_nonce(
            content,
            source=source,
            caller_token=None,  # direct tag(T3, ...) is always refused
            **metadata,
        )
    if tier not in _APPROVED_TIERS:
        approved = sorted(t_cls.name for t_cls in _APPROVED_TIERS)
        raise ValueError(
            f"unsupported trust tier for this build: "
            f"{getattr(tier, 'name', tier)!r} (approved: {approved})"
        )
    return TaggedContent[tier](  # type: ignore[valid-type]
        content=content, source=source, tier=tier, metadata=dict(metadata)
    )


def tag_t3_with_nonce(
    content: str,
    source: str = "unspecified",
    *,
    caller_token: CapabilityGateNonce | None,
    **metadata: Any,
) -> TaggedContent[T3]:
    """Tag content with the T3 (untrusted) tier — capability-gated.

    The caller must pass the exact ``CapabilityGateNonce`` object that
    was distributed to them at bootstrap via dependency injection. The
    check uses Python ``is`` (identity), not ``==`` (equality), so a
    re-constructed or imported-value copy cannot forge the gate. Spec §3.2.

    The authorised nonce comes from the module-level
    ``_AUTHORIZED_T3_NONCE`` slot, set exactly once at process start by
    ``alfred.bootstrap.nonce_factory.create_and_register_t3_nonce()``.
    Tests install fixture state via the ``authorized_t3_nonce`` pytest
    fixture (``tests/unit/security/conftest.py``); the pre-CR-138 per-
    call ``_authorized_nonce=`` test-injection seam was removed because
    any caller could pass the same object as both ``caller_token`` and
    ``_authorized_nonce`` and defeat the gate. CR-138 finding #7.

    Raises:
        ValueError: when ``caller_token`` is ``None`` or is not the
            authorised nonce. The message contains the i18n key
            ``security.tag_t3_unauthorized`` per i18n rule #1. A
            structlog warning ``security.t3_boundary.refused`` is also
            emitted; the full AuditWriter wiring lands in PR-S3-4.
    """
    authorized = _AUTHORIZED_T3_NONCE
    if caller_token is None or caller_token is not authorized:
        # Best-effort frame-derived caller label for forensics only — NOT
        # a security gate. Spec §3.2 is explicit: frame introspection is
        # forgeable via sys.modules manipulation, so it must NEVER
        # influence the allow/deny decision. The gate is the identity
        # check above; this label is purely so audit reviewers can see
        # *something* about the failed call site. An attacker who forges
        # sys.modules will see their forged label in the audit row — that
        # is by design (unverified = forensic, not authoritative).
        import sys

        # sys._getframe is "private" but stable CPython API; ruff's SLF001
        # private-member-access rule is not enabled here. The use is
        # forensic-only — see the block comment above.
        frame = sys._getframe(1)
        caller_module_unverified = frame.f_globals.get("__name__", "<unknown>")
        _log_t3.warning(
            "security.t3_boundary.refused",
            caller_module_unverified=caller_module_unverified,
            attempted_tier="T3",
        )
        raise ValueError(t("security.tag_t3_unauthorized", caller=caller_module_unverified))
    return TaggedContent[T3](
        content=content,
        source=source,
        tier=T3,
        metadata=dict(metadata),
    )

"""Trust-tier types for AlfredOS.

The closed tier model (PRD §7.1 / ADR-0017): {T0, T1, T2, T3}.

Slice 3 adds T1 (operator) and T3 (untrusted ingestion) alongside the
dual-LLM split. The ``tag(T3, ...)`` factory is capability-gated by a
per-process nonce token — see ``CapabilityGateNonce`` and spec §3.2.

Minting a T3 object off the nonce path is refused at every seam pydantic exposes
(#518): the validating path via ``_enforce_tier_admissible``, and the seams that skip
validation — ``model_construct``, ``model_copy``, the deprecated ``copy`` — via
module-level guard dispatch a subclass cannot intercept. ``__init_subclass__`` closes
subclassing, which is otherwise a lever on the validator itself.

Three layers, each closing what the one before cannot:

1. ``_enforce_tier_admissible`` via the ``tier`` field validator — the validating path.
2. ``model_post_init`` — EVERY construction, including
   ``BaseModel.model_construct.__func__(cls, ...)``, because pydantic invokes
   ``cls.model_post_init`` from inside the base implementation. Also the check that
   survives the field validator being dropped by a refactor.
3. ``model_construct`` / ``model_copy`` / ``copy`` overrides plus ``__init_subclass__``,
   dispatching through module-level functions no subclass can rebind.

**Named residual — still ADMITTED (exactly two spellings):**

``BaseModel.copy(obj, update={"tier": T3})`` and
``BaseModel.model_copy(obj, update={"tier": T3})`` on an EXISTING instance. Both build
the result through ``_copy_and_set_values`` / ``__dict__.update``, which reach neither
the overrides nor ``model_post_init`` (verified across all six dispatch shapes), and
``object.__setattr__`` / ``__setstate__`` writes, which never traverse ``__setattr__``
so ``frozen=True`` cannot observe them.

Governing limit: every one of these requires either arbitrary in-process code execution
in the privileged orchestrator — already accepted as out of scope by spec §3.2 and corpus
``tl-2026-003``, and an attacker with it can simply call
``_T3_CONSTRUCTION_AUTHORIZED.set(True)`` and use the front door — or a line written into
``src/``, which is an AUTHORING risk. So the layer that matters for the residual is the
commit-time detector, not another runtime guard.

``obj.__dict__["tier"] = T3`` and ``BaseModel.model_copy`` are interceptable by
installing a guarded ``dict`` subclass as the instance ``__dict__``; deliberately not
done, because it breaks pydantic's own ``__copy__`` (which round-trips through
``__dict__`` assignment) while ``object.__setattr__`` stays open regardless.

``scripts/check_tag_t3.py`` refuses these spellings as of #538, and it is the ONLY
enforcement layer they will ever have. An earlier revision of this paragraph prescribed
keying the rule on the written ``"tier"`` attribute rather than refusing
``object.__setattr__``, whose bare form is an established idiom here
(``src/alfred/plugins/web_fetch/allowlist.py``,
``src/alfred/plugins/web_fetch/fetch_dispatcher.py``, ``src/alfred/hooks/context.py``).
That design is defeated BY CONSTRUCTION: ``object.__setattr__(obj, "__dict__", {"tier":
T3})`` writes ``__dict__`` and never names ``tier`` at all. The shipped rules
default-deny the VEHICLE and the CALL SHAPE instead — the vehicle dunders, ``vars()``,
``__class__`` in store context, a vehicle name written as a folded string, the
carrier-by-reference primitives, unbound ``BaseModel`` seam dispatch, and this module's
own private surface — while the three live sites above stay clean because none of them
writes a ``_TAGGED_STATE_FIELDS`` name. Corpus ``tl-2026-013`` carries the accepted
residuals; the gate's module docstring carries the same list next to the rules.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextvars import ContextVar
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

# Defined above its first use in ``_refuse_unauthorized_t3`` below.
_log_t3 = structlog.get_logger(__name__)

# #518: the nonce gate lived in ``tag_t3_with_nonce`` alone, so the MODEL never
# asked whether the caller held it. Seven constructions could therefore mint a
# T3-tagged object without ever passing the gate — bare keyword, ``model_construct``,
# ``model_validate``, ``model_validate_json``, ``model_copy(update=...)``, a renamed
# import, and a non-literal generic argument. A static detector can only catch the
# shapes it was taught; this closes the whole class at runtime.
#
# A ContextVar, not a module flag: the core is async, and a flag would leak
# authorisation across concurrently-running tasks. Set (and reset) exclusively around
# the single authorised construction at the end of ``tag_t3_with_nonce``.
_T3_CONSTRUCTION_AUTHORIZED: ContextVar[bool] = ContextVar(
    "alfred_t3_construction_authorized", default=False
)


_FORENSIC_FRAME_LIMIT: int = 64

# Whole PACKAGES to skip when labelling a refusal — dispatch machinery, never the code
# that decided to construct. A label of ``pydantic.main`` names the framework, which
# tells an incident responder exactly as little as naming this module did.
#
# ``pydantic`` only. An earlier revision skipped ``__name__.partition(".")[0]`` — i.e.
# the whole ``alfred`` package — which meant every FIRST-PARTY caller was skipped and the
# label walked past the real ingestion boundary entirely (verified: a caller in
# ``alfred.plugins.web_fetch.*`` was reported as ``__main__``). Naming first-party
# callers is the entire purpose of the field. The unit tests could not see this because
# they live in ``tests.*``, outside the ``alfred`` package — hence
# ``test_a_first_party_alfred_caller_is_named``.
_FORENSICALLY_OPAQUE_PACKAGES: frozenset[str] = frozenset({"pydantic"})


def _is_forensically_opaque(module: str) -> bool:
    """True when ``module`` is dispatch machinery rather than a decision-making caller.

    This module is skipped by EXACT name so sibling first-party modules
    (``alfred.security.quarantine``, ``alfred.plugins.*``) remain nameable.
    """
    return module == __name__ or module.partition(".")[0] in _FORENSICALLY_OPAQUE_PACKAGES


def _nearest_foreign_module() -> str:
    """Name the closest stack frame outside the dispatch machinery, for forensics only.

    Was ``sys._getframe(2)`` — a hard-coded depth, which silently degraded the moment
    the guard grew an intermediate frame: the #518 follow-on refactor inserted
    ``_enforce_tier_admissible`` into the chain, depth 2 landed back inside this module,
    and every refusal reported ``alfred.security.tiers`` — the guard's own module — as
    the caller. The depth also differs per route (the ``model_construct`` seam and the
    pydantic field validator sit at different depths), so no single constant is correct
    for all of them.

    Skipping by PACKAGE rather than counting frames survives the next refactor. Both
    this module and ``pydantic`` are skipped: on the validating route pydantic-core
    calls the validator from Rust with ``BaseModel.__init__`` as the nearest Python
    frame, so a bare "first foreign module" walk reports ``pydantic.main`` on the most
    common ingestion path — the wire-deserialisation route — and names the framework
    instead of the caller.

    The label is FORENSIC ONLY and deliberately unverified — spec §3.2 is explicit that
    frame introspection is forgeable via ``sys.modules`` manipulation, so it must never
    influence the allow/deny decision. Callers decide allow/deny BEFORE calling this.
    """
    import sys

    # sys._getframe is "private" but stable CPython API; the use is forensic-only.
    # Bounded rather than ``while True``: a test double that patches ``sys._getframe``
    # to RETURN a frame instead of raising would otherwise spin forever, and a bounded
    # walk has identical behaviour on every real stack.
    #
    # Best-effort throughout, catching Exception not just ValueError: the refusal is the
    # security outcome, so nothing in this label may convert a clean refusal into an
    # unrelated exception type the callers' except-arms do not expect.
    try:
        for depth in range(1, _FORENSIC_FRAME_LIMIT):
            module = str(sys._getframe(depth).f_globals.get("__name__", "<unknown>"))
            if not _is_forensically_opaque(module):
                return module
    except Exception:
        return "<unknown>"
    # Stack exhausted (or bound reached) without leaving the dispatch machinery — the
    # authorised path already covers construction originating inside this module.
    return "<unknown>"


def _refuse_unauthorized_t3(tier: object) -> None:
    """Raise unless a T3 construction is happening inside the authorised path.

    Non-T3 tiers are untouched — the invariant is specifically that the untrusted
    tier cannot be minted off the capability gate (spec §3.2).

    The forensic record is written by :func:`_record_unauthorized_t3_attempt`, called
    earlier in :func:`_enforce_tier_admissible` so that it survives a competing
    admissibility message winning the raise. A refusal in a security path with no
    observable signal is a silent failure (hard rule #7) and an incident-response gap:
    these seams close the CLOSER class of bypasses, so a bug or a bad actor tripping
    ``model_construct(tier=T3)`` would otherwise get a clean ``ValueError`` and leave
    nothing in the audit stream.
    """
    if _is_unauthorized_t3(tier):
        raise ValueError(t("security.t3_construction_unauthorized"))


def _is_unauthorized_t3(tier: object) -> bool:
    """True when ``tier`` is the untrusted tier and no authorisation is in scope.

    ``issubclass``, not ``is``: ``class Spoof(T3)`` is still the untrusted tier for every
    practical purpose, and an identity check would have waved it through.
    ``isinstance(tier, type)`` first because ``issubclass`` raises on a non-class, and a
    bad value must reach the approved-tier check rather than crash here.
    """
    return isinstance(tier, type) and issubclass(tier, T3) and not _T3_CONSTRUCTION_AUTHORIZED.get()


def _record_unauthorized_t3_attempt(tier: object) -> None:
    """Emit the forensic record for an unauthorised T3 attempt, without raising.

    Split from :func:`_refuse_unauthorized_t3` so the record can be written BEFORE the
    admissibility checks choose which message to raise. Exactly one caller writes it, so
    a refusal still produces exactly one ``security.t3_boundary.refused`` event.
    """
    if not _is_unauthorized_t3(tier):
        return
    _log_t3.warning(
        "security.t3_boundary.refused",
        caller_module_unverified=_nearest_foreign_module(),
        attempted_tier="T3",
        gate="construction",
    )


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


# Attribute names a GENUINE pydantic parametrisation of TaggedContent defines. Calibrated
# at import from a real parametrisation (below the class body) rather than hard-coded, so
# it tracks pydantic's own set across versions instead of drifting against it. ``None``
# until then, because the calibrating parametrisation must itself be admitted.
_PARAMETRISATION_ATTRS: frozenset[str] | None = None

# Names a subclass must not redefine: each is a tier guard, and pydantic rebinds
# validator targets BY NAME off the subclass MRO, so redefining one replaces the parent's
# check inside the parent's own slot. Kept as data next to the class so adding a guard
# means adding it here — ``test_the_guard_name_set_covers_every_guard_on_the_class``
# reds if one is added to the class but not to this set.
#
# NO name-mangled entry: an earlier revision guarded a
# ``_TaggedContent__enforce_tier_invariant`` model validator, which a namespace could
# defeat by planting that literal string. ``model_post_init`` superseded it — it fires on
# strictly more paths, including inside ``BaseModel.model_construct`` — so the mangled
# name is now inert because the validator it named no longer EXISTS, not because it is
# listed here. Do not re-add it; that would imply a guard that is not there.
_TIER_GUARD_NAMES: frozenset[str] = frozenset(
    {
        "_validate_tier",
        "model_post_init",
        "_resolve_tier_from_wire",
        "model_construct",
        "model_copy",
        "copy",
    }
)


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

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Refuse subclassing outside this module (#518 follow-on).

        Pydantic rebinds ``@field_validator`` targets BY NAME off the subclass MRO
        (``Decorator.build`` → ``get_attribute_from_bases``). So a subclass that
        defines a plain ``_validate_tier`` replaces this class's guard inside this
        class's own registered validator slot — verified admitted: a subclass minted
        ``tier=T3`` with no refusal, no log and no exception. Every subclass is a lever
        on the guard, so the lever is removed rather than the individual holes patched.

        ``bcad7103`` closed subclassing of the TIER; this closes subclassing of the
        MODEL, which is the same defect class one level out.

        The discriminator is the defining MODULE. Pydantic's generic parametrisation
        (``TaggedContent[T3]``) creates a real subclass, but
        ``_generics.create_generic_submodel`` builds it with
        ``namespace = {"__module__": origin.__module__}`` — so a parametrisation always
        reports THIS module, wherever in the codebase it is written (verified for all
        four tiers, at module scope, function-local, and from a foreign module). A
        ``class`` statement elsewhere reports its own module.

        An earlier revision also required ``cls.__name__.isidentifier()``, on the theory
        that a parametrisation is named ``"TaggedContent[T3]"`` and a class statement
        cannot be. That conjunct was strictly WEAKER and has been dropped: it admitted
        ``type("evil[x]", (TaggedContent,), {...})``, which forges a non-identifier name,
        and it made the guard depend on pydantic's cosmetic naming. The module check
        alone admits every parametrisation and refuses the forged-name subclass.

        ``__pydantic_generic_metadata__`` is NOT usable here: at ``__init_subclass__``
        time a parametrisation still reports ``origin=None``, identical to
        ``class Kid(TaggedContent)``.

        Zero subclasses exist in ``src/``, ``tests/`` or ``plugins/``, so this costs
        nothing today.

        THREE conditions, because each earlier one leaves a hole the next closes:

        1. **A foreign defining module** — the ordinary case.
        2. **A namespace redefining a name in :data:`_TIER_GUARD_NAMES`**, EVEN from this
           module. A namespace forging ``__module__`` passes condition 1, so without this
           it could still shadow ``_validate_tier`` or ``model_post_init``. Checked first
           of the two namespace rules so guard shadowing gets its own precise diagnostic
           rather than the generic one below.
        3. **A namespace defining ANYTHING a genuine parametrisation does not** — the
           catch-all. Conditions 1-2 together still admitted a forged-``__module__``
           subclass that overrode ``__init__``: pydantic's ``__init__`` is where
           validation and ``model_post_init`` are invoked, so replacing it skipped both
           and minted T3 (verified admitted; ``__new__`` and ``__setattr__`` did NOT,
           because construction still routes through ``__init__``).

           Enumerating lifecycle hooks would have fixed the three names someone thought
           of. Default-denying the namespace closes the class — including hooks nobody
           has thought of yet, which is the failure mode this epic keeps hitting.

           The allow-list is CALIBRATED at import from a real parametrisation rather than
           hard-coded, so it tracks pydantic's own attribute set instead of drifting
           against it.
        """
        super().__init_subclass__(**kwargs)
        shadowed_guards = sorted(_TIER_GUARD_NAMES & set(vars(cls)))
        if shadowed_guards:
            raise TypeError(
                t(
                    "security.tagged_content_guard_shadow_refused",
                    subclass=cls.__name__,
                    guards=", ".join(shadowed_guards),
                )
            )
        # ``None`` while this module is still initialising: the calibrating
        # parametrisation below the class body has to be admitted to be measured.
        if _PARAMETRISATION_ATTRS is not None:
            user_defined = sorted(set(vars(cls)) - _PARAMETRISATION_ATTRS)
            if user_defined:
                raise TypeError(
                    t(
                        "security.tagged_content_namespace_refused",
                        subclass=cls.__name__,
                        attributes=", ".join(user_defined),
                    )
                )
        if cls.__module__ != __name__:
            raise TypeError(
                t(
                    "security.tagged_content_subclass_refused",
                    subclass=cls.__name__,
                    module=cls.__module__,
                )
            )

    def model_post_init(self, context: Any, /) -> None:
        """Re-check the tier invariant on EVERY construction, however it was dispatched.

        Layer B. Pydantic invokes ``cls.model_post_init`` from inside
        ``BaseModel.model_construct`` itself, so this fires even when the caller reaches
        the base implementation directly —
        ``BaseModel.model_construct.__func__(TaggedContent[T3], ...)`` was a verified
        bypass of every class-level override and is closed here. Verified by execution
        across all six dispatch shapes.

        It also runs on the validating path, so it is the check that survives the FIELD
        VALIDATOR going missing (a refactor dropping ``@field_validator("tier")``).
        That makes it strictly stronger than the name-mangled ``model_validator`` it
        replaced, and one guard rather than two redundant ones.

        Reads ``__dict__`` rather than ``self.tier``: ``model_construct`` may omit the
        field entirely, and an absent tier is pydantic's concern, not a security event.

        ``model_post_init`` is itself a class attribute, so it is in
        :data:`_TIER_GUARD_NAMES` — a subclass redefining it is refused at class creation.

        NOT closed by this: ``BaseModel.copy`` / ``BaseModel.model_copy`` on an existing
        instance, which build the new object through ``_copy_and_set_values`` /
        ``__dict__.update`` and never reach this hook (verified), and raw
        ``object.__setattr__`` / ``__setstate__`` writes. See the module docstring.
        """
        super().model_post_init(context)
        _guard_tier_value(type(self), self.__dict__.get("tier"))

    @field_validator("tier")
    @classmethod
    def _validate_tier(cls, value: type[TrustTier]) -> type[TrustTier]:
        """Reject any tier outside the Slice-3 closed allowlist.

        Delegates to the module-level :func:`_enforce_tier_admissible` so there is ONE
        source of truth that a subclass cannot intercept. Four checks (the fourth is
        cross-tier):

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
        return _enforce_tier_admissible(cls, value)

    @classmethod
    def model_construct(
        cls, _fields_set: set[str] | None = None, **values: Any
    ) -> TaggedContent[TierT]:
        """Guarded ``model_construct`` (#518).

        Pydantic's ``model_construct`` skips validation ENTIRELY — it exists to build
        a model from data already known to be valid. That makes it the sharpest of the
        seven bypasses: the field validator above never runs. Re-checking here keeps
        the invariant true for every construction route, not merely the validating ones.

        Calls the module-level guard DIRECTLY, not ``cls._assert_tier_admissible`` — a
        subclass owns that attribute lookup and shadowing it disabled this seam
        entirely (verified admitted, #518 follow-on).
        """
        _guard_tier_value(cls, values.get("tier"))
        return super().model_construct(_fields_set, **values)

    def model_copy(
        self, *, update: Mapping[str, Any] | None = None, deep: bool = False
    ) -> TaggedContent[TierT]:
        """Guarded ``model_copy`` (#518).

        ``model_copy`` does not re-validate, so ``update={"tier": T3}`` silently
        upgraded a lower-tier object to untrusted. The most plausible accident of the
        seven — an author copies an object and edits the tier, never touching a
        function the gate protects.
        """
        coerced = _coerce_and_guard_update(type(self), update)
        return super().model_copy(update=coerced, deep=deep)

    def copy(
        self, *, update: Mapping[str, Any] | None = None, deep: bool = False, **kwargs: Any
    ) -> TaggedContent[TierT]:
        """Guarded deprecated ``copy`` (#518 follow-on).

        ``BaseModel.copy`` does NOT route through ``model_copy``: it merges ``update``
        inside ``copy_internals`` and writes ``__dict__`` via ``_copy_and_set_values``,
        so the ``model_copy`` override was never consulted. Verified admitted —
        ``low.copy(update={"tier": T3})`` produced a ``TaggedContent[T2]`` whose runtime
        tier read ``T3``, i.e. the cross-tier laundering of spec §3.5 with the static
        type still claiming the lower tier.

        Guarding it rather than removing it: the base method stays reachable whatever we
        do here, so the guard has to sit on the same name.

        ``include``/``exclude`` can only NARROW the field set, but narrowing can drop
        ``tier`` — ``copy(exclude={"tier"})`` returned a ``TaggedContent`` with no tier
        at all, so ``getattr(obj, "tier", default)`` silently yielded the default and the
        object's provenance was gone. Refused: a tagged-content object without its tag is
        not a narrower view, it is an untagged payload.
        """
        _refuse_if_tier_is_narrowed_away(kwargs)
        coerced = _coerce_and_guard_update(type(self), update)
        return super().copy(update=coerced, deep=deep, **kwargs)

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
                    t(
                        "security.tier_unknown_wire",
                        tier_name=tier_name,
                        approved=", ".join(approved),
                    )
                )
            data = {**data, "tier": resolved}
        return data


# Calibrate the namespace allow-list from a real parametrisation — AFTER the class body,
# BEFORE any other subclass exists. T0 is arbitrary; every tier yields the same attribute
# set (verified for all four). `test_the_parametrisation_allow_list_is_calibrated` pins it.
_PARAMETRISATION_ATTRS = frozenset(vars(TaggedContent[T0]))


def _guard_tier_value(owner: type[BaseModel], tier: object) -> None:
    """Module-level tier guard for the seams pydantic does not validate.

    Module-level, and called as a plain function rather than through ``cls.``: a
    subclass controls every attribute lookup made through the class. The previous
    ``cls._assert_tier_admissible(...)`` dispatch was shadowable, and shadowing it
    disabled ``model_construct`` and ``model_copy`` entirely (verified admitted, #518
    follow-on). That classmethod is deliberately GONE rather than kept as a delegating
    alias: leaving a shadowable entry point in place is the footgun a future author
    reaches for, and it is how the hole was made the first time.

    A ``None`` tier is treated as "field absent" and passed over: ``model_construct``
    may legitimately omit a field and pydantic owns required-field handling, so raising
    would turn a pydantic concern into a spurious security refusal. Note this leaves
    ``model_construct(tier=None)`` producing a tier-less object — it satisfies no
    ``.tier is T3`` test and crashes any ``.tier.name`` read, so it fails closed rather
    than laundering, and it is pydantic's contract for the unvalidated seam.
    """
    if tier is None:
        return
    _enforce_tier_admissible(owner, tier)


_MAX_FORENSIC_REPR: int = 120


def _bounded_repr(value: object) -> str:
    """``repr(value)`` truncated, for a log field derived from attacker-influenced input.

    An unbounded ``repr`` of a hostile object (a megabyte string, a class with a
    pathological ``__repr__``) floods the audit stream from a security path. ``repr``
    itself may raise, and a refusal must not become an unrelated crash.
    """
    try:
        text = repr(value)
    except Exception:
        return "<unreprable>"
    if len(text) <= _MAX_FORENSIC_REPR:
        return text
    return text[:_MAX_FORENSIC_REPR] + "…<truncated>"


def _refuse_if_tier_is_narrowed_away(kwargs: Mapping[str, Any]) -> None:
    """Refuse a deprecated-``copy`` field selection that would drop ``tier``.

    ``include={"content"}`` or ``exclude={"tier"}`` yields a ``TaggedContent`` carrying no
    tier, so ``getattr(obj, "tier", fallback)`` silently returns the fallback and the
    provenance a trust-boundary object exists to carry is simply gone. Narrowing away the
    tag is not a narrower view of tagged content.
    """
    exclude = kwargs.get("exclude")
    include = kwargs.get("include")
    drops_tier = (exclude is not None and "tier" in exclude) or (
        include is not None and "tier" not in include
    )
    if drops_tier:
        raise ValueError(t("security.tagged_content_tier_not_selectable"))


def _coerce_and_guard_update(
    owner: type[BaseModel], update: Mapping[str, Any] | None
) -> dict[str, Any] | None:
    """Coerce a caller's ``update`` mapping ONCE, then guard the coerced copy.

    The previous form tested ``"tier" in update`` on the CALLER's mapping and then
    passed ``dict(update)`` to the base implementation — two reads of an object the
    caller controls. A ``Mapping`` whose ``__contains__`` returns False while iteration
    yields ``tier`` split the check from the value actually applied, and was verified
    admitted. Coercing first collapses the two reads into one.
    """
    if update is None:
        return None
    coerced = dict(update)
    if "tier" in coerced:
        # An EXPLICIT ``{"tier": None}`` is an erasure, not an absent field.
        # ``_guard_tier_value`` passes ``None`` over (correctly — ``model_construct`` may
        # legitimately omit a field), so routing it there let an update strip the tag off
        # an existing T3 object and leave a tier-less TaggedContent whose
        # ``getattr(obj, "tier", fallback)`` silently yields the fallback. Same outcome as
        # narrowing the field away, so the same refusal.
        if coerced["tier"] is None:
            raise ValueError(t("security.tagged_content_tier_not_selectable"))
        _guard_tier_value(owner, coerced["tier"])
    return coerced


def _enforce_tier_admissible(owner: type[BaseModel], value: object) -> type[TrustTier]:
    """The single source of truth for tier admissibility (#518 follow-on).

    Extracted from ``TaggedContent._validate_tier`` so that no enforcement path
    depends on an attribute a subclass can rebind. ``owner`` supplies the generic
    metadata for the cross-tier check.

    ``value`` is typed ``object``, not ``type[TrustTier]``: the unvalidated seams hand it
    through without pydantic coercion, so a wire string or an int genuinely arrives here.
    Annotating the narrower type made the runtime guard below provably unreachable to
    mypy while it was very much reachable at runtime.
    """
    # A non-class or non-TrustTier value reaches here only from the unvalidated seams
    # (``model_construct``/``model_copy``/``copy``), where pydantic never coerced it.
    # Reading ``value.name`` on e.g. the wire string ``"T3"`` raised a bare
    # ``AttributeError`` — an untyped crash with NO audit row, from a security path.
    # Refuse it through the normal typed+logged route instead.
    if not (isinstance(value, type) and issubclass(value, TrustTier)):
        # A DISTINCT event, not ``security.t3_boundary.refused``: that one means "someone
        # tried to mint T3 off the gate" and its count is the forensic signal for exactly
        # that. Emitting it for a garbage value conflated the two and inflated the T3
        # accounting with non-T3 events.
        #
        # The value is attacker-influenced, so the label is TYPE plus a length-bounded
        # repr — an unbounded repr() of a hostile object floods the audit stream.
        _log_t3.warning(
            "security.tier_boundary.refused_invalid_type",
            caller_module_unverified=_nearest_foreign_module(),
            attempted_tier_type=type(value).__name__,
            attempted_tier_repr=_bounded_repr(value),
            gate="construction",
        )
        approved = sorted(t_cls.name for t_cls in _APPROVED_TIERS)
        raise ValueError(
            t(
                "security.tier_unsupported",
                tier_name=_bounded_repr(value),
                approved=", ".join(approved),
            )
        )
    # A T3 attempt off the authorised path gets its forensic record HERE, before the
    # message-selection order below. The cross-tier check raises first for the most
    # plausible attack (upgrading a parameterised ``TaggedContent[T2]``), which
    # pre-empted ``_refuse_unauthorized_t3`` and left that refusal with NO audit row at
    # all — a silent failure in a security path (hard rule #7). Logging here and raising
    # below keeps the better cross-tier DIAGNOSTIC while still emitting the record.
    _record_unauthorized_t3_attempt(value)
    if not value.name:
        # arch-003 (slice-3 retrospective): catalog-key i18n. The
        # operator may not read English; the audit row carries the
        # raw key so a non-English UI can re-render at display time.
        raise ValueError(
            t(
                "security.tier_subclass_missing_name",
                subclass=value.__name__,
            )
        )
    # IDENTITY, not ``in``: set membership consults ``__hash__``/``__eq__``, which a
    # metaclass on an attacker-supplied TrustTier subclass controls — it could report
    # equal to T2 and be admitted while being a different class. The closed PRD §7.1
    # model means these four exact objects.
    if not any(value is approved_tier for approved_tier in _APPROVED_TIERS):
        approved = sorted(t_cls.name for t_cls in _APPROVED_TIERS)
        raise ValueError(
            t(
                "security.tier_unsupported",
                tier_name=value.name,
                approved=", ".join(approved),
            )
        )
    # Cross-tier guard: the generic argument (when present) MUST match.
    # __pydantic_generic_metadata__["args"] is a tuple of the type
    # parameters supplied to the parameterised class; for the
    # unparameterised base TaggedContent it is empty. Pydantic v2 always
    # populates this attribute on BaseModel subclasses, and every caller passes ``cls`` or
    # ``type(self)``, so the lookup needs no None guard — an earlier ``owner is None`` arm
    # was unreachable, and a same-line ternary records no branch arc for coverage, so the
    # 100%-branch gate could not see that it was dead.
    args = owner.__pydantic_generic_metadata__.get("args", ()) or ()
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
                t(
                    "security.tier_mismatch",
                    got=value.name,
                    expected=expected_tier.name,
                )
            )
    # #518: the nonce gate is a property of the TIER, not of one function, so it
    # is enforced here — where every validating construction passes — rather than
    # only in ``tag_t3_with_nonce``. ``model_construct`` and ``model_copy`` skip
    # validation by design and are guarded separately.
    #
    # LAST, deliberately. When a wire payload claims T3 against a T2-expecting
    # consumer both this and the cross-tier guard above apply, and the cross-tier
    # message is the more useful one — it names both tiers and identifies the
    # laundering attack (spec §3.5). Checking first would shadow that diagnostic
    # with a generic "unauthorized construction" for an attack the corpus has a
    # dedicated case for.
    _refuse_unauthorized_t3(value)
    return value


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
            t(
                "security.tier_unsupported",
                tier_name=getattr(tier, "name", str(tier)),
                approved=", ".join(approved),
            )
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
    # The sole authorised T3 construction (#518). The token is set immediately around
    # it and reset in ``finally``, so an exception mid-construction cannot leave a
    # context authorised for later unrelated work.
    token = _T3_CONSTRUCTION_AUTHORIZED.set(True)
    try:
        return TaggedContent[T3](
            content=content,
            source=source,
            tier=T3,
            metadata=dict(metadata),
        )
    finally:
        _T3_CONSTRUCTION_AUTHORIZED.reset(token)

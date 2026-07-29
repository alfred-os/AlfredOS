"""Minting seams #534 left open (#518 follow-on).

#534 closed seven constructions so a ``T3`` object could not be minted off the
``tag_t3_with_nonce`` capability gate. Reviewing the CI-detector follow-up surfaced
five MORE seams, each verified admitted against the merged guard:

1. ``obj.copy(update={"tier": T3})`` — pydantic's deprecated ``BaseModel.copy`` does
   NOT route through ``model_copy``; it merges ``update`` in ``copy_internals`` and
   writes ``__dict__`` directly, so the ``model_copy`` override was never consulted.
2. A subclass shadowing ``_validate_tier`` — pydantic rebinds ``@field_validator``
   targets BY NAME off the subclass MRO, so a subclass that redefines the validator
   replaces the parent's guard inside the parent's own registered slot.
3. A subclass shadowing ``_assert_tier_admissible`` — the unvalidated seams dispatched
   the guard through ``cls.``/``type(self).``, which a subclass controls.
4. ``update=`` mappings read twice — the guard tested ``"tier" in update`` on the
   CALLER's mapping and then passed ``dict(update)`` to the base, so a ``Mapping``
   whose ``__contains__`` lies split the check from the value actually applied.
5. Unbound base dispatch (``BaseModel.model_construct.__func__``,
   ``BaseModel.copy``/``model_copy`` on an instance) and raw state writes
   (``object.__setattr__``, ``__setstate__``).

1-4 are closed. So is HALF of 5: ``BaseModel.model_construct.__func__(cls, ...)`` was
originally recorded as unclosable and is not — pydantic invokes ``cls.model_post_init``
from inside the base implementation, so a layer-B hook there catches a path that skips
every override. That is why ``model_post_init`` replaced the name-mangled model
validator, which this route walked past.

What genuinely remains is ``BaseModel.copy``/``model_copy`` on an existing instance
(built via ``_copy_and_set_values`` / ``__dict__.update``, reaching no hook) and raw
``object.__setattr__`` / ``__setstate__`` writes. Each needs either arbitrary in-process
code execution — already out of scope per spec §3.2 and ``tl-2026-003``, and an attacker
with it can just call ``_T3_CONSTRUCTION_AUTHORIZED.set(True)`` — or a line written into
``src/``, which is an authoring risk the commit-time detector owns. That gap is pinned
executably by ``test_tl_2026_013_is_currently_undefended_at_the_authoring_layer_too``
rather than asserted away in prose.

Severity note: 1 and 2 are worse than a plain refusal bypass. Both yield an object
whose STATIC type is ``TaggedContent[T2]`` while its runtime ``tier`` reads ``T3`` —
the cross-tier laundering that ``_validate_tier`` check 4 exists to stop (spec §3.5).
Every generic-typed consumer downstream treats it as authenticated-user content.
"""

from __future__ import annotations

import pickle
import re
import sys
import types
import warnings
from collections.abc import Iterator, Mapping
from typing import Any

import pytest
import structlog
from pydantic import BaseModel, TypeAdapter, ValidationError
from pydantic.errors import PydanticUserError
from pydantic.warnings import PydanticDeprecatedSince20

from alfred.i18n import t as _t
from alfred.security import tiers as tiers_module
from alfred.security.tiers import T2, T3, TaggedContent, TrustTier, tag_t3_with_nonce

_T3_PAYLOAD: dict[str, Any] = {"content": "untrusted", "source": "test", "tier": T3}


class _SpoofT3(T3):
    """A T3 subclass wearing T3's name — the ``bcad7103`` defect, reused at the copy seam."""

    name = "T3"


class _Envelope(BaseModel):
    """Carries a T3 field so nested validation is exercised, not just top-level."""

    payload: TaggedContent[T3]


# Expected refusal text derived from the CATALOG, never hardcoded prose: asserting on
# rendered English couples every test to catalog wording and to the active locale, so a
# translator or a reworded msgstr reds the security suite for no security reason
# (CodeRabbit). Deriving keeps BY-MESSAGE discrimination without that coupling.
_CROSS_TIER_MSG: str = re.escape(_t("security.tier_mismatch", got="T3", expected="T2"))
_NONCE_REFUSAL_MSG: str = re.escape("security.t3_construction_unauthorized")
_TIER_NOT_SELECTABLE_MSG: str = re.escape(_t("security.tagged_content_tier_not_selectable")[:40])


def _expect_refusal() -> pytest.RaisesExc[Exception]:
    """A tier-minting attempt off the nonce path must raise, whatever the route."""
    return pytest.raises((ValidationError, ValueError))


def _lower() -> TaggedContent[T2]:
    """A legitimately-constructed low-tier object — the launder attempts' starting point."""
    return TaggedContent[T2](content="ok", source="test", tier=T2, metadata={})


@pytest.fixture(autouse=True)
def _deprecation_is_not_the_assertion() -> Iterator[None]:
    """``BaseModel.copy`` is deprecated; that warning must not decide these tests.

    Without this, a ``-W error`` run would raise ``PydanticDeprecatedSince20`` before
    reaching the guard, and every ``.copy`` case below would pass on the WRONG
    exception — the "payload could not reach the branch" vacuity shape.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", PydanticDeprecatedSince20)
        yield


# ---------------------------------------------------------------------------
# Seam 1 — the deprecated copy() API
# ---------------------------------------------------------------------------


def test_deprecated_copy_cannot_upgrade_the_tier() -> None:
    """``obj.copy(update={"tier": T3})`` minted a statically-T2 object reading T3.

    ``BaseModel.copy`` bypasses ``model_copy`` entirely, so guarding only the modern
    API left the deprecated one wide open. Verified admitted before this fix.

    Both branches asserted BY MESSAGE. With only the broad ``_expect_refusal()``, this
    test passed with the T3 nonce guard deleted outright, because ``_lower()`` is a
    ``TaggedContent[T2]`` and the cross-tier guard fires first — so it pinned "some guard
    runs here", not the guard it is named for.
    """
    # Parameterised receiver: the cross-tier guard owns this diagnostic (spec §3.5).
    with pytest.raises(ValueError, match=_CROSS_TIER_MSG):
        _lower().copy(update={"tier": T3})

    # Unparameterised receiver: no generic to cross-check, so the nonce guard is the
    # only thing standing between the caller and a minted T3.
    unparametrised = TaggedContent.model_construct(content="ok", source="test", tier=T2)
    with pytest.raises(ValueError, match=_NONCE_REFUSAL_MSG):
        unparametrised.copy(update={"tier": T3})


def test_deprecated_copy_still_works_without_a_tier_change() -> None:
    """Vacuity floor: refusing every ``copy()`` would satisfy the case above."""
    copied = _lower().copy(update={"source": "elsewhere"})

    assert copied.source == "elsewhere"
    assert copied.tier is T2


def test_deprecated_copy_of_an_authorised_t3_object_is_allowed(
    authorized_t3_nonce: object,
) -> None:
    """Holding a legitimate T3 object must not make the deprecated API unusable.

    The invariant is about MINTING T3, not handling it — same carve-out
    ``model_copy`` already has.
    """
    tagged = tag_t3_with_nonce("untrusted", "test", caller_token=authorized_t3_nonce)  # type: ignore[arg-type]

    copied = tagged.copy(update={"source": "relabelled"})

    assert copied.tier is T3
    assert copied.source == "relabelled"


# ---------------------------------------------------------------------------
# Seam 4 — a mapping read twice can be a mapping that lies
# ---------------------------------------------------------------------------


class _LyingUpdate(Mapping[str, Any]):
    """``"tier" in self`` is False while iteration yields ``tier`` → T3.

    Splits a guard that tests membership on the caller's mapping from the ``dict()``
    it hands to the base implementation.
    """

    def __contains__(self, key: object) -> bool:
        return False

    def __getitem__(self, key: str) -> Any:
        return {"tier": T3}[key]

    def __iter__(self) -> Iterator[str]:
        return iter(["tier"])

    def __len__(self) -> int:
        return 1


def test_a_lying_update_mapping_cannot_split_the_guard() -> None:
    """The guard must validate the COERCED mapping it actually applies, read once.

    Message-asserted for the same reason as the copy case: the broad form passed with the
    nonce guard deleted, because the cross-tier check fires first on a parameterised
    receiver.
    """
    with pytest.raises(ValueError, match=_CROSS_TIER_MSG):
        _lower().model_copy(update=_LyingUpdate())

    unparametrised = TaggedContent.model_construct(content="ok", source="test", tier=T2)
    with pytest.raises(ValueError, match=_NONCE_REFUSAL_MSG):
        unparametrised.model_copy(update=_LyingUpdate())


def test_a_lying_update_mapping_cannot_split_the_deprecated_guard() -> None:
    """The same single-read discipline on the deprecated API."""
    with pytest.raises(ValueError, match=_CROSS_TIER_MSG):
        _lower().copy(update=_LyingUpdate())


def test_an_update_mapping_is_only_read_once() -> None:
    """The single-read property directly, not via its consequence.

    A guard that read the caller's mapping twice would still refuse a mapping that lies
    consistently; what makes it safe is that the value CHECKED is the value APPLIED.
    """
    reads: list[str] = []

    class _CountingUpdate(Mapping[str, Any]):
        def __contains__(self, key: object) -> bool:
            reads.append(f"contains:{key!r}")
            return key == "source"

        def __getitem__(self, key: str) -> Any:
            reads.append(f"getitem:{key!r}")
            return {"source": "elsewhere"}[key]

        def __iter__(self) -> Iterator[str]:
            return iter(["source"])

        def __len__(self) -> int:
            return 1

    copied = _lower().model_copy(update=_CountingUpdate())

    assert copied.source == "elsewhere"
    assert not [r for r in reads if r.startswith("contains:'tier'")], (
        f"the guard consulted the CALLER's mapping for 'tier' ({reads}); it must test the "
        "coerced dict it hands to the base implementation"
    )


def test_a_cross_tier_refusal_still_leaves_a_forensic_record() -> None:
    """The cross-tier raise must not swallow the T3 refusal record (hard rule #7).

    ``_refuse_unauthorized_t3`` runs LAST so the cross-tier message wins the diagnostic —
    it names both tiers and identifies the laundering attack (spec §3.5). But on the most
    plausible attack, upgrading a parameterised ``TaggedContent[T2]``, that raise
    pre-empted the only writer of ``security.t3_boundary.refused``, so the refusal left
    NOTHING in the audit stream. Emitting the record before message selection keeps the
    better diagnostic AND the forensic trail.

    Mutation-verified: deleting ``_record_unauthorized_t3_attempt`` survived every other
    test in this module and the adversarial suite, because none of them asserted the log
    on a cross-tier path.
    """
    for label, attempt in (
        ("model_copy", lambda: _lower().model_copy(update={"tier": T3})),
        ("copy", lambda: _lower().copy(update={"tier": T3})),
        (
            "model_construct",
            lambda: TaggedContent[T2].model_construct(content="x", source="test", tier=T3),
        ),
    ):
        with (
            structlog.testing.capture_logs() as logs,
            pytest.raises(ValueError, match=_CROSS_TIER_MSG),
        ):
            attempt()

        refusals = [e for e in logs if e["event"] == "security.t3_boundary.refused"]
        assert len(refusals) == 1, (
            f"the cross-tier refusal on {label} left no forensic record ({logs}); the "
            "better diagnostic must not cost the audit row"
        )
        assert refusals[0]["attempted_tier"] == "T3"


def test_an_explicit_tier_none_update_is_refused(authorized_t3_nonce: object) -> None:
    """``update={"tier": None}`` is an ERASURE, not an absent field.

    ``_guard_tier_value`` passes ``None`` over on purpose — ``model_construct`` may
    legitimately omit a field and required-field handling is pydantic's job. Routing an
    explicit ``None`` there let an update strip the tag off an existing T3 object, leaving
    a tier-less ``TaggedContent`` whose ``getattr(obj, "tier", fallback)`` silently yields
    the fallback. Same provenance loss as narrowing the field away, so the same refusal.
    """
    tagged = tag_t3_with_nonce("untrusted", "test", caller_token=authorized_t3_nonce)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match=_TIER_NOT_SELECTABLE_MSG):
        tagged.model_copy(update={"tier": None})
    with pytest.raises(ValueError, match=_TIER_NOT_SELECTABLE_MSG):
        tagged.copy(update={"tier": None})

    # Floor: an update that does not mention the tier is ordinary use.
    assert tagged.model_copy(update={"source": "elsewhere"}).tier is T3


def test_a_hostile_repr_cannot_flood_the_audit_stream() -> None:
    """The refused value's log field must be length-bounded.

    The value is attacker-influenced, so an unbounded ``repr()`` of a megabyte string — or
    of an object with a pathological ``__repr__`` — writes that straight into the audit
    stream from a security path.
    """
    with structlog.testing.capture_logs() as logs, pytest.raises(ValueError):
        TaggedContent[T2].model_construct(content="x", source="test", tier="T3" * 100_000)

    invalid = [e for e in logs if e["event"] == "security.tier_boundary.refused_invalid_type"]
    assert invalid, f"no forensic record for the refused value: {logs}"
    assert len(invalid[0]["attempted_tier_repr"]) < 200, (
        f"the refusal logged {len(invalid[0]['attempted_tier_repr'])} characters of "
        "attacker-controlled repr; it must be bounded"
    )

    # And a repr that RAISES must not convert the refusal into an unrelated crash.
    class _Unreprable:
        def __repr__(self) -> str:
            raise RuntimeError("hostile __repr__")

    with pytest.raises(ValueError, match=r"Unsupported trust tier"):
        TaggedContent[T2].model_construct(content="x", source="test", tier=_Unreprable())


def test_a_tier_that_is_not_a_trust_tier_class_is_refused_loudly() -> None:
    """A wire string at an unvalidated seam must not escape as a bare AttributeError.

    ``model_construct(tier="T3")`` reached ``value.name`` on a ``str`` and raised
    ``AttributeError`` — an untyped crash from a security path with NO audit row, which
    hard rule #7 forbids and which ``_expect_refusal()`` would not even have caught.
    """
    for bad_tier in ("T3", 123, object()):
        with (
            structlog.testing.capture_logs() as logs,
            pytest.raises(ValueError, match=r"Unsupported trust tier"),
        ):
            TaggedContent[T2].model_construct(content="x", source="test", tier=bad_tier)

        invalid = [e for e in logs if e["event"] == "security.tier_boundary.refused_invalid_type"]
        assert invalid, f"tier={bad_tier!r} was refused with no forensic record: {logs}"
        # A DISTINCT event: the T3 refusal count is the forensic signal for "someone
        # tried to mint T3", and a garbage value is not that. Reusing it inflated the
        # T3 accounting with non-T3 events.
        assert not [e for e in logs if e["event"] == "security.t3_boundary.refused"], (
            "a non-T3 garbage value polluted the T3 refusal accounting"
        )
        assert invalid[0]["attempted_tier_type"] == type(bad_tier).__name__


def test_a_tier_that_merely_compares_equal_to_an_approved_one_is_refused() -> None:
    """Approved-tier membership must be IDENTITY, not ``in``.

    ``value in _APPROVED_TIERS`` consults ``__hash__``/``__eq__``, which a metaclass on
    an attacker-supplied ``TrustTier`` subclass controls. A class reporting equal to T2
    was admitted while being a different class — the closed PRD §7.1 model means those
    four exact objects, not "anything that claims to be one of them".
    """

    class _ImpersonatingMeta(type):
        def __eq__(cls, other: object) -> bool:
            return other is T2 or super().__eq__(other)

        def __hash__(cls) -> int:
            return hash(T2)

    class _Impersonator(TrustTier, metaclass=_ImpersonatingMeta):
        name = "T2"

    # Sanity: the impersonation really does fool set membership, so the assertion below
    # is testing the guard rather than a value that was never confusable.
    assert _Impersonator in {T2}, "the impersonation no longer fools `in` — rebase this test"

    with pytest.raises(ValueError, match=r"Unsupported trust tier"):
        TaggedContent[T2].model_construct(content="x", source="test", tier=_Impersonator)


def test_deprecated_copy_cannot_narrow_the_tier_away() -> None:
    """``copy(exclude={"tier"})`` returned a TaggedContent with NO tier.

    ``getattr(obj, "tier", fallback)`` then silently yielded the fallback and the
    provenance the object exists to carry was gone — a tagged-content value with no tag
    is not a narrower view, it is an untagged payload.
    """
    with pytest.raises(ValueError, match=_TIER_NOT_SELECTABLE_MSG):
        _lower().copy(exclude={"tier"})

    with pytest.raises(ValueError, match=_TIER_NOT_SELECTABLE_MSG):
        _lower().copy(include={"content"})

    # Floor: a narrowing that KEEPS the tier is ordinary use and must stay ordinary.
    narrowed = _lower().copy(include={"content", "tier"})

    assert narrowed.tier is T2


@pytest.mark.parametrize(
    ("label", "kwargs", "drops_tier"),
    [
        # pydantic accepts include/exclude as a set OR a (possibly nested) dict, so the
        # guard must read both spellings. A refactor that flattened the selector, or that
        # assumed a set, would silently stop seeing the dict form.
        ("exclude empty set", {"exclude": set()}, False),
        ("exclude other field", {"exclude": {"metadata"}}, False),
        ("exclude nested dict elsewhere", {"exclude": {"metadata": {"k"}}}, False),
        ("exclude tier", {"exclude": {"tier"}}, True),
        ("include empty set", {"include": set()}, True),
        ("include dict with tier", {"include": {"content": True, "tier": True}}, False),
        ("include dict without tier", {"include": {"content": True}}, True),
    ],
)
def test_the_tier_selector_guard_reads_both_set_and_dict_forms(
    label: str, kwargs: dict[str, Any], *, drops_tier: bool
) -> None:
    """Both selector spellings, both directions — so the guard cannot be half-right."""
    if drops_tier:
        with pytest.raises(ValueError, match=_TIER_NOT_SELECTABLE_MSG):
            _lower().copy(**kwargs)
    else:
        assert _lower().copy(**kwargs).tier is T2, f"{label} should have kept the tier"


# ---------------------------------------------------------------------------
# Seams 2 + 3 — subclassing
#
# Layer A closes subclassing outright, keyed on the defining MODULE. Layer B (a
# name-mangled model validator plus module-level guard dispatch) is the defence BEHIND
# layer A: it must hold even for a subclass that gets past layer A, or it is
# unverifiable dead defence. The only way past layer A is forging ``__module__``, so
# that is the hole layer B is tested through.
# ---------------------------------------------------------------------------


def test_a_subclass_of_tagged_content_cannot_be_defined() -> None:
    """Layer A: close the class, not the instance.

    Pydantic rebinds validator targets by name off the subclass MRO, so ANY subclass
    is a lever on the guard. There are zero legitimate subclasses in ``src/``,
    ``tests/`` or ``plugins/``, so refusing them costs nothing and removes the lever.

    Spelled via ``type(...)`` rather than a ``class`` statement: creation raises, so a
    ``class`` statement binds a name nothing can ever read (CodeQL 629). Both spellings
    route through the same metaclass, and ``__init_subclass__`` fires identically for each
    — verified — so this loses no coverage.
    """
    with pytest.raises(TypeError, match="subclass"):
        type("_Kid", (TaggedContent[T3],), {})


def test_a_forged_class_name_does_not_get_past_layer_a() -> None:
    """A non-identifier name must NOT be a way in.

    An earlier revision keyed layer A on ``cls.__name__.isidentifier()``, reasoning that
    a pydantic parametrisation is named ``"TaggedContent[T3]"`` and a ``class`` statement
    cannot be. ``type("evil[x]", (TaggedContent,), {})`` forges exactly that, and was
    admitted. The module check replaced it; this pins the closure.
    """
    with pytest.raises(TypeError, match="subclass"):
        type("evil[x]", (TaggedContent[T3],), {})


def test_parametrisation_stays_usable_and_reports_this_module() -> None:
    """The tripwire for layer A's real premise.

    Layer A admits a parametrisation because pydantic's ``create_generic_submodel``
    builds it with ``namespace = {"__module__": origin.__module__}`` — so it reports THIS
    module wherever it is written. That, not the class NAME, is what the guard rests on;
    an earlier version of this test canaried the naming instead, which the guard no
    longer consults.

    If a future pydantic stops propagating ``__module__``, layer A would refuse every
    legitimate construction at import time. This fails loudly here first.
    """
    parametrised = TaggedContent[T2]

    assert parametrised.__module__ == tiers_module.__name__, (
        f"pydantic now builds parametrised generics in {parametrised.__module__!r} rather "
        "than the origin's module — layer A would refuse every legitimate "
        "TaggedContent[T] construction and must be re-keyed."
    )
    # The property layer A could most easily break, asserted directly rather than as
    # the absence of a failure.
    assert parametrised(content="ok", source="test", tier=T2, metadata={}).tier is T2


def _plain_subclass(name: str, namespace: dict[str, Any] | None = None) -> type[Any]:
    """Build a TaggedContent subclass that forges ``__module__`` past layer A's module check.

    Used to reach the guards BEHIND the module check. It must contain no
    ``_TIER_GUARD_NAMES`` entry — planting one of those is refused outright, which is the
    property ``test_a_subclass_redefining_any_tier_guard_is_refused`` pins.
    """
    return type(
        name, (TaggedContent[T3],), {"__module__": tiers_module.__name__, **(namespace or {})}
    )


@pytest.mark.parametrize(
    "guard",
    [
        "_validate_tier",
        "model_post_init",
        "_resolve_tier_from_wire",
        "model_construct",
        "model_copy",
        "copy",
    ],
)
def test_a_subclass_redefining_any_tier_guard_is_refused(guard: str) -> None:
    """Redefining a guard is refused at CLASS CREATION, even from this module.

    Both subclass residuals are closed here rather than documented:

    * a namespace forging ``__module__`` passes the module check;
    * a namespace forging ``__module__`` passes the module check, so without the
      guard-name condition it could still shadow ``_validate_tier`` or ``model_post_init``.

    Refusing the redefinition closes it. Parametrised over
    every name in ``_TIER_GUARD_NAMES`` so adding a guard without adding it to that set
    fails here.
    """
    with pytest.raises(TypeError, match=r"redefines trust-tier guard"):
        type(
            "ShadowAnyGuard",
            (TaggedContent[T3],),
            {"__module__": tiers_module.__name__, guard: classmethod(lambda cls, *a, **k: None)},
        )


def test_the_guard_name_set_covers_every_guard_on_the_class() -> None:
    """``_TIER_GUARD_NAMES`` must not drift behind the guards it protects.

    A guard added to ``TaggedContent`` but not to the set is silently shadowable — the
    hole this closes, reopened by omission. Keys on the class's own attributes so the
    check cannot be satisfied by the set agreeing with itself.
    """
    validator_like = {
        name
        for name, value in vars(TaggedContent).items()
        if name.startswith(("_validate", "_resolve"))
        or name in {"model_construct", "model_copy", "copy", "model_post_init"}
    }

    missing = validator_like - tiers_module._TIER_GUARD_NAMES
    assert not missing, (
        f"guards on TaggedContent that a subclass could still shadow: {sorted(missing)}. "
        "Add them to _TIER_GUARD_NAMES."
    )


def test_no_shadowable_guard_alias_survives_on_the_class() -> None:
    """The seams must have NO class-attribute guard entry point at all.

    ``_assert_tier_admissible`` was the shadowable dispatch that made the seam bypass
    work. It is deleted rather than kept as a delegating alias, because an alias is
    what a future author reaches for — and re-adding one silently restores the hole.
    A cheap named tripwire for that exact regression; the behavioural sweep below is
    what actually enforces the property, since this one only knows one spelling.
    """
    assert not hasattr(TaggedContent, "_assert_tier_admissible"), (
        "a class-attribute tier guard is back on TaggedContent; a subclass can shadow "
        "it and re-open the model_construct/model_copy bypass — dispatch the guard as "
        "a module-level function instead"
    )


def test_no_seam_dispatches_its_guard_through_any_shadowable_attribute() -> None:
    """The PROPERTY, not one spelling: no seam may route its guard via a class attribute.

    The ``hasattr`` tripwire above pins the name ``_assert_tier_admissible``. A future
    author re-introducing the identical shadowable pattern under any other name —
    ``_verify_tier_admissible``, say — reopens the exact hole #518 closed with the whole
    suite green. Verified: that mutant survives every other test in this module.

    So shadow every non-guard callable in turn and require the seams to hold. Guard names
    are excluded because planting one is refused at class creation (covered above); this
    sweep is about names that are NOT yet recognised as guards, which is precisely where
    a re-introduced shadowable dispatch would hide.
    """
    guardable = [
        name
        for name, value in vars(TaggedContent).items()
        if (isinstance(value, classmethod | staticmethod) or callable(value))
        and name not in tiers_module._TIER_GUARD_NAMES
    ]
    assert guardable, "no non-guard callables on TaggedContent — the sweep would be vacuous"

    swept: list[str] = []
    for name in guardable:
        try:
            planted = _plain_subclass(
                "SweepShadow",
                {name: classmethod(lambda cls, *args, **kwargs: None)},
            )
        except PydanticUserError:
            # Planting this name breaks class creation outright — pydantic rejects the
            # unrecognised validator/serializer signature. Not a usable shadow vector.
            # Caught NARROWLY on purpose: a broad except here would swallow a genuine
            # failure and silently shrink the sweep.
            continue
        swept.append(name)

        # The property is "no T3-tagged object comes out", NOT "it raises". Shadowing a
        # constructor with a no-op returning None raises nothing but also mints nothing,
        # so the adversary gains nothing. Requiring a raise flagged that as a hole;
        # requiring no T3 object is the real invariant.
        #
        # ALL THREE seams per plant, not just model_construct: a shadow that disables the
        # copy seams while leaving construct intact would otherwise pass (CodeRabbit).
        base = planted.model_construct(content="ok", source="test", tier=T2, metadata={})
        # Loop variables bound as defaults: the lambdas are consumed in the same
        # iteration, but late binding here is the kind of latent hazard ruff B023 exists
        # for and a future edit could make it real.
        for seam, mint in (
            (
                "model_construct",
                lambda cls=planted: cls.model_construct(
                    content="untrusted", source="test", tier=T3, metadata={}
                ),
            ),
            ("model_copy", lambda obj=base: obj.model_copy(update={"tier": T3})),
            ("copy", lambda obj=base: obj.copy(update={"tier": T3})),
        ):
            try:
                built = mint()
            except (ValidationError, ValueError):
                continue
            assert getattr(built, "tier", None) is not T3, (
                f"shadowing {name!r} yielded a T3-tagged object via {seam} — that seam is "
                "dispatching its guard through a class attribute a subclass owns"
            )

    assert swept, (
        f"none of {guardable} could be shadowed, so the sweep asserted nothing; "
        "re-base it on names that can actually be planted"
    )


def test_the_seam_guard_is_not_reachable_through_the_class_at_all() -> None:
    """The seams' guard must be a module-level function, not any class attribute.

    Complements the sweep: rather than shadowing names one by one, assert directly that
    the guard the unvalidated seams call is not exposed on the class under ANY name, so
    there is nothing for a subclass to rebind.
    """
    exposed = [
        name
        for name, value in vars(TaggedContent).items()
        if getattr(value, "__func__", value) is tiers_module._guard_tier_value
    ]

    assert not exposed, (
        f"the seam guard is reachable as a class attribute ({exposed}); a subclass can "
        "rebind it and re-open the model_construct/model_copy bypass"
    )


def test_layer_b_still_refuses_when_the_field_validator_is_absent() -> None:
    """Layer B must be load-bearing, not decoration behind layer A.

    Closing guard-shadowing at layer A means layer B can no longer be reached via a
    hostile subclass — which raises the fair question of whether it still does anything.
    It does: it is the check that survives the FIELD VALIDATOR going missing, e.g. a
    refactor that drops the ``@field_validator("tier")`` decorator. Called directly here
    on an object whose tier was raw-written (the tl-2026-013 residual shape), which is a
    state the field validator never sees.

    Without this, deleting layer B would survive every other test in the module — the
    definition of a decorative guard.
    """
    # Unparameterised, so there is no generic to cross-check and the NONCE guard is what
    # must fire — a parameterised object would raise the cross-tier message instead and
    # this test would not show that layer B reaches the nonce check at all.
    smuggled = TaggedContent.model_construct(content="ok", source="test", tier=T2)
    object.__setattr__(smuggled, "tier", T3)  # the residual: bypasses every seam

    with pytest.raises(ValueError, match=_NONCE_REFUSAL_MSG):
        smuggled.model_post_init(None)


def test_unbound_base_model_construct_is_refused() -> None:
    """``BaseModel.model_construct.__func__(cls, ...)`` bypasses every class override.

    It was verified ADMITTED and originally recorded as an unclosable residual. It is
    not: pydantic invokes ``cls.model_post_init`` from INSIDE the base implementation, so
    the layer-B hook fires on a path that skips the overrides entirely. That is why
    ``model_post_init`` replaced the name-mangled model validator, which this route
    walked straight past.
    """
    with pytest.raises(ValueError, match=_NONCE_REFUSAL_MSG):
        BaseModel.model_construct.__func__(  # type: ignore[attr-defined]
            TaggedContent[T3], content="untrusted", source="test", tier=T3
        )


def test_unbound_base_model_construct_still_works_for_a_lower_tier() -> None:
    """Vacuity floor: refusing all base dispatch would satisfy the case above."""
    built = BaseModel.model_construct.__func__(  # type: ignore[attr-defined]
        TaggedContent[T2], content="fine", source="test", tier=T2
    )

    assert built.tier is T2


def test_a_first_party_alfred_caller_is_named() -> None:
    """The forensic label must name an ``alfred.*`` caller, not skip it.

    An earlier revision skipped the whole ``alfred`` package, so every FIRST-PARTY caller
    — the ingestion boundaries this field exists to identify — was walked past. Verified:
    a caller in ``alfred.plugins.web_fetch.*`` was reported as ``__main__``.

    The other label tests could not catch this because they live in ``tests.*``, outside
    the ``alfred`` package. So this one synthesises a module INSIDE the package, which is
    the only way to exhibit the failure.
    """
    caller_name = "alfred.plugins.web_fetch._synthetic_ingest_probe"
    module = types.ModuleType(caller_name)
    module.__dict__.update({"TaggedContent": TaggedContent, "T3": T3})
    exec(  # noqa: S102 - fixed literal source; the point is the frame's __name__
        "def mint():\n"
        "    return TaggedContent[T3].model_construct(content='x', source='web', tier=T3)\n",
        module.__dict__,
    )
    sys.modules[caller_name] = module
    try:
        with structlog.testing.capture_logs() as logs, _expect_refusal():
            module.mint()
    finally:
        del sys.modules[caller_name]

    refusals = [e for e in logs if e["event"] == "security.t3_boundary.refused"]
    assert len(refusals) == 1, f"no forensic record for a first-party caller: {logs}"
    assert refusals[0]["caller_module_unverified"] == caller_name, (
        f"a first-party caller was reported as "
        f"{refusals[0]['caller_module_unverified']!r} instead of {caller_name!r}; only "
        "this module and pydantic may be skipped"
    )


def test_layer_b_passes_a_legitimately_tiered_object() -> None:
    """Vacuity floor for layer B: it must not refuse everything."""
    legitimate = _lower()

    legitimate.model_post_init(None)  # must not raise

    assert legitimate.tier is T2


# ---------------------------------------------------------------------------
# The seven shapes #534 closed must STAY closed — this PR rewrites their guard
# ---------------------------------------------------------------------------


def test_the_seven_shapes_from_534_remain_refused() -> None:
    """Regression floor: this PR moves the guard, so re-pin what #534 established.

    Not a duplicate of ``test_t3_construction_requires_the_nonce_path`` — that module
    pins the invariant; this asserts the REFACTOR did not relocate it into a seam that
    stopped running.
    """
    with _expect_refusal():
        TaggedContent(content="x", source="test", tier=T3, metadata={})
    with _expect_refusal():
        TaggedContent[T3].model_construct(content="x", source="test", tier=T3, metadata={})
    with _expect_refusal():
        TaggedContent[T3].model_validate({"content": "x", "source": "s", "tier": T3})
    with _expect_refusal():
        _lower().model_copy(update={"tier": T3})


@pytest.mark.parametrize(
    ("alias", "attempt"),
    [
        # Pydantic-v1-era aliases still present on BaseModel in v2. Each currently
        # funnels into a guarded override, so each is ONE refactor away from becoming a
        # bypass — exactly how the deprecated ``copy`` hole came to exist.
        ("parse_obj", lambda: TaggedContent[T3].parse_obj(dict(_T3_PAYLOAD))),
        (
            "parse_raw",
            lambda: TaggedContent[T3].parse_raw('{"content":"x","source":"s","tier":"T3"}'),
        ),
        ("construct", lambda: TaggedContent[T3].construct(**_T3_PAYLOAD)),
        (
            "model_validate_strings",
            lambda: TaggedContent[T3].model_validate_strings(
                {"content": "x", "source": "s", "tier": "T3"}
            ),
        ),
        (
            "type_adapter",
            lambda: TypeAdapter(TaggedContent[T3]).validate_python(dict(_T3_PAYLOAD)),
        ),
        (
            "nested_model",
            lambda: _Envelope.model_validate(
                {"payload": {"content": "x", "source": "s", "tier": "T3"}}
            ),
        ),
        ("deep_copy", lambda: _lower().model_copy(update={"tier": T3}, deep=True)),
        ("t3_subclass_at_copy_seam", lambda: _lower().model_copy(update={"tier": _SpoofT3})),
    ],
)
def test_every_other_pydantic_entry_point_also_refuses_t3(alias: str, attempt: Any) -> None:
    """Breadth floor: the guard must not be specific to the routes #518 enumerated.

    None of these was covered before. They all refuse today — this pins that, so a
    refactor that reroutes one around the overrides fails here instead of shipping a
    silent mint. ``t3_subclass_at_copy_seam`` is the ``bcad7103`` defect one level down:
    a ``T3`` subclass passed as the copy-seam tier.
    """
    with _expect_refusal():
        attempt()


def test_an_all_opaque_stack_degrades_the_label_instead_of_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The frame walk's bound-reached fallback must degrade, not crash or spin.

    Exercised by shrinking the bound so the loop finds no foreign frame — the same state
    as a stack consisting entirely of dispatch machinery. The bound exists because a test
    double that patches ``sys._getframe`` to RETURN a frame rather than raise would make
    an unbounded walk spin forever; this pins the exit it guarantees.
    """
    monkeypatch.setattr(tiers_module, "_FORENSIC_FRAME_LIMIT", 1)

    with structlog.testing.capture_logs() as logs, _expect_refusal():
        TaggedContent[T3].model_construct(**_T3_PAYLOAD)

    refusals = [e for e in logs if e["event"] == "security.t3_boundary.refused"]
    assert len(refusals) == 1, f"the refusal left no forensic record: {logs}"
    assert refusals[0]["caller_module_unverified"] == "<unknown>"


def test_a_tagged_content_cannot_be_pickled_at_all() -> None:
    """Pickle is not an available transport for tagged content — a stronger mitigation.

    A tampered ``__setstate__`` payload is an accepted residual (tl-2026-013), and no
    authoring-time detector can inspect pickle DATA rather than source. What closes it in
    practice is that a parameterised pydantic generic is not picklable: the class is not
    reachable by qualified name, so ``dumps`` fails before any payload exists.

    Pinned because it is load-bearing for that residual's risk assessment. If a future
    pydantic makes these picklable, the ``__setstate__`` shape becomes reachable through
    ordinary serialisation and tl-2026-013 needs re-rating — this test is the trigger.
    """
    with pytest.raises((pickle.PicklingError, AttributeError, TypeError)):
        pickle.dumps(_lower())


def test_the_authorised_path_still_works(authorized_t3_nonce: object) -> None:
    """The floor that makes every refusal above meaningful."""
    tagged = tag_t3_with_nonce("untrusted", "test", caller_token=authorized_t3_nonce)  # type: ignore[arg-type]

    assert tagged.tier is T3
    assert tagged.content == "untrusted"


# ---------------------------------------------------------------------------
# The forensic label must survive refactoring
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("route", "attempt"),
    [
        (
            "model_construct",
            lambda: TaggedContent[T3].model_construct(
                content="x", source="test", tier=T3, metadata={}
            ),
        ),
        ("field_validator", lambda: TaggedContent(content="x", source="test", tier=T3)),
        (
            "deprecated_copy",
            lambda: TaggedContent.model_construct(content="ok", source="test", tier=T2).copy(
                update={"tier": T3}
            ),
        ),
    ],
)
def test_the_refusal_names_this_test_module_as_the_caller(route: str, attempt: Any) -> None:
    """``caller_module_unverified`` must name THIS module — the code that constructed.

    This is the assertion #534 was missing. Its refusal-logging test asserted the event
    fired and carried the right tier/gate, so it stayed green when this PR's refactor
    inserted a frame into the chain and the hard-coded ``sys._getframe(2)`` started
    reporting ``alfred.security.tiers`` — the guard's own module — for every refusal.

    EQUALITY, not "not the guard's module". An earlier revision asserted only
    ``label != tiers`` and ``label != "<unknown>"``; replacing the whole frame walk with
    ``return "pydantic.main"`` satisfied both, and ``pydantic.main`` names the framework,
    which tells an incident responder exactly as little as naming the guard did. That is
    not hypothetical — before pydantic frames were skipped, the field-validator route
    (the wire-ingest path) really did report ``pydantic.main``.

    Parametrised across three routes because the frame depth differs per route, which is
    exactly why a single hard-coded depth could not be right for all of them.
    """
    with structlog.testing.capture_logs() as logs, _expect_refusal():
        attempt()

    refusals = [e for e in logs if e["event"] == "security.t3_boundary.refused"]
    assert len(refusals) == 1, f"route {route!r} left no forensic record: {logs}"
    assert refusals[0]["caller_module_unverified"] == __name__, (
        f"route {route!r} named {refusals[0]['caller_module_unverified']!r} as the caller "
        f"rather than the constructing module ({__name__!r}); the frame walk must skip "
        "the guard's own module AND the pydantic dispatch machinery"
    )

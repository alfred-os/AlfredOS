#!/usr/bin/env python3
"""CI grep gate: reject unauthorised ``tag(T3`` and ``cast(TaggedContent[`` uses.

Invoked by ``make check`` and CI. Exits 0 if clean; exits 1 with violation
messages if any non-approved file contains:

- ``tag(T3, ...)``           — direct calls to the capability-gated factory
                               from outside the single approved home,
                               ``security/tiers.py``.
- ``TaggedContent[T3](...)`` — direct subscript construction that bypasses
                               the ``tag_t3_with_nonce`` capability gate.
                               The Pydantic field validator on ``tier`` does
                               NOT check the nonce; only ``tag_t3_with_nonce``
                               does. Direct construction therefore admits
                               raw T3 content without the per-process nonce
                               check that closes the import-copy-and-call
                               attack (spec §3.2). sec-S3-002.
- ``cast(TaggedContent[...]``— type-erasure bypasses that discard provenance.
- ``# type: ignore`` on a line containing ``TaggedContent`` — suppressing the
                               type error that prevents cast-bypass detection.

Detection strategy (CR-138 finding #2):

The call-site patterns are detected via :mod:`ast` so a call split across
multiple physical lines is still caught — line-based regex would have been
trivially bypassed by inserting a newline between ``tag(`` and ``T3``.
The ``# type: ignore`` suppression sits in comment text that the parser
discards, so it stays on a line-based regex.

Spec §3.2, §3.3, §3.7-3.8.

Authorised callers (the EXACT list — keep in sync with the briefing):

- ``src/alfred/security/tiers.py``      — the ``tag`` overload bodies
                                          (the home of the factory itself).
- ``tests/unit/security/**``            — tests assert the gate's behaviour
                                          using the same patterns.

Usage:

    python scripts/check_tag_t3.py [file_or_dir ...]

If no arguments are given, scans every root declared in
``_DEFAULT_SCAN_ROOTS`` (``src/alfred`` and ``plugins``). An in-repo
DIRECTORY scan that does not cover all of them is refused at runtime — the
roots live here, not at the call sites (#541).

That runtime refusal covers directory arguments only. An invocation that
enumerates explicit FILE paths can still gate a subset (measured: the 293
tracked ``src/alfred/**.py`` files passed individually exit 0 with
``plugins`` unscanned). What closes THAT is the call-site pin in
``tests/unit/meta/test_gate_surfaces_are_pinned.py``, which requires every
invocation site to pass no arguments at all. Neither layer is complete on
its own; see :func:`_collect_paths` for the split.

#538 deleted the second whole-file exemption. ``src/alfred/security/quarantine.py``
carried one until the full rule set measured it dead: 0 violations across its 1634
lines, 0 ``tag(`` calls, 0 ``TaggedContent`` constructions. It is scanned like every
other file now, and ``test_quarantine_scans_clean_without_its_exemption`` pins that.
Narrowing the exemption rather than deleting it would have left a live soft-landing
zone in the one module that provably does not need one; deleting it means the day a
line there does need it back, the build fails loudly and someone has to make that
decision on the record instead of inheriting it. Recorded in
``docs/adr/0058-single-approved-t3-authoring-home.md``.

WHAT THE #538 RULES CANNOT DO — accepted residuals, stated rather than claimed closed:

- **Cross-module re-export aliasing.** Both alias environments are per-file.
- **A name assembled by any operation other than ``+`` or implicit concatenation.**
  :func:`_fold_str` folds ``BinOp(Add)`` chains and literal-only ``JoinedStr``, so
  ``"_set_authorized%s" % "_t3_nonce"``, ``"_set_authorized{}".format("_t3_nonce")``
  and ``"".join([...])`` are assembled ENTIRELY from literals and all scan clean. The
  residual is the OPERATION, not the operands — so it applies to EVERY name-keyed rule
  that folds a string, ``_RAW_STATE_VEHICLE_NAMES`` included:
  ``getattr(low, "__dict%s" % "__")["tier"] = T3`` scans clean for the same reason. It
  used to be written down only against the ``tiers`` private surface, which read as a
  property of that one set (PR #553 review, F6).
- **Carrier-by-reference beyond the named primitives.** The vehicle set is a class ban
  plus a named primitive list, not a proof of completeness. NO COUNT IS NAMED, and the
  one that used to be here is why: it said "six" and PR #553 review found the seventh
  (``gc.get_referrers``, the unlisted sibling of two listed ``gc`` primitives).
- **A name-keyed collision.** Another module defining its own ``_log_t3`` reds
  benignly. Measured: zero today.
- **``TaggedContent.model_construct(...)`` WAS a #538 residual and is no longer one.**
  #539's seam rule is receiver-scoped to the TaggedContent alias environment and
  default-denies an unparameterised receiver, so all three unparameterised spellings now
  red at the authoring layer. What remains residual is narrower and is stated on the rule
  itself: ``TaggedContent[T2].model_construct(tier=T3, …)`` slips it, because the receiver
  names a benign tier and the laundering rides in the keyword.
- **``object.__setattr__(self, "metadata", …)`` and ``object.__delattr__(self,
  "metadata")`` on a ``TaggedContent``.** ``metadata`` is deliberately NOT in
  ``_TAGGED_STATE_FIELDS``: ``src/alfred/hooks/context.py:106`` writes it on a
  ``HookContext``, an unrelated frozen dataclass that happens to share the field name,
  so banning it would red a legitimate site for a name collision. The residual cannot
  change or remove ``tier``, ``content`` or ``source``, so it cannot mint, relabel or
  untag T3 — only alter auxiliary metadata.
- **``self`` is a NAMING convention, not a type guarantee.** A plain function whose
  first parameter is called ``self`` reaches the admissible branch with no subclass
  involved. ``_TAGGED_STATE_FIELDS`` is what actually holds; the ``self`` check
  narrows the surface but proves nothing on its own.

WHAT THE #539 RULES CANNOT DO — the seven T3-construction shapes, added on the same
terms. Every one of these is refused at RUNTIME (verified: 19/19, each with a
``security.t3_boundary.refused`` audit row), so this layer is defence-in-depth and the
residuals below are ergonomic ceilings rather than open holes. See
``docs/adr/0059-default-deny-on-unresolvable-tier-slices.md``.

- **The tier alias environment is PER-FILE.** A ``TaggedContent`` or a tier re-exported
  through another module and imported under its new spelling is not resolved. Inherited
  from ``_alias_names`` and restated because it bites harder here: this environment
  decides four rules rather than one.
- **A BENIGN-NAME BINDING cannot be decided lexically.** ``benign_tier`` holds bare
  names, so ``def f(T2): TaggedContent[T2](...)`` with a caller passing ``T3`` scans
  clean. The same applies to ``tiers.py:949``'s ``TaggedContent[tier](...)``, where the
  tier is a plain parameter. A name-keyed set cannot decide a runtime binding.
- **A BENIGN-SLICE CONSTRUCTOR CARRYING THE TIER AS A KEYWORD.**
  ``TaggedContent[T2](content=x, tier=T3)`` names a benign tier in the position this gate
  reads and puts the laundering in a keyword it does not. It is the constructor twin of the
  seam residual below, and it was undeclared while its twin was declared — the asymmetry,
  not the residual, was the defect. Refused at RUNTIME by the cross-tier field validator,
  which writes a ``security.t3_boundary.refused`` audit row.
- **The construction seam's safety is BORROWED from the runtime guard.**
  ``TaggedContent[T2].model_construct(tier=T3, ...)`` slips the lexical rule entirely —
  the receiver names a benign tier and the laundering rides in the keyword — and is
  caught only by ``_enforce_tier_admissible`` / ``model_post_init``. Said plainly because
  a rule whose stated basis does not survive measurement is what this epic exists to stop
  shipping.
- **The copy rule needs its update mapping AT THE CALL SITE.**
  ``payload = {"tier": T3}; obj.model_copy(update=payload)`` carries an ``ast.Name``, not
  a mapping this gate can read. Refused at runtime by ``_coerce_and_guard_update``;
  closing it lexically would mean flagging every ``model_copy`` in the tree, which costs
  two named benign floors.
- **``getattr(x, var)``, ``REGISTRY[k](...)`` and a tier arriving through ``**kwargs``**
  reach a constructor with no identifier in code position for any rule to key on.
- **``exec``/``eval``** are out of reach in any form; ruff ``S102``/``S307`` are the
  defence, not this gate.
- **A tuple-target binding** (``A, B = TaggedContent[T3], other``) carries no subscript in
  ``.value``, so the name is simply unknown rather than misread.

THE ESCAPE HATCH, and it is the only one: a legitimate future need for one of these
vehicles — or for a benign wire round-trip — belongs behind a NAMED helper inside the
already-exempt ``security/tiers.py``, not behind a loosened rule here. A rule relaxed to
admit one caller admits every caller that can spell the same shape, and the relaxation is
invisible at every site that later depends on it.
"""

from __future__ import annotations

import ast
import enum
import errno
import io
import os
import re
import stat
import subprocess
import sys
import tokenize
from collections.abc import Mapping
from pathlib import Path
from typing import NamedTuple

# Suppression sits in comment text the parser discards, so AST detection cannot see it.
# That much was always true; what changed is the instrument. THREE measured reasons force
# `tokenize` over a line regex:
#
# 1. THE NAIVE WIDENING IS THE LIKELY WRONG IMPLEMENTATION. Written with a top-level
#    alternation — `TaggedContent.*#\s*(?:type|pyright):\s*ignore|noqa` — the `noqa` arm
#    binds at the TOP level and matches any line containing the word, anywhere, including
#    inside a string. Measured across both scan roots: 98 hits against 1 correctly grouped,
#    so 97 pure false positives. The non-capturing group below is load-bearing.
# 2. A "TOKEN REGEX" IS WORSE THAN THE NAIVE FORM ON ONE CASE — it readmits prose inside a
#    real comment. Only anchoring at the START of a real COMMENT token's body separates a
#    directive from a sentence that mentions one.
# 3. THE OLD RULE NEEDED THE SUPPRESSOR AND `TaggedContent` ON THE SAME PHYSICAL LINE, so
#    reformatting a call across lines and putting `# type: ignore` on the closing paren made
#    it blind. The LOGICAL line is the correct scope, and only the tokenizer knows where one
#    ends.
#
# `re.match`, never `re.search`: "we do not noqa here" is prose ABOUT a directive, because
# the word is not where a directive would start. "noqa is the wrong tool", by contrast, IS a
# bare directive to every linter that reads it, and reds — the anchor decides that correctly
# and a review floor asserting otherwise was itself wrong. (This very comment block cannot
# spell a directive out in full: ruff reads one inside a comment no matter what surrounds
# it, and flags the unused suppression. That is the same phenomenon, one layer up.)
#
# `ruff: noqa`, `flake8: noqa` and `mypy: ignore-errors` are FILE-WIDE suppressors — the
# strongest of the family — and were invisible to every earlier draft of this rule.
# TWO CLASSES, because the real tools scope them differently and one span rule cannot be
# right for both.
#
# FILE-WIDE suppressors disable checking for the WHOLE MODULE, so their scope is the file:
# a blanket ruff or flake8 directive at the top of a module full of `TaggedContent` has
# silenced every line in it. Scoping those to their own line would make the STRONGEST
# members of the family the easiest to hide behind, which is exactly backwards.
#
# (This block cannot spell either directive out in full. ruff parses one inside a comment
# regardless of the surrounding prose and then reports it as malformed — the same
# comment-is-not-prose phenomenon the rule below exists to decide, one layer up.)
#
# LINE-SCOPED suppressors apply to the logical line they sit on and nothing else — a bare
# `# type: ignore` on its own line suppresses NOTHING in mypy, so attaching it to whatever
# statement happens to follow would be a false positive invented by this gate rather than a
# property of the source.
#
# `mypy: ignore-errors` is matched before `mypy: ignore` would be reached, and the file-wide
# pattern is tested first, so the longer directive cannot be swallowed by its own prefix.
_FILE_WIDE_SUPPRESSOR_PATTERN: re.Pattern[str] = re.compile(
    r"(?:(?:ruff|flake8)\s*:\s*noqa|mypy\s*:\s*ignore-errors)\b"
)
_LINE_SUPPRESSOR_PATTERN: re.Pattern[str] = re.compile(
    r"(?:(?:type|pyright|mypy)\s*:\s*ignore|noqa)\b"
)

# Token kinds that carry no CODE, so none of them may open a logical-line span. Module-level
# rather than a local, because a frozenset rebuilt per call is work this gate does 332 times
# and because ruff's N806 correctly reads an upper-case local as a misplaced constant.
_NON_CODE_TOKENS: frozenset[int] = frozenset(
    {
        tokenize.COMMENT,
        tokenize.NL,
        tokenize.NEWLINE,
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.ENDMARKER,
        tokenize.ENCODING,
    }
)
_TYPE_IGNORE_MESSAGE: str = "# type: ignore on TaggedContent line — fix the type, don't suppress"

# AST-detected call-site violations. Each entry describes the call name
# and the shape of its first positional argument; ``_node_matches`` decides
# whether a given ``ast.Call`` node trips the rule.
_TAG_T3_MESSAGE: str = "tag(T3, ...) direct call — use tag_t3_with_nonce() with injected nonce"
_CAST_TAGGED_CONTENT_MESSAGE: str = (
    "cast(TaggedContent[...]) — use AnyTaggedContent for observers (spec §3.3)"
)
_TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE: str = (
    "TaggedContent[T3](...) direct subscript construction — use "
    "tag_t3_with_nonce() with injected nonce (spec §3.2, sec-S3-002)"
)

# ---------------------------------------------------------------------------
# #538 — THE SOLE-LAYER RULES.
#
# The runtime CANNOT refuse these. Raw state writes never traverse any method the
# model can override (`frozen=True` observes `__setattr__`, and none of these reach
# it), so no seam is left to guard. The authoring layer is the ONLY enforcement layer
# that can exist for them.
#
# DEFAULT-DENY THE VEHICLE OR THE SHAPE, NEVER ENUMERATE THE SPELLING. Round-2 probes
# minted two genuine `TaggedContent[T3]` objects with attacker-controlled content from
# a file that scanned clean under BOTH the merged detector AND a fully enumerated rule
# set. The decisive spelling:
#
#     object.__setattr__(obj, "__dict__", {..., "tier": T3})
#
# An earlier constraints doc mandated "key on the written `tier` attribute, not on the
# call". That rule cannot see this line BY CONSTRUCTION — the attribute written is
# `__dict__`.
#
# AND THE SAME MISTAKE RECURRED INSIDE THE FIX: the first revision of these rules
# matched the receiver as the bare identifier `object`, so `builtins.object.__setattr__`,
# `_o = object` and `from builtins import object as _o` all scanned clean. The review
# fleet executed all three and minted T3. Hence receiver-BLIND matching on
# `__setattr__`, and hence `_alias_names` on every other identifier a rule keys on.
#
# `__doc__` IS ONE OF THESE (PR #553 review, F1), and it is here for a reason the other
# members do not share: it hands the PROSE EXCLUSION back as data. `_prose_string_ids`
# excludes a bare string statement from both string-keyed rules on the premise that a
# string in statement position documents rather than acts — and `__doc__` retrieves that
# exact string in code position. Executed end to end: a class whose docstring IS
# `_set_authorized_t3_nonce`, read back through `getattr(_t, _Codec.__doc__)`, installed
# an attacker nonce and minted a genuine `TaggedContent[T3]`. The premise cannot be
# repaired by excluding fewer strings (that readmits `getattr(_t, "…")`), so the
# RETRIEVAL is the vehicle. Measured cost across both scan roots: ZERO `__doc__` nodes.
_RAW_STATE_VEHICLE_ATTRS: frozenset[str] = frozenset(
    {
        "__dict__",
        "__setstate__",
        "__getstate__",
        "__reduce__",
        "__reduce_ex__",
        "__new__",
        "__mro__",
        "__bases__",
        "__doc__",
    }
)

# Vehicles when NAMED AS A STRING. DELIBERATELY WIDER than the attribute set above.
# `getattr(object, "__setattr__")(low, "tier", T3)` produces NO `ast.Attribute` node at
# all, so every attribute-keyed rule is blind to it — executed, it turned a
# TaggedContent[T2] into T3. `__setattr__` must NOT join the attribute set: the three
# live benign `object.__setattr__(...)` sites all carry that attribute node, and the
# receiver-blind rules below already cover the attribute form.
#
# `__init__` joins on EXACTLY the `__setattr__` precedent (PR #553 review, F3), and for
# exactly the same reasons in both directions. It must be here, because
# `getattr(type(low), "__init__")(low, content=ATTACKER)` carries no attribute node and
# the receiver-blind call rule cannot see it. It must NOT join the attribute set, because
# 62 live sites carry that attribute node and the call rule already decides them on
# shape.
#
# `__delattr__` SAT IN THIS SET WITH NO CALL-SHAPE RULE AND NO ALIAS RULE (PR #553
# review, C1) — the third member of the `__setattr__`/`__init__` family, given only the
# folded-string treatment, so `object.__delattr__(low, "tier")` and
# `_d = object.__delattr__; _d(low, "tier")` both scanned clean. EXECUTED against a real
# `TaggedContent[T2]` and a real `TaggedContent[T3]`: `frozen=True` does not observe it
# (the ordinary `del low.tier` IS refused — pydantic raises `frozen_instance` — so this
# is the sole-layer class exactly), and what it leaves behind is a laundering rather
# than a crash. The tier field goes ABSENT, and `getattr(obj, "tier", fallback)` then
# returns the fallback: measured `getattr(hot, "tier", None) is T3` -> False on a
# genuine T3 object still carrying attacker content, with `repr()`, `dict()` and
# `model_copy()` all succeeding and silently omitting the tag. `tiers.py` already
# refuses that exact end state on the two seams it CAN reach — see
# `_refuse_if_tier_is_narrowed_away` and the `{"tier": None}` erasure arm of
# `_coerce_and_guard_update`, both of which cite the same `getattr` mechanism — so this
# is not a new judgement about what counts as laundering, it is the same one on the seam
# no runtime guard can observe. It stays OUT of the attribute set for the same reason
# its two siblings do: the pair of rules below decides the attribute form on SHAPE, and
# the string set has to stay wider than the attribute set for the getattr spelling.
_RAW_STATE_VEHICLE_NAMES: frozenset[str] = _RAW_STATE_VEHICLE_ATTRS | frozenset(
    {"__setattr__", "__delattr__", "__class__", "__init__"}
)

# Reaching PRIMITIVES that hand back an object's raw state (`_RAW_STATE_CARRIERS`) sit
# below; this set has THREE carriers of its own and each needs its own arm in `_detect`:
# an `ast.Attribute` node, a folded STRING, and a bare `ast.Name`.
#
# THE BARE NAME is not hypothetical padding (PR #553 review, F1). A module's own
# docstring is bound to the identifier `__doc__` with no attribute node and no string
# constant anywhere, so a module docstring reading `_set_authorized_t3_nonce` followed by
# `getattr(_t, __doc__)(mine)` is the F1 channel one level further down — and the
# docstring is prose-excluded, so the private-surface rule cannot see it either. Closed
# as a CARRIER over the whole name set rather than as the one member that happens to have
# this spelling today. Measured cost across both scan roots: ZERO bare `ast.Name` nodes
# carrying any of these ids.

# The `TaggedContent` state fields no `__setattr__` call may write, whatever its target.
# `metadata` is deliberately ABSENT — `src/alfred/hooks/context.py:106` writes it on a
# `HookContext`, an unrelated frozen dataclass sharing the field name. Banning it would
# red a legitimate site for a name collision, and the residual cannot change `tier`,
# `content` or `source`, so it can neither mint nor relabel T3.
_TAGGED_STATE_FIELDS: frozenset[str] = frozenset({"tier", "content", "source"})

# Reaching PRIMITIVES that hand back an object's raw state. Scoped to the primitive,
# not the module: banning `gc` and `ctypes` outright costs two legitimate sites
# (`ctypes.CDLL` for libc in `supervisor/process_posture.py`, `gc.collect()` in
# `fd3_key_delivery.py`) while this form costs ZERO. The class is "primitives that
# hand back raw state", not "modules that happen to contain one".
#
# `gc.get_referrers` was the UNLISTED SIBLING of the two `gc` primitives already here
# (PR #553 review, F2): same module, same class of return value — it hands back an
# instance `__dict__` — and it was simply not thought of. Executed, it relabelled a live
# object with the static type still reading `TaggedContent[T2]`. The lesson is the one
# this whole comment block is about: a named-primitive list closes what it names, so it
# has to be revisited every time somebody looks, and a member costing zero is never worth
# leaving out. Measured cost of this one across both scan roots: ZERO sites.
_RAW_STATE_CARRIERS: frozenset[tuple[str, str]] = frozenset(
    {
        ("gc", "get_referents"),
        ("gc", "get_objects"),
        ("gc", "get_referrers"),
        ("ctypes", "py_object"),
        ("ctypes", "cast"),
        ("copyreg", "_reconstructor"),
        ("copyreg", "__newobj__"),
    }
)

# Seam methods that write field state when dispatched with the CLASS as receiver.
# `copy` is pydantic v1's spelling and does NOT route through `model_copy` (it merges
# `update` inside `copy_internals`); the `model_validate*` pair is included because a
# wire round-trip is a construction path.
_BASEMODEL_SEAM_ATTRS: frozenset[str] = frozenset(
    {"copy", "model_copy", "model_construct", "model_validate", "model_validate_json"}
)

# THE PRIVATE SURFACE OF `alfred.security.tiers` — 21 module-level `_`-prefixed names.
#
# THE TWO BYPASSES NOTHING ELSE IN THE REPO CATCHES, and nothing else CAN:
#
#     _set_authorized_t3_nonce(mine)          # install an attacker nonce
#     _T3_CONSTRUCTION_AUTHORIZED.set(True)   # flip the guard off wholesale
#
# These names ARE the T3 authorisation mechanism. A runtime guard that refused them
# would refuse the bootstrap that installs the real nonce, so no such guard can exist.
# The authoring layer is the ONLY enforcement layer available, which is why the ban is
# DEFAULT-DENY over the whole private surface rather than an enumeration of the two
# spellings an attacker happened to use.
#
# HARD-CODED, not derived at import: the gate runs under bare `python3` from the
# Makefile with no venv and no `alfred` importable, so it cannot ask the module. It
# also must not read `tiers.py` at import time — that would put filesystem I/O in this
# module's import path. `_derive_tiers_private_surface` is the DRIFT GUARD that keeps
# the hard-coded copy honest, and it is called from the test suite, never from here.
_TIERS_PRIVATE_SURFACE: frozenset[str] = frozenset(
    {
        "_APPROVED_TIERS",
        "_AUTHORIZED_T3_NONCE",
        "_FORENSICALLY_OPAQUE_PACKAGES",
        "_FORENSIC_FRAME_LIMIT",
        "_MAX_FORENSIC_REPR",
        "_PARAMETRISATION_ATTRS",
        "_T3_CONSTRUCTION_AUTHORIZED",
        "_TIER_GUARD_NAMES",
        "_bounded_repr",
        "_coerce_and_guard_update",
        "_enforce_tier_admissible",
        "_guard_tier_value",
        "_is_forensically_opaque",
        "_is_unauthorized_t3",
        "_log_t3",
        "_nearest_foreign_module",
        "_record_unauthorized_t3_attempt",
        "_refuse_if_tier_is_narrowed_away",
        "_refuse_unauthorized_t3",
        "_set_authorized_t3_nonce",
        "_tier_by_name",
    }
)

_RAW_VEHICLE_ATTR_MESSAGE: str = (
    "raw-state vehicle attribute — reaches instance state without traversing any "
    "method the model can guard. Use tag_t3_with_nonce()."
)
_RAW_VEHICLE_VARS_MESSAGE: str = (
    "vars() exposes the instance mapping directly — the same unguarded reach as "
    "__dict__. Use tag_t3_with_nonce()."
)
_RAW_VEHICLE_STR_MESSAGE: str = (
    "a raw-state vehicle named as a string in code position — getattr() and friends "
    "reach it without an attribute node. Use tag_t3_with_nonce()."
)
_RAW_VEHICLE_NAME_MESSAGE: str = (
    "a raw-state vehicle bound to a bare identifier — a module docstring reaches "
    "__doc__ this way, carrying neither an attribute node nor a string constant."
)
_RAW_INIT_SHAPE_MESSAGE: str = (
    "__init__ re-entered on something other than `self` — pydantic writes the instance "
    "mapping through validate_python(self_instance=...), so content and source are "
    "replaced in place past frozen=True. Build the object you want instead."
)
_RAW_INIT_ALIASED_MESSAGE: str = (
    "__init__ taken as a value rather than called — an alias defeats any rule keyed on "
    "the call. Invoke it inline, on `self` or through zero-argument super()."
)
_RAW_SETATTR_SHAPE_MESSAGE: str = (
    "__setattr__ call whose target is not `self` or whose field name is computed, "
    "dunder or a TaggedContent state field — bypasses frozen=True and every tier guard."
)
_RAW_SETATTR_ALIASED_MESSAGE: str = (
    "__setattr__ referenced outside direct-call position — an alias defeats any rule "
    "keyed on the call. Call it inline on `self` with a literal field name."
)
_RAW_DELATTR_SHAPE_MESSAGE: str = (
    "__delattr__ call whose target is not `self` or whose field name is computed, "
    "dunder or a TaggedContent state field — removing the tag leaves a tagged object "
    "with nothing to read, and getattr(obj, 'tier', fallback) then yields the fallback."
)
_RAW_DELATTR_ALIASED_MESSAGE: str = (
    "__delattr__ taken as a value rather than called — an alias defeats any rule keyed "
    "on the call. Invoke it inline, on `self`, naming a literal non-state field."
)
_RAW_CLASS_SWAP_MESSAGE: str = (
    "assignment to __class__ — retypes a live object past every constructor guard. "
    "Build the right type instead."
)
_RAW_CARRIER_MESSAGE: str = (
    "a carrier primitive that hands back an object's raw state mapping — reaches "
    "instance state while naming no attribute. Use tag_t3_with_nonce()."
)
_BASEMODEL_VALUE_MESSAGE: str = (
    "unbound BaseModel seam dispatch — builds field state through "
    "_copy_and_set_values, reaching neither the class overrides nor model_post_init. "
    "Call the seam on the INSTANCE, or use tag_t3_with_nonce()."
)
_ALIAS_BUDGET_MESSAGE: str = (
    "alias chain deeper than the resolver's budget — the gate cannot decide what "
    "these names are bound to. Simplify the aliasing."
)
_PRIVATE_SURFACE_MESSAGE: str = (
    "a private name from alfred.security.tiers, named in code — that surface IS the "
    "T3 authorisation mechanism, so no runtime guard can refuse a use of it. Take the "
    "nonce from bootstrap and go through tag_t3_with_nonce()."
)
_TAGGED_CONTENT_UNRESOLVED_SLICE_MESSAGE: str = (
    "TaggedContent[...] whose generic argument is not a tier this gate can read — a "
    "computed, quoted-non-tier or otherwise non-identifier slice. The gate cannot tell "
    "T3 from T2 here, so it refuses. Name the tier literally, or use tag_t3_with_nonce()."
)
_UNPARAMETERISED_CONSTRUCTION_MESSAGE: str = (
    "TaggedContent(...) built with no generic argument — the tier arrives as data the "
    "gate cannot read, so it cannot tell a T3 construction from a T0 one. Parameterise "
    "the construction, or use tag_t3_with_nonce()."
)
_TAGGED_SEAM_MESSAGE: str = (
    "a TaggedContent construction seam (model_construct / model_validate*) that does not "
    "name a benign tier — these build field state from DATA, so the tier is not a token "
    "this gate can read. Use tag_t3_with_nonce()."
)
_TIER_MUTATING_COPY_MESSAGE: str = (
    "a copy seam whose update mapping reaches a 'tier' key — relabelling the tier on an "
    "existing object never passes the capability gate. Build the object you want with "
    "tag_t3_with_nonce()."
)

# Read-surface failures. These are VIOLATIONS, not silent passes (#537):
# a file the gate cannot read is a file the gate is not gating, and Python's
# import machinery is far more permissive than this reader.
#
# A ``# -*- coding: latin-1 -*-`` header (PEP 263) makes
# ``read_text(encoding="utf-8")`` raise ``UnicodeDecodeError`` while the module
# imports and executes perfectly. Measured: the gate returned rc=0 for a file
# that constructed ``TaggedContent[T3]`` — one header line defeated every rule
# here, current and proposed. The same swallow hid a file carrying a real
# violation alongside a ``SyntaxError``, and made every "must PASS" floor in
# the suite vacuously green on text that was never parsed.
#
# FIVE DISTINCT strings so a test for one cannot be satisfied by another
# firing. Measured false-positive cost across the scan root: 0 unparseable,
# 0 unreadable, 0 unscannable.
#
# The fifth exists because ONE string used to cover both the parser arm in
# :func:`_scan_text` and the path arm in :func:`_scan_file`, so it had to
# suggest two remedies ("Simplify the file, or fix the path") of which the
# wrong one was always half the advice (#543 review, dx-003). Splitting them
# matches the ``_UNPARSEABLE``/``_UNREADABLE`` pair already here.
_UNDECODABLE_MESSAGE: str = (
    "file is not valid UTF-8 — the gate cannot read it but Python can execute "
    "it (PEP 263 coding declaration). Re-encode as UTF-8."
)
_UNPARSEABLE_MESSAGE: str = "file does not parse — the gate cannot scan it. Fix the syntax error."
_UNREADABLE_MESSAGE: str = "file could not be read — the gate cannot scan it."
_UNSCANNABLE_MESSAGE: str = (
    "file could not be scanned — the parser failed on its CONTENT. Simplify the file."
)
_UNSCANNABLE_PATH_MESSAGE: str = (
    "file could not be scanned — the reader failed on its PATH, before any "
    "content was read. Fix the path."
)


class _ScannedOk(list[str]):
    """Violations from a scan that RAN TO COMPLETION. Empty list = clean.

    DEFAULT-DENY on the outcome axis (#547). ``main``'s census counts a file
    only when its result is one of these, so a return path nobody has thought
    of yet — a new ``except`` arm, an early return, a future refactor — counts
    as a failure rather than as a clean scan.

    RETURNED ON A COMPLETION EVENT, NEVER ON A FALL-THROUGH. ``_scan_text``
    sets ``completed = True`` as the last statement of its ``try`` body. An
    earlier draft instead gave the broad ``except`` arm an early ``return`` and
    left the marked return as the fall-through, which is not the same thing: a
    new ``except`` arm written the ordinary way (append, no ``return``) reached
    the marked return and its files scored as clean scans. Measured with a real
    ``except MemoryError`` arm at 4 of 4 — identical to having no guard at all.

    MARKING THE FAILURES INSTEAD WAS ALSO MEASURED FAIL-OPEN. That variant
    derived its guard from the ``_*_MESSAGE`` constants while enumerating the
    producing sites, and this file already carries two shapes that enumeration
    misses: the ``S_ISREG`` refusal reuses ``_UNREADABLE_MESSAGE`` rather than
    adding a message, and ``_NOT_A_REGULAR_FILE_REASON`` carries no
    ``_MESSAGE`` suffix at all.

    A ``list`` subclass rather than a richer return type because ``==`` against
    a plain list is transparent, so every existing assertion holds unchanged.
    Rebuilding the list (``+``, a comprehension, ``sorted()``, ``list(...)``)
    drops the marker — and that direction is FAIL-CLOSED, which is the whole
    reason the polarity is this way round.

    CONSTRUCTED IN EXACTLY ONE PLACE, pinned by
    ``test_the_scanned_ok_marker_is_constructed_in_exactly_one_place``, which
    caps the TOTAL number of ``ast.Name`` references at two — the construction
    here and the ``isinstance`` in ``main``. Capping only this function while
    leaving ``main`` open was measured insufficient: ``_ScannedOk(_scan_file(
    path))`` inside ``main`` counted every file as a completed scan and the
    guard stayed green. Its blind spot is named rather than claimed closed:
    ``globals()[...]``, ``getattr(sys.modules[...])``, ``type(x)(...)`` and
    ``copy.copy(x)`` never spell the identifier, so no source-level instrument
    sees them.
    """

    __slots__ = ()


# The REASON line under `_UNREADABLE_MESSAGE` for a non-regular file (#546),
# where every other cause supplies the OS's own `strerror`. Deliberately NOT
# named `*_MESSAGE`: `test_every_collection_failure_message_is_enumerated`
# derives the collection-failure set from names with that suffix, and this is
# a reason under an existing message, not a sixth message.
_NOT_A_REGULAR_FILE_REASON: str = "not a regular file"

# NOT a collection-failure message: this one says the GATE is broken, not the
# file (#543 review, err-001). It travels on :class:`GateInternalError`, which
# `main` turns into exit 2 ("the gate could not run") rather than exit 1
# ("violations found") — the distinction the exit contract exists for.
_GATE_INTERNAL_MESSAGE: str = (
    "the gate's own detector raised while scanning this file. This is a BUG IN "
    "check_tag_t3.py, not a finding in the file. The scan is abandoned: no "
    "file's verdict is trustworthy while a detector predicate is faulting."
)

# THE GATE OWNS ITS SCAN ROOTS (#541). They used to live in the two
# invocation strings (``Makefile`` and ``pr-validate-python.yml``), so
# dropping ``plugins`` from either one was a one-word edit that stopped
# gating 39 first-party plugin files — including
# ``plugins/alfred_discord/inbound_emitter.py``, a real ingestion boundary —
# while the census (293 for ``src/alfred`` alone, floor 250) still passed.
#
# Raising the census was considered and rejected: at 300 it sits 7 files
# above the ``src/alfred`` count, and that tree grew +19 files in 23 days, so
# the guard would have stopped working within about a week. A count is a
# proxy for "both roots were gated"; the runtime invariant in
# :func:`_collect_paths` is the property itself.
#
# Callers now pass NO arguments, so there is no root to drop. Changing what
# is gated means editing this tuple — in a file under a 100% coverage gate,
# mypy --strict and pyright, pinned by a test that does not monkeypatch it.
_DEFAULT_SCAN_ROOTS: tuple[str, ...] = ("src/alfred", "plugins")

# Assert-RAN floor (#245, #514). ``_collect_paths([])`` resolves the default
# roots relative to CWD, so an argument-less run from the wrong directory
# scanned 0 files, exited 0 and printed nothing — a required check reporting
# green while gating nothing. A test-side census cannot catch that, because
# the failure mode IS the caller.
#
# WHAT IT STILL GUARDS, corrected after #541 (the earlier text here claimed
# "the WRONG-DIRECTORY case only", which measurement contradicts):
#
#   * The PLAIN wrong-directory run no longer reaches this floor. From
#     ``/tmp``, ``src/alfred`` is not a directory, so the missing-default-root
#     branch in ``_collect_paths`` raises first — measured rc=2 with the
#     specific "the default scan root does not exist relative to the current
#     directory" message, which is a better diagnosis than a count ever was.
#   * A DECOY TREE **no longer lands here at all** (#543 review, sec-002).
#     The text this replaces claimed a decoy was "caught by this floor alone.
#     Measured: 2 files scanned, rc=2" — true of a 2-file decoy and FALSE of a
#     realistic one. Security review built a 260-file clean decoy, reached
#     through an in-repo symlink so both roots resolved OUTSIDE the repo and
#     the runtime invariant exempted them by design, and measured **rc=0 with
#     zero bytes of src/alfred or plugins scanned**: the floor is 250 and a
#     real copy of this repo holds 332 files under the two roots, so any decoy
#     of realistic size cleared it. A count was the wrong instrument — it has a
#     margin, and the margin was widening. The property itself now lives in
#     :func:`_collect_paths`: on the argument-less path, EVERY declared root
#     must resolve INSIDE this repo.
#
#     Stated over a SAMPLE of the collected files instead — "at least one
#     collected file resolves inside" — it had a margin after all, and #548
#     review found it: ``rglob`` runs with ``recurse_symlinks=True``, so a
#     decoy holding ONE link to any real repo ``.py`` file satisfied the
#     ``any(...)``. Measured rc=0, 261 files collected, 1 inside this repo and
#     260 decoy files carrying every verdict. The root form is what the
#     paragraph above always claimed; only the code was weaker.
#   * A GUTTED in-repo tree: both roots present and covered, but mass-deleted
#     below the floor. This is what the floor still catches, and all it
#     catches.
#
# 332 tracked ``.py`` files live under the two roots today (293 + 39); 250
# leaves headroom for deletions without leaving room for the gate to go
# vacuous. Unchanged at 250 by #541 and #543 — it is not, and never was, a
# check that every root was supplied, nor (as of #543) the decoy defence; that
# is what ``_DEFAULT_SCAN_ROOTS`` plus the two runtime invariants are for.
#
# SINCE #547 THIS CONSTANT GOVERNS TWO DIFFERENT POPULATIONS, and the reader
# needs both:
#
#   * the PRE-SCAN floor compares it against files COLLECTED — includes exempt
#     files, includes duplicate paths resolving to one file. 332 today.
#   * the POST-SCAN census compares it against DISTINCT files actually read and
#     parsed — excludes the exempt ones. 331 today (332 collected, 1 exempt).
#
# The 81-file margin above 250 therefore belongs to the tighter of the two.
# Do NOT pin either number in a test: the tree grew ~25 ``.py`` files in the 30
# days before #547, so a count-keyed assertion reds on an unrelated merge
# within days. That is the same growth argument that rejected raising this
# constant to 300 — it applies to test oracles too.
_MIN_SCANNED_FILES: int = 250

# The authorised non-test home — resolved to an absolute path inside THIS
# repo at import time. SINGULAR since #538 (see the module docstring): the
# second entry was measured dead and deleted rather than narrowed.
#
# CR-138 finding #11: suffix matching (``endswith``) was bypassable by any
# file whose path happened to end with the same segment
# (``/tmp/attacker/src/alfred/security/tiers.py`` would have been exempt).
# Exact absolute-path equality against the real file in this checkout
# closes that path.
#
# ``__file__`` resolves to ``<repo>/scripts/check_tag_t3.py``; the repo
# root is two parents up. The script always runs against files in this
# same checkout (CI invokes it with paths under the workspace), so any
# path that does NOT resolve to that exact file is not the real
# authorised home — even if it ends with the same segment.
_REPO_ROOT: Path = Path(__file__).resolve().parent.parent
_APPROVED_PATHS: frozenset[Path] = frozenset(
    {_REPO_ROOT / "src" / "alfred" / "security" / "tiers.py"}
)

# THE ONLY LEGITIMATE CALLER of the private surface outside `tiers.py` itself.
#
# Narrowed to (path, FUNCTION), never path-only. `_set_authorized_t3_nonce` is a bare
# `global` write with NO guard of its own — the idempotency check lives in
# `create_and_register_t3_nonce`, its caller. A path-only exemption would therefore
# leave the bypass wide open WITHIN the exempt file, which is the whole point of
# narrowing it: a second function in this module could install any object it liked.
_NONCE_FACTORY_PATH: Path = _REPO_ROOT / "src" / "alfred" / "bootstrap" / "nonce_factory.py"
_FUNCTION_SCOPED_EXEMPTIONS: frozenset[tuple[Path, str]] = frozenset(
    {(_NONCE_FACTORY_PATH, "create_and_register_t3_nonce")}
)

# The same file's MODULE-LEVEL import line, which sits outside the exempt function and
# so cannot be covered by the (path, function) key. Scoped to `ast.alias` so a
# module-level CALL still reds, and — see `_private_surface_is_exempt` — to MODULE
# SCOPE, so a function-local aliased import does not inherit it. Without that second
# condition the exemption is functionally path-only again, by a different route.
_IMPORT_ONLY_EXEMPT_PATHS: frozenset[Path] = frozenset({_NONCE_FACTORY_PATH})

# Test trees are exempt: tests assert the patterns the gate forbids.
# Matched as a resolved PATH COMPONENT, never as a substring of the raw
# string. Two bugs lived in the old substring-on-raw-string form (#537):
#
#   * ``tests/../src/alfred/foo.py`` was exempt while ``src/alfred/foo.py``
#     was not — the same file. A DIRECTORY argument poisoned everything
#     beneath it, and it needed no absolute path, so it was reachable from
#     the production invocation (``Makefile`` and CI both pass relative
#     paths). This is #428's ``/lib64/../etc`` class on the exemption axis.
#   * a checkout under any ancestor directory named ``tests`` made the whole
#     gate vacuous for absolute-path invocations.
#
# Resolving first fixes both: the component check runs on the real location.
_TEST_DIR_NAME: str = "tests"


def _is_exempt(path: Path) -> bool:
    """Return True if ``path`` is allowed to contain the disallowed patterns.

    **Resolve first, then match.** Every exemption decision is made against
    the resolved absolute path, so ``..`` traversal and symlinks cannot
    present one identity to the matcher and another to the reader.

    Exempt set:
      * the explicit authorised home in ``_APPROVED_PATHS``, by resolved
        absolute-path equality — a file outside this repo that merely ends
        with ``src/alfred/security/tiers.py`` is NOT exempt;
      * any path under this repo's own ``tests/`` tree, matched by resolved
        path COMPONENTS relative to the repo root. CR-138 round-2 finding #1
        still holds: an in-repo ``test_*.py`` outside ``tests/`` is not
        exempt, so an attacker cannot ship ``src/alfred/foo/test_bypass.py``;
      * any ``test_*.py`` whose **resolved** path is outside this repo — the
        ``tmp_path`` fixtures the unit suite plants. Keyed on
        ``resolved.name``, NOT ``path.name``: an in-repo symlink named
        ``test_bypass.py`` pointing at an out-of-repo file previously
        satisfied the basename check with the LINK and the location check
        with the TARGET.
    """
    try:
        resolved = path.resolve(strict=False)
        # ``absolute()`` + ``normpath`` are pure-lexical and consult the same cwd
        # ``resolve()`` does, so they cannot fail once it has succeeded. They
        # share this guard rather than carrying an unreachable one of their own.
        lexical = Path(os.path.normpath(path.absolute()))
    except (OSError, RuntimeError, ValueError):
        # A path we cannot resolve is not one of the known-good homes.
        # ValueError is NOT redundant: an embedded NUL raises ValueError, not
        # OSError, on POSIX. NOT "on every supported platform" — that claim was
        # here and #547 measured it false: windows-latest resolves an embedded
        # NUL without complaint. The guard stays broad because WHICH exception
        # a hostile path produces is a platform fact this code should not
        # predict, which is the same reason the arm catches three classes.
        return False

    # Lexical normalisation collapses ``..`` WITHOUT following symlinks. Both
    # views are needed because they answer different questions:
    #
    #   * ``..`` traversal is a pure string problem  -> normalise lexically.
    #   * a symlink is a filesystem fact             -> resolve().
    #
    # Deciding on the RESOLVED path alone was a regression: a tracked symlink at
    # ``src/alfred/security/loader.py`` pointing into ``tests/`` bought exemption
    # for production code (measured rc=0 where the previous gate reported rc=1).
    # Deciding on the LEXICAL path alone reopens the ``..`` traversal. Both ends
    # of a symlink are author-controlled, so a path is exempt only when BOTH
    # views agree that it is — the stricter of the two always wins.
    return _view_is_exempt(lexical) and _view_is_exempt(resolved)


def _view_is_exempt(candidate: Path) -> bool:
    """Exemption verdict for ONE absolute view of a path. See :func:`_is_exempt`.

    ``candidate`` must already be absolute and free of ``..`` segments.
    """
    if candidate in _APPROVED_PATHS:
        return True

    if candidate.is_relative_to(_REPO_ROOT):
        # In-repo: exempt only by living under the repo's own TOP-LEVEL tests/
        # tree. Matching ``tests`` at any depth exempted production code —
        # ``src/alfred/security/tests/bypass.py`` is importable as
        # ``alfred.security.tests.bypass`` and was exempt. That hole predates
        # this gate's rewrite but the scan root now includes ``plugins/`` too,
        # so it is closed here rather than carried forward.
        parts = candidate.relative_to(_REPO_ROOT).parts
        return bool(parts) and parts[0] == _TEST_DIR_NAME

    # Out-of-repo: the tmp_path fixture exemption. Keyed on this view's own
    # basename so a symlink cannot borrow a ``test_*`` name it does not own.
    return candidate.name.startswith("test_") and candidate.suffix == ".py"


def _call_name(node: ast.Call) -> str | None:
    """Return the bare callable name for ``node`` (e.g. ``tag``, ``cast``).

    Both shapes resolve to the same callable name from the gate's POV:

    - ``tag(T3, ...)``        → ``ast.Name(id="tag")``      → ``"tag"``
    - ``module.tag(T3, ...)`` → ``ast.Attribute(attr="tag")`` → ``"tag"``
    - ``typing.cast(...)``    → ``ast.Attribute(attr="cast")`` → ``"cast"``

    Returns ``None`` for any other shape (subscript, lambda call, etc.) —
    those are not the patterns the gate is looking for.

    CR-138 round-2 finding #2: prior versions returned ``None`` for any
    ``ast.Attribute`` target, so qualified calls like ``module.tag(T3,
    ...)`` or ``typing.cast(TaggedContent[T2], x)`` silently bypassed
    both ``_is_tag_t3_call`` and ``_is_cast_tagged_content_call``. The
    import-rename attack (``from … import tag as t; t(T3, x)``) remains
    out of scope — the renamed binding still trips the suppression-
    comment rule whenever a cast-style suppressor is added.
    """
    func = _callee(node)
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _arg_name(node: ast.expr) -> str | None:
    """Return the bare identifier for ``node`` (e.g. ``T3``, ``TaggedContent``).

    Mirrors :func:`_call_name` on the argument side: both ``T3`` and
    ``tiers.T3`` resolve to the identifier ``"T3"``. Without this, the
    qualified-call widening from CR-138 round-2 finding #2 would only
    cover the call target — the first positional arg pattern
    ``module.T3`` would still slip past.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


# Bounded, and deliberately INPUT-INDEPENDENT. A bound of `len(assignments) + 1`
# makes the loop-exhaustion arc unreachable BY CONSTRUCTION — the fixed point always
# converges first — and this file is under a REQUIRED 100% branch gate with no
# pragmas allowed, so an unreachable arc is an unsatisfiable gate, not a safe
# default. A fixed budget makes exhaustion a real outcome a test can reach, and the
# honest disposition for it is a reported violation: the input is pathological, not
# the gate (contrast `GateInternalError`, which means the gate itself is broken).
_ALIAS_RESOLUTION_BUDGET: int = 32

# `_fold_str` recurses once per nested operand, and it is called from inside
# `_scan_text`'s `GateInternalError` fence, where an exception means "the GATE is
# broken": `main` prints it, DISCARDS every violation collected so far and exits 2.
# So an unbounded fold turns one pathological `+` chain (~2000 operands raises
# RecursionError under the default limit) into the suppression of a real laundering
# finding in an EARLIER file. Bounding here keeps the fence meaning what it says.
#
# Past the bound `_fold_str` returns None, which every caller reads as "not a string
# literal". The cost is therefore local and one-directional: a name assembled by a
# chain that deep is not matched, exactly as a name assembled by `%`, `.format()` or
# `"".join()` is not matched — an already-stated residual, not a new class.
#
# Its OWN constant rather than a reuse of `_ALIAS_RESOLUTION_BUDGET`: one bounds a
# fixed-point iteration over a file's assignments, the other bounds expression
# nesting. Sharing a name would let a future retune of either silently move the other.
_FOLD_MAX_DEPTH: int = 32


def _prose_string_ids(tree: ast.AST) -> frozenset[int]:
    """``id()`` of every string constant that is PROSE rather than code.

    Prose is a **bare string expression statement**: a module, class or function
    docstring, or a PEP-258 attribute docstring (a bare string after an assignment).
    ``ast.get_docstring`` covers only the first three; ``src/alfred/hooks/invoke.py:466``
    is the fourth shape and is a MEASURED false positive without it.

    WHY NOT exclude every string constant: ``getattr(_t, "_set_authorized_t3_nonce")``
    hides the name in a string ARGUMENT. Excluding all strings would admit it. The
    discriminator is POSITION — a string that is a whole statement is not MATCHED here.

    IT IS STILL REACHABLE AS DATA, and the earlier wording of this docstring denied it
    (PR #553 review, F1). It claimed "a string anywhere else is data the program uses",
    which reads as: prose cannot be used. False — ``__doc__`` hands the excluded string
    straight back in code position, and the review executed both halves of that channel
    (an attacker nonce installed from a class docstring; a live object's ``tier``
    rewritten from a function docstring). What this function decides is only whether a
    string is MATCHED, never whether it is inert. ``__doc__`` is therefore a member of
    :data:`_RAW_STATE_VEHICLE_ATTRS` — the exclusion stays and the RETRIEVAL is banned,
    because narrowing the exclusion instead would readmit the ``getattr`` spelling above.

    WHAT THIS CANNOT DO: a ``#`` comment is invisible to the parser, so a private name
    there is neither prose-excluded nor flagged. Correct (a comment cannot launder) but
    a different mechanism from this one.
    """
    return frozenset(
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _enclosing_functions(tree: ast.AST) -> dict[int, tuple[str, int]]:
    """Map every line to its INNERMOST enclosing ``(function name, scope depth)``.

    Module-scope lines are ABSENT from the map, which is load-bearing: the
    module-level import exemption keys on ``.get(lineno) is None``.

    **Both ``def`` and ``async def``**, in ONE ``isinstance`` over the tuple. A walk
    matching only ``ast.FunctionDef`` silently maps nothing for ``async def`` and no
    test in this repo fails — the sole real (path, function) exemption is a plain
    ``def``. One tuple check also means the 332-file real-tree scan exercises both
    node types, so the branch cannot rot behind a fixture.

    THE DEPTH IS WHY THIS IS A DFS RATHER THAN ``ast.walk`` (PR #553 review, F4). The
    innermost mapping alone made the (path, function) exemption defeatable by NESTING: a
    ``def create_and_register_t3_nonce`` written inside another function in
    ``nonce_factory.py`` was mapped to that name and inherited the exemption — which is
    precisely the property the (path, function) key was chosen to have ("a second
    function in this module could install any object it liked"). The nested def IS that
    second function, wearing the first one's name.

    Depth counts ENCLOSING SCOPES, not enclosing functions, so ``class`` bodies count.
    A method of a module-level class is depth 1: counting only functions would have
    closed the nested-``def`` spelling and left the same-named METHOD open, which is the
    enumerate-the-spelling mistake this file exists to stop repeating.

    Pre-order DFS: a node is mapped BEFORE its children are pushed, so an inner function
    always overwrites the lines of the one containing it — the same "innermost wins"
    property ``ast.walk``'s breadth-first order gave, now with the depth in hand.
    """
    mapping: dict[int, tuple[str, int]] = {}
    stack: list[tuple[ast.AST, int]] = [(tree, 0)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # MEASURED, not assumed: the parser sets `end_lineno` on every function it
            # produces — 13 381 function defs across the 1 211 tracked `.py` files in
            # this repo, zero of them None. typeshed types it `int | None` because a
            # HAND-BUILT node (constructed, never parsed) leaves it None, and this gate
            # only ever sees `ast.parse` output.
            #
            # ASSERTED, not defaulted. An `x if x is not None else node.lineno` fallback
            # would silently truncate the map on the one input that could reach it, and
            # `coverage.py` does not branch on a conditional expression — so that dead
            # arm would be invisible to this file's REQUIRED 100% branch gate, exempting
            # by construction precisely what the no-pragma rule forbids exempting.
            assert node.end_lineno is not None
            for line in range(node.lineno, node.end_lineno + 1):
                mapping[line] = (node.name, depth)
        # An `if`/`else` rather than a conditional expression, for the reason `_record`
        # gives: `coverage.py` does not branch on a ternary, so writing it that way would
        # hide an arm from this file's REQUIRED 100% branch gate. (Unlike `_record`'s,
        # this one needs no `noqa: SIM108` — ruff does not raise it here — so adding one
        # would itself red under RUF100.)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            child_depth = depth + 1
        else:
            child_depth = depth
        for child in ast.iter_child_nodes(node):
            stack.append((child, child_depth))
    return mapping


def _fold_str(node: ast.expr, depth: int = 0) -> str | None:
    """Constant-fold a string expression, or ``None`` if it is not a literal.

    ``ast.parse`` folds IMPLICIT concatenation (``"a" "b"``) into one ``Constant`` but
    leaves ``"a" + "b"`` as a ``BinOp``. Matching raw ``Constant`` nodes therefore
    missed ``"_set_authorized" + "_t3_nonce"``, which the review fleet executed
    end-to-end: it registered an attacker nonce and minted a fully legitimate
    ``TaggedContent[T3]`` for attacker content through ``tag_t3_with_nonce``.

    Recursion is bounded by ``_FOLD_MAX_DEPTH`` rather than by the input's own depth,
    because this runs inside ``_scan_text``'s ``GateInternalError`` fence — see that
    constant for why an unbounded fold suppresses findings in OTHER files.

    RESIDUAL, stated rather than implied: this folds ``+`` and implicit concatenation
    and nothing else. ``"_set_authorized%s" % "_t3_nonce"``,
    ``"_set_authorized{}".format("_t3_nonce")`` and ``"".join([...])`` are assembled
    entirely from literals and all fold to ``None`` here.

    THE SAME RESIDUAL APPLIES TO :data:`_RAW_STATE_VEHICLE_NAMES`, and it used to be
    written down only against the private-surface names (PR #553 review, F6):
    ``getattr(low, "__dict%s" % "__")["tier"] = T3`` scans clean for exactly this
    reason. Every caller of this function inherits it — the residual is the OPERATION,
    not the operands, so it is not a property of one name set.

    Deliberately NOT ``ast.literal_eval``: that evaluates tuples, dicts and numbers
    too, so it would answer a different question and raise on the common case.
    """
    if depth > _FOLD_MAX_DEPTH:
        return None
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _fold_str(node.left, depth + 1)
        right = _fold_str(node.right, depth + 1)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            folded = _fold_str(value, depth + 1)
            if folded is None:
                return None
            parts.append(folded)
        return "".join(parts)
    return None


def _name_bindings(node: ast.AST) -> list[tuple[str, str]]:
    """``(bound name, source name)`` for every statement that binds one NAME to another.

    DEFAULT-DENY OVER BINDING SHAPES. :func:`_alias_names` read ``ast.Assign`` alone, so
    ``X: TypeAlias = TaggedContent``, PEP-695 ``type X = TaggedContent`` and
    ``(X := TaggedContent)`` never entered any alias set — and a name outside ``tc_bare``
    silences the unparameterised, seam and subscript rules at once. Measured before this
    helper existed: all three scanned CLEAN while the plain assignment red.

    It is the same enumeration mistake :func:`_parameterised_bindings` was already written
    to avoid one layer up. Fixing it there and not here is what left the bare-class axis
    open, so it is fixed in the SHARED resolver — every rule that reads an alias set,
    #538's included, gains the closure at once.

    RESIDUAL, and it is the tuple-target one :func:`_parameterised_bindings` also states:
    ``A, B = TaggedContent, other`` binds through an ``ast.Tuple`` whose element order
    would have to be tracked against the value side. That shape has no ``ast.Name`` value,
    so it does not reach here — an unread binding rather than a misread one.
    """
    value = getattr(node, "value", None)
    if not isinstance(value, ast.Name):
        return []
    if isinstance(node, ast.Assign):
        targets: list[ast.expr] = list(node.targets)
    elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
        targets = [node.target]
    elif isinstance(node, ast.TypeAlias):
        targets = [node.name]
    else:
        return []
    return [(t.id, value.id) for t in targets if isinstance(t, ast.Name)]


def _alias_names(tree: ast.AST, seed: str) -> tuple[frozenset[str], bool]:
    """Local names bound to ``seed``, to a fixed point. Returns (names, overflowed).

    Two binding forms: ``from m import X as Y`` and a plain ``B = X`` rebind, including
    chains. THE FIXED POINT IS PROVEN REQUIRED: with ``C = B`` written BEFORE
    ``B = BaseModel``, a single pass yields ``{BaseModel, B}`` and misses ``C``. Source
    order is the author's to choose, so a resolver that depends on it is one an attacker
    controls.

    Parameterised by ``seed`` because more than one rule needs it. v1 built this for
    ``BaseModel`` only and matched every other identifier bare, so ``_g = gc``,
    ``from gc import get_referents`` and ``_v = vars`` all scanned clean — and on the
    ``object`` receiver, executed, they minted genuine T3 objects with attacker content.

    RESIDUAL: the alias set is PER-FILE. A name re-exported through another module and
    imported under its new spelling is not resolved here.
    """
    names = {seed}
    assignments: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.alias) and node.name == seed and node.asname is not None:
            names.add(node.asname)
        # DEFAULT-DENY OVER BINDING SHAPES, not `ast.Assign` alone. Reading one statement
        # kind left `X: TypeAlias = TaggedContent`, PEP-695 `type X = TaggedContent` and
        # `(X := TaggedContent)` outside every alias set — and a name outside `tc_bare`
        # silences the unparameterised, seam and subscript rules simultaneously. Measured
        # on the shipped gate before this: all three scanned CLEAN while the plain
        # assignment red.
        #
        # This is the SAME enumeration mistake `_parameterised_bindings` was already
        # written to avoid one layer up, and fixing it there and not here is what left the
        # bare-class axis open. Widening the shared resolver closes it for every rule that
        # reads an alias set, #538's included.
        for bound_name, value in _name_bindings(node):
            assignments.append((bound_name, value))
    for _ in range(_ALIAS_RESOLUTION_BUDGET):
        grown = {t for t, source in assignments if source in names} - names
        if not grown:
            return frozenset(names), False
        names |= grown
    return frozenset(names), True


# The tier identifiers that are NOT T3, and the bound a generic tier helper carries.
#
# HARD-CODED on `_TIERS_PRIVATE_SURFACE`'s precedent and for its reason: the gate runs
# under bare `python3` from the Makefile with no venv and no `alfred` importable, so it
# cannot ask the module, and it must not read `tiers.py` at import time. The drift guard
# is `test_the_benign_tier_seeds_match_the_real_module`, called from the suite.
_BENIGN_TIER_SEEDS: tuple[str, ...] = ("T0", "T1", "T2")
_TRUST_TIER_NAME: str = "TrustTier"
_TYPEVAR_NAME: str = "TypeVar"


class _SliceVerdict(enum.Enum):
    """What a ``TaggedContent[...]`` generic argument resolves to. THREE, not two.

    ``UNRESOLVED`` is the whole point of this type. The rule this replaces asked "is this
    slice the name ``T3``?" and answered "no" for ``"T"+"3"``, ``globals()["T3"]``,
    ``TIERS["T3"]``, ``T3 if x else T2`` and ``(T3,)`` alike — fail-OPEN on every
    non-``Name`` shape. A two-valued verdict cannot express "I could not read this", so it
    has to guess, and the safe guess and the quiet guess are different guesses.

    THE THIRD MEMBER IS NOT DECORATION, and the plan review proved it by execution. The
    first revision of :func:`_tier_alias_env` classified derived bindings with
    ``t3_seeds if verdict is T3 else benign_seeds`` — a two-way ternary over a
    three-valued verdict — which routed every ``UNRESOLVED`` into the BENIGN bucket. All
    shapes above then scanned CLEAN once bound to a name
    (``X = TaggedContent["T" + "3"]``; ``X(content=ATTACKER)``) while the identical inline
    slice correctly red. A set-per-verdict silently drops the verdict that has no set,
    which is why parameterised bindings travel as a verdict MAP below.
    """

    T3 = "t3"
    BENIGN = "benign"
    UNRESOLVED = "unresolved"


# DEFAULT-DENY ORDER. When one name is bound more than once the STRICTER verdict wins, so
# `X = P` followed by `X = Q` cannot be used to walk a name back down to benign.
_SLICE_VERDICT_STRICTNESS: dict[_SliceVerdict, int] = {
    _SliceVerdict.BENIGN: 0,
    _SliceVerdict.UNRESOLVED: 1,
    _SliceVerdict.T3: 2,
}


def _stricter(candidate: _SliceVerdict, incumbent: _SliceVerdict | None) -> _SliceVerdict:
    """The stricter of two verdicts; ``candidate`` when there is no incumbent."""
    if incumbent is None:
        return candidate
    if _SLICE_VERDICT_STRICTNESS[candidate] > _SLICE_VERDICT_STRICTNESS[incumbent]:
        return candidate
    return incumbent


def _slice_verdict(
    node: ast.expr, t3_names: frozenset[str], benign_names: frozenset[str]
) -> _SliceVerdict:
    """TOTAL over ``ast.expr``. Every shape gets a verdict, and the default is DENY.

    Written as an ALLOW-LIST over the two shapes this gate can read — a bare or qualified
    identifier, and a quoted generic — with everything else falling through to
    ``UNRESOLVED``. An enumeration of BAD shapes closes what it names and silently widens
    the day the grammar grows one; this closes the axis.

    A QUOTED GENERIC IS A FORWARD-REFERENCED NAME, so it resolves through the SAME sets as
    the bare form. Matching it against the raw seed tuple instead was an asymmetry the
    review executed: with ``T2 = T3`` in scope, ``TaggedContent[T2](...)`` red while
    ``TaggedContent["T2"](...)`` scanned clean, because one arm was alias-resolved and the
    other was not.

    TOTALITY IS LOAD-BEARING BEYOND CORRECTNESS. This function is called from BOTH sides of
    ``_scan_text``'s :class:`GateInternalError` fence — from :func:`_detect` inside it, and
    from :func:`_tier_alias_env` outside it — so a raise here would surface as exit 2 down
    one path and exit 1 down the other for the same input. It has no raise path: every
    branch returns, and ``_arg_name`` is itself total over ``ast.expr``.

    The benign sets are what make the default-deny affordable. Measured across both scan
    roots: the only non-``T0..T3`` slices are ``TaggedContent[TierT]`` x3, ``[Any]`` x1 and
    ``[tier]`` x1, and ALL FIVE are inside the whole-file-exempt ``tiers.py``. The first
    generic helper written OUTSIDE it reds unless its TypeVar is bound to ``TrustTier`` —
    which :func:`_trust_tier_type_aliases` seeds — and a plain PARAMETER (``tiers.py:949``)
    is not rescued by anything lexical.
    """
    name = _arg_name(node)
    if name is None and isinstance(node, ast.Constant) and isinstance(node.value, str):
        name = node.value
    if name is None:
        return _SliceVerdict.UNRESOLVED
    if name in t3_names:
        return _SliceVerdict.T3
    if name in benign_names:
        return _SliceVerdict.BENIGN
    return _SliceVerdict.UNRESOLVED


class TierAliasEnv(NamedTuple):
    """The per-file tier name environment every tier rule decides on.

    ``tc_param`` is a MAPPING rather than one set per verdict, and that is the shape the
    plan review forced: a set-per-verdict has no home for ``UNRESOLVED``, so classification
    collapses to two ways and the default lands on the OPEN side. A map cannot lose a
    verdict. See :class:`_SliceVerdict` for the executed bypass.

    Every member is produced by :func:`_alias_names`, the ONE seed-parameterised resolver
    this gate owns. A second resolver would be the #422 shape — a shared helper fails LOUD,
    N copies drift SILENTLY — and on this axis the drift is a bypass.
    """

    tc_bare: frozenset[str]
    """Names bound to the bare ``TaggedContent`` class."""

    tc_param: Mapping[str, _SliceVerdict]
    """Names bound to a PARAMETERISED ``TaggedContent[...]``, mapped to the tier verdict.

    A read-only ``Mapping`` rather than a ``dict``: it is built once and never mutated
    after construction, and this repo's conventions say ``Mapping`` for read-only inputs.
    """

    t3: frozenset[str]
    """Names bound to ``T3``."""

    benign_tier: frozenset[str]
    """Names bound to a non-T3 tier, plus in-file generic tier parameters."""

    dict_names: frozenset[str]
    """Names bound to the ``dict`` builtin.

    KEYED ON THE ADMITTING SIDE, which is why it is resolved rather than declared a
    residual. The copy rule reads a mapping only when it can recognise its constructor, so
    an UNRESOLVED ``dict`` alias meant `_d = dict; low.model_copy(update=_d(tier=T3))`
    scanned CLEAN — measured. An earlier revision declared that rebinding `dict` "makes
    the gate stricter"; that is true inside a ``**`` operand and false at the top level,
    which is exactly the kind of promise this repo has learned to measure instead.
    """


def _parameterised_bindings(node: ast.AST) -> list[tuple[str, ast.Subscript]]:
    """``(bound name, subscript)`` for every binding of a subscript to a NAME.

    DEFAULT-DENY OVER BINDING SHAPES, not an enumeration of the one the review happened to
    write. Keyed on ``.value`` being an ``ast.Subscript`` and then on the node kind that
    names the target, which is the same discipline :func:`_binding_name` already applies
    one layer down. Reading ``ast.Assign`` alone left ``X: TypeAlias = TaggedContent[T3]``,
    PEP-695 ``type X = TaggedContent[T3]`` and the walrus all scanning clean — measured,
    not supposed.

    RESIDUAL, and the enumeration here is the WHOLE list rather than the one shape that
    came to mind first: a binding whose value is not directly a ``Subscript`` in ``.value``
    does not reach this function at all. That covers a tuple target
    (``A, B = TaggedContent[T3], other``), a starred target, a ``for``/``with``/``except``
    target, and an augmented assignment. Each is an UNREAD binding rather than a misread
    one — the name simply stays unknown, which leaves the unparameterised rule to decide it
    on the bare-class axis. Stated in full because a short list reads as a complete one.
    """
    value = getattr(node, "value", None)
    if not isinstance(value, ast.Subscript):
        return []
    if isinstance(node, ast.Assign):
        targets: list[ast.expr] = list(node.targets)
    elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
        targets = [node.target]
    elif isinstance(node, ast.TypeAlias):
        targets = [node.name]
    else:
        return []
    return [(t.id, value) for t in targets if isinstance(t, ast.Name)]


def _trust_tier_type_aliases(
    tree: ast.AST, t3_names: frozenset[str]
) -> tuple[frozenset[str], bool]:
    """In-file generic tier parameters — PEP-695 aliases and ``TypeVar(bound=TrustTier)``.

    WITHOUT THIS the first generic helper written OUTSIDE ``tiers.py`` reds for a benign
    reason: ``TaggedContent[TierT]`` is a legitimate shape and ``TierT`` is in no tier set.
    ``tiers.py`` carries three such sites today and is whole-file exempt, so this seeding
    buys nothing on the current tree — it is what keeps :func:`_slice_verdict`'s
    default-deny affordable for the NEXT such helper.

    ``TrustTier`` IS ALIAS-RESOLVED, AND A BOUND THAT NAMES A TIER IS REFUSED. This set is
    on the ADMITTING side, so a bare literal here is a bypass rather than a residual — and
    the review executed it: with ``TrustTier = T3`` in scope, ``type TierT = TrustTier``
    followed by ``TaggedContent[TierT](...)`` scanned clean. The first revision declared
    that "rebinding makes the gate STRICTER", which is false in every direction for an
    admitting set. Both legitimate spellings stay clean; the rebound one does not.

    IT DOES NOT RESCUE A PLAIN PARAMETER. ``tiers.py:949`` is ``TaggedContent[tier](...)``
    where ``tier`` is a function parameter, and no lexical set can decide what a caller
    passed. Stated here so the next reader does not expect it to.
    """
    # THE OVERFLOW FLAG IS RETURNED, not dropped. This was the one `_alias_names` call
    # site of nine that swallowed it. The direction is fail-CLOSED — an unresolved
    # `TrustTier` chain shrinks the admitting set, so the gate gets stricter — but the
    # gate's contract is to fail closed AND LOUDLY, and a swallowed flag means an
    # overflowing file is decided on an admittedly incomplete set with no diagnosis.
    trust_names, overflowed = _alias_names(tree, _TRUST_TIER_NAME)
    admitting = trust_names - t3_names
    # THE CALLEE MATTERS, and omitting it widened the ADMITTING set to any call at all:
    # `X = attacker(bound=TrustTier)` seeded `X` as a benign tier, so `TaggedContent[X](...)`
    # scanned clean. Only a `TypeVar` bound counts, and `TypeVar` is itself alias-resolved
    # because this whole set is keyed in the admitting direction — where a rebind WIDENS.
    typevar_names, grew = _alias_names(tree, _TYPEVAR_NAME)
    overflowed = overflowed or grew
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.TypeAlias):
            if _arg_name(node.value) in admitting:
                names.add(node.name.id)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            bound = next((kw.value for kw in node.value.keywords if kw.arg == "bound"), None)
            callee = _arg_name(_callee(node.value))
            if bound is not None and _arg_name(bound) in admitting and callee in typevar_names:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
    return frozenset(names), overflowed


def _tier_alias_env(tree: ast.AST) -> tuple[TierAliasEnv, bool]:
    """The tier name environment for ONE file, plus whether any alias chain overflowed.

    DERIVATION ORDER IS A DAG, NOT AN OUTER FIXED POINT. ``tc_bare``, ``t3`` and
    ``benign_tier`` are direct :func:`_alias_names` seeds. ``tc_param`` is then derived from
    ``X = <tc_bare>[<slice>]`` bindings, and each discovered TARGET is fanned back through
    ``_alias_names`` — so ``B = A`` written before ``A = TaggedContent[T3]`` still resolves
    ``B``, because the fixed point is ``_alias_names``'s rather than a second one written
    here.

    THE SEED LOOPS DELIBERATELY USE THE VARIABLE NAME ``seed``. The meta-guard's derivation
    (`_identifiers_the_gate_keys_on`) collects loop variables that reach ``_alias_names``,
    and it recognises this call shape by that name. Renaming the variable hard-reds
    `test_every_keyed_identifier_is_alias_resolved`; `test_the_seed_loop_variable_is_named_seed`
    pins it so the coupling is visible rather than discovered.

    A NAME BOUND BOTH BARE AND PARAMETERISED IS AMBIGUOUS, and is raised to at least
    ``UNRESOLVED``. Without that, ``Cool = TaggedContent[T2]`` followed by
    ``Cool = TaggedContent`` returned BENIGN and silenced the unparameterised-construction
    rule for ``Cool(tier=T3)`` — executed by the review.

    RESIDUAL, inherited from :func:`_alias_names` and restated because it bites harder on
    this axis: the environment is PER-FILE. A ``TaggedContent`` re-exported through another
    module and imported under its new spelling is not resolved.

    RESIDUAL, and a name-keyed set cannot close it: ``benign_tier`` holds bare NAMES, so a
    parameter or local named ``T2`` is treated as benign — ``def f(T2): TaggedContent[T2](...)``
    with a caller passing ``T3`` scans clean. It is masked by the runtime guard
    (``_refuse_unauthorized_t3`` fires regardless of parameterisation), which is what makes
    it an acceptable residual rather than a hole.
    """
    overflowed = False
    tc_bare, grew = _alias_names(tree, "TaggedContent")
    overflowed = overflowed or grew
    t3, grew = _alias_names(tree, "T3")
    overflowed = overflowed or grew

    benign: set[str] = set()
    for seed in _BENIGN_TIER_SEEDS:
        resolved, grew = _alias_names(tree, seed)
        benign |= resolved
        overflowed = overflowed or grew
    dict_names, grew = _alias_names(tree, "dict")
    overflowed = overflowed or grew
    trust_aliases, grew = _trust_tier_type_aliases(tree, t3)
    overflowed = overflowed or grew
    benign |= trust_aliases
    benign_tier = frozenset(benign)

    seeds: dict[str, _SliceVerdict] = {}
    for node in ast.walk(tree):
        for name, subscript in _parameterised_bindings(node):
            if _arg_name(subscript.value) not in tc_bare:
                continue
            verdict = _slice_verdict(subscript.slice, t3, benign_tier)
            seeds[name] = _stricter(verdict, seeds.get(name))

    tc_param: dict[str, _SliceVerdict] = {}
    for seed, verdict in sorted(seeds.items()):
        resolved, grew = _alias_names(tree, seed)
        overflowed = overflowed or grew
        for name in resolved:
            tc_param[name] = _stricter(verdict, tc_param.get(name))
    for name in tc_param:
        if name in tc_bare:
            tc_param[name] = _stricter(_SliceVerdict.UNRESOLVED, tc_param[name])

    return (
        TierAliasEnv(
            tc_bare=tc_bare,
            tc_param=tc_param,
            t3=t3,
            benign_tier=benign_tier,
            dict_names=dict_names,
        ),
        overflowed,
    )


def _record(violations: list[str], lines: list[str], path: Path, lineno: int, message: str) -> None:
    """Append a violation MESSAGE line plus its source SNIPPET line.

    Every rule reports the same two-line shape, so tests assert the returned list by
    equality rather than by substring search. Factored out because every rule repeating
    the pair would be one more place for the shape to drift (#422: a shared helper fails
    LOUD, N copies drift SILENTLY). NO COUNT IS NAMED HERE, for the reason
    :class:`GateInternalError` gives: this text said "nine rules" and Task 3 made it ten
    on the first edit after it was written.

    ``path`` travels as an argument because this repo forbids global state.

    THE BOUNDS GUARD, and why it is an ``if``/``else`` rather than a conditional
    expression: ``coverage.py`` does not branch on a ternary, so writing it that way
    would hide the arm from this file's REQUIRED 100% branch gate — exempting by
    construction exactly what the no-pragma rule forbids exempting. No ``_scan_text``
    INPUT is known to reach the else arm (``str.splitlines`` splits on strictly more
    separators than the tokenizer does, so the line list is never SHORTER than the
    parser's line numbering). It stays anyway because every rule shares this helper, and
    a finding must never become an ``IndexError`` that the broad ``except`` re-files as
    an unscannable file — a real laundering finding downgraded to a vague one. It is
    covered by a direct unit test rather than by a pragma.
    """
    # The SIM108 suppression below is DELIBERATE and load-bearing, not a style
    # concession. `coverage.py` does not branch on a conditional expression, so ruff's
    # suggested ternary would make the else arm invisible to this file's REQUIRED 100%
    # branch gate — the no-pragma rule forbids exempting a branch, and a ternary
    # exempts it silently.
    if 0 <= lineno - 1 < len(lines):  # noqa: SIM108
        snippet = lines[lineno - 1].rstrip()
    else:
        snippet = ""
    violations.append(f"{path}:{lineno}: {message}")
    violations.append(f"  {snippet}")


def _is_benign_state_mutation_target(node: ast.Call) -> bool:
    """True for the established frozen-dataclass idiom, false for every vehicle.

    SHARED BY ``__setattr__`` AND ``__delattr__`` (PR #553 review, C1), because the
    question is character-for-character the same one: both put the TARGET at ``args[0]``
    and the FIELD NAME at ``args[1]``, and everything this predicate reads lives in
    those two positions. ``__setattr__``'s third argument is the value and ``__delattr__``
    has none, neither of which changes admissibility. A second copy differing only in the
    dunder it is called for is the #422 shape the rest of this file keeps naming — a
    shared helper fails LOUD, N copies drift SILENTLY — and the drift here would be
    silent in the worst direction: one of the two rules quietly admitting a shape the
    other refuses. Named for the CLASS rather than for either dunder so the next member
    of the family does not have to rename it.

    DEFAULT-DENY ON SHAPE. Admissible only when ALL of:

    * ``args[1]`` folds to a plain string literal — a computed name cannot be read by
      any lexical rule;
    * that literal is not a dunder — those reach interpreter state, not a field;
    * that literal is not in :data:`_TAGGED_STATE_FIELDS`. THIS IS THE CONDITION THAT
      HOLDS. v1 denied only ``"tier"``, so ``object.__setattr__(low, "content",
      ATTACKER)`` was admitted and EXECUTED to place raw attacker text inside a
      T2-tagged object the privileged orchestrator is entitled to read, and
      ``"source"`` forged audit provenance;
    * ``args[0]`` is the bare name ``self``. This NARROWS the surface but proves
      nothing on its own, and the comment here must not claim otherwise: an earlier
      revision justified it with "reaching a TaggedContent as ``self`` requires
      subclassing it, which ``__init_subclass__`` refuses at runtime". That is FALSE,
      and was disproved by execution — ``def _apply(self, v): object.__setattr__(self,
      "content", v)`` is a plain function whose first parameter merely happens to be
      called ``self``. ``self`` is a naming convention, not a type.

    A call with fewer than two arguments (``object.__setattr__(*parts)``,
    ``object.__delattr__(*parts)``) is refused rather than admitted: a call this rule
    cannot read is a call it must not admit.

    Three live sites depend on the admissible case and none may red:
    ``src/alfred/hooks/context.py:106``, ``src/alfred/plugins/web_fetch/allowlist.py:139``,
    ``src/alfred/plugins/web_fetch/fetch_dispatcher.py:219``. All three write ``self``. Measured
    false-positive cost of this shape across both scan roots: ZERO on the ``__setattr__``
    side, and ZERO on the ``__delattr__`` side for the stronger reason that the tree
    holds no ``__delattr__`` node of ANY carrier — attribute, bare name or string.

    ESCAPE HATCH, named so nobody invents one: a frozen dataclass that genuinely needs
    a ``tier`` field and is NOT a ``TaggedContent`` should set it through its own
    constructor, or the write belongs behind a named helper inside the already-exempt
    ``security/tiers.py`` — not behind a loosened rule.
    """
    if len(node.args) < 2:
        return False
    target = node.args[0]
    if not (isinstance(target, ast.Name) and target.id == "self"):
        return False
    name = _fold_str(node.args[1])
    if name is None:
        return False
    if name.startswith("__") and name.endswith("__"):
        return False
    return name not in _TAGGED_STATE_FIELDS


def _is_self_init_re_entry(node: ast.Call, receiver: ast.expr) -> bool:
    """True when this ``__init__`` call provably re-enters ``self``, false otherwise.

    THE SIBLING OF :func:`_is_benign_state_mutation_target`, and it exists for the same
    class of write (PR #553 review, F3). It is a SEPARATE function rather than a third
    caller of that one because the admissibility question genuinely differs: ``__init__``
    admits a zero-argument ``super()`` RECEIVER with no positional argument at all, and
    it has no field-name argument to fold. ``BaseModel.__init__`` calls
    ``validate_python(..., self_instance=self)``, which writes the instance mapping
    DIRECTLY — it traverses no method the model can override, so ``frozen=True`` never
    sees it. Executed against a real ``TaggedContent[T2]``:
    ``type(low).__init__(low, content=ATTACKER, source="operator.console",
    tier=low.tier)`` replaced the content and forged the provenance with the gate at
    rc=0. The BOUND spelling ``low.__init__(content=…)`` reaches the identical write with
    no positional argument at all, which is why admissibility is decided on the TARGET
    rather than on the presence of arguments.

    The tier is safe by a different mechanism, recorded here so nobody assumes this rule
    carries it: the cross-tier field validator refuses ``tier=T3`` on a
    ``TaggedContent[T2]`` and writes a ``security.t3_boundary.refused`` audit row
    (verified by execution). ``content`` and ``source`` had nothing.

    DEFAULT-DENY ON SHAPE, admissible only when the target is provably ``self``:

    * a ZERO-ARGUMENT ``super()`` receiver. The compiler binds that form to the enclosing
      method's own first parameter, so it cannot name a foreign object. ``super(C, obj)``
      names one explicitly and is refused. A starred ``super(*pair)`` is refused with it
      — any argument at all disqualifies the receiver. Keyword arguments do not need
      excluding: ``super`` accepts none (``TypeError`` at runtime), so ``super(**kw)``
      can only ever be the zero-argument form.
    * otherwise ``args[0]`` is the bare name ``self`` — the unbound-dispatch-onto-self
      idiom, live at three ``AlfredError.__init__(self, …)`` sites in
      ``src/alfred/egress/errors.py``.

    ``self`` and ``super`` are matched as LITERAL names, and unlike every other
    identifier in this gate that is correct rather than a gap: they are keyed in the
    ADMISSIBILITY direction, so rebinding either one makes the gate STRICTER. MEASURED,
    not argued: ``_s = super`` followed by ``_s()`` raises ``RuntimeError: super():
    __class__ cell not found``, because the compiler only creates the ``__class__`` cell
    when it sees the literal name ``super`` in the method body. The rebound spelling is
    dead at runtime and refused here anyway.

    Measured false-positive cost across both scan roots: ZERO. All 62 ``__init__``
    attribute nodes are calls, 59 through zero-argument ``super()`` and 3 onto ``self``.
    """
    if (
        isinstance(receiver, ast.Call)
        and isinstance(receiver.func, ast.Name)
        and receiver.func.id == "super"
        and not receiver.args
    ):
        return True
    if not node.args:
        return False
    target = node.args[0]
    return isinstance(target, ast.Name) and target.id == "self"


def _carrier_bindings(tree: ast.AST) -> tuple[frozenset[tuple[str, str]], frozenset[str], bool]:
    """Resolve :data:`_RAW_STATE_CARRIERS` against ONE file's bindings.

    Returns ``(qualified_pairs, direct_names, overflowed)``:

    * ``qualified_pairs`` — every ``(module_alias, primitive)`` the file could spell as
      an attribute call. The MODULE half is alias-resolved because keying on the literal
      ``gc`` left ``import gc as _g`` and ``_g = gc`` scanning clean (fleet sec2-003).
    * ``direct_names`` — primitives bound as bare ``Name``s by
      ``from gc import get_referents``. No module identifier appears at that call site
      at all, so no amount of receiver resolution can see it; it needs its own pass.
      That pass runs ONCE over ``ast.ImportFrom`` rather than inside a per-carrier loop:
      a ``break`` in the per-carrier form attributes the finding to whichever carrier
      the loop happened to be on.
    * ``overflowed`` — any module's alias chain exceeded
      :data:`_ALIAS_RESOLUTION_BUDGET`, which the caller reports as a violation.

    The ``from`` module is matched literally on purpose: Python has no syntax that
    aliases the module name in ``from <module> import <name>``, so there is no
    identifier to resolve on that side.
    """
    resolved: dict[str, frozenset[str]] = {}
    overflowed = False
    for module in sorted({module for module, _ in _RAW_STATE_CARRIERS}):
        aliases, module_overflowed = _alias_names(tree, module)
        resolved[module] = aliases
        overflowed = overflowed or module_overflowed
    pairs = frozenset(
        (alias, primitive)
        for module, primitive in _RAW_STATE_CARRIERS
        for alias in resolved[module]
    )
    direct: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for imported in node.names:
                if (node.module, imported.name) in _RAW_STATE_CARRIERS:
                    direct.add(imported.asname or imported.name)
    return pairs, frozenset(direct), overflowed


def _private_surface_names(tree: ast.AST) -> tuple[frozenset[str], bool]:
    """Resolve :data:`_TIERS_PRIVATE_SURFACE` against ONE file's bindings.

    Returns ``(names, overflowed)``, mirroring :func:`_carrier_bindings`.

    R2-A, and it is the whole rule rather than a refinement of it: with
    ``from alfred.security.tiers import _set_authorized_t3_nonce as _reg``, the CALL
    ``_reg(mine)`` is the laundering and the import is only its setup. A rule that saw
    the import alone would be closed by moving the import into a helper module. So the
    asname is POISONED — every local name bound to a private name is itself private.

    Fans :func:`_alias_names` out over the 21 seeds rather than adding a second
    resolver: an identifier this gate keys on must be resolved by the ONE mechanism the
    meta-guard test enumerates, or the next rebinding spelling walks straight through.
    Measured cost of the fan-out across the 332 files under both scan roots: ~2s.
    """
    names: set[str] = set()
    overflowed = False
    for seed in sorted(_TIERS_PRIVATE_SURFACE):
        resolved, seed_overflowed = _alias_names(tree, seed)
        names |= resolved
        overflowed = overflowed or seed_overflowed
    return frozenset(names), overflowed


def _binding_name(node: ast.AST) -> str | None:
    """The single name ``node`` BINDS, or ``None`` if it binds nothing.

    Used only by :func:`_derive_tiers_private_surface`. Keyed on the BINDING NODE, not
    on the statement kind: R2-N measured that a six-arm statement walk
    (``Assign``/``AnnAssign``/``TypeAlias``/``def``/``class`` plus recursion) misses
    ``import _mod``, ``from m import y as _z``, ``for`` targets, ``with ... as``,
    ``except ... as``, the walrus, all three ``match`` capture kinds, and — inside the
    shape it claimed to cover — the ``_rest`` of ``_h, *_rest = ...``. Every one of
    those reaches this function as a node whose kind names the binding directly.

    ``ast.TypeAlias`` needs no arm of its own: its ``name`` field is an ``ast.Name``
    in ``Store`` context, so the first arm already sees it.
    """
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
        return node.id
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name
    if isinstance(node, ast.alias):
        # `import a.b.c` binds `a`, not `a.b.c`. `asname` wins when present.
        return (node.asname or node.name).partition(".")[0]
    if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
        return node.name
    if isinstance(node, ast.MatchMapping):
        return node.rest
    return None


def _derive_tiers_private_surface(source: str) -> frozenset[str]:
    """Every ``_``-prefixed non-dunder name ``source`` binds at MODULE level.

    THE DRIFT GUARD for :data:`_TIERS_PRIVATE_SURFACE`, called from the test suite and
    never from the gate — the gate must not read ``tiers.py`` at import time.

    DEFAULT-DENY OVER BINDING SHAPES (R2-N). The walk descends through every node of
    every module-level statement, so a name bound inside ``if TYPE_CHECKING:``, a
    ``try``/``except``, a ``with`` or a ``match`` is collected exactly like one bound
    at the top. It STOPS at a scope boundary — ``def``, ``async def``, ``class`` and
    ``lambda`` contribute their own name and nothing from their body, because a name
    bound in there belongs to that scope and is not part of the module's surface.

    Iterative rather than recursive: this walks arbitrary parsed source, and a
    recursive form would inherit the interpreter's stack limit on input it does not
    control.

    RESIDUAL: a comprehension's own target leaks into the result (it binds in the
    comprehension's scope, not the module's). That over-collects, so it can only make
    the drift guard FAIL LOUDLY and never silently under-cover; ``tiers.py`` has no
    module-level comprehension binding a private name today.
    """
    bound: set[str] = set()
    stack: list[ast.AST] = list(ast.parse(source).body)
    while stack:
        node = stack.pop()
        name = _binding_name(node)
        if name is not None and name.startswith("_") and not name.startswith("__"):
            bound.add(name)
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(node))
    return frozenset(bound)


def _private_surface_hit(
    node: ast.AST,
    prose: frozenset[int],
    private_names: frozenset[str] = _TIERS_PRIVATE_SURFACE,
) -> str | None:
    """The private name ``node`` reaches, or ``None``. FOUR carriers.

    ``ast.Name`` and ``ast.Attribute`` are the ordinary spellings
    (``_set_authorized_t3_nonce(x)`` and ``_t._AUTHORIZED_T3_NONCE``). ``ast.alias``
    covers BOTH halves of an import: the imported ``name``, and the ``asname``, which
    nothing else reaches — every other alias fixture binds a name that is already
    private, so the ``name`` check short-circuits first.

    The fourth carrier is any expression :func:`_fold_str` resolves to a string in
    NON-PROSE position. ``getattr(_t, "_set_authorized_t3_nonce")(mine)`` produces no
    ``Name`` or ``Attribute`` node carrying the name at all, and
    ``"_set_authorized" + "_t3_nonce"`` was executed by the review fleet to forge the
    nonce end to end. Matched by CONTAINMENT, not equality, so the dotted spelling
    ``"alfred.security.tiers._set_authorized_t3_nonce"`` is caught too.

    ``private_names`` DEFAULTS to the module's own surface, and :func:`_scan_text`
    passes the per-file ALIAS-RESOLVED superset instead. The default exists for callers
    that have no tree in hand (the cardinality pin on ``nonce_factory.py``, which
    asserts the two sets coincide for that file before relying on it).
    """
    if isinstance(node, ast.Name) and node.id in private_names:
        return node.id
    if isinstance(node, ast.Attribute) and node.attr in private_names:
        return node.attr
    if isinstance(node, ast.alias):
        if node.name in private_names:
            return node.name
        if node.asname is not None and node.asname in private_names:
            return node.asname
    if isinstance(node, (ast.Constant, ast.BinOp, ast.JoinedStr)) and id(node) not in prose:
        folded = _fold_str(node)
        if folded is not None:
            for candidate in sorted(private_names):
                if candidate in folded:
                    return candidate
    return None


def _private_surface_is_exempt(
    node: ast.AST, resolved_path: Path, enclosing: dict[int, tuple[str, int]]
) -> bool:
    """Whether this private-surface reference is one of the authorised ones.

    NO COUNT IS NAMED, for the reason :class:`GateInternalError` gives: a number in
    prose rots the next time the exempt set moves, and this one is pinned by a
    cardinality test instead.

    ``resolved_path`` is resolved ONCE by :func:`_scan_file` and passed down, so this
    predicate — and :func:`_scan_text` around it — stays pure over its arguments. An
    earlier revision called ``path.resolve()`` per hit inside ``_scan_text``; measured,
    identical arguments then returned OPPOSITE verdicts depending on the process cwd
    while the purity pin stayed green.
    """
    if isinstance(node, ast.alias) and resolved_path in _IMPORT_ONLY_EXEMPT_PATHS:
        # MODULE SCOPE ONLY. Scoped to `ast.alias` so a module-level CALL still reds,
        # and to module scope so a FUNCTION-LOCAL aliased import does not inherit the
        # exemption — which it did in the first revision, making the whole thing
        # functionally path-only. `_enclosing_functions` leaves module-scope lines
        # ABSENT from the map, which is what `is None` reads.
        return enclosing.get(getattr(node, "lineno", 0)) is None
    # MODULE SCOPE (depth 0) on this arm too, which is the SAME discriminator the import
    # arm above uses (PR #553 review, F4). Without it the (path, function) key was
    # defeatable by writing a second `def create_and_register_t3_nonce` INSIDE another
    # function in the exempt file — `_enclosing_functions` maps a line to its innermost
    # function, so the nested def inherited the exemption and could install any object it
    # liked. Keying on the name alone made the narrowing cosmetic, exactly as the
    # `ast.alias`-only version of the import arm was before it grew this same condition.
    #
    # ONE expression rather than an early `return False`: this predicate is called per
    # hit, and a bare `and` chain adds no branch arc for the 100% gate to have to cover.
    enclosed = enclosing.get(getattr(node, "lineno", 0))
    return (
        enclosed is not None
        and enclosed[1] == 0
        and (resolved_path, enclosed[0]) in _FUNCTION_SCOPED_EXEMPTIONS
    )


def _is_tag_t3_call(node: ast.Call) -> bool:
    """``tag(T3, ...)`` — first positional arg is the identifier ``T3``.

    Accepts both the bare ``T3`` (``ast.Name``) and the qualified
    ``module.T3`` (``ast.Attribute``) form via :func:`_arg_name`. The
    qualified-call widening for CR-138 round-2 finding #2 covers the
    callable target; this helper covers the matching arg shape so the
    pair stays consistent (``tiers.tag(tiers.T3, ...)`` is the most
    natural qualified form an author would write).
    """
    if _call_name(node) != "tag":
        return False
    if not node.args:
        return False
    return _arg_name(node.args[0]) == "T3"


def _callee(node: ast.Call) -> ast.expr:
    """THE ONLY WAY ANY RULE MAY READ A CALL'S CALLABLE. Never ``node.func`` directly.

    ``(f := tag)(T3, payload)`` puts an ``ast.NamedExpr`` in ``Call.func``, so every rule
    that reads ``node.func`` and asks ``isinstance(..., ast.Name)`` or
    ``isinstance(..., ast.Attribute)`` answers "no" and scans CLEAN.

    THIS EXISTS BECAUSE THE FIRST FIX WAS AN ENUMERATION. #539 introduced
    :func:`_unwrap_walrus` and applied it at TWO of the eight positions that read a
    callable — so the subscript rule saw through the wrapper and seven others did not.
    Measured on the shipped gate before this accessor: ``(X := TaggedContent)(...)``,
    ``(f := tag)(T3, A)``, ``(f := cast)(...)``, ``(f := BaseModel.model_copy)(...)``,
    ``(f := low.model_copy)(...)``, ``(f := TaggedContent[T3].model_construct)(...)`` and
    ``(f := vars)(obj)`` ALL scanned clean while every unwrapped twin red — and two of the
    blinded rules are #538 sole-layer rules whose docstrings state that no runtime guard
    for them can exist.

    Most of those spellings were already blind BEFORE #539, because ``_call_name`` has
    always returned ``None`` for a non-``Name``/``Attribute`` callee. That makes this a
    pre-existing hole rather than a regression — and makes closing it here the only
    honest option, because fixing two positions and leaving six is precisely the
    enumerate-the-spelling mistake this whole epic exists to stop repeating.

    ``test_no_rule_reads_call_func_directly`` derives the rule set from this module's own
    AST and fails if any function other than this one touches ``.func`` on a call, so the
    NEXT rule cannot reintroduce the hole by writing the obvious thing.

    ``_scan_text``'s ``call_func_ids`` deliberately keeps the RAW ``node.func`` identity:
    a walrus-wrapped ``object.__setattr__`` then carries no attribute node in
    ``Call.func`` position, so the one-position whitelist reports it under the ALIASED
    rule — which is the correct verdict for it, and is why that rule was the one of the
    eight that already red.
    """
    return _unwrap_walrus(node.func)


def _unwrap_walrus(node: ast.expr) -> ast.expr:
    """Strip an assignment expression down to the value it binds.

    ``(X := TaggedContent[T3])(...)`` puts an ``ast.NamedExpr`` in ``Call.func``, so every
    rule that reads a callable or a receiver through :func:`_arg_name` sees ``None`` and
    falls through. The two-statement spelling — bind on one line, call on the next — is
    caught by the alias environment, so without this the SHORTER form was the one that
    scanned clean. Measured during acceptance, not supposed.

    Loops rather than recursing once: ``((X := (Y := TaggedContent[T3])))(...)`` nests, and
    the parser discards the parentheses but not the nodes. Bounded by the expression's own
    depth, which ``ast.parse`` has already bounded.
    """
    while isinstance(node, ast.NamedExpr):
        node = node.value
    return node


def _tagged_subscript_verdict(node: ast.Call, env: TierAliasEnv) -> _SliceVerdict | None:
    """The tier a ``TaggedContent``-ish construction CALL mints, or ``None`` if it is not one.

    Succeeds :func:`_is_tag_t3_call`'s sibling ``_is_tagged_content_t3_subscript_call``,
    which asked a yes/no question keyed on the literal identifiers ``TaggedContent`` and
    ``T3``. Both were rebindable, and both are now resolved through :class:`TierAliasEnv`.

    sec-S3-002: ``tag_t3_with_nonce`` checks the per-process nonce; the ``TaggedContent``
    Pydantic field validator does NOT. A direct subscript construction therefore admits raw
    T3 content without the gate. The single authorised home — ``security/tiers.py``, for the
    ``tag_t3_with_nonce`` body — is exempt via ``_APPROVED_PATHS``; everywhere else this
    trips, including every other module inside ``security/`` (#538).

    TWO CALL SHAPES reach the same construction and both must be read here:

    * ``TaggedContent[T3](...)`` — the subscript sits in ``Call.func``. Bare and qualified
      forms on BOTH halves collapse through :func:`_arg_name`, so ``tiers.TaggedContent``
      and ``tiers.T3`` are covered, as is the quoted ``TaggedContent["T3"]``.
    * ``Hot(...)`` where ``Hot = TaggedContent[T3]`` — there is NO subscript at the call
      site at all, so the predicate this replaces was blind to it by construction.

    ONE-POSITION WHITELIST, and it is why the 22 annotation sites across 5 files do not red:
    ``Call.func`` is the only position read. NEVER an ancestor blacklist — not because a
    blacklist misfires (a correctly scoped ``.annotation``-subtree blacklist regresses
    zero), but because it must ENUMERATE annotation-bearing positions and silently widens
    the day the grammar grows one. ``ast.TypeAlias`` already did exactly that. Thirteen of
    those 22 sites live outside any exempt file, in ``orchestrator/core.py``,
    ``plugins/content_store_base.py``, ``security/quarantine_transport.py`` and
    ``comms_mcp/real_turn_adapter.py``.
    """
    func = _callee(node)
    if isinstance(func, ast.Subscript):
        if _arg_name(func.value) is None:
            # AN UNREADABLE BASE IS NOT A CLEAN BASE. `_get_tc()[T3](...)` and
            # `_TCS[0][T3](...)` name no identifier this gate can resolve, so returning
            # the not-a-construction sentinel here reintroduces on the BASE axis exactly
            # the two-valued guess `_SliceVerdict` exists to remove from the SLICE axis.
            #
            # Scoped to a slice that resolves T3-ish, so it costs nothing on the benign
            # side: `whatever()[T2](...)` stays clean. Measured across both scan roots
            # with this arm live: ZERO new findings.
            verdict = _slice_verdict(func.slice, env.t3, env.benign_tier)
            if verdict is _SliceVerdict.BENIGN:
                return None
            return _SliceVerdict.UNRESOLVED
        if _arg_name(func.value) not in env.tc_bare:
            return None
        return _slice_verdict(func.slice, env.t3, env.benign_tier)
    name = _arg_name(func)
    if name is None:
        return None
    return env.tc_param.get(name)


def _is_cast_tagged_content_call(node: ast.Call) -> bool:
    """``cast(TaggedContent[...], ...)`` — first arg subscripts ``TaggedContent``.

    Accepts:

    - ``cast(TaggedContent[T2], x)``           — bare name
    - ``cast(tiers.TaggedContent[T2], x)``     — qualified Attribute
    - ``typing.cast(TaggedContent[T2], x)``    — qualified call target (covered by ``_call_name``)
    - ``cast("TaggedContent[T2]", x)``         — string-form generic

    The qualified subscript form (``tiers.TaggedContent[T2]``) is the
    matching round-2 finding #2 widening on the argument side: without
    it, an author who imports the security module and casts via
    ``tiers.TaggedContent[T2]`` would skip the gate.
    """
    if _call_name(node) != "cast":
        return False
    if not node.args:
        return False
    first = node.args[0]
    if isinstance(first, ast.Subscript):
        # ``_arg_name`` collapses ``ast.Name`` and ``ast.Attribute`` to the
        # same identifier so qualified subscripts also match.
        return _arg_name(first.value) == "TaggedContent"
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        # String-form generic: the parser keeps it as a literal, so look
        # for the same syntactic shape inside the constant.
        return "TaggedContent[" in first.value
    return False


def _is_unbound_basemodel_seam_call(node: ast.Call, basemodel_names: frozenset[str]) -> bool:
    """``BaseModel.<seam>(obj, ...)`` — dispatch with the CLASS as receiver.

    This is the original tl-2026-013 shape. Called on the class, the seam builds field
    state through ``_copy_and_set_values`` and reaches neither the subclass overrides
    nor ``model_post_init``, so a ``TaggedContent`` can be produced without the tier
    ever passing a guard the runtime owns.

    The receiver is collapsed with :func:`_arg_name`, which maps ``ast.Name`` and
    ``ast.Attribute`` to the same identifier. A hand-rolled
    ``isinstance(func.value, ast.Name)`` check saw only the bare spelling and missed
    ``pydantic.BaseModel.model_copy(...)`` — the CR-138 round-2 finding #2 class this
    very helper exists to close. Reusing ``_arg_name`` also means the two widenings
    cannot drift apart.

    RECEIVER-SCOPED on purpose: a receiver-blind rule flagging every ``model_copy``
    reds ordinary pydantic instance use across the tree. Measured cost of this form:
    ZERO sites in the 332 files under both scan roots.

    Two shapes: ``BM.model_copy(obj, …)`` and ``BM.model_construct.__func__(cls, …)``,
    the latter one hop further through the unbound function object — which skips every
    override on the way in exactly as the first does.

    WHAT THIS CANNOT DO: a cross-module re-export (``from x import BaseModel as Y`` in
    module A, imported from A by module B) is invisible — the alias set is per-file.
    ``TaggedContent.model_construct(...)`` is not flagged BY THIS RULE either, and that is
    now a division of labour rather than a residual: #539's :func:`_is_tagged_seam_call`
    refuses it, receiver-scoped to the TaggedContent alias environment. This rule stays
    scoped to ``BaseModel`` aliases so the two do not overlap into double reporting.
    """
    func = _callee(node)
    if not isinstance(func, ast.Attribute):
        return False
    if _arg_name(func.value) in basemodel_names and func.attr in _BASEMODEL_SEAM_ATTRS:
        return True
    receiver = func.value
    return (
        isinstance(receiver, ast.Attribute)
        and _arg_name(receiver.value) in basemodel_names
        and receiver.attr in _BASEMODEL_SEAM_ATTRS
    )


# The `_BASEMODEL_SEAM_ATTRS` PARTITION. Two rules need disjoint halves of it: the
# construction seams build field state from DATA (so the tier is not a token this gate can
# read, and the rule is receiver-scoped), while the copy seams mutate an EXISTING object
# through an update mapping (so the rule is receiver-BLIND and keys on the mapping).
#
# DERIVED, not transcribed. Three overlapping vocabularies of the same five names is the
# #422 shape, and `test_the_seam_partition_covers_basemodel_seam_attrs` asserts the two
# halves are disjoint and exhaustive — so adding a sixth seam to the parent forces a
# decision about which half it belongs to instead of silently belonging to neither.
_COPY_SEAM_ATTRS: frozenset[str] = frozenset({"copy", "model_copy"})
_TAGGED_SEAM_ATTRS: frozenset[str] = _BASEMODEL_SEAM_ATTRS - _COPY_SEAM_ATTRS


def _is_readable_mapping(node: ast.expr, dict_names: frozenset[str]) -> bool:
    """Whether :func:`_mapping_mentions_tier` can actually READ ``node``'s keys.

    The distinction the ``**`` arm turns on, and getting it wrong was a fail-open:
    ``{**payload}`` was refused (an ``ast.Name`` names no key) while
    ``{**build_update()}`` was ADMITTED, because the arm exempted every ``ast.Call``
    rather than only a ``dict(...)`` one. Measured on the shipped gate:
    ``low.model_copy(update={**build_update()})`` and ``{**self.build()}`` both scanned
    clean. An opaque call is exactly as unreadable as an opaque name.
    """
    if isinstance(node, ast.Dict):
        return True
    return isinstance(node, ast.Call) and _arg_name(_callee(node)) in dict_names


def _mapping_mentions_tier(node: ast.expr, dict_names: frozenset[str], depth: int = 0) -> bool:
    """True when ``node`` is a mapping expression that can reach a ``"tier"`` key.

    TOTAL over the mapping shapes a copy seam accepts, and DEFAULT-DENY on the ones it
    cannot read. Keying on ``ast.Dict`` with a folded ``"tier"`` key alone left
    ``dict(tier=T3)`` and ``{**{"tier": T3}}`` scanning clean — measured, and both reach
    the identical write.

    The ``**`` arm is where the default-deny lives. ``{**payload}`` names no key this gate
    can read, so it is REFUSED rather than admitted: a mapping the rule cannot read is a
    mapping it must not admit. Measured cost of that strictness across both scan roots:
    ZERO — the two live ``model_copy(update=...)`` sites carry literal ``wire_seq`` keys.

    RESIDUAL: a mapping built anywhere but at the call site
    (``payload = {"tier": T3}; obj.model_copy(update=payload)``) is an ``ast.Name`` here and
    is not matched. Refused at RUNTIME by ``_coerce_and_guard_update``; closing it lexically
    would mean flagging every ``model_copy`` in the tree, which costs two named floors.
    """
    # BOUNDED, on `_fold_str`'s precedent and for its reason. This predicate runs INSIDE
    # `_scan_text`'s `GateInternalError` fence, whose contract is that every rule does
    # BOUNDED work on one parsed node — an unbounded recursion here would let one
    # pathological `{**{**{**...}}}` chain raise from inside the fence, and `main` then
    # DISCARDS every violation collected so far and exits 2, hiding a real laundering
    # finding in an EARLIER file. CPython's parser happens to cap this shape at ~199
    # frames today, but that is an undocumented limit on a different layer, not a
    # property of this code.
    #
    # Past the bound the answer is REFUSE, not admit: it is the same "a mapping this rule
    # cannot read is one it must not admit" default the `**` arm below applies.
    if depth > _FOLD_MAX_DEPTH:
        return True
    if isinstance(node, ast.Dict):
        # `strict=True` is a free assertion, not ceremony: the parser produces one entry in
        # `values` per entry in `keys` (a `**` unpack carries a `None` key), so a length
        # mismatch would mean the tree is not one `ast.parse` built.
        for key, value in zip(node.keys, node.values, strict=True):
            if key is None:
                # `{**other}` — recurse when the unpacked operand is itself READABLE,
                # refuse when it is not. Readability is decided by
                # `_is_readable_mapping`, not by node class: exempting every `ast.Call`
                # admitted `{**build_update()}`, which names no key this gate can see.
                if _mapping_mentions_tier(value, dict_names, depth + 1):
                    return True
                if not _is_readable_mapping(value, dict_names):
                    return True
            elif _fold_str(key) == "tier":
                return True
        return False
    if isinstance(node, ast.Call) and _arg_name(_callee(node)) in dict_names:
        if any(keyword.arg == "tier" for keyword in node.keywords):
            return True
        if any(keyword.arg is None for keyword in node.keywords):
            # `dict(**other)` — the same unreadable operand as the `**` arm above.
            return True
        # POSITIONAL OPERANDS GET THE SAME DEFAULT-DENY as the `**` arm above. Returning
        # `any(...)` admitted `dict(payload)` — a mapping built from a name this gate
        # cannot read — while the equivalent `{**payload}` and `dict(**payload)` were both
        # refused. Three spellings of one idea must not have two answers.
        for argument in node.args:
            if _mapping_mentions_tier(argument, dict_names, depth + 1):
                return True
            if not _is_readable_mapping(argument, dict_names):
                return True
        return False
    return False


def _mutates_tier_in_a_copy(node: ast.Call, env: TierAliasEnv) -> bool:
    """True when a ``copy``/``model_copy`` call carries a tier-bearing update mapping.

    RECEIVER-BLIND, and it has to be: the shape this exists for is
    ``lower.model_copy(update={"tier": T3})`` on an INSTANCE, where there is no class
    identifier to scope against. It is the most plausible accident of the seven — an author
    copies an object and edits the tier, never touching a guarded function.

    EVERY argument is read, positional and keyword alike, rather than the index pydantic v1
    happens to give ``update`` today. ``BaseModel.copy(obj, None, None, {...})`` reaches the
    write positionally; a signature-derived index closes the spelling it was written against
    and silently widens when the signature moves, while a shape rule does not.

    ``copy`` is pydantic v1's spelling and does NOT route through ``model_copy`` — it merges
    ``update`` inside ``copy_internals`` — so both names are needed.
    """
    func = _callee(node)
    if not (isinstance(func, ast.Attribute) and func.attr in _COPY_SEAM_ATTRS):
        return False
    supplied = list(node.args) + [keyword.value for keyword in node.keywords]
    return any(_mapping_mentions_tier(a, env.dict_names) for a in supplied)


def _is_tagged_seam_call(node: ast.Call, env: TierAliasEnv) -> bool:
    """``TaggedContent[...].model_construct/model_validate*(...)`` that names no benign tier.

    RECEIVER-SCOPED **AND** SLICE-DISCRIMINATING, and the second half is not an
    optimisation. A receiver-scoped but tier-AGNOSTIC rule fires on
    ``test_model_construct_still_works_for_a_lower_tier`` —
    ``TaggedContent[T2].model_construct(...)`` — failing a floor this repo explicitly named
    "still works". Discrimination costs nothing and saves a named benign floor.

    The wire-round-trip argument for tier-agnosticism is measurably FALSE at **0** sites:
    no seam call anywhere under either scan root has a ``TaggedContent``-shaped receiver.
    And a NAKED (non-receiver-scoped) tier-agnostic rule is far worse — **34** legitimate
    seam calls live outside ``tiers.py`` (``model_validate`` 26, ``model_validate_json`` 6,
    ``model_copy`` 2), every one of which would red.

    AN UNPARAMETERISED RECEIVER IS REFUSED. ``TaggedContent.model_construct(...)`` names no
    tier the gate can read, so it default-denies like any unresolved slice.

    THIS RULE'S SAFETY IS BORROWED FROM THE RUNTIME GUARD, and saying so is the point:
    ``TaggedContent[T2].model_construct(tier=T3, ...)`` slips this lexical rule entirely —
    the receiver names a benign tier and the laundering rides in the keyword — and is caught
    only by ``_enforce_tier_admissible`` / ``model_post_init``. A rule whose stated basis
    does not survive measurement is what this epic exists to stop shipping.
    """
    func = _callee(node)
    if not (isinstance(func, ast.Attribute) and func.attr in _TAGGED_SEAM_ATTRS):
        return False
    receiver = _unwrap_walrus(func.value)
    if isinstance(receiver, ast.Subscript):
        verdict = _slice_verdict(receiver.slice, env.t3, env.benign_tier)
        if _arg_name(receiver.value) is None:
            # AN UNREADABLE RECEIVER IS NOT A CLEAN RECEIVER — the same two-valued guess
            # `_SliceVerdict` exists to remove, reintroduced on the receiver axis.
            # `_get()[T3].model_validate(p)` names no identifier this gate can resolve.
            # Scoped to a non-benign slice, so `_get()[T2].model_validate(p)` stays clean.
            return verdict is not _SliceVerdict.BENIGN
        if _arg_name(receiver.value) not in env.tc_bare:
            return False
        return verdict is not _SliceVerdict.BENIGN
    name = _arg_name(receiver)
    if name is None:
        return False
    # A DIFFERENT NAME from the slice verdict above: this one is optional (the receiver may
    # carry no parameterised binding at all), and reusing the identifier made mypy narrow
    # the two together and call the fallthrough unreachable.
    bound_verdict = env.tc_param.get(name)
    if bound_verdict is not None:
        return bound_verdict is not _SliceVerdict.BENIGN
    return name in env.tc_bare


def _detect(
    node: ast.AST,
    prose: frozenset[int],
    call_func_ids: frozenset[int],
    vars_names: frozenset[str],
    carrier_pairs: frozenset[tuple[str, str]],
    carrier_names: frozenset[str],
    basemodel_names: frozenset[str],
    private_names: frozenset[str],
    enclosing: dict[int, tuple[str, int]],
    resolved: Path,
    env: TierAliasEnv,
) -> list[str]:
    """Every rule's verdict on ONE already-parsed node, as a list of messages.

    PURE and CONSTANT-WORK over its arguments, which is what lets ``_scan_text`` fence
    the whole detector behind a single :class:`GateInternalError` rather than fencing
    each rule separately. The per-file maps are built by the CALLER, outside that
    fence: a defect in one of them is a defect in the maps, not in the file, and
    reporting it as an unscannable FILE at exit 1 is the #543 err-001 failure the fence
    exists to prevent.

    ``ast.AST`` rather than a narrower type: the caller walks every node, because rules
    here key on ``ast.Attribute``, ``ast.Constant`` and ``ast.alias`` rather than on
    ``ast.Call``. NO COUNT IS NAMED — this line said "three" and the private-surface
    rule made it more on the next edit.
    """
    messages: list[str] = []
    if isinstance(node, ast.Call):
        if _is_tag_t3_call(node):
            messages.append(_TAG_T3_MESSAGE)
        if _is_cast_tagged_content_call(node):
            messages.append(_CAST_TAGGED_CONTENT_MESSAGE)
        # R4 and R1 share ONE verdict, and that is what keeps them disjoint. A `None`
        # verdict means "not a TaggedContent-ish construction call at all", which is the
        # only state in which the unparameterised rule may speak — a name carrying a
        # verdict has already been decided on its tier.
        #
        # `if`/`elif` with no `else`, never a ternary: `coverage.py` does not branch on a
        # conditional expression, and the first revision of this dispatch WAS a ternary —
        # which is precisely how it hid a fail-open arm from this file's REQUIRED 100%
        # branch gate. See `_SliceVerdict` for the executed bypass.
        verdict = _tagged_subscript_verdict(node, env)
        if verdict is _SliceVerdict.T3:
            messages.append(_TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE)
        elif verdict is _SliceVerdict.UNRESOLVED:
            messages.append(_TAGGED_CONTENT_UNRESOLVED_SLICE_MESSAGE)
        elif verdict is None and _arg_name(_callee(node)) in env.tc_bare:
            # R1. Deliberately reads NO tier: `tier=_ALIAS` and `**payload` reach the same
            # write, so an unparameterised construction is refused on SHAPE.
            #
            # Justified on the honest ground only. The older plan claimed `tiers.py`'s
            # empty-generic short-circuit makes this a T3 bypass; that is true of the
            # tier/generic cross-check and IRRELEVANT for T3, because
            # `_refuse_unauthorized_t3` fires regardless of parameterisation. This rule
            # exists because the authoring layer fires when the line is WRITTEN and an
            # unexercised branch in `src/` ships unrefused until it runs.
            messages.append(_UNPARAMETERISED_CONSTRUCTION_MESSAGE)
        if _is_tagged_seam_call(node, env):
            messages.append(_TAGGED_SEAM_MESSAGE)
        if _mutates_tier_in_a_copy(node, env):
            messages.append(_TIER_MUTATING_COPY_MESSAGE)
        if _is_unbound_basemodel_seam_call(node, basemodel_names):
            messages.append(_BASEMODEL_VALUE_MESSAGE)
        func = _callee(node)
        if isinstance(func, ast.Name):
            # `vars` and the directly-bound carrier primitives are BARE IDENTIFIERS, so
            # both name sets arrive alias-resolved. `_v = vars` was the last identifier
            # in this gate still matched as a literal, found by self-audit.
            if func.id in vars_names:
                messages.append(_RAW_VEHICLE_VARS_MESSAGE)
            if func.id in carrier_names:
                messages.append(_RAW_CARRIER_MESSAGE)
        elif isinstance(func, ast.Attribute):
            # RECEIVER-BLIND. The rule never asks who the receiver is, so there is no
            # identifier left to rebind — that, not a wider alias set, is what closed
            # the four executed sec-001 spellings.
            if func.attr == "__setattr__" and not _is_benign_state_mutation_target(node):
                messages.append(_RAW_SETATTR_SHAPE_MESSAGE)
            # THE THIRD MEMBER OF THE FAMILY, receiver-blind on the same grounds (PR #553
            # review, C1). `__delattr__` was in the vehicle-NAME set — so the folded-string
            # spelling red — but had neither of the two rules its siblings got, and both
            # `object.__delattr__(low, "tier")` and the aliased `_d = object.__delattr__`
            # scanned clean. REJECTED ALTERNATIVE, on the record because it is the shorter
            # patch and someone will propose it again: adding `__delattr__` to
            # `_RAW_STATE_VEHICLE_ATTRS` closes both spellings in one word and costs zero
            # today (the tree holds no `__delattr__` node at all). It was not taken because
            # it is a blanket ban with no admissible shape, so the day a frozen dataclass
            # legitimately deletes one of its own non-state fields the only remedy is
            # deleting the member — a wholesale relaxation, invisible at every site that
            # then depends on it, which is the failure this module's docstring closes with.
            # The pair below already carries the right escape hatch.
            if func.attr == "__delattr__" and not _is_benign_state_mutation_target(node):
                messages.append(_RAW_DELATTR_SHAPE_MESSAGE)
            # RECEIVER-BLIND for the same reason, and it has to be: the bound spelling
            # `low.__init__(content=…)` and the unbound `type(low).__init__(low, …)`
            # reach the identical write, so a rule that read the receiver would have to
            # enumerate the ways of naming one.
            if func.attr == "__init__" and not _is_self_init_re_entry(node, func.value):
                messages.append(_RAW_INIT_SHAPE_MESSAGE)
            if (_arg_name(func.value), func.attr) in carrier_pairs:
                messages.append(_RAW_CARRIER_MESSAGE)
    if isinstance(node, ast.Name) and node.id in _RAW_STATE_VEHICLE_NAMES:
        # THE THIRD CARRIER for the vehicle-name set. `__doc__` is a bare identifier in
        # every module and class body, so the attribute arm and the folded-string arm are
        # both blind to it — see `_RAW_STATE_VEHICLE_NAMES`.
        messages.append(_RAW_VEHICLE_NAME_MESSAGE)
    if isinstance(node, ast.Attribute):
        if node.attr in _RAW_STATE_VEHICLE_ATTRS:
            messages.append(_RAW_VEHICLE_ATTR_MESSAGE)
        # `__class__` by CONTEXT, not by name: a class swap is a laundering vehicle and
        # `exc.__class__.__name__` (live at hooks/invoke.py:1265) is an ordinary read.
        # Banning the name costs a false positive; banning the store context costs zero.
        if node.attr == "__class__" and isinstance(node.ctx, (ast.Store, ast.Del)):
            messages.append(_RAW_CLASS_SWAP_MESSAGE)
        # ONE-POSITION WHITELIST. `Call.func` is the ONLY admissible position for a
        # `__setattr__` reference; every other position is the A05 alias vehicle. Never
        # an ancestor blacklist — that must ENUMERATE the bad positions and silently
        # widens the day a new one appears.
        if node.attr == "__setattr__" and id(node) not in call_func_ids:
            messages.append(_RAW_SETATTR_ALIASED_MESSAGE)
        # THE SAME ONE-POSITION WHITELIST for `__delattr__` (PR #553 review, C1).
        # `_d = object.__delattr__` followed by `_d(low, "tier")` puts no `__delattr__`
        # node in `Call.func` position, so the shape rule above cannot see it BY
        # CONSTRUCTION — measured, that spelling scanned clean while the equivalent
        # `__setattr__` and `__init__` spellings both red. Measured cost: zero
        # `__delattr__` attribute nodes exist across both scan roots, in any position.
        if node.attr == "__delattr__" and id(node) not in call_func_ids:
            messages.append(_RAW_DELATTR_ALIASED_MESSAGE)
        # THE SAME ONE-POSITION WHITELIST for `__init__` (PR #553 review, F3). Without
        # it, `_f = type(low).__init__` followed by `_f(low, content=ATTACKER)` reaches
        # the write with no `__init__` node in `Call.func` position at all, so the shape
        # rule above is blind to it BY CONSTRUCTION. Measured: all 62 `__init__`
        # attribute nodes across both scan roots sit in `Call.func`, so this costs zero.
        if node.attr == "__init__" and id(node) not in call_func_ids:
            messages.append(_RAW_INIT_ALIASED_MESSAGE)
    if isinstance(node, (ast.Constant, ast.BinOp, ast.JoinedStr)) and id(node) not in prose:
        # EQUALITY, not containment: a docstring or message that merely mentions a
        # vehicle name is prose about the rule, and widening this to containment reds
        # nothing in the tree today.
        #
        # THE REST OF THAT SENTENCE USED TO READ "while admitting no new attack", and
        # that was measurably false (PR #553 review, F5). Containment WOULD catch at
        # least one thing equality does not: `exec("object.__setattr__(low, '__dict__',
        # {...})")` folds to one long string that equals no member, scans clean, and
        # executes. Equality stays anyway — containment was measured as a widening with
        # its own costs, and `exec`/`eval` are out of this rule's reach in any form: ruff
        # `S102`/`S307` refuse them instead. Verified by execution in BOTH scan roots,
        # not inferred from the config: `[tool.ruff.lint] select` carries `"S"` and
        # ignores only `S101`, `per-file-ignores` covers `tests/**` only, and CI runs
        # `ruff check .` so `plugins/` is inside it too. Naming the real defence matters
        # more than the widening: the false claim is what would invite a future author to
        # keep equality for a reason that does not hold.
        folded = _fold_str(node)
        if folded is not None and folded in _RAW_STATE_VEHICLE_NAMES:
            messages.append(_RAW_VEHICLE_STR_MESSAGE)
    # THE SOLE-LAYER RULE. Keyed on the node rather than on `ast.Call`, because the
    # name arrives on four different carriers and one of them (`ast.alias`) is not an
    # expression at all. The exemption is consulted only AFTER a hit, so the authorised
    # references in `nonce_factory.py` are the only thing it can admit — how many of
    # them there are is pinned by a cardinality test, not written down here.
    private_name = _private_surface_hit(node, prose, private_names)
    if private_name is not None and not _private_surface_is_exempt(node, resolved, enclosing):
        messages.append(_PRIVATE_SURFACE_MESSAGE)
    return messages


def _suppressed_spans(text: str) -> list[tuple[int, tuple[int, int]]]:
    """``(comment line, enclosing logical-line span)`` for every real suppressor comment.

    The span is what lets the caller ask "does the statement this suppressor sits on mention
    ``TaggedContent``?" rather than "does its physical line?" — the difference between
    seeing a suppressor on a reformatted call's closing paren and being blind to it.

    A STANDALONE COMMENT HAS NO LOGICAL LINE. The tokenizer emits ``NL`` for a comment-only
    line, not ``NEWLINE``, so such a comment falls into no span at all and gets a degenerate
    span of itself. That is not a defensive default: it is the shape that keeps
    ``# noqa is the wrong tool for TaggedContent problems`` on its own line decided by its
    own text rather than by whatever statement happens to follow it.

    Raises whatever the tokenizer raises. That is deliberate — see :func:`_scan_text`, which
    runs this INSIDE the arm that reports an unscannable file, because a file the gate
    cannot tokenize is a file the gate is not gating (#537). It is NOT inside the
    :class:`GateInternalError` fence: the tokenizer is input-driven in exactly the way
    ``ast.parse`` is, and misfiling that as a gate defect would be the #543 err-001
    confusion in the other direction.
    """
    # A span is delimited by the CODE it contains, not by a running line cursor. Tracking
    # `start` as "one past the previous NEWLINE" swept a standalone comment into the span of
    # the statement BELOW it, because a comment-only line emits `NL` rather than `NEWLINE`
    # and so never advanced the cursor. Opening a span at the first REAL token instead means
    # a comment-only line sits in no span at all, which is precisely the property wanted:
    # a bare `# type: ignore` on its own line suppresses nothing in mypy, so it must not
    # inherit whatever follows it.
    spans: list[tuple[int, int]] = []
    line_scoped: list[int] = []
    file_wide: list[int] = []
    opened: int | None = None
    last_line = 1
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        last_line = max(last_line, token.end[0])
        if token.type == tokenize.COMMENT:
            body = token.string.lstrip("#").strip()
            if _FILE_WIDE_SUPPRESSOR_PATTERN.match(body):
                file_wide.append(token.start[0])
            elif _LINE_SUPPRESSOR_PATTERN.match(body):
                line_scoped.append(token.start[0])
        elif token.type == tokenize.NEWLINE:
            # ASSERTED, not defaulted, on `_enclosing_functions`'s precedent. `NEWLINE`
            # terminates a LOGICAL line, and a logical line contains code by definition —
            # a blank or comment-only line emits `NL` instead — so a span is always open
            # here. MEASURED, not assumed: 15 edge-case spellings (bare `;`, form feed,
            # decorator, continuation, docstring-only, comment-then-code) plus all 332
            # tracked files under both scan roots produce ZERO arrivals with none open.
            #
            # An `if` here would be a branch no input can take, and this file is under a
            # REQUIRED 100% branch gate with no pragmas: an unreachable arc makes that gate
            # unsatisfiable rather than safe. Writing it as a conditional expression would
            # be worse still — `coverage.py` does not branch on a ternary, so the dead arm
            # would be hidden from the very gate meant to find it.
            assert opened is not None
            spans.append((opened, token.end[0]))
            opened = None
        elif token.type not in _NON_CODE_TOKENS and opened is None:
            opened = token.start[0]
    located = [(comment, (1, last_line)) for comment in file_wide]
    for comment in line_scoped:
        span = next(((a, b) for a, b in spans if a <= comment <= b), (comment, comment))
        located.append((comment, span))
    return located


class GateInternalError(RuntimeError):
    """A DETECTOR PREDICATE raised. The gate is broken, not the file.

    #543 review (err-001). ``_scan_text``'s ``except Exception`` wrapped the
    whole scan body, every ``_is_*`` predicate included, so an
    ``AttributeError`` in the gate's own logic reported as an unscannable
    FILE at exit 1 ("violations found") on a completely clean file —
    indistinguishable from a real T3-laundering finding. Measured, on a file
    with no ``tag``/``cast``/subscript pattern in it at all.

    NO COUNT IS NAMED HERE ON PURPOSE. This docstring said "the three
    predicates" while :func:`_detect` already dispatched more than three, and
    a number in prose rots silently the next time a rule is added. The
    property is about the KIND of work, not how many rules do it.

    Every detector predicate does BOUNDED work on one already-parsed node —
    ``isinstance`` checks, attribute reads, and ``_fold_str``'s recursion,
    which is capped at :data:`_FOLD_MAX_DEPTH` precisely so that this claim
    stays true (an unbounded fold would let a long ``+`` chain raise from
    INSIDE the fence, and ``main`` would then discard every violation
    collected so far — hiding a real laundering finding in an earlier file
    behind a "the gate is broken" exit). No I/O, no unbounded recursion, so
    no INPUT can make them raise. Anything they raise is a defect, and
    `main` reports it as exit 2, "the gate could not run".

    ``ast.parse`` and ``ast.walk`` stay OUTSIDE this fence deliberately: both
    are genuinely input-driven (a 20 000-deep ``not`` chain raises
    ``MemoryError`` from the parser), and misfiling those as gate defects
    would be the same confusion in the other direction.
    """


def _scan_text(text: str, path: Path, resolved: Path | None = None) -> list[str]:
    """Return violation messages for ``text``, attributed to ``path``.

    PURE OVER ITS ARGUMENTS: performs no filesystem access. ``path`` is a label for
    the messages; ``resolved`` is the exemption KEY, already resolved by
    :func:`_scan_file` — this function never resolves anything itself. Omitting it
    means "use ``path`` as given", which is what every direct caller in the suite does.

    The split is load-bearing rather than tidy (R2-D). An earlier revision called
    ``path.resolve()`` per hit in here; measured, identical ``(text, path)`` arguments
    then returned OPPOSITE verdicts depending on the process cwd, while
    ``test_scan_text_reports_a_violation_without_touching_the_filesystem`` — the pin
    that exists to prevent exactly that — stayed green, because it asserts only that
    a nonexistent path is not read. ``_scan_text`` applies path-keyed exemptions now;
    what it does not do is decide for itself what the path IS.

    Split out of :func:`_scan_file` (#537) for two reasons:

    1. Tests can feed *mutated real source* under its REAL path. A ``tmp_path``
       copy of this script would recompute ``_REPO_ROOT`` from ``__file__`` and
       silently invert every exemption, so a copy-based test measures the
       wrong tree while still passing.
    2. It lets the suite run the scanner in-process, which is what makes a
       100%-coverage gate on this file achievable at all: a ``subprocess`` run
       records nothing without ``COVERAGE_PROCESS_START``, and the pre-existing
       suites are entirely subprocess-based (measured: 0% coverage).

    Two-pass scan:

    1. AST walk over EVERY node, delegating to :func:`_detect` — the
       ``tag(T3, ...)`` / ``cast(TaggedContent[...], ...)`` call patterns plus
       the #538 raw-state-write vehicle and ``tiers``-private-surface rules,
       which key on ``ast.Attribute``, ``ast.Constant`` and ``ast.alias``
       rather than on ``ast.Call``. Multiline-safe by construction (the parser
       doesn't care about line breaks inside a call).
    2. Per-line regex for ``# type: ignore`` on a ``TaggedContent`` line —
       comments are discarded by the parser, so they need the line-based
       scan.

    **Never raises for an INPUT fault** (short of ``BaseException``): a scan
    failure becomes a reported violation rather than an exception that aborts
    ``main``'s loop and leaves every later file unscanned (#542). See the
    ``except Exception`` arm.

    The one exception is :class:`GateInternalError`, raised when a DETECTOR
    PREDICATE faults. That is not an input fault and aborting is correct for
    it: the gate is broken, so no later file's verdict would mean anything.
    ``main`` reports it as exit 2, never as exit 1 — which is precisely the
    difference #542 was about (it exited 1, "violations found", naming none).
    """
    if resolved is None:
        resolved = path
    violations: list[str] = []
    completed = False
    try:
        lines = text.splitlines()

        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            # A file the parser cannot read is a file this gate is not gating.
            # Returning early skips the line-based suppression pass, which is
            # correct: a half-parsed view of a broken file is exactly what the
            # previous comment here warned against — the difference is that we
            # now REPORT it instead of passing it.
            return [f"{path}:{exc.lineno or 1}: {_UNPARSEABLE_MESSAGE}", f"  {exc.msg}"]

        # No ``if tree is not None`` guard: the SyntaxError arm above RETURNS, so
        # ``tree`` is always a parsed module here. The guard was a leftover from the
        # shape where an unparseable file set ``tree = None`` and fell through — it
        # became unreachable when that became a violation, and an unreachable branch
        # is a coverage hole that a pragma would hide rather than fix.
        #
        # THE PER-FILE MAPS, built OUTSIDE the detector fence alongside `ast.parse`.
        # They walk the tree, so they are input-driven in exactly the way `ast.parse`
        # and `ast.walk` are; a fault in one is not a faulting PREDICATE, and reporting
        # it as exit 2 "the gate is broken" would be the #543 err-001 confusion in the
        # other direction.
        prose = _prose_string_ids(tree)
        # ONE-POSITION WHITELIST for `__setattr__`: `Call.func` is the only admissible
        # position, and this is the set of node identities occupying it.
        call_func_ids = frozenset(id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call))
        vars_names, vars_overflow = _alias_names(tree, "vars")
        carrier_pairs, carrier_names, carrier_overflow = _carrier_bindings(tree)
        basemodel_names, basemodel_overflow = _alias_names(tree, "BaseModel")
        private_names, private_overflow = _private_surface_names(tree)
        # The TIER environment, built here with the other per-file maps and for the same
        # reason: it walks the tree, so it is input-driven exactly as `ast.parse` is, and a
        # fault in it is not a faulting detector PREDICATE.
        env, env_overflow = _tier_alias_env(tree)
        # Module-scope lines are ABSENT from this map, which both private-surface
        # exemption arms read as "module scope".
        enclosing = _enclosing_functions(tree)

        # FAIL CLOSED, and LOUDLY. A chain past the budget means the resolver cannot say
        # what these names are bound to, so every alias-resolved rule below is deciding
        # on an incomplete set. Attributed to line 1 because the overflow is a property
        # of the FILE's alias graph, not of any single line.
        #
        # ONE condition over EVERY resolved seed, not one report per seed: an overflow
        # means the FILE's alias graph is past the budget, and one copy of the same
        # message per seed on the same line would say the same thing over and over.
        if (
            vars_overflow
            or carrier_overflow
            or basemodel_overflow
            or private_overflow
            or env_overflow
        ):
            _record(violations, lines, path, 1, _ALIAS_BUDGET_MESSAGE)

        for node in ast.walk(tree):
            # `getattr`, never `node.lineno`. `ast.walk` yields `ast.AST`, which carries
            # no `lineno`; the previous code type-checked only because the
            # `isinstance(node, ast.Call)` guard narrowed it, and that guard is gone —
            # rules here key on `ast.Attribute`, `ast.Constant` and `ast.alias`. And
            # `ast.alias` is why `getattr` still earns its keep past those two: it is
            # not an `ast.expr` at all, so no narrowing covers it. Measured:
            # `mypy --strict` and `pyright` BOTH error on the attribute form, at 12
            # required sites including the pre-push lefthook.
            lineno = getattr(node, "lineno", 1)
            # THE DETECTOR, fenced off from the input-driven arms around it.
            # It does constant work on an already-parsed node, so an exception
            # here is a bug in this file — not a property of the scanned
            # source. Without the fence it reported as an unscannable FILE at
            # exit 1, i.e. as a T3-laundering finding in a clean file (#543
            # review, err-001). The `for` statement stays outside: it is
            # `ast.walk` advancing, which IS input-driven.
            try:
                findings = _detect(
                    node,
                    prose,
                    call_func_ids,
                    vars_names,
                    carrier_pairs,
                    carrier_names,
                    basemodel_names,
                    private_names,
                    enclosing,
                    resolved,
                    env,
                )
            except Exception as exc:
                raise GateInternalError(
                    f"{path}:{lineno}: {_GATE_INTERNAL_MESSAGE} {type(exc).__name__}: {exc}"
                ) from exc
            for message in findings:
                _record(violations, lines, path, lineno, message)

        # THE SUPPRESSION PASS RUNS HERE, after the walk, exactly where the line loop it
        # replaces ran. That placement is load-bearing rather than incidental: findings
        # already collected are APPENDED to, so a tokenizer failure downgrades nothing —
        # the `except Exception` arm below appends its own message to whatever the walk
        # found. Moving it up beside `ast.parse` would discard real findings.
        # THE TWO FAILURE MODES OF THE TOKENIZE PASS NEED OPPOSITE EXIT CODES, and
        # sharing one arm gave the reachable one's disposition to the unreachable one.
        #
        # `TokenError` is an INPUT fault — reproduced from real source — and belongs in
        # the broad arm below as an unscannable FILE at exit 1. The `assert` inside
        # `_suppressed_spans` is not: no input reaches it (measured across 15 edge-case
        # spellings and every tracked file), so if it ever fires the GATE is broken, and
        # #543 err-001 is exactly about not reporting that as a finding in a clean file.
        # Exit 2 says "the gate could not run", which is what would be true.
        try:
            suppressed = _suppressed_spans(text)
        except AssertionError as exc:
            raise GateInternalError(
                f"{path}:1: {_GATE_INTERNAL_MESSAGE} "
                f"{type(exc).__name__}: a logical-line invariant in _suppressed_spans "
                f"does not hold for this file."
            ) from exc
        # THE ALIAS ENVIRONMENT, resolved through the AST rather than matched against the
        # raw text. Two corrections live here, and they pull in opposite directions.
        #
        # Keying on the literal `"TaggedContent"` made a suppressor on an ALIASED
        # construction invisible: `from a import TaggedContent as TC` then
        # `TC[T2](y)  # type: ignore` scanned clean. So the resolved set is what to look
        # for.
        #
        # But looking for it as a SUBSTRING is worse than the bug it fixes. An alias is
        # often short, and `TC` occurs inside `MATCHER` — measured, `MATCHER = 1` with a
        # suppressor on it red for no reason at all, as did the word `TCP` inside a string.
        # Asking the parser which lines actually REFERENCE a tagged name costs nothing and
        # cannot be fooled by prose, by a longer identifier, or by a string literal.
        tagged_names = env.tc_bare | frozenset(env.tc_param)
        tagged_lines: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Name, ast.Attribute)) and _arg_name(node) in tagged_names:
                start = getattr(node, "lineno", 1)
                tagged_lines.update(range(start, getattr(node, "end_lineno", start) + 1))
        for lineno, (first, last) in suppressed:
            if any(line in tagged_lines for line in range(first, last + 1)):
                _record(violations, lines, path, lineno, _TYPE_IGNORE_MESSAGE)
        # THE COMPLETION EVENT (#547). Last statement of the `try` body, so it
        # is reached only when every preceding step ran. An `except` arm added
        # later cannot set it, and — unlike a scheme that marks the statement's
        # FALL-THROUGH — cannot reach the marked return by simply omitting a
        # `return` of its own. That distinction was measured: with the marker on
        # the fall-through, a naive `except MemoryError` arm scored 4 files of 4
        # as clean scans.
        completed = True
    except GateInternalError:
        # ORDER IS LOAD-BEARING. `GateInternalError` is an `Exception`, so the
        # broad arm below would swallow it and re-file the gate's own defect as
        # an unscannable input file at exit 1 — the exact confusion the fence
        # above exists to remove (#543 review, err-001). Re-raise so `main`
        # reports exit 2, "the gate could not run".
        raise
    except Exception as exc:
        # ``ast.parse`` raises more than ``SyntaxError``, and WHICH exception
        # depends on the interpreter BUILD. Measured on two CPython 3.14.6
        # builds: ``"not " * 20000`` raises MemoryError("Parser stack
        # overflowed") on both, while a 50 000-operand ``+`` chain raises
        # RecursionError("Stack overflow (used 8144 kB) during compilation")
        # on the uv/proto standalone build and parses CLEANLY on Homebrew.
        # 3.14's stack guard trips on real C-stack bytes, not on
        # sys.setrecursionlimit. CI uses ``uv python install 3.14``, so
        # RecursionError is live there even when a dev box never sees it.
        #
        # CONSEQUENCE FOR FUTURE TESTS (#545): "CPython 3.14.6" does not name
        # an environment. A test that asserts a SPECIFIC exception type out of
        # ``ast.parse`` is asserting a property of the BUILD, so it passes on
        # one runner and fails on another for reasons no version pin explains.
        # Assert the reported OUTCOME (a violation, this arm's message) rather
        # than the exception class, or skip on the builds where the input does
        # not trip the guard.
        #
        # Uncaught, these escaped ``_scan_text``, escaped ``main``, and killed
        # the process with a traceback — exit 1, the code that means
        # "violations found", for a file that was never scanned. Worse, they
        # ABORTED THE SCAN LOOP, so every later file went unscanned with
        # nothing reported (#542).
        #
        # Deliberately the CLASS, not a name list. Enumerating MemoryError and
        # RecursionError closes the two shapes we happened to think of and
        # leaves the next build-specific one open — the #518 guard-name-list
        # mistake. The scope covers the whole scan, not just ``ast.parse``:
        # ``splitlines``, ``ast.walk`` and the line pass can raise too, and an
        # exception in any of them aborted the loop just as effectively.
        #
        # APPEND, never replace: by the time this fires the walk may already
        # have found a real ``tag(T3, ...)``. Returning only the unscannable
        # message would downgrade a T3-laundering finding into a vague one.
        #
        # ``KeyboardInterrupt`` and ``SystemExit`` derive from
        # ``BaseException``, so they are NOT caught here and still interrupt
        # the run.
        #
        # Not a silent-failure concession: the result is a reported violation,
        # printed to stderr by ``main``, and the gate exits non-zero.
        violations.append(f"{path}:1: {_UNSCANNABLE_MESSAGE}")
        violations.append(f"  {type(exc).__name__}: {exc}")

    # NOT a ternary: `coverage.py` does not branch on a conditional expression,
    # so a ternary would hide an arm from this file's REQUIRED 100% branch gate
    # (#538). Both arcs are driven by real inputs — the True arc by any clean
    # file, the False arc by `_ALWAYS_UNSCANNABLE`.
    if completed:
        return _ScannedOk(violations)
    return violations


def _scan_file(path: Path) -> list[str]:
    """Return a list of violation messages for ``path``. Empty list = clean.

    Applies the exemption, reads the source, and delegates the scanning to
    :func:`_scan_text`.

    **Never raises for an INPUT fault** (short of ``BaseException``), for the
    same reason :func:`_scan_text` does not: a read failure this function lets
    escape aborts ``main``'s loop and silently un-gates every later file
    (#542). :class:`GateInternalError` from the delegate propagates by design —
    see :func:`_scan_text`.
    """
    if _is_exempt(path):
        return []
    try:
        # #546. `open()` on a FIFO for reading BLOCKS until a writer arrives,
        # and nothing here ever writes — so `read_text` on a FIFO named `*.py`
        # never returns and the gate hangs until CI kills the job, reporting
        # no diagnosis at all. Measured at exit 124 on both paths that reach
        # here: an explicit file argument, and the `rglob` traversal fallback
        # past the census floor. A character device (`/dev/zero`) is the same
        # shape with a different ending — an unbounded read instead of a
        # blocked one.
        #
        # DEFAULT-DENY the class, not the two shapes we thought of (#518): a
        # regular file is the only thing this gate can scan, so everything
        # else is refused by construction. `stat()` does not open the path, so
        # it cannot block on the very FIFO it is classifying — probed, not
        # assumed.
        #
        # WHAT THIS GUARD CANNOT DO: `stat` and `open` are two syscalls, so a
        # path swapped between them is still read as whatever it became. That
        # residual is accepted rather than closed. It needs write access to
        # the tree mid-scan (which already defeats a gate that reads the tree
        # it is gating), and its worst outcome is the ORIGINAL hang, not a
        # missed T3 violation — the security property this file exists for is
        # unaffected either way. Closing it would mean opening with
        # `O_NONBLOCK` and re-checking the fd, which is POSIX-only and would
        # red the Windows unit leg for no gain in the property that matters.
        #
        # Raised into the arm below rather than returned separately, and that
        # is deliberate on TWO counts. It is genuinely the same fault the arm
        # already reports — a path the reader cannot open — so it must give
        # the operator the same message. And a separate `return` would strand
        # `read_text`'s own OSError arm: a directory (its only portable
        # trigger, and what `test_unreadable_path_is_a_violation` uses) would
        # stop reaching it, leaving EACCES as the sole cover — untriggerable
        # on the root runners, which reds the required 100% branch gate on
        # this file. One funnel keeps both sides of the new branch covered.
        if not stat.S_ISREG(path.stat().st_mode):
            raise OSError(errno.EINVAL, _NOT_A_REGULAR_FILE_REASON)
        # RESOLVE ONCE, here, and hand the result to `_scan_text` (R2-D). The
        # path-keyed private-surface exemptions must decide on the file's real
        # identity, and doing it per hit inside `_scan_text` made identical
        # arguments return opposite verdicts depending on the process cwd.
        #
        # DELIBERATELY INSIDE the existing try, with NO arm of its own. A guard
        # written as `except (OSError, RuntimeError, ValueError): resolved = path`
        # would be unreachable in practice — every input that makes `resolve` raise
        # (an embedded NUL, most obviously) makes the `stat()` above raise first, so
        # the arm could only ever be reached by monkeypatching `Path.resolve`. An
        # unreachable branch is a design fault under this file's REQUIRED 100% gate,
        # and a monkeypatch-only branch is a pragma wearing a different hat. Sharing
        # the arms that already exist keeps both sides covered by real inputs.
        resolved = path.resolve(strict=False)
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [f"{path}:1: {_UNDECODABLE_MESSAGE}", "  <undecodable>"]
    except OSError as exc:
        return [f"{path}:1: {_UNREADABLE_MESSAGE}", f"  {exc.strerror or exc}"]
    except Exception as exc:
        # A path with an embedded NUL raises ``ValueError``, not ``OSError`` —
        # measured, and the exact cause ``_is_exempt`` already catches
        # ValueError for. The same input was handled by one function and
        # escaped the next. Same class-not-names reasoning as ``_scan_text``.
        #
        # No third catch-all in ``main``'s loop: with this arm and
        # ``_scan_text``'s, a per-file failure cannot reach it, so a backstop
        # there would be unreachable — a coverage hole on a file that must
        # stay at 100%.
        #
        # Its own message (#543 review, dx-003): this arm only ever fires on a
        # PATH the reader could not open, never on content, so it must not
        # suggest simplifying the file.
        return [f"{path}:1: {_UNSCANNABLE_PATH_MESSAGE}", f"  {type(exc).__name__}: {exc}"]
    return _scan_text(text, path, resolved)


def _warn_git_unavailable(directory: Path, why: str) -> None:
    """Announce a degradation to filesystem traversal on stderr.

    Every other "the gate could not do the thing it claims" condition here is
    loud; this one was mute. Falling back to ``rglob`` restores the traversal
    this gate exists to remove — it scans a superset so it cannot hide a
    violation, but the operator should know the default-deny derivation is not
    the one that ran.
    """
    print(
        f"check_tag_t3: {directory}: {why} — falling back to filesystem "
        f"traversal. The git-derived scan set (which honours .gitignore) is NOT "
        f"in effect for this path.",
        file=sys.stderr,
    )


class EmptyScanRootError(RuntimeError):
    """A directory argument yielded no Python files.

    Not an ordinary violation: it means the gate was pointed somewhere it
    cannot gate. Raised rather than returned so no caller can mistake it for
    a clean result.
    """


class PartialScanRootError(EmptyScanRootError):
    """An in-repo directory scan covered only SOME of ``_DEFAULT_SCAN_ROOTS``.

    A DISTINCT type, not a reuse of the parent (#541). The parent means "the
    gate was pointed at nothing"; this means "the gate was pointed at less
    than everything" — a different fault with a different remedy.

    Sharing one type collapsed a real oracle: with the per-directory floor in
    :func:`_collect_paths` deleted, ``_collect_paths(["build"])`` raised the
    partial-coverage error instead and the guard's dedicated regression test
    still passed. Tests must therefore discriminate with ``match=`` (and, for
    the parent, an ``isinstance`` exclusion) rather than on the base type.

    Subclasses ``EmptyScanRootError`` on purpose: :func:`main` already turns
    that into exit 2 ("the gate could not run"), which is the correct exit
    contract here too.
    """


def _git_tracked_python_files(directory: Path) -> list[Path] | None:
    """Return the tracked ``.py`` files under ``directory``.

    ``None`` means **git could not answer** (not a checkout, git absent, or a
    non-zero exit). An empty list means **git answered: nothing tracked here** —
    the distinction is load-bearing, see :func:`_collect_paths`.

    ``git ls-files`` is DEFAULT-DENY where an exclusion list is
    enumerate-and-hope: a file that is not tracked cannot land in a PR, and
    gitignored trees (the vendored ``plugins/alfred_tui/.venv`` — 856 of that
    tree's 895 ``.py`` files) disappear without anyone maintaining a list of
    directory names to skip.

    It also removes the filesystem traversal that let a symlinked package
    directory hide its whole subtree: ``Path.rglob`` does not recurse a
    symlinked directory met mid-walk. Tracked files are listed under their own
    real paths regardless of what links point at them.
    """
    try:
        # S603/S607: literal argv, no shell, no user-controlled executable. The
        # two codes are reported on DIFFERENT lines — S603 on the call, S607 on
        # the argv list — so a single combined noqa suppresses neither.
        proc = subprocess.run(  # noqa: S603
            # --cached lists the index; --others adds files that are NOT yet
            # tracked; --exclude-standard keeps .gitignore honoured so the
            # default-deny property survives. Without --others a brand-new file
            # was invisible to a directory scan until it was `git add`ed —
            # measured: an untracked src/alfred file containing
            # TaggedContent[T3](...) scanned rc=0, while the previous rglob gate
            # reported rc=1. CI is unaffected (it scans a committed merge ref),
            # so the loss was entirely in the local `make check` loop, which is
            # exactly where an author needs the gate to speak.
            [  # noqa: S607 — git is resolved from PATH by design; no user input
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
                str(directory),
            ],
            capture_output=True,
            check=False,
            cwd=_REPO_ROOT,
        )
    except (OSError, ValueError):
        _warn_git_unavailable(directory, "git could not be executed")
        return None
    if proc.returncode != 0:
        _warn_git_unavailable(directory, f"git exited {proc.returncode}")
        return None
    names = proc.stdout.decode("utf-8", errors="surrogateescape").split("\0")
    # --cached also lists index entries whose working-tree file is gone (a
    # deletion that has not been staged). Those cannot contain a violation, and
    # reporting them as unreadable would be noise rather than a finding.
    #
    # `is_file()` is S_ISREG-following-symlinks, so this ALSO drops a tracked
    # path whose working-tree entry has become non-regular — the shape
    # `_scan_file` now refuses LOUDLY (#546). The asymmetry is deliberate and
    # narrow (#549 review, sec-001): git cannot store a FIFO, so the only way
    # to reach it is a local working tree where someone replaced a tracked file
    # with one, and this arm cannot tell that apart from the staged-deletion
    # case it exists for — both present as "in the index, not a regular file
    # on disk". Refusing here would fail the gate on an ordinary unstaged
    # deletion, which is a far more common state than a hand-planted FIFO.
    # A file swapped for a FIFO is therefore silently unscanned on this path
    # and reported on the other two; the census in `main` is what notices if
    # enough of them disappear.
    return [p for n in names if n.endswith(".py") if (p := _REPO_ROOT / n).is_file()]


def _collect_paths(argv: list[str]) -> list[Path]:
    """Expand the CLI arg list into a flat list of ``.py`` paths to scan.

    Explicit FILE arguments are returned unconditionally — the unit suite
    plants untracked fixtures in ``tmp_path`` and passes them by path, and
    swallowing those would make every one of those tests vacuous.

    Directory arguments inside the repo are derived from ``git ls-files``.
    **An in-repo directory git reports as empty RAISES rather than falling
    back to traversal**: falling back there would re-scan exactly the
    gitignored trees the derivation exists to exclude.

    Finally, an in-repo DIRECTORY scan must cover every root in
    ``_DEFAULT_SCAN_ROOTS`` or it raises :class:`PartialScanRootError`.
    """
    default_root = not argv
    if default_root:
        argv = list(_DEFAULT_SCAN_ROOTS)
    paths: list[Path] = []
    in_repo_directory_args: set[Path] = set()
    for arg in argv:
        candidate = Path(arg)
        if not candidate.is_dir():
            # Order matters: the default-root case gets the more specific,
            # more actionable message, so it is tested first.
            if default_root:
                # The DEFAULT root is resolved relative to CWD, so an
                # argument-less run from the wrong directory used to scan 0
                # files and exit 0. Treating a missing default root as an
                # ordinary file argument would report it as an unreadable
                # FILE, which describes the symptom rather than the fault.
                raise EmptyScanRootError(
                    f"{arg}: no Python files found — the default scan root does "
                    f"not exist relative to the current directory. Run the gate "
                    f"from the repository root, or pass an explicit path."
                )
            if not candidate.exists():
                # Neither a directory nor a file. Falling through to the file
                # branch reported it as an unreadable FILE (rc=1, the code that
                # means "violations found") — the wrong exit code and the wrong
                # diagnosis for a mistyped scan root.
                raise EmptyScanRootError(
                    f"{arg}: no such file or directory — the gate cannot scan it."
                )
            paths.append(candidate)
            continue

        found: list[Path] | None = None
        resolved = candidate.resolve(strict=False)
        if resolved.is_relative_to(_REPO_ROOT):
            # Recorded here rather than in a second pass so the runtime
            # invariant below reuses this exact in-repo verdict — a separate
            # walk would be a second predicate that could drift from this one.
            in_repo_directory_args.add(resolved)
            # Pass the REPO-RELATIVE path, not the caller's spelling.
            # ``_git_tracked_python_files`` runs git with ``cwd=_REPO_ROOT``, so a
            # relative argument that is valid in the caller's directory resolves
            # against the wrong base: from ``src/``, ``check_tag_t3.py alfred``
            # made git list 0 entries and the gate refused with "check whether it
            # is gitignored" for a 293-file tree. Fails closed, but diagnoses the
            # wrong fault.
            found = _git_tracked_python_files(resolved.relative_to(_REPO_ROOT))

        if found is None:
            # Out-of-repo directory (test fixtures), or git could not answer.
            # recurse_symlinks=True is required: without it a symlinked package
            # met MID-WALK is skipped silently, which is the bypass this change
            # exists to close.
            found = list(candidate.rglob("*.py", recurse_symlinks=True))

        # PER-DIRECTORY floor. The aggregate census in main() cannot catch an
        # empty scan root: ``src/alfred plugins`` yielding 293 + 0 still clears
        # a 250-file floor while gating zero plugin files. ``git ls-files``
        # exits 0 with empty output for an ignored, absent or submodule path,
        # so this is the only place that failure becomes visible.
        if not found:
            raise EmptyScanRootError(
                f"{arg}: no Python files found. The gate refuses to treat an "
                f"empty scan root as clean — check the path, and check whether "
                f"it is gitignored."
            )
        paths.extend(found)

    # RUNTIME INVARIANT (#541). The call-site pin is a LEXICAL layer, and
    # review defeated it lexically: a backslash line-continuation split the
    # argv across lines and slipped `src/alfred` through with `plugins`
    # dropped — proved against real `make`, `plugins/` ungated, rc=0. So the
    # property holds at RUNTIME too, where no amount of shell quoting reaches
    # it: an in-repo DIRECTORY scan must cover every declared root.
    #
    # TWO exemptions, both deliberate:
    #
    #   * OUT-OF-REPO directories. The unit suite plants `tmp_path` trees and
    #     scans them by path. Holding a fixture directory to THIS repo's root
    #     set would red every one of those tests while saying nothing about
    #     production, which only ever scans in-repo paths.
    #   * Explicit FILE arguments. `check_tag_t3.py path/to/one.py` is the
    #     single-file developer invocation and the shape every fixture-based
    #     test uses.
    #
    # The second exemption is a MEASURED RESIDUAL, not a closed hole: passing
    # the 293 tracked `src/alfred/**.py` files individually exits 0 with
    # `plugins` never scanned. This layer cannot see that. What closes it is
    # the call-site pin in `tests/unit/meta/test_gate_surfaces_are_pinned.py`,
    # which requires every invocation site to pass NO arguments at all — so
    # the enumeration cannot be written at a call site in the first place.
    # Neither layer is complete alone: the pin covers arguments of ANY shape
    # but only at the call sites it searches; the invariant covers directory
    # subsetting from ANYWHERE, including a call site nobody has pinned yet.
    if in_repo_directory_args:
        missing = [
            root
            for root in _DEFAULT_SCAN_ROOTS
            if (_REPO_ROOT / root).resolve(strict=False) not in in_repo_directory_args
        ]
        if missing:
            # The remedy, not just the diagnosis (#543 review, dx-001).
            # ``check_tag_t3.py src/alfred`` — the documented pre-#541 usage,
            # and the most natural manual invocation — now exits 2 here, and
            # the old message named an internal constant a first-time
            # contributor would have to read the source to act on.
            raise PartialScanRootError(
                f"directory scan does not cover every declared root: missing "
                f"{missing}. A caller may not gate a subset of them. Fix: run "
                f"`python3 scripts/check_tag_t3.py` with NO arguments to scan "
                f"every declared root ({', '.join(_DEFAULT_SCAN_ROOTS)}), or "
                f"pass all of them explicitly. To change WHAT is gated, edit "
                f"_DEFAULT_SCAN_ROOTS in this script (#541)."
            )

    # THE DECOY DEFENCE (#543 review, sec-002). An argument-less run whose
    # roots all resolve OUTSIDE this repo is a wrong checkout or a scratch copy
    # — and it is exempt from the invariant above by design, because that one
    # is scoped to in-repo directories. The aggregate census in `main` was
    # documented as covering this and does not: a 260-file decoy clears a
    # 250-file floor and exits 0 having gated nothing (measured).
    #
    # A property, not a count: the run is argument-less, so it is gating THIS
    # repo or it is gating nothing. Explicit arguments are untouched — the unit
    # suite plants `tmp_path` trees and scans them by path, and out-of-repo
    # fixtures are the whole point of that path.
    #
    # Asserted on the ROOTS, not on a sample of the COLLECTED FILES (#548
    # review, sec-001). The predicate here was
    # `any(p.resolve().is_relative_to(_REPO_ROOT) for p in paths)`, satisfied by
    # ONE collected file — and `rglob` above runs with `recurse_symlinks=True`,
    # so a decoy carrying a single link into this repo measured rc=0 with 260
    # decoy files supplying every verdict. EVERY root or none of them: that form
    # cannot be bought with one link, and it does not depend on what the walk
    # happened to reach.
    #
    # `argv` IS `_DEFAULT_SCAN_ROOTS` on this path (rebound above), so this
    # names the roots that were actually scanned rather than re-reading the
    # constant — a monkeypatched tuple reaches this check like any other.
    #
    # What it does NOT cover, stated so the next reader does not have to
    # measure it: an in-repo root whose every tracked file is a symlink out of
    # the repo. Reaching that needs TRACKED symlinks, and in-repo directory sets
    # are derived from `git ls-files` under `_REPO_ROOT`; it is not the wrong-
    # checkout shape this guard exists for.
    if default_root:
        outside = [
            root for root in argv if not Path(root).resolve(strict=False).is_relative_to(_REPO_ROOT)
        ]
        if outside:
            raise EmptyScanRootError(
                f"an argument-less scan collected {len(paths)} files and its "
                f"declared roots {outside} do NOT resolve inside {_REPO_ROOT} "
                f"— they resolved to a different tree (a wrong checkout, or a "
                f"scratch copy). Refusing to report success while gating "
                f"nothing. Run the gate from the repository root."
            )
    return paths


def _resolved_identity(path: Path) -> Path:
    """The identity the census counts ``path`` under. NEVER raises.

    ``Path.resolve`` raises ``ValueError`` on an embedded NUL and ``OSError`` on
    some platform edges, and ``_is_exempt`` two lines away already guards that
    exact class. Leaving the census's own resolution bare was an asymmetry, not
    a decision: today `_collect_paths` refuses a NUL argument before it reaches
    here, but "unreachable today" is the reasoning that produced the defect this
    whole change exists to fix.

    FAIL-CLOSED on failure: fall back to the lexical absolute path, which is
    unique per spelling. An unresolvable path therefore counts as its OWN
    distinct file and can never be merged into another file's identity — the
    direction that cannot hide a violation. Merging is what the symlink-alias
    regression proved dangerous.
    """
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return Path(os.path.normpath(path.absolute()))


def _print_violations(violations: list[str], header: str) -> None:
    """Print collected violation lines to stderr under ``header``.

    The HEADER is a parameter, not a constant (#547). Sharing the printer must
    not share the headline: exit 1 means "every listed line is a finding in a
    file", and printing that over a wall of read failures tells the operator
    the opposite of the truth.
    """
    if violations:
        print(header, file=sys.stderr)
        for line in violations:
            print(line, file=sys.stderr)


_FINDINGS_HEADER: str = "check_tag_t3: violations found:"
_PARTIAL_HEADER: str = (
    "check_tag_t3: partial results from a scan that did NOT complete — these are what "
    "the gate managed to collect before refusing, NOT a clean bill of health for "
    "anything absent from this list:"
)


def main(argv: list[str]) -> int:
    """Return 0 clean, 1 violations found, 2 the gate could not run.

    Exit 2 is deliberately distinct from 1: a caller must be able to tell
    "the gate failed" from "the gate never gated anything".

    FOUR routes to exit 2, all of them "the gate could not run":

    * :class:`EmptyScanRootError` (and its :class:`PartialScanRootError`
      subclass) — the gate was pointed at nothing, at less than everything,
      or at a tree that is not this repo;
    * the PRE-SCAN collection floor — traversal did not reach the source tree;
    * the POST-SCAN census (#547) — traversal reached it and the gate could not
      READ it. Counted over DISTINCT resolved files that were actually read and
      parsed, because collection proves none of that: a tree of unreadable
      files, a tree of exempt files, and 260 symlinks to one file all cleared
      the old count-what-traversal-found floor;
    * :class:`GateInternalError` — a detector predicate faulted. #543 review
      (err-001) found that arriving here as exit 1, so a broken predicate
      read as "violations found" on files that were clean.

    Exit 1 therefore means what it says: every listed line is a finding in a
    file, not a fault in the gate. #547 moved a whole input class the other way
    — a mass read failure used to arrive here as exit 1, which contradicted
    that sentence.

    A refusal still PRINTS what it collected, under
    :data:`_PARTIAL_HEADER` rather than :data:`_FINDINGS_HEADER`: discarding a
    real ``tag(T3, ...)`` finding because the same run also hit read failures
    would trade one diagnostic defect for a worse one, but announcing read
    failures as "violations found" would be a second lie.
    """
    try:
        paths = sorted(_collect_paths(argv))
    except EmptyScanRootError as exc:
        print(f"check_tag_t3: {exc}", file=sys.stderr)
        return 2

    # The AGGREGATE census. The per-directory floor in `_collect_paths` catches
    # a root that yields zero files; this catches a directory scan that
    # resolved somewhere unexpected but non-empty. Explicit file arguments are
    # how the unit suite plants fixtures, so they are exempt — holding those to
    # a 250-file floor would red every one of them.
    scanned_a_directory = not argv or any(Path(a).is_dir() for a in argv)
    if scanned_a_directory and len(paths) < _MIN_SCANNED_FILES:
        print(
            f"check_tag_t3: collected {len(paths)} files, expected at least "
            f"{_MIN_SCANNED_FILES}. The gate is not reaching the source tree "
            f"(wrong working directory, or the scan root moved) — refusing to "
            f"report success while gating nothing.",
            file=sys.stderr,
        )
        return 2

    # DEDUPE BY RESOLVED PATH (#547). `_collect_paths` returns what traversal
    # found and nothing deduped it, so the census counted scan EVENTS rather
    # than distinct files. Measured on the pre-#547 gate with no monkeypatch:
    # 260 symlinks to one `x = 1` file exited 0 with empty stderr, having gated
    # exactly one distinct file. Every one of them scans perfectly, so a census
    # over successful scans alone cannot see it.
    #
    # Deduping is for COUNTING ONLY. It must never decide WHICH files are
    # scanned, and a draft of this change did exactly that, with measured
    # consequences. Keying a dict on the resolved path and iterating the
    # survivors made the winner depend on sort order, and `_is_exempt`
    # deliberately requires the LEXICAL and RESOLVED views to AGREE. So a
    # tracked symlink `src/alfred/core/alias.py -> security/tiers.py` collapsed
    # onto the exempt real file, which `main` then skipped: measured rc=1 with
    # the violation named before that draft, rc=0 with empty stderr after. It
    # failed OPEN and SILENT, and only for aliases sorting BEFORE their target —
    # so an ordering-blind test passes straight through it.
    #
    # Every collected path is therefore still scanned, exactly as before. The
    # census counts DISTINCT RESOLVED files by accumulating what was actually
    # seen. `_collect_paths` stays untouched for the same reason as before: its
    # per-directory floor and decoy defence are specified over what traversal
    # FOUND, and `recurse_symlinks=True` is load-bearing there (#541).
    # EXPLICIT FILE ARGUMENTS ARE CENSUS-EXEMPT — a contract this file has
    # documented since #541, and which the census silently broke. Measured: a
    # directory whose every file failed to scan, passed alongside six clean
    # explicit files, exited 1 because the explicit files carried `scanned_ok`
    # over the floor; the same directory alone exits 2. The floors exist to
    # judge what the DIRECTORY scan gated, so they must count only what the
    # directory contributed.
    explicit_files = {_resolved_identity(Path(a)) for a in argv if Path(a).is_file()}

    all_violations: list[str] = []
    census_paths = 0
    exempt_files: set[Path] = set()
    scanned_files: set[Path] = set()
    failed_files: set[Path] = set()
    try:
        for path in paths:
            # EXEMPT FILES COUNT ON NEITHER SIDE. An exemption is a decision not
            # to gate, so counting one as a successful scan counts a non-event —
            # and with `_APPROVED_PATHS` at size one, a production run always has
            # one, which is what made an all-or-nothing test over the collected
            # set unreachable in production (ADR-0058).
            #
            # `_scan_file` checks this again. One redundant CALL to one
            # implementation, not a second implementation — #422's drift trap is
            # copy-pasted logic, and there is none here.
            resolved = _resolved_identity(path)
            # Gate EVERY path regardless of provenance; only the CENSUS
            # accounting is scoped to directory-derived paths.
            counts_toward_census = resolved not in explicit_files
            census_paths += 1 if counts_toward_census else 0
            if _is_exempt(path):
                if counts_toward_census:
                    exempt_files.add(resolved)
                continue
            violations = _scan_file(path)
            all_violations.extend(violations)
            # DEFAULT-DENY: only a completed scan carries the marker, so any
            # other return path — including one added later — is a failure.
            if not counts_toward_census:
                continue
            if isinstance(violations, _ScannedOk):
                scanned_files.add(resolved)
            else:
                failed_files.add(resolved)
    except GateInternalError as exc:
        # NOT exit 1. Whatever was collected before the fault is discarded on
        # purpose: a faulting detector means no file's verdict is trustworthy,
        # including the ones that came back clean. Exit 2 says exactly that.
        print(f"check_tag_t3: {exc}", file=sys.stderr)
        return 2

    # A path scanned under one spelling and exempt under another counts as
    # SCANNED: it was gated. Subtracting keeps the tally honest without letting
    # an exemption erase a real scan.
    # DISJOINT, with a stated precedence. One resolved file can be reached by
    # several spellings and get different verdicts: exempt under its own name,
    # non-exempt (and possibly failing) under an alias. Counting it in two
    # buckets makes the tally lie. SCANNED wins over everything — it WAS gated —
    # and FAILED wins over EXEMPT, because a spelling the gate could not read is
    # the fact worth surfacing.
    scanned_ok = len(scanned_files)
    unscannable = len(failed_files - scanned_files)
    exempt = len(exempt_files - scanned_files - failed_files)
    distinct_count = len(exempt_files | scanned_files | failed_files)

    # The POST-SCAN census (#547). `len(paths)` counted files COLLECTED during
    # traversal — `git ls-files` plus a `stat`, which proves nothing was read,
    # parsed or gated. Two measured shapes cleared it: a tree the gate could not
    # read exited 1 ("violations found") against an exit contract that reserves
    # 2 for "the gate could not run", and a tree of exempt files exited 0 in
    # silence having scanned nothing at all.
    #
    # ONE self-diagnosing message rather than two arms: reporting the full tally
    # distinguishes "all exempt" from "could not read" without a second branch
    # to cover under this file's 100% gate.
    if scanned_a_directory and scanned_ok < _MIN_SCANNED_FILES:
        # PRINT WHAT WE FOUND BEFORE REFUSING, under its OWN header. Returning
        # above this discarded every violation collected so far — a real
        # tag(T3, ...) finding alongside read failures vanished entirely, and a
        # change that fixes a diagnostic defect must not introduce a worse one.
        _print_violations(all_violations, _PARTIAL_HEADER)
        print(
            f"check_tag_t3: the directory scan collected {census_paths} paths "
            f"resolving to {distinct_count} distinct files "
            f"({len(paths) - census_paths} explicit file arguments are "
            f"census-exempt and excluded): {exempt} exempt, {scanned_ok} "
            f"scanned, {unscannable} could not be scanned — expected at least "
            f"{_MIN_SCANNED_FILES} scanned. Refusing to report success while "
            f"gating nothing. If collected greatly exceeds distinct, the scan "
            f"root is full of links to the same files; otherwise check that "
            f"the gate can read the tree it was pointed at.",
            file=sys.stderr,
        )
        return 2

    if all_violations:
        _print_violations(all_violations, _FINDINGS_HEADER)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

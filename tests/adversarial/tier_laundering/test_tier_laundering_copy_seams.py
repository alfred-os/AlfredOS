"""Executable defence for tl-2026-011 / tl-2026-012 (#518 follow-on).

Both payloads mint a T3-tagged object through a seam the #534 guard did not cover,
and both were verified admitted before the fix. Each produced an object whose STATIC
type was ``TaggedContent[T2]`` while its runtime ``tier`` read ``T3`` — spec §3.5
cross-tier laundering with the type system still vouching for the lower tier.

tl-2026-013 (unbound base dispatch / raw state writes) is deliberately NOT executed
here: it is recorded ``out_of_scope=True`` because no runtime seam remains to guard,
following the tl-2026-003 precedent. Its executable defence is the CI detector.

These assert the SPECIFIC laundering outcome, not merely "something raised" — a
refusal for an unrelated reason would otherwise satisfy the case.
"""

from __future__ import annotations

import importlib.util
import warnings
from collections.abc import Iterator
from pathlib import Path

import pytest

from alfred.security import tiers as tiers_module
from alfred.security.tiers import T2, T3, TaggedContent
from tests.adversarial.payload_schema import AdversarialPayload

# Import the gate script by path: `scripts/` is not a package, and importing a COPY
# would recompute its `_REPO_ROOT`/`_APPROVED_PATHS` from the wrong `__file__` and
# silently invert every exemption.
_SCRIPT_PATH = Path(__file__).resolve().parents[3] / "scripts" / "check_tag_t3.py"
_spec = importlib.util.spec_from_file_location("check_tag_t3", _SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
check_tag_t3 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_tag_t3)
assert _SCRIPT_PATH.parents[1] == check_tag_t3._REPO_ROOT, (
    "the gate module resolved a different repo root than this test — its path "
    "exemptions would not match the real authorised homes"
)


@pytest.fixture(autouse=True)
def _deprecation_is_not_the_assertion() -> Iterator[None]:
    """``BaseModel.copy`` is deprecated; that warning must not decide the outcome."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        yield


def _payload(
    corpus_payloads: tuple[AdversarialPayload, ...], payload_id: str
) -> AdversarialPayload:
    """Fetch a corpus entry by id, failing loudly if the corpus drifted.

    Raises rather than calling ``pytest.fail``: that helper is ``NoReturn``, but CodeQL
    does not model it and read the fall-through as an implicit ``return None`` mixed with
    an explicit return (CodeQL 628).
    """
    for entry in corpus_payloads:
        if entry.id == payload_id:
            return entry
    raise AssertionError(
        f"corpus entry {payload_id!r} missing — the payload and its test have drifted"
    )


def _lower() -> TaggedContent[T2]:
    return TaggedContent[T2](content="ok", source="test", tier=T2, metadata={})


def test_tl_2026_011_deprecated_copy_cannot_launder_the_tier(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> None:
    """The deprecated ``copy`` API must not upgrade a tier (tl-2026-011)."""
    entry = _payload(corpus_payloads, "tl-2026-011")
    assert entry.expected_outcome == "boundary_refused"
    assert not entry.out_of_scope, "tl-2026-011 is a CLOSED seam; it must not be out_of_scope"

    # The CROSS-TIER message, not the generic nonce refusal: upgrading a
    # ``TaggedContent[T2]`` to T3 is exactly the spec §3.5 laundering shape, and the
    # guard order in ``_enforce_tier_admissible`` is deliberate so this attack gets the
    # diagnostic that names both tiers. Pinning the specific message keeps that
    # ordering from regressing into the vaguer "unauthorized construction".
    with pytest.raises(ValueError, match=r"declared 'T3' but parser expects 'T2'"):
        _lower().copy(update={"tier": T3})

    # The nonce refusal is the disposition when there is no generic to cross-check —
    # the same seam, the other branch, so neither is left unexercised.
    unparametrised = TaggedContent.model_construct(content="ok", source="test", tier=T2)
    with pytest.raises(ValueError, match=r"security\.t3_construction_unauthorized"):
        unparametrised.copy(update={"tier": T3})


def test_tl_2026_012_subclass_validator_shadow_cannot_launder_the_tier(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> None:
    """Subclassing must not be a lever on the tier guard (tl-2026-012)."""
    entry = _payload(corpus_payloads, "tl-2026-012")
    assert entry.expected_outcome == "boundary_refused"
    assert not entry.out_of_scope, "tl-2026-012 is a CLOSED seam; it must not be out_of_scope"

    # Layer A: the subclass cannot even be defined. Spelled via ``type(...)`` because
    # creation raises, so a ``class`` statement would bind a name nothing can read
    # (CodeQL 630); both spellings go through the same metaclass.
    with pytest.raises(TypeError, match="subclass"):
        type(
            "_Shadow",
            (TaggedContent[T3],),
            {"_validate_tier": classmethod(lambda cls, value: value)},
        )

    # A forged non-identifier class name is NOT a way in — layer A keys on the defining
    # module, which pydantic guarantees for a genuine parametrisation.
    with pytest.raises(TypeError, match="subclass"):
        type("shadow[forged]", (TaggedContent[T3],), {})

    # Forging ``__module__`` past the module check is ALSO refused: layer A's second
    # condition rejects any subclass redefining a tier guard, whatever module it claims.
    # Both residuals review identified are closed, not documented.
    # Iterate the REAL set rather than a hardcoded tuple: a hardcoded list silently omits
    # a guard (this one missed `_resolve_tier_from_wire`) and cannot cover future additions.
    assert tiers_module._TIER_GUARD_NAMES, "the guard set is empty — this sweep would be vacuous"
    for guard in sorted(tiers_module._TIER_GUARD_NAMES):
        with pytest.raises(TypeError, match=r"redefines trust-tier guard"):
            type(
                "ShadowForged",
                (TaggedContent[T3],),
                {
                    "__module__": "alfred.security.tiers",
                    guard: classmethod(lambda cls, *a, **k: None),
                },
            )

    # A subclass that forges ``__module__`` WITHOUT touching a guard is admitted (nothing
    # about it is dangerous), and every construction route on it must still refuse T3 —
    # so the closure above is not the only thing standing between an attacker and a mint.
    #
    # Each asserts the NONCE message, not the cross-tier one, even though the base is
    # ``TaggedContent[T2]``: a three-argument ``type()`` subclass does not inherit the
    # generic metadata (``__pydantic_generic_metadata__["args"]`` is empty), so there is no
    # generic to cross-check and the nonce guard is the only thing left standing. Verified
    # by execution — that is the branch these cases are here to exercise.
    benign_subclass = type(
        "ShadowSeams", (TaggedContent[T2],), {"__module__": "alfred.security.tiers"}
    )
    with pytest.raises(ValueError, match=r"security\.t3_construction_unauthorized"):
        benign_subclass(content="untrusted", source="attack", tier=T3, metadata={})
    with pytest.raises(ValueError, match=r"security\.t3_construction_unauthorized"):
        benign_subclass.model_construct(content="untrusted", source="attack", tier=T3)

    legitimate = benign_subclass.model_construct(content="ok", source="test", tier=T2)
    with pytest.raises(ValueError, match=r"security\.t3_construction_unauthorized"):
        legitimate.model_copy(update={"tier": T3})
    with pytest.raises(ValueError, match=r"security\.t3_construction_unauthorized"):
        legitimate.copy(update={"tier": T3})


_RESIDUAL_SPELLINGS = """\
from pydantic import BaseModel
from alfred.security import tiers as tiers_module
from alfred.security.tiers import T2, T3, TaggedContent

low = TaggedContent[T2](content="ok", source="test", tier=T2, metadata={})
object.__setattr__(low, "tier", T3)
low.__dict__["tier"] = T3
laundered = BaseModel.model_copy(low, update={"tier": T3})
also = BaseModel.copy(low, update={"tier": T3})
built = BaseModel.model_construct.__func__(TaggedContent[T3], content="x", tier=T3)
"""


def test_tl_2026_013_residual_is_recorded_as_out_of_scope(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> None:
    """The undefended residual must stay explicitly acknowledged (tl-2026-013).

    Its siblings above are closed seams, which could imply the whole class is covered.
    Per tl-2026-003, an out-of-scope payload carries no executable defence at this layer.
    """
    entry = _payload(corpus_payloads, "tl-2026-013")

    assert entry.out_of_scope, (
        "tl-2026-013 is not runtime-closable (base dispatch / raw state writes traverse "
        "no guardable seam); marking it in-scope claims a defence that does not exist"
    )
    assert (entry.out_of_scope_rationale or "").strip(), "an out-of-scope payload needs a rationale"


def test_tl_2026_013_is_currently_undefended_at_the_authoring_layer_too(
    tmp_path: Path,
) -> None:
    """The residual's named fallback layer does NOT yet detect it — pinned, not asserted away.

    An earlier revision asserted ``"check_tag_t3" in rationale``: a substring check on
    prose, which pins a spelling rather than a defence. Measured: a file containing all
    five residual spellings scans CLEAN. So the honest status is "undefended at every
    layer", and the rationale must not imply otherwise.

    This follows the recorded-residuals precedent (``test_de_egress_recorded_residuals``).
    It is expected to FAIL when the #518 detector rules land — that failure is the signal
    to flip the assertion to ``== 1`` and update tl-2026-013, not a regression.
    """
    probe = tmp_path / "residual_spellings.py"
    probe.write_text(_RESIDUAL_SPELLINGS)

    # Positive control FIRST: proves the file is actually reachable and scanned, so a
    # clean result below cannot come from the detector silently skipping it.
    control = tmp_path / "known_bad.py"
    control.write_text(_RESIDUAL_SPELLINGS + '\ntagged = tag(T3, "x")\n')
    assert check_tag_t3.main([str(control)]) == 1, (
        "the detector did not flag a known-bad file — the scan is not reaching these "
        "paths, so the result below would be meaningless"
    )

    assert check_tag_t3.main([str(probe)]) == 0, (
        "scripts/check_tag_t3.py now flags the tl-2026-013 residual spellings. That is "
        "the intended outcome of the #518 detector work — update this test to assert 1 "
        "and rewrite tl-2026-013's out_of_scope_rationale to name the real defence."
    )

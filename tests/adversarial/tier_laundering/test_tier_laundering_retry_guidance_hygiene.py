"""Retry-guidance hygiene (spec §6.3, §12.3, payload ``tl-2026-008``).

The second-turn retry prompt token set MUST be a strict subset of:
``{schema_json_tokens} U {fixed_template_tokens}``.

The closed-vocabulary :data:`ValidatorErrorCategory` argument means
the retry builder NEVER receives the raw validator-error string —
that string can carry prior LLM output (a T3-derived fragment); echoing
it into the retry prompt would close the laundering loop.

This module exercises three orthogonal contracts:

1. **Structural absence pin** (``inspect.signature``).
   :meth:`QuarantinedExtractor._build_retry_prompt` MUST NOT have a
   ``prior_response`` / ``malformed_output`` / ``last_response``
   parameter. The signature-shape check is the type-level invariant
   that survives ``# type: ignore`` and is independent of any one
   prompt-body change.

2. **Token-set invariant** (positive, no-escape-hatch).
   For every closed ``validator_error_category``, the returned prompt's
   lowercase whitespace tokens are a STRICT subset of
   ``schema_json_tokens U _FIXED_TEMPLATE_TOKENS``. The
   ``_FIXED_TEMPLATE_TOKENS`` set is duplicated here (deliberately —
   each test-owned copy is the source-of-truth pin; the production
   template MUST stay narrow enough that this set covers it).
   The original ``len(t) <= 2`` escape hatch was removed (err-016 /
   prov-002): admitting short adversarial tokens (``do``, ``go``,
   ``or``) without semantic check is a defence-in-depth gap.

3. **Poisoned-input positive control** (negative).
   A retry prompt that erroneously echoes a prior-response token
   MUST trip the same invariant — confirming the assertion in (2) is
   not vacuous.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Final

import yaml

from alfred.security.quarantine import QuarantinedExtractor

# ---------------------------------------------------------------------------
# Payload-shape drift guard.
# ---------------------------------------------------------------------------

_PAYLOAD_ID: Final[str] = "tl-2026-008"
_PAYLOAD_PATH: Final[Path] = Path(__file__).parent / "tl_retry_guidance_hygiene.yaml"


def test_payload_yaml_present_and_well_formed() -> None:
    """The ``tl-2026-008`` payload exists with the corpus-required shape."""
    assert _PAYLOAD_PATH.exists(), f"Missing adversarial payload {_PAYLOAD_PATH.name}"
    payload = yaml.safe_load(_PAYLOAD_PATH.read_text())
    assert payload["id"] == _PAYLOAD_ID
    assert payload["category"] == "tier_laundering"
    assert payload["expected_outcome"] == "boundary_refused"
    assert "INJECTED_SYSTEM_OVERRIDE" in payload["payload"]


# ---------------------------------------------------------------------------
# Contract 1 — signature pin (prior_response / malformed_output absent).
# ---------------------------------------------------------------------------


def test_retry_prompt_signature_has_no_prior_response_parameter() -> None:
    """``_build_retry_prompt`` MUST NOT accept any prior-response parameter.

    Any of ``prior_response`` / ``malformed_output`` / ``last_response``
    would let the caller pass the bad LLM output into the retry prompt
    — closing the prompt-injection laundering loop on turn two. The
    closed-vocabulary :data:`ValidatorErrorCategory` argument is the
    only legitimate retry-context input.
    """
    sig = inspect.signature(QuarantinedExtractor._build_retry_prompt)
    forbidden = {
        "prior_response",
        "previous_output",
        "last_response",
        "malformed_output",
        "validator_error",  # the free-form variant of the closed-set arg
    }
    leaked = set(sig.parameters.keys()) & forbidden
    assert not leaked, (
        f"_build_retry_prompt has forbidden parameter(s) {leaked!r}; "
        "any of these would close the prompt-injection laundering loop "
        "on the second turn (spec §6.3 / err-016)."
    )


# ---------------------------------------------------------------------------
# Contract 2 — token-set invariant, strict.
# ---------------------------------------------------------------------------

# The fixed-template token set MUST cover every word the production
# `_build_retry_prompt` body emits. Update this set when the template
# changes — the test forces the deliberate audit.
#
# Source: src/alfred/security/quarantine.py _RETRY_CATEGORY_LABELS +
# the template literal in `_build_retry_prompt`:
#
#   "Previous extraction failed: {label}.\n\n"
#   "Try again. Output valid JSON matching this schema:\n{schema_json}"
#
# Plus the label phrases:
#   "the previous response did not match the schema"
#   "the previous response was not valid JSON"
#   "the previous response was missing one or more required fields"
#   "the previous response was invalid"
_FIXED_TEMPLATE_TOKENS: Final[frozenset[str]] = frozenset(
    {
        # Template-frame words.
        "previous",
        "extraction",
        "failed:",
        "failed",
        "try",
        "again.",
        "again",
        "output",
        "valid",
        "json",
        "matching",
        "this",
        "schema:",
        "schema",
        # Label-body words across every category.
        "the",
        "response",
        "did",
        "not",
        "match",
        "was",
        "missing",
        "one",
        "or",
        "more",
        "required",
        "fields",
        "fields.",
        "invalid",
        "invalid.",
        "schema.",
        "json.",
    }
)


def _allowed_tokens(schema_json: str) -> frozenset[str]:
    """Union of the schema-JSON tokens and the fixed-template tokens."""
    schema_tokens = frozenset(schema_json.lower().split())
    return schema_tokens | _FIXED_TEMPLATE_TOKENS


_CATEGORIES = (
    "schema_mismatch",
    "json_parse_error",
    "missing_required_field",
    "unknown",
)


def test_retry_prompt_token_set_strict_subset_invariant() -> None:
    """For every closed category, the retry prompt's tokens are a strict subset.

    Per err-016 / prov-002 the prior ``len(t) <= 2`` escape hatch was
    removed: admitting short adversarial tokens (``do``, ``go``,
    ``or``) without semantic check is a defence-in-depth gap.
    """
    extractor = QuarantinedExtractor.__new__(QuarantinedExtractor)
    schema_json = (
        '{"type": "object", "required": ["title"], "properties": {"title": {"type": "string"}}}'
    )

    for category in _CATEGORIES:
        prompt = extractor._build_retry_prompt(
            validator_error_category=category,  # type: ignore[arg-type]
            schema_json=schema_json,
        )
        retry_tokens = frozenset(prompt.lower().split())
        extra = retry_tokens - _allowed_tokens(schema_json)
        # STRICT: any extra token is a violation. Update
        # ``_FIXED_TEMPLATE_TOKENS`` after a deliberate audit if a
        # template change adds a legitimate static word.
        assert not extra, (
            f"category={category!r}: retry prompt has tokens outside "
            f"the allowed set: {sorted(extra)!r}. Add to "
            "`_FIXED_TEMPLATE_TOKENS` if these come from the static "
            "template; do NOT add tokens from any free-form input. "
            "Spec §6.3."
        )


# ---------------------------------------------------------------------------
# Contract 3 — poisoned-input positive control.
# ---------------------------------------------------------------------------


def test_poisoned_retry_prompt_trips_the_strict_invariant() -> None:
    """A simulated prior-response echo MUST violate the strict subset invariant.

    Positive-control to confirm the assertion in
    :func:`test_retry_prompt_token_set_strict_subset_invariant` is not
    vacuous. The "bad builder" simulated here is what the codebase
    MUST NOT produce: a retry prompt that includes a token from the
    prior LLM output (``INJECTED_SYSTEM_OVERRIDE``).
    """
    prior_bad_token = "INJECTED_SYSTEM_OVERRIDE"  # noqa: S105 — test fixture, not a credential
    poisoned_prompt = (
        "Previous extraction failed: invalid.\n\n"
        f"Bad prior response was: {prior_bad_token}\n"
        "Try again. Output valid JSON matching this schema:\n{}"
    )
    schema_json = "{}"
    retry_tokens = frozenset(poisoned_prompt.lower().split())
    extra = retry_tokens - _allowed_tokens(schema_json)
    lowered = {t.lower() for t in extra}
    # The injected token (lowercased) must be detected as out-of-set.
    assert any("injected" in t for t in lowered), (
        "Expected the adversarial INJECTED_SYSTEM_OVERRIDE token to be "
        f"detected as out-of-set; extra tokens were {sorted(extra)!r}. "
        "The strict invariant would not be catching this exfil."
    )

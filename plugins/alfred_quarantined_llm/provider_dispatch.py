"""Provider dispatch for the quarantined-LLM extractor (PR-S3-4, spec §6.2/6.3).

This module is the capability-branched dispatcher that turns a
``(content, schema, provider)`` triple into a ``dict`` shaped like
:data:`alfred.security.quarantine.ExtractionResult`. It runs inside the
quarantined-LLM subprocess; the orchestrator never imports it directly
(orchestrator-side calls flow through
:class:`alfred.plugins.quarantine_extractor.QuarantinedExtractor`).

Three branches, closed-domain on the provider's declared
:class:`alfred.providers.base.ProviderCapability` set (spec §6.2):

1. ``NATIVE_CONSTRAINED_GENERATION`` — Anthropic tool-use shape. The
   schema lives at ``tools[0].input_schema``; the response is
   schema-constrained by the provider itself.
2. ``JSON_OBJECT_MODE`` — DeepSeek-style ``response_format=
   {"type": "json_object"}``. The model returns JSON but not
   necessarily schema-valid; the host validates with Pydantic.
3. neither → ``prompt_embedded_fallback``. Schema embedded in the user
   prompt; the host validates after the call.

Native_constrained wins when both 1 and 2 are declared (the dispatcher's
``if/elif/else`` order pins this). The choice is documented in the
closed :data:`alfred.security.quarantine.ExtractionMode` Literal so any
drift fails type-check.

Retry contract (spec §6.3):

* Up to ``_MAX_RETRIES + 1`` total attempts.
* Only :class:`pydantic.ValidationError` and :class:`json.JSONDecodeError`
  are retry-eligible. Every other exception propagates — silently
  swallowing provider HTTP failures would hide outages from the audit
  log (err-009).
* On exhaustion the dispatcher returns ``{"kind": "typed_refusal",
  "reason": "cannot_extract"}``. It NEVER returns an ``Extracted`` with
  ``extraction_mode="malformed_output"`` — that string is a transport-
  layer protocol-violation marker, not a legitimate outcome
  (spec §6.7 / prov-011).
* The retry prompt is built ONLY from a closed-vocabulary
  :data:`ValidatorErrorCategory` tag + the schema JSON. Free-form
  ``str(exc)`` (or the older ``sanitize_validator_error`` string) is
  NOT carried into the prompt — Pydantic ``loc`` tuples can include
  attacker-controlled JSON keys when the quarantined LLM returns a
  poisoned dict, and ``json.JSONDecodeError`` carries column numbers
  that depend on the model's output. The closed-vocab builder
  :func:`alfred.security.quarantine.QuarantinedExtractor._build_retry_prompt`
  is the single source for both sides of the boundary (sec-001 /
  rvw-1 / AI-5 fix, replacing the prior :func:`_build_extraction_prompt`
  free-form retry path).

Retry back-off (perf-1 fix): the loop sleeps
``0.5 * (2 ** attempt)`` seconds between retries (exponential back-off)
and caps total wall-clock at :data:`_MAX_TOTAL_WALL_CLOCK_SECONDS`.
A budget breach short-circuits to ``cannot_extract`` so the dispatcher
does not block forever on a thrashing provider.
"""

from __future__ import annotations

import asyncio
import functools
import json
import time
from typing import Any

import httpx
from pydantic import ValidationError

from alfred.providers.base import ProviderCapability
from alfred.security.quarantine import (
    ValidatorErrorCategory,
    _build_retry_prompt,
)

# Maximum retries on validation / JSON-decode failure (spec §6.3). Total
# attempts is ``_MAX_RETRIES + 1`` — one initial call plus this many
# retries. Configurable per the spec via ``config/policies.yaml``
# ``quarantine.extraction_max_retries``; the constant lives here so the
# Slice-3 surface is stable while the policies-yaml loader lands later.
_MAX_RETRIES = 2

# Per-extraction wall-clock budget (perf-1 fix). The retry loop was firing
# back-to-back attempts with no back-off and no upper bound — a thrashing
# provider could pin a quarantine subprocess for the full
# orchestrator-side deadline. 30 seconds keeps the loop bounded well
# under the orchestrator's 30s action_deadline_seconds (config/policies.yaml).
_MAX_TOTAL_WALL_CLOCK_SECONDS: float = 30.0

# Exponential back-off base. Sleep between attempt N and N+1 is
# ``_BACKOFF_BASE_SECONDS * (2 ** attempt)`` — 0.5s after attempt 0,
# 1.0s after attempt 1. Keeps the loop inside the wall-clock budget
# while giving a thrashing provider time to recover.
_BACKOFF_BASE_SECONDS: float = 0.5


@functools.cache
def _cached_parsed_schema(schema_json: str) -> dict[str, Any]:
    """Parse ``schema_json`` once per unique string and cache the result.

    The dispatcher receives the same schema text on every call from the
    orchestrator side; re-running ``json.loads`` on every invocation is
    wasted CPU. ``functools.cache`` is bounded by the closed set of
    schema strings the orchestrator ships (every distinct
    :class:`ExtractionSchema` subclass produces one entry), so the cache
    never grows unboundedly in production. perf-2 fix.
    """
    parsed = json.loads(schema_json)
    if not isinstance(parsed, dict):
        # Defensive: schema_json is host-controlled, but a malformed
        # entry would otherwise blow up far from the source.
        raise TypeError("schema_json must decode to a JSON object")
    return parsed


# ---------------------------------------------------------------------------
# Public entry point — the seam :func:`handle_extract` binds to.
# ---------------------------------------------------------------------------


def _categorise_validator_error(
    exc: ValidationError | json.JSONDecodeError,
) -> ValidatorErrorCategory:
    """Map a retry-eligible exception to a closed-vocab category.

    The retry-prompt builder accepts ONLY :data:`ValidatorErrorCategory`
    labels — free-form ``str(exc)`` is the prov-002 / err-009 / sec-001
    injection vector. This helper is the single map from concrete
    exception types to the closed set; every other code path that wants
    a retry prompt MUST go through it.
    """
    if isinstance(exc, json.JSONDecodeError):
        return "json_parse_error"
    # ValidationError leg. We could inspect ``exc.errors()`` to
    # distinguish ``missing_required_field`` vs ``schema_mismatch``,
    # but the closed-vocab gate makes that optional — the
    # ``schema_mismatch`` label is the conservative default that
    # never widens into attacker-controlled text. Slice 4 can refine
    # this by walking ``exc.errors()`` for the ``type == "missing"``
    # case if telemetry shows it matters.
    return "schema_mismatch"


async def dispatch_extraction(
    *,
    content: bytes,
    schema_json: str,
    schema_version: int,  # noqa: ARG001 — accepted for ExtractionResult parity (audit row)
    provider: Any,
) -> dict[str, Any]:
    """Dispatch a structured extraction via the quarantined LLM provider.

    Selects the dispatch path from the provider's capability set
    (spec §6.2):

    * ``NATIVE_CONSTRAINED_GENERATION`` → ``native_constrained`` mode
      (tool-use shape, schema-constrained by the provider).
    * ``JSON_OBJECT_MODE`` → ``json_object_unconstrained`` mode
      (JSON-mode wire format, Pydantic-validated host-side).
    * neither → ``prompt_embedded_fallback`` mode (schema embedded in
      the user prompt, parsed + validated host-side).

    Up to ``_MAX_RETRIES + 1`` attempts; on exhaustion returns
    ``{"kind": "typed_refusal", "reason": "cannot_extract"}``.

    Between attempts the loop sleeps ``_BACKOFF_BASE_SECONDS * (2 ** attempt)``
    seconds (perf-1 fix: the prior loop fired back-to-back). Total
    wall-clock per extraction is capped at
    :data:`_MAX_TOTAL_WALL_CLOCK_SECONDS`; exceeding the cap short-circuits
    to ``cannot_extract`` so the dispatcher does not block forever on a
    thrashing provider.

    Only :class:`ValidationError` and :class:`json.JSONDecodeError`
    are caught as retry-eligible. :class:`httpx.HTTPError` is converted
    to a ``TypedRefusal(reason="provider_unavailable")`` — distinct from
    ``cannot_extract`` so audit consumers can tell provider outages
    apart from model-output failures (err-002 fix). Every other
    exception propagates so the supervisor's audit log captures
    unexpected failures with their real shape (err-009).

    ``schema_version`` is accepted-and-ignored here because it travels
    on the audit row via the orchestrator-side caller
    (:class:`QuarantinedExtractor`); the dispatcher itself doesn't act
    on the version (the :data:`ExtractionSchema` ABC + Literal[1] check
    on the orchestrator side gates the version invariant before any
    subprocess call lands).
    """
    caps = provider.capabilities()
    if ProviderCapability.NATIVE_CONSTRAINED_GENERATION in caps:
        extraction_mode = "native_constrained"
    elif ProviderCapability.JSON_OBJECT_MODE in caps:
        extraction_mode = "json_object_unconstrained"
    else:
        extraction_mode = "prompt_embedded_fallback"

    # ``errors="replace"`` keeps the loop alive on partially-corrupt
    # T3 bytes — the LLM downstream can still see something. The
    # replacement char (U+FFFD) is a stable signal it can flag as
    # ambiguous_input on the next prompt build.
    content_text = content.decode("utf-8", errors="replace")
    deadline_monotonic = time.monotonic() + _MAX_TOTAL_WALL_CLOCK_SECONDS
    retry_category: ValidatorErrorCategory | None = None
    for attempt in range(_MAX_RETRIES + 1):
        if time.monotonic() >= deadline_monotonic:
            # Per-extraction wall-clock budget breach (perf-1 fix). Short
            # circuit to cannot_extract so a thrashing provider does not
            # block the orchestrator's action_deadline_seconds.
            return {"kind": "typed_refusal", "reason": "cannot_extract"}
        prompt = _build_extraction_prompt(content_text, schema_json, retry_category)
        try:
            raw_response = await _call_provider(
                prompt=prompt,
                schema_json=schema_json,
                provider=provider,
                extraction_mode=extraction_mode,
            )
        except httpx.HTTPError:
            # err-002 fix: previously ``provider_unavailable`` was
            # declared in :data:`TypedRefusalReason` but no path
            # actually returned it. Provider connection errors
            # (timeouts, DNS failures, TLS handshake failures, 5xx
            # responses lifted by ``raise_for_status``) map here so
            # audit consumers can tell provider outages apart from
            # model-output failures.
            return {"kind": "typed_refusal", "reason": "provider_unavailable"}
        try:
            validated = _validate_response(raw_response, schema_json)
            return {
                "kind": "extracted",
                "data": validated,
                "extraction_mode": extraction_mode,
            }
        except (ValidationError, json.JSONDecodeError) as exc:
            # Free-form ``str(exc)`` is the prov-002 / err-009 / sec-001
            # injection vector — Pydantic ``loc`` tuples can include
            # attacker-controlled JSON keys when the quarantined LLM
            # returns a poisoned dict. Map to a closed-vocab category
            # and route through the shared :func:`_build_retry_prompt`
            # helper instead.
            retry_category = _categorise_validator_error(exc)
        # Exponential back-off (perf-1 fix). Skip the sleep on the
        # last attempt — there is no next try, the loop is about to
        # exit and the refusal is the next emit.
        if attempt < _MAX_RETRIES:
            await asyncio.sleep(_BACKOFF_BASE_SECONDS * (2**attempt))
    # Exhaustion is a closed-domain TypedRefusal, NOT an Extracted with
    # a malformed_output mode (spec §6.7 / prov-011).
    return {"kind": "typed_refusal", "reason": "cannot_extract"}


# ---------------------------------------------------------------------------
# Prompt building (closed-vocab retry guidance) + provider call shaping.
# ---------------------------------------------------------------------------


def _build_extraction_prompt(
    content: str,
    schema_json: str,
    retry_category: ValidatorErrorCategory | None,
) -> str:
    """Build the user prompt for the extractor (spec §6.3).

    First attempt: schema + content. The model has everything it needs.

    Retry attempt: closed-vocab category + schema ONLY, via the shared
    :func:`alfred.security.quarantine._build_retry_prompt` helper. The
    prior LLM response is deliberately absent — including it (or any
    derivative like the older ``sanitize_validator_error`` string)
    would propagate prompt-injection payloads forward (prov-004 /
    sec-001 / rvw-1 / AI-5). Pydantic ``loc`` tuples in particular can
    embed attacker-controlled JSON keys when the quarantined LLM
    returns a poisoned dict; the closed-vocab category gate is the
    structural defence.
    """
    if retry_category is None:
        return (
            f"Extract structured data matching this schema:\n{schema_json}\n\nContent:\n{content}"
        )
    return _build_retry_prompt(
        validator_error_category=retry_category,
        schema_json=schema_json,
    )


async def _call_provider(
    *,
    prompt: str,
    schema_json: str,
    provider: Any,
    extraction_mode: str,
) -> str:
    """Dispatch the provider call using the wire shape for ``extraction_mode``.

    Three shapes (spec §6.2):

    * ``native_constrained``: Anthropic tool-use — ``tools=[{
      "name": ..., "description": ..., "input_schema": <schema>}]``,
      ``tool_choice`` pinned to the tool name. Returns the tool's
      ``input_schema``-validated payload.
    * ``json_object_unconstrained``: ``response_format={"type":
      "json_object"}`` (DeepSeek / OpenAI). The model returns a JSON
      string we parse host-side.
    * ``prompt_embedded_fallback``: bare completion. The schema is in
      the user prompt; the response is text we parse host-side.

    Returns a JSON string in every branch so :func:`_validate_response`
    has a uniform shape to work with.

    Uses :func:`_cached_parsed_schema` for the JSON-parse step so
    repeated extractions against the same schema do not re-decode the
    same string (perf-2 fix).
    """
    schema = _cached_parsed_schema(schema_json)
    if extraction_mode == "native_constrained":
        response = await provider.complete(
            messages=[{"role": "user", "content": prompt}],
            tools=[
                {
                    "name": "extract_structured_data",
                    "description": "Extract structured data from content per schema.",
                    "input_schema": schema,
                }
            ],
            tool_choice={"type": "tool", "name": "extract_structured_data"},
        )
        # Anthropic returns a tool_use block; the dispatcher reads the
        # input dict directly and re-serialises it so the validator
        # has a JSON string to work with (parity with the other two
        # branches).
        return json.dumps(response.tool_use_input)
    if extraction_mode == "json_object_unconstrained":
        response = await provider.complete(
            messages=[{"role": "user", "content": f"{prompt}\nReturn valid JSON."}],
            response_format={"type": "json_object"},
        )
        return str(response.content)
    # prompt_embedded_fallback: bare completion, no provider-side JSON
    # mode, no tools. The schema is embedded in the prompt and the
    # validator catches malformed output on the host.
    response = await provider.complete(
        messages=[{"role": "user", "content": prompt}],
    )
    return str(response.content)


# ---------------------------------------------------------------------------
# Validation (raises only retry-eligible exceptions).
# ---------------------------------------------------------------------------


def _validate_response(raw: str, schema_json: str) -> dict[str, object]:
    """Validate ``raw`` against the JSON schema; return a dict on success.

    Raises :class:`json.JSONDecodeError` if ``raw`` is not parseable
    JSON, or :class:`pydantic.ValidationError` if it parses but fails
    schema validation — both retry-eligible exception types the
    dispatcher's ``except`` clause catches.

    Slice-3 contract (prov-008 partial): the dispatcher inside the
    plugin subprocess does NOT yet thread the full Pydantic schema
    class through the wire (the orchestrator ships ``schema_json``,
    not ``type[ExtractionSchema]``). For now the validator parses
    the JSON + asserts it's a dict. PR-S3-4's QuarantinedExtractor
    (Task 6) re-validates on the orchestrator side against the
    actual schema class, where the type system can pin
    ``schema_version: Literal[1]``. End-to-end schema validation
    inside the subprocess lands in Slice 4 once the schema-class
    serialiser is in place.
    """
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        # Re-raise as JSONDecodeError so the dispatcher's retry path
        # treats this the same as a parse failure — the model
        # returned the wrong top-level shape, which is the same
        # class of "model misbehaved" problem.
        raise json.JSONDecodeError("extraction response must be a JSON object", raw, 0)
    # schema_json is accepted for the Slice-4 thread-through; in
    # Slice 3 the dispatcher leaves orchestrator-side Pydantic
    # validation to QuarantinedExtractor. The variable is consumed by
    # this docstring + the JSON.loads above for parse-error parity.
    _ = schema_json
    return parsed

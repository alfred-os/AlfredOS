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
* The retry prompt is built from the SANITISED validator error +
  schema only. Calling ``str(exc)`` on a Pydantic ``ValidationError``
  embeds the offending input value (potentially T3-derived); the
  sanitised form extracts only ``exc.errors()`` field-paths +
  validator types (prov-004 / err-009).
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from alfred.providers.base import ProviderCapability

# Maximum retries on validation / JSON-decode failure (spec §6.3). Total
# attempts is ``_MAX_RETRIES + 1`` — one initial call plus this many
# retries. Configurable per the spec via ``config/policies.yaml``
# ``quarantine.extraction_max_retries``; the constant lives here so the
# Slice-3 surface is stable while the policies-yaml loader lands later.
_MAX_RETRIES = 2


# ---------------------------------------------------------------------------
# Public entry point — the seam :func:`handle_extract` binds to.
# ---------------------------------------------------------------------------


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
    Only :class:`ValidationError` and :class:`json.JSONDecodeError`
    are caught — every other exception propagates so the supervisor's
    audit log captures provider outages with their real shape
    (err-009).

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
    last_error: str | None = None
    for _attempt in range(_MAX_RETRIES + 1):
        prompt = _build_extraction_prompt(content_text, schema_json, last_error)
        raw_response = await _call_provider(
            prompt=prompt,
            schema_json=schema_json,
            provider=provider,
            extraction_mode=extraction_mode,
        )
        try:
            validated = _validate_response(raw_response, schema_json)
            return {
                "kind": "extracted",
                "data": validated,
                "extraction_mode": extraction_mode,
            }
        except (ValidationError, json.JSONDecodeError) as exc:
            # ``str(exc)`` would embed the offending input value (a
            # potentially T3-derived string); the sanitised form
            # extracts only field paths + validator types. The retry
            # prompt is built from this sanitised string + the schema
            # — never the prior LLM response (prov-004 / err-009).
            last_error = sanitize_validator_error(exc)
    # Exhaustion is a closed-domain TypedRefusal, NOT an Extracted with
    # a malformed_output mode (spec §6.7 / prov-011).
    return {"kind": "typed_refusal", "reason": "cannot_extract"}


# ---------------------------------------------------------------------------
# sanitize_validator_error — prov-004 / err-009.
# ---------------------------------------------------------------------------


def sanitize_validator_error(exc: ValidationError | json.JSONDecodeError) -> str:
    """Produce a safe validator-error string that never embeds the input.

    The retry-prompt path is forbidden from carrying the offending input
    value forward — that would propagate prior LLM output (potentially
    T3-derived prompt-injection) into the next prompt (prov-004 /
    err-009).

    For :class:`ValidationError`, this helper extracts ``exc.errors()``
    field-paths + validator types only — never the ``input`` key.
    ``include_url=False`` suppresses Pydantic's docs URLs which would
    otherwise show up in the prompt and add noise without value.

    For :class:`json.JSONDecodeError`, the helper returns a stable
    identifier (the exception class name) — the message itself includes
    a column number but never the raw bytes the parser choked on, so
    even that is safe-by-construction. We surface the class name only
    to keep retry prompts stable across pydantic / stdlib versions.
    """
    if isinstance(exc, ValidationError):
        parts = [
            f"{'.'.join(str(loc) for loc in e['loc'])}: {e['type']}"
            for e in exc.errors(include_url=False)
        ]
        return "; ".join(parts)
    # json.JSONDecodeError leg — the type-name identifier is stable and
    # carries no user input. Even the column number would be safe but
    # we omit it to keep retry prompts deterministic across attempts.
    return f"json_decode_error: {type(exc).__name__}"


# ---------------------------------------------------------------------------
# Prompt building (sanitised retry guidance) + provider call shaping.
# ---------------------------------------------------------------------------


def _build_extraction_prompt(content: str, schema_json: str, validator_error: str | None) -> str:
    """Build the user prompt for the extractor (spec §6.3).

    First attempt: schema + content. The model has everything it needs.

    Retry attempt: SANITISED validator error + schema ONLY. The prior
    LLM response is deliberately absent — including it would
    propagate prompt-injection payloads forward (prov-004). The
    sanitised validator error names the failing field path + validator
    type so the model has actionable feedback.
    """
    if validator_error is None:
        return (
            f"Extract structured data matching this schema:\n{schema_json}\n\nContent:\n{content}"
        )
    return (
        f"Previous extraction failed validation:\n{validator_error}\n\n"
        f"Try again. Output valid JSON matching this schema:\n{schema_json}"
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
    """
    schema = json.loads(schema_json)
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

"""Provider dispatch for the quarantined-LLM extractor (#339 seam port, #340 PR1).

This module is the capability-branched dispatcher that turns a
``(content, schema, provider)`` triple into a ``dict`` shaped like
:data:`alfred.security.quarantine.ExtractionResult`. It runs inside the
quarantined-LLM subprocess; the orchestrator never imports it directly
(orchestrator-side calls flow through
:class:`alfred.plugins.quarantine_extractor.QuarantinedExtractor`).

Two branches, closed-domain on the provider's declared
:class:`alfred.providers.base.ProviderCapability` set (fork b, #340):

1. ``NATIVE_CONSTRAINED_GENERATION`` — the #339
   ``CompletionRequest``/``CompletionResponse`` tool-use shape. A single
   forced ``extract_structured_data`` tool is advertised with the schema
   at ``tools[0].input_schema``; the response's ``tool_calls[0].arguments``
   is schema-constrained by the provider itself.
2. neither → ``prompt_embedded_fallback``. Schema embedded in the user
   prompt; the host validates the plain-text ``content`` after the call.

The DeepSeek-style ``JSON_OBJECT_MODE`` runtime branch is REMOVED
(#340 fork b): no shipped provider is JSON-object-only, and every
constrained-capable provider declares a native tool-use path. A provider
without ``NATIVE_CONSTRAINED_GENERATION`` (including deepseek-chat /
deepseek-reasoner) now uses the prompt-embedded fallback. The
``json_object_unconstrained`` member of
:data:`alfred.security.quarantine.ExtractionMode` is RESERVED (not
selected at runtime) — see that module for the audit-row-continuity note.

Retry contract (spec §6.3):

* Up to ``EXTRACTION_MAX_RETRIES + 1`` total attempts.
* Only :class:`pydantic.ValidationError`, :class:`json.JSONDecodeError`,
  and :class:`alfred.providers.base.ProviderMalformedToolArgumentsError`
  are retry-eligible. Every other exception propagates — silently
  swallowing provider failures would hide outages from the audit
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

Egress-free (#340 PR1): this module imports NO SDK and NO ``httpx`` — the
provider it drives is injected by the caller, and provider/transport
outages surface as :class:`alfred.providers.base.ProviderUnavailableError`,
which each adapter raises at its own SDK-call boundary. The dispatcher
maps that to ``TypedRefusal(reason="provider_unavailable")``.
"""

from __future__ import annotations

import asyncio
import functools
import json
import time
from typing import Any

import structlog
from pydantic import ValidationError

from alfred.providers.base import (
    CompletionRequest,
    ForcedTool,
    Message,
    ProviderCapability,
    ProviderMalformedToolArgumentsError,
    ProviderUnavailableError,
    ToolDefinition,
)
from alfred.security.quarantine import (
    EXTRACTION_MAX_RETRIES,
    ValidatorErrorCategory,
    _build_retry_prompt,
)

# Pinned to STDERR by ``__main__._pin_structlog_to_stderr`` before any child log is
# emitted — structlog's default is stdout, which is the fd-1 JSON-RPC wire. Same
# module-scope pattern as ``brokered_egress``.
_log = structlog.get_logger(__name__)

# The tool name forced on the native_constrained path (spec §6.2, #339 seam).
_EXTRACT_TOOL_NAME = "extract_structured_data"

# CompletionRequest's own max_tokens default, read from the model so an unset
# per-extraction budget stays byte-identical to the provider seam's default
# (no drift with base.py). Used when dispatch_extraction is called without a
# max_tokens (P1b, #340) — golive threads the routing.yaml budget instead.
# ``.default`` is typed ``Any``; the ``int(...)`` VERIFIES it (rather than merely
# asserting the annotation) so a future base.py switch to a ``default_factory``
# (whose ``.default`` is the ``PydanticUndefined`` sentinel) fails loud HERE at
# import, not deep inside an extraction (fleet review: reviewer/provider/security/devex).
_COMPLETION_DEFAULT_MAX_TOKENS: int = int(CompletionRequest.model_fields["max_tokens"].default)

# Per-extraction wall-clock budget (perf-1 fix). The retry loop was firing
# back-to-back attempts with no back-off and no upper bound — a thrashing
# provider could pin a quarantine subprocess for the full orchestrator-side
# deadline. This budget sits UNDER the host read-frame timeout (25s,
# quarantine_child_io._READ_FRAME_TIMEOUT_S) UNDER the orchestrator
# action_deadline (30s) — monotone per P1e (#340); the prior 30s was EQUAL to
# action_deadline (the "well under" claim was wrong, surviving only because the
# echo child replies instantly). The loop-top check alone is NOT a hard ceiling
# (a single provider.complete() could outrun it) — and neither is the
# asyncio.wait_for wrap: the SDK's blocking recv runs in a shielded worker thread
# (anyio to_thread.run_sync, abandon_on_cancel=False), so wait_for cancels and
# then AWAITS it. What makes this budget a real ceiling is that
# dispatch_extraction hands the REMAINING budget to source.bind(), which anchors
# it as an ABSOLUTE socket deadline clamping every syscall of that attempt
# (brokered_egress). N attempts therefore share one wall-clock ceiling, not N of
# them (#340 PR2b Task 5). The 8s SDK read
# (brokered_egress._CHILD_SDK_READ_TIMEOUT, Task 3) is the per-syscall IDLE cap
# under it — on its own it resets per byte and bounds nothing cumulatively.
_MAX_TOTAL_WALL_CLOCK_SECONDS: float = 20.0

# Exponential back-off base. Sleep between attempt N and N+1 is
# ``_BACKOFF_BASE_SECONDS * (2 ** attempt)`` — 0.5s after attempt 0,
# 1.0s after attempt 1 — but CLAMPED at the call site to the remaining
# wall-clock budget (#472 finding 1), so the back-off itself can never
# carry the loop past the ceiling; it only fills time a thrashing provider
# is given to recover WITHIN that budget.
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
    exc: ValidationError | json.JSONDecodeError | ProviderMalformedToolArgumentsError,
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
    # ValidationError | ProviderMalformedToolArgumentsError (the latter
    # raised by _call_provider on an empty/malformed forced-tool
    # response, #340) both map to the conservative closed-vocab default.
    # We could inspect ValidationError.errors() to distinguish
    # ``missing_required_field`` vs ``schema_mismatch``, but the
    # closed-vocab gate makes that optional — ``schema_mismatch`` never
    # widens into attacker-controlled text. Slice 4 can refine this by
    # walking ``exc.errors()`` for the ``type == "missing"`` case if
    # telemetry shows it matters.
    return "schema_mismatch"


async def dispatch_extraction(
    *,
    content: bytes,
    schema_json: str,
    schema_version: int,  # noqa: ARG001 — accepted for ExtractionResult parity (audit row)
    source: Any,
    max_tokens: int | None = None,
) -> dict[str, Any]:
    """Dispatch a structured extraction via a per-attempt provider ``source``.

    ``source`` is the provider-binding seam (``capabilities()`` +
    ``bind()``, the :class:`BrokeredProviderSource` surface from #340
    PR2b Task 4). Per extraction the host brokers ONE fresh gateway socket
    per retry attempt, and a bound provider cannot re-dial its single
    socket, so each attempt binds a FRESH provider off the source
    (``async with source.bind() as provider``). Capabilities are picked
    ONCE before the loop — they are a model-invariant property of the
    source, not the socket.

    ``source`` is typed ``Any`` (not the ``ProviderSource`` Protocol) on
    purpose: that Protocol lives in ``brokered_egress.py``, whose module
    scope imports httpx/ssl/socket. Annotating against it here — even only
    for the type — would drag the egress-capable import closure onto this
    module's graph. This module stays egress-free by DOCUMENTED INTENT; the
    real network client is built inside ``source.bind()``, never here (same
    rationale that typed the pre-seam ``provider`` as ``Any``). NB the
    enforcing any-scope oracle does not yet exist (tracked in #465): the
    module-scope ``test_quarantine_child_import_closure.py`` forbids the
    privileged host subsystems but names NO egress module in its
    ``_FORBIDDEN_ROOTS``, so nothing today would actually TRIP on such an
    import — the containment is the kernel ``--unshare-net`` + the fd-4
    SCM_RIGHTS broker, both independently gated.

    Selects the dispatch path from the source's capability set
    (fork b, #340):

    * ``NATIVE_CONSTRAINED_GENERATION`` → ``native_constrained`` mode
      (forced tool-use shape, schema-constrained by the provider).
    * neither → ``prompt_embedded_fallback`` mode (schema embedded in
      the user prompt, parsed + validated host-side).

    Up to ``EXTRACTION_MAX_RETRIES + 1`` attempts; on exhaustion returns
    ``{"kind": "typed_refusal", "reason": "cannot_extract", ...}``.

    Between attempts the loop sleeps ``_BACKOFF_BASE_SECONDS * (2 ** attempt)``
    seconds (perf-1 fix: the prior loop fired back-to-back), CLAMPED to the
    remaining budget (#472 finding 1) so the back-off can never itself overrun
    the cap. Total wall-clock per extraction is capped at
    :data:`_MAX_TOTAL_WALL_CLOCK_SECONDS`. Four mechanisms hold that cap,
    only the third of which can stop a blocking provider read: the loop-top
    check short-circuits an already-breached budget; each call is wrapped in
    ``asyncio.wait_for(remaining)``; the REMAINING budget is passed to
    ``source.bind()``, which anchors it as an absolute socket deadline clamping
    every syscall of that attempt (load-bearing); and the inter-attempt back-off
    is clamped to that same remaining budget. The ``wait_for`` cannot do the
    socket job alone because the SDK's blocking ``recv`` runs in a shielded
    worker thread it can only cancel-then-await. A ``TimeoutError`` from either
    is TERMINAL ``cannot_extract`` — not retry-eligible (a call that blew the
    budget will not recover inside a shrinking one; HARD #7 forbids a silent
    hang).

    :class:`ValidationError`, :class:`json.JSONDecodeError`, and
    :class:`ProviderMalformedToolArgumentsError` (an empty/malformed
    forced-tool response) are caught as retry-eligible.
    :class:`ProviderUnavailableError` is converted to a terminal
    ``TypedRefusal(reason="provider_unavailable")`` — distinct from
    ``cannot_extract`` so audit consumers can tell provider outages
    apart from model-output failures (err-002 fix). Every other
    exception propagates so the supervisor's audit log captures
    unexpected failures with their real shape (err-009).

    ``cost_usd`` (P1c, #340 PR2b Task 5) accrues across EVERY provider
    call that returns a ``(text, cost)`` pair — a call whose response the
    host then rejects in validation was still paid for, so a 3-attempt
    thrash is 3 paid calls. The summed cost rides BOTH the ``extracted``
    and every ``typed_refusal`` return. It is a structured, non-T3 field
    (never T3-derived) — the privileged-side turn-record consumer that
    joins it with the #338 privileged cost is out of scope here
    (child-boundary-out; ADR-0052 names the owner / Task 12).

    ``schema_version`` is accepted-and-ignored here because it travels
    on the audit row via the orchestrator-side caller
    (:class:`QuarantinedExtractor`); the dispatcher itself doesn't act
    on the version (the :data:`ExtractionSchema` ABC + Literal[1] check
    on the orchestrator side gates the version invariant before any
    subprocess call lands).
    """
    # Capabilities are model-invariant — read once off the source, not per
    # socket. ``source`` is duck-typed Any (egress-free rationale in the
    # docstring above), so ``.capabilities()`` / ``.bind()`` resolve at runtime.
    caps = source.capabilities()
    if ProviderCapability.NATIVE_CONSTRAINED_GENERATION in caps:
        extraction_mode = "native_constrained"
    else:
        # fork (b), #340: the JSON-object branch is removed — no shipped
        # provider is JSON-object-only, and every constrained-capable
        # provider declares a native tool-use path. A provider WITHOUT
        # native constrained generation (incl. deepseek-chat /
        # deepseek-reasoner) uses the prompt-embedded fallback (host-
        # validated). Routing a TOOL_USE-but-not-native provider through
        # a distinctly-labelled tool-use mode is deferred (needs a new
        # ExtractionMode member) — see the spec §4.2 fork (b) note.
        extraction_mode = "prompt_embedded_fallback"

    # ``errors="replace"`` keeps the loop alive on partially-corrupt
    # T3 bytes — the LLM downstream can still see something. The
    # replacement char (U+FFFD) is a stable signal it can flag as
    # ambiguous_input on the next prompt build.
    content_text = content.decode("utf-8", errors="replace")
    # Parsed ONCE, outside the loop and outside any try (FIX-A). schema_json
    # is host/orchestrator-supplied and identical across every retry
    # attempt — a syntactically-invalid schema is a host-side bug, not a
    # model failure, and must propagate loud rather than be silently
    # retried to cannot_extract inside the retry-eligible catch below.
    parsed_schema = _cached_parsed_schema(schema_json)
    deadline_monotonic = time.monotonic() + _MAX_TOTAL_WALL_CLOCK_SECONDS
    retry_category: ValidatorErrorCategory | None = None
    # cost_usd sums across every paid attempt and rides every return (P1c).
    cost_total = 0.0
    for attempt in range(EXTRACTION_MAX_RETRIES + 1):
        remaining_budget = deadline_monotonic - time.monotonic()
        if remaining_budget <= 0:
            # Per-extraction wall-clock budget breach (perf-1 fix). Short
            # circuit to cannot_extract so a thrashing provider does not
            # block the orchestrator's action_deadline_seconds.
            return {"kind": "typed_refusal", "reason": "cannot_extract", "cost_usd": cost_total}
        prompt = _build_extraction_prompt(content_text, schema_json, retry_category)
        try:
            # Bind a FRESH provider off the source for THIS attempt: the host
            # brokers one gateway socket per attempt and a bound provider
            # cannot re-dial its single socket (RedialError).
            #
            # The REMAINING budget is handed to bind() because that is what
            # actually enforces the ceiling. asyncio.wait_for cannot: the SDK's
            # blocking recv runs in anyio.to_thread.run_sync with
            # abandon_on_cancel=False, so wait_for cancels and then AWAITS the
            # shielded thread. bind() turns this budget into an absolute socket
            # deadline every syscall of the attempt is clamped against, so a
            # late attempt is truncated rather than handed a fresh 8s read (which
            # would let the child reply at ~28s, past the host's 25s read_frame,
            # losing the in-budget refusal entirely). wait_for stays as the
            # in-loop belt for the non-blocking portions of the call.
            async with source.bind(budget_seconds=remaining_budget) as provider:
                raw_response, call_cost = await asyncio.wait_for(
                    _call_provider(
                        prompt=prompt,
                        schema=parsed_schema,
                        provider=provider,
                        extraction_mode=extraction_mode,
                        max_tokens=max_tokens,
                    ),
                    # Re-measured AFTER bind(): the control-fd recv inside it is
                    # charged to the same budget, so a stale pre-bind snapshot
                    # would hand the call more time than the extraction has left.
                    timeout=deadline_monotonic - time.monotonic(),
                )
            # The call returned, so it was paid for — count it before
            # validation, which may still reject the response and retry.
            cost_total += call_cost
            validated = _validate_response(raw_response, schema_json)
            return {
                "kind": "extracted",
                "data": validated,
                "extraction_mode": extraction_mode,
                "cost_usd": cost_total,
            }
        except TimeoutError:
            # Per-call wall-clock ceiling breach (spec §4 P1e / §19-A3):
            # TERMINAL, NOT retry-eligible. A provider slow enough to blow the
            # remaining budget will not recover inside a shrinking one, and the
            # orchestrator's action_deadline is closing. HARD #7: a loud
            # closed-vocab refusal, never a silent hang.
            #
            # LOUD means logged, not merely typed. This arm and retry-exhaustion below
            # return the IDENTICAL ``cannot_extract`` refusal, so without this line an
            # operator cannot tell three rejected model responses (a content problem) from
            # one blown socket deadline (an infrastructure problem) — same reason, opposite
            # remediation. The reason string itself is deliberately unchanged: a new
            # TypedRefusalReason member is a schema change, deferred by design.
            _log.warning(
                "quarantine.child.extraction_deadline_exceeded",
                attempt=attempt,
                remaining_budget_s=round(deadline_monotonic - time.monotonic(), 3),
                max_attempts=EXTRACTION_MAX_RETRIES + 1,
            )
            return {"kind": "typed_refusal", "reason": "cannot_extract", "cost_usd": cost_total}
        except ProviderUnavailableError:
            # Terminal (NOT retry-eligible): a provider outage, not a
            # model-output failure, so audit consumers can tell them
            # apart (err-002).
            #
            # LOUD, not merely typed (#472 finding 4 / HARD #7): this arm returns the same
            # provider_unavailable refusal whether the SDK reported an outage, the host never
            # brokered a socket, or the attempt budget was exhausted before the provider was
            # built — three infrastructure faults with the same reason but different
            # remediation. Without this line an operator cannot tell them from one another,
            # nor from a model-content failure. Mirrors the extraction_deadline_exceeded arm.
            _log.warning(
                "quarantine.child.provider_unavailable",
                attempt=attempt,
                remaining_budget_s=round(deadline_monotonic - time.monotonic(), 3),
                max_attempts=EXTRACTION_MAX_RETRIES + 1,
            )
            return {
                "kind": "typed_refusal",
                "reason": "provider_unavailable",
                "cost_usd": cost_total,
            }
        except (ValidationError, json.JSONDecodeError, ProviderMalformedToolArgumentsError) as exc:
            # ONE try wraps BOTH the provider call and validation so an
            # empty/malformed forced-tool response
            # (ProviderMalformedToolArgumentsError, raised by
            # _call_provider) is retry-eligible and can never escape
            # dispatch_extraction uncaught — HARD #7
            # (rev-001/sec-001/test-001, #340 FIX-1). Free-form
            # ``str(exc)`` is the prov-002 / err-009 / sec-001 injection
            # vector — Pydantic ``loc`` tuples can include attacker-
            # controlled JSON keys when the quarantined LLM returns a
            # poisoned dict. Map to a closed-vocab category and route
            # through the shared :func:`_build_retry_prompt` helper
            # instead.
            retry_category = _categorise_validator_error(exc)
        # Exponential back-off (perf-1 fix). Skip the sleep on the
        # last attempt — there is no next try, the loop is about to
        # exit and the refusal is the next emit.
        if attempt < EXTRACTION_MAX_RETRIES:
            # CLAMPED to the remaining budget (#472 finding 1). Uncapped, the sleep is
            # computed from ``attempt`` alone and can carry the loop PAST
            # ``deadline_monotonic`` — the loop head then refuses, but only after the
            # overrun has already happened. A ceiling a back-off can overrun is not a
            # ceiling. ``max(0.0, ...)`` normalises an already-breached budget to an
            # explicit zero-sleep yield rather than leaning on ``asyncio.sleep``'s
            # negative-delay short-circuit; the loop head converts it to
            # ``cannot_extract`` on the next pass.
            await asyncio.sleep(
                max(
                    0.0,
                    min(
                        _BACKOFF_BASE_SECONDS * (2**attempt), deadline_monotonic - time.monotonic()
                    ),
                )
            )
    # Exhaustion is a closed-domain TypedRefusal, NOT an Extracted with
    # a malformed_output mode (spec §6.7 / prov-011).
    return {"kind": "typed_refusal", "reason": "cannot_extract", "cost_usd": cost_total}


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
    schema: dict[str, Any],
    provider: Any,
    extraction_mode: str,
    max_tokens: int | None = None,
) -> tuple[str, float]:
    """Dispatch the provider call for ``extraction_mode`` via the #339 seam.

    Two shapes (fork b, #340):

    * ``native_constrained``: force the single ``extract_structured_data``
      tool whose ``input_schema`` is the extraction schema; read the
      first ``tool_call``'s ``arguments`` and re-serialise to JSON. An
      empty ``tool_calls`` (a ``max_tokens``-truncated forced tool —
      ``CompletionResponse.tool_calls`` is non-empty only when
      ``stop_reason == "tool_use"``) raises
      :class:`ProviderMalformedToolArgumentsError` so the retry loop
      treats it like a schema failure and exhausts to
      ``cannot_extract`` — never an uncaught ``IndexError`` that skips
      the audit (HARD #7).
    * ``prompt_embedded_fallback``: bare completion; the schema is
      embedded in the prompt and the response text is validated
      host-side.

    Returns ``(json_text, cost_usd)`` in both branches: the JSON string so
    :func:`_validate_response` has a uniform shape to work with, and the
    response's ``cost_usd`` so the caller can sum spend across attempts
    (P1c, #340). ``cost_usd`` is a structured, non-T3 field (never
    T3-derived). NB the empty-``tool_calls`` guard below raises BEFORE it
    can read a cost — a truncated forced-tool response is not summed (see
    the caller's cost note); every path that RETURNS surfaces the cost.

    ``schema`` is the ALREADY-PARSED dict (FIX-A) — the caller parses it
    once via :func:`_cached_parsed_schema` outside the per-attempt retry
    loop, so a syntactically-invalid ``schema_json`` propagates loud
    instead of being silently retried here. This function no longer
    parses schema JSON itself.
    """
    # Resolve max_tokens to CompletionRequest's OWN default when unset (P1b, #340) — its
    # >0 validator rejects None, and reading the field default avoids drift with base.py.
    # PR2b-golive threads the routing.yaml max_tokens_per_extraction here via the spawn env.
    resolved_max_tokens: int = _COMPLETION_DEFAULT_MAX_TOKENS if max_tokens is None else max_tokens
    if extraction_mode == "native_constrained":
        request = CompletionRequest(
            messages=[Message(role="user", content=prompt)],
            tools=(
                ToolDefinition(
                    name=_EXTRACT_TOOL_NAME,
                    description="Extract structured data from content per schema.",
                    input_schema=schema,
                ),
            ),
            tool_choice=ForcedTool(name=_EXTRACT_TOOL_NAME),
            max_tokens=resolved_max_tokens,
        )
        response = await provider.complete(request)
        if not response.tool_calls:
            raise ProviderMalformedToolArgumentsError(
                "quarantine extractor: forced tool returned no tool_call"
            )
        return json.dumps(dict(response.tool_calls[0].arguments)), response.cost_usd
    # prompt_embedded_fallback: bare completion, no tools advertised.
    # The schema is embedded in the prompt and the validator catches
    # malformed output on the host.
    request = CompletionRequest(
        messages=[Message(role="user", content=prompt)], max_tokens=resolved_max_tokens
    )
    response = await provider.complete(request)
    return str(response.content), response.cost_usd


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

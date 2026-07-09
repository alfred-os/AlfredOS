# ADR-0045: Provider tool-protocol seam

- **Status:** Accepted
- **Date:** 2026-07-05
- **Deciders:** #339 (LLM tool-calling epic), PR1; 7-agent plan-review + provider/test 2-lens plan-review
- **Related:** [ADR-0008](0008-llm-output-trust-tier.md) (LLM output trust tier), the #339 design spec (`docs/superpowers/specs/2026-07-05-issue-339-llm-tool-calling-design.md` §4/§14), #338, #340

## Context

The frozen provider contract (`src/alfred/providers/base.py`) could not represent
a tool call. `CompletionRequest` / `CompletionResponse` are `frozen,
extra="forbid"` with no `tools` / `tool_choice` / `tool_use` / `tool_calls` /
`stop_reason` fields; `Message` had roles `{system, user, assistant}` only.
Neither adapter carried tool data — Anthropic discarded non-text response blocks
and DeepSeek never sent or read `tool_calls`; `ProviderCapability.TOOL_USE` was
declared but dead.

The #339 agentic act-phase loop (PR3) needs one provider-neutral tool
abstraction that both wire shapes normalize behind: Anthropic's content-block
`tool_use` / `tool_result` + `stop_reason` **vs** OpenAI/DeepSeek's `tool_calls[]` +
`finish_reason` + `role:"tool"` result messages. This is a breaking change to a
structural invariant (the frozen provider contract), hence an ADR.

## Decision

1. **Additive, default-valued tool fields on the frozen models.** `Message` gains
   `role="tool"`, `tool_calls: tuple[ToolCall, ...] = ()`, `tool_call_id: str |
   None = None`; `CompletionRequest` gains `tools`, `tool_choice`;
   `CompletionResponse` gains `stop_reason`, `tool_calls`. All defaults, so every
   existing single-completion caller is byte-identical to the pre-#339 shape.
   `extra="forbid"` is preserved.
2. **A flat internal representation**, not Anthropic content-blocks. DeepSeek is
   the *primary* provider (build_router) and is flat-shaped; the flat form maps
   cleanly onto the existing flat `(role, content)` storage; the Anthropic
   content-block mapping is mechanical and localized to that adapter.
3. **Official SDK types, not hand-rolled dicts.** Adapters construct requests via
   the vendor SDKs' typed param TypedDicts (openai `ChatCompletion…Param`,
   anthropic `…BlockParam` / `ToolParam` / `ToolChoice…Param`) and parse responses
   via the official response types (`ChatCompletionMessageToolCallUnion`,
   anthropic `ContentBlock`). Because those params are TypedDicts (runtime dicts),
   this keeps mock-based tests valid while giving `mypy --strict` real shape
   checking. **Per-role wire serialization** replaces the blanket `model_dump()`,
   which would otherwise emit empty tool fields onto every plain message and 400
   the provider.
4. **`TOOL_USE` wired with a refuse-loud guard.** deepseek-chat and Anthropic
   declare `TOOL_USE`; a `complete()` carrying `tools` whose provider lacks
   `TOOL_USE` (e.g. deepseek-reasoner) raises `ProviderToolUnsupportedError`
   *before* building the request, and the router **re-raises** it rather than
   falling back — a capability refusal is a loud operator-misconfiguration signal,
   not a transient failure. The router otherwise stays primary→fallback with **no
   capability routing**.
5. **Malformed tool arguments fail loud.** DeepSeek returns arguments as a JSON
   string; an un-parseable value raises `ProviderMalformedToolArgumentsError` at
   the boundary (the PR3 loop turns this into an error `tool_result`).

## Consequences

- Existing callers are unchanged; the smoke/fixture provider tests pass with the
  additive defaults.
- The router advertises tools only when non-empty and refuses loud for a
  non-tool-capable primary; operators running a reasoner-primary config get a
  clear typed error instead of a silent 400.
- `security/quarantine_child/provider_dispatch.py` (unwired, echo today) assumes
  an aspirational `provider.complete(..., tools=, response_format=)` +
  `response.tool_use_input` shape that no adapter implemented. **#340** ports it
  onto this seam (constrained generation = `tools=(one,)` +
  `tool_choice=ForcedTool` reading `response.tool_calls[0].arguments`).
- `response_format` / JSON-object constrained-generation is **out of scope**
  here; it remains #340's concern.
- No orchestrator/loop, tool-registry, or web.fetch wiring lands in PR1 — those
  are PR2/PR3 of the epic.
- The live comms cutover (**#338**) is a separate epic, gated on #340's real
  quarantine child before go-live (design spec §2); this seam neither blocks nor
  unblocks it.
- **Provider function-name grammar is narrower than AlfredOS's canonical tool
  names, and is sanitized ONLY at the wire.** OpenAI/DeepSeek require
  `^[a-zA-Z0-9_-]+$`; Anthropic additionally caps length at
  `^[a-zA-Z0-9_-]{1,64}$`. AlfredOS's canonical tool names are dotted (e.g.
  `web.fetch`) and unbounded in length. `providers/_tool_names.py` sanitizes
  to that intersection grammar (dots and other unsafe characters -> `_`,
  hash-disambiguated truncation past 64 chars) immediately before the SDK
  call, and reverse-maps the provider's echoed name back to the canonical
  form on receive — `dispatch_tool`, the audit log, and i18n keys never see
  the sanitized wire form. This was caught by the #339 real-LLM smoke's
  first live run (PR #406), not by the fixture-based unit suite, since every
  fixture up to that point round-tripped `tool.name` through the mock
  boundary unchanged.

## Alternatives considered

- **Content-block internal representation (Anthropic-shaped).** Rejected: heavier
  storage/rehydrate footprint and further from the primary provider; the flat
  shape carries the same information with a smaller blast radius.
- **Hand-rolled wire dicts + `getattr` response duck-typing.** Rejected per the
  maintainer directive to use official SDK types: hand-rolled shapes drift from
  the SDK and evade `mypy` shape-checking (wrong shapes 400 the provider).
- **Router falls back to a tool-capable provider when the primary lacks
  `TOOL_USE`.** Rejected: that is capability routing (explicitly deferred) and
  would silently change the cost/behaviour profile of every tool turn; refuse
  loud instead.

## Amendments

### 2026-07-09 — additive `ProviderUnavailableError` (#340 PR1)

**#340 PR1** adds one additive error type to the seam,
`alfred.providers.base.ProviderUnavailableError(AlfredError)`. Each adapter maps
its SDK/transport failures (`anthropic`/`openai` API errors, `httpx`) to it at the
adapter boundary so downstream callers — the router and the quarantine child's
`provider_dispatch` — get one typed error instead of the provider-specific
hierarchies. It is deliberately excluded from `router._TOOL_PROTOCOL_ERRORS`
(a transport failure should fall back to the secondary provider). No change to the
frozen `CompletionRequest`/`CompletionResponse` models. This keeps the quarantine
child free of any SDK import (the in-core HTTP-egress import guard).

"""Provider plugin contract for Slice 1.

A provider is anything that can take a sequence of messages and produce a
completion plus token usage and cost. Slice 1 has DeepSeek and Anthropic;
Slice 2 adds tiered routing across more providers.

Slice 3 adds the capability surface (PR-S3-4) that drives the
quarantined-LLM dispatch path. See ``ProviderCapability`` below and the
``capabilities()`` Protocol method.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from alfred.errors import AlfredError

# "tool" carries a tool-call RESULT back to the model (spec §4.2). Added for the
# #339 tool-calling seam; no existing code path produces it, so widening the
# Literal is additive.
Role = Literal["system", "user", "assistant", "tool"]

# Normalized stop reason across providers: Anthropic ``stop_reason`` and
# OpenAI/DeepSeek ``finish_reason`` both map onto this closed set. ``tool_use``
# is the value the act-phase loop (PR3) branches on.
StopReason = Literal["end_turn", "tool_use", "max_tokens", "stop_sequence", "other"]


class ProviderCapability(StrEnum):
    """Closed-set capabilities a provider may declare (spec §6.1).

    The quarantined-LLM dispatch path (spec §6.2) branches on these:

    * ``NATIVE_CONSTRAINED_GENERATION`` → Anthropic tool-use shape;
      schema-constrained at the provider level. The only path that
      guarantees the response is JSON-schema-valid by construction.
    * ``JSON_OBJECT_MODE`` → DeepSeek's ``response_format={"type":
      "json_object"}``; produces JSON but is NOT schema-constrained.
      The host validates with Pydantic after the call (spec §6.2
      reclassification).
    * neither → ``prompt_embedded_fallback``; schema embedded in the
      user prompt, response parsed as JSON, validated with Pydantic.

    ``TOOL_USE``, ``VISION``, ``LONG_CONTEXT_1M`` are pre-declared per
    PRD §6.6 line 290 so the routing layer can resolve provider
    fallbacks by capability without subclass-level extension.

    The enum subclasses ``str`` so the value can flow through audit-row
    fields and JSON serialisation without explicit ``.value`` calls.
    """

    NATIVE_CONSTRAINED_GENERATION = "native_constrained_generation"
    JSON_OBJECT_MODE = "json_object_mode"
    TOOL_USE = "tool_use"
    VISION = "vision"
    LONG_CONTEXT_1M = "long_context_1m"


def register_provider[ProviderT](cls: type[ProviderT]) -> type[ProviderT]:
    """Decorator that asserts ``capabilities()`` is callable on ``cls``.

    Uses PEP 695 generic syntax (Python 3.12+) — the type parameter is
    scoped to the decorator and round-trips ``cls`` so static-analysis
    sees the same symbol the source file declared.

    Why this exists rather than ``__init_subclass__`` on the
    ``Provider`` Protocol: real concrete providers
    (``AnthropicProvider``, ``DeepSeekProvider``) are duck-typed and do
    NOT inherit from ``Provider``. ``typing.Protocol.__init_subclass__``
    fires only for explicit subclasses, so it cannot enforce the
    capabilities() invariant on the actual providers shipped today
    (prov-001 / arch-002).

    The decorator is the only place the assertion can land at
    import-time for duck-typed providers. A provider class missing
    ``capabilities()`` raises ``TypeError`` when its module is
    imported — the failure is impossible to ship past a ``make check``
    pass.

    Returns ``cls`` unchanged so static-analysis sees the same symbol
    the source file declared.
    """
    if not callable(getattr(cls, "capabilities", None)):
        raise TypeError(
            f"{cls.__name__} must implement capabilities() -> frozenset[ProviderCapability] "
            "(register_provider check; prov-001/arch-002)"
        )
    return cls


class ToolDefinition(BaseModel):
    """Provider-neutral tool advertisement (spec §4.2). ``input_schema`` is a
    JSON Schema; each adapter maps this to its SDK's tool-param shape."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    description: str
    # JSON object typed ``object`` (not ``Any``) so callers must narrow before use.
    input_schema: Mapping[str, object]


class ToolCall(BaseModel):
    """A parsed tool-use request from the model, OR its echo in message history."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    name: str
    arguments: Mapping[str, object]


class ForcedTool(BaseModel):
    """``tool_choice`` variant forcing exactly one named tool (used by #340
    constrained-generation)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str


# "auto" (model decides) | "none" (no tool call) | "required" (must call some
# tool) | ForcedTool (must call THIS tool).
ToolChoice = Literal["auto", "none", "required"] | ForcedTool


class ProviderToolUnsupportedError(AlfredError):
    """A request carries ``tools`` but the resolved provider does not declare
    ``ProviderCapability.TOOL_USE``. Refuse loud rather than emit a request the
    provider SDK will 400 on (spec §4.1)."""


class ProviderMalformedToolArgumentsError(AlfredError):
    """A provider returned tool-call arguments that are not valid JSON (DeepSeek
    returns arguments as a JSON *string*). Fail loud at the boundary; the
    act-phase loop (#339 PR3) turns this into an error ``tool_result``
    (spec §4.3)."""


class ProviderToolNameCollisionError(AlfredError):
    """Two distinct canonical tool names sanitize to the same provider-safe
    wire name (e.g. a future ``web.fetch`` alongside a ``web_fetch`` would
    both sanitize to ``web_fetch``). Raised by
    ``alfred.providers._tool_names.build_tool_name_map``.

    Silently keeping only one mapping would let a provider's tool_call for
    the DROPPED wire name resolve to the WRONG canonical tool at dispatch
    time — HARD rule #7 (no silent failures in security-adjacent paths)
    requires a loud refusal here, not a silent clobber. No tool shipped
    today triggers this (``web.fetch`` / ``clock.now`` sanitize to distinct
    names); the guard exists so a future tool name can't introduce the
    ambiguity unnoticed."""


class ProviderUnavailableError(AlfredError):
    """A TRANSIENT/retryable provider failure: connection error, timeout,
    rate-limit, or a 5xx status. Deterministic 4xx failures (auth, bad-request,
    permission, not-found, etc.) are NOT mapped to this error — they propagate
    as the raw SDK error, since masking a config/host-side bug as a retryable
    outage would hide it from the operator instead of surfacing it loud.

    Raised by each adapter's ``complete()`` at the SDK-call boundary so callers
    (the router; the quarantine child's ``provider_dispatch``) get ONE typed
    error instead of the provider-specific ``anthropic``/``openai`` hierarchies.
    The quarantine child maps this to ``TypedRefusal(reason="provider_unavailable")``
    so audit consumers can tell provider outages apart from model-output failures.

    Deliberately NOT in ``router._TOOL_PROTOCOL_ERRORS`` — a transient transport
    failure SHOULD fall back to the secondary provider (contrast a deterministic
    tool-protocol error, which would fail identically on the fallback)."""


def ensure_tool_capability(
    *,
    has_tools: bool,
    capabilities: frozenset[ProviderCapability],
    provider_name: str,
    model: str,
) -> None:
    """Refuse loud when a request carries tools but the provider lacks TOOL_USE.

    Shared by every adapter's ``complete()`` so this security-relevant
    refuse-loud check (and its ``t()`` key) cannot drift between adapters
    (spec §4.1). Raises before the request is built, so no un-answerable
    request reaches the provider SDK.
    """
    if has_tools and ProviderCapability.TOOL_USE not in capabilities:
        from alfred.i18n import t

        raise ProviderToolUnsupportedError(
            t("providers.tool_use_unsupported", provider=provider_name, model=model)
        )


class Message(BaseModel):
    # Frozen so a request can be safely shared / replayed without a caller
    # mutating it mid-flight. extra="forbid" catches typos at the boundary.
    model_config = ConfigDict(frozen=True, extra="forbid")

    role: Role
    content: str = ""
    # tool_calls populate ONLY on an assistant turn that requested tools;
    # tool_call_id ONLY on a role="tool" result message (links the result to
    # the ToolCall.id that produced it). Default-empty so every existing
    # construction is unchanged.
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str | None = None

    @model_validator(mode="after")
    def _check_role_tool_fields(self) -> Message:
        # Enforce the seam's linkage invariants at construction so a malformed
        # Message fails loud here, not as an opaque provider 400 downstream
        # (spec §4.2 result linkage). tool_call_id links a result to its call.
        if self.role == "tool" and self.tool_call_id is None:
            raise ValueError('a role="tool" message requires tool_call_id')
        if self.role != "tool" and self.tool_call_id is not None:
            raise ValueError('tool_call_id is only valid on a role="tool" message')
        if self.tool_calls and self.role != "assistant":
            raise ValueError("tool_calls are only valid on an assistant message")
        return self


class CompletionRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    messages: list[Message]
    max_tokens: int = 1024
    temperature: float = 0.7
    # Default-empty: a request without tools is byte-identical to the pre-#339
    # shape, so no existing caller changes. The router advertises these to the
    # provider only when non-empty (spec §4).
    tools: tuple[ToolDefinition, ...] = ()
    tool_choice: ToolChoice = "auto"

    @field_validator("max_tokens")
    @classmethod
    def _max_tokens_positive(cls, v: int) -> int:
        # A non-positive max_tokens would silently produce an empty completion
        # or a provider error — fail loud at the boundary instead.
        if v <= 0:
            raise ValueError(f"max_tokens must be > 0, got {v}")
        return v


class CompletionResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    content: str
    tokens_in: int
    tokens_out: int
    cost_usd: float
    # The model the provider actually used (e.g. "deepseek-chat" or
    # "claude-sonnet-4-6"). Required so the orchestrator's audit entry and
    # the smoke test can attribute cost/behavior to the exact model — critical
    # for the multi-provider fallback case where the response came from the
    # fallback rather than the primary.
    model: str
    # Default end_turn/empty: a plain text completion is byte-identical to the
    # pre-#339 shape. stop_reason == "tool_use" + non-empty tool_calls is how
    # the PR3 act-phase loop detects the model wants to call a tool (spec §4.2).
    stop_reason: StopReason = "end_turn"
    tool_calls: tuple[ToolCall, ...] = ()

    @model_validator(mode="after")
    def _tool_use_consistency(self) -> CompletionResponse:
        # stop_reason="tool_use" with no tool_calls is the inconsistent state the
        # act-phase loop (#339 PR3) branches on — reject it so a buggy adapter
        # parse cannot produce it silently (spec §4.2). Adapters downgrade
        # stop_reason to "other" when every tool_call was dropped.
        if self.stop_reason == "tool_use" and not self.tool_calls:
            raise ValueError('stop_reason="tool_use" requires non-empty tool_calls')
        return self

    @field_validator("tokens_in", "tokens_out", "cost_usd")
    @classmethod
    def _non_negative(cls, v: float) -> float:
        # Negative usage or cost would corrupt the budget guard's running
        # totals (a negative charge could "refund" past spend and bypass the
        # daily cap). Reject at construction time.
        if v < 0:
            raise ValueError(f"must be >= 0, got {v}")
        return v


# slice 2 adds stream/embed/tools/capabilities (see PRD §6.6)
# slice 3 (PR-S3-4) adds capabilities() — the dispatch key for the
# quarantined-LLM provider router.
class Provider(Protocol):
    """The minimal slice-1 provider interface plus the slice-3
    ``capabilities()`` Protocol method.
    """

    name: str

    async def complete(self, request: CompletionRequest) -> CompletionResponse: ...

    def capabilities(self) -> frozenset[ProviderCapability]:
        """Return the closed-set of capabilities this provider declares.

        Implemented as a per-provider constant (or model-aware classmethod
        for providers whose feature set varies by model), NOT SDK-
        introspected. SDK shape drift would silently degrade capability
        detection at exactly the moment a security-load-bearing dispatch
        depends on it (spec §6.1).
        """
        ...

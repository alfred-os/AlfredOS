"""Provider plugin contract for Slice 1.

A provider is anything that can take a sequence of messages and produce a
completion plus token usage and cost. Slice 1 has DeepSeek and Anthropic;
Slice 2 adds tiered routing across more providers.

Slice 3 adds the capability surface (PR-S3-4) that drives the
quarantined-LLM dispatch path. See ``ProviderCapability`` below and the
``capabilities()`` Protocol method.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal, Protocol, TypeVar

from pydantic import BaseModel, ConfigDict, field_validator

Role = Literal["system", "user", "assistant"]

# Generic TypeVar used by the ``register_provider`` decorator. The decorator
# is identity at the value level (it returns ``cls`` unchanged) so the type
# round-trips without information loss — mypy/pyright see the same class
# the source file declared.
_ProviderT = TypeVar("_ProviderT")


class ProviderCapability(str, Enum):
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


def register_provider(cls: type[_ProviderT]) -> type[_ProviderT]:
    """Decorator that asserts ``capabilities()`` is callable on ``cls``.

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


class Message(BaseModel):
    # Frozen so a request can be safely shared / replayed without a caller
    # mutating it mid-flight. extra="forbid" catches typos at the boundary.
    model_config = ConfigDict(frozen=True, extra="forbid")

    role: Role
    content: str


class CompletionRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    messages: list[Message]
    max_tokens: int = 1024
    temperature: float = 0.7

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

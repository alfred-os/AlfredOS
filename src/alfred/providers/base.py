"""Provider plugin contract for Slice 1.

A provider is anything that can take a sequence of messages and produce a
completion plus token usage and cost. Slice 1 has DeepSeek and Anthropic;
Slice 2 adds tiered routing across more providers.
"""

from __future__ import annotations

from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict

Role = Literal["system", "user", "assistant"]


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


class Provider(Protocol):
    """The minimal slice-1 provider interface."""

    name: str

    async def complete(self, request: CompletionRequest) -> CompletionResponse: ...

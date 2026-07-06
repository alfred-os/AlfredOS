"""Provider-neutral tool registry + spec model (#339 PR2, spec §8).

``result_tier`` DEFAULTS to T3 (fail-closed, sec-001): every external tool goes
through the quarantine-extract path. Only tools on
``FIRST_PARTY_LE_T2_TOOL_ALLOWLIST`` may declare ≤T2 (the ``InternalToolSpec``
direct path); the ``ToolRegistry`` constructor ENFORCES that claim.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal

from alfred.errors import AlfredError

if TYPE_CHECKING:
    from alfred.egress.egress_id import TurnEgressContext
    from alfred.egress.egress_response_extract import EgressExtractOutcome
    from alfred.providers.base import ToolDefinition
    from alfred.security.quarantine import ExtractionSchema

# The ONLY tools permitted to declare a ≤T2 result tier (bypass quarantine).
# Hardcoded first-party allowlist — a plugin manifest can NEVER add to it
# (sec-001 / CLAUDE.md rule #4). Every name here is test-verified ≤T2.
FIRST_PARTY_LE_T2_TOOL_ALLOWLIST: Final[frozenset[str]] = frozenset({"clock.now"})


class ToolTierClaimError(AlfredError):
    """A ``ToolSpec`` declared ≤T2 but its name is not on the first-party
    allowlist. Fail loud at construction (no trust-the-manifest)."""


@dataclass(frozen=True, slots=True)
class ToolInvocation:
    """The per-call runtime context handed to a tool's dispatch callable."""

    arguments: Mapping[str, object]
    ctx: TurnEgressContext
    call_index: int
    user_id: str
    correlation_id: str
    language: str | None


@dataclass(frozen=True, slots=True)
class ExternalToolSpec:
    """A T3 tool: dispatch returns a T2 ``EgressExtractOutcome`` (the fused
    fetch+extract already crossed the T3→T2 boundary via the sanctioned seam)."""

    name: str
    definition: ToolDefinition
    extraction_schema: type[ExtractionSchema]
    dispatch: Callable[[ToolInvocation], Awaitable[EgressExtractOutcome]]
    result_tier: Literal["T3"] = "T3"


@dataclass(frozen=True, slots=True)
class InternalToolSpec:
    """A first-party ≤T2 tool: dispatch returns a ready ≤T2 string directly (no
    quarantine, no relay). Its name MUST be on ``FIRST_PARTY_LE_T2_TOOL_ALLOWLIST``."""

    name: str
    definition: ToolDefinition
    dispatch: Callable[[ToolInvocation], Awaitable[str]]
    result_tier: Literal["T2"] = "T2"


ToolSpec = ExternalToolSpec | InternalToolSpec


class ToolRegistry:
    """Maps ``name → ToolSpec`` and advertises ``ToolDefinition``s to the planner."""

    def __init__(self, specs: Iterable[ToolSpec]) -> None:
        by_name: dict[str, ToolSpec] = {}
        for spec in specs:
            if spec.name in by_name:
                raise ValueError(f"duplicate tool name: {spec.name!r}")
            if spec.result_tier != "T3" and spec.name not in FIRST_PARTY_LE_T2_TOOL_ALLOWLIST:
                raise ToolTierClaimError(
                    f"tool {spec.name!r} declares result_tier={spec.result_tier!r} but is not on "
                    "FIRST_PARTY_LE_T2_TOOL_ALLOWLIST (sec-001: no trust-the-manifest)"
                )
            by_name[spec.name] = spec
        self._by_name = by_name

    def get(self, name: str) -> ToolSpec | None:
        return self._by_name.get(name)

    def definitions(self) -> tuple[ToolDefinition, ...]:
        return tuple(spec.definition for spec in self._by_name.values())


def arguments_conform(arguments: Mapping[str, object], input_schema: Mapping[str, object]) -> bool:
    """Minimal structural check: every ``required`` property is present, and — when
    ``additionalProperties`` is ``False`` — no key falls outside ``properties``.

    NOT full JSON-Schema validation (deferred): enough to reject a call missing a
    required argument (spec §6). ``ToolCall.arguments`` is already parsed to a dict
    at the provider boundary (PR1).
    """
    required = input_schema.get("required", ())
    if isinstance(required, (list, tuple)):
        for key in required:
            if key not in arguments:
                return False
    if input_schema.get("additionalProperties") is False:
        allowed = input_schema.get("properties", {})
        if isinstance(allowed, Mapping):
            for key in arguments:
                if key not in allowed:
                    return False
    return True

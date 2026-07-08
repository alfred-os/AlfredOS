"""Shared test-only ``ProviderRouter`` doubles for the #338 PR2 boot-graph cutover.

``_build_comms_boot_graph``'s ``router_override`` seam (#338 PR2) lets a test
skip the REAL ``build_router`` — which needs a live egress proxy + a real
provider secret (the gateway is the sole external egress plane; CLAUDE.md hard
rule) — while still assembling a genuine ``Orchestrator`` /
``RealTurnOrchestratorAdapter`` over it. Every boot-graph caller that needs an
offline router double imports :class:`FixedAnswerRouter` from HERE rather than
reimplementing the same few lines per test file (CLAUDE.md DRY convention —
this is the second-plus duplication site, so the shared helper is justified).

Mirrors ``tests/integration/orchestrator/test_act_loop_real_chain.py``'s
``_ScriptedRouter`` in shape, but is intentionally simpler: those tests script a
tool-calling sequence; the #338 PR2 boot-graph callers are conversational-only
(empty tool registry, spec scope) and only need ONE canned completion.
"""

from __future__ import annotations

from alfred.providers.base import CompletionRequest, CompletionResponse


class FixedAnswerRouter:
    """A ``ProviderRouter``-shaped test double that always returns one fixed answer.

    NOT a subclass of :class:`alfred.providers.router.ProviderRouter` (a concrete
    class, not a Protocol) — callers ``cast`` the instance at the injection site,
    the same pattern ``_ScriptedRouter`` uses. Records every request it received
    so a test can assert whether (and how often) a turn actually reached the
    planner, distinguishing "the turn ran" from "the turn was skipped" (the
    PR4c/FIX-11 false-green lesson: a scripted double that is never exercised
    would make an assertion about its output vacuously true).
    """

    def __init__(self, answer: str = "scripted-answer") -> None:
        self.answer = answer
        self.requests: list[CompletionRequest] = []

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.requests.append(request)
        return CompletionResponse(
            content=self.answer,
            tokens_in=1,
            tokens_out=1,
            cost_usd=0.0,
            model="fixed-answer-test-double",
            stop_reason="end_turn",
            tool_calls=(),
        )


__all__ = ["FixedAnswerRouter"]

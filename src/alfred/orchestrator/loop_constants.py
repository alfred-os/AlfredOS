"""Bounds for the #339 PR3 agentic act-phase loop (spec §7/§9).

Kept in a tiny standalone module so tests can import + monkeypatch them
without importing the whole orchestrator, and so the numeric policy lives
in one greppable place. The per-action DEADLINE (``DeadlineWrapper`` in
``handle_user_message``) is the real wall-clock bound (core-004); these are
cost / fan-out backstops that bound spend and provider round-trips.
"""

from __future__ import annotations

from typing import Final

# Max privileged-planner completions per turn. A backstop under the outer
# action-deadline: bounds total spend + provider round-trips if a model
# loops on tool calls without converging.
MAX_TOOL_ITERATIONS: Final[int] = 8

# Max tool calls honoured from a SINGLE completion. Bounds intra-iteration
# egress fan-out (one completion could otherwise request N tools that all
# fire before the next per-iteration budget check — mem-003/core-006).
MAX_TOOL_CALLS_PER_ITERATION: Final[int] = 8

# Max chars of a tool_result fed back to the planner. Caps context growth +
# a pathological tool from ballooning the next request (spec §6).
TOOL_RESULT_MAX_CHARS: Final[int] = 8192

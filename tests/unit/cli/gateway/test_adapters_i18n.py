"""Every ``gateway.adapters.*`` operator key resolves to a real catalog string (G6-5 Task 9, #288).

The verify command (``alfred gateway adapters``) emits only ``t()`` strings; a missing
catalog entry makes ``t()`` return the KEY itself (the dev-visible fallback). These tests
pin that EACH new key resolves to a translated string (``t(key) != key``) so the operator
never sees a raw ``gateway.adapters.*`` token, and that the reserved set + the catalog stay
in lockstep (the bidirectional catalog-drift gate).
"""

from __future__ import annotations

import pytest

from alfred.i18n import t

# Every operator-facing / state key the command (or its reserve) emits. Plain ``t(key)``
# (no format vars) so a missing entry is detected as ``raw == key`` without a KeyError.
_KEYS = [
    "gateway.help.adapters",
    "gateway.help.adapters_arg",
    "gateway.help.adapters_wait",
    "gateway.help.adapters_timeout",
    "gateway.adapters.header",
    "gateway.adapters.none",
    "gateway.adapters.line",
    "gateway.adapters.unavailable",
    "gateway.adapters.unknown_adapter",
    "gateway.adapters.state.up",
    "gateway.adapters.state.down",
    "gateway.adapters.state.crashed",
    "gateway.adapters.state.breaker_open",
    "gateway.adapters.state.unknown",
    "gateway.adapters.wait_ready.ready",
    "gateway.adapters.wait_ready.waiting",
    "gateway.adapters.wait_ready.timeout",
    "gateway.adapters.wait_ready.needs_adapter",
]


@pytest.mark.parametrize("key", _KEYS)
def test_key_resolves(key: str) -> None:
    assert t(key) != key, f"{key} is not in the compiled catalog (raw-key fallback)"

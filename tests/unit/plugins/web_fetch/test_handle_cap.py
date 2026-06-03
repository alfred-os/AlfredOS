"""HandleCap module tests — Lua semantics, atomicity, TTL behaviour,
error paths, ARGV validation. Lua scripts run against real Redis via
testcontainers (mocking would test our mental model, not the interpreter).
"""

from __future__ import annotations

import pytest

from alfred.plugins.web_fetch.handle_cap import HandleCapConfig


def test_default_config_matches_spec() -> None:
    """HandleCapConfig() defaults to per_user=5 (spec §7)."""
    cfg = HandleCapConfig()
    assert cfg.per_user == 5


def test_cap_bool_rejected_at_load() -> None:
    """bool is a subclass of int in Python — must be rejected at config-load time."""
    with pytest.raises(ValueError, match="per_user must be an int"):
        HandleCapConfig(per_user=True)  # type: ignore[arg-type]


def test_cap_float_rejected_at_load() -> None:
    """float is not int — must be rejected at config-load time."""
    with pytest.raises(ValueError, match="per_user must be an int"):
        HandleCapConfig(per_user=1.5)  # type: ignore[arg-type]


def test_cap_zero_raises_at_load() -> None:
    """A cap of 0 would refuse every fetch — loud at config-load, not silent."""
    with pytest.raises(ValueError, match="per_user must be >= 1"):
        HandleCapConfig(per_user=0)


def test_cap_negative_raises_at_load() -> None:
    with pytest.raises(ValueError, match="per_user must be >= 1"):
        HandleCapConfig(per_user=-1)


def test_cap_one_valid() -> None:
    cfg = HandleCapConfig(per_user=1)
    assert cfg.per_user == 1


def test_cap_large_value_valid() -> None:
    cfg = HandleCapConfig(per_user=10_000)
    assert cfg.per_user == 10_000


def test_config_is_frozen() -> None:
    """Operator config is immutable after construction (consistent with
    RateLimitConfig)."""
    cfg = HandleCapConfig(per_user=5)
    with pytest.raises((AttributeError, TypeError)):
        cfg.per_user = 10  # type: ignore[misc]

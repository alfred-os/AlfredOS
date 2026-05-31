"""Tests for _ingest_tier() role-x-adapter trust-tier derivation. Spec §3.6.

_ingest_tier lives in src/alfred/identity/_ingest.py (NOT in
orchestrator/core.py — the orchestrator's module docstring establishes
that external input arrives already-tagged by the time it reaches the
orchestrator). Each CommsAdapter calls _ingest_tier at the ingress
boundary before passing tagged content to the orchestrator.
"""

from __future__ import annotations

from alfred.identity._ingest import _ingest_tier

from alfred.identity.models import Authorization, User
from alfred.security.tiers import T1, T2, TrustTier


def _make_user(authorization: Authorization) -> User:
    """Minimal User stub for testing _ingest_tier."""
    user = User.__new__(User)
    # Set the attributes directly on the ORM object for test isolation
    object.__setattr__(user, "authorization", authorization.value)
    object.__setattr__(user, "slug", f"test-{authorization.value}")
    return user


def test_tui_operator_resolves_to_t1() -> None:
    """TUI adapter + operator role → T1 (highest-trust operator tier).
    Spec §3.6: 'TUI + operator role -> T1.'"""
    user = _make_user(Authorization.OPERATOR)
    result = _ingest_tier(user, adapter_name="tui")
    assert result is T1


def test_tui_standard_user_resolves_to_t2() -> None:
    """TUI adapter + non-operator role → T2. Spec §3.6."""
    user = _make_user(Authorization.STANDARD)
    result = _ingest_tier(user, adapter_name="tui")
    assert result is T2


def test_tui_trusted_user_resolves_to_t2() -> None:
    """TUI + trusted role → T2. Only operator + TUI → T1."""
    user = _make_user(Authorization.TRUSTED)
    result = _ingest_tier(user, adapter_name="tui")
    assert result is T2


def test_tui_read_only_user_resolves_to_t2() -> None:
    user = _make_user(Authorization.READ_ONLY)
    result = _ingest_tier(user, adapter_name="tui")
    assert result is T2


def test_discord_operator_resolves_to_t2() -> None:
    """Discord adapter + operator role → T2.
    Spec §3.6: 'Discord + operator role -> T2 (Discord is broadcast-shaped,
    never T1).'"""
    user = _make_user(Authorization.OPERATOR)
    result = _ingest_tier(user, adapter_name="discord")
    assert result is T2


def test_discord_standard_user_resolves_to_t2() -> None:
    user = _make_user(Authorization.STANDARD)
    result = _ingest_tier(user, adapter_name="discord")
    assert result is T2


def test_unknown_adapter_resolves_to_t2() -> None:
    """Any unknown adapter → T2 (fail-safe default). Spec §3.6."""
    user = _make_user(Authorization.OPERATOR)
    result = _ingest_tier(user, adapter_name="unknown_adapter")
    assert result is T2


def test_ingest_tier_returns_type_not_instance() -> None:
    """_ingest_tier returns the TrustTier class (type), not an instance."""
    user = _make_user(Authorization.OPERATOR)
    result = _ingest_tier(user, adapter_name="tui")
    assert isinstance(result, type)
    assert issubclass(result, TrustTier)

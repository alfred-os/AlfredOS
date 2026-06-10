"""Tests for _ingest_tier() role-x-adapter trust-tier derivation. Spec §3.6.

_ingest_tier lives in src/alfred/identity/_ingest.py (NOT in
orchestrator/core.py — the orchestrator's module docstring establishes
that external input arrives already-tagged by the time it reaches the
orchestrator). Each CommsAdapter calls _ingest_tier at the ingress
boundary before passing tagged content to the orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from alfred.identity._ingest import _ingest_tier
from alfred.identity.models import Authorization
from alfred.security.tiers import T1, T2, TrustTier


@dataclass(frozen=True, slots=True)
class _UserStub:
    """Minimal stand-in for the User ORM at the _ingest_tier boundary.

    ``_ingest_tier`` reads only ``.authorization`` off the user (it is
    typed ``object`` and uses ``getattr``) so a tiny dataclass with the
    same two attributes is sufficient. Constructing a real ``User`` via
    ``User.__new__`` would require SQLAlchemy's InstrumentedAttribute
    machinery to be initialised, which is unit-test heavyweight for a
    boundary that doesn't need ORM semantics.
    """

    authorization: str
    slug: str


def _make_user(authorization: Authorization) -> _UserStub:
    """Build a minimal stub User for testing _ingest_tier."""
    return _UserStub(authorization=authorization.value, slug=f"test-{authorization.value}")


def test_tui_operator_resolves_to_t1() -> None:
    """TUI adapter + operator role → T1 (highest-trust operator tier).
    Spec §3.6: 'TUI + operator role -> T1.'"""
    user = _make_user(Authorization.OPERATOR)
    result = _ingest_tier(user, adapter_id="tui")
    assert result is T1


def test_tui_standard_user_resolves_to_t2() -> None:
    """TUI adapter + non-operator role → T2. Spec §3.6."""
    user = _make_user(Authorization.STANDARD)
    result = _ingest_tier(user, adapter_id="tui")
    assert result is T2


def test_tui_trusted_user_resolves_to_t2() -> None:
    """TUI + trusted role → T2. Only operator + TUI → T1."""
    user = _make_user(Authorization.TRUSTED)
    result = _ingest_tier(user, adapter_id="tui")
    assert result is T2


def test_tui_read_only_user_resolves_to_t2() -> None:
    user = _make_user(Authorization.READ_ONLY)
    result = _ingest_tier(user, adapter_id="tui")
    assert result is T2


def test_discord_operator_resolves_to_t2() -> None:
    """Discord adapter + operator role → T2.
    Spec §3.6: 'Discord + operator role -> T2 (Discord is broadcast-shaped,
    never T1).'"""
    user = _make_user(Authorization.OPERATOR)
    result = _ingest_tier(user, adapter_id="discord")
    assert result is T2


def test_discord_standard_user_resolves_to_t2() -> None:
    user = _make_user(Authorization.STANDARD)
    result = _ingest_tier(user, adapter_id="discord")
    assert result is T2


def test_unknown_adapter_resolves_to_t2() -> None:
    """Any unknown adapter → T2 (fail-safe default). Spec §3.6."""
    user = _make_user(Authorization.OPERATOR)
    result = _ingest_tier(user, adapter_id="unknown_adapter")
    assert result is T2


def test_ingest_tier_returns_type_not_instance() -> None:
    """_ingest_tier returns the TrustTier class (type), not an instance."""
    user = _make_user(Authorization.OPERATOR)
    result = _ingest_tier(user, adapter_id="tui")
    assert isinstance(result, type)
    assert issubclass(result, TrustTier)


def test_ingest_tier_recognises_tui_kind_via_adapter_id_prefix() -> None:
    """A per-instance comms-MCP adapter id (``tui-<uuid>``) still classifies T1.

    PR-S4-10 (#206): the in-process Protocol exposed ``CommsAdapter.name``
    (``"tui"``); the comms-MCP wire carries a per-instance ``adapter_id``
    (e.g. ``tui-9f3c2b1e``). The TUI-kind gate keys on the ``tui`` prefix,
    not string equality, so a per-instance id still resolves to the
    operator tier. Spec §3.6.
    """
    user = _make_user(Authorization.OPERATOR)
    result = _ingest_tier(user, adapter_id="tui-9f3c2b1e")
    assert result is T1


def test_ingest_tier_recognises_discord_kind_via_adapter_id_prefix() -> None:
    """A per-instance Discord adapter id classifies T2 (broadcast-shaped).

    Discord is never T1 even for an operator-role user — the prefix lookup
    preserves that invariant for per-instance ids like ``discord-bot-prod``.
    Spec §3.6.
    """
    user = _make_user(Authorization.OPERATOR)
    result = _ingest_tier(user, adapter_id="discord-bot-prod")
    assert result is T2


def test_ingest_tier_rejects_legacy_adapter_name_kwarg() -> None:
    """The Slice-2 ``adapter_name=`` kwarg is a hard break in Slice 4.

    Slice-2 callers passed ``adapter_name=``; Slice-4 callers pass
    ``adapter_id=``. The rename is deliberate (the wire contract carries an
    id, not a name) — a stale caller must surface loudly as a ``TypeError``
    rather than silently binding to a forgotten kwarg. PR-S4-10 (#206).
    """
    user = _make_user(Authorization.OPERATOR)
    with pytest.raises(TypeError, match="adapter_id|adapter_name"):
        _ingest_tier(user, adapter_name="tui")  # type: ignore[call-arg]

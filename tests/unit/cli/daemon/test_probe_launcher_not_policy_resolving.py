"""Verify the launcher policy-resolving probe (#174).

PR-S4-1 ships a no-op stub that passes by default; PR-S4-6 replaces the
``_launcher_self_test_impl`` with a real subprocess call. sec-004 closure:
in production, a Slice-3 stub signature refuses the boot.
"""

from __future__ import annotations

import pytest

from alfred.cli.daemon._daemon_probes import probe_launcher_policy_resolving
from alfred.cli.daemon._failures import LauncherNotPolicyResolvingFailure


@pytest.mark.asyncio
async def test_probe_stub_passes_in_development() -> None:
    """PR-S4-1 stub returns None (no failure) in development."""
    result = await probe_launcher_policy_resolving(environment="development")
    assert result is None


@pytest.mark.asyncio
async def test_probe_passes_in_production_when_signature_ok() -> None:
    """A policy-resolving signature passes even in production."""
    result = await probe_launcher_policy_resolving(environment="production")
    assert result is None


@pytest.mark.asyncio
async def test_probe_refuses_stub_signature_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sec-004: the Slice-3 stub signature refuses the boot in production."""

    async def _slice3_stub() -> str:
        return "slice-3-stub-signature"

    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes._launcher_self_test_impl",
        _slice3_stub,
    )
    result = await probe_launcher_policy_resolving(environment="production")
    assert isinstance(result, LauncherNotPolicyResolvingFailure)
    assert result.probe_response == "slice-3-stub-signature"


@pytest.mark.asyncio
async def test_probe_tolerates_stub_signature_in_development(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Outside production, the stub signature is tolerated (dev convenience)."""

    async def _slice3_stub() -> str:
        return "slice-3-stub-signature"

    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes._launcher_self_test_impl",
        _slice3_stub,
    )
    result = await probe_launcher_policy_resolving(environment="development")
    assert result is None

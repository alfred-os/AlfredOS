"""Verify the launcher policy-resolving probe (#174).

PR-S4-1 ships a stub whose self-test returns the ``_STUB_SIGNATURE`` —
NOT the policy-resolving one — so production refuses to boot on the
unverified launcher (sec-004). PR-S4-6 replaces ``_launcher_self_test_impl``
with a real subprocess call that returns the resolving signature only when
the launcher genuinely sandboxes.
"""

from __future__ import annotations

import pytest

from alfred.cli.daemon._daemon_probes import (
    _POLICY_RESOLVING_SIGNATURE,
    _STUB_SIGNATURE,
    probe_launcher_policy_resolving,
)
from alfred.cli.daemon._failures import LauncherNotPolicyResolvingFailure


@pytest.mark.asyncio
async def test_probe_stub_passes_in_development() -> None:
    """sec-004: the PR-S4-1 stub signature is tolerated in development."""
    result = await probe_launcher_policy_resolving(environment="development")
    assert result is None


@pytest.mark.asyncio
async def test_probe_stub_refuses_in_production() -> None:
    """sec-004: the default PR-S4-1 stub launcher refuses to boot in production.

    No monkeypatch — this exercises the SHIPPED stub. A prod deploy on an
    unverified (possibly unsandboxed) launcher must refuse until PR-S4-6
    ships the real self-test.
    """
    result = await probe_launcher_policy_resolving(environment="production")
    assert isinstance(result, LauncherNotPolicyResolvingFailure)
    assert result.probe_response == _STUB_SIGNATURE


@pytest.mark.asyncio
async def test_probe_passes_in_production_when_signature_resolving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A genuine policy-resolving signature passes even in production."""

    async def _resolving() -> str:
        return _POLICY_RESOLVING_SIGNATURE

    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes._launcher_self_test_impl",
        _resolving,
    )
    result = await probe_launcher_policy_resolving(environment="production")
    assert result is None


@pytest.mark.asyncio
async def test_probe_refuses_arbitrary_signature_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sec-004: any non-resolving signature refuses the boot in production."""

    async def _other() -> str:
        return "some-other-signature"

    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes._launcher_self_test_impl",
        _other,
    )
    result = await probe_launcher_policy_resolving(environment="production")
    assert isinstance(result, LauncherNotPolicyResolvingFailure)
    assert result.probe_response == "some-other-signature"


@pytest.mark.asyncio
async def test_probe_tolerates_arbitrary_signature_in_development(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Outside production, a non-resolving signature is tolerated (dev)."""

    async def _other() -> str:
        return "some-other-signature"

    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes._launcher_self_test_impl",
        _other,
    )
    result = await probe_launcher_policy_resolving(environment="development")
    assert result is None

"""``build_boot_real_gate`` seed-then-load factory (PR-S4-11b0 / ADR-0026).

The production daemon needs a RealGate whose in-memory policy already
contains the first-party system grants the moment it is constructed —
otherwise the :class:`alfred.security.quarantine.QuarantinedExtractor`
the daemon builds next would be denied its DLP-subscriber registration.

The ORDERING is the load-bearing invariant: the seed must land in
Postgres BEFORE :meth:`RealGate.create` reads the grant snapshot via
``load_grants``. This factory encapsulates that ordering in ONE place so
it is tested once here.
"""

from __future__ import annotations

from collections.abc import Iterable
from unittest.mock import AsyncMock, MagicMock, create_autospec

from alfred.security.capability_gate._bootstrap_grants import (
    FIRST_PARTY_SYSTEM_GRANTS,
)
from alfred.security.capability_gate.backend import StorageBackend
from alfred.security.capability_gate.policy import GrantRow


class _OrderRecordingBackend:
    """Records the seed→load ordering and serves the seeded grants back.

    Mimics a real Postgres round-trip: whatever ``seed_first_party_grants``
    was handed is what ``load_grants`` returns — so the constructed gate's
    policy reflects the seed, and a load-before-seed regression surfaces
    as an empty policy.
    """

    def __init__(self) -> None:
        self.calls: list[str] = []
        self._seeded: frozenset[GrantRow] = frozenset()

    async def seed_first_party_grants(self, grants: Iterable[GrantRow]) -> None:
        self.calls.append("seed")
        self._seeded = frozenset(grants)

    async def load_grants(self) -> frozenset[GrantRow]:
        self.calls.append("load")
        return self._seeded

    async def ping(self) -> None:  # pragma: no cover - not exercised here
        return None


def _noop_audit_sink() -> object:
    sink = MagicMock()
    sink.append_schema = AsyncMock(return_value=None)
    return sink


async def test_build_boot_real_gate_seeds_before_loading() -> None:
    from alfred.bootstrap.gate_factory import build_boot_real_gate

    backend = _OrderRecordingBackend()
    gate = await build_boot_real_gate(
        backend=backend,
        audit_sink=_noop_audit_sink(),
        start_heartbeat=False,
    )

    # The seed MUST precede the policy load.
    assert backend.calls == ["seed", "load"]
    # The constructed gate's policy reflects the seeded first-party grant.
    assert gate.check(
        plugin_id="alfred.security._extract_dlp_subscriber",
        hookpoint="security.quarantined.extract",
        requested_tier="system",
    )


async def test_build_boot_real_gate_seeds_exactly_first_party_constant() -> None:
    """The factory drives the seed off :data:`FIRST_PARTY_SYSTEM_GRANTS`
    — the SAME constant the daemon's grant assertion checks, so seed and
    assertion can never drift."""
    backend = create_autospec(StorageBackend, spec_set=True, instance=True)
    backend.load_grants.return_value = frozenset(FIRST_PARTY_SYSTEM_GRANTS)

    from alfred.bootstrap.gate_factory import build_boot_real_gate

    await build_boot_real_gate(
        backend=backend,
        audit_sink=_noop_audit_sink(),
        start_heartbeat=False,
    )

    backend.seed_first_party_grants.assert_awaited_once_with(FIRST_PARTY_SYSTEM_GRANTS)


async def test_build_boot_real_gate_denies_unseeded_request() -> None:
    """Fail-closed: a request OUTSIDE the seeded scope still denies — the
    seed authorises ONLY the first-party DLP subscriber, nothing else."""
    backend = _OrderRecordingBackend()

    from alfred.bootstrap.gate_factory import build_boot_real_gate

    gate = await build_boot_real_gate(
        backend=backend,
        audit_sink=_noop_audit_sink(),
        start_heartbeat=False,
    )

    assert not gate.check(
        plugin_id="some.untrusted.plugin",
        hookpoint="security.quarantined.extract",
        requested_tier="system",
    )

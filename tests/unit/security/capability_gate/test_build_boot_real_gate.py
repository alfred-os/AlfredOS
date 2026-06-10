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

    async def reconcile_comms_adapter_grants(self, desired: Iterable[GrantRow]) -> None:
        # FIX 2: the boot factory reconciles the dynamic comms-adapter grants
        # AFTER the additive seed. The desired set is already a subset of the
        # seeded rows here (build_boot_real_gate seeds them too), so the recorded
        # ``_seeded`` snapshot already reflects the reconciled state; just record
        # the ordering so a seed→reconcile→load regression surfaces.
        self.calls.append("reconcile")

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

    # The seed MUST precede the reconcile, which precedes the policy load.
    assert backend.calls == ["seed", "reconcile", "load"]
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
    # FIX 2: no comms adapters enabled -> reconcile runs with the empty desired
    # set, which DROPS any stale sentinel rows from a previously-enabled adapter
    # the operator has since removed.
    backend.reconcile_comms_adapter_grants.assert_awaited_once_with(())


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


# ---------------------------------------------------------------------------
# PR-S4-11b / ADR-0027: additive comms-adapter load grants (config-sourced)
# ---------------------------------------------------------------------------


def _comms_adapter_grant() -> GrantRow:
    """A representative comms-adapter plugin-LOAD grant (wildcard hookpoint)."""
    return GrantRow(
        plugin_id="alfred.comms-test",
        subscriber_tier="user-plugin",
        hookpoint="*",
        content_tier=None,
        proposal_branch="bootstrap:first-party-comms-adapter",
    )


async def test_build_boot_real_gate_seeds_first_party_plus_extra_grants() -> None:
    """``extra_grants`` are seeded ALONGSIDE the static first-party grants.

    A comms-adapter load grant passed as ``extra_grants`` lands in the same
    seed transaction; the static DLP seed is unchanged (still present), so
    the comms seed is purely additive.
    """
    from alfred.bootstrap.gate_factory import build_boot_real_gate

    backend = _OrderRecordingBackend()
    comms_grant = _comms_adapter_grant()

    gate = await build_boot_real_gate(
        backend=backend,
        audit_sink=_noop_audit_sink(),
        start_heartbeat=False,
        extra_grants=(comms_grant,),
    )

    # Seed still precedes reconcile, which precedes load.
    assert backend.calls == ["seed", "reconcile", "load"]
    # The static DLP grant is still live (additive — extra grants do not
    # displace the first-party constant).
    assert gate.check(
        plugin_id="alfred.security._extract_dlp_subscriber",
        hookpoint="security.quarantined.extract",
        requested_tier="system",
    )
    # The comms-adapter load grant is live: check_plugin_load clears for the
    # manifest plugin id at the manifest tier (the handshake's exact query).
    assert gate.check_plugin_load(
        plugin_id="alfred.comms-test",
        manifest_tier="user-plugin",
    )


async def test_build_boot_real_gate_seeds_combined_constant_plus_extra() -> None:
    """The seed call receives FIRST_PARTY_SYSTEM_GRANTS + extra_grants.

    Pins the additive contract at the seed boundary: the backend is handed
    the static constant tuple FOLLOWED BY the extra grants, in one call, so a
    regression that dropped the static seed when extra grants are present
    surfaces here.
    """
    backend = create_autospec(StorageBackend, spec_set=True, instance=True)
    comms_grant = _comms_adapter_grant()
    backend.load_grants.return_value = frozenset((*FIRST_PARTY_SYSTEM_GRANTS, comms_grant))

    from alfred.bootstrap.gate_factory import build_boot_real_gate

    await build_boot_real_gate(
        backend=backend,
        audit_sink=_noop_audit_sink(),
        start_heartbeat=False,
        extra_grants=(comms_grant,),
    )

    backend.seed_first_party_grants.assert_awaited_once_with(
        (*FIRST_PARTY_SYSTEM_GRANTS, comms_grant)
    )
    # FIX 2: the dynamic comms-adapter grants are ALSO reconciled (scoped
    # revoke-diff) so a removed adapter's stale grant is dropped. The reconcile
    # receives EXACTLY the extra (comms-adapter) grants — never the static set.
    backend.reconcile_comms_adapter_grants.assert_awaited_once_with((comms_grant,))


async def test_build_boot_real_gate_default_extra_grants_empty() -> None:
    """Omitting ``extra_grants`` seeds EXACTLY the static first-party set.

    Back-compat: the default-empty ``extra_grants`` keeps the pre-11b boot
    byte-for-byte unchanged (the daemon's existing grant assertion still
    passes; no comms grant is seeded).
    """
    backend = create_autospec(StorageBackend, spec_set=True, instance=True)
    backend.load_grants.return_value = frozenset(FIRST_PARTY_SYSTEM_GRANTS)

    from alfred.bootstrap.gate_factory import build_boot_real_gate

    await build_boot_real_gate(
        backend=backend,
        audit_sink=_noop_audit_sink(),
        start_heartbeat=False,
    )

    backend.seed_first_party_grants.assert_awaited_once_with(FIRST_PARTY_SYSTEM_GRANTS)
    # FIX 2: no comms adapters enabled -> reconcile runs with the empty desired
    # set, which DROPS any stale sentinel rows from a previously-enabled adapter
    # the operator has since removed.
    backend.reconcile_comms_adapter_grants.assert_awaited_once_with(())

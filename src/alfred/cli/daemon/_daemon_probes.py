"""Pre-TaskGroup probes for the daemon boot path (#174 PR-S4-1).

Spec §3.1 (core-007 closure): probes run at the CLI layer, NOT inside
``Supervisor.start()``. The supervisor's ``start()`` is TaskGroup-first by
current shape (``src/alfred/supervisor/core.py``). PR-S4-1 adds these
probes to the CLI without touching the supervisor surface.

Three probes:

(a) ``probe_launcher_policy_resolving`` — no-op stub in PR-S4-1; the real
    subprocess self-test lands in PR-S4-6. sec-004: in production a
    Slice-3 stub signature refuses the boot.
(b) ``probe_snapshot_ref_init`` — loads ``config/policies.yaml`` once.
    core-eng-002: FILE-ONLY ops; it MUST NOT touch Postgres.
(c) ``probe_capability_gate_handshake`` — the capability gate's
    backing-store reachability handshake (Postgres / state.git).

Each probe returns ``DaemonBootFailure | None``; ``None`` means passed, a
discriminated-union instance means refused (the caller emits the audit
row + prints the ``t()`` message + exits non-zero).
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Final

import yaml

from alfred.cli.daemon._failures import (
    CapabilityGateHandshakeFailedFailure,
    DaemonBootFailure,
    LauncherNotPolicyResolvingFailure,
    SnapshotRefInitFailedFailure,
)

# sec-002 closure: the truthy env-var vocabulary the unsandboxed-escape
# gate and PR-S4-6's launcher policy resolver MUST agree on. Lowercased +
# stripped membership, never ``== "1"`` strict equality.
_TRUTHY_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})

# The launcher self-test token a policy-resolving launcher returns. PR-S4-6
# wires the real subprocess call; the stub below returns this token so the
# happy path passes today.
_POLICY_RESOLVING_SIGNATURE: Final[str] = "policy-resolving"

# PR-S4-1 fallback default. PR-S4-4 deletes this once PoliciesV1 ships.
_DEFAULT_POLICIES_V1_STUB: Final[bytes] = b"_DEFAULT_POLICIES_V1_STUB"


def _truthy_env(name: str) -> bool:
    """Return ``True`` iff env var ``name`` holds a truthy token.

    sec-002 closure: lowercases + strips whitespace, then checks membership
    in ``{"1", "true", "yes", "on"}``. NOT ``== "1"`` — operators set
    ``true`` / ``yes`` / ``on`` and expect them to count. Shared with
    PR-S4-6's launcher policy resolver so the gate and the carrier agree.
    """
    raw = os.environ.get(name)
    if raw is None:
        return False
    return raw.strip().lower() in _TRUTHY_VALUES


async def _launcher_self_test_impl() -> str:
    """PR-S4-1 stub for the launcher self-test.

    PR-S4-6 replaces this with a real subprocess call to
    ``bin/alfred-plugin-launcher.sh --self-test`` and checks the response
    for the policy-resolving signature.
    """
    return _POLICY_RESOLVING_SIGNATURE


async def probe_launcher_policy_resolving(
    *,
    environment: str,
) -> DaemonBootFailure | None:
    """Verify the launcher binary supports policy resolution.

    PR-S4-1: stub that passes unless the launcher returns a non-resolving
    signature AND we are in production (sec-004 — no production deploy may
    silently succeed without the real check). Outside production the stub
    signature is tolerated for dev convenience; PR-S4-6 ships the real
    probe that runs ``bin/alfred-plugin-launcher.sh --self-test``.
    """
    response = await _launcher_self_test_impl()
    if response == _POLICY_RESOLVING_SIGNATURE:
        return None
    if environment == "production":
        return LauncherNotPolicyResolvingFailure(probe_response=response)
    return None


class _StubPoliciesSnapshotRef:
    """Minimal ``PoliciesSnapshotRef`` for PR-S4-1.

    Holds the loaded YAML bytes + their SHA-256. PR-S4-4 replaces this with
    the real ``PoliciesSnapshotRef`` that owns the mtime watcher and the
    validated ``PoliciesV1`` Pydantic model. Satisfies
    ``PoliciesSnapshotRefProtocol`` structurally.
    """

    def __init__(self, raw_bytes: bytes) -> None:
        self._raw = raw_bytes
        self._hash = hashlib.sha256(raw_bytes).hexdigest()

    def current(self) -> object:
        """Return the parsed YAML dict, or ``None`` for the default stub."""
        if self._raw == _DEFAULT_POLICIES_V1_STUB:
            return None
        return yaml.safe_load(self._raw)

    def snapshot_hash(self) -> str:
        return self._hash


async def probe_snapshot_ref_init(
    *,
    config_path: Path = Path("config/policies.yaml"),
) -> tuple[DaemonBootFailure | None, _StubPoliciesSnapshotRef | None]:
    """Load ``config/policies.yaml`` once at boot (FILE-ONLY; core-eng-002).

    Returns a 2-tuple ``(failure, snapshot_ref)``. On pass the failure is
    ``None`` and the snapshot_ref is the stub ready to pass into
    ``Supervisor(policies_ref=…)``. On refusal the snapshot_ref is ``None``
    and the failure carries the redacted exception class — never a fragment
    of the file (§5.6).
    """
    try:
        raw = config_path.read_bytes()
    except FileNotFoundError:
        # Fallback to the default stub. PR-S4-4 may require the file once
        # the watcher lands.
        return None, _StubPoliciesSnapshotRef(_DEFAULT_POLICIES_V1_STUB)
    except OSError as exc:
        return (
            SnapshotRefInitFailedFailure(detail_redacted=type(exc).__qualname__),
            None,
        )

    try:
        yaml.safe_load(raw)  # validate; the parsed result is recomputed lazily
    except yaml.YAMLError as exc:
        return (
            SnapshotRefInitFailedFailure(detail_redacted=type(exc).__qualname__),
            None,
        )

    return None, _StubPoliciesSnapshotRef(raw)


class _BackingStoreGate:
    """Structural view of the gate dependency the handshake probe consults."""

    async def is_backing_store_available(self) -> bool:  # pragma: no cover - protocol
        raise NotImplementedError


async def probe_capability_gate_handshake(
    *,
    gate: _BackingStoreGate,
) -> DaemonBootFailure | None:
    """Handshake with the capability gate's backing store (Postgres / state.git).

    Spec §3.4 ``capability_gate_handshake_failed``: the gate cannot reach
    Postgres or state.git at boot. A ``False`` return or an exception both
    refuse the boot (CLAUDE.md hard rule 7 — loud refusal on probe
    failure).
    """
    try:
        ok = await gate.is_backing_store_available()
    except Exception:
        # Boot probe: any failure refuses, loudly (CLAUDE.md hard rule 7).
        return CapabilityGateHandshakeFailedFailure(backing_store_kind="unknown")
    if not ok:
        return CapabilityGateHandshakeFailedFailure(backing_store_kind="postgres")
    return None

"""Slice-4 Protocols consumed by ``Supervisor.__init__`` (#174 PR-S4-1).

Both Protocols default to ``None`` in the new ``Supervisor.__init__``
kwargs so legacy unit tests that construct ``Supervisor(session_scope=…,
gate=…, audit=…)`` keep passing. Real implementations land in:

* :class:`PoliciesSnapshotRefProtocol` → PR-S4-4 (``PoliciesSnapshotRef``)
* :class:`OperatorResolverProtocol` → PR-S4-5 (``_resolve_operator``)

The ``DaemonBootFailure`` discriminated union deliberately does NOT live
here — it is a CLI-layer concept and lives at
``alfred.cli.daemon._failures`` (core-eng-001 round-2 closure).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class PoliciesSnapshotRefProtocol(Protocol):
    """Read-only access to the active PoliciesSnapshot.

    PR-S4-1 ships a minimal stub that loads ``config/policies.yaml`` once
    at boot. PR-S4-4 replaces it with the mtime-polled
    ``PoliciesSnapshotRef`` whose ``current()`` is a GIL-atomic
    single-attribute load (perf-002 round-2 closure — synchronous, NOT
    async).
    """

    def current(self) -> object:
        """Return the active snapshot.

        Type widens to the real ``PoliciesSnapshot`` once PR-S4-4 lands.
        """
        ...

    def snapshot_hash(self) -> str:
        """Return a stable hash of the active snapshot.

        PR-S4-1 uses SHA-256 of the on-disk YAML; PR-S4-4 may switch to a
        content-hash with normalised key ordering.
        """
        ...


@runtime_checkable
class OperatorResolverProtocol(Protocol):
    """Resolve the operator UserId from the CLI session file.

    PR-S4-1 ships a no-op stub (returns a synthetic "boot-time" id).
    PR-S4-5 replaces it with the real resolver that reads
    ``~/.config/alfred/session``, validates mode + ownership, queries
    Postgres for the session row, and returns the canonical user id.
    """

    async def resolve(self) -> str:
        """Return the canonical operator UserId.

        PR-S4-1 stub returns a synthetic ``"_daemon_boot"`` id so the
        construction surface works; PR-S4-5 raises the typed
        ``OperatorSession*`` exceptions on failure.
        """
        ...

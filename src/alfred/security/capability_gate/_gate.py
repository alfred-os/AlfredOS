"""RealGate — production :class:`alfred.hooks.capability.CapabilityGate`.

Spec §8.1 (Fork 7) — hybrid storage (state.git source of truth + Postgres
runtime cache). Spec §8.2 — three keyword-only methods on every gate
implementation. Spec §8.4 — co-exists with :class:`DevGate` until the
PR-S3-7 flag-day removal.

This file lands incrementally across PR-S3-2:

* PR-S3-2 Tasks 1-8 (this commit) — happy-path :meth:`check` /
  :meth:`check_plugin_load` / :meth:`check_content_clearance`, the
  :meth:`_apply_grants` Postgres sync path, and the
  err-002 fail-loud :meth:`rebuild_from_state_git` deferred stub.
* PR-S3-2 Tasks 9-10 (Component E) — heartbeat task + fail-closed
  audit emission (``supervisor.capability_gate_unavailable``).
* PR-S3-6 — replaces the :meth:`rebuild_from_state_git`
  ``NotImplementedError`` with the gitpython-backed parse, calling
  :meth:`_apply_grants` directly.

Thread-safety: :class:`GatePolicy` is immutable; ``_policy`` is replaced
atomically via asyncio (single-threaded event loop). No locks needed on
the hot path.

This module does NOT ``import os`` (sec-007 extension). ``ALFRED_ENV``
selection lives in :mod:`alfred.bootstrap.gate_factory` (forthcoming).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import structlog

from alfred.security.capability_gate.policy import GatePolicy, GrantRow

if TYPE_CHECKING:
    from alfred.security.capability_gate.backend import StorageBackend

_log = structlog.get_logger(__name__)

# Spec §8.1: after 60s without a successful heartbeat, gate transitions
# to fail-closed. Constants are module-level so Component E's
# constant-product invariant test can lock the 60s window without
# importing private state.
_HEARTBEAT_INTERVAL_SECONDS: float = 10.0
_FAIL_CLOSED_AFTER_SECONDS: float = 60.0
_MAX_MISSED_HEARTBEATS: int = int(_FAIL_CLOSED_AFTER_SECONDS / _HEARTBEAT_INTERVAL_SECONDS)


class RealGate:
    """Production :class:`CapabilityGate` backed by Postgres + state.git.

    Spec §8.1. Constructed via :meth:`create` which performs the initial
    Postgres load and optionally starts the heartbeat task. The
    :class:`alfred.hooks.capability.CapabilityGate` Protocol is satisfied
    structurally — :class:`RealGate` exposes ``check`` /
    ``check_plugin_load`` / ``check_content_clearance`` as keyword-only
    methods.

    Production code does NOT import this class directly: the bootstrap
    factory in :mod:`alfred.bootstrap.gate_factory` chooses between
    :class:`RealGate` and :class:`alfred.hooks.capability.DevGate` based
    on ``ALFRED_ENV``; that's the sec-007 env-isolation seam.
    """

    def __init__(
        self,
        *,
        policy: GatePolicy,
        backend: StorageBackend,
        audit_sink: object,
    ) -> None:
        self._policy = policy
        self._backend = backend
        self._audit_sink = audit_sink
        self._fail_closed: bool = False
        self._missed_heartbeats: int = 0
        self._denied_dispatch_count: int = 0
        self._heartbeat_task: asyncio.Task[None] | None = None

    @classmethod
    async def create(
        cls,
        *,
        backend: StorageBackend,
        audit_sink: object,
        start_heartbeat: bool = False,
    ) -> RealGate:
        """Factory: load grants from Postgres, return a ready :class:`RealGate`.

        Spec §8.1: on AlfredOS startup, the host checks if the state.git
        HEAD differs from the cached commit hash; if so, the rebuild
        runs (PR-S3-6 wiring). The initial load is always from Postgres
        (fast); the state.git rebuild happens separately.

        ``audit_sink`` is required (err-003). Pass a no-op sink in tests
        that do not need audit assertions; a missing audit sink would
        let a fail-closed state transition (entering / exiting) slip
        through without an audit row — CLAUDE.md hard rule #7 forbids
        the silent path. The runtime type is checked at the call site,
        not here, because the in-process Protocol matches the test fake
        without needing the production AuditWriter on the import path.

        ``start_heartbeat`` defaults to ``False`` so unit tests can
        inspect / advance state without a background task racing them.
        Production bootstrap sets ``start_heartbeat=True`` after the
        gate is wired into the supervisor.
        """
        grants = await backend.load_grants()
        policy = GatePolicy(grants=grants)
        gate = cls(policy=policy, backend=backend, audit_sink=audit_sink)
        if start_heartbeat:
            # Tasks 9-10 (Component E) ship _heartbeat_loop; until then
            # the supervisor wires its own heartbeat. This branch stays
            # so the constructor signature is stable when Component E
            # lands.
            gate._heartbeat_task = asyncio.create_task(  # pragma: no cover
                gate._heartbeat_loop()
            )
        return gate

    # ------------------------------------------------------------------
    # Hot-path check methods (spec §8.2)
    # ------------------------------------------------------------------

    def check(
        self,
        *,
        plugin_id: str,
        hookpoint: str,
        requested_tier: str,
    ) -> bool:
        """Return ``False`` when fail-closed; otherwise delegate to GatePolicy.

        Spec §8.1: hot-path checks consult the Postgres-derived
        in-memory policy. When fail-closed, all dispatches deny —
        including in-process ones — after the 60s heartbeat staleness
        window.
        """
        if self._fail_closed:
            self._denied_dispatch_count += 1
            return False
        return self._policy.check(
            plugin_id=plugin_id,
            hookpoint=hookpoint,
            requested_tier=requested_tier,
        )

    def check_plugin_load(
        self,
        *,
        plugin_id: str,
        manifest_tier: str,
    ) -> bool:
        """Gate plugin load at handshake time. Spec §8.2."""
        if self._fail_closed:
            self._denied_dispatch_count += 1
            return False
        return self._policy.check_plugin_load(
            plugin_id=plugin_id,
            manifest_tier=manifest_tier,
        )

    def check_content_clearance(
        self,
        *,
        plugin_id: str,
        hookpoint: str,
        content_tier: str,
    ) -> bool:
        """Gate content-tier access. Spec §8.2."""
        if self._fail_closed:
            self._denied_dispatch_count += 1
            return False
        return self._policy.check_content_clearance(
            plugin_id=plugin_id,
            hookpoint=hookpoint,
            content_tier=content_tier,
        )

    # ------------------------------------------------------------------
    # State.git rebuild (PR-S3-6 wires the parser)
    # ------------------------------------------------------------------

    async def rebuild_from_state_git(self, *, state_git_head: str) -> None:
        """Rebuild Postgres projection when state.git HEAD changes.

        Spec §8.1: the rebuild is idempotent. Called at startup and
        after every state.git push to ``main``. The caller supplies the
        new HEAD commit hash; this method checks the cached hash and
        short-circuits if unchanged.

        DEFERRED-STUB CONTRACT (err-002 acknowledgement):

        PR-S3-2 intentionally ships this method as a fail-loud
        :class:`NotImplementedError` rather than a working
        implementation. The real ``parse_state_git_head``
        (gitpython-backed) lands in PR-S3-6 Task 22a/22b. Rationale:
        parsing the state.git ``policies/grants/`` tree requires
        gitpython integration with the bare state.git repo, which is
        first introduced by PR-S3-6 (the same PR that owns the
        host-side proposal-merge → rebuild trigger). Pulling gitpython
        forward into PR-S3-2 would inflate the slice scope by ~1 task
        and one external dep without exercising the integration
        end-to-end. The fail-loud stub keeps the slice scope tight
        while making the deferred surface impossible to call
        accidentally — any caller before PR-S3-6 merges raises,
        surfacing the contract violation at integration time.

        Per CLAUDE.md hard rule #7 this is the acceptable shape for a
        deferred security path: loud, not silent. The previous shape
        was a silent ``return`` that left the policy cache stale — the
        err-002 fix replaces that with this raise so every caller
        before PR-S3-6 fails loudly.

        Callers that have already parsed state.git and hold
        :class:`GrantRow` objects MUST use :meth:`_apply_grants`
        directly until PR-S3-6 replaces the raise with:

            grants = await parse_state_git_head(state_git_head)
            await self._apply_grants(grants, commit_hash=state_git_head)
        """
        cached = await self._backend.get_sync_hash()
        if cached == state_git_head:
            _log.debug(
                "capability_gate.rebuild.skipped",
                commit_hash=state_git_head,
            )
            return
        msg = (
            "rebuild_from_state_git requires gitpython state.git parser "
            "(ships in PR-S3-6). Call _apply_grants() directly until then."
        )
        raise NotImplementedError(msg)

    async def _apply_grants(
        self,
        grants: frozenset[GrantRow],
        *,
        commit_hash: str,
    ) -> None:
        """Replace the in-memory policy with the new grants and sync to Postgres.

        Called by PR-S3-6's ``parse_state_git_head`` after parsing the
        state.git tree on a new HEAD commit; until then, the supervisor
        calls this directly with pre-parsed grants. Upserts each grant
        individually (idempotent); revocations are handled by the full
        replacement of the in-memory policy below.

        Persistence ordering: upsert each grant, then set the sync hash.
        On any DB failure the in-memory policy is NOT swapped — the
        previous policy stays authoritative until a future rebuild
        succeeds.
        """
        for grant in grants:
            await self._backend.upsert_grant(grant)
        await self._backend.set_sync_hash(commit_hash)
        # Atomic policy swap (single-threaded asyncio event loop). The
        # frozen :class:`GatePolicy` semantics mean any hot-path check
        # mid-flight sees either the old or new snapshot — never a
        # half-mutated state.
        self._policy = GatePolicy(grants=grants)
        _log.info(
            "capability_gate.rebuild.complete",
            grant_count=len(grants),
            commit_hash=commit_hash,
        )

    # ------------------------------------------------------------------
    # Heartbeat / fail-closed machinery — Components E-F (subsequent PR-S3-2 tasks)
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:  # pragma: no cover - lands in Tasks 9-10
        """Background task: ping Postgres every 10s; fail-closed after 60s silence.

        Full implementation lands in PR-S3-2 Component E (Tasks 9-10).
        The signature is fixed here so :meth:`create` can dispatch to
        it conditionally without ABI churn when the body lands.
        """
        raise NotImplementedError(
            "RealGate._heartbeat_loop lands in PR-S3-2 Component E (Tasks 9-10)"
        )

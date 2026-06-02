"""RealGate — production :class:`alfred.hooks.capability.CapabilityGate`.

Spec §8.1 (Fork 7) — hybrid storage (state.git source of truth + Postgres
runtime cache). Spec §8.2 — three keyword-only methods on every gate
implementation. Spec §8.4 — co-exists with :class:`DevGate` until the
PR-S3-7 flag-day removal.

This file lands incrementally across PR-S3-2:

* PR-S3-2 Tasks 1-8 — happy-path :meth:`check` /
  :meth:`check_plugin_load` / :meth:`check_content_clearance`, the
  :meth:`_apply_grants` Postgres sync path, and the
  err-002 fail-loud :meth:`rebuild_from_state_git` deferred stub.
* PR-S3-2 Tasks 9-10 (this commit) — heartbeat loop body +
  :meth:`_emit_gate_unavailable_audit` /
  :meth:`stop_heartbeat`, emitting
  ``supervisor.capability_gate_unavailable`` on both fail-closed
  transitions.
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
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

import structlog
from sqlalchemy.exc import SQLAlchemyError

from alfred.audit.audit_row_schemas import (
    CAPABILITY_GATE_REBUILD_FIELDS,
    SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS,
)

# CR reviewer F1: ``_AuditSink`` lives in ``_audit_protocols`` so the
# gate and the proposal flow share ONE source of truth for the
# audit-sink signature. Re-imported here so existing call sites that
# reference ``alfred.security.capability_gate._gate._AuditSink`` continue
# to type-check; the canonical home is the dedicated module.
from ._audit_protocols import _AuditSink
from ._state_git_parser import parse_state_git_head
from .policy import GatePolicy, GrantRow

if TYPE_CHECKING:
    from .backend import StorageBackend


_log = structlog.get_logger(__name__)

# Spec §8.1: after 60s without a successful heartbeat, gate transitions
# to fail-closed. Constants are module-level so Component E's
# constant-product invariant test can lock the 60s window without
# importing private state.
_HEARTBEAT_INTERVAL_SECONDS: float = 10.0
_FAIL_CLOSED_AFTER_SECONDS: float = 60.0
_MAX_MISSED_HEARTBEATS: int = int(_FAIL_CLOSED_AFTER_SECONDS / _HEARTBEAT_INTERVAL_SECONDS)

# Default state.git path per the Slice-3 operator runbook (spec §15.4).
# sec-007 keeps env reads out of this module: the bootstrap layer
# (:mod:`alfred.bootstrap.gate_factory`) reads ``ALFRED_STATE_GIT_PATH``
# and threads the resolved Path into :meth:`RealGate.create` so this
# module stays env-isolated. Tests override via the constructor arg.
_DEFAULT_STATE_GIT_PATH: Path = Path("/var/lib/alfred/state.git")


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
        audit_sink: _AuditSink,
        state_git_path: Path = _DEFAULT_STATE_GIT_PATH,
    ) -> None:
        self._policy = policy
        self._backend = backend
        self._audit_sink = audit_sink
        self._state_git_path = state_git_path
        self._fail_closed: bool = False
        self._missed_heartbeats: int = 0
        self._denied_dispatch_count: int = 0
        self._heartbeat_task: asyncio.Task[None] | None = None

    @classmethod
    async def create(
        cls,
        *,
        backend: StorageBackend,
        audit_sink: _AuditSink,
        state_git_path: Path = _DEFAULT_STATE_GIT_PATH,
        start_heartbeat: bool = False,
    ) -> RealGate:
        """Factory: load grants from Postgres, return a ready :class:`RealGate`.

        Spec §8.1: on AlfredOS startup, the host checks if the state.git
        HEAD differs from the cached commit hash; if so, the rebuild
        runs via :meth:`rebuild_from_state_git`. The initial load is
        always from Postgres (fast); the state.git rebuild happens
        separately.

        ``audit_sink`` is required (err-003). Pass a no-op sink in tests
        that do not need audit assertions; a missing audit sink would
        let a fail-closed state transition (entering / exiting) slip
        through without an audit row — CLAUDE.md hard rule #7 forbids
        the silent path. The runtime type is checked at the call site,
        not here, because the in-process Protocol matches the test fake
        without needing the production AuditWriter on the import path.

        ``state_git_path`` is the bare state.git repo path used by the
        rebuild parser (PR-S3-6 err-002 wiring). Defaults to
        ``/var/lib/alfred/state.git`` per the Slice-3 operator runbook.
        Production wires the resolved Path from
        :mod:`alfred.bootstrap.gate_factory` (which performs the
        ``ALFRED_STATE_GIT_PATH`` env read sec-007 forbids in this
        module); tests inject a per-test bare repo.

        ``start_heartbeat`` defaults to ``False`` so unit tests can
        inspect / advance state without a background task racing them.
        Production bootstrap sets ``start_heartbeat=True`` after the
        gate is wired into the supervisor.
        """
        grants = await backend.load_grants()
        policy = GatePolicy(grants=grants)
        gate = cls(
            policy=policy,
            backend=backend,
            audit_sink=audit_sink,
            state_git_path=state_git_path,
        )
        if start_heartbeat:
            gate._heartbeat_task = asyncio.create_task(gate._heartbeat_loop())
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

        PR-S3-6 err-002 wiring. Replaces PR-S3-2's fail-loud
        :class:`NotImplementedError` stub with the real path:

        1. Cache-hit short-circuit on equal HEAD (no parse, no audit row
           — the supervisor heartbeat calls this eagerly so a per-call
           audit emit would balloon the log).
        2. :func:`parse_state_git_head` reads the ``policies/grants/``
           tree at the new HEAD. The synchronous gitpython call is
           wrapped in :func:`asyncio.to_thread` so the asyncio event
           loop stays unblocked on a cold-cache rebuild.
        3. :meth:`_apply_grants` projects the snapshot into the Postgres
           cache (upserts new grants, revokes absent ones, swaps the
           in-memory policy atomically) and persists the new sync hash.
        4. Audit row emit on success. Schema:
           :data:`CAPABILITY_GATE_REBUILD_FIELDS`. Order matters: the
           audit row goes LAST so a parser / apply failure does not
           emit a "rebuilt" row for a partial state.

        The state.git path comes from ``self._state_git_path``
        (constructor-injected; sec-007 keeps env reads in
        :mod:`alfred.bootstrap.gate_factory`).
        """
        cached = await self._backend.get_sync_hash()
        if cached == state_git_head:
            _log.debug(
                "capability_gate.rebuild.skipped",
                commit_hash=state_git_head,
            )
            return

        # CR-149 round-3: mirror the rollback audit path for
        # parser-side / repo-read failures. Without this, a bad
        # state.git head (corrupted commit object, missing tree, raised
        # gitpython error) propagated out of ``asyncio.to_thread``
        # before any ``plugin.grant.rebuilt`` row landed — the
        # capability projection stayed on the previous snapshot AND
        # the trust-boundary audit trail had no forensic record that
        # the privileged rebuild attempt failed. CLAUDE.md hard rule
        # #7 (no silent failures in security paths) requires that
        # pre-DB failure surfaces in the audit log too. ``Exception``
        # is intentionally broad: GitPython raises a heterogeneous
        # mix (``git.exc.*``, ``OSError``, ``ValueError``, ...) and
        # the audit row must fire for any of them before re-raising
        # so the supervisor's outer exception path stays intact.
        # gitpython reads are synchronous; offload so we do not block
        # the event loop on a cold object DB read.
        try:
            grants = await asyncio.to_thread(
                parse_state_git_head,
                self._state_git_path,
                state_git_head,
            )
        except Exception as exc:
            # CR-149 round-6: mint the correlation_id HERE and thread it
            # through both the audit row and the adjacent structured
            # log so an incident-response query that surfaces one can
            # join to the other. Previously the audit emitter minted
            # its own UUID locally and the log line carried no id, so
            # a repeated rebuild on the same commit_hash was unjoinable
            # between the two streams — the on-call lost the forensic
            # bridge ``src/alfred/security/**`` (highest-scrutiny
            # surface) is supposed to carry.
            correlation_id = str(uuid.uuid4())
            await self._emit_rebuild_rolled_back_audit(
                commit_hash=state_git_head,
                grant_count=0,
                correlation_id=correlation_id,
            )
            _log.warning(
                "capability_gate.rebuild.parser_failed",
                commit_hash=state_git_head,
                error_type=type(exc).__name__,
                correlation_id=correlation_id,
            )
            raise

        # CR-149 round-6: mint the rebuild-flow correlation_id BEFORE
        # ``_apply_grants`` so the success-arm structlog line emitted
        # by :meth:`_apply_grants` AND the success-arm audit row
        # emitted below both carry the SAME id. The SQL-rollback arm
        # inside ``_apply_grants`` also picks up this id so its audit
        # + log streams join too — without the shared identifier the
        # ``src/alfred/security/**`` forensic bridge would silently
        # break (highest-scrutiny surface; CLAUDE.md hard rule #7).
        correlation_id = str(uuid.uuid4())
        await self._apply_grants(
            grants,
            commit_hash=state_git_head,
            correlation_id=correlation_id,
        )

        # Audit emit LAST — a parse / apply failure must not surface a
        # "rebuilt" row for a partial state. The audit row carries the
        # grant_count so an operator can spot unexpected churn between
        # adjacent rebuilds.
        await self._emit_rebuild_success_audit(
            commit_hash=state_git_head,
            grant_count=len(grants),
            correlation_id=correlation_id,
        )

    async def _apply_grants(
        self,
        grants: frozenset[GrantRow],
        *,
        commit_hash: str,
        correlation_id: str | None = None,
    ) -> None:
        """Replace the in-memory policy with the new grants and sync to Postgres.

        Called by PR-S3-6's ``parse_state_git_head`` after parsing the
        state.git tree on a new HEAD commit; until then, the supervisor
        calls this directly with pre-parsed grants.

        Persistence delta (CR-139 finding #2): the previous in-memory
        snapshot is the source of truth for what was approved. Any
        grant in the previous snapshot but NOT in ``grants`` is a
        revocation — :meth:`StorageBackend.apply_atomic` removes the
        Postgres rows. Without this, the runtime cache stayed
        in-memory-revoked but Postgres-approved; the next process
        restart loaded the stale row and resurrected the capability —
        a CLAUDE.md hard-rule #2 silent privilege-escalation shape.

        Atomicity (sec-pr-s3-6-02 / perf-002 / err-003): the previous
        shape ran the revokes, upserts, and ``set_sync_hash`` as
        separate transactions. A driver error mid-revoke (or between
        the revoke pass and the upsert pass) left Postgres with a
        partially-mutated grant table AND no sync-hash update — silent
        split-brain. CLAUDE.md hard rule #7 (no silent failures in
        security paths) requires all-or-nothing. The work is now
        delegated to :meth:`StorageBackend.apply_atomic`, which runs
        every SQL row inside one ``async with session.begin()`` block.
        On :class:`sqlalchemy.exc.SQLAlchemyError`, the transaction
        rolls back, this method emits a ``plugin.grant.rebuilt`` audit
        row with ``result="rolled_back"`` (err-003: every state-change
        attempt surfaces in the audit log, success OR failure), and
        re-raises so the orchestrator's exception path fires.

        Ordering: revokes are computed first, ``apply_atomic`` runs
        them before the upserts, then the sync-hash set lands LAST
        inside the same transaction. The in-memory policy is swapped
        ONLY after the transaction commits — on rollback the previous
        policy stays authoritative until a future rebuild succeeds.

        Note on grant identity: :class:`GrantRow` equality / hashing is
        structural (frozen dataclass with slots). The
        ``previous - grants`` set difference yields every row whose
        ``(plugin_id, subscriber_tier, hookpoint, content_tier,
        proposal_branch)`` tuple disappeared from the new snapshot.
        The backend's revoke SQL keys on
        ``(plugin_id, hookpoint, subscriber_tier)`` so a row whose
        ``content_tier`` or ``proposal_branch`` changed (but key didn't)
        is a revoke-then-upsert — the upsert recreates it with the new
        payload inside the same transaction. That's the correct
        semantics: a content-tier widening is a separate reviewer
        decision from the original grant, and the Postgres row should
        reflect the latest approved shape.

        Raises:
            sqlalchemy.exc.SQLAlchemyError: Re-raised from the backend
                after the rollback audit row is emitted. The
                in-memory policy is NOT swapped on this path.
        """
        previous_grants = self._policy.grants
        revoked = previous_grants - grants
        try:
            await self._backend.apply_atomic(
                revokes=revoked,
                upserts=grants,
                commit_hash=commit_hash,
            )
        except SQLAlchemyError as exc:
            # err-003: a partial-failure rebuild MUST surface in the audit
            # log. The previous shape emitted ``result="success"`` only on
            # the happy path — a rollback after revoke 1 succeeded but
            # revoke 2 raised left no audit signal at all. We capture
            # ``type(exc).__name__`` only (spec §5.6: never persist
            # ``str(exc)`` / ``exc.args`` because they may carry T3
            # content fragments). The full success row continues to emit
            # from :meth:`rebuild_from_state_git` after this method returns.
            #
            # CR-149 round-6: reuse the caller-supplied correlation_id
            # (or mint one) for both the audit row and the structlog
            # warning so the two streams join on a single identifier.
            # Without this, an incident investigator who finds the
            # structlog warning could not jump to the matching
            # ``plugin.grant.rebuilt`` row (and vice versa) — the
            # trust-boundary forensic bridge would silently break.
            rollback_correlation_id = correlation_id or str(uuid.uuid4())
            await self._emit_rebuild_rolled_back_audit(
                commit_hash=commit_hash,
                grant_count=len(grants),
                correlation_id=rollback_correlation_id,
            )
            _log.warning(
                "capability_gate.rebuild.rolled_back",
                grant_count=len(grants),
                revoked_count=len(revoked),
                commit_hash=commit_hash,
                backing_store_error_type=type(exc).__name__,
                correlation_id=rollback_correlation_id,
            )
            raise

        # Atomic policy swap (single-threaded asyncio event loop). The
        # frozen :class:`GatePolicy` semantics mean any hot-path check
        # mid-flight sees either the old or new snapshot — never a
        # half-mutated state. The swap runs ONLY after ``apply_atomic``
        # committed, so a rollback leaves the previous policy
        # authoritative.
        self._policy = GatePolicy(grants=grants)
        # CR-149 round-6: emit the success log with the caller-supplied
        # correlation_id so it joins to the matching ``plugin.grant.rebuilt``
        # audit row. Stale call sites (the integration tests that drive
        # ``_apply_grants`` directly) pass ``None``; the
        # ``structlog`` key remains present with the explicit ``None``
        # so the schema stays uniform across call sites and a log-
        # grepping consumer can distinguish "no rebuild correlation
        # assigned" from "field accidentally dropped".
        _log.info(
            "capability_gate.rebuild.complete",
            grant_count=len(grants),
            revoked_count=len(revoked),
            commit_hash=commit_hash,
            correlation_id=correlation_id,
        )

    async def _emit_rebuild_success_audit(
        self,
        *,
        commit_hash: str,
        grant_count: int,
        correlation_id: str,
    ) -> None:
        """Emit one ``plugin.grant.rebuilt`` row with ``result="success"``.

        CR-149 round-6: extracted from :meth:`rebuild_from_state_git`
        so the success arm and the rollback arm share the same audit
        emit shape (subject keys, ``trust_tier_of_trigger``, ``trace_id``).
        The caller passes ``correlation_id`` rather than minting it
        locally so the structlog stream and the audit row join on a
        single identifier — same forensic-joinability contract as the
        rollback path documents.
        """
        await self._audit_sink.append_schema(
            fields=CAPABILITY_GATE_REBUILD_FIELDS,
            schema_name="CAPABILITY_GATE_REBUILD_FIELDS",
            event="plugin.grant.rebuilt",
            actor_user_id=None,
            subject={
                "commit_hash": commit_hash,
                "grant_count": grant_count,
                "trust_tier_of_trigger": "T0",
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result="success",
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )

    # ------------------------------------------------------------------
    # Heartbeat / fail-closed machinery (spec §8.1, Tasks 9-10)
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        """Background task: ping the backing store and track outage state.

        Spec §8.1: every ``_HEARTBEAT_INTERVAL_SECONDS`` (10 s), call
        :meth:`StorageBackend.ping`. On success, the miss counter resets;
        if we were fail-closed, emit the ``exiting_fail_closed`` audit
        row and re-open the gate. On failure, the miss counter
        increments; once it reaches ``_MAX_MISSED_HEARTBEATS`` (6 misses
        ≡ 60 s window) and we are not already fail-closed, emit the
        ``entering_fail_closed`` audit row and trip the flag.

        The loop runs forever and only exits on :class:`asyncio.CancelledError`
        (from :meth:`stop_heartbeat`). All other exceptions on the ping
        path are treated as backing-store failures — CLAUDE.md hard rule
        #7 forbids silent broken-pipe states. We capture
        ``type(exc).__name__`` only (spec §5.6: never persist
        ``str(exc)`` / ``exc.args`` because they may carry T3 content
        fragments).
        """
        while True:
            try:
                await self._backend.ping()
            except asyncio.CancelledError:
                # Cooperative shutdown: stop_heartbeat() cancelled us.
                raise
            except Exception as exc:
                error_type = type(exc).__name__
                self._missed_heartbeats += 1
                if self._missed_heartbeats >= _MAX_MISSED_HEARTBEATS and not self._fail_closed:
                    # CR-139 finding #3: flip fail-closed BEFORE awaiting
                    # the audit sink. If ``append_schema`` raises (the
                    # audit subsystem may itself be wedged on the same
                    # backing-store outage), the previous ordering left
                    # ``self._fail_closed`` False and the gate kept
                    # admitting dispatches — exactly the silent
                    # privilege-stay-open shape CLAUDE.md hard rule #7
                    # forbids. Setting the flag first guarantees every
                    # subsequent ``check*`` denies even if the audit
                    # path crashes the heartbeat loop.
                    self._fail_closed = True
                    await self._emit_gate_unavailable_audit(
                        state_transition="entering_fail_closed",
                        denied_dispatch_count=None,
                        backing_store_error_type=error_type,
                    )
            else:
                self._missed_heartbeats = 0
                if self._fail_closed:
                    # Recovery: emit the exiting row with the cumulative
                    # denied-dispatch count, then re-open the gate.
                    await self._emit_gate_unavailable_audit(
                        state_transition="exiting_fail_closed",
                        denied_dispatch_count=self._denied_dispatch_count,
                        backing_store_error_type=None,
                    )
                    self._fail_closed = False
                    self._denied_dispatch_count = 0
            await asyncio.sleep(_HEARTBEAT_INTERVAL_SECONDS)

    async def _emit_gate_unavailable_audit(
        self,
        *,
        state_transition: str,
        denied_dispatch_count: int | None,
        backing_store_error_type: str | None,
    ) -> None:
        """Emit one ``supervisor.capability_gate_unavailable`` audit row.

        Spec §8.1 / §8.5: a fail-closed state transition (entering OR
        exiting) MUST surface as an audit row. The ``subject`` dict is
        constructed against
        :data:`SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS` exactly —
        every declared key is present (``None`` where conditionally
        absent) so :meth:`AuditWriter.append_schema` symmetric
        validation passes.

        CLAUDE.md hard rule #7: this method does NOT swallow audit
        failures. If the sink raises, the heartbeat loop's
        exception-bare-handler does NOT catch it (this method is invoked
        outside the ``try/except`` around ``backend.ping()``); the loop
        crashes loudly. A future PR-S3 task can wire a supervisor-level
        crash-restart strategy, but the silent path is forbidden.
        """
        correlation_id = str(uuid.uuid4())
        await self._audit_sink.append_schema(
            fields=SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS,
            schema_name="SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS",
            event="supervisor.capability_gate_unavailable",
            actor_user_id=None,
            subject={
                "state_transition": state_transition,
                "denied_dispatch_count": denied_dispatch_count,
                "backing_store_error_type": backing_store_error_type,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result="success",
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )
        _log.warning(
            "capability_gate.unavailable",
            state_transition=state_transition,
            denied_dispatch_count=denied_dispatch_count,
            backing_store_error_type=backing_store_error_type,
        )

    async def _emit_rebuild_rolled_back_audit(
        self,
        *,
        commit_hash: str,
        grant_count: int,
        correlation_id: str,
    ) -> None:
        """Emit one ``plugin.grant.rebuilt`` row with ``result="rolled_back"``.

        Shared between the :meth:`_apply_grants` SQL-error rollback arm
        and the :meth:`rebuild_from_state_git` parser-failure arm
        (CR-149 round-3). Both surfaces represent the same forensic
        contract: a privileged rebuild attempt failed before the
        in-memory snapshot was swapped, and the audit graph MUST carry
        a row pinning that failure (CLAUDE.md hard rule #7 — no silent
        failures in security paths).

        Spec §5.6: the failing exception's class name is captured by
        each caller's adjacent structured log line — never copied into
        the audit row, because the ``CAPABILITY_GATE_REBUILD_FIELDS``
        schema is symmetric-strict and would reject extra subject keys.
        Operators correlate via ``correlation_id`` / ``trace_id``: the
        audit row and the structured log share the same UUID.

        CR-149 round-6: ``correlation_id`` is now a REQUIRED kwarg
        rather than locally minted. The caller mints the id and
        reuses it for the adjacent ``_log.warning`` so the audit
        stream and the structlog stream join on a single identifier.
        """
        await self._audit_sink.append_schema(
            fields=CAPABILITY_GATE_REBUILD_FIELDS,
            schema_name="CAPABILITY_GATE_REBUILD_FIELDS",
            event="plugin.grant.rebuilt",
            actor_user_id=None,
            subject={
                "commit_hash": commit_hash,
                "grant_count": grant_count,
                "trust_tier_of_trigger": "T0",
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result="rolled_back",
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )

    def stop_heartbeat(self) -> None:
        """Cancel the heartbeat task. Safe to call when no task is running.

        Tests that opt in to ``start_heartbeat=True`` MUST call this in a
        ``finally`` block; without cancellation the task lingers across
        tests and asyncio warns about unawaited coroutines. Production
        bootstrap calls this during graceful shutdown.
        """
        task = self._heartbeat_task
        if task is not None and not task.done():
            task.cancel()

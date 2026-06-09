"""``PolicyWatcher`` — mtime-polled hot-reload for ``config/policies.yaml``.

ADR-0023, #159. The watcher is the ONLY reader of ``config/policies.yaml`` at
runtime. It polls ``(mtime, size)`` at ``poll_interval`` (default 1 s); on a
change it loads (TOCTOU-safe), parses, validates, computes the canonical SHA,
and — if the SHA differs from the active snapshot and no high-blast key moved —
swaps the :class:`PoliciesSnapshotRef` via audit-then-swap. Every other
subsystem reads the active policy through ``ref.current()``; nobody else opens
the file.

Idempotency (sec-007): the **watcher-side SHA short-circuit** is the entire
idempotency mechanism. There is no ``AuditWriter.dedupe_surface`` (it does not
exist and must not be invented). A transient error that re-observes the same
file content collapses to a no-op before ``swap()`` is reached.

Rejection durability (sec-2): on a REJECT the ``(mtime, size)`` cache is NOT
updated, so the watcher re-emits the same rejection every tick until the
operator fixes the file — operators see a sustained signal, not a one-shot.

stale-snapshot-for-one-iteration invariant (arch-004): see
:mod:`alfred.policies.snapshot_ref`.

Latency budget (perf-001): ``_tick`` offloads the synchronous stat + read +
parse + validate to ``asyncio.to_thread`` so the event loop is never blocked by
disk I/O; the async swap (audit write) runs back on the loop.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal, Protocol, assert_never

import structlog
import yaml
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from alfred.audit.audit_row_schemas import CONFIG_RELOAD_REJECTED_FIELDS
from alfred.i18n import t
from alfred.policies.load import (
    MAX_POLICIES_BYTES,
    PolicyFileTooLarge,
    canonical_bytes,
    compute_sha256,
    load_yaml_bytes,
    parse_policies,
)
from alfred.policies.model import LOW_BLAST_ALLOWLIST, PoliciesV1
from alfred.policies.snapshot_ref import (
    PoliciesSnapshot,
    PoliciesSnapshotRef,
    PolicySnapshotHistoryWriter,
    _diff_keys,
)

_STAT_FAILURE_DEGRADED_THRESHOLD: Final[int] = 3
_STAT_RECOVERY_THRESHOLD: Final[int] = 3
_DEGRADED_BACKOFF_MULTIPLIER: Final[int] = 10

_LOG = structlog.get_logger("alfred.policies.watcher")

RejectReason = Literal[
    "parse_failure",
    "high_blast_change",
    "validation_failure",
    "file_vanished",
    "stat_failed",
    "audit_write_failed",
]


def _reject_message(reason: RejectReason, *, offending_key: str) -> str:
    """Return the operator-facing rejection string for ``reason`` (rev-002).

    Every branch is an explicit ``t("...")`` literal so the i18n extractor and
    the ``test_t_keys_invoked`` AST guard both see the catalog key at this call
    site (a dict-indexed ``t(dynamic_key)`` would be invisible to both).
    """
    match reason:
        case "parse_failure":
            return t("supervisor.config_reload.rejected.parse_failure", detail=offending_key)
        case "high_blast_change":
            return t("supervisor.config_reload.rejected.high_blast_change", key=offending_key)
        case "validation_failure":
            return t("supervisor.config_reload.rejected.validation_failure", detail=offending_key)
        case "file_vanished":
            return t("supervisor.config_reload.rejected.file_vanished")
        case "stat_failed":
            return t("supervisor.config_reload.rejected.stat_failed", detail=offending_key)
        case "audit_write_failed":
            return t("supervisor.config_reload.rejected.audit_write_failed", detail=offending_key)
        case _:  # pragma: no cover - closed-union exhaustiveness backstop
            assert_never(reason)


def _fallback_jsonl_path() -> Path:
    """Return the sec-4 fallback sink path (overridable in tests)."""
    return Path.home() / ".local" / "state" / "alfred" / "policies-rejected-fallback.jsonl"


class _AuditWriterLike(Protocol):
    async def append_schema(
        self,
        *,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        actor_user_id: str | None,
        subject: dict[str, Any],
        trust_tier_of_trigger: str,
        result: str,
        cost_estimate_usd: float,
        trace_id: str,
    ) -> None: ...


class _HistoryWriterLike(Protocol):
    async def append(
        self,
        snapshot: PoliciesSnapshot,
        *,
        applied_at: datetime,
        operator_session_id: str | None,
        swapped_from_snapshot_id: str | None = ...,
    ) -> str: ...


# Default hookpoint invoker — wraps the real ``invoke`` with the canonical T0
# ``post`` dispatch shape (mirrors ``alfred.cli.daemon._commands._invoke_*``).
async def _default_invoke(name: str, payload: dict[str, Any]) -> None:
    import uuid

    from alfred.hooks import SYSTEM_ONLY_TIERS
    from alfred.hooks.context import HookContext
    from alfred.hooks.invoke import invoke

    correlation_id = str(uuid.uuid4())
    ctx: HookContext[dict[str, object]] = HookContext(
        action_id=name,
        hookpoint=name,
        input={**payload, "correlation_id": correlation_id},
        correlation_id=correlation_id,
        kind="post",
    )
    await invoke(
        name,
        ctx,
        kind="post",
        subscribable_tiers=SYSTEM_ONLY_TIERS,
        fail_closed=True,
    )


@dataclass(frozen=True, slots=True)
class _LoadOutcome:
    """Result of the sync load+parse leg (runs in a worker thread)."""

    model: PoliciesV1 | None
    new_sha: str | None
    reject_reason: RejectReason | None
    offending_key: str | None
    mtime: float


def declare_hookpoints(registry: object | None = None) -> None:
    """Register the watcher's hookpoints (carrier_tier=T0, fail_closed=True).

    Mirrors the ``declare_hookpoints`` pattern used by
    :mod:`alfred.security.quarantine` / :mod:`alfred.memory.episodic`. All
    hookpoints are system-internal operational signals — none carries operator
    or untrusted content, so ``T0`` is the correct carrier-tier upper bound.

    Args:
        registry: Optional :class:`alfred.hooks.registry.HookRegistry` override
            for tests; defaults to the process singleton.
    """
    from alfred.hooks import SYSTEM_ONLY_TIERS, get_registry
    from alfred.security.tiers import T0

    target = registry if registry is not None else get_registry()
    for name in (
        "supervisor.config_reload",
        "supervisor.config_reload_rejected",
        "supervisor.config_watcher.recovered",
        "supervisor.config_watcher.degraded",
        "policies.watcher.degraded",
    ):
        target.register_hookpoint(  # type: ignore[attr-defined]
            name=name,
            subscribable_tiers=SYSTEM_ONLY_TIERS,
            refusable_tiers=frozenset(),
            fail_closed=True,
            carrier_tier=T0,
        )


class PolicyWatcher:
    """Polls ``config/policies.yaml`` and swaps the snapshot ref on change."""

    def __init__(
        self,
        *,
        config_path: Path,
        snapshot_ref: PoliciesSnapshotRef,
        audit_writer: _AuditWriterLike,
        poll_interval: float = 1.0,
        invoke_fn: Callable[[str, dict[str, Any]], Awaitable[None]] = _default_invoke,
        history_writer: _HistoryWriterLike | None = None,
        operator_session_id: str | None = None,
    ) -> None:
        self._path = config_path
        self._ref = snapshot_ref
        self._audit = audit_writer
        self._interval = poll_interval
        self._invoke = invoke_fn
        self._history = history_writer
        self._operator_session_id = operator_session_id
        # Nanosecond mtime (perf-005 / CR round-3): ``st_mtime`` is second-
        # resolution on some filesystems, so a same-second + same-size edit
        # (e.g. an operator rewriting the file twice within one second to the
        # same byte length) would be a false-negative on a ``(st_mtime, size)``
        # gate. ``st_mtime_ns`` closes most of that hole cheaply. The residual
        # window (a same-NANOSECOND edit that also keeps the byte length
        # identical) is astronomically unlikely, and the watcher-side SHA
        # short-circuit (sec-007) catches it on the NEXT genuine change anyway.
        self._cached_mtime_size: tuple[int, int] | None = None
        self._stat_failures = 0
        self._stat_successes = 0
        self._state: Literal["normal", "degraded"] = "normal"
        # perf-S4-4-5: the (reason, attempted_sha256) of the last fallback line
        # written. A sustained audit-store outage re-emits the same rejection
        # every tick (sec-2); we append a fallback line only when this pair
        # changes, bounding growth to one line per distinct bad file.
        self._last_fallback_key: tuple[str, str | None] | None = None

    @property
    def state(self) -> Literal["normal", "degraded"]:
        return self._state

    async def run(self) -> None:
        """Poll forever. Performs an immediate tick BEFORE the first sleep (perf-003)."""
        while True:
            await self._tick()
            await asyncio.sleep(self._effective_interval())

    def _effective_interval(self) -> float:
        if self._state == "degraded":
            return self._interval * _DEGRADED_BACKOFF_MULTIPLIER
        return self._interval

    async def _tick(self) -> None:
        # Stat first; route stat errors before any read attempt. ``os.stat``
        # (not ``Path.stat``) keeps symmetry with the TOCTOU ``os.open`` +
        # ``os.fstat`` path in load.py and is the seam tests monkeypatch.
        try:
            st = os.stat(self._path)  # noqa: PTH116
        except FileNotFoundError:
            await self._reject(
                reason="file_vanished", attempted_sha=None, offending_key=str(self._path)
            )
            self._on_stat_failure_counters()
            await self._maybe_emit_degraded()
            return
        except OSError:
            await self._reject(
                reason="stat_failed", attempted_sha=None, offending_key="<filesystem>"
            )
            self._on_stat_failure_counters()
            await self._maybe_emit_degraded()
            return

        await self._on_stat_success()

        # Mtime gate (perf-005). Skip re-read on unchanged (mtime_ns, size).
        # ``st_mtime_ns`` (not ``st_mtime``) so a same-second, same-size edit on
        # a second-resolution filesystem is not a false-negative (CR round-3).
        new_pair = (st.st_mtime_ns, st.st_size)
        if self._cached_mtime_size == new_pair:
            return

        # Offload the synchronous load+parse+validate+hash to a worker thread
        # so the event loop never blocks on disk I/O (perf-001).
        outcome = await asyncio.to_thread(self._load_and_parse, st.st_mtime)

        if outcome.reject_reason is not None:
            await self._reject(
                reason=outcome.reject_reason,
                attempted_sha=outcome.new_sha,
                offending_key=outcome.offending_key or "<unknown>",
            )
            # sec-2: do NOT update the cache on reject — sustained signal.
            return

        assert outcome.model is not None and outcome.new_sha is not None

        # Single deref before any await (perf-S4-4-2): every read below uses
        # this local. There is no await between this deref and the swap, so the
        # snapshot cannot move out from under us mid-tick.
        active = self._ref.current()

        # Phase 0 — watcher-side SHA short-circuit (sec-007). No audit, no swap.
        if outcome.new_sha == active.file_sha256:
            self._cached_mtime_size = new_pair
            return

        # Allowlist diff — refuse hot-reload of any high-blast key (ADR-0023 §5
        # / sec-3 / arch-003). The changed-keys diff is computed once and reused
        # for the applied-message hint below.
        changed_keys = _diff_keys(active.policies, outcome.model)
        offending = next((k for k in changed_keys if k not in LOW_BLAST_ALLOWLIST), None)
        if offending is not None:
            await self._reject(
                reason="high_blast_change", attempted_sha=outcome.new_sha, offending_key=offending
            )
            return  # sec-2: no cache update.

        resolved_path = self._path.resolve()
        new_snapshot = PoliciesSnapshot(
            policies=outcome.model,
            loaded_at=datetime.now(UTC),
            file_mtime=st.st_mtime,
            file_sha256=outcome.new_sha,
            file_path=resolved_path,
        )
        prev_sha = active.file_sha256
        import uuid

        trace_id = str(uuid.uuid4())
        try:
            await self._ref.swap(
                new_snapshot,
                audit=self._audit,
                trace_id=trace_id,
                operator_session_id=self._operator_session_id,
            )
        except SQLAlchemyError:
            # err-010 / err-011 — TRANSIENT audit-write failure inside swap().
            # The ref aborted the assignment; emit the rejected row + fall back.
            # A wrong-shape append_schema (ValueError / TypeError /
            # ValidationError) is a programmer error and propagates loudly (it
            # is NOT reclassified as transient ``audit_write_failed``).
            await self._reject(
                reason="audit_write_failed",
                attempted_sha=outcome.new_sha,
                offending_key="<audit_store>",
            )
            return  # sec-2: no cache update so the swap retries next tick.

        # Optional forensic history row (sec-3). Best-effort: a history-write
        # failure does not unwind the already-committed swap, but is loud.
        if self._history is not None:
            try:
                await self._history.append(
                    new_snapshot,
                    applied_at=new_snapshot.loaded_at,
                    operator_session_id=self._operator_session_id,
                )
            except Exception:
                _LOG.warning("policies.watcher.history_write_failed", exc_info=True)

        # sec-2: cache moves AFTER a successful swap.
        self._cached_mtime_size = new_pair

        await self._invoke(
            "supervisor.config_reload",
            {
                "new_sha": new_snapshot.file_sha256,
                "prev_sha": prev_sha,
                "file_path": str(self._path),
                "message": t(
                    "supervisor.config_reload.applied",
                    changed_keys=", ".join(changed_keys) or "<none>",
                ),
            },
        )

    def _load_and_parse(self, mtime: float) -> _LoadOutcome:
        """Synchronous load+parse leg (runs in a worker thread; perf-001)."""
        try:
            raw = load_yaml_bytes(self._path, max_size=MAX_POLICIES_BYTES)
        except FileNotFoundError:
            return _LoadOutcome(None, None, "file_vanished", str(self._path), mtime)
        except (PolicyFileTooLarge, ValueError):
            return _LoadOutcome(None, None, "parse_failure", "<yaml_load>", mtime)
        except OSError:  # pragma: no cover — TOCTOU race: _tick stat()'d the
            # file successfully just before this load; an OSError here is a
            # rare swap-between-stat-and-open. Routed to stat_failed defensively.
            return _LoadOutcome(None, None, "stat_failed", "<filesystem>", mtime)

        try:
            model = parse_policies(raw, max_size_bytes=MAX_POLICIES_BYTES)
        except yaml.YAMLError:
            return _LoadOutcome(None, None, "parse_failure", "<yaml_parse>", mtime)
        except ValidationError as exc:
            return _LoadOutcome(None, None, "validation_failure", _first_error_key(exc), mtime)
        except PolicyFileTooLarge:  # pragma: no cover — defensive: load_yaml_bytes
            # already capped at MAX_POLICIES_BYTES, so parse_policies' re-check
            # cannot fire for bytes that came through the loader.
            return _LoadOutcome(None, None, "parse_failure", "<yaml_load>", mtime)

        new_sha = compute_sha256(canonical_bytes(model))
        return _LoadOutcome(model, new_sha, None, None, mtime)

    async def _reject(
        self,
        *,
        reason: RejectReason,
        attempted_sha: str | None,
        offending_key: str,
    ) -> None:
        import uuid

        subject = {
            "file_path": str(self._path),
            "attempted_sha256": attempted_sha,
            "reason": reason,
            "offending_key": offending_key,
            "dlp_scan_result": "n_a",
            "operator_session_id": self._operator_session_id,
        }
        # Operator-facing string (rev-002): route the reason through t().
        message = _reject_message(reason, offending_key=offending_key)
        try:
            await self._audit.append_schema(
                fields=CONFIG_RELOAD_REJECTED_FIELDS,
                schema_name="CONFIG_RELOAD_REJECTED_FIELDS",
                event="config.reload.rejected",
                actor_user_id=None,
                subject=subject,
                trust_tier_of_trigger="T0",
                result="refused",
                cost_estimate_usd=0.0,
                trace_id=str(uuid.uuid4()),
            )
        except SQLAlchemyError:
            # sec-4: the audit store is unwritable. Do NOT swallow the
            # rejection — log critically, append to a fallback JSONL sink, and
            # surface the degraded state to operators via a hookpoint. The
            # watcher continues; the rejection is not lost. ValueError /
            # TypeError (key-validation / programming errors) are NOT caught —
            # they propagate as loud bugs (gap #2).
            _LOG.critical("policies.watcher.audit_write_failed", reason=reason, exc_info=True)
            self._append_fallback_jsonl(subject)
            await self._invoke(
                "policies.watcher.degraded",
                {"reason": "audit_log_unwritable", "message": message},
            )
            return

        await self._invoke(
            "supervisor.config_reload_rejected",
            {"reason": reason, "file_path": str(self._path), "message": message},
        )

    def _append_fallback_jsonl(self, subject: dict[str, Any]) -> None:
        """Append one fallback-sink line, deduped and crash-safe (sec-4).

        perf-S4-4-5: a sustained audit-store outage re-emits the same rejection
        every tick (sec-2). We append a line only when the
        ``(reason, attempted_sha256)`` pair differs from the last one written,
        bounding the file to one line per distinct bad file instead of ~86k
        lines/day.

        err-S4-4-3: the fallback sink is the LAST line of defence — both the
        audit store and this sink being down must NOT kill the watcher. A full /
        read-only / permission-denied state dir raises ``OSError`` from
        ``mkdir`` / ``open`` / ``write``; we log critically and continue rather
        than let it propagate out of ``run()``'s loop (CLAUDE.md hard rule 7:
        loud, never silent — but the watcher survives a sink failure).
        """
        dedup_key = (str(subject.get("reason")), subject.get("attempted_sha256"))
        if dedup_key == self._last_fallback_key:
            return
        path = _fallback_jsonl_path()
        line = json.dumps({"emitted_at": datetime.now(UTC).isoformat(), **subject})
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            _LOG.critical(
                "policies.watcher.fallback_write_failed",
                message=t("policies.watcher.fallback_write_failed", path=str(path)),
                exc_info=True,
            )
            return
        # Only advance the dedup cursor on a SUCCESSFUL write so a failed write
        # is retried (and re-logged) on the next tick rather than suppressed.
        self._last_fallback_key = dedup_key

    def _on_stat_failure_counters(self) -> None:
        self._stat_failures += 1
        self._stat_successes = 0

    async def _maybe_emit_degraded(self) -> None:
        if self._stat_failures >= _STAT_FAILURE_DEGRADED_THRESHOLD and self._state == "normal":
            self._state = "degraded"
            _LOG.warning(
                "supervisor.config_watcher.degraded",
                message=t("supervisor.config_watcher.degraded", reason="stat_failures"),
                failures=self._stat_failures,
            )
            await self._invoke(
                "supervisor.config_watcher.degraded",
                {"failures": self._stat_failures},
            )

    async def _on_stat_success(self) -> None:
        self._stat_failures = 0
        self._stat_successes += 1
        if self._state == "degraded" and self._stat_successes >= _STAT_RECOVERY_THRESHOLD:
            self._state = "normal"
            await self._invoke(
                "supervisor.config_watcher.recovered",
                {
                    "successes": self._stat_successes,
                    "message": t("supervisor.config_watcher.recovered"),
                },
            )

    @staticmethod
    def _high_blast_offending_key(prev: PoliciesV1, new: PoliciesV1) -> str | None:
        """Return the first changed HIGH-BLAST dotted key, or None if all changes are low-blast.

        Default-refuse, allowlist-permit (ADR-0023 §5 / closure arch-003): a
        changed key hot-reloads ONLY when its dotted path is in
        :data:`LOW_BLAST_ALLOWLIST`. EVERY other changed key — ``rate_limits.*``,
        ``handle_caps.*``, ``high_blast.*`` — is high-blast and refuses
        hot-reload. The allowlist is currently empty, so any change to a
        modelled field refuses. This is intentionally NOT a high-blast denylist:
        an allowlist defaults a future field to refuse rather than silently
        permitting it.

        ``_diff_keys`` does a frozen-Pydantic ``==`` short-circuit per top-level
        field (perf-002), descending into a sub-model only when it differs.
        """
        for key in _diff_keys(prev, new):
            if key not in LOW_BLAST_ALLOWLIST:
                return key
        return None


def _first_error_key(exc: ValidationError) -> str:
    errs = exc.errors()
    if not errs:
        return "<unknown>"
    return ".".join(str(part) for part in errs[0]["loc"])


# Module-bottom declaration — mirrors quarantine.py / episodic.py so the
# hookpoints are declared at import time before any subscriber or dispatch.
declare_hookpoints()


__all__ = ["PolicySnapshotHistoryWriter", "PolicyWatcher", "declare_hookpoints"]

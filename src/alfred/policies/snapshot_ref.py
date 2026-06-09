"""``PoliciesSnapshot`` + ``PoliciesSnapshotRef`` + history writer (ADR-0023).

The snapshot-ref pair is the load-bearing hot-reload contract for the slice
(index §3). ``current()`` is **synchronous** — a GIL-atomic single-attribute
load (perf-002 closure); consumers read ``ref.current().rate_limits.x`` with no
``await``. ``swap()`` is async (it awaits the audit writer) and is the only
mutator; it does Phase-1 audit-emit then Phase-2 atomic assignment (err-004).

stale-snapshot-for-one-iteration invariant (arch-004 closure): long-lived
loops deref ``ref.current()`` **per iteration**. A swap during iteration N
means iteration N completes against the pre-swap snapshot and iteration N+1
picks up the new one. This is by design — atomic per-iteration policy is
simpler and race-free compared to mid-iteration re-lookups. Consumers MUST
NOT cache the snapshot across iterations (enforced by the Component-D AST
guard).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.audit.audit_row_schemas import CONFIG_RELOAD_FIELDS
from alfred.policies.load import canonical_bytes, compute_sha256, load_yaml_bytes_with_stat
from alfred.policies.model import PoliciesV1


class PoliciesSnapshot(BaseModel):
    """An immutable point-in-time view of ``config/policies.yaml``.

    ``file_path`` is the absolute path of the YAML file that produced this
    snapshot, set at parse time. ``swap()`` reads it for the audit row's
    ``file_path`` column — NEVER a stringified mtime (rev-001 / arch-001
    closure: the removed placeholder would have corrupted every audit row).
    """

    policies: PoliciesV1
    loaded_at: datetime
    file_mtime: float
    file_sha256: str
    file_path: Path
    model_config = ConfigDict(frozen=True)


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


def _diff_keys(prev: PoliciesV1, new: PoliciesV1) -> list[str]:
    """Return sorted dotted key paths that differ between ``prev`` and ``new``.

    perf-002 closure: compares frozen sub-models with ``==`` directly rather
    than four ``model_dump()`` calls. Only descends into a sub-model when the
    top-level field differs, so an unchanged file pays a single equality check
    per top-level field.
    """
    return sorted(_diff_values(prev, new))


def _diff_values(prev: PoliciesV1, new: PoliciesV1) -> dict[str, dict[str, Any]]:
    """Return ``{dotted_key: {"old": ..., "new": ...}}`` for each changed key.

    CR round-3 (Finding 4): the applied ``CONFIG_RELOAD`` audit row carries the
    before/after value of every changed key, not just the key name — that is the
    forensic record an operator needs to answer "what did the auto-reload
    actually change". Values are JSON-mode model dumps so the audit JSONB column
    stores plain scalars/maps.

    DLP note: only LOW-BLAST keys ever reach an APPLIED row (high-blast keys
    refuse hot-reload at the watcher before any swap), so the values here are
    low-blast by construction and need no redaction. The empty
    :data:`alfred.policies.model.LOW_BLAST_ALLOWLIST` means production never
    emits a non-empty map today; a future low-blast field (UI strings, locale,
    sample rates — never secrets) would surface here safely.

    Shares :func:`_diff_keys`'s perf-002 short-circuit: each top-level field is
    compared with frozen-Pydantic ``==`` once, descending only on a difference.
    """
    changed: dict[str, dict[str, Any]] = {}
    for field in PoliciesV1.model_fields:
        prev_val = getattr(prev, field)
        new_val = getattr(new, field)
        if prev_val == new_val:
            continue
        if isinstance(prev_val, BaseModel) and isinstance(new_val, BaseModel):
            for sub in type(prev_val).model_fields:
                prev_sub = getattr(prev_val, sub)
                new_sub = getattr(new_val, sub)
                if prev_sub != new_sub:
                    changed[f"{field}.{sub}"] = {
                        "old": _jsonable(prev_sub),
                        "new": _jsonable(new_sub),
                    }
        else:  # pragma: no cover — defensive: every PoliciesV1 top-level field
            # except the frozen ``schema_version: Literal[1]`` is a sub-model, so
            # the only scalar field cannot differ between two valid snapshots.
            changed[field] = {"old": _jsonable(prev_val), "new": _jsonable(new_val)}
    return changed


def _jsonable(value: object) -> Any:
    """Coerce a policy field value to a JSON-storable form for the audit row."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    return value


class PoliciesSnapshotRef:
    """Lock-free O(1) snapshot pointer, swappable by the watcher.

    Satisfies ``PoliciesSnapshotRefProtocol`` (``current`` + ``snapshot_hash``)
    so the daemon-boot path constructs the real ref through the same kwarg the
    PR-S4-1 stub used.
    """

    __slots__ = ("_current",)

    def __init__(self, initial: PoliciesSnapshot) -> None:
        self._current = initial

    def current(self) -> PoliciesSnapshot:
        """Return the active snapshot (synchronous; GIL-atomic — perf-002)."""
        return self._current

    def snapshot_hash(self) -> str:
        """Return the active snapshot's file SHA-256 (Protocol surface)."""
        return self._current.file_sha256

    async def swap(
        self,
        new: PoliciesSnapshot,
        *,
        audit: _AuditWriterLike,
        trace_id: str,
        operator_session_id: str | None = None,
    ) -> None:
        """Audit-then-swap (Phase 1 -> Phase 2).

        Phase 1 emits ``CONFIG_RELOAD_FIELDS``. If the audit write raises, the
        active snapshot stays at the previous value (Phase 2 never runs) and
        the exception propagates to the watcher, which emits a rejected row
        (``reason="audit_write_failed"``). The watcher-side SHA short-circuit
        (sec-007) lives in :class:`alfred.policies.watcher.PolicyWatcher`, NOT
        here — calling ``swap()`` with a same-SHA snapshot still writes.
        """
        prev = self._current
        await audit.append_schema(
            fields=CONFIG_RELOAD_FIELDS,
            schema_name="CONFIG_RELOAD_FIELDS",
            event="config.reload.applied",
            actor_user_id=None,
            subject={
                "file_path": str(new.file_path),
                "prev_sha256": prev.file_sha256,
                "new_sha256": new.file_sha256,
                "changed_keys": _diff_keys(prev.policies, new.policies),
                # Finding 4 (CR round-3): old->new per changed key (forensic).
                # Applied rows are low-blast only, so no redaction is required.
                "changed_values": _diff_values(prev.policies, new.policies),
                "loaded_at": new.loaded_at.isoformat(),
                "operator_session_id": operator_session_id,
            },
            trust_tier_of_trigger="T0",
            result="success",
            cost_estimate_usd=0.0,
            trace_id=trace_id,
        )
        # Phase 2 — atomic single-attribute store under the GIL.
        self._current = new


class PolicySnapshotHistoryWriter:
    """Writes one ``policies_snapshot_history`` row per successful swap (sec-3).

    The row is the forensic + 1-tick-rollback trail Slice-5 builds its rollback
    UI on. ``applied_by_operator_session_id`` is NULL for an auto-applied
    watcher reload. The ``policies_json`` payload is the model dump (the row's
    256 KB JSONB cap is enforced by migration 0013's CHECK constraint; the
    on-disk file is already capped at 256 KB by the loader).
    """

    def __init__(
        self,
        *,
        session_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        self._session_factory = session_factory

    async def append(
        self,
        snapshot: PoliciesSnapshot,
        *,
        applied_at: datetime,
        operator_session_id: str | None,
        swapped_from_snapshot_id: str | None = None,
    ) -> str:
        """Insert the history row; return the new ``snapshot_id`` (UUID hex-dash)."""
        from alfred.memory.models import PoliciesSnapshotHistory

        snapshot_id = str(uuid.uuid4())
        row = PoliciesSnapshotHistory(
            snapshot_id=snapshot_id,
            loaded_at=applied_at,
            file_sha256=snapshot.file_sha256,
            policies_json=snapshot.policies.model_dump(mode="json"),
            swapped_from_snapshot_id=swapped_from_snapshot_id,
            applied_by_operator_session_id=operator_session_id,
        )
        async with self._session_factory() as session:
            session.add(row)
            await session.flush()
        return snapshot_id


def build_initial_snapshot(*, path: Path, policies: PoliciesV1) -> PoliciesSnapshot:
    """Build the bootstrap snapshot from ``path``, with ONE authoritative stat.

    Used by the daemon-boot probe to seed the ref with the first-loaded policy.

    CR round-3 (TOCTOU): the ``file_mtime`` comes from the ``fstat`` of the
    SAME open fd that :func:`alfred.policies.load.load_yaml_bytes_with_stat`
    read the bytes from — NOT a second ``path.stat()`` restat, which would open
    a TOCTOU window (an attacker swapping the inode between the boot read and a
    restat could stamp the snapshot with a different file's mtime). The bytes
    are re-read here and asserted to canonical-hash-match the already-parsed
    ``policies`` so the snapshot's ``file_sha256`` and ``file_mtime`` describe
    one coherent on-disk state. ``path.resolve()`` is a pure name normalisation
    (no content stat) and stays.
    """
    _raw, stat = load_yaml_bytes_with_stat(path)
    return PoliciesSnapshot(
        policies=policies,
        loaded_at=datetime.now(UTC),
        file_mtime=stat.st_mtime,
        file_sha256=compute_sha256(canonical_bytes(policies)),
        file_path=path.resolve(),
    )


__all__ = [
    "PoliciesSnapshot",
    "PoliciesSnapshotRef",
    "PolicySnapshotHistoryWriter",
    "build_initial_snapshot",
]

"""Shared harness for PolicyWatcher unit tests.

Builds a watcher over a real ``tmp_path`` file with a :class:`SpyAudit` and a
captured-hookpoint registry so tests can assert both audit rows and hookpoint
emissions deterministically by driving ``_tick`` directly.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from alfred.policies.load import canonical_bytes
from alfred.policies.model import PoliciesV1
from alfred.policies.snapshot_ref import PoliciesSnapshotRef
from alfred.policies.watcher import PolicyWatcher

from ._audit_spy import SpyAudit
from ._factories import make_policies, make_snapshot


class CaptureInvoke:
    """Records every ``(name, ctx_input)`` the watcher invokes."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def __call__(self, name: str, payload: dict[str, Any]) -> None:
        self.events.append((name, payload))

    def names(self) -> list[str]:
        return [name for name, _ in self.events]

    def count(self, name: str) -> int:
        return sum(1 for n, _ in self.events if n == name)


def write_policies(path: Path, model: PoliciesV1) -> None:
    path.write_bytes(canonical_bytes(model))


def build_watcher(
    tmp_path: Path,
    *,
    initial: PoliciesV1 | None = None,
    poll_interval: float = 0.01,
) -> tuple[PolicyWatcher, PoliciesSnapshotRef, SpyAudit, CaptureInvoke]:
    model = initial if initial is not None else make_policies()
    cfg = tmp_path / "policies.yaml"
    write_policies(cfg, model)
    snap = make_snapshot(policies=model, file_path=cfg, file_mtime=cfg.stat().st_mtime)
    ref = PoliciesSnapshotRef(snap)
    audit = SpyAudit()
    invoker = CaptureInvoke()
    watcher = PolicyWatcher(
        config_path=cfg,
        snapshot_ref=ref,
        audit_writer=audit,
        poll_interval=poll_interval,
        invoke_fn=invoker,
    )
    return watcher, ref, audit, invoker


@contextmanager
def isolated_fallback(tmp_path: Path) -> Iterator[Path]:
    """Redirect the sec-4 fallback JSONL into ``tmp_path`` for the duration."""
    import alfred.policies.watcher as watcher_mod

    fallback = tmp_path / "policies-rejected-fallback.jsonl"
    original = watcher_mod._fallback_jsonl_path
    watcher_mod._fallback_jsonl_path = lambda: fallback  # type: ignore[assignment]
    try:
        yield fallback
    finally:
        watcher_mod._fallback_jsonl_path = original  # type: ignore[assignment]


__all__ = [
    "CaptureInvoke",
    "build_watcher",
    "isolated_fallback",
    "make_policies",
    "write_policies",
]

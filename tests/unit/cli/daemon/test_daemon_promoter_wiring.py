"""PR-S4-235-1: the daemon wires a per-adapter ``SubPayloadPromoter`` on inbound.

The #235 item-1 cut: the live daemon inbound path constructs + injects a
``SubPayloadPromoter`` keyed on the wire ``adapter_kind`` so a classifier-bearing
adapter (e.g. ``discord``) promotes T3 sub-payloads to content-handle refs BEFORE
the quarantined extractor sees them, while an empty-set kind (the reference plugin)
stays on the byte-for-byte-unchanged ``None``-promoter path.

These tests exercise three invariants hermetically (NO real Redis / subprocess):

* the per-adapter factory returns a configured promoter for a classifier-bearing
  kind and ``None`` for an empty-set kind;
* the daemon-owned ``ContentStore`` is constructed once and REAPED on the exit
  paths (the Redis-client analog of the bwrap-child reap — CR #255);
* a classifier-bearing kind that yields a ``None`` promoter REFUSES boot
  fail-closed (audited ``comms_promoter_misconfigured``, exit 2), mirroring the
  inbound M2 guard at boot rather than at first-message.

The end-to-end "promoted body reaches ``quarantined_extract`` carrying handle refs,
not raw bytes" proof ALREADY lives in
``tests/unit/comms_mcp/test_inbound_promotion_wiring.py``
(``test_orchestrator_never_sees_raw_subpayload_when_promoter_injected`` drives
``process_inbound_message`` with a REAL ``SubPayloadPromoter`` + a faked content
store and asserts the extract body carries only ``$content_handle_id`` refs) — so
this file deliberately does NOT re-prove it; it proves the daemon CONSTRUCTS and
INJECTS that promoter on the live boot path. The primitive itself + the M2 guard are
covered by ``test_sub_payload_promotion.py`` / ``test_inbound_handler_promoter.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.cli.daemon._comms_boot import _build_sub_payload_promoter
from alfred.comms_mcp.classifier_registry import REQUIRED_CLASSIFIERS_BY_KIND
from alfred.comms_mcp.sub_payload_promotion import SubPayloadPromoter
from alfred.hooks.registry import HookRegistry

from .conftest import FakeAuditWriter, FakeSupervisor
from .test_daemon_comms_spawn import (
    _ENABLED_ADAPTER,
    _patch_comms_seams,
    quarantine_registry,
)

__all__ = ["quarantine_registry"]  # re-exported fixture; silence the unused-import lint


class _StoreSpy:
    """Records ``close`` calls; satisfies the promoter's ``write`` contract loosely."""

    def __init__(self) -> None:
        self.close_calls = 0

    async def write(self, *, handle_id: str, body: bytes, source_url: str) -> object:
        raise AssertionError("the factory unit test never promotes a body")

    async def close(self) -> None:
        self.close_calls += 1


def test_factory_builds_promoter_for_classifier_bearing_kind() -> None:
    """A classifier-bearing kind (``discord``) -> a configured ``SubPayloadPromoter``."""
    # Guard the premise: discord IS classifier-bearing in the registry.
    assert REQUIRED_CLASSIFIERS_BY_KIND.get("discord")
    store = _StoreSpy()

    promoter = _build_sub_payload_promoter(adapter_kind="discord", content_store=store)

    assert isinstance(promoter, SubPayloadPromoter)


def test_factory_returns_none_for_empty_set_kind() -> None:
    """An empty-required-set kind (the reference plugin) -> ``None`` (inert promotion)."""
    # Guard the premise: the reference plugin kind has an EMPTY required set.
    assert REQUIRED_CLASSIFIERS_BY_KIND.get(_ENABLED_ADAPTER) == frozenset()
    store = _StoreSpy()

    promoter = _build_sub_payload_promoter(adapter_kind=_ENABLED_ADAPTER, content_store=store)

    assert promoter is None


def test_factory_fails_loud_on_unregistered_kind() -> None:
    """The promoter factory fails LOUD on an unregistered kind (#374 defence-in-depth).

    Post-#374 the factory reads ``REQUIRED_CLASSIFIERS_BY_KIND[adapter_kind]`` (a plain
    subscript, not ``.get(..., frozenset())``), so a kind the manifest chokepoint would
    already have refused — reachable only if a future caller bypasses that chokepoint —
    raises ``KeyError`` rather than silently masking the typo as an empty-classifier
    kind (a ``None`` promoter). The chokepoint (``_resolve_comms_adapter_wire_spec``) is
    the audited refusal; this subscript is the internal tripwire against drift.
    """
    store = _StoreSpy()
    with pytest.raises(KeyError):
        _build_sub_payload_promoter(adapter_kind="bogus_unregistered", content_store=store)


def test_enabled_empty_set_adapter_wires_none_promoter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """The reference (empty-set) adapter boots clean — its handler gets a ``None`` promoter.

    Proves PR-S4-235-1 keeps the ``alfred_comms_test`` path byte-for-byte unchanged:
    the empty-required-set kind still wires a ``None`` promoter (no misconfig refusal,
    a pump registered, exit 0).
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    captured: list[Any] = []
    from alfred.comms_mcp.handlers import InboundMessageHandler

    original_init = InboundMessageHandler.__init__

    def _spy_init(self: Any, **kwargs: Any) -> None:
        captured.append(kwargs.get("sub_payload_promoter"))
        original_init(self, **kwargs)

    monkeypatch.setattr(InboundMessageHandler, "__init__", _spy_init)
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    # Exactly one inbound handler built, wired with a None promoter (empty-set kind).
    assert captured == [None]
    sup = FakeSupervisor.last_instance
    assert sup is not None
    assert len(sup.registered_tasks) == 1


def test_boot_reaps_content_store_on_normal_shutdown(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """The daemon-owned ContentStore is REAPED on normal shutdown (CR #255).

    A leaked Redis client is the analog of a leaked bwrap child. The boot graph's
    ``aclose`` (in the daemon ``finally``) must close the process-lived ContentStore.
    Spy on ``ContentStore.close`` to prove it ran.
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    close_calls: list[int] = []
    from alfred.plugins.web_fetch.content_store import ContentStore

    original_close = ContentStore.close

    async def _spy_close(self: ContentStore) -> None:
        close_calls.append(1)
        await original_close(self)

    monkeypatch.setattr(ContentStore, "close", _spy_close)
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    # The store was reaped at least once on the normal-shutdown finally path.
    assert close_calls


def test_boot_reaps_content_store_when_post_spawn_step_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """A post-graph boot failure still REAPS the daemon-owned ContentStore (CR #255).

    Inject the failure at ``write_pidfile`` (after the graph built the store + the
    Supervisor constructed). The ``finally`` must still close the store.
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    close_calls: list[int] = []
    from alfred.plugins.web_fetch.content_store import ContentStore

    original_close = ContentStore.close

    async def _spy_close(self: ContentStore) -> None:
        close_calls.append(1)
        await original_close(self)

    monkeypatch.setattr(ContentStore, "close", _spy_close)

    def _boom(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("pidfile write failed (test)")

    monkeypatch.setattr("alfred.cli.daemon._commands.write_pidfile", _boom)
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code != 0
    assert close_calls


def test_boot_refuses_fail_closed_on_misconfigured_promoter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """A classifier-bearing kind yielding a ``None`` promoter -> refuse boot (exit 2).

    The boot-time mirror of the inbound M2 guard. Force the (deterministic) factory
    to return ``None`` for the enabled adapter AND make that adapter kind appear
    classifier-bearing, so the misconfig arm fires. Proves the daemon refuses
    fail-closed at boot with the distinct audited reason rather than parking a graph
    that would trip M2 on the first inbound message (CLAUDE.md hard rules #5 + #7).
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    # Make the enabled adapter kind look classifier-bearing for the boot assertion's
    # lookup, while the factory still hands back None (the structural-drift defect).
    from types import MappingProxyType

    drifted = MappingProxyType(
        {**dict(REQUIRED_CLASSIFIERS_BY_KIND), _ENABLED_ADAPTER: frozenset({"phantom"})}
    )
    # The boot assertion in ``_spawn_comms_adapter`` imports the table LAZILY from
    # its source module each call, so patch it at the SOURCE (not a stale binding on
    # ``_commands``).
    monkeypatch.setattr(
        "alfred.comms_mcp.classifier_registry.REQUIRED_CLASSIFIERS_BY_KIND", drifted
    )

    def _none_factory(*, adapter_kind: str, content_store: object) -> None:
        return None

    monkeypatch.setattr("alfred.cli.daemon._comms_boot._build_sub_payload_promoter", _none_factory)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2, result.output

    sup = FakeSupervisor.last_instance
    assert sup is not None
    # The pump was NEVER registered — fail-closed, not parked-with-misconfig.
    assert sup.registered_tasks == []
    rows = boot_success_env.rows_for("DAEMON_BOOT_FAILED_FIELDS")
    assert rows
    reasons = {r["subject"]["failure_reason"] for r in rows if isinstance(r["subject"], dict)}
    assert "comms_promoter_misconfigured" in reasons
    # No (lying) completion row — the refusal happened inside the spawn loop, BEFORE
    # the completion signal.
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []


@pytest.mark.asyncio
async def test_graph_aclose_skips_close_for_non_content_store() -> None:
    """``_CommsBootGraph.aclose`` only ``.close()``s a real ``ContentStore``.

    The reap's ``isinstance`` guard is defensive: a non-``ContentStore`` object on the
    graph (a test double / future seam) must close the transport but NOT attempt
    ``.close()`` on something that may not have it. This drives the False arm of that
    guard directly so the teardown contract is pinned, not just the production
    happy-path where the store is always a real ``ContentStore``.
    """
    from alfred.cli.daemon._comms_boot import _CommsBootGraph

    transport_closed: list[int] = []

    class _FakeTransport:
        async def close(self) -> None:
            transport_closed.append(1)

    not_a_store = _StoreSpy()  # has close(), but is NOT a ContentStore instance
    graph = _CommsBootGraph(
        secret_broker=object(),
        resolver_bridge=object(),
        extractor_bridge=object(),
        burst_limiter=object(),
        inbound_orchestrator=object(),  # type: ignore[arg-type]
        t3_nonce=object(),  # type: ignore[arg-type]
        quarantine_transport=_FakeTransport(),  # type: ignore[arg-type]
        content_store=not_a_store,
        idempotency_store=object(),  # type: ignore[arg-type]  # unused by aclose
        status_observer=object(),  # type: ignore[arg-type]  # unused by aclose
        credential_resolver=object(),  # type: ignore[arg-type]  # unused by aclose
        crash_incident_reconciler=object(),  # type: ignore[arg-type]  # unused by aclose
        forwarded_inbound_receiver=object(),  # type: ignore[arg-type]  # unused by aclose
    )

    await graph.aclose()

    # The transport was reaped; the non-ContentStore object's close() was NOT called
    # (the isinstance guard skipped it).
    assert transport_closed == [1]
    assert not_a_store.close_calls == 0


# These two run LAST: the supervisor-stop case boots fully (registers a pump) and
# the misconfig test above reads the shared FakeSupervisor.last_instance, so a
# full-boot test must not precede a last_instance reader (the #255 isolation quirk).
def test_boot_reaps_content_store_when_graph_assembly_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """Comms-graph assembly that raises AFTER the spawn still REAPS the ContentStore.

    Mirrors the bwrap-child reap on this path (CR #255): `_build_comms_boot_graph`'s
    post-spawn `except` closes BOTH the quarantine transport AND the ContentStore, so
    a constructor failure can't leak the Redis client.
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    close_calls: list[int] = []
    from alfred.plugins.web_fetch.content_store import ContentStore

    original_close = ContentStore.close

    async def _spy_close(self: ContentStore) -> None:
        close_calls.append(1)
        await original_close(self)

    monkeypatch.setattr(ContentStore, "close", _spy_close)
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    def _boom_recorder(**_kwargs: Any) -> object:
        raise RuntimeError("recorder construction failed (test)")

    monkeypatch.setattr("alfred.security.quarantine_transport.T3BodyRecorder", _boom_recorder)

    result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code != 0
    # The store was reaped in the graph-assembly except, despite the build failing.
    assert close_calls


def test_boot_reaps_content_store_when_supervisor_stop_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """A failing ``supervisor.stop()`` must NOT skip the ContentStore reap (CR #255).

    The daemon's `finally` isolates `supervisor.stop()` from the reap, so a stop()
    error can't leave the Redis client leaked. Mirrors the bwrap-child case.
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    close_calls: list[int] = []
    from alfred.plugins.web_fetch.content_store import ContentStore

    original_close = ContentStore.close

    async def _spy_close(self: ContentStore) -> None:
        close_calls.append(1)
        await original_close(self)

    monkeypatch.setattr(ContentStore, "close", _spy_close)
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    async def _boom_stop(_self: Any) -> None:
        raise RuntimeError("supervisor stop failed (test)")

    monkeypatch.setattr(FakeSupervisor, "stop", _boom_stop)

    result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code != 0
    # The store was reaped despite supervisor.stop() raising.
    assert close_calls

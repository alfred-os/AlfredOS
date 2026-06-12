"""PR-S4-11c-2a0: the daemon registers the authorised T3 nonce at boot.

``create_and_register_t3_nonce`` mints the per-process ``CapabilityGateNonce``
and installs it in the ``alfred.security.tiers._AUTHORIZED_T3_NONCE`` slot — but
no production process called it. So in a live ``alfred daemon`` the slot was
``None`` and EVERY authorised T3-tagging path was dead (``tag_t3_with_nonce``
raised). This suite proves the daemon boot path now mints + registers the nonce,
and threads the SAME object into the comms boot graph (the seam PR-S4-11c-2a's
``record_body`` will consume).

Reentrancy: every test that drives a boot hits ``create_and_register_t3_nonce``,
whose second call in a process raises ``T3NonceAlreadyRegisteredError`` (there is
no production reset API by design — CR-138 round-2 finding #4). The
``boot_success_env`` fixture cleans the slot for the duration of each boot test
(it now wraps the same lock-guarded reset the ``clean_t3_nonce_slot`` fixture
uses), so these tests neither poison each other nor leak a registered nonce into
the wider suite.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.security import tiers as _tiers
from alfred.security.quarantine import declare_hookpoints
from alfred.security.tiers import T3, TaggedContent, tag_t3_with_nonce
from tests.helpers.gates import make_quarantined_extract_chain_gate

from .conftest import FakeAuditWriter

_ENABLED_ADAPTER = "alfred_comms_test"


@pytest.fixture
def quarantine_registry() -> Iterator[HookRegistry]:
    """Install a scoped registry granting the system-tier DLP grant.

    The comms boot graph constructs a REAL ``QuarantinedExtractor`` which refuses
    to construct without an active post-stage DLP subscriber on the
    ``security.quarantined.extract`` chain. Mirrors ``test_daemon_comms_spawn``.
    """
    prior = get_registry()
    registry = HookRegistry(
        gate=make_quarantined_extract_chain_gate(),
        strict_declarations=False,
    )
    try:
        set_registry(registry)
        declare_hookpoints(registry)
        yield registry
    finally:
        set_registry(prior)


def test_boot_registers_authorized_t3_nonce(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    """After boot, the authorised T3 slot is non-None and is the booted nonce."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")

    assert _tiers._AUTHORIZED_T3_NONCE is None  # clean_t3_nonce_slot reset it

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    booted = _tiers._AUTHORIZED_T3_NONCE
    assert booted is not None

    # The registered nonce is the AUTHORISED one: tagging with it returns
    # TaggedContent[T3] (proves the slot the gate reads holds this object).
    tagged = tag_t3_with_nonce("x", source="comms-mcp://inbound", caller_token=booted)
    assert isinstance(tagged, TaggedContent)
    assert tagged.tier is T3
    assert tagged.content == "x"

    # A foreign nonce is still refused (the gate is identity-checked, not
    # weakened by registering one).
    from alfred.security.tiers import CapabilityGateNonce

    with pytest.raises(ValueError, match="tag_t3_unauthorized"):
        tag_t3_with_nonce("y", caller_token=CapabilityGateNonce())


def test_boot_threads_same_nonce_into_comms_graph(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[object],
) -> None:
    """The comms boot graph is handed the SAME nonce object registered at boot."""
    del quarantine_registry  # installed via fixture side effect
    del patch_quarantine_child_spawn  # in-proc fake child-IO; no real bwrap spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')

    # Capture the nonce threaded into the comms graph builder AND the graph it
    # returns (where 2b's record_body reads the nonce). The builder is now ASYNC
    # (PR-S4-11c-2b: it spawns the quarantined child), so the spy + delegation are
    # async.
    captured: list[object] = []
    built_graphs: list[object] = []
    from alfred.cli.daemon import _commands

    original = _commands._build_comms_boot_graph

    async def _spy(
        *, settings: object, audit: object, outbound_dlp: object, t3_nonce: object
    ) -> object:
        captured.append(t3_nonce)
        graph = await original(
            settings=settings,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            outbound_dlp=outbound_dlp,  # type: ignore[arg-type]
            t3_nonce=t3_nonce,  # type: ignore[arg-type]
        )
        built_graphs.append(graph)
        return graph

    monkeypatch.setattr(_commands, "_build_comms_boot_graph", _spy)
    # Avoid a real subprocess spawn: the spawn loop is exercised elsewhere.
    monkeypatch.setattr(_commands, "_spawn_comms_adapter", _make_async_noop_returning_none())

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    booted = _tiers._AUTHORIZED_T3_NONCE
    assert booted is not None
    assert len(captured) == 1
    # IDENTITY: the graph builder received the exact nonce registered in the
    # tiers slot — not a copy (a copy would fail the gate's ``is`` check).
    assert captured[0] is booted

    # And the graph carries it through to its field (where 2b's record_body reads it).
    assert len(built_graphs) == 1
    assert built_graphs[0].t3_nonce is booted  # type: ignore[attr-defined]


def test_boot_does_not_double_call_factory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    """A single boot calls the factory exactly once (no double-call self-poison)."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")

    from alfred.cli.daemon import _commands

    calls: list[int] = []
    original = _commands.create_and_register_t3_nonce

    def _counting() -> object:
        calls.append(1)
        return original()

    monkeypatch.setattr(_commands, "create_and_register_t3_nonce", _counting)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output
    assert sum(calls) == 1


def test_boot_refuses_when_nonce_already_registered(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    """A pre-registered slot -> fail-closed refusal (exit 2 + audited row).

    Production boots a fresh process so the slot is ``None``; a non-None slot at
    boot means something already minted a nonce (a re-entrant boot, a leaked
    test, a duplicate registration) — the daemon refuses fail-closed rather than
    parking with a slot it cannot own (CLAUDE.md hard rule #7).
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")

    # Pre-register a nonce so the boot path's factory call raises.
    from alfred.bootstrap.nonce_factory import _NONCE_LOCK
    from alfred.security.tiers import CapabilityGateNonce

    with _NONCE_LOCK:
        _tiers._set_authorized_t3_nonce(CapabilityGateNonce())

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2

    rows = boot_success_env.rows_for("DAEMON_BOOT_FAILED_FIELDS")
    assert rows
    reasons = {r["subject"]["failure_reason"] for r in rows if isinstance(r["subject"], dict)}
    assert "t3_nonce_registration_failed" in reasons
    # The completion row must NOT have been emitted (the refusal happened first).
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []


def _make_async_noop_returning_none() -> object:
    async def _f(**_kwargs: object) -> None:
        return None

    return _f

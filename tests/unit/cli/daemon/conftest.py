"""Shared fixtures for the daemon CLI unit tests (#174).

The success-path tests need every external dependency of ``start_daemon``
(audit writer, capability gate, session scope, state.git head reader,
operator resolver, Supervisor) replaced with in-memory fakes so the boot
sequence runs without Postgres / state.git / an event-loop-bound
supervisor.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest


class FakeAuditWriter:
    """Records every ``append_schema`` call for assertion."""

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def append_schema(self, **kw: Any) -> None:
        self.rows.append(kw)

    def rows_for(self, schema_name: str) -> list[dict[str, Any]]:
        return [r for r in self.rows if r.get("schema_name") == schema_name]


class FakeSupervisor:
    """No-op Supervisor double — records construction + lifecycle calls."""

    last_instance: FakeSupervisor | None = None

    def __init__(self, **kwargs: Any) -> None:
        import asyncio

        self.kwargs = kwargs
        self.started = False
        self.stopped = False
        # PR-S4-11b: every comms pump the boot path registers lands here so a
        # test can assert exactly how many supervised tasks were scheduled.
        self.registered_tasks: list[Any] = []
        # PR-S4-11b DEFECT 1: the boot path reads ``supervisor.shutdown_event``
        # to wire the comms runner's graceful-drain signal. Mirror the real
        # Supervisor's per-instance ``asyncio.Event`` accessor.
        self.shutdown_event = asyncio.Event()
        FakeSupervisor.last_instance = self

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    def register_plugin_task(self, coro: Any) -> Any:
        """Record + immediately close the coroutine (no event loop scheduling).

        The unit boot-wiring tests assert on the COUNT + identity of registered
        pumps, not their execution, so the coroutine is closed to avoid a
        "coroutine was never awaited" warning.
        """
        self.registered_tasks.append(coro)
        with suppress(AttributeError):
            coro.close()
        return coro


@pytest.fixture
def fake_audit_writer() -> FakeAuditWriter:
    return FakeAuditWriter()


def apply_boot_success_patches(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    audit_writer: FakeAuditWriter,
) -> Callable[[], None]:
    """Patch every external builder so the boot success path runs in-memory.

    The reusable body behind the :func:`boot_success_env` fixture — exposed
    as a plain function so OTHER suites (the ``cap-2026-001`` adversarial
    corpus entry, which lives outside this conftest's package and cannot see
    the fixture) drive the SAME in-memory boot setup without duplicating it.
    There is one source of truth for "what a daemon-boot-success harness
    patches".

    Returns a restore callable the caller MUST invoke at teardown to restore
    the process registry singleton the boot path installs via
    ``set_registry`` (otherwise the boot registry leaks into sibling tests),
    AND to restore the authorised-T3-nonce slot.

    PR-S4-11c-2a0: the boot path now mints + registers the per-process
    authorised T3 nonce via ``create_and_register_t3_nonce`` (slot
    ``alfred.security.tiers._AUTHORIZED_T3_NONCE``). The factory raises
    ``T3NonceAlreadyRegisteredError`` on a second call, so without a per-test
    reset the SECOND boot test in a pytest process would refuse boot — and the
    registered nonce would leak into the wider suite, flipping the previously-
    ``None`` slot non-``None`` under tests that assume an empty slot. This
    harness clears the slot to ``None`` before the boot runs (under the same
    ``_NONCE_LOCK`` the ``clean_t3_nonce_slot`` fixture uses, so it stays
    race-safe against a concurrent bootstrap) and the returned restore callable
    puts the prior value back — exactly the ``clean_t3_nonce_slot`` contract,
    inlined here so every daemon-boot-success test inherits it.
    """
    from alfred.bootstrap.nonce_factory import _NONCE_LOCK
    from alfred.security import tiers as _tiers

    with _NONCE_LOCK:
        _prior_t3_nonce = _tiers._AUTHORIZED_T3_NONCE
        _tiers._set_authorized_t3_nonce(None)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.delenv("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", raising=False)
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent-etc",
    )
    # CR #6: the snapshot-ref probe reads ``Settings.policies_path`` (anchored
    # at /etc/alfred), NOT a CWD-relative ``config/policies.yaml``. Point it at
    # a real file under tmp so the boot-success path passes regardless of the
    # test runner's CWD — including the production-environment success tests
    # that would otherwise refuse on an absent /etc/alfred/policies.yaml.
    policies_file = tmp_path / "policies.yaml"
    policies_file.write_text("schema_version: 1\n", encoding="utf-8")
    monkeypatch.setenv("ALFRED_POLICIES_PATH", str(policies_file))

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: audit_writer,
    )
    # sec-004 (INTENTIONAL launcher-probe bypass): the shipped PR-S4-1
    # launcher stub returns ``_STUB_SIGNATURE`` and so REFUSES the boot in
    # production — that production refusal is the real, security-required
    # behaviour and is asserted directly by
    # ``test_probe_launcher_not_policy_resolving.py`` (the prod-refusal
    # test). It must NOT be weakened. Boot-SUCCESS tests that run with
    # ALFRED_ENVIRONMENT=production (e.g. the source-conflict test) only need
    # to isolate their assertion from that refusal, so this fixture pins the
    # launcher probe to "passing" (standing in for a genuine
    # policy-resolving launcher PR-S4-6 will ship). Probe-refusal tests
    # monkeypatch this back to the failure they exercise.
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.probe_launcher_policy_resolving",
        _make_async(lambda **_kw: None),
    )
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_session_scope",
        lambda _settings: lambda: None,
    )
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_handshake",
        lambda _scope: _HealthyGate(),
    )
    # PR-S4-11b0: the daemon now builds a RAW seeded RealGate, installs the
    # boot HookRegistry over it, and asserts the first-party DLP grant is
    # live. The success path needs a gate that GRANTS that first-party
    # grant — ``make_quarantined_extract_chain_gate`` seeds exactly the
    # ``security.quarantined.extract`` system-tier grant via a FIXTURE
    # (RealGate, not a permissive shim — CLAUDE.md hard rule #2). The
    # process registry singleton is restored after the test so the
    # installed boot registry does not leak into sibling tests.
    from alfred.hooks import get_registry, set_registry
    from tests.helpers.gates import make_quarantined_extract_chain_gate

    _prior_registry = get_registry()
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_real_gate_for_daemon",
        _make_async(lambda _settings: make_quarantined_extract_chain_gate()),
    )
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.read_state_git_head_sha",
        lambda _path: "deadbeefcafe",
    )
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.Supervisor",
        FakeSupervisor,
    )
    # Park-for-shutdown returns immediately so the command does not block.
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.wait_for_shutdown",
        _make_async_noop(),
    )
    # PID file goes under tmp so the test never touches ~/.run.
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.default_pidfile_path",
        lambda: tmp_path / "daemon.pid",
    )

    def _restore() -> None:
        # Restore the process registry singleton: the boot path installs a
        # boot HookRegistry via ``set_registry``, which would otherwise leak
        # into sibling tests and shift the active gate/sink out from under
        # them.
        set_registry(_prior_registry)
        # Restore the authorised-T3-nonce slot the boot path registered (under
        # the bootstrap lock) so the nonce this boot minted never leaks into a
        # sibling test that assumes an empty slot.
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(_prior_t3_nonce)

    return _restore


@pytest.fixture
def boot_success_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fake_audit_writer: FakeAuditWriter,
) -> Iterator[FakeAuditWriter]:
    """Patch every external builder so the boot success path runs in-memory.

    Yields the recording audit writer so tests can assert on the rows, then
    restores the process registry singleton the boot path installed. Thin
    wrapper over :func:`apply_boot_success_patches` (the reusable body).
    """
    restore = apply_boot_success_patches(monkeypatch, tmp_path, fake_audit_writer)
    yield fake_audit_writer
    restore()


class _HealthyGate:
    """Async handshake double for probe (c)."""

    async def is_backing_store_available(self) -> bool:
        return True


def _make_async(fn: Any) -> Any:
    async def _f(*args: Any, **kwargs: Any) -> Any:
        return fn(*args, **kwargs)

    return _f


def _make_async_noop() -> Any:
    async def _f(*_args: Any, **_kwargs: Any) -> None:
        return None

    return _f

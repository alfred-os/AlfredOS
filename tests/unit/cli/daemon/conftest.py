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
from typing import Any, ClassVar

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
    # When set, ``stop()`` raises — lets a test drive the boot finally's inner
    # ``try: supervisor.stop() finally: <reap listeners + delete pidfile>`` arm,
    # proving a failing ``stop()`` never skips the socket-listener reap or the
    # pidfile delete (the exact leaks that inner finally exists to prevent).
    fail_stop: ClassVar[bool] = False

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
        if FakeSupervisor.fail_stop:
            raise RuntimeError("supervisor.stop() failed (fake)")

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

    from alfred.bootstrap.lifecycle_epoch import reset_boot_epoch_for_tests

    # Spec A G1 (#237): each harnessed boot mints a fresh per-boot epoch.
    # ``mint_boot_epoch`` raises on a second mint in a process, so reset the
    # slot before THIS boot runs and clear it on teardown — mirroring the
    # T3-nonce clean above. The epoch is non-secret, so (unlike the nonce) the
    # reset grants no privilege; it only prevents cross-test mint poisoning.
    reset_boot_epoch_for_tests()
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
    # boot HookRegistry over it, and asserts EVERY first-party grant is
    # live (ADR-0026). The success path needs a gate that GRANTS all of
    # them — #339 PR3 grew :data:`FIRST_PARTY_SYSTEM_GRANTS` from one row
    # (the DLP subscriber) to four (+ tool.dispatch, quarantine.dereference,
    # t3.downgrade_to_orchestrator), so the fixture is wired DIRECTLY off
    # that production constant via ``make_comms_adapter_load_gate`` (a
    # generic "RealGate seeded with these exact GrantRows" builder — real
    # gate + real policy match, not a permissive shim; CLAUDE.md hard rule
    # #2) rather than off a hand-maintained subset. A future grant added to
    # the constant is therefore live on this fixture automatically, so the
    # boot-success double can never drift back out of sync with the seed
    # the way a hardcoded row list would. The process registry singleton is
    # restored after the test so the installed boot registry does not leak
    # into sibling tests.
    from alfred.hooks import get_registry, set_registry
    from alfred.security.capability_gate._bootstrap_grants import (
        FIRST_PARTY_SYSTEM_GRANTS,
    )
    from tests.helpers.gates import make_comms_adapter_load_gate

    _prior_registry = get_registry()
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_real_gate_for_daemon",
        _make_async(lambda _settings: make_comms_adapter_load_gate(FIRST_PARTY_SYSTEM_GRANTS)),
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
        # Spec A G1 (#237): clear the per-boot epoch the boot minted so it never
        # leaks into a sibling test that asserts an unminted slot (the
        # production invariant between processes is "no epoch until boot mints
        # one").
        reset_boot_epoch_for_tests()

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


@pytest.fixture(autouse=True)
def _assert_t3_nonce_slot_restored() -> Iterator[None]:
    """Fail loud if a daemon-boot test leaks the authorised T3 nonce.

    PR-S4-11c-2a carry-forward from the #243 review (ADR-0028 accepted-negative):
    the daemon boot path registers the per-process authorised T3 nonce
    (``alfred.security.tiers._AUTHORIZED_T3_NONCE``) via
    ``create_and_register_t3_nonce``. The ``boot_success_env`` fixture cleans the
    slot to ``None`` before the boot and restores the prior value on teardown — so
    a test that drives boot THROUGH that harness leaves the slot exactly as it
    found it. A test that reaches nonce registration while BYPASSING
    ``boot_success_env`` (a new boot harness, a direct ``start_daemon`` call) would
    instead leak a live nonce into the wider suite, flipping the previously-``None``
    slot non-``None`` under siblings that assume an empty slot — a cross-test
    contamination that surfaces as a baffling ``T3NonceAlreadyRegisteredError`` or a
    silently-wrong gate identity far from its cause.

    This autouse guard pins the failure to the leaking test's OWN teardown
    boundary. It is autouse so it is set up BEFORE the explicitly-requested
    ``boot_success_env`` and therefore TORN DOWN AFTER it (pytest finalisers run in
    reverse setup order) — the assertion observes the slot AFTER
    ``boot_success_env``'s ``restore()`` has run, so it never races the harness's
    own clean/restore.

    It captures the slot value at its OWN setup and asserts the slot returns to
    that exact value — normally ``None`` in a clean pytest process, which makes the
    common case the ``is None`` assertion the review asked for, while staying robust
    if some earlier module legitimately registered a process nonce (no false
    positive against a pre-existing live slot).
    """
    from alfred.security import tiers as _tiers

    at_setup = _tiers._AUTHORIZED_T3_NONCE
    yield
    assert _tiers._AUTHORIZED_T3_NONCE is at_setup, (
        "daemon-boot test leaked the authorised T3 nonce: the slot was not "
        "restored to its pre-test value. A boot test that registers the nonce "
        "MUST go through the boot_success_env harness (which cleans + restores "
        "the slot) so the registration does not poison sibling tests."
    )


@pytest.fixture(autouse=True)
def _assert_boot_epoch_slot_restored() -> Iterator[None]:
    """Fail loud if a daemon-boot test leaks the per-boot lifecycle epoch.

    Spec A G1 (#237): the boot path mints the per-process lifecycle epoch
    (``alfred.bootstrap.lifecycle_epoch._BOOT_EPOCH``). ``boot_success_env``
    resets the slot before the boot and clears it on teardown, so a test that
    drives boot THROUGH the harness leaves the slot empty. A test that mints
    while BYPASSING the harness would leak a live epoch, so the NEXT boot's
    ``mint_boot_epoch`` would raise ``BootEpochAlreadyMintedError`` far from its
    cause. This autouse guard pins the failure to the leaking test's OWN
    teardown.

    Autouse, so it is set up BEFORE the explicitly-requested ``boot_success_env``
    and torn down AFTER it (pytest finalisers run in reverse setup order) — it
    observes the slot AFTER ``boot_success_env``'s ``restore()`` ran, so it never
    races the harness's own reset/clear. It captures the slot at its own setup
    and asserts the slot returns to that value (normally ``None`` in a clean
    process), so it never false-positives against a pre-existing minted slot.
    """
    from alfred.bootstrap import lifecycle_epoch as _epoch

    at_setup = _epoch._BOOT_EPOCH
    yield
    assert _epoch._BOOT_EPOCH is at_setup, (
        "daemon-boot test leaked the per-boot lifecycle epoch: the slot was "
        "not cleared to its pre-test value. A boot test that mints the epoch "
        "MUST go through the boot_success_env harness (which resets + clears "
        "the slot) so the mint does not poison sibling tests."
    )


class _HealthyGate:
    """Async handshake double for probe (c)."""

    async def is_backing_store_available(self) -> bool:
        return True


class _FakeQuarantineChildIO:
    """In-proc stand-in for ``spawn_quarantine_child_io``'s ``_SubprocessChildIO``.

    PR-S4-11c-2b: the daemon's ``_build_comms_inbound_extractor`` now spawns a REAL
    bwrap quarantined child. The boot-WIRING unit tests assert construction order +
    fail-closed posture, NOT a real subprocess (the genuine bwrap spawn + round-trip
    is the docker-only integration test's job). This fake satisfies the
    ``alfred.security.quarantine_transport.ChildIO`` Protocol so
    ``QuarantineStdioTransport`` constructs against it. ``write_frame`` is a no-op
    and ``read_frame`` is never reached on the construction-only boot path (no
    inbound turn is driven); ``aclose`` is an idempotent no-op.
    """

    def __init__(self, *, provider_key: str) -> None:
        # Recorded so a test can assert the key flowed into the spawn (the real
        # spawn delivers it over fd 3; here we only prove the seam carried it).
        self.provider_key = provider_key
        # Counts aclose() calls so a test can prove the daemon reaps the live child
        # on its exit paths (CR #255 — the boot graph's quarantine teardown).
        self.aclose_calls = 0

    def write_frame(self, frame: bytes) -> None:
        return None

    async def read_frame(self) -> bytes:  # pragma: no cover - no inbound turn on boot-wiring path
        raise AssertionError("the boot-wiring unit cut drives no inbound turn")

    async def aclose(self) -> None:
        self.aclose_calls += 1


@pytest.fixture
def patch_quarantine_child_spawn(monkeypatch: pytest.MonkeyPatch) -> list[_FakeQuarantineChildIO]:
    """Monkeypatch the quarantined-child spawn seam to an in-proc fake child-IO.

    PR-S4-11c-2b: comms-enabled boot tests must NOT attempt a real bwrap spawn on a
    non-Linux / unprovisioned CI host (it would fail-closed and refuse the boot).
    This patches ``spawn_quarantine_child_io`` at its SOURCE module
    (``alfred.security.quarantine_child_io``) — the seam the daemon's
    ``_build_comms_inbound_extractor`` imports lazily — so the live-spawn path is
    exercised structurally without a subprocess. Returns the list of spawned fakes
    so a test can assert the spawn happened + the provider key flowed.
    """
    spawned: list[_FakeQuarantineChildIO] = []

    async def _fake_spawn(*, provider_key: str) -> _FakeQuarantineChildIO:
        child = _FakeQuarantineChildIO(provider_key=provider_key)
        spawned.append(child)
        return child

    monkeypatch.setattr(
        "alfred.security.quarantine_child_io.spawn_quarantine_child_io", _fake_spawn
    )
    return spawned


def _make_async(fn: Any) -> Any:
    async def _f(*args: Any, **kwargs: Any) -> Any:
        return fn(*args, **kwargs)

    return _f


def _make_async_noop() -> Any:
    async def _f(*_args: Any, **_kwargs: Any) -> None:
        return None

    return _f

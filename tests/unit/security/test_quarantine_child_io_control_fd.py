"""#340 PR2a Task 3: opt-in control-fd spawn plumbing (ADR-0050 dormancy invariant).

Drives the SAME hermetic discipline as ``test_quarantine_child_io.py`` (fake
``subprocess.Popen`` + faked ``deliver_provider_key_via_fd3`` + a faked
``os.dup2`` that records the call instead of performing a real dup onto
literal fd 3/4 — a real dup2 onto either target in-process would clobber the
test runner's own fd table) against the GROWN seam: an opt-in, default-OFF
``control_fd`` parameter that, when set, also dups a pre-connected-gateway
socket's child-end onto literal fd 4 (peer to the existing fd-3 provider-key
dance) so the empty-netns quarantine child can later receive a broked socket.

The dormancy invariant (ADR-0050) is the headline behavioural contract this
file protects: the LIVE/ECHO spawn path (``control_fd`` defaults ``False``)
must stay byte-for-byte unchanged — ``pass_fds == (3,)`` only, no fd 4 dup2,
no socketpair construction. Every test below that does NOT pass
``control_fd=True`` is implicitly a dormancy regression guard.

Covers, per the PR2a plan's mandatory coverage list:

* the default (``control_fd=False``) spawn passes fd 3 only (dormancy);
* an opt-in ``control_fd=True`` spawn passes fd 3 AND fd 4, and the returned
  ``_SubprocessChildIO.broker_sockets()`` delegates to
  ``control_fd_broker.broker_connected_sockets`` with the owned parent
  control-end + the injected ``EgressProxyConfig``;
* ``control_fd=True`` with no ``egress_config`` refuses loudly (misconfigured
  opt-in, not a silent no-op);
* ``child_module`` outside the frozen ``_ALLOWED_CHILD_MODULES`` allowlist
  refuses (a free module string would be a spawn-arbitrary-module hole — the
  child inherits fd 3 [+ fd 4]);
* the ``_lift_above_targets`` aliasing branch (a pipe/socketpair source fd
  that happens to already sit ON a literal target) and the finally
  unsaved-target ``else: os.close(fd)`` arc, both forced via monkeypatch
  since real ``os.pipe``/``socketpair`` never land on fd 3/4 under pytest;
* a ``ProviderKeyDeliveryError`` on a ``control_fd=True`` spawn closes the
  owned parent control-end (no leak on the fail-closed refusal path);
* an OS spawn failure (``Popen`` raising) on a ``control_fd=True`` spawn ALSO
  closes the owned parent control-end (L-3: the leak guard is not limited to
  the key-delivery-failure arc);
* ``broker_sockets()`` on an unconfigured ``_SubprocessChildIO``
  (``control_parent=None`` or ``egress_config=None``) refuses loudly — a
  fail-loud security branch (CLAUDE.md hard rule #7), never pragma'd out;
* ``aclose`` closes the owned parent control-end.
"""

from __future__ import annotations

import socket
import sys
from typing import Any
from unittest.mock import AsyncMock

import pytest

import alfred.security.quarantine_child_io as qcio
from alfred.security.quarantine_child._handshake import HELLO_FRAME, READY_FRAME
from alfred.security.quarantine_child_io import (
    QuarantineChildSpawnError,
    _SubprocessChildIO,
    spawn_quarantine_child_io,
)
from alfred.supervisor.fd3_key_delivery import ProviderKeyDeliveryError
from tests.unit.security.test_quarantine_child_io import _FakeStdout


class _Cfg:
    """A minimal ``EgressProxyConfig``-shaped stub (structural, PEP 544)."""

    egress_proxy_url = "http://alfred-gateway:8889"


class _FakePopen:
    """A ``subprocess.Popen``-shaped double that never execs a real child."""

    def __init__(self, argv: list[str], **kwargs: Any) -> None:
        self.argv = argv
        self.pass_fds = tuple(kwargs.get("pass_fds", ()))
        self.stdin = self.stderr = None
        # A real child emits hello+ready at boot; the host handshake reads them inside
        # the spawn (#443). The probe reads hello only, so an extra ready sits unread —
        # harmless. Both control_fd spawn tests therefore work with the same seed.
        self.stdout = _FakeStdout([HELLO_FRAME, READY_FRAME])
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return 0

    def terminate(self) -> None:
        return None

    def wait(self) -> int:
        self.returncode = 0
        return 0


@pytest.fixture
def _spawn_capture(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Fake ``Popen``/fd-3 delivery/``os.dup2`` — mirrors ``test_quarantine_child_io.py``.

    ``os.dup2`` is faked (records the call, returns ``dst`` without a real
    dup) because a real dup2 onto literal fd 3 or fd 4 in-process would
    clobber the pytest worker's own fd table (the discipline the sibling
    file's ``_spawn_capture`` documents). ``os.dup``/``os.close`` are left
    REAL here — the ambient test process has neither fd 3 nor fd 4 open, so
    the "save a prior occupant" dance safely no-ops on its own for the
    default cases; tests that need to force a SPECIFIC branch deterministic
    (rather than relying on that ambient absence) layer their own
    monkeypatches on top of this fixture.
    """
    captured: dict[str, Any] = {"proc": None, "dup2": []}

    def _fake_popen(argv: list[str], **kwargs: Any) -> _FakePopen:
        proc = _FakePopen(argv, **kwargs)
        captured["proc"] = proc
        captured["argv"] = argv
        captured["pass_fds"] = proc.pass_fds
        captured["env"] = kwargs.get("env")
        return proc

    def _fake_deliver(*, write_fd: int, key: str) -> None:
        captured["delivery"] = {"write_fd": write_fd, "key": key}

    def _fake_dup2(src: int, dst: int, *_a: Any, **_k: Any) -> int:
        captured["dup2"].append((src, dst))
        return dst

    monkeypatch.setattr(qcio.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(qcio, "deliver_provider_key_via_fd3", _fake_deliver)
    monkeypatch.setattr(qcio.os, "dup2", _fake_dup2)
    return captured


async def test_default_spawn_passes_no_control_fd(_spawn_capture: dict[str, Any]) -> None:
    """The live/echo spawn (``control_fd`` default ``False``) is dormancy-unchanged.

    ``pass_fds == (3,)`` only — no fd 4, no socketpair construction — and the
    argv still execs the real (non-probe) child module.
    """
    io = await spawn_quarantine_child_io(provider_key="k")
    try:
        assert _spawn_capture["pass_fds"] == (3,)
        assert qcio._CHILD_MODULE in _spawn_capture["argv"]
    finally:
        await io.aclose()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_control_fd_spawn_passes_fd_3_and_4(
    _spawn_capture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An opt-in ``control_fd=True`` spawn passes BOTH fd 3 and fd 4.

    ``broker_sockets()`` on the returned IO delegates to
    ``control_fd_broker.broker_connected_sockets`` with the owned parent
    control-end and the injected ``egress_config``.
    """
    io = await spawn_quarantine_child_io(
        provider_key="k",
        control_fd=True,
        child_module=qcio._BROKERED_PROBE_MODULE,
        egress_config=_Cfg(),
    )
    try:
        assert _spawn_capture["pass_fds"] == (3, 4)
        broker_mock = AsyncMock(return_value=[("gw", 8889)])
        monkeypatch.setattr(qcio.control_fd_broker, "broker_connected_sockets", broker_mock)
        await io.broker_sockets(1)
        broker_mock.assert_awaited_once()
        assert broker_mock.await_args.kwargs["proxy_config"] is not None
        assert broker_mock.await_args.kwargs["count"] == 1
    finally:
        await io.aclose()


async def test_control_fd_with_no_egress_config_raises(_spawn_capture: dict[str, Any]) -> None:
    """``control_fd=True`` with no ``egress_config`` refuses loudly (misconfigured opt-in)."""
    with pytest.raises(QuarantineChildSpawnError):
        await spawn_quarantine_child_io(provider_key="k", control_fd=True, egress_config=None)


async def test_child_module_outside_allowlist_refuses(_spawn_capture: dict[str, Any]) -> None:
    """A ``child_module`` outside the frozen allowlist refuses (no free-module spawn hole)."""
    with pytest.raises(QuarantineChildSpawnError):
        await spawn_quarantine_child_io(
            provider_key="k", control_fd=True, child_module="os", egress_config=_Cfg()
        )


async def test_aliasing_loop_lifts_source_fd_off_a_literal_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A source fd that already sits ON a literal target is lifted above the range first.

    Real ``os.pipe``/``socketpair`` never land on fd 3/4 under pytest (they
    return high fds — the ambient fd-3/4-occupied test environment makes
    that doubly true), so this branch is forced: ``os.pipe`` is faked to
    fabricate a read-end fd that COLLIDES with literal fd 3, and every
    ``os.dup``/``os.dup2``/``os.close`` this forces is faked too (never a
    real syscall against literal fd 3/4 — would clobber the test runner).
    """
    captured: dict[str, Any] = {}

    def _fake_popen(argv: list[str], **kwargs: Any) -> _FakePopen:
        proc = _FakePopen(argv, **kwargs)
        captured["pass_fds"] = proc.pass_fds
        return proc

    real_pipe = qcio.os.pipe

    def _colliding_pipe() -> tuple[int, int]:
        _real_r, real_w = real_pipe()
        # Fabricate a read-end that collides with the literal fd-3 target —
        # `_lift_above_targets` must dup it off before dup2'ing onto fd 3.
        return qcio._PROVIDER_KEY_FD, real_w

    dup_calls: list[int] = []
    dup2_calls: list[tuple[int, int]] = []
    fake_fd_counter = [10_000]

    def _fake_dup(fd: int) -> int:
        dup_calls.append(fd)
        fake_fd_counter[0] += 1
        return fake_fd_counter[0]

    def _fake_dup2(src: int, dst: int, *_a: Any, **_k: Any) -> int:
        dup2_calls.append((src, dst))
        return dst

    def _fake_close(_fd: int) -> None:
        return None

    monkeypatch.setattr(qcio.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(qcio, "deliver_provider_key_via_fd3", lambda **_k: None)
    monkeypatch.setattr(qcio.os, "pipe", _colliding_pipe)
    monkeypatch.setattr(qcio.os, "dup", _fake_dup)
    monkeypatch.setattr(qcio.os, "dup2", _fake_dup2)
    monkeypatch.setattr(qcio.os, "close", _fake_close)

    io = await spawn_quarantine_child_io(provider_key="k")
    try:
        # The colliding fd (3) was fed into os.dup at least once (the lift attempt).
        assert qcio._PROVIDER_KEY_FD in dup_calls
        assert captured["pass_fds"] == (3,)
        # The load-bearing assertion: the FIRST dup2 call (which installs literal
        # fd 3 — the finally block's restore dup2 comes later) must NOT dup FROM
        # fd 3 onto itself — the source must have been LIFTED to one of our
        # fabricated high fake fds first. A naive (unlifted) implementation would
        # call os.dup2(3, 3) here instead (src == dst == the colliding fd), which
        # this assertion catches.
        install_src, install_dst = dup2_calls[0]
        assert install_dst == qcio._PROVIDER_KEY_FD
        assert install_src != qcio._PROVIDER_KEY_FD
        assert install_src >= 10_000
    finally:
        await io.aclose()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_unsaved_target_closes_installed_fd_for_both_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Neither fd 3 nor fd 4 has a prior occupant → both installed dups are closed.

    Forces the ``else: os.close(fd)`` arc deterministically (rather than
    relying on the ambient absence of fd 3/4 in the test process) by faking
    ``os.dup`` to always raise — mirrors
    ``test_quarantine_child_io.py::test_spawn_without_prior_fd3_closes_installed_fd``,
    extended to the fd-4 control target.
    """
    closed: list[int] = []

    def _fake_popen(argv: list[str], **kwargs: Any) -> _FakePopen:
        return _FakePopen(argv, **kwargs)

    def _no_dup(_fd: int) -> int:
        raise OSError("no prior occupant")

    def _fake_dup2(src: int, dst: int, *_a: Any, **_k: Any) -> int:
        return dst

    def _tracking_close(fd: int) -> None:
        closed.append(fd)

    monkeypatch.setattr(qcio.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(qcio, "deliver_provider_key_via_fd3", lambda **_k: None)
    monkeypatch.setattr(qcio.os, "dup", _no_dup)
    monkeypatch.setattr(qcio.os, "dup2", _fake_dup2)
    monkeypatch.setattr(qcio.os, "close", _tracking_close)

    io = await spawn_quarantine_child_io(
        provider_key="k",
        control_fd=True,
        child_module=qcio._BROKERED_PROBE_MODULE,
        egress_config=_Cfg(),
    )
    try:
        assert qcio._PROVIDER_KEY_FD in closed
        assert qcio._CONTROL_FD in closed
    finally:
        await io.aclose()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_provider_key_delivery_failure_closes_control_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fd-3 delivery failure on a ``control_fd=True`` spawn closes the parent control-end."""
    captured: dict[str, Any] = {}
    real_make_pair = qcio.control_fd_broker.make_control_socketpair

    def _capturing_pair() -> tuple[socket.socket, socket.socket]:
        parent, child = real_make_pair()
        captured["control_parent"] = parent
        return parent, child

    def _fake_popen(argv: list[str], **kwargs: Any) -> _FakePopen:
        return _FakePopen(argv, **kwargs)

    def _boom(*, write_fd: int, key: str) -> None:
        raise ProviderKeyDeliveryError()

    def _fake_dup2(src: int, dst: int, *_a: Any, **_k: Any) -> int:
        return dst

    monkeypatch.setattr(qcio.control_fd_broker, "make_control_socketpair", _capturing_pair)
    monkeypatch.setattr(qcio.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(qcio, "deliver_provider_key_via_fd3", _boom)
    monkeypatch.setattr(qcio.os, "dup2", _fake_dup2)

    with pytest.raises(QuarantineChildSpawnError):
        await spawn_quarantine_child_io(
            provider_key="k",
            control_fd=True,
            child_module=qcio._BROKERED_PROBE_MODULE,
            egress_config=_Cfg(),
        )

    with pytest.raises(OSError):
        captured["control_parent"].getsockname()  # closed


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_popen_oserror_closes_control_parent(monkeypatch: pytest.MonkeyPatch) -> None:
    """An OS spawn failure on a ``control_fd=True`` spawn ALSO closes the parent control-end.

    L-3: the control-end leak guard is not limited to the key-delivery-
    failure arc — a failed ``Popen`` must not leak the owned parent socket
    either.
    """
    captured: dict[str, Any] = {}
    real_make_pair = qcio.control_fd_broker.make_control_socketpair

    def _capturing_pair() -> tuple[socket.socket, socket.socket]:
        parent, child = real_make_pair()
        captured["control_parent"] = parent
        return parent, child

    def _boom_popen(_argv: list[str], **_kwargs: Any) -> _FakePopen:
        raise FileNotFoundError("launcher missing")

    def _fake_dup2(src: int, dst: int, *_a: Any, **_k: Any) -> int:
        return dst

    monkeypatch.setattr(qcio.control_fd_broker, "make_control_socketpair", _capturing_pair)
    monkeypatch.setattr(qcio.subprocess, "Popen", _boom_popen)
    monkeypatch.setattr(qcio, "deliver_provider_key_via_fd3", lambda **_k: None)
    monkeypatch.setattr(qcio.os, "dup2", _fake_dup2)

    with pytest.raises(QuarantineChildSpawnError):
        await spawn_quarantine_child_io(
            provider_key="k",
            control_fd=True,
            child_module=qcio._BROKERED_PROBE_MODULE,
            egress_config=_Cfg(),
        )

    with pytest.raises(OSError):
        captured["control_parent"].getsockname()  # closed


async def test_broker_sockets_unconfigured_raises() -> None:
    """``broker_sockets()`` on an unconfigured IO refuses loudly (fail-loud security branch)."""
    io = _SubprocessChildIO(_FakePopen([]), control_parent=None, egress_config=None)
    with pytest.raises(QuarantineChildSpawnError):
        await io.broker_sockets(1)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_aclose_closes_the_parent_control_end() -> None:
    """``aclose`` closes the owned parent control-end (no fd leak on teardown)."""
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    io = _SubprocessChildIO(_FakePopen([]), control_parent=parent, egress_config=_Cfg())
    await io.aclose()
    with pytest.raises(OSError):
        parent.getsockname()  # closed
    child.close()


# ---------------------------------------------------------------------------
# #340 PR2b-golive Task 8: _child_env provider-config threading + byte-identity
# ---------------------------------------------------------------------------

#: The golive provider-config keys the LIVE (control_fd=True) spawn threads into the
#: scrubbed child env. The dormant/echo (control_fd=False) spawn sets NONE of them —
#: the ADR-0050 dormancy byte-identity invariant.
_GOLIVE_ENV_KEYS = frozenset(
    {"ALFRED_QUARANTINE_MODEL", "ALFRED_QUARANTINE_MAX_TOKENS", "SSL_CERT_FILE"}
)


def test_default_ssl_cert_file_is_the_spike_verified_system_bundle() -> None:
    """The spawn's default CA bundle is the spike-verified system-store path."""
    assert qcio._DEFAULT_SSL_CERT_FILE == "/etc/ssl/certs/ca-certificates.crt"


def test_child_env_default_omits_golive_provider_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A no-arg (dormant/control_fd=False) ``_child_env`` sets NONE of the golive keys.

    The three keys are on the scrubbed allowlist (Task 2), so ``delenv`` them first
    to isolate the FUNCTION's behaviour from an ambient host value — the assertion is
    "``_child_env`` does not ADD them", not "the host had none".
    """
    for key in _GOLIVE_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    env = qcio._child_env()
    assert _GOLIVE_ENV_KEYS.isdisjoint(env)


def test_child_env_live_carries_model_budget_and_ssl() -> None:
    """The live (control_fd=True) ``_child_env`` carries model + budget + CA path."""
    env = qcio._child_env(
        model="claude-haiku-4-5",
        max_tokens=8192,
        ssl_cert_file="/etc/ssl/certs/ca-certificates.crt",
    )
    assert env["ALFRED_QUARANTINE_MODEL"] == "claude-haiku-4-5"
    assert env["ALFRED_QUARANTINE_MAX_TOKENS"] == "8192"
    assert env["SSL_CERT_FILE"] == "/etc/ssl/certs/ca-certificates.crt"


def test_child_env_live_is_dormant_plus_exactly_the_three_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Live env == dormant env + EXACTLY the three golive keys (strict byte-identity).

    Nothing else in the dormant env changes value; the live path only ADDS the three
    host-passed keys — the precise contract the ADR-0050 dormancy invariant rests on.
    """
    for key in _GOLIVE_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    dormant = qcio._child_env()
    live = qcio._child_env(
        model="claude-haiku-4-5",
        max_tokens=8192,
        ssl_cert_file="/etc/ssl/certs/ca-certificates.crt",
    )
    assert set(live) - set(dormant) == _GOLIVE_ENV_KEYS
    for key in dormant:
        assert live[key] == dormant[key]


async def test_default_spawn_env_omits_golive_provider_config(
    _spawn_capture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A control_fd=False spawn's child env carries NONE of the golive keys (dormancy)."""
    for key in _GOLIVE_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    io = await spawn_quarantine_child_io(provider_key="k")
    try:
        assert _GOLIVE_ENV_KEYS.isdisjoint(_spawn_capture["env"])
    finally:
        await io.aclose()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_control_fd_spawn_env_carries_provider_config(
    _spawn_capture: dict[str, Any],
) -> None:
    """A control_fd=True spawn threads model + budget + the default CA path into the env."""
    io = await spawn_quarantine_child_io(
        provider_key="k",
        control_fd=True,
        child_module=qcio._BROKERED_PROBE_MODULE,
        egress_config=_Cfg(),
        model="claude-haiku-4-5",
        max_tokens=8192,
    )
    try:
        env = _spawn_capture["env"]
        assert env["ALFRED_QUARANTINE_MODEL"] == "claude-haiku-4-5"
        assert env["ALFRED_QUARANTINE_MAX_TOKENS"] == "8192"
        assert env["SSL_CERT_FILE"] == qcio._DEFAULT_SSL_CERT_FILE
    finally:
        await io.aclose()

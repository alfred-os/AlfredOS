# #340 PR2a — SCM_RIGHTS fd-broker topology (core-side) Implementation Plan

> **rev.2 (2026-07-10):** a 3-lens focused plan-review (core + security + test) folded — see **"Plan-review fold log"** at the end. It found 1 Critical + gate-breaking Highs in the rev.1 task code (the Task-3 aliasing double-close/leak, coverage-gate breaks, a non-functional Task-8 paper-gate). **The fold log OVERRIDES the task bodies where they conflict — read it before implementing each task.** `FOLD-A`/`FOLD-B`, the Task-8 paper-gate, and the `make_control_socketpair` name are already applied inline.
>
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the core-side SCM_RIGHTS reachability-broker + opt-in control-fd spawn plumbing so the empty-netns quarantine child can (in PR2b) receive a pre-connected gateway socket — proven here by a docker C1/C2 test — while the live echo child stays byte-for-byte unchanged.

**Architecture:** A new `egress/control_fd_broker.py` opens a bare TCP socket to the gateway proxy and passes the fd to the child via `SCM_RIGHTS` over an inherited AF_UNIX control fd (fd 4), writing zero application bytes (HARD #5). `spawn_quarantine_child_io` grows an **opt-in** `control_fd` flag (default off → live path unchanged) that adds fd 4 to the existing zero-`await` dup2 window; `_SubprocessChildIO` owns the parent control-end. A thin `# pragma: no cover` probe child proves C1 (empty netns) + C2 (SCM_RIGHTS crosses bwrap) in a docker test. A new AST ratchet keeps the broker the sole raw-socket-egress site.

**Tech Stack:** Python 3.14+, asyncio, `socket` (AF_UNIX socketpair + SCM_RIGHTS `sendmsg`/`recvmsg`), `subprocess.Popen` (synchronous spawn), bubblewrap (docker-gated), pytest + testcontainers-style privileged-docker, structlog, `mypy --strict` + pyright, ruff.

## Global Constraints

- **Python floor `>=3.14.6`**; PEP 604 unions, PEP 585 generics, no `Optional`/`typing.List`.
- **Ratified design = `docs/superpowers/specs/2026-07-10-issue-340-pr2a-fd-broker-topology-design.md` (rev.2).** §13 folds override rev.1 body on conflict.
- **THIN cut.** PR2a ships NO child-side httpx transport, NO `_CONSTRUCT_ALLOWLIST` edit, NO shipped bwrap-policy edit, NO `_build_provider`/extract-branch change. `src/alfred/security/quarantine_child/__main__.py` stays **byte-for-byte unchanged**.
- **`control_fd` defaults OFF.** The live/echo spawn passes no fd 4 and no `child_module` override. This is the dormancy invariant (ADR-0050).
- **Security-boundary change → the adversarial suite is RELEASE-BLOCKING.** Run `uv run pytest tests/adversarial` before the PR (CLAUDE.md).
- **HARD #7 (no silent failures on security paths):** every broker failure raises a loud `ControlFdBrokerError`/`IOPlaneUnavailableError`; never a hang or a swallowed empty result.
- **i18n:** every operator-facing string goes through `t()`; add message keys to the catalog + `pybabel` (see Task 1 Step 8).
- **100% line+branch coverage on `src/alfred/security/*`** (recursive glob gate) and a NEW named per-file 100% gate for `src/alfred/egress/control_fd_broker.py` (it is OUTSIDE the `security/*` glob).
- **Conventional Commits with a literal `#340` AFTER the colon in every commit subject** (a `(340)` scope does NOT satisfy the `Conventional commit format` check).
- **Never `git add -A`** (untracked rulesync/tool-outputs). Add named paths only. **No `--no-verify`.**
- End every commit message body with the `MrReasonable <4990954+MrReasonable@users.noreply.github.com>` trailer.

## PREDEPENDENCY — #251 lands FIRST (a SEPARATE PR, not part of this plan)

**#251 (quarantine child-IO swallows child stderr)** must be merged to `main` before **Task 7** (the docker probe test) is executed, and this branch rebased onto it. The docker test drives a real bwrapped child; without a drained stderr, a child failure (interp exec, recvmsg, framing) presents as a hang / mis-attributed truncation (the spike hit exactly this). Tasks 1–6, 8, 9 do **not** depend on #251 and can proceed first. Do NOT fold the #251 fix into this branch.

## File Structure

- **Create** `src/alfred/egress/control_fd_broker.py` — the core-side broker: `ControlFdBrokerError`, `make_control_socketpair`, `recv_passed_fd`, `_resolve_proxy_addr`, `broker_connected_socket`. The ONE sanctioned raw-socket-egress site; both the send half and the receive half are unit-covered here (the probe reuses `recv_passed_fd`).
- **Modify** `src/alfred/security/quarantine_child_io.py` — `spawn_quarantine_child_io` gains opt-in `control_fd` + `child_module` + `egress_config`; the two-fd zero-`await` window; `_SubprocessChildIO` owns the parent control-end + gains `broker_socket()`; `_BROKERED_PROBE_MODULE` + the `child_module` frozen allowlist.
- **Modify** `src/alfred/security/quarantine_transport.py` — add `broker_socket()` to the `ChildIO` Protocol (+ the in-test double if one lives here).
- **Create** `src/alfred/security/quarantine_child/_brokered_probe.py` — thin `# pragma: no cover` subprocess-entry probe (reuses `recv_passed_fd`); reports C1/C2/usability over **stdout**.
- **Create** `docs/adr/0050-quarantine-child-scm-rights-reachability-broker.md`.
- **Create** `tests/unit/egress/test_control_fd_broker.py` — unit coverage for the broker (socketpair, no bwrap).
- **Modify** `tests/unit/security/test_quarantine_child_io.py` (or create alongside) — opt-in default, `child_module` allowlist, two-fd window, `broker_socket`, `aclose`.
- **Create** `tests/adversarial/sandbox_escape/test_only_sanctioned_raw_socket_egress_site.py` — the raw-socket-egress ratchet.
- **Create** `tests/adversarial/sandbox_escape/sbx_2026_0XX_brokered_fd_dormant.yaml` + `test_brokered_fd_dormant_mechanism.py` — the dormant-mechanism corpus payload + its collected-node registration.
- **Create** `tests/integration/test_quarantine_fd_broker_real_spawn.py` — the docker-gated C1/C2 probe test (GATED on #251).
- **Modify** `.github/workflows/ci.yml` — the named per-file coverage gate + the "assert the brokered leg RAN" both-halves paper-gate.
- **Modify** `.github/workflows/adversarial.yml` — register the new payload node-id in the collected-node enumeration.

---

### Task 1: `control_fd_broker` primitives — error, socketpair, recv, proxy-addr

**Files:**

- Create: `src/alfred/egress/control_fd_broker.py`
- Test: `tests/unit/egress/test_control_fd_broker.py`

**Interfaces:**

- Produces: `ControlFdBrokerError(AlfredError)` with `.reason: str`; `make_control_socketpair() -> tuple[socket.socket, socket.socket]`; `recv_passed_fd(control_end: socket.socket) -> tuple[bytes, int]`; `_resolve_proxy_addr(proxy_config: EgressProxyConfig) -> tuple[str, int]`.
- Consumes: `alfred.egress._config_protocols.EgressProxyConfig` (`.egress_proxy_url: str | None`), `alfred.egress.errors.IOPlaneUnavailableError(*, detail: str)`, `alfred.errors.AlfredError`, `alfred.i18n.t`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/egress/test_control_fd_broker.py
from __future__ import annotations

import array
import socket

import pytest

from alfred.egress.control_fd_broker import (
    ControlFdBrokerError,
    _resolve_proxy_addr,
    make_control_socketpair,
    recv_passed_fd,
)
from alfred.egress.errors import IOPlaneUnavailableError


class _Cfg:
    def __init__(self, url: str | None) -> None:
        self.egress_proxy_url = url


def test_make_control_socketpair_child_end_is_inheritable() -> None:
    parent, child = make_control_socketpair()
    try:
        assert child.get_inheritable() is True  # non-CLOEXEC so bwrap inherits it (core-001)
        assert parent.get_inheritable() is False  # parent end must NOT leak to the child
        assert child.family == socket.AF_UNIX
    finally:
        parent.close()
        child.close()


def test_recv_passed_fd_returns_frame_and_one_fd() -> None:
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    donor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        parent.sendmsg([b"\x01"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [donor.fileno()]))])
        data, fd = recv_passed_fd(child)
        assert data == b"\x01"
        got = socket.socket(fileno=fd)
        try:
            assert got.family == socket.AF_INET
        finally:
            got.detach()  # the recvmsg'd fd aliases donor; don't double-close
    finally:
        parent.close(); child.close(); donor.close()


def test_recv_passed_fd_no_fd_is_loud() -> None:
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        parent.sendall(b"\x01")  # data only, no ancillary fd
        with pytest.raises(ControlFdBrokerError) as exc:
            recv_passed_fd(child)
        assert exc.value.reason == "expected_exactly_one_fd"
    finally:
        parent.close(); child.close()


def test_resolve_proxy_addr_blank_is_io_plane_unavailable() -> None:
    with pytest.raises(IOPlaneUnavailableError):
        _resolve_proxy_addr(_Cfg("   "))
    with pytest.raises(IOPlaneUnavailableError):
        _resolve_proxy_addr(_Cfg(None))


def test_resolve_proxy_addr_missing_port_is_io_plane_unavailable() -> None:
    with pytest.raises(IOPlaneUnavailableError):
        _resolve_proxy_addr(_Cfg("http://alfred-gateway"))  # no :port


def test_resolve_proxy_addr_splits_host_port() -> None:
    assert _resolve_proxy_addr(_Cfg("http://alfred-gateway:8889")) == ("alfred-gateway", 8889)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/egress/test_control_fd_broker.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'alfred.egress.control_fd_broker'`.

- [ ] **Step 3: Write the module (primitives only — `broker_connected_socket` is Task 2)**

```python
# src/alfred/egress/control_fd_broker.py
"""Core-side SCM_RIGHTS reachability-broker for the quarantine child (#340 PR2a, ADR-0050).

The empty-netns quarantine child cannot open its own socket. This is the ONE sanctioned in-core
site that opens a bare TCP socket toward the gateway L7 CONNECT proxy and passes the connected fd
to the child via SCM_RIGHTS over an inherited AF_UNIX control fd. It writes ZERO application bytes
over that socket — the child performs CONNECT+TLS+HTTP and terminates TLS itself (HARD #5). Distinct
from EgressClient (which does httpx I/O over its proxied client); the raw-socket-egress ratchet
(tests/adversarial/sandbox_escape/test_only_sanctioned_raw_socket_egress_site.py) keeps this the
sole INET-connect + sendmsg(SCM_RIGHTS) site in src/alfred.
"""
from __future__ import annotations

import array
import socket
from urllib.parse import urlsplit

from alfred.egress._config_protocols import EgressProxyConfig
from alfred.egress.errors import IOPlaneUnavailableError
from alfred.errors import AlfredError


class ControlFdBrokerError(AlfredError):
    """The core could not broker a connected socket to the quarantine child (loud refusal, HARD #7).

    Rooted at :class:`AlfredError` (not bare ``Exception``) with a closed-vocabulary ``reason`` so a
    caller can attribute a ``SANDBOX_REFUSED`` audit row uniformly. PR2a has no live audited caller
    (only the docker probe drives the broker); the audit-row WRITE lands in PR2b.
    """

    def __init__(self, reason: str = "control_fd_broker_failed") -> None:
        super().__init__(reason)
        self.reason = reason


def make_control_socketpair() -> tuple[socket.socket, socket.socket]:
    """Return ``(parent_end, child_end)``; the child end is non-CLOEXEC so bwrap inherits it (core-001).

    The parent end keeps the PEP 446 CLOEXEC default (non-inheritable) so the child never gets a copy
    of the privileged end — a compromised child cannot intercept or suppress EOF on the parent side.
    """
    parent_end, child_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    child_end.set_inheritable(True)  # noqa: FBT003 - positional-only bool
    return parent_end, child_end


def recv_passed_fd(control_end: socket.socket) -> tuple[bytes, int]:
    """Receive the framed data + EXACTLY ONE SCM_RIGHTS fd on ``control_end`` (loud on truncation).

    Used by the docker probe (child side). A truncated ancillary payload (``MSG_CTRUNC``) or a frame
    carrying zero or >1 fds is a loud :class:`ControlFdBrokerError` — the capability envelope is
    "exactly one connected gateway socket per frame".
    """
    fds = array.array("i")
    msg, ancdata, flags, _addr = control_end.recvmsg(4096, socket.CMSG_SPACE(fds.itemsize))
    if flags & socket.MSG_CTRUNC:
        raise ControlFdBrokerError("ancillary_truncated")
    for level, typ, cmsg in ancdata:
        if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            fds.frombytes(cmsg[: len(cmsg) - (len(cmsg) % fds.itemsize)])
    if len(fds) != 1:
        raise ControlFdBrokerError("expected_exactly_one_fd")
    return msg, int(fds[0])


def _resolve_proxy_addr(proxy_config: EgressProxyConfig) -> tuple[str, int]:
    """``host, port`` from ``egress_proxy_url`` — fail-closed like ``EgressClient.from_settings``."""
    proxy_url = proxy_config.egress_proxy_url
    if not (proxy_url and proxy_url.strip()):
        raise IOPlaneUnavailableError(
            detail="ALFRED_EGRESS_PROXY_URL is unset or blank — cannot broker a gateway socket."
        )
    parts = urlsplit(proxy_url)
    if parts.hostname is None or parts.port is None:
        raise IOPlaneUnavailableError(
            detail=f"ALFRED_EGRESS_PROXY_URL has no host:port ({proxy_url!r})."
        )
    return parts.hostname, parts.port


__all__ = ["ControlFdBrokerError", "make_control_socketpair", "recv_passed_fd"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/egress/test_control_fd_broker.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Type-check + lint**

Run: `uv run mypy src/alfred/egress/control_fd_broker.py && uv run ruff check src/alfred/egress/control_fd_broker.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/egress/control_fd_broker.py tests/unit/egress/test_control_fd_broker.py
git commit -m "feat(egress): control_fd_broker primitives — socketpair, recv_passed_fd, addr-resolve #340

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 2: `broker_connected_socket` — connect + SCM_RIGHTS + close-in-finally

**Files:**

- Modify: `src/alfred/egress/control_fd_broker.py`
- Test: `tests/unit/egress/test_control_fd_broker.py`

**Interfaces:**

- Produces: `async broker_connected_socket(*, parent_end: socket.socket, proxy_config: EgressProxyConfig) -> None` (off-loop connect + `sendmsg(SCM_RIGHTS)` + close-in-`finally`); internal `_connect_and_send(parent_end, host, port) -> None`.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/unit/egress/test_control_fd_broker.py
import threading

from alfred.egress.control_fd_broker import broker_connected_socket


def _accept_once(listener: socket.socket) -> None:
    conn, _ = listener.accept()
    conn.recv(16)  # let the client connect; we only need the connection to exist
    conn.close()


@pytest.mark.asyncio
async def test_broker_connected_socket_passes_a_live_fd_and_closes_core_copy() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    t = threading.Thread(target=_accept_once, args=(listener,), daemon=True)
    t.start()
    parent, child = make_control_socketpair()
    try:
        await broker_connected_socket(parent_end=parent, proxy_config=_Cfg(f"http://{host}:{port}"))
        data, fd = recv_passed_fd(child)
        assert data  # >=1 data byte accompanies the SCM_RIGHTS
        passed = socket.socket(fileno=fd)
        try:
            assert passed.getpeername() == (host, port)  # a LIVE connected socket crossed
            assert passed.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0
            assert passed.getblocking() is True  # settimeout(None) restored blocking after the timed connect
        finally:
            passed.detach()
    finally:
        parent.close(); child.close(); listener.close(); t.join(timeout=2)


@pytest.mark.asyncio
async def test_broker_connected_socket_unreachable_is_loud() -> None:
    parent, child = make_control_socketpair()
    try:
        with pytest.raises(ControlFdBrokerError) as exc:
            # 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — unroutable; connect times out fast in-thread.
            await broker_connected_socket(parent_end=parent, proxy_config=_Cfg("http://203.0.113.1:9"))
        assert exc.value.reason == "gateway_unreachable"
    finally:
        parent.close(); child.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/egress/test_control_fd_broker.py -k broker_connected -q`
Expected: FAIL — `ImportError: cannot import name 'broker_connected_socket'`.

- [ ] **Step 3: Implement `broker_connected_socket` + `_connect_and_send`**

```python
# add to src/alfred/egress/control_fd_broker.py (imports: add asyncio, structlog)
import asyncio
import struct  # noqa: F401 - reserved for a future framed control protocol; remove if unused by ruff

import structlog

_log = structlog.get_logger(__name__)

# Bounded connect toward the gateway proxy: a SET-but-unreachable proxy must fail loud, not wedge the
# executor thread (core-002). Distinct from the PR2b provider read-timeout hierarchy.
_CONNECT_TIMEOUT_S = 10.0


def _connect_and_send(parent_end: socket.socket, host: str, port: int) -> None:
    """Blocking (executor-thread) body: connect, SCM_RIGHTS-pass the fd, close the core's copy.

    The core writes ZERO application bytes to ``sock`` (HARD #5) — it only passes the descriptor. The
    ``\\x01`` frame is the >=1 data byte an ancillary-only ``sendmsg`` over ``SOCK_STREAM`` requires so
    the kernel does not drop the fd.
    """
    try:
        sock = socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT_S)
    except OSError as exc:
        _log.error("egress.control_fd_broker.gateway_unreachable", error_class=type(exc).__name__)
        raise ControlFdBrokerError("gateway_unreachable") from exc
    try:
        # create_connection(timeout=) leaves O_NONBLOCK set on the returned socket; that flag rides the
        # shared file description across the SCM_RIGHTS pass. Restore blocking so the child's recv blocks.
        sock.settimeout(None)
        frame = b"\x01"
        sent = parent_end.sendmsg(
            [frame],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [sock.fileno()]))],
        )
        if sent != len(frame):
            raise ControlFdBrokerError("short_data_send")
    except ControlFdBrokerError:
        raise
    except OSError as exc:
        _log.error("egress.control_fd_broker.sendmsg_failed", error_class=type(exc).__name__)
        raise ControlFdBrokerError("sendmsg_failed") from exc
    finally:
        # SCM_RIGHTS DUPLICATED the descriptor (refcount 2) — drop the core's copy immediately or the
        # child's later close sends no FIN and the core leaks one fd per broker. Safe: already duplicated
        # into the socket buffer by the time sendmsg returned. Also covers a raise before/at sendmsg.
        sock.close()


async def broker_connected_socket(*, parent_end: socket.socket, proxy_config: EgressProxyConfig) -> None:
    """Broker ONE connected gateway socket to the child over ``parent_end`` (off-loop).

    ``sendmsg``/``recvmsg`` with ``SCM_RIGHTS`` are blocking with no asyncio ancillary helper, so the
    connect+send run in the default executor (the ``_blocking_read_exactly`` precedent). Fail-closed:
    any failure raises :class:`ControlFdBrokerError` (or :class:`IOPlaneUnavailableError` for an unset
    proxy) — never a hang (HARD #7).
    """
    host, port = _resolve_proxy_addr(proxy_config)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _connect_and_send, parent_end, host, port)
```

Add `broker_connected_socket` to `__all__`. Drop the `struct` import if ruff flags it unused (it is a reserved-for-PR2b marker only — do not keep a dead import).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/egress/test_control_fd_broker.py -q`
Expected: PASS (8 passed).

- [ ] **Step 5: Type-check + lint + full-file branch coverage**

Run: `uv run mypy src/alfred/egress/control_fd_broker.py && uv run ruff check src/alfred/egress/control_fd_broker.py && uv run pytest tests/unit/egress/test_control_fd_broker.py --cov=alfred.egress.control_fd_broker --cov-branch --cov-report=term-missing -q`
Expected: no type/lint errors; coverage report shows **100%** line+branch on `control_fd_broker.py` (add a test for the `short_data_send` + `sendmsg_failed` branches if the report shows a miss — e.g. patch `parent_end.sendmsg` to return `0` / raise `OSError`).

- [ ] **Step 6: Commit**

```bash
git add src/alfred/egress/control_fd_broker.py tests/unit/egress/test_control_fd_broker.py
git commit -m "feat(egress): broker_connected_socket — connect + SCM_RIGHTS + close-in-finally #340

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 3: opt-in control-fd plumbing on `spawn_quarantine_child_io` + `_SubprocessChildIO` ownership

**Files:**

- Modify: `src/alfred/security/quarantine_child_io.py`
- Modify: `src/alfred/security/quarantine_transport.py:~100` (add `broker_socket` to the `ChildIO` Protocol)
- Test: `tests/unit/security/test_quarantine_child_io_control_fd.py` (create)

**Interfaces:**

- Consumes: `alfred.egress.control_fd_broker.make_control_socketpair`, `broker_connected_socket`; `alfred.egress._config_protocols.EgressProxyConfig`.
- Produces: `spawn_quarantine_child_io(*, provider_key: str, control_fd: bool = False, child_module: str = _CHILD_MODULE, egress_config: EgressProxyConfig | None = None) -> _SubprocessChildIO`; `_SubprocessChildIO.broker_socket() -> None` (async); module constant `_BROKERED_PROBE_MODULE = "alfred.security.quarantine_child._brokered_probe"`; `_ALLOWED_CHILD_MODULES: frozenset[str]`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/security/test_quarantine_child_io_control_fd.py
from __future__ import annotations

import socket
from unittest.mock import AsyncMock, patch

import pytest

from alfred.security import quarantine_child_io as qcio
from alfred.security.quarantine_child_io import (
    QuarantineChildSpawnError,
    _CHILD_MODULE,
    spawn_quarantine_child_io,
)


class _Cfg:
    egress_proxy_url = "http://alfred-gateway:8889"


@pytest.mark.asyncio
async def test_child_module_outside_allowlist_refuses() -> None:
    with pytest.raises(QuarantineChildSpawnError):
        await spawn_quarantine_child_io(
            provider_key="k", control_fd=True, child_module="os", egress_config=_Cfg()
        )


@pytest.mark.asyncio
async def test_default_spawn_passes_no_control_fd() -> None:
    # The live/echo spawn (control_fd default False) must pass_fds=(3,) only — no fd 4.
    captured: dict[str, object] = {}

    class _FakePopen:
        def __init__(self, argv, **kw):  # noqa: ANN001
            captured["pass_fds"] = kw["pass_fds"]
            captured["argv"] = argv
            self.stdin = self.stdout = self.stderr = None
            self.returncode = None
        def poll(self):  # noqa: ANN001
            return 0

    with patch.object(qcio.subprocess, "Popen", _FakePopen), patch.object(
        qcio, "deliver_provider_key_via_fd3"
    ):
        await spawn_quarantine_child_io(provider_key="k")
    assert captured["pass_fds"] == (3,)
    assert _CHILD_MODULE in captured["argv"]


@pytest.mark.asyncio
async def test_control_fd_spawn_passes_fd_3_and_4() -> None:
    captured: dict[str, object] = {}

    class _FakePopen:
        def __init__(self, argv, **kw):  # noqa: ANN001
            captured["pass_fds"] = tuple(kw["pass_fds"])
            self.stdin = self.stdout = self.stderr = None
            self.returncode = None
        def poll(self):  # noqa: ANN001
            return 0

    with patch.object(qcio.subprocess, "Popen", _FakePopen), patch.object(
        qcio, "deliver_provider_key_via_fd3"
    ):
        io = await spawn_quarantine_child_io(
            provider_key="k", control_fd=True,
            child_module=qcio._BROKERED_PROBE_MODULE, egress_config=_Cfg(),
        )
    assert captured["pass_fds"] == (3, 4)
    # broker_socket delegates to the egress broker with the owned parent control-end.
    with patch.object(qcio.control_fd_broker, "broker_connected_socket", new=AsyncMock()) as m:
        await io.broker_socket()
    m.assert_awaited_once()
    assert m.await_args.kwargs["proxy_config"] is not None


@pytest.mark.asyncio
async def test_aclose_closes_the_parent_control_end() -> None:
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    class _FakePopen:
        def __init__(self, *a, **kw):  # noqa: ANN001,ANN002,ANN003
            self.stdin = self.stdout = self.stderr = None
            self.returncode = 0
        def poll(self):  # noqa: ANN001
            return 0

    io = qcio._SubprocessChildIO(_FakePopen(), control_parent=parent, egress_config=_Cfg())
    await io.aclose()
    with pytest.raises(OSError):
        parent.getsockname()  # closed
    child.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/security/test_quarantine_child_io_control_fd.py -q`
Expected: FAIL — `spawn_quarantine_child_io() got an unexpected keyword argument 'control_fd'` / `no attribute '_BROKERED_PROBE_MODULE'`.

- [ ] **Step 3: Add `broker_socket` to the `ChildIO` Protocol**

In `src/alfred/security/quarantine_transport.py`, inside `class ChildIO(Protocol)` (after `read_frame`), add:

```python
    async def broker_socket(self) -> None: ...
```

Update the Protocol docstring one line to note that `broker_socket` brokers one connected gateway socket to the child via SCM_RIGHTS (no-op on the echo path; PR2a docker probe only).

- [ ] **Step 4: Implement the plumbing in `quarantine_child_io.py`**

Add near the top constants:

```python
from alfred.egress import control_fd_broker
from alfred.egress._config_protocols import EgressProxyConfig  # TYPE_CHECKING-safe if preferred

# The literal fd the pre-connected gateway socket is brokered over (peer to _PROVIDER_KEY_FD = 3).
_CONTROL_FD = 4

# The wheel-co-located diagnostic probe entry the docker C1/C2 test drives (Task 4). Inert in prod.
_BROKERED_PROBE_MODULE = "alfred.security.quarantine_child._brokered_probe"

# child_module is a CLOSED SET, never a free string — a free module would be a spawn-arbitrary-module
# hole (the child inherits fd 3 + fd 4). Only the real child or the probe.
_ALLOWED_CHILD_MODULES: frozenset[str] = frozenset({_CHILD_MODULE, _BROKERED_PROBE_MODULE})
```

Rewrite the `_SubprocessChildIO.__init__` + add `broker_socket` + extend `aclose`:

```python
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        *,
        control_parent: socket.socket | None = None,
        egress_config: EgressProxyConfig | None = None,
    ) -> None:
        self._process = process
        self._closed = False
        self._control_parent = control_parent  # owned here (CR-#255 single-teardown seam)
        self._egress_config = egress_config

    async def broker_socket(self) -> None:
        """Broker one connected gateway socket to the child (PR2a: docker probe only)."""
        if self._control_parent is None or self._egress_config is None:  # pragma: no cover - guarded by caller
            raise QuarantineChildSpawnError(t("security.quarantine_child.broker_unconfigured"))
        await control_fd_broker.broker_connected_socket(
            parent_end=self._control_parent, proxy_config=self._egress_config
        )
```

In `aclose`, after the existing terminate/reap, close the owned control-end:

```python
    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await _terminate_and_reap(self._process)
        if self._control_parent is not None:
            with contextlib.suppress(OSError):
                self._control_parent.close()
```

Rewrite `spawn_quarantine_child_io` signature + the two-fd window. The load-bearing change is the **two-dup2 zero-`await` window with BOTH fds saved/restored, the aliasing guard, and the socketpair-child-end close**:

```python
async def spawn_quarantine_child_io(
    *,
    provider_key: str,
    control_fd: bool = False,
    child_module: str = _CHILD_MODULE,
    egress_config: EgressProxyConfig | None = None,
) -> _SubprocessChildIO:
    if child_module not in _ALLOWED_CHILD_MODULES:
        raise QuarantineChildSpawnError(t("security.quarantine_child.child_module_not_allowed"))
    if control_fd and egress_config is None:
        raise QuarantineChildSpawnError(t("security.quarantine_child.broker_unconfigured"))

    read_fd, write_fd = os.pipe()
    os.set_inheritable(read_fd, True)  # noqa: FBT003

    control_parent: socket.socket | None = None
    control_child_fd: int | None = None
    if control_fd:
        control_parent, control_child = make_control_socketpair()
        control_child_fd = control_child.detach()  # raw int for the fd dance (core-001: never a live socket)

    # --- CORRECTED fd dance (rev.2: FOLD-A, core-H1/security-H-3). The rev.1 aliasing cleanup
    # double-closed read_fd/control_child_fd (they ended up BOTH explicitly closed AND in alias_temps)
    # and, when a source started ON a target, let `saved` capture the source and "restore" (leak) it.
    # Robust fix: move BOTH sources ABOVE the target range FIRST (so neither a dup2-onto-a-target nor
    # the save-of-a-prior-occupant can touch a source), then close each source exactly once. ---
    literal_targets = (_PROVIDER_KEY_FD,) if not control_fd else (_PROVIDER_KEY_FD, _CONTROL_FD)

    def _lift_above_targets(fd: int) -> tuple[int, bool]:
        """Return (usable_fd, moved). If ``fd`` sits on a target, dup it high; else return it as-is."""
        moved = False
        while fd in literal_targets:
            fd = os.dup(fd)
            moved = True
        return fd, moved

    read_src, read_moved = _lift_above_targets(read_fd)
    control_src, control_moved = (
        _lift_above_targets(control_child_fd) if control_child_fd is not None else (None, False)
    )

    saved: dict[int, int] = {}
    for fd in literal_targets:
        with contextlib.suppress(OSError):
            saved[fd] = os.dup(fd)  # sources are lifted above the range → this captures ONLY prior occupants

    process: subprocess.Popen[bytes] | None = None
    try:
        # --- fd-clobber window OPENS. NO ``await`` until it CLOSES below (#237; now BOTH fd 3 and fd 4
        # are clobbered process-wide — the await-free discipline still protects the loop selector). ---
        os.dup2(read_src, _PROVIDER_KEY_FD)
        os.set_inheritable(_PROVIDER_KEY_FD, True)  # noqa: FBT003
        if control_src is not None:
            os.dup2(control_src, _CONTROL_FD)
            os.set_inheritable(_CONTROL_FD, True)  # noqa: FBT003
        argv = [_launcher_path(), _PLUGIN_ID, _child_python(), "-m", child_module]
        try:
            process = subprocess.Popen(  # noqa: S603
                argv,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=_child_env(), pass_fds=literal_targets,
            )
        except OSError as exc:
            _log.error("security.quarantine_child.spawn_failed", error_class=type(exc).__name__)
            raise QuarantineChildSpawnError(t("security.quarantine_child.spawn_failed")) from exc
    finally:
        # --- window CLOSES (no ``await`` ran). Restore prior occupants (or clear the target). ---
        for fd in literal_targets:
            if fd in saved:
                os.dup2(saved[fd], fd)
                os.close(saved[fd])
            else:
                with contextlib.suppress(OSError):
                    os.close(fd)
        # Close each source EXACTLY ONCE. If lifted, close both the temp dup and the original; else the
        # original alone (which is `*_src`). The child holds its own fd 3/4 via pass_fds, so dropping the
        # parent copies here is correct.
        for original, src, moved in (
            (read_fd, read_src, read_moved),
            (control_child_fd, control_src, control_moved),
        ):
            if src is None:
                continue
            with contextlib.suppress(OSError):
                os.close(src)
            if moved:
                with contextlib.suppress(OSError):
                    os.close(original)

    try:
        deliver_provider_key_via_fd3(write_fd=write_fd, key=provider_key)
    except ProviderKeyDeliveryError as exc:
        _log.error("security.quarantine_child.provider_key_delivery_failed", reason=exc.reason)
        await _terminate_and_reap(process)
        if control_parent is not None:
            with contextlib.suppress(OSError):
                control_parent.close()
        raise QuarantineChildSpawnError(
            t("security.quarantine_child.provider_key_delivery_failed")
        ) from exc

    return _SubprocessChildIO(process, control_parent=control_parent, egress_config=egress_config)
```

> **FOLD-A coverage mandate (rev.2, H2/H3):** the aliasing (`_lift_above_targets` moved-True) branch and the finally `else: os.close(fd)` arc are NOT reachable with real `os.pipe`/socketpair under pytest (they return high fds). Unit-test them by **monkeypatching `os.dup2`/`os.dup`/`os.pipe`/`make_control_socketpair`** (the existing `test_quarantine_child_io.py` discipline — "do not actually dup onto fd 3 in-process; it clobbers the test runner"), forcing a source onto fd 3/4 and forcing the unsaved-target `else`. Also add the `control_fd=True + egress_config=None` raise and a `ProviderKeyDeliveryError` on a `control_fd=True` spawn (control-end close arc). This block is a starting point; TDD RED→GREEN on these tests is what verifies the final form.

**FOLD-B (rev.2, M-3): keep `broker_socket` CONCRETE — do NOT widen the `ChildIO` Protocol in PR2a.** PR2a never dispatches `broker_socket` through a `ChildIO`-typed variable (only the docker probe calls it on the concrete `_SubprocessChildIO`), and adding a required Protocol method breaks three existing test doubles (`_RecordingChildIO`, `_FakeQuarantineChildIO`, `_EchoingChildDouble`) under pyright. So **Step 3 below (the Protocol edit) is DROPPED**; add `broker_socket` only on `_SubprocessChildIO`. The Protocol widening lands in PR2b when `QuarantineStdioTransport.dispatch` actually calls it. **Also remove the `# pragma: no cover` on `broker_socket`'s unconfigured guard** (M-1/L-3: it is a fail-loud security branch — §9 forbids pragma-ing security logic) and add a 3-line test: `_SubprocessChildIO(fake, control_parent=None, egress_config=None).broker_socket()` → raises `QuarantineChildSpawnError`.

Use the name `make_control_socketpair` (imported directly from `control_fd_broker`) consistently in both the code and the import — the rev.1 `make_control_pair_for_spawn` alias is dropped (FOLD L1). Add `import socket` to the module imports. Add the two new `t()` keys in Step 5.

- [ ] **Step 5: Add the i18n message keys**

Add to the message catalog source (the `security.quarantine_child.*` group): `broker_unconfigured` = "Quarantine child egress broker is not configured.", `child_module_not_allowed` = "Refusing to spawn the quarantine child with a non-allowlisted module.". Then run the i18n drift cycle:

Run: `uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins && uv run pybabel update -i /tmp/alfred.pot -d src/alfred/locale --no-fuzzy-matching && uv run pybabel compile -d src/alfred/locale`
Fill the new `msgstr`s by hand (brace-free). Never pass `--omit-header`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/unit/security/test_quarantine_child_io_control_fd.py -q`
Expected: PASS (4 passed).

- [ ] **Step 7: Regression — the existing spawn tests + import/egress guards stay green**

Run: `uv run pytest tests/unit/security/test_quarantine_child_import_closure.py tests/unit/egress/test_in_core_http_egress_guard.py tests/adversarial/sandbox_escape/test_quarantined_llm_not_yet_spawned_while_egress_open.py -q`
Expected: PASS — `__main__.py` is untouched, `control_fd_broker` uses only raw sockets (G4-exempt), so no guard regresses.

- [ ] **Step 8: Type-check + commit**

Run: `uv run mypy src/alfred/security/quarantine_child_io.py src/alfred/security/quarantine_transport.py`

```bash
git add src/alfred/security/quarantine_child_io.py src/alfred/security/quarantine_transport.py tests/unit/security/test_quarantine_child_io_control_fd.py src/alfred/locale
git commit -m "feat(security): opt-in control-fd spawn plumbing + _SubprocessChildIO.broker_socket #340

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 4: the wheel-co-located probe child (`_brokered_probe.py`)

**Files:**

- Create: `src/alfred/security/quarantine_child/_brokered_probe.py`
- Test: unit-covered indirectly via `recv_passed_fd` (Task 1); the probe body itself is `# pragma: no cover` (subprocess entry, docker-only — the `__main__.py:310` precedent).

**Interfaces:**

- Consumes: `alfred.egress.control_fd_broker.recv_passed_fd`, `ControlFdBrokerError`; the inherited control fd `4`.
- Produces: a JSON verdict on **stdout** (fd 1): `{"c1_enetunreach": bool, "c1_errno": int, "c2_live": bool, "peer": [...], "usable": bool}`.

- [ ] **Step 1: Write the probe (thin, pragma'd; reusable mechanics already unit-covered in Task 1)**

```python
# src/alfred/security/quarantine_child/_brokered_probe.py
"""Diagnostic probe child for the #340 PR2a docker C1/C2 test — INERT in production.

Spawned only by tests/integration/test_quarantine_fd_broker_real_spawn.py with child_module=
_BROKERED_PROBE_MODULE. Ships in the wheel so it lands under the bwrap policy's /usr ro-bind
(ADR-0030) — no policy widening. It receives one SCM_RIGHTS fd per control frame on fd 4, and writes
its C1/C2/usability verdict to STDOUT (fd 1) — NEVER back over fd 4 (fd 4 is strictly one-way,
core->child; the core never recv's it, closing reverse-fd-injection by construction; sec-002).

The reusable recvmsg mechanics live in (and are unit-covered by) egress.control_fd_broker; this entry
is a thin `# pragma: no cover` subprocess shim (the __main__.py subprocess-entry precedent) — only the
genuinely netns-only C1 line cannot be unit-covered.
"""
from __future__ import annotations

import json
import socket
import struct
import sys

from alfred.egress.control_fd_broker import recv_passed_fd

_CONTROL_FD = 4
_LITERAL_IP = ("1.1.1.1", 443)  # a routable public IP — a fresh connect MUST fail ENETUNREACH in the empty netns


def _write_verdict(verdict: dict[str, object]) -> None:  # pragma: no cover - subprocess I/O
    body = json.dumps(verdict).encode("utf-8")
    sys.stdout.buffer.write(struct.pack(">I", len(body)) + body)
    sys.stdout.buffer.flush()


def _probe_once(control_end: socket.socket) -> dict[str, object]:  # pragma: no cover - needs the empty netns
    _data, fd = recv_passed_fd(control_end)
    passed = socket.socket(fileno=fd, family=socket.AF_INET, type=socket.SOCK_STREAM)
    try:
        peer = list(passed.getpeername())
        so_error = passed.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)  # C2 liveness
        passed.sendall(b"ping")  # minimal usability over the passed fd (plaintext; no TLS in PR2a)
        usable = passed.recv(16) != b""
    finally:
        passed.detach()  # do not double-close the passed fd
    # C1 negative control: a FRESH socket to a routable IP must be ENETUNREACH (empty netns).
    try:
        socket.create_connection(_LITERAL_IP, timeout=3).close()
        c1 = {"c1_enetunreach": False, "c1_errno": 0}
    except OSError as exc:
        c1 = {"c1_enetunreach": True, "c1_errno": exc.errno or 0}
    return {**c1, "c2_live": so_error == 0, "peer": peer, "usable": usable}


def main() -> None:  # pragma: no cover - subprocess entry (docker-only)
    control_end = socket.socket(fileno=_CONTROL_FD, family=socket.AF_UNIX, type=socket.SOCK_STREAM)
    while True:
        try:
            verdict = _probe_once(control_end)
        except (OSError, ValueError):
            return  # control channel closed / EOF — the test tore the child down
        _write_verdict(verdict)


if __name__ == "__main__":  # pragma: no cover - subprocess entry point
    main()
```

- [ ] **Step 2: Verify it imports cleanly + does not touch fd 4 at import**

Run: `uv run python -c "import alfred.security.quarantine_child._brokered_probe as p; print('ok', hasattr(p, 'main'))"`
Expected: `ok True` (no hang — the fd-4 socket is built in `main()`, never at import).

- [ ] **Step 3: Confirm no guard regression (probe is not `__main__.py`, constructs no httpx)**

Run: `uv run pytest tests/unit/security/test_quarantine_child_import_closure.py tests/unit/egress/test_in_core_http_egress_guard.py -q`
Expected: PASS. (`_brokered_probe` imports `alfred.egress.control_fd_broker` → `socket`; G1 forbids none of these; G4 exempts raw sockets; G3 reads only `__main__.py`.)

- [ ] **Step 4: Type-check + lint + commit**

Run: `uv run mypy src/alfred/security/quarantine_child/_brokered_probe.py && uv run ruff check src/alfred/security/quarantine_child/_brokered_probe.py`

```bash
git add src/alfred/security/quarantine_child/_brokered_probe.py
git commit -m "feat(security): wheel-co-located brokered-fd probe child (docker C1/C2, pragma-no-cover) #340

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 5: the raw-socket-egress ratchet guard

**Files:**

- Create: `tests/adversarial/sandbox_escape/test_only_sanctioned_raw_socket_egress_site.py`

**Interfaces:**

- Consumes: an AST walk of `src/alfred/**/*.py`. Produces: a release-blocking guard.

- [ ] **Step 1: Write the guard test (it must PASS immediately — the invariant already holds)**

```python
# tests/adversarial/sandbox_escape/test_only_sanctioned_raw_socket_egress_site.py
"""Ratchet: control_fd_broker.py is the SOLE in-core site that connects an INET socket AND passes a
descriptor via sendmsg(SCM_RIGHTS) in the same module (#340 PR2a, ADR-0050).

Pinned on the CONJUNCTION (sec-001): create_connection OR socket.socket(AF_INET*)+.connect(), AND a
sendmsg(..., SCM_RIGHTS, ...) — either half alone is a bad discriminator (socket is pervasive in-core;
create_connection is bypassable). A documented AST residual in the ADR-0042 tradition: an obfuscated
raw-socket egress evading the match is the accepted static-analysis gap, backstopped by the child's
empty netns. A NEW file matching the conjunction trips this red.
"""
from __future__ import annotations

import ast
from pathlib import Path

_SRC_ROOT = Path(__file__).resolve().parents[3] / "src" / "alfred"
_SANCTIONED = {"egress/control_fd_broker.py"}
_MIN_SRC_FILES = 100  # floor so a broken _SRC_ROOT fails loud, not vacuously


def _has_scm_rights_sendmsg(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "sendmsg":
            if any(
                isinstance(sub, ast.Attribute) and sub.attr == "SCM_RIGHTS" for sub in ast.walk(node)
            ):
                return True
    return False


def _has_inet_connect(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "create_connection":
                return True
            if node.func.attr == "connect":  # x.connect((host, port)) — pair with an AF_INET socket() below
                return True
    # AF_INET / AF_INET6 socket construction is the connect's companion signal.
    has_inet_sock = any(
        isinstance(sub, ast.Attribute) and sub.attr in {"AF_INET", "AF_INET6"} for sub in ast.walk(tree)
    )
    return has_inet_sock and any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "connect"
        for n in ast.walk(tree)
    )


def test_only_sanctioned_raw_socket_egress_site() -> None:
    files = sorted(_SRC_ROOT.rglob("*.py"))
    assert len(files) >= _MIN_SRC_FILES, f"src scan too small ({len(files)}) — _SRC_ROOT broken?"
    offenders: list[str] = []
    for path in files:
        rel = path.relative_to(_SRC_ROOT.parent.parent / "src" / "alfred").as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if _has_scm_rights_sendmsg(tree) and _has_inet_connect(tree) and rel not in _SANCTIONED:
            offenders.append(rel)
    assert not offenders, (
        "new raw-socket-egress site(s) outside the sanctioned broker (ADR-0050): "
        f"{offenders}. Route gateway reachability through egress/control_fd_broker.py."
    )
```

- [ ] **Step 2: Run it — must pass now, and prove it BITES (temporarily plant an offender)**

Run: `uv run pytest tests/adversarial/sandbox_escape/test_only_sanctioned_raw_socket_egress_site.py -q`
Expected: PASS.
Then temporarily add a scratch file `src/alfred/_scratch_offender.py` with `import socket, array` and a function doing `s=socket.create_connection((h,p)); p2.sendmsg([b"x"],[(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i",[s.fileno()]))])`, re-run, confirm it FAILS naming `_scratch_offender.py`, then delete the scratch file and re-run to confirm PASS. (Do not commit the scratch file.)

- [ ] **Step 3: Commit**

```bash
git add tests/adversarial/sandbox_escape/test_only_sanctioned_raw_socket_egress_site.py
git commit -m "test(adversarial): raw-socket-egress ratchet — control_fd_broker is the sole site #340

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 6: the dormant-mechanism adversarial corpus payload

**Files:**

- Create: `tests/adversarial/sandbox_escape/sbx_2026_0XX_brokered_fd_dormant.yaml` (pick the next free `sbx-2026-0XX` id via `ls tests/adversarial/sandbox_escape/sbx_2026_*.yaml`)
- Create: `tests/adversarial/sandbox_escape/test_brokered_fd_dormant_mechanism.py`
- Modify: `.github/workflows/adversarial.yml` (register the new test node-id)

**Interfaces:**

- Consumes: `spawn_quarantine_child_io` (the opt-in default), `recv_passed_fd`, the shipped policy.

- [ ] **Step 1: Write the corpus YAML** (follow the existing `sbx_2026_005_*.yaml` shape — id, category `sandbox_escape`, threat-model ref, provenance, expected containment):

```yaml
id: sbx-2026-0XX-brokered-fd-dormant
category: sandbox_escape
title: The PR2a fd-broker mechanism grants no egress while dormant on the live path
threat_model: HARD #5 (dual-LLM) + ADR-0040 (connectivity-free core) + #230/#340
provenance: "#340 PR2a — the SCM_RIGHTS reachability-broker ships dormant; the live echo child never receives a control fd."
containment: enforced
assertions:
  - "The live spawn (control_fd default off) passes no fd 4 — pass_fds == (3,)."
  - "The child still cannot self-connect — a fresh socket to a routable IP is ENETUNREACH (empty netns preserved)."
  - "The control channel passes exactly one connected gateway socket, one direction — no reverse fd."
```

- [ ] **Step 2: Write the enforcing test**

```python
# tests/adversarial/sandbox_escape/test_brokered_fd_dormant_mechanism.py
from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from alfred.security import quarantine_child_io as qcio
from alfred.egress.control_fd_broker import ControlFdBrokerError, recv_passed_fd


@pytest.mark.asyncio
async def test_live_echo_spawn_passes_no_control_fd() -> None:
    captured: dict[str, object] = {}

    class _FakePopen:
        def __init__(self, argv, **kw):  # noqa: ANN001
            captured["pass_fds"] = tuple(kw["pass_fds"])
            self.stdin = self.stdout = self.stderr = None
            self.returncode = None
        def poll(self):  # noqa: ANN001
            return 0

    with patch.object(qcio.subprocess, "Popen", _FakePopen), patch.object(qcio, "deliver_provider_key_via_fd3"):
        await qcio.spawn_quarantine_child_io(provider_key="k")  # default: control_fd False
    assert captured["pass_fds"] == (3,)  # dormant: no fd 4 on the live path


def test_control_channel_refuses_a_second_or_zero_fd() -> None:
    # Capability envelope: exactly one fd; zero fds is loud (a compromised child cannot coax a no-fd frame through).
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        parent.sendall(b"\x01")  # data, no fd
        with pytest.raises(ControlFdBrokerError):
            recv_passed_fd(child)
    finally:
        parent.close(); child.close()
```

(The C1-ENETUNREACH-in-the-real-netns assertion is exercised by the docker probe in Task 7; this unit test covers the dormancy + capability-envelope halves that run without bwrap.)

- [ ] **Step 3: Register the node-id in `adversarial.yml`**

Add `tests/adversarial/sandbox_escape/test_brokered_fd_dormant_mechanism.py::test_live_echo_spawn_passes_no_control_fd` (and `::test_control_channel_refuses_a_second_or_zero_fd`) to the hardcoded collected-node enumeration in `.github/workflows/adversarial.yml` (the block that asserts sandbox_escape nodes are collected-even-if-skipped) so a silent deletion of the payload fails the release-blocking gate (test-003).

- [ ] **Step 4: Run + confirm collected**

Run: `uv run pytest tests/adversarial/sandbox_escape/test_brokered_fd_dormant_mechanism.py -q && uv run pytest tests/adversarial/sandbox_escape/ --collect-only -q | grep brokered_fd_dormant`
Expected: tests PASS; the collect-only listing shows both nodes.

- [ ] **Step 5: Commit**

```bash
git add tests/adversarial/sandbox_escape/sbx_2026_0XX_brokered_fd_dormant.yaml tests/adversarial/sandbox_escape/test_brokered_fd_dormant_mechanism.py .github/workflows/adversarial.yml
git commit -m "test(adversarial): dormant-mechanism corpus payload — broker grants no live egress #340

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 7: docker-gated C1/C2 real-spawn integration test (GATED on #251)

**Files:**

- Create: `tests/integration/test_quarantine_fd_broker_real_spawn.py`

**PRE-CONDITION:** #251 (child stderr drain) merged to `main` and this branch rebased onto it — otherwise a probe failure hangs / mis-attributes (spec §11.6). Do not execute this task before #251 lands.

**Interfaces:**

- Consumes: `spawn_quarantine_child_io(control_fd=True, child_module=_BROKERED_PROBE_MODULE, egress_config=...)`, `io.broker_socket()`, `io.read_frame()`. A minimal in-test stdlib stub TCP proxy standing in for the gateway.

- [ ] **Step 1: Write the docker-gated test** (mirror the `_DOCKER_ONLY` skipif of `tests/integration/test_quarantine_child_real_spawn.py`):

```python
# tests/integration/test_quarantine_fd_broker_real_spawn.py
from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import sys
import threading

import pytest

from alfred.security import quarantine_child_io as qcio

_DOCKER_ONLY = pytest.mark.skipif(
    not (sys.platform.startswith("linux") and shutil.which("bwrap") and os.geteuid() == 0
         and os.environ.get("ALFRED_QUARANTINE_CHILD_PYTHON")),
    reason="brokered-fd real-spawn needs bwrap + Linux + root + a provisioned child interpreter (integration-privileged)",
)


class _StubProxy:
    """A trivial TCP server the core 'brokers' a connection to; echoes so the probe's usability I/O passes."""
    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0)); self._sock.listen(4)
        self.host, self.port = self._sock.getsockname()
        self._t = threading.Thread(target=self._serve, daemon=True); self._t.start()
    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()
    def _echo(self, conn: socket.socket) -> None:
        with conn:
            data = conn.recv(64)
            if data:
                conn.sendall(data)
    def close(self) -> None:
        self._sock.close()


class _Cfg:
    def __init__(self, host: str, port: int) -> None:
        self.egress_proxy_url = f"http://{host}:{port}"


def _read_verdict(io: qcio._SubprocessChildIO) -> dict:  # read_frame returns header+body; strip header
    raw = _await(io.read_frame())
    length = struct.unpack(">I", raw[:4])[0]
    return json.loads(raw[4 : 4 + length])


@_DOCKER_ONLY
@pytest.mark.asyncio
async def test_brokered_fd_crosses_bwrap_and_child_cannot_self_connect() -> None:
    proxy = _StubProxy()
    io = await qcio.spawn_quarantine_child_io(
        provider_key="probe-key", control_fd=True,
        child_module=qcio._BROKERED_PROBE_MODULE, egress_config=_Cfg(proxy.host, proxy.port),
    )
    try:
        fd_counts = []
        for _ in range(2):  # >=2 sequential passes to the SAME still-alive child
            await io.broker_socket()
            verdict = _read_verdict(io)
            assert verdict["c1_enetunreach"] is True   # C1: empty netns (fresh socket -> ENETUNREACH)
            assert verdict["c2_live"] is True           # C2: getpeername/SO_ERROR — a live socket crossed
            assert list(verdict["peer"]) == [proxy.host, proxy.port]
            assert verdict["usable"] is True            # minimal plaintext I/O over the passed fd
            fd_counts.append(len(os.listdir("/proc/self/fd")))  # CORE-process fd count (close-after-sendmsg)
        assert fd_counts[0] == fd_counts[1]  # fd-count stable across passes — no core-side leak
    finally:
        await io.aclose()
        proxy.close()
```

(Provide a small `_await` helper or restructure to `await` directly — the plan's `_read_verdict` is illustrative; the executor should inline the `read_frame` await inside the async test. Keep the assertions verbatim.)

- [ ] **Step 2: Run under the privileged docker harness** (the sandbox adversarial pattern):

Run: `docker run --rm --privileged -v "$PWD":/work -w /work debian:bookworm bash spikes/...` → in-container: install bwrap + a provisioned `ALFRED_QUARANTINE_CHILD_PYTHON`, `pip install -e .`, then `uv run pytest tests/integration/test_quarantine_fd_broker_real_spawn.py -v`.
Expected: PASS (the C1/C2/usability/fd-stable assertions hold). Use the repo's existing `integration-privileged` provisioning recipe; do NOT add an arm64 leg (#269).

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_quarantine_fd_broker_real_spawn.py
git commit -m "test(integration): docker C1/C2 brokered-fd real-spawn (amd64 privileged) #340

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 8: CI gates — named per-file coverage + the both-halves "assert RAN" paper-gate

**Files:**

- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add the named 100% per-file gate for `control_fd_broker.py`** in the `coverage-gates` job, in **BOTH** the unit `--include` list AND the combined `--include` list (there is no `egress/*` glob — `egress/` files are protected only by enumerated entries; mirror the existing named `quarantine_child_io.py` gate). Example line to add alongside the existing named gates:

```yaml
      - name: 100% coverage gate — control_fd_broker (raw-socket egress primitive)
        run: uv run coverage report --include='src/alfred/egress/control_fd_broker.py' --fail-under=100 --show-missing
```

- [ ] **Step 2: Add the both-halves brokered-leg "assert RAN" paper-gate** in `integration-privileged` — **COPY THE WORKING SIBLING VERBATIM** (`ci.yml:1398-1408`, the `#245` test-104 gate). The rev.1 snippet was broken twice (test-C1): (1) `pytest -rs -q` emits **no per-node `PASSED` line** (only dots + a `N passed` summary — a `PASSED` line needs `-rA`/`-rP`), and the pytest format is `PASSED <path>::<node>` (outcome FIRST), so the rev.1 grep matched nothing and the job was **permanently red even on success**; (2) the command lacked `sudo`/root + `ALFRED_QUARANTINE_CHILD_PYTHON`, so the skipif was always True → the test always SKIPPED. The correct gate runs the leg **as root with the provisioned interpreter**, fails on any `skipped`, and asserts `1 passed` (the file has one test):

```yaml
      - name: Assert the brokered-fd real-spawn leg RAN (not skipped)
        run: |
          sudo env "PATH=${UV_DIR}:${PATH}" "ALFRED_QUARANTINE_CHILD_PYTHON=${BOUND_PY}" \
            "${UV_BIN}" run pytest tests/integration/test_quarantine_fd_broker_real_spawn.py \
            -rs -p no:cacheprovider --cov-fail-under=0 | tee /tmp/broker.out
          if grep -qE "(^|[^0-9])[1-9][0-9]* skipped" /tmp/broker.out; then
            echo '::error::brokered-fd leg SKIPPED — release-blocking'; exit 1; fi
          grep -q "1 passed" /tmp/broker.out \
            || { echo '::error::brokered-fd leg did not report 1 passed'; exit 1; }
```

(Reuse the exact `UV_DIR`/`UV_BIN`/`BOUND_PY` env the sibling `#245` step already sets in `integration-privileged` — do NOT reinvent them. The pre-check half is the sibling's existing "Assert spawn-enabling preconditions hold" step; extend it to also check the stub-proxy/probe preconditions if writing-plans finds a gap.)

- [ ] **Step 3: Validate the workflow YAML**

Run: `uv run python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ci.yml ok')"`
Expected: `ci.yml ok`. (Full CI validation happens on the PR; this is a local syntax guard.)

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci(340): named control_fd_broker 100% gate + both-halves brokered-leg RAN paper-gate #340

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 9: ADR-0050 + human-gated doc-drift flag

**Files:**

- Create: `docs/adr/0050-quarantine-child-scm-rights-reachability-broker.md`

- [ ] **Step 1: Write ADR-0050** (standard ADR shape: Context / Decision / Consequences / Alternatives). It MUST record, per spec §8 (rev.2, arch-001 corrected):
  1. The core-side raw-socket + SCM_RIGHTS **reachability-broker** as a deliberate audited egress exception (core opens a bare TCP socket to the gateway proxy, passes the fd, writes zero application bytes; child does CONNECT+TLS+HTTP; TLS terminates in the child).
  2. The **empty-netns-preserved** invariant (evidence: the C1 ENETUNREACH negative control).
  3. The **two-layer mapping**: child kernel empty-netns = enforcement-of-record; core `connect()` to `alfred-gateway` is **internal `alfred_internal` traffic**, the same hop `EgressClient` makes — NOT external reach, so NOT a connectivity-free-core weakening (PRD §5 is about external sockets).
  4. The guard-exemption as a **conscious extension** + the new raw-socket-egress ratchet (pinned on the INET-connect + SCM_RIGHTS conjunction; a documented AST residual, ADR-0042 tradition) + the child-side ratchet flips PR2b will make and why they're safe.
  5. The **CONNECT-location decision** (child-does-CONNECT reference; PR2a passes a bare socket) + the **#358 Proxy-Auth forward-gate**.
  6. Why the **Discord AF_UNIX bridge cannot be reused** — the CORRECTED reasons (arch-001): the ADR-0043 byte-splice carries TLS **ciphertext** (the Discord child also terminates TLS), so "a plaintext relay would expose raw T3" is a FALSE inference; the real reasons are (a) connectivity-free-core hosting (a gateway-egress socket can't be mounted in the child without reopening G7-3) and (b) `aiohttp` exposes no fd hook (so ADR-0043 reserved the fd-broker for the in-house child). Cross-ref ADR-0015, ADR-0043, ADR-0042.
  7. The **dormancy contract as an explicit auditable invariant** (arch-003): `control_fd=False` by default (software guard) over the kernel empty netns; the PR2b `control_fd`-flip is the security-posture change under the sign-off.
  8. The **per-extraction core-side egress-audit row** as a hard PR2b pre-gate (ADR-0040 residual vii) — PR2a defines the error type only.
  Add a dated reference line to ADR-0040's residual panel pointing at ADR-0050 (arch-004).

- [ ] **Step 2: Markdown-lint the ADR**

Run: `npx markdownlint-cli2 docs/adr/0050-quarantine-child-scm-rights-reachability-broker.md`
Expected: clean (fix MD060 spaced-separators, MD032 list blanks, MD031 fence blanks, MD004 no `+`/`-` bullets; re-read after any `--fix`, it can corrupt prose).

- [ ] **Step 3: Note the human-gated CLAUDE.md carve-out in the PR body (do NOT edit CLAUDE.md)**

Record in the eventual PR description (not a code change — CLAUDE.md self-improvement rule #4 is human-gated): "CLAUDE.md security rule ('never open an external socket directly from core') wants a one-line carve-out for the sanctioned raw-socket reachability-broker toward the **internal** gateway proxy (ADR-0050 pointer) — the broker opens an internal socket, not a literal violation, but a reviewer could misread `control_fd_broker.py` doing `socket.connect()`."

- [ ] **Step 4: Commit**

```bash
git add docs/adr/0050-quarantine-child-scm-rights-reachability-broker.md docs/adr/0040-connectivity-free-core-mandatory-egress-chokepoint.md
git commit -m "docs(adr): ADR-0050 quarantine-child SCM_RIGHTS reachability-broker #340

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Final verification (before PR)

- [ ] `uv run pytest tests/unit tests/adversarial -q` — all green (adversarial is release-blocking; PR2a edits `src/alfred/security/`).
- [ ] `uv run mypy src/ && uv run pyright src/` — clean.
- [ ] `uv run ruff check . && uv run ruff format --check .` — clean.
- [ ] `uv run coverage` gates: `src/alfred/security/*` 100% and the named `control_fd_broker.py` 100%.
- [ ] Task 7 (docker leg) green under the privileged-Linux amd64 harness (after #251 merged).
- [ ] `make check` before push (catches mechanical breakage in ~5s; `make …|tail` masks the exit code — check `$?`).
- [ ] Confirm `git status` shows only the named PR2a paths (NEVER `git add -A` — the untracked `.github/mcp.json` / rulesync / `uv.lock` tool-outputs must stay out).

## Self-Review (author, against the spec)

**Spec coverage:** §4.1 broker → Tasks 1–2; §4.2 spawn plumbing + ownership → Task 3; §4.3 probe → Task 4; §5 data-flow (fd-4 one-way, stdout verdict) → Tasks 3/4/7; §6 CONNECT-location → ADR-0050 (Task 9); §7 raw-socket ratchet → Task 5, dormant-mechanism gate → Task 6, "no policy edit / G-guards untouched" → Task 3 Step 7 regression; §8 ADR-0050 + doc-drift → Task 9; §9 testing (docker C1/C2 + paper-gate + named gate + unit coverage + corpus registration) → Tasks 6–8; §13 folds — H1 (probe pragma + factored mechanics) Task 4/Task 1, sec-002/core-003 (fd-4 one-way/stdout) Tasks 3/4, core-002 (settimeout) Task 2, arch-001 (Discord rationale) Task 9, ratchet conjunction Task 5, two-gates Task 8, adversarial registration Task 6. **§11 (PR2b) is deliberately out of scope** — no task builds the child-side transport / `_CONSTRUCT_ALLOWLIST` / policy edit / `_build_provider`.

**Placeholder scan:** the `sbx-2026-0XX` id and the exact `ci.yml` line numbers are resolved at execution (`ls`/`grep`) — flagged inline, not left as prose TODOs. The docker `_await`/`_read_verdict` helper is illustrative and its resolution is spelled out (inline the await). No "add error handling"/"similar to Task N" placeholders.

**Type consistency:** `ControlFdBrokerError.reason: str`, `make_control_socketpair() -> tuple[socket.socket, socket.socket]`, `recv_passed_fd(...) -> tuple[bytes, int]`, `broker_connected_socket(*, parent_end, proxy_config)`, `_SubprocessChildIO(process, *, control_parent, egress_config)`, `spawn_quarantine_child_io(*, provider_key, control_fd=False, child_module=_CHILD_MODULE, egress_config=None)`, `_CONTROL_FD = 4`, `_BROKERED_PROBE_MODULE` — consistent across Tasks 1–7.

---

## Plan-review fold log (3-lens focused: core + security + test, rev.2 — 2026-07-10)

**1 Critical + gate-breaking Highs caught before TDD** (0 design objections — the design is ratified). No trust-boundary property is broken (dormancy holds, zero-app-byte core, one-way fd 4, ratchet passes clean — all three lenses confirm). **The folds below OVERRIDE the task bodies above where they conflict — read this log before implementing each task.** `FOLD-A` (Task-3 aliasing), `FOLD-B` (broker_socket concrete), the Task-8 paper-gate, and the `make_control_socketpair` name are already applied inline above.

### Critical / High (must be done or the release-blocking gates fail on first `make check`)

- **[C1 — Task 8] paper-gate rewritten** (applied inline): the rev.1 grep + missing root/provisioning made it permanently red AND blind to skips. Now copies the working `#245` sibling (sudo + `ALFRED_QUARANTINE_CHILD_PYTHON`, fail-on-`skipped`, assert `1 passed`).
- **[H — Task 3 aliasing] FOLD-A applied inline** (double-close + read-end leak): lift both sources above the target range first, close each source once; unit-test the aliasing + `else`-restore arcs by monkeypatching `os.dup2`/`os.dup`/`os.pipe`/`make_control_socketpair`.
- **[H — Task 1/2 control_fd_broker 100% gate] WRITE these coverage tests (do not defer):**
  - `recv_passed_fd` **MSG_CTRUNC** branch → `sendmsg` **two** fds into the 1-fd ancillary buffer; assert `reason == "ancillary_truncated"`. (Also closes the >1-fd capability-envelope teeth gap — Task 6 M4.)
  - `recv_passed_fd` inner `if level==SOL_SOCKET and typ==SCM_RIGHTS` **False** branch → monkeypatch `control_end.recvmsg` to return a non-`SCM_RIGHTS` cmsg; assert `expected_exactly_one_fd`. (A real socket can't produce this — needs the mock, or `# pragma: no branch` on the inner-if with justification.)
  - `_connect_and_send` `short_data_send` → monkeypatch `parent_end.sendmsg` to return `0`; `sendmsg_failed` → monkeypatch it to raise `OSError`. Task 2 Step 5's "add if the report shows a miss" is UPGRADED to "write these explicitly" — the file is under a named 100% line+branch gate.
- **[H — Task 3 quarantine_child_io 100% gate] add the new-branch tests + fix the regression list:**
  - Force each new branch: `control_fd=True + egress_config=None` raise; the aliasing loop (monkeypatch `os.pipe`/`make_control_socketpair` so a source lands on 3/4); the finally unsaved-target `else` (monkeypatch `os.dup` to raise for fd 4); a `ProviderKeyDeliveryError` on a `control_fd=True` spawn (the `control_parent.close()` arc).
  - **[M1] Monkeypatch `os.dup2` in the new tests** — do NOT run real `os.dup2(read_fd, 3)` in the pytest process (`test_quarantine_child_io.py:129`: "would clobber the test runner"). This is also the lever that makes the branch coverage deterministic.
  - **Step 7 regression run must ALSO include** `tests/unit/security/test_quarantine_child_io.py` and `tests/unit/security/test_quarantine_child_io_i18n.py` (the i18n test enumerates the `security.quarantine_child.*` key set Step 5 grows).
- **[H — Task 4 probe module-scope coverage] add a one-line import test** run under pytest/coverage: `import alfred.security.quarantine_child._brokered_probe as p; assert hasattr(p, "main")` (covers the module-scope lines; the function bodies stay `# pragma: no cover`). The rev.1 `python -c` in Step 2 runs OUTSIDE coverage and covers nothing → the `security/*` glob gate would go red (the H1 anti-pattern re-introduced at module scope). Alternative: add the file to `[tool.coverage.run] omit` — prefer the import test (matches how `__main__.py` module scope is covered).

### Medium

- **[M-1/L-3 — Task 3] `broker_socket` unconfigured guard:** remove its `# pragma: no cover` (FOLD-B, applied inline) and add the 3-line raise test — a fail-loud security branch must not be pragma'd (§9).
- **[M-2 — Task 7] assert the real HARD #5 property:** the rev.1 usability check passes even if the core wrote a stray byte (the stub echoes it). `_StubProxy` must **record the first bytes it receives** on the brokered connection and the test must assert they equal `b"ping"` — nothing the core prepended. (This is the headline mechanism-level HARD #5 claim; without it Task 7 doesn't prove it.)
- **[M6 — Task 7] write the inlined async form directly** — the rev.1 `_read_verdict`/`_await` helper is non-runnable (`_await` undefined; sync fn awaiting). `await io.read_frame()` inside the async test; the `raw[4:4+length]` strip is correct (`read_frame` returns header+body, verified `quarantine_child_io.py:274-279`).
- **[M-4 — Task 5] add an anti-rot test** `test_sanctioned_site_actually_matches_the_conjunction()` asserting `control_fd_broker.py` trips both `_has_scm_rights_sendmsg` and the connect matcher (the sibling ships `test_sanctioned_spawn_site_actually_exists` for exactly this — else a refactor makes the ratchet vacuously permissive).
- **[M5 — Task 5] register `test_only_sanctioned_raw_socket_egress_site` in `adversarial.yml`'s collected-node enumeration** (the sibling spawn-site guard is at `adversarial.yml:120`) — it runs in the main non-bwrap adversarial pass, so without registration a silent deletion is not caught by the release-blocking collected-node gate.
- **[M2 — Task 2] fix the unreachable test** — connect to a **closed port on `127.0.0.1`** (immediate `ECONNREFUSED` → `gateway_unreachable`), not TEST-NET-3 `203.0.113.1:9` (blocks up to 10 s on a blackhole route).
- **[M3 — Task 2] the live-fd test doesn't assert "closes core copy"** — rename it, or add a core-side `/proc/self/fd` count assertion, or cross-reference that Task 7 proves it. Also use `passed.close()` (not `detach()`) so the accept-thread EOFs and `t.join` returns immediately (L2).

### Low (apply during TDD)

- **[L-1 — Task 5] `_has_inet_connect` dead code:** the AF_INET/AF_INET6 block is unreachable (the loop `return True`s on any `.connect`/`create_connection` first). Simplify to "**any `.connect` OR `create_connection`** AND `sendmsg(SCM_RIGHTS)` in the same module" — confirmed no in-core false positive (SQLAlchemy/psycopg `.connect` sites carry no `SCM_RIGHTS`). Update the docstring/comment to match (don't claim AF_INET is required).
- **[L-2 — Task 1] MSG_CTRUNC fd leak:** on truncation the kernel may install one fd before discarding; close any received fds before raising `ancillary_truncated`.
- **[L-3 — Task 3] control-end + write_fd leak on the `Popen`-OSError path:** close `control_parent` (and let the pipe fds fall to the finally) in the spawn-failure branch too, not only in `aclose`/key-delivery-failure.
- **[L-4 — Task 1] credential leak in the error message:** `_resolve_proxy_addr` interpolates `{proxy_url!r}` into `IOPlaneUnavailableError.detail`; if the proxy URL ever carries basic-auth (foreseeable with the #358 forward-gate) that surfaces the credential. Omit/redact the URL (log scheme/host/port only, the `EgressClient` precedent). NB: `detail=` English inside a `t()` frame is NOT an i18n violation (matches the existing `IOPlaneUnavailableError`).
- **[L2 — Task 4] `passed.close()` not `detach()`** in `_probe_once` (the probe solely owns the SCM-received fd; `detach()` leaks one per loop). Add a one-line "stdout stays frame-only (no stray writes between frames)" note (L5).
- **[L-5 — Task 9] record the probe's import-closure as an accepted residual in ADR-0050** (sec-006: `_brokered_probe` → `control_fd_broker` → `egress.errors`/`i18n`/`errors` is bounded by no guard; clean today but G1 measures only `__main__`). Also record the **fd-4 process-wide clobber widening** (fd 3 AND 4 now clobbered in the window) as an accepted risk (core-L4).
- **[L-6 — Task 2] no outer deadline on the executor `sendmsg`:** theoretical (a 1-byte+1-fd frame to a fresh socketpair won't block), but HARD #7's "never a hang" argues for wrapping the `run_in_executor` in `asyncio.wait_for` with a short bound. Judgment call — note it.
- **[L1 — Task 8] the named `control_fd_broker.py` gate must live in BOTH the `python` (unit) job AND the `coverage-gates` combined job** (the two-gates convention, `ci.yml:619`; there is no `egress/*` glob — `ci.yml:606`). The Step-1 snippet shows one line; add it to both `--include` lists.
- **[L4 — Task 6] confirm a corpus loader/validator consumes `sbx_2026_0XX_brokered_fd_dormant.yaml`** (or mark its assertions documentation-only) — the enforcing test is a separate hand-written module that does not read the YAML.
- **[L-7 — Task 6] the plan's dormancy tests are pure-unit (mock `Popen` + socketpair) and MUST NOT be `@_bwrap_required`** — that would skip them on normal CI and destroy their teeth. This deliberately deviates from spec §9's "mark `@_bwrap_required`"; the plan is correct — call it out so a reviewer doesn't "restore" the gate. The `adversarial.yml` enumeration uses **bare function names** (`grep -q "::${node}"`), not `path::node`.

### Confirmed sound (do not second-guess)

The zero-`await` window discipline; `_connect_and_send`'s `finally: sock.close()` covering a pre-sendmsg raise; the `settimeout(None)` O_NONBLOCK reasoning; `aclose` preserving the CR-#255 single-teardown seam; the ratchet passing clean on the current tree (no existing INET-connect + SCM_RIGHTS site; the Discord bridge is a byte-splice, not fd-passing); the `read_frame` header+body framing math in Task 7; the `ChildIO` runtime-checkable change being runtime-safe (but deferred anyway per FOLD-B); Task 3 Step 7's "G4-exempt" verification; the docker skipif De Morgan shape.

# #443 PR2 — Two-Frame Boot Handshake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the quarantined-LLM child's launcher-refusal detection from first-extraction to boot, by having `spawn_quarantine_child_io` read a two-frame boot handshake (`hello` before `_build_provider`, `ready` before the request loop) from the child INSIDE the spawn — so a genuine launcher refusal refuses boot with an attributed audit row instead of surfacing late.

**Architecture:** The child emits two unsolicited outbound frames during boot: a `hello` (raw `sys.stdout.buffer` write, before its provider exists — provenance: "I exec'd") and a `ready` (via the asyncio writer, before the loop — liveness: "I'm serving"). The diagnostic probe emits `hello` only (it is parent-speaks-first on fd 4; a second read would deadlock — spec §6.1). The host reads these inside `spawn_quarantine_child_io` via the existing `read_frame`; a missing frame raises `QuarantineChildSpawnError`, which the boot caller already maps to a fail-closed `_refuse_boot`, and `read_frame`'s own gate records the launcher-authored `sandbox_refused` row + dispatches the fail-closed T0 hookpoint (the hookpoint PR1 made boot-declarable — so core-001 "goes live" here). The handshake is **count-based**: the host does not parse frame bodies; the security property is that a stdout byte arrived (setting `_child_wrote_stdout`) and the required number of frames completed.

**Tech Stack:** Python 3.14+, asyncio, `subprocess.Popen` (synchronous spawn), `struct` 4-byte-big-endian length framing, structlog, pytest, the adversarial YAML corpus, ADR + spec Markdown.

**Design source:** `docs/superpowers/specs/2026-07-16-443-boot-time-quarantine-health-check-design.md` (rev 3). The three open decisions are RESOLVED (§0) — do not re-litigate. This plan implements §5 (two frames), §6.1 (probe hello), §8 (ADR amendments), §9 (testing + corpus), §11 (residuals), §12 (prose corrections).

## Global Constraints

Every task's requirements implicitly include this section.

- **HARD GATE (launch directive + spec §10):** PR2 builds the handshake **mechanism** only. It does **NOT** activate the real-LLM quarantine child — that is #340 PR2b (human-sign-off gated). The child's `_build_provider` must still return `_DeterministicProvider()`; do not add an Anthropic/DeepSeek client, egress, or a live model.
- **Security hard rules (CLAUDE.md):** fail-closed on the spawn boundary; no silent failures on security paths; the host handshake code is a security boundary → **100% line + branch coverage**. Do not stub the capability/audit layer to "always allow" — use real fixtures.
- **Adversarial suite is release-blocking** — this PR touches `src/alfred/security/`, so run `uv run pytest tests/adversarial` locally before every push.
- **i18n (HARD):** all operator-facing strings via `t()`. This PR adds **no new `t()` key** — the handshake reuses the existing `security.quarantine_child.read_frame_failed` message, and the new boot-context signal is a **structlog event name** (`security.quarantine_child.boot_handshake_failed`), which is NOT `t()` scope. If an implementer nonetheless adds a `t()` string, they MUST run the pybabel extract/update/compile drift dance (`pybabel extract -F babel.cfg`, `pybabel update --no-fuzzy-matching`, `pybabel compile`) and re-run after any line-shifting edit.
- **Child import closure (ADR-0030):** the new `_handshake.py` must be **stdlib-only** (`json`, `struct`) — no privileged imports. The import-closure test (`test_quarantine_child_import_closure.py`) is forbidden-set based, so a stdlib-only sibling under `alfred.security.quarantine_child` needs no allowlist edit, but it must not transitively pull a forbidden root.
- **No new refusal reason.** A launcher refusal already carries its true reason (e.g. `sandbox_block_missing`) in the `SANDBOX_REFUSED_REASONS` vocab. `provider_key_delivery_failed` stays RESERVED (that writer is #444, not this PR).
- **Typing:** `mypy --strict` + `pyright`, PEP 604/585/695, frozen/immutable by default, no bare `Any` without justification, `Mapping` over `dict` for read-only inputs.
- **Commits:** Conventional-commit subject with a literal `#443` AFTER the colon (e.g. `feat(security): #443 read the two-frame boot handshake inside the spawn`). Markdown lint (`markdownlint-cli2@0.22.1 "docs/**/*.md"`) on any `docs/` change.
- **Prose-wave rule (durable lesson):** any prose-only fix on a drift-guard surface (ADR / spec / corpus provenance) MUST be re-reviewed — fix waves reliably introduce a NEW false claim. Verify each claim against the code by execution, not by reading.

**Verified anchors (current `main` @ `65d86886`; re-verify line numbers before editing — they drift):**

- Production spawn: `src/alfred/comms_mcp/daemon_runtime.py:338` (`await spawn_quarantine_child_io(provider_key=..., refusal_recorder=...)`), inside `_build_comms_inbound_extractor`. The `SandboxRefusalAuditor` is built at `:335`. **Already wired — PR2 changes nothing here.**
- Boot refusal: a `QuarantineChildSpawnError` is caught at `src/alfred/cli/daemon/_commands.py:687` → `_refuse_boot(...)` (fail-closed, `NoReturn`). `Supervisor(...)` is 125 lines later at `:783`.
- Host spawn: `src/alfred/security/quarantine_child_io.py` — `spawn_quarantine_child_io` (def `:741`), returns `_SubprocessChildIO(...)` at `:923-928`; `read_frame` `:433`; the sec-001 gate `if refusal_candidate and not self._child_wrote_stdout:` `:580`; `_CHILD_MODULE` `:119`; `_BROKERED_PROBE_MODULE` `:141`; `_ALLOWED_CHILD_MODULES` `:146`.
- Child: `src/alfred/security/quarantine_child/__main__.py` — `main()` `:317`; fd-3 read `:338`; `_build_provider` call `:340`; asyncio writer built `:351`; `_run_mcp_server` call `:352`.
- Probe: `src/alfred/security/quarantine_child/_brokered_probe.py` — `main()` `:99`; fd-4 socket built `:106`; `while True:` `:107`.

---

### Task 1: Shared boot-handshake frame module

**Files:**

- Create: `src/alfred/security/quarantine_child/_handshake.py`
- Test: `tests/unit/quarantine/test_boot_handshake_frames.py`

**Interfaces:**

- Produces (consumed by Tasks 2, 3, 5-test, 6):
  - `HELLO_FRAME: bytes` — a complete length-prefixed frame `struct.pack(">I", len(body)) + body`, body = `{"jsonrpc":"2.0","method":"boot.hello"}` (UTF-8).
  - `READY_FRAME: bytes` — same shape, method `boot.ready`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/quarantine/test_boot_handshake_frames.py
"""The shared boot-handshake frames are well-formed length-prefixed frames (#443)."""

from __future__ import annotations

import json
import struct

from alfred.security.quarantine_child._handshake import HELLO_FRAME, READY_FRAME


def _decode(frame: bytes) -> dict[str, object]:
    length = struct.unpack(">I", frame[:4])[0]
    body = frame[4:]
    assert len(body) == length, "length prefix must equal the body length"
    return json.loads(body)


def test_hello_frame_is_wellformed_and_names_boot_hello() -> None:
    assert _decode(HELLO_FRAME) == {"jsonrpc": "2.0", "method": "boot.hello"}


def test_ready_frame_is_wellformed_and_names_boot_ready() -> None:
    assert _decode(READY_FRAME) == {"jsonrpc": "2.0", "method": "boot.ready"}


def test_hello_and_ready_are_distinct() -> None:
    assert HELLO_FRAME != READY_FRAME
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/quarantine/test_boot_handshake_frames.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'alfred.security.quarantine_child._handshake'`.

- [ ] **Step 3: Write the module**

```python
# src/alfred/security/quarantine_child/_handshake.py
"""Boot-handshake frames for the quarantined-LLM child (#443 PR2).

Two unsolicited, outbound child->host frames emitted during child boot, BEFORE the
JSON-RPC request loop is entered. They let the host verify — INSIDE
``spawn_quarantine_child_io`` — that a real child exec'd and initialized, instead of
inferring it late (at first extraction) from a ``read_frame`` failure shape:

* ``HELLO_FRAME`` — emitted before ``_build_provider`` (a raw ``sys.stdout.buffer``
  write in the child; the asyncio writer does not exist that early). Provenance:
  "a real, exec'd child is running." The host keys its launcher-vs-child audit
  discriminator (``_child_wrote_stdout``) on the FIRST stdout byte, so this frame is
  what proves exec at the boot barrier.
* ``READY_FRAME`` — emitted after the child's asyncio streams are built, before the
  request loop. Liveness: "initialized and serving."

Both use the SAME 4-byte big-endian length prefix as the JSON-RPC wire
(``struct.pack(">I", len(body)) + body``), so the host reads them with the existing
``read_frame`` — no special-casing, and the host never parses the body (the security
property is byte-arrival + frame-count, not content). Stdlib-only (``json``,
``struct``) so the child's minimal import surface (ADR-0030 import-closure gate) is
preserved; the diagnostic probe imports ``HELLO_FRAME`` too.
"""

from __future__ import annotations

import json
import struct

_HELLO_METHOD = "boot.hello"
_READY_METHOD = "boot.ready"


def _boot_frame(method: str) -> bytes:
    body = json.dumps({"jsonrpc": "2.0", "method": method}).encode("utf-8")
    return struct.pack(">I", len(body)) + body


HELLO_FRAME: bytes = _boot_frame(_HELLO_METHOD)
READY_FRAME: bytes = _boot_frame(_READY_METHOD)

__all__ = ["HELLO_FRAME", "READY_FRAME"]
```

- [ ] **Step 4: Run tests + the import-closure guard**

Run: `uv run pytest tests/unit/quarantine/test_boot_handshake_frames.py tests/unit/security/test_quarantine_child_import_closure.py -q`
Expected: PASS (the import-closure test still green — `_handshake` is stdlib-only and under a non-forbidden root).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/security/quarantine_child/_handshake.py tests/unit/quarantine/test_boot_handshake_frames.py
git commit -m "feat(security): #443 add shared boot-handshake frame constants"
```

---

### Task 2: Child emits `hello` (pre-provider) + `ready` (pre-loop)

**Files:**

- Modify: `src/alfred/security/quarantine_child/__main__.py` (import; add `_write_boot_hello` + `_write_boot_ready`; wire into `main()` at `:338`→pre-`_build_provider` and `:351`→pre-`_run_mcp_server`)
- Test: `tests/unit/quarantine/test_quarantine_child_loop.py` (add helper tests; reuse its `_FakeWriter` at `:62`)

**Interfaces:**

- Consumes: `HELLO_FRAME`, `READY_FRAME` (Task 1); the module's existing `_FrameWriter` Protocol (`__main__.py:288`).
- Produces: `_write_boot_hello() -> None` (raw stdout write + flush); `async def _write_boot_ready(writer: _FrameWriter) -> None`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/quarantine/test_quarantine_child_loop.py`:

```python
def test_write_boot_hello_emits_hello_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    """``_write_boot_hello`` writes exactly HELLO_FRAME to the raw stdout buffer + flushes."""
    from alfred.security.quarantine_child import __main__ as qc
    from alfred.security.quarantine_child._handshake import HELLO_FRAME

    written: list[bytes] = []
    flushes = {"n": 0}

    class _Buf:
        def write(self, data: bytes) -> None:
            written.append(bytes(data))

        def flush(self) -> None:
            flushes["n"] += 1

    class _Stdout:
        buffer = _Buf()

    monkeypatch.setattr(qc.sys, "stdout", _Stdout())
    qc._write_boot_hello()
    assert written == [HELLO_FRAME]
    assert flushes["n"] == 1


async def test_write_boot_ready_emits_ready_frame_via_writer() -> None:
    """``_write_boot_ready`` writes READY_FRAME through the asyncio writer + drains."""
    from alfred.security.quarantine_child import __main__ as qc
    from alfred.security.quarantine_child._handshake import READY_FRAME

    writer = _FakeWriter()  # the existing double at test_quarantine_child_loop.py:62
    await qc._write_boot_ready(writer)
    assert b"".join(writer.chunks) == READY_FRAME  # adapt to _FakeWriter's collected-bytes attr
```

> Note: adapt the `_FakeWriter` accessor to whatever attribute it collects into (the recon shows it "collects written frame chunks"). If `_FakeWriter` is not importable at module scope, define a 3-line local writer double with `write`/`async drain`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/quarantine/test_quarantine_child_loop.py -k boot -q`
Expected: FAIL — `AttributeError: module ... has no attribute '_write_boot_hello'`.

- [ ] **Step 3: Add the import + helpers to `__main__.py`**

Add the import near the other `alfred` import (after `__main__.py:54`):

```python
from alfred.security.quarantine_child._handshake import HELLO_FRAME, READY_FRAME
```

Add the two helpers (place them just above `async def main()` at `:317`):

```python
def _write_boot_hello() -> None:
    """Emit the boot ``hello`` frame on fd 1 via a RAW buffered write + flush (#443).

    Called from ``main`` after the fd-3 key read and BEFORE ``_build_provider``: the
    asyncio writer does not exist that early, and the raw write is safe because
    ``configure_stderr_logging`` has already pinned all logging to stderr, so fd 1
    stays byte-pure. This is the child's PROVENANCE signal — the host sets its
    launcher-vs-child audit discriminator on this first stdout byte.
    """
    sys.stdout.buffer.write(HELLO_FRAME)
    sys.stdout.buffer.flush()


async def _write_boot_ready(writer: _FrameWriter) -> None:
    """Emit the boot ``ready`` frame via the asyncio ``writer`` — LIVENESS signal (#443).

    Called from ``main`` after the asyncio streams are built and BEFORE the request
    loop is entered: proof the child initialized and is serving.
    """
    writer.write(READY_FRAME)
    await writer.drain()
```

- [ ] **Step 4: Wire the helpers into `main()`**

In `main()`, insert the hello immediately after the fd-3 read (`:338`) and before the `try:`/`_build_provider` (`:339-340`):

```python
    configure_stderr_logging()
    provider_key = _read_provider_key_from_fd3()
    _write_boot_hello()  # provenance: proves this is a real exec'd child (#443)
    try:
        provider = _build_provider(provider_key)
    finally:
        del provider_key
```

Insert the ready after the writer is constructed (`:351`) and before `_run_mcp_server` (`:352`):

```python
    writer = asyncio.StreamWriter(w_transport, w_protocol, reader, loop)
    await _write_boot_ready(writer)  # liveness: proves initialized + serving (#443)
    await _run_mcp_server(provider, reader=reader, writer=writer)
```

- [ ] **Step 5: Run the child tests**

Run: `uv run pytest tests/unit/quarantine/ -q`
Expected: PASS (the helper tests pass; the existing loop/skeleton tests still pass — `main()` stays `# pragma: no cover`; the hello/ready logic is in the covered helpers).

- [ ] **Step 6: Commit**

```bash
git add src/alfred/security/quarantine_child/__main__.py tests/unit/quarantine/test_quarantine_child_loop.py
git commit -m "feat(security): #443 emit boot hello+ready frames from the quarantine child"
```

---

### Task 3: Diagnostic probe emits `hello` (deadlock fix, §6.1)

**Files:**

- Modify: `src/alfred/security/quarantine_child/_brokered_probe.py` (import; add `_emit_boot_hello`; wire into `main()` after fd-4 socket at `:106`, before `while True:` at `:107`)
- Test: `tests/unit/quarantine/test_brokered_probe_import.py`

**Interfaces:**

- Consumes: `HELLO_FRAME` (Task 1).
- Produces: `_emit_boot_hello() -> None` (raw stdout write + flush). **Only a hello — never a ready.**

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/quarantine/test_brokered_probe_import.py`:

```python
def test_emit_boot_hello_writes_hello_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    """The probe emits exactly HELLO_FRAME (and only a hello) before its recv loop (#443 §6.1)."""
    from alfred.security.quarantine_child import _brokered_probe as bp
    from alfred.security.quarantine_child._handshake import HELLO_FRAME

    written: list[bytes] = []

    class _Buf:
        def write(self, data: bytes) -> None:
            written.append(bytes(data))

        def flush(self) -> None:
            return None

    class _Stdout:
        buffer = _Buf()

    monkeypatch.setattr(bp.sys, "stdout", _Stdout())
    bp._emit_boot_hello()
    assert written == [HELLO_FRAME]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/quarantine/test_brokered_probe_import.py -k boot_hello -q`
Expected: FAIL — `AttributeError: ... has no attribute '_emit_boot_hello'`.

- [ ] **Step 3: Add the import + helper to `_brokered_probe.py`**

Add near the existing import (after `_brokered_probe.py:32`):

```python
from alfred.security.quarantine_child._handshake import HELLO_FRAME
```

Add the helper (place above `def main()` at `:99`):

```python
def _emit_boot_hello() -> None:
    """Emit the boot ``hello`` frame on fd 1 (raw write + flush) — deadlock fix (#443 §6.1).

    The probe is parent-speaks-first: after reconstructing fd 4 it blocks in
    ``recv_passed_fd`` waiting for the parent to broker a socket, writing its first
    verdict only AFTER. Without an early hello, the host's in-spawn handshake read
    would block waiting for a frame while the probe blocks waiting for a brokered fd —
    a deadlock that trips the 25s ``read_frame`` bound and reds the arm64 real-spawn
    CI lane. Emitting the hello BEFORE the recv loop lets the host complete its
    (hello-only) handshake for the probe module and proceed to broker the socket. The
    probe emits ONLY a hello — never a ``ready`` — it has no provider to build.
    """
    sys.stdout.buffer.write(HELLO_FRAME)
    sys.stdout.buffer.flush()
```

- [ ] **Step 4: Wire it into `main()`**

Insert the hello after the fd-4 socket is reconstructed (`:106`) and before the `while True:` loop (`:107`):

```python
    control_end = socket.socket(fileno=_CONTROL_FD, family=socket.AF_UNIX, type=socket.SOCK_STREAM)
    _emit_boot_hello()  # #443 §6.1: unblock the host handshake before the parent-speaks-first recv loop
    while True:
```

> `main()` stays `# pragma: no cover` (docker-only subprocess entry). The hello logic is covered by the Step-1 helper test.

- [ ] **Step 5: Run the probe test**

Run: `uv run pytest tests/unit/quarantine/test_brokered_probe_import.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/security/quarantine_child/_brokered_probe.py tests/unit/quarantine/test_brokered_probe_import.py
git commit -m "fix(security): #443 emit a boot hello from the diagnostic probe to avoid the handshake deadlock"
```

---

### Task 4: Pre-seed boot frames into the non-frame-reading spawn fakes

**Why first:** Task 5 flips `spawn_quarantine_child_io` to READ the handshake. Test fakes that only assert `pass_fds`/dup2/`broker_socket` (never `read_frame` post-spawn) would then fail on a `None`/empty stdout. Pre-seeding their stdout with `[HELLO_FRAME, READY_FRAME]` is a **no-op under today's spawn** (the frames sit unread) and satisfies the new handshake read — so each commit stays green regardless of task order.

**Files:**

- Modify: `tests/unit/security/test_quarantine_child_io_control_fd.py` (its `_FakePopen` at `:69` — give it a stdout)
- Modify: `tests/unit/gateway/test_fd3_spawn_window_shared_property.py` (its `_SyncFakePopen` — give it a stdout)
- Modify: `tests/adversarial/sandbox_escape/test_brokered_fd_dormant_mechanism.py` (its `_FakePopen` — give it a stdout)

**Interfaces:**

- Consumes: `HELLO_FRAME`, `READY_FRAME` (Task 1).

- [ ] **Step 1: control_fd fake — give `_FakePopen` a boot-frame stdout**

In `test_quarantine_child_io_control_fd.py`, import the base helpers + frames near the top:

```python
from alfred.security.quarantine_child._handshake import HELLO_FRAME, READY_FRAME
from tests.unit.security.test_quarantine_child_io import _FakeStdout
```

Change `_FakePopen.__init__` (`:72`) so `stdout` yields the boot frames (leave `stdin`/`stderr` as `None` — `aclose` handles a `None` stderr, and no control_fd test writes to stdin):

```python
    def __init__(self, argv: list[str], **kwargs: Any) -> None:
        self.argv = argv
        self.pass_fds = tuple(kwargs.get("pass_fds", ()))
        self.stdin = self.stderr = None
        # A real child emits hello+ready at boot; the host handshake reads them inside
        # the spawn (#443). The probe reads hello only, so an extra ready sits unread —
        # harmless. Both control_fd spawn tests therefore work with the same seed.
        self.stdout = _FakeStdout([HELLO_FRAME, READY_FRAME])
        self.returncode: int | None = None
```

> The direct-construction tests at `:386`/`:398` (`_FakePopen([])`) call `broker_socket`/`aclose` only — never `read_frame` — so a seeded stdout is harmless there.

- [ ] **Step 2: fd3-window fake — seed `_SyncFakePopen` stdout**

In `test_fd3_spawn_window_shared_property.py`, ensure `_SyncFakePopen` exposes a `stdout` that yields `[HELLO_FRAME, READY_FRAME]` (import them + a `_FakeStdout`-equivalent, or reuse the base `_FakeStdout`). The test asserts the fd-3 window discipline + `pass_fds`; the handshake `await`s run AFTER the dup2 window closes, so `sentinel_ran_at_spawn` (captured at Popen time) is unaffected — but the spawn must now find frames on stdout to return.

- [ ] **Step 3: dormant-mechanism fake — seed its `_FakePopen` stdout**

In `test_brokered_fd_dormant_mechanism.py`, give its local `_FakePopen` a `stdout` yielding `[HELLO_FRAME, READY_FRAME]` (same pattern). The test asserts `pass_fds == (3,)`; the seeded stdout only lets the spawn return.

- [ ] **Step 4: Run the three files (still on today's spawn)**

Run:

```bash
uv run pytest tests/unit/security/test_quarantine_child_io_control_fd.py tests/unit/gateway/test_fd3_spawn_window_shared_property.py tests/adversarial/sandbox_escape/test_brokered_fd_dormant_mechanism.py -q
```

Expected: PASS — the extra stdout frames are unread by today's spawn, so behavior is unchanged.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/security/test_quarantine_child_io_control_fd.py tests/unit/gateway/test_fd3_spawn_window_shared_property.py tests/adversarial/sandbox_escape/test_brokered_fd_dormant_mechanism.py
git commit -m "test(security): #443 pre-seed boot frames into the non-frame-reading spawn fakes"
```

---

### Task 5: Host reads the two-frame handshake inside the spawn (core change)

**Files:**

- Modify: `src/alfred/security/quarantine_child_io.py` (add `_MODULES_EMITTING_READY`; add `_await_boot_handshake`; restructure the tail of `spawn_quarantine_child_io`; correct the §12 docstring)
- Modify: `tests/unit/security/test_quarantine_child_io.py` (fixture + boot-frame sweep + re-target the `_HangingStdout` tests + NEW handshake tests)

**Interfaces:**

- Consumes: `_SubprocessChildIO` (`:368`), `read_frame` (`:433`), `_CHILD_MODULE` (`:119`), `refusal_recorder` seam (already threaded).
- Produces: `_MODULES_EMITTING_READY: frozenset[str]`; `async def _await_boot_handshake(child_io: _SubprocessChildIO, *, child_module: str) -> None`; `spawn_quarantine_child_io` now returns a **handshake-completed** IO or raises.

- [ ] **Step 1: Write the failing host handshake tests**

Add to `tests/unit/security/test_quarantine_child_io.py` (uses the module's own `_FakePopen`/`_framed`; import the frames at top: `from alfred.security.quarantine_child._handshake import HELLO_FRAME, READY_FRAME`):

```python
def _boot_frames() -> list[bytes]:
    """The two frames a real child emits at boot (hello + ready), for a fake stdout (#443)."""
    return [HELLO_FRAME, READY_FRAME]


async def test_spawn_completes_two_frame_handshake_and_returns(monkeypatch, _spawn_capture) -> None:
    """A child that emits hello+ready lets the spawn return a live IO (#443)."""
    # The fixture default now pre-loads [hello, ready, {ok:1}] (see fixture update below).
    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        # The boot frames were consumed by the handshake; the next read is the reply.
        frame = await cio.read_frame()
        assert _decode_result_payload(frame) == {"ok": 1}
    finally:
        await cio.aclose()


async def test_spawn_probe_module_reads_hello_only(monkeypatch) -> None:
    """The probe module handshakes on hello ALONE — a second read would deadlock (§6.1).

    Spawned with control_fd=False (no socketpair needed for this assertion): the point
    is that ``_BROKERED_PROBE_MODULE`` is not in ``_MODULES_EMITTING_READY``, so a
    stdout carrying ONLY a hello (no ready) still lets the spawn RETURN — if the host
    waited for a ready it would hit EOF and raise.
    """
    fake = _FakePopen(stdout_frames=[HELLO_FRAME])  # hello only, no ready
    monkeypatch.setattr(child_io_mod.subprocess, "Popen", lambda *a, **k: fake)
    monkeypatch.setattr(child_io_mod, "deliver_provider_key_via_fd3", lambda **_k: None)
    monkeypatch.setattr(child_io_mod.os, "dup2", lambda s, d, *a, **k: d)
    cio = await spawn_quarantine_child_io(
        provider_key="k", child_module=child_io_mod._BROKERED_PROBE_MODULE
    )
    await cio.aclose()  # returned without a second read → no deadlock


async def test_spawn_launcher_refusal_records_row_and_refuses_boot(monkeypatch) -> None:
    """A zero-stdout refusal at the hello read records the launcher row + raises (§9 sbx-021)."""
    refusal_row = (
        b'{"event":"supervisor.plugin.sandbox_refused","plugin_id":"alfred.quarantined-llm",'
        b'"policy_ref":"","host_os":"linux","reason":"sandbox_block_missing",'
        b'"environment":"development"}\n'
    )
    fake = _FakePopen(stdout_frames=[], stderr_bytes=refusal_row)  # zero stdout → EOF at hello
    fake.returncode = 0  # exited (a refused launcher exits pre-exec)
    recorded: list[tuple] = []

    class _Recorder:
        async def record(self, rows) -> None:
            recorded.append(rows)

    monkeypatch.setattr(child_io_mod.subprocess, "Popen", lambda *a, **k: fake)
    monkeypatch.setattr(child_io_mod, "deliver_provider_key_via_fd3", lambda **_k: None)
    monkeypatch.setattr(child_io_mod.os, "dup2", lambda s, d, *a, **k: d)

    with pytest.raises(QuarantineChildSpawnError):
        await spawn_quarantine_child_io(provider_key="k", refusal_recorder=_Recorder())
    assert len(recorded) == 1
    assert recorded[0][0].reason == "sandbox_block_missing"
    assert fake.wait_calls >= 1  # torn down via aclose (reaped; an already-exited child skips terminate)


async def test_spawn_hello_then_no_ready_refuses_without_recording(monkeypatch) -> None:
    """hello but no ready (a `_build_provider` death) refuses boot but records NO launcher row.

    The child proved exec with the hello (``_child_wrote_stdout`` True), so the missing
    ready is child-authored — the gate must NOT attribute it to the launcher (§3.2 row 2).
    """
    fake = _FakePopen(stdout_frames=[HELLO_FRAME], stderr_bytes=b"provider build crashed\n")
    fake.returncode = 1
    recorded: list[tuple] = []

    class _Recorder:
        async def record(self, rows) -> None:
            recorded.append(rows)

    monkeypatch.setattr(child_io_mod.subprocess, "Popen", lambda *a, **k: fake)
    monkeypatch.setattr(child_io_mod, "deliver_provider_key_via_fd3", lambda **_k: None)
    monkeypatch.setattr(child_io_mod.os, "dup2", lambda s, d, *a, **k: d)

    with pytest.raises(QuarantineChildSpawnError):
        await spawn_quarantine_child_io(provider_key="k", refusal_recorder=_Recorder())
    assert recorded == []  # child-authored → NOT recorded as a launcher refusal
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest tests/unit/security/test_quarantine_child_io.py -k "handshake or probe_module or launcher_refusal or no_ready" -q`
Expected: FAIL — today the spawn returns without reading, so `test_spawn_launcher_refusal_records_row_and_refuses_boot` does NOT raise and records nothing.

- [ ] **Step 3: Add `_MODULES_EMITTING_READY` + `_await_boot_handshake` to `quarantine_child_io.py`**

Add the constant next to `_ALLOWED_CHILD_MODULES` (`:146`):

```python
# Modules whose child emits a `ready` frame after the `hello` (the real quarantine
# child builds a provider + asyncio streams, then signals liveness). The diagnostic
# probe is DELIBERATELY excluded: it is parent-speaks-first on fd 4, so a second
# handshake read would deadlock (spec §6.1). The `hello` read is UNCONDITIONAL for
# every allowed module, so every returned instance has proven exec.
_MODULES_EMITTING_READY: frozenset[str] = frozenset({_CHILD_MODULE})
```

Add the handshake helper (place just above `spawn_quarantine_child_io` at `:741`):

```python
async def _await_boot_handshake(
    child_io: _SubprocessChildIO, *, child_module: str
) -> None:
    """Read the child's boot frames INSIDE the spawn; refuse boot if any is missing (#443).

    Every allowed child emits an unsolicited ``hello`` frame before it builds its
    provider — proof it exec'd (provenance; the read sets ``_child_wrote_stdout``). The
    real quarantine child ADDITIONALLY emits a ``ready`` frame before its request loop —
    proof it initialized and is serving (liveness). The diagnostic probe emits ONLY a
    hello (``_MODULES_EMITTING_READY`` excludes it — a second read would deadlock, §6.1).
    The hello read is UNCONDITIONAL, so every returned instance has proven exec — the
    invariant the launcher-vs-child audit gate rests on.

    A missing frame surfaces as a ``read_frame`` failure -> ``QuarantineChildSpawnError``,
    which the boot caller maps to ``_refuse_boot`` (fail-closed, hard rule #7).
    ``read_frame``'s own failure arm records the launcher-authored ``sandbox_refused``
    row + dispatches the ``fail_closed`` T0 hookpoint iff the failure is a zero-byte EOF
    with no prior stdout byte (the sec-001 gate) — so a GENUINE launcher refusal now
    persists its row + fires the hookpoint HERE, at boot, instead of at first extraction
    (the dispatch PR1 made boot-declarable). On any handshake failure the half-spawned
    child is torn down (``aclose``: terminate+reap, close the control-parent) before the
    error propagates; the stderr drain already ran inside ``read_frame``, so ``aclose``'s
    own drain is an idempotent no-op.
    """
    try:
        await child_io.read_frame()  # hello: provenance — sets _child_wrote_stdout
        if child_module in _MODULES_EMITTING_READY:
            await child_io.read_frame()  # ready: liveness
    except QuarantineChildSpawnError:
        _log.error("security.quarantine_child.boot_handshake_failed", child_module=child_module)
        await child_io.aclose()
        raise
```

- [ ] **Step 4: Restructure the tail of `spawn_quarantine_child_io`**

Replace the final `return _SubprocessChildIO(...)` block (`:923-928`) with:

```python
    child_io = _SubprocessChildIO(
        process,
        control_parent=control_parent,
        egress_config=egress_config,
        refusal_recorder=refusal_recorder,
    )
    # Read the two-frame boot handshake INSIDE the spawn (#443): a launcher refusal now
    # refuses boot with an attributed audit row here, instead of surfacing as a corpse at
    # first extraction. The recorder was threaded into `child_io` above so the read_frame
    # failure arm can persist the row + fire the fail_closed T0 hookpoint at boot.
    await _await_boot_handshake(child_io, child_module=child_module)
    return child_io
```

- [ ] **Step 5: Correct the §12 docstring claim**

In `spawn_quarantine_child_io`'s docstring (the paragraph at `:802-805` describing refusal handling), append a sentence noting the new boot-handshake behavior (§12 correction — "a launcher refusal returns a corpse" is no longer true):

```
    A launcher refusal (the launcher exits pre-``exec``, so the child produces no
    ``hello``) now refuses the spawn HERE via the boot handshake — ``read_frame`` hits a
    zero-byte EOF, records the launcher-authored ``sandbox_refused`` row, and raises
    ``QuarantineChildSpawnError`` — rather than returning a corpse the caller only
    discovers dead at first extraction (#443).
```

- [ ] **Step 6: Update the base suite for the handshake — fixture + sweep + re-targets**

(a) **Fixture** (`_spawn_capture` at `:139`): prepend the boot frames to the default stdout so every fixture-using "spawn then inspect" test still returns:

```python
    fake_proc = _FakePopen(
        stdout_frames=[*_boot_frames(), _framed(b'{"jsonrpc":"2.0","result":{"ok":1}}')]
    )
```

(b) **`_FakeStdout([...])` overrides** — prepend `*_boot_frames()` at each site (the spawn consumes hello+ready; the test's post-spawn `read_frame` then sees its original override content):

- `:303` → `_FakeStdout([*_boot_frames(), b"\x00\x00"])`
- `:315` → `_FakeStdout([*_boot_frames(), struct.pack(">I", 8) + b"ab"])`
- `:560` → `_FakeStdout([*_boot_frames(), b"\x00\x00"])`
- `:632` → `_FakeStdout([*_boot_frames(), b"\x00\x00"])`
- `:817` → `_FakeStdout([*_boot_frames(), b"\x00\x00"])`

(c) **`_HangingStdout` tests** — the handshake's hello read would hang, so these read_frame/aclose *method* tests must NOT route through the spawn. Re-target them to construct `_SubprocessChildIO` directly (mirror the refusal-audit file's direct-construction pattern). The three sites: `:324` (`test_read_frame_is_bounded`), `:581` (`test_read_frame_failure_skips_stderr_when_child_still_running`), `:783` (`test_aclose_drains_stderr_after_reap_for_wedged_child`). Example transform for `:324`:

```python
async def test_read_frame_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A child that never replies trips the wait_for deadline (loud, not a hang)."""
    release = threading.Event()

    class _HangingStdout:
        def read(self, n: int) -> bytes:
            release.wait(timeout=30)
            return b""  # pragma: no cover - the wait_for fires first

    fake = _FakePopen(stdout_frames=[])
    fake.stdout = _HangingStdout()
    monkeypatch.setattr(child_io_mod, "_READ_FRAME_TIMEOUT_S", 0.05)
    cio = _SubprocessChildIO(fake)  # construct directly — do NOT go through the spawn handshake
    try:
        with pytest.raises(QuarantineChildSpawnError):
            await cio.read_frame()
    finally:
        release.set()
        await cio.aclose()
```

Apply the same "construct `_SubprocessChildIO(fake)` directly" shape to `:581` and `:783` (keep each test's existing poll/returncode/stderr setup on the fake).

- [ ] **Step 7: Run the full base suite + the pre-seeded files + the refusal-audit file**

Run:

```bash
uv run pytest tests/unit/security/test_quarantine_child_io.py \
  tests/unit/security/test_quarantine_child_io_refusal_audit.py \
  tests/unit/security/test_quarantine_child_io_control_fd.py \
  tests/unit/security/test_quarantine_child_io_i18n.py \
  tests/unit/gateway/test_fd3_spawn_window_shared_property.py \
  tests/adversarial/sandbox_escape/test_brokered_fd_dormant_mechanism.py -q
```

Expected: PASS. Fix any straggler that overrides `.stdout` and drives `read_frame` via the spawn using the rule in Step 6 (prepend `*_boot_frames()` for `_FakeStdout`; re-target for a hanging stdout).

- [ ] **Step 8: Coverage check on the boundary**

Run:

```bash
uv run pytest tests/unit/security/test_quarantine_child_io.py tests/unit/security/test_quarantine_child_io_refusal_audit.py \
  --cov=alfred.security.quarantine_child_io --cov-report=term-missing --cov-branch
```

Expected: 100% line + branch on `quarantine_child_io.py` (add a targeted test for any uncovered handshake branch — e.g. the probe-only path, the hello-EOF path, the hello-then-no-ready path are all covered by Step 1's tests).

- [ ] **Step 9: Commit**

```bash
git add src/alfred/security/quarantine_child_io.py tests/unit/security/test_quarantine_child_io.py
git commit -m "feat(security): #443 read the two-frame boot handshake inside spawn_quarantine_child_io"
```

---

### Task 6: Adversarial corpus — sbx-2026-021..024 + amend sbx-2026-019

**Files:**

- Create: `tests/adversarial/sandbox_escape/sbx_2026_021_boot_barrier_absent_launcher_refusal_reaches_runtime.yaml`
- Create: `tests/adversarial/sandbox_escape/sbx_2026_022_exec_d_child_cannot_forge_refusal_after_boot_handshake.yaml`
- Create: `tests/adversarial/sandbox_escape/sbx_2026_023_slow_launcher_refusal_still_refuses_boot.yaml`
- Create: `tests/adversarial/sandbox_escape/sbx_2026_024_child_boot_performs_no_external_io.yaml`
- Modify: `tests/adversarial/sandbox_escape/sbx_2026_019_stub_used_forgery_not_persisted.yaml` (append a provenance note only)
- Modify: `tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py` (add `test_sbx_2026_021..024`)

Each YAML uses the schema in `tests/adversarial/payload_schema.py` (`id`, `category: sandbox_escape`, `threat`, `ingestion_path`, `payload`, `expected_outcome`, `provenance`, `references`). `ingestion_path` for 021/023 = `launcher_refusal_stderr`; choose the closest existing `IngestionPath` member for 022/024 (`launcher_refusal_stderr` fits 022; 024 asserts a boot-time no-IO property — reuse `stdio_fd3_key_delivery` or add a new member to `IngestionPath` if none fits, updating `payload_schema.py` accordingly). `expected_outcome`: 021 `refused`, 022 `neutralized`, 023 `refused`, 024 `neutralized`.

- [ ] **Step 1: Write sbx-2026-021 (the core-001 regression oracle) + its asserting test**

YAML `threat`: "A genuine (slow) launcher sandbox refusal must refuse BOOT with exactly one attributed `sandbox_refused` row AND an actually-dispatched `fail_closed` T0 hookpoint — not surface late at first extraction." Pin a **slow** reason (`sandbox_block_missing`) in the payload — a fast reason (`plugin_id_charset_invalid`) EPIPEs before the child is constructed (§8.4), records nothing, and would make the oracle nondeterministic.

Asserting test in `test_sbx_corpus_executable.py` (models the existing `test_sandbox_refusal_audit.py` real-registry pattern — declare the supervisor hookpoints into a real registry, wire a real `SandboxRefusalAuditor` over a capturing `AuditWriter`, drive `spawn_quarantine_child_io` with a fake refusing launcher, assert: `QuarantineChildSpawnError` raised FROM the spawn, exactly one row, `reason == "sandbox_block_missing"`, and the `invoke` dispatch SUCCEEDED — not a `refusal_record_failed`). Assert on the **dispatch**, not just the row (a row-only assertion passes straight through the core-001 bug).

- [ ] **Step 2: Write sbx-2026-022 (post-handshake forgery is inert) + test**

`threat`: "An exec'd child that completed the boot handshake (wrote stdout) then crashes emitting a forged `sandbox_refused` on stderr must NOT persist a row — `_child_wrote_stdout` is True, so the gate is closed." Asserting test: spawn with `[HELLO, READY]` stdout (handshake completes → flag True), then drive a subsequent `read_frame` failure with a forged row on stderr → assert **no** row recorded. Derive "no row" from the (capturing) audit store, never from the gate predicate (`domain_a_test_that_asks_the_code_if_the_code_is_right`).

- [ ] **Step 3: Write sbx-2026-023 (slow refusal still refuses) + test**

`threat`: "A launcher that exits (zero stdout) after a delay still refuses boot — a future 'just bounded-wait' design that defaulted open on 'did not exit in N seconds' would go red here (§3.3)." Asserting test: a fake whose stdout EOFs at zero bytes after a short delay → `QuarantineChildSpawnError` from the spawn.

- [ ] **Step 4: Write sbx-2026-024 (child boot performs no external IO) + test**

`threat`: "The child performs no external network IO during boot (`_build_provider` → `hello`/`ready`) — defence-in-depth over the empty-netns policy that already forecloses it (§4.1)." Mark it clearly as defence-in-depth in `provenance` (the netns `ENETUNREACH` control is the load-bearing guard; this is a belt-and-suspenders assertion). Asserting test: assert the child boot path constructs `_DeterministicProvider` and makes no socket/httpx call (import-graph or monkeypatched-socket assertion) — keep it lightweight.

- [ ] **Step 5: Amend sbx-2026-019 provenance (careful — re-review required)**

Append ONE sentence to `sbx_2026_019...yaml`'s `provenance` noting that a successful exec now produces boot frames — a candidate success-path provenance signal that #447 (persisting `sandbox_stub_used`) currently lacks; **the handshake may make #447 tractable, but this PR does NOT fold #447**. Do **not** touch the `forged_stub_variants` list or its load-bearing-variant comment. Post the corresponding note on #447 (not in this file). Re-review this diff per the prose-wave rule.

- [ ] **Step 6: Run the corpus gates**

Run:

```bash
uv run pytest tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py tests/adversarial/test_corpus_health.py tests/adversarial/test_corpus_density.py tests/adversarial/test_payload_schema.py -q
```

Expected: PASS (schema-valid, ids unique + monotonic, every new asserting test green).

- [ ] **Step 7: Commit**

```bash
git add tests/adversarial/sandbox_escape/sbx_2026_021*.yaml tests/adversarial/sandbox_escape/sbx_2026_022*.yaml \
  tests/adversarial/sandbox_escape/sbx_2026_023*.yaml tests/adversarial/sandbox_escape/sbx_2026_024*.yaml \
  tests/adversarial/sandbox_escape/sbx_2026_019*.yaml tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py \
  tests/adversarial/payload_schema.py
git commit -m "test(security): #443 add sbx-2026-021..024 boot-handshake corpus entries"
```

---

### Task 7: ADR-0051 §8 amendments + §12 prose corrections + spec status

**Files:**

- Modify: `docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md` (add an "Amendment (#443 PR2)" section)
- Modify: `src/alfred/comms_mcp/daemon_runtime.py` (verify + correct the §12 "only await" comment IF still false)
- Modify: `src/alfred/supervisor/core.py` (verify the §12 "six hookpoints" comment — likely already corrected by PR1; correct only if still present)
- Modify: `docs/superpowers/specs/2026-07-16-443-boot-time-quarantine-health-check-design.md` (flip §10 PR2 status to LANDED once merged; not a code claim)

- [ ] **Step 1: Add the ADR-0051 amendment section**

Append a new `## Amendment (#443 PR2 — boot-time handshake)` section to ADR-0051 recording spec §8:

- **§8.1** the writev-buffers premise is a RACE, not structural — the parent closes every read-end copy before the `writev`, so a launcher that exits first ⟹ EPIPE ⟹ `ProviderKeyDeliveryError` ⟹ boot refuses *nondeterministically*; the fast path (`plugin_id_charset_invalid`, pre-`python3`) was never in Task 0's slow-only sample.
- **§8.2** ADR-0051's "four spawn sites drain that stderr" is wrong — only the quarantine child drains; the comms-adapter and gateway-adapter pipe stderr and never read it, so #440/#441 are "build the drain, THEN attach the auditor" (materially larger than the ADR implies), and #442's producer is dead code.
- **§8.3** the A-vs-B reversal — option A (boot-time barrier) is now adopted for the quarantine path; #443 is a hard pre-gate on #340 PR2b; CodeRabbit's #446 Major stands vindicated.
- **§8.4** the fast-refusal EPIPE hole is a distinct residual (§11.4) that this handshake cannot close (no `_SubprocessChildIO` is constructed on that arm) and that #444 does not fix (it writes a *different* reason). Name it as an accepted residual requiring option (C) or a conscious accept — NOT deferred to #444.

Verify each claim against the code by execution before writing it (prose-wave rule).

- [ ] **Step 2: Verify + correct the §12 prose targets**

Re-read the current text before editing (line numbers drifted):

```bash
grep -n "only await\|the only await" src/alfred/comms_mcp/daemon_runtime.py
grep -n "six hookpoints\|six\b" src/alfred/supervisor/core.py | head
```

- If `daemon_runtime.py` still claims the spawn await is "the only await in this builder", correct it (there are post-spawn awaits). If already accurate, skip.
- The `core.py` "six hookpoints" comment was rewritten by PR1 (the area now delegates to `hookpoints.declare_hookpoints`); if no false "six" claim remains, skip. Do NOT invent an edit.

- [ ] **Step 3: Markdown lint + commit**

Run: `npx markdownlint-cli2@0.22.1 "docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md" "docs/superpowers/specs/2026-07-16-443-boot-time-quarantine-health-check-design.md"`
Expected: clean.

```bash
git add docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md \
  docs/superpowers/specs/2026-07-16-443-boot-time-quarantine-health-check-design.md
# add src files only if an edit was actually needed:
git add -p src/alfred/comms_mcp/daemon_runtime.py src/alfred/supervisor/core.py 2>/dev/null || true
git commit -m "docs(security): #443 amend ADR-0051 for the boot-time handshake + correct stale prose"
```

> Re-review this commit (prose-wave rule): dispatch a docs/reviewer pass, verifying each claim by execution.

---

### Task 8: Integration / docker real-spawn verification

The real-spawn lanes run only in CI's privileged Linux job (macOS cannot run bwrap). No test-code change is expected — the real child (Task 2) now emits `hello`+`ready`, the probe (Task 3) emits `hello`, and the host (Task 5) reads them — so both lanes should stay green.

**Files (verify; edit only if a lane goes red):**

- `tests/integration/test_quarantine_child_real_spawn.py` — the real round-trip; the spawn now completes the handshake before the ingest/extract round-trip.
- `tests/integration/test_quarantine_fd_broker_real_spawn.py` — the probe spawn now reads `hello` before the test brokers the socket (the §6.1 deadlock is what Task 3 prevents).
- `.github/workflows/ci.yml` — the assert-RAN floors (`ci.yml:1662-1704` for the real-spawn leg, `ci.yml:1531-1566` for the brokered-fd leg) MUST stay intact; do not weaken them.

- [ ] **Step 1: Confirm the assert-RAN floors are untouched** — re-read the two `ci.yml` steps and confirm the skip-check / passed-check greps still gate the lane (a paper-only gate is not a gate).
- [ ] **Step 2: (If a lane can be run locally)** reproduce per the memory recipe — privileged `linux/arm64` docker container, deps-only install + `PYTHONPATH=/repo/src`, read-only repo mount — and confirm both real-spawn tests pass with the handshake. Otherwise rely on CI's privileged lane.
- [ ] **Step 3:** If either lane goes red in CI, the most likely cause is a handshake timing/ordering bug (e.g. the child flushing hello after `connect_write_pipe` reorders bytes) — debug via `superpowers:systematic-debugging`, do not weaken the assert-RAN floor to go green.
- [ ] **Step 4: Commit** any needed integration tweak: `git commit -m "test(security): #443 <specific integration fix>"`. If no change was needed, note that in the PR description and skip.

---

## Definition of done / final gates

Run the full local gate set before every push (and especially before opening the PR):

```bash
make check                                   # ruff + format + mypy + pyright + unit
uv run pytest tests/adversarial -q           # release-blocking (this PR touches src/alfred/security/)
uv run mypy src/ && uv run pyright src/
# i18n drift (no new key expected — this confirms the catalog is unchanged):
pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins && pybabel update --no-fuzzy-matching -i /tmp/alfred.pot -d locale && pybabel compile -d locale
```

- **HARD GATE re-check:** `grep -n "_DeterministicProvider" src/alfred/security/quarantine_child/__main__.py` — `_build_provider` must still return it. No live LLM client, no egress. If this PR would activate the real child, STOP — that is #340 PR2b.
- **Coverage:** 100% line + branch on `quarantine_child_io.py`.
- **Review:** run the FULL `/review-pr` fleet (security ALWAYS) + CodeRabbit (both cloud + CLI with `--base origin/main`); resolve every thread; re-review every prose-only wave (ADR/spec/corpus provenance). Then merge with a plain `gh pr merge --rebase` — never `--admin`, never `--auto` while a Critical is open.
- **Commits:** every subject carries `#443` after the colon.

## Notes for the executor

- **Do not activate #340 PR2b.** This plan builds the handshake mechanism against the deterministic-echo child only.
- **core-001 "goes live" here** and is exercised by sbx-2026-021 — it *fails on today's main* and must pass after Task 5. Its oracle asserts the dispatch actually fired, not merely that a row exists.
- **The probe reads hello-only** — if you ever find yourself adding a conditional that returns a probe IO with `_child_wrote_stdout` False, STOP: that reopens #446 on the probe path (§6.1). The hello read must be unconditional; only the `ready` read is gated by `_MODULES_EMITTING_READY`.
- **#444 is coupled but separate** — its `provider_key_delivery_failed` writer is NOT in this PR; the fast-refusal EPIPE path (§8.4) is a named residual, not this handshake's job.

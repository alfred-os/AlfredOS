# #443 PR2 — Two-Frame Boot Handshake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the quarantined-LLM child's launcher-refusal detection from first-extraction to boot, by having `spawn_quarantine_child_io` read a two-frame boot handshake (`hello` before `_build_provider`, `ready` before the request loop) from the child INSIDE the spawn — so a genuine launcher refusal refuses boot with an attributed audit row instead of surfacing late. This covers **both** refusal arms: a **handshake-observable** (slow) refusal is caught by the `hello` read's zero-byte EOF; the **fast-refusal EPIPE** arm — where the launcher exits before the `writev`, so `deliver_provider_key_via_fd3` raises `ProviderKeyDeliveryError` before the child exists — is routed through the SAME zero-stdout-gated drain (`_record_fast_launcher_refusal`, ADR-0051 §8.4) so it too records its attributed `sandbox_refused` row and fires the `fail_closed` T0 hookpoint. The only residual is §11.5's accepted pre-hello window (an exec'd child that writes zero stdout then forges — unreachable here without out-racing the synchronous `writev`).

**Architecture:** The child emits two unsolicited outbound frames during boot: a `hello` (raw `sys.stdout.buffer` write, before its provider exists — provenance: "I exec'd") and a `ready` (via the asyncio writer, before the loop — liveness: "I'm serving"). The diagnostic probe emits `hello` only (it is parent-speaks-first on fd 4; a second read would deadlock — spec §6.1). The host reads these inside `spawn_quarantine_child_io` via the existing `read_frame`; a missing frame raises `QuarantineChildSpawnError`, which the boot caller already maps to a fail-closed `_refuse_boot`, and `read_frame`'s own gate records the launcher-authored `sandbox_refused` row + dispatches the fail-closed T0 hookpoint (the hookpoint PR1 made boot-declarable — so core-001 "goes live" here). The handshake is **count-based**: the host does not parse frame bodies; the security property is that a stdout byte arrived (setting `_child_wrote_stdout`) and the required number of frames completed.

**Tech Stack:** Python 3.14+, asyncio, `subprocess.Popen` (synchronous spawn), `struct` 4-byte-big-endian length framing, structlog, pytest, the adversarial YAML corpus, ADR + spec Markdown.

**Design source:** `docs/superpowers/specs/2026-07-16-443-boot-time-quarantine-health-check-design.md` (rev 3). The three open decisions are RESOLVED (§0) — do not re-litigate. This plan implements §5 (two frames), §6.1 (probe hello), §8 (ADR amendments), §9 (testing + corpus), §11 (residuals), §12 (prose corrections).

## Review status (rev 2)

Reviewed by the 6-agent `/review-plan` fleet + coordinator (0 Critical, 5 High, 10 Medium, 14 Low; 13 corroborated, all 11 cross-checks confirmed, nothing retracted). **No design defect** — the design was validated sound on every hard-rule axis. This revision folds every High + every corroborated Medium and the cheap Lows:

- **Highs:** the sbx-2026-021 oracle now points at the real-registry tests (not the vacuous `_fake_invoke` model) with a code skeleton asserting the dispatch fired (arch-002); the ADR amendment now MANDATES retracting ADR-0051's "core-001 is moot" (docs-002/arch-006) and grounds the "#442" claim instead of writing "dead code" (docs-001); the probe test now pins `_child_wrote_stdout is True` (SEC-001); the coverage command now includes the `control_fd` + dormant files (te-001).
- **Corroborated Mediums:** the §12 list now includes `sandbox_refusal_audit.py:12-14` + `quarantine_child_io.py:578-579` + the `_write_verdict` docstring (arch-001/core-engineer-001/docs-003/te-004); green-per-commit is scoped to the unit lanes with the docker-window caveat (te-002/arch-004); the fd3-window fake keeps `close()` (rev-001/core-engineer-003); the hello emitter is hoisted to a single shared `emit_hello()` (rev-002); `git add -p` is replaced with named-path adds (arch-003/rev-005).
- **Lows folded:** rev-004 (sbx-024 `ingestion_path` pinned), rev-006 (`.chunks` hedge dropped), rev-007 (`_decode_result_payload` import), core-engineer-002 (`os.pipe` leak note), te-005 (no bwrap-skip on corpus tests), te-006 (assert `boot_handshake_failed`), rev-008 (child-ordering guarded only by Task 8).

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
  - `emit_hello() -> None` — raw `sys.stdout.buffer` write of `HELLO_FRAME` + flush; the single shared hello emitter both `main()`s call (rev-002 DRY).

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/quarantine/test_boot_handshake_frames.py
"""The shared boot-handshake frames are well-formed length-prefixed frames (#443)."""

from __future__ import annotations

import json
import struct

import pytest

from alfred.security.quarantine_child import _handshake as hs
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


def test_emit_hello_writes_hello_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    """``emit_hello`` writes exactly HELLO_FRAME to the raw stdout buffer + flushes (rev-002)."""
    written: list[bytes] = []
    flushes = {"n": 0}

    class _Buf:
        def write(self, data: bytes) -> None:
            written.append(bytes(data))

        def flush(self) -> None:
            flushes["n"] += 1

    class _Stdout:
        buffer = _Buf()

    monkeypatch.setattr(hs.sys, "stdout", _Stdout())
    hs.emit_hello()
    assert written == [HELLO_FRAME]
    assert flushes["n"] == 1
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
``struct``, ``sys``) so the child's minimal import surface (ADR-0030 import-closure
gate) is preserved; both the child and the diagnostic probe call ``emit_hello``.
"""

from __future__ import annotations

import json
import struct
import sys

_HELLO_METHOD = "boot.hello"
_READY_METHOD = "boot.ready"


def _boot_frame(method: str) -> bytes:
    body = json.dumps({"jsonrpc": "2.0", "method": method}).encode("utf-8")
    return struct.pack(">I", len(body)) + body


HELLO_FRAME: bytes = _boot_frame(_HELLO_METHOD)
READY_FRAME: bytes = _boot_frame(_READY_METHOD)


def emit_hello() -> None:
    """Write the boot ``hello`` frame to fd 1 via a RAW buffered write + flush (#443).

    Shared by BOTH the quarantine child (`__main__.main`) and the diagnostic probe
    (`_brokered_probe.main`) — the emitter bodies were byte-identical, so this is the
    single definition (rev-002 DRY; also unifies the name — no per-module
    `_write_boot_hello`/`_emit_boot_hello`). A raw write because at the child's hello
    point the asyncio writer does not exist yet; safe because both callers pin logging
    to stderr before calling it, keeping fd 1 byte-pure. Stdlib-only, so the child's
    import closure (ADR-0030) is unchanged.
    """
    sys.stdout.buffer.write(HELLO_FRAME)
    sys.stdout.buffer.flush()


__all__ = ["HELLO_FRAME", "READY_FRAME", "emit_hello"]
```

> **rev-002 (DRY):** `emit_hello()` lives HERE and is called by both `main()`s (Tasks 2 and 3). Do NOT define per-module `_write_boot_hello` / `_emit_boot_hello` — that was byte-identical duplication with an inconsistent name. The child keeps its own `_write_boot_ready` (it uses the asyncio writer, not a raw write, so it is genuinely different).

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

- Modify: `src/alfred/security/quarantine_child/__main__.py` (import `emit_hello` + `READY_FRAME`; add `_write_boot_ready`; wire `emit_hello()` into `main()` at `:338`→pre-`_build_provider` and `_write_boot_ready` at `:351`→pre-`_run_mcp_server`)
- Test: `tests/unit/quarantine/test_quarantine_child_loop.py` (add the ready-helper test; reuse its `_FakeWriter` at `:62`). The hello emitter is the shared `emit_hello`, already covered by Task 1's test.

**Interfaces:**

- Consumes: `emit_hello`, `READY_FRAME` (Task 1); the module's existing `_FrameWriter` Protocol (`__main__.py:288`).
- Produces: `async def _write_boot_ready(writer: _FrameWriter) -> None`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/quarantine/test_quarantine_child_loop.py` (the hello emitter is already covered by Task 1's `emit_hello` test — Task 2 tests only the child-specific `_write_boot_ready`):

```python
async def test_write_boot_ready_emits_ready_frame_via_writer() -> None:
    """``_write_boot_ready`` writes READY_FRAME through the asyncio writer + drains."""
    from alfred.security.quarantine_child import __main__ as qc
    from alfred.security.quarantine_child._handshake import READY_FRAME

    writer = _FakeWriter()  # the existing double at test_quarantine_child_loop.py:62 — collects into .chunks
    await qc._write_boot_ready(writer)
    assert b"".join(writer.chunks) == READY_FRAME
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/quarantine/test_quarantine_child_loop.py -k boot -q`
Expected: FAIL — `AttributeError: module ... has no attribute '_write_boot_ready'`.

- [ ] **Step 3: Add the import + the ready helper to `__main__.py`**

Add the import near the other `alfred` import (after `__main__.py:54`):

```python
from alfred.security.quarantine_child._handshake import READY_FRAME, emit_hello
```

Add the ready helper (place it just above `async def main()` at `:317`). Do NOT define a per-module hello emitter — `main()` calls the shared `emit_hello` from Task 1 (rev-002 DRY):

```python
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
    emit_hello()  # provenance: proves this is a real exec'd child (#443)
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

- Modify: `src/alfred/security/quarantine_child/_brokered_probe.py` (import `emit_hello`; call it in `main()` after the fd-4 socket at `:106`, before `while True:` at `:107`; correct the `_write_verdict` docstring — te-004)
- Test: `tests/unit/quarantine/test_brokered_probe_import.py` (the existing import test stays the guard)

**Interfaces:**

- Consumes: `emit_hello` (Task 1). The probe emits **only a hello — never a ready** (it has no provider to build; a second host read would deadlock — §6.1).
- Produces: nothing new — the wiring calls the shared emitter.

> No new unit-testable symbol here: Task 3 wires the shared `emit_hello` (Task 1, already unit-covered) into the probe's `# pragma: no cover` `main()` and corrects one docstring. The behavioral proof — no deadlock — is the Task 8 docker `test_quarantine_fd_broker_real_spawn.py` lane, which must not be skipped (rev-008). So Task 3 is a wiring + docs commit, not a fresh TDD cycle.

- [ ] **Step 1: Add the import + wire `emit_hello` into `main()`**

Add near the existing import (after `_brokered_probe.py:32`):

```python
from alfred.security.quarantine_child._handshake import emit_hello
```

Call it after the fd-4 socket is reconstructed (`:106`) and before the `while True:` loop (`:107`):

```python
    control_end = socket.socket(fileno=_CONTROL_FD, family=socket.AF_UNIX, type=socket.SOCK_STREAM)
    emit_hello()  # #443 §6.1: unblock the host handshake before the parent-speaks-first recv loop
    while True:
```

- [ ] **Step 2: Correct the `_write_verdict` docstring (te-004)**

`_write_verdict`'s docstring at `_brokered_probe.py:56` claims the verdict is "the only thing this process ever puts on fd 1" — no longer true after the boot hello. Reword to acknowledge the one pre-loop boot `hello` frame (e.g. "besides the single boot `hello` frame emitted before the recv loop, the verdict is the only thing this process writes to fd 1").

- [ ] **Step 3: Run the probe import test**

Run: `uv run pytest tests/unit/quarantine/test_brokered_probe_import.py -q`
Expected: PASS (the module still imports; no fd-4 touch at import time).

- [ ] **Step 4: Commit**

```bash
git add src/alfred/security/quarantine_child/_brokered_probe.py
git commit -m "fix(security): #443 emit a boot hello from the diagnostic probe to avoid the handshake deadlock"
```

---

### Task 4: Pre-seed boot frames into the non-frame-reading spawn fakes

**Why first:** Task 5 flips `spawn_quarantine_child_io` to READ the handshake. Test fakes that only assert `pass_fds`/dup2/`broker_socket` (never `read_frame` post-spawn) would then fail on a `None`/empty stdout. Pre-seeding their stdout with `[HELLO_FRAME, READY_FRAME]` is a **no-op under today's spawn** (the frames sit unread) and satisfies the new handshake read — so each commit stays green **on the unit + `make check` lanes** regardless of task order.

> **Green-per-commit scope (te-002 / arch-004 — read before pushing).** The "green per commit" guarantee is **unit-lane only**. The docker-gated real-spawn lanes (`test_quarantine_child_real_spawn.py`, `test_quarantine_fd_broker_real_spawn.py`, CI's privileged Linux job) are RED between the Task 2/3 commits (child/probe now emit frames) and the Task 5 commit (host reads them) — child and host are one atomic wire change (spec §5.3). This is a transient mid-sequence red, not a bug. **Push the Task 2→5 sequence together (or push only once Task 5 has landed), never a partial prefix**, so CI's privileged lane never observes the half-applied wire.

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

In `test_fd3_spawn_window_shared_property.py`, teach `_SyncFakePopen`'s stdio double to serve `[HELLO_FRAME, READY_FRAME]` from `read()` **while keeping its `close()` method** (rev-001 / core-engineer-003): the gateway leg of this file's shared fake drives `adapter_child_factory.aclose`, which calls `.close()` on the stdio, so do NOT substitute the base `_FakeStdout` (it has no `close()`) — extend `_SyncFakePopen`'s existing stdio type with an optional frames buffer instead, and set `self.stdout` to it seeded with the two boot frames. The test asserts the fd-3 window discipline + `pass_fds`; the handshake `await`s run AFTER the dup2 window closes, so `sentinel_ran_at_spawn` (captured at Popen time) is unaffected — but the spawn must now find frames on stdout to return.

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
    # SEC-001 (load-bearing): the returned probe instance MUST have proven exec via the
    # hello read. This is the §6.1 invariant — a future conditional-hello mutation that
    # returned a probe with _child_wrote_stdout False would reopen #446 on the probe path
    # while branch coverage stayed green. Assert it directly, not just "no deadlock".
    assert cio._child_wrote_stdout is True
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

Three refinements to the tests above before you write them:

- **rev-007 (import):** `test_spawn_completes_two_frame_handshake_and_returns` uses `_decode_result_payload` — import it at the top of the file (the sibling `test_read_frame_returns_full_frame` already does).
- **core-engineer-002 (fd hygiene):** the standalone tests that monkeypatch `Popen`/`deliver_provider_key_via_fd3`/`os.dup2` directly (rather than via `_spawn_capture`) must ALSO wrap `os.pipe` with a tracking closer that closes the real write-end — the faked delivery no-ops the close the real `deliver_provider_key_via_fd3` performs, so the real `os.pipe()` the spawn opens would leak its write-end. Mirror `_spawn_capture`'s `_tracking_pipe`, or build these tests on top of `_spawn_capture` and swap the fake's stdout per case.
- **te-006 (assert the security event):** add a `structlog.testing.capture_logs()` assertion for `security.quarantine_child.boot_handshake_failed` (with the `child_module` field) to at least one handshake-failure test — the module's discipline is to assert every emitted security event (hard rule #7), and structlog events do not reach `caplog`.

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
uv run pytest \
  tests/unit/security/test_quarantine_child_io.py \
  tests/unit/security/test_quarantine_child_io_refusal_audit.py \
  tests/unit/security/test_quarantine_child_io_control_fd.py \
  tests/adversarial/sandbox_escape/test_brokered_fd_dormant_mechanism.py \
  --cov=alfred.security.quarantine_child_io --cov=alfred.security.quarantine_child._handshake \
  --cov-report=term-missing --cov-branch
```

Expected: 100% line + branch on `quarantine_child_io.py` and `_handshake.py`. **te-001 (load-bearing):** `test_quarantine_child_io_control_fd.py` is the ONLY exerciser of the `control_fd=True` / `broker_socket` / fd-4-dance branches (the base file has zero such references), and `test_brokered_fd_dormant_mechanism.py` exercises the dormant-path spawn — omitting them under-reports and makes the "Expected 100%" claim undemonstrable. Add a targeted test for any uncovered handshake branch (the probe-only path, the hello-EOF path, and the hello-then-no-ready path are covered by Step 1's tests). Alternatively, accumulate coverage across the whole `tests/unit` + adversarial run exactly as CI does (`ci.yml` coverage-gate), rather than a hand-picked file list.

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

Each YAML uses the schema in `tests/adversarial/payload_schema.py` (`id`, `category: sandbox_escape`, `threat`, `ingestion_path`, `payload`, `expected_outcome`, `provenance`, `references`). `ingestion_path`: 021/023 = `launcher_refusal_stderr`; 022 = `launcher_refusal_stderr`; **024 = `stdio_fd3_key_delivery`** (the existing boot-time fd-3 member — pinned per rev-004; prefer reusing an existing `IngestionPath` member over adding a new one, which would also require updating the `.rulesync/skills/alfred-adversarial-corpus/SKILL.md` source-of-truth in the same commit to avoid `.rulesync` drift). `expected_outcome`: 021 `refused`, 022 `neutralized`, 023 `refused`, 024 `neutralized`.

> **te-005 (no paper-gate):** all four asserting tests are PURE-UNIT (monkeypatched `Popen`, no bwrap). They MUST carry **no** bwrap/docker skip marker (mirror `test_brokered_fd_dormant_mechanism.py`), or they become paper-only gates (#245). `test_sbx_corpus_executable.py` mixes bwrap-required tests — if placing them there risks an ambient skip, put sbx-021..024's asserting tests in a dedicated non-bwrap module (e.g. `test_sbx_boot_handshake.py`) that the corpus-health gate still discovers, and keep the `_load()` helper import.

- [ ] **Step 1: Write sbx-2026-021 (the core-001 regression oracle) + its asserting test**

YAML `threat`: "A genuine (slow) **handshake-observable** launcher sandbox refusal must refuse BOOT with exactly one attributed `sandbox_refused` row AND an actually-dispatched `fail_closed` T0 hookpoint — not surface late at first extraction." Pin a **slow** reason (`sandbox_block_missing`) in the payload — this oracle deliberately exercises the *handshake* arm, so it must not accidentally take the fast-EPIPE arm; pinning the slow reason keeps it deterministic. The fast-refusal EPIPE arm (`plugin_id_charset_invalid` etc.) is **now covered** by its own oracle sbx-2026-025 (§8.4 close: the EPIPE arm routes through the same zero-stdout-gated drain and DOES record an attributed row), so it is no longer a residual out of scope — just a different oracle.

Asserting test — model it on the **real-registry** tests in `test_sandbox_refusal_audit.py` (the ones ~line 175+ that build a real `HookRegistry` and run the auditor's real, UNPATCHED `invoke`), **NOT** that file's dominant `_fake_invoke`-monkeypatch tests: arch-002 / te-003 — a monkeypatched `invoke` makes the dispatch assertion **vacuous** (it "succeeds" even on `main`, certifying nothing). Assert on the **dispatch**, not just the row. Skeleton (confirm the exact `HookRegistry`/`set_registry`/`declare_hookpoints`/`_REFUSAL_ROW_*` symbols against the real `test_sandbox_refusal_audit.py` — this is a shape, not a drop-in):

```python
async def test_sbx_2026_021_boot_barrier_refusal_reaches_runtime(monkeypatch) -> None:
    payload = _load("sbx-2026-021")
    assert payload.expected_outcome == "refused"
    registry = HookRegistry(strict_declarations=True)   # real registry, not a fake invoke
    declare_hookpoints(registry)                          # alfred.supervisor.hookpoints (PR1)
    set_registry(registry)                                # so the auditor's invoke() resolves it
    rows: list[dict] = []

    class _CapturingWriter:                               # minimal AuditWriter double
        async def append_schema(self, **kw): rows.append(kw)

    recorder = SandboxRefusalAuditor(audit_writer=_CapturingWriter())
    fake = _FakePopen(stdout_frames=[], stderr_bytes=_REFUSAL_ROW_SANDBOX_BLOCK_MISSING)
    fake.returncode = 0                                   # a refused launcher exits pre-exec
    monkeypatch.setattr(qcio.subprocess, "Popen", lambda *a, **k: fake)
    monkeypatch.setattr(qcio, "deliver_provider_key_via_fd3", lambda **_k: None)
    monkeypatch.setattr(qcio.os, "dup2", lambda s, d, *a, **k: d)
    with structlog.testing.capture_logs() as logs:
        with pytest.raises(qcio.QuarantineChildSpawnError):
            await qcio.spawn_quarantine_child_io(provider_key="k", refusal_recorder=recorder)
    assert len(rows) == 1 and rows[0]["subject"]["reason"] == "sandbox_block_missing"
    # THE core-001 assertion: the fail_closed dispatch actually FIRED — it was NOT
    # swallowed as refusal_record_failed (which is exactly what an undeclared hookpoint
    # produces; a row-only assertion passes straight through the core-001 bug).
    assert not any(e["event"] == "security.quarantine_child.refusal_record_failed" for e in logs)
```

> **te-003 (scope the claim honestly):** this oracle declares the hookpoint MANUALLY, so it proves the record→dispatch **mechanism**, not the production boot **ordering** (that `install_boot_hook_registry` runs before the spawn). That ordering rests on PR1's boot seam + `test_boot_registry` membership + the extractor-builds-later invariant. Do not let this test's existence be cited as proof of the production sequence — the "Notes for the executor" wording is softened accordingly.

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

- Modify: `docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md` (add an "Amendment (#443 PR2)" section **and** retract the now-false core-001-moot claims in Decision 2 :81-89 + Consequences :142-148 — docs-002 / arch-006)
- Modify: `src/alfred/security/sandbox_refusal_audit.py` (§12 — the module docstring :12-14 "dispatch happens at first extraction, post-`Supervisor`" is falsified by PR2 — arch-001 / core-engineer-001 / docs-003)
- Modify: `src/alfred/security/quarantine_child_io.py` (§12 — the `_log_child_stderr` residual comment ~:578-579 "defers to the boot-time probe (ADR-0051 option A, #443)" now describes THIS PR's mechanism, not future work — docs-003; may be folded into Task 5's commit since that task already edits this file)
- Modify: `src/alfred/comms_mcp/daemon_runtime.py` (verify + correct the §12 "only await" comment IF still false — preserve any load-bearing "dup2 window" clause)
- Modify: `src/alfred/supervisor/core.py` (verify the §12 "six hookpoints" comment — PR1 already delegated `_register_hookpoints`; correct only if a false "six" claim remains, else skip)
- Modify: `docs/superpowers/specs/2026-07-16-443-boot-time-quarantine-health-check-design.md` (flip §10 PR2 status to LANDED once merged; not a code claim)

- [ ] **Step 1: Add the ADR-0051 amendment section**

Append a new `## Amendment (#443 PR2 — boot-time handshake)` section to ADR-0051 recording spec §8:

- **§8.1** the writev-buffers premise is a RACE, not structural — the parent closes every read-end copy before the `writev`, so a launcher that exits first ⟹ EPIPE ⟹ `ProviderKeyDeliveryError` ⟹ boot refuses *nondeterministically*; the fast path (`plugin_id_charset_invalid`, pre-`python3`) was never in Task 0's slow-only sample.
- **§8.2** ADR-0051's "four spawn sites drain that stderr" is wrong — verified: only the quarantine child drains (`_log_child_stderr`); the comms-adapter and gateway-adapter **pipe** stderr but never read it, so #440/#441 are "build the drain, THEN attach the auditor" (materially larger than the ADR implies). **docs-001: do NOT write the bare phrase "#442's producer is dead code."** State the verified fact: `cli/_launcher_spawn.spawn_plugin_via_launcher` has **zero production call sites** (`alfred chat` dials the gateway socket, Spec A G5) though the module is still imported — that "unreachable in production, rescope #442 to delete the dead seam" claim belongs to the §7-decomposition framing, NOT to an §8.2 stderr-draining bullet, and it must not be phrased so as to contradict ADR-0051's existing "the TUI inherits stderr today rather than piping it" note.
- **§8.3** the A-vs-B reversal — option A (boot-time barrier) is now adopted for the quarantine path; #443 is a hard pre-gate on #340 PR2b; CodeRabbit's #446 Major stands vindicated.
- **§8.4** the fast-refusal EPIPE hole is a distinct residual (§11.4) that this handshake cannot close (no `_SubprocessChildIO` is constructed on that arm) and that #444 does not fix (it writes a *different* reason). Name it as an accepted residual requiring option (C) or a conscious accept — NOT deferred to #444.
- **Retraction (docs-002 / arch-006 — MANDATORY, not optional).** The amendment section alone is insufficient: ADR-0051's Decision 2 (:81-89) and Consequences (:142-148) still assert "core-001 is moot … the dispatch happens strictly after `Supervisor.__init__`". PR2 makes that FALSE (dispatch now fires inside the boot handshake, pre-`Supervisor`). Edit those two passages to mark them **superseded for the quarantine path by this amendment** (a one-line "SUPERSEDED by the #443 PR2 amendment below" pointer at Decision 2 also discharges arch-006's A/B back-reference), so the ADR is not internally self-contradicting after PR2 lands.

Verify each claim against the code by execution before writing it (prose-wave rule — this epic has shipped a false prose claim on a drift surface three times; every bullet above is a candidate).

- [ ] **Step 2: Verify + correct the §12 prose targets**

Re-read the current text before editing (line numbers drifted):

```bash
grep -n "only await\|the only await" src/alfred/comms_mcp/daemon_runtime.py
grep -n "six hookpoints\|six\b" src/alfred/supervisor/core.py | head
```

- **`sandbox_refusal_audit.py:12-14` (MUST — arch-001/core-engineer-001/docs-003):** the docstring says the quarantine-child dispatch "happens at first extraction, post-`Supervisor`, so the hookpoint is registered". PR2 inverts it — reword to: the quarantine child now dispatches at BOOT, inside the spawn handshake, pre-`Supervisor`, relying on PR1's boot-time declaration.
- **`quarantine_child_io.py:~578-579` (MUST — docs-003):** the `_log_child_stderr` residual comment "defers to the boot-time probe (ADR-0051 option A, #443)" describes THIS PR as future work — reword to say the boot handshake (this PR) performs that check at boot, leaving only the fast-refusal EPIPE sliver (§8.4) as a residual.
- If `daemon_runtime.py` still claims the spawn await is "the only await in this builder", correct it (there are post-spawn awaits) — but **preserve any load-bearing second clause** about nothing interleaving in the dup2 window (docs-003). If already accurate, skip.
- The `core.py` "six hookpoints" comment was rewritten by PR1 (the area now delegates to `hookpoints.declare_hookpoints`); the grep in the box above confirms whether a false "six" claim remains — skip if none. Do NOT invent an edit.

- [ ] **Step 3: Markdown lint + commit**

Run: `npx markdownlint-cli2@0.22.1 "docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md" "docs/superpowers/specs/2026-07-16-443-boot-time-quarantine-health-check-design.md"`
Expected: clean.

```bash
git add docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md \
  docs/superpowers/specs/2026-07-16-443-boot-time-quarantine-health-check-design.md \
  src/alfred/security/sandbox_refusal_audit.py src/alfred/security/quarantine_child_io.py
# arch-003 / rev-005: NO interactive `git add -p`. Add each src file by name ONLY if Step 2
# actually edited it — omit the line for any file the "verify then skip" branch left untouched:
git add src/alfred/comms_mcp/daemon_runtime.py   # only if Step 2 corrected the "only await" comment
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
- **core-001's dispatch fires at boot after PR2.** sbx-2026-021 proves the record→dispatch **mechanism** (with a manually-declared registry) — it *fails on today's main* and must pass after Task 5, asserting the dispatch actually fired (not merely that a row exists), i.e. no `refusal_record_failed`. **te-003:** it does NOT by itself prove the production boot *ordering* (that `install_boot_hook_registry` runs before the spawn) — that rests on PR1's boot seam + `test_boot_registry` membership + the extractor-builds-later invariant. Do not overstate sbx-021 as certifying the production sequence.
- **Child-side frame ordering is only guarded by the docker lane (rev-008).** The hello-before-`_build_provider` / ready-before-loop ordering lives in `main()` (`# pragma: no cover`), so the only executable guard is Task 8's real-spawn round-trip — Task 8 must not be skipped even though it needs no code change.
- **The probe reads hello-only** — if you ever find yourself adding a conditional that returns a probe IO with `_child_wrote_stdout` False, STOP: that reopens #446 on the probe path (§6.1). The hello read must be unconditional; only the `ready` read is gated by `_MODULES_EMITTING_READY`.
- **#444 is coupled but separate** — its `provider_key_delivery_failed` writer is NOT in this PR; the fast-refusal EPIPE path (§8.4) is a named residual, not this handshake's job.

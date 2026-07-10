# Quarantine Child stderr Drain (#251) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface the quarantined-LLM child's stderr through the host's structured
logger as a sanitized `child_stderr` field on the `read_frame` failure path and in
`aclose`, so a failed spawn/extract is no longer diagnosed blind — without ever
raw-inheriting the adversary-facing child's stderr.

**Architecture:** Scope A "best-effort bounded drain" (see spec §3). Two pure
module-private helpers (`_read_stderr_bytes`, `_sanitize_child_stderr`) plus one
exit-gated, idempotent `_SubprocessChildIO._log_child_stderr` coroutine wired into
the two existing failure/teardown paths. The drain runs ONLY when the child has
exited (`poll()` gate) so it can never block on a wedged child; the read is
off-loop (executor); the field is single-line and control-char-free (log-injection
defense) and passes through the bootstrap structlog leaf-redactor for secret
masking. `aclose` additionally closes the drained `stderr` pipe (stderr-only — see
spec §4.3 for why not stdin/stdout).

**Tech Stack:** Python 3.14+, asyncio, `subprocess.Popen`, structlog, pytest
(async), `structlog.testing.capture_logs`. Everything hermetic on macOS / non-root
CI (fake subprocess) — no real bwrap spawn.

## Global Constraints

- **Single module touched:** `src/alfred/security/quarantine_child_io.py` + its
  unit tests `tests/unit/security/test_quarantine_child_io.py`. No other src file,
  no wire-contract change, no spawn-discipline change, no egress touch.

- **Security boundary (`src/alfred/security/`)** → the release-blocking adversarial
  suite MUST run locally before the PR (`uv run pytest tests/adversarial`).

- **100% line + branch coverage** on `quarantine_child_io.py` is a required CI gate
  (ci.yml `security/*` glob `--fail-under=100` + the dedicated per-file gate). Add
  NO new `# pragma: no cover` — every new branch is made test-reachable here.

- **No new i18n.** The log event key `security.quarantine_child.child_stderr` is a
  bare structured event name (like the existing `read_frame_failed` /
  `spawn_failed`); `child_stderr` is a data field. No `t()` string, no catalog
  entry, no `pybabel` run.

- **Modern typing:** PEP 604 unions (`str | None`), no `Any` without cause, mypy
  strict + pyright clean.

- **Commits:** conventional-commit subject with a literal `#251` AFTER the colon in
  EVERY subject; end every commit message with the trailer
  `MrReasonable <4990954+MrReasonable@users.noreply.github.com>`. Never
  `git add -A` (add named paths only). Never `--no-verify`.

- **Branch:** `251-quarantine-child-stderr-drain` (already created off `main`
  `3c560c97`; spec committed at `17af8adf`).

---

### Task 1: Pure helpers — `_read_stderr_bytes` + `_sanitize_child_stderr`

**Files:**

- Modify: `src/alfred/security/quarantine_child_io.py` (add `import unicodedata`;
  add two constants after `_READ_FRAME_TIMEOUT_S`; add two module-private helpers
  after `_blocking_read_exactly`, before `class _SubprocessChildIO`).

- Test: `tests/unit/security/test_quarantine_child_io.py` (add a reusable
  `_FakeStderr` double + a `types.SimpleNamespace`-based process stub for the
  reader; add helper unit tests).

**Interfaces:**

- Produces:
  - `_STDERR_LOG_CAP_BYTES: int` (= 4096) and
    `_STDERR_TRUNCATION_MARKER: str` (= `"…[truncated]"`).
  - `_read_stderr_bytes(process: subprocess.Popen[bytes], cap: int) -> bytes` —
    reads up to `cap` bytes of `process.stderr`; `b""` if `stderr is None` or
    nothing buffered. `cap` is POSITIONAL (fed to `run_in_executor` in Task 2).
    Caller guarantees the child has exited.
  - `_sanitize_child_stderr(raw: bytes, *, cap: int) -> str | None` — decode
    (`errors="replace"`), replace every Unicode `Cc` control char with a space,
    collapse whitespace runs, strip. Returns `None` when empty; truncates to `cap`
    chars + `_STDERR_TRUNCATION_MARKER` when longer.
  - `_FakeStderr` test double (has `read(n) -> bytes` raw-pipe semantics, `close()`,
    `closed: bool`) — reused by Tasks 2 and 3.

- [ ] **Step 1: Add the `_FakeStderr` double + import to the test file**

At the top of `tests/unit/security/test_quarantine_child_io.py`, add `types` to the
imports (next to the existing `import struct` / `import sys` / `import threading`):

```python
import types
```

Add this double right after the existing `_FakeStdout` class:

```python
class _FakeStderr:
    """A raw-pipe stderr stand-in: synchronous ``read(n)`` over a byte buffer.

    Mirrors ``_FakeStdout`` (returns at most ``n`` bytes per call, ``b""`` at EOF)
    and adds ``close()`` so the aclose stderr-pipe-close (Task 3) is observable.
    """

    def __init__(self, data: bytes = b"") -> None:
        self._buf = bytearray(data)
        self.closed = False

    def read(self, n: int) -> bytes:
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk

    def close(self) -> None:
        self.closed = True
```

- [ ] **Step 2: Write the failing helper tests**

Append to `tests/unit/security/test_quarantine_child_io.py`:

```python
# --- #251: stderr drain helpers ---------------------------------------------

def test_sanitize_child_stderr_plain_text_passes_through() -> None:
    out = child_io_mod._sanitize_child_stderr(b"sandbox_refused reason=x", cap=4096)
    assert out == "sandbox_refused reason=x"

def test_sanitize_child_stderr_collapses_newlines_and_tabs_to_single_line() -> None:
    out = child_io_mod._sanitize_child_stderr(b"line one\n\tline two\r\nline three", cap=4096)
    # Single line, no control chars, whitespace runs collapsed to one space.
    assert out == "line one line two line three"
    assert "\n" not in out and "\r" not in out and "\t" not in out

def test_sanitize_child_stderr_defangs_ansi_escapes() -> None:
    # ESC (0x1b) is a Cc control char -> replaced; the inert "[31m"/"[0m" remain.
    out = child_io_mod._sanitize_child_stderr(b"\x1b[31mRED\x1b[0m alert", cap=4096)
    assert "\x1b" not in out
    assert out == "[31mRED [0m alert"

def test_sanitize_child_stderr_non_utf8_does_not_crash() -> None:
    out = child_io_mod._sanitize_child_stderr(b"bad\xffbyte", cap=4096)
    assert out is not None
    assert "bad" in out and "byte" in out

def test_sanitize_child_stderr_empty_returns_none() -> None:
    assert child_io_mod._sanitize_child_stderr(b"", cap=4096) is None

def test_sanitize_child_stderr_all_control_returns_none() -> None:
    # Non-empty raw, but every char is control/whitespace -> collapses to "" -> None.
    assert child_io_mod._sanitize_child_stderr(b"\n\r\n\t  ", cap=4096) is None

def test_sanitize_child_stderr_truncates_over_cap_with_marker() -> None:
    out = child_io_mod._sanitize_child_stderr(b"a" * 5000, cap=4096)
    assert out is not None
    assert out.endswith(child_io_mod._STDERR_TRUNCATION_MARKER)
    assert len(out) == 4096 + len(child_io_mod._STDERR_TRUNCATION_MARKER)

def test_read_stderr_bytes_reads_all_under_cap() -> None:
    proc = types.SimpleNamespace(stderr=_FakeStderr(b"boom reason"))
    assert child_io_mod._read_stderr_bytes(proc, 4096) == b"boom reason"  # type: ignore[arg-type]

def test_read_stderr_bytes_caps_at_limit() -> None:
    proc = types.SimpleNamespace(stderr=_FakeStderr(b"x" * 100))
    assert child_io_mod._read_stderr_bytes(proc, 10) == b"x" * 10  # type: ignore[arg-type]

def test_read_stderr_bytes_no_pipe_returns_empty() -> None:
    proc = types.SimpleNamespace(stderr=None)
    assert child_io_mod._read_stderr_bytes(proc, 4096) == b""  # type: ignore[arg-type]
```

- [ ] **Step 3: Run the tests to verify they FAIL**

Run:

```bash
uv run pytest tests/unit/security/test_quarantine_child_io.py -k "sanitize_child_stderr or read_stderr_bytes" -q
```

Expected: FAIL — `AttributeError: module 'alfred.security.quarantine_child_io' has
no attribute '_sanitize_child_stderr'` (and `_read_stderr_bytes`,
`_STDERR_TRUNCATION_MARKER`).

- [ ] **Step 4: Implement the constants + helpers**

In `src/alfred/security/quarantine_child_io.py`, add `import unicodedata` to the
stdlib import block (alphabetically, right after `import sys`):

```python
import sys
import unicodedata
```

Add the two constants immediately after the `_READ_FRAME_TIMEOUT_S = 15.0` line:

```python
# Bounded best-effort drain of the quarantined child's stderr (#251). The child is
# spawned with ``stderr=PIPE``; on a failed/torn ``read_frame`` or on ``aclose`` the
# host reads up to this many bytes — ONLY once the child has exited (so the drain
# can never block on a wedged child) — and surfaces a SANITIZED single-line
# ``child_stderr`` field through the structured logger. Never a raw inherit: the
# quarantined child is the most adversary-facing surface, so its stderr is
# de-fanged (control chars stripped -> no forged log lines / terminal escapes) and
# masked by the bootstrap structlog leaf-redactor before it reaches a renderer.
_STDERR_LOG_CAP_BYTES = 4096
_STDERR_TRUNCATION_MARKER = "…[truncated]"
```

Add the two helpers right after `_blocking_read_exactly` (before
`class _SubprocessChildIO`):

```python
def _read_stderr_bytes(process: subprocess.Popen[bytes], cap: int) -> bytes:
    """Read up to ``cap`` bytes of the child's stderr. Caller guarantees exited.

    A pure blocking reader for ``loop.run_in_executor`` (off-loop, same posture as
    ``_blocking_read_exactly``). The child has already exited (the async caller's
    ``poll()`` gate), so its stderr write-end is closed and the read cannot block.
    Returns ``b""`` when there is no stderr pipe (defensive) or nothing was
    buffered. ``cap`` is positional so the caller needs no ``functools.partial``.
    """
    stderr = process.stderr
    if stderr is None:
        return b""
    chunks: list[bytes] = []
    remaining = cap
    while remaining > 0:
        chunk = stderr.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

def _sanitize_child_stderr(raw: bytes, *, cap: int) -> str | None:
    """De-fang child stderr into a single-line structured-log field (or ``None``).

    The quarantined child is the most adversary-facing surface: its stderr may
    carry attacker-influenced bytes (newlines that forge log lines, ANSI escapes
    that manipulate an operator's terminal, other C0/C1 control chars). Every
    Unicode ``Cc`` control char (covers ``\\n \\r \\t \\x1b``, DEL, C1) is replaced
    with a space; whitespace runs are collapsed and the result stripped, so the
    field is single-line-searchable and injection-proof under BOTH the JSON and
    console renderers. Truncated to ``cap`` chars with a marker. Returns ``None``
    when nothing printable remains (no empty-field noise). Secret-shape masking is
    handled DOWNSTREAM by the bootstrap structlog leaf-redactor once this lands as
    a log field.
    """
    text = raw.decode("utf-8", errors="replace")
    despaced = "".join(" " if unicodedata.category(ch) == "Cc" else ch for ch in text)
    collapsed = " ".join(despaced.split())
    if not collapsed:
        return None
    if len(collapsed) > cap:
        return collapsed[:cap] + _STDERR_TRUNCATION_MARKER
    return collapsed
```

- [ ] **Step 5: Run the tests to verify they PASS**

Run:

```bash
uv run pytest tests/unit/security/test_quarantine_child_io.py -k "sanitize_child_stderr or read_stderr_bytes" -q
```

Expected: PASS (10 tests).

- [ ] **Step 6: Lint + type-check the touched files**

Run:

```bash
uv run ruff check src/alfred/security/quarantine_child_io.py tests/unit/security/test_quarantine_child_io.py
uv run ruff format --check src/alfred/security/quarantine_child_io.py tests/unit/security/test_quarantine_child_io.py
uv run mypy src/alfred/security/quarantine_child_io.py
```

Expected: all clean. (If `ruff format --check` flags the new code, run
`uv run ruff format` on the two files and re-check.)

- [ ] **Step 7: Commit**

```bash
git add src/alfred/security/quarantine_child_io.py tests/unit/security/test_quarantine_child_io.py
git commit -m "$(cat <<'EOF'
feat(security): #251 add bounded child-stderr sanitizer + reader helpers

Pure module-private helpers for the quarantine child-IO stderr drain:
_read_stderr_bytes (bounded off-loop reader, exited-child precondition) and
_sanitize_child_stderr (Cc-control-strip -> single-line, injection-proof,
capped). No wiring yet. Under the security/* 100% line+branch gate.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

### Task 2: Exit-gated drain coroutine + `read_frame` failure-arm wiring

**Files:**

- Modify: `src/alfred/security/quarantine_child_io.py`
  (`_SubprocessChildIO.__init__` — add the `_stderr_drained` flag; add the
  `_log_child_stderr` coroutine before `aclose`; wire it into `read_frame`'s
  `except` arm).

- Test: `tests/unit/security/test_quarantine_child_io.py` (extend `_FakePopen` to
  carry a `_FakeStderr`; add read_frame drain tests).

**Interfaces:**

- Consumes: `_read_stderr_bytes`, `_sanitize_child_stderr`, `_STDERR_LOG_CAP_BYTES`
  (Task 1).

- Produces: `_SubprocessChildIO._log_child_stderr(self) -> None` — exit-gated,
  idempotent (`_stderr_drained` flag), emits
  `security.quarantine_child.child_stderr` (warning) with `child_stderr=<str>` ONLY
  when the exited child had non-empty printable stderr. Called by `read_frame`'s
  except arm (Task 2) and `aclose` (Task 3).

- `_FakePopen` gains a `stderr` attribute (`_FakeStderr`) built from a
  `stderr_bytes` ctor kwarg (default `b""`).

- [ ] **Step 1: Extend `_FakePopen` with a stderr pipe**

In `tests/unit/security/test_quarantine_child_io.py`, change `_FakePopen.__init__`
to accept and expose stderr. Replace:

```python
class _FakePopen:
    def __init__(self, stdout_frames: list[bytes]) -> None:
        self.stdin = _FakeStdin()
        self.stdout = _FakeStdout(stdout_frames)
        self.returncode: int | None = None
        self.terminate_calls = 0
        self.wait_calls = 0
```

with:

```python
class _FakePopen:
    def __init__(self, stdout_frames: list[bytes], stderr_bytes: bytes = b"") -> None:
        self.stdin = _FakeStdin()
        self.stdout = _FakeStdout(stdout_frames)
        self.stderr = _FakeStderr(stderr_bytes)
        self.returncode: int | None = None
        self.terminate_calls = 0
        self.wait_calls = 0
```

- [ ] **Step 2: Write the failing read_frame drain tests**

Append to `tests/unit/security/test_quarantine_child_io.py`:

```python
async def test_read_frame_failure_logs_child_stderr_when_exited(
    _spawn_capture: dict[str, Any],
) -> None:
    """A torn read_frame on an EXITED child surfaces its stderr reason (harm 1)."""
    import structlog.testing

    proc = _spawn_capture["proc"]
    proc.stdout = _FakeStdout([b"\x00\x00"])  # truncated header -> _TruncatedFrameError
    proc.stderr = _FakeStderr(b"supervisor.plugin.sandbox_refused reason=environment_not_set")
    proc.returncode = 1  # child has EXITED -> poll() gate passes, drain proceeds

    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        with structlog.testing.capture_logs() as logs:
            with pytest.raises(QuarantineChildSpawnError):
                await cio.read_frame()
        events = [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]
        assert len(events) == 1
        assert "environment_not_set" in events[0]["child_stderr"]
    finally:
        await cio.aclose()

async def test_read_frame_failure_skips_stderr_when_child_still_running(
    monkeypatch: pytest.MonkeyPatch, _spawn_capture: dict[str, Any]
) -> None:
    """A wedged (still-running) child is NOT drained at the failure point (no block)."""
    import structlog.testing

    release = threading.Event()

    class _HangingStdout:
        def read(self, n: int) -> bytes:
            release.wait(timeout=30)
            return b""  # pragma: no cover - the wait_for fires first

    proc = _spawn_capture["proc"]
    proc.stdout = _HangingStdout()
    # If the drain were ever attempted on this running child it would read this;
    # the poll()-gate must skip it (returncode stays None -> poll() is None).
    proc.stderr = _FakeStderr(b"should-not-be-read-while-running")
    monkeypatch.setattr(child_io_mod, "_READ_FRAME_TIMEOUT_S", 0.05)

    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        with structlog.testing.capture_logs() as logs:
            with pytest.raises(QuarantineChildSpawnError):
                await cio.read_frame()
        # No child_stderr event at the failure point — the child is still running.
        assert not [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]
    finally:
        release.set()
        await cio.aclose()
```

- [ ] **Step 3: Run the tests to verify they FAIL**

Run:

```bash
uv run pytest tests/unit/security/test_quarantine_child_io.py -k "read_frame_failure" -q
```

Expected: FAIL — `test_read_frame_failure_logs_child_stderr_when_exited` asserts a
`child_stderr` event that is never emitted (0 events, `len(events) == 1` fails).

- [ ] **Step 4: Add the flag, the coroutine, and wire the read_frame arm**

In `src/alfred/security/quarantine_child_io.py`, add the flag to
`_SubprocessChildIO.__init__` (after `self._closed = False`):

```python
        self._closed = False
        self._stderr_drained = False
```

Add the coroutine to `_SubprocessChildIO`, immediately before `async def aclose`:

```python
    async def _log_child_stderr(self) -> None:
        """Drain (iff the child has exited) + structured-log its stderr, at most once.

        Exit-gated AND idempotent (#251). Order matters:

        1. Already drained -> return (the pipe is consumed; nothing to re-read).
        2. Child NOT exited (``poll() is None``) -> return WITHOUT setting the flag.
           Draining a live child could block on a wedged process; the ``read_frame``
           arm hits this on the timeout/wedged path and ``aclose`` retries after
           ``_terminate_and_reap`` guarantees exit.
        3. Child exited -> read off-loop, SET the flag, and emit
           ``security.quarantine_child.child_stderr`` ONLY when there is printable
           content (no empty-field noise on the happy teardown).

        ``poll()`` is a non-blocking ``waitpid(WNOHANG)`` — it actively detects a
        just-exited child (so the common EOF-after-exit case surfaces at the
        ``read_frame`` arm without a prior ``wait``); after ``_terminate_and_reap``
        it short-circuits on the cached ``returncode``.
        """
        if self._stderr_drained:
            return
        if self._process.poll() is None:  # still running — do NOT set the flag
            return
        loop = asyncio.get_running_loop()
        raw = await loop.run_in_executor(
            None, _read_stderr_bytes, self._process, _STDERR_LOG_CAP_BYTES
        )
        self._stderr_drained = True
        if not raw:
            return
        sanitized = _sanitize_child_stderr(raw, cap=_STDERR_LOG_CAP_BYTES)
        if sanitized is not None:
            _log.warning("security.quarantine_child.child_stderr", child_stderr=sanitized)
```

Wire it into `read_frame`'s `except` arm — insert the `await` between the existing
`_log.error(...)` and the `raise`:

```python
        except (TimeoutError, _TruncatedFrameError) as exc:
            _log.error(
                "security.quarantine_child.read_frame_failed", error_class=type(exc).__name__
            )
            await self._log_child_stderr()
            raise QuarantineChildSpawnError(
                t("security.quarantine_child.read_frame_failed")
            ) from exc
```

- [ ] **Step 5: Run the tests to verify they PASS**

Run:

```bash
uv run pytest tests/unit/security/test_quarantine_child_io.py -k "read_frame_failure" -q
```

Expected: PASS (2 tests). Then run the whole file to confirm no regression:

```bash
uv run pytest tests/unit/security/test_quarantine_child_io.py -q
```

Expected: all PASS.

- [ ] **Step 6: Lint + type-check**

Run:

```bash
uv run ruff check src/alfred/security/quarantine_child_io.py tests/unit/security/test_quarantine_child_io.py
uv run ruff format --check src/alfred/security/quarantine_child_io.py tests/unit/security/test_quarantine_child_io.py
uv run mypy src/alfred/security/quarantine_child_io.py
```

Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/security/quarantine_child_io.py tests/unit/security/test_quarantine_child_io.py
git commit -m "$(cat <<'EOF'
feat(security): #251 drain child stderr on read_frame failure

Exit-gated, idempotent _SubprocessChildIO._log_child_stderr: drains stderr
ONLY when the child has exited (poll() gate -> never blocks a wedged child),
off-loop, and emits a sanitized single-line child_stderr field. Wired into
read_frame's failure arm so a torn frame from an exited child surfaces the
child-side reason (fixes blind failures, hard rule #7) instead of raising blind.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

### Task 3: `aclose` drain-then-close-stderr + remaining branch coverage + adversarial suite

**Files:**

- Modify: `src/alfred/security/quarantine_child_io.py` (`_SubprocessChildIO.aclose`
  — drain after reap, then close the stderr pipe).

- Test: `tests/unit/security/test_quarantine_child_io.py` (aclose drain/idempotency/
  empty/all-control/stderr-none/close tests).

**Interfaces:**

- Consumes: `_log_child_stderr` (Task 2), `_FakeStderr.closed` (Task 1).
- Produces: no new public surface — completes the wiring so a wedged/timeout child's
  stderr is drained after reap, and the stderr pipe fd is closed on teardown.

- [ ] **Step 1: Write the failing aclose tests**

Append to `tests/unit/security/test_quarantine_child_io.py`:

```python
async def test_aclose_drains_stderr_after_reap_for_wedged_child(
    monkeypatch: pytest.MonkeyPatch, _spawn_capture: dict[str, Any]
) -> None:
    """aclose drains the stderr the read_frame arm skipped (the wedged/timeout case)."""
    import structlog.testing

    release = threading.Event()

    class _HangingStdout:
        def read(self, n: int) -> bytes:
            release.wait(timeout=30)
            return b""  # pragma: no cover - the wait_for fires first

    proc = _spawn_capture["proc"]
    proc.stdout = _HangingStdout()
    proc.stderr = _FakeStderr(b"child wedged: stderr buffer full")
    monkeypatch.setattr(child_io_mod, "_READ_FRAME_TIMEOUT_S", 0.05)

    cio = await spawn_quarantine_child_io(provider_key="k")
    with structlog.testing.capture_logs() as logs:
        with pytest.raises(QuarantineChildSpawnError):
            await cio.read_frame()  # child still "running" -> arm skips the drain
        release.set()
        await cio.aclose()  # _terminate_and_reap flips poll() -> exited -> drain runs
    events = [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]
    assert len(events) == 1
    assert "buffer full" in events[0]["child_stderr"]

async def test_child_stderr_logged_at_most_once(_spawn_capture: dict[str, Any]) -> None:
    """read_frame drained+logged -> aclose does NOT re-emit (idempotency flag)."""
    import structlog.testing

    proc = _spawn_capture["proc"]
    proc.stdout = _FakeStdout([b"\x00\x00"])  # truncated -> read_frame raises
    proc.stderr = _FakeStderr(b"boom reason")
    proc.returncode = 1  # exited

    cio = await spawn_quarantine_child_io(provider_key="k")
    with structlog.testing.capture_logs() as logs:
        with pytest.raises(QuarantineChildSpawnError):
            await cio.read_frame()
        await cio.aclose()
    events = [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]
    assert len(events) == 1  # exactly one, from read_frame; aclose is a no-op

async def test_aclose_empty_stderr_emits_no_event(_spawn_capture: dict[str, Any]) -> None:
    """A clean exit with empty stderr emits no child_stderr noise."""
    import structlog.testing

    proc = _spawn_capture["proc"]
    proc.returncode = 0  # exited, and the fixture stderr defaults to b""
    cio = await spawn_quarantine_child_io(provider_key="k")
    with structlog.testing.capture_logs() as logs:
        await cio.aclose()
    assert not [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]

async def test_aclose_all_control_stderr_emits_no_event(_spawn_capture: dict[str, Any]) -> None:
    """Non-empty but all-control stderr sanitizes to None -> no event."""
    import structlog.testing

    proc = _spawn_capture["proc"]
    proc.stderr = _FakeStderr(b"\n\r\n\t   ")
    proc.returncode = 0
    cio = await spawn_quarantine_child_io(provider_key="k")
    with structlog.testing.capture_logs() as logs:
        await cio.aclose()
    assert not [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]

async def test_aclose_closes_stderr_pipe(_spawn_capture: dict[str, Any]) -> None:
    """aclose closes the stderr pipe (fd hygiene) — after draining it."""
    proc = _spawn_capture["proc"]
    proc.returncode = 0
    cio = await spawn_quarantine_child_io(provider_key="k")
    await cio.aclose()
    assert proc.stderr.closed is True

async def test_aclose_with_no_stderr_pipe_is_safe(_spawn_capture: dict[str, Any]) -> None:
    """A None stderr pipe (defensive) neither crashes nor emits an event."""
    import structlog.testing

    proc = _spawn_capture["proc"]
    proc.stderr = None
    proc.returncode = 0
    cio = await spawn_quarantine_child_io(provider_key="k")
    with structlog.testing.capture_logs() as logs:
        await cio.aclose()  # must not raise AttributeError on None.close()
    assert not [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]
```

- [ ] **Step 2: Run the tests to verify they FAIL**

Run:

```bash
uv run pytest tests/unit/security/test_quarantine_child_io.py -k "aclose_drains_stderr or child_stderr_logged_at_most_once or aclose_empty_stderr or aclose_all_control or aclose_closes_stderr or aclose_with_no_stderr" -q
```

Expected: FAIL — `test_aclose_drains_stderr_after_reap_for_wedged_child` (0 events)
and `test_aclose_closes_stderr_pipe` (`proc.stderr.closed` is `False` — aclose does
not close it yet).

- [ ] **Step 3: Wire the drain + stderr-close into `aclose`**

In `src/alfred/security/quarantine_child_io.py`, replace `aclose`:

```python
    async def aclose(self) -> None:
        """Terminate + reap the child (idempotent); close the owned control-end, if any."""
        if self._closed:
            return
        self._closed = True
        await _terminate_and_reap(self._process)
        if self._control_parent is not None:
            with contextlib.suppress(OSError):
                self._control_parent.close()
```

with:

```python
    async def aclose(self) -> None:
        """Terminate+reap the child; drain+log its stderr; close pipe/control-end.

        Idempotent. After ``_terminate_and_reap`` the child is guaranteed exited, so
        ``_log_child_stderr`` drains the stderr the ``read_frame`` arm skipped on a
        wedged/timeout child (#251), then the stderr pipe fd is closed (it is the
        pipe this IO owns end-to-end and the only one never read/closed before —
        stdin/stdout are left to ``Popen`` GC to avoid racing an orphaned
        ``read_frame`` executor thread still reading stdout).
        """
        if self._closed:
            return
        self._closed = True
        await _terminate_and_reap(self._process)
        await self._log_child_stderr()
        stderr = self._process.stderr
        if stderr is not None:
            with contextlib.suppress(OSError):
                stderr.close()
        if self._control_parent is not None:
            with contextlib.suppress(OSError):
                self._control_parent.close()
```

- [ ] **Step 4: Run the tests to verify they PASS**

Run:

```bash
uv run pytest tests/unit/security/test_quarantine_child_io.py -k "aclose_drains_stderr or child_stderr_logged_at_most_once or aclose_empty_stderr or aclose_all_control or aclose_closes_stderr or aclose_with_no_stderr" -q
```

Expected: PASS (6 tests).

- [ ] **Step 5: Full file + sibling suites + 100% coverage gate**

Run the whole target test file:

```bash
uv run pytest tests/unit/security/test_quarantine_child_io.py -q
```

Expected: all PASS.

Confirm the security 100% line+branch gate for this file (mirrors ci.yml:265):

```bash
uv run pytest tests/unit/security/test_quarantine_child_io.py -q \
  --cov=src/alfred/security/quarantine_child_io --cov-branch \
  --cov-report=term-missing --cov-fail-under=100
```

Expected: `TOTAL ... 100%`, exit 0, no `Missing` lines for the new code. If any new
branch is uncovered, add the missing-branch test here (do NOT add `# pragma: no
cover` on this security-gated file).

- [ ] **Step 6: Lint, type-check, and the release-blocking adversarial suite**

`src/alfred/security/` changed → the adversarial suite is release-blocking:

```bash
uv run ruff check src/alfred/security/quarantine_child_io.py tests/unit/security/test_quarantine_child_io.py
uv run ruff format --check src/alfred/security/quarantine_child_io.py tests/unit/security/test_quarantine_child_io.py
uv run mypy src/alfred/security/quarantine_child_io.py && uv run pyright src/alfred/security/quarantine_child_io.py
uv run pytest tests/adversarial -q
```

Expected: lint/format/types clean; adversarial suite PASS (exit 0). Any bwrap-gated
adversarial tests may SKIP on this macOS host — that is expected (trust Linux CI).

- [ ] **Step 7: Commit**

```bash
git add src/alfred/security/quarantine_child_io.py tests/unit/security/test_quarantine_child_io.py
git commit -m "$(cat <<'EOF'
feat(security): #251 drain+close child stderr on aclose teardown

aclose now drains the wedged/timeout child's stderr after terminate+reap (the
case read_frame's arm skips while the child is still running) and closes the
stderr pipe fd (hygiene — the one pipe never read/closed before). stdin/stdout
left to Popen GC to avoid racing an orphaned read_frame executor thread.
Completes #251; security/* 100% line+branch gate green; adversarial suite run.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Post-implementation (pre-PR — held for the user)

After all three tasks are green (do NOT push without the user — outward-facing):

1. `make check` (lint + format + type + full unit) — the mechanical gate before any
   push; check `$?` (a piped `tail` masks the exit code).
2. Full `/review-pr` fleet (security ALWAYS) + BOTH CodeRabbit (CLI `--base
   origin/main` + cloud) — they catch disjoint bugs.
3. Push + open the PR. The body must NOT use a closing keyword ("Closes/Fixes
   #251") — #251 is a standalone fix but sits UNDER the #340 epic; use "Part of
   #340 / fixes the #251 predependency" wording so GitHub does not auto-close the
   epic. Reference the spec + this plan.
4. Resolve every review thread; wait for the Linux Python + Integration lanes before
   assuming green; plain `gh pr merge --rebase` (never `--admin`).
5. After merge: rebase the #340 PR2a follow-up work (Task 7 docker C1/C2 + Task 8b
   paper-gate) onto the new main — #251 was its hard predependency.

## Self-Review (author checklist — completed)

- **Spec coverage:** §3 Scope A → all 3 tasks; §4.1 helpers → Task 1; §4.2 drain +
  read_frame/aclose wiring → Tasks 2/3; §4.3 stderr-only close → Task 3; §4.4
  no-exception-note/no-message-change → honored (no `t()` touched); §5 all 8 test
  themes → covered (sanitization ×5, reader ×3, read_frame exited/running ×2, aclose
  wedge/idempotency/empty/all-control/close/none ×6); §6 adversarial suite → Task 3
  Step 6.

- **Placeholder scan:** none — every step has concrete code/commands.
- **Type/name consistency:** `_read_stderr_bytes` (positional `cap`),
  `_sanitize_child_stderr(raw, *, cap)`, `_STDERR_LOG_CAP_BYTES`,
  `_STDERR_TRUNCATION_MARKER`, `_stderr_drained`, `_log_child_stderr`,
  `security.quarantine_child.child_stderr`, `_FakeStderr` — used identically across
  tasks.

- **Branch-coverage inventory (no new pragmas):** `_read_stderr_bytes`
  (None / loop-cap-exit / EOF-break), `_sanitize_child_stderr` (empty→None /
  content / >cap), `_log_child_stderr` (drained / poll-None / not-raw /
  sanitized-None), `aclose` (stderr not-None / None) — each has a dedicated test.

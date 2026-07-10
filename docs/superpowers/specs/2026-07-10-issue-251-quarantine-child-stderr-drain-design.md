# Issue #251 — Drain the quarantine child's stderr (design)

**Status:** RATIFICATION-PENDING (best-judgment pass; user away at design time).
**Issue:** #251 — *Quarantine child-IO swallows child stderr (blind failures + latent deadlock).*
**Branch target:** off `main` `3c560c97`.
**Scope:** a SMALL standalone security-boundary PR. It is the hard predependency
for #340 PR2a's deferred **Task 7** (docker C1/C2 real-spawn test), which needs
child-side stderr visibility to diagnose a failed real spawn.

---

## 1. Problem

`spawn_quarantine_child_io` (`src/alfred/security/quarantine_child_io.py`)
launches the bwrapped quarantined-LLM child with `stderr=subprocess.PIPE`, but
`_SubprocessChildIO` **never reads that pipe**. Two consequences:

1. **Blind failures (CLAUDE.md hard rule #7).** When the child crashes or the
   launcher refuses (e.g. `supervisor.plugin.sandbox_refused
   reason=environment_not_set`), `read_frame` raises a bare
   `QuarantineChildSpawnError` (`_TruncatedFrameError` / `TimeoutError` arm) with
   **no child-side cause** — the actual reason sits in the undrained pipe.
   Diagnosing the #250 failure required a full docker repro that read
   `process.stderr` directly.
2. **Latent pipe-buffer stall.** A child that writes more than the pipe buffer
   (~64KB on Linux) to its never-drained stderr blocks on the stderr `write(2)`,
   cannot finish writing its stdout reply frame, and the host's `read_frame`
   truncates/wedges. The existing 15s `read_frame` bound
   (`_READ_FRAME_TIMEOUT_S`) already caps this to a *bounded* failure rather than
   an infinite host hang — but the child-side reason is still lost, and a child
   that would otherwise have succeeded is failed spuriously.

## 2. Goal / non-goals

**Goal.** Surface the child's stderr through the host's **structured** logger as
a sanitized `child_stderr=…` field on the failure/teardown paths, so an operator
(and the Task-7 docker test) can see *why* a spawn/extract failed — without
ever inheriting the adversary-facing child's raw stderr into the host log stream.

**Non-goals.**

- **Not** preventing the >64KB stall outright (that is "Scope B" — a concurrent
  background stderr reader; see §7). This PR makes the stall *bounded* (already
  true via the 15s read bound) and *diagnosable*.
- **Not** changing the wire contract, framing, spawn discipline, the fd-3 key
  delivery, the opt-in control-fd (#340 PR2a) plumbing, or any egress ratchet.
- **Not** adding any operator-facing prose string (no new i18n catalog entries).

## 3. Chosen approach — Scope A: best-effort bounded drain

Drain the child's stderr **only when the child has exited**, bounded and
off-loop, on the `read_frame` failure arm AND in `aclose` (after terminate+reap).

### 3.1 Why Scope A over Scope B (concurrent drain)

| Concern | Scope A (chosen) | Scope B (deferred) |
| --- | --- | --- |
| Fixes blind failures (harm 1) | Yes, fully | Yes |
| Prevents the >64KB stall (harm 2) | No — bounded (15s) + diagnosable only | Yes |
| Mechanism | drain-iff-exited helper on 2 existing paths | background asyncio reader task + ring buffer at spawn |
| Blast radius | 1 module, 2 methods, no new lifecycle | a concurrent task in the most adversary-facing spawn path |

Scope A matches the issue's literal proposal, is YAGNI-correct (the child's
stderr volume is our own controllable code + the launcher; the >64KB case is
genuinely latent), and is the smallest, most-reviewable change on a
security-boundary path. Scope B is a clean follow-up **iff** a chatty child ever
makes the stall real.

## 4. Design

All changes are confined to `src/alfred/security/quarantine_child_io.py` and its
unit tests.

### 4.1 Sanitized bounded drain (module-private)

```python
_STDERR_LOG_CAP_BYTES = 4096  # enough for a launcher refusal / short traceback; bounded for log hygiene

def _sanitize_child_stderr(raw: bytes, *, cap: int) -> str | None:
    """Decode + de-fang child stderr for a single-line structured-log field.

    The quarantined child is the most adversary-facing surface: its stderr may
    carry attacker-influenced bytes (embedded newlines that forge log lines, ANSI
    escape sequences that manipulate an operator's terminal, bidi overrides that
    display-spoof the line, other C0/C1 control or format chars). Every char in a
    stripped Unicode category is collapsed to a single space so the field is
    single-line-searchable and injection-proof under BOTH the JSON and console
    renderers; the result is truncated to ``cap`` with a marker. Secret-shape
    masking is handled DOWNSTREAM by the bootstrap's structlog leaf-redactor
    (``_redact_value``) once this lands as a log FIELD.
    """
```

- Decode `errors="replace"` (a non-UTF-8 child stderr must never crash the drain).
- Replace every char in a stripped Unicode category — `Cc` (C0/C1 controls,
  covering `\n \r \t \x1b` and DEL) **and** `Cf` (format chars: bidi overrides
  U+202E / directional isolates U+2066-2069, zero-width U+200B / BOM U+FEFF) — with
  a space; collapse runs of whitespace; `strip()`. Result is single-line. Stripping
  `Cf` closes the "Trojan Source" bidi display-spoof, a control-char-free attack the
  child could otherwise smuggle into an operator's terminal (task-review fold).
- Truncate to `cap` characters; append `…[truncated]` if it was longer. The drain
  caller reads `_STDERR_LOG_CAP_BYTES + 1` bytes (one past the log cap) so an
  over-cap child's stderr actually trips this marker end-to-end — otherwise
  read-cap == log-cap makes the decoded char count unable to exceed the cap and a
  long diagnostic is silently clipped (final-review fold).
- Return `None` when the sanitized string is empty (nothing to log).

```python
def _read_stderr_bytes(process: subprocess.Popen[bytes], cap: int) -> bytes:
    """Read up to ``cap`` bytes of the child's stderr. Caller guarantees exited.

    ``cap`` is positional (not keyword-only) so the async caller can hand this to
    ``loop.run_in_executor(None, _read_stderr_bytes, process, cap)`` without a
    ``functools.partial`` wrapper.

    A pure blocking reader run in the caller's executor (off-loop, same as
    ``_blocking_read_exactly``). The EXITED precondition is enforced by the async
    caller (below) — NOT here — because the exited-vs-running decision also drives
    the idempotency flag and must not be entangled with "no pipe". Returns ``b""``
    when there is no stderr pipe (defensive) or nothing was buffered.
    """
```

- `if process.stderr is None: return b""`.
- Read up to `cap` bytes (loop over short reads until `cap` reached or EOF).
  The child has exited (caller's precondition) → its stderr write-end is closed
  → the read cannot block.

**The `poll()`-exited gate lives in the async caller, not this reader** — so the
idempotency flag (below) is set only once the child has actually exited. A reader
that folded "still running" into a `None` return would let the `read_frame` arm
(child still wedged → skip) set the flag and starve `aclose`'s post-reap drain.

### 4.2 `_SubprocessChildIO` — drain-and-log, idempotent

Add one instance flag and one async helper:

```python
self._stderr_drained = False  # in __init__

async def _log_child_stderr(self) -> None:
    """Drain (iff exited) + structured-log the child's stderr, at most once.

    Exit-gated, idempotent, AND best-effort-never-raises. Order matters:
      1. If already drained → return (consumed pipe; nothing to re-read).
      2. If the child has NOT exited (``poll() is None``) → return WITHOUT setting
         the flag. Draining a live child could block on a wedged process. The
         ``read_frame`` arm hits this on the timeout/wedged path; ``aclose``
         retries after ``_terminate_and_reap`` guarantees exit.
      3. Child exited → SET the flag (before the read, so a read failure is not
         retried), read (off-loop), log iff non-empty.
    A diagnostic-drain failure (e.g. an ``OSError`` on the pipe) must NEVER preempt
    the caller's ``QuarantineChildSpawnError`` (hard rule #7 + §6): the body past
    the exit gate is wrapped so any failure is surfaced LOUDLY as
    ``stderr_drain_failed`` (never silent), mirroring ``_terminate_and_reap``.
    """
    if self._stderr_drained:
        return
    try:
        if self._process.poll() is None:  # still running — do NOT set the flag
            return
        self._stderr_drained = True  # set before the read: a read failure won't retry
        loop = asyncio.get_running_loop()
        # Read one byte PAST the log cap so an over-cap child trips the truncation
        # marker (with read-cap == log-cap the decoded char count could never exceed
        # cap → a long stderr was silently clipped with no "…[truncated]" hint).
        raw = await loop.run_in_executor(
            None, _read_stderr_bytes, self._process, _STDERR_LOG_CAP_BYTES + 1
        )
        if not raw:
            return
        sanitized = _sanitize_child_stderr(raw, cap=_STDERR_LOG_CAP_BYTES)
        if sanitized is not None:
            _log.warning("security.quarantine_child.child_stderr", child_stderr=sanitized)
    except Exception:  # best-effort: never preempt the caller's error (hard rule #7)
        _log.warning("security.quarantine_child.stderr_drain_failed", exc_info=True)
```

`process.poll()` is a non-blocking `waitpid(WNOHANG)` — cheap on the loop thread,
and it actively detects a just-exited child (so the common #250 EOF case surfaces
at the `read_frame` arm without a prior `wait`). After `_terminate_and_reap` has
called `process.wait()`, `poll()` short-circuits on the cached `returncode`.

Wire it into the two existing paths:

- **`read_frame` except arm** — `await self._log_child_stderr()` **before**
  `raise QuarantineChildSpawnError(...)`. The common #250 case (launcher refuses
  → child exits → EOF → `_TruncatedFrameError`) has the child already exited by
  the time we reach the arm, so the reason surfaces at the point of failure. If
  the child is still running (timeout/wedged), the drain skips (returns `None`);
  `aclose` picks it up after the reap.
- **`aclose`** — after `_terminate_and_reap(self._process)` (child now
  guaranteed exited), `await self._log_child_stderr()` (catches the
  wedged/timeout case and anything not yet drained), **then** close the `stderr`
  pipe file object under `contextlib.suppress(OSError)` (see §4.3), then close the
  owned control-parent as today.

### 4.3 Adjacent fd hygiene (in-scope) — stderr-only close

`aclose` currently terminates+reaps but never closes the parent-side stderr pipe
file object — CPython closes it only at `Popen` garbage-collection. Since this PR
already drains stderr, it closes **that pipe** explicitly (after the drain, so the
drain can still read it). stderr is the pipe this PR owns end-to-end, and the only
one that was *never* read or closed before this change (stdin/stdout are consumed
during normal operation).

**Why stderr-only and NOT stdin/stdout.** The bounded `read_frame` path cancels
its `asyncio.wait_for` on timeout but leaves the executor thread still blocked in
`stdout.read()` (see `test_read_frame_is_bounded`). Closing `stdout` out from
under that orphaned reader is a race. stderr normally has no such hazard:
`_log_child_stderr` **awaits** the drain's executor read to completion before
`aclose` proceeds, so there is normally no concurrent stderr reader. The one
exception is the drain's OWN `asyncio.wait_for` bound (`_STDERR_DRAIN_TIMEOUT_S`,
added for the `/review-pr` security finding): a drain that TIMES OUT orphans an
executor thread still reading stderr, so `_log_child_stderr` sets
`_stderr_reader_orphaned` and `aclose` then **skips** the `stderr.close()` for
exactly that pipe (left to `Popen` GC), avoiding a close that would re-block on the
reader's `BufferedReader` lock. That timeout path is unreachable under the shipped
`kind="full"` PID-namespace policy (the write-end closes on child exit → the read
returns EOF promptly). Residual stdin/stdout parent-fd cleanup is likewise left to
`Popen` GC; reclaiming those explicitly is not worth re-opening the stdout race.

### 4.4 What is deliberately NOT done

- **No exception note.** Unlike `_state_git.py` (which does both `_log.warning`
  and `err.add_note(...)`), the child stderr is surfaced via the **structured
  log ONLY**. An exception note can be rendered on a path that does not run the
  redactor; the log field always does. More conservative for the most
  adversary-facing surface.
- **No change** to the raised `QuarantineChildSpawnError` messages (still the
  existing `t(...)` keys) — so no i18n drift.

## 5. Testing (TDD)

All hermetic on macOS / non-root CI (no real subprocess), reusing the existing
`test_quarantine_child_io.py` monkeypatch discipline (`_FakePopen`, faked
`os.dup2`/`Popen`/`deliver_provider_key_via_fd3`). `structlog.testing.capture_logs`
asserts the emitted field (the security-suite idiom).

`_FakePopen` gains:

- a `_FakeStderr` raw-pipe stand-in (`read(n)` over a buffer; EOF on drain);
- a settable exit state so `poll()` returns `None` (running) or an int (exited).

Tests:

1. **read_frame truncated-EOF, child EXITED** → `child_stderr` event emitted with
   the fake stderr content; `QuarantineChildSpawnError` still raised.
2. **read_frame failure, child STILL RUNNING** (`poll()` is `None`) → NO
   `child_stderr` event at the failure point, and the drain does not block.
3. **aclose after a wedged read_frame** → terminate+reap flips `poll()` to exited
   → `aclose` drains + emits `child_stderr`.
4. **Sanitization** — stderr containing `\n`, `\r`, `\x1b[31m…`, and other control
   chars → the logged field is single-line and control-char-free.
5. **Cap** — stderr longer than `_STDERR_LOG_CAP_BYTES` → field truncated with the
   `…[truncated]` marker.
6. **Idempotency** — read_frame drains+logs, then aclose does NOT emit a second
   `child_stderr` event (flag set; consumed pipe).
7. **Empty stderr** → no `child_stderr` event on the happy teardown.
8. **stderr pipe closed on aclose** — `_FakeStderr.close()` was called after the
   drain. (stdin/stdout are intentionally left to `Popen` GC — §4.3.)

`test_quarantine_child_io_i18n.py` is unaffected (no new catalog keys) and must
still pass. No `security/*` coverage-gate regression: the new lines are all
unit-reachable.

## 6. Security review anchors (self-check before /review-pr)

- **Hard rule #7 (no silent failures).** The drain makes a previously-silent
  failure LOUD with its cause; it never swallows an error — the
  `QuarantineChildSpawnError` still propagates unchanged. The drain itself is
  **best-effort-never-raises** (enforced in `_log_child_stderr`, not just
  asserted): a diagnostic-read failure surfaces LOUDLY as `stderr_drain_failed`
  and cannot preempt the primary `QuarantineChildSpawnError` — a secondary
  diagnostic must never mask the primary error (task-review fold).
- **Log-injection defense.** Control chars collapsed at the source → no forged
  log lines / terminal escapes under either renderer.
- **Secret leakage.** The `child_stderr` field passes through the bootstrap
  leaf-redactor (`_redact_value`, stage-1 broker + stage-2 generic-key regex)
  like every other log field. The drain adds no new bypass. The `stderr_drain_failed`
  fallback logs only `error_class` (the exception TYPE), never the child's bytes and
  never `exc_info` (which the bootstrap chain would not render anyway).
- **T3-derived-content disclosure to the ops-log plane (accepted residual).** The
  quarantined child is precisely the process that touches T3 content, so a buggy /
  adversarial extraction could embed T3-DERIVED (non-secret) fragments in its stderr,
  which now flow — capped + sanitized + redactor-scanned, but NOT DLP-stripped of
  arbitrary T3 text — into the operational-log/observability plane (PRD §7.5), whose
  retention/access posture differs from the audit log (PRD §7.4). This does NOT break
  the dual-LLM invariant (the privileged orchestrator never reads `child_stderr`) and
  the field is bounded/de-fanged, so it is an accepted residual, not release-blocking —
  the same hazard `docs/subsystems/quarantine.md` names for the sibling
  `downgrade_to_orchestrator` audit path. Revisit if child stderr is ever routed
  anywhere lower-trust than the operator log.
- **Canary forward-gate.** Today `configure_logging` wires the redactor with
  `canary=None`, so the shared log path cannot raise `OutboundCanaryTripped`. When
  canary vocabulary IS wired, a canary token surfacing in child stderr would raise
  inside `_log_child_stderr`'s try and be demoted to `stderr_drain_failed` by the
  best-effort `except` — at that point the `except` MUST special-case + escalate it
  (a code comment marks this gate).
- **Bounded drain (no hang).** The drain read is `asyncio.wait_for`-bounded
  (`_STDERR_DRAIN_TIMEOUT_S`), so liveness does not rest solely on the bwrap
  PID-namespace reaping assumption — a write-end held open past child exit trips the
  deadline (caught as `stderr_drain_failed`) instead of hanging `aclose`.
- **No raw inherit.** The child's stderr is captured to a PIPE and surfaced only
  as a sanitized field — never `stderr=None` (host fd 2 raw inherit), which would
  be the actual injection hole.
- **Adversarial suite.** `src/alfred/security/` is touched → run the full
  adversarial suite locally (release-blocking).

## 7. Deferred (Scope B — only if a chatty child ever makes the stall real)

A background stderr reader task started at spawn that continuously drains stderr
into a bounded ring buffer, so the child can never block on a full stderr pipe.
Prevents harm 2 outright. Deferred as YAGNI: the child's stderr volume is our own
code + the launcher, and the 15s read bound already caps the failure.

## 8. Open decision for the user (ratify at the spec gate)

- **D1 — Scope A vs Scope B.** Chosen: **A** (best-effort drain). Confirm, or
  switch to B if you want the stall *prevented* now.
- **D2 — fd-hygiene breadth.** Chosen: close **`stderr` only** in `aclose`
  (stdin/stdout left to `Popen` GC to avoid the orphaned-executor-thread race on
  stdout — see §4.3). Confirm, or widen to all three if you want the explicit
  reclaim and accept the stdout race handling.

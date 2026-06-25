# G4a — Gateway `ReplayBuffer` (pure un-acked retention) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the pure, dependency-free `ReplayBuffer` state machine that retains un-acked **inbound** (client→core) gateway frames, trims+zeroes them on cumulative ack, bounds itself by frames/bytes/TTL with a back-pressure breaker latch (plus a last-resort hard ceiling), and replays the un-acked remainder — *carrying each frame's original seq* — with **no I/O, no clock, no logging**.

**Architecture:** A single pure class (`src/alfred/gateway/replay_buffer.py`) modelled on the existing pure-state-machine siblings `_seq_tracker.py` (`BoundedSeqAckTracker`) and `link_state.py` (`LinkStateMachine`). It stores each retained inbound frame as a **mutable `bytearray` copy** (so the bytes can be zeroed on removal — the security requirement of spec §6) keyed by its per-direction monotonic `seq`. Time is injected as an explicit `now: float` argument on the methods that need it (the spec §7 "fake clock" seam), so the class stays pure and hypothesis-testable in isolation. **Loudness is the wiring's job (G4b):** this class never audits or logs; it surfaces signals (return values + `breaker_tripped`) the G4b reconnect/relay wiring polls to write the spec §6 loud audit rows. This is the deliberate "pure state machine, no deps" boundary the spec §7 component list mandates.

**Tech Stack:** Python 3.12+ (PEP 604/585/695 idioms), frozen-where-possible dataclasses, `mypy --strict` + `pyright`, `ruff`, `pytest` + `hypothesis`. No new dependencies. No `prometheus_client`, no `structlog`, no `asyncio` in this module.

---

## Context the engineer needs

**Where this sits in the program.** This is **G4a** of Spec A (the Comms-Resume Gateway). Read `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md` §4 (Wire protocol — the seq/ack/epoch model), §5 (Resume flow), §6 (Trust-boundary posture), §7 (Components — the `ReplayBuffer` bullet), §8 (Epic decomposition — the G4 row + its `G4a buffer / G4b reconnect+replay+frames` split), and §9 (Testing). The merged G3 work (`src/alfred/gateway/`) already ships the relay, the link-state machine, the core-link, and the seq codec — **G4a does not touch any of them**. G4b (a later PR) wires this buffer into `relay.py`/`core_link.py`, drives the `breaker_tripped` → `GatewayLinkEvent.BREAKER_TRIPPED` → `LinkControl.UNAVAILABLE` link-state transition, and writes the audit rows. **Do not do G4b's wiring here.**

**Read these sibling files before writing code** (match their docstring density, naming, and the fail-loud idiom):

- `src/alfred/gateway/_seq_tracker.py` — the closest analog: a pure bounded state machine, `from __future__ import annotations`, `typing.Final` constants, fail-loud `ValueError`/`AlfredError` on a negative seq, an `__all__` export, no I/O.
- `src/alfred/gateway/link_state.py` — the `GatewayLinkState`/`GatewayLinkEvent`/`LinkControl` enums and the `AlfredError`-rooted exception. Note line 84: `LinkControl.UNAVAILABLE` already exists "for the wire vocabulary even though G3-3a never emits it" — **G4b** is what makes the gateway emit it; G4a only supplies the breaker signal.
- `src/alfred/plugins/comms_seq_codec.py` lines 78-167 — the `SeqFrame` dataclass. The relay (G4b) will call `buffer.append(frame.seq, frame.payload, now=...)`; G4a takes the primitives (`int` seq + `bytes` payload), **not** a `SeqFrame`, so the buffer never couples to the codec.

**The exception root.** `from alfred.errors import AlfredError`. All programming-error raises subclass a module-local `ReplayBufferError(AlfredError)`.

### The seq model — read this twice (it is the #1 review finding)

The inbound (client→core) seq this buffer retains is **gateway-owned and monotonic across a core restart**. Spec §4: *"the gateway preserves `id` end-to-end"* and *"epoch reconciles 'new-core seq=0' vs the gateway's retained high-water (seq resets on a fresh core)"* — the **seq reset is the core→client direction**; the **client→core direction the gateway mints stays monotonic** through a core bounce. Concretely, the normal-restart path is:

1. Gateway appends inbound seqs `0..40`; core durably acks through 20; buffer retains `21..40`, `_last_seq == 40`.
2. Core crashes; gateway keeps buffering inbound: `41, 42` → `_last_seq == 42`. **No discard** (resume is being attempted).
3. New core handshakes, epoch re-checked, advertises its durable high-water (say 20). G4b calls `trim_to_ack(20)` (no-op here — already trimmed), then `unacked_frames()` re-sends `21..42` **with their original seqs** (the core dedups on `(leg, seq)`).
4. Operator types again; the gateway mints `43`. `append(43, …)` — strictly increasing, accepted. **The monotonic guard is never tripped on a normal restart.**

Therefore: **`discard()` does NOT reset the seq floor**, and there is **no seq-floor reset method in G4a**. A genuine seq-space restart (a brand-new session reusing the buffer with seq back at 0) is a G4b *epoch-handshake* concern — G4b will add an explicit, epoch-gated floor-reset operation *when it wires the handshake*, sequenced AFTER it has torn down the old leg and bound the new epoch, so a late stale-stream frame cannot be silently re-admitted (Security F1). G4a deliberately leaves the floor monotonic-for-life: a lower seq after a `discard` is a programming error and stays a loud `ReplayBufferError`.

**`now` must be monotonic too (Security F5).** `append` requires `now >= the previous append's now`; a violation raises `ReplayBufferError`. This makes the "expired frames are a leading FIFO prefix" assumption that `evict_expired` relies on a *guaranteed* invariant, not a hope — a non-monotonic clock seam would otherwise silently under-evict expired pre-DLP input past its TTL. G4b MUST inject a `time.monotonic()`-derived clock.

### Trust-boundary posture (spec §6) — bake these into the docstrings

- **Payload-blind / T1 carrier (hard rule #5).** The buffer stores opaque inbound bytes verbatim and replays them verbatim. It never inspects, decodes, or trust-tags them — T3 tagging stays in the core. It holds **pre-DLP operator input**, which is why the cap+TTL+zeroing bound is a *security* property.
- **Zeroing is non-optional (spec §6).** Every byte that leaves on a removal path (`trim_to_ack`, `evict_expired`, `discard`) is overwritten in place (`body[:] = b"\x00" * len(body)` — a sound in-place `bytearray` overwrite, confirmed by the security review) before its reference is dropped, with white-box tests asserting the captured body reads all-zero afterward.
- **Zeroing residual-risk caveat (document explicitly).** Python gives no true crypto-erase guarantee (the GC may have copied, interned, or paged the bytes). We zero *our own* mutable copy best-effort. Two un-zeroable surfaces the buffer does NOT cover, and which therefore depend on G4b's process hardening (`MADV_DONTDUMP` / core-dump suppression — out of scope here, load-bearing there): (1) the immutable `bytes` a caller passes to `append` (caller-owned); (2) the immutable `bytes` `unacked_frames` hands back — and a flapping reconnect can mint *many* such copies live at once (Security F3), so G4b must not retain replay results beyond the single send.
- **Bounded retention is a TWO-PART contract (Security F2).** The buffer *signals*; G4b *enforces*. On a soft-cap breach `append` keeps the frame (the spec §5 no-silent-drop guarantee) and trips the `breaker_tripped` latch; G4b polls it and back-pressures by *ceasing to drain the client socket*. **Post-breach growth is bounded only by G4b's read-halt latency** — that residual window is the half this pure layer does not close, and the adversarial "wedged-core flood → bounded + loud" corpus entry (spec §6(d)) is a G4b release-blocker asserting G4b actually halts. As a defence-in-depth backstop against a *buggy* G4b that never halts, `append` enforces a **hard ceiling** at `_HARD_CAP_MULTIPLIER ×` each soft cap: beyond it `append` raises `ReplayBufferError` (fail-closed, loud — never a silent drop) so the always-up security process cannot be driven to OOM. The soft cap is the normal back-pressure signal; the hard ceiling is the last resort.
- **`trim_to_ack` is the one non-loss removal (Security F4).** It removes frames the core has **durably acked**, so it is *not* input loss and correctly returns nothing (unlike `evict_expired`, which returns the evicted seqs because TTL eviction *is* loss). Precondition G4b MUST honour: the `cumulative_ack` passed in comes ONLY from the core's epoch-validated durable-intake high-water — a trim driven by a *spoofed/stale-epoch* ack (spec §6 threat (c)) would zero un-committed input. The pure buffer cannot tell a real ack from a forged one; the epoch check gates trust, and that gating is G4b's obligation.

**No-silent-failure (CLAUDE.md hard rule #7).** TTL eviction returns the evicted seqs (G4b audits each); `breaker_tripped` is a polled latch; the hard ceiling raises loud. Programming errors (non-monotonic/negative `seq`, non-monotonic `now`, non-positive cap) raise loud. The "expose, don't audit, at this pure layer" posture matches `_seq_tracker.py`'s caller-audits-the-warning idiom — the security review confirmed it acceptable *provided* G4b turns every signal loud.

**i18n.** This module has **zero** operator-/user-facing strings (developer-facing exceptions only; the operator-facing `link.unavailable` string is G4b's). No `t()` — same posture as `_seq_tracker.py`.

---

## File structure

- **Create:** `src/alfred/gateway/replay_buffer.py` — the G4a deliverable: `ReplayBuffer`, `ReplayBufferError(AlfredError)`, the public `ReplayFrame` value type, the private `_Retained` entry, the `_*` `Final` constants, an `__all__`.
- **Create:** `tests/unit/gateway/test_replay_buffer.py` — example-based (Tasks 1-7) + hypothesis property tests (Task 8).
- **Modify:** `src/alfred/gateway/__init__.py` — re-exports every sibling kernel in a sorted `__all__` (confirmed by the review). Add `ReplayBuffer`, `ReplayBufferError`, `ReplayFrame`.
- **Modify:** `.github/workflows/ci.yml` — add `src/alfred/gateway/replay_buffer.py` to BOTH per-file 100% coverage `--include` lists (the `python` job ~line 230 and the `coverage-gates` job ~line 1265) AND BOTH `hashFiles(...)` existence guards (~line 227 and ~line 1262).
- **Modify:** `docs/adr/0032-*.md` — Task 10 adds the buffer's security-bounded-retention subsection (spec §6 says ADR-0032 records it).

---

## Public API (lock this — later tasks reference these exact signatures)

```python
class ReplayBufferError(AlfredError):
    """A programming-error misuse of the buffer (non-monotonic/negative seq, non-monotonic now, bad cap, hard-ceiling breach)."""


@dataclass(frozen=True, slots=True)
class ReplayFrame:
    """A replayable un-acked frame: its gateway-owned per-direction seq + opaque payload.

    Replay MUST carry the ORIGINAL seq — the core dedups on ``(leg, seq)`` (spec §4
    decision 4), so re-minting would defeat the no-double-effect guarantee.
    """
    seq: int
    payload: bytes


@dataclass(slots=True)
class _Retained:
    """One retained un-acked inbound frame: seq + a mutable, zeroable body + its monotonic enqueue time."""
    seq: int
    body: bytearray
    enqueued_at: float


class ReplayBuffer:
    def __init__(self, *, max_frames: int, max_bytes: int, ttl_seconds: float) -> None: ...

    @property
    def depth_frames(self) -> int: ...
    @property
    def depth_bytes(self) -> int: ...
    @property
    def breaker_tripped(self) -> bool: ...

    def append(self, seq: int, payload: bytes, *, now: float) -> None: ...
    def trim_to_ack(self, cumulative_ack: int) -> None: ...
    def evict_expired(self, *, now: float) -> tuple[int, ...]: ...
    def unacked_frames(self) -> tuple[ReplayFrame, ...]: ...
    def discard(self) -> None: ...
```

Semantics (the contract every test pins):

- **`append`** — FIFO-appends a fresh inbound frame. `seq` must be `>= 0` and `> the last appended seq`; `now` must be `>= the last appended now`; either monotonicity violation, or a negative seq, raises `ReplayBufferError` (programming error). Stores a `bytearray(payload)` copy + stamps `enqueued_at=now`. **Soft cap:** if the append pushes depth past `max_frames` or `max_bytes`, it KEEPS the frame and sets the `breaker_tripped` latch (never drops). **Hard ceiling:** if the append *would* push depth past `_HARD_CAP_MULTIPLIER × max_frames` or `× max_bytes`, it raises `ReplayBufferError` BEFORE storing (fail-closed backstop against a G4b that ignores back-pressure).
- **`trim_to_ack`** — removes-and-zeroes the FIFO prefix with `seq <= cumulative_ack`. `-1` / below-first / `>=` last are all handled (no-op / no-op / empties). Does NOT clear the breaker. Returns nothing (trim is not input-loss — see Security F4).
- **`evict_expired`** — removes-and-zeroes every frame with `now - enqueued_at > ttl_seconds` (exactly-at-TTL retained); returns evicted seqs FIFO. Does NOT clear the breaker.
- **`unacked_frames`** — returns the retained frames as `ReplayFrame(seq, payload)` in FIFO (ascending-seq) order, for G4b's reconnect re-send. **Read-only** (no removal; frames stay until the new core acks). G4b call contract on reconnect: `trim_to_ack(core_durable_high_water)` FIRST, then `unacked_frames()` returns exactly the un-acked remainder.
- **`discard`** — removes-and-zeroes **everything** and **clears the breaker latch**. Does **NOT** reset the seq/now monotonic floor (Security F1 / Architect CRITICAL). Used by G4b on clean shutdown and retry-window exhaustion.
- **`breaker_tripped`** — monotone latch: `False` at construction, `True` on first soft-cap breach, cleared ONLY by `discard()`.

---

### Task 1: Module skeleton — types, constructor, depth properties, zeroing helper

**Files:**

- Create: `src/alfred/gateway/replay_buffer.py`
- Test: `tests/unit/gateway/test_replay_buffer.py`

- [ ] **Step 1: Write the failing test**

```python
"""Unit tests for the pure ``ReplayBuffer`` (Spec A G4a / ADR-0032, #237)."""

from __future__ import annotations

import pytest

from alfred.gateway.replay_buffer import ReplayBuffer, ReplayBufferError, ReplayFrame


def _buffer(*, max_frames: int = 8, max_bytes: int = 1024, ttl_seconds: float = 30.0) -> ReplayBuffer:
    return ReplayBuffer(max_frames=max_frames, max_bytes=max_bytes, ttl_seconds=ttl_seconds)


def test_fresh_buffer_is_empty_and_not_tripped() -> None:
    buf = _buffer()
    assert buf.depth_frames == 0
    assert buf.depth_bytes == 0
    assert buf.breaker_tripped is False


def test_replay_frame_is_frozen() -> None:
    frame = ReplayFrame(seq=3, payload=b"x")
    with pytest.raises(Exception):  # frozen dataclass -> FrozenInstanceError
        frame.seq = 4  # type: ignore[misc]


@pytest.mark.parametrize(
    ("max_frames", "max_bytes", "ttl_seconds"),
    [(0, 1024, 30.0), (-1, 1024, 30.0), (8, 0, 30.0), (8, -1, 30.0), (8, 1024, 0.0), (8, 1024, -1.0)],
)
def test_non_positive_caps_raise(max_frames: int, max_bytes: int, ttl_seconds: float) -> None:
    with pytest.raises(ReplayBufferError):
        ReplayBuffer(max_frames=max_frames, max_bytes=max_bytes, ttl_seconds=ttl_seconds)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'alfred.gateway.replay_buffer'`.

- [ ] **Step 3: Write minimal implementation**

```python
"""``ReplayBuffer`` — pure un-acked inbound retention for the resume gateway.

Spec A G4a / ADR-0032 (#237). The always-up ``alfred-gateway`` holds the client
connection across a core restart; this buffer is where the operator's un-acked
**inbound** (client->core) frames live between the moment the gateway forwards them
and the moment the (possibly freshly-restarted) core durably acks them. On
reconnect the gateway replays the un-acked remainder so nothing typed is lost
(spec §5); the core dedups by ``(leg, seq)`` so replay never double-executes.

**Seq is gateway-owned and monotonic across a core restart.** The client->core seq
the gateway mints does NOT reset on a core bounce (only the core->client direction
resets — spec §4). A normal reconnect does NOT discard; the gateway keeps minting
the next seq, so the monotonic guard is never tripped on a successful resume. A
genuine seq-space restart is a G4b epoch-handshake concern; :meth:`discard` does
NOT reset the monotonic floor.

**Pure — no I/O, no clock, no logging.** Mirrors the sibling pure machines
:class:`~alfred.gateway.link_state.LinkStateMachine` and
:class:`~alfred.gateway._seq_tracker.BoundedSeqAckTracker`. Time is injected as an
explicit, monotonic ``now`` argument (the spec §7 fake-clock seam). **Loudness is
the G4b wiring's job:** this class never audits/logs; it surfaces signals
(:meth:`evict_expired` return value, :attr:`breaker_tripped`, the hard-ceiling
raise) the reconnect/relay layer polls to write the spec §6 loud audit rows.

**Trust posture (spec §6).** A **T1 carrier** of opaque, *pre-DLP* operator input
(payload-blind — never decodes a frame; T3 tagging stays in the core). Pinning that
input in the always-up process across a crash-loop is an exposure, so the cap
(``max_frames`` + ``max_bytes``) and ``ttl_seconds`` retention bound are **security**
properties, and every byte that leaves on a removal path is overwritten before its
reference is dropped.

**Bounded retention is a two-part contract.** On a soft-cap breach :meth:`append`
KEEPS the frame (the no-silent-drop guarantee) and trips :attr:`breaker_tripped`;
G4b enforces the bound by ceasing to drain the client socket. Post-breach growth is
bounded only by G4b's read-halt latency — the residual window this pure layer does
not close. As a backstop against a buggy G4b, :meth:`append` raises at a hard
ceiling (``_HARD_CAP_MULTIPLIER`` x each soft cap) so the process cannot be driven
to OOM (fail-closed, loud — never silent).

**Zeroing is best-effort.** We overwrite our own mutable ``bytearray`` body in place
on every removal. Python gives no crypto-erase guarantee; ``MADV_DONTDUMP`` /
core-dump suppression are G4b process-level mitigations, out of scope here. The
immutable ``bytes`` a caller passes to :meth:`append`, and those
:meth:`unacked_frames` returns (a flapping reconnect can mint many live copies at
once), are caller/wire-owned and not ours to zero — G4b's process hardening bounds
that exposure.

**No-silent-failure (CLAUDE.md hard rule #7).** TTL eviction returns the evicted
seqs (G4b audits each as input-loss); a non-monotonic/negative ``seq``, a
non-monotonic ``now``, a non-positive cap, and a hard-ceiling breach all raise
:class:`ReplayBufferError`. :meth:`trim_to_ack` is the one removal that is NOT
input-loss (it removes durably-acked frames) and so returns nothing — G4b must only
ever pass an epoch-validated cumulative ack.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from alfred.errors import AlfredError

_DEFAULT_MAX_FRAMES: Final[int] = 4096
_DEFAULT_MAX_BYTES: Final[int] = 8 * 1024 * 1024
_DEFAULT_TTL_SECONDS: Final[float] = 300.0

# The soft cap (``max_frames``/``max_bytes``) is the back-pressure SIGNAL: a breach
# trips the breaker but keeps the frame (no silent drop). The hard ceiling is this
# multiple of the soft cap and is a fail-closed BACKSTOP: reaching it means G4b
# ignored the back-pressure signal (a bug/wedge), so ``append`` refuses loud rather
# than let the always-up security process grow to OOM. 2x leaves generous head-room
# for the in-flight frames between a breach and G4b halting its read loop.
_HARD_CAP_MULTIPLIER: Final[int] = 2


class ReplayBufferError(AlfredError):
    """A programming-error / fail-closed misuse of the buffer.

    Fail-loud (CLAUDE.md hard rule #7): a non-monotonic or negative ``seq``, a
    non-monotonic ``now``, a non-positive cap, or a hard-ceiling breach is never a
    silent no-op.
    """


@dataclass(frozen=True, slots=True)
class ReplayFrame:
    """A replayable un-acked frame: its gateway-owned per-direction seq + opaque payload.

    Replay MUST carry the ORIGINAL ``seq`` — the core dedups on ``(leg, seq)`` (spec
    §4 decision 4), so re-minting would defeat the no-double-effect guarantee.
    """

    seq: int
    payload: bytes


@dataclass(slots=True)
class _Retained:
    """One retained un-acked inbound frame.

    ``body`` is a MUTABLE copy of the opaque payload so it can be zeroed in place on
    removal; ``enqueued_at`` is the caller-supplied monotonic stamp the TTL reads.
    """

    seq: int
    body: bytearray
    enqueued_at: float


def _zero(body: bytearray) -> None:
    """Best-effort in-place overwrite of a retained body before its ref is dropped."""
    body[:] = b"\x00" * len(body)


class ReplayBuffer:
    """Pure FIFO retention of un-acked inbound frames; cap + TTL + breaker + zeroing."""

    def __init__(
        self,
        *,
        max_frames: int = _DEFAULT_MAX_FRAMES,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        ttl_seconds: float = _DEFAULT_TTL_SECONDS,
    ) -> None:
        if max_frames <= 0 or max_bytes <= 0 or ttl_seconds <= 0:
            raise ReplayBufferError(
                "ReplayBuffer caps must be positive: "
                f"max_frames={max_frames} max_bytes={max_bytes} ttl_seconds={ttl_seconds}"
            )
        self._max_frames: Final[int] = max_frames
        self._max_bytes: Final[int] = max_bytes
        self._ttl_seconds: Final[float] = ttl_seconds
        self._hard_max_frames: Final[int] = max_frames * _HARD_CAP_MULTIPLIER
        self._hard_max_bytes: Final[int] = max_bytes * _HARD_CAP_MULTIPLIER
        self._retained: list[_Retained] = []
        self._depth_bytes: int = 0
        self._last_seq: int = -1
        self._last_now: float = float("-inf")
        self._breaker_tripped: bool = False

    @property
    def depth_frames(self) -> int:
        """Number of un-acked frames currently retained."""
        return len(self._retained)

    @property
    def depth_bytes(self) -> int:
        """Sum of retained payload lengths (the byte-cap measure)."""
        return self._depth_bytes

    @property
    def breaker_tripped(self) -> bool:
        """``True`` once a soft cap was breached; cleared only by :meth:`discard`."""
        return self._breaker_tripped


__all__ = ["ReplayBuffer", "ReplayBufferError", "ReplayFrame"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v`
Expected: PASS (empty buffer, frozen-frame, 6 parametrized cap cases).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/replay_buffer.py tests/unit/gateway/test_replay_buffer.py
git commit -m "feat(gateway): pure ReplayBuffer skeleton — types, caps, depth, zeroing helper (Spec A G4a / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 2: `append` — FIFO store, monotonic seq + now guards, soft-cap breaker, hard-ceiling refusal

**Files:**

- Modify: `src/alfred/gateway/replay_buffer.py`
- Test: `tests/unit/gateway/test_replay_buffer.py`

- [ ] **Step 1: Write the failing test**

```python
def test_append_increments_depths() -> None:
    buf = _buffer()
    buf.append(0, b"hello", now=1.0)
    buf.append(1, b"world!", now=2.0)
    assert buf.depth_frames == 2
    assert buf.depth_bytes == len(b"hello") + len(b"world!")


def test_append_requires_strictly_increasing_seq() -> None:
    buf = _buffer()
    buf.append(5, b"a", now=1.0)
    with pytest.raises(ReplayBufferError):
        buf.append(5, b"b", now=2.0)  # equal — not strictly increasing
    with pytest.raises(ReplayBufferError):
        buf.append(4, b"c", now=3.0)  # decreasing


def test_append_rejects_negative_seq() -> None:
    buf = _buffer()
    with pytest.raises(ReplayBufferError):
        buf.append(-1, b"a", now=1.0)


def test_append_requires_non_decreasing_now() -> None:
    buf = _buffer()
    buf.append(0, b"a", now=5.0)
    with pytest.raises(ReplayBufferError):
        buf.append(1, b"b", now=4.0)  # clock went backwards
    buf.append(1, b"b", now=5.0)  # equal now is allowed


def test_append_stores_independent_mutable_copy() -> None:
    buf = _buffer()
    source = bytearray(b"mutable")
    buf.append(0, bytes(source), now=1.0)
    source[:] = b"XXXXXXX"  # mutating the source must not change what we retained
    assert buf.unacked_frames() == (ReplayFrame(seq=0, payload=b"mutable"),)
```

(Note: `test_append_stores_independent_mutable_copy` depends on `unacked_frames` from Task 6. If running strictly task-by-task, mark it `@pytest.mark.skip(reason="unacked_frames lands in Task 6")` now and de-skip it in Task 6.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v -k append`
Expected: FAIL — `AttributeError: 'ReplayBuffer' object has no attribute 'append'`.

- [ ] **Step 3: Write minimal implementation**

Add to `ReplayBuffer` (after `breaker_tripped`):

```python
    def append(self, seq: int, payload: bytes, *, now: float) -> None:
        """FIFO-append a fresh un-acked inbound frame.

        ``seq`` is the gateway's per-direction monotonic counter and must be ``>= 0``
        and strictly greater than the previously appended seq; ``now`` must be ``>=``
        the previously appended ``now`` (a monotonic clock — the TTL prefix invariant
        depends on it). A violation is a programming error, raised loud. The payload
        is copied into a mutable ``bytearray`` we own (so we can zero it on removal)
        and stamped with ``now``.

        Soft cap: appending NEVER drops (spec §5). If it pushes depth past
        ``max_frames``/``max_bytes`` the frame is kept and :attr:`breaker_tripped` is
        set so G4b back-pressures the client read. Hard ceiling: if the append would
        push depth past ``_HARD_CAP_MULTIPLIER`` x either cap it raises
        :class:`ReplayBufferError` BEFORE storing — a fail-closed backstop against a
        G4b that ignored back-pressure, so the always-up process cannot OOM.
        """
        if seq < 0:
            raise ReplayBufferError(f"seq must be non-negative: {seq}")
        if seq <= self._last_seq:
            raise ReplayBufferError(
                f"seq must strictly increase: got {seq} after {self._last_seq}"
            )
        if now < self._last_now:
            raise ReplayBufferError(
                f"now must be monotonic: got {now} after {self._last_now}"
            )
        if (
            len(self._retained) + 1 > self._hard_max_frames
            or self._depth_bytes + len(payload) > self._hard_max_bytes
        ):
            raise ReplayBufferError(
                "ReplayBuffer hard ceiling breached — G4b is not honouring "
                f"back-pressure (frames={len(self._retained)}, bytes={self._depth_bytes})"
            )
        self._retained.append(_Retained(seq=seq, body=bytearray(payload), enqueued_at=now))
        self._depth_bytes += len(payload)
        self._last_seq = seq
        self._last_now = now
        if len(self._retained) > self._max_frames or self._depth_bytes > self._max_bytes:
            self._breaker_tripped = True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v -k append`
Expected: PASS for the non-skipped append tests; `test_append_stores_independent_mutable_copy` SKIPPED.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/replay_buffer.py tests/unit/gateway/test_replay_buffer.py
git commit -m "feat(gateway): ReplayBuffer.append — monotonic seq+now guards, soft-breaker, hard-ceiling (Spec A G4a / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 3: `trim_to_ack` — remove + zero the acked FIFO prefix

**Files:**

- Modify: `src/alfred/gateway/replay_buffer.py`
- Test: `tests/unit/gateway/test_replay_buffer.py`

- [ ] **Step 1: Write the failing test**

```python
def test_trim_removes_acked_prefix() -> None:
    buf = _buffer()
    for seq in range(5):
        buf.append(seq, bytes([seq]) * 4, now=float(seq))
    buf.trim_to_ack(2)  # acks seqs 0,1,2
    assert buf.depth_frames == 2  # 3,4 remain
    assert buf.depth_bytes == 4 + 4


def test_trim_zeroes_removed_bodies() -> None:
    buf = _buffer()
    buf.append(0, b"secret", now=1.0)
    body = buf._retained[0].body  # noqa: SLF001 - white-box assertion of zeroing
    buf.trim_to_ack(0)
    assert bytes(body) == b"\x00" * len(b"secret")


def test_trim_below_first_seq_is_noop() -> None:
    buf = _buffer()
    buf.append(3, b"x", now=1.0)
    buf.trim_to_ack(-1)
    buf.trim_to_ack(2)
    assert buf.depth_frames == 1


def test_trim_at_or_past_last_seq_empties() -> None:
    buf = _buffer()
    buf.append(0, b"a", now=1.0)
    buf.append(1, b"bb", now=2.0)
    buf.trim_to_ack(9)
    assert buf.depth_frames == 0
    assert buf.depth_bytes == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v -k trim`
Expected: FAIL — `AttributeError: ... 'trim_to_ack'`.

- [ ] **Step 3: Write minimal implementation**

Add after `append`:

```python
    def trim_to_ack(self, cumulative_ack: int) -> None:
        """Remove + zero every retained frame with ``seq <= cumulative_ack``.

        ``cumulative_ack`` is the core's epoch-validated durable contiguous-intake
        high-water (spec §4). Because retention is FIFO-ascending in seq, the acked
        frames are a leading prefix. ``-1`` / below-first-seq is a no-op; at/above the
        last seq empties. Does NOT clear :attr:`breaker_tripped`.

        This is the ONE removal that is not input-loss (the frames are durably
        committed), so it returns nothing. Security precondition (G4b's obligation):
        ``cumulative_ack`` must come only from an epoch-validated ack — a spoofed ack
        would zero un-committed input, and the pure buffer cannot tell them apart.
        """
        removed = 0
        for entry in self._retained:
            if entry.seq > cumulative_ack:
                break
            self._depth_bytes -= len(entry.body)
            _zero(entry.body)
            removed += 1
        if removed:
            del self._retained[:removed]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v -k trim`
Expected: PASS (4 cases).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/replay_buffer.py tests/unit/gateway/test_replay_buffer.py
git commit -m "feat(gateway): ReplayBuffer.trim_to_ack — zero+remove durably-acked prefix (Spec A G4a / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 4: cap semantics — soft-cap breaker latch + hard-ceiling refusal

**Files:**

- Modify: `src/alfred/gateway/replay_buffer.py` (no change expected — code lands in Task 2; this task pins the multi-method contract)
- Test: `tests/unit/gateway/test_replay_buffer.py`

- [ ] **Step 1: Write the failing test**

```python
def test_soft_frame_cap_breach_trips_breaker_and_keeps_frame() -> None:
    buf = _buffer(max_frames=2, max_bytes=10_000)
    buf.append(0, b"a", now=1.0)
    buf.append(1, b"b", now=2.0)
    assert buf.breaker_tripped is False
    buf.append(2, b"c", now=3.0)  # 3rd frame, over soft max_frames=2 (hard=4)
    assert buf.breaker_tripped is True
    assert buf.depth_frames == 3  # NEVER dropped


def test_soft_byte_cap_breach_trips_breaker_and_keeps_frame() -> None:
    buf = _buffer(max_frames=100, max_bytes=8)
    buf.append(0, b"aaaa", now=1.0)
    buf.append(1, b"bbbb", now=2.0)  # depth_bytes == 8 == cap, not over
    assert buf.breaker_tripped is False
    buf.append(2, b"c", now=3.0)  # depth_bytes == 9 > 8 (hard=16)
    assert buf.breaker_tripped is True
    assert buf.depth_frames == 3


def test_hard_frame_ceiling_refuses_loud() -> None:
    buf = _buffer(max_frames=2, max_bytes=10_000)  # hard=4 frames
    for seq in range(4):
        buf.append(seq, b"x", now=float(seq))  # fills to the hard ceiling
    assert buf.depth_frames == 4
    with pytest.raises(ReplayBufferError, match="hard ceiling"):
        buf.append(4, b"y", now=5.0)
    assert buf.depth_frames == 4  # the refused frame was NOT stored


def test_hard_byte_ceiling_refuses_loud() -> None:
    buf = _buffer(max_frames=100, max_bytes=4)  # hard=8 bytes
    buf.append(0, b"aaaa", now=1.0)
    buf.append(1, b"bbbb", now=2.0)  # depth_bytes == 8 == hard ceiling
    with pytest.raises(ReplayBufferError, match="hard ceiling"):
        buf.append(2, b"c", now=3.0)  # would be 9 > 8
    assert buf.depth_bytes == 8


def test_breaker_is_a_latch_trim_does_not_clear() -> None:
    buf = _buffer(max_frames=1, max_bytes=10_000)
    buf.append(0, b"a", now=1.0)
    buf.append(1, b"b", now=2.0)  # trips
    assert buf.breaker_tripped is True
    buf.trim_to_ack(1)  # back to empty, under cap
    assert buf.depth_frames == 0
    assert buf.breaker_tripped is True  # still latched
```

- [ ] **Step 2: Run test to verify it fails / passes**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v -k "cap or breaker or ceiling"`
Expected: PASS (Task 2's `append` + Task 3's `trim_to_ack` already satisfy the contract). If a case FAILS, fix the production code — NOT the test. Confirm: soft breach uses strictly-greater-than (`> self._max_bytes`); the hard ceiling refuses BEFORE storing; nothing but `discard` writes `_breaker_tripped = False`.

- [ ] **Step 3: Write minimal implementation**

No new code expected.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v -k "cap or breaker or ceiling"`
Expected: PASS (5 cases).

- [ ] **Step 5: Commit**

```bash
git add tests/unit/gateway/test_replay_buffer.py src/alfred/gateway/replay_buffer.py
git commit -m "test(gateway): pin ReplayBuffer soft-breaker latch + hard-ceiling fail-closed (Spec A G4a / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 5: `evict_expired` — TTL removal + zero, returns evicted seqs (observable loss)

**Files:**

- Modify: `src/alfred/gateway/replay_buffer.py`
- Test: `tests/unit/gateway/test_replay_buffer.py`

- [ ] **Step 1: Write the failing test**

```python
def test_evict_removes_only_expired_frames() -> None:
    buf = _buffer(ttl_seconds=10.0)
    buf.append(0, b"old", now=0.0)
    buf.append(1, b"mid", now=5.0)
    buf.append(2, b"new", now=9.0)
    evicted = buf.evict_expired(now=11.0)  # frame@0 age 11 > 10; @5 age 6; @9 age 2
    assert evicted == (0,)
    assert buf.depth_frames == 2


def test_evict_boundary_age_equal_ttl_is_retained() -> None:
    buf = _buffer(ttl_seconds=10.0)
    buf.append(0, b"x", now=0.0)
    assert buf.evict_expired(now=10.0) == ()  # age exactly 10, not > 10
    assert buf.depth_frames == 1


def test_evict_zeroes_removed_bodies() -> None:
    buf = _buffer(ttl_seconds=1.0)
    buf.append(0, b"secret", now=0.0)
    body = buf._retained[0].body  # noqa: SLF001 - white-box assertion of zeroing
    buf.evict_expired(now=100.0)
    assert bytes(body) == b"\x00" * len(b"secret")


def test_evict_returns_empty_when_nothing_expired() -> None:
    buf = _buffer(ttl_seconds=10.0)
    buf.append(0, b"x", now=0.0)
    assert buf.evict_expired(now=1.0) == ()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v -k evict`
Expected: FAIL — `AttributeError: ... 'evict_expired'`.

- [ ] **Step 3: Write minimal implementation**

Add after `trim_to_ack`:

```python
    def evict_expired(self, *, now: float) -> tuple[int, ...]:
        """Remove + zero frames older than ``ttl_seconds``; return the evicted seqs.

        A frame is expired when ``now - enqueued_at > ttl_seconds`` (exactly-at-TTL
        retained). Because ``append`` enforces a monotonic ``now``, the expired frames
        are a leading FIFO prefix. Evicting un-acked input is deliberate
        security-over-liveness loss (pre-DLP input cannot be pinned across an unbounded
        crash-loop), so it is OBSERVABLE — the returned seqs let G4b write the spec §6
        loud audit row per dropped frame. Does NOT clear :attr:`breaker_tripped`.
        """
        evicted: list[int] = []
        for entry in self._retained:
            if now - entry.enqueued_at <= self._ttl_seconds:
                break
            self._depth_bytes -= len(entry.body)
            _zero(entry.body)
            evicted.append(entry.seq)
        if evicted:
            del self._retained[: len(evicted)]
        return tuple(evicted)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v -k evict`
Expected: PASS (4 cases).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/replay_buffer.py tests/unit/gateway/test_replay_buffer.py
git commit -m "feat(gateway): ReplayBuffer.evict_expired — TTL zero+remove, evicted seqs observable (Spec A G4a / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 6: `unacked_frames` — FIFO `ReplayFrame` copies for re-send, no removal

**Files:**

- Modify: `src/alfred/gateway/replay_buffer.py`
- Test: `tests/unit/gateway/test_replay_buffer.py` (also de-skip `test_append_stores_independent_mutable_copy`)

- [ ] **Step 1: Write the failing test**

De-skip `test_append_stores_independent_mutable_copy` (Task 2), and add:

```python
def test_unacked_frames_returns_fifo_replayframes_carrying_seq() -> None:
    buf = _buffer()
    buf.append(0, b"a", now=1.0)
    buf.append(1, b"bb", now=2.0)
    buf.append(2, b"ccc", now=3.0)
    assert buf.unacked_frames() == (
        ReplayFrame(seq=0, payload=b"a"),
        ReplayFrame(seq=1, payload=b"bb"),
        ReplayFrame(seq=2, payload=b"ccc"),
    )
    assert all(isinstance(f.payload, bytes) for f in buf.unacked_frames())  # immutable for the wire


def test_unacked_frames_does_not_remove() -> None:
    buf = _buffer()
    buf.append(0, b"a", now=1.0)
    buf.unacked_frames()
    buf.unacked_frames()
    assert buf.depth_frames == 1  # still retained until the NEW core acks


def test_unacked_frames_reflects_post_trim_remainder_with_original_seqs() -> None:
    buf = _buffer()
    for seq in range(4):
        buf.append(seq, bytes([65 + seq]), now=float(seq))  # b"A".."D"
    buf.trim_to_ack(1)
    # The remainder carries its ORIGINAL seqs 2,3 (the core dedups on (leg, seq)).
    assert buf.unacked_frames() == (ReplayFrame(seq=2, payload=b"C"), ReplayFrame(seq=3, payload=b"D"))


def test_normal_restart_replay_then_continue_never_trips_monotonic_guard() -> None:
    """Spec §4: inbound seq is gateway-owned + monotonic across a core restart."""
    buf = _buffer()
    for seq in range(4):
        buf.append(seq, bytes([seq]), now=float(seq))
    buf.trim_to_ack(1)  # core durably acked 0,1
    # ...core crashes; gateway keeps buffering inbound (no discard)...
    buf.append(4, b"x", now=4.0)
    buf.append(5, b"y", now=5.0)
    # ...new core handshakes, advertises high-water 1 -> trim no-op -> replay remainder.
    replayed = buf.unacked_frames()
    assert [f.seq for f in replayed] == [2, 3, 4, 5]
    # operator types again; gateway mints the next seq -> accepted, no reset needed.
    buf.append(6, b"z", now=6.0)
    assert [f.seq for f in buf.unacked_frames()] == [2, 3, 4, 5, 6]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v -k "unacked or normal_restart"`
Expected: FAIL — `AttributeError: ... 'unacked_frames'`.

- [ ] **Step 3: Write minimal implementation**

Add after `evict_expired`:

```python
    def unacked_frames(self) -> tuple[ReplayFrame, ...]:
        """Return the retained un-acked frames as :class:`ReplayFrame`, FIFO order.

        The G4b reconnect path calls this after a fresh core handshakes + emits
        ``ready`` to re-send the un-acked inbound (spec §5 step 3). Each frame carries
        its ORIGINAL seq so the core dedups on ``(leg, seq)`` — a replayed,
        already-committed frame short-circuits. Read-only: frames stay retained until
        the NEW core acks them. G4b call contract: ``trim_to_ack(core_durable_high_water)``
        FIRST, then this returns exactly the un-acked remainder. Each returned
        ``payload`` is a fresh immutable copy of a retained body.
        """
        return tuple(ReplayFrame(seq=entry.seq, payload=bytes(entry.body)) for entry in self._retained)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v -k "unacked or normal_restart or append"`
Expected: PASS — including the now-de-skipped `test_append_stores_independent_mutable_copy`.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/replay_buffer.py tests/unit/gateway/test_replay_buffer.py
git commit -m "feat(gateway): ReplayBuffer.unacked_frames — FIFO ReplayFrames carry original seq (Spec A G4a / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 7: `discard` — zero everything + clear breaker; does NOT reset the monotonic floor

**Files:**

- Modify: `src/alfred/gateway/replay_buffer.py`
- Test: `tests/unit/gateway/test_replay_buffer.py`

- [ ] **Step 1: Write the failing test**

```python
def test_discard_empties_and_clears_breaker() -> None:
    buf = _buffer(max_frames=1, max_bytes=10_000)
    buf.append(0, b"a", now=1.0)
    buf.append(1, b"b", now=2.0)  # trips breaker
    assert buf.breaker_tripped is True
    buf.discard()
    assert buf.depth_frames == 0
    assert buf.depth_bytes == 0
    assert buf.breaker_tripped is False


def test_discard_zeroes_all_bodies() -> None:
    buf = _buffer()
    buf.append(0, b"alpha", now=1.0)
    buf.append(1, b"bravo", now=2.0)
    bodies = [entry.body for entry in buf._retained]  # noqa: SLF001 - white-box zeroing assertion
    buf.discard()
    assert all(bytes(b) == b"\x00" * len(b) for b in bodies)


def test_discard_does_not_reset_seq_floor() -> None:
    """Security F1 / Architect CRITICAL: the gateway-owned seq stays monotonic.

    discard is the give-up/shutdown path; it must NOT re-admit a lower seq, so a
    late stale-stream frame after discard cannot be silently accepted. A genuine
    seq-space restart is G4b's epoch-handshake concern, not a discard side-effect.
    """
    buf = _buffer()
    buf.append(7, b"x", now=1.0)
    buf.discard()
    with pytest.raises(ReplayBufferError):
        buf.append(5, b"stale", now=2.0)  # below the retained floor -> loud reject
    buf.append(8, b"ok", now=3.0)  # still-monotonic continuation is accepted
    assert buf.unacked_frames() == (ReplayFrame(seq=8, payload=b"ok"),)


def test_discard_does_not_reset_now_floor() -> None:
    buf = _buffer()
    buf.append(0, b"x", now=10.0)
    buf.discard()
    with pytest.raises(ReplayBufferError):
        buf.append(1, b"y", now=9.0)  # clock can't go backwards across a discard either
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v -k discard`
Expected: FAIL — `AttributeError: ... 'discard'`.

- [ ] **Step 3: Write minimal implementation**

Add after `unacked_frames`:

```python
    def discard(self) -> None:
        """Remove + zero EVERYTHING and clear the breaker latch.

        Called by G4b on clean gateway shutdown and when the reconnect retry-window
        is exhausted (resume gave up — the max-retry-window cap the pure buffer cannot
        observe). Does NOT reset the monotonic seq/now floor: the inbound seq is
        gateway-owned and stays monotonic across a core restart (spec §4), and not
        resetting here means a late stale-stream frame after a discard is rejected loud
        rather than silently admitted (Security F1). A genuine seq-space restart is
        G4b's epoch-handshake concern, sequenced after the old leg is torn down.
        """
        for entry in self._retained:
            _zero(entry.body)
        self._retained.clear()
        self._depth_bytes = 0
        self._breaker_tripped = False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v -k discard`
Expected: PASS (4 cases).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/replay_buffer.py tests/unit/gateway/test_replay_buffer.py
git commit -m "feat(gateway): ReplayBuffer.discard — zero-all + clear breaker, monotonic floor preserved (Spec A G4a / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 8: Hypothesis property tests — the invariants that span operations

**Files:**

- Modify: `tests/unit/gateway/test_replay_buffer.py`

- [ ] **Step 1: Write the failing test**

```python
from hypothesis import given, strategies as st

# (payload, monotonic dt) appends with strictly-increasing seq 0..n-1 and non-decreasing now.
_payloads = st.lists(
    st.tuples(st.binary(min_size=0, max_size=16), st.floats(min_value=0.0, max_value=5.0)),
    min_size=0,
    max_size=40,
)


def _fill(payloads: list[tuple[bytes, float]]) -> tuple[ReplayBuffer, list[bytes]]:
    # Generous caps so the hard ceiling never fires in these structural properties.
    buf = ReplayBuffer(max_frames=10_000, max_bytes=10_000_000, ttl_seconds=10_000.0)
    bodies: list[bytes] = []
    clock = 0.0
    for seq, (payload, dt) in enumerate(payloads):
        clock += dt  # dt >= 0 -> now is non-decreasing
        buf.append(seq, payload, now=clock)
        bodies.append(payload)
    return buf, bodies


@given(_payloads)
def test_depth_bytes_equals_sum_of_retained_lengths(payloads: list[tuple[bytes, float]]) -> None:
    buf, bodies = _fill(payloads)
    assert buf.depth_bytes == sum(len(b) for b in bodies)
    assert buf.depth_frames == len(bodies)


@given(_payloads, st.integers(min_value=-1, max_value=60))
def test_trim_is_a_fifo_prefix_and_never_grows_depth(
    payloads: list[tuple[bytes, float]], ack: int
) -> None:
    buf, bodies = _fill(payloads)
    before = buf.depth_frames
    buf.trim_to_ack(ack)
    assert buf.depth_frames <= before
    expected = [(seq, b) for seq, b in enumerate(bodies) if seq > ack]
    assert [(f.seq, f.payload) for f in buf.unacked_frames()] == expected


@given(_payloads)
def test_replay_order_and_seqs_match_append(payloads: list[tuple[bytes, float]]) -> None:
    buf, bodies = _fill(payloads)
    assert [(f.seq, f.payload) for f in buf.unacked_frames()] == list(enumerate(bodies))


@given(_payloads, st.floats(min_value=0.0, max_value=10_000.0))
def test_evict_is_a_fifo_prefix(payloads: list[tuple[bytes, float]], horizon: float) -> None:
    buf, _ = _fill(payloads)
    depth_before = buf.depth_frames
    evicted = buf.evict_expired(now=horizon)
    assert len(evicted) + buf.depth_frames == depth_before
    assert list(evicted) == sorted(evicted)  # leading ascending run
```

- [ ] **Step 2: Run test to verify it passes (these pin existing behaviour)**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v -k "depth_bytes or trim_is or replay_order or evict_is"`
Expected: PASS. A hypothesis counterexample means a REAL bug — fix `replay_buffer.py`, not the property.

- [ ] **Step 3: Write minimal implementation**

No new production code expected.

- [ ] **Step 4: Run the full module suite**

Run: `uv run pytest tests/unit/gateway/test_replay_buffer.py -v`
Expected: PASS (all example-based + property tests).

- [ ] **Step 5: Commit**

```bash
git add tests/unit/gateway/test_replay_buffer.py
git commit -m "test(gateway): ReplayBuffer hypothesis props — FIFO-prefix trim/evict, seq-carrying replay (Spec A G4a / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 9: Package export + CI per-file coverage gate + full quality gates

**Files:**

- Modify: `src/alfred/gateway/__init__.py`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Export the new public surface**

`src/alfred/gateway/__init__.py` re-exports every sibling kernel in a sorted `__all__` (confirmed). Add `ReplayBuffer`, `ReplayBufferError`, and `ReplayFrame` the same way (import + sorted `__all__` entries). Do NOT export `_Retained` (private).

- [ ] **Step 2: Add the new file to BOTH CI per-file coverage gates**

In `.github/workflows/ci.yml`, for EACH of the two `Gateway kernel trust-boundary 100%` steps (the `python` job ~line 227-231 and the `coverage-gates` job ~line 1262-1266):

1. Append `&& hashFiles('src/alfred/gateway/replay_buffer.py') != ''` to the `if:` guard.
2. Add `src/alfred/gateway/replay_buffer.py` to the comma-separated `--include='...'` list.

Verify:

Run: `grep -c "replay_buffer.py" .github/workflows/ci.yml`
Expected: `4` (two `hashFiles` guards + two `--include` lists).

- [ ] **Step 3: Confirm 100% coverage by the unit tier**

Run: `uv run coverage run -m pytest tests/unit/gateway/test_replay_buffer.py -q && uv run coverage report --include='src/alfred/gateway/replay_buffer.py' --show-missing`
Expected: `replay_buffer.py` at `100%`, no missing lines/branches. If an empty-body `_zero` or a branch is uncovered, add a targeted test (e.g. `append(0, b"", now=1.0)` then `discard()`).

- [ ] **Step 4: Run the full quality gates**

Run: `make check`
Expected: ruff format clean, ruff check clean, mypy --strict clean, pyright clean, unit+integration green. (Do NOT pipe through `tail`.)

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/__init__.py .github/workflows/ci.yml
git commit -m "build(gateway): export ReplayBuffer/ReplayFrame + wire two-gates per-file coverage (Spec A G4a / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 10: ADR-0032 — record the buffer's security-bounded retention

**Files:**

- Modify: `docs/adr/0032-*.md` (the gateway comms-resume transport ADR)

Spec §6 says *"ADR-0032 records it"* for the buffer's cap+TTL+zero-on-removal security property. Record the **decision** in the ADR (the residual-risk *caveat* lives in the module docstring).

- [ ] **Step 1: Find the ADR file**

Run: `ls docs/adr/ | grep 0032`

- [ ] **Step 2: Add a subsection** (under the existing consequences/decisions, matching the ADR's heading style) stating:
  - The `ReplayBuffer` retains **pre-DLP, payload-blind (T1-carrier)** inbound operator input between forward and the core's durable ack.
  - Its retention is **bounded as a security property**: a soft cap (`max_frames` + `max_bytes`) trips a back-pressure breaker (kept-not-dropped); a hard ceiling at `2×` refuses loud (fail-closed) so the always-up process cannot OOM; a TTL bound evicts pre-DLP input that cannot be pinned across a crash-loop (evictions are surfaced, not silent).
  - **Zero-on-removal** (best-effort `bytearray` overwrite on ack-trim / TTL-eviction / discard), with the documented residual-risk caveat (no Python crypto-erase; `MADV_DONTDUMP` / core-dump suppression are the G4b process-level mitigations; replay mints un-zeroable immutable copies G4b must not retain).
  - The **inbound seq is gateway-owned and monotonic across a core restart** (the buffer never resets its floor; a seq-space restart is a G4b epoch-handshake concern).
  - **Loudness is the G4b wiring's obligation** (the pure buffer exposes signals: `evict_expired` seqs, `breaker_tripped`, the hard-ceiling raise).

- [ ] **Step 3: Markdownlint the ADR**

Run: `npx --yes markdownlint-cli2 docs/adr/0032-*.md`
Expected: no errors on the ADR (MD032 around lists/tables — keep blank lines around them).

- [ ] **Step 4: Commit**

```bash
git add docs/adr/0032-*.md
git commit -m "docs(adr): ADR-0032 records ReplayBuffer security-bounded retention (Spec A G4a) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Self-Review

**Spec coverage (spec §4/§5/§6/§7/§9):**

| Spec requirement | Task |
|---|---|
| `ReplayBuffer` — per-direction un-acked retention | Tasks 1-2 |
| trim + zero on ack | Task 3 |
| cap (frames **and** bytes) + hard-ceiling backstop | Tasks 1, 2, 4 |
| TTL retention bound + zero on eviction (observable) | Task 5 |
| breaker / back-pressure signal (latch) + two-part contract documented | Tasks 1, 4 |
| FIFO replay of un-acked remainder **carrying original seq** (dedup `(leg, seq)`) | Task 6 |
| gateway-owned seq monotonic across restart (no floor reset in discard) | Tasks 6, 7 |
| zero on discard + clear breaker | Task 7 |
| pure state machine, no deps, monotonic fake-clock seam | Tasks 1-8 |
| §9 props: replay idempotent / ack-trim / FIFO | Task 8 |
| no-silent-failure: eviction observable, hard-ceiling loud, monotonicity loud | Tasks 2, 5 |
| zeroing as a security property (white-box assertions) | Tasks 3, 5, 7 |
| trust-boundary 100% coverage gate wired | Task 9 |
| ADR-0032 records the buffer security property | Task 10 |

**Review findings applied** (architect + security, 2026-06-15):

- **Architect CRITICAL / Security F1** — `discard` no longer resets the seq floor; the seq model is reframed as gateway-owned-monotonic-across-restart with an explicit normal-restart positive test (Task 6) and a stale-frame-rejection test (Task 7).
- **Architect MAJOR (seq dropped on replay)** — `replay_since` → `unacked_frames` returning `ReplayFrame(seq, payload)` so replay carries the original seq for `(leg, seq)` dedup.
- **Architect MAJOR (partial-replay cursor)** — documented the G4b call contract (`trim_to_ack` first, then `unacked_frames`).
- **Security F2 (back-pressure)** — documented the two-part contract + added the hard-ceiling fail-closed backstop (Tasks 1, 2, 4).
- **Security F3 (replay copies)** — residual-risk caveat names the un-zeroable replay copies + G4b's process-hardening obligation.
- **Security F4 (trim is non-loss)** — documented; the epoch-validated-ack precondition is a stated G4b obligation.
- **Security F5 (now monotonicity)** — `append` enforces non-decreasing `now`, raising loud (Task 2).
- **Architect/Security MINOR** — ADR-0032 update is Task 10; `__init__.py` export confirmed (Task 9).

**G4b follow-up obligations (carry into the G4b plan):** enforce the back-pressure read-halt (the release-blocking half of bounded-retention; adversarial wedged-core-flood corpus entry); add the epoch-gated seq-floor-reset at the handshake; gate `trim_to_ack` on epoch-validated acks; process hardening (`MADV_DONTDUMP` / core-dump suppression); drive `breaker_tripped` → `GatewayLinkEvent.BREAKER_TRIPPED` → `LinkControl.UNAVAILABLE`; audit every eviction/breaker-trip/hard-ceiling-raise; read `depth_frames`/`depth_bytes` after each mutating call for the Prometheus gauges.

**Placeholder scan:** none — every code step is complete.

**Type consistency:** `append(seq: int, payload: bytes, *, now: float) -> None`, `trim_to_ack(cumulative_ack: int) -> None`, `evict_expired(*, now: float) -> tuple[int, ...]`, `unacked_frames() -> tuple[ReplayFrame, ...]`, `discard() -> None`, `ReplayFrame(seq: int, payload: bytes)`, `depth_frames`/`depth_bytes: int`, `breaker_tripped: bool` — consistent across Tasks 1-10.

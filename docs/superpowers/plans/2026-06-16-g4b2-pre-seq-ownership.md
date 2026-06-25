# G4b-2-pre — caller-owned send-seq contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the gateway client→core send-seq from the transport's internal counter to a **caller-owned** seq on `send_payload_unit(payload, *, seq, ack)`, so the upcoming G4b-2a buffer can key each appended frame on the exact wire seq it carries (even across loud-dropped sends). Behaviour-preserving: the wire seqs are identical (per-connection `0,1,2,…`).

**Architecture:** `send_payload_unit` is gateway-only (callers: `relay.py:147` client leg, `core_link.py:744` core leg; only `CommsSocketTransport` implements it). The transport's `_write_payload_unit` gains an optional `seq: int | None` — `None` keeps the internal `_send_seq` auto-increment (the `send()` lifecycle path, unchanged); an explicit `seq` encodes with it and does NOT touch `_send_seq` (the relay path). `GatewayCoreLink` owns `_client_to_core_seq` (reset to 0 per `_peer_handshake`, like the existing receive-tracker reset); `relay_to_core` mints + passes it. `GatewayRelay` owns `_client_send_seq` for its core→client `send_payload_unit` (moot on the plain production TUI leg, required by the signature).

**Tech Stack:** Python 3.12+, `mypy --strict` + `pyright`, `ruff`, `pytest` + `hypothesis`. No new deps. Design: `docs/superpowers/specs/2026-06-16-g4b2-replay-wiring-design.md` §3.

---

## Context the engineer needs

**Where this sits.** Spec A **G4b-2-pre** — the first of three PRs wiring the merged `ReplayBuffer` into the relay (design doc §7). This PR ships ONLY the seq-ownership contract change; **no buffering** (that is G4b-2a). The point: a buffered frame's wire seq must EQUAL its buffer key, even when the *previous* frame's send was loud-dropped on a dying leg — a transport-internal auto-increment would advance independently of buffer appends and desync wire-seq from buffer-key (design §3.1). So the gateway mints the seq, and (in 2a) appends under it, and sends it explicitly — one counter, one source of truth.

**Read before coding:** `src/alfred/plugins/comms_socket_transport.py` (`_write_payload_unit` :345-374, `send` :331-343, `send_payload_unit` :376-389, the `_send_seq`/`_send_lock` init :302-310), `src/alfred/gateway/core_link.py` (the `_CommsTransportLike` Protocol :151-169, `__init__` :185-260, `relay_to_core` :707-752, `_peer_handshake` :576-619 — note the receive-tracker reset at :619), `src/alfred/gateway/relay.py` (`_send_to_client` :122-155, esp. the `send_payload_unit(payload, ack=ack)` at :147), and `tests/unit/gateway/test_relay_wire_contract.py` (the real-encode round-trip style for the wire test).

**Key facts (verified):**

- `send_payload_unit` callers are ONLY `relay.py:147` and `core_link.py:744`. NOT `comms_mcp`/the daemon. So this signature change is gateway-local.
- Post-`enable_seq_ack`, the gateway core leg sends ONLY via `send_payload_unit` (the handshake `send` at `core_link.py:607` is pre-`enable_seq_ack`, seq-OFF). So the relay path never interleaves a lifecycle `send` on the gateway core leg.
- The transport increments `_send_seq` only when `_seq_ack_enabled`. On the seq-OFF (plain TUI client) leg, the seq is ignored and the unit is `payload + b"\n"`.
- `_write_payload_unit` runs under `_send_lock` (the C2 race fix) covering encode→write→drain→seq-increment. Preserve that critical section exactly.

**i18n:** none — no operator-facing strings (developer-facing log/exception text only). No `t()`.

---

## File structure

- **Modify:** `src/alfred/plugins/comms_socket_transport.py` — `_write_payload_unit` gains `seq: int | None = None`; `send_payload_unit` signature → `(payload, *, seq, ack)`.
- **Modify:** `src/alfred/gateway/core_link.py` — `_CommsTransportLike.send_payload_unit` Protocol signature; `__init__` adds `_client_to_core_seq`; `_peer_handshake` resets it; `relay_to_core` mints + passes it.
- **Modify:** `src/alfred/gateway/relay.py` — `__init__` adds `_client_send_seq`; `_send_to_client` mints + passes it.
- **Modify:** `tests/unit/gateway/test_*.py` — update existing call-site tests + add the new unit + wire-contract + property tests.
- **No change** to `comms_mcp/*` (daemon `send` path untouched), the buffer, or `ci.yml` (these files are already in the gateway coverage gate).

---

### Task 1: Transport — `_write_payload_unit` takes optional `seq`; `send_payload_unit` requires it

**Files:**

- Modify: `src/alfred/plugins/comms_socket_transport.py`
- Test: `tests/unit/comms_mcp/` or `tests/unit/gateway/` (wherever the socket transport is unit-tested — find with `grep -rl "CommsSocketTransport" tests/unit`)

- [ ] **Step 1: Write the failing test** (in the socket-transport test module)

```python
import pytest

from alfred.plugins.comms_seq_codec import decode_seq_frame


@pytest.mark.asyncio
async def test_send_payload_unit_encodes_the_caller_supplied_seq() -> None:
    """The relay path encodes the caller's explicit seq, not the internal counter."""
    transport = _make_seq_enabled_transport()  # helper: seq/ack ON, capturing writer
    await transport.send_payload_unit(b"hello", seq=7, ack=2)
    unit = _last_written_unit()  # the bytes handed to the writer
    frame = decode_seq_frame(unit)
    assert frame.seq == 7
    assert frame.ack == 2
    assert frame.payload == b"hello"


@pytest.mark.asyncio
async def test_relay_path_does_not_touch_internal_send_seq() -> None:
    """An explicit-seq send must NOT advance the internal _send_seq (that counter is
    only for the lifecycle send() path)."""
    transport = _make_seq_enabled_transport()
    before = transport._send_seq
    await transport.send_payload_unit(b"a", seq=100, ack=0)
    await transport.send_payload_unit(b"b", seq=101, ack=0)
    assert transport._send_seq == before  # untouched by the relay path


@pytest.mark.asyncio
async def test_send_lifecycle_path_still_uses_and_increments_internal_seq() -> None:
    """send() (a=0 lifecycle frame) keeps minting from the internal counter."""
    transport = _make_seq_enabled_transport()
    start = transport._send_seq
    await transport.send({"jsonrpc": "2.0", "method": "ping"})
    assert transport._send_seq == start + 1
    frame = decode_seq_frame(_last_written_unit())
    assert frame.seq == start and frame.ack == 0
```

(If the existing test module lacks `_make_seq_enabled_transport`/`_last_written_unit` helpers, write minimal ones using a fake `asyncio.StreamWriter` that captures `write()` bytes; the transport ctor takes `(adapter_id, reader, writer, max_line_bytes)` — see `comms_socket_transport.py:286-310`. Call `transport.enable_seq_ack()` to flip seq/ack ON.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest -k "caller_supplied_seq or does_not_touch_internal or lifecycle_path_still" -v`
Expected: FAIL — `send_payload_unit() got an unexpected keyword argument 'seq'`.

- [ ] **Step 3: Write minimal implementation**

In `comms_socket_transport.py`, change `_write_payload_unit` to accept an optional `seq` and `send_payload_unit` to require it:

```python
    async def _write_payload_unit(
        self, payload: bytes, *, ack: int, seq: int | None = None
    ) -> None:
        """Serialised encode -> write -> drain for one wire unit.

        Spec A G3-2 C2: the whole critical section is serialised under ``_send_lock``.
        ``seq`` selects the source of the wire seq (Spec A G4b-2-pre / ADR-0032): when
        ``None`` (the :meth:`send` lifecycle path) the internal ``self._send_seq`` is
        used AND post-incremented; when an explicit ``seq`` is given (the
        :meth:`send_payload_unit` relay path) it is encoded verbatim and ``_send_seq``
        is NOT touched — so the gateway can own the relay seq and key its ReplayBuffer
        on it without the transport's counter drifting on a loud-dropped send.

        With seq/ack OFF the unit is the byte-for-byte ADR-0025 ``payload + "\\n"`` and
        both ``seq`` and ``ack`` are unused.
        """
        async with self._send_lock:
            if self._seq_ack_enabled:
                wire_seq = self._send_seq if seq is None else seq
                unit = encode_seq_frame(
                    payload,
                    seq=wire_seq,
                    ack=ack,
                    max_unit_bytes=self._max_line_bytes,
                )
                if seq is None:
                    self._send_seq += 1
            else:
                unit = payload + b"\n"
            try:
                self._writer.write(unit)
                await self._writer.drain()
            except (BrokenPipeError, ConnectionResetError):
                log.warning("comms.socket.send_broken_pipe", adapter_id=self._adapter_id)
                raise

    async def send_payload_unit(self, payload: bytes, *, seq: int, ack: int) -> None:
        """Write one OPAQUE ADR-0025 payload unit verbatim, carrying a CALLER-OWNED seq.

        Spec A G4b-2-pre (#237 / ADR-0032): the gateway relay mints the client->core
        ``seq`` (so a buffered frame's wire seq equals its ReplayBuffer key even across
        a loud-dropped send) and passes it here. On the seq-OFF (plain TUI) leg both
        ``seq`` and ``ack`` are unused and the unit is a plain ``payload + "\\n"`` line.
        Loud on a broken pipe / over-bound reframe, exactly like :meth:`send`.
        """
        await self._write_payload_unit(payload, seq=seq, ack=ack)
```

Leave `send()` calling `self._write_payload_unit(body, ack=0)` (no `seq` → `None` → internal counter, unchanged).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest -k "caller_supplied_seq or does_not_touch_internal or lifecycle_path_still" -v`
Expected: PASS (3 cases).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/plugins/comms_socket_transport.py tests/<the-transport-test-file>.py
git commit -m "feat(comms): caller-owned seq on send_payload_unit; internal seq for send() (Spec A G4b-2-pre / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 2: Protocol + core leg — `GatewayCoreLink` mints the client→core seq

**Files:**

- Modify: `src/alfred/gateway/core_link.py`
- Test: `tests/unit/gateway/test_core_link.py`

- [ ] **Step 1: Write the failing test**

```python
@pytest.mark.asyncio
async def test_relay_to_core_mints_contiguous_seq_and_passes_it_explicitly() -> None:
    """relay_to_core mints 0,1,2,... and passes each as the explicit send seq."""
    link, fake_transport = _make_up_core_link()  # helper: link with a live fake core transport
    sent: list[tuple[bytes, int, int]] = fake_transport.sent  # records (payload, seq, ack)
    await link.relay_to_core(b"one")
    await link.relay_to_core(b"two")
    assert [(p, s) for (p, s, _a) in sent] == [(b"one", 0), (b"two", 1)]


@pytest.mark.asyncio
async def test_peer_handshake_resets_the_client_to_core_seq() -> None:
    """A fresh handshake (new core leg) resets the send-seq to 0 — per-connection space."""
    link, fake_transport = _make_up_core_link()
    await link.relay_to_core(b"a")
    await link.relay_to_core(b"b")  # seq now at 2
    await link._peer_handshake(_make_handshake_transport())  # fresh leg
    link2_transport = link._current_core_transport
    await link.relay_to_core(b"c")
    assert link2_transport.sent[-1][1] == 0  # reset to 0 on the new leg
```

(Use the existing `test_core_link.py` fakes; the fake transport's `send_payload_unit` must now accept `seq`. Update the fake to record `(payload, seq, ack)`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_core_link.py -v -k "mints_contiguous or resets_the_client_to_core"`
Expected: FAIL — the fake's `send_payload_unit` signature mismatch / `relay_to_core` still passes no seq.

- [ ] **Step 3: Write minimal implementation**

In `core_link.py`:

1. Update the Protocol (`:169`):

```python
    async def send_payload_unit(self, payload: bytes, *, seq: int, ack: int) -> None: ...
```

2. In `__init__` (near the `_core_tracker` init at `:255`), add the per-leg send counter:

```python
        # Spec A G4b-2-pre (#237): the gateway OWNS the client->core send-seq (so a
        # G4b-2a buffered frame's wire seq equals its ReplayBuffer key even across a
        # loud-dropped send). Per-connection: reset to 0 each _peer_handshake, like the
        # receive tracker — a fresh core leg is a fresh seq space (design §3.2).
        self._client_to_core_seq = 0
```

3. In `_peer_handshake`, reset it alongside the receive-tracker reset (after `self._core_tracker = BoundedSeqAckTracker()` at `:619`):

```python
        self._client_to_core_seq = 0
```

4. In `relay_to_core` (`:742-744`), mint + pass the seq (append-before-send lands in G4b-2a; here it is mint-then-send):

```python
        ack = max(self._core_tracker.cumulative_ack(), 0)
        seq = self._client_to_core_seq
        self._client_to_core_seq += 1
        try:
            await local.send_payload_unit(payload, seq=seq, ack=ack)
```

(The `seq` is minted from the counter regardless of whether the send then loud-drops — the counter advances per relay_to_core call, matching the buffer-append-per-call that 2a adds. A `None`-transport early-return at `:736` happens BEFORE the mint, so a no-transport drop does NOT consume a seq — consistent: 2a appends only when a transport exists to send on... NOTE for 2a: append must move to AFTER the None-check, BEFORE send.)

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_core_link.py -v -k "mints_contiguous or resets_the_client_to_core"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/core_link.py tests/unit/gateway/test_core_link.py
git commit -m "feat(gateway): GatewayCoreLink owns the client->core send-seq, reset per handshake (Spec A G4b-2-pre / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 3: Client leg — `GatewayRelay` mints its core→client send-seq

**Files:**

- Modify: `src/alfred/gateway/relay.py`
- Test: `tests/unit/gateway/test_relay.py`

- [ ] **Step 1: Write the failing test**

```python
@pytest.mark.asyncio
async def test_send_to_client_passes_an_explicit_minted_seq() -> None:
    """_send_to_client mints its own core->client seq and passes it explicitly.

    On the production plain-client leg the seq is ignored by the transport, but the
    call must still pass one (the post-G4b-2-pre signature requires it).
    """
    relay, fake_client = _make_relay(client_seq_enabled=True)  # capture sent (payload, seq, ack)
    await relay._send_to_client(b"x")
    await relay._send_to_client(b"y")
    assert [(p, s) for (p, s, _a) in fake_client.sent] == [(b"x", 0), (b"y", 1)]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_relay.py -v -k "send_to_client_passes_an_explicit"`
Expected: FAIL — `_send_to_client` calls `send_payload_unit(payload, ack=ack)` (no seq).

- [ ] **Step 3: Write minimal implementation**

In `relay.py` `__init__` (near `_client_tracker` at `:84`):

```python
        # Spec A G4b-2-pre (#237): the relay OWNS its core->client send-seq (the post-
        # G4b-2-pre send_payload_unit requires a caller seq). On the plain production
        # TUI leg the transport ignores it; a seq-enabled client (G4/G5) carries it.
        self._client_send_seq = 0
```

In `_send_to_client` (`:145-147`):

```python
        ack = max(self._client_tracker.cumulative_ack(), 0) if self._client_seq_enabled else 0
        seq = self._client_send_seq
        self._client_send_seq += 1
        try:
            await self._client_transport.send_payload_unit(payload, seq=seq, ack=ack)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_relay.py -v -k "send_to_client_passes_an_explicit"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/relay.py tests/unit/gateway/test_relay.py
git commit -m "feat(gateway): GatewayRelay owns its core->client send-seq (Spec A G4b-2-pre / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 4: Update existing call-site tests + fakes for the new signature

**Files:**

- Modify: any `tests/unit/gateway/` (and transport) tests whose fakes/asserts use the old `send_payload_unit(payload, *, ack)` signature.

- [ ] **Step 1: Find every fake/assert touching the old signature**

Run: `grep -rn "send_payload_unit" tests/ | grep -v "seq="`
Expected: a list of fakes/calls still on the old `(payload, *, ack)` shape (e.g. `test_relay_wire_contract.py`, `test_process_e2e.py`, fakes in `test_relay.py`/`test_core_link.py`).

- [ ] **Step 2: Update each** to the `(payload, *, seq, ack)` shape: fakes accept `seq` (record it), and any direct callers pass an explicit `seq`. Do NOT weaken any existing assertion — only thread the new `seq` param through.

- [ ] **Step 3: Run the whole gateway + transport suite**

Run: `uv run pytest tests/unit/gateway tests/unit/comms_mcp -q`
Expected: PASS (all green after the signature thread-through).

- [ ] **Step 4: Commit**

```bash
git add tests/
git commit -m "test(gateway): thread caller-owned seq through relay/transport fakes (Spec A G4b-2-pre / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 5: Real-wire round-trip + contiguity property + full gates

**Files:**

- Modify: `tests/unit/gateway/test_relay_wire_contract.py` (or a new sibling) + a property test.

- [ ] **Step 1: Write the real-encode wire round-trip test**

```python
@pytest.mark.asyncio
async def test_relay_explicit_seq_lands_on_the_wire_and_decodes_back() -> None:
    """End-to-end real-encode: relay_to_core's minted seq is the seq on the wire."""
    # Build a real seq-enabled socket transport pair (loopback), like the existing
    # wire-contract test. Drive two relay_to_core calls; read the raw units off the
    # other end; decode_seq_frame each; assert seqs are 0 then 1 and payloads match.
    ...  # mirror test_relay_wire_contract.py's real-loopback setup
```

- [ ] **Step 2: Write the contiguity property test**

```python
from hypothesis import given
from hypothesis import strategies as st


@given(st.lists(st.binary(min_size=0, max_size=8), min_size=0, max_size=30))
@pytest.mark.asyncio
async def test_minted_core_seqs_are_contiguous_within_a_leg(payloads: list[bytes]) -> None:
    """Each relay_to_core mints the next contiguous seq; a fresh handshake resets to 0."""
    link, fake = _make_up_core_link()
    for p in payloads:
        await link.relay_to_core(p)
    assert [s for (_p, s, _a) in fake.sent] == list(range(len(payloads)))
```

(Hypothesis + asyncio: use the project's existing async-property pattern — check how other `tests/unit/gateway` property tests combine `@given` with async, or wrap the body in `asyncio.run` inside a sync `@given` test.)

- [ ] **Step 3: Run the new tests**

Run: `uv run pytest tests/unit/gateway -v -k "lands_on_the_wire or contiguous_within_a_leg"`
Expected: PASS.

- [ ] **Step 4: Coverage + full gates**

Run: `uv run coverage run -m pytest tests/unit/gateway tests/unit/comms_mcp -q && uv run coverage report --include='src/alfred/gateway/core_link.py,src/alfred/gateway/relay.py,src/alfred/plugins/comms_socket_transport.py' --show-missing`
Expected: `core_link.py` + `relay.py` at 100% (their gate); `comms_socket_transport.py` at its existing bar (check it didn't regress — the new branch in `_write_payload_unit` must be covered by Task 1's tests).

Run: `make check`
Expected: green (do NOT pipe through `tail`). Note the known pre-existing flake `tests/unit/memory/test_working_pool.py::TestPerKeyLock::test_per_key_asyncio_lock` (passes in isolation) — re-run that one test if it trips; it is orthogonal.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/gateway/
git commit -m "test(gateway): real-wire explicit-seq round-trip + contiguity property (Spec A G4b-2-pre / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Self-Review

**Spec coverage (design §3):**

| Requirement | Task |
|---|---|
| `send_payload_unit(payload, *, seq, ack)` caller-owned seq | Task 1 |
| `_write_payload_unit` split (None→internal, explicit→caller; `_send_seq` untouched on relay path) | Task 1 |
| `send()` lifecycle path unchanged (internal seq + `a=0`) | Task 1 |
| `_CommsTransportLike` Protocol updated | Task 2 |
| `GatewayCoreLink._client_to_core_seq` minted in `relay_to_core`, reset in `_peer_handshake` | Task 2 |
| `GatewayRelay._client_send_seq` minted in `_send_to_client` | Task 3 |
| existing fakes/call-sites threaded through | Task 4 |
| real-wire round-trip (explicit seq on the wire) + contiguity property | Task 5 |
| behaviour-preserving (wire seqs identical) | whole PR |

**Scope discipline:** NO buffering, NO `append`/`trim`/breaker, NO reconnect-replay — those are G4b-2a/2b. This PR only relocates seq ownership. The `relay_to_core` mint-then-send ordering note (Task 2 Step 3) flags where 2a's append slots in (after the None-check, before send).

**Known follow-up (G4b-2a):** inject the `ReplayBuffer`; `append` after the None-transport check + before send in `relay_to_core`; `trim_to_ack` from `frame.ack` in `_route_unit`; `breaker_tripped` → feed `BREAKER_TRIPPED` (G4b-1) + read-halt in `_client_to_core_pump`; `evict_expired` timer; add `ReplayBuffer.reset_for_new_epoch()`; §6(d) wedged-core-flood adversarial.

**Placeholder scan:** the Task 1/2/3/5 test helpers (`_make_seq_enabled_transport`, `_make_up_core_link`, `_make_relay`, `_last_written_unit`) reference existing test fixtures — the implementer must locate/reuse the real ones in the existing gateway test modules (named in each task), not invent new harnesses. Every production code block is complete.

**Type consistency:** `send_payload_unit(payload: bytes, *, seq: int, ack: int) -> None`, `_write_payload_unit(payload: bytes, *, ack: int, seq: int | None = None)`, `_client_to_core_seq: int`, `_client_send_seq: int` — consistent across tasks.

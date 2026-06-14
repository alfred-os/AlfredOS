# G3-2 — Core Lifecycle Wire-Send Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`. This is PR 2 of the G3 sub-epic (parent plan: `2026-06-14-g3-alfred-gateway-process.md`); G3-1 (PR #263) is MERGED. Design decisions C1/C2/H1/H2 were locked in the parent plan's architect review and confirmed against merged code by a G3-2 code map.

**Goal:** Make the core actually SEND `daemon.lifecycle.ready` / `daemon.lifecycle.going_down` as id-less JSON-RPC notification frames over the **socket-listener carrier** (the foreground-TUI / future-gateway dial-in), alongside the existing G1 audit rows — so the G3-3 gateway can consume them — without breaking the #259 TUI.

**Architecture:** The runner gains an id-less `send_notification` seam; `CommsSocketTransport.send` gains a single-writer lock (a second writer — the boot code's lifecycle-send — now races the pump's `send_request`). A tiny `LifecycleBroadcaster` held on the boot graph collects the socket-carrier runner's sender; `_emit_ready`/`_emit_going_down` broadcast through it after the audit row (wire-send failure logged-not-fatal). The #259 TUI dispatch is fixed to ignore unknown notifications (correct JSON-RPC). Lifecycle frames go ONLY to the socket carrier — daemon-spawned stdio adapters die with the core, so they neither need nor receive them.

**Tech Stack:** Python 3.12+, asyncio, Pydantic v2 wire models, structlog, pytest.

---

## Locked decisions (from the parent plan's architect review + the G3-2 code map)

1. **C1 — canonical method name = `daemon.lifecycle.ready` / `daemon.lifecycle.going_down`.** This matches the merged G1 audit event names (`_commands.py:1273,1302`), the i18n keys (`_slice_4_reserve.py:126-127`), and `_WireModel` inference. Export TWO `Final` constants both the core-send and the G3-3 gateway-consume import. Update the spec prose (which said `core.lifecycle.*`) and the stale `lifecycle_epoch.py:6` docstring to match. Do NOT rename to `core.lifecycle.*` (needless catalog churn).
2. **C2 — mandatory single-writer lock.** Pre-G3-2 the runner is single-writer (only the pump's dispatch tasks call `send_request`). G3-2 adds a SECOND writer (the boot coroutine's lifecycle-send), so two tasks now call `transport.send` concurrently → interleaved byte writes corrupt the seq codec + race `_send_seq`. Add an `asyncio.Lock` INSIDE `CommsSocketTransport.send` (and the stdio sibling `CommsStdioTransport.send`) wrapping the entire `encode → write → drain → seq-increment` critical section. NOT optional.
3. **H1 — drain ordering confirmed.** `_emit_going_down` runs at `_commands.py:1857-1859` (inside `if ready_emitted:`) BEFORE `supervisor.stop()` (L1872) reaps the pump — the transport is still open. Broadcast `going_down` THERE; a wire-send failure is logged-not-fatal (the audit row already committed; the core is draining).
4. **H2 — socket-carrier-only + TUI tolerance fix.** The TUI dispatch (`plugins/alfred_tui/src/alfred_tui/server.py:82-105`) would reply to an unknown notification with a malformed `id:null` error frame. Fix it: a notification (no `id`) with an unknown method is logged + ignored (return `None`, never reply). AND send lifecycle frames ONLY via the socket-listener carrier's runner — NOT the stdio (daemon-spawned) adapters, which die with the core and would each need their own tolerance fix.
5. **Carry-forward from G3-1** (fold in here — same rejection/message cohesion): the **peer-auth-reject daemon audit row**, the **devex-263-001** message enrichment (`expected_uid` + actionable next-step), **devex-263-002** (macOS `hasattr`-miss breadcrumb), the **perf `calcsize` hoist**, and the `lifecycle_epoch.py:6` docstring fix (already covered by C1).

### Refinements folded from the G3-2 plan-review (architect + security)

6. **EPOCH IN THE HANDSHAKE — was dropped, now a first-class task (architect H-2, highest priority).** The boot-time `ready` broadcast reaches **zero senders in the normal case** (architect H-1: `_emit_ready` fires synchronously on the boot coroutine at L1842, while the socket peer connects on-demand later via the separately-scheduled `_accept_and_pump`). So the G3-3 gateway CANNOT derive core-liveness from a received `ready` frame — it must derive it from a **successful handshake that carries the epoch**. Therefore the runner's `lifecycle.start` request params MUST include `epoch` (`current_boot_epoch()`, non-secret) alongside the existing `seq_ack`. Without this, G3-3 has no epoch to reconcile and the late-connect-`ready` deferral breaks. (Task 1.)
7. **Lifecycle frames occupy seq slots on a negotiated wire (architect H-3).** Once `AlfredSeqAck/1` is negotiated, `transport.send` frames EVERY payload with an incrementing `_send_seq` — so a `ready`/`going_down` notification consumes a seq number and rides INSIDE the seq stream (in-band in the seq sequence, out-of-band only in JSON-RPC semantics). This is correct; the G3-3 gateway `decode_seq_frame`s them then routes by `method`. Record this in ADR-0033 (no separate unframed write).
8. **Broadcaster is a BOOT-LOCAL var, not a field on the frozen `_CommsBootGraph` (architect M-1).** `_CommsBootGraph` is an immutable DI bundle; a mutable late-binding registry doesn't belong on it (and risks broadcasting through an already-reaped transport at `aclose` time). Hold the broadcaster as a local in `daemon_start` (alongside `socket_listeners`), passed explicitly to `_emit_ready`/`_emit_going_down` and to `_listen_socket_comms_adapter` for registration.
9. **Broadcaster failure contract (security H-1/H-2):** distinguish **zero senders registered** (debug-level, the expected normal-boot no-op — the headline G3-2 runtime behaviour) from **a registered sender raised** (warning-level). The per-sender catch is NARROW (`BrokenPipeError, ConnectionResetError, CommsProtocolError, OSError`) — NEVER bare `Exception`; `asyncio.CancelledError` MUST propagate (the `going_down` broadcast runs in the shutdown `finally`; swallowing cancellation would wedge the drain). The warning carries `adapter_id` + `error=repr(exc)`. The audit row remains authoritative; the wire frame is best-effort.
10. **Constants live in `comms_mcp/protocol.py`** with the `*Notification` models (architect L-1) — both core-send and the G3-3 gateway-consume import them there (avoids a gateway→runner dependency). `_emit_ready`/`_emit_going_down` reference the SAME constants as the wire `method` so the audit-event-name and wire-method-name cannot drift (architect L-1 / security L-1).
11. **Single-writer lock framing (architect M-3 / security M-2):** the SOCKET lock is REQUIRED (a real second writer — the boot lifecycle-send — exists now); the STDIO lock is DEFENSIVE symmetry (no second writer in G3-2; future-proofs Spec B). Label them accordingly in the commit. The lock intentionally spans `drain()` (a torn frame is worse than a delayed one); `going_down` can be DELAYED behind a wedged peer's drain but not starved (asyncio.Lock is FIFO-fair) — that's why the audit row, not the frame, is authoritative. NO lock-acquisition timeout in G3-2 (a G4 back-pressure concern). The reader (`read_frame`) never takes the lock → no reader/writer deadlock.

### Open item — RESOLVED by plan-review

- **Late-connect `ready` delivery:** deferred to G3-3, but **only valid because the epoch now rides the handshake** (item 6). G3-2 broadcasts `ready`/`going_down` at the emit points (boot-`ready` is a structural no-op today, item 6); the G3-3 gateway derives liveness from handshake-completion + the handshake epoch, and consumes the next `going_down`/`ready` cycle. Record the deferral in ADR-0033.

---

## File structure

- Modify `src/alfred/plugins/comms_runner.py` — `send_notification` + method-name constants.
- Modify `src/alfred/plugins/comms_socket_transport.py` — `asyncio.Lock` in `send`; carry-forward devex/perf nits.
- Modify `src/alfred/plugins/comms_stdio_transport.py` — `asyncio.Lock` in `send` (sibling).
- Modify `src/alfred/cli/daemon/_commands.py` — `LifecycleBroadcaster` on `_CommsBootGraph`; register the socket-carrier runner's sender in `_accept_and_pump`; broadcast in `_emit_ready`/`_emit_going_down`; peer-auth-reject audit row.
- Modify `plugins/alfred_tui/src/alfred_tui/server.py` — ignore unknown notifications.
- Modify `src/alfred/bootstrap/lifecycle_epoch.py` — docstring `core.` → `daemon.`.
- Modify `src/alfred/i18n/_slice_4_reserve.py` + `locale/...` — enrich `comms.socket.peer_uid_rejected` (`{expected_uid}`); new audit-reason key if needed.
- Modify `docs/adr/0033-core-owned-lifecycle-signalling.md` — wire-send amendment.
- Modify `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md` — `core.lifecycle.*` → `daemon.lifecycle.*`.
- Tests: `tests/unit/plugins/test_comms_runner.py` (send_notification + write-lock ordering), `tests/unit/plugins/test_comms_socket_transport.py` (lock serialization + devex breadcrumb), `tests/unit/cli/daemon/test_*` (broadcast at emit points + drain order + peer-auth audit row), `plugins/alfred_tui/tests/` (notification-ignored), `tests/adversarial/comms/` (peer-auth-reject audit row).

---

## Tasks

### Task 1: Method-name constants (in protocol.py) + `send_notification` seam + epoch in handshake (TDD)

**Files:** `src/alfred/comms_mcp/protocol.py` (constants), `src/alfred/plugins/comms_runner.py` (seam + handshake epoch); Test: `tests/unit/plugins/test_comms_runner.py`

- [ ] **Step 1 — failing tests:**
  - `send_notification(DAEMON_LIFECYCLE_READY, {"epoch": "a"*32})` writes ONE frame `{"jsonrpc":"2.0","method":"daemon.lifecycle.ready","params":{"epoch":...}}` with NO `id` and registers NO pending future.
  - the `lifecycle.start` handshake request the runner sends includes `params["epoch"]` (the injected boot epoch) alongside `seq_ack` (architect H-2 — load-bearing for G3-3 reconciliation).

```python
async def test_send_notification_writes_idless_frame():
    from alfred.comms_mcp.protocol import DAEMON_LIFECYCLE_READY
    transport = _FakeTransport()
    runner = _make_runner(transport)
    await runner.send_notification(DAEMON_LIFECYCLE_READY, {"epoch": "a" * 32})
    (frame,) = transport.sent
    assert frame["method"] == "daemon.lifecycle.ready"
    assert "id" not in frame
    assert frame["params"] == {"epoch": "a" * 32}
    assert runner._pending == {}  # no response awaited


async def test_handshake_carries_boot_epoch():
    transport = _FakeHandshakeTransport(boot_epoch="b" * 32)
    runner = _make_runner(transport, boot_epoch="b" * 32)
    await runner.start_and_handshake()
    start = transport.first_sent_with_method("lifecycle.start")
    assert start["params"]["epoch"] == "b" * 32
```

- [ ] **Step 2 — run, expect FAIL.** `uv run pytest tests/unit/plugins/test_comms_runner.py -k "send_notification or handshake_carries" -v`
- [ ] **Step 3 — implement:**
  - In `src/alfred/comms_mcp/protocol.py` (next to `ReadyNotification`/`GoingDownNotification`): `DAEMON_LIFECYCLE_READY: Final[str] = "daemon.lifecycle.ready"` and `DAEMON_LIFECYCLE_GOING_DOWN: Final[str] = "daemon.lifecycle.going_down"`. Export in `__all__`. Then have `_emit_ready`/`_emit_going_down` import + use these SAME constants for their audit `event=` (architect L-1 — no audit↔wire drift).
  - In `comms_runner.py`: add a `send_notification` method (id-less; writes via the now-locked `self._transport.send`); accept a `boot_epoch: str | None` ctor param and add it to the `_handshake` `lifecycle.start` params: `"params": {"adapter_id": ..., "seq_ack": {"version": SEQ_VERSION}, "epoch": self._boot_epoch}` (omit the key when `boot_epoch is None`, e.g. stdio adapters that don't need it — or always send it; it is non-secret and ignored by peers that don't read it). `_build_comms_runner` passes `current_boot_epoch()`.

```python
async def send_notification(self, method: str, params: Mapping[str, object]) -> None:
    """Send an id-less JSON-RPC NOTIFICATION (no response awaited).

    Unlike :meth:`send_request`, a notification carries NO ``id`` and registers
    NO pending future — the core announces lifecycle state (ready/going_down)
    that the peer consumes without acking at the JSON-RPC layer. Writes through
    the single-writer-locked ``transport.send`` so it cannot interleave a
    concurrent ``send_request`` frame (Spec A G3-2 C2).
    """
    await self._transport.send({"jsonrpc": "2.0", "method": method, "params": dict(params)})
```

- [ ] **Step 4 — run, expect PASS.** **Step 5 — commit** (`feat(comms): id-less send_notification + lifecycle constants (protocol.py) + boot epoch in the handshake (Spec A G3-2 / ADR-0033) (#237)` + trailer).

### Task 2: Single-writer lock in both transports (C2) (TDD)

**Files:** `src/alfred/plugins/comms_socket_transport.py`, `comms_stdio_transport.py`; Test: `tests/unit/plugins/test_comms_socket_transport.py`

- [ ] **Step 1 — failing test:** two `asyncio.gather`-ed `send` calls on one transport (with a fake writer whose `drain` yields control) must produce two WHOLE, non-interleaved frames on the wire and a contiguous `_send_seq` (0 then 1), never a torn write.

```python
async def test_concurrent_sends_do_not_interleave(monkeypatch):
    transport = _socket_transport_with_yielding_writer()
    transport.enable_seq_ack()
    await asyncio.gather(
        transport.send({"jsonrpc": "2.0", "method": "a"}),
        transport.send({"jsonrpc": "2.0", "method": "b"}),
    )
    # Each written unit decodes as one complete seq frame; seqs are 0 and 1.
    units = _split_units(transport._writer.buffer)
    seqs = sorted(decode_seq_frame(u).seq for u in units)
    assert seqs == [0, 1]
    assert all(_is_whole_frame(u) for u in units)
```

- [ ] **Step 2 — run, expect FAIL** (interleaved writes / torn frame without the lock).
- [ ] **Step 3 — implement:** add `self._send_lock = asyncio.Lock()` in `__init__`; wrap the `encode → write → drain → _send_seq += 1` body of `send` in `async with self._send_lock:`. Mirror in `CommsStdioTransport.send`. The lock intentionally spans `drain()` (a torn frame is worse than a delayed one); no acquisition timeout (G4 back-pressure concern). The reader (`read_frame`) never takes the lock → no reader/writer deadlock (architect M-3 / security M-2).
- [ ] **Step 4 — run, expect PASS.** **Step 5 — commit** — label the asymmetry in the message: the SOCKET lock is REQUIRED (a real second writer — the boot lifecycle-send — exists in G3-2); the STDIO lock is DEFENSIVE symmetry (no second writer on stdio in G3-2; future-proofs Spec B). (`fix(comms): single-writer lock around transport.send — required on socket, defensive on stdio (Spec A G3-2) (#237)` + trailer).

### Task 3: `LifecycleBroadcaster` (boot-local) + socket-carrier registration + emit-point broadcast (TDD)

**Files:** `src/alfred/cli/daemon/_commands.py`; Test: `tests/unit/cli/daemon/test_lifecycle_wire_send.py`

- [ ] **Step 1 — failing tests (the HEADLINE test is the zero-sender no-op — architect H-1):**
  - `await LifecycleBroadcaster().broadcast_ready(epoch)` with NO registered senders is a clean no-op, logs at DEBUG (`comms.lifecycle.no_peer`), does NOT raise, does NOT warn. **This is the normal-boot runtime behaviour** (the socket peer connects on-demand, so boot-`ready` reaches zero senders).
  - one registered sender → `broadcast_ready(epoch)` calls it once with `(DAEMON_LIFECYCLE_READY, {"epoch": epoch})`.
  - a registered sender raising `BrokenPipeError` → logged at WARNING (`comms.lifecycle.wire_send_failed`, with `error=repr(exc)`), broadcast still returns, other senders still called.
  - `broadcast_going_down` re-raises `asyncio.CancelledError` (does NOT swallow it — it runs in the shutdown finally).
  - `_emit_going_down`'s broadcast happens BEFORE `supervisor.stop()` sets `shutdown_event` (architect M-2 ordering invariant) — assert the `going_down` frame is observable on a connected fake peer before `stop()` completes.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement:**
  - A `LifecycleBroadcaster` class: holds `list[tuple[str, Callable[[str, Mapping[str, object]], Awaitable[None]]]]` (adapter_id + sender). `register(adapter_id, sender)`. `broadcast_ready(epoch)` / `broadcast_going_down(reason)`: if NO senders → `log.debug("comms.lifecycle.no_peer", phase=...)` and return. Else iterate; each call wrapped in `try/except (BrokenPipeError, ConnectionResetError, CommsProtocolError, OSError) as exc: log.warning("comms.lifecycle.wire_send_failed", adapter_id=..., phase=..., error=repr(exc))`. NEVER catch bare `Exception`; let `asyncio.CancelledError` propagate. The audit row (already committed at the callsite) is authoritative; the frame is best-effort (spec §6).
  - Hold the broadcaster as a **boot-local variable in `daemon_start`** (alongside `socket_listeners`), NOT a field on `_CommsBootGraph` (architect M-1 — the graph is an immutable DI bundle). Pass it explicitly to `_emit_ready`/`_emit_going_down` and to `_listen_socket_comms_adapter`.
  - In `_listen_socket_comms_adapter._accept_and_pump`, AFTER the runner is built (L960) and handshake done, `broadcaster.register(adapter_id, runner.send_notification)`. (Socket carrier ONLY — never the `_spawn_comms_adapter` stdio runners.)
  - `_emit_ready` (L1842): broadcast `ready` AFTER the audit row. `_emit_going_down` (L1857-1859): broadcast `going_down` AFTER the audit row, BEFORE `supervisor.stop()`. Add a comment at the `supervisor.stop()` callsite pinning the ordering invariant (architect M-2).
- [ ] **Step 4 — run, expect PASS.** **Step 5 — commit** (`feat(comms): broadcast daemon.lifecycle ready/going_down over the socket carrier (Spec A G3-2 / ADR-0033) (#237)` + trailer).

### Task 4: TUI ignores unknown notifications — on the REAL receive path (H2 / architect C-1/C-2) (TDD)

**Files:** `plugins/alfred_tui/src/alfred_tui/server.py` (`dispatch`) + `plugins/alfred_tui/src/alfred_tui/cohost.py` (`_serve_wire` — THE PRODUCTION RECEIVE LOOP); Test: `plugins/alfred_tui/tests/test_cohost.py` + `test_server.py`

> **Architect C-1:** production daemon→TUI frames arrive via `cohost._serve_wire` (L120-144), NOT `TuiServer.dispatch` directly. `_serve_wire` does `await transport.send(await server.dispatch(dict(frame)))` — sends UNCONDITIONALLY (L144), explicitly assuming "no notification path." So BOTH surfaces need the fix: `dispatch` must return `None` for an unknown notification, AND `_serve_wire` must skip the write when the return is `None` (architect C-2 — else `transport.send(None)` writes a malformed `null\n` frame).

- [ ] **Step 1 — failing tests:**
  - drive a notification frame `{"jsonrpc":"2.0","method":"daemon.lifecycle.ready","params":{"epoch":"a"*32}}` (NO `id`) through the REAL `_serve_wire` loop (fake transport) → assert NO bytes written back (no reply) and NO raise.
  - a KNOWN notification method (if any) is NOT swallowed by the new branch (security M-4 — guards branch placement); a REQUEST (has `id`) with an unknown method STILL returns method-not-found.
- [ ] **Step 2 — run, expect FAIL** (today `_serve_wire` writes the `dispatch` error back unconditionally).
- [ ] **Step 3 — implement:**
  - `TuiServer.dispatch`: BEFORE the method-not-found error, if `"id" not in request` (a notification) AND the method is unknown → `log.debug("comms.tui.notification_ignored", method=method)` and `return None`. A request (has `id`) with an unknown method still returns method-not-found; a KNOWN method still dispatches.
  - `cohost._serve_wire` (L144): `response = await server.dispatch(dict(frame)); if response is not None: await transport.send(response)`. Update the L131-134 comment (which claims "no notification path to guard against").
- [ ] **Step 4 — run, expect PASS.** **Step 5 — commit** (`fix(tui): ignore unknown id-less notifications on the cohost receive loop (Spec A G3-2) (#237)` + trailer).

### Task 5: Peer-auth-reject audit row + devex/perf carry-forward (TDD)

**Files:** `src/alfred/plugins/comms_socket_transport.py`, `src/alfred/cli/daemon/_commands.py`, i18n, `tests/adversarial/comms/`, `tests/unit/test_catalog_slice_4_keys.py`

- [ ] **devex-263-001:** enrich `comms.socket.peer_uid_rejected` (i18n + the structlog warning) with `expected_uid` (`os.getuid()`) + actionable next-step; update the render test to assert BOTH uids interpolate.
- [ ] **devex-263-002:** `log.debug` breadcrumb on the `hasattr(socket,"SO_PEERCRED")`-miss branch of `_resolve_peer_uid`.
- [ ] **perf:** hoist `struct.calcsize(_UCRED_STRUCT)` to a module `Final` constant.
- [ ] **audit row (G3-1 deferral, arch-263-001) — a CALLBACK, not a counter (security M-3 / architect L-3):** add an `on_peer_rejected: Callable[[int | None], Awaitable[None]] | None = None` param to `CommsSocketListener.__init__`, invoked synchronously in `_on_connect` at the reject point (BEFORE `writer.close()`), passing the rejected `peer_uid`. The daemon supplies a callback that writes the `comms.socket.peer_uid_rejected` AUDIT row via the audit writer it already holds (with `peer_uid` + `expected_uid`). A counter is INSUFFICIENT (loses peer_uid + can miss a reject immediately followed by a legitimate accept). **Do NOT wire this into `_refuse_boot`** (security M-3): a rejected impostor is an EXPECTED adversarial event, not a daemon fault — refusing the boot would be a self-inflicted DoS (an attacker racing the socket could kill every boot). On a rejection: loud audit row + metric, boot continues. If the audit WRITE itself fails, that IS hard-rule-#7 territory → loud (the existing `_emit_or_quarantine` discipline). Adversarial test asserts the row + that boot is not refused.
- [ ] **Commit** (`feat(comms): audit + enrich the peer-auth reject diagnostic via a reject callback (Spec A G3-2, closes G3-1 deferral) (#237)` + trailer).

### Task 6: Docs — ADR-0033 wire-send amendment + spec method-name fix + lifecycle_epoch docstring

**Files:** `docs/adr/0033-core-owned-lifecycle-signalling.md`, `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md`, `src/alfred/bootstrap/lifecycle_epoch.py`

- [ ] ADR-0033: amend to record G3-2 SENDS the frames (G1 = audit-only) on the socket carrier; the canonical `daemon.lifecycle.*` method names; the single-writer-lock rationale; socket-carrier-only scoping; **the boot-`ready` reaches zero senders normally + the epoch rides the handshake (so G3-3 derives liveness without a `ready` frame), with late-connect-`ready` deferred to G3-3** (architect H-1/H-2); **lifecycle frames occupy seq slots on a negotiated wire** — the gateway `decode_seq_frame`s then routes by `method` (architect H-3); **the epoch's wire-exposure was reviewed and is non-disclosing** because it is non-secret + the peer is same-uid T1 — a future multi-user/non-local-client change (spec §10) re-opens this (security M-1). MD032-clean.
- [ ] Spec: replace `core.lifecycle.*` with `daemon.lifecycle.*` everywhere; note the reconciliation.
- [ ] `lifecycle_epoch.py:6` docstring: `core.lifecycle.ready` → `daemon.lifecycle.ready`.
- [ ] **Commit** (`docs(adr): ADR-0033 lifecycle wire-send amendment + canonical daemon.lifecycle.* names (Spec A G3-2) (#237)` + trailer).

### Task 7: Full gate + open PR

- [ ] `make check` (NOT piped through `tail` — it masks the exit code) green; the ARM64 `/lib64` bwrap docker test fails local-only (x86-64 CI passes) — ignore that one.
- [ ] `npx markdownlint-cli2@0.14.0` on the ADR + spec + this plan.
- [ ] Open the PR; run the FULL `/review-pr` fleet (all 9 always-include + comms-engineer + core-engineer since `src/alfred/cli/daemon/` is touched) + CodeRabbit. Merge with `gh pr merge <n> --rebase --delete-branch`. If CR sticks CHANGES_REQUESTED on a stale sha after a force-push, land the next fix as a NORMAL new commit (not autosquash) to trigger CR's APPROVED (G3-1 learning).

## Self-review

- **Spec coverage:** sends ready+going_down (§4); audit stays authoritative (§6); socket-carrier scoping (G2-lesson: daemon-spawned plugins die with the core). ✓
- **Decisions folded:** C1 (constants + docstring + spec), C2 (lock), H1 (drain order), H2 (TUI ignore + socket-only), G3-1 carry-forward (Task 5). ✓
- **Risks for plan-review:** runner-reachability seam (broadcaster register in the accept closure); late-connect `ready` (recommend defer to G3-3); the write-lock must not deadlock with the pump's read path (lock is send-only; the reader never takes it). ✓

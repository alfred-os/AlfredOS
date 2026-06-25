# G6-7-4 — Core-side receive + dispatch of the forwarded `gateway.adapter.inbound` leg unit

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the inbound bridge (epic #309, ADR-0039 option 1) on the CORE side: the daemon's HOST runner over the gateway leg receives a forwarded `gateway.adapter.inbound` notification, re-parses it, enforces K4 receive-side admission, selects the per-`adapter_id` collaborator set, dispatches it through `process_inbound_message`, and moves the G0 commit + seq-ack `observe` to the **dispatched edge** for the forwarded path (the direct TUI/daemon path stays receipt-time, byte-for-byte unchanged).

**Architecture:** A new fully-covered trust module `GatewayForwardedInboundReceiver` (in `src/alfred/comms_mcp/`) owns the receive trust boundary: parse the `GatewayAdapterInboundEnvelope` from the notification `params`, K4-admit the closed-vocab `adapter_id` against a registry of hostable kinds, `reparse_forwarded_inbound` (catching the two typed errors), rebind the **real** leg-carrier `wire_seq`, select the per-kind collaborator set, and dispatch in **dispatched-edge commit mode**. `SessionDispatchDisposition` gains one thin interception arm for the new method (mirroring the existing `gateway.adapter.spawn_request` interception) that delegates to the injected receiver — so the frame never reaches the session's `gateway.adapter.*` prefix → `AdapterStatusObserver` `unknown_method` refusal. `process_inbound_message` gains a `commit_at_dispatch_edge: bool = False` mode; the `InboundIdempotencyStore` gains a non-mutating `has_committed` read. **The gateway send side (`forward_adapter_inbound`, merged in G6-7-3) is corrected to wrap the forward in a real JSON-RPC notification frame** so the daemon pump routes it as a notification (not a response) — this is Task 0 and is what makes the whole receive arm reachable (and conforms G6-7-3 to ADR-0039 item 3).

**Tech Stack:** Python 3.14, asyncio, Pydantic v2, structlog, SQLAlchemy 2.0 async (Postgres), pytest + hypothesis, mypy --strict + pyright, ruff.

**Scope fence (what G6-7-4 lands):** the gateway forward shape correction (Task 0) + receive route + K4 receive-side admission + envelope==body equality disposition + per-`adapter_id` collaborator registry (fail-closed at boot) + dispatched-edge G0 commit/`observe` + ack-to-drain for every terminal-drop disposition (malformed / unknown-adapter / mismatch) + audit-write-failure loud escalation.

**Deferred to G6-7-5 (poison ceiling):** the dispatch-failure replay BOUND — per-`(adapter_id, inbound_id)` attempt counter, cost-budget charge, terminal `poisoned` dead-letter. G6-7-4 lands a `dispatch_failed` audit row + leaves the frame un-`observe`d (it replays); the *bound* on that replay is -5.

> **CROSS-SLICE SAFETY SEQUENCING (ADR-0039 items 4 / 4b / L4).** Because G6-7-4 ships the dispatched-edge path **without** the poison ceiling, a deterministically-failing (poison) forwarded frame on a live leg replays unboundedly and re-charges `quarantined_extract` every reconnect. **The gateway-hosted Discord leg therefore stays TEST-ONLY until G6-7-5 lands the ceiling — G6-7-4 must NOT be flag-day'd / put on the live Discord leg.** The flag-day is G6-7-8 and is gated on -7 anyway; this note records the additional -5 dependency. (An interim in-memory per-`inbound_id` attempt cap inside -4 was considered and DEFERRED to keep -5's scope intact, given the leg is test-only until then. Architect to confirm at plan-review.)

---

## Key design decisions (RATIFIED in plan-review — architect `a7c507b4a18aa6c96` + security `a1778094629a31bb2`)

These were reviewed; the verdicts are folded below. The semantic invariants are fixed by ADR-0039; the *mechanisms* were the engineer's call the ADR defers.

1. **Gateway forward shape (Task 0 — was the #1 open question; review found the plan's original assumption FALSE).**
   - **As merged in G6-7-3 (DEFECT):** `forward_adapter_inbound` (`core_link.py:1235-1236`) sends `GatewayAdapterInboundEnvelope.model_dump_json().encode()` — a bare `{"adapter_id","body"}` object with **no JSON-RPC `method`/`params`**. The daemon pump (`comms_runner.py:608-622`) sees `frame.get("method") is None` and routes it to `_resolve_pending` (the response-frame path) → **silently dropped**, never reaching the disposition. This also never conformed to ADR-0039 item 3 ("discriminate by METHOD NAME, never by an `adapter_id` heuristic").
   - **Fix (Task 0):** wrap the forward in a real JSON-RPC notification: `payload = json.dumps({"jsonrpc": "2.0", "method": GATEWAY_ADAPTER_INBOUND, "params": GatewayAdapterInboundEnvelope(adapter_id=adapter_id, body=body).model_dump(mode="json")}).encode()`. Then `frame.get("method") == "gateway.adapter.inbound"`, `frame.get("params") == {"adapter_id","body"}`, the notification path runs, `_wire_seq_of` lifts the real leg seq, and the disposition fires. Byte-stability (SEC-309-2): the opaque `body` str is unchanged inside `params.body`, so the embedded `inbound_id` is still byte-stable across replay → G0 dedup is never a no-op.

2. **Commit/observe deferral mechanism (ADR-0039 item 4 — THE keystone). RATIFIED.**
   - **Invariant (fixed):** forwarded path = exactly-once-once-committed; at-least-once on the dispatched edge. The G0 commit on `(adapter_id, inbound_id)` is durable **only after dispatch succeeds**; a dispatch failure leaves the seq un-`observe`d → the leg replays it → re-dispatch. No committed-but-undispatched row may ever exist.
   - **Mechanism:** `commit_at_dispatch_edge: bool = False` on `process_inbound_message` + a non-mutating `InboundIdempotencyStore.has_committed(*, inbound_id, adapter_id) -> bool`.
     - `False` (direct path) → **UNCHANGED**: `commit_once` upfront; `True` → `observe`, proceed; `False` → `replay_observed`, return (no `observe`).
     - `True` (forwarded path) → upfront `has_committed`: if `True` → `replay_observed` + `observe(wire_seq)` (drain the contiguous-ack tail) + return; if `False` → pipeline → `dispatch` → **on success**: `commit_once` + `observe(wire_seq)`; **on raise**: emit `dispatch_failed` audit row, re-raise (no commit, no `observe` → replays).
   - **Why read + late commit (not compensating-delete):** a compensating delete has a crash window leaving a committed-but-undispatched row = silent loss — forbidden. A read-then-late-commit has no such row. **Concurrency: the gateway forward path routes SYNCHRONOUSLY (`comms_runner.py:632-645`, the `_back_pressure_gate is not None` branch `await`s the dispatch), so at most ONE forwarded frame is in flight per leg.** The only residual double-dispatch is the crash-after-dispatch-before-commit window (bounded in -5), NOT concurrent same-id.

3. **Receive-arm location:** a new interception arm in `SessionDispatchDisposition.dispatch` for `method == GATEWAY_ADAPTER_INBOUND`, parallel to the existing `GATEWAY_ADAPTER_SPAWN_REQUEST` arm, delegating to an injected receiver. Fires **before** `self._session._on_post_handshake_method`, so the `gateway.adapter.*` prefix → `AdapterStatusObserver` `unknown_method` refusal is never reached. The disposition passes `params` straight through (payload-blind); the receiver parses the envelope.

4. **Per-`adapter_id` collaborator registry, fail-closed at boot:** build `{kind: _ForwardedCollaborators}` at boot for each hostable forwarded kind (initially `"discord"`), keyed + selected by the **validated** envelope `adapter_id`. The registry build **REFUSES BOOT** (mirror the existing `CommsPromoterMisconfiguredFailure`) if a kind with a non-empty `REQUIRED_CLASSIFIERS_BY_KIND` got a `None` promoter — never defer that to a per-message `PromoterRequiredError`. Each entry carries a **long-lived** `pre_resolution_limiter` (sec-003 coarse DoS gate; a `None` silently disables it). The registry shares the **per-connection** `BoundedSeqAckTracker` (bound at accept time via `set_ack_tracker`, the same instance the ack-emit timer reads).

5. **K4 receive-side admission + drain semantics (REVERSED from the first draft per review H4).** The validated envelope `adapter_id` must be a registered hostable kind. **Every terminal-drop disposition — unknown-adapter, envelope/body mismatch, malformed body — writes its loud signed audit row FIRST, and then ACKS-TO-DRAIN the real leg `wire_seq`** (`observe(wire_seq)`) so the contiguous high-water is not permanently stalled (an un-observed drop on a live seq leg wedges the leg → infinite replay → hard-rule-#7 violation). If the signed audit write FAILS, do **not** drain — escalate loud (Decision 6) so the frame replays rather than draining an unrecorded drop.

6. **Audit-write-failure escalation (review H1/H2 — HARD).** Every new audit-write site (`dispatch_failed`, `body_malformed`, `unknown_adapter`, `envelope_body_mismatch`, forwarded `replay_observed`) must treat an audit-write failure as a **distinct, non-skippable, loud-escalating** event (restart-request / quarantine), mirroring the existing `AdapterStatusAuditWriteError` arm at `inbound_disposition.py:170-200`. It must **never** fall into the disposition's blanket `except Exception` catch-and-continue (which downgrades it to a structlog warning = a lost security signal).

---

## File structure

**Create:**

- `src/alfred/comms_mcp/forwarded_inbound_receiver.py` — `GatewayForwardedInboundReceiver` (+ `_ForwardedCollaborators`). The receive trust boundary. **100%-coverage gated.**
- `tests/unit/comms/test_forwarded_inbound_receiver.py`
- `tests/unit/comms/test_inbound_dispatched_edge.py`
- `tests/unit/memory/test_inbound_idempotency_has_committed.py`
- `tests/adversarial/comms/test_forwarded_inbound_admission.py` (non-root)

**Modify:**

- `src/alfred/gateway/core_link.py` — `forward_adapter_inbound` JSON-RPC notification wrap (Task 0).
- `src/alfred/comms_mcp/inbound.py` — `commit_at_dispatch_edge` param + dispatched-edge branch + `_emit_dispatch_failed`; direct path byte-for-byte unchanged.
- `src/alfred/memory/inbound_idempotency.py` — `has_committed`.
- `src/alfred/plugins/inbound_disposition.py` — inject `forwarded_inbound_receiver`; add the `GATEWAY_ADAPTER_INBOUND` arm; add the audit-unwritable escalation arm for the receiver path.
- `src/alfred/cli/daemon/_commands.py` — build the fail-closed per-kind registry + receiver; inject into the gateway-leg runner; bind the per-connection ack tracker onto the receiver.
- `src/alfred/audit/audit_row_schemas.py` — the 4 new audit field-sets (co-located with the tasks that use them).
- i18n catalog (`locale/.../alfred.po` + `.mo`) + the `SLICE_4_KEYS` / catalog drift test.
- `.github/workflows/ci.yml` — add `forwarded_inbound_receiver.py` to BOTH per-file 100%-coverage gate sites (mirror the standalone `inbound_reparse.py` block).
- The gateway forward tests + the SEC-309-2 byte-stability test (re-pin to the new frame shape).

---

## Grounding facts (verified against `main` @ 132160d3 — DO NOT re-derive)

- **Task 0 evidence:** `forward_adapter_inbound` `core_link.py:1235-1236` (`envelope.model_dump_json().encode()`, no method). Daemon pump `comms_runner.py:608-622` (`method = frame.get("method"); if method is None: self._resolve_pending(frame); continue`). `_wire_seq_of` lift at `comms_runner.py:631` (AFTER the method-None branch — so a method-less frame never gets its seq lifted). `read_frame` json-decodes the payload-unit `comms_socket_transport.py:441-474`. `GATEWAY_ADAPTER_INBOUND = "gateway.adapter.inbound"` `protocol.py:440`.
- `process_inbound_message` sig `inbound.py:403-415`; commit/observe block `inbound.py:479-507`; `audit_hash.set_broker` at 514 (OUTSIDE the gate — keep); PromoterRequiredError guard 452-465; dispatch `await orchestrator.dispatch(ingested)` ~609; `_emit_idempotency_replay_observed` 371-400.
- `InboundIdempotencyStore` Protocol `inbound_idempotency.py:44-59`; `commit_once` impl 78-88; SQL 35-40 (`ON CONFLICT (adapter_id, inbound_id) DO NOTHING RETURNING inbound_id`); fail-loud contract docstring 14-19.
- `BoundedSeqAckTracker` `_seq_tracker.py:43-97` — `observe(seq)` raises on negative; advances **contiguous** high-water (82-93 — an un-observed seq is a permanent hole); `cumulative_ack() -> int`.
- `reparse_forwarded_inbound` `inbound_reparse.py:78-152`; `_structural_summary` leak-safety (redacts `extra_forbidden@<key>`) 46-75. Raises `InboundBodyMalformedError` / `InboundEnvelopeBodyMismatchError`; scrubs body `wire_seq`→None.
- `GatewayAdapterInboundEnvelope` `protocol.py:540-567` (`adapter_id: AdapterId`, `body: bytes | str`). `InboundMessageNotification` 322-353 (`wire_seq: int | None = Field(default=None, ge=0)`).
- Error hierarchy `errors.py:62-108`. `REQUIRED_CLASSIFIERS_BY_KIND` `classifier_registry.py:38-44` (`"discord": {"discord_sub_payloads"}`).
- `_build_sub_payload_promoter(*, adapter_kind, content_store)` `_commands.py:308-341` (None for empty-classifier kinds).
- Daemon graph exposes the identity resolver as **`graph.resolver_bridge`** (`_commands.py:930`), orchestrator `graph.inbound_orchestrator`, `graph.burst_limiter`, `graph.secret_broker`, `graph.content_store`, `graph.idempotency_store`.
- Gateway-leg socket accept block (per-connection ack tracker born here): `_commands.py:1217-1320`. `ack_tracker = BoundedSeqAckTracker()` (1300); `wiring.inbound_handler.set_ack_tracker(ack_tracker)` (1301); ack-emit timer 1302-1308. Line 1274 comment: "The SOCKET carrier IS the gateway leg." `_build_comms_runner(..., with_credential_resolver=True)` 1267-1276.
- `SessionDispatchDisposition.dispatch` `inbound_disposition.py:137-209`; `GATEWAY_ADAPTER_SPAWN_REQUEST` interception 165-167; session delegation 169; the `AdapterStatusAuditWriteError` loud-escalation arm 170-200; blanket catch-and-continue ~201-209.
- The forward path routes synchronously: `comms_runner.py:632-645` (gate branch `await self._route_notification(...)`); daemon path fire-and-forget `_spawn_notification_dispatch` ~650.
- ci.yml: `inbound_reparse.py` standalone single-file gate — python-job **196-199**, coverage-gates **1297-1300**. Big comms_mcp block 1332-1335. Gateway block lists `inbound_forward_runner.py` (python-job ~306-310, coverage-gates ~1369-1373) — `core_link.py` is already there (Task 0 stays in-gate).
- Audit field-set module: **`src/alfred/audit/audit_row_schemas.py`** (imported `inbound.py:51`).

---

## Task 0 — Gateway forward emits a JSON-RPC `gateway.adapter.inbound` notification frame

**Files:**

- Modify: `src/alfred/gateway/core_link.py` (`forward_adapter_inbound` ~1235-1236)
- Modify: the G6-7-3 forward tests + the SEC-309-2 byte-stability test (find them under `tests/unit/gateway/` / `tests/adversarial/gateway/` — grep `forward_adapter_inbound` and `GatewayAdapterInboundEnvelope`).

**Why:** without this the daemon pump silently drops every forwarded frame as a response (Decision 1). This makes the receive arm reachable and conforms G6-7-3 to ADR-0039 item 3.

- [ ] **Step 1: Write/repin the failing test** — assert the leg payload `forward_adapter_inbound` routes is a JSON-RPC notification:

```python
# The leg payload is now json.loads-able into a notification frame:
#   decoded = json.loads(payload)
#   assert decoded["jsonrpc"] == "2.0"
#   assert decoded["method"] == "gateway.adapter.inbound"
#   assert "id" not in decoded                      # a notification (fire-and-forget)
#   assert decoded["params"] == {"adapter_id": "discord", "body": <the forwarded body str>}
# SEC-309-2 byte-stability: decoded["params"]["body"] is byte-identical to the input body
#   across two forwards of the same body (the embedded inbound_id stays stable).
```

> Repin (do NOT delete) the existing assertion that the payload was the bare `model_dump_json()` of the envelope — it becomes the inner `params` now.

- [ ] **Step 2: Run, verify fail** — `uv run pytest tests/unit/gateway -k forward_adapter_inbound -v` → FAIL.

- [ ] **Step 3: Implement** in `core_link.py`:

```python
        envelope = GatewayAdapterInboundEnvelope(adapter_id=adapter_id, body=body)
        # ADR-0039 item 3 (Spec B G6-7-4, #309): the core discriminates a forwarded inbound
        # from a directly-connected adapter's ``inbound.message`` by METHOD NAME — so the
        # forward rides as a JSON-RPC NOTIFICATION (no ``id``: fire-and-forget; ``inbound.message``
        # itself is fire-and-forget), NOT a bare envelope object the daemon pump would mistake for
        # a response frame and drop. The opaque body stays verbatim inside ``params.body``
        # (payload-blind, byte-stable for G0 — SEC-309-2).
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": GATEWAY_ADAPTER_INBOUND,
                "params": envelope.model_dump(mode="json"),
            }
        ).encode()
        outcome = self._leg_router.route(adapter_id, payload)
```

- Add `import json` + `from alfred.comms_mcp.protocol import GATEWAY_ADAPTER_INBOUND` if not already imported (`GatewayAdapterInboundEnvelope` is already imported per grounding).

- [ ] **Step 4: Run, verify pass** — `uv run pytest tests/unit/gateway tests/adversarial/gateway -k "forward or inbound" -v` → PASS. Confirm `core_link.py` still at 100% (it's in the gateway gate).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/core_link.py tests/
git commit -m "fix(gateway): forward inbound as a JSON-RPC notification frame (Spec B G6-7-4, #309)"
```

---

## Task 1 — `InboundIdempotencyStore.has_committed` (non-mutating dedup read)

**Files:**

- Modify: `src/alfred/memory/inbound_idempotency.py`
- Test: `tests/unit/memory/test_inbound_idempotency_has_committed.py` (create)

- [ ] **Step 1: Write the failing tests**

```python
"""has_committed read for the forwarded dispatched-edge dedup (Spec B G6-7-4, #309)."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import SQLAlchemyError


@pytest.mark.asyncio
async def test_has_committed_false_then_true_after_commit(inbound_idempotency_store):
    store = inbound_idempotency_store
    assert await store.has_committed(inbound_id="m1", adapter_id="discord") is False
    assert await store.commit_once(inbound_id="m1", adapter_id="discord") is True
    assert await store.has_committed(inbound_id="m1", adapter_id="discord") is True


@pytest.mark.asyncio
async def test_has_committed_is_composite_keyed(inbound_idempotency_store):
    store = inbound_idempotency_store
    await store.commit_once(inbound_id="dup", adapter_id="discord")
    assert await store.has_committed(inbound_id="dup", adapter_id="tui") is False


@pytest.mark.asyncio
async def test_has_committed_does_not_commit(inbound_idempotency_store):
    store = inbound_idempotency_store
    assert await store.has_committed(inbound_id="readonly", adapter_id="discord") is False
    assert await store.commit_once(inbound_id="readonly", adapter_id="discord") is True


@pytest.mark.asyncio
async def test_has_committed_propagates_db_error(failing_idempotency_store):
    # fail-loud (hard rule #7): a DB error MUST propagate, never be swallowed into a bool —
    # a swallowed error would silently re-dispatch a committed frame or drop a fresh one.
    with pytest.raises(SQLAlchemyError):
        await failing_idempotency_store.has_committed(inbound_id="x", adapter_id="discord")
```

> Reuse the existing `inbound_idempotency_store` fixture (in `tests/unit/memory/conftest.py` or the existing idempotency test). For `failing_idempotency_store`, mirror however the existing `commit_once` fail-loud test injects a raising session scope (grep the existing idempotency test for the DB-error case).

- [ ] **Step 2: Run, verify fail** — `uv run pytest tests/unit/memory/test_inbound_idempotency_has_committed.py -v` → FAIL.

- [ ] **Step 3: Implement** — Protocol + impl in `inbound_idempotency.py`:

```python
# Protocol (after commit_once):
    async def has_committed(self, *, inbound_id: str, adapter_id: str) -> bool:
        """Non-mutating: True iff ``(adapter_id, inbound_id)`` is already accepted.

        The forwarded dispatched-edge path (Spec B G6-7-4, ADR-0039 item 4) reads this
        BEFORE dispatch to short-circuit a replay (drain its leg seq, do not re-dispatch),
        and only ``commit_once`` AFTER dispatch succeeds — so no committed-but-undispatched
        row can ever exist. Raises ``SQLAlchemyError`` only on a genuine DB failure
        (fail-loud; never swallowed into a bool).
        """
        ...
```

```python
# module-level, next to _COMMIT_ONCE_SQL:
_HAS_COMMITTED_SQL = sa.text(
    "SELECT 1 FROM inbound_idempotency "
    "WHERE adapter_id = :adapter_id AND inbound_id = :inbound_id"
)

# Postgres impl:
    async def has_committed(self, *, inbound_id: str, adapter_id: str) -> bool:
        async with self._session_scope() as session:
            result = await session.execute(
                _HAS_COMMITTED_SQL,
                {"inbound_id": inbound_id, "adapter_id": adapter_id},
            )
            return result.scalar_one_or_none() is not None
```

- [ ] **Step 4: Run, verify pass** — `uv run pytest tests/unit/memory/test_inbound_idempotency_has_committed.py -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/memory/inbound_idempotency.py tests/unit/memory/test_inbound_idempotency_has_committed.py
git commit -m "feat(comms): add InboundIdempotencyStore.has_committed read (Spec B G6-7-4, #309)"
```

---

## Task 2 — `process_inbound_message(commit_at_dispatch_edge=True)` + `dispatch_failed` audit

**Files:**

- Modify: `src/alfred/comms_mcp/inbound.py`
- Modify: `src/alfred/audit/audit_row_schemas.py` (the `dispatch_failed` field-set — co-located here, per review M5)
- Test: `tests/unit/comms/test_inbound_dispatched_edge.py` (create)

- [ ] **Step 1: Write the failing tests** (reuse the existing inbound fakes; record call order in an `order: list[str]`). Cases:

```python
# 1. SUCCESS (commit_at_dispatch_edge=True, fresh id, dispatch ok):
#    has_committed called BEFORE dispatch; commit_once + observe(wire_seq) called AFTER dispatch
#    returns; observe got notification.wire_seq.  assert order.index("dispatch") < order.index("commit_once")
# 2. REPLAY (True, has_committed -> True): NO dispatch, NO commit_once; observe(wire_seq) IS called
#    (drain the tail); a replay_observed audit row emitted; returns.
# 3. DISPATCH FAILURE (True, dispatch raises): NO commit_once, NO observe; a dispatch_failed audit
#    row emitted; the exception PROPAGATES.
# 4. DIRECT-PATH UNCHANGED (False, default): commit_once BEFORE the pipeline; observe on the True
#    branch only; replay branch emits replay_observed and does NOT observe; None-store falls through.
# 5. has_committed is NEVER called when commit_at_dispatch_edge=False.
# 6. AUDIT-WRITE FAILURE on dispatch_failed (audit_writer raises): the error PROPAGATES loud
#    (not swallowed), the frame is NOT committed and NOT observed.
```

- [ ] **Step 2: Run, verify fail** — FAIL (unexpected kwarg).

- [ ] **Step 3: Implement** in `inbound.py`.
  - Add `commit_at_dispatch_edge: bool = False,` (keyword-only) to the signature.
  - **Do NOT wholesale re-indent 479-507** (review M2). Add a NEW dispatched-edge short-circuit block BEFORE the existing block, and guard ONLY the existing commit_once/observe lines:

```python
    if commit_at_dispatch_edge:
        # Forwarded path (ADR-0039 item 4): do NOT commit at receipt. A replay (row already
        # durable) is DRAINED here (advance the contiguous high-water so its dispatched tail
        # can trim) and short-circuited WITHOUT re-dispatch.
        if idempotency_store is not None and await idempotency_store.has_committed(
            inbound_id=notification.inbound_id,
            adapter_id=notification.adapter_id,
        ):
            audit_hash.set_broker(secret_broker)
            await _emit_idempotency_replay_observed(notification, audit_writer=audit_writer)
            if ack_tracker is not None and notification.wire_seq is not None:
                ack_tracker.observe(notification.wire_seq)
            _log.info(
                "comms.inbound.idempotency.replay_short_circuit",
                adapter_id=notification.adapter_id,
            )
            return
    elif idempotency_store is not None:
        # Direct TUI/daemon path — UNCHANGED receipt-time commit_once + observe (existing 480-505).
        if not await idempotency_store.commit_once(
            inbound_id=notification.inbound_id, adapter_id=notification.adapter_id
        ):
            audit_hash.set_broker(secret_broker)
            await _emit_idempotency_replay_observed(notification, audit_writer=audit_writer)
            _log.info("comms.inbound.idempotency.replay_short_circuit", adapter_id=notification.adapter_id)
            return
        if ack_tracker is not None and notification.wire_seq is not None:
            ack_tracker.observe(notification.wire_seq)
    # ``audit_hash.set_broker(secret_broker)`` at the existing line 514 stays OUTSIDE this gate.
```

- At the dispatch site (~609), gate the dispatched-edge commit/observe:

```python
    if commit_at_dispatch_edge:
        try:
            await orchestrator.dispatch(ingested)
        except Exception:
            # Dispatched-edge fail-loud (ADR-0039 item 4): NOT committed, NOT observed, so the
            # leg replays it. Distinct closed-vocab audit row from replay_observed. The bound on
            # this replay (poison ceiling / dead-letter) is G6-7-5. An audit-write failure here
            # PROPAGATES (loud — hard rule #7), it is not nested-swallowed.
            await _emit_dispatch_failed(notification, audit_writer=audit_writer)
            raise
        if idempotency_store is not None:
            await idempotency_store.commit_once(
                inbound_id=notification.inbound_id, adapter_id=notification.adapter_id
            )
        if ack_tracker is not None and notification.wire_seq is not None:
            ack_tracker.observe(notification.wire_seq)
    else:
        await orchestrator.dispatch(ingested)
```

- Add `_emit_dispatch_failed` next to `_emit_idempotency_replay_observed` (closed-vocab `result="dispatch_failed"`, only `adapter_id` + non-T3 bounded fields). Add its field-set to `src/alfred/audit/audit_row_schemas.py`.

- [ ] **Step 4: Run, verify pass** — `uv run pytest tests/unit/comms/test_inbound_dispatched_edge.py tests/unit/comms -k inbound -v` → PASS; existing inbound tests still green (direct path unchanged).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/inbound.py src/alfred/audit/audit_row_schemas.py tests/unit/comms/test_inbound_dispatched_edge.py
git commit -m "feat(comms): dispatched-edge commit/observe mode + dispatch_failed audit (Spec B G6-7-4, #309)"
```

---

## Task 3 — `GatewayForwardedInboundReceiver` (the receive trust boundary)

**Files:**

- Create: `src/alfred/comms_mcp/forwarded_inbound_receiver.py`
- Modify: `src/alfred/audit/audit_row_schemas.py` (field-sets: `forwarded.unknown_adapter`, `forwarded.envelope_body_mismatch`, `forwarded.body_malformed`)
- Test: `tests/unit/comms/test_forwarded_inbound_receiver.py`

- [ ] **Step 1: Write the failing tests** — build the receiver with a fake registry of `{"discord": <collab with a non-None fake promoter + a long-lived limiter>}`, fake idempotency store + ack tracker + audit writer, and an injected fake `dispatch` (so the unit test does not need the whole pipeline). Cases:

```python
# A. HAPPY: well-formed discord notification (params re-parse, body adapter_id=="discord", matches)
#    -> dispatch called with commit_at_dispatch_edge=True, the DISCORD collaborator set (incl. the
#    long-lived pre_resolution_limiter — SAME instance across two calls), and notification.wire_seq
#    REBOUND to the REAL leg wire_seq passed to receive() (NOT the body's scrubbed None, NOT a
#    body-smuggled value).
# B. UNKNOWN ADAPTER (envelope adapter_id NOT in registry) -> NO dispatch; a
#    comms.inbound.forwarded.unknown_adapter signed audit row; THEN observe(wire_seq) (ack-to-drain,
#    review H4 — never leave it un-observed to wedge the contiguous high-water); return.
# C. ENVELOPE/BODY MISMATCH (reparse raises InboundEnvelopeBodyMismatchError) -> NO dispatch; a
#    comms.inbound.forwarded.envelope_body_mismatch signed audit row; THEN observe(wire_seq); return.
# D. MALFORMED BODY (reparse raises InboundBodyMalformedError) -> NO dispatch; a
#    comms.inbound.forwarded.body_malformed signed audit row; THEN observe(wire_seq); return (no raise).
# E. ROUTING USES THE ENVELOPE adapter_id, never the body (SEC-309-1): assert the registry was
#    queried with the ENVELOPE id.
# F. PromoterRequiredError is NOT caught here (misconfig fail-loud) -> propagates.
# G. AUDIT-WRITE FAILURE on any drop disposition (B/C/D): the audit row raises -> do NOT observe
#    (do not drain an unrecorded drop) -> escalate loud (the error propagates to the disposition's
#    audit-unwritable arm, Task 4). assert observe was NOT called.
```

- [ ] **Step 2: Run, verify fail** — module does not exist.

- [ ] **Step 3: Implement** `forwarded_inbound_receiver.py`:
  - Module docstring: the trust boundary; K4 admission; reparse + drain-on-terminal-drop; wire_seq rebind; per-kind collaborator selection by ENVELOPE id; dispatched-edge dispatch; never reads the body for routing; runs core-side only.
  - `_ForwardedCollaborators` frozen dataclass — fields mirroring `process_inbound_message`'s collaborator params: `sub_payload_promoter`, `resolver_bridge` (the identity resolver — NAME it `resolver_bridge` per review N3), `orchestrator`, `burst_limiter`, `secret_broker`, `pre_resolution_limiter` (long-lived, REQUIRED — review M4).
  - `GatewayForwardedInboundReceiver.__init__(*, registry: Mapping[str, _ForwardedCollaborators], idempotency_store, audit_writer, dispatch=process_inbound_message)`.
  - `set_ack_tracker(self, ack_tracker)` — per-connection, mutable slot (the receiver is a per-boot singleton; the tracker is per-connection — review H2).
  - `async def receive(self, *, params: object, wire_seq: int | None) -> None`:
    1. `envelope = GatewayAdapterInboundEnvelope.model_validate(params)` (off-vocab `adapter_id` → loud `ValidationError` at the wire — let it surface).
    2. K4 admit: `if envelope.adapter_id not in self._registry:` → `await self._audit_unknown_adapter(envelope.adapter_id)` THEN `self._drain(wire_seq)` THEN `return`.
    3. `try: notification = reparse_forwarded_inbound(envelope)` — `except InboundEnvelopeBodyMismatchError:` → audit `envelope_body_mismatch`, drain, return — `except InboundBodyMalformedError as exc:` → audit `body_malformed` (carry ONLY `adapter_id` + a bounded structural code from `exc`'s leak-safe summary, NEVER `str(exc)` verbatim — review M4-leak), drain, return.
    4. rebind: `notification = notification.model_copy(update={"wire_seq": wire_seq})`.
    5. `collab = self._registry[envelope.adapter_id]`.
    6. `await self._dispatch(notification, identity_resolver=collab.resolver_bridge, orchestrator=collab.orchestrator, burst_limiter=collab.burst_limiter, audit_writer=self._audit_writer, secret_broker=collab.secret_broker, pre_resolution_limiter=collab.pre_resolution_limiter, sub_payload_promoter=collab.sub_payload_promoter, idempotency_store=self._idempotency_store, ack_tracker=self._ack_tracker, commit_at_dispatch_edge=True)`.
  - `_drain(self, wire_seq)`: `if self._ack_tracker is not None and wire_seq is not None: self._ack_tracker.observe(wire_seq)`. **Called ONLY after a successful audit write** (review H4/G — a failed audit must not drain; the audit helper raising propagates before `_drain` runs, satisfying case G).
  - Audit helpers raise on write failure (do NOT swallow); the disposition's audit-unwritable arm (Task 4) escalates.
  - `__all__ = ["GatewayForwardedInboundReceiver", "_ForwardedCollaborators"]`.

- [ ] **Step 4: Run, verify pass** — `uv run pytest tests/unit/comms/test_forwarded_inbound_receiver.py -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/forwarded_inbound_receiver.py src/alfred/audit/audit_row_schemas.py tests/unit/comms/test_forwarded_inbound_receiver.py
git commit -m "feat(comms): GatewayForwardedInboundReceiver receive trust boundary (Spec B G6-7-4, #309)"
```

---

## Task 4 — Route `gateway.adapter.inbound` through `SessionDispatchDisposition` + audit-unwritable escalation

**Files:**

- Modify: `src/alfred/plugins/inbound_disposition.py`
- Test: `tests/unit/plugins/test_inbound_disposition.py` (extend)

- [ ] **Step 1: Write the failing tests**

```python
# - receiver injected: dispatch("gateway.adapter.inbound", params, wire_seq=7) calls
#   receiver.receive(params=params, wire_seq=7); does NOT call session._on_post_handshake_method.
# - NO receiver injected: "gateway.adapter.inbound" falls through to session delegation, which
#   hits the gateway.adapter.* prefix -> AdapterStatusObserver unknown_method LOUD refusal
#   (fail-closed; a forwarded frame should only arrive on the gateway leg that has the receiver).
# - "gateway.adapter.spawn_request" still routes to the credential resolver (regression).
# - plain "inbound.message" still delegates to the session (regression).
# - AUDIT-UNWRITABLE: when receiver.receive raises the audit-write-failure error family, the
#   disposition routes it to the LOUD escalation arm (restart-request / quarantine), NOT the
#   blanket except Exception catch-and-continue (mirror the AdapterStatusAuditWriteError arm).
```

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement** — add `forwarded_inbound_receiver: <ReceiverLike> | None = None` to `SessionDispatchDisposition.__init__`; add the arm BEFORE session delegation (after spawn_request); add the audit-unwritable escalation arm (catch the same audit-write-failure family the existing `AdapterStatusAuditWriteError` arm catches, before the blanket catch):

```python
        if method == GATEWAY_ADAPTER_INBOUND and self._forwarded_inbound_receiver is not None:
            # Spec B G6-7-4 (#309): a gateway-forwarded hosted-adapter inbound. Intercept here
            # (parallel to spawn_request) so it never reaches the session's gateway.adapter.*
            # prefix -> AdapterStatusObserver unknown_method refusal. An audit-write failure
            # inside the receiver escalates LOUD via the arm below (never the blanket catch).
            await self._forwarded_inbound_receiver.receive(params=params_mapping, wire_seq=wire_seq)
            return
```

- Import `GATEWAY_ADAPTER_INBOUND` from `alfred.comms_mcp.protocol`. Reuse the existing audit-write-failure error type the status arm catches (confirm its name — likely `AuditWriteError`/`SQLAlchemyError`; match the `AdapterStatusAuditWriteError` arm's exception class).

- [ ] **Step 4: Run, verify pass** — `uv run pytest tests/unit/plugins/test_inbound_disposition.py -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/plugins/inbound_disposition.py tests/unit/plugins/test_inbound_disposition.py
git commit -m "feat(comms): route gateway.adapter.inbound to the receiver + audit-unwritable escalation (Spec B G6-7-4, #309)"
```

---

## Task 5 — Wire the fail-closed per-kind registry + receiver into the daemon gateway leg

**Files:**

- Modify: `src/alfred/cli/daemon/_commands.py`
- Test: `tests/unit/cli/daemon/` (extend the daemon boot/wiring tests)

- [ ] **Step 1: Write the failing tests**

```python
# - the gateway-leg runner (with_credential_resolver=True carrier) is built with a
#   forwarded_inbound_receiver; the daemon-spawned stdio path is NOT.
# - the registry's discord entry has a NON-None SubPayloadPromoter and a long-lived
#   pre_resolution_limiter (same instance across receive calls).
# - BOOT FAIL-CLOSE: a discord registry entry with a None promoter REFUSES BOOT (a
#   CommsPromoterMisconfiguredFailure-style refusal), never a per-message PromoterRequiredError.
# - at accept, receiver.set_ack_tracker is called with the SAME BoundedSeqAckTracker instance
#   bound to wiring.inbound_handler (one tracker per connection; the ack timer reads it).
# - the default / alfred_comms_test boot path is byte-for-byte unchanged.
```

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement.**
  - `_build_forwarded_inbound_registry(*, settings, audit, graph) -> Mapping[str, _ForwardedCollaborators]` — one entry per hostable forwarded kind (initially `"discord"`), reusing `_build_sub_payload_promoter(adapter_kind="discord", content_store=graph.content_store)` + `graph.resolver_bridge` + `graph.inbound_orchestrator` + `graph.burst_limiter` + `graph.secret_broker` + a long-lived `_PreResolutionLimiter()` per kind. **Fail-close at boot:** if a kind with a non-empty `REQUIRED_CLASSIFIERS_BY_KIND` got a `None` promoter, raise the existing `CommsPromoterMisconfiguredFailure` (boot-refusing) — never a per-message trip.
  - Construct `GatewayForwardedInboundReceiver(registry=..., idempotency_store=graph.idempotency_store, audit_writer=audit)` once; thread it to the gateway-leg runner via a new `_build_comms_runner(..., forwarded_inbound_receiver=receiver)` kwarg → into the `SessionDispatchDisposition`.
  - In the accept block (~1301), after `wiring.inbound_handler.set_ack_tracker(ack_tracker)`, add `receiver.set_ack_tracker(ack_tracker)` (same per-connection instance — review H2).

> **VERIFY in TDD:** trace where `SessionDispatchDisposition` is constructed for the gateway leg (inside `_build_comms_runner` / `CommsPluginRunner.__init__` when `session is not None` + `with_credential_resolver=True`) so the receiver injection lands in the right ctor.

- [ ] **Step 4: Run, verify pass** — `uv run pytest tests/unit/cli/daemon -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_commands.py tests/unit/cli/daemon/
git commit -m "feat(daemon): wire fail-closed forwarded-inbound registry onto the gateway leg (Spec B G6-7-4, #309)"
```

---

## Task 6 — i18n + ci.yml coverage gates

**Files:**

- Modify: i18n catalog (`locale/.../alfred.po` + recompile `.mo`) + `SLICE_4_KEYS` / `test_catalog_slice_4_keys`.
- Modify: `.github/workflows/ci.yml` — add `src/alfred/comms_mcp/forwarded_inbound_receiver.py` to BOTH the python-job per-file gate (mirror `inbound_reparse.py` at lines 196-199) AND the coverage-gates per-file gate (mirror lines 1297-1300), each `--fail-under=100`.

> Audit field-sets already landed co-located in Tasks 2/3 (review M5). This task is i18n + gates only.

- [ ] **Step 1:** Write/extend the catalog drift test for any operator-facing string the new audit/log paths surface via `t()` (e.g. `alfred audit log` rendering of the new reasons — mirror how `ingress_audit.reason_i18n_key` reserves keys).
- [ ] **Step 2:** Run, verify fail.
- [ ] **Step 3:** Add i18n keys; recompile with `uv run pybabel compile -d locale` (NEVER `--omit-header`; use `pybabel update -i ... --no-fuzzy-matching` if updating, to preserve the header + fix `#:` refs so the drift gate passes). Add the module to BOTH ci.yml gate sites.
- [ ] **Step 4:** `grep -n forwarded_inbound_receiver .github/workflows/ci.yml` shows it in BOTH the `hashFiles` guard AND the `--include` list; catalog drift + `pybabel compile --check` green.
- [ ] **Step 5: Commit**

```bash
git add locale/ .github/workflows/ci.yml tests/
git commit -m "feat(comms): i18n keys + 100% coverage gate for forwarded receive (Spec B G6-7-4, #309)"
```

---

## Task 7 — Adversarial suite (non-root) incl. real read→pump→route e2e + full quality gate

**Files:**

- Create: `tests/adversarial/comms/test_forwarded_inbound_admission.py`

- [ ] **Step 1:** Write adversarial cases (in-process, non-root — this is the GATING layer per the G2-lesson; root-only integration is a paper gate):
  - **REAL e2e (review L1):** drive a real `forward_adapter_inbound`-shaped payload through the actual `CommsSocketTransport.read_frame` + `CommsPluginRunner` pump → assert it reaches the receiver AND the dispatched notification's `wire_seq` equals the **leg-frame** seq (the fold→lift→rebind chain, not just a direct-injection unit). This is the case that would have caught C1/C2.
  - forged envelope `adapter_id` (unknown kind) → `unknown_adapter` refusal, ack-to-drain (high-water ADVANCES past it — assert the leg is NOT wedged), NOT dispatched.
  - envelope/body `adapter_id` disagreement → `envelope_body_mismatch` refusal, ack-to-drain.
  - malformed body (non-JSON / non-object / missing field / `extra_forbidden` with a T3 key) → `body_malformed` drop, ack-to-drain, AND a **canary-absence** assertion: a high-entropy secret / canary token in a top-level extra key produces NO canary substring in ANY audit row or log line (review M4-leak).
  - body-smuggled `wire_seq` scrubbed AND real leg seq rebound (dispatched notification carries the real seq, not the smuggled one).
  - dispatch-failure replay: dispatch raises → no commit/observe → re-delivery RE-dispatches; after a success the same id re-delivered is `replay_observed` + drained, NOT re-dispatched.
  - **documented known-this-slice property:** a deterministically-failing (poison) frame replays UNBOUNDEDLY in -4 (the bound is -5) — a test asserting the un-observed-on-failure behaviour, with a comment that the leg is test-only until -5.
  - audit-unwritable on a drop disposition → the frame is NOT drained (not observed) → loud escalation (no silent drain of an unrecorded drop).
- [ ] **Step 2:** Run, verify (the e2e + wedge + canary cases lock properties not covered by units).
- [ ] **Step 3:** Fill any gap.
- [ ] **Step 4: Full local gate** (BEFORE any push):

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy src/ && uv run pyright src/
uv run pytest tests/unit tests/adversarial -q
uv run coverage run -m pytest tests/unit tests/adversarial -q && \
  uv run coverage report --include='src/alfred/comms_mcp/forwarded_inbound_receiver.py' --fail-under=100
# confirm core_link.py still 100% after Task 0:
uv run coverage report --include='src/alfred/gateway/core_link.py' --fail-under=100
```

Expected: all green; both new/changed trust modules at 100%.

- [ ] **Step 5: Commit**

```bash
git add tests/adversarial/comms/test_forwarded_inbound_admission.py
git commit -m "test(comms): adversarial receive admission + real e2e + ack-to-drain (Spec B G6-7-4, #309)"
```

---

## Resolved open questions (from plan-review)

1. **Commit/observe mechanism** — RATIFIED: `has_committed` read + late `commit_once`; no committed-but-undispatched window; gateway path synchronous-single-in-flight so the only double-dispatch is the crash window (bounded in -5).
2. **Leg-frame shape on receive** — RESOLVED (the original assumption was WRONG): Task 0 makes the forward a JSON-RPC notification; the receiver does `model_validate(params)` on the envelope dict.
3. **Unknown-adapter / mismatch drop** — REVERSED: MUST ack-to-drain (audit first, then `observe`) to avoid wedging the contiguous high-water.
4. **`receive()` signature** — receiver-parses-envelope; the disposition passes `params` + `wire_seq` only (payload-blind).
5. **`SessionDispatchDisposition` construction site** — Task 5 verifies the injection lands in the gateway-leg runner's ctor.

## Self-review checklist

- **ADR-0039 coverage:** item 3 receive route + two-sided admission → Tasks 0,3,4; item 4 dispatched-edge → Tasks 1,2; collaborator registry (fail-closed) → Tasks 3,5; ack-to-drain (malformed/unknown/mismatch) → Tasks 3,7; item 4b poison ceiling → **explicitly deferred to G6-7-5** (scope fence + cross-slice safety note). ✓
- **Direct path unchanged:** Task 2 default `False` + regression (Task 2 cases 4/5, Task 4 regressions). ✓
- **Fail-loud / no silent loss:** all drops loud-audited + ack-to-drain; dispatch_failed loud + re-raise; audit-write-failure escalates loud (never blanket-catch); dispatch-failure replays (bound = -5). ✓
- **Payload-blind carrier; T3 only core-side; leak-safe audit:** gateway never parses; receiver re-parses core-side; body_malformed row carries only adapter_id + bounded structural code; canary-absence test. ✓
- **Type/name consistency:** `commit_at_dispatch_edge` (Tasks 2,3,5); `has_committed` kw-only (Tasks 1,2,3); `resolver_bridge` field name (Tasks 3,5); `_ForwardedCollaborators` carries long-lived `pre_resolution_limiter` (Tasks 3,5). ✓
- **ci.yml BOTH gate sites + audit module path correct (`src/alfred/audit/audit_row_schemas.py`):** Tasks 2,3,6. ✓

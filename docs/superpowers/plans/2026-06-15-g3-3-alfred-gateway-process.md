# G3-3 — The `alfred-gateway` Process Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`. This is PR 3 of the G3 sub-epic (parent: `2026-06-14-g3-alfred-gateway-process.md`); **G3-1 (#263) and G3-2 (#264) are MERGED**. G3-3's scope was fixed + architect/security plan-reviewed in the parent plan. Because the gateway process is large, G3-3 is split into **two PRs** (the parent plan's flagged split): **G3-3a** (the stable kernel — detailed below) and **G3-3b** (the core-link + relay + process — scope fixed here, detailed against G3-3a's merged reality).

**Goal:** Build the standalone, always-up `alfred-gateway` process: a pure, reconnect-capable, payload-blind relay between a dial-in client (the TUI) and the core. G3-3 is a PURE RELAY — NO `ReplayBuffer`/resume (G4), NO egress proxy (Spec C).

**Architecture:** The gateway terminates the client connection on a stable client-facing `0600` AF_UNIX socket (reusing the merged G3-1 `CommsSocketListener` posture) and dials the core over the shared-volume socket (G3-4 relocates it). It is the **first real `AlfredSeqAck/1` peer**: it echoes the capability AND deframes/reframes (unlike the plain plugins). It consumes G1's `daemon.lifecycle.going_down`/`ready` frames to drive a link-state machine and emits `link.reconnecting`/`restored`/`unavailable` control frames to the client. It is a **T1 carrier** — T3 stays in the core.

**Tech Stack:** Python 3.12+, asyncio, AF_UNIX, Pydantic v2 wire models, structlog, prometheus_client, pytest + hypothesis, mypy --strict + pyright.

---

## G3-3 sub-epic decomposition

| PR | Scope | Trust-boundary? |
| --- | --- | --- |
| **G3-3a** | The stable kernel: the `GatewayLinkState` machine (`UP / DOWN_SIGNALLED / DOWN_CRASH / REDIALING`) + control-frame derivation (the spec §9 invariant: no `restored` without a preceding `reconnecting`; exactly one per gap), the gateway→client control-frame wire models (`link.reconnecting`/`restored`/`unavailable`), and a thin `GatewayClientListener` (reuses the merged `CommsSocketListener` 0600/0700 + peer-auth) that accepts the client + can emit control frames. NO core dial, NO seq/ack relay. Pure + hypothesis-testable. | Yes — client-facing socket. |
| **G3-3b** | The core-facing half + the process: `GatewayCoreLink` (dials the core via `dial_comms_socket`; **dial-side `SO_PEERCRED`** — the both-direction dial side G3-1 deferred; fake-clock reconnect/backoff; the lifecycle-frame consume → drives the G3-3a state machine; **seq/ack deframe/reframe** as the first real peer; lifecycle-frame Pydantic validation + epoch check), the pure relay loop (client↔core, payload byte-for-byte, `id` preserved, no buffering), the `alfred gateway` CLI + `src/alfred/gateway/__main__.py`, Prometheus metrics, the **non-root in-process wire-contract test**, and the **payload-blindness canary test**. | Yes — always-up T1 carrier. |

**Deferred (NOT G3-3):** `ReplayBuffer`/resume/cap/TTL/breaker/back-pressure/zeroing + gateway-local audit reconcile (G4); the Compose service + long-running core daemon + shared-volume socket relocation (G3-4); re-pointing `alfred chat` + the PTY smoke (G5); egress proxy (Spec C).

---

## PR G3-3a — The stable kernel (link-state machine + control frames + client listener)

**Goal:** The connection-holder + link-state core of the gateway, independently testable without any core connection. This is the "stable kernel" the parent plan + spec §3 call out (the part that rarely changes; resume/buffer logic sits above it in G4).

### Files

- Create: `src/alfred/gateway/__init__.py` (package marker + `__all__`).
- Create: `src/alfred/gateway/link_state.py` — `GatewayLinkState` enum + `LinkStateMachine`.
- Create: `src/alfred/gateway/client_listener.py` — `GatewayClientListener`.
- Modify: `src/alfred/comms_mcp/protocol.py` — the three gateway→client control-frame models + their method-name constants.
- Test: `tests/unit/gateway/test_link_state.py` (the machine + the §9 invariant, hypothesis-property-tested).
- Test: `tests/unit/gateway/test_client_listener.py` (accept + control-frame emission + peer-auth reuse).
- (NO i18n change in 3a — the control-frame methods are wire constants, not `t()`, and the frames carry NO operator text: the banner is dropped from the wire, so the operator-facing reconnect banner is the **client's** `t()` call site against `{user.language}` in G5, not the gateway's. Reserve `gateway.link.*` keys when G5/the client renders them.)
- Modify: `docs/adr/0032-gateway-comms-resume-transport.md` — record the link-state machine + control-frame contract (the §9 invariant).

### Design notes (read before Task 1)

- **The link-state machine is PURE** (no I/O, no clock): `feed(event) -> LinkControl | None` returns which control frame (if any) to emit on that transition. Events in G3-3a: `core_going_down`, `core_crash_eof`, `redial_started`, `core_ready`. (The `breaker_tripped` event + the `unavailable` *transition* are **G4** — its trigger is the ReplayBuffer cap breach, spec §5 — so G3-3a ships only the `unavailable` *wire model*, not a transition that emits it, keeping the wire vocab whole without a half-specified G4 edge — architect H1.) The spec §9 invariant: **no `restored` without a preceding `reconnecting`; exactly one control frame per gap.**
- **`feed()` takes TYPED events only — it makes NO wire-trust decision** (security M4). Deriving a `core_ready` event from a lifecycle frame is a **G3-3b obligation**: the frame must be `ReadyNotification`-parsed + epoch-checked BEFORE `feed(core_ready)` is called. The pure machine is structurally incapable of being driven by raw wire bytes, so a forged `ready` cannot reach it.
- **Transitions + emitted frame** (the table; an undefined `(state, event)` raises `GatewayLinkStateError` — fail-loud, never a silent no-op):
  - `UP` + `core_going_down` → `DOWN_SIGNALLED`, emit `reconnecting`.
  - `UP` + `core_crash_eof` → `DOWN_CRASH`, emit `reconnecting`.
  - `UP` + `core_ready` (a duplicate/late ready while already up) → `UP`, emit nothing (idempotent; never a spurious second `restored`).
  - `DOWN_SIGNALLED`/`DOWN_CRASH` + `core_going_down`/`core_crash_eof` → stay (idempotent — a second down-signal within one gap), emit nothing (the gap was already announced).
  - `DOWN_SIGNALLED`/`DOWN_CRASH` + `redial_started` → `REDIALING`, emit nothing.
  - `DOWN_SIGNALLED`/`DOWN_CRASH` + `core_ready` → `UP`, emit `restored` (architect H2 — a `ready` can legitimately race AHEAD of `redial_started`; the gap closes regardless, so this must NOT fail-loud-crash a real sequence).
  - `REDIALING` + `core_ready` → `UP`, emit `restored`.
  - `REDIALING` + `redial_started` → stay (idempotent — repeated redial attempts within one gap), emit nothing.
  - `REDIALING` + `core_going_down`/`core_crash_eof` → stay (the core bounced again mid-redial; gap still open), emit nothing.
- **Control-frame models are PURE STATE SIGNALS — NO `banner` string on the wire** (security H1 + i18n M3). The `link.*` frames carry NO operator-text field: an open `str` is a standing invitation to later smuggle a core-supplied / T3-derived `reason` into a client-visible frame, and operator text on the wire is an i18n-rule-#1 hazard. The gateway sends only the STATE; the **client (the TUI, G5) renders its own localized banner** from the method, against `{user.language}` where the user's language lives. Methods: `link.reconnecting` / `link.restored` / `link.unavailable`. id-less notifications, `extra="forbid"` (a stray field is rejected loud).
- **`GatewayClientListener`** REUSES `CommsSocketListener` (merged G3-1: 0600/0700 + `SO_PEERCRED` peer-auth) with `adapter_id="gateway"` (socket `comms-gateway.sock` — the gateway's OWN stable externally-owned path per spec §10; the one-time client dial-target change from `comms-tui.sock`→`comms-gateway.sock` is **G5's** job, which already owns "re-point `alfred chat` at the gateway" — architect C1). **Single-accept-for-life** (architect L1): the client connection is held ACROSS core restarts (spec §1) — the listener accepts ONE client; all reconnect churn is on `GatewayCoreLink` (G3-3b), never a client re-accept. It adds `send_control(notification)` — routes the id-less control frame through the accepted transport's `send()` (reusing its single-writer lock + the future client-leg seq/ack wrapping G3-3b adds — security L1), NOT a bespoke serialize; loud (structlog) on a write-to-dead-client failure (security M2). It does NOT relay payload (G3-3b). The client peer-auth reject reuses the merged `on_peer_rejected` seam — in 3a a **structlog-only** callback (or `None`, relying on the listener's own `comms.socket.peer_uid_rejected` warning): the gateway has NO audit sink until G4, so the durable reject audit row + the `gateway_peer_auth_rejected_total` metric are G3-3b/G4 (security M3).
- **Audit deferral (security M2):** every link-state transition is **loud via structlog** in G3-3a; the durable, signed, reconcilable gateway-local audit row is **G4** (spec §6) — 3a's pure machine has no audit sink. State this in the ADR amendment so a spec-cross-checking reviewer reads it as a deliberate deferral, not a gap.

### Tasks

- [ ] **Task 1: Control-frame wire models + constants (TDD)**

**Files:** `src/alfred/comms_mcp/protocol.py`; Test: `tests/unit/gateway/test_link_state.py` (model round-trip).

- [ ] Step 1 — failing test: the three models are EMPTY state-signal notifications (no fields), carry the right `method` constant, and `extra="forbid"` rejects ANY field (proving no banner/reason/T3 can ride the wire).

```python
def test_link_control_frames_are_empty_state_signals():
    import pytest
    from pydantic import ValidationError
    from alfred.comms_mcp.protocol import (
        LINK_RECONNECTING, LINK_RESTORED, LINK_UNAVAILABLE,
        LinkReconnectingNotification, LinkRestoredNotification, LinkUnavailableNotification,
    )
    assert (LINK_RECONNECTING, LINK_RESTORED, LINK_UNAVAILABLE) == (
        "link.reconnecting", "link.restored", "link.unavailable")
    # Pure state signals: no fields, and extra="forbid" rejects any smuggled text
    # (banner/reason/T3) — the client renders its own localized banner from the method.
    assert LinkReconnectingNotification().model_dump() == {}
    for model in (LinkReconnectingNotification, LinkRestoredNotification, LinkUnavailableNotification):
        with pytest.raises(ValidationError):
            model(banner="x")  # type: ignore[call-arg]
```

- [ ] Step 2 — run, expect FAIL. `uv run pytest tests/unit/gateway/test_link_state.py -k link_control -v`
- [ ] Step 3 — implement in `protocol.py` (next to the lifecycle models): three FIELDLESS `_WireModel` subclasses (each with a code comment: "gateway→client state signal — NOT adapter-keyed (deliberately no `adapter_id`), NO banner/reason text — the client renders its own localized banner from the method"; architect H3) + the three `Final[str]` method constants; export in `__all__`. (`"gateway"` does NOT need adding to `adapter_kind` — these frames carry no `adapter_id` and `default_comms_socket_path` validates the socket id by regex only; the `adapter_kind`-membership question for metrics labels is a G3-3b note.)
- [ ] Step 4 — run, expect PASS. Step 5 — commit (`feat(gateway): link.* control-frame wire models + method constants (Spec A G3-3a / ADR-0032) (#237)` + trailer).

- [ ] **Task 2: `LinkStateMachine` + the §9 invariant (TDD, hypothesis)**

**Files:** `src/alfred/gateway/link_state.py`, `src/alfred/gateway/__init__.py`; Test: `tests/unit/gateway/test_link_state.py`

- [ ] Step 1 — failing tests:
  - the explicit transition table in the design notes (each `(state, event) -> (new_state, emitted_frame)`), INCLUDING the idempotent self-loops and `DOWN_* + core_ready → UP/restored` (architect H2 — must not crash a legitimate ready-before-redial_started race);
  - a hypothesis property over random sequences of the four G3-3a events: **every `restored` is preceded by a `reconnecting` with no intervening `restored`** (exactly one `restored` per gap; never `restored` from `UP` without an open gap; never a spurious second `restored`);
  - an undefined `(state, event)` raises `GatewayLinkStateError` (fail-loud). NB: with the H2 fix, `DOWN_* + core_ready` is now DEFINED, so the test asserts the fail-loud only for a genuinely-undefined pair.
- [ ] Step 2 — run, expect FAIL.
- [ ] Step 3 — implement: `GatewayLinkState(StrEnum)` (`UP/DOWN_SIGNALLED/DOWN_CRASH/REDIALING`), `GatewayLinkEvent(StrEnum)` (the FOUR G3-3a events — NO `breaker_tripped`, that's G4), `LinkControl(StrEnum)` (`RECONNECTING/RESTORED/UNAVAILABLE` — `UNAVAILABLE` defined for the wire vocab even though G3-3a never emits it), and `class LinkStateMachine` with `state` (starts `UP`) + `feed(event: GatewayLinkEvent) -> LinkControl | None`. Pure, explicit transition dict, fail-loud on an undefined pair. No I/O, no clock.
- [ ] Step 4 — run, expect PASS. Step 5 — commit (`feat(gateway): pure link-state machine enforcing the §9 reconnecting/restored contract (Spec A G3-3a) (#237)` + trailer).

- [ ] **Task 2b: machine→wire integration — the §9 invariant end-to-end (architect M1) (TDD)**

**Files:** Test: `tests/unit/gateway/test_link_state.py` (or `test_client_listener.py`)

- [ ] Step 1 — failing test: drive an event sequence (e.g. `going_down`, `redial_started`, `core_ready`, then a crash gap) through `LinkStateMachine`, and for each non-`None` `LinkControl` call `GatewayClientListener.send_control(<the matching model>)`; assert the connected fake client OBSERVES exactly the §9-correct frame sequence (`reconnecting` then `restored`, one per gap), proving the kernel delivers the invariant machine→wire — not just in the pure unit (de-risks the G3-3b wiring).
- [ ] Step 2 — run, expect FAIL. Step 3 — wire a tiny helper mapping `LinkControl -> Link*Notification`; drive it. Step 4 — PASS. (Folds into the Task 3 commit.)

- [ ] **Task 3: `GatewayClientListener` — accept + `send_control` (TDD)**

**Files:** `src/alfred/gateway/client_listener.py`; Test: `tests/unit/gateway/test_client_listener.py`

- [ ] Step 1 — failing tests: a `GatewayClientListener` binds (reused `CommsSocketListener`, `adapter_id="gateway"`), accepts a same-uid loopback client, and `send_control(LinkReconnectingNotification())` writes the id-less `{"jsonrpc":"2.0","method":"link.reconnecting","params":{}}` frame to the client; a mismatched-uid peer is refused (merged peer-auth + the structlog-only `on_peer_rejected`); `send_control` to a closed client is LOUD (structlog warning), not silent (security M2).
- [ ] Step 2 — run, expect FAIL.
- [ ] Step 3 — implement: `GatewayClientListener` composes `CommsSocketListener(adapter_id="gateway", on_peer_rejected=<structlog-only stub or None>)` (3a has no audit sink — security M3); exposes `bind()`/`accept()` (delegating; **single-accept-for-life** — never re-accept on a core gap, architect L1) + `send_control(notification)` that builds the id-less frame `{"jsonrpc":"2.0","method":<link.* method const>,"params":notification.model_dump()}` and routes it through the accepted transport's `send()` (NOT a bespoke serialize — inherits the transport's single-writer lock + future client-leg seq/ack wrapping, security L1); a `(BrokenPipeError, ConnectionResetError)` on the write is logged loud (`comms.gateway.control_send_failed`) and re-raised. Reaps on `aclose()`. No payload relay (G3-3b).
- [ ] Step 4 — run, expect PASS. Step 5 — commit (`feat(gateway): GatewayClientListener — client-facing socket + control-frame emit (Spec A G3-3a / ADR-0031) (#237)` + trailer).

- [ ] **Task 4: ADR-0032 amendment + full gate + open PR**

- [ ] ADR-0032: add a "Link-state machine + control frames (G3-3a)" subsection — the state table, the §9 invariant, the T1-carrier/**no-banner-no-T3** posture (frames are pure state signals; the client renders its own banner), the **audit deferral** (link transitions are loud via structlog in 3a; the durable signed reconcilable audit row is G4 — spec §6, NOT a gap), and the typed-event boundary (`feed()` makes no wire-trust decision; the forged-`ready` defense is G3-3b). MD032-clean.
- [ ] **Add the per-file 100%-line+branch CI coverage gate** for the new `src/alfred/gateway/link_state.py` + `client_listener.py` in `ci.yml` (python-job + combined gates), mirroring the existing `comms_socket_transport.py` entries (architect L2 — a new trust-boundary package needs its gate wired, not assumed).
- [ ] `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/ && uv run pytest tests/unit/gateway -q && npx markdownlint-cli2@0.14.0 docs/adr/0032-gateway-comms-resume-transport.md docs/superpowers/plans/2026-06-15-g3-3-alfred-gateway-process.md`
- [ ] `make check` (NOT piped through `tail`); ignore ONLY a local arm64 docker artifact if any (the `/lib64` fix is merged, so it should be clean).
- [ ] Commit the plan + ADR; open the PR; run the FULL `/review-pr` fleet (security ALWAYS) + CodeRabbit; **resolve every addressed CR thread** (the merge-unblock discipline — `resolveReviewThread`, NOT waiting for a re-review); merge `gh pr merge <n> --rebase --delete-branch`.

### G3-3a acceptance

- The link-state machine enforces the §9 invariant under hypothesis; an undefined transition fails loud.
- `GatewayClientListener` accepts a same-uid client + emits control frames; a mismatched-uid peer is refused (peer-auth reuse).
- New `src/alfred/gateway/` files at 100% branch (trust-boundary kernel); `make check` green.

---

## PR G3-3b — Core-link + relay + process (scope fixed; detailed plan written against G3-3a's merged reality)

**Goal:** The core-facing half + the runnable `alfred-gateway` process.

**Key tasks (all already architect/security plan-reviewed in the parent plan):**

- `GatewayCoreLink` (`src/alfred/gateway/core_link.py`): `dial_comms_socket` to the core; respond to the core's handshake as the peer (echo `AlfredSeqAck/1`, read the core's `epoch` from the start params). **Cite the EXACT merged constants, not prose method-names** (architect M2): the lifecycle methods are `DAEMON_LIFECYCLE_READY`/`DAEMON_LIFECYCLE_GOING_DOWN` (imported from `comms_mcp/protocol.py`, NOT `core.lifecycle.*`); ground the handshake-method name in the merged `comms_runner` constant rather than the spec's `lifecycle.start` prose — confirm the actual name when 3b is detailed. **Dial-side `SO_PEERCRED`** on the dialed core socket (the both-direction dial side G3-1 deferred — same `(OSError, struct.error)` + length-guard discipline). A **fake-clock-injectable** reconnect/backoff loop (initial ≥100–250 ms, exp to a 2–5 s ceiling, full jitter, never a 0-delay first retry). Consume `DAEMON_LIFECYCLE_GOING_DOWN`/`READY` → `LinkStateMachine.feed(...)` → `GatewayClientListener.send_control(...)`. **Always feed `redial_started` then `core_ready`** where possible, but G3-3a's machine tolerates `DOWN_* + core_ready` directly (architect H2), so a ready-before-redial_started race is safe. Decide whether `"gateway"` joins the `adapter_kind` frozenset here (for metrics/log labels — architect H3); it is NOT needed by the link.* frames (they carry no `adapter_id`).
- **Validate the lifecycle frame, don't trust it:** parse via the merged G1 `ReadyNotification`/`GoingDownNotification` Pydantic models (epoch pinned 32-hex, `reason` closed `Literal`) — fail-loud on a malformed frame; a forged `ready` past peer-auth with a mismatched epoch is rejected + audited (false `restored` is an attack surface), NOT fed as `core_ready`. The epoch CHECK ships here even though the buffer-flush it guards is G4.
- **Seq/ack deframe/reframe** (the first real peer): `decode_seq_frame` on the core leg / `encode_seq_frame` on the re-send, own per-leg `seq` + real `cumulative_ack` via `SeqDedupWindow` — NOT the `a=0` placeholder.
- The relay loop (`src/alfred/gateway/relay.py`): `client→core` + `core→client` as two pumped directions; opaque payload forwarded byte-for-byte; `id` preserved end-to-end. **No buffering** — a frame in flight across a core gap is dropped (G4 adds the buffer).
- Metrics (`src/alfred/gateway/metrics.py`, following `comms_mcp/observability.py`): `gateway_core_link_up`, `gateway_reconnect_attempts_total`, `gateway_core_unavailable_seconds`, `gateway_peer_auth_rejected_total`.
- `alfred gateway` CLI + `src/alfred/gateway/__main__.py` (registered like the `daemon` subcommand).
- **Non-root in-process wire-contract test** (#245 paper-gate hazard): in-process gateway↔fake-core exercising deframe/reframe + reconnect WITHOUT the root-only launcher gate.
- **Payload-blindness canary test** (spec §6 corpus (a)): the relay forwards a canary-T3-bearing payload byte-for-byte; the canary trips ONLY in the core.

**Coverage:** `GatewayClientListener` bind + core-frame ingest/containment 100% branch; ≥80% relay/core-link.

---

## Self-review (G3-3a)

- **Spec coverage:** §3 stable-kernel split (listener is the kernel) → G3-3a; §9 invariant (no `restored` without `reconnecting`) → the hypothesis property; the control frames (§4) → the three models. Core-link/relay/seq-ack (§4/§7) → G3-3b. ✓
- **Placeholders:** none in G3-3a — every step has real code/commands. G3-3b is scope-only (detailed against 3a's merged reality), each parent-plan-reviewed item captured as a named task. ✓
- **Type consistency:** `LinkStateMachine.feed(event: GatewayLinkEvent) -> LinkControl | None`; `GatewayLinkState`/`GatewayLinkEvent`/`LinkControl` StrEnums; `GatewayClientListener.send_control(notification)` — names consistent across tasks 1–3. ✓
- **CR discipline:** Task 4 explicitly resolves addressed CR threads (the merge-unblock learned this session), not waiting for a re-review. ✓

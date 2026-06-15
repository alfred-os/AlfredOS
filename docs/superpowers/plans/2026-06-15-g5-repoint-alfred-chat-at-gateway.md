# G5 — Re-point `alfred chat` at the Gateway + TUI Banners Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`. This is **G5** of the Spec A Comms-Resume Gateway (`docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md` §8). **G3 is fully merged** — the `alfred gateway` process (binds `comms-gateway.sock`, dials the daemon's `comms-tui.sock`, payload-blind relay, reconnect banner frames) is on `main`. G5 makes `alfred chat` dial the gateway instead of the daemon directly, renders the reconnect banners in the TUI, deletes the #259 direct-dial path (no dual-mode, per Spec A), and proves a REAL operator turn round-trips through the gateway — closing #237 graduation criterion #7 (transport substance).

**Goal:** `alfred chat` → `alfred gateway` → `alfred-core` daemon: a real operator turn round-trips through the gateway, and the TUI paints a reconnect/restored banner when the core link gaps — proving the resumable front door end-to-end in a real (non-fake-core) session.

**Architecture:** The foreground `alfred chat` (cohost) dials `comms-gateway.sock` (the gateway's bind) instead of `comms-tui.sock` (the daemon's bind). The gateway relays the operator turn to the daemon (which it dials over `comms-tui.sock`) and forwards the daemon's stubbed ack back. When the daemon link gaps, the gateway emits `link.reconnecting`/`link.restored` control frames; the cohost's wire pump routes them to the TUI app, which paints a banner. No dual-mode: the direct cohost→daemon dial is deleted.

**Tech Stack:** Python 3.12+, asyncio, AF_UNIX, Textual (the TUI), typer, structlog, pytest, testcontainers (real Postgres for the turn's audit row).

---

## Scope

**In G5:** re-point the cohost dial target `tui`→`gateway`; delete the #259 direct-dial path (no dual-mode); route the gateway's `link.*` control frames through the cohost wire pump into a TUI banner; a real-socket integration test (daemon + gateway + cohost over real sockets — a real turn + a banner-on-core-restart); the operator-config + runbook note for the daemon's `comms_enabled_adapters=("tui",)` prerequisite; the `alfred chat` friendly-error wiring for a gateway-absent dial.

**Deferred:** the full PTY smoke against `docker compose up` (the production stack — needs G3-4's Compose service; this PR proves the chain with an in-process/real-socket integration test, and the PTY smoke lands with G3-4/the deploy); G4 (ReplayBuffer/resume — so the interim no-resume window between #259 and G4 stands, noted per Spec A); a real persona REPLY (2c/#230 — the turn round-trips with the daemon's stubbed `{"content":"ack"}`).

---

## Design notes (read before any task — grounded in the G5 surface map)

### The re-point is a dial-target change + delete the direct path (no dual-mode)

`src/alfred/cli/main.py:365` calls `run_cohosted(adapter_id="tui")` → `dial_comms_socket("tui")` → `~/.run/alfred/comms-tui.sock` (the daemon's bind). G5 changes the dial target to `"gateway"` → `comms-gateway.sock` (the gateway's bind). Spec A §8 G5 mandates **"delete the #259 direct-dial path (no dual-mode)"** — so this is a HARDCODE to `"gateway"`, NOT a Settings toggle. The cohost is protocol-agnostic on `adapter_id` (it passes it only to the dial path; the wire `adapter_id` the gateway sends in `lifecycle.start` is `"tui"`, decoupled from the socket-path id `"gateway"` — the dual-identity invariant, ADR-0031). So changing the dial target does NOT touch the cohost's handshake-response or the turn shape. A gateway-absent dial surfaces as the existing `DaemonUnavailableError` → friendly `_chat_main` message + exit 3 (the message should now say "gateway", not "daemon" — see Task 2).

### The daemon TUI-socket prerequisite (a real scoping fact)

`alfred daemon start` binds `comms-tui.sock` ONLY when `Settings.comms_enabled_adapters` (`settings.py:154`, default `()`) includes an adapter whose carrier kind is `"tui"` (`_commands.py:357` `_is_socket_backed_adapter_kind` / `_SOCKET_BACKED_ADAPTER_KIND="tui"`). So the gateway can dial the daemon ONLY if the operator enabled the tui adapter. **G5 does NOT change the daemon default** (not every deployment wants the socket; a default change is a separate ops decision) — instead: (a) the integration test seeds `comms_enabled_adapters=("tui",)`; (b) a runbook / the ADR documents the operator must enable the tui adapter + run `alfred gateway start` before `alfred chat`. (The Compose deploy that wires this for production is G3-4.)

### The turn shape (round-trips with the stubbed ack — testable without 2c)

Operator keystroke → cohost emits an `inbound.message` NOTIFICATION (`cohost.py:100` `_make_socket_inbound_sink`) → the gateway relays it opaquely to the daemon → `process_inbound_message` → `CommsInboundOrchestratorAdapter.dispatch` sends an `outbound.message` REQUEST with the stubbed `_ACK_BODY={"content":"ack"}` (`daemon_runtime.py:86`) → the gateway relays it to the cohost → the cohost's `TuiServer` answers it → the response relays back. So a full turn round-trips with the stubbed ack — provable WITHOUT a real persona reply (2c/#230). The G5 integration test drives exactly this through the real daemon+gateway+cohost chain.

### TUI banners — route `link.*` control frames to the app

The gateway sends id-less `link.reconnecting`/`link.restored`/`link.unavailable` notifications (the merged `LINK_*` constants) to the client on a core gap/restore. Today the cohost's wire pump (`cohost.py:_serve_wire` ~124) routes daemon REQUESTS to `TuiServer.dispatch` + resolves RESPONSES — but `link.*` are notifications the gateway ORIGINATES (not the daemon's requests). G5 adds a route: the wire pump recognizes the `link.*` methods and calls into the TUI app to set a banner state (reconnecting → show "Reconnecting…"; restored → clear it; unavailable → show "Core unavailable"). The banner is the client's OWN localized render (`t()` against `{user.language}` — the gateway sends only the state, per the merged `link.*` design). This is the Textual UI work + the wire-route.

---

## Plan-review findings — MUST be applied (architect + comms, 2026-06-15)

**The big one (comms C1/C2 — CRITICAL):** the gateway and the cohost were built to a shared spec but **NEVER connected** — G5 is the first time they speak. The gateway's `client_handshake` (`client_link.py`) SENDS `lifecycle.start` with params `{adapter_id:"tui", seq_ack:{version:SEQ_VERSION}}` and validates the result with STRICTER-than-runner checks (`LifecycleStartResult.model_validate`: `extra="forbid"`, requires `plugin_version` + `ok`). The cohost's `TuiServer._handle` returns `LifecycleStartResult(ok=True, plugin_version=__version__)` and validates the incoming params via `LifecycleStartRequest.model_validate`. **This exact handshake has never run.** → **Task 0 (NEW, de-risk FIRST):** a focused unit test that the cohost's `TuiServer.dispatch` accepts the gateway's EXACT `lifecycle.start` params shape AND returns a result that passes the gateway's strict `LifecycleStartResult` validation — the real wire contract between the two peers, asserted in isolation before the full chain. Task 4 then asserts the handshake COMPLETES (the `client_handshake` returns) before the turn, not just the turn by luck.

Other folded findings, by task:

- **Task 1 (H1 + architect M1):** route `link.*` in `_serve_wire` BEFORE `server.dispatch` — do NOT add `link.*` to `TuiServer._METHODS` (it would pollute the plugin's closed method set / manifest surface). The branch is a NARROW allowlist (`LINK_RECONNECTING`/`RESTORED`/`UNAVAILABLE` only); an UNKNOWN id-less notification (incl. the daemon's `daemon.lifecycle.*` broadcast) STILL falls through to the existing dispatch→`None` skip — assert both (a `link.*` → callback, NOT dispatch; a `daemon.lifecycle.*`/unknown id-less → still the existing skip, NOT the banner). Assert `link.reconnecting` is ABSENT from `TuiServer.list_methods()`. The `link.*` frames are client-TERMINAL — never relayed/acked back.
- **Task 1/3 (M2):** ground the three banner states against what the merged `GatewayCoreLink` ACTUALLY emits — it emits `reconnecting`/`restored` on a core gap/restore; `link.unavailable` is the **G4** trigger (ReplayBuffer cap-breach). So render all three (cheap, vocab-complete) but UNIT-test `unavailable` at the callback only; Task 4 asserts ONLY `reconnecting`→`restored` through the real chain. State the `unavailable`-render-ahead-of-its-G4-trigger explicitly (honesty on the banner surface).
- **Task 2 (architect M2 + L2 + L3 + M4):** (a) do NOT touch the DAEMON-side `_SOCKET_BACKED_ADAPTER_KIND="tui"` (`_commands.py:354`) — only the CHAT CLIENT's dial target moves; the daemon still binds `comms-tui.sock`. (b) Use the shared `_GATEWAY_ADAPTER_ID="gateway"` constant from `client_listener.py` (not a bare literal) so dial-id == bind-id provably. (c) The no-dual-mode grep MUST cover the SECOND chat entry `plugins/alfred_tui/src/alfred_tui/server.py:serve()` (it also calls `run_cohosted(adapter_id=_ADAPTER_KIND="tui")`) — re-point it too or the no-dual-mode invariant has a hole. (d) Register the new/renamed `t()` keys in the active key-allowlist (`SLICE_4_KEYS` / `_slice_4_reserve.py` per the established 3-places pattern) or the catalog drift gate fails CI.
- **Task 4 (C1 + H2 + M3):** (a) assert the gateway↔cohost handshake COMPLETES before the turn (C1). (b) assert `client_seq_enabled is False` on the real chain — the production TUI is PLAIN; a cohost echoing `seq_ack` would be the G2 echo-without-deframe CRITICAL (H2). (c) The merged `GatewayProcess` constructs `GatewayCoreLink` internally with NO sleep/jitter seam injection → a real-process test gets production backoff (full jitter, real sleeps) → flaky reconnect polling. **Resolve (M3):** prefer driving `GatewayCoreLink` directly in the test with injected `sleep`/`jitter` (deterministic) rather than the full `GatewayProcess`, OR add an optional `sleep`/`jitter` injection param to `GatewayProcess` for the test. Decide + state; poll with a bounded retry, never wall-clock.
- **Task 5 (H3 + L1/architect-L2):** the runbook MUST enumerate the THREE failure modes the deleted direct-dial now hides: (a) gateway down → "start the gateway" + exit 3; (b) gateway up but daemon down → a `link.unavailable`/reconnect banner, no turn echoes; (c) daemon up but the tui adapter not enabled → the gateway's core dial fails → also a banner. The `alfred chat` error stays HONEST ("can't reach the gateway") and does NOT overclaim to diagnose (b)/(c) — those are the gateway's own logs. Record the amendment in **ADR-0031** (it owns the dial-target/dual-identity/Shape-A cohost contract), cross-referencing ADR-0032 for the codec-blindness of the `link.*` frames.

---

## Tasks

- [ ] **Task 0: validate the (never-exercised) gateway↔cohost `lifecycle.start` handshake contract (TDD — de-risk FIRST)**

**Files:** Test: `plugins/alfred_tui/tests/test_server_methods.py` (or a new `test_gateway_handshake_contract.py`).

- [ ] Step 1 — failing test: build the EXACT `lifecycle.start` params the gateway's `client_link.client_handshake` sends — `{adapter_id:"tui", seq_ack:{version:SEQ_VERSION}}` — and assert `TuiServer.dispatch(lifecycle.start, params)` (a) ACCEPTS them (`LifecycleStartRequest.model_validate` succeeds — relies on the merged ADR-0035 optional credentials) and (b) returns a result mapping that PASSES the gateway's strict validation: `LifecycleStartResult.model_validate(result)` succeeds with `ok is True` + a non-empty `plugin_version` + `extra="forbid"` satisfied. (This is the wire contract between the two merged-but-never-connected peers — exercise it in isolation.)
- [ ] Step 2 — run, expect PASS or FAIL: if it FAILS, the contract is genuinely broken (e.g. the cohost rejects the gateway's params, or returns a `seq_ack` field the gateway's strict result-validation forbids) — that is a real G5 blocker to fix HERE (in the cohost's handshake response) before re-pointing. If it PASSES, the contract composes and Task 4 can rely on it.
- [ ] Step 3 — if a fix is needed, make the cohost's `lifecycle.start` response gateway-compatible (minimal); else this task is the contract-pinning test only. Step 5 — commit (`test(tui): pin the gateway↔cohost lifecycle.start handshake contract (Spec A G5) (#237)` + trailer + any fix).

- [ ] **Task 1: route `link.*` control frames in the cohost wire pump → a banner callback (TDD)**

**Files:** `plugins/alfred_tui/src/alfred_tui/cohost.py` (the wire pump) + the TuiSession/app banner seam; Test: `plugins/alfred_tui/tests/test_cohost.py` + `test_server_methods.py`.

- [ ] Step 1 — failing test: feed the cohost wire pump an id-less `{"method":"link.reconnecting","params":{}}` frame (and `link.restored`/`link.unavailable`) → assert it does NOT route to `TuiServer.dispatch` as a normal request, and instead invokes a `on_link_state(LinkState)` callback (the banner seam) with the right state; a normal daemon request (`outbound.message`) still routes to dispatch; a response frame still resolves. Import the `LINK_*` constants from `alfred.comms_mcp.protocol`.
- [ ] Step 2 — FAIL. Step 3 — implement: in `_serve_wire` (or the pump), branch on the method: a `LINK_RECONNECTING`/`LINK_RESTORED`/`LINK_UNAVAILABLE` notification → `await on_link_state(...)` (a callback injected into the cohost, default a no-op for the non-banner tests); everything else unchanged. Keep the cohost protocol-agnostic on `adapter_id`.
- [ ] Step 4 — PASS. Step 5 — commit (`feat(tui): route gateway link.* control frames to a banner callback in the cohost pump (Spec A G5 / ADR-0031) (#237)` + trailer).

- [ ] **Task 2: re-point the cohost dial target tui→gateway + delete the direct-dial path (TDD)**

**Files:** `src/alfred/cli/main.py` (`_chat_main`), `plugins/alfred_tui/src/alfred_tui/cohost.py`; Test: `tests/unit/cli/test_chat_daemon_required.py` + a new dial-target test.

- [ ] Step 1 — failing test: `_chat_main` dials `comms-gateway.sock` (assert `run_cohosted` is called with `adapter_id="gateway"`, or the dial resolves the gateway socket path); a gateway-absent dial → `DaemonUnavailableError` mapped to the friendly "start the gateway" message + exit 3 (the message now references the GATEWAY — update the `t()` key/text). No `"tui"` direct-dial path remains (Spec A no-dual-mode — grep that nothing still dials `adapter_id="tui"` from the chat path).
- [ ] Step 2 — FAIL. Step 3 — implement: `main.py:365` `run_cohosted(adapter_id="gateway")`; update the `_chat_main` docstring (it currently says "dial the running daemon's comms socket" → "dial the running gateway's comms socket"); update the daemon-required friendly message + `t()` key to "gateway-required" (and note `alfred gateway start`). Delete any direct-daemon-dial fallback. i18n: `pybabel update -i ... --no-fuzzy-matching` + compile for the changed/new key.
- [ ] Step 4 — PASS. Step 5 — commit (`feat(cli): alfred chat dials the gateway, not the daemon — no dual-mode (Spec A G5) (#237)` + trailer + catalog).

- [ ] **Task 3: TUI banner render for the link states (TDD)**

**Files:** the Textual app in `plugins/alfred_tui/src/alfred_tui/` (the app/widget that shows the banner) + wire the Task-1 `on_link_state` callback to it; Test: `plugins/alfred_tui/tests/` (a Textual app-level test of the banner state).

- [ ] Step 1 — failing test: the TUI app, on `on_link_state(reconnecting)`, shows a banner widget with the reconnecting text (a `t()` string against `{user.language}`); on `restored`, clears it; on `unavailable`, shows the unavailable text. (Use Textual's test harness / a headless app run; assert the banner widget's visibility/text.)
- [ ] Step 2 — FAIL. Step 3 — implement: a banner widget (or a reactive state) on the app; the `on_link_state` callback (threaded from the cohost into the app) sets it; the banner text via `t("tui.banner.reconnecting"/"restored"/"unavailable")`. The gateway sends only the STATE; the TUI renders its own localized banner (the merged `link.*` design). i18n keys added.
- [ ] Step 4 — PASS. Step 5 — commit (`feat(tui): render the gateway reconnect/restored/unavailable banner (Spec A G5) (#237)` + trailer + catalog).

- [ ] **Task 4: real-socket end-to-end integration test — a turn + a banner through the real chain (TDD)**

**Files:** Test: `tests/integration/cli/daemon/test_chat_gateway_socket_turn.py` (or `tests/integration/gateway/`).

- [ ] Step 1 — failing test (real sockets, real Postgres via testcontainers — reuse the `test_daemon_comms_inbound_turn.py` harness shape): boot a real daemon with `comms_enabled_adapters=("tui",)` seeded (so it binds `comms-tui.sock`); start a real `GatewayProcess` (dials `comms-tui.sock`, binds `comms-gateway.sock`); run a real cohost dialing `comms-gateway.sock`. Drive a turn: the cohost emits an `inbound.message` → it reaches the daemon (assert the T3-promotion audit row lands in Postgres) → the daemon's stubbed ack `outbound.message` relays back through the gateway → the cohost receives it. THEN: gap the daemon link (stop/restart the daemon socket) → assert the cohost receives `link.reconnecting` then `link.restored` (the banner-driving frames) AND the held cohost connection survives (single-accept-for-life). This is the substance of #237 criterion #7 through the REAL chain (stubbed ack; real reply is 2c).
- [ ] Step 2 — FAIL. Step 3 — wire the harness (daemon boot + gateway process + cohost, all real sockets under a tmp `$HOME`; poll for the audit row + the banner frames, no wall-clock). Step 4 — PASS. Step 5 — commit (`test(integration): real alfred chat turn + reconnect banner through the gateway (Spec A G5) (#237)` + trailer).

- [ ] **Task 5: ADR + runbook + CI gate + full gate + open PR**

- [ ] ADR-0031 amendment (or a short G5 note in ADR-0032): record the re-point (no dual-mode — the direct-dial path deleted), the TUI banner contract (the gateway sends state, the TUI renders its own localized banner), the daemon `comms_enabled_adapters=("tui",)` prerequisite, and the criterion-#7-transport-substance-closed-here / real-reply-2c / production-deploy-G3-4 framing + the interim no-resume window (G4). MD032-clean.
- [ ] Runbook: a short `docs/runbooks/` note (or extend an existing comms runbook) — the operator sequence: enable the tui adapter (`comms_enabled_adapters=("tui",)`) → `alfred daemon start` → `alfred gateway start` → `alfred chat`.
- [ ] CI: any new trust-boundary file at its coverage gate (the cohost/TUI changes are plugin-package — follow the plugin test conventions; the integration test runs in the integration CI leg).
- [ ] `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/ && uv run pytest tests/unit plugins/alfred_tui/tests -q && uv run pytest tests/integration/cli/daemon/test_chat_gateway_socket_turn.py -q && npx markdownlint-cli2@0.14.0 docs/adr/0031-*.md docs/superpowers/plans/2026-06-15-g5-repoint-alfred-chat-at-gateway.md`
- [ ] `make check` (NOT piped through `tail`). Commit the plan + ADR + runbook; open the PR; run the FULL `/review-pr` fleet (security ALWAYS + comms, error, test, performance, docs, i18n, devex, architect; conditional: comms-engineer for the wire-route, devex for the operator UX) + CodeRabbit; **resolve every addressed CR thread**; auto-merge `gh pr merge <n> --auto --rebase --delete-branch` (NO `--admin`).

---

## Acceptance

- `alfred chat` dials `comms-gateway.sock` (not the daemon directly); the direct-dial path is gone (no dual-mode).
- A real operator turn round-trips `cohost → gateway → daemon → stubbed ack → cohost` (proven in the real-socket integration test against real Postgres — the audit row lands).
- The TUI paints a reconnect banner when the core link gaps and clears it on restore (the gateway's `link.*` frames → the cohost pump → the app banner).
- The operator-config prerequisite (`comms_enabled_adapters=("tui",)`) + the start sequence are documented.
- `make check` green; the criterion-#7 transport substance is closed end-to-end (real reply = 2c; production deploy = G3-4; resume = G4 — the interim no-resume window noted).

---

## Self-review

- **Spec coverage:** Spec A §8 G5 — re-point to the gateway (Task 2), delete the direct-dial path / no dual-mode (Task 2), banners (Tasks 1+3), the smoke (Task 4 real-socket integration; the PTY-against-Compose smoke is G3-4-gated, noted). The interim no-resume window (G4) noted in the ADR. ✓
- **Grounded in the map:** `main.py:365` dial target, `cohost.run_cohosted`/`_serve_wire`/`_make_socket_inbound_sink`, `TuiServer.dispatch`, the `LINK_*` constants, `_ACK_BODY`, the `comms_enabled_adapters`/`_is_socket_backed_adapter_kind` prerequisite, the `test_daemon_comms_inbound_turn` harness — all cited. ✓
- **Scoping facts surfaced:** the daemon-socket-not-default prerequisite (test seeds + ops doc, no default change); no-dual-mode hardcode (Spec A); the stubbed-ack turn (2c-independent); the deferred PTY/Compose smoke (G3-4) + resume (G4). ✓
- **Placeholders:** none — each task has real file refs + tests + commands. The banner Textual specifics are grounded in the app structure (Task 3 reads the app first). ✓
- **CR discipline:** Task 5 resolves addressed CR threads. ✓
- **Honesty:** G5 closes criterion #7's TRANSPORT substance (real turn through the gateway); the real persona reply is 2c/#230, the production Compose deploy is G3-4, resume is G4 — stated, not overclaimed. ✓

# G3-3b-2b — The `alfred gateway` Process + CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`. Final PR of G3-3b-2 (parent: `2026-06-15-g3-3b2-gateway-relay-process.md`; **G3-3b-2a / #273 is MERGED** — the opaque relay engine: `read_payload_unit`/`send_payload_unit`, `GatewayCoreLink` raw-unit relay sink + `relay_to_core`, `GatewayRelay`, `BoundedSeqAckTracker`, the non-root wire-contract gate are on `main`). This PR wraps the merged relay engine in a runnable, supervised process + the `alfred gateway` CLI.

**Goal:** Ship the runnable `alfred gateway` process — bind the client socket, accept the dial-in client, run the client-leg HOST handshake, wire the merged `GatewayCoreLink` + `GatewayRelay`, supervise both relay directions, and expose `alfred gateway start|status`. Prove a real client↔core turn round-trips through the gateway process end-to-end (the substance of #237 criterion #7; production `alfred chat` re-pointing is G5).

**Architecture:** `GatewayProcess` mirrors the daemon's socket-carrier pattern (`_listen_socket_comms_adapter`): bind a `GatewayClientListener` inline (fail-closed), accept ONE client (single-accept-for-life), run the client-leg HOST handshake, then supervise `GatewayRelay.run()` (which drives `core_link.run()` — core dial/handshake/reconnect/pump — + the client→core pump) under one `asyncio.TaskGroup` with a shared `shutdown_event`, reaping every transport + the listener on every exit. The gateway is HOST toward the TUI (sends `lifecycle.start`) and PEER toward the core (responds to its `lifecycle.start` — merged).

**Tech Stack:** Python 3.12+, asyncio, AF_UNIX, Pydantic v2, typer, structlog, prometheus_client, pytest, mypy --strict + pyright.

---

## Scope

**In G3-3b-2b:** the injectable `on_peer_rejected` + a `transport` getter on `GatewayClientListener`; the `gateway_peer_auth_rejected_total` metric; the client-leg HOST handshake; `GatewayProcess`; the `alfred gateway` CLI (`start`/`status`) + registration; an end-to-end smoke proving a real turn through the process; i18n for the operator strings.

**Deferred:** `ReplayBuffer`/resume + the durable signed gateway audit reconcile (G4); the Compose service + long-running core daemon + shared-volume socket relocation (G3-4); **re-pointing `alfred chat` from `comms-tui.sock` → `comms-gateway.sock` + the production PTY smoke (G5)** — so #237 criterion #7 is **PROVEN end-to-end at the process level here** (a real turn through the gateway) and **production-wired in G5**; the egress proxy (Spec C); the per-frame `_read_or_shutdown` task-churn optimization (deferred from 2a — needs core-engineer vetting).

---

## Design notes (read before any task)

### The client-leg HOST handshake + the `LifecycleStartRequest` over-spec (root-cause fix, NOT a sentinel)

The gateway is HOST on the client leg: it sends `lifecycle.start` to the dialed-in TUI. The TUI validates the params via `LifecycleStartRequest.model_validate(params)` (`plugins/alfred_tui/src/alfred_tui/server.py:120`), and `LifecycleStartRequest` (`src/alfred/comms_mcp/protocol.py:165`) currently REQUIRES `credentials_ref: str (min_length=1)` + `policies_snapshot_hash: str (min_length=1)`.

**Root cause (plan-review architect H1 — verified):** NO producer ever sends those two fields. The merged HOST runner (`comms_runner._handshake`) sends only `{adapter_id, seq_ack, epoch?}`; the daemon never constructs `LifecycleStartRequest` for the wire (the only `policies_snapshot_hash` in `_commands.py` is a `daemon.boot.completed` AUDIT field, unrelated). Only ONE consumer validates the model (the TUI, `server.py:120`), and it then reads ONLY `start_req.adapter_id` — it DISCARDS `credentials_ref`/`policies_snapshot_hash`. So the model is **over-specified**: it requires two fields no producer sends and the sole consumer ignores. This is why the merged **daemon→TUI** socket handshake would ALSO fail validation today (a latent bug — the TUI socket adapter was never driven e2e; criterion #7 unmet).

**The fix is to RELAX the model (Task 0), NOT to send a sentinel `credentials_ref`** (a sentinel in a credential-named field is a foot-gun + a hard-rule-#6 precedent smell; the root cause is the model, not the sender). `LifecycleStartRequest.credentials_ref` + `policies_snapshot_hash` become `str | None = None` (adapter-dependent — the TUI leg has no credentials; if a future credential-bearing adapter needs them, the HOST supplies them, but they are not universally required). This fixes BOTH the gateway→TUI AND the merged daemon→TUI path, with no sentinel. It is a shared wire-contract change → its own dedicated ADR (Task 0) + a security-review callout (the field-name `credentials_ref` going optional must NOT weaken Discord's credential handling — confirmed: Discord credentials flow through the secret broker at the tool-call boundary, NOT via `lifecycle.start` params, and the Discord/reference plugins do not validate `LifecycleStartRequest`).

So the gateway-as-HOST handshake sends the SAME shape as the merged runner (now valid against the relaxed model):

- `adapter_id="tui"` (NOT `"gateway"` — the `AdapterId` frozenset is `{"alfred_comms_test","discord","tui"}`; the gateway stands in for the daemon toward an unmodified TUI that only knows kind `"tui"`).
- `seq_ack={"version": SEQ_VERSION}`: the gateway advertises seq/ack. The real TUI returns `seq_ack=None` → the gateway leaves the client transport PLAIN (`client_seq_enabled=False`). A future seq/ack-capable client echoes it → `enable_seq_ack()` + `client_seq_enabled=True`. The half-negotiated gate (enable IFF echoed) is load-bearing (assert `enable_seq_ack` is NOT called on the `seq_ack=None` path — security L1).
- NO `credentials_ref`/`policies_snapshot_hash` (relaxed-optional), NO `epoch` (the gateway is not a core boot — comms L2).

Read the result, validate `result.ok` truthy + `plugin_version` present (mirror `comms_runner._handshake`'s read side) with a **bounded pre-ack frame cap** (security M1 — the merged `_read_until_start` warn-and-drops UNBOUNDED; the client is same-uid-trusted but a "trust boundary" plan caps it: drop at most `_MAX_PRE_ACK_FRAMES` non-matching frames then fail-closed, inheriting the per-frame `_MAX_COMMS_LINE_BYTES` bound). A not-ok / EOF / over-cap / malformed ack is a fail-closed `GatewayHandshakeError` (the client is unusable → the process refuses / tears down loud).

### `GatewayClientListener` needs two small seams (architect §6 + the relay)

The merged `GatewayClientListener.__init__` (`client_listener.py:93`) HARDCODES `on_peer_rejected=_structlog_only_peer_rejected` and stores the accepted transport in a private `_transport` with NO getter. 2b adds:

- an injectable `on_peer_rejected: Callable[[int | None], Awaitable[None]] | None = None` ctor param (default to the existing `_structlog_only_peer_rejected` stub) so `GatewayProcess` injects a callback that increments `gateway_peer_auth_rejected_total` + logs `peer_uid` (keep the CALLBACK shape — preserves `peer_uid` for the structlog row + the G4 audit row; arch-263-001). The durable signed reject audit row stays G4 (no audit sink yet).
- a `transport` property (`@property def transport(self) -> CommsSocketTransport | None`) exposing the accepted transport so `GatewayProcess` hands it to `GatewayRelay` (which needs `read_payload_unit`/`send_payload_unit`). `send_control` keeps using the internal `_transport` (the link-state frames).

### `GatewayProcess` lifecycle (mirror the daemon socket-carrier)

```text
async def run(self) -> None:
  bind the GatewayClientListener (fail-closed on OSError — refuse loud)
  try:
    accept ONE client, racing the shutdown_event (a shutdown before a client connects → clean return)
    run the client-leg HOST handshake on listener.transport → client_seq_enabled
    core_link = GatewayCoreLink(client_listener=listener, shutdown_event=self._shutdown_event, ...)
    relay = GatewayRelay(core_link=core_link, client_transport=listener.transport, client_seq_enabled=...)
    await relay.run()   # TaskGroup: core_link.run() (dial+handshake+reconnect+pump) + client→core pump
  finally:
    await listener.aclose()   # reaps the accepted transport + the socket file (every exit path)
```

- **Single-accept-for-life:** the client connection is held across core gaps (the merged listener never re-accepts; all reconnect churn is on the core leg). A client EOF ends the relay → the process tears down (the client hung up).
- **Fail-closed boot:** a listener bind failure (`OSError`) or a client-handshake failure refuses loud — the process does not run a half-wired relay (hard rule #7).
- **Shutdown:** a shared `asyncio.Event`; `GatewayCoreLink`/`GatewayRelay` already observe it (the merged `_read_or_shutdown`/`_sleep_or_shutdown` + the TaskGroup). The CLI wires a SIGTERM/SIGINT handler to set it.
- **No core dial until a client connects?** Decide: the gateway dials the core only AFTER accepting a client (the relay needs both legs) — so `core_link.run()` starts inside `relay.run()` AFTER accept. (A core-down-at-start is handled by the merged reconnect/backoff, so the process comes up + waits.)

### CLI + entry point

`alfred gateway start` (long-running: build + run `GatewayProcess` under `asyncio.run`, with a signal handler setting the shutdown event) + `alfred gateway status` (a light health line — is the `comms-gateway.sock` present + the runtime dir posture, mirroring `alfred daemon status`'s Settings-only surface). Register `app.add_typer(gateway_app, name="gateway")` in `cli/main.py`. Lazy heavy imports inside the command callbacks (perf-001 — `alfred --help` must not pull the relay graph). All operator strings via `t()`. (No `__main__.py` — the CLI is the entry, matching `alfred daemon`.)

---

## Tasks

- [ ] **Task 0: relax `LifecycleStartRequest` over-spec + dedicated ADR (TDD) — the root-cause fix (architect H1)**

**Files:** `src/alfred/comms_mcp/protocol.py`; Create: `docs/adr/0035-lifecycle-start-credentials-optional.md`; Test: `tests/unit/comms_mcp/test_protocol_schemas.py`.

- [ ] Step 1 — failing tests: `LifecycleStartRequest.model_validate({"adapter_id": "tui", "seq_ack": {"version": SEQ_VERSION}})` SUCCEEDS (no `credentials_ref`/`policies_snapshot_hash`) — the shape the merged runner + the gateway actually send; a request WITH them still validates (back-compat for any future credential-bearing adapter); `extra="forbid"` still rejects an unknown field.
- [ ] Step 2 — run, expect FAIL (today the model requires the two fields).
- [ ] Step 3 — implement: `credentials_ref: str | None = None`, `policies_snapshot_hash: str | None = None` in `LifecycleStartRequest`. Update the class docstring to note they are adapter-dependent (the TUI leg has none; the secret broker — NOT this field — carries real adapter credentials at the tool-call boundary, hard rule #6). Write `docs/adr/0035-...` (one decision: the two fields are optional because no producer sends them + the sole strict consumer (the TUI) discards them; this also fixes the latent daemon→TUI handshake; the secret-broker credential path is unchanged). MD032-clean.
- [ ] Step 4 — run, expect PASS (incl. the existing protocol-schema tests — confirm no other consumer relied on the required-ness). Step 5 — commit (`fix(comms): LifecycleStartRequest credentials_ref/policies_snapshot_hash optional — no producer sends them (ADR-0035, Spec A G3-3b-2b) (#237)` + trailer + the ADR).

- [ ] **Task 1: `GatewayClientListener` injectable `on_peer_rejected` + `transport` getter (TDD)**

**Files:** `src/alfred/gateway/client_listener.py`; Test: `tests/unit/gateway/test_client_listener.py`.

- [ ] Step 1 — failing tests: `GatewayClientListener(on_peer_rejected=<cb>)` routes a same-uid-mismatch reject to the injected `<cb>` (not the stub); the default ctor still uses `_structlog_only_peer_rejected`; after `accept()`, `.transport` returns the accepted `CommsSocketTransport` (and `None` before accept).
- [ ] Step 2 — run, expect FAIL.
- [ ] Step 3 — implement: add `on_peer_rejected: Callable[[int | None], Awaitable[None]] | None = None` to `__init__` (default → `_structlog_only_peer_rejected`), thread it into the composed `CommsSocketListener`; add the `transport` property. Keep `send_control`/`aclose` unchanged.
- [ ] Step 4 — run, expect PASS. Step 5 — commit (`feat(gateway): injectable on_peer_rejected + transport getter on GatewayClientListener (Spec A G3-3b-2b) (#237)` + trailer).

- [ ] **Task 2: `gateway_peer_auth_rejected_total` metric (TDD)**

**Files:** `src/alfred/gateway/metrics.py`; Test: `tests/unit/gateway/test_metrics.py`.

- [ ] Step 1 — failing test: `alfred.gateway.metrics.PEER_AUTH_REJECTED` is a `Counter` exposing `gateway_peer_auth_rejected_total`.
- [ ] Step 2 — FAIL. Step 3 — implement `PEER_AUTH_REJECTED = Counter("gateway_peer_auth_rejected", "Count of client-leg SO_PEERCRED peer-uid rejections.")` + `__all__`. Step 4 — PASS. Step 5 — commit (`feat(gateway): gateway_peer_auth_rejected_total metric (Spec A G3-3b-2b) (#237)` + trailer).

- [ ] **Task 3: client-leg HOST handshake (TDD)**

**Files:** Create `src/alfred/gateway/client_link.py` — `client_handshake(transport) -> bool` (returns `client_seq_enabled`) + `GatewayHandshakeError`; Test: `tests/unit/gateway/test_client_link.py`.

- [ ] Step 1 — failing tests over a fake/loopback transport playing the TUI PEER:
  - the gateway sends `lifecycle.start` with params `{adapter_id:"tui", seq_ack:{version:SEQ_VERSION}}` (NO credentials_ref/policies_snapshot_hash — relaxed in Task 0; NO epoch) — assert `LifecycleStartRequest.model_validate(sent_params)` SUCCEEDS;
  - the TUI returns `LifecycleStartResult(ok=True, plugin_version="x", seq_ack=None)` → `client_handshake` returns `False` (plain leg), `enable_seq_ack` NOT called (security L1 — assert this hard);
  - a seq/ack-capable client (`seq_ack={"version": SEQ_VERSION}`) → returns `True` + `enable_seq_ack()` called (forward-looking);
  - a not-ok result / EOF before the ack / malformed result → raises `GatewayHandshakeError` (fail-closed);
  - **bounded pre-ack cap (security M1):** a peer that streams `_MAX_PRE_ACK_FRAMES + 1` non-matching frames before the ack → `GatewayHandshakeError` (does not loop forever; inherits the per-frame `_MAX_COMMS_LINE_BYTES` bound).
- [ ] Step 2 — FAIL. Step 3 — implement: `transport.send({"jsonrpc":"2.0","id":0,"method":"lifecycle.start","params":{"adapter_id":"tui","seq_ack":{"version":SEQ_VERSION}}})`, read frames until the matching `id` (capped at `_MAX_PRE_ACK_FRAMES`), validate `result.ok` + `plugin_version`; gate `enable_seq_ack()` on the echoed `seq_ack.version`. Mirror `comms_runner._handshake`'s read side + the cap. Step 4 — PASS. Step 5 — commit (`feat(gateway): client-leg HOST lifecycle.start handshake (Spec A G3-3b-2b / ADR-0031) (#237)` + trailer).

- [ ] **Task 4: `GatewayProcess` — bind/accept/handshake/supervise/reap (TDD)**

**Files:** Create `src/alfred/gateway/process.py` — `GatewayProcess`; Modify `src/alfred/gateway/__init__.py`; Test: `tests/unit/gateway/test_process.py`.

- [ ] Step 1 — failing tests (in-process, real loopback client + a fake/real core listener, mirroring the 2a wire-contract harness):
  - `run()` binds the client socket, accepts a loopback client, runs the client handshake, then relays a real turn (client→core payload byte-for-byte; core→client payload byte-for-byte) — the e2e relay through the process;
  - a `shutdown_event` set BEFORE a client connects → `run()` returns cleanly (no core dial, listener reaped);
  - a `shutdown_event` set mid-relay → `run()` returns promptly, every transport + the listener reaped (no FD/socket leak — assert the socket file is unlinked);
  - a client-handshake failure (`GatewayHandshakeError`) → `run()` refuses loud + reaps (fail-closed);
  - a listener bind `OSError` → loud refuse;
  - the injected `on_peer_rejected` increments `gateway_peer_auth_rejected_total` on a mismatched-uid client (monkeypatch `_resolve_peer_uid`).
- [ ] Step 2 — FAIL.
- [ ] Step 3 — implement `GatewayProcess(*, shutdown_event, dial_adapter_id="tui", ...)` per the lifecycle skeleton above: bind (fail-closed), accept-racing-shutdown, client handshake, build `GatewayCoreLink(client_listener=listener, shutdown_event=...)` + `GatewayRelay(core_link, client_transport=listener.transport, client_seq_enabled=...)`, `await relay.run()`, `finally: await listener.aclose()`. Wire the `on_peer_rejected` → metric callback. Export `GatewayProcess`.
- [ ] Step 4 — PASS. Step 5 — commit (`feat(gateway): GatewayProcess — bind/accept/handshake/supervise/reap (Spec A G3-3b-2b / ADR-0031) (#237)` + trailer).

- [ ] **Task 5: `alfred gateway` CLI + registration (TDD)**

**Files:** Create `src/alfred/cli/gateway/__init__.py` (`gateway_app`) + `src/alfred/cli/gateway/_commands.py`; Modify `src/alfred/cli/main.py`; Test: `tests/unit/cli/test_gateway_cli.py` + extend the lazy-import + subapp-in-help tests.

- [ ] Step 1 — failing tests: `alfred gateway` appears in `alfred --help`; `alfred gateway start` builds + runs a `GatewayProcess` (mock the process `run` to assert it is constructed + awaited under `asyncio.run` with a signal-wired shutdown event); `alfred gateway status` prints a `t()`-routed health line (socket presence / runtime-dir posture) + exits 0; importing `alfred.cli.main` does NOT eagerly pull `alfred.gateway.relay` (the lazy-import discipline, mirror `test_main_lazy_imports.py`).
- [ ] Step 2 — FAIL.
- [ ] Step 3 — implement `gateway_app = typer.Typer(help=t("gateway.help.root"))` with `start`/`status` commands (lazy imports inside callbacks → `_commands.start_gateway()` / `status_gateway()`); `start_gateway()` builds the shutdown event + a SIGTERM/SIGINT handler + `asyncio.run(GatewayProcess(...).run())`. **Signal-handler robustness (security M2):** `loop.add_signal_handler` can raise `NotImplementedError`/`ValueError` (non-main-thread / unsupported platform) — on failure, log loud and fall back to letting `asyncio.run` translate `KeyboardInterrupt` into a cancel (the gateway has no supervisor fallback like the daemon); CRITICALLY, `GatewayProcess.run`'s `finally: listener.aclose()` MUST run on the `asyncio.run` CANCEL/`KeyboardInterrupt` unwind, not only the event-driven clean return — assert this with a test that cancels `run()` mid-relay and checks the socket file is unlinked. `status_gateway()` is a Settings-only health line — `Path.exists()` + stat of `comms-gateway.sock` + the 0700 runtime-dir posture; it MUST NEVER dial or read the socket (security L3 — no un-authenticated wire read). Register `app.add_typer(gateway_app, name="gateway")` in `main.py`. All strings via `t()`.
- [ ] Step 4 — PASS. Step 5 — i18n: `pybabel extract` + `pybabel update -i locale/alfred.pot -d locale -D alfred --no-fuzzy-matching` (NEVER `--omit-header`), translate the new `gateway.*` keys, `pybabel compile -d locale -D alfred`; confirm `pybabel update --check` passes. Commit (`feat(cli): alfred gateway start|status command (Spec A G3-3b-2b) (#237)` + trailer + the catalog).

- [ ] **Task 6: end-to-end smoke — a real turn through the gateway process (TDD)**

**Files:** Test: `tests/unit/gateway/test_process_e2e.py` (or `tests/smoke/` if it needs a running stack — prefer in-process non-root, the #245 lesson).

- [ ] Step 1 — failing test: stand up a real loopback **conformant fake-core** (a `CommsSocketListener` host that sends `lifecycle.start` + echoes opaque payloads) + a real loopback client dialing `comms-gateway.sock`, with a real `GatewayProcess` between them. Drive: a client opaque payload → arrives at the core **byte-for-byte**; a core opaque payload → arrives at the client **byte-for-byte**; a core gap+reconnect mid-session → the client connection is HELD (single-accept-for-life) + a `link.reconnecting`/`restored` control frame reaches the client; the payload-blindness canary never leaks. **Acceptance language (architect M2 — be precise):** this proves a real OPAQUE PAYLOAD relays byte-for-byte through the running process against a conformant fake core + the resumable hold-across-gap — the TRANSPORT substance of criterion #7. The full real-orchestrator turn (real client → real core → real persona reply) is gated on 2c/#230 (no real reply yet) AND G5 (production `alfred chat` re-point); do NOT claim the orchestrator turn here.
- [ ] Step 2 — FAIL. Step 3 — wire the harness (reuse the 2a `test_relay_wire_contract` harness shape + add the real `GatewayProcess`). Step 4 — PASS. Step 5 — commit (`test(gateway): end-to-end opaque turn through the alfred gateway process (Spec A G3-3b-2b) (#237)` + trailer).

- [ ] **Task 6b: adversarial-suite entry — process-level peer-reject + epoch-forgery + payload-blindness (TDD) (security must-add)**

**Files:** Test: `tests/adversarial/comms/test_gateway_process_boundary.py`.

- [ ] Step 1 — failing tests exercising the trust boundary THROUGH a running `GatewayProcess` (not just unit-level monkeypatch): (a) a wrong-uid client (monkeypatch `_resolve_peer_uid` to a foreign uid) is rejected end-to-end + `gateway_peer_auth_rejected_total` increments + the loud `comms.socket.peer_uid_rejected` row fires; (b) a forged `daemon.lifecycle.ready` with a mismatched epoch from the fake-core NEVER produces a `restored` to the client through the process (the merged `_consume_ready` forgery defense survives the process wiring); (c) a canary-T3-bearing payload relayed through the process never appears in any gateway log/metric (payload-blindness end-to-end).
- [ ] Step 2 — FAIL. Step 3 — wire (reuse the Task-6 harness). Step 4 — PASS. Step 5 — fold into the Task 6 commit or its own (`test(adversarial): gateway-process peer-reject + epoch-forgery + payload-blindness (Spec A G3-3b-2b) (#237)` + trailer). Run the FULL adversarial suite (`uv run pytest tests/adversarial -q`) since this is a trust-boundary process.

- [ ] **Task 7: ADR + CLAUDE.md command table + CI gate + full gate + open PR**

- [ ] ADR-0031 (the socket-carrier ADR): add an amendment recording the `alfred gateway` PROCESS — the client-leg HOST handshake (sends `{adapter_id:"tui", seq_ack}`, the over-spec relaxed in ADR-0035), the bind/accept/handshake/supervise/reap lifecycle, the injectable peer-reject seam + the metric, and the TRANSPORT-substance-of-#7-proven-here / production-wired-in-G5 framing. **Record these security sign-offs explicitly:** (1) the peer-reject is metric+structlog ONLY in the G3→G4 window (no gateway audit sink yet) — the ACCEPTED interim, with the durable signed reject row HARD-SCHEDULED for G4 (security H1); the gateway is not the production front door until G5, so production peer-reject exposure begins with G4's audit sink in place. (2) the bind-side owner guarantee is the **0700 parent dir** (`~/.run/alfred`); G3-4's shared-volume socket relocation MUST re-establish an equivalent owner-only-parent invariant or a shared-volume socket is plantable (security M3). (3) the dual-identity invariant: bind-id = `"gateway"` (path ownership), handshake-adapter-id = `"tui"` (wire compat) — deliberately different (security L2). MD032-clean.
- [ ] CLAUDE.md command table: add `alfred gateway start|status` (this is a human-gated file — the entry is a factual command addition; if the pre-commit/CLAUDE rules block it, note it for human approval rather than forcing).
- [ ] CI per-file 100%-coverage gate: add `src/alfred/gateway/process.py` + `client_link.py` to BOTH gateway coverage gates (the trust-boundary process + handshake), keeping them symmetric; `metrics.py`/`client_listener.py` are already gated.
- [ ] `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/ && uv run pytest tests/unit/gateway tests/unit/cli tests/unit/comms_mcp -q && uv run pytest tests/adversarial -k gateway -q && npx markdownlint-cli2@0.14.0 docs/adr/0031-*.md docs/adr/0035-*.md docs/superpowers/plans/2026-06-15-g3-3b2b-gateway-process.md`
- [ ] `make check` (NOT piped through `tail`). Commit the plan + ADR; open the PR; run the FULL `/review-pr` fleet (security ALWAYS — the handshake/sentinel-credentials + the process trust boundary; + error, test, performance, comms, docs, i18n, devex, architect, devops) + CodeRabbit; **resolve every addressed CR thread** (`resolveReviewThread`); auto-merge `gh pr merge <n> --auto --rebase --delete-branch` (NO `--admin`).

---

## Acceptance

- `alfred gateway start` runs a supervised `GatewayProcess`; `alfred gateway status` reports health; both appear in `alfred --help`; the lazy-import discipline holds.
- The client-leg HOST handshake sends a TUI-valid `LifecycleStartRequest` (the sentinel-credentials gotcha resolved) + negotiates seq/ack iff echoed.
- A real turn round-trips client↔core through the `GatewayProcess` byte-for-byte, the client is held across a core reconnect (`reconnecting`/`restored` reaches it), and the canary never leaks (the substance of criterion #7; G5 wires production `alfred chat`).
- Every transport + the listener reaped on every exit path (no FD/socket leak); fail-closed on bind / handshake failure.
- New `process.py` + `client_link.py` at 100% branch (trust boundary); `make check` green.

---

## Self-review

- **Spec coverage:** the runnable process (§3 — the always-up front door) → `GatewayProcess`; the client-leg handshake (§7 — the gateway as the client-leg HOST) → `client_link`; the peer-reject metric (§6) → Task 2/4; criterion #7 (a real turn through the resumable front door) → the e2e smoke (process-level; production `alfred chat` = G5). ✓
- **Grounded in merged seams:** `GatewayClientListener` (the new `on_peer_rejected`/`transport` seams), `GatewayRelay(core_link, client_transport, client_seq_enabled)`, `GatewayCoreLink(client_listener, shutdown_event, ...)`, `LifecycleStartRequest`/`LifecycleStartResult`/`SeqAckCapability`/`AdapterId`, the daemon `_listen_socket_comms_adapter` skeleton, the `daemon_app` CLI pattern — all cited. ✓
- **The handshake gotcha is captured + flagged for security review** (sentinel `credentials_ref` to a credential-ignoring TUI — not a broker bypass). ✓
- **Placeholders:** none — every task has real signatures/tests/commands. ✓
- **Type consistency:** `client_handshake(transport) -> bool`; `GatewayProcess(*, shutdown_event, ...)`; `GatewayClientListener(on_peer_rejected=...)` + `.transport`; `PEER_AUTH_REJECTED` — consistent across tasks. ✓
- **CR discipline:** Task 7 resolves addressed CR threads (the merge-unblock discipline). ✓
- **Framing honesty:** 2b PROVES criterion #7 at the process level (a real turn through the gateway) but does NOT re-point production `alfred chat` (G5) — stated, not overclaimed. ✓

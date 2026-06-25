# G6-3 — Real gateway adapter credential (spawn_request / spawn_grant / fd-3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.
>
> **This plan is LOCAL-ONLY — do NOT `git add` it** (plan docs are markdownlint-gated in CI + kept out of the merge). Commit only code/docs/tests. **i18n commit type = `feat(i18n):` NOT `i18n:`.**

**Goal:** Replace the G6-2 fake-credential seam with the REAL core-injects-at-spawn credential path: on each (re)spawn the gateway sends `gateway.adapter.spawn_request{adapter_id}` to the core over the trusted leg; the core's new `CoreAdapterCredentialResolver` resolves the platform credential from the secret broker and returns `core.adapter.spawn_grant{adapter_id, credential_material}` (epoch-bound, dedup-keyed); the gateway's new `GatewayAdapterCredentialClient` delivers the plaintext to the bwrap child **over fd 3** (mirroring `deliver_provider_key_via_fd3`, which **owns and zeroes the only mutable buffer** — the `str` credential itself cannot be zeroed in Python) — never env, never retained, never cached, no vault key. **THE HEAVIEST TRUST BOUNDARY IN SPEC B.**

**Architecture:** Two new collaborators on the existing trusted gateway↔core leg (ADR-0031 socket + ADR-0033 epoch): gateway-side `GatewayAdapterCredentialClient` (the `spawn_request → spawn_grant` round-trip + fd-3 write (the delivery library zeroes its own buffer); fail-closed; await-core-on-outage with bounded backoff + terminal alert ceiling) wired into `GatewayAdapterSupervisor`'s spawn path (replacing the `cred_seam` fake); core-side `CoreAdapterCredentialResolver` (the only component that decrypts the platform cred → `spawn_grant`, epoch-bound + dedup-keyed) wired into the daemon's comms boot graph. The credential frames ride the SAME trusted leg the G6-2a status notifications use, but are **request/response** (like the G6-2c control plane) not fire-and-forget. The fd-3 delivery copies `fd3_key_delivery.deliver_provider_key_via_fd3` exactly. B-testable invariant: *the gateway never holds a vault key and never retains a credential past a single spawn; the credential never appears in the child's environment.*

**Tech Stack:** Python 3.12+, asyncio, Pydantic v2 (frozen `extra="forbid"` wire frames), structlog, bwrap launcher (the real-spawn path runs on the privileged Linux CI lane; the lifecycle/client logic is unit-tested non-root via injected seams + a fake fd-3 sink + a fake core). Adversarial corpus entries (a)/(b)/(e) are release-blocking.

---

## Context the implementer must hold (verified against main @ c75a19cc)

- **fd-3 delivery to MIRROR:** `src/alfred/security/fd3_key_delivery.py` — `deliver_provider_key_via_fd3(write_fd, key)` does an atomic `writev` (4-byte length prefix + key bytes) then **zeroes the source bytearray**; fail-closed via `ProviderKeyDeliveryError`. The bwrap child reads fd 3 directly (length-prefixed). G6-3's gateway→adapter-child credential delivery copies this discipline EXACTLY (it is the established secret-broker-not-env channel; env injection would breach the HARD rule + leak via `/proc/<pid>/environ`).
- **bwrap spawn to REUSE:** `src/alfred/.../quarantine_child_io.py` — `spawn_quarantine_child_io(provider_key)` sets up fd-3 on the child (`pass_fds=(3,)`, `os.dup2` clobber window around a synchronous `Popen`), a scrubbed env (metadata only, no secrets), and the ADR-0030 interpreter-prefix bind. The comms adapter child spawns the same way; G6-3 threads the resolved credential into this spawn's fd-3.
- **`GatewayAdapterSupervisor`** (`src/alfred/gateway/adapter_supervisor.py`, built G6-2a/2b): constructor injects `child_factory`, **`cred_seam`** (the FAKE credential seam G6-2 used — an `is_available` toggle, the §4 fake), `emitter`, `epoch`. The pre-spawn credential check is at `_spawn_or_terminal` (~lines 299-304): cred unavailable → `AWAITING_CORE`. `_AdapterRun.restart_count` is the incarnation (the G6-2b-2b `host_restart_seq`). G6-3 REPLACES the `cred_seam` fake with the real `GatewayAdapterCredentialClient` (same structural seam, real round-trip + fd-3 write).
- **Trusted leg + epoch:** the gateway↔core leg is the ADR-0031 0600/SO_PEERCRED socket; G6-2a's `AdapterStatusEmitter` (gateway) → `AdapterStatusObserver` (core) ride it for `gateway.adapter.*` NOTIFICATIONS. G1/ADR-0033 gives the per-core-boot epoch; G6-2c's control-plane (`_daemon_control_*`) is the request/response shape to mirror for spawn_request/grant. The epoch + dedup (SeqDedupWindow / `(adapter_id, incarnation)`) defend adversarial (e) (spoofed/replayed grant).
- **Secret broker:** `src/alfred/security/secrets.py` — `SecretBroker.get(name)` (file-preferred for comms keys, fail-closed, 0600-validated). The Discord adapter TODAY self-brokers (`DiscordLifecycle.start → self._broker.get('discord_bot_token')`); the child stops self-brokering and reads fd-3 — **that plugin change is G6-5, NOT here.** G6-3 builds the core-side resolver; the real Discord child read is G6-5.
- **Test seams:** `tests/unit/gateway/test_adapter_supervisor.py` has the fake `child_factory` (scripted "ok"/"spawn_error"/"handshake_fail"), the fake `cred_seam` (`is_available`), a recording sink. G6-3 adds a **fake core** (answers spawn_request with a spawn_grant) + a **fake fd-3 sink** (captures the delivered bytes + asserts zeroed-after) so the real client is unit-testable non-root; the real bwrap spawn + `/proc` negative run on the privileged CI lane.
- **Crash reconciler / incarnation:** `host_restart_seq` (G6-2b-2b) is the per-adapter incarnation — the dedup key for `spawn_grant` is `(adapter_id, host_restart_seq/epoch)`.

### Scope guards

- **IN:** the credential client (round-trip + fd-3 + zero-after-write + fail-closed + await-core), the core resolver (decrypt → grant, epoch-bound + dedup), the spawn_request/grant wire frames, wiring both into the supervisor + daemon boot graph (still against the FAKE adapter child / fake fd-3 sink in unit tests + the real bwrap on the privileged lane), the audit rows (spawn_request, spawn_grant, awaiting-core, spawn-abort), and adversarial corpus (a)/(b)/(e).
- **OUT (deferred):** the Discord child reading fd-3 instead of self-brokering → **G6-5**. The Compose secret relocation → G6-5. The ingress gate / leg scheduler / ReplayBuffer → G6-4. The SCM_RIGHTS core→child fd-pass (gateway never transits plaintext) → **Spec C**. The connectivity-free core → Spec C.

---

## File structure

**Created:**

- `src/alfred/gateway/adapter_credential_client.py` — `GatewayAdapterCredentialClient`: `acquire_and_deliver(adapter_id, host_restart_seq, write_fd) -> None` (spawn_request round-trip over the leg → receive grant → write plaintext to fd-3 via the mirrored `deliver_*_via_fd3` → zero the copy; fail-closed `AdapterCredentialError`; await-core with bounded backoff + terminal ceiling on link-down).
- `src/alfred/comms_mcp/adapter_credential_resolver.py` (or `src/alfred/cli/daemon/...`) — `CoreAdapterCredentialResolver`: `resolve(spawn_request) -> SpawnGrant` (the ONLY component that decrypts the platform cred via `SecretBroker.get`; epoch-bound; dedup-keyed; audited). Maps `adapter_id → secret_id` (e.g. `discord → discord_bot_token`) via a small static manifest.
- `src/alfred/comms_mcp/adapter_credential_protocol.py` — frozen `SpawnRequest{adapter_id, host_restart_seq, epoch}` + `SpawnGrant{adapter_id, host_restart_seq, epoch, credential_material}` Pydantic frames (`extra="forbid"`; `credential_material` is the plaintext over the trusted leg only; field-set locked; redaction on any log/audit of these frames — the credential NEVER appears in an audit row or log).
- `src/alfred/audit/audit_row_schemas.py` additions — `GATEWAY_ADAPTER_SPAWN_REQUEST_FIELDS`, `CORE_ADAPTER_SPAWN_GRANT_FIELDS` (NO credential field — only adapter_id/host_restart_seq/epoch/result), `GATEWAY_ADAPTER_AWAITING_CORE_FIELDS`, `GATEWAY_ADAPTER_SPAWN_ABORTED_FIELDS`.
- Tests: `tests/unit/gateway/test_adapter_credential_client.py`, `tests/unit/comms_mcp/test_adapter_credential_resolver.py`, `test_adapter_credential_protocol.py`, `tests/unit/gateway/test_adapter_supervisor_credential.py` (the supervisor spawn path with the real client + fake core + fake fd-3 sink), `tests/adversarial/test_adapter_credential_corpus.py` (cases a/b/e), and the privileged-lane real-spawn + `/proc`-negative integration test.

**Modified:**

- `src/alfred/gateway/adapter_supervisor.py` — `_spawn_or_terminal` calls the real `GatewayAdapterCredentialClient.acquire_and_deliver` (replacing the `cred_seam` fake); the await-core state machine (`AWAITING_CORE` + bounded backoff + terminal ceiling) consumes the client's link-down signal; fail-closed spawn-abort on grant-refusal / launcher-fail / fd-3-write-fail / zero-after-write-fail.
- `src/alfred/cli/daemon/_commands.py` — build the `CoreAdapterCredentialResolver` in the comms boot graph; route `gateway.adapter.spawn_request` → resolver → `core.adapter.spawn_grant` on the leg (request/response handler, mirroring the G6-2c control-plane router); reaped/owned like the other boot-graph collaborators.
- `src/alfred/gateway/process.py` (GatewayProcess) — construct + inject the `GatewayAdapterCredentialClient` into the supervisor (it holds the leg client).
- `docs/adr/0036-...md` — annotate that G6-3 realized the credential contract (fd-3 transient delivery, zero-after-write, await-core); confirm the serial-harvest residual stands (Spec C closes it).
- `docs/subsystems/comms.md` (or a new `gateway.md`) — the credential path.
- `.github/workflows/ci.yml` — per-file 100% gates for the new credential modules; the adversarial corpus (a/b/e) gate; the privileged-lane real-spawn test.

---

## Tasks (TDD; each: failing test → RED → minimal impl → GREEN → commit `(#288)` + trailer)

### Task 1 — `SpawnRequest`/`SpawnGrant` frames + field-set locks (no credential in audit)

Create `adapter_credential_protocol.py`: frozen `extra="forbid"` `SpawnRequest{adapter_id, host_restart_seq: int ge=0, epoch: str}` and `SpawnGrant{adapter_id, host_restart_seq, epoch, credential_material: str}`. Add the audit field-sets (NO `credential_material` key — only adapter_id/host_restart_seq/epoch/result). Tests: exact-field-set lock on both frames; a structural test that `credential_material` is NOT in any of the audit field-sets (the credential never reaches an audit row); `model_dump_json` of a `SpawnGrant` round-trips but a redaction helper used on any LOGGED frame elides `credential_material`. Commit.

### Task 2 — `CoreAdapterCredentialResolver` (the only decryptor; epoch-bound + dedup)

Create the resolver: `resolve(request: SpawnRequest) -> SpawnGrant`. Maps `adapter_id → secret_id` via a static manifest (`discord → "discord_bot_token"`); `SecretBroker.get(secret_id)` → `credential_material`; binds the grant to the request's epoch (refuse a stale/foreign epoch → loud audited refusal); dedup-keyed on `(adapter_id, host_restart_seq, epoch)` (a replayed request returns the same grant, audited `duplicate=true`, never a fresh decrypt-storm). Writes a `CORE_ADAPTER_SPAWN_GRANT_FIELDS` audit row (result=granted/refused, NO credential). Fail-closed: unknown adapter_id / missing secret / wrong epoch → typed refusal, no grant. Tests: happy grant; unknown-adapter refused; missing-secret refused (broker raises); stale/foreign-epoch refused (adversarial e precursor); replayed request → deduped + audited. Commit.

### Task 3 — `GatewayAdapterCredentialClient`: round-trip + fd-3 + zero-after-write (fail-closed)

Create the client: `acquire_and_deliver(*, adapter_id, host_restart_seq, write_fd, epoch) -> None`. Sends `SpawnRequest` over the leg (request/response, mirroring the G6-2c control-plane client), receives `SpawnGrant`, verifies the grant's `(adapter_id, host_restart_seq, epoch)` matches the request (refuse a mismatched/forged grant — adversarial e), delivers `credential_material` to `write_fd` via the mirrored `deliver_provider_key_via_fd3` discipline (atomic writev + length-prefix), then **zeroes its own copy** (a `bytearray`; verify-zeroed or fail). Every failure (grant refusal, fd-3 write error, zero-after-write unconfirmed) raises a loud audited `AdapterCredentialError` and aborts the spawn — NEVER log-and-continue. Tests (fake core + fake fd-3 sink): happy deliver→zeroed (assert the sink received the bytes AND the client's copy is zeroed); grant-refusal → AdapterCredentialError + spawn abort; fd-3 write failure → abort; mismatched/forged grant → refused; the credential never appears in a log (capture_logs assert). Commit.

### Task 4 — await-core-on-outage (non-spin, bounded backoff, terminal ceiling, loud)

The client's leg-down path: a `spawn_request` interrupted by a link drop surfaces a typed loud error (not a hang); the supervisor's restart loop enters `AWAITING_CORE` — a non-spin bounded-backoff wait with decorrelated jitter + a terminal alert ceiling (past it: adapter marked durably down + a distinct `GATEWAY_ADAPTER_SPAWN_ABORTED` alert; no quiet-dark). Each awaiting-core wait writes `GATEWAY_ADAPTER_AWAITING_CORE_FIELDS`. Tests (fake clock): link-down → awaiting-core (loud + audited); recovery within ceiling → spawn proceeds; ceiling exceeded → durably-down + distinct alert; the await interacts correctly with the per-adapter breaker (breaker does not mask awaiting-core). Commit.

### Task 5 — wire the real client into `GatewayAdapterSupervisor._spawn_or_terminal`

Replace the `cred_seam` fake with the real `GatewayAdapterCredentialClient`: `_spawn_or_terminal` calls `acquire_and_deliver(adapter_id, run.restart_count, child_write_fd, epoch)` BEFORE/at the child spawn; a credential failure aborts the spawn fail-closed (audited spawn-abort); on success the child gets its fd-3 credential. Keep the existing crash/backoff/breaker behavior. Update the existing supervisor tests for the new client ctor param (mirror the G6-2 fake-cred-seam tests → real-client-with-fake-core). Tests: spawn delivers the credential to the child's fd-3 then proceeds to handshake; grant-refusal aborts the spawn loudly; the per-adapter isolation (each child its own fd-3, no shared cred memory). Commit.

### Task 6 — route spawn_request→resolver→spawn_grant in the daemon boot graph

In `_commands.py`, build the `CoreAdapterCredentialResolver` in the comms boot graph + register a request/response handler for `gateway.adapter.spawn_request` on the trusted leg (mirror the G6-2c control-plane router / the G6-2a observer wiring): request → resolver.resolve → `core.adapter.spawn_grant` reply. Owned/reaped like the other boot-graph collaborators. Tests (the daemon boot-graph test): a spawn_request over the leg gets a spawn_grant; an unknown-adapter/stale-epoch request gets a refusal; the resolver is the boot graph's single decryptor. Commit.

### Task 7 — GatewayProcess construction + the real leg client

Construct the `GatewayAdapterCredentialClient` (holding the leg client) in `GatewayProcess` and inject it into the supervisor (replacing the fake seam at the process boundary). Reap on every exit path. Tests: the process builds the supervisor with the real credential client; shutdown reaps it. Commit.

### Task 8 — adversarial corpus a/b/e (RELEASE-BLOCKING)

Create `tests/adversarial/test_adapter_credential_corpus.py`:

- **(a)** cross-adapter credential read attempt (one adapter reads another's fd-3 / env) → refused + audited (per-adapter isolation: separate bwrap child, own fd-3, scrubbed env, no shared cred memory).
- **(b)** gateway memory inspected after a spawn → NO retained plaintext credential (mechanically: the client's `bytearray` is zeroed post-write) + the structural "gateway holds no vault key" invariant; the `/proc`/core-dump negative runs on the privileged CI lane (or explicitly deferred with rationale).
- **(e)** spoofed / replayed `spawn_grant` (forged or stale-epoch credential frame) → refused; epoch-reconcile on the cred leg.
Wire these into the adversarial gate. Commit.

### Task 9 — real-spawn privileged-lane integration + CI gates + docs

The privileged Linux lane: a REAL bwrap adapter child spawned with a real fd-3 credential delivery (deterministic/echo credential, no real Discord), asserting the child receives the credential over fd-3 and the credential is NOT in the child's `/proc/<pid>/environ`. Add per-file 100% coverage gates for the new credential modules (both python-job + coverage-gates per the two-gates pattern); add the adversarial-corpus gate. ADR-0036 annotation + comms.md/gateway.md docs. Full quality bar (ruff/mypy/pyright/i18n-drift/markdownlint/FULL coverage). Commit.

---

## Self-review checklist (run before plan-review)

- Every failure in the credential pipeline is fail-closed + loud + audited (grant-refusal, launcher-fail, fd-3-write-fail, zero-after-write-unconfirmed) — no log-and-continue.
- The credential NEVER appears in: an audit row, a log line, the child's env, a cached field, or a second spawn (zeroed after write).
- The resolver is the ONLY decryptor; the gateway holds no vault key.
- spawn_grant is epoch-bound + dedup-keyed (adversarial e).
- Per-adapter isolation: separate child, own fd-3, scrubbed env (adversarial a).
- await-core is non-spin + bounded + terminal-ceilinged + loud (no quiet-dark).
- Injectable seams (fake core, fake fd-3 sink, fake clock) make the logic non-root unit-testable; the real bwrap + /proc negative is on the privileged lane.

## Scope-boundary (OUT)

Discord child fd-3 read (stop self-brokering) + Compose secret relocation → G6-5. Ingress gate / leg scheduler / ReplayBuffer → G6-4. SCM_RIGHTS core→child fd-pass + connectivity-free core → Spec C.

---

## Plan-review corrections (MUST apply — architect + security + test, 2026-06-20) + maintainer C1 ruling

All three returned **approve-with-changes**. The plan rests on a wrong premise about the gateway↔core leg (it has NO request/response today) and over-claims credential zeroing. Apply these — they OVERRIDE conflicting earlier text. **Do NOT start Task-1 RED until the structural ones (A-C1, S-C1, A-H2) are reflected in the task list.**

### MAINTAINER DECISION — C1 credential zeroing: **option (a), honest-scope** (chosen 2026-06-20)

The credential is carried as a **`str`** in G6-3 (matching `SecretBroker.get() -> str` and the **already-shipped** quarantine provider-key fd-3 path). Do NOT claim a "verify-zeroed bytearray of the gateway's own copy" — an immutable `str` cannot be zeroed; the ONLY verifiably-zeroed object is the ephemeral writev `bytearray` *inside* the existing `deliver_provider_key_via_fd3`. **Honest-scope it:** the module docstring records the str-residency window + `gc.collect()` mitigation (mirror `fd3_key_delivery.py` lines 33-36 verbatim in spirit), and names the closure as a SEPARATE future hardening: a cross-cutting `SecretBroker.get_bytes` + bytes-end-to-end that upgrades **BOTH** the quarantine and adapter paths together (NOT in G6-3 — keeps the two cred paths consistent). **Drop** the Task-3 "zeroes its own copy (a bytearray; verify-zeroed or fail)" and the Task-8(b) "the client's bytearray is zeroed post-write" literal claims. Adversarial (b) instead asserts the STRUCTURAL invariants (gateway holds no vault key; credential never in env/audit/log/a retained field; the ephemeral fd-3 writev buffer is zeroed by the reused library fn) + the `/proc` env-absence negative.

### Architect A-C1 (STRUCTURAL, biggest): the leg has NO request/response — build the correlation primitive

Delete every "mirror the G6-2c control-plane router/client" reference — that is ADR-0038's SEPARATE 0600 CLI↔daemon socket (`_daemon_control_*`), NOT the gateway↔core leg. The credential frames ride the **ADR-0031 leg = `src/alfred/gateway/core_link.py`**, which today is a **fire-and-forget notification pump**: `send_status_frame()` is loud-drop no-correlation; `_consume_frame()` consumes ONLY `daemon.lifecycle.going_down|ready` and **drops+counts every other inbound method/response**. There is NO `request_id` correlation, NO `await_response`, NO `send_request`. **ADD a new task (sequence it BEFORE the credential client — call it Task 2.5):** a request/response correlation primitive on the leg — `gateway.adapter.spawn_request{request_id, adapter_id, host_restart_seq, epoch}` (gateway→core) → `core.adapter.spawn_grant{request_id, ...}` (core→gateway, the **FIRST core→gateway *response* frame on this leg — a third frame class** alongside opaque T3 payload units + fire-and-forget status notifications), with: id-correlation, a bounded await, and **extending `_consume_frame` to route `core.adapter.spawn_grant` to the pending waiter** (instead of dropping it). State whether this lives in `core_link.py` or a thin collaborator over it; share ONE envelope module between the gateway client (Task 3) and the daemon route (Task 6) so the two ends cannot drift (precedent: `gateway/_control_frames.py` + `comms_mcp/protocol.py`).

### Architect A-C2: bounded-await fail-closed on a dropped/unrouted reply (distinct from await-core)

await-core (Task 4) covers link-DOWN. ADD: the `spawn_request` await must ALSO be bounded by a timeout that **fails closed loudly** when the link is nominally UP but the reply is dropped/unrouted (the current leg silently drops unknown inbound methods → a spawn could hang). Typed loud abort, not a hang. Record the "third frame class on the ADR-0031 leg" + this bounded-await in the ADR-0036 annotation.

### Security/Architect file + signature facts (H1/C2)

The fd-3 module is **`src/alfred/supervisor/fd3_key_delivery.py`** (NOT `security/`). `deliver_provider_key_via_fd3(*, write_fd: int, key: str) -> None` is **keyword-only**, takes a **`str`**, builds the bytearray internally, **zeroes that internal buffer**, and **closes `write_fd` itself on every path**. REUSE it (+ the `src/alfred/security/quarantine_child_io.py::spawn_quarantine_child_io` dup2→synchronous-Popen→restore spawn pattern, including its load-bearing **"no `await` while fd 3 is clobbered"** discipline — an `await asyncio.create_subprocess_exec` here hits the nondeterministic `OSError [Errno 22]` regression). Do NOT reimplement (DRY on a security primitive). Fix every path/signature reference in the plan.

### Security S-C3 + Test C3: credential structurally un-loggable (not opt-in redaction)

Make `credential_material` un-`repr`-able at the MODEL level: `Field(..., repr=False)` + override `__repr__`/`__str__` on the grant frame to elide it (so `log.info(frame)` / f-strings / exception args are safe-by-default). FORBID the frame as an exception arg: `AdapterCredentialError` is built from `adapter_id`/reason only — never `from` a Pydantic `ValidationError` carrying the raw input, never with the frame in `args`. `SecretBroker.redact()` will NOT help (it only knows registered secret values; the wire-delivered cred isn't registered at the gateway). **Test:** a unique sentinel credential fed through resolver→grant→client→fd-3→audit→log appears ONLY on the fd-3 sink — NOT in any audit row, log line (`capture_logs`), emitted frame param, or exception `detail`/`str()`/`args`, across happy AND all failure paths.

### Security/Architect H1: source the epoch LIVE (real latent bug)

The supervisor passes a FIXED `self._epoch` captured at construction; `GatewayCoreLink.current_core_epoch()` updates per handshake. After a core bounce the fixed epoch is stale → either every spawn refused (DoS) or a wrong-epoch grant accepted. **The request epoch MUST be sourced live from `current_core_epoch()` at spawn time.** Test: core bounces → new epoch → next `spawn_request` carries the NEW epoch + succeeds; a grant echoing the OLD/foreign epoch is refused. State the authenticity bound: "no process other than the genuine same-uid peer can forge a grant"; a same-uid-leg compromise is the **Spec-C serial-harvest residual**, NOT defended in B.

### Architect A-H2 + Security H2: the seam is two moments, and the child-factory contract must change (Task 5 under-scoped)

The cred gate today is in **`supervise_one` (~lines 299-304)** — `if not await self._cred.is_available(...)`, a BOOLEAN pre-spawn probe — NOT in `_spawn_or_terminal` (which never touches cred). The real flow is TWO moments: (i) a **pre-spawn availability/await-core gate** (keep a CHEAP local link-state probe — do NOT fire a full `spawn_request`+core-decrypt just to check liveness, that's wasteful + a minor harvest-amplification surface), and (ii) an **at-spawn fd-3 delivery** (`acquire_and_deliver`, which needs the child's fd-3 WRITE END — created by the child factory during spawn). The `_AdapterChildFactoryLike` contract today is `spawn_and_handshake(adapter_id, epoch)` — **no fd-3, no cred hook**. It MUST change to create/expose the fd-3 write end and sequence delivery with pipe creation. **Split Task 5 into 5a (factory fd-3 contract + pipe ownership) / 5b (wire the client into the spawn).** Per-adapter isolation (adversarial a): `acquire_and_deliver` allocates a **fresh `bytearray` per call** (no instance-level reusable buffer, no `self.`-scoped credential field); structural test that two adapters' spawns share no buffer identity + the client holds no cred attr after either call.

### H3: canonical dedup/replay key

Use `(adapter_id, host_restart_seq, epoch)` EVERYWHERE (the plan currently mixes "incarnation"/"host_restart_seq/epoch"). Field name `host_restart_seq` (= `_AdapterRun.restart_count` on the wire). The **epoch is load-bearing**: `restart_count` resets on gateway restart (not cross-restart-unique), so `(adapter_id, host_restart_seq)` alone is replayable across a gateway bounce — only the per-core-boot epoch disambiguates. Resolver dedup matches ALL THREE or it's a **refusal, not a dedup**.

### H4: dedup caching discipline

The **gateway NEVER caches a credential to dedup** — its anti-replay is "verify the grant matches my outstanding request, else discard"; it retains nothing. The resolver's "replay → same grant" must (i) match all of `(adapter_id, host_restart_seq, epoch)` byte-for-byte else refuse, (ii) call `SecretBroker.get` **exactly once** on a true replay (assert the call count — the security property; no decrypt-storm/oracle), (iii) audit `duplicate=true`. An **unsolicited** `core.adapter.spawn_grant` (no pending request) → refused (part of adversarial e).

### Test MUST-ADDs (consolidated — beyond the per-task tests)

1. **Value-sentinel sweep** (S-C3): per above.
2. **Non-root scrubbed-env assertion** (adversarial b in-process analog — NOT deferred): the child env dict the spawn builder constructs contains no credential value and no `*_TOKEN`/`*_KEY` key; the `/proc/<pid>/environ` real-bwrap negative runs on the privileged lane as CORROBORATION (the #245 paper-gate lesson — the env-absence property gates merge in-process).
3. **Adversarial (a) two-layer**: in-process per-adapter fd/buffer isolation (two fake sinks, no shared buffer identity) on the required gate + OS-level cross-`os.read` negative on the privileged lane (don't conflate them).
4. **Adversarial (e) full set**: forged adapter_id/host_restart_seq/epoch (three distinct refuse branches), STALE epoch, REPLAYED request (deduped + broker-called-once), UNSOLICITED grant (no pending request) → refused.
5. **await-core fake-clock** (reuse the existing `sleep`/`rng`/`monotonic` seams — adapter_supervisor.py:194-218, NOT a new clock): link-down→awaiting-core (loud+audited); recovery-within-ceiling→spawn; ceiling-exceeded→durably-down + DISTINCT alert; breaker-does-not-mask-awaiting-core; **cred-down ∩ link-down interleave** (the existing cred-AWAITING_CORE and the new link-AWAITING_CORE are two triggers into one state); **no credential held during the wait** (the rejected MADV_DONTDUMP overturn).
6. **Fail-closed matrix WITH no-continue**: grant-refusal / launcher-fail / fd-3-write-fail (the lib raises `ProviderKeyDeliveryError`) → loud audited abort + **assert no `up` frame / child never serves** (catches "logs then spawns anyway"). [Note: with C1-(a) there is no separate "zero-after-write-unconfirmed" branch on a str copy — the lib owns its buffer zero.]
7. **Fake core round-trips SERIALIZED frames** (bytes over an in-memory transport), not Python-object passthrough — so the real Pydantic codec + the C3 redaction + the correlation layer are exercised.

### Smaller (M/L)

- **ADR-0036 annotation** (Task 9) must record: the new request/response frame-class on the ADR-0031 leg, the bounded-await fail-closed, AND the honest str-residency residual (per C1-a) + the deferred `get_bytes` closure — not just "realized the contract."
- **Audit reasons** are closed-vocabulary (mirror `quarantine_child_io`'s `reason="provider_key_delivery_failed"`); each fail-closed branch emits its distinct reason; gateway holds no signing key → these reconcile into the CORE signed log (as the G6-2b-2a observer does), not a gateway-local signed append.
- **Resolver lives in `src/alfred/comms_mcp/adapter_credential_resolver.py`** (parallels `adapter_status_observer.py`, built in `_build_comms_boot_graph`). Name it in BOTH the python-job AND coverage-gates per-file 100% lists.
- **Error hierarchy** (L1): `AdapterCredentialError` rooted at `AlfredError`; wrap it as `GatewayAdapterSpawnError` in the spawn path so the supervisor's existing crash/breaker arms treat it uniformly. Don't reuse `ProviderKeyDeliveryError` (different subsystem, rooted at `Exception`).
- **Static adapter→secret ALLOWLIST** (L4): `discord → "discord_bot_token"` is a closed map; an unknown `adapter_id` → typed refusal, **never** `broker.get(adapter_id)` passthrough (part of adversarial a's confused-deputy defence).
- **i18n** (L3): new refusal/awaiting-core/spawn-aborted reason keys go through `t()` + the reason module + the slice key-set + `alfred.po/.mo` (`pybabel update --no-fuzzy-matching`, never `--omit-header`); commit type `feat(i18n):` NOT `i18n:`.
- **Privileged-lane real-spawn child = a DETERMINISTIC ECHO adapter, NOT real Discord** (Discord child fd-3 read is G6-5); mirror the 2b0/2c quarantine real-spawn precedent.
- **`extra="forbid"`** on the frames: add a test that a grant with a smuggled extra field is rejected.
- **Decision-2 clarity:** the grant is a RESPONSE to a gateway-initiated request (a precondition the gateway consumes), NOT a core directive — the gateway decides whether/when to spawn. One sentence in the plan + ADR annotation.

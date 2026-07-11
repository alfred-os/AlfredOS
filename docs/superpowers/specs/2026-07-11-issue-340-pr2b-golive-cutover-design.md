# #340 PR2b — real-LLM quarantine child go-live cutover (design)

**Status:** RATIFIED rev.2 (2026-07-11) — §14 forks 1–5 ratified by the requester; proceeding to
`writing-plans` for PR2b-prep. Committed on branch `340-pr2b-golive-design` off main `42377a52`.
rev.2 folds a focused 4-lens design review (architect / security / core / provider — all
AGREE/SOUND-WITH-CHANGES, 0 design-killers; §19 is the fold log, which **overrides section bodies
where they conflict**). The go-live PR still carries a **HUMAN SIGN-OFF** at merge (§13) — that gate
is separate from this ratification; PR2b-prep is behavior-neutral and needs no sign-off.

Parent design: `docs/superpowers/specs/2026-07-09-issue-340-real-quarantine-child-design.md`
(the 2-PR machinery→go-live decomposition; PR2b = go-live). fd-broker spike findings +
the verified M1 transport shape live on branch `340-fd-broker-spike`
(`docs/superpowers/specs/2026-07-10-issue-340-fd-broker-feasibility-spike-design.md` §11).
PR2a topology: `docs/superpowers/specs/2026-07-10-issue-340-pr2a-fd-broker-topology-design.md`.

---

## 1. Goal

Graduate the quarantine child (the dual-LLM structured extractor — the **only** consumer of
raw T3) from the deterministic-echo loop to a **real Anthropic-Haiku extract call** over the
audited Spec-C gateway egress proxy, using the SCM_RIGHTS fd-broker topology PR2a shipped
dormant. After this cutover the privileged half (already real, #338) and the quarantine half
are both live: real T3 inbound → structured extraction by a real quarantined LLM → typed T2
back to the orchestrator, with the privileged process never seeing raw T3 (HARD #5).

This is the **2c** carve-out (Spec C decision 9 / §12) with its own human sign-off. #333 is
done → egress unblocked; PR1 (#411) reconciled the provider seam; PR2a (#412) + Task 7/8b
(#415) shipped and CI-proved the dormant broker topology.

## 2. Verified current-state anchors (confirmed vs tree `42377a52`, 2026-07-11)

- **Child still echoes.** `security/quarantine_child/__main__.py`:
  - `_build_provider(key)` (`:348`) → `_DeterministicProvider()` sentinel (reads+scrubs the
    fd-3 key via `main()`, builds NO client).
  - The extract branch (`:396–409`) writes `_echo_extracted_frame(context)` — it never reaches
    `handle_extract`. `handle_extract` (`:160`) already exists and delegates to
    `provider_dispatch.dispatch_extraction` (the real PR1 seam), imported LAZILY (`:198`) —
    load-bearing for the egress gate (the echo loop never triggers the egress-capable import).
  - `_run_mcp_server(provider, ...)` (`:360`) currently `del provider`s; the loop is structured
    so the 2c swap is surgical.
- **Provider seam is real (PR1).** `provider_dispatch.dispatch_extraction` speaks the #339 seam:
  `native_constrained` iff `NATIVE_CONSTRAINED_GENERATION` (→ `ForcedTool(extract_structured_data)`
  → `tool_calls[0].arguments`) else `prompt_embedded_fallback` (→ `response.content`). Retry loop
  `for attempt in range(_MAX_RETRIES + 1)` (`provider_dispatch.py:236`), `_MAX_RETRIES = 2`
  (`:100`) → **up to 3 `provider.complete()` calls per extraction**; 30 s wall-clock budget
  (`_MAX_TOTAL_WALL_CLOCK_SECONDS = 30.0`).
- **Anthropic adapter already has the egress seam.** `AnthropicProvider.from_settings(cls,
  api_key, model, *, http_client: httpx.AsyncClient | None = None)` (`providers/anthropic_native.py:237`)
  injects an `http_client` (the G7-1 Spec-C seam) but hardcodes `max_retries=2` on the SDK ctor
  (`:253`) — the injected client does **not** carry `max_retries`, so `max_retries=0` must become
  a ctor arg (pre-gate P1a). Same on `deepseek.py`.
- **Core-side broker shipped (PR2a).** `egress/control_fd_broker.py`:
  `make_control_socketpair()` → `(parent_end, child_end)`; `broker_connected_socket(*, parent_end,
  proxy_config)` connects to the gateway proxy off-loop, SCM_RIGHTS-passes the fd, closes the
  core's copy in `finally` (the **must-not-remove** dup-owner close); `recv_passed_fd(control_end)`
  (child side). fd-4 is **strictly one-way** (core→child); the child never sends over it —
  reverse-fd-injection closed by construction.
- **Probe pattern is the child template.** `_brokered_probe.py` reconstructs fd-4 as an AF_UNIX
  socket in `main()`, loops `recv_passed_fd` → one brokered TCP fd per control frame → uses →
  `close()`. The real transport mirrors exactly this receive shape.
- **fd-dance.** `quarantine_child_io.py`: `_lift_above_targets(fd)` (`:668`) + the cleanup loop
  (`:747`) — the ≥2-iteration intermediate-orphan hardening item lives here; the balancing
  `os.close(original)` under `moved=True` **must not be removed** (removing it introduces a
  leak — a PR2a misdiagnosis was corrected).
- **Shipped bwrap policy** (`config/sandbox/quarantined-llm.linux.bwrap.policy`):
  `unshare = ["pid","uts","cgroup","ipc","net"]` (empty netns — **stays**);
  `keep_fds = [3]` (→ `[3,4]`); `ro_binds = [["/usr","/usr"], … ["/lib64","/lib64"]]` with an
  explicit **NO `/etc` bind** security note; **no env-passing key** (so `SSL_CERT_FILE` rides the
  spawn env, not the policy).
- **routing.yaml `[quarantine]`**: `provider: anthropic`, `model: "claude-haiku-3-5"` (STALE — the
  `_ANTHROPIC_PRICING` table has only `claude-haiku-4-5` → unknown-model → most-expensive tariff +
  likely 404), `secret_id: quarantine_provider_api_key`, `max_tokens_per_extraction` present but
  **unwired**. Changing `[quarantine].provider`/`secret_id` is reviewer-gated; the `model` field is
  a documented value edit (treat as human-gated config — §12).
- **Egress gates to invert / extend:**
  `tests/unit/security/test_quarantine_child_import_closure.py` (module-scope closure — `alfred.providers`
  is **not** forbidden, but the egress-capable modules `httpx`/`socket`/`anthropic` must stay off the
  live module-scope graph today); `tests/adversarial/sandbox_escape/test_quarantined_llm_not_yet_spawned_while_egress_open.py`
  (the closed-egress anchor); `tests/unit/egress/test_in_core_http_egress_guard.py` (in-core AST guard);
  `tests/adversarial/sandbox_escape/test_only_sanctioned_raw_socket_egress_site.py` (raw-socket ratchet — the
  broker is the sole INET-connect ∧ SCM_RIGHTS site).

## 3. Decomposition (RATIFICATION FORK 1)

**Chosen (best-judgment, proceeding while requester away): Option A — two PRs.**

- **PR2b-prep** — behavior-neutral hardening (§4). Touches only the real-provider path (dead code
  on today's echo loop) + the fd-dance robustness + config. No egress-ratchet crossing, no shipped
  security-policy edit, **no sign-off**. Normal cadence. Merges first; shrinks the sign-off review.
- **PR2b-golive** — the cutover (§5–§12). Everything that crosses an egress ratchet or edits the
  shipped sandbox policy. **HUMAN SIGN-OFF** at merge (§13). Proven end-to-end against a canned-
  Anthropic docker stub (no real key / gateway / paid call).
- **Follow-up (separate issue, ops, post-merge):** a nightly real-key smoke against the real
  provider (needs a real key in CI secrets) — this is the only piece that exercises real external
  egress, and it is an ops concern, not part of the code cutover. Filed, not gating.

Rejected: **single PR2b** (couples the behavior-neutral fixes to the sign-off gate + one very
large security review); **three PRs / "arm then fire"** (the "arm" stage already inverts the
egress gate + edits the shipped policy — that *is* the posture change, so it is not cleanly
dormant like PR2a; an armed-but-echoing intermediate only adds reviewer burden).

## 4. PR2b-prep — behavior-neutral hardening (no sign-off)

Each item is independently correct regardless of go-live, and testable without a live provider.

1. **P1a — `max_retries=0` on both `from_settings`.** Add a parameter (default preserving today's
   `2`, or flip the default — decide at plan time; the quarantine child passes `0`) so the injected-
   client path can disable SDK-level retries. The spike proved re-dial taming needs `max_retries=0`
   on the SDK ctor (the injected `http_client` cannot carry it). Applies to `anthropic_native.py:253`
   + `deepseek.py` (which currently passes no `max_retries` → SDK-default 2, so P1a *adds* the param
   there). **Keep the `from_settings` default at `2`** — flipping it regresses the live #338 privileged
   path; only the quarantine child passes `0` explicitly (§19-D3). Unit-test both.
2. **P1b — wire `max_tokens_per_extraction`.** Thread the routing.yaml `[quarantine]` value into
   `CompletionRequest(max_tokens=…)` at `provider_dispatch.py:354` + `:374` (today defaults to
   `base.py`'s 1024 → silent truncation of an 8192-budgeted extraction). Config-plumbed; test against
   the fake seam provider.
3. **P1c — thread the cost channel.** `CompletionResponse` carries `tokens_in`/`tokens_out`/
   `cost_usd`; **sum across all attempts** (a 3-attempt thrash = 3 paid calls) and carry the total on
   BOTH the `extracted` AND `typed_refusal` returns — a distinct structured field (never a T3-derived
   field), covered by the `OutboundDlp` post-scan + a no-T3-field test (§19-D2). Name the turn-level
   aggregation seam/owner where privileged (#338) + quarantine cost sum into one turn record.
4. **P1d — `_lift_above_targets` ≥2-iteration orphan.** Harden the fd-dance loop
   (`quarantine_child_io.py:668/747`) so a source landing on the *other* target across ≥2 dup
   iterations cannot orphan an intermediate fd (triple-unreachable today, dormant). Unit-test via
   monkeypatched `os.dup2`/`os.dup` (never real dup2-onto-3/4 in pytest). **Do not remove** the
   `os.close(original)` balancing close under `moved=True`.
5. **P1e — coherent timeout hierarchy (NOT behavior-neutral; §19-A3).** As shipped it is INVERTED and
   under-scoped. Four terms, not three: **`action_deadline (30) ≥ host read-frame ≥ child wall-clock
   budget ≥ SDK per-request read`**. Two traps: (a) `action_deadline` is the true outer bound and the
   child budget already *equals* it (30) → the budget must drop below (target `30 > ~25 > ~20 > ~8`);
   (b) `_HTTP_TIMEOUT` (`anthropic_native.py:61`) is **module-shared with the live privileged path** —
   the child needs its OWN injected `timeout` (a `from_settings` param, parallel to P1a), never a global
   lower. And the child budget is checked only *between* attempts → wrap each `complete()` in
   `asyncio.wait_for(remaining_budget)` to make it a hard ceiling (else a call starting just under budget
   runs a full SDK read past it). The broker `_CONNECT_TIMEOUT_S = 10` is a distinct connect bound and
   stays; the gateway CONNECT-wait idle timeout is a *fifth* constraint (≥ child budget, §6/C1). A unit
   test asserts the full 4-term ordering. Because P1e touches the live host read-frame constant, its
   prep tests assert the echo path is observably unchanged.

**Config caveat:** the routing.yaml `model` correction (P-config) is coupled to go-live (a real model
id is inert while the child echoes) and is human-gated config — carry it with **golive**, not prep
(§12), so prep stays purely code + reviewer-free.

## 5. PR2b-golive — child-side `brokered_egress` transport

New module `security/quarantine_child/brokered_egress.py` (import-closure-safe until the extract
path runs; egress-capable imports stay lazy/off the module-scope graph per §9). Reference shape
(verified by the spike against pinned `anthropic 0.116.0` / `httpx 0.28.1` / `httpcore 1.0.9`):

```
recv_passed_fd(control_end) -> (·, tcp_fd)          # one brokered socket, per attempt (§6)
  PassedFdBackend(tcp_fd)                            # httpcore.AsyncNetworkBackend
    # connect_tcp(host, port, timeout, local_address, socket_options) ignores host/port,
    #   returns a stream over the passed fd; start_tls wraps the SAME fd via the system-store
    #   ssl context; a call counter raises on any 2nd connect_tcp (re-dial instrument).
    -> httpcore.AsyncHTTPProxy(proxy_url=<gateway>, ssl_context=create_default_context(),
                               network_backend=backend, retries=0,
                               max_connections=1, max_keepalive_connections=0)
    -> custom httpx.AsyncHTTPTransport subclass (self._pool = the AsyncHTTPProxy)
    -> httpx.AsyncClient(transport=that)
    -> AnthropicProvider.from_settings(api_key, model, http_client=that)  # max_retries=0 (P1a)
```

**Per-call, no-keepalive** is the spike verdict: one brokered socket → one client → one request →
close. Pooling/keepalive over a one-shot passed fd is unusable (a consumed fd cannot serve a 2nd
dial) and un-de-risked. TLS terminates **in the child** (HARD #5): the core opens a bare TCP socket
and writes zero bytes; the gateway blind-splices ciphertext.

**TLS verify path (spike prov-001):** standalone-python's default OpenSSL verify path misses
`/etc/ssl`; the child must set `SSL_CERT_FILE` to the system bundle (spawn env, §10) so
`create_default_context()` resolves the provider's public CA. This is a real system-store verify
path, **not** disabled verification.

## 6. The retry × one-shot-socket resolution (RATIFICATION FORK 2)

**Problem:** `dispatch_extraction` retries `complete()` up to `_MAX_RETRIES+1 = 3` times per
extraction (schema-validation failures); each `complete()` needs a fresh one-shot socket; fd-4 is
strictly one-way so the child cannot request more mid-extraction.

**Chosen (best-judgment, 4-lens endorsed): the host brokers `_MAX_RETRIES+1` sockets up-front per
extraction; the child consumes one per attempt and drains any it did not use.** Sound and essentially
forced — fd-4 is one-way and the host reads exactly one reply frame, so there is no host-side loop to
service just-in-time socket requests. fd-4 stays strictly one-way: all N `sendmsg`s are core→child;
the child never writes fd-4 (PR2a's reverse-fd-injection closure untouched).

**`N = _MAX_RETRIES+1 = 3` is a hard ceiling — CONDITIONAL on P1a (provider-lens, gating).** Trace:
`_call_provider` is the sole `complete()` site, called once per loop iteration, ≤3 iterations;
`ProviderUnavailableError` short-circuits (≤N); empty-tool_calls/malformed consume one socket then
retry (≤N); the wall-clock deadline only *reduces* the count. **But** this holds only if the SDK does
not re-dial under a single `complete()` — with `max_retries≥1` a 429/5xx/`APIConnectionError` re-dials
at the SDK layer, the one-shot `PassedFdBackend` cannot serve it, demand balloons to 3×3=9, and the
backend raise is a *generic* exception (unmapped to `ProviderUnavailableError`) that propagates raw. So
P1a (`max_retries=0`) + httpcore `retries=0` (§5) are a **hard pre-gate**: N=3 is correct only once P1a
is live. A unit test asserts the child provider is built `max_retries=0`.

**Leftover drain — deterministic, non-blocking, EOF-aware.** The child is spawned once per daemon boot
(`daemon_runtime.py:334`) and services every extraction over one long-lived fd-4, so leftover hygiene is
a whole-daemon-life concern, not per-turn. After `dispatch_extraction` returns, the child drains the
`(N − attempts_used)` unused sockets. Use a **non-blocking** `MSG_DONTWAIT` recv loop (close each fd,
stop on `EAGAIN`) — NOT a hard-count blocking `recv_passed_fd` (a miscount blocks forever and wedges
the child under the host read-frame timeout). Race-free: the host's N `sendmsg`s all enqueue into the
child's fd-4 buffer *before* the extract frame is written to stdin, and the child drains only *after*
reading that frame → all leftovers are already present; a 0-byte/no-fd `recvmsg` (peer closed / STOP)
also ends the drain. Drain lives in `_run_mcp_server`'s extract-branch `finally` (which owns the fd-4
socket), never inside the egress-free `dispatch_extraction`. Close (never `detach`).

**Ordering + partial-broker-failure.** Host brokers the N **concurrently** (`asyncio.gather` — else
up-front latency is `N × _CONNECT_TIMEOUT_S` serial before the extract frame even dispatches), then
writes the extract frame. **If brokering fails on socket k of N**, k−1 fds are already in-flight in the
fd-4 buffer un-received; the extraction refuses before dispatch, but on the persistent child those k−1
would be consumed by the *next* extraction's attempt-1 (stale-socket confusion). So a mid-batch failure
must reclaim the in-flight fds (a next-extraction preamble drain, or close+rebuild the control
socketpair); an integration test drives "broker fails on socket 2 of 3 → then a clean extraction".

**Gateway idle-reaping (new risk — core-lens; none-else-named).** Pre-brokered sockets #2/#3 sit
accepted-but-idle at the gateway (no CONNECT sent) until a late retry uses them — possibly the whole
retry-loop duration later. If the gateway L7 proxy's CONNECT-wait / idle-accept timeout is shorter than
the child's worst-case time-to-third-attempt, the socket is dead on arrival → `complete()` fails →
terminal `provider_unavailable`, a legitimate retry silently lost. **Invariant: gateway CONNECT-wait
timeout ≥ child wall-clock budget** (reinforces the small-budget target in §4 P1e); a sign-off item +
an integration test (broker N, delay past a plausible idle window, use socket #N). Verify the gateway's
actual timeout at plan time.

Rejected: reversing fd-4 to request/response (security regression vs PR2a); moving the retry loop
host-side (the T3 *content* lives only in the child's `_content_cache` and the socket binding is
child-side — **note:** the retry prompt does NOT carry the previous attempt; `_build_extraction_prompt`
rebuilds from a closed-vocab category + schema only, the prior response deliberately removed per
sec-001 — the earlier "retry prompt embeds the previous attempt" rationale was factually wrong, the
conclusion holds); one-socket + disable retries (loses schema-validation reliability).

## 7. Host-side wiring (privileged side)

- **Spawn.** Turn on the PR2a opt-in: `spawn_quarantine_child_io(control_fd=True,
  child_module=_CHILD_MODULE, egress_config=<EgressProxyConfig>)`. The live/echo default stays
  `control_fd=False`; go-live flips the *production* spawn-site (the supervisor/`QuarantinedExtractor`
  construction path) to pass `True`. Both `dup2`s (key fd 3 + control fd 4) already live in one
  synchronous Popen zero-await window (PR2a).
- **Per-extraction brokering lives in `QuarantineStdioTransport.dispatch`, NOT `QuarantinedExtractor.extract`
  (architect + core, code-backed).** The extractor speaks JSON-RPC over an abstract `PluginTransport`
  and holds no `_SubprocessChildIO`; `broker_socket()` lives on the child-io the stdio transport owns,
  and the shipped PR2a code names this exact home (`quarantine_child_io.py:361-367`: "PR2b, when
  `QuarantineStdioTransport.dispatch` actually calls it"). `dispatch` already owns the
  `write_frame → read_frame` sequence, so it guarantees "broker N (concurrently), *then* write the
  extract frame" atomically, leaving the extractor + its `dispatch("quarantine.extract", …)` call
  untouched. The retry count is a shared constant hoisted to `alfred.security.quarantine` (both host
  and child already import it) — NOT the privileged host importing the child-only `provider_dispatch`.
- **Per-call egress-audit success row (ADR-0050 Decision 7 — HARD PR2b pre-gate).** ADR-0050 requires
  the durable, signed, core-side **success-path** per-extraction egress-audit row (each brokered target
  host:port) to be implemented *before* the sign-off, not left as a residual. Golive wires it (each
  `broker_connected_socket` success → an audit row) + its write-path test; §13 lists it.
- **Failure audit.** A broker `ControlFdBrokerError` → a `SANDBOX_REFUSED`-class row keyed on the
  closed-vocab `reason` + a `quarantine.transport_failed` typed refusal (HARD #7); never a hang. First
  live audited broker caller (PR2a deferred it).
- **DLP / hookpoint chain unchanged.** The `security.quarantined.extract` pre/post/error chain +
  `OutboundDlpExtractSubscriber` continue to gate the *result* (post-scan of the validated model_dump);
  brokering is transport plumbing beneath the existing contract.

## 8. Provider construction reshape (RATIFICATION FORK 3 — wrapper-provider, not a bare factory)

Per-call sockets mean the client cannot be built at boot, AND the seam must keep `dispatch_extraction`
egress-free (its docstring guarantees "imports no SDK/httpx"), so the per-call socket must NOT come from
a factory the dispatcher rebinds inside its loop. Shape (core-lens seam, security-corroborated):

- `_build_provider(key)` (boot, import-light — no httpx/anthropic at module scope) → a `_ProviderFactory`
  (frozen: key + model), NOT a live client. Refuse-boot on unset key (§11). Key-free `__repr__` + an
  anti-leak test (the `_DeterministicProvider` discipline — the factory holds the key for the child's
  whole life).
- A `BrokeredProviderSource(factory, control_end)` (lazy egress imports live in `brokered_egress` only):
  - `capabilities()` — **socket-free** (Anthropic caps are a model-invariant classvar), so
    `dispatch_extraction` picks `extraction_mode` **once before the loop** with no bound provider
    (`provider_dispatch.py:209`).
  - `bind()` — an `@asynccontextmanager`: `recv_passed_fd` (off-loop) the next pre-brokered socket →
    `PassedFdBackend(fd)`→transport→`httpx.AsyncClient` → `factory.build(http_client=…, max_retries=0,
    timeout=<child read timeout, §4 P1e>)` → `yield provider` → **`finally: await client.aclose()`**.
    `aclose()` is the **sole fd owner** — do NOT also `socket.socket(fileno=fd)` + close it (the
    `_brokered_probe.py` raw-socket close is for the probe, not the httpx path; a second close hits
    EBADF or closes a *reused* fd number). Runs on every exit incl. the `ProviderUnavailableError`
    raise from inside `complete()`.
  - `drain_leftovers()` — the non-blocking sweep (§6).
- `dispatch_extraction(source)` (renamed param) calls `capabilities()` once, then per attempt
  `async with source.bind() as provider: raw = await asyncio.wait_for(_call_provider(...),
  timeout=remaining_budget)` (the per-call hard ceiling, §4 P1e). Structure + import contract stay
  surgical; each `complete()` gets exactly one socket, closed after.
- **Model + `max_tokens` delivery.** The bwrapped child has a scrubbed env + no config bind → cannot
  read `routing.yaml`. The model id + `max_tokens_per_extraction` reach the child via the scrubbed
  spawn-env allowlist (`_child_env`, the `SSL_CERT_FILE` precedent) — host-controlled, non-secret,
  non-T3. The stale-model correction (§12) rides that same channel; threaded `handle_extract →
  dispatch_extraction → _call_provider` into `CompletionRequest.max_tokens`.
- **Empty-content short-circuit.** A missing handle → `content = b""` → three *real* paid `complete()`
  calls all failing validation. Add a child-side guard: `if not content: return cannot_extract` before
  the loop (honours the `handle_extract` "missing → cannot_extract" contract without 3 paid round-trips
  + 3 consumed sockets).

## 9. Security-gate inversions + guards

- **Child module-scope egress gate.** The live child must now reach egress-capable imports (`socket`
  for `recvmsg`; `httpx`/`httpcore`/`anthropic` for the transport). Keep them **lazy** (imported on
  the extract path, off the module-scope graph) where possible — the closure test
  (`test_quarantine_child_import_closure.py`) stays green for module scope. Where a module-scope
  import is unavoidable, **invert** the closed-egress anchor
  (`test_quarantined_llm_not_yet_spawned_while_egress_open.py`) with the sbx-2026-005 precedent, and
  record the inversion + its justification. `alfred.providers` is already allowed.
- **`_CONSTRUCT_ALLOWLIST` / in-core AST guard.** The child's `AsyncAnthropic` / `httpx.AsyncClient`
  construction is a *new* sanctioned egress-capable construct — allowlist it in the in-core HTTP-egress
  guard (`test_in_core_http_egress_guard.py`) narrowly (the `brokered_egress` module only). The raw-
  socket ratchet (`test_only_sanctioned_raw_socket_egress_site.py`) already covers the core broker;
  confirm the child's `socket(fileno=…)` reconstruction + `recv_passed_fd` do not trip it (no
  INET-connect ∧ SCM_RIGHTS in the child — the child only *receives*).
- **ADR (§19-D8).** NEW **ADR-0051 (quarantine-half go-live)** — sibling to ADR-0049 (the privileged-half
  go-live) — records forks 2+3, the per-call no-keepalive provider lifecycle, and the `/etc/ssl/certs`
  CA carve-out. Amend **ADR-0050** (Proposed→Accepted; record the flips it forward-gated: dormancy
  off→on, CA bind, `_CONSTRUCT_ALLOWLIST` entry, and Decision 5's CONNECT-location = child-does-CONNECT
  since #358 is still open). Amend **ADR-0040** residual panel ((iv) now has a live brokered caller;
  (vii) resolved by the per-call egress-audit row, §7). The empty-netns kernel isolation + one-way fd-4
  remain the containment; note the accepted residuals (§13 non-claims).

## 10. Shipped bwrap policy edit (`quarantined-llm.linux.bwrap.policy`)

- `keep_fds = [3]` → `[3, 4]` (declaration-only; `keep_fds` emits no bwrap flag — fd 4 crosses via
  bwrap default inheritance of the non-CLOEXEC `pass_fds=(3,4)` child end).
- Add the **narrowest** CA bind: `["/etc/ssl/certs", "/etc/ssl/certs"]` — never `/etc`. The policy's
  explicit "NO `/etc` bind" security note must be updated to carve out this CA-store-only subpath
  (no `/etc/passwd`/`shadow`/`resolv.conf` exposure); record the carve-out in the ADR.
- `SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt` in the **spawn env** (the policy has no env key;
  the supervisor/launcher builds the child env). Verify the real proto-python interpreter's verify
  path resolves the CA (the spike's standalone-python needed this).
- **empty netns stays** (`unshare` keeps `net`) — the whole point: egress ONLY via the brokered fd.
- `--ro-bind /lib64` is x86-only (#269 arm64 drops it); the real x86 CI lane keeps it. Flag #269 as a
  known arch residual (the docker real-spawn lane runs true-x86_64).
- The closed-egress anchor gate must still pass (the child cannot open its own socket — the C1
  ENETUNREACH negative control from Task 7 proves it); the CA bind + keep_fds edit must not widen
  egress.

## 11. Refuse-boot (unset key)

Today the fd-3 key is read + scrubbed but a `_DeterministicProvider` is built regardless. Go-live:
an unset / empty provider key → **refuse to boot** (typed error + a `_BootFailure` carrier /
`failure_reason`, `t()`-localized, an except-arm at `_commands.py` mirroring `QuarantineChildSpawnError`).
Host-side broker/proxy resolution happens before spawn; a missing proxy config fail-closes
(`IOPlaneUnavailableError`) the same way. No silent fallback to echo (that would be a HARD #7 silent
security-path failure).

## 12. HARD #5 provenance re-validation + config

- **Provenance premise + the CORRECT HARD#5 invariant (security-lens).** The #338
  `_ExtractionAwareChildDouble` plants the marker on a **schema-dropped** field (`__injected_frame__`);
  the real LLM has no such concept — it projects raw body text into `{text,intent}`, so a marker in the
  message *body* is *legitimately* extracted into `text`. The "marker never rides a returned field"
  invariant is therefore **wrong** for the real extractor (falsely-failing when the marker is in the
  body, or vacuous when it's in a schema-dropped field the real path can't reproduce). Restate HARD#5
  **structurally**: assert (a) the reply is schema-valid, `extra="forbid"`, **no `tool_calls`**, no
  extra keys (no free-form escape); (b) it is tagged **T2**; (c) no control-frame / raw-envelope
  passthrough; (d) the raw T3 **envelope** (transport framing, `handle_id`, host envelope) never appears
  verbatim — NOT the message *content*, which the schema is designed to carry. The privileged process
  only ever sees the validated `Extracted`/`TypedRefusal`. The double must stay faithful to the real
  extractor schema.
- **T3-steers-extraction adversarial corpus (release-blocking).** Containment here = schema + T2 tag,
  **not** content sanitization: a faithful extraction of hostile T3 yields *hostile-but-typed* T2. The
  ai-001 payload instructs the *quarantined* extractor to break schema (emit `tool_calls` / extra keys /
  a system-override / free-form text) → assert a schema-bound refusal, no free-form escape. NOTE it can
  only truly pass once the child does real extraction (the echo child false-greens), so it lands **in
  golive** (pre-written/reviewed so the sign-off isn't seeing net-new payloads cold), or is registered
  in `adversarial.yml` skip-until-golive. Schema-valid `AdversarialPayload` (`extra="forbid"`; real
  `id`/`threat`/`ingestion_path`/`payload`/`expected_outcome`/`references`).
- **Config (human-gated, carried with golive):** correct routing.yaml `[quarantine].model`
  `claude-haiku-3-5` → the current Haiku id in `_ANTHROPIC_PRICING` (`claude-haiku-4-5` — confirm the
  live id at plan time) so pricing resolves + the model exists. `[quarantine].provider`/`secret_id`
  are reviewer-gated and unchanged.

## 13. Human sign-off (the go-live gate)

PR2b-golive merges only on an explicit maintainer sign-off. The sign-off checklist (what the human is
attesting to):

1. The child performs real egress **only** over the brokered fd; empty netns intact; C1 ENETUNREACH
   negative control green on the x86 real-spawn lane.
2. HARD #5 intact: TLS terminates in the child; core writes zero bytes; the privileged process never
   sees raw T3 (provenance re-validation §12 green).
3. Refuse-boot on unset key + fail-closed on unset proxy (§11); **the echo path is DELETED** — the
   child cannot emit an `extracted` frame without a real `provider.complete()` (§16/§19-B1).
4. The T3-steers adversarial corpus is release-blocking + green; the full adversarial suite green
   (security path touched).
5. fd-4 stays one-way; the `os.close(original)` balancing close intact; `_lift_above_targets` orphan
   hardened; leftover sockets drained deterministically (no fd leak across ≥2 extractions, §6).
6. The docker canned-Anthropic integration test proves the full path (real bwrap + real broker + real
   TLS + real SDK) with **no** real key / gateway / paid call — including a *retry* socket and a
   *delayed-use* (idle-reaping) socket.
7. The durable success-path per-call egress-audit row (target host:port) is wired + tested
   (ADR-0050 Decision 7 hard pre-gate, §7/§19-B4).
8. The gateway CONNECT-wait/idle timeout ≥ the child wall-clock budget (verified, §6/§19-C1).

**Explicit non-claims (accepted residuals, recorded in the ADR):** the canned stub validates nothing
about the real gateway's acceptance policy (destination allowlist, gateway-side DNS, refuse-literal-IP,
reject-non-globally-routable, `Proxy-Authorization`/mTLS — the #358 residual); real-gateway + real-
provider + real-key is the nightly smoke follow-up. #269 (arm64 `/lib64`) unchanged.

## 14. Ratification forks (summary)

1. **Decomposition** — Option A (prep PR → golive PR + nightly-smoke follow-up). 4-lens endorsed; §3.
2. **Retry × one-shot socket** — host brokers `_MAX_RETRIES+1` up-front (concurrently), child consumes
   + drains leftovers (non-blocking), fd-4 stays one-way. 4-lens endorsed; N=3 conditional on P1a; §6.
3. **Provider construction reshape** — a `BrokeredProviderSource` wrapper-provider (socket-free
   `capabilities()` + per-attempt `bind()` CM), NOT a bare factory handed to the egress-free
   dispatcher. §8. (Seam pinned by the core+security lenses.)
4. **Sign-off is at merge** — this spec + the plan are negotiated normally; the human gate is the
   golive merge, per §13.
5. **ADR-0050 Decision 7 audit row** — best-judgment: **wire** the durable success-path per-call
   egress-audit row into golive (ADR-0050 makes it a hard pre-gate; re-deferring weakens the posture at
   go-live). §7/§13/§19-A5. User may override to re-defer + amend ADR-0050 §7.

## 15. Test strategy

- **Unit (100% line+branch on touched security paths):** prep items (P1a–P1e) against fakes; the
  `brokered_egress` transport shape (a fake `recv_passed_fd` + a canned-response stream — the spike's
  `test_backend.py` is the template, ported into the real suite); the provider factory `bind`; refuse-
  boot; the egress-gate inversions (assert the new allowlist entries + that the closure holds for
  everything else).
- **Integration (docker, privileged-Linux lane):** extend the Task-7 real-spawn test to drive a REAL
  extract end-to-end — real bwrapped empty-netns child, real broker, real TLS, a **canned-Anthropic
  https stub** (self-signed CA in the system store; Anthropic-shaped JSON; the spike's `canned.py`/
  `stubs.py` ported). Assert: a real `Extracted` returns; HARD #5 (the first bytes the stub-gateway
  sees on the brokered socket are the **child's** `CONNECT` request — then blind-spliced TLS
  ciphertext — proving the core prepended zero app bytes; the `\x01` broker frame rode the AF_UNIX
  control fd, not the TCP socket); the retry path brokers/consumes N sockets; no fd leak across ≥2
  extractions. No real key / gateway / paid call. Mirror the `#245` both-halves paper-gate (assert
  RAN, not skipped).
- **Adversarial (release-blocking):** the T3-steers corpus (§12) + the full suite (security path
  touched). The closed-egress anchor + raw-socket ratchet stay green.
- **CI gates:** the named `brokered_egress` + `control_fd_broker` 100% coverage gates in both jobs;
  the docker leg's assert-RAN paper-gate.

## 16. Must-not-regress (carried from PR2a review)

- **Golive DELETES the echo path — does not bypass it (security HIGH).** Remove `_echo_extracted_frame`,
  `_DeterministicProvider`, and the `_build_provider` sentinel return. If any survive behind a residual
  branch/flag, a misconfig routes to echo → the child fabricates a schema-valid `extracted` frame from
  raw T3, the host tags it T2 and trusts it (HARD #7 silent security-path failure; T3 laundered to
  trusted T2 with no LLM in the loop). Test: the child cannot emit an `extracted` frame without a real
  `provider.complete()` (no provider → refuse/raise, never echo).
- **Do not remove** the fd-dance `os.close(original)` balancing close under `moved=True`
  (`quarantine_child_io.py:747`) — removing it introduces an fd leak (a single-lift path is balanced;
  the PR2a "extra live ref" concern was a proven misdiagnosis). P1d closes only *already-moved*
  intermediates in-loop; the caller's original-close stays.
- fd-4 stays **strictly one-way** (core→child).
- The `__main__.py` live-echo path stays byte-identical **only in prep**; golive is exactly the change
  that flips it — do not claim byte-identity for golive. Prep's P1c/P1e/P1d touch *live* surfaces (fd-1
  frame, host read-frame timeout, the control_fd=False clobber window) so prep tests assert the echo
  path is observably unchanged.
- Empty netns preserved; the child never opens its own socket.

## 17. Out of scope / follow-ups

- **Nightly real-key smoke** (real Anthropic, real gateway, real key in CI secrets) — separate ops
  issue; the only real-external-egress exercise; not gating the cutover.
- **#358** — core→proxy `Proxy-Authorization`/mTLS (the brokered socket carries no proxy auth today).
- **#414** — `_terminate_and_reap` reap-error logging (mirror the `read_frame_failed`/`stderr_drain_failed`
  `error_class` idiom); small, standalone, can land anytime.
- **#269** — arm64 `/lib64` launcher hard-bind.
- **#410** — tools-on (`build_tool_registry`/`web.fetch` live-wire) — the deferred half of #338,
  unrelated to the quarantine cutover.
- **policies.yaml `quarantine.extraction_max_retries` loader** — `_MAX_RETRIES` is a constant today;
  wiring the config loader is orthogonal (if it lands, the host reads the same value it brokers for).

### PR2b-prep review carry-forwards (golive MUST address)

From the PR2b-prep whole-branch review (security + provider, both READY-TO-MERGE) — dormant paths
prep introduced that golive activates:

- **Validate `max_tokens_per_extraction > 0` at the config-load / spawn-env boundary (fail loud).**
  When golive threads the routing.yaml value into `CompletionRequest(max_tokens=…)` inside
  `_call_provider`'s `try`, a `<= 0` value raises pydantic `ValidationError` — which the retry loop
  catches as retry-eligible → 3 identical failing attempts → `cannot_extract`, masking a config
  misconfiguration as an extraction refusal (loses the loud fail; HARD #7 shape). Guard it upstream
  (2-lens corroborated).
- **Make the child SDK read-timeout ↔ attempt-count a deliberate tuning decision.** With golive's
  per-call `wait_for(remaining_budget)` the 20s budget is a hard ceiling, but "3 attempts × ~8s read
  + backoff (0.5+1.0)" ≈ 25.5s > 20s, so attempt 3 gets a truncated ~2-3s remainder — effectively ~2
  solid attempts under a slow provider. Pick the SDK read timeout + `_MAX_RETRIES` so the intended
  attempt count actually fits the budget (provider-lens).
- **The per-frame host bound is `2 × _READ_FRAME_TIMEOUT_S` (header + body = 50s theoretical).** It is
  capped at 30s only by the `asyncio.timeout(action_deadline_seconds)` outer wrap on the extraction
  path (`fetch_dispatcher.py:662`). If golive routes an extraction through a path lacking that wrap,
  add an equivalent outer bound (security-lens; golive sign-off checklist note).

## 18. Next

Ratify §14 (esp. forks 1 + 2) → `writing-plans` for PR2b-prep (small) → focused plan-review →
subagent-driven TDD → full `/review-pr` fleet (security ALWAYS) + BOTH CodeRabbit → merge. Then
`writing-plans` for PR2b-golive → focused plan-review (core + security own the dense transport + gate
code) → subagent-driven TDD → full `/review-pr` fleet + BOTH CR → **HUMAN SIGN-OFF** → merge. Then file
the nightly-smoke follow-up. Give write/fix subagents the HARD "never git stash/checkout/reset — read a
base via `git show <base>:<path>`" line.

## 19. rev.2 fold log — focused 4-lens design review (2026-07-11)

Ran a focused 4-lens design review on rev.1 (architect / security / core / provider), each read-only
against the tree. **All four AGREE/SOUND-WITH-CHANGES; 0 design-killers** — the decomposition (Option
A), broker-N-up-front, one-way fd-4, and every rejected alternative are endorsed. `N=3` was traced +
confirmed (provider) and the framing proven deadlock-free (core: AF_UNIX `SOCK_STREAM` never coalesces
across an `SCM_RIGHTS` skb — one frame per `recv`). Findings below make it trustworthy/complete, not
"don't do this". Lens attribution in brackets; this log **overrides** section bodies where they conflict.

**A. Strongly corroborated (multi-lens) — folded HIGH:**

- **A1 — Drain deterministic on a persistent child [security + provider + core].** Child = one spawn
  per daemon (`daemon_runtime.py:334`); un-received leftovers sit in the fd-4 buffer and the *next*
  extraction pulls a stale one. Fold: **non-blocking `MSG_DONTWAIT` drain-until-EAGAIN** in the
  extract-branch `finally` (a hard-count blocking drain wedges the child on a miscount); race-free
  because all N enqueue before the extract frame. §6.
- **A2 — N=3 conditional on P1a [provider, core concurs].** `max_retries≥1` → SDK re-dial → one-shot
  backend raises raw → demand up to 9. P1a (`max_retries=0`) + httpcore `retries=0` are a hard pre-gate;
  §6 states the dependency + a unit test asserts `max_retries=0`.
- **A3 — Timeout hierarchy worse than rev.1 [core + security + provider].** `action_deadline` (30) is
  the real outer bound and child budget already *equals* it (no headroom → drop it below); `_HTTP_TIMEOUT`
  is **shared with the live privileged path** (can't lower globally → the child needs its OWN injected
  `timeout` param, parallel to P1a); the budget is checked only between attempts (wrap each `complete()`
  in `asyncio.wait_for(remaining_budget)`). Target `action_deadline(30) > host_read(~25) > child_budget
  (~20) > SDK_read(~8)`; a 4-term ordering assertion. P1e reclassified **not** behavior-neutral. §4/§8.
- **A4 — Fork-3 seam = wrapper-provider, not bare factory [security + core + provider].** `dispatch_extraction`
  is egress-free by contract → a `BrokeredProviderSource` (socket-free `capabilities()` + per-attempt
  `bind()` CM, `client.aclose()` the sole fd owner) — NOT a factory rebinding inside the loop. §8.

**B. Solo but decisive (code/ADR-backed) — folded HIGH:**

- **B1 — Golive DELETES the echo path [security].** A surviving `_echo_extracted_frame`/`_DeterministicProvider`
  behind any branch = raw-T3-laundered-to-T2 with no LLM (HARD #7). Remove them + a no-echo test. §16.
- **B2 — HARD#5 test invariant wrong for the real extractor [security].** "marker never rides a
  returned field" is falsely-failing/vacuous; restate structurally (schema-valid / `extra="forbid"` /
  no `tool_calls` / raw T3 *envelope* never verbatim — the *content* is what the schema carries). §12.
- **B3 — Brokering placement wrong [architect + core].** Belongs in `QuarantineStdioTransport.dispatch`,
  not `QuarantinedExtractor.extract` (the shipped PR2a comment `quarantine_child_io.py:361-367` names it).
  Retry count hoisted to a shared `alfred.security.quarantine` constant (no child→privileged import). §7.
- **B4 — ADR-0050 Decision 7 audit row dropped [architect, ratification-blocking].** The durable
  success-path per-call egress-audit row (target host:port) is a hard PR2b pre-gate. **Best-judgment:
  wire it into golive** (§7) + list in §13; fork 5 lets the user re-defer + amend ADR-0050 §7.

**C. New risk none-else-named — folded HIGH:**

- **C1 — Gateway idle-reaping of pre-brokered sockets [core].** Sockets #2/#3 sit accepted-but-idle at
  the gateway until a late retry; if the gateway CONNECT-wait timeout < time-to-3rd-attempt, the socket
  is dead on arrival. Invariant: gateway CONNECT-wait ≥ child budget; sign-off item + delayed-use test;
  verify the gateway's actual timeout at plan time. §6/§13.

**D. Folded MED:**

- **D1 — Model + `max_tokens` delivery [provider + core].** Child has no config bind → both ride the
  scrubbed spawn-env allowlist (`_child_env`, `SSL_CERT_FILE` precedent); `max_tokens` threaded to
  `CompletionRequest.max_tokens`; over-budget still surfaces as `cannot_extract`. §8.
- **D2 — Cost sums across attempts + rides refusals [provider + security + architect].** A 3-attempt
  thrash = 3 paid calls; accumulate in the loop, carry on BOTH `extracted` AND `typed_refusal`, distinct
  non-T3 field under `OutboundDlp` post-scan + a no-T3-field test. Architect: name a turn-level
  aggregation seam/owner where privileged (#338) + quarantine cost sum into one turn record. §4 P1c.
- **D3 — P1a default stays 2 [architect + provider + security].** Flipping `from_settings` default to 0
  regresses the live #338 privileged path; the child passes `0` explicitly; `deepseek.py` must *add* the
  param (currently SDK-default 2). §4 P1a.
- **D4 — Partial-broker-failure fd hygiene [security].** Broker fails on socket k of N → k−1 in-flight
  fds orphaned → consumed by the next extraction. Reclaim on failure (preamble drain or rebuild the
  socketpair) + a "broker fails on 2 of 3 → clean extraction" test. §6.
- **D5 — fd double-close owner [core + provider].** httpcore closes the passed fd on `aclose`; do not
  also `socket.socket(fileno=fd)`+close it (EBADF / reused-fd). Sole owner = the httpx client's `aclose`.
  §8.
- **D6 — P1d edits the LIVE clobber window [security + core].** `_lift_above_targets` runs on every
  echo spawn (control_fd=False single-target path); guard with a byte-identity test; close only
  already-`moved` intermediates; keep the original-close. §4 P1d / §16.
- **D7 — Empty-content short-circuit [core].** Missing handle → `content=b""` → 3 paid calls; child-side
  `if not content: return cannot_extract` before the loop. §8.
- **D8 — New ADR-0051 [architect].** The quarantine-half go-live gets its own ADR (sibling to ADR-0049
  the privileged-half go-live) recording forks 2+3, the per-call no-keepalive lifecycle, and the
  `/etc/ssl/certs` CA carve-out; amend ADR-0050 (Proposed→Accepted) + ADR-0040 residual panel
  ((iv) now has a live brokered caller; (vii) per B4). §9.
- **D9 — Broker N concurrently + gateway audit noise [provider + security].** `asyncio.gather` the N
  brokers (else `N × _CONNECT_TIMEOUT_S` serial); confirm the gateway doesn't audit
  connect-then-close-without-CONNECT as a deny/anomaly (2/extraction = audit-graph noise resembling
  probing). §6.

**E. Folded LOW / confirmations:**

- **E1** In-core HTTP-egress guard needs exactly ONE `_CONSTRUCT_ALLOWLIST` entry for `brokered_egress.py`
  (constructs `httpx.AsyncClient`); the raw-socket ratchet is NOT tripped (child only `recvmsg`s, no
  `sendmsg(SCM_RIGHTS)`), no entry there [core, confirms §9].
- **E2** `follow_redirects=False` on the child client (a redirect forces a 2nd `connect_tcp` the
  one-shot backend raises on) [provider].
- **E3** §6 rationale factual fix: the retry prompt does NOT carry the previous attempt (closed-vocab +
  schema only, sec-001) [security] — folded into §6.
- **E4** CA-file resolves under the bound `/etc/ssl/certs` subpath (may be a symlink; the integration
  TLS handshake proves it); leftover release uses `close`, never `detach` [security + core].
- **E5** Doc drift to file (human-gated, not edit): golive makes CLAUDE.md HARD#5 fully true + lands the
  "never open an external socket from core" carve-out PR2a deferred; ADR-0050 Decision 5 CONNECT-location
  forward-gate stays Option A since #358 is still open — state explicitly [architect].

**Plan-time verifications (raise confidence to high):** (1) the spike's `PassedFdBackend` fd-ownership
on stream `aclose` (D5); (2) `anthropic 0.116.0` fully suppresses SDK re-dial at `max_retries=0` (A2);
(3) whether the Task-7 docker leg brokered ≥2 sockets *simultaneously queued* then drained, or in
lockstep — if lockstep, the "N in-flight at once" mechanic is unproven and the §15 integration test must
add it explicitly (core); (4) the AlfredOS gateway's CONNECT-wait/idle timeout value (C1); (5) the live
Haiku model id in `_ANTHROPIC_PRICING` + the SDK per-request `timeout` still applying with an injected
`http_client` (A3).

Review transcripts (agent outputs) were consumed inline; no separate audit-trail dir this pass.

# #340 PR2b — real-LLM quarantine child go-live cutover (design)

**Status:** DRAFT — awaiting ratification. Committed on branch `340-pr2b-golive-design`
off main `42377a52`. Do **not** proceed to `writing-plans` until the decomposition +
design forks in §14 are ratified. The go-live PR additionally carries a **HUMAN SIGN-OFF**
at merge (§13) — design + ratify here; the sign-off gates the *merge*, not this spec.

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
   + `deepseek.py`. Unit-test both.
2. **P1b — wire `max_tokens_per_extraction`.** Thread the routing.yaml `[quarantine]` value into
   `CompletionRequest(max_tokens=…)` at `provider_dispatch.py:354` + `:374` (today defaults to
   `base.py`'s 1024 → silent truncation of an 8192-budgeted extraction). Config-plumbed; test against
   the fake seam provider.
3. **P1c — thread the cost channel.** `CompletionResponse` carries `tokens_in`/`tokens_out`/
   `cost_usd`; surface them from the extraction into the turn cost model (the fd-1 result already
   round-trips the extraction — decide the carrier at plan time; the cost fields must not ride a
   T3-derived field).
4. **P1d — `_lift_above_targets` ≥2-iteration orphan.** Harden the fd-dance loop
   (`quarantine_child_io.py:668/747`) so a source landing on the *other* target across ≥2 dup
   iterations cannot orphan an intermediate fd (triple-unreachable today, dormant). Unit-test via
   monkeypatched `os.dup2`/`os.dup` (never real dup2-onto-3/4 in pytest). **Do not remove** the
   `os.close(original)` balancing close under `moved=True`.
5. **P1e — coherent timeout hierarchy.** As shipped the hierarchy is INVERTED: host read-frame
   `_READ_FRAME_TIMEOUT_S = 15` < child budget 30 s < SDK read 60 s → a real 20 s extraction is torn
   host-side as a spurious `transport_failed`. Make it monotone: **host read-frame ≥ child wall-clock
   budget ≥ SDK per-request read timeout**. Reconcile the three constants (host `quarantine_child_io`,
   child `provider_dispatch._MAX_TOTAL_WALL_CLOCK_SECONDS`, adapter `_HTTP_TIMEOUT`); the broker
   `_CONNECT_TIMEOUT_S = 10` is a distinct connect bound and stays. This is constants + a documented
   invariant; a unit test asserts the ordering so it can't silently re-invert.

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

**Chosen (best-judgment): host brokers `_MAX_RETRIES+1` sockets up-front per extraction; the child
consumes one per attempt via `recv_passed_fd`, and closes any it did not use.**

- Keeps fd-4 strictly one-way (no reverse-fd-injection surface reopened).
- Cheap: an unused brokered socket only ever connected to the **local** gateway proxy port; it never
  sent a CONNECT, so the gateway never dialed upstream to the provider — closing it is a local FIN,
  no wasted upstream/paid work.
- The retry attempt count is a single shared constant (`_MAX_RETRIES`) both sides read, so "how many
  to broker" is not guesswork. If P1b/retry config makes it dynamic, the host reads the same value it
  passes to the child.
- The child MUST close leftover sockets when the extraction ends (success or exhaustion) so no fd
  leaks across extractions; the host closes its parent-end copies immediately after each `sendmsg`
  (the existing broker `finally`).

**Ordering:** host brokers the N sockets, then dispatches the `quarantine.extract` frame; the child
reads extract, then `recv_passed_fd`s attempt-1's socket already waiting (recv blocks if not). A STOP/
teardown closes the parent control end; the child's `recv_passed_fd` then raises `ControlFdBrokerError`
(loud), ending the loop cleanly.

Rejected: reversing fd-4 to request/response (security regression vs PR2a); moving the retry loop
host-side (the retry prompt embeds the *previous attempt* — a T3-derived, child-only, single-use
concern; hoisting it host-side forces re-ingest and statefulness across calls); one-socket +
disable retries (loses the schema-validation reliability the seam was built for).

## 7. Host-side wiring (privileged side)

- **Spawn.** Turn on the PR2a opt-in: `spawn_quarantine_child_io(control_fd=True,
  child_module=_CHILD_MODULE, egress_config=<EgressProxyConfig>)`. The live/echo default stays
  `control_fd=False`; go-live flips the *production* spawn-site (the supervisor/`QuarantinedExtractor`
  construction path) to pass `True`. Both `dup2`s (key fd 3 + control fd 4) already live in one
  synchronous Popen zero-await window (PR2a).
- **Per-extraction brokering.** In `QuarantinedExtractor.extract` (`quarantine.py`), before dispatching
  the `quarantine.extract` frame, broker `_MAX_RETRIES+1` sockets over the child's `parent_end`
  (`_SubprocessChildIO.broker_socket()` — the concrete accessor PR2a added) via
  `broker_connected_socket`. A broker failure → loud `ControlFdBrokerError` → a `quarantine.transport_failed`
  audit row + typed refusal (HARD #7); never a hang.
- **Audit.** The broker's `ControlFdBrokerError` becomes the first live audited caller (PR2a deferred
  the audit-row write) — a `SANDBOX_REFUSED`-class row keyed on the closed-vocab `reason`.
- **DLP / hookpoint chain unchanged.** The `security.quarantined.extract` pre/post/error chain +
  `OutboundDlpExtractSubscriber` continue to gate the *result* (post-scan of the validated model_dump);
  the brokering is transport plumbing beneath the existing contract.

## 8. Provider construction reshape

Per-call sockets mean the final `httpx`/SDK client cannot be built at boot (no socket yet). Reshape:

- `_build_provider(key)` (boot) → returns a **provider factory / config** holding the key + model
  (from routing.yaml) — NOT a live `Provider`. Boot still fails loud if the key is unset (§11).
- Per extract attempt: `recv_passed_fd` → build `PassedFdBackend`/transport/`http_client` → the
  factory builds the real `AnthropicProvider.from_settings(key, model, http_client=…, max_retries=0)`
  bound to that socket → `dispatch_extraction`'s single `complete()` runs on it → socket closed.
- The `provider` threaded through `_run_mcp_server` becomes the factory (the loop stays surgical:
  the extract branch calls `handle_extract` with a freshly-bound provider per attempt). Exact seam
  (does the child rebuild per attempt inside the retry loop, or does the factory expose a
  `bind(socket)` the dispatch loop calls?) is resolved at plan time; the constraint is **one socket
  per `complete()`, provider bound to that socket, closed after**.

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
- **ADR.** Update ADR-0040 (two-layer egress enforcement) + ADR-0050 (fd-broker) to record the live
  posture change: the child now performs real egress over the brokered fd; the empty-netns kernel
  isolation + the one-way fd-4 remain the containment. Note the accepted residuals (§13 non-claims).

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

- **Provenance premise.** `test_real_turn_inbound_boundary.py` (#338) uses `_ExtractionAwareChildDouble`
  — a schema-shaped `CommsBodyExtraction{text,intent}` projection with the injection marker on the
  schema-dropped `__injected_frame__`, NOT a byte-for-byte echo. It does **not** mechanically break
  under the real extractor, but the double must stay faithful to the **real** extractor schema, and
  the real path must be proven not to leak raw T3 into the privileged process. Re-validate: the T2 the
  orchestrator receives is the schema-shaped extraction, never raw T3; the privileged process only ever
  sees the validated `Extracted`/`TypedRefusal`.
- **T3-steers-extraction adversarial corpus (release-blocking).** Add a payload class for the ai-001
  threat: T3 content that tries to steer the *quarantined* LLM's extraction (prompt-inject the
  extractor) — distinct from structural containment (proven). Assert the extraction refuses / stays
  schema-bound; the marker never rides a returned field. Schema-valid `AdversarialPayload`
  (`extra="forbid"`; real `id`/`threat`/`ingestion_path`/`payload`/`expected_outcome`/`references`).
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
3. Refuse-boot on unset key + fail-closed on unset proxy (§11); no silent echo fallback.
4. The T3-steers adversarial corpus is release-blocking + green; the full adversarial suite green
   (security path touched).
5. fd-4 stays one-way; the `os.close(original)` balancing close intact; `_lift_above_targets` orphan
   hardened.
6. The docker canned-Anthropic integration test proves the full path (real bwrap + real broker + real
   TLS + real SDK) with **no** real key / gateway / paid call.

**Explicit non-claims (accepted residuals, recorded in the ADR):** the canned stub validates nothing
about the real gateway's acceptance policy (destination allowlist, gateway-side DNS, refuse-literal-IP,
reject-non-globally-routable, `Proxy-Authorization`/mTLS — the #358 residual); real-gateway + real-
provider + real-key is the nightly smoke follow-up. #269 (arm64 `/lib64`) unchanged.

## 14. Ratification forks (summary)

1. **Decomposition** — Option A (prep PR → golive PR + nightly-smoke follow-up). Best-judgment; §3.
2. **Retry × one-shot socket** — host brokers `_MAX_RETRIES+1` up-front, child consumes + closes
   leftovers, fd-4 stays one-way. Best-judgment; §6. (This is the one genuinely-new risk the spike
   did not cover.)
3. **Provider construction reshape** — `_build_provider` returns a factory; the real client is built
   per attempt bound to the brokered socket. §8. (Mechanism detail; resolve the exact `bind` seam at
   plan time.)
4. **Sign-off is at merge** — this spec + the plan are negotiated normally; the human gate is the
   golive merge, per §13.

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

- **Do not remove** the fd-dance `os.close(original)` balancing close under `moved=True`
  (`quarantine_child_io.py:747`) — removing it introduces an fd leak (a single-lift path is balanced;
  the PR2a "extra live ref" concern was a proven misdiagnosis).
- fd-4 stays **strictly one-way** (core→child).
- The `__main__.py` live-echo path stays byte-identical **only in prep**; golive is exactly the change
  that flips it — do not claim byte-identity for golive.
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

## 18. Next

Ratify §14 (esp. forks 1 + 2) → `writing-plans` for PR2b-prep (small) → focused plan-review →
subagent-driven TDD → full `/review-pr` fleet (security ALWAYS) + BOTH CodeRabbit → merge. Then
`writing-plans` for PR2b-golive → focused plan-review (core + security own the dense transport + gate
code) → subagent-driven TDD → full `/review-pr` fleet + BOTH CR → **HUMAN SIGN-OFF** → merge. Then file
the nightly-smoke follow-up. Give write/fix subagents the HARD "never git stash/checkout/reset — read a
base via `git show <base>:<path>`" line.

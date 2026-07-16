# #443 — boot-time fail-closed quarantine health-check (design)

- **Issue**: [#443](https://github.com/alfred-os/AlfredOS/issues/443)
- **Status**: DESIGN COMPLETE — **BLOCKED on a maintainer decision** (see §9)
- **Date**: 2026-07-16
- **Amends**: ADR-0051 (three separate corrections — see §7)
- **Pre-gates**: #340 PR2b (maintainer decision, 2026-07-16, recorded on #443)
- **Predecessors**: #433 (PR #445), #446 (the fast-follow whose residual this closes)

## 1. Problem

ADR-0051 Decision 2 chose **(B)** — record a launcher sandbox refusal at the
`read_frame` drain, at first extraction — over **(A)**, a spawn-time probe
barrier. #446 narrowed, but could not close, a forgery residual there:

> a child that execs, writes **zero** stdout bytes, then dies while emitting a
> forged `sandbox_refused` row on stderr is indistinguishable from a genuine
> launcher refusal — both present as `read_frame` EOF with
> `_child_wrote_stdout is False`.

CodeRabbit filed a 🔒 Major on #446: the gate must require independently
**attested** provenance, not inference from signal shape — *"parser validation
cannot establish provenance."* It was declined there on the narrow basis that
reversing a recorded ADR is the maintainer's call. **The maintainer has now made
that call: adopt option A, before PR2b.** The residual is latent only while the
live child is the trusted deterministic-echo child; at PR2b a compromised or
prompt-injected child reaches it.

## 2. The finding that reframes the fix

Verified by grep against main @ `967d8e2e` — not inferred from prose:

1. The quarantine child is spawned **exactly once, at boot**: `_commands.py:658`
   → `_comms_boot.py:718` → `daemon_runtime.py:338`. One production call site,
   gated on `if settings.comms_enabled_adapters:` (`_commands.py:648`).
2. `spawn_quarantine_child_io` **never inspects the outcome** — no `read_frame`,
   `poll`, `wait`, or handshake in its body (`quarantine_child_io.py:741-928`).
3. There is **no respawn path** for the quarantine child.

So a launcher refusal can only ever happen at boot. Today it is merely
*discovered* late, at first extraction, when `read_frame` trips over a corpse
that has been dead since boot.

### The unified invariant

> The zero-stdout/EOF gate is a **correct** oracle at the **first read of a spawn
> attempt**, and an **inverted** oracle after that attempt has proven exec.

Today the quarantine child's first read happens at first-extraction — arbitrarily
long after the spawn, by which time the launcher is long gone and only forgeries
remain. **The gate was never the bug. Reading late was the bug.**

## 3. Decision: positive handshake, inside the spawn — and the gate STAYS

**Do NOT flip the runtime gate.** `_child_wrote_stdout` is set on the first
stdout byte (`quarantine_child_io.py:457`, and `:474-475` on a partial read) and
is **never reset** — not by `aclose` (`:654-681`), not anywhere. So once a boot
handshake's `read_frame` succeeds, the gate at `:580`

```python
if refusal_candidate and not self._child_wrote_stdout:
```

is **dead for the remainder of that instance's life**. The runtime
launcher-attribution becomes unreachable *by construction*, with zero edits to
`_log_child_stderr` — while the gate stays live and correct on the boot
handshake's own failure arm, where a launcher refusal genuinely is the cause.

Placing the handshake **inside `spawn_quarantine_child_io`** makes the invariant
**structural** ("no `_SubprocessChildIO` is ever returned without a proven
exec") rather than **lexical** ("there is exactly one call site"). Every present
and future call site inherits it.

### Why not a bounded wait (option A) — refuted

(A) has **two** ambiguities, not one:

| branch | resolves to | safe? |
| --- | --- | --- |
| exited within window — refusal vs instant crash | refuse boot | ✅ symmetric |
| **alive at window expiry — healthy child vs slow launcher** | **proceed** | ❌ **defaults open** |

(A)'s success signal is the *absence* of an event. A healthy child never exits,
so "did not exit" is the only success evidence available — the permissive default
is **structural**, not a tuning choice. That is a timing rule deciding a runtime
fact with the ambiguous branch defaulting to allow
(`domain_guard_completeness_and_oracle_independence`).

Empirically reachable: the launcher runs **two `python3 -m
alfred.plugins.manifest_reader` cold-starts** (`alfred-plugin-launcher.sh:216`,
`:326-334`) plus `jq` (`:400`) and `mktemp` (`:191`) before most refusal paths.
`policy_ref_missing` (`:411`), `bwrap_unavailable` (`:524`) and
`interpreter_prefix_too_broad` (`:502`) all land after two interpreter
cold-starts. "Exits in ms" is false for the majority of refusal paths.

Under (A) the premise *"the launcher provably exec'd"* is never established — only
*"it had not exited N seconds after fork."* So removing the gate under (A) would
delete the only recorder for a real, reachable refusal: a hard-rule-#7
regression, not a cleanup.

Under (B) the polarity inverts: the ambiguous branch defaults to **refuse boot**.
(B)'s clock is a **liveness bound**, not a provenance oracle — its only failure
direction is a spurious refusal (availability), never a silently-unbarriered boot
(security).

### Why not a dedicated launcher fd (option C)

(C) buys provenance-by-construction but not the boot barrier — (B) would still be
needed for the fail-closed-at-boot half, and (C) alone leaves the "boot proceeded
with no child" hole. It rewrites ~19 emit sites across five `exec` targets and
touches the fd dance PR2b touches (`keep_fds=[3,4]`). **Record (C) as the
escalation path** if the §6 residual stops being acceptable — specifically if the
child ever gains a boot-time external input.

### Flipping the gate would weaken four things

1. The **boot-path oracle** — under (B) the correct one, and the row's only writer.
2. The **`aclose` teardown protection** — `aclose` (`:674`) passes
   `refusal_candidate` defaulting to `False` (`:510`); that protection lives *in*
   the gate.
3. The **`TimeoutError` exclusion** (`:482`) — the #446 timeout-attribution fix.
4. **#441's correctness** (§8).

## 4. Why the boot-time drain is trustworthy

At boot the child has consumed **zero inputs whose provenance is not the host's
own**:

- **argv** — module-internal, validated against the closed `_ALLOWED_CHILD_MODULES`
  (`quarantine_child_io.py:146`, enforced `:807-808`).
- **env** — `_child_env()` (`:235-263`), a scrubbed allowlist, never
  `dict(os.environ)`.
- **fd 3** — the broker-held provider key (`:912`).
- **Nothing else.** `main()` (`quarantine_child/__main__.py:337-352`) does
  `configure_stderr_logging` → `_read_provider_key_from_fd3` → `_build_provider` →
  connect pipes → `_run_mcp_server`. The loop (`:382-418`) writes stdout **only**
  on the extract branch (`:414`), reached only after the host ships an extract
  request. T3 arrives strictly at runtime.

So a child forging a row at boot must do so **from its own code image** — and that
image is the same `alfred` wheel the host runs, under the same interpreter
(`_child_python()` → `sys.executable`, `:220-232`). An attacker who can alter it
has already altered `SandboxRefusalAuditor` itself. **The boot-time residual is
not a defence gap but a restatement of the wheel-integrity trust root every other
T0 primitive already assumes.**

### Forward gate — binding on #340 PR2b

This argument rests on *"the child performs no external I/O before the boot
handshake completes."* PR2b gives the child a real Anthropic client and a
brokered-egress control fd. It holds **only while provider construction stays
lazy and network-free**. Any boot-time network call — a health probe, a
`models.list`, a token refresh, an SDK telemetry ping — makes a hostile provider
response a **boot-time input** and **voids this argument**, widening the residual
from "supply-chain" to "anyone who can answer the child's first socket." A test
must pin this, not a comment (`sbx-2026-024`, §10).

## 5. Architecture

Three changes, each single-responsibility.

1. **Child** (`quarantine_child/__main__.py`) — emit one hello frame after
   `_build_provider()` succeeds and before entering `_run_mcp_server`.
   **This is a protocol change — see §9.**
2. **Host** (`quarantine_child_io.py`, inside `spawn_quarantine_child_io`) — after
   `deliver_provider_key_via_fd3`, `await read_frame()` for the hello. Success →
   return `child_io` (with `_child_wrote_stdout` now `True`). EOF/timeout → the
   existing drain + `_record_launcher_refusals` + raise
   `QuarantineChildSpawnError`, which `_commands.py:686-693` **already** maps to
   `_refuse_boot`.
3. **core-001** (§6) — an explicit idempotent pre-spawn hookpoint declaration.

No new failure-union member is needed: the spawn now genuinely *raises* on a
refusal, so the existing `QuarantineChildSpawnFailedFailure` (`_failures.py:167`)
becomes accurate rather than conflated.

## 6. core-001 is a real blocker

ADR-0051:86-89 flagged it; it is verified, and it fails **silently, in the wrong
direction**:

1. Spawn at `_commands.py:658`; `Supervisor(...)` at `_commands.py:783` — **125
   lines later**.
2. `supervisor.plugin.sandbox_refused` is declared **only** at
   `supervisor/core.py:1089`, via `core.py:307` `_register_hookpoints()`.
   (`_known_hookpoints.py:86` is a drift map, not a declarer.)
3. `strict_declarations` defaults **True** (`hooks/registry.py:521`), pinned by
   `tests/unit/security/test_default_strict_declarations_invariant.py`.
4. `invoke()` on an undeclared hookpoint: `hooks/invoke.py:1410` → `:1413` →
   **`:1439` `raise HookError`**.

So `SandboxRefusalAuditor.record()` at the spawn writes the row
(`sandbox_refusal_audit.py:53-65`) then **raises `HookError`** at the
`fail_closed=True` dispatch — and `_record_launcher_refusals` catches it and logs
`refusal_record_failed` (`quarantine_child_io.py:648-652`). **The fail-closed T0
hookpoint never fires; the failure is demoted to a log line on the one path whose
purpose is to trip quarantine.** Hard rule #7.

**Fix**: an explicit idempotent `declare_sandbox_hookpoints(registry)` called in
`_start_async` **before** `:658`. `register_hookpoint` is idempotent on equal
metadata and strict on drift (`hooks/registry.py:587`, `supervisor/core.py:1030-1038`),
so `Supervisor._register_hookpoints()` re-registering later is a proven no-op —
**provided both sites pass the same metadata**. Have `_register_hookpoints`
delegate to the new function so one tuple has two callers and drift is
structurally impossible; `test_known_hookpoints_sync.py` pins it.

**NOT import-time** — `supervisor/core.py:1023-1028` explicitly rejected that
under core-010 (pytest collects imports before fixtures → publisher metadata
persists across tests expecting a clean registry). core-010 rejects the
*module-bottom call*; ADR-0051:204-207 asks for the *function*. Both hold.

**This likely closes #444 too** — ADR-0051:205-207 defers the reserved
`provider_key_delivery_failed` writer for the same pre-`Supervisor` reason, and
§7.1 makes that path more reachable. One declaration fix closes both.

## 7. ADR-0051 amendments (three corrections, all verified)

### 7.1 The writev-buffers premise is a RACE, not structural

ADR-0051:42-54 states the fd-3 `writev` buffers and succeeds, so
`ProviderKeyDeliveryError` "never fires on a refusal" — "empirically confirmed"
on two platforms (:124-134).

**The parent closes every read-end copy at `quarantine_child_io.py:883-908`
(`os.close(fd)` :889, `os.close(src)` :901, `os.close(original)` :907) BEFORE the
writev at `:912`.** Only the child holds a read end. A launcher that exits
*before* the writev ⟹ EPIPE ⟹ `OSError` (`fd3_key_delivery.py:104-105`) ⟹
`ProviderKeyDeliveryError` ⟹ `QuarantineChildSpawnError` (`:913-921`) — boot
already refuses, **nondeterministically**.

Task 0 only exercised **slow** refusal paths. The **fast** path —
`plugin_id_charset_invalid` (`alfred-plugin-launcher.sh:123-136`), which fires
before any `python3` — is the one plausibly fast enough to win the race and was
never sampled. This changes no decision (both outcomes refuse boot under (B)) but
a "proven on two platforms" claim that is actually load-dependent is exactly
`domain_verify_mirrors_production_claims`.

### 7.2 ADR-0051 is wrong about three of the four producers

ADR-0051:21-24 says *"Four spawn sites drain that stderr today… the row was
logged into a `child_stderr` field and nothing else."* **False.** Only the
quarantine child drains (`quarantine_child_io.py:509`). The other live producers
pipe stderr and **never read it**:

- `plugins/comms_stdio_transport.py:173` — `stderr=asyncio.subprocess.PIPE`, the
  only occurrence of `stderr` in the file.
- `gateway/adapter_child_factory.py:497` — same.

So for #440/#441 the row is not "logged and dropped" — it is **never read**. That
turns them from "swap a log line for an auditor" into "**build the drain, then
attach the auditor**": materially larger than the ADR implies. (Aside, worth its
own issue: an unread, 64 KB-bounded stderr pipe on a long-lived adapter is a
wedge waiting to happen.)

### 7.3 The A-vs-B reversal and the gating relationship

Record the maintainer's 2026-07-16 decision: option A adopted, #443 is a hard
pre-gate on #340 PR2b, and CodeRabbit's #446 Major stands vindicated.

## 8. Scope: what transfers to #440/#441/#442

- **#441 (gateway-adapter) — re-runs the launcher at runtime.**
  `GatewayAdapterSupervisor.supervise_one` (`gateway/adapter_supervisor.py:365`)
  is a `while True:` loop (`:376`) → `_spawn_or_terminal` (`:394`) → launcher +
  `Popen` (`adapter_child_factory.py:477-499`), with backoff and a per-adapter
  breaker. A runtime refusal is genuinely reachable. **But it needs no
  exception**: the factory already runs `await runner.start_and_handshake()` on
  **every** spawn including restarts (`adapter_child_factory.py:29`) — the (B)
  shape, per-spawn. The shared auditor is correct there under the same unified
  invariant. No divergence, no per-producer special-casing.
- **#442 (foreground-TUI) — the producer does not exist.**
  `spawn_plugin_via_launcher` (`cli/_launcher_spawn.py:188`) has **zero
  production call sites**; `alfred chat` (`cli/main.py:273`) dials the gateway's
  `comms-gateway.sock` (Spec A G5). **#442 should be rescoped to delete the dead
  seam**, not wire an auditor into it.
- **#440 (comms-adapter)** — per §7.2, needs the drain built first.

## 9. BLOCKED — the decision this needs

**The chosen mechanism requires adding a hello frame to the quarantine child's
protocol** (`quarantine_child/__main__.py`). Verified: there is no initialize and
no unsolicited frame today — the loop writes stdout **only** on the extract branch
(`:414`), and unknown methods are a loud refusal by design (`:418`).

That protocol is exactly what **#340 PR2b** rewrites — its own comment says so
(`:387-390`: *"PR-S4-11c-2c replaces this deterministic-echo body… Keep the loop,
`handle_extract`, and the skeleton/loop tests in sync when that swap lands"*).

So #443's correct fix touches the surface of the human-sign-off-gated PR it is
meant to pre-gate. Three things follow that only the maintainer can settle:

1. **The approved scope was "probe + flip the runtime gate". The flip is wrong** —
   §3 shows it weakens four things, and (B) inverts the gate for free. Confirm the
   scope change.
2. **Is a quarantine-child protocol change acceptable inside #443**, given #443
   pre-gates PR2b and PR2b must then preserve the hello frame?
3. **core-001's fix (§6) may fold #444 into #443.** Confirm, or split.

Everything up to this line is analysis and is durable. Implementation is
deliberately not started.

## 10. Testing

- 100% line + branch on the boundary (CLAUDE.md: every security boundary).
- **No AST call-site guard.** Under (B)-inside-the-spawn, correctness does not
  depend on "spawned exactly once", so a lexical guard would advertise a property
  it cannot hold — and would be blind to the lazy, function-local import
  production actually uses (`daemon_runtime.py:328`). Structure, not lexical rule.
- Real-execution oracles instead:
  1. child double writing zero stdout ⟹ `spawn_quarantine_child_io` raises **and**
     the row is recorded (the mutation-killing test);
  2. `_child_wrote_stdout` monotonicity — no path assigns `False` after
     `__init__` (the single fact the design rests on);
  3. extend the docker-gated real-spawn lane
     (`tests/integration/test_quarantine_child_real_spawn.py:195`) to assert boot
     refuses on a genuine refusal, with an **assert-RAN (not skipped)** floor
     (`domain_paper_only_gates`, the #245 pattern).
- One guard **is** warranted: pin that `bwrap`/`runuser` stderr can never parse as
  a valid row (feed real `bwrap --bogus-flag` / `runuser -u nosuchuser` output,
  assert zero rows). It is a claim about third-party output — the kind that rots.

### Adversarial corpus (next free id: 021)

- **`sbx-2026-021`** `boot_barrier_absent_launcher_refusal_reaches_runtime` — a
  real refusal ⟹ `QuarantineChildSpawnError` **from the spawn**, exactly one row
  with the true reason, and the `fail_closed` T0 hookpoint **actually dispatched**
  (not `refusal_record_failed`). **This is the core-001 regression oracle** — it
  fails today. Write it first; assert on the **dispatch**, not just the row (a
  row-only assertion passes straight through the bug).
- **`sbx-2026-022`** `exec_d_child_cannot_forge_refusal_after_boot_handshake` — the
  #446 residual, closed. Derive "no row written" from the audit store, never from
  the gate predicate (`domain_a_test_that_asks_the_code_if_the_code_is_right`).
- **`sbx-2026-023`** `slow_launcher_refusal_still_refuses_boot` — the (A)-refutation
  pinned, so a future "let's just bounded-wait" PR goes red instead of going in.
- **`sbx-2026-024`** `child_boot_performs_no_external_io` — §4's forward gate made
  executable. The only thing standing between "the child's provider client is
  lazy" and "the child's provider client *used to be* lazy."
- **Amend `sbx-2026-019`**: under (B) a successful exec now produces a hello frame
  — precisely the success-path signal ADR-0051:228-231 says #447 needs and lacks.
  **(B) may make #447 tractable rather than blocked.** Note on #447; do not fold.

## 11. Residuals (named, per CLAUDE.md hard rule 7)

1. **Supply-chain compromise of the wheel or bound interpreter** — accepted;
   strictly-stronger attacker (§4). Closable only by (C).
2. **`bwrap`/`runuser` diagnostics on the shared fd 2 after exec** — not
   exploitable (`parse_launcher_refusal_rows` requires a JSON object with keys ⊆
   `SANDBOX_REFUSED_FIELDS`, string values, Cc/Cf-free, `reason` in the closed
   vocab), but this is an assumption about third-party stderr. **Pin it.**
3. **Grandchildren inheriting fd 2** — not reachable under the shipped
   `--unshare-pid` policy; at boot the child forks nothing. **Name the policy
   dependency** (`domain_lexical_rules_cannot_decide_filesystem_facts`).
4. **The fast-refusal race (§7.1)** surfaces as `ProviderKeyDeliveryError`, which
   writes no row today — reserved reason #444. #443 and #444 are coupled.

## 12. Related

- #455 — `request_plugin_restart` documents a restart scheduler that was never
  built (filed during this analysis; contradicts `supervisor/core.py:51-54`).
- #449 — the blank-REASON premise did not reproduce for `sandbox_refused`
  (`cli/audit.py:126-145` returns `subject.reason`; `as_subject()` always sets it).
  Evidence posted; awaiting a repro. #450's half is real.
- `daemon_runtime.py:324-326` claims the spawn await is "the only await in this
  builder"; `:355`/`:357` are post-spawn awaits in the same function. The real
  invariant is "no await INSIDE dup2→restore" (window opens
  `quarantine_child_io.py:844`, closes `:881`, around a synchronous `Popen` at
  `:859`), enforced within the spawn. Correct the comment in this PR.

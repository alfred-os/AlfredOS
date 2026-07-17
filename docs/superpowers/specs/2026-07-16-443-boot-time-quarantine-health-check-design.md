# #443 — boot-time fail-closed quarantine health-check (design)

- **Issue**: [#443](https://github.com/alfred-os/AlfredOS/issues/443)
- **Status**: DESIGN COMPLETE — **all three open decisions resolved 2026-07-17**
  (below). PR1 building; PR2 follows.
- **Date**: 2026-07-16 (rev 2: 2026-07-17; rev 3: 2026-07-17)
- **Amends**: ADR-0051 (four corrections — §8)
- **Pre-gates**: #340 PR2b (maintainer decision, 2026-07-16, recorded on #443)
- **Predecessors**: #433 (PR #445), #446 (the fast-follow whose residual this closes)

## 0. The three decisions — RESOLVED 2026-07-17

Delegated by the maintainer to the specialist agents, then cross-examined against
each other. Both conceded their own position and converged.

1. **Is the flip off?** — **YES, off.** Not merely unnecessary but *unsafe*: the
   `except` at `quarantine_child_io.py:469` wraps both reads and `:457` sets the
   flag between them, so on header-then-body-EOF both conditions fire on a fresh
   instance's first read. The second conjunct is the **only** thing suppressing the
   forged row (pinned by `test_first_turn_full_header_then_body_eof_not_recorded`).
   Under this design the first read **is** the boot handshake — so flipping would
   reopen #446's bypass at the boot barrier itself. §3.1.
2. **Is a quarantine-child protocol change acceptable inside #443?** — **YES.**
   Both reviewers recommend taking it. The collision with #340 PR2b is textually
   trivial (PR2b's `main()` edits land at `:351-352`; the hello sits at `:339`, so
   it collides *less* than the alternative), it adds **zero** inbound methods (both
   frames are unsolicited outbound, so `:418`'s closed refusal surface is
   untouched), no protocol-free alternative attests the right proposition (§3.5),
   and splitting it into a hello-only PR would **break extraction** (§5.3).
3. **Does core-001's fix fold #444 in?** — **NO: it UNBLOCKS it.** #444 additionally
   needs a `provider_key_delivery_failed` writer at the `ProviderKeyDeliveryError`
   arm — a separate writer, corpus entry, and reachability argument (§8.1's race).
   PR1 ships the declaration #444 is blocked on; #444 ships its writer.

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

Verified by grep against main @ `967d8e2e`:

1. The quarantine **child** is spawned exactly once, at boot: `_commands.py:658`
   → `_comms_boot.py:718` → `daemon_runtime.py:338`. One call site for that
   module, gated on `if settings.comms_enabled_adapters:` (`_commands.py:648`).
2. `spawn_quarantine_child_io` **never inspects the outcome** — no `read_frame`,
   `poll`, `wait`, or handshake in its body (`quarantine_child_io.py:741-928`).
3. There is **no respawn path** for the quarantine child.

So a launcher refusal can only ever happen at boot. Today it is merely
*discovered* late, at first extraction, when `read_frame` trips over a corpse
that has been dead since boot.

> **The zero-stdout/EOF gate is a CORRECT oracle at a spawn attempt's first read,
> and an INVERTED oracle after that attempt has proven exec.**
>
> **The gate was never the bug. Reading late was the bug.**

### 2.1 CORRECTION (rev 2) — the spawn seam is SHARED; finding 1 does not generalise

`_ALLOWED_CHILD_MODULES` (`quarantine_child_io.py:146`) is a **closed set of two**:
`_CHILD_MODULE` and `_BROKERED_PROBE_MODULE` (`:141`). Finding 1 above is true of
the *quarantine child*; rev 1 silently applied it to *`spawn_quarantine_child_io`*,
which is the shared spawn seam for **both**. See §6.1 — this is a blocker, and it
is the same over-generalisation this epic keeps producing.

## 3. Decision: TWO FRAMES, inside the spawn — and the gate STAYS

**Do NOT flip the runtime gate.** `_child_wrote_stdout` is set on the first
stdout byte (`quarantine_child_io.py:457`, `:474-475`) and **never reset** —
exactly three assignments exist repo-wide (`:415` `False` in `__init__`, `:457`,
`:475`), no `setattr`/`__dict__` vector, and `_SubprocessChildIO` has **one**
production construction site (`:923`), so instance and `Popen` are born 1:1 and no
instance can ever wrap an already-exec'd child. So once a boot handshake's
`read_frame` succeeds, the gate at `:580` is **dead for that instance's life**.
The runtime launcher-attribution becomes unreachable *by construction*, with zero
edits to `_log_child_stderr`.

### 3.1 Why flipping is not merely unnecessary but UNSAFE (rev 2 — stronger than rev 1)

Rev 1 argued the second conjunct guards teardown and timeouts. The real reason is
sharper: the `except` at `:469` wraps **both** reads, and `:457` sets the flag
**between** them. So on the header-succeeds-then-body-EOF-at-offset-zero path,
`:457` sets `True` **and** `:482` computes `refusal_candidate = True` —
**both fire simultaneously, on a fresh instance, on its first read.** The second
conjunct is the *only* thing suppressing that forged row.
`tests/unit/security/test_quarantine_child_io_refusal_audit.py:148-171` pins it as
"the exact first-turn forgery bypass CodeRabbit flagged."

Under #443 the first read **is** the boot handshake. **Flipping the gate would
reopen #446's bypass at the boot barrier itself.** The steelman is not weak; it is
actively unsafe.

**Corollary for §9's tests:** the invariant is load-bearing **per byte, not per
read**. "First read" is a lossy approximation of it.

### 3.2 Two frames, not one — the rev-1 design conflated two propositions

A single hello was being asked to carry two assertions with **opposite optimal
positions**:

| proposition | wants to be | purpose |
| --- | --- | --- |
| "I am a real exec'd child" | as **early** as possible | provenance — close the forgery gate |
| "I am initialized and serving" | as **late** as possible | liveness — the boot barrier |

Separating them is the same lesson #446 taught, one level up. The decision table
is complete and correctly attributed only with two frames:

| event | flag at read | gate | row | boot |
| --- | --- | --- | --- | --- |
| launcher refuses (pre-exec, zero stdout) | `False` | **opens** | ✅ correct, launcher-authored | **refuse** |
| child dies in `_build_provider` (hello, no ready) | `True` | **closed** | ✅ none — correctly child-authored | **refuse** |
| healthy (hello + ready) | `True` | dead for life | none | proceed |
| child dies pre-hello (fd-3 framing error) | `False` | opens on child stderr; parser yields nothing | none | refuse — **residual §11.5** |

Row 2 is the one **neither single-frame design gets right**: hello-only refuses
nothing; ready-only mis-attributes a `_build_provider` crash to the launcher —
leaving *parser validation* as the only thing between a crash and a forged row,
which is verbatim what CR's #446 Major says is insufficient.

### 3.3 Why not a bounded wait (option A) — refuted

(A) has **two** ambiguities:

| branch | resolves to | safe? |
| --- | --- | --- |
| exited within window — refusal vs instant crash | refuse boot | ✅ symmetric |
| **alive at window expiry — healthy child vs slow launcher** | **proceed** | ❌ **defaults open** |

(A)'s success signal is the *absence* of an event. A healthy child never exits, so
"did not exit" is the only success evidence — the permissive default is
**structural**, not a tuning choice
(`domain_guard_completeness_and_oracle_independence`).

Empirically reachable: the launcher runs **two `python3 -m
alfred.plugins.manifest_reader` cold-starts** (`alfred-plugin-launcher.sh:216`,
`:326-334`) plus `jq` (`:400`) and `mktemp` (`:191`) before most refusal paths.
"Exits in ms" is false for the majority of them.

Under (A) the premise *"the launcher provably exec'd"* is never established — only
*"it had not exited N seconds after fork."* A two-frame handshake's clock is a
**liveness bound**, not a provenance oracle: its only failure direction is a
spurious refusal (availability), never a silently-unbarriered boot (security).

### 3.4 Why not a dedicated launcher fd (option C) — and rev 1 costed it wrongly

Rev 1 said (C) "rewrites ~19 emit sites". **Wrong**: (C) needs ~5 edits, one per
exec target (`alfred-plugin-launcher.sh:299`, `:312`, `:528`, `:549`, `:569`);
refusal paths need nothing. The real objection is different and stronger:

**(C) attests the wrong proposition.** A launcher marker says "the launcher
reached `exec`" — but failure modes exist *between* that exec and the child's
`main()`: bwrap sandbox-setup failure, interpreter crash, `ImportError`, the fd-3
framing exits (`__main__.py:84-99`). Marker-present + bwrap-fails → gate closes →
**boot proceeds on a corpse with no row**. A new fail-open hole.

Record (C) as the escalation path only for §11.5's residual, which no
child-authored frame can close.

### 3.5 No protocol-free alternative exists (rev 2 — all five checked)

- **fd-3 read receipt** — a pipe write returns on *buffering*, not on the peer's
  read. That is ADR-0051:42-54's own premise. Dead end.
- **Control socketpair (fd 4)** — not built at the live spawn
  (`daemon_runtime.py:338` passes only `provider_key` + `refusal_recorder`;
  `quarantine_child_io.py:776-778` "the live/echo spawn never sets it"). Using it
  flips the ADR-0050 dormancy invariant *and* still needs the child to write.
- **`/proc` / exec-vs-alive** — Linux-only; the pid held is the *launcher's*; it is
  a poll (§3.3's timing ambiguity); `--unshare-pid` makes it policy-dependent.
- **bwrap `--info-fd`/`--sync-fd`** — `sandbox_policy.py:26-30` and launcher
  `:21-22` record that the translator deliberately emits **no** fd flag
  ("`--sync-fd` would consume fd 3").
- **Launcher stderr marker** — §3.4.

**The only host-observable fact attesting "a real child reached its main loop" is a
byte the child itself wrote.**

## 4. Why the boot-time drain is trustworthy

At boot the child has consumed **zero inputs whose provenance is not the host's
own**: argv validated against the closed `_ALLOWED_CHILD_MODULES`
(`quarantine_child_io.py:146`, enforced `:807-808`); env from `_child_env()`
(`:235-263`), a scrubbed allowlist, never `dict(os.environ)`; fd 3, the
broker-held provider key (`:912`). T3 arrives strictly at runtime — the loop
writes stdout only on the extract branch (`__main__.py:414`).

So a child forging a row at boot must do so from its own code image — the same
`alfred` wheel the host runs, under the same interpreter (`_child_python()`,
`:220-232`). An attacker who can alter it has already altered
`SandboxRefusalAuditor`. **Not a defence gap but a restatement of the
wheel-integrity trust root every other T0 primitive already assumes.**

### 4.1 CORRECTION (rev 2) — this residual is NARROWER than rev 1 implied, and §4 covers `_build_provider`

Rev 1 framed a binding "keep `_build_provider` network-free" forward gate on PR2b.
Two verified facts shrink it:

1. **The child is already in an empty network namespace.**
   `config/sandbox/quarantined-llm.linux.bwrap.policy:90` —
   `unshare = ["pid", "uts", "cgroup", "ipc", "net"]`, pinned by the probe's C1
   control (`_brokered_probe.py:35-45`, `_EMPTY_NETNS_ERRNO = ENETUNREACH`,
   asserted in the required CI lane). PR2b's egress arrives only via the
   post-spawn SCM_RIGHTS fd. **`_build_provider` structurally cannot reach the
   network at boot.**
2. **The host imports `anthropic` too** (`providers/anthropic_native.py:16`;
   `pyproject.toml:22`). A compromised SDK already owns the privileged
   orchestrator — the §11.1 strictly-stronger attacker. So §4's argument genuinely
   extends over `_build_provider`'s window.

**Consequence:** the hello-before-`_build_provider` ordering is
**defence-in-depth that retires a forward gate**, not a fix for a live hole. Say
so plainly — overstating it would be another false claim in a spec about false
claims. What it buys is that the PR2b contract becomes **positional** ("hello
before `_build_provider`, ready after" — greppable, mechanically checkable)
rather than **behavioural** ("stays lazy and network-free" — voidable by a
transitive SDK change, and needing a test to pin).

## 5. Architecture

### 5.1 Child (`quarantine_child/__main__.py`)

Verified sequence today: `configure_stderr_logging()` `:337` →
`_read_provider_key_from_fd3()` `:338` → `_build_provider(provider_key)` `:340`
(inside a `try/finally` that scrubs the key) → asyncio reader/writer construction
`:345-351` → `_run_mcp_server(...)` `:352`.

- **Hello** — a raw `sys.stdout.buffer.write(...)` + flush at **`:339`**, i.e.
  after `_read_provider_key_from_fd3` and before `_build_provider`. It **must** be
  a raw write: the asyncio `writer` does not exist until `:351`, after
  `_build_provider`. It is safe because `configure_stderr_logging()` (`:337`)
  already pins all logging to stderr.
  **Not before `:338`** — `_emit_fd3_framing_error_and_exit` (`:84-98`) exits with
  zero stdout, so an earlier hello would push fd-3 framing failures outside the
  barrier for no gain.
- **Ready** — one frame via the asyncio writer, after `:351`, before `:352`.

Neither is a new **inbound** method: `:398-418` dispatches host→child `method`
against the closed `_INGEST_METHOD`/`_EXTRACT_METHOD` set with `:418` refusing
anything else. Both frames are **outbound**, written before the loop is entered.
**Zero vocabulary expansion; `:418`'s refusal surface untouched.**

### 5.2 Host (`quarantine_child_io.py`, inside `spawn_quarantine_child_io`)

After `deliver_provider_key_via_fd3` (`:912`), construct `_SubprocessChildIO`
(`:923`), then `await read_frame()` twice — hello, then ready — and return the
instance only if both arrive. Either missing → the existing drain +
`_record_launcher_refusals` + raise `QuarantineChildSpawnError`, which
`_commands.py:686-693` **already** maps to `_refuse_boot`. No new failure-union
member: the spawn now genuinely *raises* on a refusal, so
`QuarantineChildSpawnFailedFailure` (`_failures.py:167`) becomes accurate rather
than conflated.

Ordering is deadlock-free for `_CHILD_MODULE`: the parent `writev`s and closes the
write end (`fd3_key_delivery.py:104,117`) **before** any handshake read; the child
reads fd 3 (`:121`) then writes. Strict write→read→write→read. The ~100-byte key
is far under the 64 KB pipe buffer, so the synchronous `writev` never blocks. The
handshake `await`s sit after the dup2 window closes (`:844` opens, `:880-908`
`finally` closes) — no clobbered-selector hazard.

### 5.3 Transport — untouched

`quarantine_transport.py:307` is the only quarantine-path `read_frame` caller: two
`write_frame`s then exactly one read. `read_frame` drains header **plus** body and
leaves the stream at the next frame boundary (`:458-468`), so frames consumed
inside the spawn are invisible to it. **No read-count assumption breaks.**

**A hello-only PR would be actively harmful**, not merely useless: `read_frame` is
method-agnostic, so the first extraction would consume the hello *as its extract
reply*. The child and host halves are one atomic change.

## 6. Blockers

### 6.1 The shared spawn seam deadlocks `_brokered_probe` (rev 2 — NEW)

`_brokered_probe.main()` (`_brokered_probe.py:106-113`) is **parent-speaks-first**:
it reconstructs fd 4 and immediately blocks in `_probe_once` → `recv_passed_fd`,
writing its first stdout byte only *after* receiving a brokered fd. But
`broker_socket()` is callable only on the **returned** instance
(`tests/integration/test_quarantine_fd_broker_real_spawn.py:213-222` spawns, *then*
brokers).

An unconditional handshake inside the spawn therefore **deadlocks**: parent blocks
in `read_frame`; child blocks in `recv_passed_fd`. Broken only by
`_READ_FRAME_TIMEOUT_S = 25.0` (`:157`) → `TimeoutError` → spawn raises →
**reds the `Integration (privileged Linux, real spawn) (arm64)` required check**
(`test_quarantine_fd_broker_real_spawn.py:217`) plus four unit tests
(`test_quarantine_child_io_control_fd.py:155,290,334,376`).

**Fix: give `_brokered_probe.main()` a hello before its recv loop — and ONLY a
hello, never a ready** (it has no provider to build). That asymmetry is itself an
argument for separate frames.

**Do NOT make the handshake conditional on `child_module`**: that returns a probe
instance with `_child_wrote_stdout = False`, making the invariant false for that
member and reopening #446 on the probe path. It is unexploitable today only
because no probe test passes a `refusal_recorder` (`:640-641` returns early) — an
accident, not a defence.

### 6.2 core-001 — LATENT today, activated by this design; rev 1's fix was WRONG

**Rev 3 correction.** Rev 2 called core-001 "a live hard-rule-#7 defect". **False**,
and ADR-0051:81-89 — quoted in this very spec — says so verbatim: *"core-001 … is
moot for this specific call site — the dispatch happens well after
`Supervisor.__init__` … A future boot-time fail-closed health-check (option A,
deferred) would need to re-examine core-001 for itself."*

Verified: `record()` reaches `invoke` only via `_record_launcher_refusals`
(`quarantine_child_io.py:647`) ← the gate at `:580` ← **only** `read_frame`'s except
arm (`:488`); `aclose` (`:674`) passes `refusal_candidate=False` and can never reach
it. `_SubprocessChildIO.read_frame` has exactly one driver —
`quarantine_transport.py:307`, inside `dispatch()`, the extract RPC at **turn time,
after `Supervisor(...)`**. `spawn_quarantine_child_io` contains zero `read_frame`
calls. So the hookpoint is always declared before anything dispatches it.

**§5's in-spawn handshake is what activates it** — that is the whole point: this
design moves the first read 125 lines before `Supervisor(...)`. So core-001 is a
**blocker for this design**, not a bug on main. Everything below stands; only the
"live" framing was wrong. It is also the fix **#444** is blocked on.

The chain, verified: spawn at `_commands.py:658`; `Supervisor(...)` at `:783` —
**125 lines later**; `supervisor.plugin.sandbox_refused` declared **only** at
`supervisor/core.py:1089` via `core.py:307`; `strict_declarations` defaults
**True** (`hooks/registry.py:521`, pinned by
`test_default_strict_declarations_invariant.py`); `invoke()` on an undeclared
hookpoint raises `HookError` (`hooks/invoke.py:1439`).

So `SandboxRefusalAuditor.record()` writes the row (`sandbox_refusal_audit.py:53-65`)
then **raises**, and `_record_launcher_refusals` catches it and logs
`refusal_record_failed` (`quarantine_child_io.py:648-652`). **The fail-closed T0
hookpoint never fires on the one path whose purpose is to trip quarantine.**

Two refinements rev 1 missed:

- **Rows 2..N are lost, not just demoted.** `record()` appends *then* invokes
  **per row** inside the `for` at `:51`; the caller catches at the call level
  (`:648`). Only the **first** row is ever written.
- **`sandbox_refusal_audit.py:12-14` admits the dependency**: dispatch "happens at
  first extraction, post-`Supervisor`, so the hookpoint is registered" — direct
  evidence the current design *depends* on the late dispatch #443 removes.

**Rev 1's proposed fix — "an explicit `declare_sandbox_hookpoints(registry)` called
in `_start_async` before `:658`" — is WRONG.** A declaration seam **already
exists**: `_commands.py:485` → `_gate_boot.py:245-248` → `hooks/boot.py:144`
`install_boot_hook_registry` → `:140 _declare_all_subsystem_hookpoints(registry)`,
running **173 lines before the spawn**. Its docstring (`hooks/boot.py:76-79`) is
explicit:

> "The list is the COMPLETE set of in-tree `declare_hookpoints` publishers…; a new
> subsystem publisher **MUST** be added here so its hookpoints are declarable at
> boot."

The supervisor is absent because `_register_hookpoints` is a **method on a class**,
not a `declare_hookpoints(registry)` function — that is the whole cause of
core-001. `supervisor.plugin.sandbox_refused` is the only `fail_closed=True`
security hookpoint reachable *only by constructing an object*. Adding a tenth
ad-hoc site would bypass the seam and make its "COMPLETE set" claim false in a new
way.

**Rev 1's "NOT import-time (core-010 forbids it)" is also withdrawn.**
`install_boot_hook_registry` calls `set_registry` on a **fresh** registry
(`hooks/boot.py:59-61`), so import-time declaration is irrelevant to it. core-010
(`supervisor/core.py:1023-1028`) rejects a module-bottom *call* for the supervisor;
`hooks/boot.py` is an explicit boot-time call seam — what core-010 wants. Rev 1
over-generalised a supervisor-local rationale into a repo rule the repo does not
follow (`cli/daemon/__init__.py`, `episodic.py`, `quarantine.py:1604`,
`comms_mcp/hookpoints.py` all have module-bottom calls).

Drift is pinned **by value**, not identity: `registry.py:734` compares
`stored != new_meta` on a dataclass with eagerly-normalized frozensets
(`core.py:1035-1038`'s "SAME frozenset objects" is stricter than the code demands).

### 6.3 Rejected placement: a barrier at `_commands.py:793`

Considered (post-`Supervisor`, so core-001 would be moot) and rejected on four
counts:

1. **The handle is unreachable.** `_CommsBootGraph` exposes `quarantine_transport`
   (`_comms_boot.py:535`), not `child_io`.
2. **It needs new control flow anyway.** AST-verified: the try at `:782` has
   **zero** `except` handlers (`finalbody=[935]`), so a barrier raising there
   propagates **uncaught** → exit 1, no audit row — the #368 anti-pattern the file
   names at `:724`.
3. **The invariant stays lexical** — the spawn keeps returning unproven children.
4. **It does not generalise.** #441 re-runs the launcher at runtime
   (`adapter_supervisor.py:376`). And the house precedent already agrees with
   in-spawn: `adapter_child_factory.py:25-33` documents
   `await runner.start_and_handshake()` as **step 4 of its own spawn factory**, on
   every spawn. `spawn_quarantine_child_io` is the *only* child factory that
   returns without verifying.

**Reap (AST-verified):** the try at `:657` has 6 handlers and **no finally**; the
try at `:782` has a `finally` at `:935` → `:963-966 comms_graph.aclose()`. A
`_refuse_boot` in the **771-781** window would leak the live bwrap child.
Handshaking **inside the spawn** is safest of all: the refusal precedes the
instance ever being returned, so no window exists.

## 7. Scope: what transfers to #440/#441/#442

- **#441 (gateway-adapter) — re-runs the launcher at runtime.**
  `supervise_one` (`adapter_supervisor.py:365`) is a `while True:` loop (`:376`) →
  `_spawn_or_terminal` (`:394`) → launcher + `Popen`
  (`adapter_child_factory.py:477-499`), with backoff and a breaker. A runtime
  refusal is genuinely reachable — **but it needs no exception**: the factory
  already handshakes on **every** spawn (`adapter_child_factory.py:29`). The shared
  auditor is correct there under the same unified invariant (§2). No divergence.
- **#442 (foreground-TUI) — the producer does not exist.**
  `spawn_plugin_via_launcher` (`cli/_launcher_spawn.py:188`) has **zero**
  production call sites; `alfred chat` (`cli/main.py:273`) dials the gateway
  socket (Spec A G5). **Rescope #442 to delete the dead seam.**
- **#440 (comms-adapter)** — per §8.2, the drain must be built first.

## 8. ADR-0051 amendments

### 8.1 The writev-buffers premise is a RACE, not structural

ADR-0051:42-54 records that the fd-3 `writev` buffers and succeeds, so
`ProviderKeyDeliveryError` "never fires on a refusal" — "empirically confirmed" on
two platforms (:124-134). **The parent closes every read-end copy at
`quarantine_child_io.py:883-908` BEFORE the writev at `:912`.** Only the child
holds a read end. A launcher that exits first ⟹ EPIPE ⟹ `OSError`
(`fd3_key_delivery.py:104-105`) ⟹ `ProviderKeyDeliveryError` ⟹
`QuarantineChildSpawnError` (`:913-921`) — boot already refuses,
**nondeterministically**. Task 0 sampled only **slow** refusal paths; the fast one
(`plugin_id_charset_invalid`, `alfred-plugin-launcher.sh:123-136`, before any
`python3`) was never in the sample. `domain_verify_mirrors_production_claims`,
inside a recorded ADR.

### 8.2 ADR-0051 is wrong about three of the four producers

ADR-0051:21-24 says *"Four spawn sites drain that stderr today… the row was logged
into a `child_stderr` field and nothing else."* **False.** Only the quarantine
child drains (`quarantine_child_io.py:509`). `comms_stdio_transport.py:173` and
`adapter_child_factory.py:497` pipe stderr and **never read it**. So #440/#441 are
"**build the drain, then attach the auditor**" — materially larger than the ADR
implies. (Aside worth its own issue: an unread, 64 KB-bounded stderr pipe on a
long-lived adapter is a wedge waiting to happen.)

### 8.3 The A-vs-B reversal and the gating relationship

Record the maintainer's 2026-07-16 decision: option A adopted; #443 is a hard
pre-gate on #340 PR2b; CodeRabbit's #446 Major stands vindicated.

### 8.4 The fast-refusal hole is NOT #444's, and the barrier cannot close it

On the EPIPE branch (§8.1) `:913-921` raises **before** `:923` — so **no
`_SubprocessChildIO` is ever constructed**, the handshake never runs,
`_log_child_stderr` never runs, and the launcher's stderr *containing the genuine
row* is **never read at all**. #443's headline promise ("a genuine launcher refusal
at boot ⟹ exactly one attributed row") is **false on the fast-refusal path**.

Issue #444 does **not** fix this: it writes `provider_key_delivery_failed`, a *different*
reason — the launcher's true reason is still lost. And a naive "drain and record on
the EPIPE arm" **reopens the forgery**: EPIPE proves only that all read ends
closed, not that the launcher never exec'd. **This is a structurally distinct hole
requiring option (C) or a consciously accepted residual — recorded as §11.4, not
deferred to #444.**

## 9. Testing

- 100% line + branch on the boundary (CLAUDE.md: every security boundary).
- **No AST call-site guard.** Under handshake-inside-the-spawn, correctness does
  not depend on "spawned exactly once", so a lexical guard would advertise a
  property it cannot hold — and would be blind to the lazy function-local import
  production uses (`daemon_runtime.py:328`). Structure, not lexical rule.
- **The design rests on TWO facts, not one** (rev 2): (a) `_child_wrote_stdout`
  lifetime monotonicity, and (b) the **intra-`read_frame` set at `:457`**, firing
  between header and body (§3.1). A monotonicity-only test passes straight through
  a mutation that moves `:457` below the body read — which *is* the #446 bypass.
  Both need their own test.
- Real-execution oracles: a child double writing zero stdout ⟹
  `spawn_quarantine_child_io` raises **and** the row is recorded; extend the
  docker-gated real-spawn lane (`test_quarantine_child_real_spawn.py:195`) with an
  **assert-RAN (not skipped)** floor (`domain_paper_only_gates`, the #245 pattern).
- **A probe leg is required** for every oracle (§6.1).
- One guard **is** warranted: pin that `bwrap`/`runuser` stderr can never parse as
  a valid row — a claim about third-party output, the kind that rots.

### Adversarial corpus (next free id: 021)

- **`sbx-2026-021`** `boot_barrier_absent_launcher_refusal_reaches_runtime` — a real
  refusal ⟹ `QuarantineChildSpawnError` **from the spawn**, exactly one row with
  the true reason, and the `fail_closed` T0 hookpoint **actually dispatched** (not
  `refusal_record_failed`). The core-001 regression oracle; it fails today. Assert
  on the **dispatch**, not just the row — a row-only assertion passes straight
  through the bug (§6.2).
  **Rev 2: pin the refusal reason explicitly** — a fast reason (§8.1) records
  nothing and a slow one records a row, so an unpinned reason makes this test
  **nondeterministic**. Use a slow path.
- **`sbx-2026-022`** `exec_d_child_cannot_forge_refusal_after_boot_handshake` — the
  #446 residual, closed. Derive "no row written" from the audit store, never from
  the gate predicate (`domain_a_test_that_asks_the_code_if_the_code_is_right`).
- **`sbx-2026-023`** `slow_launcher_refusal_still_refuses_boot` — the §3.3
  refutation pinned, so a future "let's just bounded-wait" PR goes red.
- **`sbx-2026-024`** `child_boot_performs_no_external_io` — **downgraded by rev 2**
  from load-bearing to defence-in-depth (§4.1: the empty netns already forecloses
  it). Still worth having; no longer the thing holding the argument up.
- **Amend `sbx-2026-019`**: a successful exec now produces frames — precisely the
  success-path signal ADR-0051:228-231 says #447 needs and lacks. **The handshake
  may make #447 tractable rather than blocked.** Note on #447; do not fold.

## 10. Decomposition and status

**PR1 — declaration placement (no behaviour change). READY; needs no maintainer
call.** Move **all ten** supervisor hookpoints (the four sandbox/boot tuples plus
the six breaker/lifecycle tuples — the four-vs-ten scope is resolved to ten below)
into a `declare_hookpoints(registry)` publisher at `src/alfred/supervisor/hookpoints.py`;
register it in `hooks/boot.py:_declare_all_subsystem_hookpoints` (discharging an
obligation that docstring already imposes); re-key `KNOWN_HOOKPOINTS`
(`_known_hookpoints.py`) off `alfred.supervisor.core` → `alfred.supervisor.hookpoints`;
delegate from `_register_hookpoints`; drop the `_StubSupervisor` unbound-call dance
(all **three** sites, not one), which exists only because these are not
boot-declarable.

**Rev 3 corrections** (from the 5-reviewer plan review — see the plan's "What rev 1
got wrong"):

- **PR1 does NOT close a live defect.** core-001 is latent (§6.2). PR1 is **PR2's
  prerequisite** and the fix **#444** is blocked on. State it that way everywhere;
  the opposite claim is the #434-436 failure mode.
- **`sbx-2026-021` does NOT ship in PR1.** Its threat has no production path until
  §5's handshake lands, so its oracle would have to manufacture its own premise —
  the self-referential oracle this repo has twice recorded as worthless. It ships
  with PR2.
- **The tuple stays function-local.** A module-level constant silently blinds
  `test_known_hookpoints_sync.py`'s AST drift resolver (which handles the inline
  `hookpoints = (...)`-then-`for` shape only, falling through to
  `# Unresolvable — silently skip` at `:290`): a reviewer ran it both ways —
  **10 names → 0, still green.** The #432 residual, reintroduced by a PR about
  drift.
- **Four-vs-ten resolved: ten.** Not for rev 2's "two tuples drift" reason
  (disjoint sets cannot drift in the #432 sense) but because §10's two deliverables
  are **incompatible** at 4/6: the six breaker/lifecycle tuples would stay reachable
  only via the stub dance §10 also demands retiring.
- **PR1 touches no file under `src/alfred/security/`** — run the adversarial suite
  as prudence, not as the CLAUDE.md mandate rev 2 claimed.

**PR2 — the two-frame boot handshake (#443 proper).** §5 + §6.1's probe hello +
the §8 ADR amendments + corpus **021**-024 (021 renumbers down from PR1, where its
threat is not yet reachable). The child protocol change is **accepted** — §0
decision 2. PR2 is where core-001 becomes live, which is why PR1 lands first.

## 11. Residuals (named, per CLAUDE.md hard rule 7)

1. **Supply-chain compromise of the wheel, the bound interpreter, or `anthropic`**
   (which the host imports too, §4.1) — accepted; strictly-stronger attacker.
2. **`bwrap`/`runuser` diagnostics on the shared fd 2 after exec** — not
   exploitable (`parse_launcher_refusal_rows` requires a JSON object with keys ⊆
   `SANDBOX_REFUSED_FIELDS`, string values, Cc/Cf-free, `reason` in the closed
   vocab), but it is an assumption about third-party stderr. **Pin it.**
3. **Grandchildren inheriting fd 2** — not reachable under the shipped
   `--unshare-pid` policy; at boot the child forks nothing. **Name the policy
   dependency** (`domain_lexical_rules_cannot_decide_filesystem_facts`).
4. **The fast-refusal EPIPE path (§8.4)** — a genuine launcher refusal whose row is
   never read. Structurally outside this mechanism. Option (C) or accept.
5. **The pre-hello window.** `_emit_fd3_framing_error_and_exit`
   (`__main__.py:84-98`) prints to stderr and exits with zero stdout, and sits
   before the hello in **every** variant. So the gate opens on child-authored
   stderr at boot in all designs; only the parser stands there. Two frames minimise
   the window; they do not eliminate it.

## 12. Related — and a pattern worth naming

Six false or stale claims found in this subsystem while designing one issue:

| claim | reality |
| --- | --- |
| `supervisor/core.py:954` — "the existing restart scheduler spawns a fresh adapter" | never built (`core.py:51-54`); filed as **#455** |
| `supervisor/core.py:1021` — "the supervisor's **six** hookpoints" | the tuple holds **ten** |
| `daemon_runtime.py:324-326` — the spawn await is "the only await in this builder" | `:355`/`:357` are post-spawn awaits |
| `quarantine_child_io.py:802-805` — a refusal "REFUSES the spawn" | a launcher refusal returns a **corpse** |
| ADR-0051:44-54 — the writev "never fires on a refusal", proven on two platforms | a **race** (§8.1) |
| ADR-0051:21-24 — "four spawn sites drain that stderr today" | **one** does (§8.2) |

Plus **#449** — the blank-REASON premise did not reproduce (`cli/audit.py:126-145`
returns `subject.reason`; `as_subject()` always sets it). Evidence posted; awaiting
a repro. #450's half is real.

**The pattern:** every one is prose that was *read* rather than *executed*, and
each became load-bearing for someone's later reasoning — the same thesis #434-436
shipped. Correct `daemon_runtime.py:324-326`, `core.py:1021`, and
`quarantine_child_io.py:802-805` in the PRs that touch them.

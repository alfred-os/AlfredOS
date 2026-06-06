# Hooks subsystem

The hooks subsystem owns "where, and on whose authority, does third-party
code get to observe, mutate, or refuse one of AlfredOS's actions?" Every
in-tree [action](../glossary.md#action) that wants to be hookable
threads its lifecycle through the same five-stage primitive; every
plugin or in-tree subscriber that wants to participate registers against
the same registry under the same [capability gate](../glossary.md#capability-gate).

Slice 2.5 is the subsystem's first slice. The dispatch engine, the
publisher helper, the capability gate, the four-kind contract, the
audit-row vocabulary, and the per-process registry all land here. The
[PoC](../glossary.md#poc) publisher (`memory.episodic.record`) lives in
the memory subsystem but its hook wiring is documented here because the
contract belongs to hooks, not to memory.

Sibling subsystem docs: [identity](identity.md), [comms](comms.md).

## Hello world

The simplest case — a `user-plugin`-tier `post` observer that watches
every recorded turn and changes nothing:

> **Hookpoint naming.** The runtime canonical form is the **stem name** the
> publisher passes to `invoke()` and the registry's
> `register_hookpoint(name=...)` (`"after_flush"`, `"before_validate"`, etc.).
> The dotted form (`memory.episodic.record.after_flush`) was an aspirational
> threat-model identifier — originally planned to land via a Slice-3 MCP
> transport normalization layer. **That layer was not built;** the MCP
> transport at `src/alfred/plugins/session.py` (shipped in PR-S3-3a) uses
> stem-form identifiers directly. The eventual canonical→stem normalization
> is deferred to Slice 4 as part of ADR-0016 (comms-MCP rewrite); see
> [#118](https://github.com/alfred-os/AlfredOS/issues/118).
>
> Until then: every subscriber, publisher, and decorator **runtime**
> example in this doc and in the source docstrings uses stem form. The
> [Manifest surface](#manifest-surface) section below still shows the
> aspirational dotted form because that's what the deferred MCP
> transport layer will accept once ADR-0016 lands. See
> `tests/unit/memory/test_episodic_hooks_wiring.py` for the as-shipped
> registration form, and `src/alfred/hooks/_known_hookpoints.py` for the
> canonical list of every stem the runtime knows about.

```python
from alfred.hooks import hook, HookContext

@hook("after_flush", kind="post", tier="user-plugin")
async def log_recorded_turn(ctx: HookContext) -> None:
    print(f"recorded turn for {ctx.input.user_id}")  # observe only
    return None  # pass through — the chain's view is unchanged
```

This is the whole observer contract: an async function decorated with
the [hookpoint](../glossary.md#hookpoint) name, the
[hook kind](../glossary.md#hook-kind), and the
[hook tier](../glossary.md#hook-tier) the subscriber is requesting.
Returning `None` means "no change" for every
kind — the dispatcher folds the prior chain ctx forward to the next
subscriber. Security material — the capability gate, the refusal
contract, the fail-closed semantics — layers on top of this minimal
shape.

### Self-check: is my subscriber registered?

Inspect the active registry directly via the
[`get_registry`](../../src/alfred/hooks/registry.py) singleton accessor:

```python
from alfred.hooks import get_registry

regs = get_registry().subscribers_for("after_flush", kind="post")
assert any(s.origin_module == __name__ for s in regs), \
    "my subscriber didn't register"
```

`HookRegistry.subscribers_for(hookpoint, kind)` is the public-surface
read path for introspecting the registry. It returns a tuple of
`Subscriber` records — frozen, slotted dataclasses — each carrying
`hook_fn` (the registered async callable), `hookpoint`, `kind`, `tier`,
`origin_module` (captured from `hook_fn.__module__` at register time),
and `registration_seq` (the monotonic counter used as the same-tier
tie-breaker). A miss returns the module-level `_EMPTY` singleton; a hit
returns a freshly-built tuple snapshot sorted by `(tier_rank,
registration_seq)`.

### Publisher hello-world: declaring a hookpoint

A subscriber registers only AFTER the publisher of the hookpoint has
declared the per-hookpoint contract — `subscribable_tiers`,
`refusable_tiers`, `fail_closed`. The declaration goes in the
publisher's module-init path (typically a `declare_hookpoints()`
function called at import time + idempotently re-called from the
publisher's `__init__`).

```python
# src/alfred/<your_publisher_module>/your_module.py

from alfred.hooks import (
    OPEN_TIERS,
    SYSTEM_OPERATOR_TIERS,
    SYSTEM_ONLY_TIERS,
    HookRegistry,
    get_registry,
)


def declare_hookpoints(registry: HookRegistry | None = None) -> None:
    """Declare every hookpoint this publisher invokes."""
    target = registry if registry is not None else get_registry()

    # Open observability hookpoint — every tier can subscribe and refuse.
    target.register_hookpoint(
        name="after_flush",
        subscribable_tiers=OPEN_TIERS,
        refusable_tiers=OPEN_TIERS,
        fail_closed=False,
    )

    # Security stage — system + operator only, system-only refusal,
    # fail-closed on subscriber error / timeout.
    target.register_hookpoint(
        name="before_db_write",
        subscribable_tiers=SYSTEM_OPERATOR_TIERS,
        refusable_tiers=SYSTEM_ONLY_TIERS,
        fail_closed=True,
    )


# Module-init: declare BEFORE any subscriber imports this module.
declare_hookpoints()
```

Why upfront declaration is required (#119): under
`strict_declarations=True` (the production default), a subscriber that
attempts to register against an undeclared hookpoint is REFUSED at
register time with a `HookError`. This forces a publisher-first
ordering — the publisher imports first and declares its metadata;
subscriber modules import second and find the declaration already in
place. Without the gate, a subscriber could register against a
misspelled hookpoint (typo on the publisher's name) and never run —
the typo would silently disable the security stage.

The reference implementation lives at
[`EpisodicMemory.declare_hookpoints`](../../src/alfred/memory/episodic.py)
— five hookpoints, three tier-set shapes, the same idempotent
declare-at-init + declare-from-instance-init pattern this example
uses.

```python
# Self-check: is the hookpoint declared?
from alfred.hooks import get_registry
assert get_registry().hookpoint_meta("before_db_write") is not None
```

### Drive a synthetic dispatch from a test

Once registered, you drive a one-shot chain via the lower-level
[`invoke`](../../src/alfred/hooks/invoke.py) primitive. `HookContext` is
frozen + slotted, so construction is keyword-friendly; the five required
fields are `action_id`, `hookpoint`, `input`, `correlation_id`, and `kind`:

```python
import asyncio
from alfred.hooks import HookContext, invoke

# A synthetic input — actions in the real publishers carry a typed
# payload (e.g. EpisodicRecordInput). Anything pickle-friendly works for
# a drive-from-test case.
fake_input = {"user_id": "alice", "content": "hello"}

ctx = HookContext(
    action_id="memory.episodic.record",
    hookpoint="after_flush",       # stem; the dispatcher rewrites it via for_stage()
    input=fake_input,
    correlation_id="test-corr-id",
    kind="post",
)

# invoke() is async — wrap the call in asyncio.run(...) at the test entry.
result = asyncio.run(invoke("after_flush", ctx, kind="post"))
```

`invoke(name, ctx, *, kind=...)` applies `HookContext.for_stage(...)`
internally so the subscriber sees the stage `invoke` was called with,
even if the caller-passed `ctx` claims a different one. The returned
`HookContext` is the end-of-chain fold (or last-good on a fault) — your
test can assert on `result.input` to confirm a `pre`-stage rewrite, or
on the absence of an exception to confirm a `post` chain ran clean.

## Progressive disclosure

### Observe

The hello-world above is the canonical `post` observer. The `pre`
observer is the mirror — fires before the action body runs, returns
`None`, sees the input the action will process:

```python
@hook("before_validate", kind="pre", tier="user-plugin")
async def count_pending_writes(ctx: HookContext) -> None:
    metrics.incr("pending_writes", tags={"user": ctx.input.user_id})
    return None
```

A `None` return from a `post` observer is end-of-story — there is no
downstream caller to see a substitution. A `None` return from a `pre`
observer means "I have nothing to rewrite; proceed with the carrier you
already have." Both fall through cleanly.

> **Snippet preamble.** The Mutate, Refuse, and System-tier examples below
> share these imports / stubs. Drop them once at the top of your subscriber
> module:
>
> ```python
> from dataclasses import replace
> from alfred.hooks import hook, HookContext, HookRefusal
> from alfred.memory.episodic import EpisodicRecordInput  # actual model name in src
>
> # placeholder for an imagined PII detector — swap in your real implementation
> def looks_like_api_key(s: str) -> bool: ...
> def redact(s: str) -> str: ...
> ```

### Mutate

A `pre` hook that returns a new `HookContext` rewrites the input the
action body will see:

```python
@hook("before_db_write", kind="pre", tier="operator")
async def normalise_content(
    ctx: HookContext[EpisodicRecordInput],
) -> HookContext[EpisodicRecordInput]:
    new_input = replace(ctx.input, content=ctx.input.content.strip())
    return ctx.with_input(new_input)
```

`HookContext` is frozen + slotted; `with_input` returns a NEW carrier.
Subsequent subscribers and the action body see the mutated input. The
dispatcher folds `chain_ctx = result` after each subscriber so the next
one starts from the most recent mutation.

The subtle bit — a later refusal **discards** an earlier mutation. If
subscriber A rewrites `content`, then subscriber B raises
[`HookRefusal`](../glossary.md#hookrefusal), the action body NEVER runs
and the caller never observes A's mutation.
The fold buffer is only realised when the chain completes. This is the
intent: a refusal means "the action is not happening," not "the action
is happening with the first half of subscribers' rewrites baked in."

### Refuse

A `pre` hook raises `HookRefusal` to short-circuit the action. The
dispatcher stops walking the chain immediately, emits a `hooks.refusal`
[audit log](../glossary.md#audit-log) row, and propagates the exception
to the caller:

```python
@hook("before_db_write", kind="pre", tier="system")
async def block_secret_leaks(
    ctx: HookContext[EpisodicRecordInput],
) -> HookContext[EpisodicRecordInput]:
    if looks_like_api_key(ctx.input.content):
        raise HookRefusal(
            hook_id="dlp-block",
            action_id=ctx.action_id,
            reason="content matches a known secret shape",
            correlation_id=ctx.correlation_id,
        )
    return ctx
```

Refusal is **authorized** per hookpoint, not unconditional. The
publisher declares which tiers may refuse via `refusable_tiers`. A
subscriber whose tier is in the set sees its refusal propagate; a
subscriber whose tier is OUTSIDE the set has its refusal **swallowed**,
its would-be mutation **discarded**, and a `hooks.unauthorized_refusal`
audit row written. The caller never sees a `HookError` for an
unauthorized refusal — the audit row IS the loud-failure escape (the
caller did not write that hook, so handing it an exception would
violate the spec; CLAUDE.md hard rule #7 is satisfied by the audit row,
not by raising). This is spec §6.5.

### System-tier

The PoC redactor on `before_db_write` is the system-tier example. It
needs `tier="system"` to see pre-DLP content (an in-tree security stage)
and it needs the registry's capability gate to grant `system`:

```python
@hook("before_db_write", kind="pre", tier="system")
async def redact_pre_persist(
    ctx: HookContext[EpisodicRecordInput],
) -> HookContext[EpisodicRecordInput]:
    redacted = redact(ctx.input.content)
    return ctx.with_input(replace(ctx.input, content=redacted))
```

`system` is the highest-blast tier. Two independent gates must pass
before such a subscriber runs (spec §6.3):

- **Publisher-side allow-list.** The hookpoint's `subscribable_tiers`
  must include `system`. For `before_db_write` that is the case —
  `subscribable_tiers={"system", "operator"}`, deliberately excluding
  `user-plugin` so a third-party plugin cannot wedge into the redactor
  seam.
- **Operator-side capability grant.** The registry's `CapabilityGate`
  must approve. In Slice 2.5 the gate is `DevGate`; the default
  refuses `system` unconditionally. The bootstrap must construct
  `DevGate(allow_system=True)` explicitly to enable system-tier
  registration. Test fixtures use `fresh_registry_allow_system` for
  the same reason.

**`subscribable_tiers` is enforced at registration AND re-checked at
dispatch** (issue #119, spec §6.2). The publisher-side allow-list is
ACTIVE — every subscriber registration consults the declared metadata
and the dispatcher rechecks on every `invoke`. Both halves of the
defense are described in
[Publisher declarations and the `subscribable_tiers` enforcement](#publisher-declarations-and-the-subscribable_tiers-enforcement)
below.

The two-gate model is what makes "a system-tier security stage is
load-bearing" survive contact with a malicious in-tree dependency: a
dependency that imports a `@hook(..., tier="system")` decorator at
import time fails the gate refusal and the registration leaves no
trace in the registry. There is no env-flag escape hatch — sec-007
forbids `DevGate` reading the environment for the
`ambient-escalation` reason given in the spec.

The PoC's `before_db_write` stage is `fail_closed=True`. A subscriber
that crashes (the redactor backend is down), refuses, or exceeds the
per-chain deadline must NOT let the un-redacted write proceed — that
is the spec §6.6 + §6.4 contract. The wrap is a `HookSubscriberError`
with the original exception chained via `__cause__`; the original
exception's `args` / `str(exc)` are NEVER copied into the audit row
(CLAUDE.md hard rule #1 — the subscriber may have inadvertently
wrapped T3 user content in its exception).

## Contract surface

### The hookpoint primitive and the four kinds

A **[hookpoint](../glossary.md#hookpoint)** is a named stage in an
[action](../glossary.md#action)'s lifecycle. The publisher calls
`invoke(name, ctx, kind=...)` at the stage; the dispatcher walks every
subscriber registered against `(name, kind)`. Spec §4 fixes four kinds:

- **`pre`** — runs BEFORE the action body. Subscribers may mutate the
  input (return a new ctx via `with_input`), or refuse via
  `HookRefusal`. The first authorized refusal short-circuits the chain
  and the action body never runs.
- **`post`** — runs AFTER the action body succeeds. Subscribers may
  return a new ctx for downstream observers; refusal is meaningless
  here (the action already happened) and `HookRefusal` propagates
  uncaught with NO refusal audit row — §6.5's authorization contract is
  `pre`-only.
- **`error`** — runs when the action body raised a non-cancellation
  exception. The first subscriber that returns a `HookContext` wins:
  "swallow-and-substitute" semantics. The upstream exception is
  exposed under `ctx.metadata["error_exc"]` so subscribers can
  introspect what went wrong. If every subscriber returns `None`, the
  original exception re-raises.
- **`cancel`** — runs on `asyncio.CancelledError`. Cleanup-only.
  Subscriber return values are IGNORED; the original cancellation
  always re-raises after the chain completes. The cancel chain fires
  BEFORE the error chain would — the spec §4 cancel-before-error
  invariant is what stops an error subscriber from misclassifying a
  cancellation as a non-cancellation failure.

### The `invoking` helper and the `invoke` primitive

Publishers thread an action through the `invoking` async context
manager rather than calling `invoke` four times. The helper mints one
`correlation_id` per action, builds the initial frozen `HookContext`,
and yields a mutable `Flow[T]` driver. The PoC's `record` reads:

```python
async with invoking("memory.episodic.record", inp) as flow:
    flow = await flow.pre("before_validate")
    self._validate(flow.input)
    flow = await flow.pre(
        "before_db_write",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )
    async with flow.body(
        post="after_flush",
        error="write_failed",
        cancel="cancelled",
    ):
        await self._persist(flow.input)
```

`flow.pre(stage, ...)` drives the `pre` chain and rebinds the flow's
internal ctx to the chain's output; `flow.body(post=..., error=...,
cancel=...)` is the async context manager that fires the right
terminal chain on the body's exit (success → post; cancellation →
cancel + re-raise; any other exception → error + re-raise-or-suppress).
This is spec §3.4.

The lower-level `invoke(name, ctx, *, kind, ...)` primitive is what
`Flow.pre` and `Flow.body` call. Callers that need finer control (a
publisher with non-standard lifecycle, a test that drives one chain
in isolation) use `invoke` directly. The same five kwargs flow through
both surfaces: `subscribable_tiers`, `refusable_tiers`, `fail_closed`,
`exc`, plus the chain deadline read from the registry.

### Tier model

Every subscriber registers at a [hook tier](../glossary.md#hook-tier)
(spec §6.1):

- **`system`** — observes pre-DLP content, may participate in security
  stages. In Slice 2.5 every in-tree module is treated as `T0`; the
  capability grant requires explicit operator opt-in
  (`DevGate(allow_system=True)`) per sec-007. Slice 3 ships the
  manifest-driven `CapabilityGate` with an install-time prompt.
- **`operator`** — the operator's own customisations. The dev-time
  gate grants this unconditionally.
- **`user-plugin`** — third-party plugins under the operator's
  authority. The dev-time gate grants this unconditionally.

Tier is a **requested capability**, not a self-declaration. The
publisher's `subscribable_tiers` allow-list and the registry's
capability gate together decide whether a registered subscriber
actually runs.

### Publisher declarations and the `subscribable_tiers` enforcement

Every hookpoint has **one publisher** — the module that owns the
action it sits inside (e.g. `alfred.memory.episodic` for
`before_db_write`). That publisher MUST declare the hookpoint's
metadata at module-init time via
`HookRegistry.register_hookpoint(...)`. The declaration carries the
three values that govern dispatch policy for the hookpoint:

- `subscribable_tiers` — which tiers may register a subscriber.
- `refusable_tiers` — which tiers' `HookRefusal` is authorized on
  the `pre` chain (§6.5).
- `fail_closed` — whether a subscriber timeout / unexpected exception
  hard-raises (`True`) or rewinds + continues (`False`).

A subscriber registration with no matching declaration is **refused at
register time**:

```text
HookError: hookpoint 'before_db_write' not declared — declare via
register_hookpoint() before registering subscribers
```

This forces module-init ordering — publishers import first and
declare; subscriber modules import second and find the declarations
already in place. The check is the load-bearing typo guard: a
subscriber registered against a misspelled hookpoint would silently
never run, defeating the security stage. The strict check turns the
typo into a loud failure.

**Declarations are idempotent** on equal metadata — re-importing a
publisher under test isolation re-runs the declaration call and the
second call is a no-op. A **conflicting** re-declaration (different
metadata for the same name) is the publisher-version-drift / copy-
paste-typo shape and raises `HookError`. The error message attributes
both declaration sites so the operator can grep both.

**Subscriber tier enforcement at registration.** When a publisher has
declared a hookpoint, every subsequent
`HookRegistry.register(..., tier=X, ...)` consults the declared
`subscribable_tiers`. If `X` is NOT in the allow-list, register raises
`HookError` and emits a `hooks.tier_rejected` audit row through the
registry's sink. The row carries the hookpoint, the kind, the
subscriber's `__qualname__`, the requested tier, AND the declared
allow-list so the operator can attribute the rejection AND grep both
declaration sites in one shot. The failed register leaves no trace —
a subsequent `subscribers_for(name, kind)` returns the empty
singleton.

**Dispatch-time defense-in-depth.** Every `invoke(name, ctx, *,
subscribable_tiers=...)` call re-checks the publisher's invoke-time
allow-list against the registry's declaration. Drift here is a
publisher bug (a refactor that split declaration and invoke sites,
then drifted one side; a vendored copy disagreeing with the active
copy). The dispatcher emits a `hooks.tier_rejected` audit row carrying
BOTH allow-lists and raises `HookError` to short-circuit the chain.
The check fires for every kind (`pre` / `post` / `error` / `cancel`)
so a regression that wires the re-check only into the most-trafficked
arm cannot defeat defense-in-depth on the others.

The two-gate model now reads:

- **Publisher-side allow-list** (declared + register-time enforced +
  dispatch-time rechecked, this section).
- **Operator-side capability grant** (registry's `CapabilityGate`,
  enforced at registration). Slice 3 lands the operator-grant gate;
  Slice 2.5 ships the dev-time `DevGate`.

Both gates must pass for a subscriber to run. Together they are what
makes "a system-tier security stage is load-bearing" survive contact
with a malicious in-tree dependency (which can lie about its requested
tier but cannot defeat either declared allow-list).

```python
# Publisher (alfred.memory.episodic) — declared at module-init.
get_registry().register_hookpoint(
    name="before_db_write",
    subscribable_tiers=frozenset({"system", "operator"}),
    refusable_tiers=frozenset({"system"}),
    fail_closed=True,
)

# Subscriber module — succeeds (operator tier IN the allow-list).
@hook("before_db_write", kind="pre", tier="operator")
async def operator_redactor(ctx): ...

# Subscriber module — refused at register time (user-plugin NOT in
# allow-list). HookError + hooks.tier_rejected audit row.
@hook("before_db_write", kind="pre", tier="user-plugin")
async def hostile_user_plugin(ctx): ...
```

### Fault semantics

A subscriber that raises an unexpected exception (a bug, a downstream
backend down) is **never silently swallowed** (spec §6.6, CLAUDE.md
hard rule #7). The dispatcher:

1. Wraps the exception as `HookSubscriberError` via
   `HookSubscriberError.from_subscriber(...)`, chained via `from exc`.
2. Emits a `hooks.subscriber_error` [audit log](../glossary.md#audit-log)
   row carrying the subscriber's `__qualname__` and the exception's
   class NAME only (never `str(exc)` / `exc.args` — they may carry T3
   content).
3. Applies `fail_closed`:
   - `fail_closed=True` — the wrap re-raises; the action body never
     runs (if the fault was in a `pre` chain) or the action's
     terminal disposition is overridden (if in a `post` / `error`).
   - `fail_closed=False` — the chain rewinds to the last-good ctx
     and continues. The audit row IS the loud-failure escape; the
     fault is recorded, not hidden.

The `cancel` chain is special. A subscriber that crashes during a
cancel chain has its exception swallowed (cleanup must be best-effort
so the cancellation always propagates) but the audit row still
fires — the swallow is no longer silent. `cancel` never honours
`fail_closed`; the upstream cancellation always re-raises.

### Per-chain timeout

Every chain is wrapped in ONE `asyncio.timeout(chain_deadline_seconds)`.
The default is **250 ms per chain** (`HOOK_CHAIN_DEADLINE_SECONDS` in
`src/alfred/hooks/registry.py`), configurable per registry. A timeout
fires `hooks.chain_timeout` audit row and applies the hookpoint's
`fail_closed` policy. The cancelled in-flight subscriber is awaited to
completion under a secondary 50 ms cleanup deadline so its `finally`
block (DB rollback, lock release, span close) runs before the audit
row lands — bounded so an adversarial subscriber that traps
`CancelledError` cannot stall the dispatcher indefinitely. The
`cleanup_timed_out` field on the audit row distinguishes a cooperative
slow cleanup from an adversarial trap.

**The 250 ms per-chain wall-clock deadline (§6.4) is a SEPARATE concern
from the µs dispatch-overhead budget below.** The wall-clock deadline
bounds how long a chain may take to complete (real subscriber work
included); the perf budget bounds how much overhead the dispatch engine
itself adds, independent of any subscriber. A regression in either is a
release blocker; do not conflate them.

### Re-entry semantics

A subscriber that re-invokes its own hookpoint within the same chain
would recurse indefinitely. The dispatcher detects this via a
`ContextVar` stack of in-flight hookpoint names
(`alfred.hooks.registry._reentry`); on detection the dispatcher routes
to `_invoke_internal`, which **skips the chain entirely** (every tier,
system included — the T0-only invariant) and emits a
`hooks.reentry_bypass` [audit log](../glossary.md#audit-log) row. This
is spec §6.9.

The stack propagates via Python's standard `ContextVar` rules,
including across `asyncio.create_task` — a subscriber that spawns a
task to re-invoke its own hookpoint also routes to the bypass path.
There is no opt-out / fresh-chain escape hatch in Slice 2.5; a
subscriber genuinely needing a detached chain lands as a Slice-3
`@hook(...)` registration flag, not a runtime knob (the runtime knob
would be an injection vector).

> **ContextVar boundary caveat.** The `_reentry` ContextVar guard inherits
> across `asyncio.create_task` (Python copies the context at task spawn).
> It does NOT inherit across:
>
> - `asyncio.to_thread(...)` — runs in a thread executor without contextvar copy
> - `loop.run_in_executor(...)` / `ThreadPoolExecutor.submit(...)` — same
> - `asyncio.run_coroutine_threadsafe(...)` — cross-loop
>
> A subscriber that spawns work via any of these escapes the re-entry guard
> for that sub-call. The defensive runtime check inside `_invoke_internal`
> will refuse the re-entry attempt LOUDLY (raising `HookError`) rather than
> silently bypass, but subscriber authors should be aware and prefer
> `asyncio.create_task(...)` for in-loop fan-out.

`_invoke_internal` is module-private + carries a defensive runtime
guard — a caller that imports it directly outside the re-entry
detection path receives `HookError`. Sec-008's "useless when misused"
pin.

### Audit vocabulary

`StructlogAuditSink` emits seven event constants from
[`src/alfred/hooks/audit_sink.py`](../../src/alfred/hooks/audit_sink.py)
(the `HOOKS_*` `Final[str]` block):

| Event | When |
|---|---|
| `hooks.refusal` | Subscriber raised `HookRefusal` (`pre` kind only) |
| `hooks.chain_timeout` | Per-chain `asyncio.timeout(...)` expired |
| `hooks.subscriber_error` | Subscriber raised a non-refusal exception |
| `hooks.error_suppressed` | A deny was suppressed because the action body had already failed (`error` stage) |
| `hooks.unauthorized_refusal` | A refusal was raised by a hook whose declared tier the capability gate denied |
| `hooks.reentry_bypass` | Re-entrant dispatch — the inner chain was bypassed |
| `hooks.tier_rejected` | A subscriber's tier was not in the hookpoint's declared `subscribable_tiers` (register-time) OR the publisher's invoke-time `subscribable_tiers` drifted from the declaration (dispatch-time, #119) |

> **Slice 2.5 design choice — failures-only auditing.** All seven events
> above are failure-path constants. Happy-path dispatch emits NO audit row
> in Slice 2.5; observability of successful subscriber execution is via the
> subscriber's own logging or via the perf benchmark output. The rationale
> traces to **CLAUDE.md hard rule #7** ("No silent failures in security
> paths — failed DLP, failed capability check, canary trip → loud audit
> entry"): the rule frames the audit log as the surface for **anomalies an
> operator would want to investigate**, not as a positive-confirmation
> ledger. The emit-site authority is `src/alfred/hooks/invoke.py` — a future
> positive-confirmation event (e.g. `hooks.dispatched`) would land as a new
> `emit()` call there plus a new `HOOKS_*` `Final[str]` constant in
> `src/alfred/hooks/audit_sink.py`, NOT as a sink-side filter. Candidate
> Slice-3 addition if operator demand emerges.

Migration `0006_audit_result_hooks_values.py` extended `ck_audit_log_result`
with `"fault"` (chain timeout / subscriber error / error suppressed) and
`"bypass"` (re-entry path); the existing Slice-1/2 dispositions
(`success`, `refused`, `cancelled`, …) remain. Operators writing SIEM
queries against the audit log should grep on the event constant
plus result-disposition pair.

## Performance budget

The perf gate measures **dispatch overhead only** — the cost the
`invoke()` machinery adds, NOT the cost of the action body or its
DB round-trip (which dominate real latency; the gate is an overhead
gate, not a throughput gate). Each bench measures **p99 delta over a
same-loop baseline** (`await` of a no-op coroutine) so the gate is
not CI-hardware-absolute and not dominated by event-loop scheduling
noise. `pytest-benchmark` is pinned at 100 rounds × 20 iterations
with 5 warmup rounds.

**Release-blocking budgets — empirically grounded** (PR-C Task 2,
NOT spec §5's a-priori illustrative numbers):

- Empty hookpoint (zero subscribers): **p99 < 100 µs** delta over
  baseline.
- 5-subscriber pre chain: **p99 < 1000 µs** delta over baseline.
- Refusal short-circuit: subscribers after the refusing one do not run
  (correctness pin paired with the bench).

The CALIBRATION NOTE in
[`tests/perf/test_hook_dispatch_perf.py`](../../tests/perf/test_hook_dispatch_perf.py)
documents the empirical p99 on PR-A's as-shipped path (25-30 µs empty,
190-240 µs 5-chain on M-series; ~2-3× slower on CI) and the ~4×
headroom rationale. The original spec §5 numbers (<10 µs empty,
<100 µs 5-chain) stand as a long-term optimisation target; reaching
them is a future dispatch-optimisation PR.

**This µs dispatch-overhead gate is distinct from the 250 ms per-chain
wall-clock deadline (§6.4).** The dispatch-overhead gate catches a
regression that doubles the dispatcher's own cost; the wall-clock
deadline catches a chain that takes too long to complete (real
subscriber work included). Conflating them would let a 200 ms slow
subscriber pass the dispatch-overhead gate while the chain-deadline
gate that should catch it gets relaxed.

The gate runs on every PR via
[`.github/workflows/perf.yml`](../../.github/workflows/perf.yml). A
regression that pushes either bench above its budget is treated as a
structural regression and must be investigated before merge (CLAUDE.md
hard rule: do not weaken security or perf defaults to make tests pass).

## Manifest surface

Plugins declare [hookpoint](../glossary.md#hookpoint) subscriptions in
their manifest's `hooks` block — the **existing** field PRD §5.1 and
[ADR-0014](../adr/0014-pluggable-hooks-for-every-action.md) already
specify. A subscription is a `(action, kind)` tuple plus the
[hook tier](../glossary.md#hook-tier) the plugin requests:

```toml
[[hooks]]
action = "memory.episodic.record.before_db_write"
kind = "pre"
tier = "operator"
```

> **Note (Slice 2.5):** PR-A's in-process dispatch keys on the LOCAL stem
> (`"before_db_write"`). The dotted form shown above is the
> canonical/threat-model identifier the Slice-3 MCP transport will
> accept; until then, a plugin manifest emitted into the in-process
> loader must use the stem. The Slice-3 MCP transport will introduce a
> canonical→runtime resolution layer.

Slice 2.5 does NOT invent new field names. An earlier draft did and a
review caught the drift against PRD §5.1 / ADR-0014; the spec text was
corrected. The manifest is consumed by the Slice-3 MCP transport. This
slice only documents the shape so Slice 3 implements against one
canonical definition.

A plugin's manifest also declares any hookpoints the plugin
**publishes** (calls `invoke()` against from its own code) so the
operator and other plugins know what surface the plugin exposes. The
publish declaration uses the same `hooks` block (spec §3.6 — a plugin
is symmetric: it both subscribes and publishes via the same primitive).

## Deferred to Slice 3

Per spec §6.10 and ADR-0014:

- **The real manifest-driven `CapabilityGate` + install-time prompt
  UX.** Slice 2.5 ships `DevGate`; Slice 3 replaces it with the
  operator-grant gate that consults a policy store, prompts the
  operator on first install, and audits the grant. `DevGate` stays
  available as the dev-time default; tests continue to construct it
  directly.
- **MCP-transport hook registration for out-of-process plugins.**
  Slice 2.5 wires only the in-process `@hook` decorator path. The MCP
  transport rewrite lands alongside [ADR-0009](../adr/0009-comms-adapter-protocol-slice2-only.md)'s
  protocol inversion: a plugin process registers via the same
  manifest field shape but the registration crosses the process
  boundary via MCP rather than via Python decorator.
- **Per-hookpoint data-classification tags.** T1/T2/T3 labels on
  hookpoints, matched against subscriber clearance. Depends on the
  trust-tier work deferred by [ADR-0013](../adr/0013-defer-t1-t3-and-dual-llm.md).
  Slice 3 treats this as a **blocking gate** on enabling
  out-of-process subscribers — an MCP plugin subscribing to a
  hookpoint that carries T3 content without a classification check
  would be a trust-boundary hole.
- **Audit-volume sampling / aggregation.** Hook-trace rows can reach
  hundreds per second once actions carry real subscribers. Sampling
  lands when the volume is measurable; until then every chain
  invocation emits an audit row.

`DevGate` is the Slice-2.5 gate. In-tree code is treated as `T0` (the
[trust tier](../glossary.md#trust-tier) the spec stamps on in-tree
modules) so `DevGate` grants
`operator` and `user-plugin` unconditionally; `system` requires
constructor opt-in. Slice 3 replaces the whole gate without touching
the publisher / subscriber call sites — the `CapabilityGate` Protocol
surface is stable.

## Cross-references

- [the hooks design spec](../superpowers/specs/2026-05-27-slice-2.5-hooks-design.md)
  — the source of truth for §3.1–§7 contract decisions.
- [ADR-0014](../adr/0014-pluggable-hooks-for-every-action.md) — the
  decision that every action is hookable, plus the PR-C amendment that
  pins "core methods ARE the producer surface."
- [ADR-0013](../adr/0013-defer-t1-t3-and-dual-llm.md) — the T1/T3
  deferral that makes the dispatcher's `T0`-only re-entry-bypass
  invariant tenable this slice.
- [ADR-0009](../adr/0009-comms-adapter-protocol-slice2-only.md) — the
  MCP-transport rewrite that will carry out-of-process hook
  registration in Slice 3.
- Glossary terms:
  [action](../glossary.md#action),
  [hookpoint](../glossary.md#hookpoint),
  [hook kind](../glossary.md#hook-kind),
  [hook tier](../glossary.md#hook-tier),
  [HookRefusal](../glossary.md#hookrefusal),
  [PoC](../glossary.md#poc),
  [trust tier](../glossary.md#trust-tier),
  [capability gate](../glossary.md#capability-gate),
  [audit log](../glossary.md#audit-log).
  `dispatch chain` and `correlation id` remain bare terms until
  subsequent slices add them.
- Source code: [`src/alfred/hooks/`](../../src/alfred/hooks/) (registry,
  invoke, decorators, capability, context, errors, audit sink) and
  [`src/alfred/memory/episodic.py`](../../src/alfred/memory/episodic.py)
  (the PoC publisher).

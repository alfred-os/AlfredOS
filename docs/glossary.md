# Glossary

Single vocabulary source for AlfredOS. Every system-specific term has
one definition here; the rest of the docs link to it
(`[trust tier](../glossary.md#trust-tier)`) rather than repeat the
definition. Repetition is rot's seed.

Headings use the GitHub slugifier convention: lowercased,
non-alphanumeric collapsed to `-`. The slugs `authorization-role` and
`canonical-user-id` are load-bearing — `docs/superpowers/specs/*.md`
forward-references resolve here and `make docs-check` enforces the
anchors exist.

## Authorization role

A per-user closed-domain enum (`Authorization`, `StrEnum` in
[`src/alfred/identity/models.py`](../src/alfred/identity/models.py))
naming the four authorization tiers AlfredOS supports. Snake-case on
the wire (`read_only`, `standard`, `trusted`, `operator`); the CLI
also accepts kebab-case (`read-only`) via a Typer normaliser. The
enum lives in the DB schema as a CHECK constraint, not a Postgres
ENUM type — new tiers land via additive CHECK migrations to keep
rollback symmetry.

| Role | Default rate limit / min | Reply on refusal? | Notes |
|---|---|---|---|
| `read_only` | `0` (no requests) | **No — reply-suppressed** | Operator can add a row without granting interactive access |
| `standard` | `30` | Yes | Default for newly-added users |
| `trusted` | `60` | Yes | Elevated tier; no semantic difference beyond rate limits in Slice 2 |
| `operator` | unlimited (`None`) | Yes | At most one live operator per deployment |

The `read_only` reply-suppression is the security-sensitive bit: a
read-only user's DM is audited but the bot does not reply, so the
absence of a reply does not signal a malformed message — it signals
deliberate refusal. Defaults live in `AUTH_DEFAULT_PER_MIN`
(`MappingProxyType` in `src/alfred/identity/rate_limit.py`).

See [ADR-0010](adr/0010-canonical-user-id-and-listen-notify.md),
[`docs/subsystems/identity.md`](subsystems/identity.md), and
[`docs/subsystems/comms.md`](subsystems/comms.md) (RateLimiter
Protocol).

## Canonical user id

The slug-form identifier AlfredOS uses as the primary key for every
user-keyed subsystem (audit log, budget guard, memory partitioning,
capability grants). Derived deterministically from the operator-supplied
display name by a six-step pipeline (`src/alfred/identity/slug.py`):

1. **NFKC** Unicode normalisation.
2. **`unidecode`** ASCII transliteration.
3. **Lowercase.**
4. **Non-alphanumeric → `-`** (any run becomes a single hyphen).
5. **Strip leading/trailing hyphens; truncate to 63 chars.**
6. **Empty fallback** — if the pipeline yields `""`, return `"user"`.

Collision detection and `-2`/`-3` suffixing live in
`IdentityResolver.add` because they need a DB session; the slug
module itself never does I/O. Truncation happens **before** the
collision suffix so the suffix budget is independent of the seed
length.

Operator-readable IDs in log lines and audit-graph node labels are
worth the one-time collision check at `add` time. UUIDs would force
every operator query through a lookup table; slugs read straight out
of the rendered output. Homograph awareness (Cyrillic `а` vs Latin
`a`) is intentional-not-bug — `unidecode` collapses both to ASCII
`a`, so the slug is the same; the `display_name` preserves the
original.

See [ADR-0010](adr/0010-canonical-user-id-and-listen-notify.md) and
[`docs/subsystems/identity.md`](subsystems/identity.md).

## Trust tier

A type-level discriminant carried by every content blob inside
AlfredOS, indicating how much the system trusts the content's
provenance. Slice 2 ships **T2 only**; T1, T3, and the dual-LLM split
are deferred to Slice 3 per [ADR-0013](adr/0013-defer-t1-t3-and-dual-llm.md).

| Tier | Source | Slice |
|---|---|---|
| `T0` | System-internal synthetic content (the system created it) | All |
| `T1` | Operator-tier — TUI ingress + outbound from the operator | Slice 3 |
| `T2` | Authenticated user — Discord DM from a bound snowflake | Slice 2 |
| `T3` | Untrusted external ingestion — web fetch, email, file, MCP tool output | Slice 3 |

Slice 2's contract: the orchestrator accepts `TaggedContent[T2]` only.
Slice 3 introduces `TaggedContent[T3]` as a new type-level discriminant
(not a runtime flag) and the quarantined LLM that processes T3 content
without the privileged orchestrator ever seeing the raw bytes.

**Not to be confused with [hook tier](#hook-tier)** — `system` /
`operator` / `user-plugin` are dispatch-order + capability gates on
hook subscribers, an entirely separate axis from content provenance.

See [ADR-0008](adr/0008-llm-output-trust-tier.md) and
[ADR-0013](adr/0013-defer-t1-t3-and-dual-llm.md).

## Action

A named unit of work the core or a plugin dispatches: a tool call, a
provider call, a memory write, a comms outbound, an audit write, a
persona-to-persona message, a skill invocation. Distinct from a *tool
call*, which is one kind of action. Every action that wants to be
hookable threads its lifecycle through the same five-stage primitive
(`pre` → body → `post` / `error` / `cancel`) so subscribers across all
actions register against one uniform contract.

See [ADR-0014](adr/0014-pluggable-hooks-for-every-action.md) and
[`docs/subsystems/hooks.md`](subsystems/hooks.md).

## Hookpoint

A named, string-keyed extension point declared at a point in some
code's execution. Any code — core or plugin — may both publish
(call `invoke(name, ctx, kind=...)` at the stage) and subscribe
(register a handler against `(name, kind)`); spec §9.1's "no
asymmetry" point pins this. Slice-2.5 PR-A's in-process dispatch keys
on the LOCAL stem name the publisher passes to `invoke()`
(`"before_db_write"`, `"after_flush"`, etc.). The dotted form
(`memory.episodic.record.before_db_write`) is the canonical
threat-model identifier the Slice-3 MCP transport will normalise to —
but a Slice-2.5 subscriber MUST use the stem to fire against the
in-process publisher. See the "Hookpoint naming" callout in
[`docs/subsystems/hooks.md`](subsystems/hooks.md) for the same
Slice-2.5 caveat.

Hookpoints are PUBLISHER-DECLARED: the action that emits the hookpoint
calls `register_hookpoint(name=..., subscribable_tiers=...,
refusable_tiers=..., fail_closed=...)` at module init. Subscribers
register against the declared metadata; mismatched tiers are refused
at registration time and audited as `hooks.tier_rejected` (#119).

See spec §3,
[`docs/subsystems/hooks.md`](subsystems/hooks.md), and
[ADR-0014](adr/0014-pluggable-hooks-for-every-action.md).

## Hook kind

One of `pre` / `post` / `error` / `cancel`. The routing axis on a hook
invocation; each kind has a distinct subscriber contract (spec §3.5,
§4):

- **`pre`** — runs before the action body; subscribers may mutate the
  input or refuse via [`HookRefusal`](#hookrefusal).
- **`post`** — runs after the action body succeeds; observe-or-rewrite
  for downstream observers; refusal is meaningless.
- **`error`** — runs when the action body raised a non-cancellation
  exception; swallow-and-substitute via returning a `HookContext`.
- **`cancel`** — runs on `asyncio.CancelledError`; cleanup-only,
  return values ignored, original cancellation always re-raises.

See [`docs/subsystems/hooks.md`](subsystems/hooks.md).

## Hook tier

One of `system` / `operator` / `user-plugin`. The deterministic
dispatch-order axis on hook subscribers (system → operator →
user-plugin, then registration order within tier) and a **requested
capability** the operator-side `CapabilityGate` must grant (spec §6.1).
Tier is a request, not a self-declaration: the publisher's
`subscribable_tiers` allow-list and the registry's capability gate
together decide whether a registered subscriber actually runs.

**Not to be confused with [trust tier](#trust-tier)** — trust tier
(T0-T3) is the type-level provenance discriminant on content blobs;
hook tier is the dispatch + authorization axis on subscribers. They
share the word "tier" only.

See spec §6.1, [`docs/subsystems/hooks.md`](subsystems/hooks.md), and
[ADR-0014](adr/0014-pluggable-hooks-for-every-action.md).

## HookRefusal

The exception a `pre` subscriber raises to short-circuit the chain
(`src/alfred/hooks/errors.py`). The action body does not run, a
`hooks.refusal` audit row is written, and the exception propagates to
the caller — provided the subscriber's tier is in the hookpoint's
`refusable_tiers` allow-list. An **unauthorized** refusal (subscriber's
tier NOT in `refusable_tiers`) is audited as
`hooks.unauthorized_refusal`, the would-be mutation is discarded, and
NO exception is raised to the caller; the audit row IS the
loud-failure escape (CLAUDE.md hard rule #7). This is spec §6.5.

`HookRefusal` is `pre`-only; raising it from a `post`, `error`, or
`cancel` subscriber propagates uncaught with no refusal audit row.

See [`docs/subsystems/hooks.md`](subsystems/hooks.md).

## PoC

Proof-of-concept. In the Slice 2.5 hooks context, the single
instrumented action — `memory.episodic.record` in
[`src/alfred/memory/episodic.py`](../src/alfred/memory/episodic.py) —
that exercises the hook contract end-to-end across all four
[hook kinds](#hook-kind) (`pre`, `post`, `error`, `cancel`). The PoC
proves the publisher / subscriber / dispatcher / capability-gate
contract on real action infrastructure before the rest of the
codebase migrates.

See spec §7 and [`docs/subsystems/hooks.md`](subsystems/hooks.md).

## CommsAdapter Protocol

The Slice-2-only in-process Python `Protocol` (`@runtime_checkable`)
that every comms adapter satisfies. Surface: `name`, `async start()`,
`async run()`, `async stop()`, `def health() -> AdapterHealth`. The
orchestrator's supervisor drives every adapter through this surface.

Bounded deviation from PRD §5 ("plugins are MCP servers"): the
deviation is documented in [ADR-0009](adr/0009-comms-adapter-protocol-slice2-only.md),
and an AST-scan test prevents the concrete adapters from being imported
outside `src/alfred/comms/` so the Slice-3 MCP-transport rewrite stays
a single-module refactor.

See [`docs/subsystems/comms.md`](subsystems/comms.md).

## IdentityResolver

The only legitimate accessor for `User` and `PlatformIdentity` ORMs
(`src/alfred/identity/resolver.py`). Owns an in-process LRU cache with a
60-second TTL backstop and an `IdentityVersionCounter`-driven
invalidation hook. Surfaces five mutating methods (`add`, `bind`,
`unbind`, `remove`, `set_`) plus read-only `resolve`, `get_operator`,
`show`, `list_`. Every mutating method bumps the version counter exactly
once and emits a Postgres `NOTIFY alfred_identity_changed` payload
inside the same transaction.

See [ADR-0010](adr/0010-canonical-user-id-and-listen-notify.md) and
[`docs/subsystems/identity.md`](subsystems/identity.md).

## IdentityVersionCounter

A monotonic `threading.Lock`-guarded integer counter
(`src/alfred/identity/version_counter.py`). Bumped on every successful
identity mutation. Subscribed by `BudgetGuard` and the resolver's LRU;
when `current()` advances, downstream caches invalidate and re-fetch
on the next access.

The counter is purely in-process. Cross-process invalidation is
delivered by `IdentityListener` (subscribed to the Postgres
`alfred_identity_changed` LISTEN channel), which bumps the local
counter on every NOTIFY. The 60-second TTL backstop on every cache
entry bounds staleness on dialects that do not support `LISTEN/NOTIFY`.

See [ADR-0010](adr/0010-canonical-user-id-and-listen-notify.md) and
[ADR-0011](adr/0011-per-user-budget-guard.md).

## BudgetGuard

The per-user cost gate keyed on canonical user_id
(`src/alfred/budget/guard.py`). Holds a `dict[str, _UserBudget]` where
each entry stores `daily_usd`, `daily_usd_version`, `per_call_max_usd`,
`day` (UTC), and `spent`. Three security invariants:

- `_spent` and `day` are source-of-truth and NEVER evict under any
  in-process logic. The only legitimate eviction is the explicit
  `BudgetGuard.evict(user_id)` escape hatch.
- Only `daily_usd` is cache-able; `IdentityVersionCounter` bumps
  refresh the cached cap without touching `spent` or `day`.
- NaN / infinity / negative values are rejected at every cost entry
  point and at the `daily_budget_usd` load path (defence-in-depth on
  top of the DB CHECK).

See [ADR-0011](adr/0011-per-user-budget-guard.md).

## SecretBroker

The sole legitimate consumer of `ALFRED_*` environment variables and
the `~/.config/alfred/secrets.toml` file for any value listed in
`SUPPORTED_SECRETS`. Every other module reads secrets via
`SecretBroker.get` — the AST-scan test
`tests/unit/security/test_no_direct_env_reads.py` enforces this.

Two backends:

- **Env backend** (Slice 1): reads `ALFRED_<UPPERSECRET>` from
  `os.environ`.
- **File backend** (Slice 2): reads the TOML file at
  `~/.config/alfred/secrets.toml` (XDG default) or wherever
  `ALFRED_SECRETS_FILE` points. Fail-closed at construction:
  permissions must be `0600`, owned by the invoking user, parent
  directory must not be group/world-writable, the file must not be a
  symlink, and no `.git/` may appear in any of the first 12 ancestor
  directories.

Per-secret precedence is controlled by `_PREFER_FILE`. The broker
exposes `redact()` for the outbound DLP's stage-1 redaction.

See [ADR-0005](adr/0005-env-backed-secret-broker-slice1.md) and
[ADR-0012](adr/0012-file-backed-secret-broker.md).

## SUPPORTED_SECRETS

The broker's allowlist of registered secret names
(`frozenset[str]` in `src/alfred/security/secrets.py`). Slice 2:
`{deepseek_api_key, anthropic_api_key, discord_bot_token}`. Anything
not in this set raises `UnknownSecretError` on `get()`. Adding a new
secret name requires editing this set plus, if the secret is
file-preferred, adding it to `_PREFER_FILE` too.

See [ADR-0012](adr/0012-file-backed-secret-broker.md).

## \_PREFER_FILE

A strict subset of `SUPPORTED_SECRETS` whose file-backend value wins
over the env-backend value
(`frozenset[str]` in `src/alfred/security/secrets.py`). Slice 2:
`{discord_bot_token}`. For names NOT in this subset, env wins for
backward compatibility with Slice-1 deployments. The subset invariant
is asserted at import time.

See [ADR-0012](adr/0012-file-backed-secret-broker.md).

## OutboundDlp

The three-stage outbound scanner every outbound message string passes
through (`src/alfred/security/dlp.py`):

1. **Broker redaction** — `SecretBroker.redact` replaces any known
   secret value with `[REDACTED:<name>]`. Patterns are processed in
   descending-length order so a longer secret whose suffix is another
   live secret is fully redacted before the shorter one runs.
2. **Generic API-key regex** —
   `\b(?:sk|pk|tok|key)[-_][A-Za-z0-9]{20,}\b` → `[REDACTED:api-key-shape]`.
3. **Canary stub** — Slice 2 is a literal no-op. Slice 3 expands.

On modification, exactly one `dlp.outbound_redacted` audit row is
written with byte deltas + `stages_triggered`. Silent redaction is a
documented Slice-2 known oracle; Slice 3 pads to a length-bucket
boundary.

See [`docs/subsystems/comms.md`](subsystems/comms.md) and
[ADR-0012](adr/0012-file-backed-secret-broker.md).

## RateLimiter

The per-user rate-limiting Protocol (`src/alfred/identity/rate_limit.py`).
Implementations decide policy (token bucket, leaky bucket, sliding
window); consumers depend only on the Protocol surface. MUST return
`False` unconditionally for `Authorization.READ_ONLY`. Slice 2 ships
`NullRateLimiter` (no-op for single-operator deployments) and
`InProcessTokenBucketRateLimiter` (per-user token bucket keyed on
slug, refilled at the authorization-tier default rate).

See [`docs/subsystems/comms.md`](subsystems/comms.md) (RateLimiter
Protocol) and the `authorization-role` entry above for tier defaults.

## WorkingMemoryPool

The `(persona, user_id)`-keyed pool of in-process working memory
buffers (`src/alfred/memory/working_pool.py`, PR-B). Per-key locks
serialise access; eviction skips entries that are currently in use
(an active orchestrator turn holding the lock). Lazy-rehydrate from
the episodic store fires on cache miss, so a `WorkingMemoryPool`
entry for a returning user reconstitutes their context without an
explicit prompt.

See [ADR-0011](adr/0011-per-user-budget-guard.md) (consumer of the
same `IdentityVersionCounter` invalidation contract).

## Audit log

Append-only event log of every tool call, memory write, config change,
reviewer decision, and persona-coordination message. Rows carry
attribution (`actor_user_id`, `actor_persona`, `language`), event-type,
and event-specific subject fields. Stored in the `audit_log` Postgres
table; the audit-graph CLI renders cross-row joins for forensic queries.
Failure to write an audit row in a security path propagates (CLAUDE.md
hard rule #7).

## Capability gate

The runtime enforcement surface for plugin permissions. Every tool call
passes through the capability gate, which consults the plugin's
manifest, the per-user grant table, and the current request context.
Slice 3 lands the full surface alongside the MCP plugin transport;
Slice 2 ships only the data-model placeholders.

## DLP

Data Loss Prevention. In AlfredOS, DLP is the chokepoint discipline:
every outbound message string passes through `OutboundDlp.scan` (the
three-stage scanner above) before reaching the recipient. DLP cannot be
disabled per-call; only manifest-declared pure-internal tools can
bypass, and the adversarial suite verifies that claim. See the
`OutboundDlp` entry above.

## Persona

A named LLM-driven actor with its own system prompt, memory partition,
and authorization scope. The default persona is **Alfred**. Operators
can enable additional personas (Lucius, Oracle, Diana, …). Personas
honour `{user.language}` so the same persona renders different
operator-facing strings in different languages without a code change
(CLAUDE.md i18n rule #2).

## Skill

A procedural plugin in `skills/` that AlfredOS itself invokes at
runtime. Distinct from a Claude Code skill (which lives in
`~/.claude/skills/` and is invoked by Claude Code agents working on
this repo). Runtime skills go through the reviewer gate before
landing.

## MCP

Model Context Protocol. The transport AlfredOS uses for first-party
and third-party plugins (Slice 3+). Comms adapters speak in-process
Python in Slice 2 (see CommsAdapter Protocol above) and convert to
MCP transport in Slice 3 per [ADR-0009](adr/0009-comms-adapter-protocol-slice2-only.md).

## OODA loop

Observe-Orient-Decide-Act. The cognitive loop AlfredOS personas run
on every conversational turn. Observe: ingest the user's message +
working memory + relevant episodic recall. Orient: identify which
skill / tool / response shape fits. Decide: choose one. Act: emit the
response, audit the action.

## Slug

The canonical-user-id form (see `canonical-user-id` above). Also used
generically for "URL-safe lowercased name" in adjacent contexts (e.g.
`docs/adr/NNNN-<slug>.md` filenames).

## Snowflake

A Discord-native 64-bit identifier (e.g. `123456789012345678`).
AlfredOS stores snowflakes as strings in `platform_identities.platform_id`
because some Discord clients round 64-bit integers in JSON-decoder
defaults; round-tripping as strings preserves precision.

## ContextVar

Python's `contextvars.ContextVar` primitive. AlfredOS uses one
`_active_language: ContextVar[str | None]` to thread the active
user's BCP-47 language tag through `t()` calls without passing it
explicitly down the call stack. Each persona turn sets the
`ContextVar` to the user's language at the orchestrator boundary;
asyncio.TaskGroup copies the context per child, so concurrent turns
do not leak language state across users.

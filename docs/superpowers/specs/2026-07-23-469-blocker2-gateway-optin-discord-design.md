# #469 Blocker 2 — opt-in Discord (the stock quickstart boots, no gateway crash-loop)

**Status:** design v1, approved in brainstorming (Approach A — "opt-in Discord").
Parent epic: #469 (first-run experience — a documented quickstart that actually
boots). This spec covers **Blocker 2 only**. The structural relative — keeping the
gateway alive when a hosted adapter's credential fails — is **#331** and is
explicitly out of scope (see below).

## Problem

On the documented quickstart — `git clone … && cp .env.example .env && docker
compose up -d` — `alfred-gateway` **crash-loops** under `restart: unless-stopped`,
and because `alfred-core` has `depends_on: alfred-gateway: condition:
service_healthy` (`docker-compose.yaml:100-101`), the core **never starts either**.
The operator sees containers that are "up"/restarting rather than an error they can
act on: a silent forever-loop, not a loud refusal.

## Root cause (traced, HEAD `786df4e1`)

The compose default enables gateway-hosted Discord out of the box:

```yaml
# docker-compose.yaml:275
ALFRED_COMMS_ENABLED_ADAPTERS: '${ALFRED_GATEWAY_HOSTED_ADAPTERS:-["alfred_discord"]}'
```

On a stock first run the operator has no `ALFRED_DISCORD_BOT_TOKEN`. The chain:

1. `_resolve_hosted_adapter_ids()` (`cli/gateway/_commands.py:136`) succeeds —
   resolving the adapter *id* needs no token — so the gateway supervises
   `["discord"]`.
2. At first spawn the core credential resolver returns `missing_secret` →
   `AdapterCredentialError` (`comms_mcp/adapter_credential_resolver.py:212`),
   audited `result="refused"` (correct; pinned by
   `tests/integration/test_gateway_unset_discord_token_fails_loud.py`).
3. The supervisor wraps it as `GatewayAdapterSpawnError` and, because
   `first_attempt` is true, **re-raises fail-closed**
   (`gateway/adapter_supervisor.py:513-521`) — by design, so boot never
   log-and-continues.
4. It propagates up through `GatewayProcess.run()` → the `start_gateway._main`
   `TaskGroup` (`cli/gateway/_commands.py:383-387`) → `_reraise_first_meaningful`
   → out of `start_gateway`. **None** of `start_gateway`'s typed `except` arms
   (lines 391-439) catch `GatewayAdapterSpawnError` (an `AlfredError`), and there
   is no global CLI error boundary (`alfred.cli.main:app`) → **raw traceback**,
   exit 1.
5. `restart: unless-stopped` → **infinite crash-loop**; the core's dependency gate
   never clears.

### The blast radius is the whole gateway, and both failure modes hit it

The gateway process co-runs three things under one `asyncio.TaskGroup`: the TUI
**relay** (the `alfred chat` front door), the **egress planes** (proxy / relay /
adapter), and the adapter **supervisor**. A first-attempt spawn failure cancels the
siblings → the entire process exits. Two distinct token states both land here:

| Token state | Where it surfaces | Gateway | Core |
| --- | --- | --- | --- |
| **Unset** (stock quickstart) | `missing_secret` at first spawn | **Dies** → crash-loop | Never starts (blocked by `depends_on`) |
| **Present but invalid** | `LoginFailure` at handshake (the Discord adapter awaits `login()` synchronously *before* reporting ready — `plugins/alfred_discord/gateway_adapter.py:69-86`, fix C1) → first-attempt `GatewayAdapterSpawnError` | **Dies** — same abort | Never starts (same gate) |
| **Valid at boot, fails later** | post-ready runtime crash → `_handle_crash` → breaker | **Survives** — adapter parks (`breaker_open`); relay/egress stay up | Unaffected |

The core never crashes from the token directly — it is `alfred_tui`-only
(`test_alfred_core_comms_adapters_stay_tui_only`). Its only problem is the
dependency gate.

### Why the existing "preflight" does not prevent this

`bin/alfred-setup.sh:489-503` (the #309 preflight) is **advisory-only**: it prints
`warn "… NOT enabling Discord …"` but never actually disables it — it does not write
`ALFRED_GATEWAY_HOSTED_ADAPTERS=[]`, so the compose default still wins. It is also
reached only *inside* the interactive snowflake-binding branch, so the stock path
(skip the snowflake, `up -d`) bypasses it entirely and gets no warning at all.

## Key enabling fact

The **code** default is already empty: `Settings.comms_enabled_adapters: tuple[str,
...] = Field(default=())` (`config/settings.py:255`). Discord-on-by-default lives
*only* in the compose fallback. So this change **aligns the deployed default with
the code default** — it is not a new posture, it reverts a compose-level default the
#309 flag-day introduced.

## Approach A — opt-in Discord

Three coordinated changes. Discord becomes explicit opt-in (the operator sets *both*
the token and the hosted-adapters var); the stock path boots with no comms adapter;
an explicit-but-misconfigured opt-in fails *legibly* instead of as a raw-traceback
crash-loop. **The fail-closed security posture is unchanged** — an explicitly
enabled adapter that cannot get a valid credential still refuses, exits non-zero, and
writes its audit row.

### 1. Compose default flip — the root lever

`docker-compose.yaml:275`:

```yaml
ALFRED_COMMS_ENABLED_ADAPTERS: '${ALFRED_GATEWAY_HOSTED_ADAPTERS:-[]}'
```

Stock `up -d` → gateway resolves `[]` → `supervise_all([])` no-op → gateway comes up
**healthy** → the core's `depends_on: service_healthy` clears → core boots.

### 2. Setup-script opt-in coherence — `bin/alfred-setup.sh`

Make the (currently mislabelled) preflight true. When `ALFRED_DISCORD_BOT_TOKEN` is
present in `.env`, idempotently ensure `.env` also carries
`ALFRED_GATEWAY_HOSTED_ADAPTERS=["alfred_discord"]`; when absent, leave the empty
default and keep the now-accurate advisory. This turns "token present" into a single
coherent opt-in and closes the new, milder "token set but Discord silently not
hosted" gap for the setup-driven path. (An operator who edits `.env` and runs
`up -d` *without* re-running setup must still set the var themselves — the
`.env.example` documents this; the script is a convenience, not the sole mechanism.)

### 3. Friendly-refusal handler — `start_gateway`

Add an `except GatewayAdapterSpawnError` arm *before* the generic arms (it is an
`AlfredError`, currently uncaught → raw traceback). Render an actionable `t()`
message + a new distinct exit code `_EXIT_ADAPTER_SPAWN_FAILED = 10`. The message
covers a **missing *or* invalid/unauthenticated** credential and names both remedies:
set `ALFRED_DISCORD_BOT_TOKEN` in `.env`, or remove the adapter from
`ALFRED_GATEWAY_HOSTED_ADAPTERS`.

This converts the *explicit* opt-in-but-misconfigured case from an opaque
raw-traceback crash-loop into a **legible** one — a clear message + a distinct exit
an operator / healthcheck can read, which is the epic's "a loud refusal an operator
can act on." It does **not** stop the abort (the process still exits non-zero and,
under `restart: unless-stopped`, still loops) — making the gateway *survive* a
first-attempt failure is #331's park-not-abort. The supervisor's `_audit_spawn_aborted`
row is still written *before* the raise (hard rules #5/#7 intact); this arm only
replaces the traceback with a message.

## Data flow (three paths)

- **Stock** (no token, no var): `[]` → no-op → healthy → core boots. *(the fix)*
- **Opt-in** (token + var): `["discord"]` → spawn succeeds → Discord live.
- **Opt-in misconfigured** (var set, token missing or invalid): first-attempt
  refusal → audited → `GatewayAdapterSpawnError` → friendly handler → legible
  message + exit 10 (still a restart-loop, but legible).

## Error handling / security

- No change to the fail-closed posture: explicit opt-in with a bad credential still
  refuses + audits + exits non-zero.
- The new handler is scoped to the typed `GatewayAdapterSpawnError` only —
  programming bugs (`TypeError`, `ValueError`, …) still surface loud (hard rule #7),
  same discipline as the existing typed arms.
- The audit row (`_audit_spawn_aborted`) precedes the raise and is unaffected.

## Testing

- **Compose invariant:** invert `test_alfred_gateway_hosts_discord`
  (`tests/unit/test_compose_invariants.py:363-367`) → assert the compose default
  hosts **no** adapter (`:-[]`, no `alfred_discord`) yet wires the
  `ALFRED_GATEWAY_HOSTED_ADAPTERS` override so opt-in is still possible.
- **Gateway CLI handler** (`tests/unit/cli/test_gateway_cli.py`): a
  `GatewayAdapterSpawnError` raised from the run path → the friendly message is
  rendered and the exit code is 10, **not** a traceback. Mutation-guard the
  non-vacuity (a stubbed message substitution must fail the assertion).
- **Setup-script** (`tests/unit/test_setup_script_env_seed.py` style, reusing
  `tests/_setup_script_helpers.py`): token present → `.env` gains the hosted-adapters
  line (idempotent on re-run); token absent → the line stays empty/absent.
- **Docstring update:** `tests/integration/test_gateway_unset_discord_token_fails_loud.py`
  — the resolver behaviour is unchanged, but note that the stock compose default no
  longer *triggers* it (Discord is now opt-in).
- **i18n:** new catalog keys in `locale/en/LC_MESSAGES/alfred.po`; `pybabel` no-drift
  gate stays green.
- **`.env.example`:** invert the WARNING block (lines 52-57) — the default is now
  empty; to *enable* Discord set **both** the token and
  `ALFRED_GATEWAY_HOSTED_ADAPTERS=["alfred_discord"]`.

## ADR-0054 (next free number)

"Gateway-hosted comms adapters default to empty (opt-in), not Discord-on." Records
the reversal of the #309 flag-day's *compose default* (the capability is unchanged —
only the zero-config default), the first-run-must-boot rationale, and that
fail-closed is preserved for explicitly-enabled adapters. (Memory notes the DIP
consolidation work also eyed 0054 but never reserved it on disk; if it needs a number
later it takes the next free one.)

## Explicitly OUT of scope

- **#331 park-not-abort** — keeping the gateway/relay alive when a hosted adapter's
  first-attempt credential fails. That is a change to the fail-closed trust boundary
  and needs its own security + adversarial sign-off. This PR keeps the posture and
  only makes the failure *legible*.
- **The CI first-run smoke lane** (clone → `cp .env.example .env` → setup → `up -d` →
  healthy) — the epic's *systemic* fix that would catch this whole class. A larger,
  separate piece; recommended as the next #469 item after the remaining blockers,
  not folded here.
- The other #469 blockers (the 4 UAT blockers).
- `CLAUDE.md` / `PRD.md` edits (human-gated; and this PR ships no new CLI surface, so
  the command table needs no change).

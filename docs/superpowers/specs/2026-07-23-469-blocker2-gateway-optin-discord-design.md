# #469 Blocker 2 — opt-in Discord (the stock quickstart boots, no gateway crash-loop)

**Status:** design **v2** — revised after a 10-lane `/review-plan` fleet (architect,
reviewer, test-engineer, security-engineer, comms, devops, devex, i18n, error, docs;
inline synthesis, no coordinator, no disputes). Fleet verdict: **0 Critical / 7 High
/ 23 Medium / 18 Low**; the core mechanism was verified sound by every lane. **All 48
findings are folded in below** — fixed in-scope, or dispositioned with a named
follow-up. Design-changing findings are marked **[R1]/[R2]/[R3]**. Parent epic: #469
(first-run experience). This spec covers **Blocker 2 only**. The structural relative —
keeping the gateway alive when a hosted adapter's credential fails — is **#331**, out
of scope.

## Problem

On the documented quickstart — `git clone … && cp .env.example .env && docker
compose up -d` — `alfred-gateway` **crash-loops** under `restart: unless-stopped`,
and because `alfred-core` has `depends_on: alfred-gateway: condition:
service_healthy` (`docker-compose.yaml:100-101`), the core **never starts either**.
The operator sees containers that are "up"/restarting rather than an error they can
act on: a silent forever-loop, not a loud refusal.

## Root cause (traced, HEAD `786df4e1`)

```yaml
# docker-compose.yaml:275 — Discord-hosting on by default
ALFRED_COMMS_ENABLED_ADAPTERS: '${ALFRED_GATEWAY_HOSTED_ADAPTERS:-["alfred_discord"]}'
```

On a stock first run the operator has no `ALFRED_DISCORD_BOT_TOKEN`:

1. `_resolve_hosted_adapter_ids()` (`cli/gateway/_commands.py:136`) succeeds
   (resolving the *id* needs no token) → the gateway supervises `["discord"]`.
2. First spawn → the core credential resolver returns `missing_secret` →
   `AdapterCredentialError` (`comms_mcp/adapter_credential_resolver.py:212`), audited
   `result="refused"` (pinned by `tests/integration/test_gateway_unset_discord_token_fails_loud.py`).
3. The supervisor wraps it as `GatewayAdapterSpawnError` and, `first_attempt` being
   true, **re-raises fail-closed** (`gateway/adapter_supervisor.py:513-521`).
4. It propagates through `GatewayProcess.run()` → the `start_gateway._main`
   `TaskGroup` (`:383-387`) → `_reraise_first_meaningful` (flattens nested groups →
   a **flat** `GatewayAdapterSpawnError`) → out of `start_gateway`. **None** of the
   typed `except` arms (`:391-439`) catch it and there is no global CLI error
   boundary (`alfred.cli.main:app`) → **raw traceback**, exit 1.
5. `restart: unless-stopped` → **infinite crash-loop**; the core's dependency gate
   never clears.

### Blast radius = the whole gateway; both bad-token modes hit it

`start_gateway._main` co-runs the TUI **relay** (the `alfred chat` front door), the
**egress planes**, and the adapter **supervisor** under one `asyncio.TaskGroup`; a
first-attempt spawn failure cancels the siblings → the whole process exits (comms lane
confirmed the invalid-token case surfaces `ok=false` inside the `lifecycle.start`
handshake, not as a post-ready breaker crash):

| Token state | Where it surfaces | Gateway | Core |
| --- | --- | --- | --- |
| **Unset** (stock quickstart) | `missing_secret` at first spawn | **Dies** → crash-loop | Never starts (`depends_on`) |
| **Present but invalid** | `LoginFailure` → `ok=false` at handshake (`plugins/alfred_discord/gateway_adapter.py:69-90`, fix C1: `login()` awaited synchronously before ready) → first-attempt `GatewayAdapterSpawnError` | **Dies** — same abort | Never starts (same gate) |
| **Valid at boot, fails later** | post-ready crash → `_handle_crash` → breaker | **Survives** — adapter parks; relay/egress stay up | Unaffected |

The core never crashes from the token directly (it is `alfred_tui`-only,
`test_alfred_core_comms_adapters_stay_tui_only`); its only problem is the gate.

### [R3] The two bad-token modes do NOT share an audit path (fleet correction ×4)

v1's "`_audit_spawn_aborted` is written before the raise on both paths" is **false**
(reviewer + error + security + comms concur). Only the **missing_secret** path calls
`_audit_spawn_aborted` (`adapter_supervisor.py:499`); the **invalid-token
`LoginFailure`** path takes the `else` branch (`:504`) with its durable trail being
the `EMIT_CRASHED` lifecycle frame. The friendly-handler rationale is narrowed
accordingly, and a test must pin that a **loud audit emission exists before the
friendly message + exit 10 on BOTH the unset and the present-but-invalid paths**; if a
pin shows no durable trail on either, that is a real gap to surface, not paper over.

### Why the existing "preflight" does not prevent this

`bin/alfred-setup.sh:489-503` (the #309 preflight) is **advisory-only** — it prints
`warn "… NOT enabling Discord …"` but never writes `ALFRED_GATEWAY_HOSTED_ADAPTERS=[]`,
so the compose default still wins — and it sits *inside* the interactive snowflake
branch, so the stock path (skip the snowflake, `up -d`) bypasses it entirely.

## Key enabling fact

The **code** default is already empty: `Settings.comms_enabled_adapters: tuple[str,
...] = Field(default=())` (`config/settings.py:255`). Discord-on-by-default lives
*only* in the compose fallback. So this change **aligns the deployed default with the
code default** — it reverts a compose-level default the #309 flag-day introduced, and
**restores PRD §4 Success-Criterion-1** (clone → setup → `up` brings up a working
stack), which the crash-loop violates. PRD §6.1 lists Discord as an MVP *capability*,
not a default-on mandate (arch-005).

## Approach A — opt-in Discord

Discord becomes explicit opt-in (set *both* the token and the hosted-adapters var);
the stock path boots with no comms adapter; an explicit opt-in that is misconfigured
in the **credential-refusal** way fails *legibly*. **The fail-closed posture is
unchanged.**

### 1. Compose default flip — the root lever

`docker-compose.yaml:275` → `'${ALFRED_GATEWAY_HOSTED_ADAPTERS:-[]}'`. Stock `up -d`
→ gateway resolves `[]` → `supervise_all([])` no-op → gateway **healthy** (verified:
`alfred gateway healthcheck` probes metrics+breaker, not adapter readiness) → the
core's gate clears → core boots. Also fix the stale comment above the line
(`:271-274`, "the gateway HOSTS the Discord adapter" — docs-003).

### 2. Setup-script opt-in coherence — `bin/alfred-setup.sh` (+ `.ps1`)

When `ALFRED_DISCORD_BOT_TOKEN` is present in `.env`, idempotently ensure `.env` also
carries `ALFRED_GATEWAY_HOSTED_ADAPTERS=["alfred_discord"]`; when absent, keep the
empty default and the (now-accurate) advisory. Fleet-required specifics:

- **Placement (devex-002/devops-001/rev-001):** a **top-level step keyed on the
  `.env` token**, NOT inside the interactive `$snowflake` branch (`:483`) — else the
  non-interactive / blank-snowflake cases still drop Discord.
- **Read source (test-005/devops-004):** `read_env_var` (the `.env` value), never the
  shell-env `${ALFRED_DISCORD_BOT_TOKEN:-}` check at `:498`.
- **Token validity (sec-004):** treat a commented / empty / placeholder token as
  *absent* (else the write re-creates the crash-loop).
- **Idempotent write (devops-002):** append-if-absent via `grep -qE
  '^ALFRED_GATEWAY_HOSTED_ADAPTERS='` (never `sed`-replace) so it preserves a
  deliberate `=[]`, coexists with a commented line, and is `set -e`-safe. Reuse the
  `umask 077` grep-else-append pattern at `alfred-setup.sh:130-134`. Never echo the
  token (devops-004).
- **Announce (devex-006)** the resulting `.env` state — no silent mutation.
- **Advisory (devex-004):** update the token-unset advisory at `:502` so its remedy
  is accurate under the new opt-in posture.
- **`.ps1` (arch-003 / #422):** confirm `bin/alfred-setup.ps1` delegates `.env`
  seeding to `alfred-setup.sh`-in-WSL, then update/remove its stale advisory twin
  (`:45`) to match; if `.ps1` seeds standalone, add the parallel write. Record the
  resolution so the two entry points cannot drift.

### 3. [R1] Friendly refusal — narrowed to a credential-origin marker

v1 proposed catching `GatewayAdapterSpawnError`. **The fleet proved that unsafe**
(error + security, corroborated): that type is a catch-**all** wrapper —
`adapter_child_factory.py:490` (`except BaseException`), `gateway_adapter.py:90`
(`except Exception`), the `_unwired_runner_factory` wiring-bug raise (`process.py:229`),
and the `LaunchTargetOverrideRefusedError` **security override-injection refusal** all
produce it. Catching the base type would downgrade a genuine code bug **or a security
refusal** into a friendly "set your Discord token" message — the exact hard-rule-#7
anti-pattern.

**Revised design:** introduce a narrow **credential-origin marker subclass**
`GatewayAdapterCredentialError(GatewayAdapterSpawnError)`, raised **only** on the
supervisor's credential-refusal arm (the `AdapterCredentialError`-wrapped
`missing_secret` / `grant_mismatch` / `delivery_failed` cases, `adapter_supervisor.py:500-503`).
`start_gateway` catches **only that subclass** and:

- renders `t("gateway.start.adapter_spawn_failed", adapter_id=…)` — a static template
  whose only interpolation is the non-tainted, closed-vocab `adapter_id` (err-004 /
  sec-003: no `str(exc)` / token / DSN), naming both remedies (set
  `ALFRED_DISCORD_BOT_TOKEN`, or remove the adapter from
  `ALFRED_GATEWAY_HOSTED_ADAPTERS`) **and** the blast radius (until fixed the gateway
  stays unhealthy, so `alfred-core` and `alfred chat` do not come up — arch-002) and
  points at `docker compose logs alfred-gateway` for specifics;
- follows the sibling-arm contract (err-002): `log.warning("gateway.cli.adapter_spawn_failed",
  error=repr(exc), exc_info=True)` (preserving `__cause__`) then `raise
  typer.Exit(code=_EXIT_ADAPTER_SPAWN_FAILED) from exc`, with `_EXIT_ADAPTER_SPAWN_FAILED
  = 10` (next free after 3-9; documented in the exit-code comment block alongside
  siblings — devex-005).

The bare wrapper, the wiring-bug raise, and `LaunchTargetOverrideRefusedError`
**continue to surface loud** — proven by an out-of-scope masking-regression test.
Import the new symbol into `start_gateway`'s lazy block (`:238-267` — comms-004/rev-003).

**Invalid-token (`LoginFailure`) legibility is a documented residual + follow-up.**
That case is a bare-`GatewayAdapterSpawnError` handshake `ok=false`, not cleanly
distinguishable from a handshake bug without a structured auth-failure reason from the
child, so it is **not** softened here (surfaces loud, same discipline as a bug). This
is acceptable because change #1 removes the *stock* crash-loop and a wrong-token
opt-in is an explicit, rarer misconfig. **Follow-up to FILE:** "Discord adapter
surfaces a typed auth-failure so a wrong-token opt-in is legible" (would let the
marker cover it too).

### 4. [R2] Doc/scope surfaces the flip changes (else the silent failure just relocates)

- **`README.md:140-191`** "Enable Discord" walkthrough (arch-001/devex-001/docs-001):
  instruct setting **both** the token and `ALFRED_GATEWAY_HOSTED_ADAPTERS=["alfred_discord"]`
  (or re-run `bin/alfred-setup.sh`, which #2 seeds); otherwise `--wait-ready discord`
  times out on a gateway hosting nothing.
- **`.env.example:52-57`** WARNING block: invert — default empty; enabling Discord
  needs **both**.
- **`docs/runbooks/2026-06-25-discord-flag-day-migration.md:119-165,184`** (docs-002):
  correct the "unset token aborts the gateway" claim to the opt-in posture.
- **`docker-compose.yaml:271-274`** comment (docs-003; see #1).

### 5. Widen the config-failed arm for the opt-in typo (comms-001)

A documented opt-in written as canonical `["discord"]` instead of the package id
`["alfred_discord"]` makes `Settings()` raise `SettingsError` (a `ValueError`) that
the config-failed arm's `except (OSError, ManifestError)` (`:279`) does **not** catch
→ a raw-traceback crash-loop on the very path this makes legible. Widen that arm to
render the config-failed refusal for the settings-construction `SettingsError`/
`ValueError` (scoped to that call so unrelated `ValueError`s still surface loud).

## Data flow (four paths)

- **Stock** (no token, no var): `[]` → no-op → healthy → core boots. *(the fix)*
- **Opt-in** (token + `["alfred_discord"]`): spawn succeeds → Discord live.
- **Opt-in, missing token**: credential-refusal → `GatewayAdapterCredentialError` →
  friendly handler → legible message + exit 10.
- **Opt-in, invalid token**: `LoginFailure` surfaces loud (documented residual);
  a `["discord"]` typo is caught by the widened config arm (#5).

## Testing

- **Compose invariant (test-007):** rename+invert `test_alfred_gateway_hosts_discord`
  (`test_compose_invariants.py:363`) → assert the default hosts **no** adapter **and**
  the `ALFRED_GATEWAY_HOSTED_ADAPTERS` override key is **present** (a bare `not in`
  passes vacuously on a deleted entry).
- **Interpolation (devops-003):** a `docker compose config` assertion that `${…:-[]}`
  renders `[]` and an override renders `["alfred_discord"]` — the interim for the
  deferred CI smoke lane.
- **Handler (test-001/002, arch-004):** drive the **real** TaskGroup unwrap (a
  supervisor first-attempt credential failure propagating through `_main`, not a
  direct raise into the arm) → assert the friendly message + exit 10; mutation-guard
  the non-vacuity (assert exit==10 **and** the rendered line **and** sibling
  `gateway.start.*` lines absent). **Out-of-scope leg:** a bare
  `GatewayAdapterSpawnError` / a `LaunchTargetOverrideRefusedError` still surfaces loud.
- **Log/audit (err-002/err-003/rev-002/sec-002):** via `structlog.testing.capture_logs`
  (a `caplog` check is vacuous for structlog) assert the `gateway.cli.adapter_spawn_failed`
  row carries the adapter/reason before exit 10; pin a loud audit emission before the
  render on BOTH the unset and present-but-invalid paths.
- **Positive boot (comms-003):** an empty hosted set resolves to `[]` and the gateway
  reaches healthy.
- **Setup-script (test-003/004):** token present → `.env` gains the line (idempotent
  on re-run); present-but-empty / explicit-`[]` opt-out preserved; token absent → line
  stays empty/absent.
- **Config-arm (#5):** a `["discord"]` typo → the config-failed refusal + its exit
  code, not a traceback.
- **Integration (test-008):** `test_gateway_unset_discord_token_fails_loud.py` —
  resolver behaviour unchanged; docstring notes the stock default no longer triggers
  it (verified the new key does not trip the `SLICE_4_KEYS` orphan check).
- **i18n (i18n-001/002/003):** add the single concrete key
  `gateway.start.adapter_spawn_failed` (static template; brace-only for the closed-vocab
  `adapter_id`; no `t(message_key=var)` indirection) to `locale/en/LC_MESSAGES/alfred.po`;
  **re-run `pybabel extract`+`update`** so the mid-function insert does not stale
  downstream `#:` refs. Note (test-006): `cli/gateway/_commands.py` is under no
  per-module 100% gate (only the 75% floor), so the handler test is the sole
  non-vacuity control — keep it strong.

## ADR-0054 (confirmed next free number; supersedes none — arch-005)

"Gateway-hosted comms adapters default to empty (opt-in), not Discord-on." Records:
the reversal of the #309 flag-day's *compose default* (capability unchanged); cites
`docs/runbooks/2026-06-25-discord-flag-day-migration.md` as the origin of the
on-by-default value and states no prior ADR is superseded (0036/0043 cover mechanism);
that it **restores PRD §4 SC-1** while leaving PRD §5 invariants (gateway sole egress
plane, connectivity-free core, dual-LLM split) untouched; that fail-closed is preserved
for explicitly-enabled adapters; and (arch-002) that **opt-in-misconfigured =
whole-stack-down** is an accepted limitation until #331 lands park-not-abort.
Cross-links #309 / ADR-0036 / the flag-day runbook (which gains a forward-pointer,
docs-004).

## Commit discipline (rev-005)

The multi-file change (compose + setup `.sh`/`.ps1` + CLI + tests + ADR + i18n + docs)
splits into focused Conventional-Commits, each subject carrying `#469` after the colon.

## Explicitly OUT of scope (with named follow-ups)

- **#331 park-not-abort** — keep the gateway/relay alive on a first-attempt credential
  failure. A fail-closed-trust-boundary change; its own security + adversarial sign-off.
- **Invalid-token legibility** — a typed auth-failure from the Discord child so a
  wrong-token opt-in is legible too. **Follow-up to be FILED** (this PR documents it as
  a residual; the default flip already fixes the stock path).
- **CI first-run smoke lane** (clone → setup → `up -d` → healthy) — the epic's
  *systemic* fix; the `docker compose config` assertion above is the cheap interim.
- The other #469 blockers; `CLAUDE.md`/`PRD.md` edits (human-gated; no new CLI surface).

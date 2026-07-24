# #469 Blocker 2 — opt-in Discord (the stock quickstart boots, no gateway crash-loop)

**Status:** design **v4** — scoped to **changes #1–5** (the boot fix). History: a 10-lane
`/review-plan` fleet on v1 (0 Crit / 7 High / 23 Med / 18 Low, all 48 folded into v2);
v3 folded in invalid-token legibility per a maintainer decision; a **focused 4-lane
re-review** (comms / security / architect / test) then found that change **Critical-as-
written** (comms-c6-001: the factory never sees `LifecycleStartResult`; a fourth,
daemon-shared, 100%-gated `comms_runner` layer is required) and trust-boundary-weighted
(marker-stripping audit gate; plugin-attested provenance; own ADR). **v4 splits it out**
to **#493** (spec `2026-07-24-469-blocker2b-invalid-token-legibility-design.md`) — the
project's "security-weighted → its own PR" rule. This PR ships the boot fix and makes a
*missing* token legible; a *wrong* token stays loud (safe residual) until #493.
Design-changing findings are marked **[R1]/[R2]/[R3]**. Parent epic: #469. The structural
relative (surviving the abort) is **#331**, out of scope.

## Problem

On the documented quickstart — `git clone … && cp .env.example .env && docker
compose up -d` — `alfred-gateway` **crash-loops** under `restart: unless-stopped`,
and because `alfred-core` has `depends_on: alfred-gateway: condition:
service_healthy` (`docker-compose.yaml:100-101`), the core **never starts either**.
The operator sees containers "up"/restarting rather than an actionable error.

## Root cause (traced, HEAD `786df4e1`)

```yaml
# docker-compose.yaml:275 — Discord-hosting on by default
ALFRED_COMMS_ENABLED_ADAPTERS: '${ALFRED_GATEWAY_HOSTED_ADAPTERS:-["alfred_discord"]}'
```

Stock first run, no `ALFRED_DISCORD_BOT_TOKEN`:

1. `_resolve_hosted_adapter_ids()` (`cli/gateway/_commands.py:136`) succeeds (the *id*
   needs no token) → the gateway supervises `["discord"]`.
2. First spawn → credential resolver returns `missing_secret` → `AdapterCredentialError`
   (`comms_mcp/adapter_credential_resolver.py:212`), audited `result="refused"` (pinned by
   `tests/integration/test_gateway_unset_discord_token_fails_loud.py`).
3. The supervisor wraps it as `GatewayAdapterSpawnError` and, `first_attempt` being true,
   **re-raises fail-closed** (`gateway/adapter_supervisor.py:513-521`).
4. It propagates through `GatewayProcess.run()` → the `start_gateway._main` `TaskGroup`
   (`:383-387`) → `_reraise_first_meaningful` (→ a **flat** `GatewayAdapterSpawnError`) →
   out of `start_gateway`. **None** of the typed `except` arms (`:391-439`) catch it and
   there is no global CLI error boundary → **raw traceback**, exit 1.
5. `restart: unless-stopped` → **infinite crash-loop**; the core's gate never clears.

### Blast radius = the whole gateway; both bad-token modes hit it

`start_gateway._main` co-runs the TUI **relay**, the **egress planes**, and the adapter
**supervisor** under one `TaskGroup`; a first-attempt spawn failure cancels the siblings →
the whole process exits:

| Token state | Where it surfaces | Gateway | Core |
| --- | --- | --- | --- |
| **Unset** (stock quickstart) | `missing_secret` at first spawn | **Dies** → crash-loop | Never starts (`depends_on`) |
| **Present but invalid** | `LoginFailure` → `ok=false` at handshake (`plugins/alfred_discord/gateway_adapter.py:69-90`) → first-attempt `GatewayAdapterSpawnError` | **Dies** — same abort | Never starts (same gate) |
| **Valid at boot, fails later** | post-ready crash → `_handle_crash` → breaker | **Survives** — adapter parks | Unaffected |

The core is `alfred_tui`-only (`test_alfred_core_comms_adapters_stay_tui_only`); its only
problem is the gate. This PR fixes the **unset** case (the stock quickstart) and makes an
explicit missing-token opt-in **legible**; the **invalid** case stays loud (a raw
traceback, unchanged) until #493 makes it legible too.

### [R3] The two bad-token modes do NOT share an audit path (fleet correction ×4)

Only the **missing_secret** path calls `_audit_spawn_aborted` (`adapter_supervisor.py:499`);
the **invalid-token `LoginFailure`** path's durable trail is the `EMIT_CRASHED` lifecycle
frame. The friendly-handler rationale (below) is narrowed to the missing-token path
accordingly, and a test pins the audit emission before the friendly render on that path.
(The invalid-token audit story is #493's concern.)

### Why the existing "preflight" does not prevent this

`bin/alfred-setup.sh:489-503` (the #309 preflight) is **advisory-only** — it prints a
`warn` but never writes `ALFRED_GATEWAY_HOSTED_ADAPTERS=[]`, so the compose default still
wins — and it sits *inside* the interactive snowflake branch, so the stock path bypasses
it entirely.

## Key enabling fact

The **code** default is already empty: `Settings.comms_enabled_adapters: tuple[str, ...]
= Field(default=())` (`config/settings.py:255`). Discord-on-by-default lives *only* in the
compose fallback. So this change **aligns the deployed default with the code default** and
**restores PRD §4 Success-Criterion-1** (clone → setup → `up` brings up a working stack).
PRD §6.1 lists Discord as an MVP *capability*, not a default-on mandate (arch-005).

## Approach A — opt-in Discord (changes #1–5)

Discord becomes explicit opt-in; the stock path boots with no comms adapter; an explicit
opt-in that is *missing* its token fails *legibly*. **The fail-closed posture is unchanged.**

### 1. Compose default flip — the root lever

`docker-compose.yaml:275` → `'${ALFRED_GATEWAY_HOSTED_ADAPTERS:-[]}'`. Stock `up -d` →
`supervise_all([])` no-op → gateway **healthy** (verified: `alfred gateway healthcheck`
probes metrics+breaker, not adapter readiness) → the core's gate clears → core boots. Fix
the stale comment above the line (`:271-274`, "the gateway HOSTS the Discord adapter" —
docs-003).

### 2. Setup-script opt-in coherence — `bin/alfred-setup.sh` (+ `.ps1`)

When `ALFRED_DISCORD_BOT_TOKEN` is present in `.env`, idempotently ensure `.env` also
carries `ALFRED_GATEWAY_HOSTED_ADAPTERS=["alfred_discord"]`; when absent, keep the empty
default and the (now-accurate) advisory. Specifics:

- **Placement (devex-002/devops-001/rev-001):** a **top-level step keyed on the `.env`
  token**, NOT inside the interactive `$snowflake` branch (`:483`).
- **Read source (test-005/devops-004):** `read_env_var` (the `.env` value), never the
  shell-env `${…:-}` check at `:498`.
- **Token validity (sec-004):** treat a commented / empty / placeholder token as *absent*.
- **Idempotent write (devops-002):** append-if-absent via `grep -qE
  '^ALFRED_GATEWAY_HOSTED_ADAPTERS='` (never `sed`-replace); reuse the `umask 077`
  grep-else-append pattern at `:130-134`; never echo the token (devops-004).
- **Announce (devex-006)** the resulting `.env` state.
- **Advisory (devex-004):** update the token-unset advisory at `:502` for the new posture.
- **`.ps1` (arch-003 / #422):** confirm `bin/alfred-setup.ps1` delegates seeding to
  `alfred-setup.sh`-in-WSL and update/remove its stale advisory (`:45`); if it seeds
  standalone, add the parallel write. Record the resolution.

### 3. [R1] Friendly refusal — narrowed to a credential-origin marker (missing-token)

v1 proposed catching `GatewayAdapterSpawnError`. **The fleet proved that unsafe:** that
type is a catch-**all** wrapper — `adapter_child_factory.py:490` (`except BaseException`),
`gateway_adapter.py:90` (`except Exception`), the `_unwired_runner_factory` wiring-bug
raise (`process.py:229`), and the `LaunchTargetOverrideRefusedError` **security override-
injection refusal** all produce it. Catching the base type would downgrade a code bug **or
a security refusal** into a friendly "set your token" message — the hard-rule-#7 anti-pattern.

**Revised design:** a narrow **credential-origin marker subclass**
`GatewayAdapterCredentialError(GatewayAdapterSpawnError)`, raised **only** on the
supervisor's credential-refusal arm (`adapter_supervisor.py:500-503`, where the
`AdapterCredentialError`-wrapped `missing_secret`/`grant_mismatch`/`delivery_failed` cases
are already audited via `_audit_spawn_aborted`) — i.e. change the wrapped
`GatewayAdapterSpawnError` there into the marker. **No factory/runner change** (that
is issue #493). `start_gateway` catches **only that subclass** and:

- renders `t("gateway.start.adapter_spawn_failed", adapter_id=…)` — a static template whose
  only interpolation is the non-tainted closed-vocab `adapter_id` (err-004/sec-003: no
  `str(exc)`/token/DSN), naming both remedies (set `ALFRED_DISCORD_BOT_TOKEN`, or remove
  the adapter from `ALFRED_GATEWAY_HOSTED_ADAPTERS`), the blast radius (until fixed the
  gateway stays unhealthy so `alfred-core`/`alfred chat` do not come up — arch-002), and
  pointing at `docker compose logs alfred-gateway`;
- follows the sibling-arm contract (err-002): `log.warning("gateway.cli.adapter_spawn_failed",
  error=repr(exc), exc_info=True)` then `raise typer.Exit(code=_EXIT_ADAPTER_SPAWN_FAILED)
  from exc`, `_EXIT_ADAPTER_SPAWN_FAILED = 10` (next free; documented in the exit-code
  comment block — devex-005).

The bare wrapper, the wiring-bug raise, `LaunchTargetOverrideRefusedError`, and the
invalid-token (`LoginFailure`) bare `GatewayAdapterSpawnError` all **continue to surface
loud** — proven by an out-of-scope masking-regression test. Import the marker into
`start_gateway`'s lazy block (`:238-267` — comms-004/rev-003).

> **Invalid-token residual → #493.** A *wrong* token is not cleanly distinguishable from a
> handshake bug at the gateway without threading a typed auth reason through the shared
> `comms_runner` (a Critical-as-written, daemon-shared, trust-boundary change), so it stays
> loud here. #493 makes it legible via the same marker + exit 10.

### 4. [R2] Doc/scope surfaces the flip changes

- **`README.md:140-191`** "Enable Discord" walkthrough (arch-001/devex-001/docs-001):
  instruct setting **both** the token and `ALFRED_GATEWAY_HOSTED_ADAPTERS=["alfred_discord"]`
  (or re-run `bin/alfred-setup.sh`), else `--wait-ready discord` times out on a gateway
  hosting nothing.
- **`.env.example:52-57`** WARNING block: invert — default empty; enabling Discord needs
  **both**.
- **`docs/runbooks/2026-06-25-discord-flag-day-migration.md:119-165,184`** (docs-002):
  correct the "unset token aborts the gateway" claim to the opt-in posture.
- **`docker-compose.yaml:271-274`** comment (docs-003; see #1).

### 5. Widen the config-failed arm for the opt-in typo (comms-001)

An opt-in written as canonical `["discord"]` instead of the package id `["alfred_discord"]`
makes `Settings()` raise `SettingsError` (a `ValueError`) that the config-failed arm's
`except (OSError, ManifestError)` (`:279`) does **not** catch → a raw-traceback crash-loop.
Widen that arm to render the config-failed refusal for the settings-construction
`SettingsError`/`ValueError` (scoped to that call so unrelated `ValueError`s still surface
loud).

## Data flow (four paths)

> **UAT-confirmed limitation (PR #495):** the "Stock → healthy → core boots" path
> below describes Blocker 2's *adapter-resolution* fix in isolation. End-to-end it is
> currently **masked** — the gateway constructs a full `Settings()` (needing
> `ALFRED_DEEPSEEK_API_KEY`, which it lacks per ADR-0036) *before* adapter resolution, so
> the stock stack still does not boot until the other known #469 UAT blockers land. This
> PR removes the Discord-default crash-loop; it is necessary, not sufficient, for the boot.

- **Stock** (no token, no var): `[]` → no-op → healthy → core boots. *(Blocker 2's step; masked end-to-end — see note above)*
- **Opt-in** (token + `["alfred_discord"]`): spawn succeeds → Discord live.
- **Opt-in, missing token**: credential-refusal → `GatewayAdapterCredentialError` →
  friendly handler → legible message + exit 10.
- **Opt-in, invalid token / typo'd id**: `LoginFailure` surfaces loud (residual → #493); a
  `["discord"]` typo is caught by the widened config arm (#5). A genuine handshake *bug*
  still surfaces loud.

## Testing

- **Compose invariant (test-007):** rename+invert `test_alfred_gateway_hosts_discord`
  (`test_compose_invariants.py:363`) → assert the default hosts **no** adapter **and** the
  `ALFRED_GATEWAY_HOSTED_ADAPTERS` override key is **present** (a bare `not in` is vacuous).
- **Interpolation (devops-003):** a `docker compose config` assertion that `${…:-[]}`
  renders `[]` and an override renders `["alfred_discord"]` — interim for the deferred CI
  smoke lane.
- **Handler (test-001/002, arch-004):** drive the **real** TaskGroup unwrap (a supervisor
  first-attempt credential failure propagating through `_main`, not a direct raise) →
  friendly message + exit 10; mutation-guard the non-vacuity (assert exit==10 **and** the
  rendered line **and** sibling `gateway.start.*` lines absent). **Out-of-scope leg:** a
  bare `GatewayAdapterSpawnError` / a `LaunchTargetOverrideRefusedError` still surfaces loud.
- **Log/audit (err-002/err-003/rev-002/sec-002):** via `structlog.testing.capture_logs`
  assert the `gateway.cli.adapter_spawn_failed` row carries the adapter/reason before exit
  10; pin the audit emission before the render on the missing-token path.
- **Positive boot (comms-003):** an empty hosted set resolves to `[]` and the gateway
  reaches healthy.
- **Setup-script (test-003/004):** token present → `.env` gains the line (idempotent);
  present-but-empty / explicit-`[]` opt-out preserved; token absent → line stays empty.
- **Config-arm (#5):** a `["discord"]` typo → the config-failed refusal + its exit code.
- **Integration (test-008):** `test_gateway_unset_discord_token_fails_loud.py` — resolver
  unchanged; docstring notes the stock default no longer triggers it (the new key does not
  trip the `SLICE_4_KEYS` orphan check).
- **i18n (i18n-001/002/003):** add the single key `gateway.start.adapter_spawn_failed`
  (static template; no `t(message_key=var)` indirection) to `locale/en/LC_MESSAGES/alfred.po`;
  **re-run `pybabel extract`+`update`** so the mid-function insert does not stale downstream
  `#:` refs. Note (test-006): `cli/gateway/_commands.py` is under no per-module 100% gate
  (75% floor), so the handler test is the sole non-vacuity control — keep it strong.

## ADR-0054 (confirmed next free; supersedes none — arch-005)

"Gateway-hosted comms adapters default to empty (opt-in), not Discord-on." Records: the
reversal of the #309 flag-day's *compose default* (capability unchanged); cites
`docs/runbooks/2026-06-25-discord-flag-day-migration.md` as the origin of the on-by-default
value; that it **restores PRD §4 SC-1** while leaving PRD §5 invariants untouched; that
fail-closed is preserved for explicitly-enabled adapters; and (arch-002) that
**opt-in-misconfigured = whole-stack-down** is an accepted limitation until #331.
Cross-links #309 / ADR-0036 / the flag-day runbook (which gains a forward-pointer, docs-004).

## Commit discipline (rev-005)

Focused Conventional-Commits (compose + setup `.sh`/`.ps1` + CLI + tests + ADR + i18n +
docs), each subject carrying `#469` after the colon.

## Explicitly OUT of scope (with named follow-ups)

- **#493 invalid-token legibility** — a typed auth-failure threaded through the shared
  `comms_runner` so a *wrong* token is legible too. Split out (Critical-as-written,
  trust-boundary, own ADR); spec `2026-07-24-469-blocker2b-invalid-token-legibility-design.md`.
- **#331 park-not-abort** — surviving the abort (keeping the gateway/relay alive). A
  fail-closed-trust-boundary change; own security + adversarial sign-off.
- **CI first-run smoke lane** (clone → setup → `up -d` → healthy) — the epic's systemic
  fix; the `docker compose config` assertion above is the cheap interim.
- The other #469 blockers; `CLAUDE.md`/`PRD.md` edits (human-gated; no new CLI surface).

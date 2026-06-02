# Slice 2 → Slice 3 operator migration

This runbook covers upgrading an AlfredOS deployment from Slice 2 to
Slice 3. Slice 3 introduces MCP plugin transport, the quarantined LLM,
the real `CapabilityGate` (`RealGate`), Redis as a required service,
and `/var/lib/alfred/state.git` as the capability-grant source of truth.
Skipping any step causes predictable, operator-visible failures (not
silent degradation).

If you are reading this for the first time, also skim
[`docs/runbooks/slice-3-plugins.md`](./slice-3-plugins.md) and
[`docs/runbooks/slice-3-quarantined-llm.md`](./slice-3-quarantined-llm.md)
— this runbook orchestrates them; those two deep-dive each subsystem.

## Prerequisites

- AlfredOS Slice 2 running and healthy (`alfred status` returns `ok`).
- Docker Compose access to the host.
- Operator role (all `alfred plugin grant` and `alfred web allowlist`
  commands require operator-tier T1 authentication).

Confirm operator-tier auth before proceeding:

```shell
alfred user show $USER   # expect authorization: operator
```

If your user is not bound or does not hold operator authorization, run
`alfred user set $USER --authorization operator` (requires an existing
root operator already bound). The flag form is `--authorization`, not
`role=`; see `alfred user set --help` for the full option set, and
[docs/subsystems/identity.md](../subsystems/identity.md) for the
user-binding workflow.

## Upgrade order

**Step 1 — Pull and build updated images**

```shell
docker compose pull
docker compose build
```

This pulls the Slice-3 `alfred-core` image (which includes the
`alfred-quarantine` system user and the `git` package) and the new
`alfred-redis` service image.

**Step 2 — Seed state.git (idempotent)**

```shell
git init --bare /var/lib/alfred/state.git
# Seed an empty root commit on `main` ONLY IF main is missing.
# A bare repo has no working tree, so `git commit --allow-empty` cannot
# run — drop down to plumbing instead. The `rev-parse --verify` guard
# makes this step idempotent on rerun: re-seeding would rewrite
# `refs/heads/main` to a new empty commit and erase grant history
# (which is state-of-truth per PRD §7.1).
if ! git -C /var/lib/alfred/state.git rev-parse --verify refs/heads/main >/dev/null 2>&1; then
    SEED_COMMIT=$(
        git -C /var/lib/alfred/state.git commit-tree \
            "$(git -C /var/lib/alfred/state.git mktree </dev/null)" \
            -m "seed: empty initial commit"
    )
    git -C /var/lib/alfred/state.git update-ref refs/heads/main "$SEED_COMMIT"
    git -C /var/lib/alfred/state.git symbolic-ref HEAD refs/heads/main
fi
```

This initialises the bare repository that `RealGate` uses as its
grant backing store and creates the initial `main` branch. The
operation is idempotent: the `rev-parse --verify` guard skips the
seed when `main` already exists, so reruns do not destroy grant
history.

*Slice 3.x+: an `alfred plugin grant seed` wrapper command that
encapsulates these two steps is tracked as a follow-up.*

If you skip this step, every plugin start (quarantined-LLM,
web-fetch) emits `plugin.lifecycle.load_refused` on the audit stream
and the corresponding capability checks deny fail-closed. There is no
dedicated `alfred chat` startup hint for the unseeded state in this
release (the design-doc-tracked `cli.chat.capability_gate_unseeded`
key does not yet exist in the catalog); the symptom surfaces as plugin
operations refusing in the chat surface. Confirm the cause with
`alfred audit log --event plugin.lifecycle.load_refused --since 5m`,
seed `state.git` per the block above, then run
`alfred supervisor reset quarantined-llm --confirm` (and the matching
reset for any other refused component).

**Step 3 — Apply database migrations**

```shell
uv run alembic upgrade head
```

This applies migrations `0007` through `0010`:

- `0007` — extends the `ck_audit_log_result` CHECK constraint with
  Slice-3 `result` values (`extracted`, `load_refused`, `crashed`, …).
- `0008` — creates the `plugin_grants` table (Postgres projection of
  state.git grants).
- `0009` — creates the `capability_gate_sync` table (commit-hash cache
  for `RealGate`).
- `0010` — creates the `circuit_breakers` table (breaker state + trip
  history for the supervisor).

**Step 4 — Start the updated stack**

```shell
docker compose up -d
```

The `alfred-redis` service starts alongside `alfred-core`. Redis is
required for the content store (fetched T3 content keyed by
`ContentHandle.id`) and rate-limit counters (`alfred:rate:{domain}`,
`alfred:rate:user:{user_id}`).

Verify Redis is healthy before proceeding — if it fails to start, the
content store silently becomes unavailable and `web.fetch` crashes are
misleading:

```shell
docker compose ps alfred-redis     # expect: Up
redis-cli -h 127.0.0.1 ping       # expect: PONG
```

If `alfred-redis` is not `Up`, check for port conflicts on 6379 and
consult `docker compose logs alfred-redis`.

**Step 5 — Verify gate and supervisor state**

```shell
alfred status
alfred supervisor status
```

Slice 3 does not extend `alfred status` with gate health. The Slice-3
`alfred status` output is identical to the Slice-2 output (provider +
budget lines, no `gate:` line). Use `alfred plugin grant list` to
inspect gate state in Slice 3.

*Slice 3.x+: gate health (`gate: RealGate (state.git: ok, postgres: ok)`)
ships in a follow-up PR that extends `alfred status` with a
`gate.health()` call.*

Expected `alfred supervisor status` output after a clean start:

```
Component             State    Trips  Last trip
quarantined-llm       CLOSED   0      —
web-fetch             CLOSED   0      —
```

## CLI surface changes

Slice 3 adds the following operator-tier commands. Each is wired to the
state.git reviewer-gate where appropriate (high-blast operations) and to
typed refusals where not (read-only and config-set operations).

### `alfred plugin`

The plugin subsystem becomes operator-visible in Slice 3. See
[docs/subsystems/plugins.md](../subsystems/plugins.md) for the transport
architecture.

| Command | Tier | Reviewer-gated | Notes |
|---|---|---|---|
| `alfred plugin grant <plugin_id> <tier> <hookpoint>` | T1 (operator) | yes | queues a state.git proposal; emits `plugin.grant.requested` audit row |
| `alfred plugin grant status <proposal_id>` | T1 | no | read-only proposal status |
| `alfred plugin grant list [--pending]` | T1 | no | read-only grant projection from Postgres |
| `alfred plugin revoke <plugin_id> <hookpoint>` | T1 | yes | queues a revoke proposal; emits `plugin.grant.revoke_requested` |
| `alfred plugin show <plugin_id>` | T1 | no | manifest + active grants |
| `alfred plugin list` | T1 | no | hidden in Slice 3; surface stabilises in Slice 4 |

### `alfred web allowlist`

The web-fetch plugin reads its allowlist from `policies.yaml`; the CLI
mutates that file via the reviewer-gate. See
[docs/subsystems/security.md](../subsystems/security.md) for the
trust-tier model that drives the allowlist enforcement.

| Command | Tier | Reviewer-gated | Notes |
|---|---|---|---|
| `alfred web allowlist add <domain>` | T1 | yes | normalises domain, validates against `T1Domain` |
| `alfred web allowlist remove <domain>` | T1 | yes | exit-nonzero if domain not in list |
| `alfred web allowlist list` | T1 | no | renders current allowlist |

### `alfred config`

| Command | Tier | Reviewer-gated | Notes |
|---|---|---|---|
| `alfred config set <key> <value>` | T1 | yes | writes `config/policies.yaml` via state.git proposal |
| `alfred config get <key>` | T1 | no | reads current value |
| `alfred config list` | T1 | no | renders all keys |

Slice-3 keys supported by `config set`:

| Short alias | Canonical key | Blast | Notes |
|---|---|---|---|
| `web-fetch-budget` | `web_fetch.user_daily_budget` | low | Per-user daily web-fetch handle budget. Mutates `policies.yaml`; hot-reloader picks up the change on the next mtime tick. |
| `operator-fetch-budget` | `web_fetch.operator_daily_budget` | low | Operator-tier daily handle budget (separate pool from per-user). |
| `extraction-max-retries` | `quarantine.extraction_max_retries` | low | Max retries the quarantined extractor performs before emitting `TypedRefusal(reason="cannot_extract")`. |
| `action-deadline` | `orchestrator.action_deadline_seconds` | low | Per-action orchestrator deadline (supervised). |
| `user-agent` | `web_fetch.user_agent` | low | UA string the web-fetch plugin advertises. |
| `quarantined-provider` | (no `policies.yaml` projection — written into `routing.yaml [quarantine]` by the reviewer-gate merge) | **high** | Switches the quarantined LLM provider. Reviewer-gated: queues a state.git proposal, `config get quarantined-provider` is refused (set-only). See [docs/runbooks/slice-3-quarantined-llm.md](./slice-3-quarantined-llm.md) for the full proposal walkthrough. |

`config set quarantined-provider <value>` is the operator-facing CLI for
switching the quarantined provider. The closed-set validator in
`alfred.cli._validators.validate_quarantined_provider` rejects any
unknown value at parse time; on success the command emits
`config.set.requested` to the audit log and prints the proposal id.
Reviewer approval then merges the change into `routing.yaml [quarantine]`
and the supervisor reloads the quarantined-LLM plugin on the next
reconcile tick.

### `alfred supervisor`

| Command | Tier | Reviewer-gated | Notes |
|---|---|---|---|
| `alfred supervisor status` | T1 | no | per-component circuit-breaker state + trip count |
| `alfred supervisor reset <component> --confirm` | T1 | no (read after `--confirm`) | clears a tripped breaker; emits `supervisor.breaker.reset` |

The `--confirm` flag is mandatory on `reset` — an unconfirmed call
surfaces a typed refusal rather than executing.

### `alfred audit graph --tier`

Slice 3 extends the existing `alfred audit graph` with a
`--tier {T0|T1|T2|T3}` filter. Each tier produces a swimlane view of
audit rows attributed to that tier:

```shell
alfred audit graph --tier T3 --since 24h
```

The validated tier set is closed (`T0`, `T1`, `T2`, `T3` — see
`_TierChoice` in `src/alfred/cli/audit.py`); passing `--tier T5` or any
out-of-set string raises a typed refusal at argument-parse time, not
after the query runs. See
[docs/subsystems/security.md](../subsystems/security.md) for the
tier model.

`alfred audit log --event <family>` is the per-family detail view used
throughout this runbook. The CLI surface ships in Slice 3
(`alfred audit log --help` documents `--event` and `--since`); the
Postgres-backed query layer it dispatches to lands in PR-S3-7. Until
that PR merges, the command surfaces a typed `AuditBackendUnavailable`
refusal with the localised message keyed
`cli.audit.backend_unavailable`:

```
alfred audit backend not yet wired (PR-S3-7). Until then the storage-layer
SQL query is unimplemented; running ``alfred audit log`` / ``alfred audit
graph`` cannot return rows. Track the unblock in PR-S3-7.
```

Until then use `alfred audit graph --since <window>` and grep the row
family from the output. Once PR-S3-7's storage layer is in, the same
`alfred audit log --event <family>` invocations throughout this runbook
return rows directly.

## Provider routing changes

Slice 3 splits the LLM surface into **privileged** (T0–T2 orchestrator
context) and **quarantined** (T3 raw content). See
[docs/subsystems/quarantine.md](../subsystems/quarantine.md) for the
dual-LLM split.

`config/routing.yaml` gains a `[quarantine]` block:

```yaml
quarantine:
  provider: "anthropic"
  model: "claude-haiku-3-5"
  secret_id: "quarantine_provider_api_key"
  max_tokens_per_extraction: 8192
```

The bootstrap-time check in
`alfred.bootstrap.quarantine.assert_provider_separation` refuses to
start when the privileged and quarantined provider IDs collide. By
default `config/alfred.toml [provider]` selects the privileged
provider; `routing.yaml [quarantine]` must select a different one.

Provider capabilities determine the `ExtractionMode` the quarantined
LLM uses:

| Capability | ExtractionMode | Provider example |
|---|---|---|
| `NATIVE_CONSTRAINED_GENERATION` | `native_constrained` | Anthropic |
| `JSON_OBJECT_MODE` | `json_object_unconstrained` | DeepSeek (chat) |
| (none) | `prompt_embedded_fallback` | unknown / OpenAI compat |

`JSON_OBJECT_MODE` providers receive the schema as an in-prompt
embedding rather than via a native constrained-generation API; the
quarantined extractor validates the response shape after the call.
This is the fall-back-but-acceptable path; native modes are preferred.

Changing the `[quarantine].provider`, `model`, or `secret_id` is a
reviewer-gated configuration change (state.git proposal). The runbook
at [docs/runbooks/slice-3-quarantined-llm.md](./slice-3-quarantined-llm.md)
walks the full proposal flow.

## Plugin transport — supervisor-loaded `web.fetch`

In Slice 2 there was no `web.fetch` capability — the orchestrator had no
authorised path to fetch arbitrary HTTP. In Slice 3 the supervisor loads
the `alfred.web-fetch` plugin as a sandboxed MCP subprocess. Every
fetch returns a `ContentHandle` keyed in the Redis content store; the
raw bytes are T3-tagged and never enter the privileged LLM context.

The plugin reads its allowlist from `policies.yaml` (managed via
`alfred web allowlist` above) and its rate-limit counters from Redis.
The launcher contract is in
[docs/subsystems/plugins.md](../subsystems/plugins.md); the
supervisor's circuit-breaker behaviour is in
[docs/subsystems/supervisor.md](../subsystems/supervisor.md).

After the migration, verify `web-fetch` loaded:

```shell
alfred supervisor status     # expect: web-fetch CLOSED
alfred plugin show alfred.web-fetch
```

## State.git bootstrap

Run-time state lives at `/var/lib/alfred/state.git` (bare repository).
Slice-3 image builds expect this to be present and writable.

`bin/alfred-setup.sh` (and the Windows `alfred-setup.ps1` equivalent)
gains a `--state-git-path` flag in Slice 3; the default
`/var/lib/alfred/state.git` matches the docker-compose volume mount.
If you customise the path, also update `ALFRED_STATE_GIT_PATH` in
your `.env`.

The compose volume `alfred_state_git` is mounted into `alfred-core` at
`/var/lib/alfred`. **Do not** `docker compose down -v` for rollback —
that destroys the volume and every committed capability grant with it.
Use `docker compose down` (no `-v`) when rolling back.

## Reviewer-gate flow (operator perspective)

The Slice-3 reviewer gate is the merge button for capability changes.
The flow looks the same for `plugin grant`, `plugin revoke`,
`web allowlist add/remove`, and `config set`:

1. **Operator queues a proposal.** Example:

   ```shell
   alfred plugin grant alfred.web-fetch system tool.web.fetch
   ```

   The command emits `plugin.grant.requested` to the audit log and
   prints a proposal ID:

   ```
   Queued proposal: prop-2026-06-02-a1b2c3d4
   Track status:  alfred plugin grant status prop-2026-06-02-a1b2c3d4
   ```

2. **Reviewer agent reviews.** The reviewer-agent process polls
   state.git for new proposals, runs sandboxed test suites against the
   proposed change, and posts an approve/reject decision.

3. **Merge activates.** On approval the proposal is fast-forwarded onto
   `main`; the supervisor watches state.git for ref changes and reloads
   affected plugins on its next reconcile tick (or immediately on
   `alfred supervisor reset <component> --confirm`).

4. **Operator verifies.**

   ```shell
   alfred plugin grant list           # expect new grant present
   alfred plugin show <plugin_id>     # confirm hookpoint listed
   ```

Track pending work with:

```shell
alfred plugin grant list --pending     # operator-visible queue
alfred plugin grant status <id>        # per-proposal detail
```

## Default plugin grants

After seeding `state.git` (Step 2 above), the quarantined-LLM and
web-fetch plugins are not yet granted any hookpoints — the `main`
branch is empty. The Slice-3 default grants ship in
`config/default-plugin-grants.yaml`.

> **Implementation dependency:** `alfred plugin grant apply <yaml>` is
> scoped to a post-Slice-3 PR. Until it ships, apply grants individually
> using the per-grant subcommand.

```shell
# Grant quarantined-LLM (system tier, all hookpoints)
alfred plugin grant alfred.quarantined-llm system security.quarantined.extract
alfred plugin grant alfred.quarantined-llm system quarantine.ingest

# Grant web-fetch plugin (system tier)
alfred plugin grant alfred.web-fetch system tool.web.fetch
```

Each command is a high-blast operation (it grants system-tier
hookpoints) and goes through the reviewer-gate flow — the command
queues a proposal and prints the proposal ID. Track approval:

```shell
alfred plugin grant list --pending     # see what's queued
alfred plugin grant status <id>        # track each approval
```

Once all grants are approved, the plugins load on the next supervisor
restart or `alfred supervisor reset`.

## Expected errors during transition

**`plugin.lifecycle.load_refused` with `bootstrap.capability_gate_unseeded`**

Cause: `state.git` was not seeded before `docker compose up`.

Fix:

```shell
git init --bare /var/lib/alfred/state.git
# Bare repos have no working tree, so `git commit --allow-empty` cannot run;
# use plumbing to seed an empty root commit on `main`. The `rev-parse --verify`
# guard makes this step idempotent on rerun: re-seeding would rewrite
# `refs/heads/main` and erase grant history.
if ! git -C /var/lib/alfred/state.git rev-parse --verify refs/heads/main >/dev/null 2>&1; then
    SEED_COMMIT=$(
        git -C /var/lib/alfred/state.git commit-tree \
            "$(git -C /var/lib/alfred/state.git mktree </dev/null)" \
            -m "seed: empty initial commit"
    )
    git -C /var/lib/alfred/state.git update-ref refs/heads/main "$SEED_COMMIT"
    git -C /var/lib/alfred/state.git symbolic-ref HEAD refs/heads/main
fi
alfred supervisor reset quarantined-llm --confirm
alfred supervisor reset web-fetch --confirm
```

**RealGate trips fail-closed — every `check*` returns `False`**

Cause: Postgres or state.git is unreachable, so the 60-second heartbeat
budget elapsed without a successful ping.

Symptom: every dispatch through the capability gate is denied; the
audit stream shows `supervisor.capability_gate_unavailable` with
`state_transition="entering_fail_closed"`. `alfred status` does not
expose this directly in Slice 3 (the gate-health line is Slice-3.x+
work); the audit graph is the definitive surface.

Fix: verify `docker compose ps` shows `alfred-db` healthy and
`/var/lib/alfred/state.git` is readable, then run
`alfred audit graph --since 5m` to confirm the fail-closed transition.
When the backing store recovers, `RealGate` exits fail-closed
automatically. One `supervisor.capability_gate_unavailable` audit row
is emitted on exit from fail-closed (with
`state_transition="exiting_fail_closed"` and `denied_dispatch_count=N`).

**`supervisor.config_insecure` in audit stream**

Cause: `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` is set. This is expected
in development but is a warning in production.

Fix (production): remove `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED` from the
compose environment. Slice 4 ships OS sandbox policy files that
replace this escape hatch.

**`supervisor.breaker.tripped` after upgrade**

Cause: the quarantined-LLM subprocess crashed 3 times in 5 minutes.
This can happen if the provider API key was not seeded or the
`config/routing.yaml` quarantine block is missing.

Fix:

1. Check `config/routing.yaml` has a `[quarantine]` block with
   `provider`, `model`, and `secret_id`.
2. Inspect recent crash events. The Slice-3 CLI ships both
   `alfred audit graph --since <window>` and
   `alfred audit log --event <family> --since <window>`. Until PR-S3-7
   wires the Postgres-backed storage layer, both commands surface
   `AuditBackendUnavailable` (see the audit-log surface change above);
   once PR-S3-7 lands the per-family query returns directly. Until
   then, use the audit graph and grep:

   ```shell
   alfred audit graph --since 5m
   # then grep for plugin.lifecycle.crashed rows
   # After PR-S3-7 backend wires:
   #   alfred audit log --event plugin.lifecycle.crashed --since 5m
   ```

3. After fixing the config:
   `alfred supervisor reset quarantined-llm --confirm`.

## Observability checklist

Slice 3 does not yet ship Grafana dashboards or Prometheus alert
manifests in-tree (`ops/` lands in Slice 4 alongside the formal
observability stack). The available operator surfaces are:

- **`alfred audit graph --tier T0|T1|T2|T3 --since <window>`** — the
  primary forensic surface. Use it after any reviewer-gate action
  or supervisor breaker trip.
- **`alfred supervisor status`** — per-component circuit-breaker
  state. Run periodically (every few minutes during a fresh
  migration); a breaker stuck OPEN past its cool-down window means
  the underlying crash repeats.
- **`docker compose logs alfred-core`** — orchestrator-level
  structured logs; redacted via the structlog redactor.
- **`docker compose logs alfred-redis`** — content-store and
  rate-limit counter health. A `LOADING Redis is loading the dataset
  in memory` line during a restart is benign; a `MISCONF` line is
  not.

When `ops/` ships in Slice 4, this section will gain dashboard URLs
and PromQL queries. Until then, plan to drive observability from the
audit graph and `docker compose logs`.

## Backwards-compatibility notes

The Slice-2.5 `DevGate` (`alfred.hooks.capability.DevGate`) is removed
as of the PR-S3-7 flag-day per
[ADR-0017 Decision 7](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md).
`RealGate` is now the sole production gate. The development bootstrap
still calls `build_dev_gate()` (the function name is preserved for
import-graph stability), but the function now constructs a
**fail-closed `RealGate`** — empty grant snapshot, in-process backend
stub, heartbeat disabled — instead of the old permissive `DevGate`. Every
`check*` call against the dev gate now denies fail-closed; developers
who need granted-system semantics for local iteration should stand up a
real Postgres + seeded `plugin_grants` table (the same shape the
production gate consults). The helpers in `tests/helpers/gates.py` are
**test-only** per ADR-0019 — they coexist with `RealGate` inside the
`tests/` tree and must not be imported from `src/` or used for local
iteration outside the test harness.

The lazy-default at the `HookRegistry` boundary
(`src/alfred/hooks/registry.py::_DenyAllGate`) is the equivalent
fail-closed sentinel for any `@hook` decorator that registers before
the bootstrap wires the real gate via `set_registry()`. Both paths
preserve CLAUDE.md hard rule #7: no silent authorisation at boundary
mis-sequencing.

Affected paths after the PR-S3-7 flag-day:

- `src/alfred/bootstrap/gate_factory.py` — `build_dev_gate()` retained,
  now returns a fail-closed `RealGate` (see the docstring on the
  function for the deliberate two-callable shape).
- `src/alfred/hooks/capability.py` — `DevGate` class removed.
- `src/alfred/hooks/registry.py::_DenyAllGate` — new fail-closed
  bootstrap sentinel for the `HookRegistry` lazy default.
- `tests/unit/hooks/test_capability_devgate.py` — removed (the
  behaviour it pinned no longer exists); replaced by RealGate
  deny-path tests under the same directory.
- `docs/runbooks/slice-3-plugins.md` — the "Step 3 — Verify gate
  selection" table simplifies to "RealGate, always".

### Dev migration: what `alfred chat` looks like after the flag-day

Devs and operators who relied on DevGate's permissive default will
notice immediately on the first post-upgrade `alfred chat`: every
hook-dispatched tool, plugin call, and capability check denies
fail-closed. The failure mode is **loud**, not silent — refusals
surface as typed `AlfredError` rows in the audit graph with
`reason="capability_gate_denied"`, and the chat surface prints the
denial — so the regression is impossible to miss.

Three migration paths, in order of preference:

1. **Seed grants against a local Postgres + state.git** (recommended
   for any iteration that exercises real capability checks). Stand
   up the same compose stack the runbook describes (`docker compose
   up -d`), seed `state.git` (Step 2), and queue per-grant proposals
   via `alfred plugin grant <plugin_id> system <hookpoint>`. The
   local reviewer-agent auto-approves in dev mode (`ALFRED_ENV=development`
   short-circuits the human-approval gate; see
   [docs/subsystems/reviewer.md](../subsystems/reviewer.md)).
2. **Set `ALFRED_ENV=development`** to opt into the in-process
   dev-gate fail-closed sentinel without standing up Postgres. The
   gate still denies every check, but `alfred chat` emits a
   localised hint pointing at the missing grants and the seed
   procedure. Useful when you only need to exercise the privileged
   loop without plugin dispatch.
3. **Drive iteration from the test harness** when you want to
   bypass the gate deliberately — `tests/helpers/gates.py` exposes
   `granted()`/`denied()` factories scoped to the test tree only
   (see ADR-0019). These helpers must not be imported from `src/`
   or used outside `tests/` — the conftest pre-commit guard
   enforces this.

If you previously ran `alfred chat` against a fresh checkout and
expected things to "just work", expect the first post-upgrade chat
to fail fast with a denial — that is the design. Path 1 above is
the production-equivalent loop; paths 2 and 3 are deliberate
scaffolding for narrower iteration.

Existing Slice-2 audit row families are preserved verbatim. Slice-3
adds new families (`plugin.lifecycle.*`, `supervisor.*`,
`quarantine.*`) without breaking the Slice-2 schema; the `0007`
migration extends the `ck_audit_log_result` CHECK constraint
additively.

## Troubleshooting matrix

Each row names (where applicable) the typed exception raised at the
operator surface, the owning subsystem, and the audit-event family.
Empty cells mean "no matching typed exception at this surface" — e.g.
container-level health-check failures surface through `docker compose`
output rather than an `AlfredError` subclass.

| Symptom | Typed exception | Subsystem | Audit family | Likely cause | Fix |
|---|---|---|---|---|---|
| `docker compose ps alfred-redis` not `Up` | — | infra (`alfred-redis`) | — (host-level; surfaces via `docker compose logs alfred-redis`) | port conflict on 6379 or volume permission | free port or chown volume; `docker compose up -d alfred-redis` |
| `plugin.lifecycle.load_refused` rows on every spawn | `ManifestError` | `src/alfred/plugins/` (supervisor load path) | `plugin.lifecycle.load_refused` | state.git not seeded | run Step 2 (seed), then `alfred supervisor reset <component> --confirm` |
| `alfred plugin grant list --pending` shows stuck proposal | `StateGitError` (when the reviewer-agent later writes a refusal) | `src/alfred/reviewer/` + `src/alfred/cli/_state_git.py` | `state_git.proposal_failed` (on agent-side write refusal) | reviewer-agent not running | start reviewer agent (`docker compose up -d alfred-reviewer`); inspect its logs |
| `supervisor.breaker.tripped` for `quarantined-llm` | `QuarantinedUnavailable` / `CircuitBreakerOpen` | `src/alfred/security/quarantine.py` + `src/alfred/supervisor/` | `supervisor.breaker.tripped` with `component="quarantined-llm"` | bad provider config or missing API key | fix `config/routing.yaml` `[quarantine]` + secret; `alfred supervisor reset quarantined-llm --confirm` |
| `supervisor.config_insecure` warnings | — (boot-time warning, not raised) | `src/alfred/bootstrap/` | `supervisor.config_insecure` | `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` set | remove env var in production compose |
| `supervisor.capability_gate_unavailable` audit rows (every dispatch denied) | — (gate denies are returned as `False`, not raised) | `src/alfred/security/capability_gate.py` (`RealGate`) | `supervisor.capability_gate_unavailable` | Postgres or state.git unreachable past the 60 s heartbeat budget | restore the backing store; gate exits fail-closed automatically — single audit row marks the transition out |
| `web.fetch` raises `DomainNotAllowed` | `WebFetchError` (subclass `DomainNotAllowed`) | `plugins/alfred_web_fetch/` | `web.fetch.domain_refused` | domain missing from allowlist | queue `alfred web allowlist add <domain>`; wait for reviewer approval |
| `web.fetch` raises `WebFetchTlsError` | `WebFetchTlsError` | `plugins/alfred_web_fetch/` | `web.fetch.tls_error` | upstream TLS failure or untrusted cert | verify the upstream cert chain; if a custom CA is required, mount it into the plugin sandbox |
| `web.fetch` raises `WebFetchCanaryTripped` | `WebFetchCanaryTripped` | `plugins/alfred_web_fetch/` | `security.canary_tripped` | DLP canary fired on fetched content | quarantine the handle, audit-graph the canary row, follow the DLP runbook |
| Quarantined extractor refuses (`cannot_extract`) | `AlfredError` (`security.quarantine.protocol_violation`) | `src/alfred/security/quarantine.py` | `quarantine.protocol_violation` | upstream schema/payload mismatch | confirm `extraction-max-retries`; inspect `alfred audit graph --since 5m` for the violation row |
| Quarantined dereference denied | `AlfredError` (`security.quarantine.dereference_denied`) | `src/alfred/security/quarantine.py` | gate-side `security.capability_gate.*` row (per spec §8.2) | hookpoint not granted at quarantine tier | queue `alfred plugin grant <id> quarantined …`; wait for reviewer approval |
| Quarantined downgrade denied | `AlfredError` (`security.quarantine.downgrade_denied`) | `src/alfred/security/quarantine.py` | gate-side `security.capability_gate.*` row | privilege-downgrade requested from privileged context | inspect originating call site — privileged context must not request a quarantined downgrade |
| `alfred audit log/graph` refuses with `AuditBackendUnavailable` | `AuditBackendUnavailable` | `src/alfred/cli/audit.py` | none (CLI-side guard; backend wires the events in PR-S3-7) | Postgres-backed audit query layer not yet wired | track PR-S3-7; until then use `alfred audit graph --since <window>` |
| `alembic upgrade head` fails on `0007` | — (Alembic surfaces its own exception) | `src/alfred/db/migrations/` | — (`docker compose logs alfred-db`) | Slice-2 schema diverged | inspect failed migration, fix Postgres state, retry |
| `bootstrap.capability_gate_unseeded` chat message | — (user-surface message; no typed exception) | `src/alfred/bootstrap/` | `plugin.lifecycle.load_refused` | first run after compose-up without seeding | run Step 2 and the two supervisor resets |

Use the audit family column with `alfred audit graph --since <window>`
(or `alfred audit log --event …` once PR-S3-7 wires the backend) to
confirm the typed-exception came from where the stack trace claims and
to surface neighbouring rows (retry counts, denied dispatch counts,
breaker trip history).

## Rollback

To roll back to Slice 2:

1. `docker compose down`.
2. `uv run alembic downgrade base` (removes migrations `0007`–`0010`).
   Note: downgrading `0008`/`0009` drops those tables (data is
   rebuildable from state.git); downgrading `0010` deletes all circuit
   breaker rows (breaker state is transient — the next run
   re-discovers failures).
3. `docker compose up -d` with the Slice-2 images.

The state.git directory at `/var/lib/alfred/state.git` is not modified
by the Alembic downgrade — it is the source of truth. A rollback
discards the Postgres projection; the next `upgrade head` rebuilds it.

> **Warning:** `config/policies.yaml` entries added or changed via
> `alfred config set` since the Slice-3 upgrade are **not rolled back
> automatically**. Review the file and restore the Slice-2 baseline
> values for any keys that Slice-3 features introduced (e.g.
> `quarantine.extraction_max_retries`,
> `orchestrator.action_deadline_seconds`).

> **Warning:** `docker compose down -v` deletes the `alfred_state_git`
> volume, permanently destroying the capability-grant history. Use
> `docker compose down` (without `-v`) for rollback.

**Verify the rollback succeeded:**

```shell
alfred status         # expect Slice-2 output (no gate: line)
alfred audit graph --since 1m
# expect no Slice-3 audit families (plugin.lifecycle.*, supervisor.*)
```

## Related docs

- [docs/subsystems/plugins.md](../subsystems/plugins.md) — plugin
  transport architecture.
- [docs/subsystems/supervisor.md](../subsystems/supervisor.md) — circuit
  breaker and per-action deadline.
- [docs/subsystems/quarantine.md](../subsystems/quarantine.md) — dual-LLM
  split and T3 extraction.
- [docs/subsystems/identity.md](../subsystems/identity.md) — operator
  binding and user-tier roles.
- [docs/subsystems/security.md](../subsystems/security.md) — trust-tier
  model, two-axis tier naming, web-fetch allowlist.
- [docs/glossary.md](../glossary.md) — RealGate, capability gate,
  ContentHandle, ExtractionMode.
- [docs/runbooks/slice-3-plugins.md](./slice-3-plugins.md) — plugin
  launcher / sandbox provisioning.
- [docs/runbooks/slice-3-quarantined-llm.md](./slice-3-quarantined-llm.md)
  — quarantined-LLM provider configuration and proposal flow.

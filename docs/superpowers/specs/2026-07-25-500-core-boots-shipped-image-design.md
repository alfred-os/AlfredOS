# #500 — alfred-core boots in the shipped image (Roadmap #469 Step 3)

- **Issue:** [#500](https://github.com/alfred-os/AlfredOS/issues/500) — alfred-core
  cannot boot in the shipped image: Dockerfile omits `plugins/`, `_REPO_ROOT`
  resolves to the install prefix.
- **Epic / roadmap:** [#469](https://github.com/alfred-os/AlfredOS/issues/469)
  first-run path-to-green; roadmap
  `docs/superpowers/specs/2026-07-24-469-first-run-path-to-green-roadmap.md`.
  Step 1 (#494 e2e lane) + Step 2 (#499 gateway Settings decoupling) SHIPPED;
  this is **Step 3**.
- **Status:** design — pending approval.
- **Relates to:** [ADR-0036](../../adr/0036-gateway-adapter-hosting-inversion.md)
  (gateway holds no provider key), the #494 e2e boot lane
  (`tests/e2e/test_first_run_boot.py` — the `alfred-core` strict-xfail this flips),
  the established `/app`-fallback precedent in `src/alfred/i18n/translator.py`.

## Context

The documented first run (`git clone` → `cp .env.example .env` → set keys →
`docker compose up -d`) never reaches a healthy `alfred-core`. Step 1's e2e lane
made the failure a strict-`xfail` (`test_core_is_healthy`, tagged `#500`); Step 2
un-hung the gateway so core's `depends_on: alfred-gateway: service_healthy` can
be satisfied. This step makes core **fully bootable in the shipped image** and
ratchets the lane's core xfail to green with real boot-posture assertions.

### Root cause — confirmed by a full `alfred daemon start` boot-path trace

`docker/alfred-core.Dockerfile` installs `alfred` **non-editable** into a PBS
python prefix, so in the built image the package lives at
`/opt/alfred-python/lib/python3.14/site-packages/alfred/…`. The non-editable
install drops the source tree's `src/` wrapper level, so every
`Path(__file__).resolve().parents[N]` "repo root" **overshoots**:

```
site-packages/alfred/config/settings.py
  parents[2] = …/site-packages
  parents[3] = /opt/alfred-python/lib/python3.14      ← _REPO_ROOT (WRONG; want /app)
```

Compounding this, the Dockerfile **never COPYs `plugins/`** (it copies `src`,
`config`, `bin`, `locale`, `alembic.ini`). The repo-root artifacts the running
container needs (`plugins/`, `bin/`) live at `/app` (WORKDIR), not relative to
the installed package.

The trace found **four repo-root resolvers on the boot-to-healthy path, at three
different `parents[N]` depths, plus one un-provisioned production gate**:

| # | Gate | Location | Depth | Refusal in image |
|---|------|----------|-------|------------------|
| 1 | Settings load: `alfred_tui` manifest probe | `config/settings.py:55` + `:141` | `parents[3]` | `SettingsError` — earliest; blocks **every** `Settings()` incl. `migrate`, `user add` |
| 2 | TUI wire-spec manifest resolve at boot | `cli/_launcher_spawn.py:62` via `cli/daemon/_comms_boot.py:162` | `parents[3]` | wire-spec resolve fails |
| 3 | First-party grant seed (comms manifest read) | `security/capability_gate/_comms_adapter_grants.py:100` | `parents[4]` | `boot_infra_install_failed` (masked by #1 until #1 fixed) |
| 4 | Probe (a) launcher self-test — **hardcoded module const, ignores `ALFRED_PLUGIN_LAUNCHER`** | `cli/daemon/_daemon_probes.py:89-91`, exec at `:111`, prod-refuse at `:166` | `parents[4]` | `launcher_not_policy_resolving` (production) |
| 5 | Probe (b) policies.yaml — `settings.policies_path` default `/etc/alfred/policies.yaml` absent in image | `config/settings.py:316`, probe `cli/daemon/_daemon_probes.py:194` | — | `snapshot_ref_init_failed` (production) |

Because the four `parents[N]` resolvers sit at **different depths**, they cannot
be fixed consistently by editing each in place — that is precisely the drift that
caused this bug, and #499's comms review already flagged the
`settings.py`/`_launcher_spawn.repo_root()` pair as an "unexercised dependency
that must agree in the shipped image." The correct fix unifies them.

### Trace findings that bound scope

- **`/app/src` is NOT needed** for the shipped `ALFRED_COMMS_ENABLED_ADAPTERS=["alfred_tui"]`
  default. The TUI adapter is **socket-backed** (`adapter_kind = "tui"`,
  `[sandbox] kind = "none"`): `daemon start` binds `comms-tui.sock` under the
  mounted `/home/alfred/.run` and spawns **no** subprocess. The
  `repo_root()/"src"` join (`_comms_boot.py:1213`) lives only in
  `_spawn_comms_adapter`, the **stdio** carrier for the opt-in Discord/reference
  adapters — not reached by the tui default. `src/` is deliberately **not** in the
  image (non-editable install; #290).
- **`audit.hash_pepper` and the `state.git` seed do NOT gate boot-to-healthy**
  for the tui default. The pepper derive is **lazy** (first inbound hash use;
  `comms_mcp/audit_hash.py:139`) — no inbound flows at boot. `state.git` is only
  read at boot via a sentinel-returning helper that does **not** refuse on an
  unseeded repo. Both remain `bin/alfred-setup.sh`'s job and matter at runtime,
  not at boot. (The `bootstrap.capability_gate_unseeded` token referenced in
  CLAUDE.md exists only as a stale comment in `bin/alfred-state-git-seed.sh` — no
  live `t()` key or raise site; not a boot gate.)
- **Migrated Postgres DOES gate boot.** `daemon start` does not auto-migrate; the
  first-party grant seed writes `plugin_grants`, so an unmigrated DB fails with
  `boot_infra_install_failed`. Migration is the separate `alfred migrate`
  (alembic; `script_location = alfred.memory:migrations`, package-relative, so it
  already resolves in the installed layout).
- **The daemon always seeds a real Postgres-backed `RealGate`** at boot
  (`build_boot_real_gate_for_daemon`), independent of `ALFRED_ENV` (the
  DevGate/RealGate selector only affects non-daemon `alfred chat`/`status`).
  `ALFRED_ENVIRONMENT=production` gates the **sec-002 sandbox refusals** — which is
  what makes probe (a) and the unsandboxed-escape refusal live, and is why #500
  sec-003 wants it explicit in the e2e env-file.

## Goal

`docker compose up -d --no-deps alfred-core` (with postgres/redis up and the DB
migrated) reaches Docker `healthy` **in the shipped image, in production mode**,
and the #494 e2e lane asserts it green with runtime boot-posture assertions —
never a bare `assert healthy`.

## Design

### Part A — one shared repo-root resolver (the mechanism)

New dependency-free module `src/alfred/_repo_root.py`:

```python
def repo_root() -> Path:
    """The directory that ships `plugins/`, `bin/`, `config/`, `alembic.ini`.

    Resolution order:
      1. ALFRED_REPO_ROOT env var (the Dockerfile sets it to /app) — the
         explicit deploy-time seam; wins so the installed image never depends
         on __file__ arithmetic that the non-editable layout breaks.
      2. Source-tree fallback: parents[2] of THIS module
         (src/alfred/_repo_root.py -> alfred -> src -> <repo>) IF it contains
         a `plugins/` marker — matches `uv run pytest` from a worktree.
      3. /app — the container default (mirrors i18n/translator.py's /app
         fallback), the last resort when neither above resolves.
    """
```

Design points:
- **Single source of truth.** Every repo-root call site computes the root via
  this one function and joins `plugins/` / `bin/` / `src/` onto it. The
  three-different-`parents[N]`-depths drift disappears: the function lives at one
  known depth and returns one root.
- **Import-cycle-safe.** The module imports only `os` + `pathlib`. `settings.py`
  loads very early in boot; it may import `alfred._repo_root` (no CLI package
  pulled into its closure), replacing the current copy-pasted `parents[3]` +
  its "do NOT import `_launcher_spawn`" comment.
- **Monkeypatch-friendly.** Tests set `ALFRED_REPO_ROOT` (or patch the function).
  Call sites that today read a module-level `_REPO_ROOT` constant and resolve it
  fresh per call (`_comms_adapter_grants.py`) call `repo_root()` per use so the
  env override / patch is honoured.
- **Env-var seam over hardcoded `/app`.** An explicit `ALFRED_REPO_ROOT` is the
  DIP-consistent deploy seam (mirrors the Dockerfile's existing
  `ALFRED_PYTHON_PREFIX` / `ALFRED_QUARANTINE_CHILD_PYTHON` env contracts) and is
  self-documenting; the `/app` literal is retained only as the terminal fallback.

**Call sites routed through `repo_root()`** (unify-all, per the approved scope):

| Module | Current | After |
|--------|---------|-------|
| `config/settings.py` | `_REPO_ROOT = parents[3]` | `repo_root()` (fresh per validator call) |
| `cli/_launcher_spawn.py` | `repo_root()` = `parents[3]` | delegates to `alfred._repo_root.repo_root()` |
| `security/capability_gate/_comms_adapter_grants.py` | `_REPO_ROOT = parents[4]` | `repo_root()` |
| `cli/daemon/_daemon_probes.py` | `_LAUNCHER_PATH` const from `parents[4]` | resolve launcher from `repo_root()` (still `ALFRED_PLUGIN_LAUNCHER`-overridable — closes the const-ignores-env bug) |
| `security/quarantine_child_io.py` | `_repo_root()` = `parents[3]` | delegate |
| `plugins/comms_stdio_transport.py` | `_repo_root()` = `parents[3]` | delegate |
| `gateway/adapter_child_factory.py` | `parents[3]` inline | `repo_root()` |

`i18n/translator.py` keeps its richer 3-candidate logic (source /
`/app/locale` / wheel `alfred/_locale` force-include) — it resolves a *specific
catalog dir* with a wheel-embedded layer the generic repo-root helper does not
have, and it already works in the image. It may optionally consume `repo_root()`
for its first candidate; not required.

`security/quarantine_child_io.py` and `gateway/adapter_child_factory.py` are in
`src/alfred/security/` / gateway trust-boundary-adjacent code → the **adversarial
suite runs** (CLAUDE.md HARD security rule).

### Part B — Dockerfile

- `COPY plugins ./plugins` in the runtime stage (alongside `config`, `bin`,
  `locale`). Chowned by the existing `RUN chown -R alfred:alfred /app`.
- `ENV ALFRED_REPO_ROOT=/app` (runtime stage). This is the seam Part A honours;
  the built image never depends on `parents[N]` arithmetic.

The builder stage still needs source `locale/` for the wheel force-include (per
its existing comment); `plugins/` is a **runtime** artifact (read by the running
container), copied only into the runtime stage — the wheel does not carry it.

### Part C — Compose

Add to `alfred-core` `environment:`:

```yaml
# Probe (b): the daemon loads policies.yaml at boot. settings.policies_path
# defaults to /etc/alfred/policies.yaml (the documented bare-host runtime-config
# root), which the image does not provision. The image ships the file at
# /app/config/policies.yaml (Dockerfile COPY config), so point the override
# there — exactly the ALFRED_POLICIES_PATH use the field's own description names.
ALFRED_POLICIES_PATH: ${ALFRED_POLICIES_PATH:-/app/config/policies.yaml}
```

No `ALFRED_ENV` change: the daemon boot gate is `ALFRED_ENV`-independent (always
seeds the real Postgres gate). `ALFRED_ENVIRONMENT` already defaults to
`production` in compose.

### Part D — e2e provisioning + env-file

- **Provision before `up`:** `test_core_is_healthy` runs
  `docker compose run --rm alfred-core migrate` (mirrors `bin/alfred-setup.sh`
  step "Running migrations") before `up -d --no-deps alfred-core`. Postgres/redis
  are already up (the `boot_stack` fixture brought up `BASELINE`). `migrate`
  constructs `Settings()`, so it exercises the Part A/B fix too. The core health
  budget is restored from the shrunken `_XFAIL_HEALTH_TIMEOUT_S` (60 s) back to
  the full baseline budget (the perpetual-`starting` rationale is gone once core
  can reach healthy).
- **sec-003 — explicit production in the env-file:** add
  `ALFRED_ENVIRONMENT=production` to `tests/e2e/_env.py:write_e2e_env_file`. Compose
  already defaults it, but making it explicit means the posture assertions
  provably test the real production gate, not an implicit default, and
  self-documents intent.

### Part E — un-xfail with runtime posture assertions (sec-002)

Replace the `xfail` + bare `assert healthy` with an explicit-posture test. Each
property has its **own concrete runtime observable** on the *booted* container —
distinct from the existing static compose-config pins in
`tests/unit/test_compose_invariants.py` (which already assert apparmor/seccomp
present, not-privileged, internal network, SETUID set):

1. **Healthy** — `boot_stack.health("alfred-core") is HEALTHY` (necessary, not
   sufficient).
2. **Egress chokepoint enforced** — `docker inspect` the running core container →
   its `NetworkSettings.Networks` contains **only** `…_alfred_internal` (the
   `internal: true` network) and **not** `…_alfred_external`. Direct runtime proof
   the core has no external egress route (the Spec C connectivity-free invariant).
3. **Capability gate seeded** — `docker compose exec -T alfred-postgres psql …
   -c "select count(*) from plugin_grants"` returns `> 0`. Runtime proof the
   `daemon start` boot seeded the first-party `RealGate` grants (not inferred from
   healthy).
4. **Sandbox active** — the launcher self-test resolves policy inside the running
   container: `docker compose exec -T alfred-core /app/bin/alfred-plugin-launcher.sh
   --self-test` returns the policy-resolving signature (the same check probe (a)
   runs at boot; production refuses a stub). This proves the bwrap sandbox
   machinery is live and correctly path-resolved in the image.

The **exact oracle set is subject to security-lane refinement in /review-plan** —
e.g. whether (4) should additionally assert an audited boot event, or (2) should
be complemented by a negative egress probe. The invariant the design commits to:
**no property is asserted by `healthy` alone.**

> **Verification caveat.** macOS Docker-Desktop does not load the `alfred-bwrap`
> AppArmor profile, so posture (4) — and possibly boot itself — fails there via a
> different mechanism. The **Linux nightly End-to-end lane is authoritative**;
> local verification uses the Linux/arm64-privileged docker repro (established
> recipe) for the sandbox parts.

### Part F — ratchet the service partition

- `tests/e2e/_services.py`: move `alfred-core` from `XFAIL_SERVICES` (which
  becomes **empty**, `{}`) into `HEALTHY_APP_SERVICES` (joining `alfred-gateway`).
- `tests/unit/e2e/test_services.py`: update the partition assertions — `xfail`
  bucket is now empty; `HEALTHY_APP_SERVICES == {"alfred-gateway", "alfred-core"}`.
  The disjoint-and-covering partition test stays honest with an empty xfail set
  (an empty set is disjoint from everything and the union still covers the six).
- The `test_every_compose_service_is_classified` derived-set guard continues to
  red if a new compose service appears unclassified.

### Part G — ADR-0055

Record two decisions:
1. **Repo-root resolution convention** — one `alfred._repo_root.repo_root()`
   honoring `ALFRED_REPO_ROOT` (deploy seam) with a source-tree + `/app`
   fallback; all repo-root call sites route through it; the installed image never
   depends on `parents[N]` arithmetic. Supersedes the copy-pasted per-module
   `parents[N]` pattern.
2. **Boot-posture assertion contract** — the e2e core-healthy assertion must
   carry runtime posture oracles (network isolation, gate seeded, sandbox active),
   never a bare `assert healthy`.

## Test plan

- **Unit:** `alfred._repo_root.repo_root()` — env-override wins; source fallback
  finds the marker; `/app` terminal fallback; each is a small pure test. Existing
  tests that monkeypatch `_REPO_ROOT` on `settings.py` / `_comms_adapter_grants.py`
  migrate to setting `ALFRED_REPO_ROOT` (or patching `repo_root`). Partition test
  updated (Part F).
- **Adversarial:** the comms-adapter-id traversal-refusal suite (`cap-2026-012`
  and siblings) must still pass — the shared resolver must not weaken the
  `is_relative_to(plugins/)` containment guard in `validate_comms_adapter_ids`.
  Full adversarial suite runs (security modules touched).
- **e2e (nightly, authoritative):** `test_core_is_healthy` XPASS→green with the
  four posture assertions; tally unchanged in shape (one xfail becomes one pass);
  `XFAIL_SERVICES` empty.
- **Local:** Linux/arm64-privileged docker repro of the full core boot to
  `healthy` + the posture probes; `make check` before push.

## Scope boundaries (explicit — follow-ups, not this PR)

- **`src/` COPY + Discord/stdio-adapter `/app/src` path.** Discord is opt-in and
  out of the shipped tui default; its stdio carrier needs `/app/src` (not in the
  image). Part A fixes the *path resolution*; the missing `src/` COPY for stdio
  adapters is a separate concern → **file a follow-up.**
- **`hash_pepper` / `state.git` provisioning** stays with `bin/alfred-setup.sh`
  (not boot-gating for the default).
- **Roadmap Steps 4/5** (#501 README/DeepSeek-key + `policies.yaml`
  confirm-by-run; promote lane to release-blocking) remain their own steps. Note:
  this step's Part C already resolves the `policies.yaml` *boot gate*; #501's
  residual is only the setup.sh credential-gate reconciliation.

## Risks

- **Wide blast radius of the resolver unification.** Mitigation: one small pure
  module + mechanical call-site routing; the shared function is covered directly;
  the adversarial + full unit suites gate it; whole-tree `mypy src/` (not
  per-module) is the real type gate (the #499 pydantic-plugin lesson).
- **Posture-assertion oracle sufficiency.** Mitigation: security lane refines the
  exact set in /review-plan; the design commits only to "not bare healthy."
- **Local macOS cannot fully verify.** Mitigation: Linux/arm64-privileged repro +
  authoritative nightly.

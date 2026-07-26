# #501 — README/setup.sh first-run credential reconciliation

> **Roadmap #469 Step 4.** The last strict-xfail on the #494 e2e first-run boot lane.
> Landing this makes the lane fully green so Step 5 can promote it to release-blocking.

**Status:** design approved 2026-07-26. Next: `superpowers:writing-plans`.

## Problem

An operator who follows the README quickstart literally cannot complete a first run:

1. `README.md:33` says `cp .env.example .env  # then set ALFRED_QUARANTINE_PROVIDER_API_KEY`.
2. The quickstart callout (`README.md:40-54`) documents **only** `ALFRED_QUARANTINE_PROVIDER_API_KEY`
   as required; it never mentions `ALFRED_DEEPSEEK_API_KEY`.
3. But `bin/alfred-setup.sh`'s credential gate ("Validating .env credentials",
   `bin/alfred-setup.sh:201-273`) **also** rejects the `.env.example` `sk-...` DeepSeek
   placeholder and `exit 1`s with all problems accumulated.

So the documented flow (`cp .env.example .env` → set only the quarantine key →
`bin/alfred-setup.sh`) hits a hard, correct refusal at the credential gate having
provisioned nothing.

The #494 lane encodes this as a strict-xfail:
`tests/e2e/test_first_run_boot.py::test_setup_sh_completes` copies the stock
`.env.example` into an isolated worktree, runs setup.sh, and xfails at the credential gate.

## Finding that shapes the fix

The issue framed this as "fix the README **or** relax setup.sh (epic owner's call)."
Investigation collapses that fork: **only the README fix is viable.**

- `src/alfred/config/settings.py:179` — `deepseek_api_key: SecretStr` is **required-no-default**,
  with `_reject_placeholder_key` (`:520`) rejecting the literal `sk-...`. The core cannot even
  construct `Settings()` without a real DeepSeek key. Relaxing setup.sh's gate would only move
  the failure to `docker compose up`, where the core crash-loops under `restart: unless-stopped`.
- setup.sh's gate is already best-in-class: it accumulates **both** keys' problems into a single
  report (`config_problems`), names each key with its provider URL and boot-refusal rationale,
  and exits 1 with "fix all of the following." It needs no change.

**The README's omission of the privileged (DeepSeek) key is the entire defect.**

## Decision

Chosen scope (epic owner, 2026-07-26): **full run** — the un-xfail'd
`test_setup_sh_completes` drives the *whole* setup.sh with non-placeholder dummy keys and
asserts it provisions successfully, rather than merely asserting the placeholder refusal.
Rationale: the #469 epic is "a documented quickstart that actually boots"; setup.sh **is**
the quickstart, and the strict-xfail was placed to force proving it runs, not that it refuses.
Post-#500 this is now achievable (core boots on dummy keys; setup.sh's `user add` is guarded;
the AppArmor reload is idempotent under the nightly's passwordless sudo).

## Design

Four components. Touches docs + tests only — no `src/alfred/**`.

### Component 1 — README fix (`README.md`)

Make the quickstart document both required keys.

- **`:33`** inline comment: replace `# then set ALFRED_QUARANTINE_PROVIDER_API_KEY (see below)`
  with wording that names **both** `ALFRED_DEEPSEEK_API_KEY` and
  `ALFRED_QUARANTINE_PROVIDER_API_KEY` (see below).
- **`:40-54`** callout: extend the existing "A provider key is required" note so it covers the
  privileged (DeepSeek) key alongside the quarantine key, with the same fail-loud framing already
  used: `ALFRED_DEEPSEEK_API_KEY` is required-no-default in `settings.py` (validated against the
  `sk-...` placeholder), setup.sh's gate rejects the placeholder, and the core cannot construct
  its settings without it. Keep the existing accurate nuance about the quarantine key gating the
  comms boot; do not overwrite it — add the privileged key as a peer requirement.

Accuracy constraints (do not regress the existing precise text):

- The quarantine-key refuse-boot is gated on `comms_enabled_adapters`; keep that caveat.
- Both keys are required for the compose quickstart (which defaults
  `ALFRED_COMMS_ENABLED_ADAPTERS=["alfred_tui"]`).

README is a user-facing doc, not `PRD.md`/`CLAUDE.md`, so it is not human-gated; still English-only.

### Component 2 — README↔gate consistency unit test

Durable drift net so the README and the gate can never diverge again.

- **New helper** in `tests/_setup_script_helpers.py`: `slice_shell_step(script: Path | str,
  step_title: str) -> str` — returns the text of the `step "<step_title>"` block up to (but not
  including) the next `step "` marker or EOF. Mirrors `slice_shell_function`'s "fail loud if the
  anchor is missing" contract (raise on a missing step). This is the same marker-slicing seam the
  `test_setup_script_env_seed.py` docstring describes; extracting it as a named helper makes it
  reusable and unit-testable.
- **New test** `tests/unit/test_setup_script_readme_consistency.py`:
  - Slice the "Validating .env credentials" block from `bin/alfred-setup.sh` via
    `slice_shell_step`.
  - Extract the set of credential keys the gate *requires* — the `ALFRED_[A-Z0-9_]*_API_KEY`
    tokens that appear on `add_config_problem "..."` lines within that block (a key that feeds an
    `add_config_problem` is, by construction, one whose absence/placeholder fails the gate).
  - Assert the set is non-empty (guards against the regex silently matching nothing) and that
    **every** such key name appears as a literal substring in `README.md`.
  - Add structural self-checks: the sliced block is non-empty and contains the marker (so a
    renamed step fails loud rather than vacuously passing).
- **Helper self-test** (`tests/unit/test_setup_script_helpers.py` sibling, or the existing file):
  add cases for `slice_shell_step` mirroring the `slice_shell_function` cases — simple block,
  block ending at the next step, missing-step raises.

This test is grep/parse-only (no bash, no Docker) and lives in `tests/unit`.

### Component 3 — e2e full-run un-xfail (`tests/e2e/test_first_run_boot.py`, `tests/e2e/_env.py`)

- **`tests/e2e/_env.py`**: DRY the dummy-key content. Today `write_e2e_env_file` writes
  `<dir>/e2e.env`. Factor the credential lines into a shared source of truth so the setup.sh test
  can write the *same* dummy keys as `<worktree>/.env`. Two acceptable shapes (writing-plans
  picks one):
  - add `write_e2e_env_file(dest_dir, *, filename="e2e.env")` and call it with `filename=".env"`
    against the worktree; or
  - expose an `e2e_env_lines()` returning the tuple of `KEY=value` lines, used by both
    `write_e2e_env_file` and a new `write_worktree_dotenv(worktree)` helper.
  Keep the `0o600` chmod and the `DUMMY_KEY_SENTINEL`. The worktree `.env` must contain at least
  `ALFRED_DEEPSEEK_API_KEY`, `ALFRED_QUARANTINE_PROVIDER_API_KEY` (both the dummy sentinel),
  `GF_SECURITY_ADMIN_PASSWORD`, and `ALFRED_ENVIRONMENT=production`.
- **`test_setup_sh_completes`**:
  - Remove the `@pytest.mark.xfail(strict=True, ...)` decorator.
  - Replace `shutil.copyfile(worktree/".env.example", worktree/".env")` with writing the dummy-key
    `.env` (from `_env`) into the worktree.
  - Run the full `bin/alfred-setup.sh` (unchanged invocation: `bash <worktree>/bin/alfred-setup.sh`,
    `cwd=worktree`, unique `COMPOSE_PROJECT_NAME`, non-TTY so setup.sh uses its `ALFRED_OPERATOR_NAME`
    default). Keep `_SETUP_SH_TIMEOUT_S = 900.0`.
  - **Assertions:**
    1. `proc.returncode == 0` — setup.sh's steps `fail` loudly on any provisioning error, so exit 0
       already means every step (migrate, state.git seed, secret prime, hash_pepper, operator
       identity) succeeded.
    2. **Outcome check (not the script's self-report):** query setup.sh's own postgres for a
       seeded operator — `docker compose -p <setup_project> exec -T alfred-postgres psql -U alfred
       -d alfred -tAc "select count(*) from users where \"authorization\"='operator'"` → assert
       `> 0`. NB `authorization` is a Postgres reserved keyword and **must be double-quoted** in
       the SQL (per migration `0004_users_and_identities`, which quotes it everywhere). Reuse the
       `_posture._is_gate_seeded`-style positive-integer parse, or a local equivalent, so a psql
       error string does not read as seeded. Query **before** the `finally` teardown, while
       setup.sh's postgres is still up.
  - Scrub any surfaced stdout/stderr with `_env.scrub_env_secrets(<text>, <the worktree .env>)`
    before it lands in an assertion message (defensive; the sentinels are non-secrets but the GF
    password is random).
  - Keep the isolated detached-worktree, unique project name, and the `finally` that runs
    `_compose.down_project(setup_project)` then `git worktree remove --force`.
- The `run --rm alfred-core user list/add` and `migrate` inside setup.sh use setup.sh's own
  compose project (its own postgres), isolated from the baseline `boot_stack` services.

### Component 4 — lane bookkeeping

- Update the `tests/e2e/test_first_run_boot.py` module docstring: it currently says "Only the
  setup.sh assertion remains strict-xfail on its roadmap blocker." With the xfail removed the lane
  is fully green — rewrite to reflect that (all first-run assertions now positive; the lane is
  ready for Step 5 promotion).
- No `_services.py` change (setup.sh is not a compose service; it is invoked directly).
- PR description notes that Step 5 (promote the #494 lane to release-blocking + close #494/#469) is
  now unblocked. **Step 5 is out of scope for this PR.**

## Definition of Done

- [ ] README quickstart documents both `ALFRED_DEEPSEEK_API_KEY` and
      `ALFRED_QUARANTINE_PROVIDER_API_KEY` as required before the first boot, without regressing
      the existing accurate quarantine-key nuance.
- [ ] `test_setup_script_readme_consistency.py` passes and fails loud if a gate-required key is
      undocumented (verified by a local mutation: temporarily drop one key from the README →
      test reds).
- [ ] `slice_shell_step` has its own unit coverage (simple / next-step boundary / missing-step
      raises).
- [ ] `test_setup_sh_completes` is un-xfail'd, runs the full setup.sh with dummy keys, and asserts
      exit 0 **and** a seeded operator in setup.sh's postgres.
- [ ] The #494 lane has no remaining strict-xfail; module docstring updated.
- [ ] `make check` clean (ruff, mypy, pyright, unit tests). i18n unaffected (docs/tests only).
- [ ] The full run is proven on the authoritative Linux nightly (`gh workflow run Nightly --ref
      <branch>`), not just static review — the #500 lesson (only the nightly caught the
      empirically-wrong review finding).

## Risks & mitigations

- **AppArmor step in setup.sh runs for the first time in this lane.** Today's xfail exits at the
  credential gate, before setup.sh's "Loading the bwrap userns AppArmor profile" step. Mitigation:
  the nightly workflow already loads `alfred-bwrap` as a pre-pytest step (`nightly.yml:60`,
  passwordless sudo on the GH runner), and setup.sh's `apparmor_parser -r` reload is idempotent,
  so the setup.sh step re-applies an already-loaded profile. Verify on the nightly run.
- **Full run is heavier than the fast xfail.** setup.sh now builds images (cache-hit in the lane),
  starts its own postgres, and provisions. It does **not** boot the app services (`docker compose
  up -d` is a separate documented step setup.sh does not run), so the cost is bounded and well
  inside the 900s budget. If flake surfaces, root-cause deterministically (the #509 lesson) — do
  not paper over with retries.
- **`user add` double-seed.** setup.sh guards on `has_operator` (runs `user list --json`, skips the
  add if an operator exists), and migration `0004` seeds the bootstrap operator — so setup.sh sees
  `has_operator=1` and skips create. No `OperatorAlreadyExists` (the exact #500 `test_core_is_healthy`
  trap). The DB assertion still passes: the operator exists (seeded by migrate).

## Out of scope

- Step 5 (promote the #494 lane to release-blocking; close #494/#469).
- Any change to `bin/alfred-setup.sh`'s gate logic (it is correct).
- Any `src/alfred/**` change.

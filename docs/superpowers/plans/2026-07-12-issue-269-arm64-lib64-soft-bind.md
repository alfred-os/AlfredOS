# #269 arm64 `/lib64` soft-bind + privileged-arm64 CI leg — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the arm64 dual-LLM real-bwrap-spawn failure (`bwrap: Can't find source path /lib64`) by making the `/lib64` sandbox bind soft (`--ro-bind-try`), and re-add + require the deferred `integration-privileged-arm64` CI leg as the airtight proof.

**Architecture:** `SandboxPolicy` grows a `ro_binds_try` field; `policy_to_bwrap_flags` emits `--ro-bind-try` for it (bwrap binds the source only if it exists, else silently skips). `/lib64` moves from `ro_binds` (hard) to `ro_binds_try` (soft) in both shipped Linux policies — present + bound on x86-64 (no behaviour change there), absent + skipped on arm64 (the loader lives under the already-bound `/lib`). A new arm64 privileged CI job runs the real dual-LLM spawn legs and becomes the required proof.

**Tech Stack:** Python 3.14 (Pydantic v2 frozen model, `tomllib`), bubblewrap, GitHub Actions, `gh api` branch protection.

## Root-cause evidence (already reproduced on native aarch64 — see session)

- Chain (A): current policies emit `--ro-bind /lib64 /lib64` unconditionally; on arm64 `/lib64` is absent (loader `/lib/ld-linux-aarch64.so.1`), so bwrap dies at launch → empty child stdout → `read_frame_failed` (the "truncated frame"). Reproduced via the real launcher: `bwrap: Can't find source path /lib64: No such file or directory`.
- Fix proven **necessary AND sufficient**: with no `/lib64` present, the exact launcher flag set (`--ro-bind /usr /lib` + `--ro-bind-try /lib64` + interp-prefix bind) execs the PBS child and completes a full ingest→extract round-trip on arm64. There is NO separate "second residual" at the spawn layer once a PBS interpreter (ADR-0030 bound-interpreter contract) is used — the earlier "necessary-but-not-sufficient" note predates #251's child-stderr visibility.
- Chain (B) / #252 (`transport_failed` CHECK) is ALREADY fixed (migration `0022`; #252 CLOSED). No work.
- Precedent: `tests/integration/test_alfred_core_image_bwrap.py` (commit `d9f487e1`) already binds `/lib64` only-when-present via a shell `[ -e /lib64 ]` guard; `--ro-bind-try` is the bwrap-native equivalent for the flag-list translator.

## Global Constraints

- **Python floor `>=3.14.6`.** Modern idioms only: PEP 604 unions, PEP 585 built-in generics, PEP 695 generics. Never `Optional[X]`/`typing.List`.
- **Immutability:** `SandboxPolicy` stays a frozen Pydantic model (`ConfigDict(frozen=True, extra="forbid")`). New field is a `Sequence[tuple[str, str]]` defaulting to `()`.
- **Typing:** `mypy --strict` + `pyright` clean. No `Any`.
- **Security (HARD):** `--ro-bind-try` is still read-only; this does NOT weaken isolation (a bound path stays RO; an absent path was never reachable anyway). Do not touch `unshare`/`die_with_parent`/`keep_fds`. The change is in `src/alfred/plugins/`, not `src/alfred/security/`, but it gates the quarantine sandbox — run the adversarial suite as verification.
- **i18n:** the translator emits bwrap flags, not operator-facing strings — no `t()` needed. CI `::error::` lines are shell, outside `t()` scope. No catalog change.
- **CI (ADR-0034):** ADD a new job with a NEW check context; never RENAME an existing required context (a matrix rename breaks branch protection on `main` for every open PR).
- **Conventional commits:** every commit subject carries a literal `#269` AFTER the colon (a `(269)` scope does NOT satisfy the `Conventional commit format` gate). Markdown edits under `docs/` must pass `markdownlint-cli2` (MD060 spaced separators, MD032 list blanks, MD031 fence blanks). No `--no-verify`.
- **Repo hygiene:** never `git add -A` (untracked rulesync outputs get swept in) — add named paths only.

---

### Task 1: `ro_binds_try` schema field + `--ro-bind-try` translation

**Files:**

- Modify: `src/alfred/plugins/sandbox_policy.py` (add `ro_binds_try` field to `SandboxPolicy`; add emission loop in `policy_to_bwrap_flags`; update both docstrings)
- Test: `tests/unit/plugins/test_sandbox_policy_translator.py`

**Interfaces:**

- Produces: `SandboxPolicy.ro_binds_try: Sequence[tuple[str, str]] = ()`; `policy_to_bwrap_flags` emits `--ro-bind-try SRC DST` for each entry, positioned immediately AFTER the hard `--ro-bind` block and BEFORE `--bind` (rw), so the stable flag order becomes: ro-bind → ro-bind-try → bind → tmpfs → dev → unshare → die-with-parent.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/plugins/test_sandbox_policy_translator.py`:

```python
def test_ro_binds_try_translates_to_soft_bind_flag() -> None:
    # A soft bind emits --ro-bind-try (bwrap binds the source only if it
    # exists; a missing source is skipped, not a launch failure). This is
    # the arch-portability primitive for /lib64 (#269): present on x86-64,
    # absent on arm64 where the loader lives under the already-bound /lib.
    policy = SandboxPolicy(
        ro_binds=[("/usr", "/usr"), ("/lib", "/lib")],
        ro_binds_try=[("/lib64", "/lib64")],
        keep_fds=[3],
    )
    flags = policy_to_bwrap_flags(policy)
    # Hard binds first, then soft binds — a stable, auditable order.
    assert flags[:9] == [
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
    ]


def test_ro_binds_try_empty_by_default_emits_nothing() -> None:
    policy = SandboxPolicy(ro_binds=[("/usr", "/usr")], keep_fds=[3])
    flags = policy_to_bwrap_flags(policy)
    assert "--ro-bind-try" not in flags


def test_ro_binds_try_round_trips_through_toml() -> None:
    policy = read_policy_toml(
        'keep_fds = [3]\n'
        'ro_binds = [["/usr", "/usr"]]\n'
        'ro_binds_try = [["/lib64", "/lib64"]]\n'
    )
    assert list(policy.ro_binds_try) == [("/lib64", "/lib64")]
    assert "--ro-bind-try" in policy_to_bwrap_flags(policy)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/plugins/test_sandbox_policy_translator.py -k ro_binds_try -v`
Expected: FAIL — `SandboxPolicy` has no `ro_binds_try` field (`extra="forbid"` → ValidationError / `SandboxPolicyInvalid`).

- [ ] **Step 3: Add the field + translation**

In `src/alfred/plugins/sandbox_policy.py`, add the field to `SandboxPolicy` (immediately after `ro_binds`):

```python
    ro_binds: Sequence[tuple[str, str]] = ()
    # SOFT read-only binds: bwrap binds the source only if it EXISTS, and
    # silently skips it otherwise (``--ro-bind-try``). This is the
    # arch-portability primitive (#269): ``/lib64`` holds the dynamic linker
    # on x86-64 (bound) but does NOT exist on arm64 (skipped — the loader
    # lives under the already-bound ``/lib``). A HARD ``--ro-bind /lib64``
    # dies with "Can't find source path /lib64" on arm64. Still read-only:
    # a soft bind never weakens isolation, it only tolerates a missing source.
    ro_binds_try: Sequence[tuple[str, str]] = ()
```

In `policy_to_bwrap_flags`, add the emission loop immediately after the `ro_binds` loop:

```python
    for src, dst in policy.ro_binds:
        flags += ["--ro-bind", src, dst]
    for src, dst in policy.ro_binds_try:
        # --ro-bind-try: bind if the source exists, else skip (no launch
        # failure). /lib64 is present on x86-64, absent on arm64 (#269).
        flags += ["--ro-bind-try", src, dst]
    for src, dst in policy.rw_binds:
        flags += ["--bind", src, dst]
```

Also add one sentence to the `policy_to_bwrap_flags` docstring's flag-order note: `binds → soft-binds → rw-binds → tmpfs → dev → unshare → die-with-parent`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/plugins/test_sandbox_policy_translator.py -v`
Expected: PASS (new tests + all existing tests — the existing `test_simple_policy_translates_in_stable_order` still holds because `ro_binds_try` defaults empty).

- [ ] **Step 5: Type-check + lint**

Run: `uv run mypy src/alfred/plugins/sandbox_policy.py && uv run pyright src/alfred/plugins/sandbox_policy.py && uv run ruff check src/alfred/plugins/sandbox_policy.py`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/plugins/sandbox_policy.py tests/unit/plugins/test_sandbox_policy_translator.py
git commit -m "feat(sandbox): #269 add ro_binds_try soft-bind (--ro-bind-try) to policy translator"
```

---

### Task 2: Move `/lib64` to `ro_binds_try` in both shipped Linux policies

**Files:**

- Modify: `config/sandbox/quarantined-llm.linux.bwrap.policy` (lines ~40-44: remove `/lib64` from `ro_binds`, add a `ro_binds_try` list; update the `/lib64` comment)
- Modify: `config/sandbox/discord-adapter.linux.bwrap.policy` (lines ~49-53: same; keep `/etc/ssl/certs` in the HARD `ro_binds`)
- Test: `tests/unit/plugins/test_discord_adapter_sandbox_policy.py` (add a shipped-policy assertion); add a new `tests/unit/plugins/test_quarantined_llm_shipped_policy.py` if no unit test parses the quarantined-llm policy today (verify first with grep)

**Interfaces:**

- Consumes: Task 1's `ro_binds_try` field + `--ro-bind-try` emission.
- Produces: both shipped policies parse with `("/lib64","/lib64")` in `ro_binds_try` and NOT in `ro_binds`; their translated flag lists contain `--ro-bind-try /lib64 /lib64` and NO hard `--ro-bind /lib64`.

- [ ] **Step 1: Write the failing test(s)**

First check for an existing shipped-quarantined-llm parse test:
`grep -rln "quarantined-llm.linux.bwrap.policy" tests/` — if none exists, create `tests/unit/plugins/test_quarantined_llm_shipped_policy.py`:

```python
"""The shipped quarantined-LLM Linux policy binds /lib64 SOFTLY (#269, arm64)."""

from __future__ import annotations

from pathlib import Path

from alfred.plugins.sandbox_policy import policy_to_bwrap_flags, read_policy_toml

_POLICY = (
    Path(__file__).resolve().parents[3]
    / "config" / "sandbox" / "quarantined-llm.linux.bwrap.policy"
)


def test_lib64_is_a_soft_bind_not_a_hard_bind() -> None:
    policy = read_policy_toml(_POLICY.read_text(encoding="utf-8"))
    assert ("/lib64", "/lib64") in policy.ro_binds_try
    assert ("/lib64", "/lib64") not in policy.ro_binds
    flags = policy_to_bwrap_flags(policy)
    assert "--ro-bind-try" in flags
    i = flags.index("--ro-bind-try")
    assert flags[i : i + 3] == ["--ro-bind-try", "/lib64", "/lib64"]
    # /lib64 must NOT survive as a hard --ro-bind (the arm64 launch failure).
    hard = [flags[j + 1] for j, f in enumerate(flags) if f == "--ro-bind"]
    assert "/lib64" not in hard
    # /usr + /lib stay HARD (they always exist; a missing one is a real error).
    assert "/usr" in hard and "/lib" in hard
```

Add the sibling assertion to `tests/unit/plugins/test_discord_adapter_sandbox_policy.py` (mirror the block, plus assert `/etc/ssl/certs` stays a HARD `--ro-bind`).

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/plugins/test_quarantined_llm_shipped_policy.py tests/unit/plugins/test_discord_adapter_sandbox_policy.py -v`
Expected: FAIL — the shipped policies still list `/lib64` under `ro_binds`.

- [ ] **Step 3: Edit the policies**

In `config/sandbox/quarantined-llm.linux.bwrap.policy`, change:

```toml
ro_binds = [
  ["/usr", "/usr"],
  ["/lib", "/lib"],
  ["/lib64", "/lib64"],
]
```

to:

```toml
ro_binds = [
  ["/usr", "/usr"],
  ["/lib", "/lib"],
]

# SOFT bind (#269): /lib64 holds the dynamic linker on x86-64 (ld-linux-
# x86-64.so.2) but does NOT exist on arm64 (the aarch64 loader lives under
# the already-bound /lib). A HARD --ro-bind /lib64 dies with "Can't find
# source path /lib64" on arm64, tearing the dual-LLM real-spawn child.
# --ro-bind-try binds it where present (x86-64) and skips it where absent
# (arm64). Still read-only — isolation is unchanged.
ro_binds_try = [
  ["/lib64", "/lib64"],
]
```

Update the prose comment block above `ro_binds` (the `usrmerged system trees (/usr, /lib, /lib64)` sentence) to note `/lib64` is now a soft bind for arm64 portability.

Apply the identical change to `config/sandbox/discord-adapter.linux.bwrap.policy` — move ONLY `/lib64` to `ro_binds_try`; `/usr`, `/lib`, and `/etc/ssl/certs` stay in the hard `ro_binds`.

- [ ] **Step 4: Run to verify pass + full translator suite**

Run: `uv run pytest tests/unit/plugins/ -v`
Expected: PASS.

- [ ] **Step 5: Native-arm64 real-spawn validation (docker)**

Rebuild the container's baked policy is unnecessary — the launcher reads the policy from the bind-mounted repo (`cwd`). With the branch checked out:

```bash
# container alfred269 already provisioned (PBS py3.14 + alfred + bwrap, aarch64)
docker exec \
  -e ALFRED_QUARANTINE_CHILD_PYTHON=/root/.local/share/uv/python/cpython-3.14.6-linux-aarch64-gnu/bin/python3.14 \
  -e ALFRED_PLUGIN_LAUNCHER=/work/bin/alfred-plugin-launcher.sh \
  -e ALFRED_ENVIRONMENT=test -e PYTHONUNBUFFERED=1 \
  alfred269 bash -c 'rm -f /lib64; python -c "import alfred" && python /probe/probe.py spawn'
```

Expected: `CHILD STILL RUNNING after 10s -> spawn OK` + `round-trip reply ... "kind": "extracted"` with NO `/lib64` present (the real `--ro-bind-try` fix, not the symlink). Reinstall alfred into `/usr/local` + PBS first if the branch changed `sandbox_policy.py` (`pip install -q --break-system-packages .` for both interpreters) so the launcher's `python3 -m alfred.plugins.manifest_reader` uses the new translator.

- [ ] **Step 6: Commit**

```bash
git add config/sandbox/quarantined-llm.linux.bwrap.policy config/sandbox/discord-adapter.linux.bwrap.policy tests/unit/plugins/test_quarantined_llm_shipped_policy.py tests/unit/plugins/test_discord_adapter_sandbox_policy.py
git commit -m "fix(sandbox): #269 bind /lib64 softly so the arm64 dual-LLM child spawns"
```

---

### Task 3: Docs — `config/sandbox/README.md` + policy schema field table

**Files:**

- Modify: `config/sandbox/README.md` (the field table + the `/lib64` arch note around lines 80-95)

- [ ] **Step 1: Update the field table**

Add a `ro_binds_try` row beneath `ro_binds`:

```markdown
| `ro_binds_try` | `[["src", "dst"], …]` | Read-only binds applied ONLY when the source exists (`--ro-bind-try`); a missing source is skipped, not a launch failure. Used for `/lib64` (present on x86-64, absent on arm64). |
```

- [ ] **Step 2: Update the `/lib64` prose note**

Replace the note that currently reads "on arches without a top-level `/lib64`, the `/usr` + `/lib` binds carry the loader via the usrmerge symlink — the production target is x86-64 Debian Bookworm" with an accurate statement that `/lib64` is now a **soft** (`ro_binds_try`) bind so the SAME policy is portable to arm64 self-hosting (#269), and that the loader on arm64 lives under the bound `/lib`.

- [ ] **Step 3: Lint the markdown**

Run: `npx --yes markdownlint-cli2 config/sandbox/README.md` (or the repo's configured lint task)
Expected: clean (fix MD060 / MD032 / MD031 if flagged; re-read after any `--fix`).

- [ ] **Step 4: Commit**

```bash
git add config/sandbox/README.md
git commit -m "docs(sandbox): #269 document ro_binds_try soft bind + arm64 /lib64 portability"
```

---

### Task 4: Re-add the `integration-privileged-arm64` CI leg

**Files:**

- Modify: `.github/workflows/ci.yml` (ADD a new `integration-privileged-arm64` job mirroring `integration-privileged` but `runs-on: ubuntu-24.04-arm`, emitting the NEW context `Integration (privileged Linux, real spawn) (arm64)`; drop the "no arm64 twin yet — #269" note from the `integration-arm64` job comment)
- Modify: `docs/ci/required-checks.md` (add the new leg under "Pending required (promote after green)" with the #269 rationale; note the deferred-third-leg text is now resolved)

**Interfaces:**

- Produces: a green `Integration (privileged Linux, real spawn) (arm64)` check on this PR's CI (the airtight arm64 proof of the fix).

- [ ] **Step 1: Add the arm64 privileged job**

Duplicate the `integration-privileged` job as `integration-privileged-arm64`. Changes vs the amd64 original:

- `name: Integration (privileged Linux, real spawn) (arm64)`
- `runs-on: ubuntu-24.04-arm`
- Keep the `sudo` + apt bubblewrap + apparmor-relax + proto py3.14 provisioning + `ALFRED_QUARANTINE_CHILD_PYTHON` / `ALFRED_GATEWAY_ADAPTER_CHILD_PYTHON` wiring VERBATIM (proto publishes arm64 PBS; the recipe is arch-neutral).
- Add a header comment: this leg is what #269 re-enables — the `/lib64` soft-bind (Task 2) makes the real dual-LLM spawn green on aarch64; ADD-not-RENAME per ADR-0034.

- [ ] **Step 2: Update the `integration-arm64` comment**

Remove the `# NOTE — no integration-privileged-arm64 twin (yet): ... tracked in #269` paragraph (the twin now exists) and replace with a one-line pointer to the new job.

- [ ] **Step 3: Validate the workflow YAML**

Run: `python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ci.yml parses')"`
Optionally `actionlint .github/workflows/ci.yml` if available.
Expected: parses; job block well-formed.

- [ ] **Step 4: Update the required-checks manifest**

In `docs/ci/required-checks.md`, under "Pending required (promote after green) — arch breadth (#265, ADR-0034)", add:

```markdown
| `Integration (privileged Linux, real spawn) (arm64)` | `.github/workflows/ci.yml` | `integration-privileged-arm64` | the arm64 twin of the required amd64 privileged leg — runs the real dual-LLM quarantine-child spawn + bwrap sandbox-escape corpus on native aarch64. Green depends on the #269 `/lib64` soft-bind. Promote to Currently-required after its first green run on this PR. |
```

Update the "still-deferred third arm64 leg" sentence (lines ~77-79) to state it is now added (#269 resolved) and pending-promotion-after-green.

- [ ] **Step 5: Lint markdown + commit**

Run: `npx --yes markdownlint-cli2 docs/ci/required-checks.md`

```bash
git add .github/workflows/ci.yml docs/ci/required-checks.md
git commit -m "ci: #269 re-add integration-privileged-arm64 real-spawn leg (arm64 /lib64 proof)"
```

---

### Task 5: Verification pass + PR

- [ ] **Step 1: Full quality gates**

Run: `make check` (ruff + format + mypy + pyright + unit). Confirm exit `0` (do NOT pipe to `tail` — it masks the exit code).

- [ ] **Step 2: Adversarial suite (sandbox-adjacent change)**

Run: `uv run pytest tests/adversarial -q`
Expected: PASS (the `/lib64` soft bind does not weaken any sandbox-escape containment; the bwrap-gated payloads skip locally without root and run in the arm64 privileged CI leg).

- [ ] **Step 3: Push + open the PR**

Branch `269-arm64-lib64-soft-bind`. PR body: "Closes #269." Summarize the two-chain diagnosis, the native-arm64 reproduction + fix proof, and that chain (B)/#252 was already closed. Note the new arm64 privileged leg is the airtight proof and will be promoted to required post-merge.

- [ ] **Step 4: Review + CR**

Full `/review-pr` fleet (security ALWAYS; devops + test + docs lanes most relevant) + BOTH CodeRabbit (CLI `--base origin/main` + cloud). Resolve every thread. Batch all folds BEFORE the first push (dismiss_stale_reviews discipline).

- [ ] **Step 5: Confirm the arm64 privileged leg is GREEN on the PR's own CI**

The `Integration (privileged Linux, real spawn) (arm64)` check must pass on this PR — it is the real-test proof. Non-admin `gh pr merge --rebase` only when all gates green + no unresolved threads.

- [ ] **Step 6 (post-merge): Promote the new context to required + close #269**

Per the author-gating-workflow skill:

```bash
gh api -X POST repos/alfred-os/AlfredOS/branches/main/protection/required_status_checks/contexts \
  -f 'contexts[]=Integration (privileged Linux, real spawn) (arm64)'
```

Move its row in `docs/ci/required-checks.md` from "Pending" to "Currently required" with today's date (a tiny follow-up docs PR, or fold into this PR's manifest edit with a note that promotion happens post-merge). Confirm #269 auto-closed by the PR merge.

---

## Self-Review

- **Spec coverage:** chain (A) fix (Tasks 1-2), docs (Task 3), the deferred CI leg re-add + require (Task 4-5). Chain (B)/#252 already done — no task, noted. ✓
- **Placeholder scan:** every code/test/policy step shows the exact content. ✓
- **Type consistency:** `ro_binds_try: Sequence[tuple[str, str]]` used identically in schema, tests, and policy TOML; flag string `--ro-bind-try` consistent throughout. ✓
- **Order invariant:** the new soft-bind loop sits between `ro_binds` and `rw_binds` in both the translator (Task 1 Step 3) and the assertion (`flags[:9]`, Task 1 Step 1). ✓

# #501 — README/setup.sh First-Run Credential Reconciliation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Document both required provider keys in the README, prove README↔gate consistency with a drift-net unit test, and un-xfail the #494 `test_setup_sh_completes` lane to a full setup.sh run — closing the last strict-xfail so Step 5 can promote the lane.

**Architecture:** Docs + tests only; **no `src/alfred/**` change**. A new `slice_shell_step` helper extracts setup.sh's credential-gate block; a unit test asserts every key the gate flags is documented in `README.md`; the e2e test runs the whole `bin/alfred-setup.sh` with dummy keys and verifies the provisioning outcome (a seeded operator) via a DB query.

**Tech Stack:** Python 3.14, pytest, bash (setup.sh), Docker Compose (e2e nightly only), markdownlint.

**Spec:** `docs/superpowers/specs/2026-07-26-501-readme-setup-reconciliation-design.md`

## Global Constraints

- **No `src/alfred/**` change.** setup.sh's credential gate is correct and must not be modified.
- **Conventional Commits** with a literal `#501` after the colon in every commit subject.
- **Commit trailer** on every commit: `MrReasonable <4990954+MrReasonable@users.noreply.github.com>`.
- **`make check` clean** before any push (ruff, ruff format, mypy, pyright, unit tests).
- **Modern Python 3.14+**: PEP 604 unions, PEP 585 built-in generics; no `Optional[X]`, no `typing.List`. `from __future__ import annotations` at the top of new modules.
- **`authorization` is a Postgres reserved keyword** — always double-quote it in SQL (`"authorization"`).
- **e2e lane is nightly-only** (`pytest.mark.e2e`); the full-run change must be proven on the authoritative Linux nightly (`gh workflow run Nightly --ref <branch>`), not just static review (the #500 lesson).
- **Markdown**: new/edited `docs/**` and `README.md` must pass `markdownlint-cli2@0.22.1` (MD032 blanks-around-lists, MD031 blanks-around-fences, MD060 table pipes).
- **README is English-only** (i18n rule 5); not human-gated (only PRD.md/CLAUDE.md are).

## Subsystem Coverage Matrix

| Subsystem | Files | Owner agent |
| --- | --- | --- |
| e2e first-run boot lane / test harness | `tests/e2e/test_first_run_boot.py`, `tests/e2e/_env.py` | `alfred-test-engineer` |
| Setup-script test seam | `tests/_setup_script_helpers.py`, `tests/unit/test_setup_script_helpers.py`, `tests/unit/test_setup_script_readme_consistency.py` | `alfred-test-engineer` |
| Operator docs / first-run UX | `README.md` | `alfred-docs-author` / `alfred-devex-reviewer` |
| First-run security posture (credential handling, provisioning) | `test_setup_sh_completes` full run | `alfred-security-engineer` |
| Setup script / CI / e2e wiring | `bin/alfred-setup.sh` (read-only reference), nightly lane | `alfred-devops-engineer` |

**Plan-level owner:** `alfred-test-engineer`. **Always-include reviewers:** architect, reviewer, test-engineer, security-engineer.

**Definition of Done:** see the spec's DoD checklist. In short: README documents both keys; consistency test fails-loud on drift; `slice_shell_step` unit-covered; `test_setup_sh_completes` un-xfail'd and asserts exit 0 + seeded operator; lane has no remaining strict-xfail; `make check` clean; proven on the Linux nightly.

---

## Task 1: `slice_shell_step` helper + unit coverage

Add a reusable, fail-loud helper that slices one `step "<title>"` block out of `bin/alfred-setup.sh`, mirroring the existing `slice_shell_function` contract. Task 2's consistency test consumes it.

**Files:**

- Modify: `tests/_setup_script_helpers.py` (add `slice_shell_step`)
- Modify: `tests/unit/test_setup_script_helpers.py` (add cases)

**Interfaces:**

- Produces: `slice_shell_step(setup_sh: Path, step_title: str) -> str` — returns the text from the `step "<step_title>"` marker line up to (but not including) the next `step "` marker or EOF; raises `ValueError` if the step is absent.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_setup_script_helpers.py` (it already imports from `tests._setup_script_helpers` and has a `_script(tmp_path, body)` helper that writes a script file — reuse it; if its signature differs, write the temp file inline with `tmp_path`):

```python
from tests._setup_script_helpers import slice_shell_step


def test_slice_step_returns_block_up_to_next_step(tmp_path: Path) -> None:
    s = _script(
        tmp_path,
        'step "First"\n'
        "echo one\n"
        'add_config_problem "x"\n'
        'step "Second"\n'
        "echo two\n",
    )
    out = slice_shell_step(s, "First")
    assert out == 'step "First"\necho one\nadd_config_problem "x"\n'
    assert "Second" not in out


def test_slice_step_runs_to_eof_when_last(tmp_path: Path) -> None:
    s = _script(tmp_path, 'step "Only"\necho done\n')
    assert slice_shell_step(s, "Only") == 'step "Only"\necho done\n'


def test_slice_step_ignores_the_step_function_definition(tmp_path: Path) -> None:
    # `step() { ... }` is the function def, not a `step "Title"` call — must not anchor on it.
    s = _script(tmp_path, 'step() {\n  echo "$1"\n}\nstep "Real"\necho body\n')
    assert slice_shell_step(s, "Real") == 'step "Real"\necho body\n'


def test_slice_step_missing_raises(tmp_path: Path) -> None:
    s = _script(tmp_path, 'step "Present"\necho hi\n')
    with pytest.raises(ValueError, match="Absent"):
        slice_shell_step(s, "Absent")


def test_the_real_credential_gate_step_is_sliced_whole() -> None:
    block = slice_shell_step(Path("bin/alfred-setup.sh"), "Validating .env credentials")
    assert block.startswith('step "Validating .env credentials"')
    assert "config_problems" in block
    assert "ALFRED_DEEPSEEK_API_KEY" in block and "ALFRED_QUARANTINE_PROVIDER_API_KEY" in block
    # Bounded: it must not run past the gate into the next step.
    assert "Loading the bwrap userns AppArmor profile" not in block
```

If `tests/unit/test_setup_script_helpers.py` does not already import `pytest` / `Path`, add those imports.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/test_setup_script_helpers.py -q`
Expected: FAIL with `ImportError` / `AttributeError` — `slice_shell_step` does not exist yet.

- [ ] **Step 3: Implement `slice_shell_step`**

Append to `tests/_setup_script_helpers.py` (keep the existing `import re` / `from pathlib import Path`):

```python
def slice_shell_step(setup_sh: Path, step_title: str) -> str:
    """Return one ``step "<step_title>"`` block, sliced out of ``setup_sh``.

    The block runs from the ``step "<step_title>"`` marker line to (but not including) the next
    top-level ``step "`` marker, or EOF. Anchoring on the exact title means a renamed or removed
    step raises ``ValueError`` rather than silently returning a stale or empty block — the same
    fail-loud contract as :func:`slice_shell_function`. Matching ``step "`` (with the quote)
    skips the ``step()`` function *definition*. Used by cross-document consistency tests that
    need a step's content (e.g. which credential keys the gate flags).
    """
    lines = setup_sh.read_text().splitlines(keepends=True)
    anchor = f'step "{step_title}"'
    start = next((i for i, ln in enumerate(lines) if ln.strip() == anchor), None)
    if start is None:
        raise ValueError(f"{anchor!r} not found in {setup_sh}")
    end = next(
        (j for j in range(start + 1, len(lines)) if lines[j].lstrip().startswith('step "')),
        len(lines),
    )
    return "".join(lines[start:end])
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/test_setup_script_helpers.py -q`
Expected: PASS (all cases, including the real-script slice).

- [ ] **Step 5: Commit**

```bash
git add tests/_setup_script_helpers.py tests/unit/test_setup_script_helpers.py
git commit -m "test: #501 add slice_shell_step helper for setup.sh step blocks

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 2: README fix, proven by a README↔gate consistency test

TDD the README fix: a new consistency test reds because the README omits `ALFRED_DEEPSEEK_API_KEY`; fixing the README greens it. The test is the durable drift-net.

**Files:**

- Create: `tests/unit/test_setup_script_readme_consistency.py`
- Modify: `README.md` (lines 33 + the `:40-54` callout)

**Interfaces:**

- Consumes: `slice_shell_step` (Task 1).

- [ ] **Step 1: Write the failing consistency test**

Create `tests/unit/test_setup_script_readme_consistency.py`:

```python
"""README <-> setup.sh credential-gate consistency (#501).

An operator who follows the README quickstart must set every credential key that
``bin/alfred-setup.sh``'s gate requires. #501 fixed a drift where the README documented only
``ALFRED_QUARANTINE_PROVIDER_API_KEY`` while the gate ALSO rejects a missing/placeholder
``ALFRED_DEEPSEEK_API_KEY``, so a literal README-follower hit ``exit 1`` having provisioned
nothing. This is the durable drift-net: every credential key the gate flags must appear in
``README.md``. Parse-only — no bash, no Docker.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests._setup_script_helpers import slice_shell_step

_SETUP_SH = Path("bin/alfred-setup.sh")
_README = Path("README.md")
_GATE_STEP = "Validating .env credentials"
# A key the gate REQUIRES is one named in an ``add_config_problem "..."`` message: its absence
# or placeholder value is what pushes it into the accumulated failure report. Match only those
# lines so a merely-mentioned key (e.g. in a comment) is not counted as "required".
_KEY_RE = re.compile(r"ALFRED_[A-Z0-9_]*_API_KEY")


def _gate_required_keys() -> set[str]:
    block = slice_shell_step(_SETUP_SH, _GATE_STEP)
    keys: set[str] = set()
    for line in block.splitlines():
        if "add_config_problem" in line:
            keys.update(_KEY_RE.findall(line))
    return keys


def test_gate_requires_at_least_the_two_known_keys() -> None:
    # Anti-vacuous guard: if the regex/marker heuristic ever matches nothing, the consistency
    # test below would pass trivially. Pin the known floor.
    assert {"ALFRED_DEEPSEEK_API_KEY", "ALFRED_QUARANTINE_PROVIDER_API_KEY"} <= _gate_required_keys()


def test_readme_documents_every_gate_required_key() -> None:
    readme = _README.read_text()
    missing = sorted(k for k in _gate_required_keys() if k not in readme)
    assert not missing, (
        f"README.md does not document credential key(s) the setup.sh gate requires: {missing}. "
        f"A first-run operator following the README would hit the gate's exit 1. Document them "
        f"in the quickstart (#501)."
    )
```

- [ ] **Step 2: Run the test to verify it fails on the current README**

Run: `uv run pytest tests/unit/test_setup_script_readme_consistency.py -q`
Expected: `test_readme_documents_every_gate_required_key` FAILS —
`missing: ['ALFRED_DEEPSEEK_API_KEY']` (the current README never names it). The floor test passes.

- [ ] **Step 3: Fix the README — line 33 inline comment**

In `README.md`, replace the quickstart `cp` line:

```text
cp .env.example .env       # then set ALFRED_QUARANTINE_PROVIDER_API_KEY (see below)
```

with:

```text
cp .env.example .env       # then set ALFRED_DEEPSEEK_API_KEY + ALFRED_QUARANTINE_PROVIDER_API_KEY (see below)
```

- [ ] **Step 4: Fix the README — the provider-key callout**

Replace the entire existing callout block (the blockquote beginning
`> **A provider key is required before the first \`docker compose up -d\`.**` through
`> is genuinely optional.`) with this expanded version. It **adds** the DeepSeek key as a peer
requirement and **preserves** the existing accurate quarantine-key nuance (comms-gated
refuse-boot; the outside-compose caveat):

```text
> **Two provider keys are required before the first `docker compose up -d`.**
> `bin/alfred-setup.sh` validates both up front and refuses to proceed (exit 1), listing every
> problem at once, if either is missing or still a placeholder:
>
> - **`ALFRED_DEEPSEEK_API_KEY`** — the privileged (primary) LLM credential. It is a required
>   setting with no default (`src/alfred/config/settings.py`): the core cannot even construct
>   its settings without it, and it rejects the literal `sk-...` placeholder shipped in
>   `.env.example`. This key is required regardless of which comms adapters are enabled. Get one
>   from <https://platform.deepseek.com>.
> - **`ALFRED_QUARANTINE_PROVIDER_API_KEY`** — the credential for the quarantined half of the
>   dual-LLM split, which now makes real provider calls. With it unset the core exits 2
>   (`quarantine_provider_key_unset`) and crash-loops under `restart: unless-stopped`. This is
>   deliberate — a real client on a placeholder key would be a silently dead LLM — but it means
>   a keyless first run does not start. `bin/alfred-setup.sh` warns when the key is missing; it
>   cannot seed one for you.
>
> **Precisely:** the *quarantine*-key refuse-boot is gated on comms being enabled
> (`settings.comms_enabled_adapters`). With no adapters enabled there is no quarantine path, so
> that key is not needed and the core boots fine. That is not the quickstart above:
> `docker-compose.yaml` defaults `ALFRED_COMMS_ENABLED_ADAPTERS` to `["alfred_tui"]`, so the
> compose stack — the path this README documents — does enable comms and does require the key.
> (`ALFRED_DEEPSEEK_API_KEY` is required either way.) If you run the core outside compose with
> `ALFRED_COMMS_ENABLED_ADAPTERS` unset, only the quarantine key is genuinely optional.
```

- [ ] **Step 5: Run the consistency test + markdownlint**

Run: `uv run pytest tests/unit/test_setup_script_readme_consistency.py -q`
Expected: PASS (README now names `ALFRED_DEEPSEEK_API_KEY`).

Run: `npx -y markdownlint-cli2@0.22.1 "README.md"`
Expected: `0 error(s)` (mind MD032 blank lines around the `-` list inside the blockquote).

- [ ] **Step 6: Commit**

```bash
git add README.md tests/unit/test_setup_script_readme_consistency.py
git commit -m "docs: #501 document ALFRED_DEEPSEEK_API_KEY in the first-run quickstart

Both provider keys are required before the first boot; the setup.sh gate already
enforces both. Adds a README<->gate consistency drift-net test.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 3: Un-xfail `test_setup_sh_completes` to a full setup.sh run

Replace the strict-xfail placeholder-refusal with a full run on dummy keys, asserting exit 0 and a seeded operator. DRY the dummy-key env content in `_env.py`.

**Files:**

- Modify: `tests/e2e/_env.py` (add a `filename` param to `write_e2e_env_file`)
- Modify: `tests/e2e/test_first_run_boot.py` (un-xfail + full run + DB assertion; module docstring)

**Interfaces:**

- Consumes: `_env.write_e2e_env_file(dest_dir, *, filename=".env")`, `_env.scrub_env_secrets`, `_env.new_project_name`, `_compose.compose`, `_compose.down_project`, `_compose.REPO_ROOT`.

- [ ] **Step 1: DRY the env writer — add a `filename` param**

In `tests/e2e/_env.py`, change `write_e2e_env_file`'s signature and body to accept a filename (default preserves current callers):

```python
def write_e2e_env_file(dest_dir: Path, *, filename: str = "e2e.env") -> Path:
    """Write ``<dest_dir>/<filename>`` (per-run random GF password + dummy keys); return it.

    ``filename`` lets the setup.sh e2e test write the SAME dummy-key content as the worktree's
    ``.env`` (#501), so the full script sees non-placeholder credentials and passes its gate.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    env_path = dest_dir / filename
    lines = (
        f"GF_SECURITY_ADMIN_PASSWORD={secrets.token_hex(24)}",
        f"ALFRED_DEEPSEEK_API_KEY={DUMMY_KEY_SENTINEL}",
        f"ALFRED_QUARANTINE_PROVIDER_API_KEY={DUMMY_KEY_SENTINEL}",
        "ALFRED_ENVIRONMENT=production",
    )
    env_path.write_text("\n".join(lines) + "\n")
    env_path.chmod(0o600)
    return env_path
```

- [ ] **Step 2: Rewrite the test — remove xfail, run full setup.sh, assert exit 0 + seeded operator**

In `tests/e2e/test_first_run_boot.py`, delete the `@pytest.mark.xfail(strict=True, reason=...)` decorator on `test_setup_sh_completes` and replace the function body. Add `from tests.e2e import _posture` at the top of the module if not already imported inside the function (it is imported inside `test_core_is_healthy`; here import it inside `test_setup_sh_completes` too, or hoist to module scope). New body:

```python
def test_setup_sh_completes() -> None:
    # #501: the documented quickstart IS bin/alfred-setup.sh. Run the FULL script with
    # non-placeholder dummy keys (as test_core_is_healthy uses) in an ISOLATED detached worktree,
    # and assert it (1) exits 0 and (2) actually seeded the operator — a DB query against
    # setup.sh's OWN postgres, not the script's self-reported stdout. setup.sh starts its own
    # postgres and provisions (migrate, state.git seed, secret prime, hash_pepper, operator); it
    # does NOT boot the app services (`docker compose up -d` is a separate documented step), so
    # the cost is bounded. user add is guarded on has_operator and migration 0004 seeds the
    # operator, so setup.sh skips the create (no OperatorAlreadyExists — the #500 trap).
    from tests.e2e import _posture

    setup_project = _env.new_project_name()
    with tempfile.TemporaryDirectory(prefix="alfred-e2e-setup-") as tmp:
        worktree = Path(tmp) / "repo"
        add = ["git", "worktree", "add", "--detach", "--force", str(worktree), "HEAD"]
        subprocess.run(
            add, cwd=_compose.REPO_ROOT, capture_output=True, text=True, timeout=120.0, check=True
        )
        env_file = _env.write_e2e_env_file(worktree, filename=".env")
        try:
            run_setup = ["bash", str(worktree / "bin" / "alfred-setup.sh")]
            proc = subprocess.run(
                run_setup,
                cwd=worktree,
                capture_output=True,
                text=True,
                timeout=_SETUP_SH_TIMEOUT_S,
                check=False,
                env={**os.environ, "COMPOSE_PROJECT_NAME": setup_project},
            )
            setup_out = _env.scrub_env_secrets((proc.stdout or "") + (proc.stderr or ""), env_file)[
                -2000:
            ]
            assert proc.returncode == 0, f"setup.sh exit {proc.returncode}: {setup_out!r}"

            # Outcome, not self-report: setup.sh's own postgres holds a seeded operator row.
            # `authorization` is a Postgres reserved keyword -> double-quote it.
            op = _compose.compose(
                setup_project,
                "exec",
                "-T",
                "alfred-postgres",
                "psql",
                "-U",
                "alfred",
                "-d",
                "alfred",
                "-tAc",
                "select count(*) from users where \"authorization\"='operator'",
                env_file=env_file,
                check=False,
            )
            op_stderr = _env.scrub_env_secrets(op.stderr, env_file)[-400:]
            assert _posture._is_gate_seeded(op.stdout), (
                f"setup.sh did not seed an operator: psql count={op.stdout.strip()!r} "
                f"rc={op.returncode} stderr={op_stderr!r}"
            )
        finally:
            _compose.down_project(setup_project)
            remove = ["git", "worktree", "remove", "--force", str(worktree)]
            with contextlib.suppress(subprocess.SubprocessError):
                subprocess.run(
                    remove,
                    cwd=_compose.REPO_ROOT,
                    capture_output=True,
                    text=True,
                    timeout=60.0,
                    check=False,
                )
```

Notes for the implementer:
- `_posture._is_gate_seeded(s)` returns `s.strip().isdigit() and int(s.strip()) > 0` — exactly the "psql count > 0" parse we need; reuse it rather than re-implementing. If a reviewer objects to importing a `_`-prefixed name across modules, hoist that predicate to a public `positive_count(psql_stdout: str) -> bool` in `_posture.py` (and have `_is_gate_seeded` call it) instead of inlining.
- Do **not** keep the old `shutil.copyfile(".env.example", ".env")` line. `shutil` may become an unused import — remove it if so (ruff will flag it).
- `os`, `contextlib`, `tempfile`, `subprocess`, `Path` imports already exist in the module.

- [ ] **Step 3: Update the module docstring (last strict-xfail is gone)**

Replace the second paragraph of the module docstring in `tests/e2e/test_first_run_boot.py`:

```text
Baseline services are asserted healthy (regression net). The gateway graduated to a plain
asserted-healthy test at #499; core graduated (provisioned + posture-asserted) at #500. Only
the setup.sh assertion remains strict-xfail on its roadmap blocker — it reds via XPASS the
instant that blocker lands, forcing the assertion to tighten (Roadmap Step 4).
```

with:

```text
Baseline services are asserted healthy (regression net). The gateway graduated to a plain
asserted-healthy test at #499; core graduated (provisioned + posture-asserted) at #500; the
setup.sh assertion graduated to a full-run provisioning test at #501 (README/gate
reconciliation). No strict-xfail remains — the lane is fully green and ready for Step 5
(promote release-blocking; close #494/#469).
```

- [ ] **Step 4: Verify locally what can be verified off-Linux**

The e2e test itself is `pytest.mark.e2e` (nightly-only; needs Docker + Linux/bwrap) and will not run on this host. Verify the non-e2e pieces and that the module still imports:

Run: `uv run pytest tests/unit/e2e -q` (posture/services unit self-tests still pass)
Run: `uv run python -c "import tests.e2e.test_first_run_boot, tests.e2e._env"` (imports clean)
Expected: PASS / no ImportError. The full run is verified on the nightly (Task 4).

- [ ] **Step 5: Commit**

```bash
git add tests/e2e/_env.py tests/e2e/test_first_run_boot.py
git commit -m "test: #501 un-xfail test_setup_sh_completes — full setup.sh provisioning run

Runs the whole bin/alfred-setup.sh with dummy keys; asserts exit 0 and a seeded
operator (DB query). Removes the last strict-xfail on the #494 lane.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 4: Whole-suite gate + Linux nightly proof

- [ ] **Step 1: `make check`**

Run: `make check`
Expected: ruff, ruff format, mypy, pyright, and the unit suite all clean. (The e2e test does not run here.)

- [ ] **Step 2: markdownlint the docs touched**

Run: `npx -y markdownlint-cli2@0.22.1 "README.md" "docs/superpowers/**/*.md"`
Expected: `0 error(s)`.

- [ ] **Step 3: Push the branch + trigger the authoritative nightly**

```bash
git push -u origin 501-readme-setup-reconciliation
gh workflow run Nightly --ref 501-readme-setup-reconciliation
```

Wait for the End-to-end lane. Expected: `test_setup_sh_completes` **PASSES** (full setup.sh run, exit 0, operator seeded) and the rest of the #494 lane stays green. If it fails, root-cause deterministically (no retry papering — the #509 lesson); likely suspects: the psql query target/quoting, setup.sh's AppArmor step under the runner's sudo, or the worktree `.env` not being read by `docker compose` from the worktree cwd.

- [ ] **Step 4: Local mutation check of the drift-net (sanity, do not commit)**

Confirm the consistency test actually fails loud: temporarily delete `ALFRED_DEEPSEEK_API_KEY` from `README.md`, run
`uv run pytest tests/unit/test_setup_script_readme_consistency.py -q` → expect FAIL, then `git checkout README.md`.

---

## Self-Review (author checklist — run before handing off)

- **Spec coverage:** README fix (Task 2), consistency test (Task 2), `slice_shell_step` (Task 1), full-run un-xfail + DB assertion (Task 3), docstring/bookkeeping (Task 3), nightly proof (Task 4) — all present.
- **Placeholders:** none — every step has exact code/commands.
- **Type consistency:** `slice_shell_step(Path, str) -> str`, `write_e2e_env_file(Path, *, filename: str) -> Path`, `_is_gate_seeded(str) -> bool` used consistently across tasks.
- **Ordering:** Task 2 depends on Task 1 (`slice_shell_step`); Task 3 is independent; Task 4 gates all. No forward references.

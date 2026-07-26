# #501 — README/setup.sh First-Run Credential Reconciliation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Document both required provider keys in the README, prove README↔gate consistency with a drift-net unit test, un-xfail the #494 `test_setup_sh_completes` lane to a full setup.sh run **isolated from the session stack**, and graduate the lane's tally guard to its fully-green shape — closing the last strict-xfail so Step 5 can promote the lane.

**Architecture:** Docs + tests + a scoped CI edit. **No `src/alfred/**` change.** A `slice_shell_step` helper extracts setup.sh's credential-gate block; a unit test asserts every key the gate flags is documented in `README.md`; the e2e test runs the whole `bin/alfred-setup.sh` with dummy keys **in its own nightly step** (no `boot_stack`, no host-port 5432 collision) and verifies the provisioning outcome via a DB query (seeded operator) + a redirected hash_pepper artifact (a late step ran). The release-gating tally guard (`_assert_ran`) graduates from "expects one strict-xfail blocker" to "fully green," with a dedicated non-vacuity guard for the isolated setup step.

**Tech Stack:** Python 3.14, pytest, bash (setup.sh, read-only), Docker Compose (e2e nightly only), GitHub Actions, markdownlint.

**Spec:** `docs/superpowers/specs/2026-07-26-501-readme-setup-reconciliation-design.md`

**Review provenance:** the focused plan-review trio (test/security/devops) cleared the README fix, consistency test, `slice_shell_step`, and the DB-assertion query, and gave a definitive SAFE verdict on the psql-injection question (static literal, argv not shell). They found **C1** (host-port 5432 collision — the full run cannot share the session with `boot_stack`), **H1** (setup.sh's `run --rm` pulls up redis + a healthy gateway, not just postgres), and **M1** (setup.sh writes to the runner `$HOME`). This plan folds all findings plus the tally-guard graduation the reviewers did not reach.

## Global Constraints

- **No `src/alfred/**` change.** setup.sh's credential gate is correct and must not be modified.
- **Conventional Commits** with a literal `#501` after the colon in every commit subject.
- **Commit trailer** on every commit: `MrReasonable <4990954+MrReasonable@users.noreply.github.com>`.
- **`make check` clean** before any push (ruff, ruff format, mypy, pyright, unit tests).
- **Modern Python 3.14+**: PEP 604 unions, PEP 585 built-in generics; no `Optional[X]`, no `typing.List`. `from __future__ import annotations` atop new modules.
- **`authorization` is a Postgres reserved keyword** — always double-quote it in SQL (`"authorization"`).
- **`--strict-markers`** is in the repo pytest default: any new marker MUST be registered in `pyproject.toml [tool.pytest.ini_options] markers` or collection fails.
- **The e2e lane is nightly-only** (`pytest.mark.e2e`); the full-run change must be proven on the authoritative Linux nightly (`gh workflow run Nightly --ref <branch>`), not just static review (the #500 lesson).
- **No paper-only gates** (the #245 lesson): the isolated setup step must have an explicit "assert it RAN" guard — a marker typo or a silent skip must red, not green.
- **Markdown**: touched `docs/**` and `README.md` pass `markdownlint-cli2@0.22.1`.
- **README is English-only** (i18n rule 5); not human-gated.

## Subsystem Coverage Matrix

| Subsystem | Files | Owner agent |
| --- | --- | --- |
| Setup-script test seam | `tests/_setup_script_helpers.py`, `tests/unit/test_setup_script_helpers.py`, `tests/unit/test_setup_script_readme_consistency.py` | `alfred-test-engineer` |
| Operator docs / first-run UX | `README.md` | `alfred-docs-author` / `alfred-devex-reviewer` |
| e2e boot lane + tally guard (release-gating) | `tests/e2e/test_first_run_boot.py`, `tests/e2e/_env.py`, `tests/e2e/_posture.py`, `tests/e2e/_assert_ran.py`, `tests/e2e/conftest.py`, `tests/unit/e2e/test_assert_ran.py` | `alfred-test-engineer` |
| First-run security posture (credential handling, provisioning) | `test_setup_sh_completes` full run | `alfred-security-engineer` |
| CI (nightly split) | `.github/workflows/nightly.yml`, `pyproject.toml` | `alfred-devops-engineer` |

**Plan-level owner:** `alfred-test-engineer`. **Always-include reviewers:** architect, reviewer, test-engineer, security-engineer.

**Definition of Done:** README documents both keys; consistency drift-net reds on omission; `slice_shell_step` + `positive_count` unit-covered; `test_setup_sh_completes` un-xfail'd, runs the full setup.sh in an isolated nightly step, asserts exit 0 + seeded operator + a redirected hash_pepper artifact; `_assert_ran` graduated to fully-green (main) + a setup-lane guard; `make check` clean; proven green on the Linux nightly (both e2e steps).

---

## Task 1: `slice_shell_step` helper + unit coverage

Add a reusable, fail-loud helper that slices one `step "<title>"` block out of `bin/alfred-setup.sh`, mirroring `slice_shell_function`. Task 2's consistency test consumes it.

**Files:**

- Modify: `tests/_setup_script_helpers.py` (add `slice_shell_step`)
- Modify: `tests/unit/test_setup_script_helpers.py` (add cases)

**Interfaces:**

- Produces: `slice_shell_step(setup_sh: Path, step_title: str) -> str` — text from the `step "<step_title>"` marker line to (but not including) the next `step "` marker or EOF; raises `ValueError` if absent.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_setup_script_helpers.py` (it already has `_script(tmp_path, body)`, `pytest`, `Path`):

```python
from tests._setup_script_helpers import slice_shell_step


def test_slice_step_returns_block_up_to_next_step(tmp_path: Path) -> None:
    s = _script(
        tmp_path,
        'step "First"\necho one\nadd_config_problem "x"\nstep "Second"\necho two\n',
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

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/test_setup_script_helpers.py -q`
Expected: FAIL — `ImportError`/`AttributeError`, `slice_shell_step` undefined.

- [ ] **Step 3: Implement `slice_shell_step`**

Append to `tests/_setup_script_helpers.py`:

```python
def slice_shell_step(setup_sh: Path, step_title: str) -> str:
    """Return one ``step "<step_title>"`` block, sliced out of ``setup_sh``.

    Runs from the ``step "<step_title>"`` marker line to (but not including) the next top-level
    ``step "`` marker, or EOF. Anchoring on the exact title raises ``ValueError`` on a
    renamed/removed step rather than returning a stale/empty block — same fail-loud contract as
    :func:`slice_shell_function`. Matching ``step "`` (with the quote) skips the ``step()``
    function *definition*. For cross-document consistency tests that need a step's content.
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

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/unit/test_setup_script_helpers.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/_setup_script_helpers.py tests/unit/test_setup_script_helpers.py
git commit -m "test: #501 add slice_shell_step helper for setup.sh step blocks

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 2: README fix, proven by a README↔gate consistency drift-net

TDD the README fix: the consistency test reds because the README omits `ALFRED_DEEPSEEK_API_KEY`; fixing the README greens it. Broadened per test-review M1 so the drift-net matches its name.

**Files:**

- Create: `tests/unit/test_setup_script_readme_consistency.py`
- Modify: `README.md`

**Interfaces:** Consumes `slice_shell_step` (Task 1).

- [ ] **Step 1: Write the failing consistency test**

Create `tests/unit/test_setup_script_readme_consistency.py`:

```python
"""README <-> setup.sh credential-gate consistency (#501).

An operator following the README quickstart must set every credential the gate requires.
#501 fixed a drift where the README documented only ALFRED_QUARANTINE_PROVIDER_API_KEY while
the gate ALSO rejects a missing/placeholder ALFRED_DEEPSEEK_API_KEY, so a literal
README-follower hit exit 1 having provisioned nothing. Durable drift-net: every credential
the gate flags must appear in README.md. Parse-only — no bash, no Docker.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests._setup_script_helpers import slice_shell_step

_SETUP_SH = Path("bin/alfred-setup.sh")
_README = Path("README.md")
_GATE_STEP = "Validating .env credentials"
# A credential the gate REQUIRES is one named in an ``add_config_problem "..."`` message: its
# absence/placeholder is what pushes it into the accumulated failure report. Match ANY
# ALFRED_* token on those lines (not just *_API_KEY) so a future non-API credential (e.g. a
# token) added to the gate is caught by the drift-net too (test-review M1).
_CRED_RE = re.compile(r"ALFRED_[A-Z0-9_]+")


def _gate_required_credentials() -> set[str]:
    block = slice_shell_step(_SETUP_SH, _GATE_STEP)
    creds: set[str] = set()
    for line in block.splitlines():
        if "add_config_problem" in line:
            creds.update(_CRED_RE.findall(line))
    return creds


def test_gate_requires_at_least_the_two_known_keys() -> None:
    # Anti-vacuous floor: if the slice/marker heuristic ever matches nothing, the consistency
    # test would pass trivially. Pin the known floor.
    assert {"ALFRED_DEEPSEEK_API_KEY", "ALFRED_QUARANTINE_PROVIDER_API_KEY"} <= (
        _gate_required_credentials()
    )


def test_readme_documents_every_gate_required_credential() -> None:
    readme = _README.read_text()
    missing = sorted(c for c in _gate_required_credentials() if c not in readme)
    assert not missing, (
        f"README.md does not document credential(s) the setup.sh gate requires: {missing}. "
        f"A first-run operator following the README would hit the gate's exit 1. Document them "
        f"in the quickstart (#501)."
    )
```

Note: verify by inspection that the current gate's `add_config_problem` lines name only `ALFRED_DEEPSEEK_API_KEY` and `ALFRED_QUARANTINE_PROVIDER_API_KEY` (no stray `ALFRED_*` token that isn't a credential). If a future line references a non-credential `ALFRED_*` in an `add_config_problem`, that is a genuine "document it" signal, which is the drift-net working as intended.

- [ ] **Step 2: Run to verify failure on the current README**

Run: `uv run pytest tests/unit/test_setup_script_readme_consistency.py -q`
Expected: `test_readme_documents_every_gate_required_credential` FAILS — `missing: ['ALFRED_DEEPSEEK_API_KEY']`. Floor test passes.

- [ ] **Step 3: Fix README line 33 (inline comment)**

Replace:

```text
cp .env.example .env       # then set ALFRED_QUARANTINE_PROVIDER_API_KEY (see below)
```

with:

```text
cp .env.example .env       # then set ALFRED_DEEPSEEK_API_KEY + ALFRED_QUARANTINE_PROVIDER_API_KEY (see below)
```

- [ ] **Step 4: Fix README callout**

Replace the whole callout blockquote (from `> **A provider key is required before the first ...` through `> is genuinely optional.`) with:

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

- [ ] **Step 5: Run test + markdownlint**

Run: `uv run pytest tests/unit/test_setup_script_readme_consistency.py -q` → PASS.
Run: `npx -y markdownlint-cli2@0.22.1 "README.md"` → `0 error(s)` (mind MD032 around the `-` list inside the blockquote).

- [ ] **Step 6: Commit**

```bash
git add README.md tests/unit/test_setup_script_readme_consistency.py
git commit -m "docs: #501 document ALFRED_DEEPSEEK_API_KEY in the first-run quickstart

Both provider keys are required before first boot; the setup.sh gate already
enforces both. Adds a README<->gate consistency drift-net test.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 3: Hoist `positive_count` to a public `_posture` predicate

Per security-L3 / test-L1: the operator-count check reuses `_posture._is_gate_seeded` (private, and named for gate-seeding). Hoist the parse to a public, self-describing predicate; Task 4 uses it.

**Files:**

- Modify: `tests/e2e/_posture.py`
- Modify: `tests/unit/e2e/test_posture.py`

**Interfaces:** Produces `positive_count(psql_stdout: str) -> bool`.

- [ ] **Step 1: Add the failing test**

Append to `tests/unit/e2e/test_posture.py`:

```python
from tests.e2e._posture import positive_count


def test_positive_count_parses_positive_int() -> None:
    assert positive_count("3\n") is True


def test_positive_count_zero_is_false() -> None:
    assert positive_count("0") is False


def test_positive_count_nondigit_is_false() -> None:
    assert positive_count('ERROR:  relation "users" does not exist') is False
```

Run: `uv run pytest tests/unit/e2e/test_posture.py -q` → FAIL (`positive_count` undefined).

- [ ] **Step 2: Implement + rewire `_is_gate_seeded`**

In `tests/e2e/_posture.py`, add the public predicate and make `_is_gate_seeded` delegate (keeps its call sites + tests working):

```python
def positive_count(psql_stdout: str) -> bool:
    """A psql ``count(*)`` reply parses as a strictly-positive integer.

    No I/O — takes captured stdout so it is unit-testable without a container. A non-digit
    reply (e.g. a psql error) or a zero count both read as False.
    """
    stripped = psql_stdout.strip()
    return stripped.isdigit() and int(stripped) > 0
```

Then change `_is_gate_seeded` to:

```python
def _is_gate_seeded(psql_stdout: str) -> bool:
    """The plugin_grants ``count(*)`` reply parses as a positive integer (>0 rows seeded)."""
    return positive_count(psql_stdout)
```

- [ ] **Step 3: Verify**

Run: `uv run pytest tests/unit/e2e/test_posture.py -q` → PASS (new + existing `_is_gate_seeded` cases).

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/_posture.py tests/unit/e2e/test_posture.py
git commit -m "test: #501 hoist positive_count to a public _posture predicate

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 4: Un-xfail `test_setup_sh_completes` — isolated full setup.sh run

Full run on dummy keys, in its own marked test, asserting exit 0 + a seeded operator + a redirected hash_pepper artifact (a late provisioning step ran). DRY the env writer; register the marker.

**Files:**

- Modify: `tests/e2e/_env.py` (add `filename` param)
- Modify: `pyproject.toml` (register the `e2e_full_setup` marker)
- Modify: `tests/e2e/test_first_run_boot.py` (marker + un-xfail + full run + assertions; module docstring)

**Interfaces:** Consumes `_env.write_e2e_env_file(dest_dir, *, filename=".env")`, `_env.scrub_env_secrets`, `_env.new_project_name`, `_posture.positive_count`, `_compose.compose`, `_compose.down_project`, `_compose.REPO_ROOT`.

- [ ] **Step 1: DRY the env writer**

In `tests/e2e/_env.py`, add a `filename` keyword (default preserves the sole existing caller in conftest):

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

- [ ] **Step 2: Register the `e2e_full_setup` marker**

In `pyproject.toml` `[tool.pytest.ini_options] markers`, add (next to the `e2e:` entry):

```toml
  "e2e_full_setup: the isolated full bin/alfred-setup.sh provisioning run (nightly-only). Runs in its OWN pytest session — it boots its own postgres+redis+gateway and would collide on host port 5432 with the session-scoped boot_stack, so it is deselected from the main e2e step and run in a dedicated nightly step (#501).",
```

- [ ] **Step 3: Rewrite the test — marker, un-xfail, full run, assertions**

In `tests/e2e/test_first_run_boot.py`, delete the `@pytest.mark.xfail(strict=True, reason=...)` decorator and replace the function. Add the module import `import tempfile`/`os`/`contextlib` already present; the body imports `_posture` locally as `test_core_is_healthy` does:

```python
@pytest.mark.e2e_full_setup
def test_setup_sh_completes(tmp_path: Path) -> None:
    # #501: the documented quickstart IS bin/alfred-setup.sh. Run the FULL script with
    # non-placeholder dummy keys (as test_core_is_healthy uses) in an ISOLATED detached worktree.
    # It runs in its OWN nightly pytest session (marker e2e_full_setup, deselected from the main
    # e2e step): setup.sh's `run --rm alfred-core ...` calls do NOT pass --no-deps, so they pull
    # up redis AND a (keyless-healthy, #499) gateway, and `up -d alfred-postgres` publishes host
    # 5432 — which would collide with the session-scoped boot_stack postgres if co-run. Asserts
    # (1) exit 0 (setup.sh `fail`s loudly on any step, so exit 0 gates migrate->seed->prime->
    # hash_pepper->operator), (2) a seeded operator (DB query, not the script's stdout), and
    # (3) a redirected hash_pepper artifact (a LATE step ran). user add is has_operator-guarded
    # and migration 0004 seeds the operator, so setup.sh skips create (no OperatorAlreadyExists,
    # the #500 trap). ALFRED_SECRETS_FILE redirects the real pepper secret into tmp_path (M1:
    # hermeticity — the pepper does not land in the runner $HOME) and gives us the artifact.
    from tests.e2e import _posture

    setup_project = _env.new_project_name()
    secrets_file = tmp_path / "secrets.toml"
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
                env={
                    **os.environ,
                    "COMPOSE_PROJECT_NAME": setup_project,
                    "ALFRED_SECRETS_FILE": str(secrets_file),
                },
            )
            setup_out = _env.scrub_env_secrets((proc.stdout or "") + (proc.stderr or ""), env_file)[
                -2000:
            ]
            assert proc.returncode == 0, f"setup.sh exit {proc.returncode}: {setup_out!r}"

            # (2) Outcome, not self-report: setup.sh's own postgres holds a seeded operator row.
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
            op_out = _env.scrub_env_secrets(op.stdout, env_file)
            op_stderr = _env.scrub_env_secrets(op.stderr, env_file)[-400:]
            assert _posture.positive_count(op.stdout), (
                f"setup.sh did not seed an operator: psql count={op_out.strip()!r} "
                f"rc={op.returncode} stderr={op_stderr!r}"
            )

            # (3) A late step ran: the hash_pepper bootstrap wrote the redirected secrets file.
            assert secrets_file.is_file() and "audit.hash_pepper" in secrets_file.read_text(), (
                "setup.sh did not bootstrap audit.hash_pepper into ALFRED_SECRETS_FILE — the "
                "provisioning did not reach the late secret-seed step."
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

Notes:

- Remove the old `shutil.copyfile(".env.example", ".env")` line; if `shutil` becomes unused, drop the import (ruff will flag it).
- `os`, `contextlib`, `tempfile`, `subprocess`, `Path`, `pytest` imports already exist in the module.
- `op.stdout` is now scrubbed too (security-L1). The count is harmless, but keep the scrub-everything discipline.

- [ ] **Step 4: Update the module docstring**

Replace the second paragraph of the module docstring:

```text
Baseline services are asserted healthy (regression net). The gateway graduated to a plain
asserted-healthy test at #499; core graduated (provisioned + posture-asserted) at #500; the
setup.sh assertion graduated to a full-run provisioning test at #501, run in its OWN nightly
step (marker `e2e_full_setup`) so it does not collide with the session-scoped boot_stack. No
strict-xfail remains — the lane is fully green and ready for Step 5 (promote release-blocking;
close #494/#469).
```

- [ ] **Step 5: Verify off-Linux (imports + marker registration)**

Run: `uv run pytest tests/e2e -o addopts='' --collect-only -q 2>&1 | tail -5` — collection succeeds; `test_setup_sh_completes` collects (marker registered). No `--strict-markers` error.
Run: `uv run pytest tests/unit/e2e -q` — posture/services unit self-tests pass.
(The e2e test itself is nightly-only; it runs in Task 7.)

- [ ] **Step 6: Commit**

```bash
git add tests/e2e/_env.py tests/e2e/test_first_run_boot.py pyproject.toml
git commit -m "test: #501 un-xfail test_setup_sh_completes as an isolated full run

Runs the whole bin/alfred-setup.sh with dummy keys in its own e2e_full_setup
lane; asserts exit 0, a seeded operator, and a redirected hash_pepper artifact.
Removes the last strict-xfail on the #494 lane.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 5: Graduate the tally guard to fully-green + add a setup-lane guard

The last blocker is gone, so the main lane has **zero** xfails: `_assert_ran`'s `xfailed >= 1` (satisfied today only by setup.sh's xfail) and `_MIN_COLLECTED = MIN_SERVICE_FLOOR + 1` (the +1 was setup.sh) must graduate. Add a non-vacuity guard for the isolated setup step (#245). Make the conftest tally path env-configurable so the two nightly steps write distinct tallies.

**Files:**

- Modify: `tests/e2e/conftest.py` (env-configurable `_TALLY_PATH`)
- Modify: `tests/e2e/_assert_ran.py` (graduate boot lane; add setup-lane guard + CLI)
- Modify: `tests/unit/e2e/test_assert_ran.py` (rewrite fixtures/assertions for the graduated shape)

**Interfaces:** Produces `assert_setup_lane_tally(tally_path: Path)`; `main(["--setup", tally])` path.

- [ ] **Step 1: Rewrite the failing unit tests for the graduated shape**

In `tests/unit/e2e/test_assert_ran.py`, replace the fixtures + the xfail assertion so the boot lane is now fully-green (no xfails) and add setup-lane cases. Key changes:

```python
from tests.e2e._assert_ran import (
    assert_boot_lane_tally,
    assert_setup_lane_tally,
    main,
    write_tally,
)

# Graduated boot lane (#501): fully green, NO xfails. 7 passes (4 baseline + classify +
# gateway + core), 0 xfailed.
_HEALTHY = {
    "collected": 7,
    "passed": 7,
    "failed": 0,
    "error": 0,
    "skipped": 0,
    "xfailed": 0,
    "xpassed": 0,
}
_REGRESSION = {**_HEALTHY, "passed": 6, "failed": 1}
_LEAKED_XFAIL = {**_HEALTHY, "passed": 6, "xfailed": 1}  # a strict-xfail reappeared -> red
_COLLAPSED = {k: 0 for k in _HEALTHY}
_PLAIN_SKIP = {**_HEALTHY, "passed": 6, "skipped": 1}
_ERRORED = {**_HEALTHY, "error": 2}

# Setup lane: exactly one genuine pass.
_SETUP_OK = {
    "collected": 1, "passed": 1, "failed": 0, "error": 0,
    "skipped": 0, "xfailed": 0, "xpassed": 0,
}
_SETUP_SKIPPED = {**_SETUP_OK, "passed": 0, "skipped": 1}
_SETUP_NONE = {k: 0 for k in _SETUP_OK}
_SETUP_FAILED = {**_SETUP_OK, "passed": 0, "failed": 1}
```

Update `test_healthy_tally_passes` to use the new `_HEALTHY`; replace `test_xfailed_zero_assertion` (which asserted xfailed==0 REDS) with its inverse:

```python
def test_leaked_xfail_reds(tmp_path: Path) -> None:
    """A reappearing strict-xfail (blocker regressed) must red — the lane is fully green now."""
    with pytest.raises(AssertionError, match="fully green|xfail"):
        assert_boot_lane_tally(_write(tmp_path, _LEAKED_XFAIL))
```

Update the `test_bad_tally_reds` parametrize list to `[_REGRESSION, _LEAKED_XFAIL, _COLLAPSED, _PLAIN_SKIP, _ERRORED]`. Add setup-lane tests:

```python
def test_setup_lane_ok(tmp_path: Path) -> None:
    assert_setup_lane_tally(_write(tmp_path, _SETUP_OK))  # no raise


@pytest.mark.parametrize("counts", [_SETUP_SKIPPED, _SETUP_NONE, _SETUP_FAILED])
def test_setup_lane_reds(tmp_path: Path, counts: Mapping[str, int]) -> None:
    with pytest.raises(AssertionError):
        assert_setup_lane_tally(_write(tmp_path, counts))


def test_main_setup_flag_ok(tmp_path: Path) -> None:
    assert main(["--setup", str(_write(tmp_path, _SETUP_OK))]) == 0


def test_main_setup_flag_reds(tmp_path: Path) -> None:
    assert main(["--setup", str(_write(tmp_path, _SETUP_NONE))]) == 1
```

Keep `test_write_tally_roundtrips`, `test_main_missing_file`, `test_main_bad_usage`, `test_main_with_healthy_tally`, `test_main_with_bad_tally`, `test_main_with_corrupt_tally_reds` (update their fixtures to the new `_HEALTHY`/`_REGRESSION`).

Run: `uv run pytest tests/unit/e2e/test_assert_ran.py -q` → FAIL (`assert_setup_lane_tally` undefined; graduated assertions not yet in place).

- [ ] **Step 2: Graduate `_assert_ran.py`**

Update `tests/e2e/_assert_ran.py`:

```python
from tests.e2e._services import MIN_SERVICE_FLOOR

# The main boot lane collects the service/app health checks (>= the service floor). The
# setup.sh full run graduated to its OWN lane at #501, so it is no longer the "+1" here.
_MIN_COLLECTED = MIN_SERVICE_FLOOR
_KEYS = ("collected", "passed", "failed", "error", "skipped", "xfailed", "xpassed")
```

Replace the `xfailed >= 1` assertion in `assert_boot_lane_tally` with the graduated invariant:

```python
    assert t["xfailed"] == 0, (
        f"{t['xfailed']} xfail(s) — the lane graduated to fully green at #501; a reappearing "
        f"strict-xfail means a blocker regressed or a new one was added without its own lane."
    )
    assert t["passed"] >= _MIN_COLLECTED, (
        f"only {t['passed']} passes — below the service floor {_MIN_COLLECTED}; a baseline "
        f"check did not run or did not pass."
    )
```

(Keep `collected >= _MIN_COLLECTED`, `failed == 0`, `error == 0`, `skipped == 0`, `xpassed == 0`. Remove the old `passed >= 1` / `xfailed >= 1` lines — superseded by the two above.)

Add the setup-lane guard:

```python
def assert_setup_lane_tally(tally_path: Path) -> None:
    """Raise unless the isolated full-setup lane ran exactly one genuine pass (#245 non-vacuity).

    A marker typo -> 0 collected -> red; a silent skip -> skipped>0 -> red. The lane must never
    skip-green.
    """
    raw = json.loads(tally_path.read_text())
    t = {k: int(raw.get(k, 0)) for k in _KEYS}
    assert t["collected"] == 1, f"setup lane collected {t['collected']} (expected exactly 1)."
    assert t["passed"] == 1, f"setup lane passed {t['passed']} (expected 1) — did it run?"
    for bad in ("failed", "error", "skipped", "xfailed", "xpassed"):
        assert t[bad] == 0, f"setup lane {bad}={t[bad]} (expected 0)."
```

Update `main` to accept an optional `--setup` flag:

```python
def main(argv: Sequence[str]) -> int:
    args = list(argv)
    setup = False
    if args and args[0] == "--setup":
        setup = True
        args = args[1:]
    if len(args) != 1:
        print("usage: python -m tests.e2e._assert_ran [--setup] <tally.json>", file=sys.stderr)
        return 2
    tally = Path(args[0])
    if not tally.is_file():
        print(f"tally file {tally} missing — pytest never wrote it (session errored?)", file=sys.stderr)
        return 1
    check = assert_setup_lane_tally if setup else assert_boot_lane_tally
    try:
        check(tally)
    except (AssertionError, json.JSONDecodeError) as exc:
        print(f"e2e {'setup' if setup else 'boot'}-lane tally FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"e2e {'setup' if setup else 'boot'}-lane tally OK")
    return 0
```

- [ ] **Step 3: Make the conftest tally path env-configurable**

In `tests/e2e/conftest.py`, add `import os` (alongside the existing stdlib imports) and change:

```python
_TALLY_PATH = Path(os.environ.get("ALFRED_E2E_TALLY_PATH", "e2e-tally.json"))
```

- [ ] **Step 4: Verify**

Run: `uv run pytest tests/unit/e2e/test_assert_ran.py -q` → PASS.
Run: `uv run pytest tests/unit/e2e -q` → PASS (posture + services + assert_ran).

- [ ] **Step 5: Commit**

```bash
git add tests/e2e/_assert_ran.py tests/e2e/conftest.py tests/unit/e2e/test_assert_ran.py
git commit -m "test: #501 graduate the e2e tally guard to fully-green + setup-lane guard

The last strict-xfail is gone: boot lane now asserts xfailed==0; add an
assert_setup_lane_tally non-vacuity guard for the isolated setup step; make the
conftest tally path env-configurable for the two nightly steps.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 6: Split the nightly e2e run — main lane + isolated setup lane

**Files:** Modify `.github/workflows/nightly.yml`.

**Interfaces:** Consumes the `e2e_full_setup` marker (Task 4) + `ALFRED_E2E_TALLY_PATH` (Task 5) + `main --setup` (Task 5).

- [ ] **Step 1: Split the run step + guards**

Replace the single e2e run + assert steps. The main step deselects the setup marker; a new step runs the setup lane in isolation (fresh pytest session → no `boot_stack` → no 5432 holder) with its own tally + guard. Keep `-o addopts=''` (clears the repo `-m "not real_llm"` default) and the `AppArmor profile load` pre-step (already present) — the full run needs it.

Give the AppArmor-load pre-step an `id: load_apparmor`. The isolated setup RUN + ASSERT gate on
`!cancelled()` (independent of the boot *pytest* outcome, but a cancellation stops the expensive
lane) **and** on `steps.load_apparmor.conclusion == 'success'` (skip if the infra setup broke, so
the always-independent assert can't red on a never-written tally). `!cancelled()` must be wrapped
in `${{ }}` — a bare leading `!` is an invalid YAML tag.

```yaml
      - name: Run the e2e boot lane (services + core/gateway; setup runs separately)
        if: steps.check.outputs.has_e2e == 'true'
        run: uv run pytest tests/e2e -o addopts='' -m 'not e2e_full_setup'
      - name: Assert the boot-lane tally is non-vacuous
        if: always() && steps.check.outputs.has_e2e == 'true'
        run: uv run python -m tests.e2e._assert_ran e2e-tally.json
      - name: Run the isolated full setup.sh provisioning lane (#501)
        # Its OWN pytest session — never instantiates the session-scoped boot_stack, so
        # setup.sh's `up -d alfred-postgres` (host 5432) does not collide. Distinct tally file.
        if: ${{ !cancelled() && steps.check.outputs.has_e2e == 'true' && steps.load_apparmor.conclusion == 'success' }}
        env:
          ALFRED_E2E_TALLY_PATH: e2e-setup-tally.json
        run: uv run pytest tests/e2e -o addopts='' -m 'e2e_full_setup'
      - name: Assert the setup-lane ran (non-vacuity, #245)
        if: ${{ !cancelled() && steps.check.outputs.has_e2e == 'true' && steps.load_apparmor.conclusion == 'success' }}
        run: uv run python -m tests.e2e._assert_ran --setup e2e-setup-tally.json
```

Confirm against the real `nightly.yml`: preserve the existing `has_e2e` gating, the `Assert ... tally` pattern, the `Upload diagnostics on failure` step (extend its `if:` / artifact list to also cover `e2e-setup-tally.json` if it uploads tally files), and step ordering relative to the AppArmor-load pre-step. Adjust names/indentation to match the file.

- [ ] **Step 2: Lint the workflow**

Run: `python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/nightly.yml'))"` → no error (valid YAML). If `actionlint` is available locally, run it.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/nightly.yml
git commit -m "ci: #501 run the full setup.sh e2e lane in an isolated nightly step

Deselect e2e_full_setup from the main e2e step (host-5432 collision with the
session-scoped boot_stack) and run it in its own session with a dedicated tally
+ non-vacuity guard.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 7: Whole-suite gate + Linux nightly proof

- [ ] **Step 1: `make check`**

Run: `make check` → ruff, ruff format, mypy, pyright, unit suite all clean. (e2e does not run here.)

- [ ] **Step 2: markdownlint**

Run: `npx -y markdownlint-cli2@0.22.1 "README.md" "docs/superpowers/**/*.md"` → `0 error(s)`.

- [ ] **Step 3: Drift-net mutation check (author verification, do not commit)**

Temporarily delete `ALFRED_DEEPSEEK_API_KEY` from `README.md`; run
`uv run pytest tests/unit/test_setup_script_readme_consistency.py -q` → expect FAIL; then `git checkout README.md`.

- [ ] **Step 4: Push + trigger the authoritative nightly**

```bash
git push -u origin 501-readme-setup-reconciliation
gh workflow run Nightly --ref 501-readme-setup-reconciliation
```

Wait for BOTH e2e steps. Expected: the main boot lane green (tally graduated, `xfailed==0`); the isolated setup lane green (`test_setup_sh_completes` passes: setup.sh exits 0, operator seeded, hash_pepper artifact present); the setup-lane non-vacuity guard OK. If red, root-cause deterministically (no retry papering — the #509 lesson). Likely suspects: the gateway dep not reaching healthy under dummy keys (H1 — should be fine per #499, confirm), the AppArmor reload, or the psql target/quoting.

---

## Self-Review (author checklist)

- **Spec coverage:** README fix (T2), consistency drift-net (T2), `slice_shell_step` (T1), `positive_count` hoist (T3), isolated full-run + operator + pepper assertions (T4), tally graduation + setup guard (T5), nightly split (T6), nightly proof (T7).
- **Findings folded:** C1 (isolation via marker + separate nightly session), H1 (comment + budget acknowledge the 3-service boot), M1 (`ALFRED_SECRETS_FILE` redirects the pepper), test-M1 (broadened drift-net regex + rename), sec-L1 (scrub `op.stdout`), sec-L3/test-L1 (public `positive_count`), test-L2 (pepper artifact = independent late-step signal, exit-0 is the primary gate).
- **Unavoidable-for-#501:** the `xfailed >= 1 -> == 0` graduation + `_MIN_COLLECTED` drop-`+1` are forced by removing the last blocker, independent of the isolation choice.
- **Placeholders:** none — every step has exact code/commands.
- **Type consistency:** `slice_shell_step(Path,str)->str`, `positive_count(str)->bool`, `assert_setup_lane_tally(Path)->None`, `write_e2e_env_file(Path,*,filename:str)->Path` used consistently.
- **Ordering:** T1→T2 (consistency needs the helper); T3 before T4 (`positive_count`); T4 before T5/T6 (marker + tally interplay); T5 before T6 (guard + tally-path before the workflow calls them); T7 gates all.

# Gitignore-Aware `.git`-Walk Narrowing (#366) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Narrow the secrets-file `.git`-in-parent boot refusal, for the layer-3 canonical XDG path only, to a gitignore-aware refusal — so a correctly-`.gitignore`'d secret in a versioned `~/.config` boots while an un-ignored one still refuses.

**Architecture:** Thread layer provenance out of `_resolve_secrets_path`, add an authoritative `git check-ignore` helper (fail-closed on absent/error/timeout), and gate the existing construction refusal so the settings-default layer allows a gitignored secret (warn-and-proceed) while kwarg/`ALFRED_SECRETS_FILE` keep the full always-refuse walk.

**Tech Stack:** Python 3.12+, `subprocess` (git check-ignore), structlog, pytest with real tmp `git init` repos.

## Global Constraints

- **Narrowing applies to `settings_default` (layer-3) ONLY.** kwarg + `ALFRED_SECRETS_FILE` layers keep the current full always-refuse walk.
- **Fail-closed** (CLAUDE.md hard rule #7): git absent / error (exit ≠ 0,1) / timeout → treat as NOT ignored → refuse.
- **Authoritative check only** — `git check-ignore`, never a hand-rolled `.gitignore` parser (false-"ignored" = security hole).
- **No `shell=True`**; args as a list; `--` before the path; `capture_output=True`.
- **Warn-and-proceed** on the allowed path: a structlog event `secrets.file_in_git_repo_but_ignored` (structured key + kwargs, NO `t()` — matches the existing `redactor.pattern_overflow` idiom). The refusal message stays `t("secrets.file_in_git_repo", ...)`.
- Touches `src/alfred/security/` → **release-blocking adversarial suite** + 100% line+branch coverage on the new code.
- Commit subjects contain a literal `#366`. Trailer: `MrReasonable <4990954+MrReasonable@users.noreply.github.com>`.

---

### Task 1: Provenance threading in `_resolve_secrets_path`

**Files:**

- Modify: `src/alfred/security/secrets.py` (`_resolve_secrets_path` ~234; the `__init__` caller ~387)
- Test: `tests/unit/security/test_secrets.py` (the 6 existing `_resolve_secrets_path` call sites ~213-247, 644)

**Interfaces:**

- Produces: `_resolve_secrets_path(constructor_arg, env, settings_default) -> tuple[Path | None, _SecretsLayer]` where `_SecretsLayer = Literal["constructor", "env", "settings_default"] | None` (`None` iff the path is `None`).

- [ ] **Step 1: Update the existing resolve tests to expect the tuple**

In `tests/unit/security/test_secrets.py`, the existing tests call `out = _resolve_secrets_path(...)` and assert on the path. Update each to unpack + assert the layer. Example (the constructor-wins test ~213):

```python
def test_constructor_override_wins(self, tmp_path: Path) -> None:
    override = tmp_path / "override.toml"
    path, layer = _resolve_secrets_path(override, {"ALFRED_SECRETS_FILE": "/env"}, Path("/default"))
    assert path == override
    assert layer == "constructor"
```

Mirror for: env-wins → `layer == "env"`; settings-default → `layer == "settings_default"`; all-unset → `(None, None)`; empty-env-value-treated-as-unset → falls through to settings_default layer.

- [ ] **Step 2: Run — expect FAIL (tuple unpack / layer assert)**

Run: `uv run pytest tests/unit/security/test_secrets.py -k resolve -q`
Expected: FAIL (current function returns a bare `Path | None`, not a tuple).

- [ ] **Step 3: Change `_resolve_secrets_path` to return `(path, layer)`**

```python
_SecretsLayer = Literal["constructor", "env", "settings_default"] | None


def _resolve_secrets_path(
    constructor_arg: Path | None,
    env: Mapping[str, str],
    settings_default: Path | None,
) -> tuple[Path | None, _SecretsLayer]:
    """Return ``(path, layer)`` honouring the layered precedence.

    Pure (no I/O). ``layer`` names which layer produced the path
    (``"constructor"`` / ``"env"`` / ``"settings_default"``) and is ``None``
    iff the path is ``None`` (env-only backend). #366 uses ``layer`` to apply
    the gitignore-aware ``.git``-walk narrowing to the ``settings_default``
    (XDG default) layer only.
    """
    if constructor_arg is not None:
        return constructor_arg, "constructor"
    env_value = env.get("ALFRED_SECRETS_FILE")
    if env_value:
        return Path(env_value), "env"
    if settings_default is not None:
        return settings_default, "settings_default"
    return None, None
```

Add `Literal` to the `typing` import if not present (it imports `TYPE_CHECKING, Final` — add `Literal`).

- [ ] **Step 4: Update the `__init__` caller (~387)**

```python
        self._secrets_file_path, self._secrets_path_layer = _resolve_secrets_path(
            secrets_file, self._env, settings_default
        )
```

Store `self._secrets_path_layer: _SecretsLayer` (used by the Task-3 narrowing). Add a `# noqa`-free type annotation on the attribute if the class annotates its attrs; otherwise the inline assignment is fine (mypy infers).

- [ ] **Step 5: Run resolve tests + mypy → PASS**

Run: `uv run pytest tests/unit/security/test_secrets.py -k resolve -q && uv run mypy src/alfred/security/secrets.py`
Expected: PASS + `Success`.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/security/secrets.py tests/unit/security/test_secrets.py
git commit -m "refactor(security): thread secrets-path layer provenance out of _resolve_secrets_path (#366)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 2: `_secret_is_gitignored` authoritative helper

**Files:**

- Modify: `src/alfred/security/secrets.py` (add `import subprocess`; new constant + helper near `_walk_for_git_parent` ~256)
- Test: `tests/unit/security/test_secrets.py`

**Interfaces:**

- Produces: `_secret_is_gitignored(repo: Path, secrets_path: Path) -> bool` — True iff `secrets_path` is git-ignored within `repo`; False (→ caller refuses) on git-absent / error / timeout.

- [ ] **Step 1: Write failing tests (real tmp git repos + fault injection)**

Add a helper + tests to `tests/unit/security/test_secrets.py`:

```python
import subprocess as _subprocess


def _git_init(repo: Path) -> None:
    _subprocess.run(["git", "init", "-q", str(repo)], check=True)


class TestSecretIsGitignored:
    def test_true_when_gitignored(self, tmp_path: Path) -> None:
        from alfred.security.secrets import _secret_is_gitignored

        repo = tmp_path / "repo"
        repo.mkdir()
        _git_init(repo)
        (repo / ".gitignore").write_text("secrets.toml\n")
        secret = repo / "secrets.toml"
        secret.write_text("x")
        assert _secret_is_gitignored(repo, secret) is True

    def test_false_when_not_gitignored(self, tmp_path: Path) -> None:
        from alfred.security.secrets import _secret_is_gitignored

        repo = tmp_path / "repo"
        repo.mkdir()
        _git_init(repo)
        secret = repo / "secrets.toml"
        secret.write_text("x")
        assert _secret_is_gitignored(repo, secret) is False

    def test_false_when_git_absent(self, tmp_path: Path, monkeypatch) -> None:
        from alfred.security import secrets as secrets_module

        def _raise(*_a, **_k):
            raise FileNotFoundError("git not found")

        monkeypatch.setattr(secrets_module.subprocess, "run", _raise)
        assert secrets_module._secret_is_gitignored(tmp_path, tmp_path / "s.toml") is False

    def test_false_on_timeout(self, tmp_path: Path, monkeypatch) -> None:
        from alfred.security import secrets as secrets_module

        def _raise(*_a, **_k):
            raise secrets_module.subprocess.TimeoutExpired(cmd="git", timeout=5.0)

        monkeypatch.setattr(secrets_module.subprocess, "run", _raise)
        assert secrets_module._secret_is_gitignored(tmp_path, tmp_path / "s.toml") is False

    def test_false_on_git_error_exit(self, tmp_path: Path, monkeypatch) -> None:
        from alfred.security import secrets as secrets_module

        class _R:
            returncode = 128

        monkeypatch.setattr(secrets_module.subprocess, "run", lambda *_a, **_k: _R())
        assert secrets_module._secret_is_gitignored(tmp_path, tmp_path / "s.toml") is False
```

- [ ] **Step 2: Run — expect FAIL (helper not defined)**

Run: `uv run pytest tests/unit/security/test_secrets.py::TestSecretIsGitignored -q`
Expected: FAIL — `AttributeError` / `ImportError` (`_secret_is_gitignored` not defined).

- [ ] **Step 3: Implement the helper**

Add `import subprocess` to the imports (after `import stat`). Add near `_walk_for_git_parent`:

```python
_GIT_CHECK_IGNORE_TIMEOUT_S: Final[float] = 5.0


def _secret_is_gitignored(repo: Path, secrets_path: Path) -> bool:
    """Return True iff ``secrets_path`` is git-ignored within ``repo``.

    Authoritative: shells out to ``git check-ignore`` (honours nested
    ``.gitignore``, ``.git/info/exclude``, ``core.excludesFile``). A hand-rolled
    parser is deliberately NOT used — a false "ignored" verdict would let a
    committable secret boot. Fail-closed: returns False (→ the caller refuses)
    if git is absent, errors, or times out. No ``shell=True``; ``--`` guards a
    path that starts with ``-``; git chatter is captured, not echoed.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "check-ignore", "--quiet", "--", str(secrets_path)],
            capture_output=True,
            timeout=_GIT_CHECK_IGNORE_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0
```

- [ ] **Step 4: Run → PASS**

Run: `uv run pytest tests/unit/security/test_secrets.py::TestSecretIsGitignored -q`
Expected: PASS (5 tests). NOTE: `test_true_when_gitignored` / `test_false_when_not_gitignored` require the `git` binary — CI Linux has it; skip guard not needed (dev + CI both have git; if a runner lacks git the real-repo tests error loudly, which is correct signal).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/security/secrets.py tests/unit/security/test_secrets.py
git commit -m "feat(security): authoritative git check-ignore helper, fail-closed (#366)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 3: Gitignore-aware narrowing at the construction walk

**Files:**

- Modify: `src/alfred/security/secrets.py` (the construction git-walk ~425-437)
- Test: `tests/unit/security/test_secrets.py`

**Interfaces:**

- Consumes: `self._secrets_path_layer` (Task 1), `_walk_for_git_parent`, `_secret_is_gitignored` (Task 2).

- [ ] **Step 1: Write failing construction tests (real tmp git repos)**

```python
class TestGitWalkNarrowing:
    def _repo_with_secret(self, tmp_path: Path, *, gitignored: bool) -> Path:
        repo = tmp_path / "dotfiles"
        repo.mkdir()
        _git_init(repo)
        if gitignored:
            (repo / ".gitignore").write_text("secrets.toml\n")
        secret = repo / "secrets.toml"
        secret.write_text('discord_bot_token = "x"\n')
        secret.chmod(0o600)
        return secret

    def test_layer3_gitignored_boots_with_warning(self, tmp_path: Path) -> None:
        """#366: a layer-3 secret that IS gitignored boots (warn-and-proceed)."""
        secret = self._repo_with_secret(tmp_path, gitignored=True)
        # settings_default layer + no allow flag → the narrowing applies.
        broker = SecretBroker(env={}, settings_default=secret)
        assert broker.secrets_file_path == secret  # booted, did not raise

    def test_layer3_not_gitignored_refuses(self, tmp_path: Path) -> None:
        secret = self._repo_with_secret(tmp_path, gitignored=False)
        with pytest.raises(SecretBrokerPermissionsError):
            SecretBroker(env={}, settings_default=secret)

    def test_kwarg_layer_refuses_even_if_gitignored(self, tmp_path: Path) -> None:
        """The narrowing is layer-3 ONLY — an explicit kwarg path still refuses."""
        secret = self._repo_with_secret(tmp_path, gitignored=True)
        with pytest.raises(SecretBrokerPermissionsError):
            SecretBroker(env={}, secrets_file=secret)

    def test_env_layer_refuses_even_if_gitignored(self, tmp_path: Path) -> None:
        secret = self._repo_with_secret(tmp_path, gitignored=True)
        with pytest.raises(SecretBrokerPermissionsError):
            SecretBroker(env={"ALFRED_SECRETS_FILE": str(secret)})

    def test_layer3_git_absent_refuses(self, tmp_path: Path, monkeypatch) -> None:
        """Fail-closed: git absent → cannot confirm ignored → refuse."""
        from alfred.security import secrets as secrets_module

        secret = self._repo_with_secret(tmp_path, gitignored=True)

        def _raise(*_a, **_k):
            raise FileNotFoundError("git not found")

        monkeypatch.setattr(secrets_module.subprocess, "run", _raise)
        with pytest.raises(SecretBrokerPermissionsError):
            SecretBroker(env={}, settings_default=secret)
```

- [ ] **Step 2: Run — expect FAIL (layer3-gitignored currently refuses)**

Run: `uv run pytest tests/unit/security/test_secrets.py::TestGitWalkNarrowing -q`
Expected: FAIL on `test_layer3_gitignored_boots_with_warning` (current code refuses on any `.git` parent regardless of layer/ignore).

- [ ] **Step 3: Implement the narrowing**

Replace the construction walk (`:425-437`):

```python
        if not allow_inside_git_worktree:
            git_parent = _walk_for_git_parent(self._secrets_file_path)
            if git_parent is not None:
                if self._secrets_path_layer == "settings_default" and _secret_is_gitignored(
                    git_parent, self._secrets_file_path
                ):
                    # #366: the layer-3 canonical XDG default whose secret is
                    # AUTHORITATIVELY gitignored — safe from accidental `git add
                    # -A`. Proceed, but WARN (defence-in-depth): a future `git
                    # add -f` or a .gitignore edit could still commit it. The
                    # kwarg / ALFRED_SECRETS_FILE layers do NOT reach this branch
                    # (they keep the full always-refuse walk — the operator
                    # explicitly named the path, where a repo-clone drop is the
                    # real threat).
                    _log.warning(
                        "secrets.file_in_git_repo_but_ignored",
                        path=str(self._secrets_file_path),
                        parent=str(git_parent),
                    )
                else:
                    raise SecretBrokerPermissionsError(
                        t(
                            "secrets.file_in_git_repo",
                            path=str(self._secrets_file_path),
                            parent=str(git_parent),
                        ),
                        path=self._secrets_file_path,
                        mode=0,
                        parent=git_parent,
                    )
```

- [ ] **Step 4: Run construction tests + full secrets file → PASS**

Run: `uv run pytest tests/unit/security/test_secrets.py -q`
Expected: PASS (all, incl. the pre-existing `.git`-walk refuse tests — verify they used the kwarg/env layer or `allow_inside_git_worktree=True`, so their behaviour is unchanged; if any pre-existing test constructed a layer-3 gitignored repo it would now flip — none do, they use `secrets_file=` kwarg).

- [ ] **Step 5: Per-file 100% branch coverage on secrets.py**

Run:

```bash
uv run pytest tests/unit/security/test_secrets.py --cov=alfred.security.secrets --cov-branch -q
uv run coverage report --include='src/alfred/security/secrets.py' --show-missing
```

Expected: `100%`. If the `git_parent is not None` + layer + ignored branch matrix has an uncovered arm, add the missing case (e.g. a layer-3 path with a `.git` parent but NOT gitignored is covered by `test_layer3_not_gitignored_refuses`; the git-absent arm by `test_layer3_git_absent_refuses`).

- [ ] **Step 6: Commit**

```bash
git add src/alfred/security/secrets.py tests/unit/security/test_secrets.py
git commit -m "feat(security): gitignore-aware .git-walk narrowing for the layer-3 secrets path (#366)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 4: ADR-0012 amendment

**Files:**

- Modify: `docs/adr/0012-file-backed-secret-broker.md`

- [ ] **Step 1: Add a dated amendment section**

Append after the existing content (before any trailing sections, matching the file's amendment style):

```markdown
## Amendment — #366 (2026-07-05): gitignore-aware `.git`-walk for the layer-3 path

The `.git`-in-parent refusal is an anti-accidental-commit defence. Once the
layer-3 host default (`~/.config/alfred/secrets.toml`, #363) activated, the walk
also applied there — where a versioned `~/.config` (dotfiles repo) makes the
canonical secrets file a real commit vector the walk correctly catches, but the
walk hard-refused even a correctly-`.gitignore`'d file (it checks for a `.git`
dir only, never ignore status).

For the **`settings_default` (layer-3) path only**, the refusal is now
**gitignore-aware**: if the secret is authoritatively gitignored (`git
check-ignore`), the broker proceeds with a `secrets.file_in_git_repo_but_ignored`
structlog WARNING (a future `git add -f` / `.gitignore` edit could still commit
it); otherwise it refuses. **Fail-closed**: git absent / error / timeout → treat
as not-ignored → refuse. The **constructor-kwarg** and **`ALFRED_SECRETS_FILE`**
layers are UNCHANGED — full always-refuse walk (the operator explicitly named
the path; a repo-clone drop is the real threat there).

No case weakens the defence: an un-gitignored secret still refuses on every
layer. Corrects the #366 "zero coverage" framing (the dotfiles-repo commit
vector is real); options (a) stop-at-XDG and (b) warn-not-refuse were rejected
because both drop the dotfiles-repo protection. Adversarial coverage: see the
#366 corpus entry.
```

- [ ] **Step 2: Markdownlint**

Run: `npx markdownlint-cli2 "docs/adr/0012-file-backed-secret-broker.md"`
Expected: 0 errors (mind MD060 spaced table separators if a table is added — none here; MD032 blank lines around any list).

- [ ] **Step 3: Commit**

```bash
git add docs/adr/0012-file-backed-secret-broker.md
git commit -m "docs(adr): ADR-0012 amendment for gitignore-aware .git-walk (#366)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 5: Adversarial corpus entry

**Files:**

- Create: `tests/adversarial/dlp_egress/secrets_in_repo_not_gitignored_refused.yaml`
- Create: `tests/adversarial/dlp_egress/test_de_2026_0NN_secrets_in_repo_not_gitignored_refused.py`

**Interfaces:**

- Consumes: `SecretBroker`, `SecretBrokerPermissionsError`, the session-scoped `corpus_payloads` fixture, `tests.adversarial.payload_schema.AdversarialPayload`.

- [ ] **Step 1: Pick the next `de-` id**

Run: `grep -rhoE '^id: de-2026-[0-9]+' tests/adversarial/dlp_egress/*.yaml | sort -t- -k3 -n | tail -1`
Use the next number (e.g. if `de-2026-016` is highest → `de-2026-017`).

- [ ] **Step 2: Write the YAML payload**

`category: dlp_egress`, `ingestion_path: secret_broker`, `expected_outcome: refused`, a `payload` dict (`builder: SecretBroker`, `layer: settings_default`, `gitignored: false`, `attempted_action: boot_with_committable_secret_in_repo`), prose `provenance` (str) framing credential-in-versioned-repo as a T3-origin credential-exfiltration vector the layer-3 gitignore-aware refusal catches (un-ignored → refused; ignored → allowed), + a `references` list (`ADR-0012`, `issue #366`, `issue #363`, `CLAUDE.md hard rule #7`). Match `payload_schema.py` (`extra=forbid`; provenance prose str, references a list). Run `uv run pytest tests/adversarial -q` first to confirm schema-valid.

- [ ] **Step 3: Write the wiring-smoke test**

Mirror the `cap-2026-005` shape: filter the corpus to the id (fail loud if missing/dup), then drive the REAL `SecretBroker` against a real tmp git repo:

- layer-3 secret NOT gitignored → `pytest.raises(SecretBrokerPermissionsError)` (the defence fires);
- layer-3 secret gitignored (positive control) → boots (the narrowing allows).

No permissive shim.

- [ ] **Step 4: Run the new test + full adversarial suite**

Run: `uv run pytest tests/adversarial -q`
Expected: all pass (corpus schema-validates; new test green).

- [ ] **Step 5: Commit**

```bash
git add tests/adversarial/dlp_egress/secrets_in_repo_not_gitignored_refused.yaml \
  tests/adversarial/dlp_egress/test_de_2026_0NN_secrets_in_repo_not_gitignored_refused.py
git commit -m "test(security): de-2026-0NN adversarial entry for gitignore-aware .git-walk (#366)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Final verification (before PR)

- [ ] `make check` (whole-repo lint+format+type+test) — exit 0. (Whole-repo `ruff format --check .`, not scoped — lesson from #380.)
- [ ] `uv run pytest tests/adversarial -q` — release-blocking suite green.
- [ ] Per-file 100% branch coverage on `secrets.py`.
- [ ] Full `/review-pr` fleet (security intensified) + CR CLI locally before push.

## Self-Review notes

- **Spec coverage:** provenance (Task 1), git check-ignore + fail-closed (Task 2), narrowing + warn-and-proceed + layer-3-only + kwarg/env-unchanged (Task 3), ADR-0012 amendment (Task 4), adversarial entry (Task 5). All spec sections mapped.
- **Type consistency:** `_resolve_secrets_path -> tuple[Path | None, _SecretsLayer]`, `self._secrets_path_layer`, `_secret_is_gitignored(repo, secrets_path) -> bool` used identically across tasks.
- **Coverage risk:** the git-subprocess fault arms (absent/timeout/exit-128) are covered via monkeypatch (Task 2); the narrowing branch matrix (layer3-ignored / layer3-not / kwarg / env / git-absent) via Task 3.

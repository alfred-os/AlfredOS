# Design — #366: gitignore-aware `.git`-walk narrowing for the layer-3 secrets path

- **Issue:** #366 (security plan review of #363; ADR-0012 amendment)
- **Date:** 2026-07-05
- **Branch:** `366-gitignore-aware-git-walk`
- **Scope:** narrows a fail-closed security default for **one layer only**; needs an ADR-0012 amendment.

## Problem (corrected threat model)

`SecretBroker` construction refuses boot if the resolved secrets file has any
ancestor containing a `.git/` dir (`_walk_for_git_parent`,
`src/alfred/security/secrets.py:256`; the refusal at construction `:425-437`
raises `SecretBrokerPermissionsError` with the `secrets.file_in_git_repo`
message). This is an anti-accidental-commit defence.

Once #363 activated the host-default layer, the walk applies to the canonical
XDG path `~/.config/alfred/secrets.toml`. The issue framed the walk as "zero
coverage" there — but that is **incomplete**: a versioned `~/.config` (dotfiles
repo: chezmoi / yadm / bare-repo / GNU stow — common for the self-host
audience) makes the canonical secrets file a **real** accidental-commit vector,
which the walk correctly catches. So the naive fixes weaken security:

- **(a) stop-at-XDG-root** — drops the dotfiles-repo protection entirely.
- **(b) warn-not-refuse** — an un-gitignored secret in a versioned tree boots
  with only a warning; the operator can ignore it and leak.

The genuinely-spurious case is narrower: a dotfiles-repo operator who has
**already `.gitignore`'d** the secret. The walk checks for a `.git` dir only,
never ignore status, so it hard-refuses even a correctly-ignored file.

## Design — option (c): gitignore-aware, layer-3 only

Refuse only when the secret is genuinely committable.

### 1. Provenance threading

`_resolve_secrets_path` (`:234`) returns `Path | None`, losing which layer won.
Change it to return `(Path | None, layer)` where
`layer: Literal["constructor", "env", "settings_default"] | None` (`None` iff
the path is `None`). The narrowing applies **only** to the `settings_default`
layer (layer-3, the setup-created XDG default). The **constructor-kwarg** and
**`ALFRED_SECRETS_FILE`** layers keep the current **full, always-refuse** walk —
for those the operator explicitly named a path, and a repo-clone drop is the
real threat the walk was built for. The constructor stores the resolved layer as
`self._secrets_path_layer` and reads it at the walk.

### 2. Authoritative gitignore check + fail-closed

New helper:

```python
_GIT_CHECK_IGNORE_TIMEOUT_S: Final[float] = 5.0

def _secret_is_gitignored(repo: Path, secrets_path: Path) -> bool:
    """True iff `secrets_path` is git-ignored within `repo` (authoritative).

    Uses `git check-ignore` — the authoritative gitignore evaluator (honours
    nested .gitignore, .git/info/exclude, core.excludesFile). Fail-closed:
    returns False (→ refuse) if git is absent, errors, or times out.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "check-ignore", "--quiet", "--", str(secrets_path)],
            capture_output=True,
            timeout=_GIT_CHECK_IGNORE_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False  # git binary absent / hung → fail-closed
    return result.returncode == 0  # 0=ignored; 1=not-ignored; 128=error → refuse
```

Rationale: a hand-rolled `.gitignore` parser is **rejected** — a parser bug that
falsely reports "ignored" is a security hole (a committable secret boots). `git
check-ignore` is the authoritative answer. Args are a list (no `shell=True`, no
injection); `--` guards a path that starts with `-`; `capture_output` keeps git
chatter off the console; timeout-bounded so a hung git can't hang boot.

### 3. The narrowing at the construction walk

```python
if not allow_inside_git_worktree:
    git_parent = _walk_for_git_parent(self._secrets_file_path)
    if git_parent is not None:
        if layer == "settings_default" and _secret_is_gitignored(
            git_parent, self._secrets_file_path
        ):
            # #366: layer-3 canonical path whose secret is authoritatively
            # gitignored — safe from accidental `git add -A`. Proceed, but WARN
            # (defence-in-depth): a future `git add -f` or a .gitignore edit
            # could still commit it.
            _log.warning(
                "secrets.file_in_git_repo_but_ignored",
                path=str(self._secrets_file_path),
                parent=str(git_parent),
            )
        else:
            raise SecretBrokerPermissionsError(
                t("secrets.file_in_git_repo", path=..., parent=...),
                path=..., mode=0, parent=git_parent,
            )
```

The warning is a **structlog event** (structured key + kwargs), matching the
existing `_log.warning("redactor.pattern_overflow", ...)` idiom — NOT a
`t()`-rendered sentence (the refusal message stays `t()`'d; the warning is
observability). No new i18n key.

## Security posture

| Case | Before | After |
| --- | --- | --- |
| layer-3, in repo, NOT gitignored | refuse | **refuse** (protection preserved) |
| layer-3, in repo, gitignored | refuse | **warn + proceed** (wart fixed) |
| layer-3, in repo, git absent/hung | refuse | **refuse** (fail-closed) |
| kwarg / `ALFRED_SECRETS_FILE`, in repo | refuse | **refuse** (unchanged) |
| any, no `.git` ancestor | proceed | proceed |

No case weakens the accidental-commit defence: an un-gitignored secret still
refuses on every layer; the only behaviour change is allowing a
**provably-gitignored** layer-3 secret.

## Tests

Touches `src/alfred/security/` → **release-blocking adversarial suite** + 100%
line+branch coverage on the new code.

### Unit (`tests/unit/security/test_secrets.py`)

Deterministic **real** fault injection via tmp `git init` repos (the codebase's
stated preference over mocks):

- layer-3 (`settings_default=`) secret in a real tmp git repo, `.gitignore`s it →
  **boots** (asserts the warn-and-proceed; capture the structlog warning).
- layer-3 secret in a real tmp git repo, NOT gitignored → **refuses**
  (`SecretBrokerPermissionsError`, `secrets.file_in_git_repo`).
- **kwarg** layer (`secrets_file=`) secret in a repo, even gitignored → **refuses**
  (the narrowing is layer-3 only).
- **env** layer (`ALFRED_SECRETS_FILE`) secret in a repo, even gitignored →
  **refuses**.
- git absent → `_secret_is_gitignored` returns False → refuse (monkeypatch
  `subprocess.run` → `FileNotFoundError`).
- git timeout → False → refuse (monkeypatch → `subprocess.TimeoutExpired`).
- `git check-ignore` exit 128 (error) → False → refuse.
- `_resolve_secrets_path` returns the correct `(path, layer)` for each of the
  three layers + the `(None, None)` env-only case.

### Adversarial (`tests/adversarial/`)

A `dlp_egress` (`de-`) corpus entry is **mandatory** here (this touches
`src/alfred/security/` — the adversarial corpus is release-blocking, not
optional): credential-in-repo is a T3-origin credential exfiltration vector. A
layer-3 secrets file inside a versioned repo, NOT gitignored → **refused**
(defence fires, no credential-committable boot); gitignored → allowed (the
narrowing positive control). Drives the real broker against a real tmp `git`
repo. (Shipped as `de-2026-017`.)

## ADR-0012 amendment

A dated amendment section: the `.git`-in-parent refusal is narrowed for the
**layer-3 settings-default path only** to a gitignore-aware refusal
(authoritative `git check-ignore`, fail-closed on absent/error/timeout,
warn-and-proceed on the allowed path); kwarg/env layers keep the full
always-refuse walk. Records the corrected threat model (dotfiles-repo commit
vector) and why (a)/(b) were rejected.

## Blast radius & verification

- Run the release-blocking adversarial suite; 100% line+branch on the new
  helper + narrowing branch.
- `make check` (whole-repo) before push; full `/review-pr` fleet (security
  intensified) + CR CLI; path-to-green; plain `gh pr merge --rebase`.

## Alternatives considered

- **(a) stop-at-XDG-root / (b) warn-not-refuse** — rejected: both drop the
  dotfiles-repo accidental-commit protection (corrected threat model).
- **Hand-rolled `.gitignore` parser** (avoid the subprocess) — rejected: a
  false-"ignored" bug is a security hole; `git check-ignore` is authoritative.
- **`pathspec` library** — rejected: a new dependency that still may diverge
  from git's real semantics (global excludes, `.git/info/exclude`).
- **Silently proceed on the allowed path** — rejected in favour of
  warn-and-proceed (surface the residual forced-add / un-ignore risk).

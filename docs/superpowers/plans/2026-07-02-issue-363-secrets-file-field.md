# Issue #363 — Complete ADR-0012: add `Settings.secrets_file` (+ fold #351 narrowing)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.
>
> **STATUS: SECURITY PLAN-REVIEW COMPLETE — awaiting maintainer greenlight before implementation.** This is a SECURITY BEHAVIOUR change (secret-file resolution), not a zero-behaviour refactor.
>
> **Security-lens verdict: SAFE to implement + merge after 4 blockers (folded below). Blast radius is NARROW — the default compose deployment is provably UNAFFECTED** (no `ALFRED_SECRETS_FILE`, no secrets bind-mount; `docker/alfred-core.Dockerfile` sets `HOME=/home/alfred` and never creates `~/.config/alfred/secrets.toml` → in-container the path is absent → env-only → unchanged). **Only bare-metal HOST `alfred` invocations** (where `alfred-setup.sh` created the file) see the change; that flip is fail-closed + toward the more-secure store (0600 file over env), per ADR-0012's intent. A (complete the ADR) confirmed over B; the bug (setup creates a file the broker ignores) confirmed real.

**Goal:** Resolve #363 by completing the accepted **ADR-0012**: add the `Settings.secrets_file` field it specifies (layer-3 host default `~/.config/alfred/secrets.toml`), so the file `bin/alfred-setup.sh` already creates is actually read by the broker. Then fold the now-possible #351 DIP narrowing of `SecretBroker.from_settings`.

**Why (the bug):** ADR-0012 (Accepted, Slice 2) specifies a 3-layer secret-file resolution: constructor kwarg → `ALFRED_SECRETS_FILE` env → **`Settings.secrets_file` default (`~/.config/alfred/secrets.toml`)**. The `settings_default` plumbing in `_resolve_secrets_path`/`SecretBroker.__init__` exists and is fully tested — but the `Settings.secrets_file` field was **never added**. `from_settings` papers over its absence with `getattr(settings, "secrets_file", None)` (always `None`). Net effect: `bin/alfred-setup.sh:190-200` creates `~/.config/alfred/secrets.toml` (touch + `chmod 600`), but the broker's host-default layer is dead, so an operator who puts a secret in that file finds it **silently ignored** unless they also set `ALFRED_SECRETS_FILE`. Option B (remove the layer) would supersede an accepted ADR and require also changing setup to stop creating the file; **Option A (this plan) completes the ADR.**

## ⚠️ Behaviour-change analysis (the crux — for the security plan review + maintainer sign-off)

Adding the field activates the host-default layer, so `from_settings(settings)` resolves `settings_default = ~/.config/alfred/secrets.toml` when `ALFRED_SECRETS_FILE` is unset. The `SecretBroker.__init__` flow (secrets.py:358-397) then, **only if that file EXISTS**:

1. runs the `.git`-in-parent refusal (unless `allow_inside_git_worktree`);
2. runs `_validate_secrets_file_security` (symlink / owner / regular-file / mode-bits / parent-writability);
3. loads it (`_PREFER_FILE = {discord_bot_token, quarantine_provider_api_key}` then file-WINS over env for those two).

**Deployment matrix (verify each in the plan review):**

| Scenario | Today (host-default dead) | After A | Assessment |
| --- | --- | --- | --- |
| `ALFRED_SECRETS_FILE` set (bind-mounted `/etc/alfred/secrets.toml`) | env-var layer used | **unchanged** (env layer still precedes host default) | safe |
| No env var, no `~/.config/alfred/secrets.toml` | env-only | env-only (file absent → `require_file=False` returns) | **unchanged** |
| No env var, populated `~/.config/alfred/secrets.toml`, good perms, not under `.git` | file **ignored** (bug) | file **loaded**; `_PREFER_FILE` secrets now file-win | **the fix — intended** |
| No env var, empty setup-created file, good perms, not under `.git` | ignored | loaded → empty → env fallback | no observable change |
| No env var, file exists but **home/config is a dotfiles `.git` repo** | ignored → daemon boots | `.git`-walk **refuses** → daemon fails to boot | **REGRESSION** for dotfiles-git operators who ran setup |
| No env var, file exists with **wrong perms** (group/world readable, wrong owner) | ignored → boots | validation **refuses** → fails to boot | fail-closed (ADR-intended) but a change |

**Compose note:** `docker-compose.yaml` does NOT set `ALFRED_SECRETS_FILE` (only a comment at :150). So the host-default applies in-container too — whether it bites depends on whether a `secrets.toml` lands at the container user's `~/.config/alfred/`. The plan review + a devops reviewer must confirm the container path.

**Open questions — RESOLVED by the security plan review (now the 4 implementation blockers):**

- **BLOCKER 1 (Q4 + env-name collision):** use `Field(default_factory=lambda: Path.home() / ".config/alfred/secrets.toml")` — already-absolute, stores no `~`, no expanduser. Do **NOT** add an expanduser validator (layer-2's `_resolve_secrets_path` reads `Path(env_value)` raw at secrets.py:206-208; expanding only the field creates a `~`-asymmetry). NOTE: with `env_prefix="ALFRED_"` (settings.py:70) the field `secrets_file` **auto-maps from `ALFRED_SECRETS_FILE`**, which ALSO feeds the broker's layer-2 `os.environ` read — collapsing ADR-0012 layers 2 & 3 onto one env var. Benign (same env, same value, `default_factory` kills the `~`-asymmetry) but must be a **conscious, documented** decision in the field docstring.
- **BLOCKER 2 (Q1 message defect):** the `.git`-in-parent refusal renders `secrets.file_perms_too_open` with `octal_mode="0"` (secrets.py:386-388) → "wrong place / move the file", which is FALSE for the ADR-blessed canonical path. Branch the canonical-path case to an accurate remedy ("your HOME/.config is a git repo — set `ALFRED_SECRETS_FILE` to a path outside any repo, or remove the file"). New/updated `t()` catalog string. (Ship the fail-closed refusal AS-IS for #363 — it is loud + escapable; the `.git`-walk *narrowing* is fast-follow #366, needs an ADR-0012 amendment.)
- **BLOCKER 3 (Q2/Q3 migration note — REQUIRED, in scope):** land an upgrade/migration note covering (a) the dotfiles-git boot-refusal + the ONLY escape hatches (`ALFRED_SECRETS_FILE=<non-repo path>` / delete the file; `.gitignore` does NOT help), and (b) the `_PREFER_FILE` (`discord_bot_token`, `quarantine_provider_api_key`) env→file flip (toward the more-secure store — not a leak, but a stale file token could shadow a fresh env token). Compose already flags this at docker-compose.yaml:150.
- **BLOCKER 4 (test-gap):** `test_ignores_non_path_settings_attribute` (test_secrets.py:514) passes a `str` and will crash on `str.exists()` once the `isinstance(raw, Path)` guard is dropped — reconcile it (its premise dies once the field is a typed `Path`). `test_uses_settings_secrets_file_when_present` (test_secrets.py:494) stays valid; `test_from_settings_constructs_broker` (test_secrets.py:74, `MagicMock`) must move to a real `Settings`/proper stub.

**Fast-follow (NOT in this PR):** #366 — narrow the `.git`-walk for the settings-default canonical path (ADR-0012 amendment). **Adversarial:** add a corpus entry for the canonical-path `.git`-walk case; run the release-blocking `tests/adversarial` suite (mandatory — touching `src/alfred/security/`).

## Global Constraints

- **Highest-care subsystem.** `src/alfred/security/` + `src/alfred/config/settings.py`. Adversarial suite (`tests/adversarial`) is release-blocking. `security-engineer` reviewer always. `security/*` + the per-file secrets coverage gates (`ci.yml`) must stay 100%.
- **ADR:** this COMPLETES ADR-0012 (no new ADR needed for A); if the plan review chooses to narrow the `.git`-walk (Q1) or otherwise deviate from ADR-0012's coded behaviour, that deviation needs an ADR amendment.
- **i18n:** any new operator-facing string via `t()`. (The field `description=` is not operator-facing runtime text.)
- **Commit trailers** (every commit): `MrReasonable <4990954+MrReasonable@users.noreply.github.com>` + `Claude-Session: https://claude.ai/code/session_01LbUbRZZj1th4ubjSk7Xm5g`. Conventional Commits + literal `#363` (and `#351` on the narrowing commit) in every subject.
- **Branch:** `363-secrets-file-field`.

## File Structure

- `src/alfred/config/settings.py` — **Modify.** Add `secrets_file: Path` field (ADR-0012 default). Q4 decides the expansion mechanism.
- `src/alfred/security/secrets.py` — **Modify.** `from_settings`: read `settings.secrets_file` directly (drop the phantom `getattr`+`isinstance`). The module docstring's 3-layer table becomes accurate (verify wording).
- `tests/unit/config/test_settings*.py` — **Add** a focused test: `Settings().secrets_file` equals the ADR default (expanded).
- `tests/unit/security/test_secrets.py` — **Modify** `test_from_settings_constructs_broker` (currently passes a `MagicMock()` that only worked because of the phantom `isinstance` guard) to use a real `Settings` / proper stub; add a `from_settings` reads-the-field test.
- `src/alfred/security/_config_protocols.py` — **Modify (commit 2, #351).** Add `SecretBrokerConfig` (`@property secrets_file: Path`) beside `CommsAdapterGrantsConfig` (the PR3 breadcrumb anticipated exactly this).
- `tests/unit/security/test_config_protocol_proof.py` — **Modify (commit 2).** Add `SecretBrokerConfig` satisfaction proof + stub DIP-win test.

## Tasks

### Task 1 — commit 1: `feat(config): add Settings.secrets_file, complete ADR-0012 (#363)` (the behaviour change)

- [ ] **Add the field** in `settings.py` (near `state_git_path`/`policies_path`, ~line 185-206):

```python
secrets_file: Path = Field(
    default_factory=lambda: Path.home() / ".config/alfred/secrets.toml",
    description=(
        "Host-default secrets.toml path (ADR-0012 layer 3). NOTE: with env_prefix "
        "'ALFRED_', this field ALSO auto-maps from ALFRED_SECRETS_FILE — the same env "
        "var the broker reads directly for its layer-2 override — so ADR-0012 layers 2 "
        "and 3 collapse onto one env var by design (both read the same value). "
        "default_factory yields an absolute path (no '~'), so no expanduser is needed "
        "and the raw Path() the broker applies to ALFRED_SECRETS_FILE stays symmetric."
    ),
)
```

Verify mypy strict accepts `default_factory=lambda: Path.home() / ...` (Pydantic v2 types it; the lambda infers `-> Path`).

- [ ] **Fix `from_settings`** (secrets.py:399-412) — drop the phantom `getattr`+`isinstance`, read the field directly:

```python
@classmethod
def from_settings(cls, settings: Settings) -> SecretBroker:
    """Build a broker primed from a Settings instance.

    Reads ``settings.secrets_file`` (ADR-0012 layer-3 host default) and passes it as the
    ``settings_default`` layer. The constructor override + ``ALFRED_SECRETS_FILE`` env var
    still take precedence.
    """
    return cls(settings_default=settings.secrets_file)
```

- [ ] **Blocker 2 — accurate `.git`-in-repo message.** Add a NEW catalog msgid `secrets.file_in_git_repo` and use it at the `.git`-parent raise (secrets.py:384-393) instead of `secrets.file_perms_too_open` (which renders a false "chmod" remedy with `octal_mode="0"`). Keep `SecretBrokerPermissionsError` + `mode=0` (API/dispatch compat). English msgstr:

```text
Secrets file '{path}' is inside a git repository (found '.git' at '{parent}'); secrets must never be committed. Move it outside any git repository, or set ALFRED_SECRETS_FILE to a path outside a repo.
```

Run the i18n flow (per project memory `i18n drift gate`): `pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins` → `pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching` (NEVER `--omit-header`) → fill the English msgstr by hand → `pybabel compile -d locale -D alfred`. A code edit that shifts line numbers re-stales the `#:` refs → re-run extract/update. (The two other secrets.py edits shift line numbers, so do the i18n flow LAST.)

- [ ] **Blocker 4 — reconcile tests** in `tests/unit/security/test_secrets.py`:
  - REMOVE `test_ignores_non_path_settings_attribute` (:514) — its "secrets_file is a str/mock" premise dies once the field is a typed `Path`; without the isinstance guard it would crash on `str.exists()`. The removal IS the point (we now trust the typed field).
  - FIX `test_from_settings_constructs_broker` (:74, `MagicMock()`) → use a real `Settings` (or `Settings.model_construct(secrets_file=<tmp path or a non-existent path>)`); a `MagicMock` secrets_file now flows to `.exists()`/`.git`-walk and crashes.
  - KEEP `test_uses_settings_secrets_file_when_present` (:494, `SimpleNamespace(secrets_file=<Path>)`) — still valid.
  - ADD: `Settings().secrets_file == Path.home() / ".config/alfred/secrets.toml"` (a config test) + a test that the `.git`-in-repo raise renders the new message (assert the msgid/text, not the old chmod text).

- [ ] **Gate + commit** (see Task 3 for the full gate; commit 1 when green).

### Task 2 — commit 2: `refactor(security): narrow SecretBroker.from_settings to SecretBrokerConfig (#351)` (zero behaviour)

- [ ] Add `SecretBrokerConfig(Protocol)` to `security/_config_protocols.py` (beside `CommsAdapterGrantsConfig`; the module breadcrumb anticipated it):

```python
class SecretBrokerConfig(Protocol):
    """The config surface ``SecretBroker.from_settings`` reads: the host-default secrets path.

    Producer invariant: ``Settings.secrets_file`` is an absolute ``Path`` (ADR-0012 layer 3,
    default ``~/.config/alfred/secrets.toml`` via ``default_factory``). The broker treats it as
    the lowest-precedence path layer and fails closed on a bad file at construction.
    """

    @property
    def secrets_file(self) -> Path: ...
```

- [ ] Narrow `from_settings(cls, config: SecretBrokerConfig)` (rename `settings`→`config`; swap the `TYPE_CHECKING` `Settings` import for `SecretBrokerConfig`).
- [ ] Add the `_settings_satisfies` proof + a plain-stub DIP-win test to `tests/unit/security/test_config_protocol_proof.py` (mirror the `CommsAdapterGrantsConfig` proof). Use the single-line getter form (coverage gate).
- [ ] Gate + commit 2.

### Task 3 — migration note (Blocker 3) + adversarial + full gate

- [ ] **Migration note (REQUIRED, Blocker 3)** — a new `docs/runbooks/2026-07-03-secrets-file-host-default.md` (operator-facing, English-only): (a) the host-default `~/.config/alfred/secrets.toml` is now READ (bare-metal host `alfred` runs; compose unaffected); ensure `0600` + owner-only; (b) if HOME/.config is a git repo, boot now REFUSES (secrets-in-repo defense) — escape hatches: `ALFRED_SECRETS_FILE=<non-repo path>` OR remove the file (`.gitignore` does NOT help); (c) `_PREFER_FILE` (`discord_bot_token`, `quarantine_provider_api_key`) now file-WIN over env when the file has them — a stale file token shadows a fresh env token.
- [ ] **Adversarial corpus** (security-review recommendation): add a `tests/adversarial/` entry for the canonical-path `.git`-walk refusal (use the `alfred-adversarial-corpus` skill for naming/schema). Lightweight — the behaviour is already unit-tested; this pins it at the adversarial tier.
- [ ] **Full gate:** `ruff check . && ruff format --check .`; `mypy src/ && pyright src/`; `pytest tests/unit/security tests/unit/config -q`; the `security/*` + per-file secrets 100% coverage gates; **`pytest tests/adversarial` (release-blocking — security subsystem changed)**; i18n `pybabel compile --check` (CI drift gate — use `--ignore-pot-creation-date`).
- [ ] Push, open PR, full `/review-pr` fleet (security ALWAYS) + CodeRabbit, resolve every thread. **DO NOT auto-merge** — this is a security behaviour change; the maintainer has greenlit the approach, but confirm the final PR is as-reviewed before `gh pr merge --rebase`.

## Self-Review (pre-implementation)

- Evidence that A (not B) is correct: ADR-0012 Accepted + specifies the field (line 50) + `alfred-setup.sh` already creates the file → completing the ADR fixes a real bug. ✓
- Behaviour-change surfaces enumerated (matrix) + 4 open questions flagged for the security plan review + maintainer, NOT decided unilaterally. ✓
- Highest-care gates named (adversarial, coverage, security reviewer). ✓
- #351 narrowing folded as a clean, separate, zero-behaviour commit that the PR3 breadcrumb anticipated. ✓

# 0012 — File-backed `SecretBroker` at `~/.config/alfred/secrets.toml`

- **Status**: Accepted
- **Date**: 2026-05-27
- **Slice**: 2 — `docs/superpowers/plans/2026-05-26-slice-2-pr-C-broker-rate-limiter-dlp.md`
- **Supersedes**: —
- **Superseded by**: —

## Context

Slice 1 shipped an env-var-only [`SecretBroker`](../glossary.md#secretbroker)
as the single legitimate accessor for any value listed in `SUPPORTED_SECRETS`.
Every other module reads secrets via `SecretBroker.get`, and an AST-scan
test (`tests/unit/security/test_no_direct_env_reads.py`) keeps that
invariant honest — see CLAUDE.md security hard rule #6.

Slice 2 introduces `discord_bot_token`. Three properties of that token
make env-var-only awkward:

1. **Long-lived.** Operators rotate Discord bot tokens rarely (months
   between rotations). `.env`-style env injection encourages
   process-environment lifetime coupling that the token does not need.
2. **Operator-visible leak surface.** Process env vars show up in
   `/proc/<pid>/environ`, `docker inspect`, debugger memory dumps, and
   crash-reporter envelopes. A file with `0600` permissions narrows the
   leak surface to a single named entity (the file's owner UID) without
   adding a new datastore.
3. **No file-perm boundary.** Env vars carry no host-level access
   control. A file does — and the broker can fail closed on any
   permission slippage at construction.

PRD §7.1 names the broker as the sole secret-access surface for plugins.
Slice 2 needs to honour that surface for a Discord-shaped secret without
broadening the env-var leak surface across the multi-process Slice-2
deployment (operator CLI + `alfred-core` + `alfred-discord`).

## Decision

`SecretBroker` gains a plaintext file backend at
`~/.config/alfred/secrets.toml` (XDG-config-home convention) with
fail-closed permission validation at construction.

### Path resolution

Three-layer precedence:

1. Constructor `secrets_file=` kwarg (test override, always wins).
2. `ALFRED_SECRETS_FILE` env var (container override; typical value
   `/etc/alfred/secrets.toml` bind-mounted into the container).
3. `Settings.secrets_file` Pydantic default (`~/.config/alfred/secrets.toml`).

`None` at every layer signals "no file backend; env-only" — a
backward-compatible Slice-1 behaviour. `require_file=True` flips that to
a fail-closed init that raises `SecretBrokerFileMissingError` if no path
resolves or the resolved path does not exist.

### Per-secret precedence (`_PREFER_FILE`)

For Slice-1 keys (`deepseek_api_key`, `anthropic_api_key`), env wins on
conflict. Operators already set these via `.env`; flipping to file-prefer
would change deployment behaviour silently for installs that have
already shipped.

For Slice-2+ keys (`_PREFER_FILE = {"discord_bot_token"}`), the file
wins. `_PREFER_FILE` is a strict subset of `SUPPORTED_SECRETS`; the
subset invariant is asserted by an import-time check in the same module.

### Fail-closed permission validation

`_validate_secrets_file_security` runs at construction (and at every
`reload()`). Order is deliberate — earliest failure is the most severe:

1. **Not a symlink.** `lstat`, never `stat`. A symlink could point at any
   other file the operator has read access to, including
   `/etc/shadow` — the broker would dutifully parse it and fail later
   somewhere downstream.
2. **Owned by the invoking user.** `st_uid == os.getuid()`.
3. **Regular file.** Not a directory, not a device. A bind-mount
   surfaces as a directory if Docker created the mount point before the
   host file existed; the typed `SecretBrokerNotAFileError` surfaces a
   precise remediation (run `bin/alfred-setup.sh`).
4. **No group/world bits on the file.** `st_mode & 0o077 == 0`.
5. **Parent directory not group/world-writable.** `& 0o022 == 0`. A
   group-writable parent lets another user replace the file under the
   broker's nose.

### `.git`-in-parent refusal

`_walk_for_git_parent` walks up to 12 ancestor directories looking for
`.git/`. If found, the broker refuses with `SecretBrokerPermissionsError`
carrying `mode=0` (the sentinel that means "not a perm-bits failure, the
file is in the wrong place"). The 12-level cap defends against
pathological symlink loops.

This is a defence-in-depth against the most common accidental-commit
shape: an operator drops `secrets.toml` into their AlfredOS clone for
convenience and gits-pushes hours later. The broker fails at construction
before the secret is read; the operator's deployment never works without
moving the file, and the secret never reaches the commit history.

> **Amended by #366** (see the amendment below): for the layer-3 host-default
> path only, this refusal is now gitignore-aware — a provably-gitignored secret
> boots with a warning; every other case (incl. git absent/error) still refuses.

### Typed error subtypes

All extend `SecretBrokerConfigError(AlfredError)` (except `UnknownSecretError`,
which is an existing `KeyError`):

- `SecretBrokerPermissionsError` — perms wrong OR `.git`-in-parent
  (sentinel `mode=0`). Carries `path` and `mode`.
- `SecretBrokerFileMissingError` — `require_file=True` and the resolved
  path does not exist.
- `SecretBrokerNotAFileError` — path resolves to a non-file (directory,
  device, …).
- `SecretBrokerMalformedError` (#370) — the file exists and is readable but
  is not valid TOML (or is not valid UTF-8). Remediation: fix the file's
  syntax/encoding.
- `SecretBrokerUnreadableError` (#370) — an `OSError` (TOCTOU race,
  `PermissionError`, …) escaped the stat/lstat/open of the validate/load step.
  Remediation: fix the file's access/ownership.
- `UnknownSecretError` (existing) — name not in `SUPPORTED_SECRETS`.

The realized handlers (`build_broker_or_die` on the CLI, the daemon boot
`_refuse_boot` path) catch the `SecretBrokerConfigError` base **once** and echo
`str(exc)`; each concrete subtype renders its own i18n message at raise time, so
the dispatch never re-branches on the subtype. The base class holds `path`;
subclasses add their specifics. The two #370 leaves deliberately do **not** echo
the raw `TOMLDecodeError` / `OSError` text into the operator message (the
redactor is not built at a construction failure — see the raise-site comments).

## Implementation reference

- `src/alfred/security/secrets.py` — full implementation, including
  `_resolve_secrets_path`, `_walk_for_git_parent`,
  `_validate_secrets_file_security`, `_load_toml_file`, and the
  perf-006 redactor cache.
- `tests/unit/security/test_secrets.py` — branch coverage of every
  validation arm, including the symlink-rejection and parent-writability
  cases.
- `tests/unit/security/test_no_direct_env_reads.py` — AST-scan test that
  rejects any new `os.environ`/`os.getenv` reads against a
  `SUPPORTED_SECRETS` name outside this module.

## Alternatives considered

- **age-encrypted file.** Strictly better than plaintext-0600. Rejected
  for Slice 2 because the surface area is too large for one slice (key
  management, key-file location, key-rotation story). Plaintext-0600 is
  the floor that Linux file permissions enforce; Slice 3+ adds
  age-encrypted as an opt-in second backend. The per-call cost is
  comparable: Slice 2 reads on every `get()`; an age backend trades one
  disk read for one decrypt.
- **OS keychain (macOS Keychain, Linux Secret Service).** Native, but
  Docker containers do not have host keychain access by default. The
  operator would have to bind-mount the keychain socket and configure
  PAM — a configuration surface disproportionate to the value over
  plaintext-0600. Rejected.
- **HashiCorp Vault.** A fourth-party datastore with its own operator
  burden, ACL system, and HA story. Disproportionate for a
  household-scale OS. Rejected.

## Consequences

**Positive:**

- One canonical secret-storage location per host. The XDG convention is
  documented and discoverable; `bin/alfred-setup.sh` creates the file
  with the right perms.
- Operator-readable + operator-editable for rotation. No special tool
  needed; the operator's text editor works.
- Bind-mountable into containers read-only via the
  `ALFRED_SECRETS_FILE` env var, keeping the host file the durable
  source-of-truth.
- Fail-closed at construction. A misconfigured deployment refuses to
  start; it does not surface three layers downstream as a misleading
  `LoginFailure` or `UnknownSecretError`.

**Negative:**

- Plaintext on disk is a backup-vector risk. Operators must exclude
  `~/.config/alfred/` from cloud backups; the README's installation
  section documents this. The deployment runbook reinforces it.
- POSIX ACLs are NOT checked. The mode-bits check catches the common
  misconfiguration (`chmod 644` on a new file) without spelunking into
  extended attributes. Defence-in-depth at the host level is the
  documented gap.
- The broker reads on every `get()`. Slice 3's age-encrypted backend
  will read + decrypt on every `get()` — comparable cost. Neither
  backend caches plaintext at the broker level (the `redact()` redactor
  cache is over derived patterns, not over decrypted plaintext).

## Amendment — #366 (2026-07-05): gitignore-aware `.git`-walk for the layer-3 path

The `### .git-in-parent refusal` above is an anti-accidental-commit defence.
Once the layer-3 host default (`~/.config/alfred/secrets.toml`, #363) activated,
the walk also applied there — where a versioned `~/.config` (dotfiles repo:
chezmoi / yadm / bare-repo / GNU stow) makes the canonical secrets file a real
commit vector the walk correctly catches, but the walk hard-refused even a
correctly-`.gitignore`'d file (it checks for a `.git` dir only, never ignore
status).

For the **`settings_default` (layer-3) path only**, the refusal is now
**gitignore-aware**: if the secret is authoritatively gitignored (`git
check-ignore` — never a hand-rolled parser, whose false "ignored" verdict would
be a security hole), the broker proceeds with a
`secrets.file_in_git_repo_but_ignored` structlog WARNING (a future `git add -f`
or `.gitignore` edit could still commit it); otherwise it refuses.
**Fail-closed**: git absent / error / timeout → treat as not-ignored → refuse.
The **constructor-kwarg** and **`ALFRED_SECRETS_FILE`** layers are UNCHANGED —
full always-refuse walk (the operator explicitly named the path; a repo-clone
drop is the real threat there).

No case weakens the defence: an un-gitignored secret still refuses on every
layer; the only behaviour change is allowing a **provably-gitignored** layer-3
secret. This corrects the #366 "zero coverage" framing (the dotfiles-repo commit
vector is real); options (a) stop-at-XDG-root and (b) warn-not-refuse were
rejected because both drop the dotfiles-repo protection. Adversarial coverage:
the `dlp_egress` corpus entry for a not-gitignored secret in a versioned repo.

**New surface / consequences.** This adds the SecretBroker's first-ever
subprocess dependency: `git` becomes a **soft, boot-time dependency on the
layer-3 `.git`-ancestor path** (its absence is fail-closed → refuse, so it is
never required to boot, but it IS the difference between refuse and
gitignore-aware-allow there). The subprocess inherits `os.environ`, so `git`
honours `GIT_CONFIG_*` / `core.excludesFile` / `GIT_DIR` — which is **correct**:
it mirrors exactly what a real `git add` in that repo would (or would not)
commit, i.e. the threat being modelled. The check fires only on the rare
layer-3-secret-inside-a-repo path (the common no-`.git`-ancestor boot never
spawns `git`), is 5s-timeout-bounded, and `check-ignore`'s index-consult means
an already-tracked secret returns not-ignored → refuse.

**Known limitation (pre-existing, #383).** `_walk_for_git_parent` detects the
enclosing repo via a `.git`-**dir** check, so a secrets file inside a git
secondary worktree or submodule (where `.git` is a **file**) escapes the refusal
on all layers — pre-existing, not introduced by this amendment; tracked in #383.

## References

- PRD §7.1 — secret broker as the sole secret-access surface.
- [ADR-0005](0005-env-backed-secret-broker-slice1.md) — Slice-1
  env-backed broker; this ADR adds the file backend on top.
- [`docs/subsystems/comms.md`](../subsystems/comms.md) —
  `OutboundDlp.scan` consumes `broker.redact` as its stage-1 source.
- [Glossary: SecretBroker](../glossary.md#secretbroker),
  [SUPPORTED_SECRETS](../glossary.md#supported_secrets),
  [\_PREFER_FILE](../glossary.md#_prefer_file).
- `tests/unit/security/test_no_direct_env_reads.py` — broker-only access
  invariant.
- #363 / PR #367 — completes this ADR: the `Settings.secrets_file` field
  specified above (layer 3) was added and `from_settings` now reads it, so the
  host-default `~/.config/alfred/secrets.toml` is finally honoured. Operator
  upgrade note:
  [`docs/runbooks/2026-07-03-secrets-file-host-default.md`](../runbooks/2026-07-03-secrets-file-host-default.md).

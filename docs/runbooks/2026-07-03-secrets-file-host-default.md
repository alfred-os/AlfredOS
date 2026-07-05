# Upgrade note — the `~/.config/alfred/secrets.toml` host default is now read (#363, ADR-0012)

**Applies to:** bare-metal / non-container `alfred` invocations where `ALFRED_SECRETS_FILE`
is **not** set. The default Docker Compose deployment is **unaffected** (it does not set
`ALFRED_SECRETS_FILE`, does not bind-mount a `secrets.toml`, and the container image never
creates `~/.config/alfred/secrets.toml` — so in-container the path is absent and the broker
stays env-only, exactly as before).

## What changed

[ADR-0012](../adr/0012-file-backed-secret-broker.md) specified a host-default secrets file at
`~/.config/alfred/secrets.toml` (layer 3 of the broker's path resolution). The
`Settings.secrets_file` field that layer depends on was never added, so the layer was **dead**:
`bin/alfred-setup.sh` created `~/.config/alfred/secrets.toml`, but the broker silently ignored
it unless you also set `ALFRED_SECRETS_FILE`.

Issue #363 completes ADR-0012 by adding the field. **The broker now reads
`~/.config/alfred/secrets.toml` when `ALFRED_SECRETS_FILE` is unset.** Precedence is unchanged:
constructor argument → `ALFRED_SECRETS_FILE` → this host default.

## What you may need to do

1. **If you keep secrets in `~/.config/alfred/secrets.toml`** (as `alfred-setup.sh` intends):
   they are now honoured. Confirm the file is `0600` and owned by you
   (`chmod 600 ~/.config/alfred/secrets.toml`), **and** that its parent directory
   `~/.config/alfred` is not group/world-writable (`chmod 700 ~/.config/alfred`). A file with
   group/world bits, wrong owner, or a symlink — **or a group/world-writable parent directory**
   (which would let another user swap the file underneath the broker) — is **refused at startup**
   (fail-closed — this is intentional).

2. **File-prefer secrets flip.** For `discord_bot_token` and `quarantine_provider_api_key`
   (the `_PREFER_FILE` set), a value in `~/.config/alfred/secrets.toml` now **wins over the
   environment variable**. This is the more-secure direction (a `0600` file over a
   process-environment value), but if you have a *stale* token in the file and a *fresh* one in
   the environment, the stale file value will now be used. Remove stale file entries, or unset
   the file value, to keep env-supplied tokens authoritative.

3. **If `$HOME` (or `~/.config`) is a git repository** (e.g. a dotfiles repo): the broker
   guards against committing the secrets file. For the **host-default path**
   (`~/.config/alfred/secrets.toml`), this is now **gitignore-aware** (#366, ADR-0012
   amendment): if the file is authoritatively gitignored (`git check-ignore`) the broker
   **boots** (with a `secrets.file_in_git_repo_but_ignored` warning); otherwise it **refuses**.
   Remedies when refused:
   - **add `~/.config/alfred/secrets.toml` to a `.gitignore`** in that repo (Alfred then boots
     with a warning — the recommended fix for a dotfiles setup), **or**
   - set `ALFRED_SECRETS_FILE=<path outside any git repo>` (e.g. `/etc/alfred/secrets.toml`), **or**
   - remove `~/.config/alfred/secrets.toml`.

   Notes: the narrowing is **fail-closed** — if `git` is absent / errors / times out, the broker
   cannot confirm the ignore status and **refuses** (install `git`, or use one of the other
   remedies). It applies **only** to the host-default path: a secrets file you point at explicitly
   via `ALFRED_SECRETS_FILE` or a constructor arg keeps the full always-refuse walk (gitignoring an
   explicitly-named path does not help — the operator chose that location).

## If you do not use the host-default file

No action needed. With no `~/.config/alfred/secrets.toml` present, the broker falls back to the
environment-only backend exactly as before.

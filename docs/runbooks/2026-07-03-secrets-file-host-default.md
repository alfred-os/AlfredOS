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
   (`chmod 600 ~/.config/alfred/secrets.toml`). A file with group/world bits, wrong owner, or a
   symlink is **refused at startup** (fail-closed — this is intentional).

2. **File-prefer secrets flip.** For `discord_bot_token` and `quarantine_provider_api_key`
   (the `_PREFER_FILE` set), a value in `~/.config/alfred/secrets.toml` now **wins over the
   environment variable**. This is the more-secure direction (a `0600` file over a
   process-environment value), but if you have a *stale* token in the file and a *fresh* one in
   the environment, the stale file value will now be used. Remove stale file entries, or unset
   the file value, to keep env-supplied tokens authoritative.

3. **If `$HOME` (or `~/.config`) is a git repository** (e.g. a dotfiles repo): the broker
   **refuses to start** when the resolved secrets file is inside a git working tree — a
   defence against committing secrets. This now applies to the host-default path. Remedies:
   - set `ALFRED_SECRETS_FILE=<path outside any git repo>` (e.g. `/etc/alfred/secrets.toml`), **or**
   - remove `~/.config/alfred/secrets.toml`.

   Note: adding the file to `.gitignore` does **not** satisfy the check — the guard refuses on
   the presence of a `.git` directory in any ancestor, not on tracked-ness. (A follow-up,
   [#366](https://github.com/alfred-os/AlfredOS/issues/366), proposes narrowing this walk for
   the canonical XDG path.)

## If you do not use the host-default file

No action needed. With no `~/.config/alfred/secrets.toml` present, the broker falls back to the
environment-only backend exactly as before.

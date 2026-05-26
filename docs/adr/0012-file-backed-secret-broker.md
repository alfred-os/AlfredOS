# 0012 — File-backed SecretBroker at `~/.config/alfred/secrets.toml`

- **Status**: Accepted
- **Date**: 2026-05-27
- **Slice**: 2 — `docs/superpowers/plans/2026-05-26-slice-2-pr-A-identity.md`
- **Supersedes**: —
- **Superseded by**: —

## Decision (summary)

Slice 2 adds a file backend to `SecretBroker` (`~/.config/alfred/secrets.toml`, 0600 perms, plaintext-with-fail-closed-perms-check). Env wins on conflict for slice-1 keys; new Slice-2+ keys (`discord_bot_token`) prefer file over env. POSIX-ACL non-coverage is documented as a known gap. Age-encryption is deferred to Slice 3+.

## Author

Full body lands in PR E. Placeholder reserves the ADR number so PR C's body can cite it without a forward-dangling reference.

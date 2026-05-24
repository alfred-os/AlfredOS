# 0005 — Env-backed secret broker stub for slice 1

- **Status**: Accepted
- **Date**: 2026-05-24
- **Slice**: 1 (`docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md`)
- **Supersedes**: —
- **Superseded by**: —

## Context

PRD §7 ("Security architecture") describes a **Secret Broker** as the single point of mediation between code and credentials. The PRD-final design uses age-encrypted files for at-rest secrets, HashiCorp Vault for production secret distribution, and OS keychain integration for local development. CLAUDE.md restates this as a HARD rule: "Secrets live in the broker, not in env vars accessible to plugins. Plugins request secret IDs; the broker substitutes at the tool-call boundary."

Slice 1 has exactly two secrets to manage: `DEEPSEEK_API_KEY` and `ANTHROPIC_API_KEY`. It has no plugins, no MCP servers, no third-party adapters that could leak the env. The full broker design (age files, Vault, keychain) is months of work and out of scope.

We need to ship slice 1 with a broker **in place** — not deferred — because the broker exists to be the only path to secrets, and deferring it would set a precedent of code reading env vars directly. Wiring it out and back in later is the kind of refactor we want to avoid.

## Decision

Slice 1 ships **`SecretBroker` as a stub backed by environment variables**. The broker exposes the slice-2-and-beyond interface (`get(secret_id: str) -> SecretStr`, `redact(text: str) -> str`) but reads the underlying value from `os.environ`. **All code paths must call `SecretBroker.get()`**; no module in `src/alfred/` may call `os.environ` for secret-shaped values directly. The CLI bootstrap is the only place that constructs the broker; from then on the broker is dependency-injected.

The broker stub also pins the **redaction surface**: `SecretBroker.redact(text)` rewrites any known secret value to `[REDACTED:<secret_id>]` in any string passed in. Log formatters call `redact()` on every record. Slice 1 enforces this via a structlog processor.

## Consequences

**Positive**

- The slice-1 invariant "secrets always go through the broker" is enforceable from day 1. A grep for `os.environ.*KEY` in `src/alfred/` outside `secrets.py` is a lint check we can add.
- The slice-3 swap to age-encrypted files (or Vault, or keychain) replaces the broker backend without touching any caller.
- Redaction of secrets in logs is in place from the first commit, not retrofitted.

**Negative**

- The broker stub does not protect against an attacker who reads `/proc/<pid>/environ`. A reader who thinks "the broker exists, therefore secrets are safe at rest" will be misled. This ADR is the answer.
- An additional indirection for a contributor reading the code. `os.environ["DEEPSEEK_API_KEY"]` is one line; `broker.get("deepseek_api_key")` is one line plus the broker fixture in tests. Acceptable.
- The `pydantic-settings` config still reads env vars at startup. **Exception boundary**: env-direct reads are confined to `src/alfred/config/settings.py` and to `SecretBroker.__init__` (which itself reads `os.environ` to populate its backing store). Every other module — orchestrator, providers, comms, audit — accesses secrets through `SecretBroker.get(name)` only. `pydantic-settings`' role is to populate the broker's input, not to be a parallel secret API. A lint rule will enforce this: any `os.environ[...KEY]` outside `settings.py` / `security/secrets.py` fails CI. This keeps PRD §7's "single mediation point" invariant intact without forcing the settings layer to also pretend it lives behind the broker.

**Neutral**

- The set of secret IDs starts at two (`deepseek_api_key`, `anthropic_api_key`). This grows as new providers and integrations land.

## Slice-3+ implications

- The age-encrypted file backend replaces the env reader in `SecretBroker`. All callers continue to use `get(secret_id)`.
- Vault and keychain backends are pluggable behind the same interface in slice 4+.
- Capability-gated secret access (a plugin can only read secrets it has been granted) is added when the capability gate lands in slice 3.

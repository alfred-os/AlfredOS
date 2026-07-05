# ADR-0044: Dependency version-constraint policy (no speculative upper caps)

- **Status:** Accepted
- **Date:** 2026-07-05
- **Deciders:** #391 (dependency modernization); architect review
- **Related:** ADR-0007 (toolchain: ruff/mypy/pyright), #391

## Context

AlfredOS is a **self-hostable application**, not a published library, and it
commits a resolved lock file (`uv.lock`). Historically many direct dependencies
in `pyproject.toml` carried speculative upper caps (`pydantic>=…,<3`,
`aiohttp>=…,<4`, `prometheus-client>=…,<1`, `cachetools>=…,<8`, …). Dependabot
only ever raises the lower *floor*; it never touches an upper cap. The net effect
was that the caps silently froze every dependency below its next major — and,
because no next-major had actually shipped for any of them, the caps blocked
nothing today while guaranteeing they would block (and cause resolution
friction) the moment a major landed.

## Decision

1. **No speculative upper caps on direct dependencies.** Declare a lower floor
   only when a specific feature/behaviour requires a minimum version (with a
   comment saying why). Do **not** add `<N` "just in case."
2. **The lock file provides reproducibility.** `uv.lock` pins exact resolved
   versions for every environment; that is the reproducibility mechanism, not the
   `pyproject.toml` ranges.
3. **Majors surface via CI + Dependabot, not caps.** A breaking major is caught
   by the test suite when the lock resolves it (or when a Dependabot PR proposes
   it), which is a real review gate — unlike a cap, which just hides the update.
4. **Exception — irreversible/operator-migration dependencies stay gated.**
   Datastore images (Postgres, Redis) whose major bumps are operator
   data-migration events are pinned by tag and have their **majors** excluded
   from Dependabot auto-PRs (see `.github/dependabot.yml` `ignore` +
   `docs/runbooks/2026-07-05-postgres-18-redis-8-upgrade.md`). Patch/minor still
   flow for security pickup.
5. **Frameworks with known-costly majors keep a floor + a comment**, not a cap —
   e.g. `discord.py` and `GitPython` note that a major would need coordinated
   work and should be reviewed deliberately when CI surfaces it.

## Consequences

- New dependency additions must justify a floor and must not add an upper cap
  without a documented, concrete incompatibility.
- The Dependabot `docker` group carries a major-version `ignore` for `postgres`
  and `redis` so a DB major is never auto-opened (it would pass green CI while
  silently breaking prod persistence — the exact trap #391 hit and fixed).
- A framework major (pydantic 3, sqlalchemy 3, discord.py 3, …) will now resolve
  into a Dependabot PR / a `uv lock --upgrade` and be gated by the test suite,
  rather than being invisibly blocked. Reviewers treat those PRs as migrations.

## Alternatives considered

- **Keep `<N+1` caps as an explicit major-review gate.** Rejected: for a
  lockfile app the same gate is provided by CI + Dependabot's major-update PRs,
  and caps add resolution friction + freeze security/feature updates in the
  meantime. This is the modern app-dependency consensus (uv / Poetry
  communities).

# 0006 — Alembic for schema migrations

- **Status**: Accepted
- **Date**: 2026-05-24
- **Slice**: 1 (`docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md`)
- **Supersedes**: —
- **Superseded by**: —

## Context

The PRD calls for Postgres 16 + pgvector as the durable datastore but does not name a migration tool. Slice 1 introduces two tables (`episodes`, `audit_log`) and is the first time the project writes a schema. Whatever we pick now will own every future schema change.

Candidates:

- **Alembic**: the de-facto SQLAlchemy migration tool. Autogenerate from ORM models, downgrade scripts, branching, online migrations possible with care.
- **sqlx-style raw SQL files** (e.g. `dbmate`, `goose`): no ORM coupling, plain `.sql` files. Better for polyglot teams, weaker for an ORM-first Python codebase.
- **Pure code-first** (let SQLAlchemy `Base.metadata.create_all` run on boot): not a migration tool at all. Works for slice 1, fails the moment the schema changes in slice 2.

## Decision

Slice 1 adopts **Alembic** as the schema-migration tool. Migrations live in `src/alfred/memory/migrations/versions/`. The env.py uses async SQLAlchemy. The initial migration (`0001_initial.py`) creates `episodes` and `audit_log` with their `language` columns and the required indexes (notably `(user_id, created_at)` for the episodic-read-on-restart query).

The smoke test and the integration test **both** run `alembic upgrade head` against their test database. Using `Base.metadata.create_all()` in tests is **forbidden** — it produces a schema that diverges silently from the migration trail.

## Consequences

**Positive**

- Schema changes are reviewable as diffs in version control.
- Downgrade scripts exist, so a bad migration in a deployed Alfred can be reversed.
- The slice-1 test suite catches "migration body forgot to add the column the ORM expects" — the most common Alembic bug — because every test starts from a fresh `alembic upgrade head`.
- Future contributors who introduce a new table do so via `alembic revision --autogenerate -m "..."` and a human review of the generated diff (autogenerate misses a lot, but it's a useful starting draft).

**Negative**

- Alembic + SQLAlchemy 2.0 async is the less-common pairing; the env.py is non-trivial. Slice 1 ships a reference env.py that future migrations follow.
- Online migrations of large tables require care (no `ALTER TABLE` with a default on a 10M-row table without a column-rewrite-free path). This is not a slice-1 problem but the team must know it before we get there.
- Alembic adds a dependency. ~3 MB installed. Acceptable.

**Neutral**

- The migration directory lives under `src/alfred/memory/` because memory owns the schema. If a future subsystem needs its own tables (e.g. the reviewer-gate audit log), it owns its own migrations dir under `src/alfred/<subsystem>/migrations/` and Alembic is configured with multiple version locations.

## Slice-2+ implications

- pgvector usage (semantic memory in slice 4+) adds the `vector` extension via a migration: `CREATE EXTENSION IF NOT EXISTS vector;`. When that lands, test fixtures must boot a Postgres image with pgvector available (testcontainers' `pgvector/pgvector:pg18` image, not the vanilla `postgres:18` image). The current schema is pgvector-free, so the fixtures use vanilla `postgres:18` (base image bumped 16→18 per the 2026-07-05 upgrade runbook).
- The audit log will grow large. Partitioning by month is a slice-5+ decision; document it in its own ADR when the time comes.

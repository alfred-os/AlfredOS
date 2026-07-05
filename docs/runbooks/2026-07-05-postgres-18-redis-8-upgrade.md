# Upgrade note — Postgres 16 → 18 and Redis 7 → 8 base images

**Applies to:** any existing `docker compose` deployment with a populated
`alfred_pg_data` volume. **Fresh installs need no action** — `initdb` creates a
Postgres 18 cluster on first boot.

## What changed

`docker-compose.yaml` (and the CI service blocks + all testcontainers fixtures)
moved from `postgres:16` → `postgres:18` and `redis:7` → `redis:8`, bringing the
datastore images to the latest stable majors. The AlfredOS schema is pgvector-free
today (vector search is Qdrant / a later slice), so the plain `postgres:18` image
is correct; no extension image is needed.

## Redis 7 → 8 — no action

Redis 8 reads a Redis 7 `dump.rdb` / AOF without conversion, so the existing
`alfred_redis_data` volume is picked up as-is on the first `docker compose up`.

Redis 8 GA folds the query/JSON/timeseries modules into the core image. Alfred
does not use them, and Redis stays on the internal `alfred_internal` network with
no external egress (Spec C), so the added surface is not exposed — but if you run
Redis with your own config, keep `protected-mode` on and do not enable the
bundled modules unless you need them.

## Postgres 16 → 18 — REQUIRED data migration

Postgres refuses to start when the server major does not match the on-disk
cluster (`database files are incompatible with server`). A `postgres:18` container
will **not** boot on a `postgres:16` data directory — the compose service pins
`PGDATA=/var/lib/postgresql/data` (the named-volume path) precisely so this loud
guard fires instead of `initdb` silently building a fresh empty cluster at
pg18's relocated default path. Migrate with a logical dump/restore **before**
pulling the new image.

> **Test this on a copy first.** This procedure is operator-run and not covered
> by CI (testcontainers use ephemeral clusters). Rehearse it against a clone of
> your data volume, or a staging stack, before running it on production.

> **⚠️ The dump is a secret.** `alfred-pg16-dump.sql` contains ALL database
> content — `episodes`, `audit_log`, `semantic_facts` (the user PII the DLP layer
> normally guards) — **plus role password hashes** (`pg_dumpall` emits
> `CREATE ROLE … PASSWORD`). Treat it like a credential: write it `0600`, keep it
> off shared storage, and shred it once the new cluster is verified. Add
> `--no-role-passwords` to the dump if you manage roles out-of-band.

```bash
# 1. With the OLD stack still on postgres:16, dump every database + roles.
#    umask 077 so the dump lands 0600 (it holds PII + password hashes):
( umask 077 && docker compose exec -T alfred-postgres \
    pg_dumpall -U "${POSTGRES_USER:-alfred}" > alfred-pg16-dump.sql )

# 2. Stop the stack and remove the old data volume. Resolve the EXACT name first
#    (compose prefixes the project dir) and verify it before deleting — a
#    substring match could hit another project's volume:
docker compose down
# Confirm the compose volume is declared, then build the EXACT project-prefixed
# name (compose prefixes with the project dir) as a separate step — do not fold
# the check into the assignment:
docker compose config --volumes | grep -qx alfred_pg_data \
  || { echo "no 'alfred_pg_data' volume in this compose project — aborting"; exit 1; }
vol="$(basename "$(pwd)")_alfred_pg_data"                  # e.g. alfredos_alfred_pg_data
docker volume ls --format '{{.Name}}' | grep -Fx "$vol"   # prints exactly this one volume
docker volume rm "$vol"

# 3. Pull postgres:18 and start ONLY the DB so initdb builds a fresh pg18 cluster:
docker compose pull alfred-postgres
docker compose up -d alfred-postgres
docker compose exec alfred-postgres \
  bash -c 'until pg_isready -U "${POSTGRES_USER:-alfred}"; do sleep 1; done'

# 4. Restore into the fresh cluster:
docker compose exec -T alfred-postgres \
  psql -U "${POSTGRES_USER:-alfred}" -d postgres < alfred-pg16-dump.sql

# 5. Bring the rest of the stack up:
docker compose up -d
```

`initdb` in step 3 pre-creates the `alfred` role and `alfred` database (from
`POSTGRES_USER`/`POSTGRES_DB`), so the step-4 restore prints
`role "alfred" already exists` / `database "alfred" already exists`. These are
**expected and harmless** — the restore continues and the data lands in the
existing database.

Keep `alfred-pg16-dump.sql` (still `0600`) until you have confirmed the new
cluster is healthy (`alfred status`, a smoke round-trip), then shred it. It is
your rollback: revert the compose tag to `postgres:16` and restore the dump into
a fresh 16 cluster.

> **`pg_upgrade` alternative.** For very large datasets a link-mode `pg_upgrade`
> is faster than dump/restore, but it needs both major binaries in one image and
> is out of scope for this note; dump/restore is the supported path.

## For self-hosters who pinned their own tag

If you overrode `image:` in a compose override file, update it too — the version
lives only in the tag, and there is no runtime version negotiation.

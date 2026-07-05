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

## Postgres 16 → 18 — REQUIRED data migration

Postgres refuses to start when the server major does not match the on-disk
cluster (`database files are incompatible with server`). A `postgres:18` container
will **not** boot on a `postgres:16` data directory. Migrate with a logical
dump/restore **before** pulling the new image:

```bash
# 1. With the OLD stack still on postgres:16, dump every database + roles:
docker compose exec -T alfred-postgres \
  pg_dumpall -U "${POSTGRES_USER:-alfred}" > alfred-pg16-dump.sql

# 2. Stop the stack and REMOVE the old data volume (name is <project>_alfred_pg_data;
#    `docker volume ls | grep alfred_pg_data` shows the exact name):
docker compose down
docker volume rm "$(docker volume ls -q | grep alfred_pg_data)"

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

Keep `alfred-pg16-dump.sql` until you have confirmed the new cluster is healthy
(`alfred status`, a smoke round-trip). It is your rollback: revert the compose tag
to `postgres:16` and restore the dump into a fresh 16 cluster.

> **`pg_upgrade` alternative.** For very large datasets a link-mode `pg_upgrade`
> is faster than dump/restore, but it needs both major binaries in one image and
> is out of scope for this note; dump/restore is the supported path.

## For self-hosters who pinned their own tag

If you overrode `image:` in a compose override file, update it too — the version
lives only in the tag, and there is no runtime version negotiation.

# Per-user concurrent ContentHandle cap — design

**Date:** 2026-06-02 (rev-2 2026-06-03 — post-review fold-in)
**Author:** Claude Code (on behalf of Ian Dominey)
**Scope:** Issue [#157](https://github.com/alfred-os/AlfredOS/issues/157) — Slice-3 UAT finding F10
**Anchors:** [`docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md`](2026-05-30-slice-3-trust-tier-completion-design.md) §7.10 line 591 (cap invariant); §7.7 (rate-limit Lua-atomic precedent); `config/policies.yaml` `web_fetch.max_concurrent_handles_per_user`
**Review pass:** 8 specialists + coordinator (2026-06-03). Findings folded inline; full review at `/tmp/claude-501/review-plan/2026-06-02-handle-cap-design-spec/`.

---

## 1. What this is for

`HandleCap` is a per-user concurrent-resource counter. It bounds **how many `ContentHandle`s a single user can have alive in Redis at one moment**, where "alive" means: the fetched response body still sits under `alfred:content:{handle_id}` and has not yet been extracted, canary-quarantined, or TTL-expired.

It complements — does not replace — the existing rate limits. Their coverage:

| Defence | What it bounds | What it doesn't bound |
|---|---|---|
| Per-domain rate (10/min) | Hammering one site | Spreading across many sites |
| Per-user rate (30/min) | Request burst rate | Bodies sitting in Redis from prior bursts |
| Per-user daily (100/day) | Long-tail abuse | Burst at any moment |
| Body size cap (5MB) | Single fetch size | Many in flight together |
| **Handle cap (5 concurrent)** | **Live Redis footprint per user** | — |

Worst-case math without it: a user at the 30/min rate limit, all fetches at the 5MB body cap, with slow extracts → up to **150 MB of T3 content parked in Redis from one user**. Redis is shared infrastructure; one user must not be able to do that. The cap binds back-pressure to the user who created it — slow to extract → can't issue more fetches until existing handles drain.

The mental model: rate limits answer "how often can you ask?"; the cap answers "how much can you have outstanding right now?"

**Why this matters now.** Slice-3 UAT (issue #134 comment 4605611300) flagged this as the only genuine spec gap surfaced by the post-merge pass. Adjacent rate-limits mitigate the worst case enough that the verdict was `PASS_WITH_PARTIALS`, but the cap is a slice-spec-promised invariant ([slice-3 design spec](2026-05-30-slice-3-trust-tier-completion-design.md) §7.10 line 591) that must be implemented to close the residual risk.

---

## 2. Architecture

### 2.1 New module

`src/alfred/plugins/web_fetch/handle_cap.py` — standalone `HandleCap` class, sibling to `RateLimiter` and `ContentStore`. SRP: one bucket (handle count), one per-id ZSET membership, one Lua script. Constructor takes `redis_url` + `HandleCapConfig`; matches `RateLimiter`'s shape so the dispatcher's wiring stays uniform.

**Connection-pool contract.** `HandleCap` mints + owns a long-lived `redis.asyncio.Redis` client on first use (perf-006 precedent — match `RateLimiter._client` lifecycle exactly). The dispatcher holds one `HandleCap` instance for the process lifetime. `aclose()` is idempotent (supervisor SIGKILL paths). The `HandleCap` Redis URL must point at the SAME Redis that `ContentStore` writes bodies into — if they diverge, the cap counts handles in a different keyspace from where the bodies actually live (silent decorrelation).

### 2.2 Redis state

Per-user sorted set:

```
key:    alfred:handles:user:{user_id}
member: {handle_id}              (UUID4 string)
score:  {expiry_epoch_ms}        (when this handle's content TTL fires)
```

One key per user; one member per live handle. `ZCARD` = current "alive" count. The `user_id` segment is the canonical user id (slug-format per `src/alfred/identity/slug.py`) — already constrained to a closed character set, so no key-injection surface.

### 2.3 Atomic check-and-reserve script

```lua
-- KEYS[1] = alfred:handles:user:{user_id}
-- ARGV[1] = cap                (int >= 1, validated host-side)
-- ARGV[2] = handle_id          (UUID4 string)
-- ARGV[3] = expiry_ms          (int, > now_ms, validated host-side)
-- ARGV[4] = now_ms             (int, > 0, validated host-side)
-- ARGV[5] = outer_key_ttl_sec  (int, > 0, validated host-side)
--
-- Returns "ok" | "exceeded"
local key = KEYS[1]
local cap = tonumber(ARGV[1])
local handle_id = ARGV[2]
local expiry_ms = tonumber(ARGV[3])
local now_ms = tonumber(ARGV[4])
local outer_ttl = tonumber(ARGV[5])

-- Passive eviction of TTL-expired handles. This is the ONLY mechanism
-- by which TTL expiry reduces the count (Redis keyspace notifications
-- are not reliable enough to use as a release signal).
redis.call('ZREMRANGEBYSCORE', key, '-inf', now_ms)

local live = redis.call('ZCARD', key)
if live >= cap then
    return 'exceeded'
end

redis.call('ZADD', key, expiry_ms, handle_id)
redis.call('EXPIRE', key, outer_ttl)
return 'ok'
```

Atomicity is load-bearing: without it, two concurrent reserves at the boundary could both observe `live = cap-1` and both succeed, breaking the cap (the same shape as the rate-limit race the existing Lua script defends against).

**ARGV validation discipline (host-side, before EVALSHA).** Every numeric ARGV is validated in the Python wrapper before the script runs. `tonumber()` in Lua returns `nil` on non-numeric / NaN / Inf input; `ZADD key, nil, member` raises a Lua-level error; `EXPIRE key, nil` does the same; a NEGATIVE TTL value passed to `EXPIRE` deletes the key in some Redis versions (silent state corruption) — all CLAUDE.md hard rule #7 violations. The Python wrapper raises `ValueError` for any invalid input BEFORE invoking the script:

```python
def _validate_argv(cap: int, expiry_ms: int, now_ms: int, outer_ttl: int) -> None:
    for name, value in (("cap", cap), ("expiry_ms", expiry_ms),
                        ("now_ms", now_ms), ("outer_ttl", outer_ttl)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"HandleCap ARGV {name!r} must be int, got {type(value).__name__}")
        if value <= 0:
            raise ValueError(f"HandleCap ARGV {name!r} must be > 0, got {value}")
    if expiry_ms <= now_ms:
        raise ValueError(f"HandleCap ARGV expiry_ms ({expiry_ms}) must be > now_ms ({now_ms})")
```

`float`, `bool`, `str`, `None`, NaN, Inf, negative, and `expiry_ms <= now_ms` all fail fast. Tested in §8.2.

**Constants.** The outer-key TTL floor is named (not magic):

```python
_OUTER_KEY_TTL_FLOOR_SECONDS: Final[int] = 600   # 10 min — bounds empty-ZSET keyspace footprint
```

`outer_ttl = max(handle_ttl_seconds * 2, _OUTER_KEY_TTL_FLOOR_SECONDS)`. The 600s floor is operationally trivial (~80-100B overhead per idle user × 10K users ≈ 1MB held ≤10 min) and prevents thrashing when handle TTLs are short.

**EVALSHA / NOSCRIPT discipline.** The script is registered once per `HandleCap` instance via `client.register_script()` (perf-006). The redis-py `AsyncScript` wrapper auto-handles `NOSCRIPT` by transparently falling back to `EVAL` + re-cache. Pinned by `test_evalsha_noscript_fallback`.

### 2.4 Release

```python
async def release(self, *, user_id: str, handle_id: str) -> None:
    # Idempotent ZREM. Safe to call after TTL has already evicted.
    await self._client.zrem(f"alfred:handles:user:{user_id}", handle_id)
```

No Lua needed — `ZREM` is atomic by itself. Same long-lived client as `try_reserve`.

---

## 3. Host pre-mints handle_id (contract change)

Today the plugin subprocess mints the `handle_id` inside `ContentStore.write` and returns it to the host. For the cap to bind the request **before** the network fetch, the host must know the id at reserve time.

**Two content-store surfaces clarification.** The codebase has two content-store types:
- `src/alfred/plugins/content_store_base.py:ContentStoreBase` Protocol (`put/get/delete` against `TaggedContent[T3]`) — the abstract trust-boundary contract.
- `src/alfred/plugins/web_fetch/content_store.py:ContentStore` (concrete Redis-backed, `write/extract/delete` against raw bytes) — the web-fetch-specific implementation that this spec modifies.

This spec changes the **concrete** Redis `ContentStore` only. The Protocol surface is not touched.

**Concrete changes:**

- `ContentStore.write` signature: `handle_id` becomes a required keyword arg. (Internal mint path removed.)
- `plugins/alfred_web_fetch/web_fetch_plugin._handle_fetch` reads `params["content_handle_id"]` and passes it through to `ContentStore.write`.
- `dispatch_web_fetch` pre-mints `handle_id = str(uuid.uuid4())` once per request and threads it into both `HandleCap.try_reserve` and the plugin dispatch params dict.

**Host-side equality check (defence-in-depth).** After the plugin returns the `ContentHandle`, the dispatcher verifies:

```python
if not isinstance(result, ContentHandle) or result.id != handle_id:
    # Plugin returned a handle with a different id than we pre-minted.
    # The body lives under THEIR id in Redis (decorrelating cap counter
    # from real memory pressure) — fail loud, release the reservation,
    # emit a dlp_scan_result="handle_id_mismatch" audit row.
    await handle_cap.release(user_id=user_id, handle_id=handle_id)
    await audit.append_schema(..., dlp_scan_result="handle_id_mismatch", ...)
    raise WebFetchError(t("web.fetch.error.handle_id_mismatch"))
```

A buggy / compromised plugin that uses a different id would otherwise silently desynchronise the cap's accounting from real Redis memory.

**Files affected (contract change ripple):**
- `src/alfred/plugins/web_fetch/content_store.py` (handle_id required)
- `plugins/alfred_web_fetch/web_fetch_plugin.py` (forward content_handle_id param)
- `tests/unit/plugins/web_fetch/test_content_handle_single_use.py` (and any other test that calls `write` directly)
- `tests/integration/test_redis_compose_service.py::test_content_handle_single_use_delete`

**Rationale for pre-mint vs alternatives.** The alternatives (plugin mints + post-add cap-counting after the body is already in Redis; placeholder-then-swap) both let the body land in Redis before the cap check sees it, which inverts the cap's intent — it's supposed to prevent the fetch, not refuse after.

---

## 4. Dispatcher flow

Insert one new step between rate-limit and transport dispatch. `dispatch_web_fetch` gains one new kwarg — `handle_cap: HandleCap` — alongside the existing `rate_limiter` / `outbound_dlp` / `audit` / `transport` injection. **`FetchDispatchConfig` (frozen, config-only) is NOT widened** — `HandleCap` is a mutable runtime collaborator, not config.

```python
# ...existing TLS → DLP → allowlist → host-IP → rate_limit checks...

handle_id = str(uuid.uuid4())
handle_ttl_seconds = (
    action_deadline_seconds
    + max_extraction_retries * per_retry_budget_seconds
    + slack_seconds
)

# try_reserve raises WebFetchRateLimited(bucket="handle_cap") if cap exceeded.
try:
    await handle_cap.try_reserve(
        user_id=user_id,
        handle_id=handle_id,
        handle_ttl_seconds=handle_ttl_seconds,
    )
except WebFetchRateLimited as e:
    await audit.append_schema(
        fields=WEB_FETCH_FIELDS, schema_name="WEB_FETCH_FIELDS",
        event="tool.web.fetch", actor_user_id=user_id,
        subject={
            "url": clean_url, "domain": domain,
            "status_code": None,
            "content_handle_id": None,    # cap refusal happens BEFORE plugin call;
                                          # the pre-minted UUID was never written.
                                          # Matches existing rate-limit refusal precedent.
            "fetch_depth": _FETCH_DEPTH,
            "rate_limit_bucket": "handle_cap",
            "manifest_commit_hash": config.manifest_commit_hash,
            "trust_tier_of_result": "T3",
            "dlp_scan_result": "handle_cap_exceeded",
            "canary_tripped": False,
            "triggering_user_id": user_id,
            "correlation_id": correlation_id,
        },
        trust_tier_of_trigger="T0",
        result="rate_limited",
        cost_estimate_usd=0.0,
        trace_id=correlation_id,
    )
    raise

# CRITICAL: use try/finally with a released flag so asyncio.CancelledError
# (which inherits BaseException in Python 3.12, NOT Exception) cannot leak
# a reservation. A bare `except Exception:` arm would miss cancellation
# and leave the slot held until ~80s passive TTL — flaky upstream → cap
# exhaustion under high cancellation rate.
released = False
try:
    try:
        result = await transport.dispatch(
            "web.fetch",
            {..., "content_handle_id": handle_id},
        )
    except Exception:
        await handle_cap.release(user_id=user_id, handle_id=handle_id)
        released = True
        # ...existing transport_error audit row...
        raise

    if isinstance(result, ControlResult):
        await handle_cap.release(user_id=user_id, handle_id=handle_id)
        released = True
        # ...existing typed-plugin-error handling...

    # Defence-in-depth: host-side handle_id equality check.
    if not isinstance(result, ContentHandle) or result.id != handle_id:
        await handle_cap.release(user_id=user_id, handle_id=handle_id)
        released = True
        await audit.append_schema(
            ...,
            subject={..., "dlp_scan_result": "handle_id_mismatch", ...},
            result="handle_id_mismatch", ...,
        )
        raise WebFetchError(t("web.fetch.error.handle_id_mismatch"))

    # Success path: try to emit success audit row.
    try:
        await audit.append_schema(..., result="ok", ...)
        # Success — leave the reservation in place. The body lives under
        # handle_id in Redis; extract / canary / passive TTL will release.
        # Set released=True so the finally arm does NOT release the slot
        # we WANT to hold.
        released = True
    except Exception:
        # Disputed-#1 decision: HOLD the cap until passive TTL.
        # The body IS in Redis under handle_id consuming memory; releasing
        # would let the user reset their cap while the body still occupies
        # the resource the cap is meant to bound. Emit a LOUD structlog
        # event so the operator sees the stuck reservation.
        log.error(
            "web_fetch.handle_cap.success_audit_failed_holding_cap",
            user_id=user_id, handle_id=handle_id,
            correlation_id=correlation_id,
            note="cap slot held until passive TTL (~80s); body in Redis",
        )
        released = True  # block the finally-arm release; passive TTL frees
        raise

    return result

finally:
    # asyncio.CancelledError catch-all. If anything cancelled this task
    # between reserve and a control-flow path that set released=True,
    # release the slot here. Idempotent — release of already-released
    # handle_id is a no-op ZREM.
    if not released:
        # Use shield + suppress to ensure release fires even under nested cancel.
        with contextlib.suppress(Exception):
            await asyncio.shield(handle_cap.release(user_id=user_id, handle_id=handle_id))
```

**Ordering rationale.** Cap is checked **after** rate-limit. A cap-exhausted user still gets their per-minute slot incremented for a refused request — acceptable; matches the existing precedent.

**Daily-budget side-effect (acknowledged).** The existing `RateLimiter.check_and_increment` is non-rollback-able: it INCRs the daily-100 counter atomically on all-pass. A user with 5 parked handles burns daily budget on cap-refused attempts. Once the parked handles drain, the daily budget may also be exhausted — the user is effectively self-DoSed for the rest of the day. This is INTENTIONAL back-pressure (encourages quick handle extraction) but is documented here so operators understand the audit-log pattern.

**`dlp_scan_result` vocabulary choice.** The slice-3 design spec §7.10 mandates the literal string `"handle_cap_exceeded"`. The existing rate-limit refusal precedent uses `"rate_limited"` for all three buckets, with the per-bucket signal on `rate_limit_bucket`. We honour the slice-3 spec text and add `"handle_cap_exceeded"` as a NEW closed-set value:

- `dlp_scan_result` legal values widen to: `{"clean", "scanned_dirty", "dlp_scan_error", "domain_not_allowed", "rate_limited", "transport_error", "dispatch_shape_error", "internal_ip_refused", "redirect_refused", "tls_verification_failed", "fetch_error", "handle_cap_exceeded", "handle_id_mismatch"}` (last two added by this spec).
- `audit_row_schemas.py` gains a `typing.Literal[...]` for the closed set so future emitter typos surface at type-check time, not at runtime.
- `CHANGELOG.md` records the closed-set expansion under the audit-vocabulary header.
- The audit `result` field stays `"rate_limited"` (per spec) so audit-graph queries filtering on `result IN ('rate_limited')` continue to surface cap refusals as part of the rate-limit family.

---

## 5. Lifecycle release wiring

Three release sites, all idempotent (calling release on an already-evicted id is a `ZREM` of a missing member — no-op).

### 5.1 Extract-success release (forward-looking)

**Status: contingent.** The canonical Redis `ContentStore.extract` (`GETDEL` against `alfred:content:{handle_id}`) has **no caller in `src/` today** — the quarantined extractor currently uses an in-process `_content_cache.pop` path. The release-on-extract wiring this section describes is the canonical SHAPE, but its actual implementation point depends on which extract path lands first.

**For this PR (scope):** the dispatcher arms (§4) + canary-trip path (§5.2) + passive TTL eviction (§5.3) cover the release sites that DO exist. A handle consumed via the in-process `_content_cache.pop` does NOT release the cap slot — the slot waits ~80s for passive TTL eviction. Acceptable interim behaviour because the Redis body IS still consuming memory until either the in-process consumer separately deletes it OR Redis TTL fires.

**For the eventual canonical wire-up:** when the quarantined extractor migrates to `ContentStore.extract` (or the Redis read path is otherwise wired through the canonical surface), the signature becomes:

```python
async def extract(self, handle_id: str, user_id: str) -> bytes:
    # Only on successful GETDEL — body returned, key deleted.
    body = await self._client.getdel(f"alfred:content:{handle_id}")
    if body is None:
        raise ContentHandleExpired(handle_id)
    # Release fires only after confirmed Redis state change.
    await self._handle_cap.release(user_id=user_id, handle_id=handle_id)
    return body
```

Release-suppression cases (apply when extract is canonically wired):
- **Miss path (`ContentHandleExpired`):** handle is already gone from Redis; passive eviction handles the ZSET entry.
- **Redis transient error mid-extract:** body is in unknown state. Conservative — do NOT release; passive eviction within ~80s will clean up.

This PR tracks the missing wire-up under a follow-up issue (to be filed against the quarantined-extractor migration).

### 5.2 `InboundCanaryScanner.scan` (canary-trip)

Signature change: `scan(*, handle_id: str, source_url: str, user_id: str) -> None`. **Only** on successful `self._store.delete(handle_id)` (the body is confirmed gone from Redis) call `handle_cap.release(user_id=user_id, handle_id=handle_id)`.

Release-suppression cases:
- **Delete raised `RedisError`:** the body may still be in Redis consuming memory. The cap's purpose is to bound Redis memory pressure; releasing the slot while the body lives would let the user reset their cap by serving canary-tripped content, which is a perverse incentive. Leave the slot held; passive TTL eviction will free it within ~80s.
- **Fault path (`CanaryScanError` on missing body):** handle is already gone; passive eviction handles it.

The typed `WebFetchCanaryTripped` exception STILL propagates in all cases (per existing `err-002` discipline) — release decisions affect cap state only, never the security-event signal.

### 5.3 TTL expiry

Zero callsites. Passive eviction via the `ZREMRANGEBYSCORE` at the head of every `try_reserve` cleans up. The outer `EXPIRE` (`max(handle_ttl*2, _OUTER_KEY_TTL_FLOOR_SECONDS)`, named in §2.3) ensures an idle user's ZSET key eventually disappears so the keyspace doesn't accumulate empty sorted sets per ever-active user.

### 5.4 user_id propagation (explicit)

The `user_id` propagation is via direct parameter threading — there is **no "correlation context" object** in `src/alfred/`. Each release site receives `user_id` as a keyword argument; the dispatcher (which receives `user_id` as a top-level arg) threads it down.

**Concrete propagation map:**

| Release site | Current state | Required change |
|---|---|---|
| `dispatch_web_fetch` error arms (§4) | Already has `user_id` as a parameter | No change |
| `InboundCanaryScanner.scan` (§5.2) | Signature is `scan(*, handle_id, source_url)` — no user_id | **Hook-payload extension:** the `tool.web.fetch` post-hookpoint dispatcher must include `triggering_user_id` in the event context, and the scanner's registration adapter pulls it out and threads to `scan()`. Update `canary_scanner.SCANNER_REGISTRATION` accordingly. |
| `ContentStore.extract` (§5.1, forward-looking) | No caller in `src/` today | Contingent on canonical extract wire-up. When wired, the quarantined extractor (host-side, post-extract) calls `release(user_id=..., handle_id=...)`. The extractor already knows `user_id` from its own correlation. |

**JSON-RPC boundary note.** `content_handle_id` crosses the plugin-subprocess JSON-RPC boundary as a request param (host → plugin). `user_id` does NOT cross — the plugin doesn't need it, and not exposing it to the subprocess preserves the trust-boundary minimisation principle.

---

## 6. Errors + audit row

### 6.1 Error type

`WebFetchRateLimited.bucket` widens from `{"per_domain", "per_user", "daily_budget"}` to also accept `"handle_cap"`. The `errors.py` docstring is updated; the bucket discriminator's documented vocabulary becomes a `typing.Literal[...]` in the module's type annotations. No new exception class — the cap refusal is operationally a rate-limit refusal (the slice-3 spec mandates `WebFetchRateLimited`).

**New exception class:** `WebFetchError` subclass for the §3 host-side equality-check failure. The spec does NOT mandate this be a `WebFetchRateLimited` subtype (it's an integrity violation, not a refusal). Concrete name: `WebFetchHandleIdMismatch(WebFetchError)`.

### 6.2 Audit row

Uses existing `WEB_FETCH_FIELDS` — no schema change:
- `rate_limit_bucket = "handle_cap"` (typed discriminator for operators filtering by bucket)
- `dlp_scan_result = "handle_cap_exceeded"` (slice-3 spec §7.10 line 591 string; closed-set expansion documented in `CHANGELOG.md`)
- `content_handle_id = None` (cap refusal happens BEFORE the plugin call; the pre-minted UUID was never written to Redis. Matches existing rate-limit refusal precedent at `fetch_dispatcher.py:483`.)
- `result = "rate_limited"` (matches existing rate-limit refusal precedent; audit-graph queries on `result IN ('rate_limited')` continue to surface cap refusals)
- `trust_tier_of_trigger = "T0"`, `trust_tier_of_result = "T3"`, `canary_tripped = False` (per existing conventions)

**Closed-vocabulary widening discipline.** Adding `"handle_cap"` to `rate_limit_bucket` and `"handle_cap_exceeded"` + `"handle_id_mismatch"` to `dlp_scan_result` widens two existing closed vocabularies. We:

1. Promote both to `typing.Literal[...]` in `src/alfred/audit/audit_row_schemas.py` so future emitter typos surface at type-check time.
2. Record the widening in `CHANGELOG.md` under an "Audit vocabulary" header so operators know to extend any DB-side filters.
3. Verify (cross-check confirmed 2026-06-03) — **no `ops/grafana/` or `ops/prometheus/` directory exists in the repo today**, so there are no live dashboards to migrate. When observability lands (future slice), the typed `Literal[...]` becomes the canonical source.

### 6.3 i18n

**Dedicated catalog entries (committed, not deferred to catalog-PR author).** The existing `web.fetch.error.rate_limited` msgstr at `locale/en/LC_MESSAGES/alfred.po:1313-1317` is mechanically clean with `bucket="handle_cap"` interpolation but substantively misleading — it points operators at `web_fetch.rate_limits` when the cap knob lives at `web_fetch.max_concurrent_handles_per_user`. We add:

```po
#: src/alfred/plugins/web_fetch/errors.py
msgid "web.fetch.error.rate_limited.handle_cap"
msgstr ""
"Too many concurrent web.fetch requests in flight for this user "
"(cap reached). Wait for an existing request to complete, or raise "
"web_fetch.max_concurrent_handles_per_user in policies.yaml."

#: src/alfred/plugins/web_fetch/errors.py
msgid "web.fetch.error.handle_id_mismatch"
msgstr ""
"The fetch plugin returned a content handle whose id does not match "
"the host-side reservation. This indicates a plugin defect; the audit "
"row carries forensic detail."
```

`WebFetchRateLimited.__init__` dispatches on `bucket` and chooses the right key:

```python
if bucket == "handle_cap":
    msg = t("web.fetch.error.rate_limited.handle_cap")
else:
    msg = t("web.fetch.error.rate_limited", bucket=bucket)
```

**Closed-vocabulary audit-row tags (NOT routed through `t()`).** `dlp_scan_result="handle_cap_exceeded"`, `rate_limit_bucket="handle_cap"`, structlog event names (`web_fetch.handle_cap.release_failed`, `web_fetch.handle_cap.success_audit_failed_holding_cap`) follow the existing precedent (`domain_not_allowed`, `rate_limited`, `transport_error`, `web_fetch.canary.quarantine_failed`) — they are operator-vocabulary discriminators, not user-facing prose, and stay as Python string literals.

---

## 7. Operator override

`config/policies.yaml` already carries `web_fetch.max_concurrent_handles_per_user: 5` (added during Slice-3 PR-S3-5, ahead of the enforcement that this design ships). The policies-loader already caches with mtime-invalidation (per slice-3 spec §7.7).

```python
@dataclass(frozen=True, slots=True)
class HandleCapConfig:
    per_user: int = 5

    def __post_init__(self) -> None:
        if self.per_user < 1:
            msg = (
                "HandleCapConfig.per_user must be >= 1; got "
                f"{self.per_user}. A cap of 0 would refuse every fetch."
            )
            raise ValueError(msg)
```

A misconfigured cap (≤ 0) fails loud at policies-loader time, not silently at first fetch.

**Default-5 rationale.** The 5 default is a small power-of-N close to the typical concurrent-research burst a single operator-tier user would issue (3-4 parallel tabs / agents). At 5 × 5MB = 25MB Redis pressure per user, an instance with 100 active users tops out at ~2.5GB worst-case — within commodity Redis sizing. Operators with single-user / high-throughput deployments raise the cap; multi-tenant operators may lower it.

---

## 8. Testing strategy

### 8.1 Where the Lua actually runs

Lua scripts run against **real Redis** (`testcontainers.redis.RedisContainer("redis:7-alpine")`) — never mocked. Mocking would test our mental model of Lua semantics, not the interpreter. Module-scoped container fixture + function-scoped `HandleCap` mirrors `test_lua_atomic_rate_limit.py` precedent.

| Layer | Backing | What it proves |
|---|---|---|
| `tests/unit/plugins/web_fetch/test_handle_cap.py` | testcontainers Redis | Lua script semantics, atomicity, TTL behaviour, error paths, ARGV validation |
| `tests/property/plugins/web_fetch/test_handle_cap_invariants.py` | testcontainers Redis + hypothesis | Stateful invariant (`ZCARD ≤ cap`) under all interleavings of reserve/release/expire |
| `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py` (extend) | `HandleCap` AsyncMock | Dispatcher wiring: reserve before transport, release on error arms, host-side equality check, CancelledError safety, no release on success |
| `tests/unit/plugins/web_fetch/test_content_handle_single_use.py` (extend) | testcontainers Redis | `write` signature change covered; eventual extract release contingent |
| `tests/adversarial/dlp_egress/handle_cap_exhaustion.yaml` | testcontainers Redis | End-to-end attacker scenario |

### 8.2 Sad-path catalogue (named tests)

**Atomicity:**
- `test_race_two_at_boundary` — 2 coroutines via `asyncio.TaskGroup`, cap=5 with 4 reserved. Exactly one succeeds, one raises.
- `test_race_six_against_empty` — 6 coroutines, cap=5, empty key. Exactly 5 succeed.
- `test_release_and_reserve_race` — release+reserve interleave. Invariant: `ZCARD <= cap` at every observation.

**ARGV validation (host-side defence against Lua nil/NaN/negative):**
- `test_reserve_rejects_non_int_cap` — `cap=5.5`, `cap="5"`, `cap=True` each raise `ValueError` before EVALSHA.
- `test_reserve_rejects_nan_inf_expiry` — `expiry_ms=float("nan")`, `float("inf")` each raise `ValueError`.
- `test_reserve_rejects_negative_or_zero_ttl` — `outer_ttl=0`, `outer_ttl=-1` each raise `ValueError` (would otherwise DELETE the key in some Redis versions).
- `test_reserve_rejects_expiry_at_or_before_now` — `expiry_ms <= now_ms` raises `ValueError`.

**TTL / passive eviction:**
- `test_expired_entries_evicted_on_next_reserve` — reserve with score in the past via direct Redis manipulation. Next reserve sees count=0, succeeds.
- `test_staggered_expiry_decrements_count` — 5 handles with staggered expiry, sleep between asserts.
- `test_user_key_outer_expire_set` — let all members expire, wait past `_OUTER_KEY_TTL_FLOOR_SECONDS`, `EXISTS = 0`.

**Idempotency:**
- `test_release_unknown_handle_id_no_op` — release of never-reserved id.
- `test_release_twice_no_op` — reserve, release, release.
- `test_reserve_same_handle_id_twice_is_score_update` — ZADD without NX → score update, count unchanged. Documents intentional behaviour.

**Concurrency under release:**
- `test_concurrent_reserve_release_cap_respected` — 20 mixed coroutines, cap=5. Track all observations; cap never breached.

**Configuration edge cases:**
- `test_cap_one_serializes` — cap=1; reserve, refuse, release, reserve.
- `test_cap_large_value_honoured` — cap=1000; 1000 succeed, 1001 refused (no off-by-one).
- `test_cap_zero_validates_at_load` — `HandleCapConfig(per_user=0)` raises at construction.
- `test_default_config_matches_spec` — `HandleCapConfig()` → `per_user=5`.

**User isolation:**
- `test_user_a_cap_does_not_affect_user_b` — independent ZSET keys.

**Redis transient failures by subtype (CLAUDE.md hard rule #7):**
- `test_reserve_timeout_raises_and_logs` — patched `redis.exceptions.TimeoutError`; reserve raises; structured warning fires.
- `test_reserve_connection_error_raises_and_logs` — patched `redis.exceptions.ConnectionError`; reserve raises; structured warning fires.
- `test_reserve_response_error_propagates` — patched `redis.exceptions.ResponseError`; reserve raises; distinguishes runtime Redis bugs from transient I/O.
- `test_reserve_busy_loading_propagates` — patched `redis.exceptions.BusyLoadingError`; reserve fails closed.
- `test_release_timeout_logs_loud_no_propagate` — release-path `ZREM` raises `TimeoutError`; LOUD `web_fetch.handle_cap.release_failed` structlog event; does NOT propagate (caller already past the conversation turn).
- `test_release_connection_error_logs_loud_no_propagate` — same shape, `ConnectionError`.
- `test_evalsha_noscript_reregisters_and_succeeds` — `SCRIPT FLUSH` between calls; auto re-register via redis-py `AsyncScript`.

**Lifecycle integration (in `test_fetch_dispatcher.py`):**
- `test_dispatcher_reserves_before_transport` — mock transport. Verify `try_reserve` fires before `transport.dispatch`.
- `test_dispatcher_releases_on_transport_error` — mock transport raises. Release fires before re-raise.
- `test_dispatcher_releases_on_plugin_typed_error` — `ControlResult` with `WebFetchSizeLimitExceeded`. Release fires.
- `test_dispatcher_releases_on_handle_id_mismatch` — plugin returns `ContentHandle(id="wrong-uuid")`. `WebFetchHandleIdMismatch` raised; release fires; audit row carries `dlp_scan_result="handle_id_mismatch"`.
- `test_dispatcher_releases_on_cancellederror` — outer `asyncio.CancelledError` raised mid-transport. Release fires in the `finally` arm; `released` flag preserved.
- `test_dispatcher_holds_cap_on_success_audit_failure` — success path; `audit.append_schema` raises. Release does NOT fire; LOUD `web_fetch.handle_cap.success_audit_failed_holding_cap` structlog event emitted; exception propagates.
- `test_extract_miss_does_not_release` — extract on expired handle (`ContentHandleExpired`); no release. (Applies when extract is canonically wired.)
- `test_extract_redis_error_does_not_release` — `GETDEL` raises `RedisError` mid-extract; no release. (Applies when extract is canonically wired.)
- `test_canary_trip_releases_on_successful_delete` — scan finds canary, `store.delete` succeeds, release fires; ZCARD drops.
- `test_canary_trip_no_release_on_delete_failure` — `store.delete` raises `RedisError`; release NOT called; `web_fetch.canary.quarantine_failed` structlog still fires; `WebFetchCanaryTripped` still propagates.
- `test_canary_scan_error_does_not_release` — `CanaryScanError` (missing body); no release.

**Property-based (hypothesis) stateful test:**
- `tests/property/plugins/web_fetch/test_handle_cap_invariants.py::HandleCapStateMachine` — `RuleBasedStateMachine` modelling `reserve(user_id, handle_id)`, `release(user_id, handle_id)`, and `expire(user_id, handle_id)` rules. Invariant decorator: `assume(ZCARD(alfred:handles:user:{any_user}) <= cap)`. Hypothesis explores random interleavings; any violation surfaces a minimal counterexample. Complements (does not replace) the example-based race tests above.

**Adversarial:**
- `tests/adversarial/dlp_egress/handle_cap_exhaustion.yaml` — single user, 100 fetches in flight across 100 allowlisted endpoints, cap=5. Verifies refusal at fetch #6. **YAML shape matches `tests/adversarial/payload_schema.py:AdversarialPayload`** — `expected_outcome: "audit_row_emitted"` (per `dlp_egress/canary_token_html.yaml` precedent); attack-class metadata documents the 5-keys Redis-keyspace bound as a derived property, not as the assertion shape itself.

### 8.3 Coverage

`HandleCap` is trust-boundary code (CLAUDE.md: trust-boundary modules at 100% line+branch coverage). Every Lua return path (`"ok"`, `"exceeded"`) and every Python branch (ARGV validation, constructor validation, idempotent close, release no-op, EVALSHA NOSCRIPT fallback) is exercised. No `# pragma: no cover` without explicit justification.

### 8.4 What is NOT mocked

- The Lua script itself (always real Redis).
- ZSET semantics, ZADD score-update behaviour, ZREMRANGEBYSCORE boundaries.
- TTL eviction (real Redis sleep + assert).

### 8.5 What IS mocked

- In dispatcher tests only: `HandleCap` as an AsyncMock. The Redis-backed contract is proven in the module's own tests; dispatcher tests prove the *wiring* (reserve before transport, release on each error arm including the CancelledError finally-arm, no release on success).

---

## 9. Out of scope (deferred to follow-up issues)

- **Multi-tenant operator cap.** Slice out-of-scope note.
- **Cross-instance counter sharing.** Already free — Redis is the single source of truth.
- **Schema migration** to split the overloaded `dlp_scan_result` field (existing `devex-002` note in dispatcher comments — separate follow-up).
- **Keyspace-notification-based eviction.** Passive ZREMRANGEBYSCORE is sufficient and avoids Redis pub/sub fragility.
- **Per-domain cap.** Cap is a per-user resource bound; per-domain caps are already covered by the rate limiter.
- **CLI `alfred web handles --user <uid>`** — operator-side inspection of a user's live handle count. Scheduled for the Slice-4 web-CLI expansion (filed as follow-up issue).
- **Prometheus `alfred_web_fetch_handle_cap_utilisation` metric** — deferred until the `ops/prometheus/` stack lands (no observability stack exists in repo today; cross-check confirmed).
- **Canonical extract-release wire-up** — §5.1 release wiring is contingent on the quarantined-extractor migrating to `ContentStore.extract` (filed as follow-up issue).

---

## 10. PR scope summary

One PR, one umbrella issue (#157):

**New files:**
- `src/alfred/plugins/web_fetch/handle_cap.py` — `HandleCap` class + `HandleCapConfig` + Lua script + ARGV validation
- `tests/unit/plugins/web_fetch/test_handle_cap.py` — testcontainers Redis sad-path catalogue
- `tests/property/plugins/web_fetch/test_handle_cap_invariants.py` — hypothesis stateful test
- `tests/adversarial/dlp_egress/handle_cap_exhaustion.yaml` — adversarial payload (schema-conformant)
- `docs/runbooks/handle-cap-exceeded.md` — operator runbook: "what does `handle_cap_exceeded` mean in the audit log; how to inspect; how to override"

**Modified files:**
- `src/alfred/plugins/web_fetch/content_store.py` — `handle_id` required kwarg
- `src/alfred/plugins/web_fetch/fetch_dispatcher.py` — `handle_cap: HandleCap` kwarg, reserve + release + try/finally + equality check + success-audit-failure HOLD
- `src/alfred/plugins/web_fetch/errors.py` — bucket vocabulary docstring; new `WebFetchHandleIdMismatch`; typed `Literal[...]` for bucket discriminator
- `src/alfred/plugins/web_fetch/canary_scanner.py` — `user_id` param + release call; hook-payload extension for `triggering_user_id`
- `plugins/alfred_web_fetch/web_fetch_plugin.py` — forward `content_handle_id` param
- `src/alfred/audit/audit_row_schemas.py` — typed `Literal[...]` for `rate_limit_bucket` + `dlp_scan_result` closed sets
- `config/policies.yaml` — no change (knob already present; document defaults in inline comment update)
- `locale/en/LC_MESSAGES/alfred.po` — new `web.fetch.error.rate_limited.handle_cap` and `web.fetch.error.handle_id_mismatch` entries
- `CHANGELOG.md` — "Audit vocabulary" entry documenting closed-set expansion
- `docs/subsystems/security.md` — cross-reference HandleCap as a slice-3 spec §7.10 defence

**No CLAUDE.md command-table update** (no new CLI surface this PR — CLI `alfred web handles` is deferred to follow-up).
**No ADR** — matches existing ADR-0017's web.fetch trust-tier completion; this is an in-scope follow-on.

---

## 11. References

- [`docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md`](2026-05-30-slice-3-trust-tier-completion-design.md) §7.10 line 591 — per-user concurrent ContentHandle cap invariant (the actual anchor)
- [`docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md`](2026-05-30-slice-3-trust-tier-completion-design.md) §7.7 — existing rate-limit Lua-atomic pattern (precedent)
- `tests/unit/plugins/web_fetch/test_lua_atomic_rate_limit.py` — testcontainers Redis test precedent
- Issue [#134 comment 4605611300](https://github.com/alfred-os/AlfredOS/issues/134#issuecomment-4605611300) — Slice-3 UAT finding F10
- `CLAUDE.md` hard rules #3 (T3 tagging), #7 (no silent security-path failures), trust-boundary coverage
- `tests/adversarial/payload_schema.py` — adversarial payload Pydantic schema (`AdversarialPayload`)
- 2026-06-03 review pass artifacts: `/tmp/claude-501/review-plan/2026-06-02-handle-cap-design-spec/` (8 specialists + coordinator + 5 cross-checks)

---

## 12. Decisions log (review-pass resolutions)

**Disputed-#1: success-audit-write-failure handling** → **HOLD** the cap until passive TTL. Body is still in Redis under the pre-minted handle_id; releasing would let the user reset their cap while the resource it bounds (Redis memory) is still occupied. LOUD structlog event `web_fetch.handle_cap.success_audit_failed_holding_cap` so operators see the stuck reservation; passive eviction within ~80s reclaims the slot.

**Disputed-#2: `content_handle_id` on cap-refusal audit row** → **`None`**. The cap refusal happens BEFORE the plugin call; the pre-minted UUID was never written to Redis. Setting the field to the UUID would falsely suggest a handle was created; matches the existing rate-limit refusal precedent at `fetch_dispatcher.py:483`.

**§5.1 release-on-extract wiring** → **forward-looking, contingent**. The canonical Redis `ContentStore.extract` has no caller in `src/` today (quarantine plugin uses in-process `_content_cache.pop`). This spec describes the canonical SHAPE; actual wire-up lands when the extractor migrates. Filed as follow-up issue.

**`dlp_scan_result` vocabulary** → **honour slice-3 spec text** (`"handle_cap_exceeded"`) and add typed `Literal[...]` + `CHANGELOG.md` entry for the closed-set expansion. `result="rate_limited"` matches the rate-limit family for audit-graph queries.

**Closed-vocab `rate_limit_bucket` widening** → forward-looking discipline. Performance cross-check verified no `ops/grafana/` or `ops/prometheus/` exists in repo today. Typed `Literal[...]` + `CHANGELOG.md` cover the discipline; no live dashboard migration needed.

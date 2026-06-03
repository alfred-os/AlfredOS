# Per-user concurrent ContentHandle cap — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This is trust-boundary work — TDD is HARD here, not advisory. Every Lua return path + every Python branch reaches 100% line + branch coverage per CLAUDE.md.

**Goal:** Ship the `HandleCap` per-user concurrent ContentHandle bound (slice-3 spec §7.10 line 591) — refuse the 6th in-flight `web.fetch` from a single user, release on lifecycle exits, audit refusals. Closes Slice-3 UAT finding F10 (issue #157).

**Architecture:** New `HandleCap` class (sibling of `RateLimiter`, `ContentStore`) backed by a per-user Redis ZSET (`alfred:handles:user:{user_id}` → members=handle_id, scores=expiry_ms). One Lua script does atomic ZREMRANGEBYSCORE + ZCARD + ZADD + EXPIRE. Release is an idempotent `ZREM`. The dispatcher pre-mints `handle_id` (host owns the id), reserves the cap before transport dispatch, releases on every error arm including `asyncio.CancelledError` via `try/finally` + `asyncio.shield`, and verifies the plugin returned the same id post-dispatch (defence-in-depth).

**Tech Stack:** Python 3.12+ • `redis.asyncio` (Lua scripts + AsyncScript EVALSHA + NOSCRIPT auto-retry) • `asyncio.TaskGroup` + `asyncio.shield` (cancellation-safe release) • `hypothesis` `RuleBasedStateMachine` (property-based invariant proof) • testcontainers Redis (Lua semantics never mocked) • Pydantic v2 (HandleCapConfig validation) • `structlog` (closed-vocabulary event names) • `t()` for all operator-facing strings • `typing.Literal[...]` for closed-set audit vocabularies.

**Spec anchor:** [`docs/superpowers/specs/2026-06-02-handle-cap-design.md`](../specs/2026-06-02-handle-cap-design.md) (rev-2, committed 2026-06-03 on this branch). All section references in this plan are to that spec unless noted.

**Depends on:** PR-S3-5 (merged — `src/alfred/plugins/web_fetch/*`, `WEB_FETCH_FIELDS`, `WebFetchRateLimited`, `RateLimiter` Lua precedent, `InboundCanaryScanner`, `ContentStore`, `fetch_dispatcher.dispatch_web_fetch`); PR-S3-0a/0b (merged — audit row schemas, i18n catalog skeleton).

**Blocks:** Nothing in flight — this is a Slice-3 follow-up against shipped code. Eventual canonical `ContentStore.extract` wire-up is filed as a separate follow-up.

---

## §1 Goal

This PR delivers the `HandleCap` module + its dispatcher integration. After merge:
1. `dispatch_web_fetch` pre-mints `handle_id` host-side; sixth in-flight fetch from one user is refused with `WebFetchRateLimited(bucket="handle_cap")` and a `tool.web.fetch` audit row carrying `dlp_scan_result="handle_cap_exceeded"`.
2. Reservations are released on every dispatcher error arm — transport error, typed plugin error, host-side id mismatch, and `asyncio.CancelledError` — via `try/finally` with a `released` flag and `asyncio.shield` so cancellation cannot leak slots.
3. Canary trip on a successful body delete releases the cap; a failed delete HOLDS the slot until passive TTL eviction (body is still consuming Redis).
4. A LOUD structlog event fires when the success-path audit write fails after a successful fetch (cap slot stays held by design).
5. The Lua script's ARGV are validated host-side (numeric / positive / finite / `expiry_ms > now_ms`) so a malformed input cannot induce silent state corruption (negative-TTL key delete in some Redis versions).
6. Operator override via `config/policies.yaml` `web_fetch.max_concurrent_handles_per_user` (already present; default 5).
7. New operator runbook `docs/runbooks/handle-cap-exceeded.md` + CHANGELOG entry documenting the closed-vocabulary widening.

Trust-boundary code reaches 100% line + branch coverage per CLAUDE.md.

---

## §2 Architecture overview

Dispatcher flow with `HandleCap` integration (the new gate sits between rate-limit and transport):

```
dispatch_web_fetch(url, headers, user_id, correlation_id, config,
                   rate_limiter, outbound_dlp, audit, transport,
                   handle_cap)              # NEW kwarg
    │
    │  ...existing: TLS → DLP → allowlist → host-IP → rate_limit...
    │
    │  handle_id = str(uuid.uuid4())                  # host pre-mints
    │  handle_ttl_seconds = action_deadline +
    │                       max_retries * per_retry +
    │                       slack                     # ≈ 80s default
    │
    │  handle_cap.try_reserve(user_id, handle_id, handle_ttl_seconds)
    │    │   Lua-atomic: ZREMRANGEBYSCORE + ZCARD + ZADD + EXPIRE
    │    │   raises WebFetchRateLimited(bucket="handle_cap") if exceeded
    │    └── on raise: emit cap-refusal audit row, propagate
    │
    │  released = False
    │  try:
    │    try:
    │      result = await transport.dispatch("web.fetch",
    │                  {..., "content_handle_id": handle_id})
    │    except Exception:
    │      await handle_cap.release(...);  released = True
    │      ...emit transport_error audit row...; raise
    │
    │    if isinstance(result, ControlResult):  # typed plugin error
    │      await handle_cap.release(...);  released = True
    │      ...existing typed-error handling...
    │
    │    if not isinstance(result, ContentHandle) or result.id != handle_id:
    │      await handle_cap.release(...);  released = True
    │      ...emit handle_id_mismatch audit row...
    │      raise WebFetchHandleIdMismatch
    │
    │    try:
    │      await audit.append_schema(..., result="ok", ...)
    │    except Exception:
    │      # HOLD the cap; body is in Redis. LOUD structlog event.
    │      log.error("web_fetch.handle_cap.success_audit_failed_holding_cap", ...)
    │      raise
    │
    │    return result
    │
    │  finally:
    │    if not released:
    │      with contextlib.suppress(Exception):
    │        await asyncio.shield(handle_cap.release(user_id, handle_id))
    ▼
plugin subprocess (alfred-web-fetch)
    │   reads params["content_handle_id"] (host-pre-minted)
    │   ContentStore.write(handle_id=..., body=..., source_url=...)
    │   returns ContentHandle{id=handle_id, source_url, fetch_timestamp}
    ▼
InboundCanaryScanner (system-tier post subscriber)
    │   scan(handle_id, source_url, user_id)        # signature change
    │   on canary detected:
    │     try: store.delete(handle_id)
    │     if delete succeeded: handle_cap.release(user_id, handle_id)
    │     if delete raised RedisError: HOLD (body still in Redis)
    │     raise WebFetchCanaryTripped (always)
```

Redis state owned by `HandleCap`:

```
key:    alfred:handles:user:{user_id}
member: {handle_id}                   (UUID4)
score:  {expiry_epoch_ms}             (when body's TTL fires)
```

ZCARD = current alive count. ZREMRANGEBYSCORE at the head of every reserve passively evicts entries whose `score < now_ms` (this is the ONLY mechanism by which TTL expiry reduces the count — Redis keyspace notifications are not reliable).

**Trust boundary**: `HandleCap` is T0 metadata about T3 handles. The cap itself never sees body bytes. The host-side equality check (`result.id == pre_minted_handle_id`) prevents a buggy/compromised plugin from desynchronising the cap counter from real Redis pressure (e.g., plugin writes body under id `X` but reports id `Y` — the cap thinks `Y` is alive, but `Y` doesn't exist in Redis; user can reserve again immediately, leaking memory).

---

## §3 File structure

| File | Status | Responsibility |
|---|---|---|
| `src/alfred/plugins/web_fetch/handle_cap.py` | Create | `HandleCap` class, `HandleCapConfig` dataclass, Lua script, ARGV validator, idempotent close (spec §2-§2.4, §7) |
| `src/alfred/plugins/web_fetch/errors.py` | Modify | Widen `WebFetchRateLimited.bucket` Literal to include `"handle_cap"`; add `WebFetchHandleIdMismatch(WebFetchError)`; update docstrings (spec §6.1) |
| `src/alfred/plugins/web_fetch/content_store.py` | Modify | `ContentStore.write(handle_id=...)` becomes required kwarg; remove internal `uuid.uuid4()` mint path (spec §3) |
| `src/alfred/plugins/web_fetch/fetch_dispatcher.py` | Modify | Add `handle_cap: HandleCap` kwarg; pre-mint handle_id; reserve before transport; release on every error arm; `try/finally` + `asyncio.shield` for CancelledError safety; host-side id equality check; success-audit-failure HOLD (spec §4) |
| `src/alfred/plugins/web_fetch/canary_scanner.py` | Modify | Add `user_id` kwarg to `scan()`; release-on-successful-delete; hook-payload extension for `triggering_user_id` (spec §5.2, §5.4) |
| `plugins/alfred_web_fetch/web_fetch_plugin.py` | Modify | `_handle_fetch` reads `params["content_handle_id"]` and forwards to `ContentStore.write` (spec §3) |
| `src/alfred/audit/audit_row_schemas.py` | Modify | Add `RateLimitBucket = Literal[...]` and `DlpScanResult = Literal[...]` typed closed sets including new values (spec §6.2) |
| `config/policies.yaml` | (no change) | Knob already present (`web_fetch.max_concurrent_handles_per_user: 5`); spec §7 |
| `locale/en/LC_MESSAGES/alfred.po` | Modify | Add `web.fetch.error.rate_limited.handle_cap` + `web.fetch.error.handle_id_mismatch` msgstrs (spec §6.3) |
| `CHANGELOG.md` | Modify | Audit vocabulary entry documenting `rate_limit_bucket` + `dlp_scan_result` closed-set widening (spec §6.2) |
| `docs/subsystems/security.md` | Modify | Cross-reference HandleCap as a slice-3 spec §7.10 defence |
| `docs/runbooks/handle-cap-exceeded.md` | Create | Operator runbook: what `handle_cap_exceeded` means in the audit log; how to inspect; how to override (spec §10) |
| `tests/unit/plugins/web_fetch/test_handle_cap.py` | Create | testcontainers Redis sad-path catalogue (spec §8.2) |
| `tests/unit/plugins/web_fetch/test_handle_cap_errors.py` | Create | `WebFetchRateLimited` bucket widening + `WebFetchHandleIdMismatch` tests |
| `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py` | Modify | Extend with reserve-before-transport, release-on-error-arms, equality check, CancelledError safety, success-audit HOLD (spec §8.2 Lifecycle integration) |
| `tests/unit/plugins/web_fetch/test_content_handle_single_use.py` | Modify | Update for `write(handle_id=...)` required kwarg |
| `tests/unit/plugins/web_fetch/test_canary_scanner_host_side.py` | Modify | Add `user_id` kwarg coverage + release-on-successful-delete + HOLD-on-delete-failure |
| `tests/property/__init__.py` | Create | Package marker |
| `tests/property/plugins/__init__.py` | Create | Package marker |
| `tests/property/plugins/web_fetch/__init__.py` | Create | Package marker |
| `tests/property/plugins/web_fetch/test_handle_cap_invariants.py` | Create | Hypothesis `RuleBasedStateMachine` proving `ZCARD ≤ cap` under all reserve/release/expire interleavings (spec §8.2) |
| `tests/unit/audit/test_audit_row_schemas.py` | Modify | Pin the new `Literal` closed sets |
| `tests/adversarial/dlp_egress/handle_cap_exhaustion.yaml` | Create | AdversarialPayload-conformant YAML: single-user cap exhaustion across 100 endpoints; cap=5; expected_outcome=audit_row_emitted (spec §8.2 Adversarial) |

---

## §4 Coverage matrix (subsystem owners)

| Subsystem | Files | Owner agent |
|---|---|---|
| HandleCap module + Lua script | `handle_cap.py`, `test_handle_cap.py`, `test_handle_cap_invariants.py` | alfred-security-engineer |
| ContentStore contract change | `content_store.py`, `test_content_handle_single_use.py` | alfred-security-engineer |
| Errors module + typed Literal | `errors.py`, `test_handle_cap_errors.py` | alfred-security-engineer |
| Audit row schemas | `audit_row_schemas.py`, `test_audit_row_schemas.py` | alfred-security-engineer |
| Dispatcher integration | `fetch_dispatcher.py`, `test_fetch_dispatcher.py` | alfred-security-engineer |
| Plugin pass-through | `web_fetch_plugin.py` | alfred-security-engineer |
| Canary scanner signature + hook-payload | `canary_scanner.py`, `test_canary_scanner_host_side.py` | alfred-security-engineer |
| i18n catalog | `alfred.po` | alfred-i18n-reviewer |
| Operator runbook + CHANGELOG | `runbooks/handle-cap-exceeded.md`, `CHANGELOG.md`, `docs/subsystems/security.md` | alfred-devex-reviewer / alfred-docs-author |
| Adversarial corpus | `dlp_egress/handle_cap_exhaustion.yaml` | alfred-test-engineer / alfred-security-engineer |

Plan-level owner: **alfred-security-engineer** (trust-boundary work).

---

## §5 Definition of Done

- [ ] All tasks in §6 marked complete.
- [ ] `uv run pytest tests/unit/plugins/web_fetch/ tests/unit/audit/ tests/property/plugins/web_fetch/ -q` → green.
- [ ] `uv run pytest tests/adversarial/dlp_egress/test_handle_cap_exhaustion* -q` → green (adversarial corpus runner picks up the new YAML).
- [ ] `uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py --cov=src/alfred/plugins/web_fetch/handle_cap --cov-branch --cov-fail-under=100` → 100% line + branch.
- [ ] `uv run ruff check . && uv run ruff format --check .` → green.
- [ ] `uv run mypy src/ && uv run pyright src/` → green.
- [ ] `make check` → green (lint + format + type + test).
- [ ] `uv run pybabel extract -F babel.cfg -o locale/alfred.pot src/alfred/ && uv run pybabel update -i locale/alfred.pot -d locale/ && uv run pybabel compile -d locale/ --check` → catalog clean, no drift.
- [ ] `git log --oneline main..HEAD` → every commit is Conventional Commits, no `fixup!` prefixes, no `--no-verify`.
- [ ] Plan + spec committed on branch; no untracked files outside the worktree's expected diff.
- [ ] User check-in before opening the PR (per project notes).

---

## §6 Tasks

### Component A — Foundations (typed Literals + config)

#### Task 1 — Widen `WebFetchRateLimited.bucket` Literal + add `WebFetchHandleIdMismatch`

**Owner:** alfred-security-engineer
**Files:**
- Modify: `src/alfred/plugins/web_fetch/errors.py`
- Create: `tests/unit/plugins/web_fetch/test_handle_cap_errors.py`
- Modify: `tests/unit/plugins/web_fetch/test_errors.py` (verify existing tests still pass under widened Literal)

- [ ] **Step 1: Write the failing tests.**

  Create `tests/unit/plugins/web_fetch/test_handle_cap_errors.py`:

  ```python
  """Tests for the WebFetchRateLimited bucket widening + WebFetchHandleIdMismatch."""

  from __future__ import annotations

  import pytest

  from alfred.plugins.web_fetch.errors import (
      WebFetchError,
      WebFetchHandleIdMismatch,
      WebFetchRateLimited,
  )


  def test_handle_cap_bucket_accepted() -> None:
      """bucket='handle_cap' is a legal value alongside the three existing buckets."""
      exc = WebFetchRateLimited("handle_cap")
      assert exc.bucket == "handle_cap"
      assert isinstance(exc, WebFetchError)


  def test_handle_cap_bucket_message_dispatches_to_dedicated_key() -> None:
      """The msgstr for bucket='handle_cap' points at the dedicated catalog key
      so operators are routed to the right config knob (not the generic
      web_fetch.rate_limits one)."""
      exc = WebFetchRateLimited("handle_cap")
      msg = str(exc)
      # The dedicated msgstr mentions max_concurrent_handles_per_user.
      assert "max_concurrent_handles_per_user" in msg or "concurrent" in msg.lower()


  def test_existing_buckets_still_use_generic_template() -> None:
      """Existing three buckets continue to use the generic web.fetch.error.rate_limited
      msgstr — no regression from the dispatch added for handle_cap."""
      for bucket in ("per_domain", "per_user", "daily_budget"):
          exc = WebFetchRateLimited(bucket)
          assert exc.bucket == bucket


  def test_handle_id_mismatch_is_webfetch_error_subclass() -> None:
      """WebFetchHandleIdMismatch is a WebFetchError (operational error,
      not a security event) — the orchestrator's operational arm surfaces it."""
      exc = WebFetchHandleIdMismatch(expected="aaa", got="bbb")
      assert isinstance(exc, WebFetchError)
      assert exc.expected == "aaa"
      assert exc.got == "bbb"


  def test_handle_id_mismatch_message_does_not_leak_ids() -> None:
      """The caller-visible message does NOT interpolate the offending ids
      (forensic detail rides on .expected / .got for the audit row)."""
      exc = WebFetchHandleIdMismatch(expected="aaaa-bbbb-cccc", got="xxxx-yyyy-zzzz")
      msg = str(exc)
      assert "aaaa-bbbb-cccc" not in msg
      assert "xxxx-yyyy-zzzz" not in msg
  ```

- [ ] **Step 2: Run to confirm failure.**

  ```bash
  cd ~/projects/AlfredOS-worktrees/issue-157-handle-cap
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap_errors.py -v
  ```

  Expected: `ImportError: cannot import name 'WebFetchHandleIdMismatch'`.

- [ ] **Step 3: Implement.**

  Edit `src/alfred/plugins/web_fetch/errors.py`. Find the `WebFetchRateLimited` class (currently ~line 107), update its docstring + add a typed `Literal` for buckets. Add `WebFetchHandleIdMismatch` after it. The diff in shape:

  ```python
  from typing import Literal

  RateLimitBucket = Literal["per_domain", "per_user", "daily_budget", "handle_cap"]
  """Closed vocabulary of rate-limit refusal buckets (spec §6.1).

  Widened from the original three-bucket vocabulary by the handle-cap design
  (slice-3 design spec §7.10 line 591) — ``"handle_cap"`` denotes the per-user
  concurrent ContentHandle bound.
  """


  class WebFetchRateLimited(WebFetchError):  # noqa: N818 -- name pinned by spec §7.10
      """A rate-limit bucket refused the request (spec §7.7, §7.10).

      ``bucket`` is one of :data:`RateLimitBucket`. Audit rows record it under
      ``WEB_FETCH_FIELDS["rate_limit_bucket"]``. The ``handle_cap`` bucket
      uses a dedicated i18n catalog entry (``web.fetch.error.rate_limited.handle_cap``)
      that points operators at ``web_fetch.max_concurrent_handles_per_user``;
      the other three use the generic ``web.fetch.error.rate_limited`` template.
      """

      def __init__(self, bucket: RateLimitBucket) -> None:
          if bucket == "handle_cap":
              super().__init__(t("web.fetch.error.rate_limited.handle_cap"))
          else:
              super().__init__(t("web.fetch.error.rate_limited", bucket=bucket))
          self.bucket: RateLimitBucket = bucket


  class WebFetchHandleIdMismatch(WebFetchError):  # noqa: N818 -- spec §3 host equality check
      """The plugin returned a ContentHandle whose id differs from the
      host-side pre-minted reservation (spec §3).

      Defence-in-depth: a buggy or compromised plugin could write the body
      under a different Redis key, decorrelating the cap counter from real
      Redis memory pressure. The dispatcher raises this typed exception,
      releases the cap slot, and emits a ``dlp_scan_result="handle_id_mismatch"``
      audit row before re-raising.

      The caller-visible message intentionally does NOT interpolate
      ``expected`` / ``got`` — leaking pre-mint metadata back to the caller
      tells an attacker the host-pre-mint shape. Forensic detail stays on
      ``self.expected`` / ``self.got`` for the audit row (operator audience).
      """

      def __init__(self, expected: str, got: str) -> None:
          super().__init__(t("web.fetch.error.handle_id_mismatch"))
          self.expected = expected
          self.got = got
  ```

  Also update `__all__` at the bottom of the module to include `WebFetchHandleIdMismatch` and `RateLimitBucket`.

- [ ] **Step 4: Run new + existing tests.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap_errors.py tests/unit/plugins/web_fetch/test_errors.py -v
  ```

  Expected: both files green. (`test_handle_cap_bucket_message_dispatches_to_dedicated_key` may still fail because the catalog entry doesn't exist yet — that's Task 14. Mark XFAIL or `skip("catalog entry added in Task 14")` for now, OR add a temporary stub msgstr inline. Recommend XFAIL + remove the marker in Task 14.)

- [ ] **Step 5: Commit.**

  ```bash
  git add src/alfred/plugins/web_fetch/errors.py tests/unit/plugins/web_fetch/test_handle_cap_errors.py
  git commit -m "feat(web-fetch): widen WebFetchRateLimited.bucket Literal + add WebFetchHandleIdMismatch (#157)

  Widen the closed vocabulary from {per_domain, per_user, daily_budget} to
  also accept 'handle_cap'. WebFetchRateLimited dispatches on bucket to
  route handle_cap refusals to a dedicated msgstr (added Task 14) so the
  operator-visible message points at max_concurrent_handles_per_user,
  not the wrong web_fetch.rate_limits knob.

  Add WebFetchHandleIdMismatch — host-side defence-in-depth equality check
  on the ContentHandle returned by the plugin subprocess. Message stays
  free of the pre-mint ids; forensic detail rides on .expected / .got
  for the audit row.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 2 — Typed `Literal` closed sets in `audit_row_schemas.py`

**Owner:** alfred-security-engineer
**Files:**
- Modify: `src/alfred/audit/audit_row_schemas.py`
- Modify: `tests/unit/audit/test_audit_row_schemas.py`

- [ ] **Step 1: Write the failing tests.**

  Append to `tests/unit/audit/test_audit_row_schemas.py`:

  ```python
  def test_rate_limit_bucket_literal_closed_set() -> None:
      """rate_limit_bucket's Literal pins the four-value closed vocabulary
      after the handle-cap widening (spec §6.2)."""
      from alfred.audit.audit_row_schemas import RateLimitBucket
      from typing import get_args
      assert set(get_args(RateLimitBucket)) == {
          "per_domain", "per_user", "daily_budget", "handle_cap",
      }


  def test_dlp_scan_result_literal_includes_new_values() -> None:
      """dlp_scan_result's Literal includes the cap-refusal value and the
      host-side id-mismatch value (spec §6.2)."""
      from alfred.audit.audit_row_schemas import DlpScanResult
      from typing import get_args
      values = set(get_args(DlpScanResult))
      assert "handle_cap_exceeded" in values
      assert "handle_id_mismatch" in values
      # Existing precedents stay.
      for legacy in ("clean", "scanned_dirty", "rate_limited",
                     "transport_error", "domain_not_allowed"):
          assert legacy in values
  ```

- [ ] **Step 2: Run to confirm failure.**

  ```bash
  uv run pytest tests/unit/audit/test_audit_row_schemas.py::test_rate_limit_bucket_literal_closed_set tests/unit/audit/test_audit_row_schemas.py::test_dlp_scan_result_literal_includes_new_values -v
  ```

  Expected: `ImportError: cannot import name 'RateLimitBucket'`.

- [ ] **Step 3: Implement.**

  At the top of `src/alfred/audit/audit_row_schemas.py`, add:

  ```python
  from typing import Final, Literal

  RateLimitBucket = Literal[
      "per_domain",
      "per_user",
      "daily_budget",
      "handle_cap",        # spec §6.2 widening — per-user concurrent ContentHandle cap
  ]
  """Closed vocabulary of rate-limit refusal buckets recorded in
  ``WEB_FETCH_FIELDS['rate_limit_bucket']``. Future emitter typos surface
  at type-check time, not runtime."""

  DlpScanResult = Literal[
      "clean",
      "scanned_dirty",
      "dlp_scan_error",
      "domain_not_allowed",
      "rate_limited",
      "transport_error",
      "dispatch_shape_error",
      "internal_ip_refused",
      "redirect_refused",
      "tls_verification_failed",
      "fetch_error",
      "handle_cap_exceeded",   # spec §6.2 — per-user concurrent ContentHandle cap refusal
      "handle_id_mismatch",    # spec §3 — host-side equality check failed
  ]
  """Closed vocabulary recorded in ``WEB_FETCH_FIELDS['dlp_scan_result']``.
  Two values widened by the handle-cap design (slice-3 design spec §7.10);
  see CHANGELOG.md."""
  ```

  (The existing `WEB_FETCH_FIELDS` constant stays as-is — these Literals are an additional layer for emitter callsites that want to typecheck their string arguments.)

- [ ] **Step 4: Run the new tests.**

  ```bash
  uv run pytest tests/unit/audit/test_audit_row_schemas.py -v
  ```

  Expected: all green.

- [ ] **Step 5: Commit.**

  ```bash
  git add src/alfred/audit/audit_row_schemas.py tests/unit/audit/test_audit_row_schemas.py
  git commit -m "feat(audit): typed Literal for rate_limit_bucket + dlp_scan_result closed sets (#157)

  Promote both closed vocabularies to typing.Literal[...] so the audit-row
  widening for handle_cap_exceeded + handle_id_mismatch (slice-3 spec §7.10
  per-user concurrent ContentHandle cap) is enforced at type-check time.
  Future emitter typos surface in mypy/pyright, not at runtime.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Component B — `HandleCap` module

#### Task 3 — `HandleCapConfig` dataclass + load-time validation

**Owner:** alfred-security-engineer
**Files:**
- Create: `src/alfred/plugins/web_fetch/handle_cap.py` (skeleton — just `HandleCapConfig`)
- Create: `tests/unit/plugins/web_fetch/test_handle_cap.py` (config tests only this task)

- [ ] **Step 1: Write the failing tests.**

  Create `tests/unit/plugins/web_fetch/test_handle_cap.py`:

  ```python
  """HandleCap module tests — Lua semantics, atomicity, TTL behaviour,
  error paths, ARGV validation. Lua scripts run against real Redis via
  testcontainers (mocking would test our mental model, not the interpreter).
  """

  from __future__ import annotations

  import pytest

  from alfred.plugins.web_fetch.handle_cap import HandleCapConfig


  def test_default_config_matches_spec() -> None:
      """HandleCapConfig() defaults to per_user=5 (spec §7)."""
      cfg = HandleCapConfig()
      assert cfg.per_user == 5


  def test_cap_zero_raises_at_load() -> None:
      """A cap of 0 would refuse every fetch — loud at config-load, not silent."""
      with pytest.raises(ValueError, match="per_user must be >= 1"):
          HandleCapConfig(per_user=0)


  def test_cap_negative_raises_at_load() -> None:
      with pytest.raises(ValueError, match="per_user must be >= 1"):
          HandleCapConfig(per_user=-1)


  def test_cap_one_valid() -> None:
      cfg = HandleCapConfig(per_user=1)
      assert cfg.per_user == 1


  def test_cap_large_value_valid() -> None:
      cfg = HandleCapConfig(per_user=10_000)
      assert cfg.per_user == 10_000


  def test_config_is_frozen() -> None:
      """Operator config is immutable after construction (consistent with
      RateLimitConfig)."""
      cfg = HandleCapConfig(per_user=5)
      with pytest.raises((AttributeError, TypeError)):
          cfg.per_user = 10  # type: ignore[misc]
  ```

- [ ] **Step 2: Run to confirm failure.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py -v
  ```

  Expected: `ImportError: cannot import name 'HandleCapConfig'`.

- [ ] **Step 3: Implement.**

  Create `src/alfred/plugins/web_fetch/handle_cap.py`:

  ```python
  """Per-user concurrent ContentHandle cap (spec §7.10 / docs/superpowers/specs/2026-06-02-handle-cap-design.md).

  Sibling of :class:`~alfred.plugins.web_fetch.rate_limit.RateLimiter`. Where
  the rate limiter bounds request rate, ``HandleCap`` bounds the number of
  live :class:`~alfred.security.quarantine.ContentHandle` instances a single
  user has outstanding in Redis — the resource the cap exists to protect.

  See ``docs/superpowers/specs/2026-06-02-handle-cap-design.md`` for the
  full design rationale, the disputed-item resolutions, and the review-pass
  audit trail.
  """

  from __future__ import annotations

  from dataclasses import dataclass


  _DEFAULT_PER_USER_CAP: int = 5
  """Slice-3 spec §7.10 line 591 default. Operators tune via
  ``config/policies.yaml`` ``web_fetch.max_concurrent_handles_per_user``."""


  @dataclass(frozen=True, slots=True)
  class HandleCapConfig:
      """Per-deployment knobs for :class:`HandleCap`.

      A misconfigured cap (≤ 0) fails loud at config-load time, not silently
      at first fetch — matches the ``RateLimitConfig`` precedent.
      """

      per_user: int = _DEFAULT_PER_USER_CAP

      def __post_init__(self) -> None:
          if self.per_user < 1:
              msg = (
                  f"HandleCapConfig.per_user must be >= 1; got {self.per_user}. "
                  "A cap of 0 would refuse every fetch."
              )
              raise ValueError(msg)


  __all__ = ["HandleCapConfig"]
  ```

- [ ] **Step 4: Run the tests.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py -v
  ```

  Expected: all green.

- [ ] **Step 5: Commit.**

  ```bash
  git add src/alfred/plugins/web_fetch/handle_cap.py tests/unit/plugins/web_fetch/test_handle_cap.py
  git commit -m "feat(handle-cap): HandleCapConfig dataclass + load-time validation (#157)

  Frozen Pydantic-style dataclass with __post_init__ refusing per_user < 1
  loud at config-load time. Matches RateLimitConfig precedent.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 4 — ARGV validator + `HandleCap` class skeleton + Lua atomic `try_reserve`

**Owner:** alfred-security-engineer
**Files:**
- Modify: `src/alfred/plugins/web_fetch/handle_cap.py`
- Modify: `tests/unit/plugins/web_fetch/test_handle_cap.py`

This task adds the load-bearing atomic check-and-reserve script and its host-side ARGV validator. Tests use a real Redis container via testcontainers (matches `test_lua_atomic_rate_limit.py` precedent).

- [ ] **Step 1: Write the failing tests (ARGV validation + atomic reserve).**

  Append to `tests/unit/plugins/web_fetch/test_handle_cap.py`:

  ```python
  import asyncio
  import time
  from collections.abc import AsyncIterator, Iterator

  import pytest
  import pytest_asyncio
  from testcontainers.redis import RedisContainer

  from alfred.plugins.web_fetch.errors import WebFetchRateLimited
  from alfred.plugins.web_fetch.handle_cap import HandleCap


  @pytest.fixture(scope="module")
  def redis_url() -> Iterator[str]:
      with RedisContainer("redis:7-alpine") as r:
          yield f"redis://{r.get_container_host_ip()}:{r.get_exposed_port(6379)}"


  @pytest_asyncio.fixture
  async def cap(redis_url: str) -> AsyncIterator[HandleCap]:
      hc = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=5))
      try:
          yield hc
      finally:
          await hc.aclose()


  def _u() -> str:
      return f"user-{time.monotonic_ns()}"


  def _h() -> str:
      import uuid
      return str(uuid.uuid4())


  # --- ARGV validation (host-side defence; spec §2.3) ---


  @pytest.mark.asyncio
  async def test_reserve_rejects_non_int_cap(cap: HandleCap) -> None:
      with pytest.raises(ValueError, match="cap"):
          await cap._try_reserve_with_args(
              user_id=_u(), handle_id=_h(),
              cap=5.5,  # type: ignore[arg-type]
              expiry_ms=int(time.time() * 1000) + 10_000,
              now_ms=int(time.time() * 1000),
              outer_ttl=600,
          )


  @pytest.mark.asyncio
  async def test_reserve_rejects_bool_cap(cap: HandleCap) -> None:
      """bool is a subclass of int in Python — must still be rejected."""
      with pytest.raises(ValueError, match="cap"):
          await cap._try_reserve_with_args(
              user_id=_u(), handle_id=_h(),
              cap=True,  # type: ignore[arg-type]
              expiry_ms=int(time.time() * 1000) + 10_000,
              now_ms=int(time.time() * 1000),
              outer_ttl=600,
          )


  @pytest.mark.asyncio
  async def test_reserve_rejects_zero_or_negative_cap(cap: HandleCap) -> None:
      for bad in (0, -1):
          with pytest.raises(ValueError, match="cap"):
              await cap._try_reserve_with_args(
                  user_id=_u(), handle_id=_h(),
                  cap=bad,
                  expiry_ms=int(time.time() * 1000) + 10_000,
                  now_ms=int(time.time() * 1000),
                  outer_ttl=600,
              )


  @pytest.mark.asyncio
  async def test_reserve_rejects_expiry_at_or_before_now(cap: HandleCap) -> None:
      now = int(time.time() * 1000)
      with pytest.raises(ValueError, match="expiry_ms"):
          await cap._try_reserve_with_args(
              user_id=_u(), handle_id=_h(),
              cap=5, expiry_ms=now, now_ms=now, outer_ttl=600,
          )
      with pytest.raises(ValueError, match="expiry_ms"):
          await cap._try_reserve_with_args(
              user_id=_u(), handle_id=_h(),
              cap=5, expiry_ms=now - 1, now_ms=now, outer_ttl=600,
          )


  @pytest.mark.asyncio
  async def test_reserve_rejects_zero_or_negative_outer_ttl(cap: HandleCap) -> None:
      """Negative TTL on EXPIRE deletes the key in some Redis versions — silent
      state corruption. Hard rule #7 violation; must fail loud host-side."""
      now = int(time.time() * 1000)
      for bad in (0, -1):
          with pytest.raises(ValueError, match="outer_ttl"):
              await cap._try_reserve_with_args(
                  user_id=_u(), handle_id=_h(),
                  cap=5, expiry_ms=now + 10_000, now_ms=now, outer_ttl=bad,
              )


  # --- Lua atomic try_reserve (spec §2.3) ---


  @pytest.mark.asyncio
  async def test_reserve_under_cap_succeeds(cap: HandleCap) -> None:
      """First reserve against an empty key succeeds."""
      await cap.try_reserve(user_id=_u(), handle_id=_h(), handle_ttl_seconds=80)


  @pytest.mark.asyncio
  async def test_reserve_at_cap_refuses(cap: HandleCap) -> None:
      """6th concurrent reserve raises WebFetchRateLimited(bucket='handle_cap')."""
      u = _u()
      for _ in range(5):
          await cap.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
      with pytest.raises(WebFetchRateLimited) as exc_info:
          await cap.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
      assert exc_info.value.bucket == "handle_cap"


  @pytest.mark.asyncio
  async def test_reserve_default_ttl_derives_outer_ttl_from_floor(cap: HandleCap) -> None:
      """outer_ttl = max(handle_ttl*2, _OUTER_KEY_TTL_FLOOR_SECONDS)."""
      from alfred.plugins.web_fetch.handle_cap import _OUTER_KEY_TTL_FLOOR_SECONDS
      assert _OUTER_KEY_TTL_FLOOR_SECONDS == 600
      # handle_ttl=10 → outer_ttl=600 (the floor wins)
      # handle_ttl=400 → outer_ttl=800 (2x wins)
      # Pinning the formula directly is brittle; we assert the floor constant exists
      # and is reachable. The behaviour is exercised by test_user_key_outer_expire_set.
  ```

- [ ] **Step 2: Run to confirm failure.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py -v -k "reserve"
  ```

  Expected: all new tests fail with `ImportError: cannot import name 'HandleCap'` (the class doesn't exist yet) and `_OUTER_KEY_TTL_FLOOR_SECONDS` missing.

- [ ] **Step 3: Implement `HandleCap` + Lua script + ARGV validator.**

  Append to `src/alfred/plugins/web_fetch/handle_cap.py`:

  ```python
  import math
  from typing import Final, cast

  import redis.asyncio as aioredis
  import structlog
  from redis.commands.core import AsyncScript

  from alfred.plugins.web_fetch.errors import WebFetchRateLimited

  _log = structlog.get_logger(__name__)

  _OUTER_KEY_TTL_FLOOR_SECONDS: Final[int] = 600
  """Floor for the ZSET key's outer EXPIRE. Bounds empty-key keyspace at ~80B
  per idle user × 10K users ≈ 1MB held ≤10 min. Prevents thrash when
  handle_ttl is short. See spec §2.3."""


  _KEY_PREFIX_USER: Final[str] = "alfred:handles:user:"


  _RESERVE_SCRIPT: Final[str] = """
  -- KEYS[1] = alfred:handles:user:{user_id}
  -- ARGV[1] = cap (int >= 1)
  -- ARGV[2] = handle_id (UUID4 string)
  -- ARGV[3] = expiry_ms (int > now_ms)
  -- ARGV[4] = now_ms (int > 0)
  -- ARGV[5] = outer_ttl (int > 0)
  -- Returns "ok" | "exceeded"

  local key = KEYS[1]
  local cap = tonumber(ARGV[1])
  local handle_id = ARGV[2]
  local expiry_ms = tonumber(ARGV[3])
  local now_ms = tonumber(ARGV[4])
  local outer_ttl = tonumber(ARGV[5])

  -- Passive eviction of TTL-expired handles. ONLY mechanism by which TTL
  -- expiry reduces the count (keyspace notifications are unreliable).
  redis.call('ZREMRANGEBYSCORE', key, '-inf', now_ms)

  local live = redis.call('ZCARD', key)
  if live >= cap then
      return 'exceeded'
  end

  redis.call('ZADD', key, expiry_ms, handle_id)
  redis.call('EXPIRE', key, outer_ttl)
  return 'ok'
  """


  def _validate_argv(*, cap: int, expiry_ms: int, now_ms: int, outer_ttl: int) -> None:
      """Host-side validation BEFORE EVALSHA.

      Lua's ``tonumber`` returns ``nil`` on non-numeric / NaN / Inf input;
      ``ZADD key, nil, member`` raises a Lua-level error; ``EXPIRE key, nil``
      does the same; a NEGATIVE TTL value passed to ``EXPIRE`` DELETES the key
      in some Redis versions (silent state corruption). All CLAUDE.md hard
      rule #7 violations. Validate host-side, raise ``ValueError`` loud.
      """
      for name, value in (("cap", cap), ("expiry_ms", expiry_ms),
                          ("now_ms", now_ms), ("outer_ttl", outer_ttl)):
          # bool is a subclass of int in Python — exclude explicitly.
          if isinstance(value, bool) or not isinstance(value, int):
              msg = f"HandleCap ARGV {name!r} must be int, got {type(value).__name__}"
              raise ValueError(msg)
          if value <= 0:
              msg = f"HandleCap ARGV {name!r} must be > 0, got {value}"
              raise ValueError(msg)
      if expiry_ms <= now_ms:
          msg = (
              f"HandleCap ARGV 'expiry_ms' ({expiry_ms}) must be > "
              f"'now_ms' ({now_ms})"
          )
          raise ValueError(msg)


  class HandleCap:
      """Per-user concurrent ContentHandle bound (spec §2-§2.4).

      Constructor takes ``redis_url`` + ``HandleCapConfig``. Constructs a
      long-lived ``redis.asyncio.Redis`` client on first use (perf-006
      precedent — match :class:`RateLimiter._client` lifecycle). The
      script is registered once per process via ``AsyncScript`` and
      reused via EVALSHA + automatic NOSCRIPT fallback.
      """

      def __init__(
          self,
          *,
          redis_url: str,
          config: HandleCapConfig | None = None,
      ) -> None:
          self._redis_url = redis_url
          self._config = config or HandleCapConfig()
          self._client: aioredis.Redis | None = None
          self._script: AsyncScript | None = None

      @property
      def redis_url(self) -> str:
          return self._redis_url

      async def _get_client(self) -> aioredis.Redis:
          if self._client is None:
              self._client = aioredis.from_url(
                  self._redis_url, decode_responses=False,
              )
          return self._client

      async def _get_script(self) -> AsyncScript:
          client = await self._get_client()
          if self._script is None:
              self._script = client.register_script(_RESERVE_SCRIPT)
          return self._script

      async def try_reserve(
          self,
          *,
          user_id: str,
          handle_id: str,
          handle_ttl_seconds: int,
      ) -> None:
          """Atomically reserve one cap slot for ``user_id``.

          Args:
              user_id: Canonical user id (slug-format, closed character set).
              handle_id: UUID4 pre-minted by the dispatcher.
              handle_ttl_seconds: TTL of the content body in Redis. Used to
                  compute the ZSET member's expiry score.

          Raises:
              WebFetchRateLimited: cap exceeded; ``.bucket == "handle_cap"``.
              ValueError: invalid ARGV (non-int, non-positive, expiry <= now).
          """
          import time
          now_ms = int(time.time() * 1000)
          expiry_ms = now_ms + handle_ttl_seconds * 1000
          outer_ttl = max(handle_ttl_seconds * 2, _OUTER_KEY_TTL_FLOOR_SECONDS)
          await self._try_reserve_with_args(
              user_id=user_id, handle_id=handle_id,
              cap=self._config.per_user,
              expiry_ms=expiry_ms, now_ms=now_ms, outer_ttl=outer_ttl,
          )

      async def _try_reserve_with_args(
          self,
          *,
          user_id: str,
          handle_id: str,
          cap: int,
          expiry_ms: int,
          now_ms: int,
          outer_ttl: int,
      ) -> None:
          """Lower-level reserve — exposes the raw ARGV for testability.

          The ARGV validator runs BEFORE the Lua script so a malformed input
          cannot induce silent Redis state corruption.
          """
          _validate_argv(
              cap=cap, expiry_ms=expiry_ms, now_ms=now_ms, outer_ttl=outer_ttl,
          )
          script = await self._get_script()
          key = f"{_KEY_PREFIX_USER}{user_id}"
          raw = await script(
              keys=[key],
              args=[str(cap), handle_id, str(expiry_ms),
                    str(now_ms), str(outer_ttl)],
          )
          result = cast("bytes", raw).decode("ascii")
          if result == "exceeded":
              _log.warning(
                  "web_fetch.handle_cap.exceeded",
                  user_id=user_id, handle_id=handle_id,
              )
              raise WebFetchRateLimited("handle_cap")

      async def aclose(self) -> None:
          """Idempotent close — supervisor SIGKILL paths."""
          if self._client is not None:
              client = self._client
              self._client = None
              self._script = None
              await client.aclose()
  ```

  Update `__all__` at the bottom of the module:

  ```python
  __all__ = [
      "HandleCap",
      "HandleCapConfig",
  ]
  ```

- [ ] **Step 4: Run the tests.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py -v -k "reserve or argv"
  ```

  Expected: all green.

- [ ] **Step 5: Commit.**

  ```bash
  git add src/alfred/plugins/web_fetch/handle_cap.py tests/unit/plugins/web_fetch/test_handle_cap.py
  git commit -m "feat(handle-cap): atomic try_reserve + host-side ARGV validation (#157)

  Lua-atomic ZREMRANGEBYSCORE + ZCARD + ZADD + EXPIRE in a single script
  (spec §2.3). Host-side _validate_argv runs BEFORE EVALSHA so non-int /
  bool / NaN / Inf / negative inputs cannot induce silent Redis state
  corruption (some Redis versions DELETE the key on EXPIRE with negative
  TTL — CLAUDE.md hard rule #7).

  Outer key TTL floor _OUTER_KEY_TTL_FLOOR_SECONDS = 600 promoted from
  magic constant per review-pass perf finding.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 5 — `HandleCap.release` (idempotent ZREM) + tests

**Owner:** alfred-security-engineer
**Files:**
- Modify: `src/alfred/plugins/web_fetch/handle_cap.py`
- Modify: `tests/unit/plugins/web_fetch/test_handle_cap.py`

- [ ] **Step 1: Write failing tests.**

  Append to `tests/unit/plugins/web_fetch/test_handle_cap.py`:

  ```python
  # --- release (spec §2.4) ---

  @pytest.mark.asyncio
  async def test_release_decrements_count(cap: HandleCap) -> None:
      u = _u(); h = _h()
      await cap.try_reserve(user_id=u, handle_id=h, handle_ttl_seconds=80)
      await cap.release(user_id=u, handle_id=h)
      # After release, the user can reserve again immediately.
      await cap.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)


  @pytest.mark.asyncio
  async def test_release_unknown_handle_id_no_op(cap: HandleCap) -> None:
      """Idempotent — release of a never-reserved id is a no-op ZREM."""
      await cap.release(user_id=_u(), handle_id="never-reserved")


  @pytest.mark.asyncio
  async def test_release_twice_no_op(cap: HandleCap) -> None:
      u = _u(); h = _h()
      await cap.try_reserve(user_id=u, handle_id=h, handle_ttl_seconds=80)
      await cap.release(user_id=u, handle_id=h)
      await cap.release(user_id=u, handle_id=h)  # second is a no-op


  @pytest.mark.asyncio
  async def test_aclose_is_idempotent(cap: HandleCap) -> None:
      await cap.aclose()
      await cap.aclose()
  ```

- [ ] **Step 2: Run to confirm failure (only the `release_decrements_count` test fails until method exists; others may already pass via `getattr` shape — confirm with `-v`).**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py -v -k "release or aclose"
  ```

- [ ] **Step 3: Implement `release`.**

  Add to `HandleCap` class in `src/alfred/plugins/web_fetch/handle_cap.py`:

  ```python
  async def release(self, *, user_id: str, handle_id: str) -> None:
      """Idempotent ZREM. Safe to call after passive TTL has already evicted.

      No Lua needed — single-command ZREM is atomic by itself.

      Args:
          user_id: same canonical id used at ``try_reserve`` time.
          handle_id: the UUID4 the dispatcher pre-minted.
      """
      client = await self._get_client()
      key = f"{_KEY_PREFIX_USER}{user_id}"
      await client.zrem(key, handle_id)
  ```

- [ ] **Step 4: Run.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py -v
  ```

  Expected: all green.

- [ ] **Step 5: Commit.**

  ```bash
  git add src/alfred/plugins/web_fetch/handle_cap.py tests/unit/plugins/web_fetch/test_handle_cap.py
  git commit -m "feat(handle-cap): idempotent release (ZREM) + aclose (#157)

  Single-command ZREM is atomic by itself. Idempotent — release of an
  already-evicted id is a no-op, matches the spec's release-suppression
  discipline (passive TTL is the canonical evict path).

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 6 — TTL / passive-eviction tests

**Owner:** alfred-security-engineer
**Files:**
- Modify: `tests/unit/plugins/web_fetch/test_handle_cap.py`

No new production code — these tests exercise the ZREMRANGEBYSCORE pruning path.

- [ ] **Step 1: Write the tests.**

  Append to `tests/unit/plugins/web_fetch/test_handle_cap.py`:

  ```python
  # --- TTL / passive eviction (spec §2.3) ---

  @pytest.mark.asyncio
  async def test_expired_entries_evicted_on_next_reserve(cap: HandleCap) -> None:
      """A handle whose score is in the past is evicted by the next reserve's
      ZREMRANGEBYSCORE — restores capacity."""
      u = _u()
      now = int(time.time() * 1000)
      # Inject 5 expired members directly (score in the past).
      client = await cap._get_client()
      key = f"alfred:handles:user:{u}"
      pipe = client.pipeline()
      for i in range(5):
          pipe.zadd(key, {f"expired-{i}": now - 1000})
      pipe.expire(key, 600)
      await pipe.execute()
      # Reserve should succeed — expired entries evicted, count drops to 0.
      await cap.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)


  @pytest.mark.asyncio
  async def test_staggered_expiry_decrements_count(cap: HandleCap) -> None:
      """Five handles with staggered expiry; later reserves succeed as earlier
      members fall out of the window."""
      u = _u()
      now = int(time.time() * 1000)
      client = await cap._get_client()
      key = f"alfred:handles:user:{u}"
      # Inject 5 members already expired at staggered times — all evictable now.
      pipe = client.pipeline()
      for i in range(5):
          pipe.zadd(key, {f"old-{i}": now - 5000 + i * 100})
      await pipe.execute()
      # First reserve evicts all 5 — succeeds.
      await cap.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)


  @pytest.mark.asyncio
  async def test_user_key_outer_expire_set(cap: HandleCap) -> None:
      """The user's ZSET key gets an outer EXPIRE so idle keys don't accumulate."""
      u = _u()
      await cap.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
      client = await cap._get_client()
      ttl = await client.ttl(f"alfred:handles:user:{u}")
      # Outer TTL = max(80*2, 600) = 600.
      assert 590 <= ttl <= 600
  ```

- [ ] **Step 2: Run.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py -v -k "expir or outer"
  ```

  Expected: all green (no production code changed).

- [ ] **Step 3: Commit.**

  ```bash
  git add tests/unit/plugins/web_fetch/test_handle_cap.py
  git commit -m "test(handle-cap): TTL / passive eviction coverage (#157)

  Pins the ZREMRANGEBYSCORE-on-reserve passive-eviction behaviour: expired
  members are silently evicted at the head of every try_reserve, restoring
  capacity. Outer key EXPIRE = max(handle_ttl*2, _OUTER_KEY_TTL_FLOOR_SECONDS)
  bounds idle-user keyspace footprint.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 7 — Atomicity / race-condition tests

**Owner:** alfred-security-engineer
**Files:**
- Modify: `tests/unit/plugins/web_fetch/test_handle_cap.py`

- [ ] **Step 1: Write the tests.**

  Append to `tests/unit/plugins/web_fetch/test_handle_cap.py`:

  ```python
  # --- Atomicity / race conditions (spec §2.3) ---

  @pytest.mark.asyncio
  async def test_race_two_at_boundary(redis_url: str) -> None:
      """Two coroutines racing the 5th-and-6th slot with cap=5 and 4 already
      reserved. Exactly one succeeds, one raises WebFetchRateLimited."""
      hc = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=5))
      try:
          u = _u()
          for _ in range(4):
              await hc.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
          results: list[bool | WebFetchRateLimited] = []
          async def attempt() -> None:
              try:
                  await hc.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
                  results.append(True)
              except WebFetchRateLimited as e:
                  results.append(e)
          async with asyncio.TaskGroup() as tg:
              tg.create_task(attempt())
              tg.create_task(attempt())
          successes = [r for r in results if r is True]
          failures = [r for r in results if isinstance(r, WebFetchRateLimited)]
          assert len(successes) == 1, f"expected exactly 1 success, got {results}"
          assert len(failures) == 1, f"expected exactly 1 failure, got {results}"
          assert failures[0].bucket == "handle_cap"
      finally:
          await hc.aclose()


  @pytest.mark.asyncio
  async def test_race_six_against_empty(redis_url: str) -> None:
      """Six concurrent reserves against an empty key with cap=5. Exactly
      5 succeed, 1 fails."""
      hc = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=5))
      try:
          u = _u()
          results: list[bool | WebFetchRateLimited] = []
          async def attempt() -> None:
              try:
                  await hc.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
                  results.append(True)
              except WebFetchRateLimited as e:
                  results.append(e)
          async with asyncio.TaskGroup() as tg:
              for _ in range(6):
                  tg.create_task(attempt())
          successes = [r for r in results if r is True]
          failures = [r for r in results if isinstance(r, WebFetchRateLimited)]
          assert len(successes) == 5, f"expected 5 successes, got {results}"
          assert len(failures) == 1, f"expected 1 failure, got {results}"
      finally:
          await hc.aclose()


  @pytest.mark.asyncio
  async def test_release_and_reserve_race_keeps_invariant(redis_url: str) -> None:
      """Interleaved release+reserve must never let ZCARD breach cap.

      Cap=3; alternate reserve/release across 50 coroutine pairs; observe
      ZCARD after each batch."""
      hc = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=3))
      try:
          u = _u()
          handles = [_h() for _ in range(50)]
          for i, h in enumerate(handles):
              try:
                  await hc.try_reserve(user_id=u, handle_id=h, handle_ttl_seconds=80)
              except WebFetchRateLimited:
                  pass
              # Periodically release the oldest active member.
              if i % 2 == 1 and i >= 2:
                  await hc.release(user_id=u, handle_id=handles[i - 2])
              client = await hc._get_client()
              card = await client.zcard(f"alfred:handles:user:{u}")
              assert card <= 3, f"cap breached at i={i}; ZCARD={card}"
      finally:
          await hc.aclose()


  @pytest.mark.asyncio
  async def test_reserve_same_handle_id_twice_is_score_update(cap: HandleCap) -> None:
      """ZADD without NX updates the score (extends expiry); count unchanged.
      Documents intentional behaviour — pinned so a future refactor doesn't
      silently break it."""
      u = _u(); h = _h()
      await cap.try_reserve(user_id=u, handle_id=h, handle_ttl_seconds=80)
      client = await cap._get_client()
      count_before = await client.zcard(f"alfred:handles:user:{u}")
      await cap.try_reserve(user_id=u, handle_id=h, handle_ttl_seconds=80)
      count_after = await client.zcard(f"alfred:handles:user:{u}")
      assert count_before == count_after == 1
  ```

- [ ] **Step 2: Run.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py -v -k "race or score_update"
  ```

  Expected: all green.

- [ ] **Step 3: Commit.**

  ```bash
  git add tests/unit/plugins/web_fetch/test_handle_cap.py
  git commit -m "test(handle-cap): atomic race / boundary coverage (#157)

  Pin the Lua-atomic guarantee against asyncio.TaskGroup concurrent reserves
  at the boundary (4→5+1) and against the empty (0→5+1) shape. Also pin
  the ZADD-without-NX score-update semantics for same-handle-id re-reserve.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 8 — Config edges + user isolation tests

**Owner:** alfred-security-engineer
**Files:**
- Modify: `tests/unit/plugins/web_fetch/test_handle_cap.py`

- [ ] **Step 1: Write the tests.**

  Append:

  ```python
  # --- Config edges + isolation ---

  @pytest.mark.asyncio
  async def test_cap_one_serializes(redis_url: str) -> None:
      hc = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=1))
      try:
          u = _u(); h1 = _h(); h2 = _h()
          await hc.try_reserve(user_id=u, handle_id=h1, handle_ttl_seconds=80)
          with pytest.raises(WebFetchRateLimited):
              await hc.try_reserve(user_id=u, handle_id=h2, handle_ttl_seconds=80)
          await hc.release(user_id=u, handle_id=h1)
          await hc.try_reserve(user_id=u, handle_id=h2, handle_ttl_seconds=80)
      finally:
          await hc.aclose()


  @pytest.mark.asyncio
  async def test_cap_large_value_honoured(redis_url: str) -> None:
      """No off-by-one: cap=1000 lets exactly 1000 succeed, 1001 refused."""
      hc = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=1000))
      try:
          u = _u()
          for _ in range(1000):
              await hc.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
          with pytest.raises(WebFetchRateLimited):
              await hc.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
      finally:
          await hc.aclose()


  @pytest.mark.asyncio
  async def test_user_a_cap_does_not_affect_user_b(cap: HandleCap) -> None:
      """Independent ZSET keys — exhausting one user doesn't refuse another."""
      a, b = _u(), _u()
      for _ in range(5):
          await cap.try_reserve(user_id=a, handle_id=_h(), handle_ttl_seconds=80)
      with pytest.raises(WebFetchRateLimited):
          await cap.try_reserve(user_id=a, handle_id=_h(), handle_ttl_seconds=80)
      # User B is unaffected.
      await cap.try_reserve(user_id=b, handle_id=_h(), handle_ttl_seconds=80)
  ```

- [ ] **Step 2: Run.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py -v -k "cap_one or cap_large or user_a"
  ```

- [ ] **Step 3: Commit.**

  ```bash
  git add tests/unit/plugins/web_fetch/test_handle_cap.py
  git commit -m "test(handle-cap): config edges + per-user key isolation (#157)

  Pin cap=1 serialised semantics, cap=1000 off-by-one absence, and the
  per-user ZSET-key namespacing so one user's exhaustion never affects
  another.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 9 — Redis transient-failure tests (per subtype)

**Owner:** alfred-security-engineer
**Files:**
- Modify: `tests/unit/plugins/web_fetch/test_handle_cap.py`
- Modify: `src/alfred/plugins/web_fetch/handle_cap.py` (loud structlog in release path)

- [ ] **Step 1: Write the failing tests.**

  Append:

  ```python
  # --- Redis transient failures by subtype (CLAUDE.md hard rule #7, spec §8.2) ---

  from unittest.mock import patch, AsyncMock
  from redis.exceptions import (
      BusyLoadingError, ConnectionError as RedisConnectionError,
      ResponseError, TimeoutError as RedisTimeoutError,
  )


  @pytest.mark.asyncio
  async def test_reserve_timeout_propagates(cap: HandleCap) -> None:
      """Reserve fails closed on TimeoutError — propagates so the dispatcher
      can emit its transport_error audit row."""
      script = await cap._get_script()
      with patch.object(cap, "_get_script", AsyncMock(return_value=AsyncMock(
              side_effect=RedisTimeoutError("simulated timeout")))):
          with pytest.raises(RedisTimeoutError):
              await cap.try_reserve(user_id=_u(), handle_id=_h(), handle_ttl_seconds=80)


  @pytest.mark.asyncio
  async def test_reserve_connection_error_propagates(cap: HandleCap) -> None:
      with patch.object(cap, "_get_script", AsyncMock(return_value=AsyncMock(
              side_effect=RedisConnectionError("simulated reset")))):
          with pytest.raises(RedisConnectionError):
              await cap.try_reserve(user_id=_u(), handle_id=_h(), handle_ttl_seconds=80)


  @pytest.mark.asyncio
  async def test_reserve_response_error_propagates(cap: HandleCap) -> None:
      """ResponseError = runtime Redis bug (e.g., WRONGTYPE). Fail closed."""
      with patch.object(cap, "_get_script", AsyncMock(return_value=AsyncMock(
              side_effect=ResponseError("WRONGTYPE")))):
          with pytest.raises(ResponseError):
              await cap.try_reserve(user_id=_u(), handle_id=_h(), handle_ttl_seconds=80)


  @pytest.mark.asyncio
  async def test_reserve_busyloading_propagates(cap: HandleCap) -> None:
      """BusyLoadingError = Redis still loading the RDB. Fail closed; operator
      sees the error class in the audit row's exception_type field."""
      with patch.object(cap, "_get_script", AsyncMock(return_value=AsyncMock(
              side_effect=BusyLoadingError("loading")))):
          with pytest.raises(BusyLoadingError):
              await cap.try_reserve(user_id=_u(), handle_id=_h(), handle_ttl_seconds=80)


  @pytest.mark.asyncio
  async def test_release_timeout_logs_loud_no_propagate(
      cap: HandleCap, caplog: pytest.LogCaptureFixture,
  ) -> None:
      """Release path's ZREM raises TimeoutError. Does NOT propagate (caller
      is past the conversation turn); LOUD web_fetch.handle_cap.release_failed
      structlog event fires."""
      fake_client = AsyncMock()
      fake_client.zrem.side_effect = RedisTimeoutError("simulated")
      with patch.object(cap, "_get_client", AsyncMock(return_value=fake_client)):
          # Should NOT raise.
          await cap.release(user_id=_u(), handle_id=_h())
      # structlog event captured by caplog (via structlog's stdlib bridge).
      assert any("handle_cap.release_failed" in r.getMessage() for r in caplog.records)


  @pytest.mark.asyncio
  async def test_release_connection_error_logs_loud_no_propagate(
      cap: HandleCap, caplog: pytest.LogCaptureFixture,
  ) -> None:
      fake_client = AsyncMock()
      fake_client.zrem.side_effect = RedisConnectionError("simulated reset")
      with patch.object(cap, "_get_client", AsyncMock(return_value=fake_client)):
          await cap.release(user_id=_u(), handle_id=_h())
      assert any("handle_cap.release_failed" in r.getMessage() for r in caplog.records)
  ```

- [ ] **Step 2: Run to confirm release tests fail.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py -v -k "timeout or connection or response or busy"
  ```

  Expected: `test_release_timeout_logs_loud_no_propagate` and `test_release_connection_error_logs_loud_no_propagate` fail (no structlog event yet).

- [ ] **Step 3: Add the loud structlog event in `release`.**

  Update `release` in `src/alfred/plugins/web_fetch/handle_cap.py`:

  ```python
  async def release(self, *, user_id: str, handle_id: str) -> None:
      """Idempotent ZREM. Safe to call after passive TTL has already evicted.

      A Redis transient error on release does NOT propagate (the caller is
      already past the conversation turn; raising would only confuse the
      caller while losing the slot anyway). Instead a LOUD structlog event
      fires so operators see the stuck reservation; passive TTL eviction
      will free it within ~80s.
      """
      from redis.exceptions import RedisError
      client = await self._get_client()
      key = f"{_KEY_PREFIX_USER}{user_id}"
      try:
          await client.zrem(key, handle_id)
      except RedisError as exc:
          _log.error(
              "web_fetch.handle_cap.release_failed",
              user_id=user_id, handle_id=handle_id,
              exception_type=type(exc).__name__,
              note=(
                  "ZREM failed; cap slot held until passive TTL (~80s). "
                  "User's effective cap is reduced by 1 until eviction."
              ),
          )
          # Deliberately not re-raised — see CLAUDE.md hard rule #7.
  ```

- [ ] **Step 4: Run.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py -v
  ```

  Expected: all green.

- [ ] **Step 5: Commit.**

  ```bash
  git add src/alfred/plugins/web_fetch/handle_cap.py tests/unit/plugins/web_fetch/test_handle_cap.py
  git commit -m "feat(handle-cap): fail-loud release on Redis transient, fail-closed reserve (#157)

  Reserve propagates redis.exceptions.{Timeout,Connection,Response,BusyLoading}
  so the dispatcher's transport_error audit arm fires (CLAUDE.md hard rule
  #7). Release does NOT propagate — caller is past the conversation turn;
  loud web_fetch.handle_cap.release_failed structlog event fires instead;
  passive TTL within ~80s frees the slot.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 10 — EVALSHA NOSCRIPT fallback test

**Owner:** alfred-security-engineer
**Files:**
- Modify: `tests/unit/plugins/web_fetch/test_handle_cap.py`

- [ ] **Step 1: Write the test.**

  Append:

  ```python
  # --- EVALSHA NOSCRIPT fallback ---

  @pytest.mark.asyncio
  async def test_evalsha_noscript_reregisters_and_succeeds(cap: HandleCap) -> None:
      """SCRIPT FLUSH between calls; the next try_reserve hits NOSCRIPT, redis-py
      AsyncScript auto-falls-back to EVAL + re-caches; reserve succeeds."""
      await cap.try_reserve(user_id=_u(), handle_id=_h(), handle_ttl_seconds=80)
      client = await cap._get_client()
      await client.execute_command("SCRIPT", "FLUSH")
      # AsyncScript's __call__ catches NOSCRIPT and retries via EVAL.
      await cap.try_reserve(user_id=_u(), handle_id=_h(), handle_ttl_seconds=80)
  ```

- [ ] **Step 2: Run.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py -v -k "noscript"
  ```

  Expected: green (redis-py handles this transparently).

- [ ] **Step 3: Commit.**

  ```bash
  git add tests/unit/plugins/web_fetch/test_handle_cap.py
  git commit -m "test(handle-cap): EVALSHA NOSCRIPT auto-fallback coverage (#157)

  Pin the redis-py AsyncScript transparent NOSCRIPT → EVAL retry. SCRIPT
  FLUSH between two reserves; second still succeeds.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 11 — Hypothesis stateful invariant test

**Owner:** alfred-security-engineer + alfred-test-engineer
**Files:**
- Create: `tests/property/__init__.py`
- Create: `tests/property/plugins/__init__.py`
- Create: `tests/property/plugins/web_fetch/__init__.py`
- Create: `tests/property/plugins/web_fetch/test_handle_cap_invariants.py`

The cap's central invariant — `ZCARD ≤ cap` under all interleavings of `reserve` / `release` / `expire` — is property-shaped. Named race tests fix `n=2` and `n=6`; hypothesis explores random interleavings and surfaces minimal counterexamples.

- [ ] **Step 1: Create package markers.**

  Create three empty `__init__.py` files at the paths in §3.

- [ ] **Step 2: Write the stateful test.**

  Create `tests/property/plugins/web_fetch/test_handle_cap_invariants.py`:

  ```python
  """Hypothesis stateful property: ZCARD(alfred:handles:user:{u}) <= cap
  for all interleavings of reserve / release / expire / aclose.

  Complements the example-based race tests in test_handle_cap.py (which fix
  n=2 / n=6). The state machine explores random interleavings and shrinks
  to a minimal counterexample on any invariant violation.
  """

  from __future__ import annotations

  import time
  import uuid
  from collections.abc import Iterator

  import pytest
  from hypothesis import strategies as st
  from hypothesis.stateful import (
      RuleBasedStateMachine,
      initialize,
      invariant,
      rule,
      run_state_machine_as_test,
  )
  from testcontainers.redis import RedisContainer

  from alfred.plugins.web_fetch.errors import WebFetchRateLimited
  from alfred.plugins.web_fetch.handle_cap import HandleCap, HandleCapConfig


  @pytest.fixture(scope="module")
  def redis_url() -> Iterator[str]:
      with RedisContainer("redis:7-alpine") as r:
          yield f"redis://{r.get_container_host_ip()}:{r.get_exposed_port(6379)}"


  class HandleCapStateMachine(RuleBasedStateMachine):
      """State machine modelling reserve / release / direct-expire operations
      against a per-user ZSET with cap=3. Invariant: ZCARD(any user) <= 3."""

      CAP = 3

      def __init__(self) -> None:
          super().__init__()
          # redis_url is injected via the module-level fixture below.
          self.hc = HandleCap(redis_url=_REDIS_URL, config=HandleCapConfig(per_user=self.CAP))
          self.user_id = f"user-{uuid.uuid4()}"
          self.live: set[str] = set()

      @initialize()
      def _setup(self) -> None:
          # Anchor state at construction; no async setup possible here.
          pass

      @rule(handle_id=st.uuids().map(str))
      def reserve(self, handle_id: str) -> None:
          import asyncio
          try:
              asyncio.run(self.hc.try_reserve(
                  user_id=self.user_id, handle_id=handle_id, handle_ttl_seconds=60,
              ))
              self.live.add(handle_id)
          except WebFetchRateLimited:
              pass

      @rule(data=st.data())
      def release(self, data: st.DataObject) -> None:
          import asyncio
          if not self.live:
              return
          h = data.draw(st.sampled_from(sorted(self.live)))
          asyncio.run(self.hc.release(user_id=self.user_id, handle_id=h))
          self.live.discard(h)

      @rule()
      def force_expire(self) -> None:
          """Direct Redis manipulation to simulate TTL eviction.
          Sets all member scores to 0 (deeply in the past)."""
          import asyncio

          async def _expire() -> None:
              client = await self.hc._get_client()
              key = f"alfred:handles:user:{self.user_id}"
              members = await client.zrange(key, 0, -1)
              if members:
                  await client.zadd(key, {m.decode(): 0 for m in members})
          asyncio.run(_expire())
          # Next reserve will ZREMRANGEBYSCORE -inf <now_ms>, which clears them.
          self.live.clear()

      @invariant()
      def zcard_never_exceeds_cap(self) -> None:
          import asyncio

          async def _check() -> None:
              client = await self.hc._get_client()
              card = await client.zcard(f"alfred:handles:user:{self.user_id}")
              assert card <= self.CAP, f"ZCARD={card} exceeded cap={self.CAP}"
          asyncio.run(_check())

      def teardown(self) -> None:
          import asyncio
          asyncio.run(self.hc.aclose())


  # Hypothesis state-machine runs via a function so we can inject redis_url.
  _REDIS_URL: str = ""


  def test_handle_cap_invariant_under_random_interleavings(redis_url: str) -> None:
      global _REDIS_URL
      _REDIS_URL = redis_url
      run_state_machine_as_test(HandleCapStateMachine)
  ```

- [ ] **Step 3: Run.**

  ```bash
  uv run pytest tests/property/plugins/web_fetch/test_handle_cap_invariants.py -v
  ```

  Expected: green. Hypothesis will draw many random rule sequences; the invariant must hold throughout.

- [ ] **Step 4: Commit.**

  ```bash
  git add tests/property/
  git commit -m "test(handle-cap): hypothesis stateful invariant — ZCARD <= cap (#157)

  RuleBasedStateMachine models reserve / release / force-expire operations
  against a real Redis-backed HandleCap with cap=3. Invariant decorator
  asserts ZCARD never exceeds the cap under random interleavings —
  complements the example-based race tests in test_handle_cap.py.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Component C — Contract changes (ContentStore + plugin)

#### Task 12 — `ContentStore.write` signature change: `handle_id` required

**Owner:** alfred-security-engineer
**Files:**
- Modify: `src/alfred/plugins/web_fetch/content_store.py`
- Modify: `tests/unit/plugins/web_fetch/test_content_handle_single_use.py`

- [ ] **Step 1: Update the failing tests.**

  Find `test_content_handle_single_use.py` and update every `store.write(body=..., source_url=...)` callsite to pass an explicit `handle_id=str(uuid.uuid4())`. Add one new test:

  ```python
  @pytest.mark.asyncio
  async def test_write_uses_passed_handle_id_not_internal_mint(
      store: ContentStore,
  ) -> None:
      """Host pre-mints handle_id; ContentStore.write uses it verbatim, no
      internal uuid4() mint. Cap-binding (spec §3) depends on this contract."""
      h = "pre-minted-deterministic-id"
      handle = await store.write(handle_id=h, body=b"x", source_url="https://example.com/")
      assert handle.id == h
  ```

- [ ] **Step 2: Run to confirm failure.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_content_handle_single_use.py -v
  ```

  Expected: `TypeError: write() got an unexpected keyword argument 'handle_id'` (or similar).

- [ ] **Step 3: Implement the contract change.**

  Edit `src/alfred/plugins/web_fetch/content_store.py`. Find the `write` method (currently ~line 163) and change its signature:

  ```python
  async def write(
      self,
      *,
      handle_id: str,                          # NEW required kwarg
      body: bytes,
      source_url: str,
      action_deadline_seconds: int = _DEFAULT_ACTION_DEADLINE_SECONDS,
      max_extraction_retries: int = _DEFAULT_MAX_EXTRACTION_RETRIES,
      per_retry_budget_seconds: int = _DEFAULT_PER_RETRY_BUDGET_SECONDS,
      slack_seconds: int = _DEFAULT_SLACK_SECONDS,
  ) -> ContentHandle:
      """Write ``body`` to Redis under the host-pre-minted ``handle_id``.

      Spec §3 contract change: the host (dispatcher) pre-mints the id so
      the cap (:class:`HandleCap`) can reserve the slot BEFORE the network
      fetch happens. Plugin no longer mints internally.
      """
      # Internal uuid4() mint REMOVED — handle_id is now caller-supplied.
      ttl = (
          action_deadline_seconds
          + (max_extraction_retries * per_retry_budget_seconds)
          + slack_seconds
      )
      if ttl <= 0:
          msg = (
              "web.fetch content-store TTL must be positive; computed "
              f"{ttl}s from action_deadline={action_deadline_seconds}, "
              f"max_extraction_retries={max_extraction_retries}, "
              f"per_retry_budget={per_retry_budget_seconds}, "
              f"slack={slack_seconds}."
          )
          raise ValueError(msg)
      key = f"{_KEY_PREFIX}{handle_id}"
      client = await self._get_client()
      await client.set(key, body, ex=ttl)
      _log.debug(
          "web_fetch.content_store.written",
          handle_id=handle_id,
          ttl_seconds=ttl,
          source_url=_sanitize_url_for_log(source_url),
          body_bytes=len(body),
      )
      return ContentHandle(
          id=handle_id,
          source_url=source_url,
          fetch_timestamp=datetime.now(tz=UTC),
      )
  ```

  Also remove the `import uuid` line if it's no longer needed elsewhere in the module.

- [ ] **Step 4: Run all web_fetch unit tests + the integration test.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/ -v
  # If the integration test exists:
  uv run pytest tests/integration/test_redis_compose_service.py -v 2>&1 | head -50
  ```

  Expected: green. If the integration test exists and fails, update its `write` callsite too.

- [ ] **Step 5: Commit.**

  ```bash
  git add src/alfred/plugins/web_fetch/content_store.py tests/unit/plugins/web_fetch/test_content_handle_single_use.py
  # If integration test changed:
  # git add tests/integration/test_redis_compose_service.py
  git commit -m "feat(content-store)!: ContentStore.write requires host-supplied handle_id (#157)

  Spec §3 contract change. Host (dispatcher) pre-mints the handle_id so
  HandleCap.try_reserve can bind the slot BEFORE the network fetch.
  Internal uuid.uuid4() mint path removed.

  BREAKING: callers of ContentStore.write must now pass handle_id=...
  explicitly. In-tree callers (Task 13: web_fetch_plugin._handle_fetch)
  updated in the next task.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 13 — Plugin subprocess forwards `content_handle_id` param

**Owner:** alfred-security-engineer
**Files:**
- Modify: `plugins/alfred_web_fetch/web_fetch_plugin.py`
- Add/Modify: a smoke test under `tests/unit/plugins/`

- [ ] **Step 1: Write the failing test.**

  Edit (or create) a smoke test that exercises `_handle_fetch` with a known `content_handle_id` and asserts the returned handle uses that id. The existing test file is `tests/unit/plugins/test_comms_test_plugin_smoke.py` — check if there's a web_fetch equivalent. If not, add one inline as a new test file `tests/unit/plugins/test_web_fetch_plugin_handle_id_passthrough.py`:

  ```python
  """Smoke test: the alfred-web-fetch plugin subprocess forwards
  params['content_handle_id'] verbatim to ContentStore.write (spec §3)."""

  from __future__ import annotations

  from unittest.mock import AsyncMock, patch

  import pytest


  @pytest.mark.asyncio
  async def test_handle_fetch_forwards_content_handle_id() -> None:
      from plugins.alfred_web_fetch.web_fetch_plugin import _handle_fetch
      from alfred.security.quarantine import ContentHandle
      from datetime import datetime, UTC

      params = {
          "url": "https://example.com/",
          "headers": {},
          "redis_url": "redis://localhost:6379",
          "content_handle_id": "test-pre-minted-id",
      }
      pre_minted = ContentHandle(
          id="test-pre-minted-id",
          source_url="https://example.com/",
          fetch_timestamp=datetime.now(tz=UTC),
      )
      mock_store = AsyncMock()
      mock_store.write.return_value = pre_minted

      # Patch the aiohttp + store fixture stack. The actual implementation
      # call should pass handle_id="test-pre-minted-id" to store.write().
      with patch("plugins.alfred_web_fetch.web_fetch_plugin._get_or_init_store",
                 AsyncMock(return_value=mock_store)):
          with patch("aiohttp.ClientSession") as session_cls:
              session_cls.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value.status = 200
              session_cls.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value.headers = {"Content-Type": "text/html"}
              async def _iter() -> object:
                  yield (b"<html></html>", True)
              session_cls.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value.content.iter_chunks = _iter
              result = await _handle_fetch(params)

      assert result["result"]["id"] == "test-pre-minted-id"
      mock_store.write.assert_called_once()
      kwargs = mock_store.write.call_args.kwargs
      assert kwargs["handle_id"] == "test-pre-minted-id"
  ```

  (Note: the aiohttp mocking in this test is intricate; if it's flaky, switch to mocking the whole `aiohttp.ClientSession.get` path with `aioresponses` or factor `_handle_fetch` to take an injected client. Pragmatically, this test pattern is documented; adjust to whatever the existing PR-S3-5 test patterns use.)

- [ ] **Step 2: Run to confirm failure.**

  ```bash
  uv run pytest tests/unit/plugins/test_web_fetch_plugin_handle_id_passthrough.py -v
  ```

  Expected: KeyError on `params["content_handle_id"]` or the write callsite not passing `handle_id`.

- [ ] **Step 3: Implement.**

  Edit `plugins/alfred_web_fetch/web_fetch_plugin.py`. In `_handle_fetch`:

  ```python
  async def _handle_fetch(params: dict[str, Any]) -> dict[str, Any]:
      url: str = params["url"]
      headers: dict[str, str] = params.get("headers", {})
      redis_url: str = params["redis_url"]
      skip_tls: bool = params.get("skip_tls_verify", False)
      # NEW: host pre-mints the handle id; plugin uses it verbatim (spec §3).
      content_handle_id: str = params["content_handle_id"]
      ...

      # At the bottom, where ContentStore.write is called:
      store = await _get_or_init_store(redis_url)
      handle = await store.write(
          handle_id=content_handle_id,   # NEW required kwarg
          body=body,
          source_url=url,
      )
      ...
  ```

- [ ] **Step 4: Run.**

  ```bash
  uv run pytest tests/unit/plugins/test_web_fetch_plugin_handle_id_passthrough.py tests/unit/plugins/web_fetch/ -v
  ```

  Expected: all green.

- [ ] **Step 5: Commit.**

  ```bash
  git add plugins/alfred_web_fetch/web_fetch_plugin.py tests/unit/plugins/test_web_fetch_plugin_handle_id_passthrough.py
  git commit -m "feat(web-fetch-plugin): forward content_handle_id from host pre-mint (#157)

  Spec §3 contract change. _handle_fetch reads params['content_handle_id']
  (host pre-minted by dispatch_web_fetch) and passes it verbatim to
  ContentStore.write. No more internal uuid4() mint path inside the plugin.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Component D — i18n catalog + canary scanner signature

#### Task 14 — i18n catalog entries

**Owner:** alfred-i18n-reviewer + alfred-security-engineer
**Files:**
- Modify: `locale/en/LC_MESSAGES/alfred.po`
- Modify: `locale/en/LC_MESSAGES/alfred.mo` (regenerated by pybabel)
- Modify: `tests/unit/plugins/web_fetch/test_handle_cap_errors.py` (remove XFAIL marker from Task 1)

- [ ] **Step 1: Add the two new entries to `locale/en/LC_MESSAGES/alfred.po`.**

  Find a logical insertion point near the existing `web.fetch.error.rate_limited` entry (around line 1313). Append:

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

- [ ] **Step 2: Regenerate the compiled catalog.**

  ```bash
  uv run pybabel compile -d locale/
  ```

- [ ] **Step 3: Remove the XFAIL marker (if added) from `test_handle_cap_bucket_message_dispatches_to_dedicated_key`.**

- [ ] **Step 4: Run the catalog drift check + the error tests.**

  ```bash
  uv run pybabel extract -F babel.cfg -o locale/alfred.pot src/alfred/
  uv run pybabel update -i locale/alfred.pot -d locale/ --previous --no-fuzzy-matching
  # Confirm no unexpected drift:
  git diff locale/en/LC_MESSAGES/alfred.po
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap_errors.py -v
  ```

  Expected: catalog stable; tests green.

- [ ] **Step 5: Commit.**

  ```bash
  git add locale/
  git commit -m "i18n(web-fetch): dedicated catalog entries for handle_cap + handle_id_mismatch (#157)

  - web.fetch.error.rate_limited.handle_cap: operator-actionable message
    pointing at web_fetch.max_concurrent_handles_per_user (NOT the generic
    web_fetch.rate_limits knob the generic rate_limited template implies).
  - web.fetch.error.handle_id_mismatch: documents the host-side
    equality-check failure without leaking pre-mint ids.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 15 — Canary scanner `user_id` param + hook-payload extension

**Owner:** alfred-security-engineer + alfred-comms-engineer (hook-payload)
**Files:**
- Modify: `src/alfred/plugins/web_fetch/canary_scanner.py`
- Modify: `tests/unit/plugins/web_fetch/test_canary_scanner_host_side.py`
- Modify: wherever `tool.web.fetch` post-hookpoint subscriber registration lives — likely in `src/alfred/plugins/web_fetch/__init__.py` or a `register_hookpoints` helper alongside `canary_scanner.py`.

- [ ] **Step 1: Update existing canary-scanner tests + add new ones.**

  Change every `scanner.scan(handle_id=..., source_url=...)` callsite to pass `user_id=...`. Add:

  ```python
  @pytest.mark.asyncio
  async def test_scan_releases_cap_on_successful_canary_delete(
      content_store: ContentStore, redis_url: str,
  ) -> None:
      """Spec §5.2 — on canary trip, store.delete succeeds → release fires."""
      from unittest.mock import AsyncMock, patch
      from alfred.plugins.web_fetch.canary_scanner import (
          CanaryToken, InboundCanaryScanner,
      )

      handle = await content_store.write(
          handle_id="canary-test-id",
          body=b"BAD_CANARY_TOKEN inside content",
          source_url="https://example.com/",
      )
      scanner = InboundCanaryScanner(
          content_store=content_store,
          known_canary_tokens=[CanaryToken(value="BAD_CANARY_TOKEN")],
          redis_url=redis_url,
      )
      mock_cap = AsyncMock()
      scanner._handle_cap = mock_cap  # injected dependency in updated signature

      with pytest.raises(WebFetchCanaryTripped):
          await scanner.scan(
              handle_id=handle.id, source_url="https://example.com/",
              user_id="user-abc",
          )
      mock_cap.release.assert_called_once_with(
          user_id="user-abc", handle_id="canary-test-id",
      )
      await scanner.aclose()


  @pytest.mark.asyncio
  async def test_scan_does_not_release_when_delete_raises(
      content_store: ContentStore, redis_url: str,
  ) -> None:
      """Spec §5.2 — store.delete raises → release NOT called; body may
      still be in Redis; HOLD the cap until passive TTL."""
      from unittest.mock import AsyncMock, patch
      from redis.exceptions import RedisError
      from alfred.plugins.web_fetch.canary_scanner import (
          CanaryToken, InboundCanaryScanner,
      )

      handle = await content_store.write(
          handle_id="canary-fail-id",
          body=b"BAD_CANARY_TOKEN content",
          source_url="https://example.com/",
      )
      scanner = InboundCanaryScanner(
          content_store=content_store,
          known_canary_tokens=[CanaryToken(value="BAD_CANARY_TOKEN")],
          redis_url=redis_url,
      )
      mock_cap = AsyncMock()
      scanner._handle_cap = mock_cap

      with patch.object(content_store, "delete",
                        AsyncMock(side_effect=RedisError("simulated"))):
          with pytest.raises(WebFetchCanaryTripped):
              await scanner.scan(
                  handle_id=handle.id, source_url="https://example.com/",
                  user_id="user-abc",
              )
      mock_cap.release.assert_not_called()
      await scanner.aclose()
  ```

- [ ] **Step 2: Run to confirm failure.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_canary_scanner_host_side.py -v
  ```

  Expected: `TypeError: scan() got an unexpected keyword argument 'user_id'`.

- [ ] **Step 3: Update `scan` signature + add HandleCap injection.**

  Edit `src/alfred/plugins/web_fetch/canary_scanner.py`. Update the `__init__` to accept an optional `handle_cap: HandleCap | None = None` kwarg; update `scan` signature to `async def scan(self, *, handle_id: str, source_url: str, user_id: str) -> None`. After the existing `self._store.delete(handle_id)` block on the canary-trip path:

  ```python
                  try:
                      await self._store.delete(handle_id)
                  except RedisError as quarantine_exc:
                      _log.error(
                          "web_fetch.canary.quarantine_failed",
                          handle_id=handle_id,
                          source_url=_sanitize_url_for_log(source_url),
                          pattern=pattern.pattern,
                          exception_type=type(quarantine_exc).__name__,
                          note=(
                              "canary quarantine I/O failed; handle may "
                              "remain in store until TTL — typed canary "
                              "exception STILL raised; cap slot HELD "
                              "(passive TTL eviction will free)"
                          ),
                      )
                  else:
                      # Spec §5.2: release ONLY on confirmed Redis state change.
                      if self._handle_cap is not None:
                          await self._handle_cap.release(
                              user_id=user_id, handle_id=handle_id,
                          )
                  raise WebFetchCanaryTripped(source_url=source_url, handle_id=handle_id)
  ```

- [ ] **Step 4: Update the hookpoint subscriber registration.**

  Find where `InboundCanaryScanner` is registered as a `tool.web.fetch` post subscriber (likely `register_hookpoints` in `__init__.py` or a similar helper). Update the registration adapter to extract `triggering_user_id` from the hookpoint event context and pass it as `user_id` to `scan()`. The hook event MUST carry `triggering_user_id` — confirm this by reading `src/alfred/hooks/registry.py` and the existing `tool.web.fetch` event-shape definition.

  If the hookpoint event doesn't currently carry `triggering_user_id`, **stop and consult with the user** — this is a hook-payload schema change that may need its own ADR or wider design alignment.

- [ ] **Step 5: Run.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_canary_scanner_host_side.py -v
  ```

  Expected: all green.

- [ ] **Step 6: Commit.**

  ```bash
  git add src/alfred/plugins/web_fetch/canary_scanner.py src/alfred/plugins/web_fetch/__init__.py tests/unit/plugins/web_fetch/test_canary_scanner_host_side.py
  git commit -m "feat(canary-scanner): user_id propagation + release-on-canary-delete (#157)

  scan() gains a required user_id kwarg threaded from the tool.web.fetch
  post-hookpoint event context (triggering_user_id). On a canary trip:
  - store.delete succeeds → handle_cap.release fires (slot freed).
  - store.delete raises RedisError → HOLD (body still in Redis).
    Passive TTL within ~80s frees the slot. Spec §5.2 discipline.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Component E — Dispatcher integration

#### Task 16 — Dispatcher accepts `handle_cap` kwarg + reserve + cap-refusal audit row

**Owner:** alfred-security-engineer
**Files:**
- Modify: `src/alfred/plugins/web_fetch/fetch_dispatcher.py`
- Modify: `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py`

- [ ] **Step 1: Write the failing tests.**

  Append to `test_fetch_dispatcher.py`:

  ```python
  @pytest.mark.asyncio
  async def test_dispatcher_reserves_cap_before_transport(
      mock_dispatcher_deps: ..., mock_handle_cap: AsyncMock,
  ) -> None:
      """try_reserve fires before transport.dispatch."""
      ...
      await dispatch_web_fetch(..., handle_cap=mock_handle_cap)
      # Assert ordering: try_reserve called BEFORE transport.dispatch.
      assert mock_handle_cap.try_reserve.call_args_list[0].kwargs["user_id"] == "user-a"
      # Verify try_reserve was called BEFORE transport via mock_calls ordering check.


  @pytest.mark.asyncio
  async def test_dispatcher_cap_refusal_emits_audit_row(
      mock_dispatcher_deps: ..., mock_handle_cap: AsyncMock,
  ) -> None:
      """Cap exceeded → audit row carries rate_limit_bucket='handle_cap',
      dlp_scan_result='handle_cap_exceeded', content_handle_id=None."""
      mock_handle_cap.try_reserve.side_effect = WebFetchRateLimited("handle_cap")
      with pytest.raises(WebFetchRateLimited) as exc_info:
          await dispatch_web_fetch(..., handle_cap=mock_handle_cap)
      assert exc_info.value.bucket == "handle_cap"
      # Audit row inspection:
      audit_call = mock_dispatcher_deps.audit.append_schema.call_args_list[-1]
      subj = audit_call.kwargs["subject"]
      assert subj["rate_limit_bucket"] == "handle_cap"
      assert subj["dlp_scan_result"] == "handle_cap_exceeded"
      assert subj["content_handle_id"] is None    # disputed-#2 decision
      assert audit_call.kwargs["result"] == "rate_limited"
  ```

  (Adapt the test fixture stack to whatever `test_fetch_dispatcher.py` already uses — the existing tests provide the wiring shape.)

- [ ] **Step 2: Run to confirm failure.**

  Expected: `TypeError: dispatch_web_fetch() got an unexpected keyword argument 'handle_cap'`.

- [ ] **Step 3: Implement the dispatcher signature + cap reserve.**

  Edit `src/alfred/plugins/web_fetch/fetch_dispatcher.py`:

  ```python
  # Add to imports at top:
  import asyncio
  import contextlib
  import uuid
  from alfred.plugins.web_fetch.handle_cap import HandleCap


  async def dispatch_web_fetch(
      *,
      url: str,
      headers: dict[str, str],
      user_id: str,
      correlation_id: str,
      config: FetchDispatchConfig,
      rate_limiter: RateLimiter,
      outbound_dlp: OutboundDlp,
      audit: AuditWriter,
      transport: PluginTransport,
      handle_cap: HandleCap,        # NEW required kwarg
  ) -> ContentHandle:
      ...
      # Existing: TLS → DLP → allowlist → host-IP → rate_limit checks.
      # AFTER the rate-limit refusal arm, BEFORE transport.dispatch:

      handle_id = str(uuid.uuid4())
      # The handle_ttl matches ContentStore.write's TTL formula.
      handle_ttl_seconds = (
          _DEFAULT_ACTION_DEADLINE_SECONDS
          + _DEFAULT_MAX_EXTRACTION_RETRIES * _DEFAULT_PER_RETRY_BUDGET_SECONDS
          + _DEFAULT_SLACK_SECONDS
      )
      try:
          await handle_cap.try_reserve(
              user_id=user_id,
              handle_id=handle_id,
              handle_ttl_seconds=handle_ttl_seconds,
          )
      except WebFetchRateLimited as e:
          await audit.append_schema(
              fields=WEB_FETCH_FIELDS,
              schema_name="WEB_FETCH_FIELDS",
              event="tool.web.fetch",
              actor_user_id=user_id,
              subject={
                  "url": clean_url, "domain": domain,
                  "status_code": None,
                  "content_handle_id": None,            # disputed-#2 → None
                  "fetch_depth": _FETCH_DEPTH,
                  "rate_limit_bucket": e.bucket,        # "handle_cap"
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

      # ... existing transport dispatch follows (will be wrapped with try/finally
      #     in Task 18). For now, just pass handle_id to the transport params.
      result = await transport.dispatch(
          "web.fetch",
          {
              "url": clean_url, "headers": clean_headers,
              "correlation_id": correlation_id,
              "redis_url": config.redis_url,
              "skip_tls_verify": config.skip_tls_verify,
              "content_handle_id": handle_id,           # NEW
          },
      )
      ...
  ```

  Also pull the default TTL constants from `content_store.py` (they're already there as `_DEFAULT_ACTION_DEADLINE_SECONDS` etc) — import them at the top of `fetch_dispatcher.py`.

- [ ] **Step 4: Run.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_fetch_dispatcher.py -v -k "reserve or cap_refusal"
  ```

- [ ] **Step 5: Commit.**

  ```bash
  git add src/alfred/plugins/web_fetch/fetch_dispatcher.py tests/unit/plugins/web_fetch/test_fetch_dispatcher.py
  git commit -m "feat(dispatcher): HandleCap kwarg + pre-mint handle_id + cap-refusal audit (#157)

  - Adds handle_cap: HandleCap as a required kwarg (NOT widened onto the
    frozen FetchDispatchConfig — HandleCap is a mutable runtime collaborator).
  - Pre-mints handle_id via uuid.uuid4() so the cap reserves the slot BEFORE
    the network fetch happens.
  - On WebFetchRateLimited(bucket='handle_cap') refusal: emit audit row
    with rate_limit_bucket='handle_cap', dlp_scan_result='handle_cap_exceeded',
    content_handle_id=None (disputed-#2 decision; matches rate-limit refusal
    precedent at line 483 — the pre-minted UUID was never written to Redis).
  - Forwards content_handle_id to the plugin via transport params.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 17 — Dispatcher release arms (transport error + typed plugin error)

**Owner:** alfred-security-engineer
**Files:**
- Modify: `src/alfred/plugins/web_fetch/fetch_dispatcher.py`
- Modify: `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py`

- [ ] **Step 1: Add the failing tests.**

  ```python
  @pytest.mark.asyncio
  async def test_dispatcher_releases_on_transport_error(
      mock_dispatcher_deps, mock_handle_cap,
  ) -> None:
      """transport.dispatch raises → release fires before re-raise."""
      mock_dispatcher_deps.transport.dispatch.side_effect = RuntimeError("boom")
      with pytest.raises(RuntimeError):
          await dispatch_web_fetch(..., handle_cap=mock_handle_cap)
      mock_handle_cap.release.assert_called()


  @pytest.mark.asyncio
  async def test_dispatcher_releases_on_typed_plugin_error(
      mock_dispatcher_deps, mock_handle_cap,
  ) -> None:
      """ControlResult with WebFetchSizeLimitExceeded → release fires."""
      from alfred.plugins.transport import ControlResult
      mock_dispatcher_deps.transport.dispatch.return_value = ControlResult(
          payload={"type": "WebFetchSizeLimitExceeded",
                   "size_bytes": 10_000_000, "limit_bytes": 5_000_000,
                   "message": "too big"},
      )
      with pytest.raises(WebFetchSizeLimitExceeded):
          await dispatch_web_fetch(..., handle_cap=mock_handle_cap)
      mock_handle_cap.release.assert_called()
  ```

- [ ] **Step 2: Run to confirm failure.**

- [ ] **Step 3: Implement.**

  In `fetch_dispatcher.py`, wrap the existing transport dispatch + result-handling in the early-release arms (the full try/finally lands in Task 18; for now just add `await handle_cap.release(...)` in the transport-error and typed-plugin-error arms BEFORE the existing audit rows + raises):

  ```python
  try:
      result = await transport.dispatch("web.fetch", {...})
  except Exception:
      await handle_cap.release(user_id=user_id, handle_id=handle_id)   # NEW
      # ... existing transport_error audit row ...
      raise

  if isinstance(result, ControlResult):
      await handle_cap.release(user_id=user_id, handle_id=handle_id)   # NEW
      # ... existing typed-error handling ...
  ```

- [ ] **Step 4: Run.**

- [ ] **Step 5: Commit.**

  ```bash
  git add src/alfred/plugins/web_fetch/fetch_dispatcher.py tests/unit/plugins/web_fetch/test_fetch_dispatcher.py
  git commit -m "feat(dispatcher): release HandleCap on transport + typed-plugin errors (#157)

  Adds release calls in the two existing error arms (raise-exception and
  ControlResult typed plugin error). The CancelledError-safe try/finally
  wrapper lands in Task 18.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 18 — Dispatcher CancelledError safety (try/finally + `asyncio.shield`)

**Owner:** alfred-security-engineer
**Files:**
- Modify: `src/alfred/plugins/web_fetch/fetch_dispatcher.py`
- Modify: `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py`

- [ ] **Step 1: Failing test.**

  ```python
  @pytest.mark.asyncio
  async def test_dispatcher_releases_on_cancellederror(
      mock_dispatcher_deps, mock_handle_cap,
  ) -> None:
      """asyncio.CancelledError mid-transport → release fires via finally arm.

      Python 3.12: CancelledError inherits from BaseException, NOT Exception.
      A bare `except Exception:` arm would miss it; this test pins the
      try/finally + asyncio.shield wrapper that catches all cases."""
      mock_dispatcher_deps.transport.dispatch.side_effect = asyncio.CancelledError()
      with pytest.raises(asyncio.CancelledError):
          await dispatch_web_fetch(..., handle_cap=mock_handle_cap)
      mock_handle_cap.release.assert_called()
  ```

- [ ] **Step 2: Run to confirm failure.**

- [ ] **Step 3: Implement.**

  Restructure the post-reserve block in `fetch_dispatcher.py`:

  ```python
  released = False
  try:
      try:
          result = await transport.dispatch("web.fetch", {...})
      except Exception:
          await handle_cap.release(user_id=user_id, handle_id=handle_id)
          released = True
          # ... existing transport_error audit row ...
          raise

      if isinstance(result, ControlResult):
          await handle_cap.release(user_id=user_id, handle_id=handle_id)
          released = True
          # ... existing typed-error handling ...

      # ... rest of success-path handling (Task 19 + 20 add equality check + HOLD) ...

  finally:
      if not released:
          # CancelledError catch-all. asyncio.shield ensures release fires
          # even under nested cancellation. suppress(Exception) so a release
          # error never masks the original raise.
          with contextlib.suppress(Exception):
              await asyncio.shield(
                  handle_cap.release(user_id=user_id, handle_id=handle_id),
              )
  ```

- [ ] **Step 4: Run.**

- [ ] **Step 5: Commit.**

  ```bash
  git add src/alfred/plugins/web_fetch/fetch_dispatcher.py tests/unit/plugins/web_fetch/test_fetch_dispatcher.py
  git commit -m "fix(dispatcher): CancelledError-safe release via try/finally + shield (#157)

  Python 3.12 CancelledError inherits from BaseException — bare `except
  Exception:` arms miss it. The try/finally + released-flag pattern
  guarantees release fires under any exit path including cancellation;
  asyncio.shield + suppress(Exception) ensures nested cancel cannot
  abort the release itself.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 19 — Dispatcher host-side handle_id equality check

**Owner:** alfred-security-engineer
**Files:**
- Modify: `src/alfred/plugins/web_fetch/fetch_dispatcher.py`
- Modify: `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py`

- [ ] **Step 1: Failing test.**

  ```python
  @pytest.mark.asyncio
  async def test_dispatcher_handle_id_mismatch_releases_and_audits(
      mock_dispatcher_deps, mock_handle_cap,
  ) -> None:
      """Plugin returns ContentHandle(id='wrong') ≠ pre-minted id.
      → WebFetchHandleIdMismatch raised; release fires; audit row carries
        dlp_scan_result='handle_id_mismatch'."""
      from alfred.security.quarantine import ContentHandle
      from datetime import datetime, UTC
      mock_dispatcher_deps.transport.dispatch.return_value = ContentHandle(
          id="wrong-uuid-from-plugin",
          source_url="https://example.com/",
          fetch_timestamp=datetime.now(tz=UTC),
      )
      with pytest.raises(WebFetchHandleIdMismatch):
          await dispatch_web_fetch(..., handle_cap=mock_handle_cap)
      mock_handle_cap.release.assert_called()
      audit_call = mock_dispatcher_deps.audit.append_schema.call_args_list[-1]
      assert audit_call.kwargs["subject"]["dlp_scan_result"] == "handle_id_mismatch"
  ```

- [ ] **Step 2: Run to confirm failure.**

- [ ] **Step 3: Implement.**

  In `fetch_dispatcher.py`, after the `ControlResult` branch and before the success-path audit-write, add:

  ```python
  # Host-side equality check (spec §3 defence-in-depth).
  if not isinstance(result, ContentHandle) or result.id != handle_id:
      await handle_cap.release(user_id=user_id, handle_id=handle_id)
      released = True
      await audit.append_schema(
          fields=WEB_FETCH_FIELDS,
          schema_name="WEB_FETCH_FIELDS",
          event="tool.web.fetch",
          actor_user_id=user_id,
          subject={
              "url": clean_url, "domain": domain,
              "status_code": None,
              "content_handle_id": handle_id,    # pre-minted id for forensics
              "fetch_depth": _FETCH_DEPTH,
              "rate_limit_bucket": None,
              "manifest_commit_hash": config.manifest_commit_hash,
              "trust_tier_of_result": "T0",
              "dlp_scan_result": "handle_id_mismatch",
              "canary_tripped": False,
              "triggering_user_id": user_id,
              "correlation_id": correlation_id,
          },
          trust_tier_of_trigger="T0",
          result="handle_id_mismatch",
          cost_estimate_usd=0.0,
          trace_id=correlation_id,
      )
      got_id = result.id if isinstance(result, ContentHandle) else "<not-a-ContentHandle>"
      raise WebFetchHandleIdMismatch(expected=handle_id, got=got_id)
  ```

  Also `from alfred.plugins.web_fetch.errors import WebFetchHandleIdMismatch` at the top.

- [ ] **Step 4: Run.**

- [ ] **Step 5: Commit.**

  ```bash
  git add src/alfred/plugins/web_fetch/fetch_dispatcher.py tests/unit/plugins/web_fetch/test_fetch_dispatcher.py
  git commit -m "feat(dispatcher): host-side handle_id equality check + handle_id_mismatch audit (#157)

  Defence-in-depth: a buggy or compromised plugin that writes the body under
  a different Redis key than the host pre-minted would silently desynchronise
  the cap counter from real Redis memory pressure. The host now verifies
  result.id == handle_id post-dispatch; mismatch triggers release + audit
  row + WebFetchHandleIdMismatch typed exception (spec §3).

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 20 — Dispatcher success-audit-failure HOLD behaviour

**Owner:** alfred-security-engineer
**Files:**
- Modify: `src/alfred/plugins/web_fetch/fetch_dispatcher.py`
- Modify: `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py`

This implements the disputed-#1 decision: HOLD the cap when the success-path audit write fails after a successful fetch.

- [ ] **Step 1: Failing test.**

  ```python
  @pytest.mark.asyncio
  async def test_dispatcher_holds_cap_on_success_audit_failure(
      mock_dispatcher_deps, mock_handle_cap, caplog: pytest.LogCaptureFixture,
  ) -> None:
      """Success path; audit.append_schema raises after fetch.

      Disputed-#1 decision: HOLD the cap until passive TTL. Body is in
      Redis; releasing would let user reset their cap while resource
      still occupied. LOUD structlog event so operator sees stuck reservation."""
      from alfred.security.quarantine import ContentHandle
      from datetime import datetime, UTC
      handle_id = "matching-id"
      mock_dispatcher_deps.transport.dispatch.return_value = ContentHandle(
          id=handle_id, source_url="https://example.com/",
          fetch_timestamp=datetime.now(tz=UTC),
      )
      # Patch uuid.uuid4 so handle_id is deterministic for this test.
      with patch("uuid.uuid4", return_value=type("U", (), {"__str__": lambda self: handle_id})()):
          # Make the success-path audit-write raise.
          original_append = mock_dispatcher_deps.audit.append_schema
          call_count = {"n": 0}
          async def flaky_append(*args, **kwargs):
              call_count["n"] += 1
              # First N-1 calls succeed (cap-refusal audits etc); the LAST
              # (success-path "result=ok") raises.
              if kwargs.get("result") == "ok":
                  raise RuntimeError("audit DB unavailable")
              return await original_append(*args, **kwargs)
          mock_dispatcher_deps.audit.append_schema = flaky_append

          with pytest.raises(RuntimeError, match="audit DB unavailable"):
              await dispatch_web_fetch(..., handle_cap=mock_handle_cap)

      # CRITICAL: release was NOT called (HOLD discipline).
      mock_handle_cap.release.assert_not_called()
      # LOUD structlog event fired.
      assert any(
          "handle_cap.success_audit_failed_holding_cap" in r.getMessage()
          for r in caplog.records
      )
  ```

- [ ] **Step 2: Run to confirm failure.**

- [ ] **Step 3: Implement.**

  In `fetch_dispatcher.py`, wrap the success-path audit write:

  ```python
  # Step 5: success audit row.
  success_subject: dict[str, object | None] = {
      "url": clean_url, "domain": domain,
      "status_code": 200,
      "content_handle_id": handle.id,
      "fetch_depth": _FETCH_DEPTH,
      "rate_limit_bucket": None,
      "manifest_commit_hash": config.manifest_commit_hash,
      "trust_tier_of_result": "T3",
      "dlp_scan_result": "clean",
      "canary_tripped": False,
      "triggering_user_id": user_id,
      "correlation_id": correlation_id,
  }
  try:
      await audit.append_schema(
          fields=WEB_FETCH_FIELDS,
          schema_name="WEB_FETCH_FIELDS",
          event="tool.web.fetch",
          actor_user_id=user_id,
          subject=success_subject,
          trust_tier_of_trigger="T0",
          result="ok",
          cost_estimate_usd=0.0,
          trace_id=correlation_id,
      )
  except Exception:
      # Disputed-#1 decision: HOLD the cap until passive TTL.
      # The body IS in Redis under handle_id consuming memory; releasing
      # would let the user reset their cap while the resource the cap is
      # meant to bound is still occupied. LOUD structlog event so operators
      # see the stuck reservation.
      log.error(
          "web_fetch.handle_cap.success_audit_failed_holding_cap",
          user_id=user_id, handle_id=handle_id,
          correlation_id=correlation_id,
          subject=success_subject,
          note="cap slot held until passive TTL (~80s); body in Redis",
      )
      # released stays False — finally arm will NOT release (we explicitly
      # set released=True here to BLOCK the finally arm's release call).
      released = True
      raise

  return handle
  ```

  Wait — actually if `released = True` blocks the finally arm, the cap IS held. But the test asserts `mock_handle_cap.release.assert_not_called()`. So setting `released = True` here means the finally arm's `if not released: release(...)` is skipped — good. The cap stays held; passive TTL frees it.

- [ ] **Step 4: Run.**

- [ ] **Step 5: Commit.**

  ```bash
  git add src/alfred/plugins/web_fetch/fetch_dispatcher.py tests/unit/plugins/web_fetch/test_fetch_dispatcher.py
  git commit -m "feat(dispatcher): HOLD cap on success-audit-write failure (#157)

  Disputed-#1 decision (spec §12). When the success-path audit row fails to
  write after a successful fetch+ContentHandle return, do NOT release the
  cap. The body IS in Redis consuming memory; releasing would let the user
  reset their cap while the resource it bounds is still occupied.

  LOUD web_fetch.handle_cap.success_audit_failed_holding_cap structlog event
  fires with the full would-be subject so an operator can correlate after
  the fact. Passive TTL within ~80s frees the slot.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Component F — Adversarial + docs + final QA

#### Task 21 — Adversarial payload YAML

**Owner:** alfred-test-engineer + alfred-security-engineer
**Files:**
- Create: `tests/adversarial/dlp_egress/handle_cap_exhaustion.yaml`

- [ ] **Step 1: Inspect the schema + a sibling YAML.**

  ```bash
  cat tests/adversarial/payload_schema.py | head -80
  cat tests/adversarial/dlp_egress/canary_token_html.yaml
  ```

- [ ] **Step 2: Author the payload.**

  Create `tests/adversarial/dlp_egress/handle_cap_exhaustion.yaml`:

  ```yaml
  id: handle_cap_exhaustion_2026_001
  name: per-user concurrent ContentHandle cap exhaustion
  category: dlp_egress
  attack_class: redis_memory_exhaustion
  spec_anchor: docs/superpowers/specs/2026-06-02-handle-cap-design.md#7-10
  description: |
    A single user attempts to exhaust Redis memory by issuing many
    concurrent web.fetch calls (each potentially returning up to the
    body-size limit). The per-user concurrent ContentHandle cap (5 by
    default) must refuse the 6th request and every subsequent request
    until existing handles drain via extract, canary trip, or passive
    TTL eviction.
  expected_outcome: audit_row_emitted
  expected_audit_row:
    event: tool.web.fetch
    rate_limit_bucket: handle_cap
    dlp_scan_result: handle_cap_exceeded
    result: rate_limited
  setup:
    cap_per_user: 5
    user_id: attacker-user-1
    allowed_domains:
      # 100 unique allowlisted endpoints so per-domain rate limit doesn't bind.
      - "endpoint-{i}.example.test"
  attack_steps:
    - issue 100 web.fetch calls in flight against unique endpoints
    - "expect: 5 fetches succeed; 95 refused with WebFetchRateLimited(bucket='handle_cap')"
    - "verify: Redis content keyspace bounded to 5 keys × max body size"
    - "verify: 95 audit rows with dlp_scan_result='handle_cap_exceeded'"
  ```

  Adapt field names + types to whatever `payload_schema.py:AdversarialPayload` actually requires — read the schema first and conform exactly.

- [ ] **Step 3: Run the adversarial corpus density test.**

  ```bash
  uv run pytest tests/adversarial/test_corpus_density.py -v
  ```

  Expected: green (new YAML loads cleanly against the schema).

- [ ] **Step 4: Commit.**

  ```bash
  git add tests/adversarial/dlp_egress/handle_cap_exhaustion.yaml
  git commit -m "test(adversarial): handle_cap_exhaustion payload (#157)

  AdversarialPayload-conformant YAML: single user issues 100 concurrent
  web.fetch calls across 100 unique allowlisted endpoints (bypassing per-
  domain rate limit). HandleCap default (per_user=5) must refuse 95 with
  WebFetchRateLimited(bucket='handle_cap') and emit 95 audit rows with
  dlp_scan_result='handle_cap_exceeded'. Redis content keyspace bounded
  to 5 × max-body-size.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 22 — Operator runbook + CHANGELOG + `docs/subsystems/security.md`

**Owner:** alfred-devex-reviewer + alfred-docs-author
**Files:**
- Create: `docs/runbooks/handle-cap-exceeded.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/subsystems/security.md`

- [ ] **Step 1: Create the runbook.**

  Create `docs/runbooks/handle-cap-exceeded.md`:

  ```markdown
  # Runbook: `handle_cap_exceeded` in the `tool.web.fetch` audit log

  > **Audit row signal:** `rate_limit_bucket="handle_cap"` + `dlp_scan_result="handle_cap_exceeded"` + `result="rate_limited"` on a `tool.web.fetch` event.

  ## What it means

  A user (`triggering_user_id`) issued a `web.fetch` call while already at
  the per-user concurrent ContentHandle cap. The cap bounds how many fetched
  response bodies the user can have alive in Redis at one moment — its purpose
  is to prevent one user from filling Redis with parked content.

  Default: 5 concurrent handles per user. Knob: `web_fetch.max_concurrent_handles_per_user` in `config/policies.yaml`.

  ## What it does NOT mean

  - **Not a security event.** A canary trip surfaces as `dlp_scan_result="canary_tripped"` — different.
  - **Not a per-minute rate limit.** That's `rate_limit_bucket="per_user"`.
  - **Not a malicious request indicator by itself.** A legitimate user with slow extracts can trip it.

  ## How to inspect

  1. **Audit log query** for a user's recent cap refusals:

     ```sql
     SELECT created_at, subject->'url' AS url, subject->'correlation_id' AS cid
     FROM audit_log
     WHERE event = 'tool.web.fetch'
       AND subject->>'rate_limit_bucket' = 'handle_cap'
       AND subject->>'triggering_user_id' = '<user_id>'
       AND created_at > now() - interval '1 hour'
     ORDER BY created_at DESC;
     ```

  2. **Live handle count** for a user (direct Redis):

     ```bash
     redis-cli ZCARD alfred:handles:user:<user_id>
     redis-cli ZRANGE alfred:handles:user:<user_id> 0 -1 WITHSCORES
     ```

     The members are handle IDs; scores are expiry epoch-ms. If
     `ZCARD = max_concurrent_handles_per_user`, the user is at cap.

  ## Common causes

  | Cause | Signal | Remediation |
  |---|---|---|
  | Legitimate burst (e.g., research agent in parallel-fetch mode) | Cap-refusals stop after extracts drain; ZCARD drops naturally | None — system is working as designed |
  | Stuck handles (extract path broken upstream) | ZCARD stays at cap, no decrement for >2× TTL | Investigate the extractor; passive TTL will free within ~80s × 2 |
  | Slow canary-quarantine I/O (delete failed) | `web_fetch.canary.quarantine_failed` structlog events | Investigate Redis health; cap slot held until passive TTL by design |
  | Success-path audit write failed | `web_fetch.handle_cap.success_audit_failed_holding_cap` structlog event | Investigate audit DB; cap slot held until passive TTL by design |
  | Cap too tight for workload | Continuous cap-refusals for a known-legitimate user | Raise `web_fetch.max_concurrent_handles_per_user` (no restart needed; mtime-polled) |

  ## How to override

  Edit `config/policies.yaml`:

  ```yaml
  web_fetch:
    max_concurrent_handles_per_user: 10   # was 5
  ```

  Save. The policies-loader picks up the change within ~1s (mtime polling).
  Existing live reservations are unaffected — the new cap applies to subsequent
  reserve attempts.

  **Refuses to load:** `max_concurrent_handles_per_user: 0` or negative. The
  policies-loader raises `ValueError` at startup; fix the value.

  ## Forensic correlation

  Every cap-refusal audit row carries `correlation_id` (links to the
  conversation turn) and `triggering_user_id`. The `content_handle_id` field
  is `None` on cap-refusal rows — the pre-minted UUID was never written to
  Redis (the refusal happens BEFORE the plugin call). The matching successful
  fetch (the one currently occupying the slot) is found via `triggering_user_id`
  and a recent `tool.web.fetch` row with `result='ok'`.

  ## Related runbooks

  - (TODO when filed) `docs/runbooks/canary-tripped.md`
  - `docs/runbooks/slice-3-operator-migration.md`
  ```

- [ ] **Step 2: Append to `CHANGELOG.md`.**

  Add under an `## Unreleased` section (or whatever the project convention is):

  ```markdown
  ## Unreleased

  ### Added

  - Per-user concurrent ContentHandle cap (slice-3 spec §7.10): refuses the
    6th in-flight `web.fetch` from a single user. Operator override via
    `web_fetch.max_concurrent_handles_per_user` in `policies.yaml` (default 5).
    Runbook: `docs/runbooks/handle-cap-exceeded.md`.

  ### Audit vocabulary

  - `WEB_FETCH_FIELDS["rate_limit_bucket"]` closed set widened from
    `{per_domain, per_user, daily_budget}` to also include `handle_cap`.
  - `WEB_FETCH_FIELDS["dlp_scan_result"]` closed set widened to include
    `handle_cap_exceeded` and `handle_id_mismatch`.
  - Both are now typed via `typing.Literal[...]` in `audit_row_schemas.py`
    so future emitter typos surface at type-check time.
  ```

- [ ] **Step 3: Cross-reference in `docs/subsystems/security.md`.**

  Find the section on slice-3 web.fetch defences and add a paragraph:

  ```markdown
  **Per-user concurrent ContentHandle cap (slice-3 spec §7.10).** A
  per-user Redis-backed counter (`HandleCap`) bounds how many `ContentHandle`
  instances a single user can have alive in Redis at one moment. Default 5;
  override via `web_fetch.max_concurrent_handles_per_user` in
  `policies.yaml`. Cap-refused fetches emit `tool.web.fetch` audit rows
  with `dlp_scan_result="handle_cap_exceeded"`. See
  [docs/runbooks/handle-cap-exceeded.md](../runbooks/handle-cap-exceeded.md)
  for the operator-facing runbook.
  ```

- [ ] **Step 4: Commit.**

  ```bash
  git add docs/runbooks/handle-cap-exceeded.md CHANGELOG.md docs/subsystems/security.md
  git commit -m "docs(handle-cap): operator runbook + CHANGELOG + security subsystem xref (#157)

  - docs/runbooks/handle-cap-exceeded.md: what the audit signal means,
    how to inspect, common causes + remediations, override knob.
  - CHANGELOG.md: 'Added' + 'Audit vocabulary' entries documenting the
    rate_limit_bucket + dlp_scan_result closed-set widening.
  - docs/subsystems/security.md: cross-reference HandleCap as a §7.10
    slice-3 defence.

  Refs: #157

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

#### Task 23 — Final QA + push + STOP for user check-in

**Owner:** alfred-security-engineer (final gate)
**Files:** none — gates only

- [ ] **Step 1: Run the full quality bar locally.**

  ```bash
  cd ~/projects/AlfredOS-worktrees/issue-157-handle-cap

  # Lint + format
  uv run ruff check . && uv run ruff format --check .

  # Type-check
  uv run mypy src/ && uv run pyright src/

  # Unit + property + integration tests (slow — testcontainers)
  uv run pytest tests/unit/plugins/web_fetch/ tests/unit/audit/ \
                tests/unit/plugins/test_web_fetch_plugin_handle_id_passthrough.py \
                tests/property/plugins/web_fetch/ -v

  # Coverage gate on HandleCap (trust-boundary 100% line+branch)
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py \
                --cov=src/alfred/plugins/web_fetch/handle_cap \
                --cov-branch --cov-fail-under=100

  # Adversarial corpus density
  uv run pytest tests/adversarial/test_corpus_density.py -v

  # i18n catalog drift (must be no diff)
  uv run pybabel extract -F babel.cfg -o locale/alfred.pot src/alfred/
  uv run pybabel update -i locale/alfred.pot -d locale/ --previous --no-fuzzy-matching
  uv run pybabel compile -d locale/ --check
  git diff --exit-code locale/   # must be clean

  # Final unified gate
  make check
  ```

  Expected: every step green. If any fails, fix in-branch (use `git commit --fixup=<sha> && git rebase -i --autosquash main` — NEVER write a "fix: apply X auto-fixes" generic commit per project memory).

- [ ] **Step 2: Pre-existing ruff failures.**

  Per project notes, **`scripts/check_strict_declarations.py` S603/S607 are RED on main from PR #129** — out of scope for this PR. If `ruff check` flags them, leave them alone. Confirm they're the only red items.

- [ ] **Step 3: Run /review-pr LOCALLY before push.**

  Per project memory (`feedback_local_review_before_push.md`), every push runs through local review first:

  ```
  /review-pr
  ```

  Address findings via the in-branch fixup-and-autosquash flow (`procedural_in_branch_fixes.md`). NEVER push generic "fix: review feedback" commits.

- [ ] **Step 4: Push the branch.**

  ```bash
  git push -u origin issue-157-handle-cap
  ```

- [ ] **Step 5: **STOP** and check in with the user before opening the PR.**

  Per the user's process notes:

  > "I have the new session stop before opening the PR so you can sanity-check the diff before the CR-cloud loop starts."

  Report to the user:
  - Branch pushed: `issue-157-handle-cap` (commit list summary).
  - Local quality bar status (all green / any pre-existing failures).
  - Local /review-pr summary.
  - Open question(s) for user decision: anything that came up during implementation and feels worth surfacing before the PR opens (e.g., if the hook-payload extension in Task 15 required a wider design touch, surface that).

  **Do NOT open the PR autonomously.** Wait for explicit user go-ahead.

---

## §7 Post-PR follow-ups (not in this PR's scope)

These are filed as separate issues once the PR opens; tracked here so they don't get lost:

1. **Canonical `ContentStore.extract` wire-up** — when the quarantined extractor migrates from in-process `_content_cache.pop` to Redis `ContentStore.extract`, the §5.1 release wiring lands. The current PR leaves the extract-success release contingent.
2. **CLI `alfred web handles --user <uid>`** — operator-side inspection of a user's live handle count. Deferred to Slice-4 web-CLI expansion.
3. **Prometheus `alfred_web_fetch_handle_cap_utilisation` metric** — deferred until the `ops/prometheus/` stack lands (none exists in repo today).
4. **`dlp_scan_result` field schema split** — existing `devex-002` note in `fetch_dispatcher.py` flags the overloaded field (genuine DLP outcomes + fetch-outcome tags). Separate audit-schema migration PR.

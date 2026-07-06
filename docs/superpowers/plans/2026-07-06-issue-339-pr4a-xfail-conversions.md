# #339 PR4a — Xfail Conversions (inbound canary + per-user handle_cap) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the two `xfail(strict=True)` merge-blocker stubs on epic #339 — the web.fetch **inbound-reflection canary** (`de-2026-012`, #347 blocker 5) and the **per-user handle_cap refusal** (`de-2026-004`, #347 blocker 1) — into real passing tests by wiring the two production seams they guard.

**Architecture:** Both blockers are "the mechanism exists but the production assembly does not pass the value." (1) `ResponsePolicy.canary` is built and consumed but `build_web_fetch_egress_extractor` passes `canary=None` because no core-side token source exists — we add a `Settings.web_fetch_canary_tokens` source and make the factory derive a non-`None` `CanaryMatcher` from it. (2) The `HandleCap` Lua-atomic per-user reserve/release class still ships fully on `main`; G7-2.5 removed only its *call site* — we re-thread it into `dispatch_web_fetch` as a reserve-before-network / release-on-every-exit-path bound. No new security mechanism is invented; both are wirings proven by tests (the "test is the proof, not a live caller" precedent — ADR-0041 — since #338 is the first live caller).

**Tech Stack:** Python 3.14+, Pydantic v2 `BaseSettings`, `redis.asyncio` (Lua EVALSHA), asyncio, pytest + `pytest.mark.asyncio` + testcontainers (Postgres 18 / Redis 8), the adversarial corpus harness (`tests/adversarial/`).

## Global Constraints

- **Language floor:** Python `>=3.14.6`. Modern idioms only — PEP 604 unions (`X | Y`), PEP 585 built-in generics, no `Optional[X]` / `typing.List`.
- **Typing:** `mypy --strict` + `pyright` clean. No unjustified `Any`. Frozen/immutable by default.
- **i18n (HARD):** every operator/user-facing string via `t()`. No new user-facing English literals outside the catalog. `pybabel extract`/`update`/`compile` must stay clean (see Task Z). The two refusal messages this PR relies on (`web.fetch.error.rate_limited.handle_cap`, `egress.inbound_canary_tripped`) already exist — no new catalog keys expected.
- **Security (HARD):** never stub the capability gate to "always allow" — use real `RealGate` fixtures (`tests/helpers/gates.py`). Every dispatch branch emits an audit row (rule #7). No silent failures in security paths.
- **Adversarial suite is release-blocking.** This PR edits two files under `tests/adversarial/` and touches trust-boundary-adjacent code (canary, per-user rate bound); run the FULL `uv run pytest tests/adversarial` locally before push (Task Z), and get explicit `alfred-security-engineer` sign-off on both converted corpus entries (#347 blockers 1 and 5 both require it).
- **Audit vocab is lockstep-pinned.** Any change to the `DlpScanResult` Literal MUST update `tests/unit/audit/test_audit_row_schemas.py::test_dlp_scan_result_literal_includes_new_values` in the same commit (exact-set equality).
- **New env var, not the gateway's.** The core inbound-canary source MUST use a *new* env var (`ALFRED_WEB_FETCH_CANARY_TOKENS`). `ALFRED_CANARY_TOKENS` is hard-forbidden on the core container by `tests/unit/test_compose_invariants.py` (that key is the gateway's outbound scanner).
- **No compose / daemon-boot wiring in this PR.** `build_tool_registry` has no production caller until #338; PR4a proves the wiring via integration tests only. Threading `handle_cap` into the live boot graph is #338's job.
- **Commits:** Conventional-commit subject with a literal `#339` in EVERY subject; type is lowercase-letters-only (`feat`/`fix`/`test`/`chore` — never `i18n` as a type). Never `--no-verify`. Non-admin merge only.

---

## File Structure

**Part A — inbound canary (blocker 5 / `de-2026-012`):**

- Modify `src/alfred/config/settings.py` — add `web_fetch_canary_tokens: tuple[str, ...]` field + a `mode="before"` comma-split normalizer.
- Modify `src/alfred/plugins/web_fetch/assembly.py` — add `_resolve_web_fetch_canary(settings)` (always non-`None` `CanaryMatcher`); make `build_web_fetch_egress_extractor` derive the canary from settings when the caller passes none; update the residual docstring.
- Modify `tests/adversarial/dlp_egress/test_de_egress_inbound_canary_unwired.py` — convert the xfail stub to a real in-process reflected-canary test.
- Modify `tests/adversarial/dlp_egress/de_egress_inbound_canary_unwired.yaml` — flip `deferred_property.merge_blocker` → `false`.
- Create `tests/integration/egress/test_web_fetch_canary_wiring.py` — the factory-wiring proof (settings token → factory → trip over a real loopback relay).
- Modify `tests/unit/config/test_settings.py` (or the nearest existing settings-unit file — confirm path in Task A1) — field-parsing unit tests.
- Modify `tests/unit/plugins/web_fetch/test_assembly.py` (or nearest existing assembly-unit file — confirm in Task A2) — `_resolve_web_fetch_canary` + factory-derivation unit tests.

**Part B — per-user handle_cap (blocker 1 / `de-2026-004`):**

- Modify `src/alfred/audit/audit_row_schemas.py` — re-add `handle_cap_exceeded` to the `DlpScanResult` Literal.
- Modify `tests/unit/audit/test_audit_row_schemas.py` — add `handle_cap_exceeded` to the lockstep set.
- Modify `src/alfred/plugins/web_fetch/constants.py` — add `_DEFAULT_HANDLE_RESERVATION_TTL_SECONDS`.
- Modify `src/alfred/plugins/web_fetch/fetch_dispatcher.py` — add `handle_cap: HandleCap` kwarg; Step 3b reserve-before-network + refusal audit; wrap Step 4+5 in `try/finally` release.
- Modify `src/alfred/orchestrator/builtin_tools.py` — thread `handle_cap` through `build_web_fetch_tool`.
- Modify `src/alfred/orchestrator/tool_assembly.py` — thread `handle_cap` through `build_tool_registry`.
- Modify `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py` — dispatcher reserve/release/refusal unit tests.
- Modify `tests/unit/orchestrator/test_builtin_tools.py` — three `build_web_fetch_tool(...)` calls (lines 65/90/125) gain `handle_cap=`; line-80 test gains the "forwards handle_cap" assertion (FIX-2).
- Modify `tests/adversarial/capability_bypass/test_cap_2026_006_tool_arg_injection.py` — the `build_web_fetch_tool(...)` call (line 163) gains `handle_cap=` (FIX-2; adversarial → security sign-off).
- Modify `tests/adversarial/dlp_egress/test_egress_no_orphan_and_inflight.py` — convert the `test_per_user_exhaustion_refusal_deferred_to_339` xfail to a real in-process refusal test.
- Modify `tests/adversarial/dlp_egress/egress_inflight_and_no_orphan.yaml` — flip `deferred_property.merge_blocker` → `false` + set `converted_in` (confirm the field path in Task B5).
- Create `tests/integration/egress/test_handle_cap_exhaustion.py` — Redis-backed per-user exhaustion atomicity proof.
- Modify `src/alfred/plugins/web_fetch/handle_cap.py` — reconcile the stale `transport_error`-arm docstring (lines 206-211) + `~80s` self-heal figures (216/399/431) → 120s (FIX-9, FIX-11). **Do NOT change `release()`'s `RedisError`-swallow (FIX-16).**
- Create `docs/adr/0047-web-fetch-handle-cap-reattach-and-inbound-canary.md` (or amend ADR-0041) — Task Y (FIX-4).

---

## Plan-review fixes (rev.2 — FOLD THESE FIRST; they OVERRIDE the task bodies below)

A 4-lens focused plan-review (security / test / error / cross-cutting) ran against rev.1. Security **withheld sign-off** pending FIX-1/FIX-3/FIX-5. Every implementer dispatch MUST apply the FIX items applicable to its task; where a FIX conflicts with a task body below, the FIX wins.

- **FIX-1 (HIGH, security — empirically proven boot-crash). Task A1 field is broken as written.** pydantic-settings 2.14.2 JSON-decodes a `tuple[str, ...]` env field in `EnvSettingsSource` **before** any `mode="before"` validator runs, so `ALFRED_WEB_FETCH_CANARY_TOKENS="a,b"` raises `SettingsError` (verified). Declare the field with `NoDecode` so the comma-split validator runs:

  ```python
  # add to imports:
  from typing import Annotated
  from pydantic_settings import NoDecode
  # field (replaces the rev.1 Task A1 Step 3 declaration):
  web_fetch_canary_tokens: Annotated[tuple[str, ...], NoDecode] = Field(default=())
  ```

  Keep the `_normalize_web_fetch_canary_tokens` `mode="before"` validator (it now executes). Do NOT use model-wide `enable_decoding=False` (breaks `comms_enabled_adapters`'s JSON-env contract). A1 Step 1 tests 2 & 3 only PASS with this fix (without it they ERROR).

- **FIX-2 (HIGH, cross-cutting + test — corroborated). Enumerate ALL `build_web_fetch_tool` callers in Task B4.** `handle_cap` is a REQUIRED kwarg (keep it required — an optional default is a fail-open footgun; it mirrors the required `rate_limiter`). Callers that break:
  - `tests/unit/orchestrator/test_builtin_tools.py:65, 90, 125` — add `handle_cap=_SpyHandleCap()`.
  - `tests/adversarial/capability_bypass/test_cap_2026_006_tool_arg_injection.py:163` — add `handle_cap=_SpyHandleCap()` (permissive; that test asserts a *domain* refusal that fires BEFORE the cap, so the cap must not itself refuse). This is an adversarial-suite edit → route past `alfred-security-engineer` sign-off.
  - Put B4 Step 1's "forwards handle_cap" assertion in `test_builtin_tools.py:80` (`test_web_fetch_adapter_threads_ctx_and_call_index`, which monkeypatches `dispatch_web_fetch` and checks `seen[...]`): `assert seen["handle_cap"] is spy`.
  - Fix Task Z Step 1's grep to also cover `build_web_fetch_tool(` and `dispatch_web_fetch(`, not only `build_tool_registry(`. B4 Step 4's "Expected: PASS" holds only AFTER these edits.

- **FIX-3 (HIGH, security + test — corroborated). Replace Task B5 Step 2's body wholesale.** The rev.1 sketch hangs/orphans tasks and mirrors the wrong double (`_GatedExtractor` exposes `.extract()`; `dispatch_web_fetch` calls `extractor.handle(...)`). Use this create-task / park / count / drain structure (deterministic + non-vacuous):

  ```python
  class _CappedHandleCap:
      """Fake per-user HandleCap: allows `cap` reserves, refuses the next (atomic)."""
      def __init__(self, *, cap: int) -> None:
          self._cap, self._live = cap, 0
      @property
      def live(self) -> int:
          return self._live
      async def try_reserve(self, *, user_id: str, handle_id: str, handle_ttl_seconds: int) -> None:
          if self._live >= self._cap:                 # no await before the check → atomic vs the loop
              raise WebFetchRateLimited("handle_cap")
          self._live += 1
      async def release(self, *, user_id: str, handle_id: str, correlation_id: str | None = None) -> None:
          self._live -= 1

  @pytest.mark.asyncio
  async def test_per_user_handle_cap_refuses_sixth_pre_network() -> None:
      """de-2026-004: the 6th concurrent web.fetch reserve for one user is refused
      pre-network. Five dispatches reserve then PARK holding the slot inside handle();
      the 6th's reserve refuses BEFORE its extractor is reached.
      alfred-security-engineer sign-off required (#347)."""
      cap = _CappedHandleCap(cap=5)
      gate = asyncio.Event()          # never set until drain → holds the 5 slots
      reached: list[str] = []         # one entry per slot genuinely held in handle()
      audit = _CapturingAuditWriter()

      def _ok_outcome() -> EgressExtractOutcome:
          return EgressExtractOutcome(
              result=Extracted(data=T3DerivedData({"payload": "ok"}), extraction_mode="native_constrained"),
              deduplicated=False, language="en", status=200)

      class _ParkingExtractor:            # EgressResponseExtractor double: .handle (NOT .extract)
          async def handle(self, *, ctx: Any, **_: Any) -> EgressExtractOutcome:
              reached.append(ctx.inbound_id)
              await gate.wait()           # park while HOLDING the reserved slot
              return _ok_outcome()

      class _MustNotFireExtractor:        # the 6th: reserve must refuse first
          async def handle(self, **_: Any) -> EgressExtractOutcome:
              raise AssertionError("6th web.fetch reached the network — handle_cap must refuse pre-network")

      config = FetchDispatchConfig(
          manifest_allowed_entries=(AllowlistEntry(domain="example.com"),),
          operator_allowed_entries=(AllowlistEntry(domain="example.com"),),
          session_allowed_entries=(AllowlistEntry(domain="example.com"),),
          manifest_commit_hash="de-2026-004")

      async def _permissive_rl(*, domain: str, user_id: str) -> None:  # only handle_cap refuses
          return None
      rate_limiter = SimpleNamespace(check_and_increment=_permissive_rl)

      def _dispatch(i: int, extractor: Any) -> Awaitable[EgressExtractOutcome]:
          return dispatch_web_fetch(
              url="https://example.com/page", headers={}, user_id="u-1", correlation_id=f"corr-{i}",
              egress_ctx=TurnEgressContext(adapter_id="ada-hc", inbound_id=f"in-{i}", session_id="sess-hc"),
              call_index=i, schema=_TestSchema, config=config,
              rate_limiter=rate_limiter, outbound_dlp=identity_outbound_dlp(),  # type: ignore[arg-type]
              audit=audit, extractor=extractor, handle_cap=cap)                 # type: ignore[arg-type]

      holders = [asyncio.create_task(_dispatch(i, _ParkingExtractor())) for i in range(5)]
      async with asyncio.timeout(5.0):            # loud fail if the reserve is never reached
          while len(reached) < 5:
              await asyncio.sleep(0)
      assert cap.live == 5, "all five per-user slots must be held before the 6th reserve"

      with pytest.raises(WebFetchRateLimited) as exc:
          await _dispatch(5, _MustNotFireExtractor())
      assert exc.value.bucket == "handle_cap"
      # Assert the refusal row BEFORE releasing — the parked 5 have not reached their
      # Step-5 success rows yet, so the last audit row is deterministically the 6th's.
      hc = [r for r in audit.rows if r["subject"].get("dlp_scan_result") == "handle_cap_exceeded"]
      assert len(hc) == 1
      assert hc[0]["subject"]["rate_limit_bucket"] == "handle_cap"
      assert hc[0]["result"] == "rate_limited"

      gate.set()                                  # release the 5 holders
      async with asyncio.timeout(5.0):
          await asyncio.gather(*holders)
      assert cap.live == 0, "every held slot must be released on the success finally-path"
  ```

  Confirm `EgressExtractOutcome` / `Extracted` / `T3DerivedData` / `AllowlistEntry` / `FetchDispatchConfig` constructor kwargs against `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py` and reuse that module's `_CapturingAuditWriter` / `identity_outbound_dlp` helpers; keep the file dependency-free (no Postgres/Redis). Add `SimpleNamespace`/`Awaitable` imports.

- **FIX-4 (HIGH, cross-cutting). PR4a reverses ADR-0041 Decision 2 — author an ADR (Task Y, below).** ADR-0041 Decision 2 (lines 56-59) states `HandleCap` is **detached** from `dispatch_web_fetch`; B3 re-attaches it. ADR-0041's residual (lines 117-122) says the inbound canary is deferred with `canary=None`; A1/A2 close it. ADRs are NOT human-gated (only `CLAUDE.md`/`PRD.md` are — self-improvement rule #4), so record the change. Frame the re-attach as a **re-purpose** (a per-user *concurrency* bound in the fused model — a different rationale than the parked-body bound Decision 2 detached), NOT a straight undo. Escalate the structural change to architect/user for sign-off at PR time.

- **FIX-5 (MED, security). Task A3 must also guard the WIRING, not only seam behavior.** The rev.1 A3 hand-builds `ResponsePolicy(canary=...)` directly and never calls `build_web_fetch_egress_extractor`, so a future re-introduction of `canary=None` in the factory would leave A3 green — the corpus entry stops guarding the merge-blocker's actual subject. Add to the converted `de-2026-012` entry a cheap inert-double factory assertion (mirror the current xfail's build at `test_de_egress_inbound_canary_unwired.py:139-167`):

  ```python
  from alfred.config.settings import Settings
  from alfred.plugins.web_fetch.assembly import build_web_fetch_egress_extractor
  assembled = build_web_fetch_egress_extractor(
      settings=Settings(egress_relay_url=_RELAY_URL, web_fetch_canary_tokens=(token,)),
      gate=Mock(name="gate"), extractor=Mock(name="extractor"), recorder=Mock(name="recorder"),
      outbound_dlp=Mock(name="outbound_dlp"), audit_writer=Mock(name="audit_writer"),
      session_scope=lambda: None,
  )
  assert assembled._response_policy.canary is not None
  assert assembled._response_policy.canary.first_match(token) == token
  ```

- **FIX-6 (MED, test). Add a canary NO-TRIP regression (A3 or A4 sub-case).** Armed matcher + benign body that does NOT contain a token → no `InboundCanaryTripped`, extractor reached, clean T2. CRITICAL detail: `inspect_response` runs canary FIRST, MIME SECOND — a no-trip test MUST set `Content-Type: text/html` on the response, else the missing-MIME soft-refusal short-circuits before the extractor and the `extract.assert_awaited_once()` becomes vacuous. Assert `mock_extractor.extract.assert_awaited_once()` and no exception.

- **FIX-7 (MED, test). Add two release-matrix branches to Task B3 tests:** (a) `extractor.handle` raises a generic `WebFetchError`/`RuntimeError` → `pytest.raises(...)` AND `released == [handle_id]` (the finally covers transport errors too); (b) an EARLY refusal (rate-limit or allowlist, which returns before Step 3b) leaves `reserved == []` AND `released == []` — pinning that the cap is only touched AFTER the rate-limit gate.

- **FIX-8 (MED, error). Harden the `finally`-release against a non-`RedisError` masking the propagating security exception.** `release()` swallows only `RedisError`; a non-`RedisError` escaping it (e.g. a `zrem` TypeError regression) would replace the in-flight `InboundCanaryTripped`/`TimeoutError`. Wrap the finally body:

  ```python
  finally:
      try:
          await handle_cap.release(user_id=user_id, handle_id=handle_id, correlation_id=correlation_id)
      except Exception:  # noqa: BLE001 — never let a release fault mask the real exception; CancelledError still propagates
          _log.error("web_fetch.handle_cap.release_unexpected", user_id=user_id, handle_id=handle_id)
  ```

  Catch `Exception` (NOT `BaseException`) so `CancelledError` propagates. Add a B3 test: a fake `release()` raising `RuntimeError` → the original `InboundCanaryTripped` still propagates. (`fetch_dispatcher.py` already has a module `_log`; if not, add `structlog.get_logger(__name__)`.)

- **FIX-9 (MED, error + security LOW-4). Reserve-transport failure stays un-audited at the dispatcher BY DESIGN — reconcile the stale contract, do NOT add a redundant arm.** Step 3b catching only `WebFetchRateLimited` matches the adjacent Step 3 rate-limiter; a `RedisError`/`ValueError`/`RuntimeError` from `try_reserve` is caught loud one layer up by `dispatch_tool`'s `except Exception → unexpected_error/fault` (`tool_dispatch.py:224-233`) — NOT a HARD-#7 regression, so no new dispatcher audit arm (security's call; a second arm would double-audit). Instead: (a) add a one-line comment in Step 3b noting the outer totality; (b) rewrite `handle_cap.py:206-211` — it still promises "the dispatcher's `transport_error` audit arm fires", but `transport_error` was removed from `DlpScanResult` at the G7-2.5 re-home. State reserve faults propagate and are audited by the `dispatch_tool` chokepoint.

- **FIX-10 (MED, cross-cutting). Task B3 must rewrite the `fetch_dispatcher.py` module docstring.** Lines 19-22 ("ADR-0041 records ... the `HandleCap` removal") and 32-35 (residual: "the per-user fairness bound ... land there too") go stale on B3. Rewrite to say HandleCap is re-attached as a per-user concurrency bound and the fairness bound lands in PR4a — but PRESERVE the "broker secret-injection for authenticated fetch" deferral clause (that is PR4b, NOT PR4a; do not over-claim broker auth).

- **FIX-11 (LOW, error + security). TTL doc drift.** Keep `_DEFAULT_HANDLE_RESERVATION_TTL_SECONDS = 120`; update the `~80s` self-heal figures in `handle_cap.py` (docstring lines 216, 399, 431) to `~120s`.

- **FIX-12 (LOW, cross-cutting). Both YAMLs keep `deferred_to: "PR #339"` after the flip.** In `de_egress_inbound_canary_unwired.yaml` and `egress_inflight_and_no_orphan.yaml`, alongside `merge_blocker: false` add `converted_in: "PR #339 PR4a"` (and null/relax `deferred_to`) so the corpus record is accurate.

- **FIX-13 (LOW, cross-cutting). Task B4's "updated in Task B6/Task Z" cross-ref is wrong** — the caller fixups live only in Task Z; B6 touches no `build_tool_registry` caller. Drop the B6 reference.

- **FIX-14 (LOW, security). Use a per-field settings test file.** Task A1's tests go in a NEW `tests/unit/config/test_settings_web_fetch_canary_tokens.py` (matches the `test_settings_egress_relay_url.py` convention), not appended to `test_settings.py`.

- **FIX-15 (LOW, test — confirmations to bake in).** Both "confirm-the-path" fallbacks are moot: `tests/unit/config/test_settings.py` and `tests/unit/plugins/web_fetch/test_assembly.py` both EXIST — A2 appends to `test_assembly.py` (A1 uses the new per-field file per FIX-14). Add a one-line comment in A3/A4 that `headers={}` on the reflecting relay is intentional (canary precedes MIME). `test_audit_log_result_domain_closed` needs NO change (Step 3b emits the literal `result="rate_limited"`, off the dynamic-site pin list); only `test_audit_row_schemas` changes (Task B1).

- **FIX-16 (LOW, security). Do NOT "improve" `HandleCap.release()` to propagate** — the `try/finally` safety depends on its `RedisError`-swallow (handle_cap.py:416-434). Leave it.

---

## Part A — Inbound-reflection canary (blocker 5)

### Task A1: `Settings.web_fetch_canary_tokens` core-side token source

**Files:**
- Modify: `src/alfred/config/settings.py` (field near `redis_url` line 120; validator near the `_normalize_egress_relay_url` block line 380-393)
- Test: `tests/unit/config/test_settings.py` (confirm the exact settings unit-test path first — `ls tests/unit/config/`; if none, create `tests/unit/config/test_settings_canary_tokens.py`)

**Interfaces:**
- Produces: `Settings.web_fetch_canary_tokens: tuple[str, ...]` (default `()`), env `ALFRED_WEB_FETCH_CANARY_TOKENS` parsed as a comma-separated list (blanks skipped). Consumed by Task A2's `_resolve_web_fetch_canary`.

- [ ] **Step 1: Write the failing test**

Add to the settings unit tests:

```python
def test_web_fetch_canary_tokens_defaults_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.delenv("ALFRED_WEB_FETCH_CANARY_TOKENS", raising=False)
    assert Settings().web_fetch_canary_tokens == ()


def test_web_fetch_canary_tokens_comma_split_skips_blanks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_WEB_FETCH_CANARY_TOKENS", " tok-a , ,tok-b, ")
    assert Settings().web_fetch_canary_tokens == ("tok-a", "tok-b")


def test_web_fetch_canary_tokens_blank_env_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_WEB_FETCH_CANARY_TOKENS", "   ")
    assert Settings().web_fetch_canary_tokens == ()


def test_web_fetch_canary_tokens_direct_tuple_passthrough(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    assert Settings(web_fetch_canary_tokens=("x", "y")).web_fetch_canary_tokens == ("x", "y")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/config/test_settings.py -k web_fetch_canary_tokens -v`
Expected: FAIL (`Settings` has no `web_fetch_canary_tokens` attribute / validation error on the kwarg).

- [ ] **Step 3: Add the field + normalizer**

In `src/alfred/config/settings.py`, add the field beside `redis_url` (after line 120):

```python
    # #339 PR4a (blocker 5, #347): the core-side INBOUND-reflection canary token
    # source for web.fetch. The gateway runs the OUTBOUND exfil scan from
    # ALFRED_CANARY_TOKENS; this is the DISTINCT core env for the inbound tripwire
    # (a seeded canary reflected in a fetched RESPONSE body). A NEW env name —
    # ALFRED_CANARY_TOKENS is hard-forbidden on the core container
    # (tests/unit/test_compose_invariants.py). Default () arms the ResponsePolicy
    # canary seam with an empty (no-op) matcher; operators populate it to enable
    # the reflection tripwire. Override via ALFRED_WEB_FETCH_CANARY_TOKENS
    # (comma-separated, blanks skipped — mirrors the gateway token format).
    web_fetch_canary_tokens: tuple[str, ...] = Field(default=())
```

Add the normalizer beside `_normalize_egress_relay_url` (after line 393):

```python
    @field_validator("web_fetch_canary_tokens", mode="before")
    @classmethod
    def _normalize_web_fetch_canary_tokens(cls, value: object) -> object:
        """Parse ALFRED_WEB_FETCH_CANARY_TOKENS as a comma-separated token list.

        Mirrors the gateway's ``resolve_canary_tokens`` split (comma-separated,
        blanks skipped) so operators use ONE token format across the core inbound
        source and the gateway outbound scanner. Without this a plain-string env
        would be JSON-parsed by pydantic-settings for a ``tuple[str, ...]`` field
        and reject a bare comma list. Blank/whitespace → ``()`` (seam armed but
        empty = no-op matcher). A tuple/list (direct construction) passes through.
        """
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/config/test_settings.py -k web_fetch_canary_tokens -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/config/settings.py tests/unit/config/test_settings.py
git commit -m "feat(config): add ALFRED_WEB_FETCH_CANARY_TOKENS core-side canary source (#339 PR4a)"
```

---

### Task A2: Factory derives a non-`None` `CanaryMatcher` from settings

**Files:**
- Modify: `src/alfred/plugins/web_fetch/assembly.py` (imports; new `_resolve_web_fetch_canary`; the `response_policy` build at lines 174-183; the docstring residual block lines 130-153, 177-181)
- Test: `tests/unit/plugins/web_fetch/test_assembly.py` (confirm the exact path — `ls tests/unit/plugins/web_fetch/`; if none, create `tests/unit/plugins/web_fetch/test_assembly_canary.py`)

**Interfaces:**
- Consumes: `Settings.web_fetch_canary_tokens` (Task A1); `CanaryMatcher` / `CanaryToken` from `alfred.security.canary_matcher`.
- Produces: `build_web_fetch_egress_extractor(...)` now yields an `EgressResponseExtractor` whose `_response_policy.canary` is ALWAYS non-`None` (empty no-op matcher when no tokens; populated when tokens set). `_resolve_web_fetch_canary(settings) -> CanaryMatcher` is a module function.

- [ ] **Step 1: Write the failing test**

`CanaryMatcher(*, tokens: Sequence[CanaryToken])` with `CanaryToken(value)` (rejects blanks); `first_match(text) -> str | None` (see `src/alfred/security/canary_matcher.py`).

```python
import pytest
from unittest.mock import Mock
from typing import Any

from alfred.config.settings import Settings
from alfred.plugins.web_fetch.assembly import (
    _resolve_web_fetch_canary,
    build_web_fetch_egress_extractor,
)

_RELAY_URL = "tcp://127.0.0.1:8890"


def _s(monkeypatch: pytest.MonkeyPatch, *, tokens: tuple[str, ...] = ()) -> Settings:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    return Settings(egress_relay_url=_RELAY_URL, web_fetch_canary_tokens=tokens)


def test_resolve_web_fetch_canary_empty_is_non_none_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    matcher = _resolve_web_fetch_canary(_s(monkeypatch))
    assert matcher is not None
    assert matcher.first_match("anything at all") is None


def test_resolve_web_fetch_canary_matches_seeded_token(monkeypatch: pytest.MonkeyPatch) -> None:
    matcher = _resolve_web_fetch_canary(_s(monkeypatch, tokens=("SEED-9",)))
    assert matcher.first_match("body contains SEED-9 reflected") == "SEED-9"


def _collab() -> dict[str, Any]:
    return {
        "gate": Mock(name="gate"),
        "extractor": Mock(name="extractor"),
        "recorder": Mock(name="recorder"),
        "outbound_dlp": Mock(name="outbound_dlp"),
        "audit_writer": Mock(name="audit_writer"),
        "session_scope": lambda: None,
    }


def test_factory_derives_non_none_canary_when_none_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _collab()
    assembled = build_web_fetch_egress_extractor(
        settings=_s(monkeypatch, tokens=("SEED-9",)),
        gate=c["gate"], extractor=c["extractor"], recorder=c["recorder"],
        outbound_dlp=c["outbound_dlp"], audit_writer=c["audit_writer"],
        session_scope=c["session_scope"],
    )
    policy = assembled._response_policy
    assert policy is not None
    assert policy.canary is not None
    assert policy.canary.first_match("SEED-9") == "SEED-9"


def test_factory_explicit_canary_overrides_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    from alfred.security.canary_matcher import CanaryMatcher, CanaryToken

    override = CanaryMatcher(tokens=[CanaryToken("OVERRIDE-1")])
    c = _collab()
    assembled = build_web_fetch_egress_extractor(
        settings=_s(monkeypatch, tokens=("SEED-9",)),
        gate=c["gate"], extractor=c["extractor"], recorder=c["recorder"],
        outbound_dlp=c["outbound_dlp"], audit_writer=c["audit_writer"],
        session_scope=c["session_scope"], canary=override,
    )
    assert assembled._response_policy.canary is override
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/plugins/web_fetch/test_assembly.py -k canary -v`
Expected: FAIL (`_resolve_web_fetch_canary` does not exist; the factory still yields `policy.canary is None`).

- [ ] **Step 3: Implement**

In `src/alfred/plugins/web_fetch/assembly.py`, change the `CanaryMatcher` import from `TYPE_CHECKING` to a runtime import and add `CanaryToken`:

```python
from alfred.security.canary_matcher import CanaryMatcher, CanaryToken
```

(remove `from alfred.security.canary_matcher import CanaryMatcher` from the `TYPE_CHECKING` block at line 58.)

Add the resolver above `build_web_fetch_egress_extractor`:

```python
def _resolve_web_fetch_canary(settings: Settings) -> CanaryMatcher:
    """Build the web.fetch INBOUND-reflection canary matcher from settings.

    The core-side counterpart to the gateway's ``resolve_canary_tokens`` (#339
    blocker 5 / #347). ALWAYS returns a NON-``None`` matcher: an empty token list
    yields a no-op matcher (``first_match`` always ``None``) so the
    ``ResponsePolicy`` canary seam is uniformly ARMED — populated when the operator
    sets ``ALFRED_WEB_FETCH_CANARY_TOKENS``, a no-op otherwise. Never ``None`` —
    that was the pre-#339 unwired state the ``de-2026-012`` merge-blocker enforces
    against.
    """
    return CanaryMatcher(
        tokens=[CanaryToken(token) for token in settings.web_fetch_canary_tokens]
    )
```

Note: `Settings` is imported under `TYPE_CHECKING` at line 56 — the resolver's annotation resolves there; no runtime `Settings` import needed (the factory receives `settings` as a value).

In `build_web_fetch_egress_extractor`, replace the `response_policy` build (lines 174-183) with:

```python
    # #339 PR4a (blocker 5, #347): the inbound-reflection canary seam is now
    # ALWAYS armed. When the caller passes an explicit ``canary`` (e.g. a test),
    # honour it; otherwise derive the matcher from the core-side token source
    # (``ALFRED_WEB_FETCH_CANARY_TOKENS``) — non-``None`` even with zero tokens
    # (a no-op matcher). This closes the ``de-2026-012`` strict-xfail merge-blocker:
    # ``policy.canary`` is never ``None`` for a factory-built extractor.
    resolved_canary = canary if canary is not None else _resolve_web_fetch_canary(settings)
    response_policy = ResponsePolicy(
        mime_allowlist=_WEB_FETCH_MIME_ALLOWLIST,
        max_bytes=_WEB_FETCH_RESPONSE_MAX_BYTES,
        canary=resolved_canary,
    )
```

Update the docstring: change the `canary` arg description (lines 130-132) and the "Residual (tracked, #339)" block (lines 145-153) to state the seam is now wired from `settings.web_fetch_canary_tokens` and that an explicit `canary` overrides. Keep it factual and concise.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/plugins/web_fetch/test_assembly.py -k canary -v`
Expected: PASS.

- [ ] **Step 5: Verify no regression in `build_tool_registry` (canary auto-threads)**

Run: `uv run pytest tests/integration/orchestrator/test_tool_assembly.py -v` (if Docker available) OR at minimum `uv run pytest tests/unit/plugins/web_fetch tests/unit/orchestrator -q`.
Expected: PASS — `build_tool_registry` already forwards `settings`, so the canary now auto-threads with no signature change there.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/plugins/web_fetch/assembly.py tests/unit/plugins/web_fetch/test_assembly.py
git commit -m "feat(web-fetch): derive inbound canary from settings; arm the ResponsePolicy seam (#339 PR4a)"
```

---

### Task A3: Convert the `de-2026-012` xfail → in-process reflected-canary test

**Files:**
- Modify: `tests/adversarial/dlp_egress/test_de_egress_inbound_canary_unwired.py` (the xfail stub `test_inbound_canary_unwired_deferred_to_339`, lines 76-167)
- Modify: `tests/adversarial/dlp_egress/de_egress_inbound_canary_unwired.yaml` (`payload.deferred_property.merge_blocker`)

**Interfaces:**
- Consumes: `EgressResponseExtractor`, `ResponsePolicy`, `CanaryMatcher`/`CanaryToken`, the `_StubRelayClient` / `_StubLedger` in-process double pattern from `test_egress_no_orphan_and_inflight.py`, `make_quarantined_extract_chain_gate`, `T3BodyRecorder`/`QuarantineStagingMap`, `authorized_t3_nonce`.

Background (read before writing): the pre-extract seam in `EgressResponseExtractor.handle` runs `inspect_response` on the fetched body when `_response_policy is not None`; a `_CanaryHit` records a terminal `TypedRefusal(reason="refused_by_safety")` to the ledger, then raises `InboundCanaryTripped` — the quarantined extractor is NEVER awaited (canary is pre-extract). Corpus token to reuse: `ALFRED-CANARY-TEST-TOKEN-8675309` (already in the YAML at line 48).

- [ ] **Step 1: Verify the xfail now XPASSES (must be converted)**

Run: `uv run pytest "tests/adversarial/dlp_egress/test_de_egress_inbound_canary_unwired.py::test_inbound_canary_unwired_deferred_to_339" -v`
Expected: **FAIL** with `[XPASS(strict)]` — because Task A2 made `policy.canary` non-`None`, the `strict=True` XPASS is now a hard failure. This is the mechanical forcing-function; converting the test is mandatory.

- [ ] **Step 2: Replace the xfail stub with a real reflected-canary test**

Delete the `@pytest.mark.xfail(...)` decorator and replace the function body. The new test builds an `EgressResponseExtractor` directly with a canary-armed `ResponsePolicy` and a stub relay whose upstream body reflects the seeded token (mirror the `_StubRelayClient` / `_StubLedger` pattern already in `test_egress_no_orphan_and_inflight.py` lines 105-140; set the stub relay's `fire()` to return a body containing the token):

```python
@pytest.mark.asyncio
async def test_inbound_canary_reflected_response_trips(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A seeded canary token reflected in the fetched RESPONSE trips InboundCanaryTripped.

    Converts the de-2026-012 merge-blocker (#347 blocker 5): #339 PR4a wires a
    non-None ResponsePolicy.canary (from ALFRED_WEB_FETCH_CANARY_TOKENS via
    build_web_fetch_egress_extractor). Here we exercise the pre-extract seam
    directly with a stub relay returning a canary-bearing body and assert:

      * handle() raises InboundCanaryTripped (loud, HARD rule #7),
      * the quarantined extractor is NEVER awaited (canary is pre-extract, HARD #5),
      * a terminal refused_by_safety refusal was recorded to the ledger.

    CLAUDE.md security rule #7: a canary trip is loud, never fail-open.
    """
    from unittest.mock import AsyncMock

    from alfred.egress.egress_response_extract import EgressResponseExtractor
    from alfred.egress.relay_client import Fired
    from alfred.egress.relay_protocol import EgressResponse, _RawToolRequest
    from alfred.egress.response_inspection import InboundCanaryTripped, ResponsePolicy
    from alfred.security.canary_matcher import CanaryMatcher, CanaryToken

    token = "ALFRED-CANARY-TEST-TOKEN-8675309"

    class _ReflectingRelay:
        def __init__(self, ledger: _StubLedger) -> None:
            self._ledger = ledger

        @property
        def ledger(self) -> _StubLedger:
            return self._ledger

        async def fire(self, **_kwargs: Any) -> Fired:
            body = f"upstream page reflecting {token} back".encode()
            return Fired(response=EgressResponse(status=200, headers={}, body=body))

    ledger = _StubLedger()
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True, dereference_plugin_id="alfred.quarantined-llm"
    )
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock()  # must NOT be reached (canary is pre-extract)

    policy = ResponsePolicy(
        mime_allowlist=frozenset({"text/html", "text/plain"}),
        max_bytes=5 * 1024 * 1024,
        canary=CanaryMatcher(tokens=[CanaryToken(token)]),
    )
    extractor_obj = EgressResponseExtractor(
        relay_client=_ReflectingRelay(ledger),  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,
        recorder=recorder,
        response_policy=policy,
    )
    raw_req = _RawToolRequest(
        method="GET", url="https://example.com/", headers={}, body="", idempotent=True
    )

    with pytest.raises(InboundCanaryTripped):
        await extractor_obj.handle(
            raw_request=raw_req, ctx=_CTX_A, call_index=_CALL_INDEX,
            schema=_TestSchema, language="en",
        )

    # Pre-extract: the quarantined child never dereferenced the T3 body.
    mock_extractor.extract.assert_not_awaited()
    # The terminal refusal was recorded (refused_by_safety) — not fail-open.
    assert ledger.record_calls, "canary trip must record a terminal ledger refusal"
    assert "refused_by_safety" in ledger.record_calls[-1]["response"]
    # No orphaned T3 body.
    assert len(staging._staged) == 0
```

Import `CapabilityGateNonce`, `QuarantineStagingMap`, `T3BodyRecorder`, `_StubLedger`, `_TestSchema`, `_CTX_A`, `_CALL_INDEX`, `make_quarantined_extract_chain_gate`, `authorized_t3_nonce` as needed — reuse the exact doubles already defined in `test_egress_no_orphan_and_inflight.py` (copy `_StubLedger` into this module or import it; prefer a small local `_StubLedger` to keep the two adversarial files independent). Confirm `EgressResponse` field names against `src/alfred/egress/relay_protocol.py` before running.

Keep `test_payload_schema_valid` but update its `deferred_property` assertions (Step 4).

- [ ] **Step 3: Run the converted test**

Run: `uv run pytest "tests/adversarial/dlp_egress/test_de_egress_inbound_canary_unwired.py" -v`
Expected: PASS (no XFAIL/XPASS markers remain on the reflected-canary test).

- [ ] **Step 4: Flip the YAML merge-blocker + fix the schema-validation test**

In `de_egress_inbound_canary_unwired.yaml`, set `payload.deferred_property.merge_blocker: false`. Update `test_payload_schema_valid` so it asserts `deferred.get("merge_blocker") is False` (and drop/relax the `deferred_to == "PR #339"` assertion if it no longer reflects a pending obligation — reword to record it as CONVERTED).

Run: `uv run pytest "tests/adversarial/dlp_egress/test_de_egress_inbound_canary_unwired.py" -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add tests/adversarial/dlp_egress/test_de_egress_inbound_canary_unwired.py tests/adversarial/dlp_egress/de_egress_inbound_canary_unwired.yaml
git commit -m "test(adversarial): convert de-2026-012 xfail to real reflected-canary test (#339 PR4a)"
```

---

### Task A4: Factory-wiring integration proof (settings token → real relay → trip)

**Files:**
- Create: `tests/integration/egress/test_web_fetch_canary_wiring.py`

**Interfaces:**
- Consumes: `build_web_fetch_egress_extractor` (Task A2), the loopback-relay harness pattern from `tests/integration/egress/test_web_fetch_assembly.py` (boot at lines 129-159; `_query_row` at 105-116; `_settings` at 99-103), the `fake_external_world` fixture + its mutable `canned` body holder, `migrated_url`, `authorized_t3_nonce`.

Rationale: Task A3 proves the canary-scan *behaviour* with a hand-built policy; A4 proves the *production wiring* — that a token in `Settings.web_fetch_canary_tokens` reaches the factory-built `ResponsePolicy.canary` and trips over a real loopback relay + real Postgres ledger. This is the "test is the proof" closure for the settings→factory path (#338 wires the live caller).

- [ ] **Step 1: Write the test**

Mirror `test_web_fetch_assembly.py::test_assembled_extractor_completes_fetch_extract_reusing_graph` (boot the loopback `EgressRelay`, reuse `migrated_url` + `authorized_t3_nonce` + `fake_external_world`) with these differences: build `Settings(egress_relay_url=..., web_fetch_canary_tokens=("ALFRED-CANARY-TEST-TOKEN-8675309",))`; set `canned.body` to a body containing that token BEFORE dispatch; assert `handle(...)` raises `InboundCanaryTripped`; assert the ledger row for `compute_egress_id(ctx, call_index=0)` is `state == "committed_with_response"` with `"refused_by_safety"` in `response`; assert `mock_extractor.extract.assert_not_awaited()` and `fire_counter.value == 1`.

```python
@pytest.mark.asyncio
async def test_factory_canary_from_settings_trips_over_real_relay(
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    monkeypatch: pytest.MonkeyPatch,
    fake_external_world: tuple[Any, Any, Any],
) -> None:
    open_client_factory, fire_counter, canned = fake_external_world
    token = "ALFRED-CANARY-TEST-TOKEN-8675309"
    canned.body = f"upstream reflecting {token}".encode()

    # ... boot loopback EgressRelay exactly as test_web_fetch_assembly.py lines 130-159 ...

    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True, dereference_plugin_id="alfred.quarantined-llm"
    )
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock()  # pre-extract canary → never reached

    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    settings = Settings(
        egress_relay_url=f"tcp://127.0.0.1:{port}",
        web_fetch_canary_tokens=(token,),
    )
    try:
        assembled = build_web_fetch_egress_extractor(
            settings=settings, gate=gate, extractor=mock_extractor, recorder=recorder,
            outbound_dlp=identity_outbound_dlp(), audit_writer=_NullAuditWriter(),  # type: ignore[arg-type]
            session_scope=lambda: session_scope(factory),
        )
        assert assembled._response_policy.canary is not None
        ctx = TurnEgressContext(adapter_id="ada-cn", inbound_id="in-cn", session_id="sess-cn")
        raw_request = _RawToolRequest(method="GET", url=_FAKE_URL, headers={}, body="", idempotent=True)
        with pytest.raises(InboundCanaryTripped):
            await assembled.handle(raw_request=raw_request, ctx=ctx, call_index=0,
                                   schema=_TestSchema, language="en")
        mock_extractor.extract.assert_not_awaited()
        assert fire_counter.value == 1
        egress_id = compute_egress_id(ctx, call_index=0)
        row = await _query_row(migrated_url, egress_id)
        assert row is not None and row["state"] == "committed_with_response"
        assert "refused_by_safety" in row["response"]
    finally:
        # ... relay + engine teardown exactly as test_web_fetch_assembly.py lines 234-241 ...
```

Copy the imports, `_FAKE_*` constants, `_TestSchema`, `migrated_url` / `authorized_t3_nonce` / `_shutdown_default_executor` fixtures, `_query_row`, and boot/teardown boilerplate verbatim from `test_web_fetch_assembly.py`. Add `from alfred.egress.response_inspection import InboundCanaryTripped`. Confirm the `fake_external_world` fixture is available to `tests/integration/egress/` (it is used by `test_web_fetch_assembly.py`).

- [ ] **Step 2: Run (requires Docker)**

Run: `uv run pytest tests/integration/egress/test_web_fetch_canary_wiring.py -v`
Expected: PASS (Postgres + loopback relay; a `TimeoutError`/skip means the container did not come up — investigate, do not xfail).

- [ ] **Step 3: Commit**

```bash
git add tests/integration/egress/test_web_fetch_canary_wiring.py
git commit -m "test(egress): prove settings-derived web.fetch canary trips over real relay (#339 PR4a)"
```

---

## Part B — Per-user handle_cap refusal (blocker 1)

### Task B1: Re-add `handle_cap_exceeded` to the audit vocab

**Files:**
- Modify: `src/alfred/audit/audit_row_schemas.py` (`DlpScanResult` Literal, lines 50-70)
- Modify: `tests/unit/audit/test_audit_row_schemas.py` (`test_dlp_scan_result_literal_includes_new_values`, the set at lines 375-392)

**Interfaces:**
- Produces: `"handle_cap_exceeded"` is a legal `DlpScanResult` token again (Task B3's Step 3b refusal audit uses it). `RateLimitBucket` already includes `"handle_cap"` (line 44) — no change there.

- [ ] **Step 1: Write the failing test**

Add `"handle_cap_exceeded"` to the expected set in `test_dlp_scan_result_literal_includes_new_values` (line 375-392), with a comment:

```python
        "size_limit_exceeded",  # NEW per G7-2.5
        "handle_cap_exceeded",  # RE-ADDED #339 PR4a — per-user concurrency refusal
```

Update the test docstring's "removed" list (lines 361-366) to drop `handle_cap_exceeded` from the removed family and note it was re-added by #339 PR4a.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest "tests/unit/audit/test_audit_row_schemas.py::test_dlp_scan_result_literal_includes_new_values" -v`
Expected: FAIL — the test's expected set now contains `handle_cap_exceeded` but `DlpScanResult` does not.

- [ ] **Step 3: Add the token to the schema**

In `src/alfred/audit/audit_row_schemas.py`, add to the `DlpScanResult` Literal (after `size_limit_exceeded`, line 58):

```python
    "handle_cap_exceeded",  # RE-ADDED #339 PR4a — per-user concurrent-fetch refusal (spec §7.10)
```

Update the Literal's docstring (lines 73-84) to remove `handle_cap_exceeded` from the "removed" list and note its #339 re-addition.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest "tests/unit/audit/test_audit_row_schemas.py" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/audit/audit_row_schemas.py tests/unit/audit/test_audit_row_schemas.py
git commit -m "feat(audit): re-add handle_cap_exceeded dlp_scan_result token (#339 PR4a)"
```

---

### Task B2: Reservation-TTL backstop constant

**Files:**
- Modify: `src/alfred/plugins/web_fetch/constants.py`

**Interfaces:**
- Produces: `_DEFAULT_HANDLE_RESERVATION_TTL_SECONDS: Final[int]` — the ZSET member self-heal TTL Task B3 passes to `HandleCap.try_reserve`.

- [ ] **Step 1: Add the constant + export**

In `src/alfred/plugins/web_fetch/constants.py`, after `_DEFAULT_ACTION_DEADLINE_SECONDS` (line 24):

```python
# #339 PR4a (blocker 1 / #347): the per-user concurrency-reservation self-heal TTL.
# G7-2.5 fused fetch+extract, so a reservation is held only for one dispatch —
# bounded by ``_DEFAULT_ACTION_DEADLINE_SECONDS`` (30s). The dispatcher releases the
# slot in a ``finally`` on every exit path; this TTL is a BACKSTOP so a leaked slot
# (a release() that no-ops on a Redis transient) self-frees via passive ZREMRANGEBYSCORE
# eviction. Comfortably above the action deadline so a slow-but-live fetch is never
# evicted mid-flight while still counting.
_DEFAULT_HANDLE_RESERVATION_TTL_SECONDS: Final[int] = 120
```

Update `__all__` to include `"_DEFAULT_HANDLE_RESERVATION_TTL_SECONDS"`.

- [ ] **Step 2: Verify import**

Run: `uv run python -c "from alfred.plugins.web_fetch.constants import _DEFAULT_HANDLE_RESERVATION_TTL_SECONDS as t; print(t)"`
Expected: `120`.

- [ ] **Step 3: Commit**

```bash
git add src/alfred/plugins/web_fetch/constants.py
git commit -m "feat(web-fetch): add handle-cap reservation TTL backstop constant (#339 PR4a)"
```

---

### Task B3: Reinstate the per-user reserve/release in `dispatch_web_fetch`

**Files:**
- Modify: `src/alfred/plugins/web_fetch/fetch_dispatcher.py` (imports; signature line 182-197; Step 3b insert after line 395; wrap Step 4+5 lines 397-520 in `try/finally`)
- Test: `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py`

**Interfaces:**
- Consumes: `HandleCap` (`alfred.plugins.web_fetch.handle_cap`), `_DEFAULT_HANDLE_RESERVATION_TTL_SECONDS` (Task B2), `handle_cap_exceeded` (Task B1).
- Produces: `dispatch_web_fetch(..., handle_cap: HandleCap, ...)` — reserves a per-user slot before the network fire and releases it on every exit path. On `WebFetchRateLimited("handle_cap")` from `try_reserve`, emits a `WEB_FETCH_FIELDS` audit row (`rate_limit_bucket="handle_cap"`, `dlp_scan_result="handle_cap_exceeded"`, `result="rate_limited"`) then re-raises pre-network.

- [ ] **Step 1: Write the failing tests**

Model on the existing dispatcher tests (fakes for `rate_limiter`, `outbound_dlp`, `audit`, `extractor`). Add a fake HandleCap spy:

```python
class _SpyHandleCap:
    def __init__(self, *, raise_on_reserve: bool = False) -> None:
        self.reserved: list[str] = []
        self.released: list[str] = []
        self._raise = raise_on_reserve

    async def try_reserve(self, *, user_id: str, handle_id: str, handle_ttl_seconds: int) -> None:
        if self._raise:
            from alfred.plugins.web_fetch.errors import WebFetchRateLimited
            raise WebFetchRateLimited("handle_cap")
        self.reserved.append(handle_id)

    async def release(self, *, user_id: str, handle_id: str, correlation_id: str | None = None) -> None:
        self.released.append(handle_id)
```

Tests (all `@pytest.mark.asyncio`), driving `dispatch_web_fetch(...)` with the SAME collaborators the existing happy-path dispatcher test uses, plus `handle_cap=`:

1. `test_reserve_before_network_and_release_on_success` — a `_SpyHandleCap()` + an extractor spy that records the order of `[reserve, fire]`; assert `handle_cap.reserved == [handle_id]` BEFORE the extractor fired, and `handle_cap.released == [handle_id]` after. (Use a fire-order recorder: have the fake extractor append `"fire"` to a shared list in `handle()`, and assert the spy's reserve happened first — e.g. capture `len(spy.reserved) == 1` inside the fake extractor.)
2. `test_release_on_soft_refusal` — extractor returns a `TypedRefusal` outcome; assert `released == [handle_id]`.
3. `test_release_on_canary_trip` — extractor raises `InboundCanaryTripped`; assert `pytest.raises(InboundCanaryTripped)` AND `released == [handle_id]`.
4. `test_release_on_timeout` — extractor sleeps past a tiny `action_deadline_seconds=0.01`; assert `pytest.raises(TimeoutError)` AND `released == [handle_id]`.
5. `test_handle_cap_exceeded_refuses_pre_network_with_audit` — `_SpyHandleCap(raise_on_reserve=True)` + a fire-spy extractor that RAISES if called; assert `pytest.raises(WebFetchRateLimited)`, the extractor was NOT awaited, and the audit spy captured exactly one row whose subject has `dlp_scan_result == "handle_cap_exceeded"`, `rate_limit_bucket == "handle_cap"`, `result == "rate_limited"`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/plugins/web_fetch/test_fetch_dispatcher.py -k "handle_cap or reserve or release" -v`
Expected: FAIL (`dispatch_web_fetch` has no `handle_cap` kwarg).

- [ ] **Step 3: Implement**

Add imports to `fetch_dispatcher.py`:

```python
import uuid
```

Extend the `constants` import (line 78) and add a `TYPE_CHECKING` import for `HandleCap`:

```python
from alfred.plugins.web_fetch.constants import (
    _DEFAULT_ACTION_DEADLINE_SECONDS,
    _DEFAULT_HANDLE_RESERVATION_TTL_SECONDS,
)
```

In the `TYPE_CHECKING` block (line 87-95) add:

```python
    from alfred.plugins.web_fetch.handle_cap import HandleCap
```

Add the parameter to the signature (after `rate_limiter: RateLimiter,`, line 192):

```python
    handle_cap: HandleCap,
```

Add the `Raises:` docstring line for the pre-network `handle_cap` refusal alongside the existing `WebFetchRateLimited` line (it already documents the bucket).

Insert **Step 3b** immediately after Step 3's rate-limit block (after line 395, before the `# Step 4:` comment at line 397):

```python
    # Step 3b: reserve one per-user concurrency slot BEFORE the network fire
    # (#339 PR4a blocker 1 / #347; spec §7.10). G7-2.5 removed the ContentHandle
    # cap when web.fetch fused fetch+extract; #339 reinstates it as a pure per-user
    # concurrency bound — the T3 body now stages in-memory transiently (not a Redis
    # ContentHandle), so ``handle_id`` is a synthetic ZSET member and the old
    # host-side handle_id-equality check is gone. The slot is released in the
    # ``finally`` below on EVERY Step-4/5 exit path (success, soft refusal, canary,
    # timeout, transport error) so a refusal cannot leak it.
    handle_id = str(uuid.uuid4())
    try:
        await handle_cap.try_reserve(
            user_id=user_id,
            handle_id=handle_id,
            handle_ttl_seconds=_DEFAULT_HANDLE_RESERVATION_TTL_SECONDS,
        )
    except WebFetchRateLimited as e:
        await audit.append_schema(
            fields=WEB_FETCH_FIELDS,
            schema_name="WEB_FETCH_FIELDS",
            event="tool.web.fetch",
            actor_user_id=user_id,
            subject={
                "url": clean_url,
                "domain": domain,
                "status_code": None,
                "content_handle_id": None,
                "fetch_depth": _FETCH_DEPTH,
                "rate_limit_bucket": e.bucket,  # "handle_cap"
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
```

Wrap Step 4 + Step 5 (lines 397-520) in a `try/finally`. The existing body from `raw_request = _RawToolRequest(...)` through `return outcome` becomes the `try` body (re-indent one level); add:

```python
    try:
        # Step 4: build the relay request ... (existing body, re-indented)
        # ...
        # Step 5: success / soft-refusal audit row ... (existing body, re-indented)
        # ...
        return outcome
    finally:
        # Release the per-user slot on EVERY exit path (#339 PR4a). release() is
        # idempotent and fails loud-but-quiet on a Redis transient (structlog only —
        # the slot self-frees via passive TTL). The reserve at Step 3b is OUTSIDE
        # this try, so a reserve-refusal path never reaches release (nothing held).
        await handle_cap.release(
            user_id=user_id, handle_id=handle_id, correlation_id=correlation_id
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/plugins/web_fetch/test_fetch_dispatcher.py -v`
Expected: PASS (new tests + existing ones must still pass — every existing dispatcher test call now needs a `handle_cap=` arg; update the shared dispatcher-call helper/fixture in that test module to pass a default `_SpyHandleCap()`).

- [ ] **Step 5: Typecheck**

Run: `uv run mypy src/alfred/plugins/web_fetch/fetch_dispatcher.py && uv run pyright src/alfred/plugins/web_fetch/fetch_dispatcher.py`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/plugins/web_fetch/fetch_dispatcher.py tests/unit/plugins/web_fetch/test_fetch_dispatcher.py
git commit -m "feat(web-fetch): reinstate per-user handle_cap reserve/release in dispatch (#339 PR4a)"
```

---

### Task B4: Thread `handle_cap` through the assembly

**Files:**
- Modify: `src/alfred/orchestrator/builtin_tools.py` (`build_web_fetch_tool`, lines 68-108; imports)
- Modify: `src/alfred/orchestrator/tool_assembly.py` (`build_tool_registry`, lines 66-130; imports)
- Test: extend the existing unit tests for `build_web_fetch_tool` / `build_tool_registry` (find them: `grep -rl build_web_fetch_tool tests/unit`)

**Interfaces:**
- Consumes: `HandleCap`, Task B3's `dispatch_web_fetch(handle_cap=...)`.
- Produces: `build_web_fetch_tool(..., handle_cap: HandleCap, ...)` forwards to `dispatch_web_fetch`; `build_tool_registry(..., handle_cap: HandleCap, ...)` forwards to `build_web_fetch_tool` (mirrors the existing `rate_limiter` parameter exactly).

- [ ] **Step 1: Write the failing test**

Add a unit test asserting the `web.fetch` tool's dispatch forwards the injected `handle_cap`. Simplest: build the registry with a `_SpyHandleCap` and a fake extractor/rate-limiter, invoke the `web.fetch` spec's `dispatch(ToolInvocation(...))`, assert `spy_handle_cap.reserved` grew (reserve happened) OR assert `build_tool_registry(handle_cap=...)` accepts the kwarg and constructs without error (contract test). A focused contract test:

```python
def test_build_tool_registry_accepts_handle_cap(...) -> None:
    reg = build_tool_registry(
        settings=..., gate=..., extractor=..., recorder=..., outbound_dlp=...,
        audit_writer=..., session_scope=..., rate_limiter=..., config=...,
        handle_cap=_SpyHandleCap(),
    )
    assert {t.name for t in reg.definitions_specs()} == {"web.fetch", "clock.now"}
```

(Confirm the registry's introspection accessor name; if none, assert `reg` is a `ToolRegistry` and the web.fetch spec is present.)

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/orchestrator -k "tool_registry or web_fetch_tool" -v`
Expected: FAIL (`build_tool_registry` / `build_web_fetch_tool` reject the `handle_cap` kwarg).

- [ ] **Step 3: Implement**

In `builtin_tools.py`: add `HandleCap` to the `TYPE_CHECKING` import block, add `handle_cap: HandleCap,` to `build_web_fetch_tool`'s keyword params (after `rate_limiter`), and pass `handle_cap=handle_cap` in the `dispatch_web_fetch(...)` call (after `rate_limiter=rate_limiter,`).

In `tool_assembly.py`: add `HandleCap` to the `TYPE_CHECKING` import block, add `handle_cap: HandleCap,` to `build_tool_registry`'s params (after `rate_limiter: RateLimiter,`), document it in the docstring (mirror the `rate_limiter` entry), and pass `handle_cap=handle_cap` into the `build_web_fetch_tool(...)` call.

- [ ] **Step 4: Run to verify it passes + full unit sweep of the touched dirs**

Run: `uv run pytest tests/unit/orchestrator tests/unit/plugins/web_fetch -q`
Expected: PASS. (Existing `build_tool_registry` integration callers — `test_tool_assembly.py`, `test_act_loop_real_chain.py` — will now need a `handle_cap=` arg; those are integration tests, updated in Task B6/Task Z.)

- [ ] **Step 5: Commit**

```bash
git add src/alfred/orchestrator/builtin_tools.py src/alfred/orchestrator/tool_assembly.py tests/unit/orchestrator
git commit -m "feat(orchestrator): thread handle_cap through build_tool_registry/web_fetch_tool (#339 PR4a)"
```

---

### Task B5: Convert the `de-2026-004` per-user-exhaustion xfail → real in-process refusal test

**Files:**
- Modify: `tests/adversarial/dlp_egress/test_egress_no_orphan_and_inflight.py` (`test_per_user_exhaustion_refusal_deferred_to_339`, lines 453-513)
- Modify: `tests/adversarial/dlp_egress/egress_inflight_and_no_orphan.yaml` (`deferred_property.merge_blocker`; confirm the exact key path with `grep -n merge_blocker` on the file)

**Interfaces:**
- Consumes: `dispatch_web_fetch` (Task B3), a fake HandleCap (the xfail docstring sanctions "a real OR fake Redis handle-cap"), a fire-spy extractor that raises if called, `WebFetchRateLimited`, `WEB_FETCH_FIELDS` audit tokens.

Rationale: this adversarial file is deliberately dependency-free (no Postgres/Docker — see its module docstring). Keep it so: prove the *refusal path* deterministically with a fake HandleCap that refuses the Nth reserve; the Redis-atomicity proof lives in Task B6 (integration). Both are release-blocking; both need `alfred-security-engineer` sign-off.

- [ ] **Step 1: Confirm the xfail still fails (raises today)**

Run: `uv run pytest "tests/adversarial/dlp_egress/test_egress_no_orphan_and_inflight.py::test_per_user_exhaustion_refusal_deferred_to_339" -v`
Expected: XFAIL (the body raises `AssertionError` today; still xfail because the property is not yet wired — Task B3 wires it but this stub does not exercise it).

- [ ] **Step 2: Replace the stub with a real refusal test**

Delete the `@pytest.mark.xfail(...)` decorator and replace the body with a test that drives the REAL `dispatch_web_fetch` against a fake HandleCap configured to allow 5 reserves then refuse the 6th, and a fire-spy `EgressResponseExtractor` double that raises if `handle()` is called on the refused call (proving pre-network). Assert the 6th call raises `WebFetchRateLimited("handle_cap")` and the audit spy row carries `dlp_scan_result="handle_cap_exceeded"`, `rate_limit_bucket="handle_cap"`, `result="rate_limited"`. Reuse the existing `identity_outbound_dlp` + a capturing audit writer + a permissive `RateLimiter` fake (only handle_cap should refuse) — model the collaborator set on Task B3's unit tests, and the fire-spy-that-raises pattern on `cap-2026-006`'s `_RelayNeverFiresExtractor` (`tests/adversarial/capability_bypass/test_cap_2026_006_tool_arg_injection.py:106-122`).

```python
@pytest.mark.asyncio
async def test_per_user_handle_cap_refuses_sixth_pre_network() -> None:
    """The 6th concurrent web.fetch reserve for one user is refused pre-network.

    Converts the de-2026-004 merge-blocker (#347 blocker 1). #339 PR4a reinstates
    the per-user HandleCap reserve in dispatch_web_fetch. A fake HandleCap allows
    5 reserves then refuses; a fire-spy extractor raises if reached — proving the
    refusal is pre-network — and the audit row carries the handle_cap tokens.

    alfred-security-engineer sign-off required (#347).
    """
    # cap-5 fake: 6th reserve raises WebFetchRateLimited("handle_cap")
    class _CappedHandleCap:
        def __init__(self, cap: int) -> None:
            self._cap, self._live = cap, 0
        async def try_reserve(self, *, user_id: str, handle_id: str, handle_ttl_seconds: int) -> None:
            if self._live >= self._cap:
                raise WebFetchRateLimited("handle_cap")
            self._live += 1
        async def release(self, *, user_id: str, handle_id: str, correlation_id: str | None = None) -> None:
            self._live -= 1
    # ... build config + capturing audit + identity DLP + permissive rate limiter +
    #     a fire-spy extractor that RAISES on handle(); issue 6 sequential dispatch_web_fetch
    #     calls WITHOUT releasing (hold the fire-spy so slots stay held), assert the 6th
    #     raises WebFetchRateLimited and the last audit row has the handle_cap tokens.
```

(Because `dispatch_web_fetch` releases in `finally`, to keep 5 slots "held" for the 6th refusal in an in-process sequential test, make the fire-spy extractor `handle()` await an `asyncio.Event` that the test never sets for the first 5, and run all 6 via `asyncio.gather` — mirror the in-flight-liveness gating already in this file (`_GatedExtractor`, lines 157-188). The 6th's reserve refuses before its `handle()` runs.)

Keep `test_payload_schema_valid`; update its `deferred_property.merge_blocker` assertion to `is False`.

- [ ] **Step 3: Run the converted test + the whole file**

Run: `uv run pytest "tests/adversarial/dlp_egress/test_egress_no_orphan_and_inflight.py" -v`
Expected: PASS (all tests; no XFAIL/XPASS markers on the converted test).

- [ ] **Step 4: Flip the YAML merge-blocker**

Set `deferred_property.merge_blocker: false` in `egress_inflight_and_no_orphan.yaml`.

Run: `uv run pytest "tests/adversarial/dlp_egress/test_egress_no_orphan_and_inflight.py::test_payload_schema_valid" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/adversarial/dlp_egress/test_egress_no_orphan_and_inflight.py tests/adversarial/dlp_egress/egress_inflight_and_no_orphan.yaml
git commit -m "test(adversarial): convert de-2026-004 xfail to real per-user handle_cap refusal (#339 PR4a)"
```

---

### Task B6: Redis-backed per-user exhaustion atomicity proof

**Files:**
- Create: `tests/integration/egress/test_handle_cap_exhaustion.py`

**Interfaces:**
- Consumes: the real `HandleCap(redis_url=...)` (`alfred.plugins.web_fetch.handle_cap`), the `redis_url` testcontainers fixture pattern (`tests/integration/orchestrator/conftest.py:76-79` — `RedisContainer("redis:8-alpine")`).

Rationale: Task B5 proves the dispatcher's refusal path with a fake cap; B6 proves the REAL Lua-atomic per-user bound holds under concurrency against a live Redis 8 — the property the fake cannot prove (that 5 concurrent `try_reserve` succeed and the 6th is refused atomically, and `release` frees a slot).

- [ ] **Step 1: Write the test**

```python
"""Integration: the real Redis-backed HandleCap per-user concurrency bound.

Proves the Lua-atomic reserve/release the #339 PR4a dispatch path relies on:
5 concurrent reserves for one user succeed; the 6th is refused with
WebFetchRateLimited(bucket='handle_cap'); a release frees exactly one slot.
"""
from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest
from testcontainers.redis import RedisContainer

from alfred.plugins.web_fetch.errors import WebFetchRateLimited
from alfred.plugins.web_fetch.handle_cap import HandleCap, HandleCapConfig

pytestmark = pytest.mark.integration


@pytest.fixture
def redis_url() -> Iterator[str]:
    with RedisContainer("redis:8-alpine") as r:
        yield f"redis://{r.get_container_host_ip()}:{r.get_exposed_port(6379)}"


@pytest.mark.asyncio
async def test_sixth_reserve_refused_then_release_frees_a_slot(redis_url: str) -> None:
    cap = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=5))
    try:
        ids = [f"h-{i}" for i in range(5)]
        await asyncio.gather(*[
            cap.try_reserve(user_id="u-1", handle_id=h, handle_ttl_seconds=120) for h in ids
        ])
        # 6th is refused atomically.
        with pytest.raises(WebFetchRateLimited) as exc:
            await cap.try_reserve(user_id="u-1", handle_id="h-6", handle_ttl_seconds=120)
        assert exc.value.bucket == "handle_cap"
        # A different user is unaffected (per-user, not global).
        await cap.try_reserve(user_id="u-2", handle_id="h-a", handle_ttl_seconds=120)
        # Releasing one of u-1's slots frees exactly one — the retry now succeeds.
        await cap.release(user_id="u-1", handle_id=ids[0])
        await cap.try_reserve(user_id="u-1", handle_id="h-6", handle_ttl_seconds=120)
    finally:
        await cap.aclose()
```

- [ ] **Step 2: Run (requires Docker)**

Run: `uv run pytest tests/integration/egress/test_handle_cap_exhaustion.py -v`
Expected: PASS. (A `TimeoutError`/skip means the Redis container did not start — investigate; do not xfail.)

- [ ] **Step 3: Commit**

```bash
git add tests/integration/egress/test_handle_cap_exhaustion.py
git commit -m "test(egress): Redis-backed per-user handle_cap exhaustion atomicity (#339 PR4a)"
```

---

## Task Y: ADR — record the ADR-0041 reversal (FIX-4)

**Files:**
- Create: `docs/adr/0047-web-fetch-handle-cap-reattach-and-inbound-canary.md` (or, if the maintainer prefers, a dated factual amendment appended to `docs/adr/0041-web-fetch-fused-fetch-extract-contract.md` — decide at PR time with the architect).

**Interfaces:** none (documentation of a structural-invariant change). ADRs are NOT human-gated (only `CLAUDE.md`/`PRD.md` are — self-improvement rule #4), so authoring this is in-remit; but the structural change itself wants architect/user sign-off at PR time.

- [ ] **Step 1: Write the ADR**

Record two coupled decisions, both landed by #339 PR4a:
1. **`HandleCap` is re-attached to `dispatch_web_fetch`** — this REVERSES ADR-0041 Decision 2 (lines 56-59: "HandleCap is detached ... no longer reserved or released by `dispatch_web_fetch`"). Frame it as a **re-purpose, not a straight undo**: the reserve is now a pure per-user *concurrency* bound in the fused fetch+extract model (the T3 body stages in-memory transiently, not as a Redis ContentHandle), whereas Decision 2 detached a *parked-body* handle bound. Context: #347 blocker 1 restored per-user fairness (the `alfred-security-engineer` D3 dissent was reconciled by G7-2.5's zero-exposure window, not by solving the property; PR4a solves it). Consequence: `handle_id` is a synthetic ZSET member; the old host-side handle_id-equality / `WebFetchHandleIdMismatch` check does not return.
2. **The inbound-reflection canary residual (ADR-0041 lines 117-122) is closed** — the core-side `ALFRED_WEB_FETCH_CANARY_TOKENS` source + `_resolve_web_fetch_canary` make `ResponsePolicy.canary` non-`None` from the factory; the gateway keeps its distinct outbound scanner (`ALFRED_CANARY_TOKENS`).

Cross-reference #339, #347 (blockers 1 & 5), and the two converted corpus entries (`de-2026-004`, `de-2026-012`). Run `markdownlint-cli2` on the new file before committing (MD031/MD032 around fences/lists; no line may start with `#NNN`).

- [ ] **Step 2: Add a dated factual amendment note to ADR-0041**

At the top of `docs/adr/0041-...md`, add a dated (`2026-07-06`) one-line note that Decision 2 and the inbound-canary residual are superseded by ADR-0047 (#339 PR4a) — the ADR-0015/0016-amendment precedent (factual amendments are in-remit; status flips stay with the maintainer).

- [ ] **Step 3: Commit**

```bash
git add docs/adr/0047-web-fetch-handle-cap-reattach-and-inbound-canary.md docs/adr/0041-web-fetch-fused-fetch-extract-contract.md
git commit -m "docs(adr): ADR-0047 handle_cap re-attach + inbound canary; amend ADR-0041 (#339 PR4a)"
```

---

## Task Z: Full verification, i18n drift, integration-caller fixups, docs

**Files:**
- Modify: `tests/integration/orchestrator/test_tool_assembly.py`, `tests/integration/orchestrator/test_act_loop_real_chain.py` (add the `handle_cap=` arg to their `build_tool_registry(...)` calls — construct a real `HandleCap(redis_url=redis_url)` from the existing `redis_url` fixture, or a permissive fake if those tests don't exercise the cap)
- Modify: `docs/subsystems/security.md` and/or `docs/subsystems/comms.md` — a factual note that the web.fetch inbound canary + per-user handle_cap are wired (not a status flip; keep human-gated docs untouched — CLAUDE.md/PRD/ADR status changes are human-gated)

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Fix the `build_tool_registry` integration callers**

`grep -rn "build_tool_registry(" tests/` — every caller now needs `handle_cap=`. In `test_tool_assembly.py` and `test_act_loop_real_chain.py`, add `handle_cap=HandleCap(redis_url=redis_url)` (both already take the `redis_url` fixture). Add `await handle_cap.aclose()` in teardown if constructing a real one.

Run: `uv run pytest tests/integration/orchestrator -v` (Docker)
Expected: PASS.

- [ ] **Step 2: i18n drift check**

The two refusal keys already exist (`web.fetch.error.rate_limited.handle_cap`, `egress.inbound_canary_tripped`) — no new catalog entries expected. Confirm no drift from line-shifting edits:

```bash
uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
uv run pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching
uv run pybabel compile -d locale -D alfred --statistics
git diff --stat locale/
```

If `#:` location refs shifted, commit the regenerated catalog. NEVER `--omit-header`. Check `$?` directly (do not pipe to `tail`).

- [ ] **Step 3: Full local quality gates**

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy src/ && uv run pyright src/
uv run pytest tests/unit -q
```
Expected: all clean. (Full `tests/unit` — the audit AST/lockstep guards and any tree-wide assertion on the `DlpScanResult` shape only surface in the full unit run, not a scoped subset.)

- [ ] **Step 4: Adversarial suite (release-blocking — two corpus entries converted)**

```bash
uv run pytest tests/adversarial -q
```
Expected: PASS, with the two converted entries now green (no XFAIL/XPASS). If Docker-gated integration adversarial entries skip locally, note it and rely on CI.

- [ ] **Step 5: `make check`**

```bash
make check; echo "exit=$?"
```
Expected: `exit=0`. (macOS integration lane can be flaky under load — verify any suspect in isolation, trust Linux CI.)

- [ ] **Step 6: Docs note + commit**

Add the factual wiring note to `docs/subsystems/security.md` (the T3-output / egress-canary subsection). Do NOT edit CLAUDE.md / PRD / ADR status (human-gated).

```bash
git add tests/integration/orchestrator docs/subsystems/security.md locale/
git commit -m "test(egress): thread handle_cap into integration callers; wiring docs + i18n (#339 PR4a)"
```

---

## Self-Review

**Spec coverage (against #347 blockers 1 & 5 + the two xfails):**
- Blocker 5 / `de-2026-012` canary: core-side token source (A1) → factory derivation (A2) → xfail conversion (A3) → wiring proof (A4). ✔
- Blocker 1 / `de-2026-004` handle_cap: audit token (B1) → TTL constant (B2) → dispatcher reserve/release (B3) → assembly threading (B4) → xfail conversion (B5) → Redis atomicity proof (B6). ✔
- Both YAML `merge_blocker` flags flipped (A3, B5). ✔
- Adversarial suite run + security sign-off called out (Global Constraints, Task Z, A3/B5). ✔

**Placeholder scan:** integration-test boot/teardown is referenced to exact existing line ranges (`test_web_fetch_assembly.py`) rather than re-transcribed — the implementer copies verbatim; this is a "repeat the harness" instruction, not a `TODO`. All source changes carry complete code. Two unit-test file paths (A1, A2) and one YAML key path (B5) are marked "confirm the exact path first" — the implementer verifies with the given `ls`/`grep` before writing.

**Type consistency:** `handle_cap: HandleCap` param name is identical across `dispatch_web_fetch` (B3), `build_web_fetch_tool` (B4), `build_tool_registry` (B4). `_resolve_web_fetch_canary(settings) -> CanaryMatcher` and `Settings.web_fetch_canary_tokens: tuple[str, ...]` are consistent A1↔A2. `handle_cap_exceeded` token identical across B1 (schema), B3 (emit), B5 (assert).

**Open risks flagged for plan-review:**
1. The B5 in-process "hold 5 slots then refuse the 6th" needs the `asyncio.gather` + gated-extractor structure (a sequential loop would release each slot in `finally` before the next reserves). Called out inline.
2. The reservation TTL (120s) is a judgement value — plan-review/security should sanity-check it against the 30s action deadline.
3. A4 asserts `"refused_by_safety" in row["response"]` — confirm the canary path stores the `TypedRefusal` JSON in the ledger `response` column (verified against agent grounding: terminal `refused_by_safety` recorded before raise) before relying on the substring.

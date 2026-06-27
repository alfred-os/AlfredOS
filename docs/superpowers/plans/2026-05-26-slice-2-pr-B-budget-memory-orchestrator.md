# Slice 2 — PR B: Per-user BudgetGuard + WorkingMemoryPool + orchestrator contract change — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development`. Steps use checkbox (`- [ ]`) syntax. One commit per task unless explicitly grouped. Drive the PR with `/path-to-green`; address review with `/address-comments`. Never `--no-verify`; never `LEFTHOOK=0`.

**Goal:** Flip the orchestrator + budget + working-memory surface to per-user shape (`User` value-object in, `TaggedContent[T2]` content, pool-owned `WorkingMemory`), atomically updating every one of the 18 call sites in production and tests, while keeping the Slice-1 TUI behaviourally identical through `IdentityResolver.get_operator()`.

**Spec:** [`docs/superpowers/specs/2026-05-26-slice-2-discord-multiuser-design.md`](../specs/2026-05-26-slice-2-discord-multiuser-design.md) — §2 (BudgetGuard contract), §3 (orchestrator contract + WorkingMemoryPool + audit-language semantics + prompt-cache layout + i18n-002 language imperative), §5 unit-test rows for budget/working_pool/orchestrator, §5 integration row for `test_audit_persistence`, §6 PR-B row + atomic-vs-split criteria.

**Depends on:** PR A merged to `main`. Concretely, this plan assumes the following are live on `main`:

- `src/alfred/identity/models.py` — `User` ORM with the column set per spec §4 line 606-619 (`id`, `slug`, `display_name`, `authorization`, `daily_budget_usd`, `language`, `rate_limit_per_min`, `rate_limit_per_day`, `created_at`, `deleted_at`).
- `src/alfred/identity/resolver.py` — `IdentityResolver` with `resolve(platform, platform_id) -> User | None`, `get_operator() -> User`, `add(...)`, `bind(...)`, `remove(slug)` (calls `BudgetGuard.evict` + `WorkingMemoryPool.evict` on soft-delete).
- `src/alfred/identity/version_counter.py` — `IdentityVersionCounter` with `.bump()` / `.current()`; `BudgetGuard` and the resolver subscribe to it.
- `src/alfred/identity/authorization.py` — `Authorization` enum (DB values snake_case: `read_only`, `standard`, `trusted`, `operator`).
- `src/alfred/memory/migrations/versions/0004_users_and_identities.py` — adds `episodes.persona_id` + `episodes.language` + `audit_log.persona_id` + `audit_log.language` columns (nullable, default NULL); creates `users` + `platform_identities`; backfills the operator row.
- `src/alfred/i18n/translator.py` — `_active_lang` is a `ContextVar[str]`; `set_language()`/`t()` go through it.

**Cross-PR contracts you publish** (PR D2 will depend on these — do not break shape after merge without coordinating):

- `BudgetGuard.check_and_charge(user_id: str, cost_usd: float) -> None`.
- `BudgetGuard.would_exceed(user_id: str, cost_usd: float) -> bool`.
- `BudgetGuard.estimate_for(user_id: str, request: CompletionRequest) -> float`.
- `BudgetGuard.evict(user_id: str) -> None` (called by `IdentityResolver.remove`).
- `BudgetGuard.spent_today(user_id: str) -> float`.
- `UnknownBudgetUserError(BudgetError)` typed exception (defense-in-depth — resolver should have caught it).
- `BudgetExceededError(BudgetError)` with `spent_usd: float` + `cap_usd: float` attributes (PR D2's `discord.budget_blocked` template renders typed kwargs, never `str(exc)`).
- `WorkingMemoryPool.acquire(key: tuple[str, str]) -> WorkingMemory`.
- `WorkingMemoryPool.release(key: tuple[str, str], wm: WorkingMemory) -> None`.
- `WorkingMemoryPool.evict(key: tuple[str, str]) -> None`.
- `Orchestrator.handle_user_message(*, user: User, content: TaggedContent[T2], working_memory: WorkingMemory) -> str`.
- `render_persona_prompt(*, persona: Persona = ALFRED_PERSONA, operator_name: str, requesting_user_name: str, language: str) -> str` with the prompt-cache-friendly layout per spec §3 lines 439-454.

**Architecture:**

The contract change moves the orchestrator from "operator-singleton holding `_operator_name` + `_operator_language` + a single `WorkingMemory`" to "stateless per-turn function taking a frozen `User`, a `TaggedContent[T2]`, and a pool-acquired `WorkingMemory`". Three load-bearing shape decisions:

1. **`user` is captured once per turn at the adapter** (TUI calls `IdentityResolver.get_operator()`; Discord will call `.resolve()`). The orchestrator never re-resolves mid-turn — eliminates the cancellation-backstop race against `self._operator_*`.
2. **`WorkingMemoryPool` owns the `WorkingMemory` lifecycle** (in `src/alfred/memory/working.py`, owned by `alfred-memory-engineer`). Adapter calls `acquire((persona, user.slug))` at top-of-turn and `release(...)` in `finally`. Per-key `asyncio.Lock` registry serialises lazy rehydrate; LRU eviction skips in-use entries. `evict(key)` is the explicit removal path called by `IdentityResolver.remove`. Key type is `tuple[str, str]` (`persona`, `user_id`) — Slice-2 first component is always `"alfred"`; Slice-4 forward-compat.
3. **`render_persona_prompt(persona=...)` re-shapes the persona prompt into a cacheable prefix + `<user_context>` XML tail** (spec §3 lines 439-454). The cacheable prefix references `<addressed_user_language>` by name and carries the BCP-47 language imperative (spec i18n-002) so prompt-caching never invalidates on a language change. Persona character/behaviour is the prefix; per-user name + language is the tail.

**Audit-log language semantics (spec i18n-003, §3 line 437 paragraph):** `audit_log.language = user.language` tags the user turn for traceability (matches `episodes.language`). `audit_log.subject` JSONB stays operator-readable **English** — canonical keys + canonical values (`event=orchestrator.turn`, `result=success`, etc.), never translated. Verbatim user content embedded in `subject` is **data**; it inherits the user's natural language unchanged. CLI / TUI / Discord chrome goes through `t()`. PR B's test rows assert this distinction.

**Atomic-vs-split call: PR B stays atomic.** Per spec §6 lines 865-870, the architect's decision criteria are:

- **Stay atomic if** every one of the 18 call sites is a pure signature transform.
- **Split if** more than 4 sites need behavioural edits OR any site needs upstream context OR scratch-branch CI fails non-typing.

Enumeration (see §0 below) confirms every site is a pure signature transform: the 9 production sites are mechanical (`Orchestrator.__init__` wiring, `handle_user_message` body re-threading the User onto already-existing kwargs), and the 9 test sites are mechanical (mocks accept extra args, asserts gain a leading user-id positional). No site needs upstream context that isn't already present; PR A's `IdentityResolver.get_operator()` resolves the household-owner row once at orchestrator construction, so the persona prompt's `operator_name` is available without a per-turn lookup. **Default plan = atomic; §5 carries the Bb/Bm/Bo fallback split sketch** for the architect to invoke if the scratch-branch CI surprises us.

**Tech Stack:** Python 3.12+ • asyncio (`asyncio.Lock` per key in the pool; `asyncio.TaskGroup` if any cleanup needs structured concurrency) • Pydantic v2 (TaggedContent, BudgetExceededError attributes) • SQLAlchemy 2.0 typed (Episode/AuditEntry already typed; no schema change in PR B beyond what migration 0004 added) • pytest + hypothesis (concurrent-rehydrate property test, NaN guard property tests) • structlog with the redactor processor in front.

**Subagent owners (dispatch one per task block per `superpowers:subagent-driven-development`):**

- `alfred-provider-engineer` owns `BudgetGuard` per-user refactor + `UnknownBudgetUserError` + `BudgetExceededError` (`src/alfred/budget/guard.py`). Budget is in the providers' purview per the routing table in `.rulesync/subagents/alfred-python-developer.md`.
- `alfred-memory-engineer` owns `WorkingMemoryPool` (`src/alfred/memory/working.py`) and the `EpisodicMemory.record(persona=, language=)` thread-through.
- `alfred-core-engineer` owns the `Orchestrator` contract change (`src/alfred/orchestrator/core.py`), the CLI wiring change (`src/alfred/cli/main.py`), and the `TuiAdapter`'s use of `IdentityResolver.get_operator()` in `src/alfred/comms/tui.py`.
- `alfred-persona-engineer` owns the `render_persona_prompt` refactor (`src/alfred/personas/alfred.py` → split into `src/alfred/personas/render.py` + the existing `alfred.py` keeping `ALFRED_PERSONA`).
- `alfred-python-developer` does a final conventions pass before the PR opens.

---

## 0. Files this PR creates or modifies

### Files modified

```
src/alfred/budget/guard.py                          MODIFY  per-user refactor; UnknownBudgetUserError; BudgetExceededError; evict; version-counter subscribe; NaN guards extended to per-user paths
src/alfred/memory/episodic.py                       MODIFY  EpisodicMemory.record already accepts `persona` + `language`; PR B threads them at every call site (no signature change needed, but the default-on-omit path becomes a release-blocker test)
src/alfred/orchestrator/core.py                     MODIFY  Orchestrator.__init__ swaps operator_name/operator_language for IdentityResolver + BudgetGuard + WorkingMemoryPool; handle_user_message gains (*, user, content, working_memory); render_persona_prompt call site; episodic/audit per-row language+persona_id from user
src/alfred/personas/alfred.py                       MODIFY  alfred_system_prompt → render_persona_prompt(persona=ALFRED_PERSONA, operator_name=…, requesting_user_name=…, language=…); cacheable prefix + <user_context> XML tail; BCP-47 imperative in prefix (i18n-002)
src/alfred/cli/main.py                              MODIFY  BudgetGuard constructed without daily_usd/per_call_max_usd-as-default-cap (caps now per-User row); WorkingMemoryPool wired; Orchestrator constructor swap; TUI passes IdentityResolver.get_operator() as the operator-name source
src/alfred/comms/tui.py                             MODIFY  _OrchestratorLike Protocol updated; _run_turn resolves user via IdentityResolver.get_operator() once at app construction, acquires WorkingMemory from pool per turn, releases in finally
src/alfred/audit/log.py                             NO CHANGE expected — append() already accepts language= and actor_persona=; PR B threads user.language + 'alfred' from the orchestrator
tests/unit/budget/test_guard.py                     MODIFY  every call site gains a user_id positional; new tests: per-user isolation, evict, UnknownBudgetUserError, BudgetExceededError attributes, NaN per-user path, version-counter cap refresh, cache-on-first-use, validation-before-mutation
tests/unit/orchestrator/test_core.py                MODIFY  _make_budget + _build helpers gain User + WorkingMemoryPool wiring; every handle_user_message("...") becomes keyword form; 7-branch audit assertion table; persona-prompt-receives-operator-and-requesting-user assertion; episodic.record + audit.append per-row language+persona_id assertion
tests/unit/personas/test_alfred.py                  MODIFY  alfred_system_prompt → render_persona_prompt; new assertions for cacheable prefix + <user_context> tail + BCP-47 imperative phrase (i18n-002)
tests/unit/comms/test_tui.py                        MODIFY  AsyncMock.handle_user_message.assert_awaited_once_with(...) becomes keyword form; TuiAdapter's resolve-on-construct path stubbed via mock IdentityResolver
tests/integration/test_audit_persistence.py         MODIFY  Orchestrator construction uses IdentityResolver + WorkingMemoryPool; handle_user_message keyword form; assert language + persona_id populate on every new row (spec §5 integration row)
tests/smoke/test_hello_alfred.py                    MODIFY  Orchestrator construction uses IdentityResolver.get_operator() (resolves the operator row migration 0004 backfilled); WorkingMemoryPool wired; handle_user_message keyword form
src/alfred/locale/en/LC_MESSAGES/messages.po        NO NEW KEYS in PR B (persona prompt strings are model-facing, not operator-facing — they are T0 system-prompt text written in canonical English per the cacheable-prefix design and do not go through t())
```

### Files created

```
src/alfred/memory/working_pool.py                   NEW     WorkingMemoryPool with (persona, user_id) tuple key + per-key asyncio.Lock registry + acquire/release/evict + LRU eviction + working_memory_pool_max settings + working_memory_pool_evictions_total Prometheus counter seed (no metrics emit in PR B — that lands Slice 5)
tests/unit/memory/test_working_pool.py              NEW     spec §5 line 791 — acquire/release semantics; per-key Lock registry; concurrent lazy-rehydrate property test (hypothesis); LRU eviction skips in-use; mid-turn-eviction property test; persona-key tuple form; evict(key) from soft-delete path; cap precedence (operator override vs auto-formula)
tests/unit/budget/test_per_user_isolation.py        NEW     hypothesis property test: charging user A never moves user B's spent_today; NaN/inf in user A's row never poisons user B's row
```

### Files NOT touched in PR B (explicitly out of scope; surface to PR C/D1/D2/E)

- `src/alfred/security/secrets.py` — file-backend lands in PR C.
- `src/alfred/security/dlp.py` — lands in PR D1.
- `src/alfred/comms/discord.py` — lands in PR D2.
- `src/alfred/identity/resolver.py` body — frozen by PR A; PR B only consumes `.get_operator()` and `.remove()`'s side-effects.

---

## 1. Task sequence

PR B is one commit cluster of ~14 commits. The architect-approved atomic path keeps every test-and-production change together so the slice-1 TUI smoke regresses or passes as a unit. Follow TDD: each non-mechanical task lands a failing test first, then makes it pass.

### Phase 1 — `BudgetGuard` per-user refactor (TDD, alfred-provider-engineer)

- [ ] **Task 1.** Define `UnknownBudgetUserError(BudgetError)` and `BudgetExceededError(BudgetError)` with `spent_usd: float` + `cap_usd: float` Pydantic-frozen attributes. Add to `src/alfred/budget/guard.py`'s exception hierarchy. Tests in `tests/unit/budget/test_guard.py` first: instantiate each, assert message format + attribute access. PR D2 will rely on the typed attributes for `discord.budget_blocked`.

- [ ] **Task 2.** Write failing tests in `tests/unit/budget/test_guard.py` for the per-user isolation contract: charging user `alice` does not move `bob`'s `spent_today`; per-call cap remains global; day-rollover is per-user (alice rolls at her first call past midnight without disturbing bob); `UnknownBudgetUserError` raised on a `check_and_charge`/`would_exceed`/`estimate_for`/`spent_today` call for a user the resolver hasn't introduced; `evict("alice")` removes the entry; `evict` on an unknown user is a no-op; NaN/inf in `cost_usd` raises `ValueError` per-user without mutating any other user's `_spent`; **validation raises BEFORE `_user_budgets` is mutated** (spec §2 line 176 — typo'd user_ids cannot leak entries); `BudgetExceededError` raised with correct `spent_usd` + `cap_usd` attributes on the daily-cap path.

- [ ] **Task 3.** Implement the per-user refactor in `src/alfred/budget/guard.py`:
  - Internal `dict[str, _UserBudget]` keyed on canonical user_id; `_UserBudget` carries `(daily_usd, daily_usd_version, per_call_max_usd, day, spent)`.
  - `check_and_charge(user_id, cost_usd)`, `would_exceed(user_id, cost_usd)`, `estimate_for(user_id, request)`, `spent_today(user_id)` — all per-user.
  - `_load_or_get_user(user_id)` internal helper that fetches the `User.daily_budget_usd` cap on first call (via injected callable returning a `User`-like), refreshes the cap when `IdentityVersionCounter.current()` is past the cached `daily_usd_version`. **Validate cost first, then mutate** — assertion in tests catches regressions.
  - `_spent` + `_day` are the in-process source of truth and **must not be evicted** (spec §2 line 176 — security invariant, not a perf knob).
  - `evict(user_id)` explicitly removes the entry; called by `IdentityResolver.remove` on soft-delete.
  - Operator's slice-1 `settings.daily_budget_usd` becomes the operator's per-user cap (not a global ceiling). Tests assert the migration-0004 backfilled operator's `daily_budget_usd` flows through.
  - Per-call cap stays global (`settings.per_call_max_usd`) — passed in at construction.
  - Subscribe to `IdentityVersionCounter` via injection (Slice-1 module-global avoidance per CLAUDE.md "No global state"). The constructor takes the counter; `_load_or_get_user` reads `counter.current()` and refetches `daily_usd` on bump.
  - NaN/inf guards mirror slice-1 input-sanitisation on every per-user surface (`check_and_charge`, `would_exceed`, `estimate_for`, `User.daily_budget_usd` load path) per spec §2 line 181.

- [ ] **Task 4.** Write `tests/unit/budget/test_per_user_isolation.py` — hypothesis property test:
  - `given(user_costs: lists(tuples(text(min_size=1), floats(min_value=0, max_value=0.01))))` — interleave charges across users; assert `spent_today(u) == sum(cost for (u', cost) in trace if u' == u)`.
  - Second property: NaN/inf injection on any one user's path never alters any other user's `_spent` or `_day`.
  - Third property: `evict(u)` followed by re-introducing the user resets `_spent` to 0 (intentional — the evict path is operator-driven soft-delete) but does NOT affect other users.
  Land this last in Phase 1 because the hypothesis shrinking exercises the validation-before-mutation invariant aggressively.

### Phase 2 — `WorkingMemoryPool` (TDD, alfred-memory-engineer)

- [ ] **Task 5.** Write failing tests in `tests/unit/memory/test_working_pool.py` (spec §5 line 791):
  - `acquire((persona, user_id))` returns a `WorkingMemory`; second `acquire` for the same key returns the **same** instance (per-key singleton until evicted).
  - **Concurrent lazy-rehydrate property test (hypothesis)** — fire N concurrent `acquire(("alfred", "alice"))` calls; assert the rehydrate path (`EpisodicMemory.recent(persona='alfred', user_id='alice', limit=20)`) runs exactly once. This is the PR-B acceptance gate per the task brief.
  - `release((persona, user_id), wm)` marks the entry idle; LRU eviction sees idle entries first.
  - LRU eviction **skips in-use** entries — assertion: acquire keys (A, B, C) with pool_max=2, acquire(A) again without release(A), then acquire(D); B (idle) is evicted, A (in-use) is NOT.
  - `evict((persona, user_id))` removes the entry unconditionally; subsequent `acquire` rehydrates fresh from `EpisodicMemory`. This is the soft-delete path.
  - Per-key `asyncio.Lock` registry — locks live inside the pool, lazy-created on first acquire of each key.
  - Persona-key tuple form: `acquire(("alfred", "alice"))` and `acquire(("lucius", "alice"))` are independent entries.
  - **Cap precedence (spec §3 line 466, perf-002):** operator override via `settings.working_memory_pool_max` always wins; `None` triggers the `max(50, active_user_count * 2)` auto-formula. Test both with a stubbed active-user-count callable.
  - **Mid-turn eviction property test (hypothesis):** drive N concurrent acquire/release pairs against pool_max=1; assert that no `release` call ever raises because its in-use entry was evicted from under it.

- [ ] **Task 6.** Implement `src/alfred/memory/working_pool.py`:

  ```python
  class WorkingMemoryPool:
      def __init__(
          self,
          *,
          episodic_factory: Callable[[AsyncSession], EpisodicMemory],
          pool_session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
          max_entries: int | None = None,
          active_user_count: Callable[[], int] = lambda: 1,
      ) -> None: ...

      async def acquire(self, key: tuple[str, str]) -> WorkingMemory: ...
      async def release(self, key: tuple[str, str], wm: WorkingMemory) -> None: ...
      def evict(self, key: tuple[str, str]) -> None: ...
  ```

  - Per-key `asyncio.Lock` registry (dict[tuple[str, str], asyncio.Lock]); lazy-create on first acquire of each key.
  - Lazy rehydrate inside the lock: open a pool-owned short-lived `pool_session_scope` session (spec §3 line 460 — "not the orchestrator's per-turn session, keeps locality clean per core-006"); call `episodic.recent(persona=key[0], user_id=key[1], limit=20)`; replay into `WorkingMemory.append(role=..., content=...)` in chronological order.
  - `_in_use: set[tuple[str, str]]` — incremented on acquire, decremented on release. LRU eviction iterates idle entries by `_last_released_at` and evicts the oldest until under cap.
  - `evict(key)` removes from both `_entries` and `_locks`. If `key` is in `_in_use`, the spec defers to the consuming agent's policy — PR B's choice is: evict eagerly, the in-flight `release` no-ops on a missing key (assertion in test 5 covers this).
  - Cap precedence: `max_entries` argument wins if not None; else `max(50, active_user_count() * 2)`. Recompute on every `acquire` call (cheap — one Python comparison) so the auto-formula stays honest as `active_user_count` drifts. Spec §3 line 466.

- [ ] **Task 7.** Update `src/alfred/memory/episodic.py` if needed. **Verify no signature change is required:** `EpisodicMemory.record` already accepts `persona: str = "alfred"` and `language: str = "en-US"` per the existing slice-1 code. `EpisodicMemory.recent` currently signature is `recent(*, user_id, limit=20)`; PR B adds `persona: str | None = None` per spec §3 line 470 ("`EpisodicMemory.recent()` grows a `persona=` kwarg that the pool passes through. Slice-2 callers always pass `'alfred'`; Slice 4 callers pass the active persona"). When `persona is None`, behaviour is identical to slice-1 (no `WHERE persona = ?` clause). When `persona` is set, filter on it. **Migration 0004 added the column nullable**, so the `WHERE persona = 'alfred'` filter is alfred-only-safe for any row written post-migration; pre-migration rows have NULL `persona_id` and won't match — that's fine because migration 0004 backfilled them to the operator's user_id only, not to a persona.

  Tests: extend `tests/unit/memory/test_episodic.py` to assert `recent(user_id="alice")` returns slice-1 shape; `recent(user_id="alice", persona="alfred")` returns only alfred rows; `recent(user_id="alice", persona="lucius")` returns nothing on a database with only alfred rows.

### Phase 3 — Persona prompt rewording + `render_persona_prompt` refactor (TDD, alfred-persona-engineer)

- [ ] **Task 8.** Write failing tests in `tests/unit/personas/test_alfred.py` for the new shape (spec §3 lines 439-454, i18n-002):
  - `render_persona_prompt(persona=ALFRED_PERSONA, operator_name="Bruce", requesting_user_name="Alice", language="en-US")` returns a string whose **cacheable prefix** (everything before `<user_context>`) contains:
    - The persona name (`Alfred`).
    - The persona character/behaviour paragraph.
    - Name-references to `<operator_name>`, `<addressed_user_name>`, `<addressed_user_language>` (so the model is instructed by element-name, not by interpolated value — that's what makes the prefix prompt-cache-friendly).
    - **The BCP-47 language imperative** (spec i18n-002, §3 line 454): an instruction along the lines of "Respond in the BCP-47 language tag identified by `<addressed_user_language>`". Assert the imperative phrase + each `<user_context>` element name appears in the rendered prefix. This is load-bearing — losing it would silently re-monolingual the bot under prompt-caching restructure.
  - The `<user_context>` XML tail contains exactly three elements: `<operator_name>Bruce</operator_name>`, `<addressed_user_name>Alice</addressed_user_name>`, `<addressed_user_language>en-US</addressed_user_language>`.
  - Changing `language` from `"en-US"` to `"ja-JP"` changes only the `<user_context>` tail; the cacheable prefix is byte-identical. Assert via string-prefix comparison (find the index of `<user_context>` in both, slice, compare).
  - Changing `requesting_user_name` from `"Alice"` to `"Bob"` changes only the `<user_context>` tail.
  - The persona description distinguishes household owner from current addressee — the prefix says "You are head butler in `<operator_name>`'s household. You are currently addressing `<addressed_user_name>`." (spec §3 line 435 — the wrong-semantics fix is that Bob isn't the operator, Bob is the addressee).
  - For Slice-2 forward-compat: `render_persona_prompt(persona=Persona(name="lucius", character="…"))` produces a Lucius-shaped prompt (cacheable prefix references the Lucius character; XML tail unchanged in shape). Slice 4 lands the real Lucius persona; PR B just proves the interface doesn't bake-in Alfred.

- [ ] **Task 9.** Refactor `src/alfred/personas/alfred.py`:
  - Keep `Persona` dataclass + `ALFRED_PERSONA` constant.
  - **Delete** `alfred_system_prompt`. **Add** `render_persona_prompt(*, persona: Persona = ALFRED_PERSONA, operator_name: str, requesting_user_name: str, language: str) -> str` with the cacheable-prefix + `<user_context>` tail shape per spec §3.
  - Implementation sketch:

    ```python
    def render_persona_prompt(
        *,
        persona: Persona = ALFRED_PERSONA,
        operator_name: str,
        requesting_user_name: str,
        language: str,
    ) -> str:
        prefix = (
            f"You are {persona.name.title()}, head butler in <operator_name>'s "
            f"household. {persona.character} "
            f"You are currently addressing <addressed_user_name>. "
            f"Respond in the BCP-47 language tag identified by <addressed_user_language>. "
            "Keep responses tight unless asked to elaborate. "
            "If you do not know something, say so plainly; do not invent."
        )
        tail = (
            "<user_context>\n"
            f"  <operator_name>{operator_name}</operator_name>\n"
            f"  <addressed_user_name>{requesting_user_name}</addressed_user_name>\n"
            f"  <addressed_user_language>{language}</addressed_user_language>\n"
            "</user_context>"
        )
        return f"{prefix}\n\n{tail}"
    ```

  - Operator-facing strings here go to the model, not to the human eye — they are T0 system-prompt text, written in canonical English, and **do not pass through `t()`**. (CLAUDE.md i18n rule #2 covers the language imperative; the model translates its own response per that imperative.)

### Phase 4 — Orchestrator contract change (TDD, alfred-core-engineer)

- [ ] **Task 10.** Write failing tests in `tests/unit/orchestrator/test_core.py` for the new signature. Update the `_make_budget` and `_build` helpers to match (these are themselves a call site — see §0 enumeration):
  - `_make_budget` returns a MagicMock whose `estimate_for`, `would_exceed`, `check_and_charge`, `spent_today`, `evict` accept a leading `user_id` positional. Default `would_exceed=False`, `estimate=0.01`, `check_and_charge` returns None.
  - `_build` gains a `user: User` arg (default a frozen `User(slug="sir", display_name="Sir", language="en-US", authorization=Authorization.operator, daily_budget_usd=1.0, ...)`). The Orchestrator constructor takes an `IdentityResolver`-like (mock returning `user` for `.get_operator()`) and a `WorkingMemoryPool`-like (mock whose `acquire(("alfred", user.slug))` returns the test's `working` mock; `release` is an AsyncMock no-op).
  - Every existing test in the file replays through the new signature:
    - `orch.handle_user_message(user=..., content=tag(T2, "...", source="test"), working_memory=...)`.
    - Audit assertions gain `audit_kwargs["language"] == user.language` and `audit_kwargs["actor_persona"] == "alfred"` (spec §3 line 433 — the orchestrator writes `persona_id='alfred'` on every audit row).
    - Episodic assertions gain `language == user.language` and `persona == "alfred"`.
    - Persona-prompt assertion changes: the request's `messages[0].content` (system) now contains both the `<user_context>` tail with `<operator_name>` and `<addressed_user_name>`, and the BCP-47 imperative referencing `<addressed_user_language>`.
  - **New test row** — `TestOrchestratorPersonaPromptThreading`:
    - `test_persona_prompt_carries_operator_and_requesting_user(self)`: a non-operator user (`user=Alice, authorization=standard`) drives a turn; the system prompt's `<operator_name>` is `Bruce` (the household owner from `IdentityResolver.get_operator()`) and `<addressed_user_name>` is `Alice`.
  - **New test row** — `TestOrchestratorPerUserAudit`:
    - `test_audit_row_carries_user_language_and_alfred_persona`: turn with `user.language="de-DE"`; assert `audit_kwargs["language"] == "de-DE"` and `audit_kwargs["actor_persona"] == "alfred"`.
    - `test_episodic_record_carries_user_language_and_alfred_persona`: same shape, episodic side.
  - **New test row** — `TestOrchestratorSevenAuditBranches` — spec §5 line 792 requires the seven audit branches each produce the spec'd `result` value. Enumeration:
    1. `result=success` (happy path).
    2. `result=budget_blocked` (pre-check refusal).
    3. `result=provider_failed` (router raises).
    4. `result=budget_overrun` (post-success per-call cap exceeded; charge truthful, no raise).
    5. `result=cancelled` (cancellation backstop — inner provider arm).
    6. `result=cancelled` (cancellation backstop — outer arm, before provider).
    7. **NEW for PR B:** `result=unknown_budget_user` — `BudgetGuard` raises `UnknownBudgetUserError` on a `check_and_charge` for a user the resolver never introduced. This is defense-in-depth — the resolver should have caught it first, but a missed call site fails loudly. Assertion: orchestrator catches `BudgetError`, writes an audit row with `result="unknown_budget_user"`, re-raises so the adapter surfaces a generic error to the user (PR D2's Discord path catches it explicitly; PR B's TUI path lets it fall through to `tui.alfred_error`).

- [ ] **Task 11.** Implement the orchestrator contract change in `src/alfred/orchestrator/core.py`:
  - Constructor signature change:

    ```python
    def __init__(
        self,
        *,
        identity_resolver: IdentityResolverLike,        # NEW — replaces operator_name/operator_language
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
        router: ProviderRouter,
        budget: BudgetGuard,
        episodic_factory: Callable[[AsyncSession], EpisodicMemory] = lambda s: EpisodicMemory(session=s),
        audit_factory: ... = lambda f: AuditWriter(session_factory=f),
        redactor: Callable[[str], str] = lambda s: s,
    ) -> None:
        self._operator = identity_resolver.get_operator()  # frozen User, cached for the orchestrator lifetime
        ...
    ```

    The orchestrator no longer holds a `WorkingMemory` — the pool owns it; the adapter passes it in per turn.
  - `handle_user_message` signature change:

    ```python
    async def handle_user_message(
        self,
        *,
        user: User,
        content: TaggedContent[T2],
        working_memory: WorkingMemory,
    ) -> str: ...
    ```

    The content is already T2-tagged (the adapter tagged it). The orchestrator no longer re-tags — it reads `content.content` and `content.tier.name == "T2"`. (Slice-1 had the orchestrator tag a raw `str`; PR B moves the tag site outward to the adapter, which is what makes Slice-3's T3 path a type-level discriminant.)
  - Inside `_handle_turn`, every `self._operator_name` becomes `user.slug`; every `self._operator_language` becomes `user.language`; the persona prompt call becomes:

    ```python
    system_prompt = render_persona_prompt(
        persona=ALFRED_PERSONA,
        operator_name=self._operator.display_name,
        requesting_user_name=user.display_name,
        language=user.language,
    )
    ```

  - Budget calls thread `user.slug`:

    ```python
    estimate = self._budget.estimate_for(user.slug, request)
    if self._budget.would_exceed(user.slug, estimate): ...
    self._budget.check_and_charge(user.slug, response.cost_usd)
    ```

  - Episodic calls thread `user.slug` + `user.language` + `persona="alfred"`:

    ```python
    await episodic.record(
        user_id=user.slug,
        role="user",
        content=user_input.content,
        trust_tier=user_input.tier.name,
        language=user.language,
        persona="alfred",
    )
    ```

  - Audit calls thread `user.slug` + `user.language` + `actor_persona="alfred"`:

    ```python
    await self._audit.append(
        event="orchestrator.turn",
        actor_user_id=user.slug,
        actor_persona="alfred",
        subject=...,
        trust_tier_of_trigger=user_input.tier.name,
        result="success",
        ...,
        language=user.language,
    )
    ```

  - **`UnknownBudgetUserError` branch:** wrap each per-user budget call in a `try/except BudgetError` and discriminate on `isinstance(exc, UnknownBudgetUserError)`. On unknown-user, audit `result="unknown_budget_user"` (subject carries `phase="budget_pre_check"` or `"budget_post_charge"` depending on which call raised) and re-raise so the adapter surfaces it. Other `BudgetError`s keep slice-1 behaviour (`budget_blocked` on pre-check, `budget_overrun` on post-charge).
  - **Cancellation backstop** — same shape as slice-1; the audit row's `actor_user_id` becomes `user.slug` (was `self._operator_name`). The top-level `_audit_cancellation` helper takes `user` as an arg (it's only callable from inside `handle_user_message`, which has the user in scope).
  - **`session.rollback()` discipline** — unchanged from slice-1. The outer try/except in `handle_user_message` is identical except that `BaseException`/`asyncio.CancelledError` arms reference the captured `user` instead of `self._operator_*`.

### Phase 5 — CLI wiring + TUI adapter change (alfred-core-engineer)

- [ ] **Task 12.** Update `src/alfred/cli/main.py`'s `_chat_main()`:
  - Resolve the operator via `IdentityResolver.resolve("tui", settings.operator_name)` (spec §4 line 775 — the TUI uses the same path Discord will use). If it returns `None`, exit with a friendly hint (`t("error.no_operator_row")`) pointing at `alfred user add --authorization operator`. **PR A ships this hint key**; PR B uses it.
  - Construct `BudgetGuard(per_call_max_usd=settings.per_call_max_usd, user_loader=..., version_counter=...)`. The `daily_usd` is no longer a constructor arg — caps come from each `User.daily_budget_usd` on first per-user call. `user_loader` is a callable `(user_id: str) -> User` that the orchestrator's `IdentityResolver` exposes (PR A's resolver has a `get_by_slug(slug)` method; PR B wires it).
  - Construct `WorkingMemoryPool(episodic_factory=..., pool_session_scope=..., max_entries=settings.working_memory_pool_max, active_user_count=...)`.
  - Construct `Orchestrator(identity_resolver=resolver, session_scope=session_scope, router=router, budget=budget, ...)`.
  - **Remove** the slice-1 rehydrate-on-startup block (`async with session_scope() as session: ... await working.append(...)`) — the pool now lazy-rehydrates on first `acquire` per user. The smoke test asserts this still produces a working "Alfred remembers our last turn" behaviour because the pool's lazy rehydrate runs against the same episodes table.

- [ ] **Task 13.** Update `src/alfred/comms/tui.py`:
  - `_OrchestratorLike` Protocol gains the new signature:

    ```python
    class _OrchestratorLike(Protocol):
        async def handle_user_message(
            self, *, user: User, content: TaggedContent[T2], working_memory: WorkingMemory,
        ) -> str: ...
    ```

  - `AlfredTuiApp.__init__` takes additional constructor injects: `identity_resolver: IdentityResolverLike`, `working_pool: WorkingMemoryPool`. CLI wires these.
  - `_run_turn(text)` becomes:

    ```python
    async def _run_turn(self, text: str) -> str:
        user = self._identity_resolver.get_operator()
        content = tag(T2, text, source="comms.tui.input")
        wm = await self._working_pool.acquire(("alfred", user.slug))
        try:
            return await self._orchestrator.handle_user_message(
                user=user, content=content, working_memory=wm,
            )
        finally:
            await self._working_pool.release(("alfred", user.slug), wm)
    ```

  - Per spec §3 line 376-398's adapter wiring pattern: capture WM once at the top of the turn; never re-enter the pool mid-turn.

- [ ] **Task 14.** Update `tests/unit/comms/test_tui.py`:
  - Every `orch.handle_user_message.assert_awaited_once_with("hi")` becomes the keyword form: `assert_awaited_once_with(user=ANY, content=ANY, working_memory=ANY)` with the `ANY` from `unittest.mock` and an additional assertion on the args matching what the TUI built. The five existing tests (happy, Esc cancel, timeout, exception, second-submit-busy) all need this update.
  - `AlfredTuiApp(orchestrator=orch)` becomes `AlfredTuiApp(orchestrator=orch, identity_resolver=mock_resolver, working_pool=mock_pool)`. The mock resolver's `get_operator()` returns a fixture `User`; the mock pool's `acquire` returns a fixture `WorkingMemory`; `release` is an AsyncMock no-op.

### Phase 6 — Integration + smoke (alfred-memory-engineer + alfred-core-engineer)

- [ ] **Task 15.** Update `tests/integration/test_audit_persistence.py` (spec §5 line 803):
  - Both tests (`test_provider_failure_audit_row_survives_rollback` and `test_budget_block_audit_row_survives_rollback`) construct the orchestrator with `IdentityResolver` instead of `operator_name`/`operator_language`. The resolver is a real one built against the testcontainer Postgres after migration 0004 has run and the operator row has been backfilled.
  - **NEW assertion** in both tests: after the failing turn, query the audit row's `language` and `actor_persona` columns and assert they match `user.language` and `"alfred"` respectively. Spec §3 line 437 — audit-log language semantics: `audit_log.language = user.language` per row; `subject` JSONB stays operator-readable English (assert by reading `rows[0].subject["phase"]` and confirming it's a canonical key like `"provider_call"` or `"budget_pre_check"`, not a translated value).

- [ ] **Task 16.** Update `tests/smoke/test_hello_alfred.py`:
  - `BudgetGuard(...)` construction changes to the new signature (per-call cap + user loader + version counter).
  - `WorkingMemoryPool` wired with the testcontainer's `session_scope` and a stubbed `active_user_count`.
  - `Orchestrator(...)` construction uses the real `IdentityResolver` built against the migration-0004 backfilled operator row.
  - `await orch.handle_user_message("hi alfred")` becomes:

    ```python
    user = resolver.get_operator()
    content = tag(T2, "hi alfred", source="smoke.test")
    wm = await pool.acquire(("alfred", user.slug))
    try:
        response = await orch.handle_user_message(user=user, content=content, working_memory=wm)
    finally:
        await pool.release(("alfred", user.slug), wm)
    ```

  - Assertions on persisted episodes + audit row gain `language` + `persona` (`Episode.persona == "alfred"`; `AuditEntry.actor_persona == "alfred"`).

### Phase 7 — Conventions pass + verification (alfred-python-developer)

- [ ] **Task 17.** Run `make fix` then `make check`. Verify all five gates pass: ruff check, ruff format, mypy, pyright, pytest unit + integration. Resolve any drift introduced by the test-mock changes (notably, the new `User`-fixture imports may surface unused-import warnings in tests that were previously self-contained).

- [ ] **Task 18.** TUI smoke regression confirmation. Drive a real `alfred chat` session against the testcontainer (or against a local dev stack) with the migration-0004 operator row backfilled. Verify:
  - The Esc-to-cancel UX still works.
  - The footer bindings still render through `t()`.
  - The conversation log shows the assistant reply normally.
  - `alfred audit log --since 1h` shows rows with `actor_persona=alfred`, `language=en-US`, `actor_user_id=<operator-slug>`.
  - PR-B acceptance gate (per the task brief): "TUI smoke test still passes; orchestrator audit branches each produce the spec'd `result` value; `WorkingMemoryPool` concurrent-rehydrate property test green."

---

## The 18 call sites — enumeration

The architect's atomic-vs-split decision rides on this list. Every site is verified a pure signature transform; PR B stays atomic.

### Production sites (9)

| # | File:Line | Slice-1 shape | PR-B shape | Pure xform? |
| --- | --- | --- | --- | --- |
| 1 | `src/alfred/orchestrator/core.py:97-126` (`Orchestrator.__init__`) | `operator_name: str`, `operator_language: str`, `working: WorkingMemory` | `identity_resolver: IdentityResolverLike` (caches `get_operator()`); no `working` (pool-owned) | yes |
| 2 | `src/alfred/orchestrator/core.py:128` (`handle_user_message`) | `(self, content: str) -> str` | `(self, *, user: User, content: TaggedContent[T2], working_memory: WorkingMemory) -> str` | yes |
| 3 | `src/alfred/orchestrator/core.py:218` (`alfred_system_prompt`) | `alfred_system_prompt(operator_name=..., language=...)` | `render_persona_prompt(persona=ALFRED_PERSONA, operator_name=self._operator.display_name, requesting_user_name=user.display_name, language=user.language)` | yes |
| 4 | `src/alfred/orchestrator/core.py:230-231, 289` (`budget.estimate_for/would_exceed/check_and_charge`) | `(cost_usd)` | `(user.slug, cost_usd)` | yes |
| 5 | `src/alfred/orchestrator/core.py:207-213, 306-315` (`episodic.record`) | `language=self._operator_language` (already passes `language`; `persona="alfred"` is the default) | `language=user.language, persona="alfred"` (explicit on every call) | yes |
| 6 | `src/alfred/orchestrator/core.py:171-186, 232-245, 265-282, 318-337` (`audit.append` × 4 branches + cancellation backstop) | `actor_user_id=self._operator_name, language=self._operator_language` | `actor_user_id=user.slug, actor_persona="alfred", language=user.language` (plus the NEW `unknown_budget_user` audit branch — Task 11) | yes |
| 7 | `src/alfred/cli/main.py:281-284` (`BudgetGuard(...)`) | `BudgetGuard(daily_usd=settings.daily_budget_usd, per_call_max_usd=settings.per_call_max_usd)` | `BudgetGuard(per_call_max_usd=settings.per_call_max_usd, user_loader=resolver.get_by_slug, version_counter=version_counter)` | yes |
| 8 | `src/alfred/cli/main.py:294-308` (`Orchestrator` construction + working-memory rehydrate) | `Orchestrator(operator_name=..., operator_language=..., working=working, ...)` plus an explicit `await working.append(...)` rehydrate loop on startup | `Orchestrator(identity_resolver=resolver, ...)`; rehydrate block deleted (pool lazy-rehydrates) | yes |
| 9 | `src/alfred/comms/tui.py:40, 62-72, 138-139` (`_OrchestratorLike` Protocol + `AlfredTuiApp.__init__` + `_run_turn`) | `_run_turn(text) -> await self._orchestrator.handle_user_message(text)` | resolve user once, tag T2, acquire WM from pool, call keyword form, release in finally | yes |

### Test sites (9)

| # | File:Line | What changes |
| --- | --- | --- |
| 10 | `tests/unit/orchestrator/test_core.py:25-30` (`_make_budget` helper) | Mocks accept leading `user_id` positional on `estimate_for/would_exceed/check_and_charge/spent_today/evict` |
| 11 | `tests/unit/orchestrator/test_core.py:54-131` (`_build` helper) | Wire `User` fixture + mock `IdentityResolver.get_operator()` + mock `WorkingMemoryPool`; drop `operator_name`/`operator_language` constructor kwargs |
| 12 | `tests/unit/orchestrator/test_core.py:137, 202, 230, 253, 274, 295, 309, 320, 343, 366, 400, 431` (every `await orch.handle_user_message("...")`) | Convert to `await orch.handle_user_message(user=user, content=tag(T2, "...", source="test"), working_memory=wm)` |
| 13 | `tests/unit/orchestrator/test_core.py:177-180, 207, 240, 269, 307-308` (every budget mock assertion) | Update `assert_called_with(approx(0.0005))` → `assert_called_with(user.slug, approx(0.0005))`; same for `assert_not_called` paths (no positional change) |
| 14 | `tests/unit/comms/test_tui.py:40, 58, 80, 130, 158, 193, 211, 220` (every `AsyncMock.handle_user_message` setup + assertion) | Update mock signature + `assert_awaited_once_with(user=ANY, content=ANY, working_memory=ANY)`; pass `identity_resolver=mock_resolver, working_pool=mock_pool` to `AlfredTuiApp` |
| 15 | `tests/unit/personas/test_alfred.py:5, 14-25, 31` (every `alfred_system_prompt(...)` call) | Convert to `render_persona_prompt(persona=ALFRED_PERSONA, operator_name=..., requesting_user_name=..., language=...)`; **new** assertions for cacheable prefix + `<user_context>` tail + BCP-47 imperative (i18n-002) |
| 16 | `tests/unit/budget/test_guard.py` (every `BudgetGuard` test method — 16 methods) | Add `user_id` positional to every `check_and_charge`/`would_exceed`/`estimate_for`/`spent_today` call; new tests for `evict`, `UnknownBudgetUserError`, `BudgetExceededError`, per-user isolation, validation-before-mutation, version-counter cap refresh |
| 17 | `tests/integration/test_audit_persistence.py:62-76, 118-141` (both integration tests) | Replace `operator_name="operator"`/`operator_language="en-US"` constructor kwargs with `identity_resolver=resolver` (built against testcontainer Postgres + migration 0004); update `handle_user_message` to keyword form; new assertions on persisted `language` + `actor_persona` columns |
| 18 | `tests/smoke/test_hello_alfred.py:43-46, 86-114` (smoke test) | `BudgetGuard` + `WorkingMemoryPool` + `Orchestrator` constructions all update; `handle_user_message` keyword form; assertions on `Episode.persona` and `AuditEntry.actor_persona` + `Episode.language` and `AuditEntry.language` |

**Verification of "pure signature transform" claim:** every site above either (a) re-threads an already-available value (`user.slug` was previously `self._operator_name`, which was just `settings.operator_name`; the migration-0004-backfilled operator row's `slug` is `slug-from-name(settings.operator_name)`, which for the default `"operator"` case is literally `"operator"` — no behaviour change), (b) adds a new kwarg with a clean default (`persona="alfred"`, `actor_persona="alfred"` — both already defaulted in slice-1 code), or (c) wraps a call in `tag(T2, ...)` that the adapter now owns instead of the orchestrator. No site requires upstream context that PR A doesn't already provide. No site needs a behavioural edit beyond the signature shape.

---

## 2. Acceptance gates

These are the PR-B-specific gates (per spec §6 line 863). All must be runnable assertions, all must be green before opening the PR.

- [ ] **G1. TUI smoke test still passes.**
  - Concrete check: `uv run pytest tests/smoke/test_hello_alfred.py -q -m smoke` exits 0.
  - Asserts: end-to-end "hi alfred" → "Good evening, operator." round-trip against real Postgres testcontainer + real migrations + per-user budget + pool-acquired working memory.
- [ ] **G2. Orchestrator audit branches each produce the spec'd `result` value.**
  - Concrete check: `uv run pytest tests/unit/orchestrator/test_core.py::TestOrchestratorSevenAuditBranches -q` exits 0.
  - Asserts: 7 branches × correct `result` value × `language == user.language` × `actor_persona == "alfred"` × subject JSONB stays English-keyed.
- [ ] **G3. `WorkingMemoryPool` concurrent-rehydrate property test green.**
  - Concrete check: `uv run pytest tests/unit/memory/test_working_pool.py::test_concurrent_acquire_rehydrates_exactly_once -q` exits 0.
  - Asserts: N concurrent `acquire(("alfred", "alice"))` calls invoke `EpisodicMemory.recent(...)` exactly once.
- [ ] **G4. Per-user budget isolation property test green.**
  - Concrete check: `uv run pytest tests/unit/budget/test_per_user_isolation.py -q` exits 0.
- [ ] **G5. `make check` green.**
  - Ruff format clean, ruff lint clean, mypy --strict clean, pyright clean, pytest unit + integration green.
- [ ] **G6. No new operator-facing strings without `t()`.**
  - Concrete check: `pybabel extract` produces no diff vs. the current catalog (per CLAUDE.md i18n hard rule #4); PR B introduces no operator-facing English literals.
- [ ] **G7. No silent failures in security paths.**
  - Concrete check: every refusal/error branch in `Orchestrator` writes an audit row (CLAUDE.md hard rule #7). Asserted by the 7-branch test row in G2 plus the existing `test_audit_persistence` integration tests in G5.
- [ ] **G8. The 18 call sites' enumeration is byte-for-byte present in the PR description.**
  - Concrete check: PR description copies the §0 enumeration table. Reviewers verify the architect's atomic decision was correctly applied — if any site turns out to need a behavioural edit during implementation, the architect rolls back to the §5 split.

---

## 3. Open questions / decisions deferred to plan time

The atomic-vs-split call is **resolved here:** PR B stays atomic. See the §1 enumeration above and the §5 fallback sketch below.

Empty otherwise. Every spec-level question for PR B's scope was resolved in the spec body (see spec §7 "Resolved since the brainstorm"). PR B does not own:

- Length-delta DLP oracle mitigation (Slice 3 task; spec §7 punch list).
- PgBouncer transaction-pooling NOTIFY backstop (spec §7 punch list; PR A's TTL fallback covers correctness).
- Multi-operator household elections (Slice 4; spec §7).

---

## 4. References

- **PRD anchors:** [§6.2 Multi-layered Memory](../../../PRD.md#62-multi-layered-memory) (working + episodic per-user), [§6.5 Budget & Cost Tracking] (per-user budget), [§6.8 Persona System](../../../PRD.md#68-persona-system) (persona prompt threading), [§7.2 Multi-User Identity & Authorization](../../../PRD.md#72-multi-user-identity--authorization) (memory partition is per-persona-per-user).
- **Spec anchors:** [§2 `BudgetGuard` contract change](../specs/2026-05-26-slice-2-discord-multiuser-design.md#2-architectural-changes), [§3 Orchestrator contract change + WorkingMemoryPool + audit-language semantics + prompt-cache layout](../specs/2026-05-26-slice-2-discord-multiuser-design.md#3-discord-adapter-detail), [§5 unit-test rows for budget/working_pool/orchestrator](../specs/2026-05-26-slice-2-discord-multiuser-design.md#5-test-strategy-adrs-slice-graduation), [§5 integration row for `test_audit_persistence`](../specs/2026-05-26-slice-2-discord-multiuser-design.md#5-test-strategy-adrs-slice-graduation), [§6 PR-B row + atomic-vs-split criteria](../specs/2026-05-26-slice-2-discord-multiuser-design.md#6-build-sequence--6-prs-a-b-c-d1-d2-e).
- **ADRs that bind PR B's design:** ADR-0011 (per-user `BudgetGuard`) — placeholder lands in PR A, body in PR E; PR B's design must remain consistent with the ADR-0011 placeholder frontmatter so PR E can write the body without retroactive changes.
- **Cross-cutting CLAUDE.md rules:** hard rule #1 (no English literals in `src/alfred/` outside catalog); hard rule #3 (T2-tag at the boundary — adapter side, not orchestrator side); hard rule #7 (no silent failures in security paths — every audit branch writes a row + structlog.bind(...).error before re-raising); i18n rule #3 (every stored user-content row carries `language`).

---

## 5. If split becomes necessary — Bb / Bm / Bo appendix

If during implementation the architect discovers one of the spec §6 lines 866-868 trigger conditions — more than 4 call sites need behavioural edits beyond the signature shape; any site requires upstream context PR A doesn't provide; or scratch-branch CI surfaces non-typing failures — the architect forks this plan into three sub-PRs landing in this exact order, each green before the next opens. This sketch fixes the boundaries; the bite-sized tasks for each sub-PR are NOT written here (the architect re-uses the §1 task list, partitioned across the three sub-PRs).

### Sub-PR Bb — `BudgetGuard` per-user refactor (alfred-provider-engineer)

**Scope:** Spec §6 line 869's "PR Bb = `BudgetGuard` per-user refactor + call-site updates in `src/alfred/budget/` only."

**Files modified:** `src/alfred/budget/guard.py`, `src/alfred/cli/main.py` (only the `BudgetGuard(...)` construction site — call site #7 in the §0 enumeration), `tests/unit/budget/test_guard.py`, `tests/unit/budget/test_per_user_isolation.py` (new).

**Call sites in this sub-PR:** §0 sites #7 (CLI construction), #16 (test file).

**Out of scope:** the orchestrator does not yet call the per-user budget signature; PR Bb adds a temporary internal `_legacy_check_and_charge(cost_usd)` shim that resolves the operator's `user_id` from `settings.operator_name` so the slice-1 orchestrator keeps working. PR Bo deletes the shim.

**Acceptance gates:** unit tests green; CLI smoke (boot, no chat — `alfred user list` against migration-0004 backfilled state, asserts the operator's budget cap is per-user) green; slice-1 TUI smoke unchanged.

### Sub-PR Bm — `WorkingMemoryPool` + memory-side call sites (alfred-memory-engineer)

**Scope:** Spec §6 line 869's "PR Bm = `WorkingMemoryPool` + call-site updates in `src/alfred/memory/` and `src/alfred/orchestrator/`."

**Files modified:** `src/alfred/memory/working_pool.py` (new), `src/alfred/memory/episodic.py` (add `persona=` kwarg to `recent`), `src/alfred/orchestrator/core.py` (only the working-memory acquisition path — the orchestrator now takes a pool instead of a `WorkingMemory`, but keeps slice-1's `operator_name`/`operator_language`/`str` signature), `src/alfred/cli/main.py` (delete slice-1 rehydrate block; wire pool — call sites #8 partial), `tests/unit/memory/test_working_pool.py` (new), `tests/unit/orchestrator/test_core.py` (only the `_build` helper's WM-mock change).

**Call sites in this sub-PR:** §0 sites #1 partial (constructor adds pool, keeps operator-name), #8 partial (CLI wires pool, keeps slice-1 budget shim from Bb).

**Out of scope:** the orchestrator's `handle_user_message` signature is still slice-1 (`content: str`). PR Bo flips it.

**Acceptance gates:** unit tests green; concurrent-rehydrate property test green; slice-1 TUI smoke unchanged (the orchestrator now acquires WM from the pool, but the call signature is still `str`).

### Sub-PR Bo — Orchestrator contract change + persona prompt + remaining call sites (alfred-core-engineer + alfred-persona-engineer)

**Scope:** Spec §6 line 869's "PR Bo = orchestrator contract change + persona prompts + episodic/audit fields + remaining call sites."

**Files modified:** every remaining file from §0 — `src/alfred/orchestrator/core.py` (signature flip + per-user audit/episodic threading + persona prompt call + `UnknownBudgetUserError` audit branch), `src/alfred/personas/alfred.py` (`render_persona_prompt`), `src/alfred/cli/main.py` (final cleanup — delete shim, swap to `IdentityResolver`), `src/alfred/comms/tui.py` (Protocol + `_run_turn`), every test file's remaining call-site updates.

**Call sites in this sub-PR:** §0 sites #2, #3, #4, #5, #6, #9, #10, #11, #12, #13, #14, #15, #17, #18.

**Out of scope:** nothing — this is the closing sub-PR.

**Acceptance gates:** identical to the atomic plan's G1-G8.

### Safety net for either path (atomic or split)

- CI must pass on every call-site permutation before merge (no `--no-verify`).
- Slice-1 TUI smoke must stay green at every commit boundary.
- The PR description enumerates which call sites changed signature vs. which gained new behaviour (the §0 enumeration table is the canonical artifact — copy it into the PR description).
- Rollback for any sub-PR = `git revert` (each is self-contained per the spec §6 line 869 invariant).

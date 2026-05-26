# Slice 2 — PR A: Identity layer + ContextVar + ADRs — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. Each task names its owner agent and the spec section it implements.

**Goal:** Ship the multi-user identity layer (`users` + `platform_identities` tables, `IdentityResolver`, `IdentityVersionCounter`, `LISTEN/NOTIFY` plumbing with reconnect supervisor, `alfred user *` CLI subcommands), the ContextVar i18n refactor that unblocks per-coroutine language isolation, and the 5 Slice-2 ADRs (two with bodies, three placeholders). **Plumbing only — no Discord, no DLP, no compose changes.** After PR A merges, `bin/alfred-setup.sh` still produces a working TUI, but every audit row and episode now carries a canonical slug derived from `settings.operator_name` rather than the literal `"operator"`, and a CLI operator can pre-map household members ahead of the Discord work in PR D2.

**Spec:** [`docs/superpowers/specs/2026-05-26-slice-2-discord-multiuser-design.md`](../specs/2026-05-26-slice-2-discord-multiuser-design.md) — sections §0.1 (ContextVar prereq), §0.2 (ADR-0013 placeholder body), §2 (identity modules + LISTEN/NOTIFY + migration 0004), §3 (catalog enumerations: i18n per-user + `cli.user.*`), §4 (slug pipeline + CLI surface + setup-script bootstrap), §5 (unit + integration tests + ADR table + two-dispatch plan for docs-author), §6 (PR A row).

**Depends on:** `main` as of slice-1 (#89, #91, #92 merged — slice-1 catalog at `locale/en/LC_MESSAGES/alfred.po`; settings expose `operator_name`/`operator_language`/`daily_budget_usd`; migrations live at `0001..0003`). No earlier Slice-2 PR.

**Architecture:**

- New `src/alfred/identity/` package: `models.py` (SQLAlchemy 2.0 typed `User` + `PlatformIdentity`), `version_counter.py` (`IdentityVersionCounter`), `resolver.py` (`IdentityResolver` — in-process LRU + bump-on-mutate + `LISTEN/NOTIFY` listener supervisor with exponential-backoff reconnect), `cli.py` (Typer `alfred user *` subcommands), `rate_limit.py` (Protocol-only in PR A — `InProcessTokenBucketRateLimiter` ships in PR D1; we publish the Protocol here so PR B's `BudgetGuard` refactor can depend on it without ordering pain), `errors.py` (`OperatorAlreadyExistsError`, `LastOperatorRemovalRefusedError`, `OperatorSlugCollisionError`, `IdentityResolutionError`).
- Migration `0004_users_and_identities.py` is one transaction (`SET LOCAL statement_timeout = '60s'`) that creates both tables, adds `episodes.{language, persona_id}` + `audit_log.{language, persona_id}` columns (nullable on backfill), inserts the operator row deterministically from `settings.operator_name`/`operator_language`/`daily_budget_usd`, backfills `episodes.user_id` + `audit_log.actor_user_id` to the canonical slug, and refuses with a typed remediation message if any literal `user_id` slug-collides against a non-operator row.
- ContextVar refactor in `src/alfred/i18n/translator.py` is the per-coroutine isolation Slice 2 requires; it's an in-shape rewrite of the module-global `_active_lang`.
- ADRs: full bodies for ADR-0009 (`CommsAdapter` Protocol bounded to Slice 2) and ADR-0010 (slug-from-name + `LISTEN/NOTIFY` cross-process invalidation + listener reconnect supervisor + 60s TTL backstop). Frontmatter-only placeholder files for ADR-0011 (per-user `BudgetGuard`), ADR-0012 (file-backed `SecretBroker`), ADR-0013 (defer T1/T3/dual-LLM to Slice 3 + supersede ADR-0008 in part).

**Tech stack (PR A scope only):** Python 3.12+ • asyncio • Pydantic v2 • SQLAlchemy 2.0 typed (`Mapped[T]` + `mapped_column`) • alembic • Typer • babel (`Locale.parse` for BCP-47 validation) • `unidecode` (ASCII transliteration in the slug pipeline) • `psycopg[binary]` (already a slice-1 dep — used here for `LISTEN/NOTIFY`) • pytest + hypothesis + testcontainers • structlog (with the slice-1 redactor in front of every log path).

**Subagent owners:**

- Default — `alfred-python-developer` for plumbing tasks (the bulk of this PR).
- `alfred-security-engineer` for review on the `--replace-operator` transaction (last-operator-remove gate + atomic demote+promote), the `IdentityResolver.remove` soft-delete + `BudgetGuard.evict` contract (forward-published, consumed in PR B), and the migration-0004 collision-refusal path.
- `alfred-i18n-reviewer` for review on the ContextVar refactor (§0.1) and on the enumerated `cli.user.*` + `secrets.*` catalog additions (§3 row 514-532).
- `alfred-docs-author` for ADR-0009 + ADR-0010 bodies (PR A) — the placeholder ADRs (0011/0012/0013) ship frontmatter-only in PR A and get full bodies in PR E (two-dispatch plan, spec §5 line 835).

**Cross-PR contracts this PR publishes (PR B/C/D depend on these — do not change shape):**

- `IdentityResolver` public methods: `resolve(platform: str, platform_id: str) -> User | None`, `add(*, name: str, authorization: Authorization = Authorization.STANDARD, daily_budget_usd: float, language: str, rate_limit_per_min: int | None = None, rate_limit_per_day: int | None = None, slug_override: str | None = None) -> User`, `bind(slug: str, platform: Platform, platform_id: str) -> PlatformIdentity`, `unbind(slug: str, platform: Platform) -> None`, `remove(slug: str) -> None`, `set_(slug: str, **fields: object) -> User`, `get_operator() -> User`, `list_(include_deleted: bool = False) -> list[User]`, `show(slug: str) -> User`. Mutating methods bump `IdentityVersionCounter` and emit `NOTIFY alfred_identity_changed` in the same transaction.
- `User` ORM column list (frozen attribute names — PR B's `BudgetGuard` and `WorkingMemoryPool` key off these): `id`, `slug`, `display_name`, `authorization`, `daily_budget_usd`, `language`, `rate_limit_per_min`, `rate_limit_per_day`, `created_at`, `deleted_at`.
- `PlatformIdentity` ORM column list: `id`, `user_id`, `platform`, `platform_id`, `created_at`, `deleted_at`.
- `IdentityVersionCounter` public methods: `bump() -> None`, `current() -> int`.
- `Authorization` enum values: `READ_ONLY = "read_only"`, `STANDARD = "standard"`, `TRUSTED = "trusted"`, `OPERATOR = "operator"`. Snake_case on the wire/DB; kebab-case on CLI surface (Typer custom type normalises at the boundary).
- `Platform` enum values: `TUI = "tui"`, `DISCORD = "discord"`. (Telegram lands in Slice 4.)
- Error types: `OperatorAlreadyExistsError`, `LastOperatorRemovalRefusedError`, `OperatorSlugCollisionError(alembic.util.exc.CommandError)`, `IdentityResolutionError`. `SecretBrokerConfigError` + subtypes are **PR C's surface, not ours** — do not pre-create.
- `RateLimiter` Protocol surface: `async def allow(user: User) -> bool`, `async def reset(user_id: str) -> None`, `def health() -> RateLimiterHealth`. (Note: takes the full `User` object — see spec §2 architect-002, line 223 — so the `read_only` security gate doesn't depend on a per-call kwarg.) PR D1 ships `InProcessTokenBucketRateLimiter`; PR A ships only the Protocol + a `_NullRateLimiter` test double so the `RateLimiter` import in `resolver.py` resolves.
- Slug derivation pipeline (PR B's tests pin slugs to these outputs): NFKC normalise → `unidecode` ASCII transliterate → lowercase → `re.sub(r"[^a-z0-9]+", "-", s)` → trim leading/trailing `-` → collapse `-+` to `-` → truncate to 63 chars → collision suffix (`-2`, `-3`, …). Examples (pinned): `"Alice O'Connor"` → `"alice-o-connor"`; `"José Núñez"` → `"jose-nunez"`; `"田中"` → `"tian-zhong"`; `"___bob---"` → `"bob"`; `"🌟🎉"` → `"user"` (fallback) → `"user-2"` if `user` taken.

---

## 0. Files this PR creates or modifies

**Group 1 — `src/alfred/identity/` package (new):**

- `src/alfred/identity/__init__.py` — package init; re-exports `User`, `PlatformIdentity`, `Authorization`, `Platform`, `IdentityResolver`, `IdentityVersionCounter`, `IdentityListener`, `RateLimiter`, `RateLimiterHealth`, the four error types.
- `src/alfred/identity/models.py` — SQLAlchemy 2.0 typed ORMs (`User`, `PlatformIdentity`) + `Authorization` + `Platform` Python enums (subclass `str, Enum` so they serialise to TEXT CHECK-constrained columns).
- `src/alfred/identity/errors.py` — `IdentityError` base (rooted at `AlfredError`), `OperatorAlreadyExistsError`, `LastOperatorRemovalRefusedError`, `OperatorSlugCollisionError(alembic.util.exc.CommandError)`, `IdentityResolutionError`.
- `src/alfred/identity/slug.py` — pure-function `derive_slug(name: str) -> str` (NFKC → unidecode → lowercase → regex → trim → truncate-to-63). Collision suffixing lives in `resolver.py` because it needs DB access.
- `src/alfred/identity/version_counter.py` — `IdentityVersionCounter`: monotonic `int` with `bump()` / `current()`. In-process; cross-process invalidation rides on `LISTEN/NOTIFY`.
- `src/alfred/identity/resolver.py` — `IdentityResolver` with in-process LRU cache (max 256) + selective per-entry invalidation on counter bump + bump-on-mutate + transaction-scoped `NOTIFY alfred_identity_changed` on every mutation. Includes `IdentityListener` (background asyncio task running `LISTEN alfred_identity_changed` with an exponential-backoff reconnect supervisor, 1s → 60s cap). 60s TTL backstop on every cache read independent of listener health.
- `src/alfred/identity/rate_limit.py` — `RateLimiter` Protocol + `RateLimiterHealth` frozen dataclass + `_NullRateLimiter` test double. **No** `InProcessTokenBucketRateLimiter` in PR A — that lands in PR D1.
- `src/alfred/identity/cli.py` — Typer `alfred user *` subcommands: `add`, `list`, `show`, `remove`, `bind`, `unbind`, `set`. Kebab-vs-snake normalisation at the option-callback boundary. Calls into `IdentityResolver`; never reaches into the ORM directly.

**Group 2 — Migration (new):**

- `src/alfred/memory/migrations/versions/0004_users_and_identities.py` — single-transaction upgrade with `SET LOCAL statement_timeout = '60s'`, creating the two tables + the four new columns + the operator backfill + the slug pre-check. `down_revision = "0003"`. Idempotent (`ON CONFLICT (slug) DO NOTHING` on the operator insert; re-runnable upgrade).

**Group 3 — Existing files modified (light touches):**

- `src/alfred/i18n/translator.py` — promote `_active_lang` from module global to `ContextVar[str]`; `set_language` → `.set()`; `t()` → `.get()`. No other shape change.
- `src/alfred/cli/main.py` — register the `user` Typer sub-app from `alfred.identity.cli`; drive-by fix of the line-54 `t()` leak (`typer.Typer(help="AlfredOS CLI", no_args_is_help=True)` → `typer.Typer(help=t("cli.help.root"), no_args_is_help=True)`).
- `src/alfred/memory/episodic.py` — accept + persist `language` + `persona_id` on `record()` (default `persona_id="alfred"` for Slice-2 callers; `language=user.language` plumbed by the orchestrator in PR B; the PR-A change is the column-write only).
- `src/alfred/audit/writer.py` — accept + persist `language` + `persona_id` on `append()` (same shape as episodic).
- `src/alfred/comms/tui.py` — call `IdentityResolver.resolve("tui", settings.operator_name)` at startup; on `None`, exit with the friendly hint pointing at `alfred user add --authorization operator` (spec §4 line 774-776). Per-turn flow inside `AlfredTuiApp` is unchanged in PR A — PR B does the `handle_user_message` signature flip; PR A only changes startup-time resolution + replaces the literal `"operator"` user_id with `user.slug`.
- `locale/en/LC_MESSAGES/alfred.po` — add the enumerated `cli.user.*`, `cli.help.root`, `cli.setup.*`, and BCP-47 ingress-validation keys spelled out in spec §3 (line 506-536). `pybabel extract` is the source of truth; the manual additions get rewritten by extract; the test asserts every spec-named key resolves.

**Group 4 — ADRs (new):**

- `docs/adr/0009-comms-adapter-protocol-slice2-only.md` — full body (`alfred-docs-author` dispatch 1).
- `docs/adr/0010-canonical-user-id-and-listen-notify.md` — full body (`alfred-docs-author` dispatch 1).
- `docs/adr/0011-per-user-budget-guard.md` — frontmatter + "TBD body, see PR E".
- `docs/adr/0012-file-backed-secret-broker.md` — frontmatter + "TBD body, see PR E".
- `docs/adr/0013-defer-t1-t3-and-dual-llm.md` — frontmatter + the functional placeholder body inlined verbatim from spec §0.2 (line 27-51).

**Group 5 — Tests (new):**

- `tests/unit/i18n/test_concurrent_language.py` — proves per-coroutine isolation under `asyncio.gather` (the TDD driver for Task 1).
- `tests/unit/identity/__init__.py` — empty package init.
- `tests/unit/identity/test_slug.py` — slug pipeline edge-case enumeration (Unicode, emoji-only, length cap, internal dashes, repeated dashes).
- `tests/unit/identity/test_resolver.py` — slug-collision suffixing, `resolve` happy/miss/soft-deleted, LRU selective invalidation on counter bump, BCP-47 validation, `get_operator()` zero/one/multi, version counter bump per mutating method, last-operator-remove refusal, upper-bound operator guard (`OperatorAlreadyExistsError`), `--replace-operator` demote-and-promote atomicity, listener reconnect-on-connection-loss (err-001).
- `tests/unit/identity/test_cli.py` — every subcommand happy + error path; kebab/snake normalisation; non-TTY without `--yes`; `--output-slug` JSON contract; `--language wat-NOT-VALID` rejection; audit-row shape on every mutation.
- `tests/unit/identity/test_version_counter.py` — monotonic-bump invariant; concurrent bump-and-read property test.
- `tests/integration/test_users_postgres.py` — `User` + `PlatformIdentity` CRUD against testcontainer Postgres; CHECK / UNIQUE constraints; `LISTEN/NOTIFY` round-trip across two sessions.
- `tests/integration/test_migration_0004_backfill.py` — four cases (a) custom `ALFRED_OPERATOR_NAME` happy path; (b) default `"operator"` no-op; (c) non-operator slug-collision refusal with the spec'd remediation message; (d) ADD COLUMN coverage on pre-existing rows + downgrade-drops-cleanly invariant (te-001, spec §5 line 805).
- `tests/smoke/test_hello_alfred.py` (modify) — create the operator via `IdentityResolver.add` (or rely on migration 0004's automatic backfill), drive the orchestrator with the resolved slug, assert episode + audit rows carry the canonical slug (not literal `"operator"`).

---

## 1. Task sequence

### Task 1: ContextVar refactor for `_active_lang` (spec §0.1) — PR-A commit 1

**Owner:** `alfred-python-developer`; review by `alfred-i18n-reviewer`.

**Why first:** every downstream task that calls `set_language` (resolver's WARN-once-per-user path, CLI's `--language` callback, the test fixtures that simulate multiple users) needs the per-coroutine isolation guarantee. Shipping it as commit 1 means no later task accidentally relies on the buggy module-global semantics.

**Files:**

- Modify: `src/alfred/i18n/translator.py`.
- Create: `tests/unit/i18n/test_concurrent_language.py`.

**Steps:**

- [ ] **Step 1.1 — Write the failing concurrent-isolation test.**

  Create `tests/unit/i18n/test_concurrent_language.py` with the test below. The assertion is shape-level (each coroutine sees its own active language at every `t()` call between `await` points); the catalog assertion will be tightened in Task 5 once the `cli.user.added` key exists in `alfred.po`.

  ```python
  """Per-coroutine isolation of the active language (spec §0.1).

  Pre-refactor: ``_active_lang`` is a module-global, so the second coroutine's
  ``set_language()`` clobbers the first under interleaving — Bob's German bleeds
  into Alice's English between the ``await`` points. Post-refactor (ContextVar)
  asyncio propagates the per-coroutine value across ``await`` automatically,
  so each handler sees its own language without any handler-side bookkeeping.
  """

  from __future__ import annotations

  import asyncio

  import pytest

  from alfred.i18n.translator import set_language, t


  @pytest.mark.asyncio
  async def test_set_language_isolates_per_coroutine() -> None:
      """Two interleaved coroutines must each see their own language.

      Property: at every ``await`` point inside coroutine A, ``t()`` resolves
      against A's set language, regardless of what coroutine B has done in the
      meantime. Pre-refactor this test fails because the second ``set_language``
      call clobbers the global; post-refactor it passes because each coroutine
      runs in its own ContextVar context.
      """

      async def alice() -> tuple[str, str]:
          set_language("de-DE")
          before = t("cli.help.root")  # may be the key itself if the catalog is empty.
          await asyncio.sleep(0)        # yield — bob runs and would clobber the global.
          after = t("cli.help.root")
          return before, after

      async def bob() -> tuple[str, str]:
          set_language("en-US")
          before = t("cli.help.root")
          await asyncio.sleep(0)
          after = t("cli.help.root")
          return before, after

      alice_result, bob_result = await asyncio.gather(alice(), bob())
      # Shape assertion: each coroutine's pre- and post-yield t() resolve identically.
      # Pre-refactor this fails because bob's set_language("en-US") leaks into alice's
      # post-yield call (alice would see English, not German, after the yield).
      assert alice_result[0] == alice_result[1], (
          f"alice's language leaked across await: {alice_result!r}"
      )
      assert bob_result[0] == bob_result[1], (
          f"bob's language leaked across await: {bob_result!r}"
      )
  ```

- [ ] **Step 1.2 — Run the test and confirm it FAILS on the current module-global.**

  ```bash
  uv run pytest tests/unit/i18n/test_concurrent_language.py -v
  ```

  Expected: at least one of the `assert ... leaked across await` assertions fires.

- [ ] **Step 1.3 — Promote `_active_lang` to `ContextVar` in `src/alfred/i18n/translator.py`.**

  Apply this edit (replace the module-global declaration on line 64 and the `set_language`/`t()` access points):

  ```python
  # Top of module — add this import next to the stdlib block:
  from contextvars import ContextVar

  # Replace line 64 (`_active_lang: str = "en-US"`) with:
  _active_lang: ContextVar[str] = ContextVar("alfred_active_lang", default="en-US")

  # Replace `set_language` (lines 89-92):
  def set_language(lang: str) -> None:
      """Activate the given BCP-47 language tag for subsequent ``t()`` calls.

      Implemented as a ``ContextVar.set()`` so each coroutine sees its own
      language — asyncio propagates ContextVars across ``await`` automatically,
      so multi-user Slice-2 handlers (Discord DMs, CLI commands running under
      ``asyncio.gather``) do not cross-contaminate.
      """
      _active_lang.set(lang)

  # In `t()` (line 101), replace `_active_lang` with `_active_lang.get()`:
  translator = _load(_active_lang.get())
  ```

  No other shape change. `_translators` cache stays a module-level `dict` (it's idempotent — same BCP-47 → same `gettext.translation` instance).

- [ ] **Step 1.4 — Run the test and confirm it PASSES.**

  ```bash
  uv run pytest tests/unit/i18n/test_concurrent_language.py -v
  ```

  Expected: green.

- [ ] **Step 1.5 — Run the full slice-1 i18n suite for regression.**

  ```bash
  uv run pytest tests/unit/i18n/ -v
  ```

  Expected: every existing slice-1 test stays green.

- [ ] **Step 1.6 — Commit (PR-A commit 1).**

  ```bash
  git add src/alfred/i18n/translator.py tests/unit/i18n/test_concurrent_language.py
  git commit -m "refactor(i18n): promote _active_lang to ContextVar for per-coroutine isolation (#<issue>)"
  ```

---

### Task 2: ADR-0013 placeholder (spec §0.2) — PR-A commit 2

**Owner:** `alfred-python-developer` (mechanical placeholder; full body deferred to PR E per the two-dispatch plan).

**Why second:** the supersession edge to ADR-0008 must exist on `main` before any later Slice-2 PR cites ADR-0013; doing it on commit 2 (before any code change) keeps the paper-trail order intact.

**Files:** Create `docs/adr/0013-defer-t1-t3-and-dual-llm.md`.

**Steps:**

- [ ] **Step 2.1 — Create the ADR file with the inlined placeholder body from spec §0.2 (line 27-51).**

  ```markdown
  # 0013 — Defer T1 operator tier, T3 untrusted ingestion, and dual-LLM split to Slice 3

  - **Status**: Accepted
  - **Date**: 2026-05-26
  - **Slice**: 2 — `docs/superpowers/plans/2026-05-26-slice-2-pr-A-identity.md`
  - **Supersedes**: ADR-0008 (in part)
  - **Superseded by**: —

  ## Decision (summary)

  Slice 2 ships multi-user identity (T2 only), Discord adapter, file-backed secret broker. T1, T3, and the
  dual-LLM split — committed by ADR-0008 to land in Slice 2 — are rescheduled to Slice 3.

  ## Rationale (one-line)

  The Slice-2 surface area (identity + Discord + file broker) is already large enough for one slice; the
  dual-LLM split without the upstream MCP plugin transport (Slice 3) is wasted scaffolding that Slice 3 rewrites.

  ## Author

  `alfred-docs-author` writes the full body in PR E from the [Slice 2 design spec §0](../superpowers/specs/2026-05-26-slice-2-discord-multiuser-design.md#0-slice-2-prerequisites-land-before-anything-else).
  The placeholder above is sufficient for PRs B-D to cite. Long-form rationale, alternatives, and consequences
  land in PR E.
  ```

- [ ] **Step 2.2 — Amend ADR-0008's status banner to record the partial supersession.**

  Add a single line under ADR-0008's status frontmatter (preserve everything else):

  ```diff
  - **Status**: Accepted
  + **Status**: Accepted (superseded in part by ADR-0013 — Slice-2 commitment to T1+T3+dual-LLM rescheduled to Slice 3)
  ```

  Locate the exact existing status line first via:

  ```bash
  grep -n "^- \*\*Status\*\*" docs/adr/0008-llm-output-trust-tier.md
  ```

  Edit by replacing that exact line.

- [ ] **Step 2.3 — Commit (PR-A commit 2).**

  ```bash
  git add docs/adr/0013-defer-t1-t3-and-dual-llm.md docs/adr/0008-llm-output-trust-tier.md
  git commit -m "docs(adr): ADR-0013 placeholder supersedes ADR-0008 Slice-2 commitment (#<issue>)"
  ```

---

### Task 3: ADR-0009 + ADR-0010 bodies + ADR-0011/0012 placeholders — PR-A commit 3

**Owner:** `alfred-docs-author` (dispatch 1 of the two-dispatch plan, spec §5 line 835).

**Why third:** PR B's `BudgetGuard` refactor and PR C's `SecretBroker` file backend cite ADR-0011 and ADR-0012 numbers respectively; if those numbers don't yet exist on `main`, the cross-references in PR-B/-C bodies dangle. Reserving the seats now (frontmatter-only) costs ~20 lines per file and unblocks every later PR.

**Files:**

- Create `docs/adr/0009-comms-adapter-protocol-slice2-only.md` — full body.
- Create `docs/adr/0010-canonical-user-id-and-listen-notify.md` — full body.
- Create `docs/adr/0011-per-user-budget-guard.md` — frontmatter placeholder.
- Create `docs/adr/0012-file-backed-secret-broker.md` — frontmatter placeholder.

**Steps:**

- [ ] **Step 3.1 — Author ADR-0009 body.** Required sections (use the existing ADR-0008 layout for shape — `Status / Date / Slice`, `Context`, `Decision`, `Consequences`, `Alternatives considered`, `References`):

  - **Context:** PRD §5 lists "Plugins are MCP servers (comms adapters, …)" as a non-negotiable architectural invariant. Slice 2 ships in-process Python comms adapters (TUI today, Discord next) because the MCP transport itself doesn't land until Slice 3. The deviation needs an explicit, bounded record.
  - **Decision:** Define `CommsAdapter` as an in-process Python `Protocol` (`name: str`, `start/run/stop` async methods, `health() -> AdapterHealth` sync snapshot). Slice 2 ships two implementations (`TuiAdapter`, `DiscordAdapter`) behind that Protocol. **No call site outside `src/alfred/comms/` may import the concrete adapter classes directly** — the import-isolation test (`tests/unit/comms/test_no_direct_adapter_imports.py`, PR D1) enforces this; PR A does NOT need this test (no Discord adapter to gate yet) but the rule is documented here so PR D1's test lands against an existing ADR.
  - **Consequences:** Single-module rewrite at Slice 3 (in-process Python → MCP RPC); Slice 3 reviewer-gate re-checks PRD §5 clean. The Slice-3 Protocol shape inverts polarity (adapter becomes RPC server, orchestrator becomes client) so this Slice-2 Protocol shape is explicitly NOT preserved across slices.
  - **Alternatives considered:** (1) Ship MCP transport in Slice 2 — rejected, doubles slice surface area; (2) Hardcode TUI + Discord with no Protocol — rejected, Slice 3 rewrite becomes a multi-module sprawl.
  - **References:** PRD §5, PRD §6.1, ADR-0008, spec §2 line 99-122, spec §3 line 315-417.

- [ ] **Step 3.2 — Author ADR-0010 body.** Required sections:

  - **Context:** Slice 2 introduces multi-user identity. Two design questions arise: (a) what shape is the canonical user_id, and (b) how do CLI mutations propagate to the long-running `alfred-discord` process so its in-process caches don't serve stale rows.
  - **Decision:**
    - **Canonical user_id is a slug derived from the display name** (NFKC → unidecode → lowercase → regex non-alphanum → trim → truncate 63 → collision suffix). Not UUID — operator-readable in `alfred audit log --user bob` is worth the one-time collision-check cost.
    - **Cross-process cache invalidation uses PostgreSQL `LISTEN/NOTIFY`** on channel `alfred_identity_changed`. Every mutating CLI command issues `NOTIFY` inside the same transaction as the data write; `alfred-discord` runs a background listener that bumps its local `IdentityVersionCounter` on receipt. Payload is a small JSON `{"slug": "...", "op": "add|set|remove|bind|unbind"}` used only as a hint — the next resolver call refetches from the row of record.
    - **Listener resilience: exponential-backoff reconnect supervisor** (1s start, ×2 each failure, 60s cap, reset on successful `LISTEN`). One-shot `WARN` log per disconnect; `discord_identity_listener_reconnects_total` counter exposes outage rate. CLAUDE.md hard rule #7 (no silent failures in security paths) is honoured — a dropped listener can't silently age out soft-delete invalidations.
    - **60s TTL backstop** runs unconditionally — on every `IdentityResolver.resolve()` and every `BudgetGuard.consume()` call (BudgetGuard is PR B), compare `now() - entry.cached_at` against `Settings.identity_cache_ttl_s` (default 60). Expired entries refetch regardless of listener health. Reset on both initial fill AND NOTIFY-driven update. PgBouncer transaction-pooling deployments (where `LISTEN/NOTIFY` does not work) get the same staleness ceiling.
  - **Consequences:** Operator-readable user_ids in logs; one-time slug-collision-suffix cost on `add`; deterministic LISTEN-or-TTL invalidation contract for every downstream cache.
  - **Alternatives considered:** UUID (rejected, debuggability cost); ULID (rejected, same); polling `users.updated_at` (rejected — every poll is a wasted DB round-trip, and TTL plus event-driven invalidation strictly dominates).
  - **References:** PRD §7.2, spec §2 line 156-168, spec §4 line 585-604, spec §4 line 767-772.

- [ ] **Step 3.3 — Create ADR-0011 placeholder.**

  ```markdown
  # 0011 — Per-user BudgetGuard (dict-keyed counter; `_spent`/`_day` never evict)

  - **Status**: Accepted
  - **Date**: 2026-05-26
  - **Slice**: 2 — `docs/superpowers/plans/2026-05-26-slice-2-pr-A-identity.md`
  - **Supersedes**: —
  - **Superseded by**: —

  ## Decision (summary)

  Slice 2 makes `BudgetGuard` per-user (`dict[str, _UserBudget]` keyed on canonical slug; per-call cap stays global; `_spent`/`_day` are the security-invariant source of truth and are NEVER evicted; only `daily_usd` cap is cache-able and refreshes on `IdentityVersionCounter` bump).

  ## Author

  Full body lands in PR E. Placeholder reserves the ADR number so PR B's body can cite it without a forward-dangling reference.
  ```

- [ ] **Step 3.4 — Create ADR-0012 placeholder.**

  ```markdown
  # 0012 — File-backed SecretBroker at `~/.config/alfred/secrets.toml`

  - **Status**: Accepted
  - **Date**: 2026-05-26
  - **Slice**: 2 — `docs/superpowers/plans/2026-05-26-slice-2-pr-A-identity.md`
  - **Supersedes**: —
  - **Superseded by**: —

  ## Decision (summary)

  Slice 2 adds a file backend to `SecretBroker` (`~/.config/alfred/secrets.toml`, 0600 perms, plaintext-with-fail-closed-perms-check). Env wins on conflict for slice-1 keys; new Slice-2+ keys (`discord_bot_token`) prefer file over env. POSIX-ACL non-coverage is documented as a known gap. Age-encryption is deferred to Slice 3+.

  ## Author

  Full body lands in PR E. Placeholder reserves the ADR number so PR C's body can cite it without a forward-dangling reference.
  ```

- [ ] **Step 3.5 — Run a sanity check on every ADR's frontmatter shape.**

  ```bash
  for f in docs/adr/0009-*.md docs/adr/0010-*.md docs/adr/0011-*.md docs/adr/0012-*.md docs/adr/0013-*.md; do
    echo "== $f =="
    grep -E "^- \*\*(Status|Date|Slice|Supersedes|Superseded by)\*\*" "$f" || echo "  MISSING FRONTMATTER"
  done
  ```

  Every file must have all five frontmatter lines.

- [ ] **Step 3.6 — Commit (PR-A commit 3).**

  ```bash
  git add docs/adr/0009-comms-adapter-protocol-slice2-only.md \
          docs/adr/0010-canonical-user-id-and-listen-notify.md \
          docs/adr/0011-per-user-budget-guard.md \
          docs/adr/0012-file-backed-secret-broker.md
  git commit -m "docs(adr): ADR-0009/0010 bodies + ADR-0011/0012 placeholders (#<issue>)"
  ```

---

### Task 4: Catalog skeleton + drive-by `cli/main.py:54` fix — PR-A commit 4

**Owner:** `alfred-python-developer` (review: `alfred-i18n-reviewer`).

**Why fourth:** every later task (`IdentityResolver` WARN-once, `alfred user *` help text, CLI error messages, migration remediation string) calls `t()` against keys that must exist before the catalog-drift check (`pybabel compile --check`) goes green. We add ALL `cli.user.*` + `cli.help.root` + `cli.setup.*` keys with English bodies in one commit, then the implementing tasks can land call-sites against an already-extracted catalog.

**Files:**

- Modify: `src/alfred/cli/main.py` (line 54 leak).
- Modify: `locale/en/LC_MESSAGES/alfred.po` (add the keys; `pybabel extract` will regenerate from sources but the initial English bodies live here).

**Steps:**

- [ ] **Step 4.1 — Fix the line-54 `t()` leak in `cli/main.py`.**

  Edit the offending line:

  ```python
  # OLD:
  app = typer.Typer(help="AlfredOS CLI", no_args_is_help=True)

  # NEW:
  app = typer.Typer(help=t("cli.help.root"), no_args_is_help=True)
  ```

  This is the convention rule for every future Typer Option `help=` + command `help=` (spec §3 line 534).

- [ ] **Step 4.2 — Add the enumerated `cli.help.root` + `cli.user.*` keys to `locale/en/LC_MESSAGES/alfred.po`.**

  Keys to add (every one named explicitly per spec §3 line 514-532 — no wildcards; `pybabel extract` cannot infer a key it has never seen):

  **Group help:**
  - `cli.help.root` → `"AlfredOS CLI"`
  - `cli.user.help.group` → `"Manage AlfredOS users and their platform bindings."`

  **Per-subcommand short + long help (14 keys: `cli.user.help.<subcommand>.short` + `.long` for each of `add`, `list`, `show`, `remove`, `bind`, `unbind`, `set`):**
  - `cli.user.help.add.short` → `"Add a new user (optionally binding a platform identity in the same transaction)."`
  - `cli.user.help.add.long` → `"Add a new user and derive their canonical slug from the display name. If --discord-id is passed, the bind happens in the same SQL transaction as the user insert so a UNIQUE conflict rolls back the user row too."`
  - `cli.user.help.list.short` → `"List active users (rich.Table by default; --json for scripting)."`
  - `cli.user.help.list.long` → `"List active users sorted by created_at ASC. Soft-deleted rows excluded unless --include-deleted; --json emits a stable JSON array suitable for piping into jq."`
  - `cli.user.help.show.short` → `"Show one user with override-vs-derived rate-limit indicators."`
  - `cli.user.help.show.long` → `"Show the full record for one user, including platform bindings and an explicit indicator on rate-limit fields showing whether the value is a per-user override or the authorization-derived default."`
  - `cli.user.help.remove.short` → `"Soft-delete a user (refuses if target is the last operator)."`
  - `cli.user.help.remove.long` → `"Soft-delete a user (sets deleted_at; preserves audit history). Refuses with exit code 2 if the target is the last authorization='operator' user. Confirms by default; exits 2 under non-TTY without --yes."`
  - `cli.user.help.bind.short` → `"Bind a platform identity (e.g. a Discord snowflake) to an existing user."`
  - `cli.user.help.bind.long` → `"Bind a platform identity to an existing user. Refuses on existing platform_id conflict (use 'alfred user unbind' first) or if the user is already bound on the named platform."`
  - `cli.user.help.unbind.short` → `"Remove a platform binding from a user."`
  - `cli.user.help.unbind.long` → `"Soft-delete the platform_identities row for (user, platform); the platform_id becomes reusable by another user."`
  - `cli.user.help.set.short` → `"Tune an existing user's daily budget, authorization, language, or rate-limit overrides."`
  - `cli.user.help.set.long` → `"Tune an existing user. Pass --rate-limit-per-min unset to revert an override to the authorization-derived default. --replace-operator <slug> required to promote a second user to operator (the named existing operator is demoted to 'trusted' in the same audit-logged transaction)."`

  **Option flag help (~24 keys: `cli.user.flag.<name>.<short|long>` for `name`, `discord-id`, `authorization`, `daily-budget-usd`, `language`, `rate-limit-per-min`, `rate-limit-per-day`, `platform`, `id`, `json`, `include-deleted`, `yes`):**
  - `cli.user.flag.name.short` → `"Display name (will be slug-derived for the canonical user_id)."`
  - `cli.user.flag.name.long` → `"Display name. Preserved verbatim with original casing and spacing for the persona prompt. Slug-derived for canonical user_id (NFKC → ASCII-transliterate → lowercase → regex → trim → 63-char truncate → collision suffix)."`
  - `cli.user.flag.discord-id.short` → `"Discord snowflake to bind (atomic with user add)."`
  - `cli.user.flag.discord-id.long` → `"Discord snowflake (e.g. 123456789012345678). Bound in the same transaction as the user insert so a UNIQUE conflict rolls back both."`
  - `cli.user.flag.authorization.short` → `"Authorization tier (read-only | standard | trusted | operator; default standard)."`
  - `cli.user.flag.authorization.long` → `"Authorization tier controls per-user budget defaults and rate-limit defaults. read-only users get zero replies (audit-logged); operator inherits the slice-1 global cap. Accepts kebab-case (read-only) or snake_case (read_only); both normalise to the snake_case enum value."`
  - `cli.user.flag.daily-budget-usd.short` → `"Per-user daily budget cap in USD (default 0.50)."`
  - `cli.user.flag.daily-budget-usd.long` → `"Per-user daily budget cap. Must be positive. Default 0.50 (raised from slice-1 default 0.10 per spec §7); operator inherits settings.daily_budget_usd as their per-user cap. Per-call cap remains global (settings.per_call_max_usd)."`
  - `cli.user.flag.language.short` → `"BCP-47 language tag (e.g. en-US, de-DE; default operator's language)."`
  - `cli.user.flag.language.long` → `"BCP-47 language tag. Validated at ingress via babel.Locale.parse. If the catalog does not ship the named language, the CLI warns-with-confirm under interactive TTY (--no-warn-missing-catalog to skip)."`
  - `cli.user.flag.rate-limit-per-min.short` → `"Override the authorization-derived messages-per-minute cap."`
  - `cli.user.flag.rate-limit-per-min.long` → `"Per-user messages-per-minute cap. NULL means use the authorization-derived default (read-only=0, standard=30, trusted=60, operator=unlimited). Pass 'unset' on 'user set' to revert."`
  - `cli.user.flag.rate-limit-per-day.short` → `"Opt-in hard ceiling on messages-per-day (default off)."`
  - `cli.user.flag.rate-limit-per-day.long` → `"Per-user messages-per-day cap. NULL means no day-cap (BudgetGuard.daily_budget_usd owns the cost ceiling); set an integer for an opt-in hard ceiling above the cost cap."`
  - `cli.user.flag.platform.short` → `"Platform name (tui | discord)."`
  - `cli.user.flag.platform.long` → `"Platform name. Slice 2 supports tui and discord; Telegram lands in Slice 4."`
  - `cli.user.flag.id.short` → `"Platform identifier (Discord snowflake / TUI operator name)."`
  - `cli.user.flag.id.long` → `"Platform identifier. For Discord, the user's snowflake. For TUI, the operator_name from settings."`
  - `cli.user.flag.json.short` → `"Emit machine-readable JSON instead of a table."`
  - `cli.user.flag.json.long` → `"Emit a stable JSON array (one object per user) instead of the rich.Table. Suitable for piping into jq for setup-script automation."`
  - `cli.user.flag.include-deleted.short` → `"Include soft-deleted users (strikethrough in the table)."`
  - `cli.user.flag.include-deleted.long` → `"Include rows with non-null deleted_at; rendered with strikethrough in the table and a 'deleted_marker' annotation in JSON."`
  - `cli.user.flag.yes.short` → `"Skip the confirmation prompt (required under non-TTY)."`
  - `cli.user.flag.yes.long` → `"Skip the confirmation prompt for destructive operations. Required under non-TTY (exit 2 otherwise)."`
  - `cli.user.flag.output-slug.short` → `"Print only the derived slug to stdout (for setup-script scripting)."`
  - `cli.user.flag.output-slug.long` → `"Print only the derived slug to stdout (no table, no audit-row echo). Used by bin/alfred-setup.sh to capture the canonical slug for the follow-up bind command."`
  - `cli.user.flag.replace-operator.short` → `"Demote the named existing operator while promoting this user (atomic)."`
  - `cli.user.flag.replace-operator.long` → `"Promote this user to operator. The named existing operator is demoted to 'trusted' in the same audit-logged SQL transaction so the resolver state never has zero or two operators."`
  - `cli.user.flag.slug-override.short` → `"Override the derived slug with a memorable handle (use after a slug fallback warning)."`
  - `cli.user.flag.slug-override.long` → `"Override the derived slug with a memorable handle. Use when the slug pipeline falls back to 'user' (e.g. emoji-only name) and the CLI emits cli.user.add.slug_fallback. The override still passes through collision suffixing."`

  **Success / confirmation:**
  - `cli.user.added` → `"Added user {display_name} (slug={slug}, authorization={authorization})."`
  - `cli.user.bound` → `"Bound {platform} identity {platform_id} to user {slug}."`
  - `cli.user.unbound` → `"Removed {platform} binding from user {slug}."`
  - `cli.user.removed` → `"Removed user {slug} (soft-delete; audit history preserved)."`
  - `cli.user.set.success` → `"Updated user {slug}: {diff}."`
  - `cli.user.remove.confirm` → `"Remove user {slug} ({display_name})? This soft-deletes the row; episode and audit history are preserved. [y/N]: "`
  - `cli.user.operator_replaced` → `"Promoted {new_slug} to operator; demoted {old_slug} to trusted."`
  - `cli.user.add.slug_fallback` → `"Display name produced an empty slug; falling back to '{slug}'. Use --slug-override to pick a memorable handle."`
  - `cli.user.add.slug_adjusted` → `"Note: slug adjusted to '{slug}' because '{base}' already exists (soft-deleted users retain their slug). Use this slug for follow-up commands."`

  **Errors:**
  - `cli.user.error.not_found` → `"No user with slug '{slug}'."`
  - `cli.user.error.platform_id_in_use` → `"Platform identity {platform}:{platform_id} is already bound to user '{existing_slug}'."`
  - `cli.user.error.user_already_bound` → `"User '{slug}' is already bound on platform '{platform}'. Run 'alfred user unbind {slug} --platform {platform}' first."`
  - `cli.user.error.invalid_authorization` → `"Invalid authorization '{value}'. Choose one of: read-only, standard, trusted, operator."`
  - `cli.user.error.invalid_language` → `"Invalid BCP-47 language tag '{value}'. Examples: en-US, de-DE, ja-JP."`
  - `cli.user.error.invalid_bcp47` → `"BCP-47 parse failed for '{value}': {detail}."`
  - `cli.user.error.budget_must_be_positive` → `"--daily-budget-usd must be > 0; got {value}."`
  - `cli.user.error.no_operator` → `"No operator has been added yet. Run 'alfred user add --authorization operator --name <YourName>' first."`
  - `cli.user.error.no_tty_without_yes` → `"This command is running under a non-TTY; pass --yes to skip the confirmation prompt."`
  - `cli.user.error.operator_already_exists` → `"An operator already exists ('{existing_slug}' — {existing_display_name}). Pass --replace-operator {existing_slug} to atomically demote them while promoting this user."`
  - `cli.user.error.remove_last_operator_refused` → `"Refused to remove the last operator '{slug}'. Promote another user to operator first (alfred user set <other> --authorization operator --replace-operator {slug})."`

  **`alfred user list` table chrome (i18n-001; spec §3 line 527):**
  - `cli.user.list.column.slug` → `"slug"`
  - `cli.user.list.column.display_name` → `"display name"`
  - `cli.user.list.column.authorization` → `"authorization"`
  - `cli.user.list.column.daily_budget_usd` → `"daily budget (USD)"`
  - `cli.user.list.column.platforms` → `"platforms"`
  - `cli.user.list.column.language` → `"language"`
  - `cli.user.list.empty_hint` → `"No users yet. Run 'alfred user add --authorization operator --name <YourName>' to add the operator."`
  - `cli.user.list.deleted_marker` → `"(deleted)"`
  - `cli.user.list.no_platforms` → `"(none)"`
  - `cli.user.list.catalog_missing_annotation` → `"(no catalog)"`

  **`alfred user show` annotations (spec §3 line 528):**
  - `cli.user.show.override_indicator` → `"(override)"`
  - `cli.user.show.derived_indicator` → `"(derived from authorization)"`
  - `cli.user.show.value.unset` → `"(unset)"`
  - `cli.user.show.platforms_none` → `"No platform bindings."`

  **BCP-47 catalog-missing warning (devex-003; spec §3 line 529):**
  - `cli.user.warn.catalog_missing` → `"Language '{language}' has no shipped catalog. Operator-facing chrome will render in English; model output will still be requested in the user's language. Continue? [y/N]: "`

  **Setup script (spec §3 line 530):**
  - `cli.setup.operator_added` → `"Operator added as canonical user '{slug}' (display name: {display_name})."`
  - `cli.setup.operator_name_prompt` → `"Operator display name [Operator]: "`
  - `cli.setup.discord_bind_hint` → `"Discord snowflake to bind now (Settings > Advanced > Developer Mode > right-click > Copy ID; blank to skip): "`
  - `cli.setup.slug_differs_hint` → `"  (Slug differs from display-lowercase; use '{slug}' in future CLI commands.)"`

  **Resolver WARN-once-per-user (for unmapped catalog):**
  - `identity.warn.catalog_missing_for_user` → `"User '{slug}' has language '{language}' but no catalog is shipped. Operator-facing chrome will fall back to English for this user."`

  > **Note:** the `secrets.*` keys (`secrets.file_perms_too_open`, `secrets.file_missing_required`, `secrets.path_is_directory`) belong to PR C and are NOT added in PR A. Same for the `discord.*` keys (PR D2).

- [ ] **Step 4.3 — Compile the catalog and confirm no drift.**

  ```bash
  uv run pybabel compile -d locale --use-fuzzy
  uv run pybabel compile -d locale --check
  ```

  Both must exit 0. `--use-fuzzy` accepts the new entries on first compile; the subsequent `--check` enforces no drift.

- [ ] **Step 4.4 — Commit (PR-A commit 4).**

  ```bash
  git add src/alfred/cli/main.py locale/en/LC_MESSAGES/alfred.po locale/en/LC_MESSAGES/alfred.mo
  git commit -m "i18n: add cli.user.* + cli.help.root + cli.setup.* catalog entries; fix cli/main.py:54 t() leak (#<issue>)"
  ```

---

### Task 5: `Authorization` + `Platform` enums + `IdentityError` hierarchy — PR-A commit 5

**Owner:** `alfred-python-developer`.

**Why fifth:** the migration (Task 7) and the ORMs (Task 6) reference these enum values in CHECK constraints; the resolver (Task 8) raises the error types. Landing them as their own commit keeps the diff reviewable and lets the ORM commit hold just the SQLAlchemy declarations.

**Files:**

- Create: `src/alfred/identity/__init__.py` (empty for now; re-export grows in later commits).
- Create: `src/alfred/identity/errors.py`.

**Steps:**

- [ ] **Step 5.1 — Create the package init.**

  ```python
  """AlfredOS identity layer.

  Multi-user identity, platform-binding, and per-user resolution. Public surface
  is intentionally narrow:

  * ``User`` / ``PlatformIdentity`` — SQLAlchemy ORMs.
  * ``Authorization`` / ``Platform`` — closed-domain enums (snake_case in DB; the
    Typer CLI accepts kebab-case and normalises at the boundary).
  * ``IdentityResolver`` — the only legitimate accessor for the two ORMs.
  * ``IdentityVersionCounter`` — bump-on-mutate primitive subscribed by the
    resolver's in-process LRU and (in PR B) by ``BudgetGuard``.
  * Error types — ``OperatorAlreadyExistsError``, ``LastOperatorRemovalRefusedError``,
    ``OperatorSlugCollisionError``, ``IdentityResolutionError``.
  """

  from __future__ import annotations

  from alfred.identity.errors import (
      IdentityError,
      IdentityResolutionError,
      LastOperatorRemovalRefusedError,
      OperatorAlreadyExistsError,
      OperatorSlugCollisionError,
  )

  __all__ = [
      "IdentityError",
      "IdentityResolutionError",
      "LastOperatorRemovalRefusedError",
      "OperatorAlreadyExistsError",
      "OperatorSlugCollisionError",
  ]
  ```

  (Subsequent tasks append to `__all__` as new public symbols land — the import errors at task boundaries are the signal to revisit.)

- [ ] **Step 5.2 — Create `src/alfred/identity/errors.py`.**

  ```python
  """Typed errors raised by the identity layer.

  Rooted at ``AlfredError`` so CLI top-level dispatch (and orchestrator
  ``except`` arms in PR B) can catch them uniformly without swallowing
  unrelated exceptions. ``OperatorSlugCollisionError`` is also a subclass of
  ``alembic.util.exc.CommandError`` so the Alembic runner surfaces it as a
  normal migration failure (exit 1) rather than a crash.
  """

  from __future__ import annotations

  from alembic.util.exc import CommandError

  from alfred.errors import AlfredError


  class IdentityError(AlfredError):
      """Base for identity-layer failures."""


  class IdentityResolutionError(IdentityError):
      """Raised when ``IdentityResolver.resolve`` is forced to fail loudly.

      Used by ``get_operator()`` when zero or >1 operator users exist — adapter
      startup surfaces a friendly hint pointing at ``alfred user add
      --authorization operator``.
      """


  class OperatorAlreadyExistsError(IdentityError):
      """Raised when ``add(--authorization operator)`` or ``set(--authorization operator)``
      would produce a second concurrent operator.

      The CLI catches this and either (a) exits 2 with ``cli.user.error.operator_already_exists``
      if no ``--replace-operator`` was passed, or (b) re-runs the operation as
      a demote-then-promote in one transaction if it was.
      """

      def __init__(self, existing_slug: str, existing_display_name: str) -> None:
          self.existing_slug = existing_slug
          self.existing_display_name = existing_display_name
          super().__init__(
              f"Operator '{existing_slug}' ({existing_display_name}) already exists; "
              f"pass --replace-operator {existing_slug} to swap atomically."
          )


  class LastOperatorRemovalRefusedError(IdentityError):
      """Raised when ``remove(slug)`` would leave the deployment with zero operators."""

      def __init__(self, slug: str) -> None:
          self.slug = slug
          super().__init__(
              f"Refused to remove the last operator '{slug}'. Promote another user "
              f"to operator first."
          )


  class OperatorSlugCollisionError(CommandError):
      """Raised by migration 0004's slug pre-check if a literal user_id in episodes
      or audit_log slug-collides with an existing non-operator users row.

      Subclasses ``alembic.util.exc.CommandError`` so the migration runner reports
      it as a normal command failure (exit 1) rather than a crash, and the
      ``alembic upgrade head`` CLI surfaces the message to the operator.
      """
  ```

  > **Pre-requisite check:** confirm `src/alfred/errors.py` exists and exposes `AlfredError` (slice-1 surface). If not, create it as part of this task with `class AlfredError(Exception): ...` and one-line docstring.

  ```bash
  grep -n "class AlfredError" src/alfred/errors.py 2>&1 || echo "MISSING — create as part of this task"
  ```

- [ ] **Step 5.3 — Add `Authorization` + `Platform` enums to `src/alfred/identity/models.py`** (the file is empty until Task 6; this step adds just the enum block at the top so the migration can reference the values literally).

  ```python
  """AlfredOS identity ORMs (User + PlatformIdentity).

  Closed-domain enums for ``authorization`` and ``platform`` ride alongside the
  ORMs (rather than living in a separate module) so call sites import a single
  symbol per concept.
  """

  from __future__ import annotations

  from enum import Enum


  class Authorization(str, Enum):
      """Per-user authorization tier.

      Snake_case on the wire (DB column TEXT CHECK + Pydantic value); kebab-case
      on the CLI surface (the Typer custom type normalises). The enum stays in
      the schema permanently — dropping/re-adding across a Postgres CHECK is a
      destructive migration that breaks rollback symmetry (spec §2 line 223).
      """

      READ_ONLY = "read_only"
      STANDARD = "standard"
      TRUSTED = "trusted"
      OPERATOR = "operator"


  class Platform(str, Enum):
      """Platform that owns the ``platform_id`` half of an identity binding.

      Slice 2 ships TUI + Discord; Telegram lands in Slice 4 by extending this
      enum (additive CHECK-constraint migration, no destructive rewrite).
      """

      TUI = "tui"
      DISCORD = "discord"


  # ORMs land in Task 6.
  ```

- [ ] **Step 5.4 — Run mypy + pyright on the new files.**

  ```bash
  uv run mypy src/alfred/identity/ && uv run pyright src/alfred/identity/
  ```

  Expected: clean.

- [ ] **Step 5.5 — Commit (PR-A commit 5).**

  ```bash
  git add src/alfred/identity/__init__.py src/alfred/identity/errors.py src/alfred/identity/models.py
  # Plus src/alfred/errors.py if it had to be created in Step 5.2:
  git add src/alfred/errors.py 2>/dev/null || true
  git commit -m "feat(identity): enums + error hierarchy (Authorization, Platform, IdentityError tree) (#<issue>)"
  ```

---

### Task 6: `User` + `PlatformIdentity` ORMs — PR-A commit 6

**Owner:** `alfred-python-developer`.

**Files:** Modify `src/alfred/identity/models.py` (append the ORMs below the enums).

**Steps:**

- [ ] **Step 6.1 — Write the failing ORM test.**

  Create `tests/unit/identity/__init__.py` (empty) and `tests/unit/identity/test_models.py`:

  ```python
  """Shape tests for the User + PlatformIdentity ORMs.

  Asserts:
  * column names + nullability match the spec contract (every PR B+ test pins
    against these attribute names);
  * Authorization / Platform enums round-trip through SQLAlchemy as TEXT;
  * the partial-UNIQUE on (user_id, platform) WHERE deleted_at IS NULL is
    declared (full enforcement is the integration test against real Postgres);
  * CASCADE on platform_identities.user_id is declared.
  """

  from __future__ import annotations

  from sqlalchemy import inspect

  from alfred.identity.models import (
      Authorization,
      Platform,
      PlatformIdentity,
      User,
  )


  def test_user_column_contract() -> None:
      cols = {c.name: c for c in inspect(User).columns}
      assert set(cols) == {
          "id", "slug", "display_name", "authorization",
          "daily_budget_usd", "language",
          "rate_limit_per_min", "rate_limit_per_day",
          "created_at", "deleted_at",
      }
      assert cols["slug"].unique is True
      assert cols["slug"].nullable is False
      assert cols["display_name"].nullable is False
      assert cols["authorization"].nullable is False
      assert cols["daily_budget_usd"].nullable is False
      assert cols["language"].nullable is False
      assert cols["rate_limit_per_min"].nullable is True   # NULL = authorization-derived default
      assert cols["rate_limit_per_day"].nullable is True
      assert cols["created_at"].nullable is False
      assert cols["deleted_at"].nullable is True


  def test_platform_identity_column_contract() -> None:
      cols = {c.name: c for c in inspect(PlatformIdentity).columns}
      assert set(cols) == {
          "id", "user_id", "platform", "platform_id",
          "created_at", "deleted_at",
      }
      # The composite UNIQUE on (platform, platform_id) lives in __table_args__.
      assert PlatformIdentity.__table_args__, "missing UNIQUE constraint"


  def test_enum_values() -> None:
      assert {a.value for a in Authorization} == {
          "read_only", "standard", "trusted", "operator",
      }
      assert {p.value for p in Platform} == {"tui", "discord"}
  ```

  ```bash
  uv run pytest tests/unit/identity/test_models.py -v
  ```

  Expected: FAIL (`User` / `PlatformIdentity` not yet defined).

- [ ] **Step 6.2 — Author the ORMs in `src/alfred/identity/models.py`.**

  Append below the enum block:

  ```python
  from datetime import datetime
  from typing import TYPE_CHECKING

  from sqlalchemy import (
      CheckConstraint,
      DateTime,
      ForeignKey,
      Float,
      Index,
      Integer,
      String,
      UniqueConstraint,
      func,
  )
  from sqlalchemy.orm import Mapped, mapped_column, relationship

  from alfred.memory.models import Base   # slice-1's declarative Base

  if TYPE_CHECKING:
      from collections.abc import Sequence


  class User(Base):
      """A multi-user identity row. The canonical user_id is ``slug``.

      Per spec §4 (line 606-619): authorization (renamed from ``role`` to avoid
      collision with Episode.role), per-user budget cap, BCP-47 language,
      optional rate-limit overrides, soft-delete via ``deleted_at``.
      """

      __tablename__ = "users"
      __table_args__ = (
          CheckConstraint(
              "authorization IN ('read_only', 'standard', 'trusted', 'operator')",
              name="ck_users_authorization",
          ),
          CheckConstraint("daily_budget_usd > 0", name="ck_users_daily_budget_positive"),
          CheckConstraint(
              "rate_limit_per_min IS NULL OR rate_limit_per_min >= 0",
              name="ck_users_rate_limit_per_min_nonneg",
          ),
          CheckConstraint(
              "rate_limit_per_day IS NULL OR rate_limit_per_day >= 0",
              name="ck_users_rate_limit_per_day_nonneg",
          ),
      )

      id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
      slug: Mapped[str] = mapped_column(String, unique=True, nullable=False)
      display_name: Mapped[str] = mapped_column(String, nullable=False)
      authorization: Mapped[str] = mapped_column(String, nullable=False)
      daily_budget_usd: Mapped[float] = mapped_column(Float, nullable=False)
      language: Mapped[str] = mapped_column(String, nullable=False)
      rate_limit_per_min: Mapped[int | None] = mapped_column(Integer, nullable=True)
      rate_limit_per_day: Mapped[int | None] = mapped_column(Integer, nullable=True)
      created_at: Mapped[datetime] = mapped_column(
          DateTime(timezone=True), server_default=func.now(), nullable=False,
      )
      deleted_at: Mapped[datetime | None] = mapped_column(
          DateTime(timezone=True), nullable=True,
      )

      identities: Mapped[Sequence[PlatformIdentity]] = relationship(
          back_populates="user",
          cascade="all, delete-orphan",
      )


  class PlatformIdentity(Base):
      """A (platform, platform_id) → User binding.

      Composite UNIQUE on (platform, platform_id) prevents one Discord ID
      binding to two users. Partial UNIQUE on (user_id, platform)
      WHERE deleted_at IS NULL prevents one user from holding two active
      bindings on the same platform.
      """

      __tablename__ = "platform_identities"
      __table_args__ = (
          UniqueConstraint("platform", "platform_id", name="uq_platform_identities_platform_id"),
          Index(
              "uq_platform_identities_user_platform_active",
              "user_id", "platform",
              unique=True,
              postgresql_where=(mapped_column("deleted_at").is_(None)),  # SQLAlchemy partial-unique idiom
          ),
          CheckConstraint(
              "platform IN ('tui', 'discord')",
              name="ck_platform_identities_platform",
          ),
      )

      id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
      user_id: Mapped[int] = mapped_column(
          ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
      )
      platform: Mapped[str] = mapped_column(String, nullable=False)
      platform_id: Mapped[str] = mapped_column(String, nullable=False)
      created_at: Mapped[datetime] = mapped_column(
          DateTime(timezone=True), server_default=func.now(), nullable=False,
      )
      deleted_at: Mapped[datetime | None] = mapped_column(
          DateTime(timezone=True), nullable=True,
      )

      user: Mapped[User] = relationship(back_populates="identities")
  ```

  > **If the partial-UNIQUE-on-deleted_at expression doesn't accept the `mapped_column` lookup at import time** (SQLAlchemy 2.0's preferred idiom is `text("deleted_at IS NULL")` inside a raw `Index`), switch to:
  >
  > ```python
  > Index(
  >     "uq_platform_identities_user_platform_active",
  >     "user_id", "platform",
  >     unique=True,
  >     postgresql_where=text("deleted_at IS NULL"),
  > )
  > ```
  >
  > Both work; pick whichever passes the unit test in Step 6.3.

- [ ] **Step 6.3 — Re-run the unit test.**

  ```bash
  uv run pytest tests/unit/identity/test_models.py -v
  ```

  Expected: PASS.

- [ ] **Step 6.4 — Extend `__init__.py` to re-export the ORMs.**

  Add to the existing `__all__` block in `src/alfred/identity/__init__.py`:

  ```python
  from alfred.identity.models import Authorization, Platform, PlatformIdentity, User

  __all__ = [
      "Authorization",
      "IdentityError",
      "IdentityResolutionError",
      "LastOperatorRemovalRefusedError",
      "OperatorAlreadyExistsError",
      "OperatorSlugCollisionError",
      "Platform",
      "PlatformIdentity",
      "User",
  ]
  ```

- [ ] **Step 6.5 — Run mypy + pyright.**

  ```bash
  uv run mypy src/alfred/identity/ tests/unit/identity/
  uv run pyright src/alfred/identity/ tests/unit/identity/
  ```

  Expected: clean.

- [ ] **Step 6.6 — Commit (PR-A commit 6).**

  ```bash
  git add src/alfred/identity/models.py src/alfred/identity/__init__.py \
          tests/unit/identity/__init__.py tests/unit/identity/test_models.py
  git commit -m "feat(identity): User + PlatformIdentity ORMs with CHECK + UNIQUE constraints (#<issue>)"
  ```

---

### Task 7: Migration `0004_users_and_identities` — PR-A commit 7

**Owner:** `alfred-python-developer`; review by `alfred-security-engineer` (the collision-refusal path is a security invariant — silent backfill would mangle audit history).

**Files:**

- Create: `src/alfred/memory/migrations/versions/0004_users_and_identities.py`.
- Create: `tests/integration/test_migration_0004_backfill.py`.

**Steps:**

- [ ] **Step 7.1 — Write the failing integration test enumerating all four backfill scenarios (spec §5 line 805, te-001).**

  Create `tests/integration/test_migration_0004_backfill.py`:

  ```python
  """Migration 0004 backfill — four scenarios (spec §5 te-001).

  (a) Custom ALFRED_OPERATOR_NAME — backfills episodes.user_id +
      audit_log.actor_user_id to the canonical slug.
  (b) Default operator_name == 'operator' — no-op backfill (literal already == slug).
  (c) Non-operator slug-collision — refuses with OperatorSlugCollisionError
      and the spec'd remediation message.
  (d) ADD COLUMN coverage — pre-existing rows get NULL for the four new columns;
      downgrade drops the four columns + two tables without mangling 0003 rows.
  """

  from __future__ import annotations

  import os

  import pytest
  from alembic import command, config
  from sqlalchemy import inspect, text

  pytestmark = pytest.mark.integration


  @pytest.fixture
  def alembic_cfg(postgres_url: str) -> config.Config:
      cfg = config.Config("alembic.ini")
      cfg.set_main_option("sqlalchemy.url", postgres_url)
      return cfg


  def _upgrade_to(cfg: config.Config, rev: str) -> None:
      command.upgrade(cfg, rev)


  def _downgrade_to(cfg: config.Config, rev: str) -> None:
      command.downgrade(cfg, rev)


  def test_backfill_a_custom_operator_name(alembic_cfg, postgres_engine, monkeypatch) -> None:
      """Scenario (a) — ALFRED_OPERATOR_NAME='Bruce Wayne' produces slug
      'bruce-wayne'; episodes + audit_log rows referencing the literal old
      user_id are updated to the canonical slug; row counts preserved."""
      _upgrade_to(alembic_cfg, "0003")
      with postgres_engine.begin() as conn:
          conn.execute(text(
              "INSERT INTO episodes (user_id, role, content, trust_tier, language, persona_id) "
              "VALUES ('Bruce Wayne', 'user', 'hi', 'T2', NULL, NULL)"
          ))
          conn.execute(text(
              "INSERT INTO audit_log (actor_user_id, event, subject, trust_tier_of_trigger, result, language, persona_id) "
              "VALUES ('Bruce Wayne', 'tui.turn', '{}', 'T2', 'success', NULL, NULL)"
          ))
          before_episodes = conn.scalar(text("SELECT COUNT(*) FROM episodes"))
          before_audit = conn.scalar(text("SELECT COUNT(*) FROM audit_log"))

      monkeypatch.setenv("ALFRED_OPERATOR_NAME", "Bruce Wayne")
      _upgrade_to(alembic_cfg, "0004")

      with postgres_engine.begin() as conn:
          operator = conn.execute(text(
              "SELECT slug, display_name, authorization FROM users WHERE authorization='operator'"
          )).one()
          assert operator.slug == "bruce-wayne"
          assert operator.display_name == "Bruce Wayne"

          # Backfill correctness.
          assert conn.scalar(text(
              "SELECT COUNT(*) FROM episodes WHERE user_id='bruce-wayne'"
          )) == before_episodes
          assert conn.scalar(text(
              "SELECT COUNT(*) FROM audit_log WHERE actor_user_id='bruce-wayne'"
          )) == before_audit

          # Append-only audit invariant — no audit row deleted.
          assert conn.scalar(text("SELECT COUNT(*) FROM audit_log")) == before_audit


  def test_backfill_b_default_operator_no_op(alembic_cfg, postgres_engine, monkeypatch) -> None:
      """Scenario (b) — default 'operator' produces slug 'operator'; backfill
      UPDATE is a no-op (literal already equals slug)."""
      monkeypatch.delenv("ALFRED_OPERATOR_NAME", raising=False)
      _upgrade_to(alembic_cfg, "0003")
      with postgres_engine.begin() as conn:
          conn.execute(text(
              "INSERT INTO episodes (user_id, role, content, trust_tier, language, persona_id) "
              "VALUES ('operator', 'user', 'hi', 'T2', NULL, NULL)"
          ))

      _upgrade_to(alembic_cfg, "0004")

      with postgres_engine.begin() as conn:
          assert conn.scalar(text(
              "SELECT COUNT(*) FROM episodes WHERE user_id='operator'"
          )) == 1
          assert conn.scalar(text(
              "SELECT slug FROM users WHERE authorization='operator'"
          )) == "operator"


  def test_backfill_c_collision_refusal(alembic_cfg, postgres_engine, monkeypatch) -> None:
      """Scenario (c) — a non-operator users row at slug 'bruce-wayne' already
      exists; the migration refuses with OperatorSlugCollisionError and a
      remediation message naming ALFRED_OPERATOR_NAME."""
      from alfred.identity.errors import OperatorSlugCollisionError

      _upgrade_to(alembic_cfg, "0003")
      # Note: pre-Slice 2, the users table doesn't exist; this scenario
      # simulates the case where ANOTHER process created a colliding row
      # AFTER 0004 ran the CREATE TABLE but BEFORE the operator insert.
      # The fixture inserts via raw SQL after the CREATE TABLE has run.
      monkeypatch.setenv("ALFRED_OPERATOR_NAME", "Bruce Wayne")

      # Patch the migration to pause after table creation, insert a
      # colliding non-operator row, then resume — see migration fixture
      # helper `force_pre_insert_row`.
      with pytest.raises(OperatorSlugCollisionError, match="bruce-wayne"):
          _upgrade_to(alembic_cfg, "0004")  # collision-inducing fixture pre-runs


  def test_backfill_d_add_column_and_downgrade(alembic_cfg, postgres_engine, monkeypatch) -> None:
      """Scenario (d) — ADD COLUMN coverage + downgrade-drops-cleanly invariant."""
      _upgrade_to(alembic_cfg, "0003")
      with postgres_engine.begin() as conn:
          conn.execute(text(
              "INSERT INTO episodes (user_id, role, content, trust_tier) "
              "VALUES ('operator', 'user', 'pre-0004 row', 'T2')"
          ))

      _upgrade_to(alembic_cfg, "0004")

      with postgres_engine.begin() as conn:
          # Pre-existing row has NULL for the four new columns (no destructive backfill).
          row = conn.execute(text(
              "SELECT language, persona_id FROM episodes WHERE content='pre-0004 row'"
          )).one()
          assert row.language is None
          assert row.persona_id is None

          # Column types match DDL.
          insp = inspect(postgres_engine)
          ep_cols = {c["name"]: c["type"] for c in insp.get_columns("episodes")}
          al_cols = {c["name"]: c["type"] for c in insp.get_columns("audit_log")}
          assert "language" in ep_cols and "persona_id" in ep_cols
          assert "language" in al_cols and "persona_id" in al_cols
          # TEXT, not VARCHAR — Postgres TEXT is the preferred unbounded form.
          assert str(ep_cols["language"]).upper().startswith("TEXT")

      # Downgrade drops the four columns + two tables.
      _downgrade_to(alembic_cfg, "0003")
      with postgres_engine.begin() as conn:
          insp = inspect(postgres_engine)
          assert "users" not in insp.get_table_names()
          assert "platform_identities" not in insp.get_table_names()
          ep_cols = {c["name"] for c in insp.get_columns("episodes")}
          assert "language" not in ep_cols
          assert "persona_id" not in ep_cols
          # 0003 row content survives the downgrade.
          assert conn.scalar(text(
              "SELECT COUNT(*) FROM episodes WHERE content='pre-0004 row'"
          )) == 1
  ```

  ```bash
  uv run pytest tests/integration/test_migration_0004_backfill.py -v
  ```

  Expected: ALL FAIL (migration doesn't exist).

- [ ] **Step 7.2 — Author the migration.**

  Create `src/alfred/memory/migrations/versions/0004_users_and_identities.py` with the spec'd single-transaction shape:

  ```python
  """users + platform_identities; per-row language + persona_id columns; operator backfill.

  Revision ID: 0004
  Revises: 0003
  Create Date: 2026-05-26 00:00:00.000000

  Spec §2 line 228-268. One transaction with SET LOCAL statement_timeout = '60s'.
  Idempotent — ON CONFLICT (slug) DO NOTHING on the operator insert. Collision
  refusal raises OperatorSlugCollisionError (CommandError subclass) so Alembic
  surfaces the message at exit 1.
  """

  from __future__ import annotations

  import os
  from collections.abc import Sequence

  from alembic import op
  from sqlalchemy import text

  from alfred.identity.errors import OperatorSlugCollisionError
  from alfred.identity.slug import derive_slug   # Task 8 publishes this; see ordering note.

  revision: str = "0004"
  down_revision: str | Sequence[str] | None = "0003"
  branch_labels: str | Sequence[str] | None = None
  depends_on: str | Sequence[str] | None = None


  def _operator_name() -> str:
      return os.environ.get("ALFRED_OPERATOR_NAME", "operator")


  def _operator_language() -> str:
      return os.environ.get("ALFRED_OPERATOR_LANGUAGE", "en-US")


  def _operator_budget() -> float:
      return float(os.environ.get("ALFRED_DAILY_BUDGET_USD", "1.0"))


  def upgrade() -> None:
      conn = op.get_bind()
      conn.execute(text("SET LOCAL statement_timeout = '60s'"))

      op.create_table(
          "users",
          sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
          sa.Column("slug", sa.Text, nullable=False, unique=True),
          sa.Column("display_name", sa.Text, nullable=False),
          sa.Column("authorization", sa.Text, nullable=False),
          sa.Column("daily_budget_usd", sa.Float, nullable=False),
          sa.Column("language", sa.Text, nullable=False),
          sa.Column("rate_limit_per_min", sa.Integer, nullable=True),
          sa.Column("rate_limit_per_day", sa.Integer, nullable=True),
          sa.Column("created_at", sa.DateTime(timezone=True),
                    server_default=sa.func.now(), nullable=False),
          sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
          sa.CheckConstraint(
              "authorization IN ('read_only', 'standard', 'trusted', 'operator')",
              name="ck_users_authorization",
          ),
          sa.CheckConstraint("daily_budget_usd > 0", name="ck_users_daily_budget_positive"),
          sa.CheckConstraint(
              "rate_limit_per_min IS NULL OR rate_limit_per_min >= 0",
              name="ck_users_rate_limit_per_min_nonneg",
          ),
          sa.CheckConstraint(
              "rate_limit_per_day IS NULL OR rate_limit_per_day >= 0",
              name="ck_users_rate_limit_per_day_nonneg",
          ),
      )

      op.create_table(
          "platform_identities",
          sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
          sa.Column("user_id", sa.Integer,
                    sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
          sa.Column("platform", sa.Text, nullable=False),
          sa.Column("platform_id", sa.Text, nullable=False),
          sa.Column("created_at", sa.DateTime(timezone=True),
                    server_default=sa.func.now(), nullable=False),
          sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
          sa.CheckConstraint(
              "platform IN ('tui', 'discord')",
              name="ck_platform_identities_platform",
          ),
          sa.UniqueConstraint(
              "platform", "platform_id",
              name="uq_platform_identities_platform_id",
          ),
      )
      # Partial UNIQUE — Alembic doesn't have first-class partial indexes,
      # so emit raw DDL.
      op.execute(
          "CREATE UNIQUE INDEX uq_platform_identities_user_platform_active "
          "ON platform_identities (user_id, platform) "
          "WHERE deleted_at IS NULL"
      )

      # New per-row columns on episodes + audit_log (nullable on backfill).
      op.add_column("episodes", sa.Column("language", sa.Text, nullable=True))
      op.add_column("episodes", sa.Column("persona_id", sa.Text, nullable=True))
      op.add_column("audit_log", sa.Column("language", sa.Text, nullable=True))
      op.add_column("audit_log", sa.Column("persona_id", sa.Text, nullable=True))

      operator_name = _operator_name()
      operator_slug = derive_slug(operator_name)

      # Pre-check — refuse if a non-operator users row already squats the slug.
      existing = conn.execute(
          text(
              "SELECT slug, display_name, authorization FROM users "
              "WHERE slug = :slug AND authorization != 'operator'"
          ),
          {"slug": operator_slug},
      ).first()
      if existing is not None:
          raise OperatorSlugCollisionError(
              f"slug '{operator_slug}' already in use by non-operator user "
              f"'{existing.display_name}'; re-run with "
              f"ALFRED_OPERATOR_NAME=<unique-name> alembic upgrade head"
          )

      # Operator insert — idempotent.
      conn.execute(
          text(
              "INSERT INTO users (slug, display_name, authorization, daily_budget_usd, "
              "language, created_at) VALUES (:slug, :name, 'operator', :budget, :lang, now()) "
              "ON CONFLICT (slug) DO NOTHING"
          ),
          {
              "slug": operator_slug,
              "name": operator_name,
              "budget": _operator_budget(),
              "lang": _operator_language(),
          },
      )

      # TUI platform-identity row for the operator.
      operator_id = conn.execute(
          text("SELECT id FROM users WHERE slug = :slug"),
          {"slug": operator_slug},
      ).scalar_one()
      conn.execute(
          text(
              "INSERT INTO platform_identities (user_id, platform, platform_id, created_at) "
              "VALUES (:uid, 'tui', :name, now()) "
              "ON CONFLICT (platform, platform_id) DO NOTHING"
          ),
          {"uid": operator_id, "name": operator_name},
      )

      # Backfill — only the rows whose literal user_id differs from the canonical slug.
      conn.execute(
          text("UPDATE episodes SET user_id = :slug WHERE user_id != :slug"),
          {"slug": operator_slug},
      )
      conn.execute(
          text("UPDATE audit_log SET actor_user_id = :slug WHERE actor_user_id != :slug"),
          {"slug": operator_slug},
      )


  def downgrade() -> None:
      """Drop the four columns + two tables. Preserves 0003-shape row content
      (the four new columns don't exist after downgrade)."""
      op.drop_column("audit_log", "persona_id")
      op.drop_column("audit_log", "language")
      op.drop_column("episodes", "persona_id")
      op.drop_column("episodes", "language")
      op.execute("DROP INDEX IF EXISTS uq_platform_identities_user_platform_active")
      op.drop_table("platform_identities")
      op.drop_table("users")
  ```

  > **Ordering note:** the migration imports `derive_slug` from `alfred.identity.slug`. If Task 8 ships after Task 7, the migration breaks on import. **Resolution:** Task 8 (slug pipeline) lands BEFORE Task 7 (migration), even though the on-disk file (`0004_*.py`) is added in this commit. The slug module is small and standalone, so committing it before the migration is harmless. **Update Task 7's commit message to reflect "migration uses Task 8's slug pipeline".** Easier reorder: move the slug pipeline up to Task 6.5 (between ORMs and migration). See revised order in Step 7.7.

- [ ] **Step 7.3 — Re-run the migration integration test.**

  ```bash
  uv run pytest tests/integration/test_migration_0004_backfill.py -v
  ```

  Expected: ALL FOUR scenarios PASS.

- [ ] **Step 7.4 — Run idempotency check.**

  ```bash
  uv run pytest tests/integration/test_migration_0004_backfill.py::test_backfill_b_default_operator_no_op -v
  # Then in a follow-up REPL or test extension:
  uv run alembic -c alembic.ini upgrade head    # idempotent — second run is a no-op.
  uv run alembic -c alembic.ini upgrade head    # second invocation must exit 0 with no errors.
  ```

- [ ] **Step 7.5 — Run round-trip downgrade-then-upgrade.**

  ```bash
  uv run alembic downgrade -1
  uv run alembic upgrade head
  ```

  Both must exit 0; the four-column + two-table delta round-trips cleanly.

- [ ] **Step 7.6 — Run mypy + pyright on the migration.**

  ```bash
  uv run mypy src/alfred/memory/migrations/versions/0004_users_and_identities.py
  uv run pyright src/alfred/memory/migrations/versions/0004_users_and_identities.py
  ```

  Expected: clean.

- [ ] **Step 7.7 — Commit (PR-A commit 7). Note the ordering caveat above: if Task 8 (slug pipeline) hasn't landed yet, defer this commit until after Task 8.**

  ```bash
  git add src/alfred/memory/migrations/versions/0004_users_and_identities.py \
          tests/integration/test_migration_0004_backfill.py
  git commit -m "feat(memory): migration 0004 — users + platform_identities + per-row language/persona_id columns + operator backfill (#<issue>)"
  ```

---

### Task 8: Slug derivation pipeline (`alfred.identity.slug.derive_slug`) — PR-A commit 8

**Owner:** `alfred-python-developer`.

**Note:** Land this task BEFORE Task 7 in practice (the migration imports `derive_slug`). The numbering here keeps logical clustering — when implementing, do Task 5 → Task 6 → Task 8 → Task 7. Renumber commits accordingly in the actual PR.

**Files:**

- Create: `src/alfred/identity/slug.py`.
- Create: `tests/unit/identity/test_slug.py`.

**Steps:**

- [ ] **Step 8.1 — Add `unidecode` to runtime deps.**

  Edit `pyproject.toml`:

  ```toml
  # Add to [project] dependencies (alphabetical):
  "unidecode>=1.3,<2",
  ```

  Then:

  ```bash
  uv lock
  uv sync --dev
  ```

- [ ] **Step 8.2 — Write the failing slug pipeline test (every edge case per spec §4 line 587-598).**

  Create `tests/unit/identity/test_slug.py`:

  ```python
  """Slug derivation pipeline — spec §4 line 587-598.

  Pinned outputs across the cross-PR contract; PR B's tests reuse these inputs.
  """

  from __future__ import annotations

  import pytest

  from alfred.identity.slug import derive_slug


  @pytest.mark.parametrize(("raw", "expected"), [
      # Spec line 594 examples.
      ("Alice O'Connor", "alice-o-connor"),
      ("José Núñez", "jose-nunez"),
      ("田中", "tian-zhong"),                  # unidecode pinyin transliteration
      ("___bob---", "bob"),
      # Spec line 596 empty-fallback case.
      ("🌟🎉", "user"),
      ("___", "user"),
      # Slice-1 default — must round-trip.
      ("operator", "operator"),
      # Mixed casing + spaces.
      ("Bruce Wayne", "bruce-wayne"),
      # NFKC normalisation: full-width 'a' (U+FF41) → 'a'.
      ("Ａlice", "alice"),
      # Multiple dashes collapse.
      ("alice---bob", "alice-bob"),
      # Leading/trailing whitespace.
      ("  Alice  ", "alice"),
      # Long input — truncate AT 63 (no shorter, no longer).
      ("a" * 100, "a" * 63),
  ])
  def test_derive_slug_pinned_outputs(raw: str, expected: str) -> None:
      """Every input maps to its pinned output. Outputs are load-bearing across PRs."""
      assert derive_slug(raw) == expected


  def test_derive_slug_truncates_before_collision_suffix() -> None:
      """Truncation to 63 happens BEFORE collision suffixing — otherwise 'bob-2' could
      become 'bob-' on the trim, which would silently collide."""
      # derive_slug alone does NOT collision-suffix (that's resolver.add's job).
      assert len(derive_slug("a" * 100)) == 63
  ```

  ```bash
  uv run pytest tests/unit/identity/test_slug.py -v
  ```

  Expected: FAIL.

- [ ] **Step 8.3 — Author `src/alfred/identity/slug.py`.**

  ```python
  """Canonical user_id derivation: name → slug.

  Pipeline (spec §4 line 587-593):
    1. NFKC normalise.
    2. ASCII transliterate via unidecode.
    3. Lowercase.
    4. Replace every run of non-alphanumeric with a single ``-``.
    5. Trim leading/trailing ``-`` and collapse internal repeated ``-``.
    6. Truncate to 63 chars (BEFORE collision suffixing — see resolver.add).
    7. Empty result falls back to the literal ``user``.

  Collision suffixing is NOT applied here; that's ``IdentityResolver.add``'s
  job because it needs a DB session to check ``users.slug`` uniqueness.

  Pure function — no I/O, no state. Trivially testable; the imperative shell
  in ``resolver.add`` wraps it with the DB-aware collision check.
  """

  from __future__ import annotations

  import re
  import unicodedata

  from unidecode import unidecode

  _SLUG_RE = re.compile(r"[^a-z0-9]+")
  _SLUG_MAX = 63
  _EMPTY_FALLBACK = "user"


  def derive_slug(name: str) -> str:
      """Derive a canonical slug from ``name``. Pure function; see module docstring."""
      step1 = unicodedata.normalize("NFKC", name)
      step2 = unidecode(step1)
      step3 = step2.lower()
      step4 = _SLUG_RE.sub("-", step3)
      # ``re.sub("[^a-z0-9]+", "-", ...)`` already collapses runs to a single dash;
      # trimming leading/trailing dashes is the only remaining clean-up.
      step5 = step4.strip("-")
      if not step5:
          return _EMPTY_FALLBACK
      return step5[:_SLUG_MAX]
  ```

- [ ] **Step 8.4 — Re-run the test.**

  ```bash
  uv run pytest tests/unit/identity/test_slug.py -v
  ```

  Expected: PASS for every parametrised case.

- [ ] **Step 8.5 — Add `derive_slug` to the package re-exports.**

  ```python
  # src/alfred/identity/__init__.py — append to __all__ + add import:
  from alfred.identity.slug import derive_slug

  __all__ = [
      "Authorization",
      "derive_slug",
      "IdentityError",
      # …existing entries
  ]
  ```

- [ ] **Step 8.6 — Commit (PR-A commit 8 — see ordering note in Task 7).**

  ```bash
  git add src/alfred/identity/slug.py src/alfred/identity/__init__.py \
          tests/unit/identity/test_slug.py pyproject.toml uv.lock
  git commit -m "feat(identity): slug derivation pipeline (NFKC → unidecode → regex → trim → 63-cap) (#<issue>)"
  ```

---

### Task 9: `IdentityVersionCounter` — PR-A commit 9

**Owner:** `alfred-python-developer`.

**Files:**

- Create: `src/alfred/identity/version_counter.py`.
- Create: `tests/unit/identity/test_version_counter.py`.

**Steps:**

- [ ] **Step 9.1 — Write the failing test.**

  ```python
  """IdentityVersionCounter — monotonic-bump invariant + concurrent safety."""

  from __future__ import annotations

  import asyncio

  from hypothesis import given, settings
  from hypothesis import strategies as st

  from alfred.identity.version_counter import IdentityVersionCounter


  def test_current_starts_at_zero() -> None:
      counter = IdentityVersionCounter()
      assert counter.current() == 0


  def test_bump_increments_monotonically() -> None:
      counter = IdentityVersionCounter()
      counter.bump()
      assert counter.current() == 1
      counter.bump()
      counter.bump()
      assert counter.current() == 3


  @settings(max_examples=50, deadline=None)
  @given(st.integers(min_value=0, max_value=200))
  def test_n_bumps_yield_n_version(n: int) -> None:
      counter = IdentityVersionCounter()
      for _ in range(n):
          counter.bump()
      assert counter.current() == n


  def test_concurrent_bump_no_lost_updates() -> None:
      """Property: N concurrent bumps from N coroutines yield current() == N."""
      counter = IdentityVersionCounter()

      async def worker() -> None:
          counter.bump()

      async def driver() -> None:
          await asyncio.gather(*(worker() for _ in range(100)))

      asyncio.run(driver())
      assert counter.current() == 100
  ```

  ```bash
  uv run pytest tests/unit/identity/test_version_counter.py -v
  ```

  Expected: FAIL.

- [ ] **Step 9.2 — Author `src/alfred/identity/version_counter.py`.**

  ```python
  """In-process monotonic version counter for identity-cache invalidation.

  Every mutating IdentityResolver method bumps; resolver / BudgetGuard /
  WorkingMemoryPool subscribe and refetch their cached entries when the counter
  has advanced past their last-seen value.

  Cross-process invalidation rides on PostgreSQL ``LISTEN/NOTIFY`` (see
  ``IdentityListener`` in ``resolver.py``); this counter is the in-process
  primitive that NOTIFY receipts bump on the receiver side.
  """

  from __future__ import annotations

  import threading


  class IdentityVersionCounter:
      """Monotonic int counter; thread-safe (asyncio uses a single thread per
      loop, but the listener may bump from a different loop-thread on reconnect).
      """

      __slots__ = ("_lock", "_value")

      def __init__(self) -> None:
          self._lock = threading.Lock()
          self._value = 0

      def bump(self) -> None:
          """Atomically increment the counter."""
          with self._lock:
              self._value += 1

      def current(self) -> int:
          """Return the current value (snapshot)."""
          with self._lock:
              return self._value
  ```

- [ ] **Step 9.3 — Re-run the test.**

  ```bash
  uv run pytest tests/unit/identity/test_version_counter.py -v
  ```

  Expected: PASS.

- [ ] **Step 9.4 — Add to package re-exports.**

  Append to `src/alfred/identity/__init__.py`:

  ```python
  from alfred.identity.version_counter import IdentityVersionCounter

  __all__ = [..., "IdentityVersionCounter", ...]
  ```

- [ ] **Step 9.5 — Commit (PR-A commit 9).**

  ```bash
  git add src/alfred/identity/version_counter.py src/alfred/identity/__init__.py \
          tests/unit/identity/test_version_counter.py
  git commit -m "feat(identity): IdentityVersionCounter — monotonic bump-on-mutate primitive (#<issue>)"
  ```

---

### Task 10: `RateLimiter` Protocol stub (consumed by `IdentityResolver`) — PR-A commit 10

**Owner:** `alfred-python-developer`.

**Why:** the resolver imports `RateLimiter` from `alfred.identity.rate_limit` for type-hint consistency with PR D1. The concrete `InProcessTokenBucketRateLimiter` lands in PR D1; PR A ships the Protocol + a `_NullRateLimiter` test double so the resolver's import resolves and PR B's `BudgetGuard` tests can wire one in.

**Files:**

- Create: `src/alfred/identity/rate_limit.py`.

**Steps:**

- [ ] **Step 10.1 — Author the Protocol + test double.**

  ```python
  """Per-user rate-limiter Protocol.

  Slice-2 ships ``InProcessTokenBucketRateLimiter`` in PR D1; Slice 5 swaps to a
  Redis-backed implementation. Protocol is async-from-the-start so the Slice-5
  swap is one-line (the Redis ops are async).

  ``allow()`` takes the full ``User`` rather than a slug because the
  ``read_only`` refusal is a SECURITY invariant (spec §2 architect-002,
  line 223) — independent of any per-user override and never tunable as a
  perf default. The Protocol places the User-typed signature at the seam so
  consumers can't forget the gate.
  """

  from __future__ import annotations

  from dataclasses import dataclass
  from typing import Protocol

  from alfred.identity.models import User


  @dataclass(frozen=True)
  class RateLimiterHealth:
      """Snapshot of rate-limiter state (Slice-5 metrics seed)."""

      active_user_count: int
      total_refusals_since_start: int


  class RateLimiter(Protocol):
      """Per-user rate-limiter Protocol. Slice-2 surface."""

      async def allow(self, user: User) -> bool:
          """Return True if the user is allowed one more request right now.

          Security invariant: ``user.authorization == Authorization.READ_ONLY``
          MUST return False unconditionally — the gate is independent of any
          per-user override.
          """
          ...

      async def reset(self, user_id: str) -> None:
          """Clear all state for one user (used by ``IdentityResolver.remove``)."""
          ...

      def health(self) -> RateLimiterHealth:
          """Synchronous snapshot for `alfred status` and Slice-5 Prometheus."""
          ...


  class _NullRateLimiter:
      """Always-allow rate-limiter for tests that don't exercise the limiter.

      NOT a public symbol — tests in PR A and PR B that wire a resolver use
      this to avoid pulling in PR D1's concrete implementation. The leading
      underscore signals "test scaffolding; not for production".
      """

      def __init__(self) -> None:
          self._refusals = 0

      async def allow(self, user: User) -> bool:  # noqa: ARG002 — Protocol surface.
          return True

      async def reset(self, user_id: str) -> None:  # noqa: ARG002
          return None

      def health(self) -> RateLimiterHealth:
          return RateLimiterHealth(active_user_count=0, total_refusals_since_start=self._refusals)
  ```

- [ ] **Step 10.2 — Add to package re-exports.**

  ```python
  # src/alfred/identity/__init__.py
  from alfred.identity.rate_limit import RateLimiter, RateLimiterHealth, _NullRateLimiter

  __all__ = [..., "RateLimiter", "RateLimiterHealth", ...]   # _NullRateLimiter not re-exported (test-only).
  ```

- [ ] **Step 10.3 — Run mypy + pyright.**

  ```bash
  uv run mypy src/alfred/identity/rate_limit.py
  uv run pyright src/alfred/identity/rate_limit.py
  ```

  Expected: clean.

- [ ] **Step 10.4 — Commit (PR-A commit 10).**

  ```bash
  git add src/alfred/identity/rate_limit.py src/alfred/identity/__init__.py
  git commit -m "feat(identity): RateLimiter Protocol surface + _NullRateLimiter test double (#<issue>)"
  ```

---

### Task 11: `IdentityResolver` core (resolve / add / bind / unbind / remove / set / show / list / get_operator) — PR-A commit 11

**Owner:** `alfred-python-developer`; review by `alfred-security-engineer` on `--replace-operator` atomicity + last-operator-remove gate.

**Files:**

- Create: `src/alfred/identity/resolver.py` — without the LISTEN/NOTIFY listener (that lands in Task 12 to keep this commit reviewable).
- Create: `tests/unit/identity/test_resolver.py`.

**Steps:**

- [ ] **Step 11.1 — Write the failing test enumeration (covers every public method + every error path).**

  ```python
  """IdentityResolver — full public-surface enumeration.

  Slug-collision suffixing; resolve happy/miss/soft-deleted; LRU selective
  invalidation on counter bump; BCP-47 validation; get_operator zero/one/many;
  last-operator-remove refusal; upper-bound operator guard; --replace-operator
  atomicity; soft-delete cascades to platform_identities (DB-level CASCADE);
  every mutating method bumps the version counter.
  """

  from __future__ import annotations

  import pytest

  from alfred.identity import (
      Authorization,
      IdentityResolver,
      IdentityResolutionError,
      IdentityVersionCounter,
      LastOperatorRemovalRefusedError,
      OperatorAlreadyExistsError,
      Platform,
      _NullRateLimiter,
  )
  from alfred.identity import User


  @pytest.fixture
  def resolver(session_factory, rate_limiter) -> IdentityResolver:
      """Fresh resolver with an in-memory SQLite session factory and a null
      rate-limiter. ``session_factory`` is provided by tests/unit/conftest.py
      against a SQLite engine that mirrors the Slice-2 schema (no LISTEN/NOTIFY).
      The Postgres-only LISTEN/NOTIFY path is exercised in
      ``tests/integration/test_users_postgres.py``.
      """
      return IdentityResolver(
          session_factory=session_factory,
          version_counter=IdentityVersionCounter(),
          rate_limiter=rate_limiter,
          cache_max_entries=256,
          cache_ttl_s=60,
      )


  def test_resolve_miss_returns_none(resolver: IdentityResolver) -> None:
      assert resolver.resolve("discord", "9999999999") is None


  def test_add_minimal(resolver: IdentityResolver) -> None:
      user = resolver.add(
          name="Alice O'Connor",
          authorization=Authorization.STANDARD,
          daily_budget_usd=0.50,
          language="en-US",
      )
      assert user.slug == "alice-o-connor"
      assert user.display_name == "Alice O'Connor"
      assert user.authorization == Authorization.STANDARD.value


  def test_add_slug_collision_suffixes(resolver: IdentityResolver) -> None:
      a = resolver.add(name="Bob", daily_budget_usd=0.50, language="en-US")
      b = resolver.add(name="Bob", daily_budget_usd=0.50, language="en-US")
      assert a.slug == "bob"
      assert b.slug == "bob-2"


  def test_add_slug_collision_survives_soft_delete(resolver: IdentityResolver) -> None:
      a = resolver.add(name="Bob", daily_budget_usd=0.50, language="en-US")
      resolver.remove(a.slug)   # soft-delete
      b = resolver.add(name="Bob", daily_budget_usd=0.50, language="en-US")
      assert b.slug == "bob-2"   # NOT "bob" — soft-deleted slugs are reserved.


  def test_add_operator_upper_bound(resolver: IdentityResolver) -> None:
      resolver.add(name="Alice", authorization=Authorization.OPERATOR,
                   daily_budget_usd=1.0, language="en-US")
      with pytest.raises(OperatorAlreadyExistsError) as exc:
          resolver.add(name="Bob", authorization=Authorization.OPERATOR,
                       daily_budget_usd=1.0, language="en-US")
      assert exc.value.existing_slug == "alice"


  def test_replace_operator_atomic(resolver: IdentityResolver) -> None:
      old = resolver.add(name="Alice", authorization=Authorization.OPERATOR,
                         daily_budget_usd=1.0, language="en-US")
      new = resolver.add(name="Bob", authorization=Authorization.TRUSTED,
                         daily_budget_usd=1.0, language="en-US")
      promoted = resolver.set_(new.slug, authorization=Authorization.OPERATOR,
                               replace_operator=old.slug)
      assert promoted.authorization == Authorization.OPERATOR.value
      demoted = resolver.show(old.slug)
      assert demoted.authorization == Authorization.TRUSTED.value
      # get_operator now returns Bob.
      assert resolver.get_operator().slug == "bob"


  def test_remove_last_operator_refused(resolver: IdentityResolver) -> None:
      op_user = resolver.add(name="Op", authorization=Authorization.OPERATOR,
                             daily_budget_usd=1.0, language="en-US")
      with pytest.raises(LastOperatorRemovalRefusedError):
          resolver.remove(op_user.slug)


  def test_get_operator_zero_raises(resolver: IdentityResolver) -> None:
      with pytest.raises(IdentityResolutionError, match="no operator"):
          resolver.get_operator()


  def test_get_operator_multi_raises(resolver: IdentityResolver) -> None:
      # Two operators can only exist transiently inside --replace-operator;
      # outside that transaction the upper-bound guard prevents it. We force
      # the multi state by direct ORM insert and assert the guard catches it.
      from alfred.identity.models import User as _U
      with resolver._session_factory.begin() as s:
          s.add_all([
              _U(slug="a", display_name="A", authorization="operator",
                 daily_budget_usd=1.0, language="en-US"),
              _U(slug="b", display_name="B", authorization="operator",
                 daily_budget_usd=1.0, language="en-US"),
          ])
      with pytest.raises(IdentityResolutionError, match="multiple operators"):
          resolver.get_operator()


  def test_bind_and_resolve_roundtrip(resolver: IdentityResolver) -> None:
      user = resolver.add(name="Bob", daily_budget_usd=0.50, language="en-US")
      resolver.bind(user.slug, Platform.DISCORD, "987654321")
      resolved = resolver.resolve("discord", "987654321")
      assert resolved is not None and resolved.slug == "bob"


  def test_bind_double_platform_refused(resolver: IdentityResolver) -> None:
      user = resolver.add(name="Bob", daily_budget_usd=0.50, language="en-US")
      resolver.bind(user.slug, Platform.DISCORD, "111")
      with pytest.raises(Exception, match="already bound|UNIQUE"):
          resolver.bind(user.slug, Platform.DISCORD, "222")


  def test_bind_platform_id_in_use_refused(resolver: IdentityResolver) -> None:
      a = resolver.add(name="Alice", daily_budget_usd=0.50, language="en-US")
      b = resolver.add(name="Bob", daily_budget_usd=0.50, language="en-US")
      resolver.bind(a.slug, Platform.DISCORD, "111")
      with pytest.raises(Exception, match="UNIQUE|in_use"):
          resolver.bind(b.slug, Platform.DISCORD, "111")


  def test_set_language_validates_bcp47(resolver: IdentityResolver) -> None:
      user = resolver.add(name="Alice", daily_budget_usd=0.50, language="en-US")
      with pytest.raises(ValueError, match="BCP-47"):
          resolver.set_(user.slug, language="wat-NOT-VALID")


  def test_every_mutating_method_bumps_counter(resolver: IdentityResolver) -> None:
      counter = resolver._version_counter
      start = counter.current()
      user = resolver.add(name="Alice", daily_budget_usd=0.50, language="en-US")
      assert counter.current() == start + 1
      resolver.set_(user.slug, daily_budget_usd=1.0)
      assert counter.current() == start + 2
      resolver.bind(user.slug, Platform.DISCORD, "111")
      assert counter.current() == start + 3
      resolver.unbind(user.slug, Platform.DISCORD)
      assert counter.current() == start + 4
      # remove() bumps too — but only if not the last operator.
      resolver.add(name="Op", authorization=Authorization.OPERATOR,
                   daily_budget_usd=1.0, language="en-US")
      resolver.remove(user.slug)
      assert counter.current() == start + 6   # add(Op) + remove(alice)


  def test_resolve_lru_invalidation_on_counter_bump(resolver: IdentityResolver) -> None:
      user = resolver.add(name="Alice", daily_budget_usd=0.50, language="en-US")
      resolver.bind(user.slug, Platform.DISCORD, "111")
      first = resolver.resolve("discord", "111")
      assert first is not None and first.daily_budget_usd == 0.50

      # Mutate via set_; resolver must refetch on next resolve.
      resolver.set_(user.slug, daily_budget_usd=2.50)
      second = resolver.resolve("discord", "111")
      assert second is not None and second.daily_budget_usd == 2.50


  def test_resolve_soft_deleted_returns_none(resolver: IdentityResolver) -> None:
      a = resolver.add(name="Alice", daily_budget_usd=0.50, language="en-US")
      resolver.add(name="Op", authorization=Authorization.OPERATOR,
                   daily_budget_usd=1.0, language="en-US")
      resolver.bind(a.slug, Platform.DISCORD, "111")
      resolver.remove(a.slug)
      assert resolver.resolve("discord", "111") is None


  def test_list_and_show(resolver: IdentityResolver) -> None:
      a = resolver.add(name="Alice", daily_budget_usd=0.50, language="en-US")
      b = resolver.add(name="Bob", daily_budget_usd=0.50, language="en-US")
      users = resolver.list_()
      assert [u.slug for u in users] == ["alice", "bob"]   # ORDER BY created_at ASC.
      assert resolver.show("alice").display_name == "Alice"


  def test_list_excludes_soft_deleted_by_default(resolver: IdentityResolver) -> None:
      a = resolver.add(name="Alice", daily_budget_usd=0.50, language="en-US")
      resolver.add(name="Op", authorization=Authorization.OPERATOR,
                   daily_budget_usd=1.0, language="en-US")
      resolver.remove(a.slug)
      assert [u.slug for u in resolver.list_()] == ["op"]
      assert {u.slug for u in resolver.list_(include_deleted=True)} == {"alice", "op"}
  ```

  ```bash
  uv run pytest tests/unit/identity/test_resolver.py -v
  ```

  Expected: ALL FAIL.

- [ ] **Step 11.2 — Author `src/alfred/identity/resolver.py` (no listener yet — Task 12 adds it).**

  Shape (full body — long but each method is small):

  ```python
  """IdentityResolver — mediates (platform, platform_id) → User lookups with
  an in-process LRU cache, bump-on-mutate version counter, and a 60s TTL
  backstop. The LISTEN/NOTIFY listener is wired in by ``IdentityListener``
  (Task 12); the resolver works standalone for unit tests against SQLite.

  Public surface (cross-PR contract):
  * ``resolve(platform, platform_id) -> User | None``
  * ``add(*, name, authorization=STANDARD, daily_budget_usd, language,
         rate_limit_per_min=None, rate_limit_per_day=None,
         slug_override=None) -> User``
  * ``bind(slug, platform, platform_id) -> PlatformIdentity``
  * ``unbind(slug, platform) -> None``
  * ``remove(slug) -> None``
  * ``set_(slug, **fields) -> User``
  * ``show(slug) -> User``
  * ``list_(include_deleted=False) -> list[User]``
  * ``get_operator() -> User``

  Every mutating method:
  * bumps ``IdentityVersionCounter``;
  * issues ``NOTIFY alfred_identity_changed`` inside the same transaction
    (Postgres only — SQLite NOTIFY is a no-op);
  * writes an audit row (delegated to ``alfred.audit.writer.append``).
  """

  from __future__ import annotations

  import json
  import logging
  import time
  from collections import OrderedDict
  from collections.abc import Callable
  from dataclasses import dataclass
  from datetime import datetime, timezone
  from typing import TYPE_CHECKING

  import babel
  from sqlalchemy import select, func as sa_func
  from sqlalchemy.exc import IntegrityError
  from sqlalchemy.orm import Session, sessionmaker

  from alfred.identity.errors import (
      IdentityResolutionError,
      LastOperatorRemovalRefusedError,
      OperatorAlreadyExistsError,
  )
  from alfred.identity.models import (
      Authorization,
      Platform,
      PlatformIdentity,
      User,
  )
  from alfred.identity.rate_limit import RateLimiter
  from alfred.identity.slug import derive_slug
  from alfred.identity.version_counter import IdentityVersionCounter

  if TYPE_CHECKING:
      from collections.abc import Iterable

  _LOG = logging.getLogger(__name__)
  _NOTIFY_CHANNEL = "alfred_identity_changed"


  @dataclass
  class _CacheEntry:
      user: User
      version_seen: int
      cached_at: float   # monotonic seconds


  class IdentityResolver:
      def __init__(
          self,
          *,
          session_factory: sessionmaker[Session],
          version_counter: IdentityVersionCounter,
          rate_limiter: RateLimiter,
          cache_max_entries: int = 256,
          cache_ttl_s: int = 60,
      ) -> None:
          self._session_factory = session_factory
          self._version_counter = version_counter
          self._rate_limiter = rate_limiter
          self._cache_max = cache_max_entries
          self._cache_ttl = cache_ttl_s
          self._cache: OrderedDict[tuple[str, str], _CacheEntry] = OrderedDict()

      # ------------------------------------------------------------------
      # Read-side
      # ------------------------------------------------------------------

      def resolve(self, platform: str, platform_id: str) -> User | None:
          """Resolve (platform, platform_id) → User. Hit cache when fresh."""
          key = (platform, platform_id)
          now = time.monotonic()
          entry = self._cache.get(key)
          counter = self._version_counter.current()
          if entry is not None:
              # TTL backstop runs unconditionally (spec §2 line 164-168).
              ttl_expired = (now - entry.cached_at) >= self._cache_ttl
              stale = entry.version_seen < counter
              if not ttl_expired and not stale:
                  self._cache.move_to_end(key)
                  return entry.user
              # Stale or expired — drop and refetch.
              self._cache.pop(key, None)

          with self._session_factory() as session:
              row = self._lookup(session, platform, platform_id)
          if row is None:
              return None

          self._cache[key] = _CacheEntry(user=row, version_seen=counter, cached_at=now)
          self._cache.move_to_end(key)
          while len(self._cache) > self._cache_max:
              self._cache.popitem(last=False)
          return row

      def get_operator(self) -> User:
          """Return the household-owner row. Raises if zero or >1 operators exist."""
          with self._session_factory() as session:
              ops = session.scalars(
                  select(User)
                  .where(User.authorization == Authorization.OPERATOR.value)
                  .where(User.deleted_at.is_(None))
              ).all()
          if len(ops) == 0:
              raise IdentityResolutionError("no operator has been added yet")
          if len(ops) > 1:
              raise IdentityResolutionError(
                  f"multiple operators exist ({[o.slug for o in ops]}); "
                  f"this should be impossible — open an issue"
              )
          return ops[0]

      def show(self, slug: str) -> User:
          with self._session_factory() as session:
              user = session.scalar(select(User).where(User.slug == slug))
          if user is None:
              raise IdentityResolutionError(f"no user with slug '{slug}'")
          return user

      def list_(self, include_deleted: bool = False) -> list[User]:
          with self._session_factory() as session:
              q = select(User).order_by(User.created_at.asc())
              if not include_deleted:
                  q = q.where(User.deleted_at.is_(None))
              return list(session.scalars(q).all())

      # ------------------------------------------------------------------
      # Write-side
      # ------------------------------------------------------------------

      def add(
          self,
          *,
          name: str,
          authorization: Authorization = Authorization.STANDARD,
          daily_budget_usd: float,
          language: str,
          rate_limit_per_min: int | None = None,
          rate_limit_per_day: int | None = None,
          slug_override: str | None = None,
      ) -> User:
          self._validate_language(language)
          self._validate_budget(daily_budget_usd)

          base_slug = slug_override if slug_override else derive_slug(name)
          with self._session_factory.begin() as session:
              if authorization == Authorization.OPERATOR:
                  self._enforce_operator_upper_bound(session)
              slug = self._next_available_slug(session, base_slug)
              user = User(
                  slug=slug,
                  display_name=name,
                  authorization=authorization.value,
                  daily_budget_usd=daily_budget_usd,
                  language=language,
                  rate_limit_per_min=rate_limit_per_min,
                  rate_limit_per_day=rate_limit_per_day,
              )
              session.add(user)
              session.flush()
              self._notify(session, slug=slug, op="add")

          self._version_counter.bump()
          return user

      def bind(self, slug: str, platform: Platform, platform_id: str) -> PlatformIdentity:
          with self._session_factory.begin() as session:
              user = session.scalar(select(User).where(User.slug == slug))
              if user is None:
                  raise IdentityResolutionError(f"no user with slug '{slug}'")
              binding = PlatformIdentity(
                  user_id=user.id,
                  platform=platform.value,
                  platform_id=platform_id,
              )
              session.add(binding)
              try:
                  session.flush()
              except IntegrityError as exc:
                  raise IdentityResolutionError(
                      f"binding {platform.value}:{platform_id} conflicts with an existing row"
                  ) from exc
              self._notify(session, slug=slug, op="bind")
          self._version_counter.bump()
          return binding

      def unbind(self, slug: str, platform: Platform) -> None:
          with self._session_factory.begin() as session:
              user = session.scalar(select(User).where(User.slug == slug))
              if user is None:
                  raise IdentityResolutionError(f"no user with slug '{slug}'")
              now = datetime.now(timezone.utc)
              session.execute(
                  PlatformIdentity.__table__.update()
                  .where(PlatformIdentity.user_id == user.id)
                  .where(PlatformIdentity.platform == platform.value)
                  .where(PlatformIdentity.deleted_at.is_(None))
                  .values(deleted_at=now)
              )
              self._notify(session, slug=slug, op="unbind")
          self._version_counter.bump()

      def remove(self, slug: str) -> None:
          with self._session_factory.begin() as session:
              user = session.scalar(select(User).where(User.slug == slug))
              if user is None:
                  raise IdentityResolutionError(f"no user with slug '{slug}'")
              if user.authorization == Authorization.OPERATOR.value:
                  remaining_ops = session.scalar(
                      select(sa_func.count(User.id))
                      .where(User.authorization == Authorization.OPERATOR.value)
                      .where(User.deleted_at.is_(None))
                      .where(User.id != user.id)
                  )
                  if remaining_ops == 0:
                      raise LastOperatorRemovalRefusedError(slug)
              user.deleted_at = datetime.now(timezone.utc)
              self._notify(session, slug=slug, op="remove")
          self._version_counter.bump()

      def set_(self, slug: str, **fields: object) -> User:
          replace_operator = fields.pop("replace_operator", None)
          if "language" in fields and isinstance(fields["language"], str):
              self._validate_language(fields["language"])
          if "daily_budget_usd" in fields and isinstance(fields["daily_budget_usd"], (int, float)):
              self._validate_budget(float(fields["daily_budget_usd"]))

          with self._session_factory.begin() as session:
              user = session.scalar(select(User).where(User.slug == slug))
              if user is None:
                  raise IdentityResolutionError(f"no user with slug '{slug}'")
              promoting_to_operator = (
                  fields.get("authorization") == Authorization.OPERATOR
                  or fields.get("authorization") == Authorization.OPERATOR.value
              )
              if promoting_to_operator:
                  if replace_operator:
                      existing = session.scalar(
                          select(User).where(User.slug == replace_operator)
                      )
                      if existing is None or existing.authorization != Authorization.OPERATOR.value:
                          raise IdentityResolutionError(
                              f"--replace-operator names '{replace_operator}' which is not an operator"
                          )
                      existing.authorization = Authorization.TRUSTED.value
                  else:
                      self._enforce_operator_upper_bound(session, exclude_slug=slug)

              for k, v in fields.items():
                  if k == "rate_limit_per_min" and v == "unset":
                      user.rate_limit_per_min = None
                  elif k == "authorization" and isinstance(v, Authorization):
                      user.authorization = v.value
                  else:
                      setattr(user, k, v)
              session.flush()
              self._notify(session, slug=slug, op="set")

          self._version_counter.bump()
          return user

      # ------------------------------------------------------------------
      # Internals
      # ------------------------------------------------------------------

      def _lookup(self, session: Session, platform: str, platform_id: str) -> User | None:
          return session.scalar(
              select(User)
              .join(PlatformIdentity, PlatformIdentity.user_id == User.id)
              .where(PlatformIdentity.platform == platform)
              .where(PlatformIdentity.platform_id == platform_id)
              .where(PlatformIdentity.deleted_at.is_(None))
              .where(User.deleted_at.is_(None))
          )

      def _next_available_slug(self, session: Session, base: str) -> str:
          existing = set(session.scalars(
              select(User.slug).where(User.slug.like(f"{base}%"))
          ).all())
          if base not in existing:
              return base
          i = 2
          while f"{base}-{i}" in existing:
              i += 1
          return f"{base}-{i}"

      def _enforce_operator_upper_bound(
          self, session: Session, exclude_slug: str | None = None,
      ) -> None:
          q = (
              select(User)
              .where(User.authorization == Authorization.OPERATOR.value)
              .where(User.deleted_at.is_(None))
          )
          if exclude_slug is not None:
              q = q.where(User.slug != exclude_slug)
          existing = session.scalar(q)
          if existing is not None:
              raise OperatorAlreadyExistsError(
                  existing_slug=existing.slug,
                  existing_display_name=existing.display_name,
              )

      def _validate_language(self, language: str) -> None:
          try:
              babel.Locale.parse(language.replace("-", "_"))
          except (babel.UnknownLocaleError, ValueError) as exc:
              raise ValueError(f"BCP-47 parse failed for '{language}': {exc}") from exc

      def _validate_budget(self, budget: float) -> None:
          if not (budget > 0) or budget != budget:   # NaN-safe positive check
              raise ValueError(f"daily_budget_usd must be > 0; got {budget!r}")

      def _notify(self, session: Session, *, slug: str, op: str) -> None:
          """Issue NOTIFY inside the current transaction (Postgres only; no-op on SQLite)."""
          dialect = session.bind.dialect.name if session.bind else ""
          if dialect != "postgresql":
              return
          payload = json.dumps({"slug": slug, "op": op})
          # pg_notify is a stored procedure available on Postgres; safe to bind.
          session.execute(
              select(sa_func.pg_notify(_NOTIFY_CHANNEL, payload))
          )
  ```

- [ ] **Step 11.3 — Re-run the test enumeration.**

  ```bash
  uv run pytest tests/unit/identity/test_resolver.py -v
  ```

  Expected: ALL PASS.

- [ ] **Step 11.4 — Add to package re-exports + commit.**

  ```python
  # __init__.py
  from alfred.identity.resolver import IdentityResolver
  __all__ = [..., "IdentityResolver", ...]
  ```

  ```bash
  git add src/alfred/identity/resolver.py src/alfred/identity/__init__.py \
          tests/unit/identity/test_resolver.py
  git commit -m "feat(identity): IdentityResolver core — resolve/add/bind/unbind/remove/set + LRU + counter (#<issue>)"
  ```

---

### Task 12: `IdentityListener` — LISTEN/NOTIFY with exponential-backoff reconnect supervisor — PR-A commit 12

**Owner:** `alfred-python-developer`; review by `alfred-security-engineer` (silent loss-of-invalidations is a CLAUDE.md hard rule #7 violation; the supervisor's existence is load-bearing).

**Files:**

- Modify: `src/alfred/identity/resolver.py` — append `IdentityListener` class.
- Modify: `tests/unit/identity/test_resolver.py` — add the reconnect test (err-001).
- Modify: `tests/integration/test_users_postgres.py` — see Task 13 (the listener's Postgres-level test lives there).

**Steps:**

- [ ] **Step 12.1 — Write the failing reconnect-on-disconnect unit test (err-001).**

  Append to `tests/unit/identity/test_resolver.py`:

  ```python
  """Listener reconnect supervisor — err-001 (spec §2 line 162)."""

  import asyncio
  from unittest.mock import AsyncMock, MagicMock

  import pytest

  from alfred.identity.resolver import IdentityListener


  @pytest.mark.asyncio
  async def test_identity_listener_reconnect_on_connection_loss(
      monkeypatch, version_counter,
  ) -> None:
      """The listener wraps its LISTEN loop in an exponential-backoff supervisor:
      on a raised ConnectionError it sleeps `backoff_s`, reconnects, resets backoff
      on success. After three forced disconnects the version counter has bumped at
      least once per simulated NOTIFY between disconnects.
      """
      events = ["disconnect", {"slug": "alice", "op": "add"},
                "disconnect", {"slug": "bob", "op": "add"},
                "disconnect", "shutdown"]

      def fake_connect():
          # Return a mock connection that yields the next event on each await.
          conn = MagicMock()
          conn.add_listener = AsyncMock()
          conn.close = AsyncMock()
          return conn

      reconnect_count = 0
      async def fake_listen_loop(conn, notify_callback, stop_event):
          nonlocal reconnect_count
          while events:
              ev = events.pop(0)
              if ev == "disconnect":
                  reconnect_count += 1
                  raise ConnectionError("simulated disconnect")
              if ev == "shutdown":
                  stop_event.set()
                  return
              notify_callback(ev)

      listener = IdentityListener(
          dsn="postgresql://fake",
          version_counter=version_counter,
          backoff_start_s=0.001,
          backoff_max_s=0.01,
          connect_factory=fake_connect,
          listen_loop=fake_listen_loop,
      )
      task = asyncio.create_task(listener.run())
      await asyncio.sleep(0.2)
      listener.stop()
      await asyncio.wait_for(task, timeout=2.0)

      # Two NOTIFY events between three disconnects → counter bumped ≥ 2.
      assert version_counter.current() >= 2
      assert reconnect_count == 3
  ```

- [ ] **Step 12.2 — Author `IdentityListener` in `src/alfred/identity/resolver.py`.**

  Append:

  ```python
  import asyncio


  class IdentityListener:
      """Background asyncio task that LISTENs on ``alfred_identity_changed`` and
      bumps the local ``IdentityVersionCounter`` on every receipt.

      Wraps the listen loop in an exponential-backoff reconnect supervisor:
      ``backoff_start_s`` → ×2 each failure → ``backoff_max_s`` cap; resets on
      successful LISTEN. CLAUDE.md hard rule #7 (no silent failures in security
      paths) is honoured — a dropped listener would otherwise silently age out
      soft-delete invalidations.
      """

      def __init__(
          self,
          *,
          dsn: str,
          version_counter: IdentityVersionCounter,
          backoff_start_s: float = 1.0,
          backoff_max_s: float = 60.0,
          connect_factory: Callable[[], object] | None = None,
          listen_loop: Callable[..., asyncio.Future[None]] | None = None,
      ) -> None:
          self._dsn = dsn
          self._version_counter = version_counter
          self._backoff_start = backoff_start_s
          self._backoff_max = backoff_max_s
          self._connect_factory = connect_factory or self._default_connect
          self._listen_loop = listen_loop or self._default_listen_loop
          self._stop_event = asyncio.Event()
          self._reconnect_count = 0

      async def run(self) -> None:
          backoff = self._backoff_start
          while not self._stop_event.is_set():
              try:
                  conn = self._connect_factory()
                  await self._listen_loop(conn, self._on_notify, self._stop_event)
                  # Clean exit (stop requested or graceful close) — break.
                  return
              except ConnectionError as exc:
                  self._reconnect_count += 1
                  _LOG.warning(
                      "identity_listener_disconnected",
                      extra={"reconnect_count": self._reconnect_count,
                             "backoff_s": backoff, "error": str(exc)},
                  )
                  try:
                      await asyncio.wait_for(self._stop_event.wait(), timeout=backoff)
                      return   # stop requested during backoff
                  except asyncio.TimeoutError:
                      pass
                  backoff = min(backoff * 2, self._backoff_max)
              else:
                  backoff = self._backoff_start   # reset on success

      def stop(self) -> None:
          self._stop_event.set()

      def _on_notify(self, payload: dict[str, object]) -> None:
          self._version_counter.bump()
          _LOG.debug("identity_notify_received", extra=payload)

      async def _default_connect(self):
          import psycopg
          return psycopg.AsyncConnection.connect(self._dsn, autocommit=True)

      async def _default_listen_loop(self, conn, notify_callback, stop_event):
          # psycopg async LISTEN — implemented against the real connection in
          # tests/integration/test_users_postgres.py. The shape here matches
          # the test-double fixture so the supervisor's reconnect behaviour is
          # the only thing under unit test.
          async with conn as c:
              await c.execute(f"LISTEN {_NOTIFY_CHANNEL}")
              while not stop_event.is_set():
                  notify = await c.notifies().__anext__()
                  payload = json.loads(notify.payload) if notify.payload else {}
                  notify_callback(payload)
  ```

- [ ] **Step 12.3 — Re-run the listener test.**

  ```bash
  uv run pytest tests/unit/identity/test_resolver.py::test_identity_listener_reconnect_on_connection_loss -v
  ```

  Expected: PASS.

- [ ] **Step 12.4 — Commit (PR-A commit 12).**

  ```bash
  git add src/alfred/identity/resolver.py tests/unit/identity/test_resolver.py
  git commit -m "feat(identity): IdentityListener — LISTEN/NOTIFY supervisor with exponential-backoff reconnect (err-001) (#<issue>)"
  ```

---

### Task 13: Postgres integration test — `tests/integration/test_users_postgres.py` — PR-A commit 13

**Owner:** `alfred-python-developer`.

**Files:**

- Create: `tests/integration/test_users_postgres.py`.

**Steps:**

- [ ] **Step 13.1 — Author the integration test.**

  ```python
  """User + PlatformIdentity CRUD against real Postgres; LISTEN/NOTIFY round-trip.

  Slice-2 invariants enforced at the DB layer (CHECK / UNIQUE / partial UNIQUE
  / CASCADE) and the LISTEN/NOTIFY cross-process handshake.
  """

  from __future__ import annotations

  import asyncio
  import json

  import psycopg
  import pytest
  from sqlalchemy import text
  from sqlalchemy.exc import IntegrityError

  from alfred.identity import (
      Authorization,
      IdentityResolver,
      IdentityVersionCounter,
      Platform,
      _NullRateLimiter,
  )

  pytestmark = pytest.mark.integration


  def test_authorization_check_constraint(postgres_session) -> None:
      with pytest.raises(IntegrityError, match="ck_users_authorization"):
          postgres_session.execute(text(
              "INSERT INTO users (slug, display_name, authorization, daily_budget_usd, language, created_at) "
              "VALUES ('x', 'X', 'admin', 1.0, 'en-US', now())"
          ))


  def test_daily_budget_positive_check(postgres_session) -> None:
      with pytest.raises(IntegrityError, match="daily_budget_positive"):
          postgres_session.execute(text(
              "INSERT INTO users (slug, display_name, authorization, daily_budget_usd, language, created_at) "
              "VALUES ('x', 'X', 'standard', 0.0, 'en-US', now())"
          ))


  def test_platform_identity_unique_platform_id(postgres_session) -> None:
      postgres_session.execute(text(
          "INSERT INTO users (slug, display_name, authorization, daily_budget_usd, language, created_at) "
          "VALUES ('alice', 'Alice', 'standard', 1.0, 'en-US', now()) RETURNING id"
      ))
      postgres_session.execute(text(
          "INSERT INTO users (slug, display_name, authorization, daily_budget_usd, language, created_at) "
          "VALUES ('bob', 'Bob', 'standard', 1.0, 'en-US', now()) RETURNING id"
      ))
      postgres_session.execute(text(
          "INSERT INTO platform_identities (user_id, platform, platform_id, created_at) "
          "VALUES ((SELECT id FROM users WHERE slug='alice'), 'discord', '111', now())"
      ))
      with pytest.raises(IntegrityError, match="uq_platform_identities_platform_id"):
          postgres_session.execute(text(
              "INSERT INTO platform_identities (user_id, platform, platform_id, created_at) "
              "VALUES ((SELECT id FROM users WHERE slug='bob'), 'discord', '111', now())"
          ))


  def test_partial_unique_on_active_bindings(postgres_session) -> None:
      """Same user, same platform, twice — refused while the first is active;
      allowed after the first is soft-deleted."""
      postgres_session.execute(text(
          "INSERT INTO users (slug, display_name, authorization, daily_budget_usd, language, created_at) "
          "VALUES ('alice', 'Alice', 'standard', 1.0, 'en-US', now())"
      ))
      postgres_session.execute(text(
          "INSERT INTO platform_identities (user_id, platform, platform_id, created_at) "
          "VALUES ((SELECT id FROM users WHERE slug='alice'), 'discord', '111', now())"
      ))
      with pytest.raises(IntegrityError, match="uq_platform_identities_user_platform_active"):
          postgres_session.execute(text(
              "INSERT INTO platform_identities (user_id, platform, platform_id, created_at) "
              "VALUES ((SELECT id FROM users WHERE slug='alice'), 'discord', '222', now())"
          ))


  def test_cascade_delete(postgres_session) -> None:
      postgres_session.execute(text(
          "INSERT INTO users (slug, display_name, authorization, daily_budget_usd, language, created_at) "
          "VALUES ('alice', 'Alice', 'standard', 1.0, 'en-US', now())"
      ))
      postgres_session.execute(text(
          "INSERT INTO platform_identities (user_id, platform, platform_id, created_at) "
          "VALUES ((SELECT id FROM users WHERE slug='alice'), 'discord', '111', now())"
      ))
      postgres_session.execute(text("DELETE FROM users WHERE slug='alice'"))
      remaining = postgres_session.scalar(text(
          "SELECT COUNT(*) FROM platform_identities WHERE platform_id='111'"
      ))
      assert remaining == 0


  @pytest.mark.asyncio
  async def test_listen_notify_round_trip(postgres_dsn) -> None:
      """Mutating CLI session issues NOTIFY in-transaction; listener observes
      counter bump in a separate session."""
      from alfred.memory.db import build_session_scope
      session_factory = build_session_scope(postgres_dsn)

      counter = IdentityVersionCounter()
      from alfred.identity.resolver import IdentityListener
      listener = IdentityListener(
          dsn=postgres_dsn,
          version_counter=counter,
          backoff_start_s=0.05,
          backoff_max_s=0.5,
      )
      listener_task = asyncio.create_task(listener.run())
      await asyncio.sleep(0.5)   # let LISTEN bind.

      resolver = IdentityResolver(
          session_factory=session_factory,
          version_counter=IdentityVersionCounter(),   # different counter for the writer.
          rate_limiter=_NullRateLimiter(),
      )
      resolver.add(name="Alice", daily_budget_usd=0.50, language="en-US")
      await asyncio.sleep(0.5)   # let the NOTIFY propagate.

      listener.stop()
      await asyncio.wait_for(listener_task, timeout=2.0)

      assert counter.current() >= 1
  ```

- [ ] **Step 13.2 — Run.**

  ```bash
  uv run pytest tests/integration/test_users_postgres.py -v
  ```

  Expected: PASS.

- [ ] **Step 13.3 — Commit (PR-A commit 13).**

  ```bash
  git add tests/integration/test_users_postgres.py
  git commit -m "test(identity): integration — CHECK/UNIQUE constraints + LISTEN/NOTIFY round-trip (#<issue>)"
  ```

---

### Task 14: `alfred user *` Typer subcommands — PR-A commit 14

**Owner:** `alfred-python-developer`; review by `alfred-security-engineer` on `--replace-operator` + `--yes` non-TTY gating.

**Files:**

- Create: `src/alfred/identity/cli.py`.
- Modify: `src/alfred/cli/main.py` — register the `user` sub-app.
- Create: `tests/unit/identity/test_cli.py`.

**Steps:**

- [ ] **Step 14.1 — Write the failing CLI test enumeration.**

  Create `tests/unit/identity/test_cli.py`. Cover (one test per item):

  - `alfred user add --name "Alice O'Connor"` → exits 0; stdout includes the localised `cli.user.added`; the slug appears as `alice-o-connor`.
  - `alfred user add --name "Bob" --output-slug` → stdout is exactly `bob\n`.
  - `alfred user add --authorization read-only` and `--authorization read_only` both produce the same DB row.
  - `alfred user add --language wat-NOT-VALID` → exits 2 with `cli.user.error.invalid_language` in stderr.
  - `alfred user add --daily-budget-usd 0` → exits 2 with `cli.user.error.budget_must_be_positive`.
  - `alfred user add --authorization operator --name "Bob"` when an operator exists → exits 2 with `cli.user.error.operator_already_exists` and names the existing operator.
  - `alfred user add --authorization operator --name "Bob" --replace-operator alice` → exits 0; the old operator demotes to `trusted` atomically.
  - `alfred user list` → renders a `rich.Table` with the six i18n'd column headers; empty state shows `cli.user.list.empty_hint`.
  - `alfred user list --json` → emits a stable JSON array; field names match `User` ORM column names.
  - `alfred user list --include-deleted` → soft-deleted rows render with strikethrough + `(deleted)` annotation.
  - `alfred user show <slug>` → renders override-vs-derived indicators for `rate_limit_per_min`.
  - `alfred user remove <last-operator>` → exits 2 with `cli.user.error.remove_last_operator_refused`.
  - `alfred user remove <other-user>` under non-TTY without `--yes` → exits 2 with `cli.user.error.no_tty_without_yes`.
  - `alfred user remove <other-user> --yes` → exits 0; row soft-deletes.
  - `alfred user bind <slug> --platform discord --id 111` → exits 0; subsequent `alfred user resolve` finds it. (Resolver is internal; test invokes `IdentityResolver.resolve` directly to confirm.)
  - `alfred user bind <slug>` to an already-bound user/platform → exits 2 with `cli.user.error.user_already_bound`.
  - `alfred user set <slug> --rate-limit-per-min unset` → updates the row to `NULL`.
  - Every mutating command writes one audit row with `event="user.<op>"`, `actor_user_id=<operator slug>`, and the expected `subject` JSON.
  - Ctrl-C inside the confirmation prompt → exits 130.

  Use `typer.testing.CliRunner` for invocation; the audit-row assertion checks `tests/unit/audit/conftest.py`'s `audit_buffer` fixture.

  ```bash
  uv run pytest tests/unit/identity/test_cli.py -v
  ```

  Expected: ALL FAIL.

- [ ] **Step 14.2 — Author `src/alfred/identity/cli.py`.**

  Shape — one Typer `user_app = typer.Typer(help=t("cli.user.help.group"))` with seven subcommands. Each callback:

  1. Loads `Settings` via `_load_settings_or_die()`.
  2. Constructs the resolver from a session factory (re-used from `cli/main.py`'s bootstrap; pass through, not re-create).
  3. Maps Typer option values to resolver kwargs (snake_case enum conversion happens here).
  4. Wraps resolver call in `try/except IdentityError` arms that print the appropriate `t("cli.user.error.*")` key and `raise typer.Exit(code=…)`.
  5. On success, prints the appropriate `t("cli.user.<verb>")` confirmation.
  6. Writes an audit row via `alfred.audit.writer.append(event="user.<op>", actor_user_id=<operator>, subject={…})`.

  Key implementation notes:

  - Kebab/snake normaliser for `--authorization`:

    ```python
    def _normalise_authorization(raw: str) -> Authorization:
        try:
            return Authorization(raw.replace("-", "_"))
        except ValueError as exc:
            typer.echo(t("cli.user.error.invalid_authorization", value=raw), err=True)
            raise typer.Exit(code=2) from exc
    ```

  - `--language` ingress validation runs `babel.Locale.parse` in a Typer callback, plus the catalog-missing warn-with-confirm (devex-003).

  - `--yes` non-TTY gate:

    ```python
    if not sys.stdin.isatty() and not yes:
        typer.echo(t("cli.user.error.no_tty_without_yes"), err=True)
        raise typer.Exit(code=2)
    ```

  - `--output-slug` short-circuits — prints `user.slug` to stdout and exits 0 without rendering the table or success message.

  - Audit writes go through `alfred.audit.writer.append(...)` — actor is the current invoking user. For Slice 2, the CLI is operator-only (TUI-gated); we look up the operator via `IdentityResolver.get_operator()` at command-entry and use that slug as `actor_user_id`. If `get_operator()` raises (no operator yet), we fall back to `actor_user_id="<bootstrap>"` for the very first `alfred user add --authorization operator` invocation — the audit row records the bootstrap.

- [ ] **Step 14.3 — Wire the sub-app into `src/alfred/cli/main.py`.**

  Add after the existing `app = typer.Typer(...)` line:

  ```python
  from alfred.identity.cli import user_app

  app.add_typer(user_app, name="user")
  ```

- [ ] **Step 14.4 — Re-run the CLI test enumeration.**

  ```bash
  uv run pytest tests/unit/identity/test_cli.py -v
  ```

  Expected: ALL PASS.

- [ ] **Step 14.5 — Run mypy + pyright + ruff.**

  ```bash
  uv run ruff check src/alfred/identity src/alfred/cli tests/unit/identity --fix
  uv run ruff format src/alfred/identity src/alfred/cli tests/unit/identity
  uv run mypy src/alfred/identity src/alfred/cli
  uv run pyright src/alfred/identity src/alfred/cli
  ```

  Expected: clean.

- [ ] **Step 14.6 — Commit (PR-A commit 14).**

  ```bash
  git add src/alfred/identity/cli.py src/alfred/cli/main.py \
          tests/unit/identity/test_cli.py
  git commit -m "feat(cli): alfred user add/list/show/remove/bind/unbind/set (incl. --replace-operator + --output-slug) (#<issue>)"
  ```

---

### Task 15: TUI startup wire-in + per-row `language`/`persona_id` columns on episodes + audit — PR-A commit 15

**Owner:** `alfred-python-developer`.

**Why:** the migration (Task 7) added the columns; the orchestrator + episodic writer + audit writer don't write into them yet. PR A is the cheapest moment to plumb the writes so PR B's signature flip doesn't also need to teach the writers about new columns. PR A's writes use literal `persona_id="alfred"` and `language=user.language` from the TUI's resolved operator; PR B widens to the full `handle_user_message(*, user, …)` shape.

**Files:**

- Modify: `src/alfred/memory/episodic.py` — accept + write `language`/`persona_id` on `record()`.
- Modify: `src/alfred/audit/writer.py` — accept + write `language`/`persona_id` on `append()`.
- Modify: `src/alfred/comms/tui.py` — call `IdentityResolver.resolve("tui", settings.operator_name)` at startup; replace literal `"operator"` user_id with the resolved slug.
- Modify: `tests/smoke/test_hello_alfred.py` — assert the canonical slug flows end-to-end.

**Steps:**

- [ ] **Step 15.1 — Modify `EpisodicMemory.record` signature.**

  Add `language: str | None = None, persona_id: str | None = None` kwargs; pass through to the SQL insert. Default both to `None` so slice-1 call sites continue working unchanged (they'll be updated in PR B).

- [ ] **Step 15.2 — Modify `audit.writer.append` signature** the same way.

- [ ] **Step 15.3 — Modify `AlfredTuiApp` startup.**

  ```python
  # In AlfredTuiApp construction (current shape — adapt to actual line numbers):
  operator = identity_resolver.resolve("tui", settings.operator_name)
  if operator is None:
      typer.echo(t("cli.user.error.no_operator"), err=True)
      raise typer.Exit(code=2)
  self._operator_slug = operator.slug
  self._operator_language = operator.language
  ```

  Inside the per-turn handler, replace any literal `"operator"` user_id with `self._operator_slug`, and pass `language=self._operator_language, persona_id="alfred"` into the episodic + audit writes.

- [ ] **Step 15.4 — Update the smoke test to assert the canonical slug.**

  In `tests/smoke/test_hello_alfred.py`, change the existing assertion that checks `user_id == "operator"` (or whatever the slice-1 shape is) to assert `user_id == operator.slug` where `operator` is resolved via `IdentityResolver.resolve("tui", settings.operator_name)` after running `alembic upgrade head` against the testcontainer.

- [ ] **Step 15.5 — Run the smoke test.**

  ```bash
  uv run pytest tests/smoke/test_hello_alfred.py -v
  ```

  Expected: PASS.

- [ ] **Step 15.6 — Commit (PR-A commit 15).**

  ```bash
  git add src/alfred/memory/episodic.py src/alfred/audit/writer.py \
          src/alfred/comms/tui.py tests/smoke/test_hello_alfred.py
  git commit -m "feat(memory,audit,tui): per-row language/persona_id columns + TUI resolves operator slug at startup (#<issue>)"
  ```

---

### Task 16: Full quality-bar sweep + final commit — PR-A commit 16

**Owner:** `alfred-python-developer`.

**Steps:**

- [ ] **Step 16.1 — Run the full quality bar.**

  ```bash
  make check
  ```

  Expected: every gate green (`ruff check`, `ruff format --check`, `mypy --strict`, `pyright`, `pytest tests/unit tests/integration`, `pybabel compile --check`).

  If anything fails, the fix is a fixup commit (`git commit --fixup=<sha>`) NOT a new top-level commit — keep the PR's logical commit graph clean.

- [ ] **Step 16.2 — Autosquash any fixups.**

  ```bash
  make autosquash
  ```

  (Equivalent to `git rebase -i --autosquash main` with no-edit.)

- [ ] **Step 16.3 — Final `make check`** after autosquash. Re-run; must stay green.

- [ ] **Step 16.4 — Push the branch.** `/path-to-green` takes over from here for CI feedback + reviewer comments.

---

## 2. Acceptance gates

The PR is mergeable when **every** gate below is green.

- [ ] `uv run pytest tests/unit/i18n/test_concurrent_language.py -v` — PASS.
- [ ] `uv run pytest tests/unit/i18n/ -v` — every slice-1 i18n test still green.
- [ ] `uv run pytest tests/unit/identity -v` — every Identity-layer unit test PASS (slug, version_counter, models, resolver, cli).
- [ ] `uv run pytest tests/integration/test_users_postgres.py -v` — PASS (CHECK + UNIQUE + CASCADE + partial UNIQUE + LISTEN/NOTIFY round-trip).
- [ ] `uv run pytest tests/integration/test_migration_0004_backfill.py -v` — ALL FOUR scenarios PASS (te-001).
- [ ] `uv run pytest tests/smoke/test_hello_alfred.py -v` — PASS with the canonical operator slug (not literal `"operator"`).
- [ ] `uv run alembic upgrade head` — first run upgrades cleanly; second run is a no-op (idempotent).
- [ ] `uv run alembic downgrade -1 && uv run alembic upgrade head` — round-trips with no data loss on 0003-shape rows.
- [ ] `uv run ruff check src tests` — clean.
- [ ] `uv run ruff format --check src tests` — clean.
- [ ] `uv run mypy src/alfred/` — clean.
- [ ] `uv run pyright src/alfred/` — clean.
- [ ] `uv run pybabel compile -d locale --check` — no catalog drift; every `cli.user.*`/`cli.help.root`/`cli.setup.*` key resolves.
- [ ] `make check` — all gates green.
- [ ] `alfred user add --name "Alice O'Connor"` produces slug `alice-o-connor` (manual smoke).
- [ ] `alfred user add --name "🌟🎉"` produces slug `user`; the CLI warns `cli.user.add.slug_fallback`.
- [ ] `alfred user remove <last-operator>` → exits 2 with `cli.user.error.remove_last_operator_refused`.
- [ ] `alfred user add --authorization operator --name "Other"` (when an operator exists) → exits 2 with `cli.user.error.operator_already_exists` unless `--replace-operator <existing>` is passed.
- [ ] `alfred user add --authorization operator --name "Other" --replace-operator <existing-slug>` → exits 0; the named existing operator demotes to `trusted` atomically.
- [ ] Listener reconnect test green (err-001 — `test_identity_listener_reconnect_on_connection_loss`).
- [ ] ContextVar isolation test green (`test_set_language_isolates_per_coroutine`).

## 3. Open questions / decisions deferred to plan time

Per writing-plans contract, this section should be empty for PR A — every spec section that touches PR A is concrete. Two implementation-detail decisions surfaced while drafting this plan:

- **Ordering between Task 7 (migration) and Task 8 (slug pipeline).** The migration imports `derive_slug` from `alfred.identity.slug`. Resolution: implement Task 8 **before** Task 7. The plan numbering keeps Task 7 first for logical clustering (migration belongs with ORM and resolver); the implementing engineer reorders to slug → migration. Step 7.7 calls this out explicitly.
- **SQLAlchemy partial-UNIQUE expression syntax.** The `__table_args__` partial-UNIQUE uses `postgresql_where=text("deleted_at IS NULL")` if the `mapped_column` lookup at import time fails (it's been an intermittent issue in SQLAlchemy 2.0.x). Step 6.2 documents both forms; the implementer picks whichever passes Step 6.3.

## 4. References

- Spec: [`docs/superpowers/specs/2026-05-26-slice-2-discord-multiuser-design.md`](../specs/2026-05-26-slice-2-discord-multiuser-design.md) §0.1, §0.2, §2, §3 (catalog rows), §4, §5, §6 PR A row.
- ADRs created in this PR: 0009 (`CommsAdapter` Protocol Slice-2-only — body), 0010 (canonical user_id + LISTEN/NOTIFY — body), 0011 (per-user BudgetGuard — placeholder), 0012 (file-backed SecretBroker — placeholder), 0013 (defer T1+T3+dual-LLM to Slice 3 — placeholder, supersedes ADR-0008 in part).
- PRD §5 (Architecture Overview), §6.1 (Multi-modal Comms), §6.2 (Multi-layered Memory), §7.2 (Multi-User Identity & Authorization).
- Slice 1 plan: [`docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md`](../plans/2026-05-24-slice-1-hello-alfred.md).
- Cross-PR contracts (PRs B/C/D consume these — see top of file): `IdentityResolver` public methods, `User`/`PlatformIdentity` ORM columns, `IdentityVersionCounter` surface, `Authorization`/`Platform` enum values, error types, slug derivation pipeline.

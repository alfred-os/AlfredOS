# Slice 2 — PR D1: CommsAdapter Protocol + OutboundDlp + RateLimiter + markdown splitter — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development`. Steps use checkbox (`- [ ]`) syntax — tick each one as the implementing subagent completes it. Dispatch one subagent per major task group (see "Subagent owner" line under each Section-1 task). Do not start a downstream task until its upstream gates are green locally.

**Goal:** Land the `CommsAdapter` Protocol seam, the `TuiAdapter` wrap, `OutboundDlp` with the generic-API-key regex stage + canary stub + structlog bridge, the `RateLimiter` Protocol + in-process token-bucket implementation with the `read_only` security invariant baked in, and the markdown-aware splitter. Backend-only — `discord.py` does **not** enter `pyproject.toml` here; PR D2 ships the real `DiscordAdapter` on top of the contracts this PR publishes.

**Spec:** [`docs/superpowers/plans/2026-05-26-slice-2-discord-multiuser-design.md`](./2026-05-26-slice-2-discord-multiuser-design.md) §2 (CommsAdapter Protocol + TuiAdapter wrap, lines 99–122), §3 (Outbound DLP lines 487–504; Per-user rate limiting lines 472–485; Markdown-aware splitter lines 577–579), §5 (unit-test rows for `test_rate_limit`/`test_dlp`/`test_tui_adapter`/`test_no_direct_adapter_imports`, lines 789, 794, 797, 798), §6 PR D1 row (line 872).

**Depends on (MUST be merged to `main` before this PR opens):**

- **PR A** — `IdentityResolver`, `User` ORM (with `User.authorization` enum: `read_only` / `standard` / `trusted` / `operator`), `IdentityVersionCounter`, `alfred user *` CLI, migration 0004, ContextVar i18n refactor.
- **PR B** — `Orchestrator.handle_user_message(*, user, content, working_memory)`, `WorkingMemoryPool` at `src/alfred/memory/working.py` keyed on `(persona, user_id)`, `BudgetGuard.check_and_charge(user_id, cost_usd)` per-user.
- **PR C** — `SecretBroker(secrets_file=…, require_file=…)` with file backend + four error subtypes (`SecretBrokerConfigError` base + `SecretBrokerPermissionsError` + `SecretBrokerFileMissingError` + `SecretBrokerNotAFileError`) + `_PREFER_FILE` set; **plus** `tests/unit/_shared/import_violation.py` shared helper (`_remediation_message(...)` + AST-walk skeleton) which this PR reuses for `test_no_direct_adapter_imports.py`.

**Architecture summary.** Two seams ship here, each one Protocol-shaped so its concrete implementation is mock-injectable in tests and swappable in later slices without touching consumer call sites:

1. **`CommsAdapter` Protocol** (`src/alfred/comms/adapter.py`). In-process, Slice-2-only. The `TuiAdapter` wrap lands now; the `DiscordAdapter` lands in PR D2; the Slice-3 MCP-transport rewrite inverts the polarity (spec line 105–110) and is documented in ADR-0009. **Hard invariant**: no consumer outside `src/alfred/comms/` imports a concrete adapter class — they import the Protocol from `adapter.py`. This is enforced by `test_no_direct_adapter_imports.py`, which is what makes the Slice-3 swap a single-module rewrite rather than a cross-cutting refactor.
2. **`RateLimiter` Protocol** (`src/alfred/identity/rate_limit.py`). Async-from-day-one (Slice 5+ swaps in a Redis-backed impl). `read_only` enforcement runs as the FIRST line of `allow()` — a security invariant, not a tunable perf default (spec line 223).

A third, smaller seam ships as a concrete service rather than a Protocol: `OutboundDlp.scan` (`src/alfred/security/dlp.py`). Two pluggable stages (stage 1 = broker redact; stage 2 = generic-API-key regex; stage 3 = canary stub returning input unchanged as a regression guard for Slice 3). The structlog leaf-string redactor in `src/alfred/cli/main.py:123` (`_redact_value`) is refactored to route through `OutboundDlp.scan` so the operator console gains the same generic-API-key coverage the Discord outbound path will (sec-003).

The markdown splitter is a pure function (`_split_for_discord` in `src/alfred/comms/markdown_split.py`); no Protocol needed.

**Tech stack:** Python 3.12+ • asyncio • `typing.Protocol` • Pydantic v2 frozen models for the health dataclasses • `hypothesis` for splitter property tests • `structlog` for the bridge refactor. No new third-party dependency.

**Subagent owner:** primary = `alfred-comms-engineer` (adapter Protocol, TuiAdapter wrap, markdown splitter, import-isolation test, TUI smoke regression). `alfred-security-engineer` co-owns the DLP module and the structlog bridge (per-file 100% coverage + audit-on-modification + canary stub). `alfred-python-developer` reviews the splitter helper and the Protocol shapes for conventions drift. `alfred-architect` confirms the cross-PR contract surface (the contract-publication list below) matches what PR D2 will consume.

**Cross-PR contracts you publish (PR D2 + Slice-3 MCP swap depend on these — DO NOT change once D1 merges):**

- `CommsAdapter(Protocol)` with `name: str`, `async def start() -> None`, `async def run() -> None`, `async def stop() -> None`, `def health() -> AdapterHealth`.
- `AdapterHealth` frozen dataclass: `gateway_connected: bool`, `last_on_ready_at: datetime | None`, `recent_reconnect_count: int`. TUI returns sensible defaults for the Discord-specific fields (`gateway_connected=True` while the Textual loop is running, `last_on_ready_at=` adapter start time, `recent_reconnect_count=0`).
- `_DiscordClientLike(Protocol)` structural Protocol covering `event/start/close/is_ready` — lives in `src/alfred/comms/discord_types.py` (NOT inside the future `discord.py`-importing module) so PR D2 imports the Protocol without a circular dep.
- `RateLimiter(Protocol)` async: `async def allow(user: User) -> bool`, `async def reset(user_id: str) -> None`, `def health() -> RateLimiterHealth`.
- `InProcessTokenBucketRateLimiter` concrete impl. `read_only` short-circuit FIRST in `allow()` (security invariant). Authorization defaults per spec line 478–483: `standard=30/min`, `trusted=60/min`, `operator=unlimited`, `read_only=0/min` (refusal). `User.rate_limit_per_min` (nullable) overrides the authorization-derived default when set on any tier EXCEPT `read_only`; the override is ignored on `read_only` because the short-circuit ran first (spec line 223).
- `OutboundDlp.scan(text: str) -> str` two-stage + canary stub: stage 1 = `broker.redact`, stage 2 = `re.compile(r"\b(?:sk|pk|tok|key)[-_][A-Za-z0-9]{20,}\b")` → `[REDACTED:api-key-shape]`, stage 3 = literal `return text` (regression guard). Audit-on-modification: when `len(pre) != len(post)` the call writes one `event=dlp.outbound_redacted` audit row with `subject={"pre_bytes": <int>, "post_bytes": <int>, "stages_triggered": [...]}`. Modification stays silent to the user; length-delta oracle is a documented Slice-3 mitigation task.
- `_split_for_discord(text, max_len=2000)` in `src/alfred/comms/markdown_split.py` — markdown-state-aware splitter. Slice-4 Telegram reuses with `max_len=4096`. Hypothesis property: for any text, concatenating the chunks modulo close/re-open markers equals the original.
- structlog `_redact_value` in `src/alfred/cli/main.py` refactored to call `OutboundDlp.scan` once-per-leaf-string. Substitution happens at structlog processor registration; **no call-site changes** elsewhere.

**ADR-0009 status.** Per spec §5 line 835 the **full body** of ADR-0009 lands in PR A (dispatched to `alfred-docs-author` alongside ADR-0010). This PR cites ADR-0009 from code comments + the import-isolation-test failure message and assumes the body is on `main`. If for any reason ADR-0009's body has NOT landed by the time this PR opens, STOP — escalate to `alfred-architect` rather than backfilling the ADR inline here.

---

## 0. Files this PR creates or modifies

**Source (creates):**

- `src/alfred/comms/adapter.py` — `CommsAdapter(Protocol)` + `AdapterHealth` frozen dataclass.
- `src/alfred/comms/discord_types.py` — `_DiscordClientLike(Protocol)` (structural, covers `event/start/close/is_ready`). Lives in `comms/` so PR D2's `discord.py`-importing `comms/discord.py` can `from .discord_types import _DiscordClientLike` without a cycle.
- `src/alfred/comms/tui_adapter.py` — `TuiAdapter(CommsAdapter)` wrapping the existing `AlfredTuiApp`. `name = "tui"`. Constructor takes the canonical inject set (`orchestrator`, `identity_resolver`, `outbound_dlp`, `rate_limiter`, `broker`). `run()` delegates to `self._app.run_async()`. Resolve-fail at `start()` raises with the friendly hint string `t("cli.tui.error.no_operator_row")` (the i18n key is added in PR A's catalog block; D1 consumes it).
- `src/alfred/comms/markdown_split.py` — `_split_for_discord(text: str, *, max_len: int = 2000) -> Iterator[str]`. Pure function; no I/O, no state. Markdown-state machine tracks: triple-backtick fences (with optional language tag), inline backticks, and bold/italic markers that the splitter does NOT close-and-reopen (per spec — only fenced and inline code are state-bearing for Discord rendering safety).
- `src/alfred/identity/rate_limit.py` — `RateLimiter(Protocol)` + `RateLimiterHealth` frozen dataclass + `InProcessTokenBucketRateLimiter` concrete impl.
- `src/alfred/security/dlp.py` — `OutboundDlp` + `_GenericApiKeyScanner` + the `[REDACTED:api-key-shape]` sentinel + audit-on-modification wiring.

**Source (modifies):**

- `src/alfred/cli/main.py` — refactor `_redact_value` (line 123) to route through `OutboundDlp.scan` instead of `broker.redact`. Substitution happens once at structlog processor registration; no other call sites change.
- `src/alfred/comms/tui.py` — extract the send-handler so it can be re-driven through the resolve → rate-limit → dispatch → DLP flow inside `AlfredTuiApp`. Mirror the shape PR D2's Discord `_handle` will use; no behaviour change for the operator. Constructor accepts the canonical inject set from `TuiAdapter`.

**Tests (creates):**

- `tests/unit/comms/test_tui_adapter.py` — `TuiAdapter.run()` delegates; resolve-fail prints friendly hint.
- `tests/unit/comms/test_no_direct_adapter_imports.py` — AST-scans every `.py` outside `src/alfred/comms/` and `tests/`; reuses PR C's `tests/unit/_shared/import_violation.py` helper.
- `tests/unit/comms/test_markdown_split.py` — boundary cases (2000/2001, open fence at boundary, inline-code at boundary, empty, single character, exactly-`max_len`, all-fenced text), language-tag preservation across re-open, hypothesis property test for concatenation-equals-input modulo state markers.
- `tests/unit/identity/test_rate_limit.py` — `read_only`-FIRST security invariant (incl. the "override does not unlock the tier" assertion), token-bucket boundary (Nth allowed, N+1th refused), 1-over recovery cadence, per-user independence, `User.rate_limit_per_min` override vs authorization default, `operator`-as-unlimited representation, `reset()` semantics, `health()` snapshot shape, soft-deleted-user short-circuit.
- `tests/unit/security/test_dlp.py` — see Task-5 acceptance list. Per-file `--cov-fail-under=100` gate (line + branch) on `src/alfred/security/dlp.py`.
- `tests/unit/security/test_dlp_structlog_bridge.py` — fabricated `sk-XXXXXXXXXXXXXXXXXXXX` value emitted via `log.warning` renders as `[REDACTED:api-key-shape]`; sec-003 regression.

**Tests (modifies):**

- `tests/smoke/test_hello_alfred.py` — confirm the existing slice-1 smoke still passes through the new `TuiAdapter` Protocol seam (no assertion changes — just re-run after the wrap). If anything fails, the wrap is wrong, not the smoke.

**Docs:** none. ADR-0009 body is PR A's responsibility (spec line 835). This PR cites it from code comments + the import-isolation test failure message only.

**Dependencies / `pyproject.toml`:** **no change**. `discord.py` is a PR-D2 addition.

---

## 1. Task sequence

Bite-sized TDD tasks, ordered so each one has its dependencies green before it opens. The implementing subagent ticks the boxes as it lands work. Dispatch one subagent per task group (Tasks 1–2 are a single dispatch to `alfred-comms-engineer`; Task 3 is `alfred-comms-engineer`; Task 4 is `alfred-comms-engineer` with `alfred-security-engineer` review for the `read_only` invariant; Tasks 5–6 are `alfred-security-engineer`; Tasks 7–10 are `alfred-comms-engineer`).

### Task 1 — `CommsAdapter` Protocol + `AdapterHealth`

**Subagent:** `alfred-comms-engineer`.

- [ ] Write `tests/unit/comms/test_adapter_protocol.py` first: structural-typing test asserting a minimal in-test stub class satisfying the four methods + `name` attribute + correct return types passes an `isinstance(stub, CommsAdapter)` check at runtime (use `runtime_checkable`). Also assert a missing-method stub fails the check. Pin `AdapterHealth` as a frozen dataclass with the three fields (`gateway_connected: bool`, `last_on_ready_at: datetime | None`, `recent_reconnect_count: int`) — assert frozenness by attempting a `dataclasses.FrozenInstanceError`-raising mutation.
- [ ] Implement `src/alfred/comms/adapter.py`: `@runtime_checkable class CommsAdapter(Protocol)` with the four async lifecycle methods (`start/run/stop`) + sync `health()` + the `name: str` attribute. Module docstring cites ADR-0009 and the bounded PRD §5 deviation (spec line 122). `AdapterHealth` is a frozen `@dataclass(frozen=True)`.
- [ ] Run `uv run pytest tests/unit/comms/test_adapter_protocol.py -q`. Green.
- [ ] Run `uv run ruff check src/alfred/comms/adapter.py && uv run ruff format --check src/alfred/comms/adapter.py && uv run mypy src/alfred/comms/adapter.py && uv run pyright src/alfred/comms/adapter.py`. Green.

### Task 2 — `_DiscordClientLike` Protocol in `discord_types.py`

**Subagent:** `alfred-comms-engineer` (same dispatch as Task 1).

- [ ] Write `tests/unit/comms/test_discord_types_protocol.py`: structural test asserting a stub with `event` (decorator-shaped callable), `start(token: str, *, reconnect: bool)` async, `close()` async, `is_ready()` sync — passes `isinstance(stub, _DiscordClientLike)`. A stub missing any method fails. (PR D2 imports this Protocol for its `client_factory` injection.)
- [ ] Implement `src/alfred/comms/discord_types.py` with `_DiscordClientLike(Protocol)`. Underscore-prefixed because it's a structural shim for the test seam, not part of the public surface. Module docstring explains why it lives in `comms/` not `comms/discord.py` (cycle avoidance for PR D2's `discord.py`-importing module).
- [ ] Tests green; lint/type green.

### Task 3 — Markdown-aware splitter

**Subagent:** `alfred-comms-engineer`.

- [ ] Write `tests/unit/comms/test_markdown_split.py` FIRST (TDD). Cover:
  - empty string → yields nothing (or single empty chunk — pin whichever the implementation picks; the consumer in `_send` must not crash on the choice);
  - text shorter than `max_len` → single chunk equal to input;
  - text exactly `max_len` → single chunk;
  - text `max_len + 1` → two chunks, first is exactly `max_len`;
  - **open triple-backtick fence at boundary**: `"```python\n" + ("x" * 1990) + "\n```"` (~2002 chars). Splitter MUST close the fence at chunk 1 and re-open `"```python\n"` at the top of chunk 2; concatenation modulo the close/re-open markers equals the original;
  - **inline code at boundary**: backtick-wrapped span straddling the boundary — close at chunk 1, re-open at chunk 2;
  - **language-tag preservation**: `"```rust\n…```rust\n…"` — both chunks carry the `rust` tag;
  - **all-fenced text**: input is entirely inside a fence; every intermediate chunk closes-and-reopens;
  - hypothesis property test (`@given(st.text(min_size=0, max_size=10000))`): `"".join(strip_state_markers(chunks))` equals the original.
- [ ] Implement `src/alfred/comms/markdown_split.py::_split_for_discord(text: str, *, max_len: int = 2000) -> Iterator[str]`. Pure function. State machine tracks `in_fence: bool` + `fence_lang: str | None` + `in_inline_code: bool`. The function takes `max_len` kwarg-only so Slice-4 Telegram can pass `max_len=4096` without ambiguity at the call site. Type-annotate the return as `Iterator[str]`, not `list[str]`, so the consumer in `_send` can yield-chunk-and-send rather than materialising the whole list.
- [ ] Tests green; lint/type green. The hypothesis suite runs `--hypothesis-show-statistics` once locally for the implementer's sanity check (no statistics requirement in CI).

### Task 4 — `RateLimiter` Protocol + `InProcessTokenBucketRateLimiter`

**Subagent:** `alfred-comms-engineer` implements; `alfred-security-engineer` reviews the `read_only` short-circuit.

- [ ] Write `tests/unit/identity/test_rate_limit.py` FIRST. Cover (each its own test function):
  - `test_read_only_user_refused_regardless_of_override`: `User(authorization='read_only', rate_limit_per_min=30)` — `allow()` returns `False` on the FIRST call; bucket counters are not even consulted. This is the security invariant. Failure mode: implementer reads `User.rate_limit_per_min` before the authorization check → silent regression of spec line 223. **THIS IS THE LOAD-BEARING TEST OF THE PROTOCOL — name the test exactly this and do not refactor it without updating the spec.**
  - `test_read_only_reset_is_noop`: `reset(slug)` on a `read_only` user returns cleanly; subsequent `allow()` still returns `False`.
  - `test_standard_default_30_per_min`: 30 allowed; 31st refused; after a 60s `time.monotonic` clock advance, refills.
  - `test_trusted_default_60_per_min`: 60 allowed; 61st refused.
  - `test_operator_unlimited`: 1000 calls in tight succession all return `True`. Implementation: special-case `operator` to skip bucket math entirely.
  - `test_explicit_override_wins_over_default`: `User(authorization='standard', rate_limit_per_min=5)` — 5 allowed, 6th refused (override is honoured ONLY because authorization is not `read_only`).
  - `test_per_user_independence`: two users in `standard` tier exhaust independently — Alice's bucket draining does not affect Bob's.
  - `test_token_bucket_recovery`: at minute boundary, drained bucket refills to capacity.
  - `test_soft_deleted_user_short_circuit`: `User(deleted_at=<recent>)` → `allow()` returns `False` without consuming a token. (Resolver should never hand a soft-deleted user to the limiter, but defense-in-depth.)
  - `test_health_snapshot_shape`: `health()` returns a frozen `RateLimiterHealth` dataclass with the documented fields (active user buckets count + total allow/refuse counters).
- [ ] Implement `src/alfred/identity/rate_limit.py`:
  - `RateLimiterHealth` frozen dataclass: `active_buckets: int`, `total_allowed: int`, `total_refused: int`.
  - `RateLimiter(Protocol)` async: `allow(user: User) -> bool`, `reset(user_id: str) -> None`, `health() -> RateLimiterHealth`.
  - `InProcessTokenBucketRateLimiter`:

    ```python
    AUTH_DEFAULT_PER_MIN: Final[Mapping[AuthorizationLevel, int | None]] = MappingProxyType({
        AuthorizationLevel.READ_ONLY: 0,        # short-circuit before lookup; value is documentation
        AuthorizationLevel.STANDARD: 30,
        AuthorizationLevel.TRUSTED: 60,
        AuthorizationLevel.OPERATOR: None,      # unlimited
    })
    ```

    `allow(user)`:
    1. **FIRST**: `if user.authorization is AuthorizationLevel.READ_ONLY: return False`. (Security invariant per spec line 223.)
    2. `if user.deleted_at is not None: return False`. (Defense-in-depth.)
    3. `if user.authorization is AuthorizationLevel.OPERATOR: return True`. (Unlimited tier short-circuit.)
    4. Resolve `per_min = user.rate_limit_per_min if user.rate_limit_per_min is not None else AUTH_DEFAULT_PER_MIN[user.authorization]`.
    5. Acquire a token from the user's bucket (lazy-init on first call); on success return `True`, on empty return `False`.
  - `reset(user_id)` clears the bucket for that user_id (the user is identified by slug at the bucket layer because `RateLimiter.reset` is called from the CLI which doesn't necessarily hold a `User` object).
  - `health()` returns the frozen snapshot.
  - Uses `asyncio.Lock` per-user-slug for the token-acquisition critical section (lazy-init lock registry, same pattern as `WorkingMemoryPool`).
- [ ] Tests green; per-file 100% coverage on `src/alfred/identity/rate_limit.py` checked locally (gate is not enforced in CI for `identity/` — that gate is `security/` only; but the implementer confirms full coverage).
- [ ] `alfred-security-engineer` reviews the `read_only`-FIRST short-circuit before this task is ticked done. The review-comment template: "Confirm: (a) `read_only` check is line 1 of `allow()`; (b) no test passes if the check is moved to after the `rate_limit_per_min` lookup; (c) the security invariant docstring on the method names spec §2 line 223."

### Task 5 — `OutboundDlp` (`src/alfred/security/dlp.py`)

**Subagent:** `alfred-security-engineer`.

- [ ] Write `tests/unit/security/test_dlp.py` FIRST. Cover (each its own test function):
  - **Stage 1 — broker redaction:** known live secret value (fixture-injected via a stubbed `SecretBroker.redact`) → replaced; clean input untouched.
  - **Stage 2 — generic API-key regex:** four assertion sub-tests covering each prefix (`sk-`, `pk_`, `tok-`, `key_`) followed by 20+ alphanumeric chars → `[REDACTED:api-key-shape]`. Edge: `sk-` followed by 19 chars must NOT match. `\b` word boundary anchoring tested with an embedded `"prefix-sk-AAAAAAAAAAAAAAAAAAAA"` to confirm prefix-attached forms don't slip past (`-` is a word-boundary). Edge: `Sk-AAAA…` (capital S) does NOT match — the regex is case-sensitive by design, lowercase prefixes match the SDK conventions of major providers.
  - **Stage 3 — canary stub:** assert `OutboundDlp._canary_stub("anything")` returns `"anything"` literally. THIS IS A REGRESSION GUARD for Slice 3's broader expansion; deleting/altering this test silently bypasses canary handling.
  - **Multi-secret longer-first ordering:** two secrets `"abc"` and `"abcdef"` both present in the broker — longer matches first (slice-1 PR #89 invariant carried forward).
  - **Audit-on-modification:** when `len(pre) != len(post)`, exactly one `event=dlp.outbound_redacted` audit row is written with `subject={"pre_bytes": <int>, "post_bytes": <int>, "stages_triggered": [...]}`. The audit writer is dependency-injected so tests stub it. **Critical:** the audit-append happens UNCONDITIONALLY on modification — failure to append raises (CLAUDE.md hard rule #7).
  - **No audit on clean input:** `len(pre) == len(post)` and no stage triggered → zero audit calls.
  - **Both backends feed redactor:** file-source secret + env-source secret both replaced; longer-first ordering preserved across backends.
- [ ] Implement `src/alfred/security/dlp.py`:

  ```python
  _GENERIC_API_KEY_RE: Final = re.compile(r"\b(?:sk|pk|tok|key)[-_][A-Za-z0-9]{20,}\b")
  _REDACTION_SENTINEL: Final = "[REDACTED:api-key-shape]"

  class OutboundDlp:
      def __init__(self, *, broker: SecretBroker, audit: AuditWriter) -> None: ...

      def scan(self, text: str) -> str:
          pre = text
          stages_triggered: list[str] = []
          text = self._broker.redact(text)
          if text != pre:
              stages_triggered.append("broker")
          stage_2 = _GENERIC_API_KEY_RE.sub(_REDACTION_SENTINEL, text)
          if stage_2 != text:
              stages_triggered.append("api_key_shape")
          text = stage_2
          text = self._canary_stub(text)   # stage 3: no-op until Slice 3
          if len(text) != len(pre):
              # audit-on-modification (synchronous append; raises on failure per CLAUDE.md #7)
              self._audit.append(
                  event="dlp.outbound_redacted",
                  subject={
                      "pre_bytes": len(pre),
                      "post_bytes": len(text),
                      "stages_triggered": stages_triggered,
                  },
              )
          return text

      @staticmethod
      def _canary_stub(text: str) -> str:
          """Slice-3 canary stage. Slice-2: literal no-op (regression-guarded)."""
          return text
  ```

- [ ] Gate: `uv run pytest tests/unit/security/test_dlp.py --cov=src/alfred/security/dlp.py --cov-branch --cov-fail-under=100 -q`. Must be 100% line AND branch.
- [ ] Lint/type green.

### Task 6 — Structlog bridge refactor (sec-003)

**Subagent:** `alfred-security-engineer`.

- [ ] Write `tests/unit/security/test_dlp_structlog_bridge.py` FIRST. Cover:
  - **Generic-API-key in log message:** `log.warning("something %s happened", "sk-AAAAAAAAAAAAAAAAAAAA")` → captured event-dict has the placeholder replaced with `[REDACTED:api-key-shape]`. (Demonstrates that stage 2 now reaches the structlog path.)
  - **Live-secret in log message** (slice-1 carry-over): a stubbed broker-known secret appears redacted exactly as it did before the refactor. (Backwards compat — sec-003 must not regress slice-1 behaviour.)
  - **Nested redaction:** the value lives inside a list-of-dicts inside the event-dict — every leaf string goes through `OutboundDlp.scan`. The existing recursion shape in `_redact_value` is preserved; only the leaf function changes.
  - **No double audit-row on log emission:** `OutboundDlp.scan` writes ONE audit row per redaction event; emitting the same value via two log lines writes two audit rows (independent calls). Stubs assert the audit writer is called the expected number of times. (This is intentional — every redaction is a separate event.)
- [ ] Modify `src/alfred/cli/main.py:_redact_value`: at structlog-processor registration time, capture a module-level `_outbound_dlp: OutboundDlp` instance. `_redact_value(v: object)` for a `str` leaf now returns `_outbound_dlp.scan(v)` instead of `broker.redact(v)`. List/dict/tuple recursion unchanged. `OutboundDlp` is constructed at CLI bootstrap with the already-bootstrap-constructed broker (PR C's eager broker construction makes this clean) and the slice-1 audit writer.
- [ ] **Substitution happens once at registration; no other call sites change.** Grep-assert: `git grep -n "broker.redact" src/alfred/` outside `dlp.py` returns zero matches (the only legitimate caller of `broker.redact` is now `OutboundDlp.scan`).
- [ ] Tests green; lint/type green; the per-file 100% gate from Task 5 stays green (the bridge change does not touch dlp.py).

### Task 7 — `TuiAdapter` wrap

**Subagent:** `alfred-comms-engineer`.

- [ ] Write `tests/unit/comms/test_tui_adapter.py` FIRST. Cover:
  - **`name == "tui"`** assertion.
  - **`run()` delegates** to a mocked `AlfredTuiApp.run_async()` — assert `app.run_async` awaited exactly once with no args; `TuiAdapter.run()` returns its result.
  - **`start()` calls `IdentityResolver.resolve("tui", settings.operator_name)`** — happy path (operator row exists) returns cleanly; the resolved `User` is stored on the instance for the send handler.
  - **Resolve-fail at startup:** when `identity_resolver.resolve(...)` returns `None`, `start()` raises with the friendly hint `t("cli.tui.error.no_operator_row")` (i18n key added in PR A). The error message includes the literal CLI fix `alfred user add --authorization operator` so a copy-paste-from-terminal recovery works for the operator. Assert the structured-log line `tui.start.no_operator_row` is emitted with `event_kv` matching the spec.
  - **`stop()` calls `app.exit()`** (or whichever Textual shutdown primitive applies) — asserted via mock.
  - **`health()` returns sensible TUI defaults:** `gateway_connected=True` while `run()` is in-flight, `last_on_ready_at=<adapter start time>`, `recent_reconnect_count=0`. (Discord-specific fields exist on `AdapterHealth` for shape-compatibility; TUI fills sensible defaults.)
  - **Inject set:** constructor accepts `(orchestrator, identity_resolver, outbound_dlp, rate_limiter, broker)`. The same five injects PR D2's Discord adapter will take; freezing the shape here keeps PR D2 from re-shuffling.
- [ ] Implement `src/alfred/comms/tui_adapter.py`. `TuiAdapter` instantiates `AlfredTuiApp` (existing `src/alfred/comms/tui.py`) with its inject set; `run()` delegates to `app.run_async()`. The resolve → rate-limit → dispatch → DLP flow lives INSIDE `AlfredTuiApp`'s send handler (modify `tui.py` accordingly), mirroring the shape Discord will adopt in PR D2. Inside the send handler:
  1. The resolved `User` from `start()` is the addressee for every TUI turn (single-user surface).
  2. `await self._rate_limiter.allow(user)` — even though the operator is `unlimited`, the call still flows through the limiter for path-shape parity with Discord (and for the test that asserts every exit branch goes through the same chain).
  3. Dispatch to `self._orchestrator.handle_user_message(user=user, content=TaggedContent[T2](...), working_memory=wm)`.
  4. Every outbound (success or error) goes through `self._outbound_dlp.scan(text)` before render.
  5. The markdown splitter is NOT invoked for TUI (Textual renders the whole string); the splitter is a Discord-specific concern.
- [ ] Tests green; lint/type green.

### Task 8 — `test_no_direct_adapter_imports.py`

**Subagent:** `alfred-comms-engineer`.

- [ ] Implement `tests/unit/comms/test_no_direct_adapter_imports.py`. AST-walks every `.py` under the repo root EXCLUDING `src/alfred/comms/` and `tests/`. Fails on any `Import` or `ImportFrom` node that mentions:
  - `alfred.comms.tui_adapter` (or `from alfred.comms import tui_adapter`)
  - `alfred.comms.tui` direct imports of `AlfredTuiApp` (the class, not the module — `from alfred.comms.tui import AlfredTuiApp`) — these get an exception slot for the existing CLI bootstrap which currently constructs the app directly; PR D1 migrates the bootstrap to construct `TuiAdapter` instead, so the exception disappears mid-PR. **By end-of-D1 the exception list is empty.**
  - `alfred.comms.discord` (ships in PR D2; tripped retroactively when D2 lands if anyone imports it directly).
  - Any future class whose name ends in `Adapter` and lives under `alfred.comms` — generalised via an importable allowlist constant `_ALLOWED_COMMS_IMPORTS: frozenset[str] = frozenset({"alfred.comms.adapter", "alfred.comms.discord_types", "alfred.comms.markdown_split"})`. Anything ELSE under `alfred.comms` imported from outside the package or the test tree fails the test.
- [ ] Reuses `tests/unit/_shared/import_violation.py::_remediation_message(file, line, symbol)` (shipped by PR C). The failure message names the violating `file:line`, the imported symbol, and points the contributor at `src/alfred/comms/adapter.py` + ADR-0009. Shape (literal example):

  ```
  src/alfred/cli/main.py:42 imports alfred.comms.tui_adapter.TuiAdapter directly.
  Consumers outside src/alfred/comms/ MUST go through the CommsAdapter Protocol
  (src/alfred/comms/adapter.py). See ADR-0009.
  ```

- [ ] Migrate the slice-1 CLI bootstrap (`src/alfred/cli/main.py` chat command) to construct `TuiAdapter` (typed as the Protocol from `adapter.py`) instead of `AlfredTuiApp` directly. After migration, run the new test and assert it passes WITHOUT any exception slots populated. If any external consumer still needs to import the concrete class for a reason unforeseen by D1, escalate to `alfred-architect` rather than adding an exception — adding an exception silently widens the Slice-3 swap surface.
- [ ] Tests green; lint/type green.

### Task 9 — TUI smoke regression

**Subagent:** `alfred-comms-engineer`.

- [ ] Run `uv run pytest tests/smoke/test_hello_alfred.py -q`. Must pass without modification. The wrap is correctly transparent — if the slice-1 smoke fails, the wrap is wrong, not the smoke.
- [ ] If the smoke trips, treat it as a regression, not a "test that needs updating." Fix the wrap.

### Task 10 — 100% coverage gate enforcement

**Subagent:** `alfred-security-engineer`.

- [ ] Wire the per-file gate into the existing `pyproject.toml` or `pytest.ini` coverage configuration. The literal command this PR's CI must run:

  ```
  uv run pytest \
    tests/unit/security/test_dlp.py \
    tests/unit/security/test_dlp_structlog_bridge.py \
    --cov=src/alfred/security/dlp.py \
    --cov-branch \
    --cov-fail-under=100 \
    -q
  ```

  Result MUST be 100% line + branch. The full `make check` invocation runs this gate alongside the existing per-file gate on `src/alfred/security/secrets.py` (from PR C); both must be green.
- [ ] Add a one-line note to `tests/unit/security/__init__.py` (or wherever the security-suite docstring lives) documenting which files are 100%-gated, so future contributors can extend the gate list without grep-and-pray.

---

## 2. Acceptance gates

Restating spec §6 row D1 (line 872) as runnable assertions. Every gate below MUST be green locally on the implementer's machine before the PR opens; CI replays the same gates.

**Local quality bar** (`make check` — identical to CI):

```bash
make check
```

…runs the union of: `ruff check src tests` (zero findings), `ruff format --check src tests` (clean), `mypy src` (zero errors), `pyright src` (zero errors), full pytest unit + integration suite (green).

**PR-D1-specific gates layered on top of `make check`:**

1. **DLP per-file 100% line + branch coverage.**

   ```bash
   uv run pytest \
     tests/unit/security/test_dlp.py \
     tests/unit/security/test_dlp_structlog_bridge.py \
     --cov=src/alfred/security/dlp.py \
     --cov-branch \
     --cov-fail-under=100 \
     -q
   ```

   Expected: every line + every branch in `src/alfred/security/dlp.py` covered. The canary-stub test counts as a separate covered branch (entering and returning from `_canary_stub`).

2. **TUI smoke through the new Protocol seam.**

   ```bash
   uv run pytest tests/smoke/test_hello_alfred.py -q
   ```

   Expected: green without modification to the smoke test. If it fails, the `TuiAdapter` wrap is incorrect.

3. **Adapter import-isolation test.**

   ```bash
   uv run pytest tests/unit/comms/test_no_direct_adapter_imports.py -q
   ```

   Expected: green with the `_ALLOWED_COMMS_IMPORTS` constant containing exactly `{"alfred.comms.adapter", "alfred.comms.discord_types", "alfred.comms.markdown_split"}` and zero exception slots. If green only because of a populated exception slot, the implementer has cheated; the test passes for the wrong reason and PR D2's import isolation is broken from day one. **`alfred-architect` reviews any non-empty exception slot before merge.**

4. **`read_only`-FIRST security-invariant test green.**

   ```bash
   uv run pytest tests/unit/identity/test_rate_limit.py::test_read_only_user_refused_regardless_of_override -q
   ```

   Named precisely so the spec line can grep for it. If the test name changes, the spec-to-code traceability breaks.

5. **Markdown splitter property test green.**

   ```bash
   uv run pytest tests/unit/comms/test_markdown_split.py -q
   ```

   Includes the hypothesis suite. No `@given` shrinks should be surfaced; if one is, fix the splitter, don't `@example`-paper-over it.

6. **No `broker.redact` callers outside `dlp.py`.**

   ```bash
   ! git grep -nE 'broker\.redact\b' src/alfred/ | grep -v 'src/alfred/security/dlp.py'
   ```

   Expected: empty match set. The structlog refactor (Task 6) is the only `broker.redact` caller after this PR; every other path goes through `OutboundDlp.scan`.

7. **Conventions discipline.** `alfred-python-developer` reviews:
   - All Protocols use `typing.Protocol` + `@runtime_checkable` where structural-typing tests run.
   - All dataclasses are `frozen=True`.
   - `AUTH_DEFAULT_PER_MIN` is `Final` + `MappingProxyType` (immutable at the value level).
   - `_GENERIC_API_KEY_RE` is module-level `Final` (compiled once, not per-call).
   - The async Protocols define their methods with `async def …: ...` ellipsis bodies (not `pass`) — pyright pins this preference.
   - Zero `except Exception: pass` anywhere in the new code; `OutboundDlp.scan` propagates audit-write failures (CLAUDE.md hard rule #7).

8. **i18n keys consumed by D1 exist in the catalog.** `t("cli.tui.error.no_operator_row")` resolves to a non-key string (i.e. the catalog has the key). The key itself ships in PR A's catalog block (spec §3 enumeration); D1 just consumes it. If `pybabel compile --check` complains about a missing key, escalate to PR A's owner — do not add catalog entries in D1.

---

## 3. Open questions / decisions deferred to plan time

None. Every contract is spelled out in the spec and re-stated above. Open Slice-2 questions (length-delta DLP oracle mitigation, PgBouncer cache backstop alternatives, multi-operator support) belong to Slice 3 / Slice 4 per spec §7 line 892–896 and are not in this PR's scope.

If during implementation a genuinely new ambiguity arises — for example, a Textual API surface the wrap exposes differently than expected — STOP and escalate to `alfred-architect`. Do not silently pick a side: the contracts this PR publishes are load-bearing for PR D2.

---

## 4. References

- **PRD anchors:** [PRD §6.1 Multi-modal Comms](../../../PRD.md#61-multi-modal-comms) (the comms-adapter shape and DM-only Slice-2 scope), [PRD §7.1 Security & Prompt Injection Defense](../../../PRD.md#71-security--prompt-injection-defense) (DLP minimum floor).
- **Spec sections:** §2 lines 99–122 (CommsAdapter Protocol + TuiAdapter wrap), §3 lines 472–504 (rate limiter + DLP), §3 lines 577–579 (markdown splitter), §5 lines 786–798 (unit tests), §6 line 872 (PR D1 row).
- **ADR-0009** — `CommsAdapter` Protocol as Slice-2-only in-process seam; PRD §5 invariant bounded; Slice-3 rewrites for MCP transport. **Body lands in PR A** (per spec §5 line 835); this PR references the ADR from code comments + the import-isolation-test failure message.
- **Cross-PR dependencies:**
  - PR A: `IdentityResolver`, `User`, `AuthorizationLevel` enum, ContextVar i18n refactor.
  - PR B: `Orchestrator.handle_user_message(*, user, content, working_memory)`, `WorkingMemoryPool`, `BudgetGuard.check_and_charge(user_id, …)`.
  - PR C: `SecretBroker(secrets_file, require_file, …)`, four error subtypes, `_PREFER_FILE`, `tests/unit/_shared/import_violation.py::_remediation_message`.
- **CLAUDE.md hard rules invoked:**
  - #1 (i18n discipline — `t()` for the resolve-fail hint).
  - #4 (DLP on by default — `OutboundDlp.scan` becomes the single chokepoint for log + Discord output paths).
  - #7 (no silent failures in security paths — audit-on-modification + audit-write-failure propagates).
- **`docs/python-conventions.md`** — every type, every Protocol, every dataclass conforms. `alfred-python-developer` reviews before PR opens.

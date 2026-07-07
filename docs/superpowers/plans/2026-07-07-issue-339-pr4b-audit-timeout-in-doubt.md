# PR4b-audit — Action-deadline TimeoutError / in-doubt cross-layer audit (#339, #347 blocker 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When a live `web.fetch` tool dispatch overruns its action deadline, emit exactly one enriched, non-skippable `tool.dispatch` audit row carrying `egress_id`, `destination_host`, `in_doubt`, and the ledger's committed state — so the in-doubt side effect (the fetch may have fired before the timeout) is forensically auditable (HARD rule #7, #347 blocker 2).

**Architecture:** The web.fetch dispatcher owns both the action-deadline (`asyncio.timeout`) and the egress idempotency ledger (via its extractor/relay). On `TimeoutError` it reads the *real* ledger state and re-raises a typed `WebFetchActionTimeout` carrying the forensic fields. The orchestrator-wiring chokepoint (`dispatch_tool`) catches that typed exception and writes the enriched `tool.dispatch` row via a new `TOOL_DISPATCH_TIMEOUT_FIELDS` superset schema. `dispatch_tool` stays ledger-free — it reads exception attributes, never a Postgres row. A new read-only `get_state` on the idempotency store (reusing the existing `_SELECT_STATE_SQL`) and a thin `ledger_state` accessor on the extractor close the "no ledger handle" plumbing gap without threading a separate ledger dependency through four layers.

**Tech Stack:** Python 3.14+, asyncio, SQLAlchemy 2.0 (async), Pydantic v2, Postgres 18 + Redis 8 (testcontainers), pytest, structlog, Babel/`t()` i18n.

## Global Constraints

- **HARD security rule #7 — no silent failures in security paths.** Every branch of the timeout path emits a loud audit row; the enriched row is non-skippable (symmetric-key `append_schema`).
- **HARD security rule #5 / audit hygiene — never carry raw T3, the fetched URL/body, `str(exc)`, or `exc.args` in an audit row.** `destination_host` is the *bare host only* (`_safe_hostname`, no userinfo/port/path/query). `egress_id` is a sha256 (no T3). `ledger_state` is a closed-vocab string. `in_doubt` is a bool.
- **HARD i18n rule #1 — all operator-facing strings via `t()`.** The new exception message goes through a new catalog key `web.fetch.error.action_timeout` (no interpolation of forensic data into the message).
- **In-domain `result=` values only.** The enriched timeout row keeps `result="refused"` (already in `ck_audit_log_result`). NO migration; NO new `result` token (PR3 FIX-1 lesson: `max_iterations_reached` was rejected, `refused` reused).
- **100% line+branch coverage on `dispatch_tool`** (existing CI gate, both jobs). Both new-touched arms (`except WebFetchActionTimeout` AND the retained defensive `except TimeoutError`) must be covered.
- **Additive, `extra="forbid"` preserved.** New audit schema is a *superset* frozenset (mirrors `PLUGIN_LIFECYCLE_CRASHED_FIELDS = PLUGIN_LIFECYCLE_FIELDS | {...}`), not new always-`None` fields on the shared schema.
- **Modern Python:** PEP 604 unions (`str | None`), PEP 585 generics, frozen dataclasses / frozen Pydantic, `mypy --strict` + `pyright`, no `Any` without justification.
- **Commit discipline:** conventional-commit subjects with a literal `#339` in EVERY subject; type is `[a-z]+` only (use `chore(i18n)`, never `i18n:` as a type). Never `git add -A` (untracked rulesync outputs). Never `--no-verify`. Never `--admin` merge.
- **This PR touches an audit trust boundary but NO file under `src/alfred/security/`.** The adversarial suite is not strictly mandated by the src/alfred/security/ rule, but it IS run in final verification (audit is a security boundary). No new adversarial corpus entry in this PR (that is PR4b-broker).

---

## File Structure

New/modified files, one responsibility each:

- `src/alfred/memory/egress_idempotency.py` — **add** a read-only `get_state(*, egress_id) -> str | None` to the `EgressIdempotencyStore` Protocol AND `PostgresEgressIdempotencyStore` (reuse `_SELECT_STATE_SQL`). The only new ledger surface.
- `src/alfred/egress/egress_response_extract.py` — **add** a thin public `ledger_state(*, egress_id) -> str | None` accessor on `EgressResponseExtractor` (delegates to `self._relay_client.ledger.get_state`). Avoids reaching through the private `_relay_client` from the dispatcher.
- `src/alfred/plugins/web_fetch/errors.py` — **add** `WebFetchActionTimeout(WebFetchError)` carrying the forensic fields.
- `src/alfred/plugins/web_fetch/fetch_dispatcher.py` — **add** an `except TimeoutError` arm around the `asyncio.timeout` block that reads ledger state and re-raises `WebFetchActionTimeout`.
- `src/alfred/audit/audit_row_schemas.py` — **add** `TOOL_DISPATCH_TIMEOUT_FIELDS` superset constant.
- `src/alfred/orchestrator/tool_dispatch.py` — **replace** the generic `except TimeoutError` handling: add `except WebFetchActionTimeout` (enriched inline emit) before `except WebFetchError`; retain a defensive `except TimeoutError` (generic fallback); fix the stale `:215-216` "lands in PR3" comment.
- `src/alfred/i18n/` (catalog source) + `locale/en/LC_MESSAGES/alfred.{po,mo}` — **add** `web.fetch.error.action_timeout`.
- Tests (see tasks): `tests/integration/test_egress_idempotency_postgres.py`, `tests/unit/egress/test_egress_response_extract.py`, `tests/unit/plugins/web_fetch/` errors + dispatcher, `tests/unit/audit/test_audit_row_schemas.py`, `tests/unit/audit/test_audit_log_result_domain_closed.py` (re-pin), `tests/unit/orchestrator/` dispatch_tool arms, and a NEW `tests/integration/orchestrator/test_tool_dispatch_timeout_audit_postgres.py` (the blocker's required cross-layer test).
- `docs/subsystems/security.md` — audit-vocabulary note for the timeout enrichment; a brief factual amendment note on ADR-0041/ADR-0046 (no new ADR — this fulfills the existing HARD-#7/#347 obligation; plan-review to confirm).

**Verified current-state anchors (tree @ main `8b9a3e15`):**

- `tool_dispatch.py:49-117` — `dispatch_tool(...)` signature + the `_audit` helper (fixed to `TOOL_DISPATCH_FIELDS`, `schema_name="TOOL_DISPATCH_FIELDS"`, `result=result` dynamic site at ~line 114).
- `tool_dispatch.py:178-233` — the external-leg `try` with arms `InboundCanaryTripped`(180) → `WebFetchRateLimited`(190) → `WebFetchDomainNotAllowed`(198) → `WebFetchError`(206) → `TimeoutError`(214, STALE comment `:215-216`) → `Exception`(224 defensive).
- `fetch_dispatcher.py:488-531` — inner `try:` / `async with asyncio.timeout(action_deadline_seconds):` / `await extractor.handle(...)` / `except InboundCanaryTripped:` only. `finally` (607-625) releases `handle_cap`. `domain = _safe_hostname(clean_url)` at :288. `_safe_hostname` at :130.
- `egress_response_extract.py:139-171` — `EgressResponseExtractor.__init__` holds `self._relay_client` (no `self._ledger`); `handle` at :173; cancellation drain guard at :307-315 skips `record_response` → ledger stays `committed_no_response`.
- `egress_idempotency.py:85` `_SELECT_STATE_SQL`; `:104-108` `IntentInDoubt`; `:127` `@runtime_checkable class EgressIdempotencyStore(Protocol)`; `:166-244` `PostgresEgressIdempotencyStore` (`__init__` holds `self._session_scope`); `:55` `_STATE_WITH_RESPONSE = "committed_with_response"`; the insert default state is `"committed_no_response"`.
- `egress_id.py:61` `compute_egress_id(ctx: TurnEgressContext, *, call_index: int) -> str` (pure); `TurnEgressContext` = frozen Pydantic `(adapter_id, inbound_id, session_id)`.
- `errors.py:39` `WebFetchError(AlfredError)`; `:61` `WebFetchRateLimited(WebFetchError)` carries `.bucket`, `# noqa: N818`, `super().__init__(t("..."))`.
- `audit_row_schemas.py:276-313` — `ToolDispatchOutcome` (already has `"timeout"`), `TOOL_DISPATCH_FIELDS` (8 fields).
- `tests/unit/audit/test_audit_row_schemas.py:20-46` — parametrized constant-name list (add the new constant); `:63` superset-test precedent.
- `tests/unit/audit/test_audit_log_result_domain_closed.py:344-410` — `expected` list of dynamic `result=<var>` sites, pins `"src/alfred/orchestrator/tool_dispatch.py:114"` (:395) — WILL shift; stale `:24` comment cites `fetch_dispatcher.py:914`.
- `tests/integration/orchestrator/conftest.py` — `migrated_url`, `redis_url` (`RedisContainer("redis:8-alpine")`), `authorized_t3_nonce`, `boot_loopback_relay(allowlist=...)`; `test_act_loop_real_chain.py` is the closest cross-layer model (real `build_tool_registry`, mock quarantined `extract`, queries `tool.dispatch` rows from Postgres).

---

### Task 1: Read-only `get_state` on the idempotency ledger

**Files:**

- Modify: `src/alfred/memory/egress_idempotency.py` (Protocol `EgressIdempotencyStore` ~127-163; `PostgresEgressIdempotencyStore` ~166-244)
- Test: `tests/integration/test_egress_idempotency_postgres.py` (existing Postgres store test)

**Interfaces:**

- Produces: `EgressIdempotencyStore.get_state(*, egress_id: str) -> str | None` (Protocol method) and its `PostgresEgressIdempotencyStore` implementation. Returns `"committed_no_response"` / `"committed_with_response"` / `None` (no row). Consumed by Task 2's extractor accessor.

- [ ] **Step 1: Write the failing integration test** (append to `tests/integration/test_egress_idempotency_postgres.py`; reuse its existing `store` / `migrated_url` fixtures)

```python
@pytest.mark.asyncio
async def test_get_state_reflects_ledger_lifecycle(store: PostgresEgressIdempotencyStore) -> None:
    egress_id = "a" * 64
    # No row yet.
    assert await store.get_state(egress_id=egress_id) is None
    # Fresh commit → committed_no_response.
    result = await store.commit_intent(
        egress_id=egress_id,
        adapter_id="adp",
        inbound_id="inb",
        session_id="sess",
        call_index=0,
        body_hash="b" * 64,
    )
    assert isinstance(result, IntentFresh)
    assert await store.get_state(egress_id=egress_id) == "committed_no_response"
    # After record_response → committed_with_response.
    await store.record_response(egress_id=egress_id, response="ok", language="en")
    assert await store.get_state(egress_id=egress_id) == "committed_with_response"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/integration/test_egress_idempotency_postgres.py::test_get_state_reflects_ledger_lifecycle -v`
Expected: FAIL — `AttributeError: 'PostgresEgressIdempotencyStore' object has no attribute 'get_state'`

- [ ] **Step 3: Add `get_state` to the Protocol** (`EgressIdempotencyStore`, after `record_response`, before `prune_expired`)

```python
    async def get_state(self, *, egress_id: str) -> str | None:
        """Read the committed state of an intent WITHOUT firing or mutating.

        Returns ``"committed_no_response"`` (intent committed, response not yet
        recorded — the in-doubt state), ``"committed_with_response"`` (completed),
        or ``None`` (no row — nothing was committed). A pure read: unlike
        ``commit_intent`` it performs no INSERT and cannot re-fire a side effect,
        so it is safe to call from a post-timeout audit path (#347 blocker 2).
        """
        ...
```

- [ ] **Step 4: Implement on `PostgresEgressIdempotencyStore`** (mirror `record_response`'s session-scope + `_SELECT_STATE_SQL` usage; `cast` for mypy strict — `cast` is already imported)

```python
    async def get_state(self, *, egress_id: str) -> str | None:
        async with self._session_scope() as session:
            row = (
                await session.execute(_SELECT_STATE_SQL, {"egress_id": egress_id})
            ).scalar_one_or_none()
            return cast("str | None", row)
```

- [ ] **Step 5: Update any duck-typed fake stores** so the `@runtime_checkable` Protocol stays satisfiable. Grep first:

Run: `grep -rn "commit_intent" tests/unit/egress/test_egress_response_extract.py tests/unit/egress/test_relay_client.py`
For each fake ledger class found (a class defining `commit_intent`/`record_response`), add a controllable stub so Task 4's unit test can drive it:

```python
    async def get_state(self, *, egress_id: str) -> str | None:
        return self._state  # e.g. attribute defaulting to "committed_no_response"
```

- [ ] **Step 6: Run test to verify it passes + no regressions in the store's other tests**

Run: `uv run pytest tests/integration/test_egress_idempotency_postgres.py -v`
Expected: PASS (new test + all existing)

- [ ] **Step 7: Commit**

```bash
git add src/alfred/memory/egress_idempotency.py tests/integration/test_egress_idempotency_postgres.py tests/unit/egress/test_egress_response_extract.py tests/unit/egress/test_relay_client.py
git commit -m "feat(egress): add read-only get_state to the idempotency ledger (#339 PR4b-audit)"
```

---

### Task 2: `ledger_state` accessor on `EgressResponseExtractor`

**Files:**

- Modify: `src/alfred/egress/egress_response_extract.py` (`EgressResponseExtractor`, add a public method after `handle`)
- Test: `tests/unit/egress/test_egress_response_extract.py`

**Interfaces:**

- Consumes: `EgressIdempotencyStore.get_state` (Task 1) via `self._relay_client.ledger`.
- Produces: `EgressResponseExtractor.ledger_state(*, egress_id: str) -> str | None`. Consumed by Task 4's dispatcher timeout arm.

- [ ] **Step 1: Write the failing unit test** (drive with a fake relay whose `.ledger.get_state` returns a canned value; reuse the file's existing fakes/fixtures)

```python
@pytest.mark.asyncio
async def test_ledger_state_delegates_to_relay_ledger() -> None:
    extractor = _build_extractor()  # existing helper / fixture in this file
    # The fake relay's ledger.get_state is stubbed to return committed_no_response.
    state = await extractor.ledger_state(egress_id="c" * 64)
    assert state == "committed_no_response"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/egress/test_egress_response_extract.py::test_ledger_state_delegates_to_relay_ledger -v`
Expected: FAIL — `AttributeError: 'EgressResponseExtractor' object has no attribute 'ledger_state'`

- [ ] **Step 3: Implement the accessor** (thin delegate — no egress_id recomputation here; the caller supplies it)

```python
    async def ledger_state(self, *, egress_id: str) -> str | None:
        """Read the idempotency-ledger state for a committed egress_id.

        Thin public accessor over the relay client's ledger so the web.fetch
        dispatcher can classify an action-deadline timeout as in-doubt without
        reaching through the private ``_relay_client`` (#347 blocker 2).
        """
        return await self._relay_client.ledger.get_state(egress_id=egress_id)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/egress/test_egress_response_extract.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/alfred/egress/egress_response_extract.py tests/unit/egress/test_egress_response_extract.py
git commit -m "feat(egress): expose ledger_state accessor on EgressResponseExtractor (#339 PR4b-audit)"
```

---

### Task 3: `WebFetchActionTimeout` typed exception + i18n key

**Files:**

- Modify: `src/alfred/plugins/web_fetch/errors.py` (add after `WebFetchRateLimited`)
- Modify: catalog — add `web.fetch.error.action_timeout` (English) via the i18n drift gate (Task 8 recompiles; add the msgstr by hand)
- Test: `tests/unit/plugins/web_fetch/test_errors.py` (create if absent; else the existing web_fetch errors test module)

**Interfaces:**

- Produces: `WebFetchActionTimeout(*, egress_id: str, destination_host: str, in_doubt: bool, ledger_state: str | None)` — subclass of `WebFetchError`, attributes `.egress_id`, `.destination_host`, `.in_doubt`, `.ledger_state`, message via `t("web.fetch.error.action_timeout")`. Consumed by Task 4 (raised) and Task 6 (`dispatch_tool` catches).

- [ ] **Step 1: Write the failing unit test**

```python
from alfred.plugins.web_fetch.errors import WebFetchActionTimeout, WebFetchError


def test_web_fetch_action_timeout_carries_forensic_fields() -> None:
    exc = WebFetchActionTimeout(
        egress_id="d" * 64,
        destination_host="example.com",
        in_doubt=True,
        ledger_state="committed_no_response",
    )
    assert isinstance(exc, WebFetchError)  # taxonomy: catchable as WebFetchError
    assert exc.egress_id == "d" * 64
    assert exc.destination_host == "example.com"
    assert exc.in_doubt is True
    assert exc.ledger_state == "committed_no_response"
    # Message is a fixed operator string — it must NOT interpolate the forensic
    # data (host/egress_id) into the message body (audit hygiene).
    assert "example.com" not in str(exc)
    assert "d" * 64 not in str(exc)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/plugins/web_fetch/test_errors.py::test_web_fetch_action_timeout_carries_forensic_fields -v`
Expected: FAIL — `ImportError: cannot import name 'WebFetchActionTimeout'`

- [ ] **Step 3: Implement the exception** (in `errors.py`, mirror `WebFetchRateLimited`'s structured shape; `# noqa: N818`)

```python
class WebFetchActionTimeout(WebFetchError):  # noqa: N818 -- forensic event, name pinned by #347 blocker-2
    """The fused fetch+extract overran its per-action deadline (spec §7, #347 blocker 2).

    Carries the forensic fields the orchestrator-wiring chokepoint records on the
    enriched ``tool.dispatch`` timeout row. The side effect may have fired before
    the deadline (``in_doubt``); the message body carries NO forensic data (audit
    hygiene) — the structured attributes do.
    """

    def __init__(
        self,
        *,
        egress_id: str,
        destination_host: str,
        in_doubt: bool,
        ledger_state: str | None,
    ) -> None:
        super().__init__(t("web.fetch.error.action_timeout"))
        self.egress_id = egress_id
        self.destination_host = destination_host
        self.in_doubt = in_doubt
        self.ledger_state = ledger_state
```

- [ ] **Step 4: Add the catalog key.** Add to the English `.po` (the `t()` literal is extracted directly by `pybabel`; fill the `msgstr` by hand — Task 8 runs the full extract/update/compile). Provisional English:

```
msgid "web.fetch.error.action_timeout"
msgstr "web.fetch exceeded its action deadline."
```

(If a catalog-key pin test like `tests/unit/test_catalog_*.py` enumerates web.fetch keys, add the key there too — grep `web.fetch.error` under `tests/unit` first.)

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/unit/plugins/web_fetch/test_errors.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/alfred/plugins/web_fetch/errors.py tests/unit/plugins/web_fetch/test_errors.py locale/en/LC_MESSAGES/alfred.po
git commit -m "feat(web-fetch): add WebFetchActionTimeout typed exception + i18n key (#339 PR4b-audit)"
```

---

### Task 4: Convert the action-deadline `TimeoutError` in `dispatch_web_fetch`

**Files:**

- Modify: `src/alfred/plugins/web_fetch/fetch_dispatcher.py` (imports; the inner `try` at 488-531)
- Test: `tests/unit/plugins/web_fetch/test_fetch_dispatcher_timeout.py` (create) or the existing dispatcher unit module

**Interfaces:**

- Consumes: `compute_egress_id` (egress_id.py), `extractor.ledger_state` (Task 2), `WebFetchActionTimeout` (Task 3), `domain` (already computed at :288).
- Produces: `dispatch_web_fetch` now raises `WebFetchActionTimeout` (not bare `TimeoutError`) when the fused fetch+extract overruns the deadline. The `finally` still releases `handle_cap`.

- [ ] **Step 1: Write the failing unit test** (fake extractor whose `handle` sleeps past a tiny deadline and whose `ledger_state` returns `committed_no_response`; assert the raised type + fields + that the ledger read happened)

```python
@pytest.mark.asyncio
async def test_action_deadline_raises_enriched_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    class _HangingExtractor:
        async def handle(self, **_: object) -> object:
            await asyncio.sleep(10)  # overruns the 0.05s deadline below
            raise AssertionError("unreachable")

        async def ledger_state(self, *, egress_id: str) -> str | None:
            return "committed_no_response"

    with pytest.raises(WebFetchActionTimeout) as ei:
        await dispatch_web_fetch(
            url="https://example.com/x",
            headers={},
            user_id="u1",
            correlation_id="corr",
            egress_ctx=TurnEgressContext(adapter_id="a", inbound_id="i", session_id="s"),
            call_index=0,
            schema=_SomeExtractionSchema,
            config=_fetch_config(),           # existing helper
            rate_limiter=_fake_rate_limiter(),
            handle_cap=_fake_handle_cap(),     # release() must be awaited in finally
            outbound_dlp=_identity_dlp(),
            audit=_capturing_audit(),
            extractor=_HangingExtractor(),
            action_deadline_seconds=0.05,
        )
    exc = ei.value
    assert exc.in_doubt is True
    assert exc.ledger_state == "committed_no_response"
    assert exc.destination_host == "example.com"
    assert exc.egress_id == compute_egress_id(
        TurnEgressContext(adapter_id="a", inbound_id="i", session_id="s"), call_index=0
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/plugins/web_fetch/test_fetch_dispatcher_timeout.py -v`
Expected: FAIL — a bare `TimeoutError` is raised, not `WebFetchActionTimeout`.

- [ ] **Step 3: Add imports** to `fetch_dispatcher.py` (top of file, with the other `alfred.egress` / `.errors` imports)

```python
from alfred.egress.egress_id import TurnEgressContext, compute_egress_id  # add compute_egress_id
from alfred.plugins.web_fetch.errors import (  # add WebFetchActionTimeout to the existing group
    WebFetchActionTimeout,
    WebFetchError,
    ...
)
```

- [ ] **Step 4: Add the `except TimeoutError` arm** to the inner `try` (the one whose only handler is `except InboundCanaryTripped:` at ~500). Place it AFTER the `InboundCanaryTripped` arm. `domain` is already in scope (:288).

```python
        except TimeoutError:
            # #347 blocker 2: the fused fetch+extract overran the action deadline.
            # We own the ledger here (via the extractor); read the REAL committed
            # state and package the in-doubt fact into a typed exception so the
            # orchestrator-wiring chokepoint writes the enriched, non-skippable
            # tool.dispatch row (HARD rule #7). asyncio.timeout has already
            # converted the CancelledError to TimeoutError, so the surrounding
            # task is no longer being cancelled and this await is safe. The outer
            # ``finally`` still releases the handle_cap slot after this raise.
            egress_id = compute_egress_id(egress_ctx, call_index=call_index)
            state = await extractor.ledger_state(egress_id=egress_id)
            raise WebFetchActionTimeout(
                egress_id=egress_id,
                destination_host=domain,
                in_doubt=state == "committed_no_response",
                ledger_state=state,
            ) from None
```

- [ ] **Step 5: Run test to verify it passes + the finally still releases the slot**

Run: `uv run pytest tests/unit/plugins/web_fetch/test_fetch_dispatcher_timeout.py -v`
Expected: PASS. Assert in the test that `_fake_handle_cap().release` was awaited exactly once (the `finally` runs after the raise).

- [ ] **Step 6: Run the whole dispatcher unit module** (no regressions to the canary/rate-limit/dlp arms)

Run: `uv run pytest tests/unit/plugins/web_fetch/ -q`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/alfred/plugins/web_fetch/fetch_dispatcher.py tests/unit/plugins/web_fetch/test_fetch_dispatcher_timeout.py
git commit -m "feat(web-fetch): raise WebFetchActionTimeout with ledger state on action-deadline timeout (#339 PR4b-audit)"
```

---

### Task 5: `TOOL_DISPATCH_TIMEOUT_FIELDS` superset schema

**Files:**

- Modify: `src/alfred/audit/audit_row_schemas.py` (after `TOOL_DISPATCH_FIELDS`, ~line 313)
- Test: `tests/unit/audit/test_audit_row_schemas.py` (parametrized name list ~20-46; superset-test precedent ~63)

**Interfaces:**

- Produces: `TOOL_DISPATCH_TIMEOUT_FIELDS: Final[frozenset[str]]` = `TOOL_DISPATCH_FIELDS | {egress_id, destination_host, in_doubt, ledger_state}`. Consumed by Task 6's enriched emit.

- [ ] **Step 1: Write the failing tests** (add to `test_audit_row_schemas.py`)

```python
def test_tool_dispatch_timeout_fields_is_superset_of_tool_dispatch() -> None:
    assert audit_row_schemas.TOOL_DISPATCH_FIELDS.issubset(
        audit_row_schemas.TOOL_DISPATCH_TIMEOUT_FIELDS
    )
    assert audit_row_schemas.TOOL_DISPATCH_TIMEOUT_FIELDS - audit_row_schemas.TOOL_DISPATCH_FIELDS == {
        "egress_id",
        "destination_host",
        "in_doubt",
        "ledger_state",
    }
```

Also add `"TOOL_DISPATCH_TIMEOUT_FIELDS"` to the parametrized constant-name list (after `"TOOL_DISPATCH_FIELDS"`, ~line 46) so `test_constant_is_frozenset_of_strings` + `test_correlation_id_present_in_all_constants` cover it.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/audit/test_audit_row_schemas.py -v -k "timeout or frozenset or correlation"`
Expected: FAIL — `AttributeError: ... has no attribute 'TOOL_DISPATCH_TIMEOUT_FIELDS'`

- [ ] **Step 3: Add the constant** (in `audit_row_schemas.py`, in the `tool.dispatch` family section)

```python
TOOL_DISPATCH_TIMEOUT_FIELDS: Final[frozenset[str]] = TOOL_DISPATCH_FIELDS | frozenset(
    {
        # sha256 egress-id of the timed-out logical call (deterministic; no T3).
        "egress_id",
        # The bare destination host ONLY (never the URL/path/query/userinfo).
        "destination_host",
        # True when the ledger is committed_no_response — the side effect may have
        # fired before the deadline and its outcome is unknown (#347 blocker 2).
        "in_doubt",
        # The ledger's committed state: "committed_no_response" |
        # "committed_with_response" | None (no row — timed out before commit).
        "ledger_state",
    }
)
"""Superset of :data:`TOOL_DISPATCH_FIELDS` for the enriched action-deadline
``tool.dispatch`` timeout row (#347 blocker 2). Same ``event="tool.dispatch"``
family; the extra fields make the in-doubt side effect forensically auditable
(HARD rule #7). NEVER carries the URL/body or ``str(exc)``."""
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/audit/test_audit_row_schemas.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/alfred/audit/audit_row_schemas.py tests/unit/audit/test_audit_row_schemas.py
git commit -m "feat(audit): add TOOL_DISPATCH_TIMEOUT_FIELDS superset schema (#339 PR4b-audit)"
```

---

### Task 6: Enrich the `dispatch_tool` timeout arm

**Files:**

- Modify: `src/alfred/orchestrator/tool_dispatch.py` (imports; the external-leg arms 178-233; the stale `:215-216` comment)
- Modify: `tests/unit/audit/test_audit_log_result_domain_closed.py` (re-pin the shifted `tool_dispatch.py:114` line; fix the stale `:24` comment)
- Test: `tests/unit/orchestrator/test_tool_dispatch*.py` (the existing dispatch_tool unit module)

**Interfaces:**

- Consumes: `WebFetchActionTimeout` (Task 3), `TOOL_DISPATCH_TIMEOUT_FIELDS` (Task 5).
- Produces: enriched `tool.dispatch` timeout row + retained recoverable `t("orchestrator.tool.timeout")` return.

- [ ] **Step 1: Write the failing unit tests** (add to the dispatch_tool unit module)

```python
@pytest.mark.asyncio
async def test_timeout_writes_enriched_audit_row() -> None:
    audit = _CapturingAudit()
    registry = _registry_with_external_tool(
        dispatch=_raises(
            WebFetchActionTimeout(
                egress_id="e" * 64,
                destination_host="example.com",
                in_doubt=True,
                ledger_state="committed_no_response",
            )
        )
    )
    out = await dispatch_tool(
        _tool_call("web.fetch", {"url": "https://example.com/x"}),
        0,
        ctx=_ctx(),
        registry=registry,
        gate=_granting_gate(),
        dlp=_identity_dlp(),
        audit=audit,
        user_id="u1",
        correlation_id="corr",
        language="en",
    )
    # Recoverable string returned to the planner (unchanged UX).
    assert out == t("orchestrator.tool.timeout", tool="web.fetch")
    row = audit.single_row(event="tool.dispatch")
    assert row.schema_name == "TOOL_DISPATCH_TIMEOUT_FIELDS"
    assert row.subject["dispatch_outcome"] == "timeout"
    assert row.subject["egress_id"] == "e" * 64
    assert row.subject["destination_host"] == "example.com"
    assert row.subject["in_doubt"] is True
    assert row.subject["ledger_state"] == "committed_no_response"
    assert row.result == "refused"


@pytest.mark.asyncio
async def test_action_timeout_not_swallowed_by_web_fetch_error_arm() -> None:
    # Ordering regression: WebFetchActionTimeout is a WebFetchError subclass; its
    # arm MUST precede the generic `except WebFetchError` arm (else it lands the
    # generic tool_error row with none of the forensic fields).
    audit = _CapturingAudit()
    registry = _registry_with_external_tool(
        dispatch=_raises(
            WebFetchActionTimeout(
                egress_id="f" * 64, destination_host="h.example", in_doubt=False, ledger_state=None
            )
        )
    )
    await dispatch_tool(_tool_call("web.fetch", {"url": "https://h.example/"}), 0, ctx=_ctx(),
                        registry=registry, gate=_granting_gate(), dlp=_identity_dlp(),
                        audit=audit, user_id="u1", correlation_id="corr", language="en")
    row = audit.single_row(event="tool.dispatch")
    assert row.schema_name == "TOOL_DISPATCH_TIMEOUT_FIELDS"  # NOT the generic tool_error row


@pytest.mark.asyncio
async def test_bare_timeout_error_falls_back_to_generic_row() -> None:
    # Defensive: a bare TimeoutError from an unexpected source still audits
    # (generic row) + returns the recoverable string (HARD #7 totality).
    audit = _CapturingAudit()
    registry = _registry_with_external_tool(dispatch=_raises(TimeoutError()))
    out = await dispatch_tool(_tool_call("web.fetch", {"url": "https://x/"}), 0, ctx=_ctx(),
                              registry=registry, gate=_granting_gate(), dlp=_identity_dlp(),
                              audit=audit, user_id="u1", correlation_id="corr", language="en")
    assert out == t("orchestrator.tool.timeout", tool="web.fetch")
    row = audit.single_row(event="tool.dispatch")
    assert row.schema_name == "TOOL_DISPATCH_FIELDS"
    assert row.subject["dispatch_outcome"] == "timeout"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/orchestrator/ -v -k "timeout"`
Expected: FAIL (the enriched row / schema name do not exist yet).

- [ ] **Step 3: Add imports** to `tool_dispatch.py`

```python
from alfred.audit.audit_row_schemas import TOOL_DISPATCH_FIELDS, TOOL_DISPATCH_TIMEOUT_FIELDS
from alfred.plugins.web_fetch.errors import (
    WebFetchActionTimeout,  # add to the existing group
    WebFetchDomainNotAllowed,
    WebFetchError,
    WebFetchRateLimited,
)
```

- [ ] **Step 4: Insert the `except WebFetchActionTimeout` arm BEFORE `except WebFetchError`** (subclass-before-base — same ordering the other web_fetch arms already rely on). It does NOT use the shared `_audit` helper (that is fixed to `TOOL_DISPATCH_FIELDS`); it emits inline with the superset schema.

```python
    except WebFetchActionTimeout as exc:
        # #347 blocker 2: enrich the timeout row with the forensic fields the
        # dispatcher packaged (egress_id / destination host / in_doubt / ledger
        # state). Non-skippable (symmetric-key append_schema); HARD rule #7. The
        # forensic fields ride the exception — this chokepoint holds no ledger.
        await audit.append_schema(
            fields=TOOL_DISPATCH_TIMEOUT_FIELDS,
            schema_name="TOOL_DISPATCH_TIMEOUT_FIELDS",
            event="tool.dispatch",
            actor_user_id=user_id,
            subject={
                "tool_name": external.name,
                "call_id": call.id,
                "call_index": call_index,
                "result_tier": "T3",
                "dispatch_outcome": "timeout",
                "triggering_user_id": user_id,
                "correlation_id": correlation_id,
                "phase": f"tool_dispatch:{external.name}:{call_index}",
                "egress_id": exc.egress_id,
                "destination_host": exc.destination_host,
                "in_doubt": exc.in_doubt,
                "ledger_state": exc.ledger_state,
            },
            trust_tier_of_trigger="T2",
            result="refused",
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )
        return t("orchestrator.tool.timeout", tool=external.name)
```

- [ ] **Step 5: Update the retained defensive `except TimeoutError` arm** (fix the stale comment; keep the generic row as the fallback for any non-web.fetch timeout)

```python
    except TimeoutError:
        # Defensive fallback: a bare TimeoutError from an unexpected source (the
        # web.fetch action-deadline is converted to WebFetchActionTimeout above,
        # which carries the forensic fields). Still audited + recoverable (HARD #7).
        await _audit(
            dispatch_outcome="timeout",
            result="refused",
            tool_name=external.name,
            result_tier="T3",
        )
        return t("orchestrator.tool.timeout", tool=external.name)
```

- [ ] **Step 6: Re-pin the audit AST guard.** Adding imports shifts the `_audit` helper's dynamic `result=result` site (was `tool_dispatch.py:114`). Find its new line and update `tests/unit/audit/test_audit_log_result_domain_closed.py` (the `expected` list entry `"src/alfred/orchestrator/tool_dispatch.py:114"`). Also fix the stale `:24` comment referencing `fetch_dispatcher.py:914`.

Run: `grep -n "result=result" src/alfred/orchestrator/tool_dispatch.py`  → note the new line number, patch the guard's `expected` entry.

The enriched arm uses a STATIC `result="refused"` literal → it is NOT a dynamic `result=<var>` site, so it needs NO new guard registration (literals are covered by the `ck_audit_log_result` CHECK constraint, per the guard's own comment).

- [ ] **Step 7: Run the dispatch_tool unit tests + the audit guard**

Run: `uv run pytest tests/unit/orchestrator/ tests/unit/audit/test_audit_log_result_domain_closed.py -q`
Expected: PASS

- [ ] **Step 8: Tree-wide assertion grep (PR3/PR4a lesson).** Any test — unit OR integration — asserting the old timeout row shape must be reconciled:

Run: `grep -rn "dispatch_outcome.*timeout\|TOOL_DISPATCH_FIELDS\|schema_name.*TOOL_DISPATCH\|orchestrator.tool.timeout" tests/`
Reconcile every hit that asserts the timeout row's schema/fields.

- [ ] **Step 9: Commit**

```bash
git add src/alfred/orchestrator/tool_dispatch.py tests/unit/orchestrator/ tests/unit/audit/test_audit_log_result_domain_closed.py
git commit -m "feat(orchestrator): enrich the tool.dispatch action-deadline timeout row (#339 PR4b-audit)"
```

---

### Task 7: Cross-layer Postgres+Redis integration test (the #347 blocker-2 required test)

**Files:**

- Create: `tests/integration/orchestrator/test_tool_dispatch_timeout_audit_postgres.py`
- Reuse: `tests/integration/orchestrator/conftest.py` (`migrated_url`, `redis_url`, `authorized_t3_nonce`, `boot_loopback_relay`); model on `test_act_loop_real_chain.py`.

**Interfaces:**

- Consumes: real `PostgresEgressIdempotencyStore`, real `RateLimiter`/`HandleCap` on `redis_url`, a real loopback relay, a mock quarantined child whose `extract` hangs, `build_web_fetch_tool(..., action_deadline_seconds=<tiny>)`, `dispatch_tool`.

- [ ] **Step 1: Write the failing cross-layer test.** Drive a REAL action-deadline timeout end-to-end and assert exactly one enriched row + the ledger left in-doubt. Build the `web.fetch` `ExternalToolSpec` directly with a tiny deadline (avoids threading `action_deadline_seconds` through `build_tool_registry` — lower blast radius), register it, and call `dispatch_tool` directly.

```python
@pytest.mark.asyncio
async def test_action_deadline_timeout_emits_enriched_in_doubt_row(
    migrated_url: str, redis_url: str, authorized_t3_nonce: object
) -> None:
    async with boot_loopback_relay(allowlist={"example.com"}) as (relay, port, fire_counter, canned):
        # Mock quarantined child that HANGS during extraction so the deadline
        # fires AFTER the relay commits+fires the intent but BEFORE record_response.
        mock_extractor = _mock_quarantined_child()
        mock_extractor.extract = AsyncMock(side_effect=lambda *a, **k: asyncio.sleep(10))

        session_scope = _real_session_scope(migrated_url)
        store = PostgresEgressIdempotencyStore(session_scope=session_scope)
        rate_limiter, handle_cap = _real_limiters(redis_url)
        audit = _real_audit_writer(session_scope)  # writes to Postgres audit_log

        extractor = build_web_fetch_egress_extractor(..., ledger=store, extractor=mock_extractor, ...)
        spec = build_web_fetch_tool(
            extractor=extractor, config=_config(port), rate_limiter=rate_limiter,
            handle_cap=handle_cap, outbound_dlp=_identity_dlp(), audit=audit,
            action_deadline_seconds=0.1,   # << force the deadline
        )
        registry = ToolRegistry(external={"web.fetch": spec}, internal={})

        ctx = TurnEgressContext(adapter_id="orchestrator.synthetic", inbound_id=_TRACE, session_id="u1")
        out = await dispatch_tool(
            _tool_call("web.fetch", {"url": "https://example.com/slow"}), 0,
            ctx=ctx, registry=registry, gate=_assembly_gate(...), dlp=_identity_dlp(),
            audit=audit, user_id="u1", correlation_id=_TRACE, language="en",
        )

    # Recoverable string to the planner.
    assert out == t("orchestrator.tool.timeout", tool="web.fetch")

    # Exactly ONE enriched tool.dispatch timeout row, in-doubt, host-only.
    egress_id = compute_egress_id(ctx, call_index=0)
    rows = await _select_audit(session_scope, event="tool.dispatch", trace_id=_TRACE)
    timeout_rows = [r for r in rows if r["dispatch_outcome"] == "timeout"]
    assert len(timeout_rows) == 1
    r = timeout_rows[0]
    assert r["egress_id"] == egress_id
    assert r["destination_host"] == "example.com"
    assert r["in_doubt"] is True
    assert r["ledger_state"] == "committed_no_response"
    assert "slow" not in json.dumps(r)  # NO URL/path leak

    # The relay actually fired (side effect in doubt) and the ledger is in-doubt.
    assert fire_counter.value == 1
    assert await store.get_state(egress_id=egress_id) == "committed_no_response"
```

- [ ] **Step 2: Run test to verify it fails first** (against the tree BEFORE Tasks 4/6 land — if implementing in order, this test drives the same code Tasks 4/6 built; run it here to confirm the cross-layer wiring). Expected on a clean run after Tasks 1-6: PASS. If red, debug the harness (relay allowlist, redis fixture, deadline value) before proceeding.

Run: `uv run pytest tests/integration/orchestrator/test_tool_dispatch_timeout_audit_postgres.py -v`
Expected: PASS (Tasks 1-6 supply the behavior)

- [ ] **Step 3: Verify negative properties.** Assert NO second fire and NO `record_response` (the ledger stays `committed_no_response`, already checked) — add an explicit assertion that a `SELECT count(*)` of `committed_with_response` rows for this `egress_id` is 0.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/orchestrator/test_tool_dispatch_timeout_audit_postgres.py
git commit -m "test(339): cross-layer action-deadline timeout audit + in-doubt ledger (#339 PR4b-audit)"
```

---

### Task 8: Docs, i18n catalog, coverage gates, full verification

**Files:**

- Modify: `docs/subsystems/security.md` (audit-vocabulary section — the timeout enrichment fields); factual amendment note on `docs/adr/0041-*.md` / `docs/adr/0046-*.md` (NO new ADR — plan-review to confirm)
- Modify: `locale/en/LC_MESSAGES/alfred.{po,mo}` (final drift-gate run)
- Verify: `ci.yml` coverage gates cover the new lines (`tool_dispatch.py` is already a named 100% gate; confirm `egress_idempotency.py` / `egress_response_extract.py` new lines are covered by their tests)

- [ ] **Step 1: Update `docs/subsystems/security.md`** — add the `tool.dispatch` timeout-enrichment fields (`egress_id` / `destination_host` / `in_doubt` / `ledger_state`) to the audit-vocabulary subsection, framed as the HARD-#7 / #347-blocker-2 in-doubt forensic surface. Note the two-arm classification (enriched `WebFetchActionTimeout` vs defensive bare `TimeoutError`).

- [ ] **Step 2: Add a factual amendment note** (dated 2026-07-07) to ADR-0041 (web-fetch fused contract) and/or ADR-0046 (dual-LLM tool-result-flow invariant): the action-deadline timeout now surfaces a durable in-doubt audit row at the orchestrator wiring. (Factual amendments are in-remit; Status flips stay human-gated. **Plan-review decides whether a standalone ADR is warranted** — default: amendment note only, since this fulfills an existing obligation rather than changing an invariant.)

- [ ] **Step 3: Run the i18n drift gate** (adds `web.fetch.error.action_timeout`)

```bash
uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
uv run pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching
# fill any new msgstr by hand (web.fetch.error.action_timeout), then:
uv run pybabel compile -d locale -D alfred --statistics
```

(NEVER `--omit-header`. A line-shifting edit re-stales `#:` refs → re-run extract/update. Check `$?` directly — a `| tail` masks the exit code.)

- [ ] **Step 4: Confirm coverage.** Run the per-file coverage the way CI does for `tool_dispatch.py` (both new arms must be hit — the enriched arm by Task 6/7 tests, the defensive bare-`TimeoutError` arm by Task 6's `test_bare_timeout_error_falls_back_to_generic_row`).

```bash
uv run coverage run -m pytest tests/unit/orchestrator/ tests/unit/plugins/web_fetch/ tests/unit/egress/ tests/unit/audit/
uv run coverage report --include='src/alfred/orchestrator/tool_dispatch.py' --fail-under=100
```

Expected: 100%. If `egress_idempotency.py` / `egress_response_extract.py` have named CI gates, run those `--include` reports too; add tests to cover any new uncovered line.

- [ ] **Step 5: Full local quality gates**

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy src/ && uv run pyright src/
make check   # check $? — do not trust a tail-piped exit code
```

Expected: all green. Investigate any macOS integration-lane flake in isolation (trust Linux CI); the Docker Hub `postgres:18` image-pull 500/timeout is infra, not code — `gh run rerun --failed`, never dismiss a real failure as flake without reading the log.

- [ ] **Step 6: Run the adversarial suite** (belt-and-suspenders — this is a trust-boundary audit change, though no file under `src/alfred/security/`)

```bash
uv run pytest tests/adversarial -q
```

Expected: PASS (no new corpus entry in this PR).

- [ ] **Step 7: Commit + push**

```bash
git add docs/subsystems/security.md docs/adr/0041-*.md docs/adr/0046-*.md locale/en/LC_MESSAGES/alfred.po locale/en/LC_MESSAGES/alfred.mo
git commit -m "docs(339): audit-vocab + ADR note for action-deadline in-doubt timeout row (#339 PR4b-audit)"
git push -u origin 339-pr4b-audit-timeout-in-doubt
```

---

## Self-Review

**1. Spec coverage (against #347 blocker 2):**

- "emit a non-skippable audit row on `TimeoutError` from the fused dispatch call (`egress_id`, destination host, `in_doubt` flag, the ledger's committed state)" → Tasks 5+6 (`TOOL_DISPATCH_TIMEOUT_FIELDS` + enriched `dispatch_tool` arm). ✅
- "at the orchestrator wiring added in #339" → the row is emitted at `dispatch_tool` (the #339 chokepoint), not the dispatcher. ✅
- "a relay that times out produces exactly one audit row with the correct `in_doubt` flag, and the ledger is left in `committed_no_response` (not dangling)" → Task 7 (cross-layer Postgres+Redis integration test). ✅
- "the ledger is left `committed_no_response` = in-doubt" → confirmed structurally (cancellation drain skips `record_response`); read via new `get_state` (Tasks 1-2). ✅
- Fix the STALE `tool_dispatch.py:215` "lands in PR3" comment → Task 6 Step 5. ✅
- Harness `test_egress_barrier_dedup_postgres.py` was named in the blocker, but the precise cross-layer path (`dispatch_tool` → `dispatch_web_fetch`) needs the orchestrator harness — Task 7 models on `test_act_loop_real_chain.py` (documented divergence: the barrier test stages in-doubt via `post_fire_hook`, which fires BEFORE extraction; a real action-deadline needs a hanging child so cancellation lands in extraction). ✅

**2. Placeholder scan:** the `...` in the Task 7 harness sketch (`build_web_fetch_egress_extractor(..., ledger=store, ...)`) are real assembly kwargs the implementer copies from `assembly.py:107` / `test_act_loop_real_chain.py:259-271`; every behavioral step has concrete asserts. No TBD/"add error handling"/"similar to Task N".

**3. Type consistency:** `get_state(*, egress_id: str) -> str | None` is used identically in Task 1 (store), Task 2 (extractor delegate), Task 4 (dispatcher read). `WebFetchActionTimeout(*, egress_id, destination_host, in_doubt, ledger_state)` fields match across Tasks 3/4/6/7. `TOOL_DISPATCH_TIMEOUT_FIELDS` field names (`egress_id`/`destination_host`/`in_doubt`/`ledger_state`) match the emit subject in Task 6 and the asserts in Task 7. `dispatch_outcome="timeout"` + `result="refused"` consistent (in-domain).

## Open questions for plan-review (fold as an override layer if the fleet flags)

- **ADR: amendment note vs standalone ADR** for the durable in-doubt timeout-audit contract. Default = amendment note on ADR-0041/0046 (fulfills existing obligation). Security/architect to confirm.
- **One row vs two.** This plan emits ONE enriched row at `dispatch_tool` (blocker wording: "at the orchestrator wiring"). The dispatcher does the ledger read + raises but writes no separate `tool.web.fetch` timeout row (asymmetric with the canary/rate-limit arms that DO write a dispatcher-layer row). Confirm the single-row choice is acceptable (vs a `tool.web.fetch` timeout row at the dispatcher too, matching the other arms).
- **Retain vs drop the defensive bare `except TimeoutError`.** Retained here (recoverable + generic row + covered by a synthetic unit test) to preserve the existing recoverable-timeout contract and HARD-#7 totality. Alternative: drop it and let `except Exception` re-raise (halt) a stray timeout. Confirm.
- **`action_deadline_seconds` threading.** Task 7 builds the `web.fetch` spec directly to force a tiny deadline (avoids threading `action_deadline_seconds` through `build_tool_registry`). Confirm this is preferable to a `build_tool_registry` param (which #338 will likely add anyway for a configurable deadline).

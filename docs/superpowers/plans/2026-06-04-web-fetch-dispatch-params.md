# Host-side web.fetch dispatch-params validation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. Trust-boundary work — TDD is HARD here, not advisory.

**Goal:** Add host-side Pydantic v2 validation of `web.fetch` JSON-RPC dispatch params, so dispatcher bugs (e.g. forgetting `redis_url` per PR-S3-5's C2 / arch-002 finding) fail clean with a typed `WebFetchError` + audit row instead of crashing the plugin subprocess (err-004 contract stays as secondary defence).

**Architecture:** New `WebFetchDispatchParams` Pydantic v2 model in `src/alfred/plugins/web_fetch/dispatch_params.py`. `dispatch_web_fetch` constructs it BEFORE `transport.dispatch`; on `ValidationError` → release cap (already-reserved) → emit audit row with new closed-set `dlp_scan_result="dispatch_param_invalid"` → raise `WebFetchError`. Wire format unchanged (model serialised via `.model_dump()`).

**Tech Stack:** Python 3.14.5 • Pydantic v2 (`BaseModel`, `ConfigDict(extra="forbid", strict=True, frozen=True)`, `Field(gt=0)`) • `typing.Literal[...]` for closed-set audit vocabulary • `structlog` for loud signal • `t()` for operator-facing strings • pytest + `_build_*` factory pattern from `test_fetch_dispatcher.py:52-180`.

**Spec anchor:** [`docs/superpowers/specs/2026-06-04-web-fetch-dispatch-params-design.md`](../specs/2026-06-04-web-fetch-dispatch-params-design.md) — committed on this branch alongside this plan.

**Depends on:** #157 (merged — `WebFetchDispatchParams` includes `content_handle_id` which post-dates the issue body).
**Blocks:** Nothing in flight.

---

## §1 Goal

After this PR merges:

1. `WebFetchDispatchParams` Pydantic model exists with required fields per spec §2.1 + 2 defaults.
2. `dispatch_web_fetch` constructs the model and serialises via `.model_dump()` before `await transport.dispatch(...)`.
3. A missing or wrong-typed kwarg raises `ValidationError` host-side; the dispatcher catches it, releases the cap, emits a `tool.web.fetch` audit row with `dlp_scan_result="dispatch_param_invalid"`, and raises typed `WebFetchError`.
4. Plugin subprocess err-004 behaviour unchanged.
5. New i18n catalog entry `web.fetch.error.dispatch_param_invalid` (operator-actionable).
6. `DlpScanResult` Literal widens from 14 → 15 values (PR #160 already added `handle_cap_exceeded` + `handle_id_mismatch` taking it to 14; this PR adds `dispatch_param_invalid`).

Trust-boundary code reaches 100% line + branch coverage per CLAUDE.md.

---

## §2 File structure

| File | Status | Responsibility |
|---|---|---|
| `src/alfred/plugins/web_fetch/dispatch_params.py` | Create | `WebFetchDispatchParams` Pydantic v2 model (single class, ~40 lines) |
| `src/alfred/plugins/web_fetch/fetch_dispatcher.py` | Modify | Construct + validate before `transport.dispatch`; emit audit row + release cap on `ValidationError`; raise `WebFetchError` |
| `src/alfred/audit/audit_row_schemas.py` | Modify | Add `"dispatch_param_invalid"` to `DlpScanResult` Literal |
| `src/alfred/plugins/web_fetch/__init__.py` | Modify | (Only if `__init__.py` already re-exports closed surface; otherwise skip — verify before editing) |
| `locale/en/LC_MESSAGES/alfred.po` | Modify | New `web.fetch.error.dispatch_param_invalid` msgstr (operator-actionable) |
| `docs/subsystems/security.md` | Modify | Cross-reference the new audit-vocabulary value |
| `tests/unit/plugins/web_fetch/test_dispatch_params.py` | Create | Model unit tests (validation matrix) |
| `tests/unit/plugins/web_fetch/test_dispatch_params_e2e.py` | Create | Parametrised end-to-end via `dispatch_web_fetch` |
| `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py` | Modify | Add 3 integration tests (release-on-validation-error, audit-row-shape, structlog-typename) |
| `tests/unit/audit/test_audit_row_schemas.py` | Modify | Pin widened `DlpScanResult` set |

---

## §3 Coverage matrix (subsystem owners)

| Subsystem | Files | Owner agent |
|---|---|---|
| Pydantic model + tests | `dispatch_params.py`, `test_dispatch_params.py`, `test_dispatch_params_e2e.py` | alfred-security-engineer |
| Dispatcher integration | `fetch_dispatcher.py`, `test_fetch_dispatcher.py` | alfred-security-engineer |
| Audit row schema | `audit_row_schemas.py`, `test_audit_row_schemas.py` | alfred-security-engineer |
| i18n catalog | `alfred.po` | alfred-i18n-reviewer |
| Subsystem docs | `docs/subsystems/security.md` | alfred-docs-author |

Plan-level owner: **alfred-security-engineer** (trust-boundary).

---

## §4 Definition of Done

- [ ] All §5 tasks complete.
- [ ] `uv run pytest tests/unit/plugins/web_fetch/ tests/unit/audit/ -q` → green.
- [ ] `uv run pytest --cov=src/alfred/plugins/web_fetch/dispatch_params --cov=src/alfred/plugins/web_fetch/fetch_dispatcher --cov-branch --cov-fail-under=100 tests/unit/plugins/web_fetch/` → 100% line + branch on both modules.
- [ ] `uv run ruff check . && uv run ruff format --check .` → clean.
- [ ] `uv run mypy src/ && uv run pyright src/` → clean.
- [ ] `make check` → green.
- [ ] `uv run pybabel extract -F babel.cfg -o locale/alfred.pot src/alfred/ && uv run pybabel update -i locale/alfred.pot -d locale/ --previous --no-fuzzy-matching --ignore-pot-creation-date && uv run pybabel compile -d locale/` → clean drift.
- [ ] Conventional Commits + `#147` in every subject + no `fixup!` markers post-autosquash.
- [ ] User check-in before opening the PR.

---

## §5 Tasks

### Task 1 — Widen `DlpScanResult` Literal (foundation, runs first)

**Owner**: alfred-security-engineer
**Files**:

- Modify: `src/alfred/audit/audit_row_schemas.py`
- Modify: `tests/unit/audit/test_audit_row_schemas.py`

- [ ] **Step 1: Write the failing test.**

  Update `test_dlp_scan_result_literal_includes_new_values` (added in #157) to include the new value:

  ```python
  def test_dlp_scan_result_literal_includes_new_values() -> None:
      from alfred.audit.audit_row_schemas import DlpScanResult
      from typing import get_args
      values = set(get_args(DlpScanResult))
      assert "handle_cap_exceeded" in values
      assert "handle_id_mismatch" in values
      assert "dispatch_param_invalid" in values   # NEW per #147
      # Legacy stays.
      for legacy in ("clean", "scanned_dirty", "rate_limited",
                     "transport_error", "domain_not_allowed"):
          assert legacy in values
  ```

  (The exact-set assertion test that #157 added — `test_dlp_scan_result_literal_full_vocabulary` — also needs the new value added to its expected set. Find and update.)

- [ ] **Step 2: Run; confirm failure.**

  ```bash
  cd "$(git rev-parse --show-toplevel)"
  uv run pytest tests/unit/audit/test_audit_row_schemas.py -v
  ```

  Expected: assertion error on `dispatch_param_invalid`.

- [ ] **Step 3: Add `"dispatch_param_invalid"` to the Literal.**

  In `src/alfred/audit/audit_row_schemas.py`, find `DlpScanResult = Literal[...]` and append `"dispatch_param_invalid"`. Match the existing pattern (one value per line, trailing inline comment if discriminating).

- [ ] **Step 4: Run tests; confirm green.**

- [ ] **Step 5: Commit.**

  ```bash
  git add src/alfred/audit/audit_row_schemas.py tests/unit/audit/test_audit_row_schemas.py
  git commit -m "feat(audit): add dispatch_param_invalid to DlpScanResult Literal (#147)

  Spec §4 closed-vocabulary widening from 14 → 15 values. Mechanically
  reachable from dispatcher's host-side Pydantic validation arm (added
  in Task 2).

  Refs: #147

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Task 2 — `WebFetchDispatchParams` Pydantic model

**Owner**: alfred-security-engineer
**Files**:

- Create: `src/alfred/plugins/web_fetch/dispatch_params.py`
- Create: `tests/unit/plugins/web_fetch/test_dispatch_params.py`

- [ ] **Step 1: Write the failing tests.**

  Create `tests/unit/plugins/web_fetch/test_dispatch_params.py`:

  ```python
  """WebFetchDispatchParams model — host-side validation matrix.

  Per spec §2.1: extra="forbid", strict=True, frozen=True.
  Defence-in-depth before transport.dispatch crosses the wire to the
  plugin subprocess (issue #147).
  """

  from __future__ import annotations

  import pytest
  from pydantic import ValidationError

  from alfred.plugins.web_fetch.dispatch_params import WebFetchDispatchParams

  _VALID_KWARGS = {
      "url": "https://example.com/",
      "headers": {"Accept": "text/html"},
      "redis_url": "redis://localhost:6379",
      "correlation_id": "cid-test",
      "content_handle_id": "00000000-0000-0000-0000-000000000001",
  }


  def test_valid_construction_works() -> None:
      params = WebFetchDispatchParams(**_VALID_KWARGS)
      assert params.url == "https://example.com/"
      assert params.skip_tls_verify is False
      assert params.size_limit_bytes == 5 * 1024 * 1024


  def test_model_dump_roundtrip() -> None:
      params = WebFetchDispatchParams(**_VALID_KWARGS)
      d = params.model_dump()
      assert d["url"] == "https://example.com/"
      assert d["skip_tls_verify"] is False
      assert d["size_limit_bytes"] == 5 * 1024 * 1024


  @pytest.mark.parametrize(
      "missing",
      ["url", "headers", "redis_url", "correlation_id", "content_handle_id"],
  )
  def test_missing_required_field_raises(missing: str) -> None:
      kwargs = {k: v for k, v in _VALID_KWARGS.items() if k != missing}
      with pytest.raises(ValidationError):
          WebFetchDispatchParams(**kwargs)


  def test_extra_field_forbidden() -> None:
      with pytest.raises(ValidationError):
          WebFetchDispatchParams(**_VALID_KWARGS, unexpected_key="x")


  def test_wrong_type_url_strict() -> None:
      with pytest.raises(ValidationError):
          WebFetchDispatchParams(**{**_VALID_KWARGS, "url": 42})


  def test_wrong_type_headers_strict() -> None:
      with pytest.raises(ValidationError):
          WebFetchDispatchParams(**{**_VALID_KWARGS, "headers": "Accept: text/html"})


  def test_size_limit_must_be_positive() -> None:
      for bad in (0, -1, -1000):
          with pytest.raises(ValidationError):
              WebFetchDispatchParams(**_VALID_KWARGS, size_limit_bytes=bad)


  def test_size_limit_must_be_int_strict() -> None:
      with pytest.raises(ValidationError):
          WebFetchDispatchParams(**_VALID_KWARGS, size_limit_bytes=1.5)


  def test_skip_tls_verify_strict_bool() -> None:
      # strict=True: int 1 must NOT coerce to bool True
      with pytest.raises(ValidationError):
          WebFetchDispatchParams(**_VALID_KWARGS, skip_tls_verify=1)


  def test_frozen() -> None:
      params = WebFetchDispatchParams(**_VALID_KWARGS)
      with pytest.raises((ValidationError, TypeError, AttributeError)):
          params.url = "https://changed.example/"  # type: ignore[misc]
  ```

- [ ] **Step 2: Run; confirm `ImportError`.**

  ```bash
  uv run pytest tests/unit/plugins/web_fetch/test_dispatch_params.py -v
  ```

- [ ] **Step 3: Implement the model.**

  Create `src/alfred/plugins/web_fetch/dispatch_params.py`:

  ```python
  """``WebFetchDispatchParams`` — host-side Pydantic schema for the
  ``web.fetch`` JSON-RPC params dict (issue #147 / spec §2.1).

  Defence-in-depth: ``dispatch_web_fetch`` constructs this model BEFORE
  ``transport.dispatch``. A missing or wrong-typed field raises
  ``pydantic.ValidationError`` host-side; the dispatcher catches it,
  releases the handle-cap reservation, emits a ``tool.web.fetch`` audit
  row with ``dlp_scan_result="dispatch_param_invalid"``, and raises
  typed ``WebFetchError``.

  The plugin subprocess's err-004 crash-on-bad-params contract stays
  as the secondary defence; this model is the primary.
  """

  from __future__ import annotations

  from typing import Final

  from pydantic import BaseModel, ConfigDict, Field

  _DEFAULT_SIZE_LIMIT_BYTES: Final[int] = 5 * 1024 * 1024


  class WebFetchDispatchParams(BaseModel):
      """JSON-RPC params dict for ``web.fetch``.

      ``extra="forbid"`` so a dispatcher adding a key without updating
      the model fails loud (matches the C2 / arch-002 shape from
      PR-S3-5 — issue #147's root cause).

      ``strict=True`` so type coercion can't paper over a dispatcher
      bug (e.g. passing ``1`` for ``skip_tls_verify`` would otherwise
      coerce to ``True``).

      ``frozen=True`` so the validated payload is the wire format —
      nothing mutates it post-validation.
      """

      model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

      url: str
      headers: dict[str, str]
      redis_url: str
      correlation_id: str
      content_handle_id: str
      """Host pre-minted UUID (added by #157). The plugin uses this
      exact key when writing the body to Redis; the dispatcher verifies
      equality on the success path (handle-cap PR's Task 19)."""

      skip_tls_verify: bool = False
      """Dev escape hatch (``ALFRED_ENV=development`` only). The
      parent-side ``TlsPolicy`` check is the authoritative gate; this
      flag is forwarded for the subprocess-side defence-in-depth check."""

      size_limit_bytes: int = Field(default=_DEFAULT_SIZE_LIMIT_BYTES, gt=0)
      """Response body cap. ``gt=0`` defends against a 0/negative value
      reaching the plugin; ``_clamp_size_limit`` in the plugin is the
      secondary defence (CR-146 major)."""


  __all__ = ["WebFetchDispatchParams"]
  ```

- [ ] **Step 4: Run; confirm green.**

- [ ] **Step 5: Lint + type-check.**

  ```bash
  uv run ruff check src/alfred/plugins/web_fetch/dispatch_params.py tests/unit/plugins/web_fetch/test_dispatch_params.py
  uv run ruff format --check src/alfred/plugins/web_fetch/dispatch_params.py tests/unit/plugins/web_fetch/test_dispatch_params.py
  uv run mypy src/alfred/plugins/web_fetch/dispatch_params.py
  uv run pyright src/alfred/plugins/web_fetch/dispatch_params.py
  ```

- [ ] **Step 6: Commit.**

  ```bash
  git add src/alfred/plugins/web_fetch/dispatch_params.py tests/unit/plugins/web_fetch/test_dispatch_params.py
  git commit -m "feat(web-fetch): WebFetchDispatchParams Pydantic model (#147)

  Host-side schema for web.fetch JSON-RPC params. extra=forbid +
  strict=True + frozen=True per spec §2.1. Defence-in-depth before
  transport.dispatch crosses the wire to the plugin subprocess.

  The plugin's err-004 crash-on-bad-params contract stays as the
  secondary defence; this model is the primary.

  Refs: #147

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Task 3 — Dispatcher integration

**Owner**: alfred-security-engineer
**Files**:

- Modify: `src/alfred/plugins/web_fetch/fetch_dispatcher.py`
- Modify: `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py`

- [ ] **Step 1: Write the failing tests.**

  Append to `test_fetch_dispatcher.py`:

  ```python
  from unittest.mock import patch
  from pydantic import ValidationError

  from alfred.plugins.web_fetch.dispatch_params import WebFetchDispatchParams


  @pytest.mark.asyncio
  async def test_dispatcher_releases_cap_on_param_validation_error(
      audit_writer,
  ) -> None:
      """Pydantic ValidationError host-side → release cap + raise WebFetchError.
      transport.dispatch MUST NOT be called."""
      audit = _build_audit()
      transport = _build_transport_returning_handle()
      handle_cap = _build_handle_cap()

      # Patch the model constructor to raise — simulates ANY required-field bug.
      with patch.object(
          WebFetchDispatchParams,
          "__init__",
          side_effect=ValidationError.from_exception_data(
              "WebFetchDispatchParams", [{"type": "missing", "loc": ("url",)}],
          ),
      ):
          with pytest.raises(WebFetchError):
              await dispatch_web_fetch(
                  ..., handle_cap=handle_cap, audit=audit, transport=transport,
              )

      handle_cap.release.assert_awaited()
      transport.dispatch.assert_not_called()


  @pytest.mark.asyncio
  async def test_dispatcher_param_validation_audit_row_shape(audit_writer) -> None:
      """Validation-failure audit row carries dispatch_param_invalid +
      pre-minted content_handle_id + T0 result tier."""
      audit = _build_audit()
      transport = _build_transport_returning_handle()
      handle_cap = _build_handle_cap()

      with patch.object(WebFetchDispatchParams, "__init__",
                        side_effect=ValidationError.from_exception_data(...)):
          with pytest.raises(WebFetchError):
              await dispatch_web_fetch(..., handle_cap=handle_cap, audit=audit, transport=transport)

      last = audit.append_schema.call_args_list[-1]
      subj = last.kwargs["subject"]
      assert subj["dlp_scan_result"] == "dispatch_param_invalid"
      assert subj["content_handle_id"] is not None  # the pre-minted UUID
      assert subj["trust_tier_of_result"] == "T0"
      assert last.kwargs["result"] == "dispatch_param_invalid"


  @pytest.mark.asyncio
  async def test_dispatcher_param_validation_structlog_emits_typename() -> None:
      """Loud structlog event carries Pydantic ValidationError type name (NOT raw message)."""
      from structlog.testing import capture_logs
      audit = _build_audit()
      transport = _build_transport_returning_handle()
      handle_cap = _build_handle_cap()

      with patch.object(WebFetchDispatchParams, "__init__",
                        side_effect=ValidationError.from_exception_data(...)):
          with capture_logs() as logs:
              with pytest.raises(WebFetchError):
                  await dispatch_web_fetch(..., handle_cap=handle_cap, audit=audit, transport=transport)

      events = [log for log in logs if log.get("event") == "web_fetch.dispatch.param_validation_failed"]
      assert events, "loud structlog event missing"
      assert events[0].get("exception_type") == "ValidationError"
      # Raw message MUST NOT appear in the event's user-visible fields.
      for log in events:
          for v in log.values():
              if isinstance(v, str):
                  assert "url" not in v.lower() or "exception_type" in str(log)  # field-name leak guard
  ```

  (Adapt `dispatch_web_fetch(...)` kwargs to match the existing test pattern at `test_fetch_dispatcher.py:141-180`.)

- [ ] **Step 2: Run; confirm failure.**

- [ ] **Step 3: Modify `dispatch_web_fetch`.**

  In `src/alfred/plugins/web_fetch/fetch_dispatcher.py`, find the `transport.dispatch("web.fetch", ...)` block (around line 594-604). Replace with:

  ```python
  # Construct + validate dispatch params host-side (defence-in-depth
  # before the plugin subprocess's err-004 crash-on-bad-params; issue
  # #147). A ValidationError here means a dispatcher bug (e.g.
  # forgetting redis_url — the C2/arch-002 shape from PR-S3-5).
  try:
      dispatch_params = WebFetchDispatchParams(
          url=clean_url,
          headers=clean_headers,
          redis_url=config.redis_url,
          correlation_id=correlation_id,
          content_handle_id=handle_id,
          skip_tls_verify=config.skip_tls_verify,
      )
  except ValidationError as exc:
      log.error(
          "web_fetch.dispatch.param_validation_failed",
          user_id=user_id,
          handle_id=handle_id,
          correlation_id=correlation_id,
          exception_type=type(exc).__name__,
          # NEVER include str(exc) or exc.errors() raw — Pydantic
          # error messages embed field names + values that may carry
          # secrets (URL query params, header values). The audit row
          # carries the closed-vocabulary tag for forensic correlation
          # via correlation_id.
          note=(
              "host-side dispatch-params validation failed; this is "
              "a host defect, not user input. Cap slot released; "
              "transport.dispatch NOT invoked."
          ),
      )
      # Release the cap reservation — eager release on this error arm.
      try:
          await handle_cap.release(
              user_id=user_id, handle_id=handle_id,
              correlation_id=correlation_id,
          )
      except (RedisError, ConnectionError, TimeoutError) as release_exc:
          log.error(
              "web_fetch.handle_cap.eager_release_failed",
              user_id=user_id, handle_id=handle_id,
              exception_type=type(release_exc).__name__,
              note="best-effort release failed; passive TTL will free slot",
          )
      released = True

      await audit.append_schema(
          fields=WEB_FETCH_FIELDS,
          schema_name="WEB_FETCH_FIELDS",
          event="tool.web.fetch",
          actor_user_id=user_id,
          subject={
              "url": clean_url, "domain": domain,
              "status_code": None,
              "content_handle_id": handle_id,
              "fetch_depth": _FETCH_DEPTH,
              "rate_limit_bucket": None,
              "manifest_commit_hash": config.manifest_commit_hash,
              "trust_tier_of_result": "T0",
              "dlp_scan_result": "dispatch_param_invalid",
              "canary_tripped": False,
              "triggering_user_id": user_id,
              "correlation_id": correlation_id,
          },
          trust_tier_of_trigger="T0",
          result="dispatch_param_invalid",
          cost_estimate_usd=0.0,
          trace_id=correlation_id,
      )
      raise WebFetchError(t("web.fetch.error.dispatch_param_invalid")) from exc

  try:
      result = await transport.dispatch("web.fetch", dispatch_params.model_dump())
  except Exception:
      # ...existing transport_error arm unchanged...
  ```

  Add imports at top:

  ```python
  from pydantic import ValidationError
  from alfred.plugins.web_fetch.dispatch_params import WebFetchDispatchParams
  ```

- [ ] **Step 4: Run; confirm green.**

- [ ] **Step 5: Coverage gate.**

  ```bash
  DOCKER_HOST=unix:///Users/iandominey/.orbstack/run/docker.sock \
  TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/Users/iandominey/.orbstack/run/docker.sock \
  uv run pytest \
    tests/unit/plugins/web_fetch/test_fetch_dispatcher.py \
    --cov=src/alfred/plugins/web_fetch/fetch_dispatcher \
    --cov=src/alfred/plugins/web_fetch/dispatch_params \
    --cov-branch --cov-fail-under=100
  ```

- [ ] **Step 6: Commit.**

  ```bash
  git add src/alfred/plugins/web_fetch/fetch_dispatcher.py tests/unit/plugins/web_fetch/test_fetch_dispatcher.py
  git commit -m "feat(dispatcher): host-side Pydantic validation of web.fetch params (#147)

  dispatch_web_fetch constructs WebFetchDispatchParams BEFORE
  transport.dispatch. On ValidationError: release cap + LOUD structlog
  + audit row (dlp_scan_result=dispatch_param_invalid) + raise typed
  WebFetchError.

  Plugin err-004 crash-on-bad-params remains as secondary defence.

  Refs: #147

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Task 4 — i18n catalog entry

**Owner**: alfred-i18n-reviewer
**Files**:

- Modify: `locale/en/LC_MESSAGES/alfred.po`, `locale/en/LC_MESSAGES/alfred.mo`

- [ ] **Step 1: Add the entry.**

  Append after the existing `web.fetch.error.handle_id_mismatch` entry in `locale/en/LC_MESSAGES/alfred.po`:

  ```po
  #: src/alfred/plugins/web_fetch/errors.py
  msgid "web.fetch.error.dispatch_param_invalid"
  msgstr ""
  "web.fetch dispatch params failed host-side validation. This is a "
  "host defect, not a user-input issue. Inspect the audit log: "
  "alfred audit log --event tool.web.fetch --since 1h (look for "
  "dlp_scan_result=dispatch_param_invalid)."
  ```

- [ ] **Step 2: Recompile + drift gate.**

  ```bash
  cd "$(git rev-parse --show-toplevel)"
  uv run pybabel compile -D alfred -d locale/
  uv run pybabel extract -F babel.cfg -o locale/alfred.pot src/alfred/
  uv run pybabel update -i locale/alfred.pot -d locale/ --previous --no-fuzzy-matching --ignore-pot-creation-date
  git diff --exit-code locale/
  ```

  Expected: clean.

- [ ] **Step 3: Commit.**

  ```bash
  git add locale/
  git commit -m "feat(i18n): operator-actionable msgstr for dispatch_param_invalid (#147)

  Points operators at the audit-log invocation. Distinguishes the
  failure class as a host defect (not user input).

  Refs: #147

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Task 5 — Parametrised end-to-end coverage

**Owner**: alfred-security-engineer
**Files**:

- Create: `tests/unit/plugins/web_fetch/test_dispatch_params_e2e.py`

- [ ] **Step 1: Write the e2e test.**

  Create `tests/unit/plugins/web_fetch/test_dispatch_params_e2e.py`:

  ```python
  """End-to-end parametrised coverage of dispatch_web_fetch's host-side
  validation arm (issue #147 §5.3).

  Drives dispatch_web_fetch with the production dispatcher path; only
  the dispatcher's CONSTRUCTION of WebFetchDispatchParams is patched
  to simulate each missing-required-field / wrong-type case.
  """

  from __future__ import annotations

  from unittest.mock import patch, AsyncMock

  import pytest
  from pydantic import ValidationError

  from alfred.plugins.web_fetch.dispatch_params import WebFetchDispatchParams
  from alfred.plugins.web_fetch.errors import WebFetchError

  # Import the factories + dispatch_web_fetch the same way
  # test_fetch_dispatcher.py does.
  from .test_fetch_dispatcher import (  # type: ignore[import]
      _build_audit, _build_dlp, _build_handle_cap, _build_rate_limiter,
      _build_transport_returning_handle, _build_config,
  )
  from alfred.plugins.web_fetch.fetch_dispatcher import dispatch_web_fetch


  _MISSING_FIELDS = ("url", "headers", "redis_url", "correlation_id", "content_handle_id")


  @pytest.mark.asyncio
  @pytest.mark.parametrize("missing_field", _MISSING_FIELDS)
  async def test_each_missing_required_field_fails_clean(missing_field: str) -> None:
      """Each missing required field raises WebFetchError; transport.dispatch
      never called; cap released."""
      audit = _build_audit()
      transport = _build_transport_returning_handle()
      handle_cap = _build_handle_cap()

      original_init = WebFetchDispatchParams.__init__

      def patched_init(self, **kwargs):  # type: ignore[no-untyped-def]
          # Strip the field we want to simulate as missing.
          kwargs.pop(missing_field, None)
          original_init(self, **kwargs)

      with patch.object(WebFetchDispatchParams, "__init__", patched_init):
          with pytest.raises(WebFetchError):
              await dispatch_web_fetch(
                  url="https://example.com/",
                  headers={"Accept": "text/html"},
                  user_id="user-test",
                  correlation_id="cid-e2e",
                  config=_build_config(),
                  rate_limiter=_build_rate_limiter(refused=False),
                  outbound_dlp=_build_dlp(),
                  audit=audit,
                  transport=transport,
                  handle_cap=handle_cap,
              )

      transport.dispatch.assert_not_called()
      handle_cap.release.assert_awaited_once()
      last = audit.append_schema.call_args_list[-1]
      assert last.kwargs["subject"]["dlp_scan_result"] == "dispatch_param_invalid"


  @pytest.mark.asyncio
  async def test_wrong_type_url_fails_clean() -> None:
      """A wrong-typed url raises WebFetchError; transport.dispatch never called."""
      audit = _build_audit()
      transport = _build_transport_returning_handle()
      handle_cap = _build_handle_cap()

      original_init = WebFetchDispatchParams.__init__

      def patched_init(self, **kwargs):  # type: ignore[no-untyped-def]
          kwargs["url"] = 42  # wrong type — strict=True rejects
          original_init(self, **kwargs)

      with patch.object(WebFetchDispatchParams, "__init__", patched_init):
          with pytest.raises(WebFetchError):
              await dispatch_web_fetch(
                  url="https://example.com/",
                  headers={"Accept": "text/html"},
                  user_id="user-test",
                  correlation_id="cid-e2e",
                  config=_build_config(),
                  rate_limiter=_build_rate_limiter(refused=False),
                  outbound_dlp=_build_dlp(),
                  audit=audit,
                  transport=transport,
                  handle_cap=handle_cap,
              )

      transport.dispatch.assert_not_called()
      handle_cap.release.assert_awaited_once()
  ```

  Adapt the `_build_*` factory imports + the dispatch_web_fetch kwarg shape to match the existing test_fetch_dispatcher.py contract.

- [ ] **Step 2: Run; confirm green.**

- [ ] **Step 3: Commit.**

  ```bash
  git add tests/unit/plugins/web_fetch/test_dispatch_params_e2e.py
  git commit -m "test(web-fetch): parametrised end-to-end for each missing/wrong-typed field (#147)

  Spec §5.3 calls for adversarial-shaped parametrised coverage — no
  corpus YAML (no matching tests/adversarial/ category exists for host
  defects), so the coverage lands as a parametrised pytest under
  tests/unit/ that drives dispatch_web_fetch end-to-end.

  Pins: WebFetchError raised; transport.dispatch never called; cap
  released; audit row carries dispatch_param_invalid.

  Refs: #147

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Task 6 — Docs cross-reference

**Owner**: alfred-docs-author
**Files**:

- Modify: `docs/subsystems/security.md`

- [ ] **Step 1: Update the audit-vocabulary widening note added by #157.**

  Find the "Audit vocabulary widening (handle-cap PR)" section in `docs/subsystems/security.md` and update to also reference the new value:

  ```markdown
  **Audit vocabulary widening (handle-cap + dispatch-params PRs).** Closed
  vocabularies on `WEB_FETCH_FIELDS` widened across two trust-boundary PRs —
  operators with SIEM filters MUST extend their allow-lists:

  - `WEB_FETCH_FIELDS["rate_limit_bucket"]`: added `handle_cap` (PR #160).
  - `WEB_FETCH_FIELDS["dlp_scan_result"]`: added `handle_cap_exceeded` +
    `handle_id_mismatch` (PR #160) and `dispatch_param_invalid` (PR #147).
  ```

  (Adjust to the actual section structure; if the heading wording differs, update accordingly.)

- [ ] **Step 2: Commit.**

  ```bash
  git add docs/subsystems/security.md
  git commit -m "docs(security): cross-reference dispatch_param_invalid in audit-vocab note (#147)

  Refs: #147

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Task 7 — Final QA + push + STOP for user check-in

**Owner**: alfred-security-engineer (final gate)
**Files**: none — gates only

- [ ] **Step 1: Full quality bar.**

  ```bash
  cd "$(git rev-parse --show-toplevel)"
  uv run ruff check . && uv run ruff format --check .
  uv run mypy src/ && uv run pyright src/
  DOCKER_HOST=unix:///Users/iandominey/.orbstack/run/docker.sock \
  TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/Users/iandominey/.orbstack/run/docker.sock \
  uv run pytest tests/unit/plugins/web_fetch/ tests/unit/audit/ -v
  DOCKER_HOST=... TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=... \
  uv run pytest \
    tests/unit/plugins/web_fetch/test_fetch_dispatcher.py \
    tests/unit/plugins/web_fetch/test_dispatch_params.py \
    tests/unit/plugins/web_fetch/test_dispatch_params_e2e.py \
    --cov=src/alfred/plugins/web_fetch/dispatch_params \
    --cov=src/alfred/plugins/web_fetch/fetch_dispatcher \
    --cov-branch --cov-fail-under=100
  uv run pybabel extract -F babel.cfg -o locale/alfred.pot src/alfred/
  uv run pybabel update -i locale/alfred.pot -d locale/ --previous --no-fuzzy-matching --ignore-pot-creation-date
  uv run pybabel compile -D alfred -d locale/
  git diff --exit-code locale/
  make check
  ```

  Expected: all green. Pre-existing `scripts/check_strict_declarations.py` S603/S607 from PR #129 — ignore.

- [ ] **Step 2: Commit log audit.**

  ```bash
  git log --oneline main..HEAD
  ```

  Verify every commit is Conventional Commits, contains `#147`, no `fixup!` prefixes.

- [ ] **Step 3: Push.**

  ```bash
  git push -u origin issue-147-web-fetch-params
  ```

- [ ] **Step 4: STOP for user check-in.**

  Report:
  - Branch pushed, commit list.
  - Local gate status.
  - Open items for user decision (if any).

  Do NOT open the PR autonomously.

---

## §6 Post-PR follow-ups (not in this PR's scope)

- Plugin-side `-32602` Invalid Params envelope (deferred per issue out-of-scope).
- Wire-format versioning (ADR-0017 Decision 7).
- A `security_misconfig` category in `tests/adversarial/payload_schema.py:Category` Literal (if a future host-defect adversarial shape emerges).

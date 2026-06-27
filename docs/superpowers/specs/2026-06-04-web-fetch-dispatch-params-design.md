# Host-side validation of web.fetch dispatch params — design

**Date:** 2026-06-04
**Author:** Claude Code (on behalf of Ian Dominey)
**Scope:** Issue [#147](https://github.com/alfred-os/AlfredOS/issues/147) — UAT-loop follow-up on PR #146 (PR-S3-5 web.fetch plugin)
**Anchors:** UAT report on PR #146; err-004 contract in `plugins/alfred_web_fetch/web_fetch_plugin.py` module docstring; C2 / arch-002 finding from the 9-reviewer team on PR-S3-5; ADR-0017 (Slice-3 trust-tier completion)

---

## 1. What this is for

The `web.fetch` plugin subprocess crashes by design on a malformed JSON-RPC `params` dict (err-004 contract: "All other exceptions are deliberately uncaught so the subprocess exits with a non-zero code and the host detects the crash via `plugin.lifecycle.crashed`"). That **is** the documented contract.

But subprocess crash should be the **secondary** defence. The **primary** defence is host-side schema validation BEFORE dispatch — a bug in the dispatcher (e.g. forgetting `redis_url` — the actual C2 / arch-002 finding from PR-S3-5) should fail clean with a typed exception, not crash the subprocess.

This PR adds host-side validation. The plugin-side defence stays.

## 2. Architecture

**New module:** `src/alfred/plugins/web_fetch/dispatch_params.py` — single Pydantic v2 `WebFetchDispatchParams` model.

**Integration point:** `dispatch_web_fetch` constructs the model immediately before the `await transport.dispatch("web.fetch", ...)` call, then serialises via `.model_dump()` to keep the wire format unchanged.

```
dispatch_web_fetch
    │
    │ ...existing TLS / DLP / allowlist / host-IP / rate-limit / handle-cap reserve...
    │
    │ try:
    │   params = WebFetchDispatchParams(
    │     url=clean_url,
    │     headers=clean_headers,
    │     redis_url=config.redis_url,
    │     correlation_id=correlation_id,
    │     content_handle_id=handle_id,
    │     skip_tls_verify=config.skip_tls_verify,
    │   )
    │ except ValidationError:
    │   release cap; emit dispatch_param_invalid audit row; raise WebFetchError
    │
    │ await transport.dispatch("web.fetch", params.model_dump())
```

### 2.1 Model definition

```python
from collections.abc import Mapping
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

_DEFAULT_SIZE_LIMIT_BYTES: Final[int] = 5 * 1024 * 1024

class WebFetchDispatchParams(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    url: str
    headers: Mapping[str, str]
    redis_url: str
    correlation_id: str
    content_handle_id: str               # host pre-minted UUID per #157
    skip_tls_verify: bool = False
    size_limit_bytes: int = Field(default=_DEFAULT_SIZE_LIMIT_BYTES, gt=0)
```

**Discipline notes:**

- `extra="forbid"` — extra fields raise. A future dispatcher adding a key without updating the model is a fail-loud regression.
- `strict=True` — no silent type coercion (`"5"` for an int field raises; bool is rejected for an int field).
- `frozen=True` — immutable after construction. The model_dump value is the wire format; nothing mutates it post-validation.
- `Field(..., gt=0)` on `size_limit_bytes` — defence against a zero/negative value reaching the plugin (the plugin's `_clamp_size_limit` is the secondary defence; this catches earlier).

### 2.2 Issue-vs-implementation drift note

The issue body lists the model fields without `content_handle_id`. That field was added by #157 (handle-cap PR) which landed AFTER the issue was filed. We include it as required: `dispatch_web_fetch` cannot proceed without a host pre-minted UUID, so the model must reflect current dispatcher contract. No design call — mechanical follow-on.

### 2.3 Dispatcher placement

The Pydantic construction happens AFTER the handle-cap reserve but BEFORE the transport dispatch. Reasoning:

- If validation fails AFTER reserve, the cap slot must be released. The dispatcher's existing released-flag pattern handles this (`released = True` before the raise).
- If validation fails BEFORE reserve, no cap action needed — but the cap-refusal audit row vocabulary isn't designed for "I never even tried". Placing AFTER reserve mirrors the existing transport_error / handle_id_mismatch arms.

## 3. Errors + audit row

### 3.1 Error type

Reuse `WebFetchError(AlfredError)` — no new exception subclass. The validation failure is operationally a dispatch-shape failure (analogous to `dispatch_shape_error`). Carrying a Pydantic `ValidationError`'s message via `t()` would leak field-name detail to the caller; the typed exception's message is operator-actionable only via the audit row.

### 3.2 Audit row

Uses existing `WEB_FETCH_FIELDS` schema. New closed-set value for `dlp_scan_result`:

- `dlp_scan_result = "dispatch_param_invalid"` (new — added to `DlpScanResult` Literal in `audit_row_schemas.py`).
- `content_handle_id = handle_id` (the pre-minted UUID — useful for forensic correlation; differs from cap-refusal which uses `None`).
- `result = "dispatch_param_invalid"` (matches `dlp_scan_result`; the structural analogue is `dispatch_shape_error` — both T0, both `content_handle_id=present`, both `result=`string-matches-`dlp_scan_result`. `transport_error` differs because that arm's failure is downstream of `transport.dispatch`).
- `rate_limit_bucket = None`.
- `trust_tier_of_trigger = "T0"`, `trust_tier_of_result = "T0"` (no T3 content crossed the boundary — same as `dispatch_shape_error`).

The structlog signal `web_fetch.dispatch.param_validation_failed` carries ONLY `exception_type=type(exc).__name__`; the Pydantic `ValidationError` message is NEVER recorded (neither on the structlog signal nor on the audit row). Type-name-only redaction per spec §5.6 and CLAUDE.md hard rule #7 — Pydantic error messages embed `input_value=...` for failed fields which may carry user-supplied URL/header fragments.

### 3.3 i18n

New catalog entry:

```po
msgid "web.fetch.error.dispatch_param_invalid"
msgstr ""
"web.fetch dispatch params failed host-side validation. This is a host "
"defect, not a user-input issue. Inspect the audit log: "
"alfred audit log --event tool.web.fetch --since 1h (look for "
"dlp_scan_result=dispatch_param_invalid)."
```

Operator-actionable: points at the audit log; clarifies it's not a user-input bug.

## 4. Closed-vocabulary widening

`DlpScanResult` Literal in `audit_row_schemas.py` widens from 14 → 15 values: adds `"dispatch_param_invalid"`. PR #160 already widened the Literal to 14 (adding `"handle_cap_exceeded"` and `"handle_id_mismatch"`); this PR adds the 15th. Discipline matches the handle-cap PR's additions:

- Typed `Literal[...]` catches future emitter typos at type-check time.
- `CHANGELOG.md` introduction still deferred (#157's note); capture in `docs/subsystems/security.md` + cross-reference here.

## 5. Tests

### 5.1 Unit (model)

`tests/unit/plugins/web_fetch/test_dispatch_params.py`:

- `test_valid_construction` — full kwarg set works; serialises round-trip.
- `test_missing_required_<field>` (×5: url, headers, redis_url, correlation_id, content_handle_id) — each raises `ValidationError`.
- `test_wrong_type_url` / `_headers` / `_correlation_id` — `strict=True` rejects type coercion.
- `test_extra_field_forbidden` — `extra="forbid"` rejects.
- `test_size_limit_must_be_positive` — `Field(gt=0)` rejects 0 and negatives.
- `test_skip_tls_verify_strict_bool` — strict rejects truthy non-bool.
- `test_frozen` — assignment after construction raises.
- `test_defaults` — `skip_tls_verify=False`, `size_limit_bytes=5MB`.

### 5.2 Dispatcher integration

Extend `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py`:

- `test_dispatcher_releases_cap_on_param_validation_error` — patch the model construction to raise; verify cap released + audit row + transport.dispatch NOT called.
- `test_dispatcher_param_validation_audit_row_shape` — pin `dlp_scan_result="dispatch_param_invalid"` + `content_handle_id=handle_id` (pre-minted) + `trust_tier_of_result="T0"`.
- `test_dispatcher_param_validation_structlog_emits_typename` — Pydantic error type name surfaces; raw message does NOT (no field-content leak).

### 5.3 Parametrised end-to-end coverage (not a corpus YAML)

The issue body calls for an "adversarial test: parametrised missing-required-field cases". The `tests/adversarial/` corpus categories (`prompt_injection`, `dlp`, `capability_bypass`, `canary`, `inter_persona`, `hooks`, `tier_laundering`, `dlp_egress`) don't include a `security_misconfig` shape — this isn't an adversarial scenario, it's defensive engineering against host-side defects. Implementation: parametrised pytest under `tests/unit/plugins/web_fetch/test_dispatch_params_e2e.py` that drives `dispatch_web_fetch` end-to-end with each missing-required-field variant + each wrong-type variant. Verifies:

- `WebFetchError` raised host-side.
- `transport.dispatch` mock NOT called.
- Cap released (`handle_cap.release` AsyncMock called).
- Audit row emitted with `dlp_scan_result="dispatch_param_invalid"` + `content_handle_id` set to the pre-minted UUID.
- Loud structlog event `web_fetch.dispatch.param_validation_failed` carries Pydantic error type name (NOT raw message).

If a future corpus shape emerges for "host defect surface area", we'd file an adjacent issue to widen the corpus categories. Out of scope here.

## 6. Out of scope

- Plugin-side `-32602` Invalid Params envelope (optional defence-in-depth refinement — out of scope per issue).
- Wire-format versioning (covered by ADR-0017 Decision 7).
- Validation of `headers` value-side (length, individual header semantics) — Pydantic's `dict[str, str]` is sufficient at this layer; per-header DLP scan already runs upstream.
- Validation of `url` shape beyond `str` — `clean_url = outbound_dlp.scan(url)` and the three-way allowlist already validate URL shape. Adding `HttpUrl` here would duplicate.

## 7. Files affected

| File | Status | Responsibility |
| --- | --- | --- |
| `src/alfred/plugins/web_fetch/dispatch_params.py` | Create | `WebFetchDispatchParams` Pydantic v2 model |
| `src/alfred/plugins/web_fetch/fetch_dispatcher.py` | Modify | Construct + validate before `transport.dispatch`; emit audit row on `ValidationError` |
| `src/alfred/audit/audit_row_schemas.py` | Modify | Add `"dispatch_param_invalid"` to `DlpScanResult` Literal |
| `src/alfred/plugins/web_fetch/__init__.py` | Modify | Re-export `WebFetchDispatchParams` if the package re-exports the closed surface |
| `locale/en/LC_MESSAGES/alfred.po` | Modify | New `web.fetch.error.dispatch_param_invalid` msgstr |
| `docs/subsystems/security.md` | Modify | Cross-reference the new audit-vocabulary value |
| `tests/unit/plugins/web_fetch/test_dispatch_params.py` | Create | Model unit tests |
| `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py` | Modify | Dispatcher integration tests |
| `tests/unit/audit/test_audit_row_schemas.py` | Modify | Pin the widened `DlpScanResult` set |
| `tests/unit/plugins/web_fetch/test_dispatch_params_e2e.py` | Create | Parametrised end-to-end coverage of each missing-required-field + wrong-type variant via `dispatch_web_fetch` |

## 8. References

- Issue #147 — UAT-loop follow-up on PR #146.
- PR #146 — PR-S3-5 (`web.fetch` MCP plugin); C2 / arch-002 finding (`redis_url` originally missing).
- err-004 contract — `plugins/alfred_web_fetch/web_fetch_plugin.py` module docstring.
- PRD §7.4 — host-side defence-in-depth invariant.
- ADR-0017 — Slice-3 trust-tier completion.
- `CLAUDE.md` hard rule #7 (no silent failures on security paths) — guides the loud-structlog + audit-row discipline.

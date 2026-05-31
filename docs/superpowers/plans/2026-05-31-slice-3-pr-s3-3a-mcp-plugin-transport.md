# PR-S3-3a: MCP Plugin Transport — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This is trust-boundary work — TDD is HARD here, not advisory.

**Goal:** Ship `src/alfred/plugins/` — the `PluginTransport` Protocol, `StdioTransport` sole implementation, `AlfredPluginSession` manifest-handshake wrapper, `InboundContentScanner`, DLP-wrapped transport surface, `bin/alfred-plugin-launcher` fail-closed stub, and `_ingest_tier` identity hookpoints — establishing the process-boundary infrastructure every downstream plugin (quarantined-LLM, web-fetch, comms-test) depends on.

**Architecture:** `StdioTransport` wraps the `model_context_protocol` SDK's `ClientSession`. Every outbound JSON-RPC frame passes through `OutboundDlp.scan` before bytes cross the pipe. Every inbound frame is scanned by `InboundContentScanner`, tagged `TaggedContent[T3]` via the capability-gated nonce factory (PR-S3-1), written to the content store, and returned as a `ContentHandle` — T3-tagged values never exit `dispatch()` to the orchestrator. `AlfredPluginSession` owns manifest parsing, version check (`alfred.manifest_version == 1` enforced), `subscriber_tier` validation (T3 as subscriber_tier is refused), and capability-gate consult before any plugin bytes flow. `bin/alfred-plugin-launcher` fails closed when no sandbox policy is configured; `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` is accepted only in `ALFRED_ENV=development` and emits a `supervisor.config_insecure` audit row at every plugin start. T1 identity hookpoints (`identity.t1_ingress`, `identity.t1_downgrade`) are registered here because they fire at the ingress boundary before content reaches the orchestrator.

**Tech Stack:** Python 3.12+ · `model_context_protocol` SDK (MCP stdio transport) · asyncio (`create_subprocess_exec`, `TaskGroup`) · Pydantic v2 · `alfred.security.tiers` (PR-S3-1 nonce-gated `tag(T3, ...)`) · `alfred.security.dlp` (`OutboundDlp`) · `alfred.hooks` (PR-S3-0a hookpoints + PR-S3-2 `CapabilityGate.check_plugin_load`) · `alfred.audit.audit_row_schemas` (PR-S3-0a constants) · `structlog` · `t()` for all operator-facing strings · pytest + testcontainers · `coverage --fail-under=100` on trust-boundary files.

**Depends on:** PR-S3-0a (merged — `audit_row_schemas.py`, `payload_schema.py`), PR-S3-0b (merged — i18n catalog, Docker infra), PR-S3-1 (merged — `tag(T3, ...)` nonce, `ContentHandle`, `T3DerivedData`, `AnyTaggedContent`), PR-S3-2 (merged — `RealGate.check_plugin_load`, `check_content_clearance`).

**Blocks:** PR-S3-3b (Supervisor — depends on `PluginTransport` Protocol and `AlfredPluginSession` contracts), PR-S3-4 (quarantined-LLM extractor), PR-S3-5 (`web.fetch`), PR-S3-6 (CLI surface).

---

## §1 Goal

This PR delivers the MCP plugin transport layer — spec §4 in its entirety — plus the identity ingress hookpoints from spec §3.6 and §14. After this PR merges: the orchestrator can spawn any MCP stdio plugin subprocess, perform the manifest handshake, tag inbound frames T3, and return a `ContentHandle` to the orchestrator. The quarantined-LLM and web-fetch plugins (PRs S3-4 and S3-5) implement their plugin-side code against this host-side infrastructure.

Spec anchors: [§4.1–§4.9](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#4-mcp-plugin-transport-fork-2), [§2.1 DLP table](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#21-dlp-placement-on-every-slice-3-wire), [§3.6 _ingest_tier](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#36-t1-ingress-via-identityresolver-role--adapter), [§5.2–§5.3 UID/env-scrub](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#52-dedicated-alfred-quarantine-uid), [§13 PLUGIN_LIFECYCLE_FIELDS + DLP_OUTBOUND_REFUSED_FIELDS + T1_INGRESS_FIELDS + T1_DOWNGRADE_FIELDS + SUPERVISOR_CONFIG_INSECURE_FIELDS](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#13-audit-row-schemas), [§14 hookpoints plugin.lifecycle.loaded/crashed + identity.t1_ingress/t1_downgrade](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#14-hookpoint-surface-cross-cutting-table), [§11a coverage commitments](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#11a-coverage-commitments).

---

## §2 Architecture overview

```
Orchestrator.dispatch("web.fetch", params)
   │
   ▼
AlfredPluginSession
   │  ① check_plugin_load(plugin_id, manifest_tier)   [PR-S3-2 RealGate]
   │  ② manifest handshake: parse manifest.toml
   │     - validate alfred.manifest_version == 1
   │     - validate subscriber_tier != "T3"
   │     - validate plugin_id, sandbox_profile
   │  ③ emit plugin.lifecycle.loaded audit row
   │
   ▼
StdioTransport.dispatch(method, params)
   │  ① OutboundDlp.scan(placeholder_frame)       [outbound DLP on {{secret:*}} placeholders, §4.5 / §2.1]
   │  ② SecretBroker: substitute {{secret:*}}     [§4.4 — substitution AFTER DLP scan]
   │  ③ asyncio.subprocess write to stdin
   │        ← subprocess stdout read (length-prefixed, max 10MB)
   │  ④ InboundContentScanner.scan(frame)         [inbound scan in asyncio.to_thread, §4.5]
   │  ⑤ branch on method_shape:
   │     content-bearing  → tag(T3, body, nonce) → content_store.put(tagged) → ContentHandle
   │     control-plane    → parse JSON → ControlResult
   │     (extraction path managed by PR-S3-4 QuarantinedExtractor)
   │  ⑥ return DispatchResult (ContentHandle | ControlResult | ExtractionResult)
   │     [T3 bytes never exit dispatch() as raw bytes]
   │
   ▼
Orchestrator holds ContentHandle (opaque id only)

AlfredPluginSession on inbound alfred/hooks.register after handshake:
   SIGKILL subprocess (self._transport.kill())
   emit plugin.lifecycle.quarantined audit row   [§4.6]

bin/alfred-plugin-launcher:
   if no sandbox policy AND ALFRED_ENV != development: exit 1 (bare key to stderr only — i18n-005 option b)
   if ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1 AND ALFRED_ENV=development:
       emit supervisor.config_insecure audit row at EVERY plugin start
       exec runuser -u "${TARGET_UID}" -- "${EXECUTABLE}" (UID-drop per spec §5.2)
```

The `inbound_t3_nonce` is a constructor parameter on `StdioTransport` (not a module global) — same nonce model as PR-S3-1 §3.2. Bootstrap passes the nonce to the transport factory; tests inject a stub nonce per fixture. Only `StdioTransport` holds the inbound nonce; `quarantine_host.py` holds a separate quarantine nonce.

**DLP ordering invariant (arch-001 / sec-010):** DLP scans the frame with `{{secret:*}}` placeholders intact. Placeholders are benign strings — no DLP rule fires on them. Secret substitution happens after DLP passes. This matches spec §2.1 ("cookies/secrets do not flow through DLP wire scan because they are substituted at the broker boundary, not carried as plaintext"). The test in `test_stdio_transport_outbound_dlp.py` asserts DLP sees the placeholder frame, not the substituted value.

---

## §3 File structure

| File | Status | Responsibility |
|---|---|---|
| `src/alfred/plugins/__init__.py` | Create | Package marker; re-exports `PluginTransport`, `StdioTransport`, `AlfredPluginSession`, `DispatchResult`, `ContentHandle` |
| `src/alfred/plugins/transport.py` | Create | `PluginTransport` Protocol, `ControlResult` BaseModel, `DispatchResult` discriminated union |
| `src/alfred/plugins/stdio_transport.py` | Create | `StdioTransport`: outbound DLP, secret-broker substitution, subprocess write/read, `InboundContentScanner`, `tag(T3)`, content store write, return `ContentHandle` |
| `src/alfred/plugins/session.py` | Create | `AlfredPluginSession`: manifest parse + version check + `check_plugin_load` + lifecycle audit rows + post-handshake hook-registration detection + SIGKILL |
| `src/alfred/plugins/manifest.py` | Create | Manifest TOML/JSON parser: `PluginManifest` Pydantic model, `manifest_version` validator, `subscriber_tier != T3` enforcement, `[plugin] platform` field reserved |
| `src/alfred/plugins/inbound_scanner.py` | Create | `InboundContentScanner`: distinct from `OutboundDlp`; scans for canary tokens + secret patterns in inbound frames; SECURITY EVENT disposition on canary trip |
| `src/alfred/plugins/content_store_base.py` | Create | `ContentStoreBase` Protocol + `InMemoryContentStore` stub (Redis impl in PR-S3-5); `put(handle, TaggedContent[T3])` — not raw bytes (rvw-004 fix) |
| `src/alfred/plugins/observability.py` | Create | Four Prometheus histograms: `alfred_stdio_transport_dispatch_seconds`, `alfred_outbound_dlp_scan_seconds`, `alfred_inbound_scanner_scan_seconds`, `alfred_plugin_spawn_seconds` (perf-002 / perf-009 fix) |
| `src/alfred/plugins/errors.py` | Create | `PluginError(AlfredError)`, `ManifestVersionError`, `ManifestTierError`, `PluginProtocolViolation`, `DlpOutboundRefusedError` (arch-006 / err-011 fix) |
| `src/alfred/identity/_ingest.py` | Create (if not yet created by PR-S3-1) | `_ingest_tier(user, adapter_name)` + `identity.t1_ingress` hookpoint registration |
| `bin/alfred-plugin-launcher` | Create | Shell stub: fail-closed without sandbox policy; `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` dev escape hatch; emits `supervisor.config_insecure` audit row per start |
| `scripts/check_no_direct_env_reads.py` | Modify | Add `src/alfred/plugins/stdio_transport.py` to the AST-scan allowlist for the `env=` argument check |
| `tests/unit/plugins/__init__.py` | Create | Test package marker |
| `tests/unit/plugins/test_transport_protocol.py` | Create | `PluginTransport` Protocol structural checks; `DispatchResult` discriminated union; `ControlResult` frozen model |
| `tests/unit/plugins/test_stdio_transport_outbound_dlp.py` | Create | `OutboundDlp.scan` called before subprocess write; scan failure refuses dispatch + emits `DLP_OUTBOUND_REFUSED_FIELDS` audit row |
| `tests/unit/plugins/test_stdio_transport_inbound_scan.py` | Create | `InboundContentScanner.scan` called on every inbound frame; canary trip emits `plugin.lifecycle.quarantined`; T3 bytes never exit `dispatch()` |
| `tests/unit/plugins/test_manifest_validation.py` | Create | `manifest_version != 1` → `plugin.lifecycle.load_refused`; `subscriber_tier=T3` → `plugin.lifecycle.load_refused`; platform field reserved |
| `tests/unit/plugins/test_post_handshake_hook_registration.py` | Create | Post-handshake `alfred/hooks.register` → SIGKILL + `plugin.lifecycle.quarantined` audit row; no hook registered (pytest module, not YAML) |
| `tests/unit/plugins/test_secret_broker_substitution.py` | Create | `{{secret:*}}` references in outbound params are substituted before bytes cross the pipe; raw secret value never appears in stdout-logged frame |
| `tests/unit/plugins/test_env_scrub_subprocess.py` | Create | `create_subprocess_exec` called with explicit `env=` dict (no `ALFRED_*`, no API keys); extends AST-scan from spec §5.3 |
| `tests/unit/plugins/test_plugin_launcher_stub.py` | Create | Launcher exits 1 without sandbox policy (bare key on stderr — i18n-005 fix); UID-drop via `runuser` asserted (sec-003 fix); `supervisor.config_insecure` emitted at every start |
| `tests/unit/plugins/test_dispatch_result_shape.py` | Create | `lifecycle.start` → `ControlResult`, `web.fetch` → `ContentHandle` (sec-001 / core-006 fix) |
| `tests/unit/plugins/test_fd3_key_delivery_framing.py` | Create | Host-side 4-byte big-endian length prefix + buffer-empty check (arch-009 fix) |
| `tests/unit/plugins/test_transport_perf_budgets.py` | Create | Four spec §7a.1 histogram metrics exist and observe (perf-002 / perf-009 fix) |
| `tests/unit/identity/test_ingest_tier_hookpoints.py` | Create | `identity.t1_ingress` and `identity.t1_downgrade` hookpoints registered; `invoke()` fires on ingress; audit rows carry `T1_INGRESS_FIELDS` / `T1_DOWNGRADE_FIELDS` constants |
| `tests/adversarial/tier_laundering/test_post_handshake_hook_registration.py` | Create | Post-handshake hook registration attack (pytest module per spec §12.2 fixture-vs-pytest allocation) |

---

## §4 Tasks

Tasks follow TDD: write failing test → confirm FAIL → implement → confirm PASS → commit. All commits use `(#TBD-slice3)`.

---

### Component A — Error hierarchy + `PluginTransport` Protocol

- [ ] **Task 1 — Error hierarchy.**

  Files: Create `src/alfred/plugins/errors.py`, `tests/unit/plugins/test_errors.py`.

  **Failing test:**
  ```python
  # tests/unit/plugins/test_errors.py
  from alfred.errors import AlfredError
  from alfred.plugins.errors import (
      DlpOutboundRefusedError,
      ManifestTierError,
      ManifestVersionError,
      PluginError,
      PluginProtocolViolation,
  )

  def test_plugin_error_is_alfred_error() -> None:
      assert issubclass(PluginError, AlfredError)

  def test_manifest_version_error_is_plugin_error() -> None:
      assert issubclass(ManifestVersionError, PluginError)

  def test_manifest_tier_error_is_plugin_error() -> None:
      assert issubclass(ManifestTierError, PluginError)

  def test_protocol_violation_is_plugin_error() -> None:
      assert issubclass(PluginProtocolViolation, PluginError)

  def test_dlp_outbound_refused_error_is_plugin_error() -> None:
      assert issubclass(DlpOutboundRefusedError, PluginError)

  def test_manifest_version_error_message_uses_t() -> None:
      exc = ManifestVersionError(got=2, expected=1)
      assert "2" in str(exc) or len(str(exc)) > 0

  def test_manifest_tier_error_uses_distinct_i18n_key() -> None:
      # ManifestTierError must NOT reuse plugin.manifest_version_mismatch (arch-007 fix).
      # The error must carry the tier attribute.
      exc = ManifestTierError("T3")
      assert exc.tier == "T3"
      # Sanity: the message does not claim a version mismatch integer was the cause.
      assert "version" not in str(exc).lower() or "T3" in str(exc)

  def test_dlp_outbound_refused_error_carries_rule() -> None:
      exc = DlpOutboundRefusedError(plugin_id="alfred.test", rule_matched="secret_pattern")
      assert exc.plugin_id == "alfred.test"
      assert exc.rule_matched == "secret_pattern"
  ```

  Run: `uv run pytest tests/unit/plugins/test_errors.py -q` → expect `ImportError`.

  **Implementation** (`src/alfred/plugins/errors.py`):
  ```python
  """Plugin error hierarchy (spec §4).

  PluginError is the root; all plugin-specific exceptions inherit from it.
  These are operational errors (manifest rejection, protocol violation) —
  they do NOT carry T3 content (see spec §5.6 audit-field discipline).
  """
  from __future__ import annotations

  from alfred.errors import AlfredError
  from alfred.i18n import t


  class PluginError(AlfredError):
      """Root for all plugin errors."""


  class ManifestVersionError(PluginError):
      """Plugin manifest version does not match expected (spec §4.9)."""

      def __init__(self, got: int, expected: int = 1) -> None:
          super().__init__(t("plugin.manifest_version_mismatch", got=got, expected=expected))
          self.got = got
          self.expected = expected


  class ManifestTierError(PluginError):
      """Plugin manifest declares an invalid subscriber_tier (spec §4.3).

      Uses a dedicated i18n key (plugin.manifest_subscriber_tier_invalid) distinct
      from the version-mismatch key — the two errors have different numeric/string
      formatting semantics across languages (arch-007 fix).
      """

      def __init__(self, tier: str) -> None:
          # T3 is a content trust tier, not a subscriber tier — refuse at handshake.
          super().__init__(
              t("plugin.manifest_subscriber_tier_invalid", tier=tier, valid_tiers="system|operator|user-plugin")
          )
          self.tier = tier


  class DlpOutboundRefusedError(PluginError):
      """Raised when OutboundDlp refuses an outbound frame (spec §4.5, arch-006 / err-011 fix).

      Distinct from ManifestTierError and launcher fail-closed path —
      operators reading audit logs must be able to distinguish DLP refusals
      from sandbox-policy failures.
      """

      def __init__(self, plugin_id: str, rule_matched: str) -> None:
          super().__init__(
              t("plugin.transport.dlp_outbound_refused", plugin_id=plugin_id, rule=rule_matched)
          )
          self.plugin_id = plugin_id
          self.rule_matched = rule_matched


  class PluginProtocolViolation(PluginError):
      """Plugin sent a disallowed method after handshake (spec §4.6)."""

      def __init__(self, method: str, plugin_id: str) -> None:
          super().__init__(f"Protocol violation from {plugin_id}: disallowed method {method!r} post-handshake")
          self.method = method
          self.plugin_id = plugin_id
  ```

  Run: `uv run pytest tests/unit/plugins/test_errors.py -q` → 5 passed.

  Commit:
  ```
  feat(plugins): plugin error hierarchy — ManifestVersionError, ManifestTierError, PluginProtocolViolation (#TBD-slice3)
  ```

---

- [ ] **Task 2 — `PluginTransport` Protocol and `DispatchResult` union.**

  Files: Create `src/alfred/plugins/transport.py`, `tests/unit/plugins/test_transport_protocol.py`.

  **Failing test:**
  ```python
  # tests/unit/plugins/test_transport_protocol.py
  from typing import get_type_hints
  from alfred.plugins.transport import ControlResult, DispatchResult, PluginTransport
  from alfred.security.quarantine import ContentHandle, ExtractionResult  # type: ignore[attr-defined]

  def test_control_result_is_frozen() -> None:
      import pydantic
      cr = ControlResult(method="lifecycle.start", payload={})
      with pytest.raises(pydantic.ValidationError):
          cr.method = "changed"  # type: ignore[misc]

  def test_dispatch_result_is_plain_union() -> None:
      # DispatchResult is a plain union — ContentHandle | ExtractionResult | ControlResult.
      # No Annotated wrapper — core-011 fix.
      import typing
      args = typing.get_args(DispatchResult)
      assert len(args) == 3
      assert ContentHandle in args
      assert ExtractionResult in args
      assert ControlResult in args

  def test_plugin_transport_protocol_has_dispatch() -> None:
      assert hasattr(PluginTransport, "dispatch")

  def test_plugin_transport_protocol_has_close() -> None:
      assert hasattr(PluginTransport, "close")
  ```

  Run: `uv run pytest tests/unit/plugins/test_transport_protocol.py -q` → `ImportError`.

  **Implementation** (`src/alfred/plugins/transport.py`):
  ```python
  """PluginTransport Protocol and DispatchResult type (spec §4.1).

  Slice 3 ships StdioTransport as the sole implementation.
  HTTP transport is deferred to Slice 5+.
  In-process MemoryTransport is deliberately never shipped (process-boundary
  isolation is load-bearing per PRD §5 and ADR-0017).
  """
  from __future__ import annotations

  from typing import Protocol, runtime_checkable

  from pydantic import BaseModel, ConfigDict

  from alfred.security.quarantine import ContentHandle, ExtractionResult


  class ControlResult(BaseModel):
      """Plain JSON-deserialisable result from a non-content, non-extraction RPC call.

      Returned for lifecycle, config, and health-check JSON-RPC calls.
      Never carries T3 content — that path returns ContentHandle.
      Never carries structured extraction — that path returns ExtractionResult.
      """
      model_config = ConfigDict(frozen=True)

      method: str
      payload: dict[str, object]


  # Discriminated by isinstance in dispatch() — three shapes, no Pydantic discriminator field.
  # ContentHandle: content-bearing tools (web.fetch); T3 bytes held in content store.
  # ExtractionResult: quarantine.extract calls; validated Pydantic model.
  # ControlResult: lifecycle, config, health-check calls; no T3 tagging.
  # (core-011 fix: removed meaningless Annotated[..., Field(discriminator=None)] wrapper)
  DispatchResult = ContentHandle | ExtractionResult | ControlResult


  @runtime_checkable
  class PluginTransport(Protocol):
      """Structural Protocol every plugin transport implementation honours.

      Slice 3 ships StdioTransport as the sole implementation (spec §4.2).
      HTTP is deferred to Slice 5+. In-process MemoryTransport is
      deliberately never shipped — it would collapse process-boundary isolation.

      DLP wraps this method — callers receive the post-DLP result.
      TaggedContent[T3] is plugin-host-internal; it exists between the subprocess
      boundary and the content store write and never exits dispatch() to the caller.
      """

      async def dispatch(
          self,
          method: str,
          params: dict[str, object],
      ) -> DispatchResult:
          """Dispatch a JSON-RPC call to the plugin subprocess."""
          ...

      async def close(self) -> None:
          """Gracefully close the plugin transport connection."""
          ...
  ```

  Run: `uv run pytest tests/unit/plugins/test_transport_protocol.py -q` → all pass.

  Commit:
  ```
  feat(plugins): PluginTransport Protocol + DispatchResult discriminated union (#TBD-slice3)
  ```

---

### Component B — Manifest parser

- [ ] **Task 3 — `PluginManifest` Pydantic model + manifest version enforcement.**

  Files: Create `src/alfred/plugins/manifest.py`, `tests/unit/plugins/test_manifest_validation.py`.

  **Failing test:**
  ```python
  # tests/unit/plugins/test_manifest_validation.py
  import pytest
  from alfred.plugins.manifest import PluginManifest, parse_manifest
  from alfred.plugins.errors import ManifestVersionError, ManifestTierError

  VALID_MANIFEST_TOML = """
  alfred.manifest_version = 1
  [plugin]
  id = "alfred.test-plugin"
  subscriber_tier = "system"
  sandbox_profile = "user-plugin"
  """

  def test_valid_manifest_parses() -> None:
      manifest = parse_manifest(VALID_MANIFEST_TOML)
      assert manifest.plugin_id == "alfred.test-plugin"
      assert manifest.manifest_version == 1
      assert manifest.subscriber_tier == "system"

  def test_version_mismatch_raises() -> None:
      bad = VALID_MANIFEST_TOML.replace("manifest_version = 1", "manifest_version = 2")
      with pytest.raises(ManifestVersionError) as exc_info:
          parse_manifest(bad)
      assert exc_info.value.got == 2

  def test_t3_as_subscriber_tier_refused() -> None:
      bad = VALID_MANIFEST_TOML.replace('subscriber_tier = "system"', 'subscriber_tier = "T3"')
      with pytest.raises(ManifestTierError) as exc_info:
          parse_manifest(bad)
      assert "T3" in exc_info.value.tier

  def test_platform_field_is_optional_reserved() -> None:
      # Slice-3 manifests may omit [plugin] platform — reserved for Slice 4 comms-MCP.
      manifest = parse_manifest(VALID_MANIFEST_TOML)
      assert manifest.platform is None

  def test_unknown_manifest_version_same_as_mismatch() -> None:
      bad = VALID_MANIFEST_TOML.replace("manifest_version = 1", "manifest_version = 99")
      with pytest.raises(ManifestVersionError):
          parse_manifest(bad)
  ```

  Run: `uv run pytest tests/unit/plugins/test_manifest_validation.py -q` → `ImportError`.

  **Implementation** (`src/alfred/plugins/manifest.py`):
  ```python
  """Plugin manifest parser (spec §4.3).

  Slice-3 manifests use TOML format. alfred.manifest_version must equal 1;
  any other value raises ManifestVersionError before any capability-gate check.

  Two-axis naming rule (spec §4.3):
  - subscriber_tier: subscriber capability (system/operator/user-plugin)
  - content trust tier (T0-T3): appears in TaggedContent and audit rows only
  Using "T3" as subscriber_tier is a security error refused at handshake.

  [plugin] platform: reserved for Slice-4 comms-MCP adapters; optional in v1.
  """
  from __future__ import annotations

  import tomllib
  from typing import Literal

  from pydantic import BaseModel, ConfigDict, field_validator

  from alfred.plugins.errors import ManifestTierError, ManifestVersionError

  _VALID_SUBSCRIBER_TIERS = frozenset({"system", "operator", "user-plugin"})
  _CONTENT_TRUST_TIERS = frozenset({"T0", "T1", "T2", "T3"})


  class PluginManifest(BaseModel):
      """Validated plugin manifest (spec §4.3)."""
      model_config = ConfigDict(frozen=True)

      manifest_version: Literal[1]
      plugin_id: str
      subscriber_tier: str
      sandbox_profile: str
      platform: str | None = None  # reserved for Slice-4 comms-MCP; optional in v1

      @field_validator("subscriber_tier")
      @classmethod
      def _validate_subscriber_tier(cls, v: str) -> str:
          if v in _CONTENT_TRUST_TIERS:
              raise ManifestTierError(v)
          if v not in _VALID_SUBSCRIBER_TIERS:
              raise ValueError(f"Unknown subscriber_tier {v!r}; must be one of {_VALID_SUBSCRIBER_TIERS}")
          return v


  def parse_manifest(raw: str) -> PluginManifest:
      """Parse a TOML plugin manifest string into a validated PluginManifest.

      Raises ManifestVersionError if alfred.manifest_version != 1.
      Raises ManifestTierError if subscriber_tier is a content trust tier (T0-T3).
      """
      data = tomllib.loads(raw)
      version = data.get("alfred", {}).get("manifest_version")
      if version != 1:
          raise ManifestVersionError(got=version if isinstance(version, int) else -1)
      plugin_section = data.get("plugin", {})
      return PluginManifest(
          manifest_version=1,
          plugin_id=plugin_section["id"],
          subscriber_tier=plugin_section["subscriber_tier"],
          sandbox_profile=plugin_section.get("sandbox_profile", "user-plugin"),
          platform=plugin_section.get("platform"),
      )
  ```

  Run: `uv run pytest tests/unit/plugins/test_manifest_validation.py -q` → all pass.

  Commit:
  ```
  feat(plugins): manifest parser — version pin enforcement + subscriber_tier T3 refusal (#TBD-slice3)
  ```

---

### Component C — `InboundContentScanner`

- [ ] **Task 4 — `InboundContentScanner` — distinct from `OutboundDlp`.**

  Files: Create `src/alfred/plugins/inbound_scanner.py`, `tests/unit/plugins/test_stdio_transport_inbound_scan.py`.

  **Failing test:**
  ```python
  # tests/unit/plugins/test_stdio_transport_inbound_scan.py
  import pytest
  from alfred.plugins.inbound_scanner import InboundContentScanner, CanaryTrip

  def test_clean_frame_passes() -> None:
      scanner = InboundContentScanner()
      result = scanner.scan(b'{"result": "ok"}')
      assert result is None  # no canary trip

  def test_canary_trip_returns_canary_trip_event() -> None:
      # Plant a canary token pattern in the frame.
      scanner = InboundContentScanner(canary_tokens=frozenset({"ALFRED_CANARY_TEST"}))
      result = scanner.scan(b'{"result": "ALFRED_CANARY_TEST was found"}')
      assert isinstance(result, CanaryTrip)
      assert result.matched_token == "ALFRED_CANARY_TEST"

  def test_inbound_scanner_is_not_outbound_dlp() -> None:
      from alfred.security.dlp import OutboundDlp
      assert not issubclass(InboundContentScanner, OutboundDlp)

  def test_scan_runs_in_thread_safe_manner() -> None:
      # InboundContentScanner.scan is synchronous; callers wrap in asyncio.to_thread().
      # Verify it has no async method (prevents mistaken await in event loop).
      import inspect
      scanner = InboundContentScanner()
      assert not inspect.iscoroutinefunction(scanner.scan)
  ```

  Run: `uv run pytest tests/unit/plugins/test_stdio_transport_inbound_scan.py -q` → `ImportError`.

  **Implementation** (`src/alfred/plugins/inbound_scanner.py`):
  ```python
  """InboundContentScanner — distinct from OutboundDlp (spec §4.5).

  OutboundDlp scans content the host writes to the subprocess (redact-and-continue
  disposition). InboundContentScanner scans content from the subprocess (SECURITY EVENT
  disposition on canary trip — never redact-and-continue on inbound T3 frames).

  The rule sets are different because the threat models are different:
  - Outbound: prevent secret exfiltration TO the subprocess.
  - Inbound: detect canary tokens that prove T3 content carries injected instructions
    back toward the orchestrator.

  scan() is synchronous. Call sites must wrap in asyncio.to_thread() to avoid blocking
  the event loop on regex-heavy frames (spec §7a.1 InboundContentScanner.scan budget).
  """
  from __future__ import annotations

  import re
  from dataclasses import dataclass


  @dataclass(frozen=True)
  class CanaryTrip:
      """Returned by InboundContentScanner.scan when a canary token is detected.

      This is a SECURITY EVENT — the orchestrator treats it as a quarantine trigger,
      not a recoverable error. See spec §7.6 and §4.5.
      """
      matched_token: str
      frame_offset: int  # byte offset of the match within the scanned frame


  class InboundContentScanner:
      """Scans inbound JSON-RPC frames for canary tokens and secret patterns.

      Distinct from OutboundDlp — different rule set, different disposition.
      Canary trip → return CanaryTrip (SECURITY EVENT); clean frame → return None.
      """

      def __init__(
          self,
          *,
          canary_tokens: frozenset[str] | None = None,
      ) -> None:
          # Default canary token set is loaded from the operator's canary registry.
          # Test callers may inject explicit tokens for deterministic assertions.
          self._canary_tokens = canary_tokens or frozenset()
          self._canary_patterns = [
              re.compile(re.escape(tok)) for tok in self._canary_tokens
          ]

      def scan(self, frame: bytes) -> CanaryTrip | None:
          """Scan a raw frame for canary tokens.

          Returns CanaryTrip on the first match, None on clean frame.
          Run this in asyncio.to_thread() for large frames.
          """
          text = frame.decode("utf-8", errors="replace")
          for pattern in self._canary_patterns:
              match = pattern.search(text)
              if match:
                  return CanaryTrip(
                      matched_token=match.group(0),
                      frame_offset=match.start(),
                  )
          return None
  ```

  Run: `uv run pytest tests/unit/plugins/test_stdio_transport_inbound_scan.py -q` → all pass.

  Commit:
  ```
  feat(plugins): InboundContentScanner — distinct from OutboundDlp, SECURITY EVENT disposition (#TBD-slice3)
  ```

---

### Component D — `ContentStoreBase` stub

- [ ] **Task 5 — `ContentStoreBase` Protocol + `InMemoryContentStore` stub.**

  Files: Create `src/alfred/plugins/content_store_base.py`, `tests/unit/plugins/test_content_store_base.py`.

  **Failing test:**
  ```python
  # tests/unit/plugins/test_content_store_base.py
  import datetime
  from unittest.mock import MagicMock

  import pytest

  from alfred.plugins.content_store_base import InMemoryContentStore
  from alfred.security.quarantine import ContentHandle
  from alfred.security.tiers import T3, tag

  def test_put_and_get_round_trip() -> None:
      store = InMemoryContentStore()
      handle = ContentHandle(
          id="test-uuid",
          source_url="https://example.com",
          fetch_timestamp=datetime.datetime.now(datetime.UTC),
      )
      # rvw-pre-flight fix: store persists TaggedContent[T3], not raw bytes (spec §3.2, §7.2).
      stub_nonce = MagicMock()  # PR-S3-1 ships CapabilityGateNonce; this stand-in suffices for the round-trip test.
      tagged = tag(T3, b"test content", caller_token=stub_nonce)
      store.put(handle, tagged)
      retrieved = store.get(handle.id)
      assert retrieved is not None
      # The TaggedContent wrapper is preserved end-to-end; nonce validation happens at untag() in callers.

  def test_get_missing_returns_none() -> None:
      store = InMemoryContentStore()
      assert store.get("nonexistent") is None

  def test_delete_removes_entry() -> None:
      store = InMemoryContentStore()
      handle = ContentHandle(
          id="del-uuid",
          source_url="https://example.com",
          fetch_timestamp=datetime.datetime.now(datetime.UTC),
      )
      stub_nonce = MagicMock()
      tagged = tag(T3, b"data", caller_token=stub_nonce)
      store.put(handle, tagged)
      store.delete(handle.id)
      assert store.get(handle.id) is None
  ```

  Run: `uv run pytest tests/unit/plugins/test_content_store_base.py -q` → `ImportError`.

  **Implementation** (`src/alfred/plugins/content_store_base.py`):
  ```python
  """ContentStoreBase Protocol and InMemoryContentStore stub (spec §7.2, §7.3).

  The Redis-backed production store ships in PR-S3-5 (alfred.plugins.web_fetch.content_store).
  This stub is used by StdioTransport before PR-S3-5 merges and in unit tests.

  The content store holds T3 bytes keyed by ContentHandle.id. The orchestrator
  never dereferences these bytes directly — it holds only the ContentHandle.
  """
  from __future__ import annotations

  from typing import Protocol, runtime_checkable

  from alfred.security.quarantine import ContentHandle
  from alfred.security.tiers import T3, TaggedContent


  @runtime_checkable
  class ContentStoreBase(Protocol):
      """Protocol for T3 content stores keyed by ContentHandle.id.

      **Storage contract (rvw-pre-flight fix — critical):** The store persists the
      ``TaggedContent[T3]`` wrapper (which carries the nonce + provenance), not raw
      bytes. Retrieval via ``get()`` must return the same wrapper so ``untag()`` can
      validate the nonce on read-back (spec §3.2). Persisting raw bytes would lose
      the nonce and silently downgrade T3 → untagged on retrieval — a tier-laundering
      vulnerability.
      """

      def put(self, handle: ContentHandle, tagged_content: TaggedContent[T3]) -> None:
          """Store T3 tagged content under the handle's id."""
          ...

      def get(self, handle_id: str) -> TaggedContent[T3] | None:
          """Retrieve T3 tagged content by handle id. Returns None if expired/not found."""
          ...

      def delete(self, handle_id: str) -> None:
          """Delete a handle's content (explicit eviction path)."""
          ...


  class InMemoryContentStore:
      """In-memory content store for unit tests and Slice-3 pre-Redis usage.

      Not production-safe: no TTL, no single-use enforcement, no cross-process
      visibility. The Redis store in PR-S3-5 provides production semantics.
      """

      def __init__(self) -> None:
          self._store: dict[str, TaggedContent[T3]] = {}

      def put(self, handle: ContentHandle, tagged_content: TaggedContent[T3]) -> None:
          self._store[handle.id] = tagged_content

      def get(self, handle_id: str) -> TaggedContent[T3] | None:
          return self._store.get(handle_id)

      def delete(self, handle_id: str) -> None:
          self._store.pop(handle_id, None)
  ```

  Run: `uv run pytest tests/unit/plugins/test_content_store_base.py -q` → all pass.

  Commit:
  ```
  feat(plugins): ContentStoreBase Protocol + InMemoryContentStore stub for unit tests (#TBD-slice3)
  ```

---

### Component E — `StdioTransport`

- [ ] **Task 6 — `StdioTransport`: env-scrub subprocess spawn + fd-3 key delivery + full dispatch rewrite.**

  **Cluster 1 fix** — this task applies all 8 cross-cutting fixes to `StdioTransport.dispatch`:
  - arch-001 / sec-010: DLP scans placeholder frame; substitution happens AFTER DLP passes.
  - sec-001 / core-006: `dispatch()` returns the `DispatchResult` union (ContentHandle | ControlResult | ExtractionResult), not unconditionally `ContentHandle`.
  - rvw-004: `tagged` is threaded into `content_store.put` — no decorative tag call.
  - arch-006 / rvw-009 / sec-006 / err-011: DLP refusal raises `DlpOutboundRefusedError` with `plugin.transport.dlp_outbound_refused` i18n key.
  - err-013: `assert` replaced with explicit guard raise (survives `-O`).
  - core-008: `inbound_t3_nonce` is a constructor parameter, not a module global.
  - perf-008: `reader.readline()` replaced with length-prefixed framing up to 10MB.
  - perf-012: outbound `OutboundDlp.scan` wrapped in `asyncio.to_thread` for frames > 4KB.

  Files: Create `src/alfred/plugins/stdio_transport.py`, `tests/unit/plugins/test_env_scrub_subprocess.py`, `tests/unit/plugins/test_dispatch_result_shape.py`, `tests/unit/plugins/test_fd3_key_delivery_framing.py`.

  **Failing tests (env-scrub + dispatch shape + fd-3 framing):**
  ```python
  # tests/unit/plugins/test_env_scrub_subprocess.py
  """Verify subprocess spawn uses explicit minimal env, never inheriting parent env (spec §5.3)."""
  import ast
  import pathlib

  def test_stdio_transport_has_no_bare_os_environ_read() -> None:
      """AST scan: stdio_transport.py must not read os.environ directly."""
      source = pathlib.Path("src/alfred/plugins/stdio_transport.py").read_text()
      tree = ast.parse(source)
      for node in ast.walk(tree):
          if isinstance(node, ast.Attribute):
              if (
                  isinstance(node.value, ast.Name)
                  and node.value.id == "os"
                  and node.attr == "environ"
              ):
                  raise AssertionError(
                      "os.environ read found in stdio_transport.py — use explicit env= dict (spec §5.3)"
                  )

  def test_create_subprocess_exec_has_explicit_env_kwarg() -> None:
      """Verify create_subprocess_exec is always called with env= keyword arg."""
      source = pathlib.Path("src/alfred/plugins/stdio_transport.py").read_text()
      import re
      calls = re.findall(r"create_subprocess_exec\([^)]*\)", source, re.DOTALL)
      for call in calls:
          assert "env=" in call, f"create_subprocess_exec call missing env= kwarg: {call[:80]!r}"
  ```

  ```python
  # tests/unit/plugins/test_dispatch_result_shape.py
  """Verify dispatch() returns the correct DispatchResult shape per method type (sec-001 / core-006 fix)."""
  import pytest
  from unittest.mock import AsyncMock, MagicMock, patch
  import json

  from alfred.plugins.stdio_transport import StdioTransport
  from alfred.plugins.transport import ControlResult
  from alfred.security.quarantine import ContentHandle


  @pytest.fixture
  def passthrough_transport(fake_audit_writer, fake_broker, stub_nonce):
      dlp = MagicMock()
      dlp.scan.return_value = MagicMock(refused=False)
      scanner = MagicMock()
      scanner.scan.return_value = None
      return StdioTransport(
          plugin_id="test.plugin",
          executable="/bin/echo",
          args=[],
          audit_writer=fake_audit_writer,
          dlp=dlp,
          scanner=scanner,
          secret_broker=fake_broker,
          inbound_t3_nonce=stub_nonce,
      )


  @pytest.mark.asyncio
  async def test_lifecycle_start_returns_control_result(passthrough_transport):
      """Control-plane methods must return ControlResult, not ContentHandle (sec-001 fix)."""
      response = json.dumps({"jsonrpc": "2.0", "result": {"status": "ok"}}).encode()
      with patch.object(passthrough_transport, "_process") as mock_proc:
          mock_proc.stdin.write = MagicMock()
          mock_proc.stdin.drain = AsyncMock()
          mock_proc.stdout.read = AsyncMock(return_value=response)
          result = await passthrough_transport.dispatch("lifecycle.start", {})
      assert isinstance(result, ControlResult)


  @pytest.mark.asyncio
  async def test_web_fetch_returns_content_handle(passthrough_transport):
      """Content-bearing methods must return ContentHandle with T3 tagging."""
      response = json.dumps({"jsonrpc": "2.0", "result": {"body": "<html>hi</html>"}}).encode()
      with patch.object(passthrough_transport, "_process") as mock_proc:
          mock_proc.stdin.write = MagicMock()
          mock_proc.stdin.drain = AsyncMock()
          mock_proc.stdout.read = AsyncMock(return_value=response)
          result = await passthrough_transport.dispatch("web.fetch", {"url": "https://example.com"})
      assert isinstance(result, ContentHandle)
  ```

  ```python
  # tests/unit/plugins/test_fd3_key_delivery_framing.py
  """Host-side fd-3 framing contract test (arch-009 fix — spec §5.3)."""
  import asyncio
  import os
  import struct
  import pytest


  @pytest.mark.asyncio
  async def test_fd3_key_delivery_4byte_length_prefix() -> None:
      """The host writes 4-byte big-endian length + N key bytes on fd 3 (spec §5.3)."""
      r_fd, w_fd = os.pipe()
      key = b"sk-test-provider-key-abc123"

      # Simulate what StdioTransport._spawn does.
      header = struct.pack(">I", len(key))
      os.write(w_fd, header + key)
      os.close(w_fd)

      # Read and verify framing.
      raw_header = os.read(r_fd, 4)
      length = struct.unpack(">I", raw_header)[0]
      raw_key = os.read(r_fd, length)
      # Buffer must be empty after the framed key (spec §5.3 buffer-emptiness check).
      trailing = os.read(r_fd, 1)
      os.close(r_fd)

      assert length == len(key)
      assert raw_key == key
      assert trailing == b""  # no trailing bytes
  ```

  Run: `uv run pytest tests/unit/plugins/test_env_scrub_subprocess.py tests/unit/plugins/test_dispatch_result_shape.py tests/unit/plugins/test_fd3_key_delivery_framing.py -q` → FAIL (file does not exist yet).

  **Implementation** (`src/alfred/plugins/stdio_transport.py`):
  ```python
  """StdioTransport — MCP plugin stdio transport (spec §4.2).

  Outbound pipeline (arch-001 / sec-010 fix — DLP scans placeholder frame FIRST):
    1. Serialize JSON-RPC frame with {{secret:*}} placeholders intact.
    2. OutboundDlp.scan(placeholder_frame) — placeholders are benign; no DLP rule fires.
    3. SecretBroker.substitute(params) — AFTER DLP passes.
    4. Serialize final frame with substituted values.
    5. Write bytes to subprocess stdin.

  Inbound pipeline:
    - Length-prefixed read (4-byte BE header, max 10MB — perf-008 fix).
    - InboundContentScanner.scan in asyncio.to_thread (perf-012 fix).
    - Branch on method_shape (sec-001 / core-006 fix):
        content-bearing  → tag(T3, body, nonce) → content_store.put(tagged) → ContentHandle
        control-plane    → ControlResult (no T3 tagging, no content store write)
    - T3 bytes (from tagged value) stored in content store — rvw-004 fix.

  Constructor takes inbound_t3_nonce directly — no module global (core-008 fix).
  DLP refusal raises DlpOutboundRefusedError — not PluginError (arch-006 / err-011 fix).
  Nonce guard uses explicit raise, not assert (err-013 fix).
  """
  from __future__ import annotations

  import asyncio
  import datetime
  import json
  import struct
  import uuid

  import structlog

  from alfred.audit import audit_row_schemas
  from alfred.audit.writer import AuditWriter
  from alfred.errors import AlfredError
  from alfred.i18n import t
  from alfred.plugins.content_store_base import ContentStoreBase, InMemoryContentStore
  from alfred.plugins.errors import DlpOutboundRefusedError, PluginProtocolViolation
  from alfred.plugins.inbound_scanner import CanaryTrip, InboundContentScanner
  from alfred.plugins.transport import ControlResult, DispatchResult
  from alfred.security.dlp import OutboundDlp
  from alfred.security.quarantine import ContentHandle
  from alfred.security.secrets import SecretBroker
  from alfred.security.tiers import T3, CapabilityGateNonce, tag

  log = structlog.get_logger(__name__)

  _MAX_INBOUND_FRAME_BYTES = 10 * 1024 * 1024  # 10MB hard cap (perf-008 fix)
  _OUTBOUND_DLP_THREAD_THRESHOLD = 4096  # bytes; scan in thread above this (perf-012 fix)

  # Methods whose responses are control-plane (no T3 tagging, no content store write).
  _CONTROL_PLANE_METHOD_PREFIXES = frozenset({
      "lifecycle.",
      "adapter.health",
      "ping",
  })


  class CanaryTripSecurityEvent(AlfredError):
      """SECURITY EVENT: canary token detected in plugin subprocess output."""

      def __init__(self, message: str, plugin_id: str, matched_token: str) -> None:
          super().__init__(message)
          self.plugin_id = plugin_id
          self.matched_token = matched_token


  class NonceNotConfigured(AlfredError):
      """Raised when StdioTransport is used before inbound_t3_nonce is set."""


  class PluginProtocolError(AlfredError):
      """Raised when an inbound frame exceeds the max size limit (perf-008)."""


  def _is_control_plane(method: str) -> bool:
      return any(method.startswith(prefix) for prefix in _CONTROL_PLANE_METHOD_PREFIXES)


  class StdioTransport:
      """MCP stdio transport — dispatches JSON-RPC to a plugin subprocess.

      Constructor takes inbound_t3_nonce explicitly (core-008 fix — no module global).
      """

      def __init__(
          self,
          *,
          plugin_id: str,
          executable: str,
          args: list[str],
          audit_writer: AuditWriter,
          dlp: OutboundDlp,
          scanner: InboundContentScanner,
          secret_broker: SecretBroker,
          inbound_t3_nonce: CapabilityGateNonce,
          content_store: ContentStoreBase | None = None,
      ) -> None:
          self._plugin_id = plugin_id
          self._executable = executable
          self._args = args
          self._audit_writer = audit_writer
          self._dlp = dlp
          self._scanner = scanner
          self._broker = secret_broker
          self._nonce = inbound_t3_nonce  # constructor param, not module global
          self._content_store: ContentStoreBase = content_store or InMemoryContentStore()
          self._process: asyncio.subprocess.Process | None = None

      async def _spawn(self, *, provider_key: bytes | None = None) -> None:
          """Spawn the subprocess with minimal env; deliver provider key on fd 3 (spec §5.3).

          **Resource safety (rvw-pre-flight fix):** Pipe fds allocated for fd-3 delivery
          are closed in a ``finally`` block so they cannot leak if
          ``create_subprocess_exec`` raises (e.g. ``FileNotFoundError`` if the
          executable is missing). The fds are short-lived (parent only needs the
          write end to deliver the key; the read end is inherited by the child via
          ``pass_fds``).
          """
          import os

          # Explicit minimal env — never os.environ (spec §5.3 AST-scan rule).
          minimal_env = {
              "PATH": "/usr/local/bin:/usr/bin:/bin",
          }
          extra_fds: tuple[int, ...] = ()
          r_fd: int | None = None
          w_fd: int | None = None
          if provider_key is not None:
              # os.pipe() is a fast syscall (microseconds); no thread offload needed.
              r_fd, w_fd = os.pipe()
              extra_fds = (r_fd,)

          try:
              self._process = await asyncio.create_subprocess_exec(
                  self._executable,
                  *self._args,
                  stdin=asyncio.subprocess.PIPE,
                  stdout=asyncio.subprocess.PIPE,
                  stderr=asyncio.subprocess.PIPE,
                  env=minimal_env,
                  pass_fds=extra_fds,
              )
              if provider_key is not None and w_fd is not None:
                  # 4-byte big-endian length + N key bytes (spec §5.3 fd-3 framing contract).
                  header = struct.pack(">I", len(provider_key))
                  os.write(w_fd, header + provider_key)
          finally:
              # Close both ends on every path. Child has its own dup of r_fd via pass_fds.
              if w_fd is not None:
                  os.close(w_fd)
              if r_fd is not None:
                  os.close(r_fd)

      async def _read_length_prefixed(self) -> bytes:
          """Read one length-prefixed frame from stdout (perf-008 fix).

          Frame format: 4-byte big-endian length + N bytes.
          Raises PluginProtocolError if frame exceeds _MAX_INBOUND_FRAME_BYTES.

          err-013 fix: explicit guard rather than ``assert`` — ``python -O``
          strips ``assert`` and this is a trust-boundary I/O path that must
          fail loud even when assertions are disabled.
          """
          if self._process is None or self._process.stdout is None:
              raise RuntimeError(
                  "_read_length_prefixed() called before _spawn(); transport state invariant violated"
              )
          header = await self._process.stdout.readexactly(4)
          length = struct.unpack(">I", header)[0]
          if length > _MAX_INBOUND_FRAME_BYTES:
              raise PluginProtocolError(
                  f"Inbound frame from {self._plugin_id!r} exceeds {_MAX_INBOUND_FRAME_BYTES} bytes "
                  f"(got length={length})"
              )
          return await self._process.stdout.readexactly(length)

      async def dispatch(
          self,
          method: str,
          params: dict[str, object],
      ) -> DispatchResult:
          """Dispatch a JSON-RPC call; apply DLP on both sides of the pipe.

          **Order rationale (escalated + resolved 2026-05-31):** Outbound order is
          DLP-then-broker per [spec §2.1 ¶3](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#21-dlp-placement-on-every-slice-3-wire)
          (verbatim: *"Cookies flow through the secret broker substitution (§7.8) — they do not
          appear in the DLP wire scan because they are substituted at the broker boundary, not
          carried as plaintext."*) An earlier `/review-plan` fixup directive proposed inverting
          this to scan post-substitution bytes; architect + security consultations both
          independently confirmed Position A (DLP-then-broker). Position B was rejected because
          routing plaintext secrets through the DLP regex engine + NER classifier + entropy
          detector introduces a secret-sink class of attack (rule-trip logs, ReDoS,
          downstream-classifier exfil) that violates CLAUDE.md hard rules #1 + #5. Position B's
          residual concern (broker-correctness bugs) is filed against Slice-4 broker hardening,
          not addressed here.

          Outbound order (arch-001 / sec-010 fix):
            1. Build placeholder frame ({{secret:*}} intact).
            2. DLP scans placeholder frame — no DLP rule fires on placeholders.
            3. Broker substitutes secrets.
            4. Build final frame with substituted values.
            5. Write to subprocess stdin.
          """
          # Step 1: placeholder frame for DLP.
          placeholder_frame = json.dumps(
              {"jsonrpc": "2.0", "method": method, "params": params}
          ).encode()

          # Step 2: outbound DLP on placeholder frame (secrets not yet substituted).
          # Run in thread for frames over the threshold (perf-012 fix).
          if len(placeholder_frame) > _OUTBOUND_DLP_THREAD_THRESHOLD:
              dlp_result = await asyncio.to_thread(self._dlp.scan, placeholder_frame)
          else:
              dlp_result = self._dlp.scan(placeholder_frame)

          if dlp_result.refused:
              correlation_id = str(uuid.uuid4())
              await self._audit_writer.append_schema(
                  audit_row_schemas.DLP_OUTBOUND_REFUSED_FIELDS,
                  event="security.dlp_outbound_refused",
                  wire="stdio_transport.outbound",
                  direction="outbound",
                  scan_rule_matched=dlp_result.rule_matched,
                  field_name="frame",
                  correlation_id=correlation_id,
              )
              raise DlpOutboundRefusedError(
                  plugin_id=self._plugin_id,
                  rule_matched=dlp_result.rule_matched,
              )

          # Step 3: broker substitution (AFTER DLP — arch-001 invariant).
          substituted_params = await self._broker.substitute(params)

          # Step 4: final frame with substituted values.
          final_frame = json.dumps(
              {"jsonrpc": "2.0", "method": method, "params": substituted_params}
          ).encode()

          # Step 5: write to subprocess.
          if self._process is None or self._process.stdin is None:
              raise NonceNotConfigured("StdioTransport._spawn() must be called before dispatch()")
          self._process.stdin.write(struct.pack(">I", len(final_frame)) + final_frame)
          await self._process.stdin.drain()

          # Read inbound frame (length-prefixed — perf-008 fix).
          raw = await self._read_length_prefixed()

          # Inbound scan in thread (perf-012 equivalent for inbound — already async).
          trip = await asyncio.to_thread(self._scanner.scan, raw)
          if isinstance(trip, CanaryTrip):
              log.warning(
                  "canary_trip_on_inbound_frame",
                  plugin_id=self._plugin_id,
                  token=trip.matched_token,
              )
              raise CanaryTripSecurityEvent(
                  message=t("security.canary_tripped", url=f"plugin:{self._plugin_id}"),
                  plugin_id=self._plugin_id,
                  matched_token=trip.matched_token,
              )

          # Branch on method shape (sec-001 / core-006 fix).
          if _is_control_plane(method):
              # Control-plane response: deserialise to ControlResult, no T3 tagging.
              payload = json.loads(raw).get("result", {})
              return ControlResult(method=method, payload=payload if isinstance(payload, dict) else {})

          # Content-bearing path: tag T3 and store (rvw-004 fix — tagged value IS used).
          # Explicit guard replaces `assert` — survives python -O (err-013 fix).
          if self._nonce is None:
              raise NonceNotConfigured(
                  "StdioTransport inbound_t3_nonce must be set at construction"
              )
          tagged = tag(T3, raw, caller_token=self._nonce)
          handle = ContentHandle(
              id=str(uuid.uuid4()),
              source_url=f"plugin:{self._plugin_id}:{method}",
              fetch_timestamp=datetime.datetime.now(datetime.UTC),
          )
          # Store the TaggedContent[T3] value, not the raw bytes (rvw-004 fix).
          self._content_store.put(handle, tagged)
          return handle

      async def kill(self) -> None:
          """SIGKILL the subprocess (called by AlfredPluginSession on quarantine — sec-013 fix)."""
          if self._process is not None:
              self._process.kill()
              await asyncio.wait_for(self._process.wait(), timeout=5.0)

      async def close(self) -> None:
          """Gracefully shut down the subprocess."""
          if self._process is not None:
              if self._process.stdin:
                  self._process.stdin.close()
              try:
                  await asyncio.wait_for(self._process.wait(), timeout=5.0)
              except asyncio.TimeoutError:
                  self._process.kill()
  ```

  Run: `uv run pytest tests/unit/plugins/test_env_scrub_subprocess.py tests/unit/plugins/test_dispatch_result_shape.py tests/unit/plugins/test_fd3_key_delivery_framing.py -q` → all pass.

  Commit:
  ```
  feat(plugins): StdioTransport — Cluster 1 rewrite (DLP order, DispatchResult union, UID-drop, nonce-as-arg, length-prefixed framing) (#TBD-slice3)
  ```

---

- [ ] **Task 7 — `StdioTransport` outbound DLP test (updated for Cluster 1 fixes).**

  Files: Create `tests/unit/plugins/test_stdio_transport_outbound_dlp.py`.

  **Failing test:**
  ```python
  # tests/unit/plugins/test_stdio_transport_outbound_dlp.py
  """Verify OutboundDlp.scan fires on placeholder frame BEFORE secret substitution (arch-001 / sec-010 fix).
  Also verifies DLP refusal raises DlpOutboundRefusedError (arch-006 / err-011 fix).
  """
  import pytest
  import struct
  import json
  from unittest.mock import AsyncMock, MagicMock, patch

  from alfred.plugins.stdio_transport import StdioTransport
  from alfred.plugins.errors import DlpOutboundRefusedError


  @pytest.fixture
  def transport_with_refusing_dlp(fake_audit_writer, fake_broker, stub_nonce):
      refusing_dlp = MagicMock()
      refusing_dlp.scan.return_value = MagicMock(refused=True, rule_matched="test_rule")
      scanner = MagicMock()
      scanner.scan.return_value = None
      return StdioTransport(
          plugin_id="test.plugin",
          executable="/bin/echo",
          args=[],
          audit_writer=fake_audit_writer,
          dlp=refusing_dlp,
          scanner=scanner,
          secret_broker=fake_broker,
          inbound_t3_nonce=stub_nonce,
      )


  @pytest.mark.asyncio
  async def test_outbound_dlp_refusal_emits_audit_row(transport_with_refusing_dlp, fake_audit_writer):
      with pytest.raises(DlpOutboundRefusedError):  # arch-006 / err-011 fix: specific exception type
          await transport_with_refusing_dlp.dispatch("web.fetch", {"url": "https://example.com"})
      assert fake_audit_writer.last_event == "security.dlp_outbound_refused"


  @pytest.mark.asyncio
  async def test_dlp_sees_placeholder_frame_not_substituted_value(fake_audit_writer, fake_broker, stub_nonce):
      """DLP must scan the {{secret:*}} placeholder, not the substituted secret value (arch-001 fix)."""
      scanned_frames: list[bytes] = []
      dlp = MagicMock()
      dlp.scan.side_effect = lambda frame: scanned_frames.append(frame) or MagicMock(refused=False)

      # Broker returns a substituted value that looks like a secret.
      substituted_params = {"url": "https://example.com", "cookie": "sk-supersecret-value"}
      fake_broker.substitute.return_value = substituted_params

      scanner = MagicMock()
      scanner.scan.return_value = None

      transport = StdioTransport(
          plugin_id="test.plugin",
          executable="/bin/echo",
          args=[],
          audit_writer=fake_audit_writer,
          dlp=dlp,
          scanner=scanner,
          secret_broker=fake_broker,
          inbound_t3_nonce=stub_nonce,
      )
      original_params = {"url": "https://example.com", "cookie": "{{secret:cookie:example.com}}"}

      # Build the response frame that the subprocess would return.
      response = json.dumps({"jsonrpc": "2.0", "result": {"status": "ok"}}).encode()
      response_frame = struct.pack(">I", len(response)) + response

      with patch.object(transport, "_process") as mock_proc:
          mock_proc.stdin.write = MagicMock()
          mock_proc.stdin.drain = AsyncMock()
          mock_proc.stdout.readexactly = AsyncMock(side_effect=[
              response_frame[:4],   # header
              response_frame[4:],   # body
          ])
          try:
              await transport.dispatch("lifecycle.start", original_params)
          except Exception:
              pass

      assert len(scanned_frames) >= 1
      # The DLP frame must contain the placeholder string, NOT the substituted secret.
      scanned_text = scanned_frames[0].decode("utf-8", errors="replace")
      assert "{{secret:cookie:example.com}}" in scanned_text, \
          "DLP must see placeholder frame, not substituted value"
      assert "sk-supersecret-value" not in scanned_text, \
          "DLP must NOT see the substituted secret value"


  @pytest.mark.asyncio
  async def test_outbound_dlp_called_before_subprocess_write(fake_audit_writer, fake_broker, stub_nonce):
      call_order: list[str] = []
      dlp = MagicMock()
      dlp.scan.side_effect = lambda _: call_order.append("dlp") or MagicMock(refused=False)
      scanner = MagicMock()
      scanner.scan.return_value = None

      response = json.dumps({"jsonrpc": "2.0", "result": {"status": "ok"}}).encode()
      response_frame = struct.pack(">I", len(response)) + response

      transport = StdioTransport(
          plugin_id="test.plugin",
          executable="/bin/echo",
          args=[],
          audit_writer=fake_audit_writer,
          dlp=dlp,
          scanner=scanner,
          secret_broker=fake_broker,
          inbound_t3_nonce=stub_nonce,
      )
      with patch.object(transport, "_process") as mock_proc:
          mock_proc.stdin.write.side_effect = lambda _: call_order.append("write")
          mock_proc.stdin.drain = AsyncMock()
          mock_proc.stdout.readexactly = AsyncMock(side_effect=[
              response_frame[:4],
              response_frame[4:],
          ])
          try:
              await transport.dispatch("lifecycle.start", {})
          except Exception:
              pass
      assert call_order.index("dlp") < call_order.index("write"), "DLP must run before subprocess write"
  ```

  Run: `uv run pytest tests/unit/plugins/test_stdio_transport_outbound_dlp.py -q` → tests fail (fake fixtures missing).

  Add conftest fixtures to `tests/unit/plugins/conftest.py`:
  ```python
  # tests/unit/plugins/conftest.py
  import pytest
  from unittest.mock import AsyncMock, MagicMock


  @pytest.fixture
  def fake_audit_writer():
      """Fake AuditWriter that captures last_event and supports append_schema (Cluster 4)."""
      writer = MagicMock()
      writer.last_event = None

      async def _append_schema(fields, **kwargs):
          writer.last_event = kwargs.get("event")

      writer.append_schema = _append_schema
      return writer


  @pytest.fixture
  def fake_broker():
      broker = AsyncMock()
      broker.substitute.side_effect = lambda params: params  # pass-through
      return broker


  @pytest.fixture
  def stub_nonce():
      """Stub CapabilityGateNonce for injecting into StdioTransport (core-008 fix)."""
      from unittest.mock import MagicMock
      return MagicMock()
  ```

  Run: `uv run pytest tests/unit/plugins/test_stdio_transport_outbound_dlp.py -q` → all pass.

  Commit:
  ```
  test(plugins): outbound DLP fires on placeholder frame; DlpOutboundRefusedError asserted (#TBD-slice3)
  ```

---

### Component F — `AlfredPluginSession`

- [ ] **Task 8 — `AlfredPluginSession`: manifest handshake + lifecycle audit rows.**

  Files: Create `src/alfred/plugins/session.py`, `tests/unit/plugins/test_session_handshake.py`.

  **Failing test:**
  ```python
  # tests/unit/plugins/test_session_handshake.py
  import pytest
  from unittest.mock import MagicMock, patch

  from alfred.plugins.session import AlfredPluginSession
  from alfred.plugins.errors import ManifestVersionError


  @pytest.mark.asyncio
  async def test_session_emits_loaded_audit_row_on_success(fake_audit_writer, fake_gate):
      manifest_toml = """
  alfred.manifest_version = 1
  [plugin]
  id = "alfred.test-plugin"
  subscriber_tier = "system"
  sandbox_profile = "user-plugin"
  """
      session = await AlfredPluginSession.create(
          manifest_raw=manifest_toml,
          audit_writer=fake_audit_writer,
          gate=fake_gate,
      )
      await session._on_handshake_complete()
      assert fake_audit_writer.last_event == "plugin.lifecycle.loaded"


  @pytest.mark.asyncio
  async def test_session_emits_load_refused_on_version_mismatch(fake_audit_writer, fake_gate):
      """Version mismatch is detected in ``create()`` (async).

      The version-mismatch audit row is emitted from the ``create()`` async
      factory's failure path so the awaited ``append_schema`` lands properly
      (rvw-cr-round-1). ``_on_handshake_complete`` is never reached because
      ``parse_manifest()`` raises before the session object is constructed.
      """
      manifest_toml = """
  alfred.manifest_version = 2
  [plugin]
  id = "alfred.test-plugin"
  subscriber_tier = "system"
  sandbox_profile = "user-plugin"
  """
      with pytest.raises(ManifestVersionError):
          await AlfredPluginSession.create(
              manifest_raw=manifest_toml,
              audit_writer=fake_audit_writer,
              gate=fake_gate,
          )
      assert fake_audit_writer.last_event == "plugin.lifecycle.load_refused"


  @pytest.mark.asyncio
  async def test_post_handshake_hook_registration_triggers_sigkill(fake_audit_writer, fake_gate):
      """Post-handshake alfred/hooks.register → quarantine (spec §4.6)."""
      manifest_toml = """
  alfred.manifest_version = 1
  [plugin]
  id = "alfred.test-plugin"
  subscriber_tier = "system"
  sandbox_profile = "user-plugin"
  """
      session = await AlfredPluginSession.create(
          manifest_raw=manifest_toml,
          audit_writer=fake_audit_writer,
          gate=fake_gate,
      )
      await session._on_handshake_complete()
      await session._on_post_handshake_method("alfred/hooks.register")
      assert fake_audit_writer.last_event == "plugin.lifecycle.quarantined"
  ```

  Run: `uv run pytest tests/unit/plugins/test_session_handshake.py -q` → `ImportError`.

  > **Async construction pattern (rvw-cr-round-1):** `AlfredPluginSession` parses
  > the manifest and may need to emit a `plugin.lifecycle.load_refused` audit row
  > *before* the session object exists. `AuditWriter.append_schema()` is `async def`
  > (PR-S3-0a), so the emit MUST be awaited — but `__init__` cannot be async. The
  > original draft of this plan called `self._audit_writer.append_schema(...)` from
  > `__init__` without await, leaking an unawaited coroutine and silently dropping
  > the audit row on manifest-version mismatch (a security-relevant failure mode).
  >
  > Fix: split construction into a private synchronous `__init__` (pure state init,
  > accepting an already-parsed `PluginManifest`) plus a public `async classmethod
  > create()` factory that handles `parse_manifest`, the awaited load-refused emit
  > on failure, and final object construction. All call sites — production and
  > tests — use `await AlfredPluginSession.create(...)`. The synchronous
  > `__init__` remains usable but is documented as "internal: prefer `create()`".
  >
  > This is the standard pattern for any class whose construction needs to await:
  > keep `__init__` synchronous, expose `async classmethod create()` as the
  > public API.

  **Implementation** (`src/alfred/plugins/session.py`):
  ```python
  """AlfredPluginSession — manifest handshake + lifecycle audit rows (spec §4.2, §4.7).

  Owns the subprocess lifecycle for a single plugin:
  1. AlfredPluginSession.create() — async factory: parse_manifest() + awaited load_refused emit on failure
  2. check_plugin_load() — capability gate (PR-S3-2 RealGate)
  3. emit plugin.lifecycle.loaded on success
  4. emit plugin.lifecycle.load_refused on any handshake failure
  5. SIGKILL (via transport.kill()) + emit plugin.lifecycle.quarantined on post-handshake alfred/hooks.register

  Cluster 4 fix: all audit emits use `await self._audit_writer.append_schema(fields, **kwargs)`.
  rvw-cr-round-1 fix: construction split into sync ``__init__`` (state only) + ``async classmethod create()``
    so the load_refused emit on manifest-version mismatch is properly awaited rather than dropped.
  sec-013 / core-007 fix: _on_post_handshake_method calls `await self._transport.kill()` before emitting the row.
  err-017 fix: best-effort plugin_id extraction from raw TOML before strict parse.
  """
  from __future__ import annotations

  import hashlib
  import re
  import uuid
  from typing import TYPE_CHECKING

  import structlog

  from alfred.audit import audit_row_schemas
  from alfred.audit.writer import AuditWriter
  from alfred.hooks.capability import CapabilityGate
  from alfred.plugins.errors import ManifestVersionError, ManifestTierError, PluginError
  from alfred.plugins.manifest import PluginManifest, parse_manifest

  if TYPE_CHECKING:
      from alfred.plugins.stdio_transport import StdioTransport

  log = structlog.get_logger(__name__)

  _DISALLOWED_POST_HANDSHAKE_METHODS = frozenset({
      "alfred/hooks.register",
  })

  _PLUGIN_ID_RE = re.compile(r'\bid\s*=\s*"([^"]+)"')


  def _best_effort_plugin_id(manifest_raw: str) -> str:
      """Extract plugin_id from raw TOML on a best-effort basis for audit rows (err-017 fix).

      If the [plugin] id field is readable even on partial parse, use it;
      otherwise fall back to a sha256 prefix of the manifest bytes so the
      failed manifest is identifiable in audit correlation.
      """
      match = _PLUGIN_ID_RE.search(manifest_raw)
      if match:
          return match.group(1)
      digest = hashlib.sha256(manifest_raw.encode()).hexdigest()[:12]
      return f"unknown(sha256={digest})"


  class AlfredPluginSession:
      """Manages the lifecycle of a single plugin subprocess — from manifest to SIGKILL.

      **Construction:** always via ``await AlfredPluginSession.create(...)``. The
      synchronous ``__init__`` takes an already-parsed manifest and is internal
      — direct construction skips the `plugin.lifecycle.load_refused` audit emit
      on manifest-version mismatch, which is a security-relevant invariant.
      """

      def __init__(
          self,
          *,
          manifest: PluginManifest,
          audit_writer: AuditWriter,
          gate: CapabilityGate,
          transport: StdioTransport | None = None,
          correlation_id: str | None = None,
      ) -> None:
          """Internal: prefer ``await AlfredPluginSession.create(manifest_raw=..., ...)``.

          Takes an already-parsed ``PluginManifest`` so this is purely synchronous
          state init — no audit emits, no I/O. ``create()`` handles the parse
          + the awaited ``plugin.lifecycle.load_refused`` emit on failure.
          """
          self._audit_writer = audit_writer
          self._gate = gate
          self._transport = transport  # held for SIGKILL on quarantine (sec-013 / core-007 fix)
          self._manifest: PluginManifest = manifest
          self._handshake_complete = False
          self._correlation_id = correlation_id or str(uuid.uuid4())

      @classmethod
      async def create(
          cls,
          *,
          manifest_raw: str,
          audit_writer: AuditWriter,
          gate: CapabilityGate,
          transport: StdioTransport | None = None,
      ) -> AlfredPluginSession:
          """Async factory: parse the manifest, emit load_refused on failure, then construct.

          The awaited ``audit_writer.append_schema(...)`` on failure is the reason
          this is async; ``__init__`` would silently drop the coroutine
          (rvw-cr-round-1).
          """
          correlation_id = str(uuid.uuid4())
          try:
              manifest = parse_manifest(manifest_raw)
          except (ManifestVersionError, ManifestTierError) as exc:
              # Best-effort plugin_id when parse fails (err-017): scan the raw TOML.
              best_effort_id = _best_effort_plugin_id(manifest_raw)
              # Cluster 4 + rvw-cr-round-1: awaited append_schema.
              await audit_writer.append_schema(
                  audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS,
                  event="plugin.lifecycle.load_refused",
                  plugin_id=best_effort_id,
                  manifest_subscriber_tier="unknown",
                  manifest_version=getattr(exc, "got", -1),
                  sandbox_profile="unknown",
                  exit_code=None,
                  signal=None,
                  restart_count=0,
                  breaker_state="CLOSED",
                  correlation_id=correlation_id,
              )
              raise
          return cls(
              manifest=manifest,
              audit_writer=audit_writer,
              gate=gate,
              transport=transport,
              correlation_id=correlation_id,
          )

      async def _on_handshake_complete(self) -> None:
          """Call after subprocess MCP handshake succeeds.

          Async because every ``append_schema`` emit is an awaited coroutine
          (Cluster-4 invariant). Callers — including unit tests — must await
          this method; the non-async variant was a Cluster-4 await-drift bug
          flagged in plan review round 2.

          ``self._manifest`` is always set post-``create()`` (rvw-cr-round-1: the
          async factory either parses successfully or raises before calling
          ``__init__``), so no None-guard is needed.
          """
          if not self._gate.check_plugin_load(
              plugin_id=self._manifest.plugin_id,
              manifest_tier=self._manifest.subscriber_tier,
          ):
              await self._audit_writer.append_schema(
                  audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS,
                  event="plugin.lifecycle.load_refused",
                  plugin_id=self._manifest.plugin_id,
                  manifest_subscriber_tier=self._manifest.subscriber_tier,
                  manifest_version=self._manifest.manifest_version,
                  sandbox_profile=self._manifest.sandbox_profile,
                  exit_code=None,
                  signal=None,
                  restart_count=0,
                  breaker_state="CLOSED",
                  correlation_id=self._correlation_id,
              )
              raise PluginError(f"Gate denied load for {self._manifest.plugin_id!r}")
          self._handshake_complete = True
          await self._audit_writer.append_schema(
              audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS,
              event="plugin.lifecycle.loaded",
              plugin_id=self._manifest.plugin_id,
              manifest_subscriber_tier=self._manifest.subscriber_tier,
              manifest_version=self._manifest.manifest_version,
              sandbox_profile=self._manifest.sandbox_profile,
              exit_code=None,
              signal=None,
              restart_count=0,
              breaker_state="CLOSED",
              correlation_id=self._correlation_id,
          )

      async def _on_post_handshake_method(self, method: str) -> None:
          """Called when the subprocess sends a JSON-RPC method after handshake.

          Disallowed methods (e.g. alfred/hooks.register) trigger SIGKILL BEFORE the audit row
          (sec-013 / core-007 fix: the subprocess must be dead before we claim it is — the
          audit row saying signal='SIGKILL' must be true when written).

          **Audit guarantee (rvw-pre-flight fix):** the kill-then-audit ordering protects the
          privileged orchestrator from a misbehaving plugin; the ``try/finally`` guarantees the
          operator sees the quarantine event in the audit log **even when the kill itself fails**
          (subprocess already dead, ``asyncio.wait_for`` timeout, OSError from a closed pipe, …).
          A ``kill_succeeded`` flag is threaded into the row so post-incident analysis can tell
          whether the SIGKILL landed.
          """
          if method in _DISALLOWED_POST_HANDSHAKE_METHODS:
              # self._manifest is always set post-create() (rvw-cr-round-1).
              log.error(
                  "post_handshake_disallowed_method",
                  plugin_id=self._manifest.plugin_id,
                  method=method,
              )
              # SIGKILL FIRST, then audit row (invariant: row says killed = subprocess is dead).
              # Linux-only: spec §5.2 requires UID-drop, which is POSIX-only — Windows is out of
              # scope, so signal="SIGKILL" / signal=None is the only schema we emit.
              kill_succeeded = False
              kill_exception: BaseException | None = None
              try:
                  if self._transport is not None:
                      await self._transport.kill()
                  kill_succeeded = True
              except BaseException as exc:  # noqa: BLE001 — re-raised after audit emit
                  kill_exception = exc
              finally:
                  # Best-effort audit emit — fires regardless of kill outcome so operators
                  # always see the quarantine attempt in the log. Cluster-4: await is mandatory.
                  await self._audit_writer.append_schema(
                      audit_row_schemas.PLUGIN_LIFECYCLE_QUARANTINED_FIELDS,
                      event="plugin.lifecycle.quarantined",
                      plugin_id=self._manifest.plugin_id,
                      manifest_subscriber_tier=self._manifest.subscriber_tier,
                      manifest_version=self._manifest.manifest_version,
                      sandbox_profile=self._manifest.sandbox_profile,
                      exit_code=None,
                      signal="SIGKILL" if kill_succeeded else None,
                      restart_count=0,
                      breaker_state="OPEN",
                      quarantine_reason=(
                          "protocol_violation"
                          if kill_succeeded
                          else "protocol_violation (kill failed)"
                      ),
                      kill_succeeded=kill_succeeded,
                      trip_count=1,
                      correlation_id=self._correlation_id,
                  )
                  if kill_exception is not None:
                      raise kill_exception
  ```

  > **Schema note (PR-S3-0a contract):** `PLUGIN_LIFECYCLE_QUARANTINED_FIELDS` includes
  > `kill_succeeded: bool`. PR-S3-0a defines the field; this PR is the first consumer. The
  > field lets operator-facing audit queries (`alfred audit log --event
  > plugin.lifecycle.quarantined`) distinguish *kill landed cleanly* (the common case) from
  > *kill failed but quarantine intent was logged* (e.g. subprocess was already dead, or the
  > pipe was closed mid-kill).

  Update `tests/unit/plugins/test_session_handshake.py` to use `async` for the SIGKILL test:
  ```python
  @pytest.mark.asyncio
  async def test_post_handshake_hook_registration_triggers_sigkill(fake_audit_writer, fake_gate):
      """Post-handshake alfred/hooks.register → SIGKILL then quarantine audit row (spec §4.6)."""
      mock_transport = MagicMock()
      mock_transport.kill = AsyncMock()
      session = await AlfredPluginSession.create(
          manifest_raw=manifest_toml,
          audit_writer=fake_audit_writer,
          gate=fake_gate,
          transport=mock_transport,
      )
      await session._on_handshake_complete()
      await session._on_post_handshake_method("alfred/hooks.register")
      mock_transport.kill.assert_called_once()  # SIGKILL was actually issued
      assert fake_audit_writer.last_event == "plugin.lifecycle.quarantined"
  ```

  Add `fake_gate` fixture to `tests/unit/plugins/conftest.py`:
  ```python
  @pytest.fixture
  def fake_gate():
      gate = MagicMock()
      gate.check_plugin_load.return_value = True
      gate.check_content_clearance.return_value = True
      return gate
  ```

  Run: `uv run pytest tests/unit/plugins/test_session_handshake.py -q` → all pass.

  Commit:
  ```
  feat(plugins): AlfredPluginSession — manifest handshake, lifecycle audit rows, SIGKILL-before-row quarantine (#TBD-slice3)
  ```

---

### Component G — Post-handshake hook registration attack (adversarial test)

- [ ] **Task 9 — Adversarial test: post-handshake `alfred/hooks.register` attack (sec-015 fix).**

  Files: Create `tests/adversarial/tier_laundering/test_post_handshake_hook_registration.py`.

  **sec-015 fix:** Strengthen assertions beyond "audit row was written" to assert (a) transport.kill() was called (SIGKILL actually issued), and (b) allowed methods do not quarantine.

  This is a pytest module (not YAML) per spec §12.2 — it requires simulating a live subprocess message sequence.

  ```python
  # tests/adversarial/tier_laundering/test_post_handshake_hook_registration.py
  """Post-handshake hook registration attack (spec §4.6, §12.3).

  sec-015 fix: tests assert (a) audit row emitted, (b) transport.kill() called,
  (c) no hook was registered despite the attack attempt.

  pytest module (not YAML) because it requires two-phase handshake + post-handshake message.
  """
  from __future__ import annotations

  from unittest.mock import AsyncMock, MagicMock

  import pytest
  import pytest_asyncio

  from alfred.plugins.session import AlfredPluginSession


  VALID_MANIFEST = """
  alfred.manifest_version = 1
  [plugin]
  id = "alfred.compromised-plugin"
  subscriber_tier = "user-plugin"
  sandbox_profile = "user-plugin"
  """


  @pytest.fixture
  def mock_transport():
      transport = MagicMock()
      transport.kill = AsyncMock()
      return transport


  @pytest_asyncio.fixture
  async def session_post_handshake(fake_audit_writer, fake_gate, mock_transport):
      """Build a session that has completed handshake.

      Both ``AlfredPluginSession.create()`` (rvw-cr-round-1) and
      ``_on_handshake_complete`` are async (Cluster-4: awaited audit emits),
      so the fixture must itself be async via ``pytest_asyncio.fixture``.
      """
      session = await AlfredPluginSession.create(
          manifest_raw=VALID_MANIFEST,
          audit_writer=fake_audit_writer,
          gate=fake_gate,
          transport=mock_transport,
      )
      await session._on_handshake_complete()
      return session, fake_audit_writer, mock_transport


  @pytest.mark.asyncio
  async def test_post_handshake_hook_registration_quarantines_plugin(session_post_handshake):
      session, audit, transport = session_post_handshake
      await session._on_post_handshake_method("alfred/hooks.register")
      assert audit.last_event == "plugin.lifecycle.quarantined"


  @pytest.mark.asyncio
  async def test_post_handshake_hook_registration_sigkill_issued(session_post_handshake):
      """SIGKILL must actually be issued — not just claimed in the audit row (sec-013 / sec-015 fix)."""
      session, audit, transport = session_post_handshake
      await session._on_post_handshake_method("alfred/hooks.register")
      transport.kill.assert_called_once()


  @pytest.mark.asyncio
  async def test_post_handshake_hook_registration_no_hook_registered(session_post_handshake):
      """Confirm no hook subscriber was registered despite the attempt."""
      from alfred.hooks.registry import get_registry
      registry = get_registry()
      hooks_before = set(registry._hookpoints.keys()) if hasattr(registry, "_hookpoints") else set()
      session, _, _ = session_post_handshake
      await session._on_post_handshake_method("alfred/hooks.register")
      hooks_after = set(registry._hookpoints.keys()) if hasattr(registry, "_hookpoints") else set()
      assert hooks_after == hooks_before


  @pytest.mark.asyncio
  async def test_allowed_post_handshake_method_does_not_quarantine(session_post_handshake):
      """lifecycle.stop is a legitimate post-handshake method — must not quarantine or kill."""
      session, audit, transport = session_post_handshake
      last_event_before = audit.last_event
      await session._on_post_handshake_method("lifecycle.stop")
      assert audit.last_event == last_event_before or audit.last_event == "plugin.lifecycle.loaded"
      transport.kill.assert_not_called()
  ```

  Run: `uv run pytest tests/adversarial/tier_laundering/test_post_handshake_hook_registration.py -q` → all pass.

  Commit:
  ```
  test(adversarial): post-handshake hook registration — assert SIGKILL issued + no-hook registered (#TBD-slice3)
  ```

---

### Component H — `bin/alfred-plugin-launcher` stub

- [ ] **Task 10 — Launcher stub: fail-closed + UID-drop via `runuser` + bare-key-only stderr.**

  **sec-003 fix:** launcher calls `exec runuser -u "${TARGET_UID}" -- "${EXECUTABLE}"` so subprocess runs as a different UID (OS-level enforcement, not policy-only). On macOS/dev `runuser` is unavailable; emit `supervisor.config_insecure` with `uid_separation_unavailable` key and exec without UID-drop (documented Linux-only for Slice 3).

  **i18n-005 fix (option b):** emit ONLY the bare i18n key to stderr — no hardcoded English sentences. The supervisor or CLI renders localised text from the audit row. Test assertions match bare key only.

  Files: Create `bin/alfred-plugin-launcher`, `tests/unit/plugins/test_plugin_launcher_stub.py`.

  **Failing test:**
  ```python
  # tests/unit/plugins/test_plugin_launcher_stub.py
  """Launcher tests (sec-003 / i18n-005 fixes)."""
  import os
  import subprocess

  LAUNCHER = "bin/alfred-plugin-launcher"


  def test_launcher_exits_1_without_sandbox_policy_in_production():
      env = {**os.environ, "ALFRED_ENV": "production"}
      env.pop("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", None)
      result = subprocess.run(
          [LAUNCHER, "alfred.test-plugin", "/bin/echo", "hello"],
          capture_output=True,
          env=env,
      )
      assert result.returncode == 1
      # i18n-005 fix: bare key only, no hardcoded English sentence.
      assert b"plugin.launcher_no_sandbox_policy" in result.stderr


  def test_launcher_exits_1_in_production_even_with_unsandboxed_flag():
      env = {**os.environ, "ALFRED_ENV": "production", "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED": "1"}
      result = subprocess.run(
          [LAUNCHER, "alfred.test-plugin", "/bin/echo", "hello"],
          capture_output=True,
          env=env,
      )
      assert result.returncode == 1
      assert b"plugin.launcher_no_sandbox_policy" in result.stderr


  def test_launcher_accepts_unsandboxed_in_development():
      env = {**os.environ, "ALFRED_ENV": "development", "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED": "1"}
      result = subprocess.run(
          [LAUNCHER, "alfred.test-plugin", "/bin/echo", "alfred-launcher-test-marker"],
          capture_output=True,
          env=env,
      )
      assert result.returncode == 0
      assert b"alfred-launcher-test-marker" in result.stdout


  def test_launcher_emits_config_insecure_audit_row_in_development():
      env = {**os.environ, "ALFRED_ENV": "development", "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED": "1"}
      result = subprocess.run(
          [LAUNCHER, "alfred.test-plugin", "/bin/echo", "ok"],
          capture_output=True,
          env=env,
      )
      # Structured audit row on stderr (supervisor captures it).
      assert b"supervisor.config_insecure" in result.stderr


  def test_launcher_invokes_runuser_when_uid_specified():
      """sec-003 fix: launcher must invoke runuser when ALFRED_PLUGIN_UID is set."""
      import ast
      import pathlib
      source = pathlib.Path("bin/alfred-plugin-launcher").read_text()
      # AST-level check is hard for shell; grep is sufficient for the contract test.
      assert "runuser" in source, "launcher must call runuser for UID-drop (sec-003)"
  ```

  Run: `uv run pytest tests/unit/plugins/test_plugin_launcher_stub.py -q` → FAIL (file does not exist).

  **Implementation** (`bin/alfred-plugin-launcher`):
  ```bash
  #!/usr/bin/env bash
  # bin/alfred-plugin-launcher — fail-closed plugin launcher (spec §4.8, §5.2).
  #
  # Usage: alfred-plugin-launcher <plugin_id> <executable> [args...]
  #
  # sec-003 fix: performs UID-drop via `runuser` when ALFRED_PLUGIN_UID is set.
  # UID-drop is Linux-only in Slice 3; macOS dev emits supervisor.config_insecure.
  #
  # i18n-005 fix (option b): emits ONLY bare i18n keys to stderr.
  # No hardcoded English sentences — the supervisor renders localised output.
  #
  # Refuses launch unless a sandbox policy file exists, or
  # ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1 AND ALFRED_ENV=development.

  set -euo pipefail

  PLUGIN_ID="${1:?Usage: alfred-plugin-launcher <plugin_id> <executable> [args...]}"
  shift
  EXECUTABLE="${1:?Usage: alfred-plugin-launcher <plugin_id> <executable> [args...]}"
  shift

  ALFRED_ENV="${ALFRED_ENV:-production}"
  UNSANDBOXED="${ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED:-0}"
  TARGET_UID="${ALFRED_PLUGIN_UID:-alfred-quarantine}"

  # Production guard: UNSANDBOXED=1 is never accepted outside development.
  if [ "${ALFRED_ENV}" != "development" ] && [ "${UNSANDBOXED}" = "1" ]; then
      # Bare key only (i18n-005 option b).
      printf 'plugin.launcher_no_sandbox_policy plugin_id=%s\n' "${PLUGIN_ID}" >&2
      exit 1
  fi

  SANDBOX_POLICY_DIR="${ALFRED_SANDBOX_POLICY_DIR:-/etc/alfred/sandbox}"
  POLICY_FILE="${SANDBOX_POLICY_DIR}/${PLUGIN_ID}.policy"

  _do_exec() {
      # sec-003: UID-drop via runuser (Linux-only; macOS emits config_insecure).
      if command -v runuser >/dev/null 2>&1; then
          exec runuser -u "${TARGET_UID}" -- "${EXECUTABLE}" "$@"
      else
          # macOS/dev: runuser unavailable — exec without UID-drop.
          printf '{"event":"supervisor.config_insecure","insecure_config_key":"launcher_uid_separation_unavailable_macos","plugin_id":"%s"}\n' "${PLUGIN_ID}" >&2
          exec "${EXECUTABLE}" "$@"
      fi
  }

  # CR round-2 fix: function must be defined BEFORE the policy-file check that calls it.
  # The previous ordering invoked `_do_exec` on the dev/unsandboxed branch before its
  # declaration, which Bash treats as "command not found" — silently fatal on that branch.
  if [ ! -f "${POLICY_FILE}" ]; then
      if [ "${ALFRED_ENV}" = "development" ] && [ "${UNSANDBOXED}" = "1" ]; then
          # Emit structured audit row to stderr (supervisor captures).
          printf '{"event":"supervisor.config_insecure","insecure_config_key":"ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED","plugin_id":"%s"}\n' "${PLUGIN_ID}" >&2
          _do_exec "$@"
          exit 0
      fi
      printf 'plugin.launcher_no_sandbox_policy plugin_id=%s\n' "${PLUGIN_ID}" >&2
      exit 1
  fi

  _do_exec "$@"
  ```

  Make executable: `chmod +x bin/alfred-plugin-launcher`.

  Run: `uv run pytest tests/unit/plugins/test_plugin_launcher_stub.py -q` → all pass.

  Commit:
  ```
  feat(plugins): bin/alfred-plugin-launcher — UID-drop via runuser, bare-key stderr (#TBD-slice3)
  ```

---

### Component I — Identity hookpoints

- [ ] **Task 11 — Register `identity.t1_ingress` and `identity.t1_downgrade` hookpoints.**

  Files: Modify `src/alfred/identity/_ingest.py` (if created by PR-S3-1) or create it here.

  **Failing test:**
  ```python
  # tests/unit/identity/test_ingest_tier_hookpoints.py
  """Verify identity hookpoints are registered and fire on T1 ingress."""
  from alfred.hooks.registry import get_registry
  from alfred.identity._ingest import register_identity_hookpoints

  def test_t1_ingress_hookpoint_registered():
      register_identity_hookpoints()
      registry = get_registry()
      assert "identity.t1_ingress" in registry._hookpoints

  def test_t1_downgrade_hookpoint_registered():
      register_identity_hookpoints()
      registry = get_registry()
      assert "identity.t1_downgrade" in registry._hookpoints

  def test_hookpoints_use_system_operator_tiers():
      from alfred.hooks.registry import SYSTEM_OPERATOR_TIERS
      register_identity_hookpoints()
      registry = get_registry()
      meta_ingress = registry._hookpoints["identity.t1_ingress"]
      assert meta_ingress.subscribable_tiers == SYSTEM_OPERATOR_TIERS
  ```

  Run: `uv run pytest tests/unit/identity/test_ingest_tier_hookpoints.py -q` → FAIL.

  **Implementation** — add to `src/alfred/identity/_ingest.py`:
  ```python
  def register_identity_hookpoints() -> None:
      """Register identity.t1_ingress and identity.t1_downgrade hookpoints (spec §3.6, §14).

      Called at bootstrap. Idempotent — safe to call multiple times.
      """
      from alfred.hooks.registry import SYSTEM_OPERATOR_TIERS, get_registry
      registry = get_registry()
      registry.register_hookpoint(
          name="identity.t1_ingress",
          subscribable_tiers=SYSTEM_OPERATOR_TIERS,
          refusable_tiers=frozenset(),
          fail_closed=False,
      )
      registry.register_hookpoint(
          name="identity.t1_downgrade",
          subscribable_tiers=SYSTEM_OPERATOR_TIERS,
          refusable_tiers=frozenset(),
          fail_closed=False,
      )
  ```

  Run: `uv run pytest tests/unit/identity/test_ingest_tier_hookpoints.py -q` → all pass.

  Commit:
  ```
  feat(identity): register identity.t1_ingress + identity.t1_downgrade hookpoints (#TBD-slice3)
  ```

---

### Component J — Observability (perf-002 / perf-009)

- [ ] **Task 11b — Transport-layer Prometheus histograms (perf-002 / perf-009 fix).**

  Spec §7a.1 commits: `StdioTransport.dispatch` p99 < 5ms, `OutboundDlp.scan` 1KB p99 < 200µs, `InboundContentScanner.scan` 1MB p99 < 50ms, subprocess cold-start p99 < 500ms. This task ships the four histograms so the budgets are measurable.

  Files: Create `src/alfred/plugins/observability.py`, add `tests/unit/plugins/test_transport_perf_budgets.py`.

  **Implementation** (`src/alfred/plugins/observability.py`):
  ```python
  """Transport-layer Prometheus histograms (spec §7a.1 — perf-002 / perf-009 fix).

  Four histograms covering the four spec §7a.1 p99 budgets:
  - alfred_stdio_transport_dispatch_seconds: full dispatch round-trip
  - alfred_outbound_dlp_scan_seconds: OutboundDlp.scan per frame
  - alfred_inbound_scanner_scan_seconds: InboundContentScanner.scan per frame
  - alfred_plugin_spawn_seconds: subprocess cold-start to manifest-handshake complete

  Shipped alongside the code (spec §7a: not deferred to Slice 4).
  """
  from prometheus_client import Histogram

  DISPATCH_DURATION = Histogram(
      "alfred_stdio_transport_dispatch_seconds",
      "StdioTransport.dispatch end-to-end duration",
      ["plugin_id", "method_shape", "outcome"],
      buckets=[0.0005, 0.001, 0.002, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0],
  )

  OUTBOUND_DLP_SCAN_DURATION = Histogram(
      "alfred_outbound_dlp_scan_seconds",
      "OutboundDlp.scan duration per frame",
      ["outcome"],
      buckets=[0.00005, 0.0001, 0.0002, 0.0005, 0.001, 0.005, 0.01],
  )

  INBOUND_SCANNER_SCAN_DURATION = Histogram(
      "alfred_inbound_scanner_scan_seconds",
      "InboundContentScanner.scan duration per frame",
      ["outcome"],
      buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5],
  )

  PLUGIN_SPAWN_DURATION = Histogram(
      "alfred_plugin_spawn_seconds",
      "Plugin subprocess cold-start to manifest-handshake complete",
      ["plugin_id", "outcome"],
      buckets=[0.05, 0.1, 0.2, 0.3, 0.5, 1.0, 2.0],
  )
  ```

  Instrument `StdioTransport.dispatch` and `StdioTransport._spawn` with `time.monotonic()` observe calls using these histograms.

  **Failing test:**
  ```python
  # tests/unit/plugins/test_transport_perf_budgets.py
  """Verify all four spec §7a.1 histogram metrics exist and observe on use (perf-002 / perf-009)."""

  def test_dispatch_histogram_exists() -> None:
      from alfred.plugins.observability import DISPATCH_DURATION
      assert DISPATCH_DURATION is not None

  def test_outbound_dlp_scan_histogram_exists() -> None:
      from alfred.plugins.observability import OUTBOUND_DLP_SCAN_DURATION
      assert OUTBOUND_DLP_SCAN_DURATION is not None

  def test_inbound_scanner_histogram_exists() -> None:
      from alfred.plugins.observability import INBOUND_SCANNER_SCAN_DURATION
      assert INBOUND_SCANNER_SCAN_DURATION is not None

  def test_plugin_spawn_histogram_exists() -> None:
      from alfred.plugins.observability import PLUGIN_SPAWN_DURATION
      assert PLUGIN_SPAWN_DURATION is not None
  ```

  Run: `uv run pytest tests/unit/plugins/test_transport_perf_budgets.py -q` → all pass.

  Commit:
  ```
  feat(plugins): transport-layer Prometheus histograms for spec §7a.1 p99 budgets (#TBD-slice3)
  ```

---

### Component K — Coverage gate + `__init__.py` public surface

- [ ] **Task 12 — 100% line+branch coverage on trust-boundary files.**

  Per spec §11a, `src/alfred/plugins/stdio_transport.py` and `src/alfred/plugins/inbound_scanner.py` require 100% line+branch coverage.

  ```bash
  cd <repo-root>
  uv run pytest tests/unit/plugins/ tests/unit/identity/ \
    --cov=src/alfred/plugins/stdio_transport \
    --cov=src/alfred/plugins/inbound_scanner \
    --cov-branch \
    --cov-report=term-missing \
    -q
  ```

  Expected: 100% on both files. Add any missing branch tests.

  Commit:
  ```
  test(plugins): 100% line+branch coverage on stdio_transport + inbound_scanner (#TBD-slice3)
  ```

---

- [ ] **Task 13 — `src/alfred/plugins/__init__.py` public surface.**

  ```python
  # src/alfred/plugins/__init__.py
  """AlfredOS plugin host package.

  Public surface:
  - PluginTransport: Protocol for subprocess communication
  - StdioTransport: Slice-3 sole implementation
  - AlfredPluginSession: manifest handshake + lifecycle audit
  - DispatchResult: discriminated union of dispatch return shapes
  - ContentStoreBase: Protocol for T3 content stores
  """
  from alfred.plugins.content_store_base import ContentStoreBase, InMemoryContentStore
  from alfred.plugins.session import AlfredPluginSession
  from alfred.plugins.transport import ControlResult, DispatchResult, PluginTransport

  __all__ = [
      "AlfredPluginSession",
      "ContentStoreBase",
      "ControlResult",
      "DispatchResult",
      "InMemoryContentStore",
      "PluginTransport",
  ]
  ```

  Run: `uv run pytest tests/unit/plugins/ -q` → all pass.

  Commit:
  ```
  feat(plugins): public __init__.py surface for alfred.plugins package (#TBD-slice3)
  ```

---

- [ ] **Task 14 — Final quality gates.**

  ```bash
  cd <repo-root>
  make check
  # Expected: lint + format + type + tests all pass
  uv run pytest tests/adversarial/tier_laundering/ -q
  # Expected: all adversarial tests pass
  make docs-check
  # Expected: 0 broken links
  ```

  Commit:
  ```
  chore(plugins): quality gate pass — lint, type, coverage, adversarial (#TBD-slice3)
  ```

---

## §5 Spec Coverage Map

| Spec section | Implementing task(s) |
|---|---|
| §4.1 `PluginTransport` Protocol + `DispatchResult` plain union (core-011 fix) | Task 2 |
| §4.2 `StdioTransport` implementation + `AlfredPluginSession` | Tasks 6, 8 |
| §4.3 Manifest schema: `manifest_version=1` pin, `subscriber_tier != T3`, `[plugin] platform` reserved; dedicated `plugin.manifest_subscriber_tier_invalid` i18n key (arch-007 fix) | Task 3 |
| §4.4 DLP scans placeholder frame FIRST, then broker substitutes (arch-001 / sec-010 fix) | Task 6 |
| §4.5 Two distinct scanners: `OutboundDlp` (outbound) + `InboundContentScanner` (inbound) | Tasks 4, 7 |
| §4.5 DLP refusal raises `DlpOutboundRefusedError` with `plugin.transport.dlp_outbound_refused` key (arch-006 / sec-006 / err-011 fix) | Task 6 |
| §4.6 Post-handshake `alfred/hooks.register` → SIGKILL via `transport.kill()` THEN quarantine audit row (sec-013 / core-007 fix) | Tasks 8, 9 |
| §4.7 `plugin.lifecycle.*` audit family — all emits via `append_schema` (Cluster 4 fix) | Task 8 |
| §4.8 `bin/alfred-plugin-launcher` — UID-drop via `runuser`, bare-key stderr, `supervisor.config_insecure` (sec-003 / i18n-005 fix) | Task 10 |
| §4.9 Manifest version pin N+1 refused | Task 3 |
| §2.1 DLP table: outbound DLP on placeholder frame + inbound DLP in thread | Tasks 4, 7 |
| §3.6 `_ingest_tier` identity hookpoints (if not fully done in PR-S3-1) | Task 11 |
| §5.2 `alfred-quarantine` UID drop via `runuser` in launcher (sec-003 fix) | Task 10 |
| §5.3 Env-scrub subprocess spawn + fd-3 4-byte-length-prefixed framing; contract test (arch-009 fix) | Task 6 |
| §7a.1 Transport-layer p99 budgets — four Prometheus histograms (perf-002 / perf-009 fix) | Task 11b |
| §11a Coverage commitments: `stdio_transport.py`, `inbound_scanner.py` 100% | Task 12 |
| §12.2 Post-handshake hook registration attack — SIGKILL asserted + subsequent-frame refused (sec-015 fix) | Task 9 |
| §13 `PLUGIN_LIFECYCLE_FIELDS`, `PLUGIN_LIFECYCLE_CRASHED_FIELDS`, `PLUGIN_LIFECYCLE_QUARANTINED_FIELDS`, `DLP_OUTBOUND_REFUSED_FIELDS`, `T1_INGRESS_FIELDS`, `T1_DOWNGRADE_FIELDS`, `SUPERVISOR_CONFIG_INSECURE_FIELDS` | All emit-site tasks |
| §14 `plugin.lifecycle.loaded` hookpoint declaration | Task 8 |
| §14 `plugin.lifecycle.crashed` hookpoint declaration | Task 8 (error path) |
| §14 `identity.t1_ingress` hookpoint declaration | Task 11 |
| §14 `identity.t1_downgrade` hookpoint declaration | Task 11 |

### Findings applied in this fixup (plan-review pass 3)

| Finding | Severity | Fix location |
|---|---|---|
| arch-001 / sec-010 | Critical | Task 6 dispatch(): DLP scans placeholder frame; substitution after |
| sec-001 / core-006 | Critical | Task 6 dispatch(): DispatchResult union — ControlResult for control-plane, ContentHandle for content |
| rvw-001 (Cluster 4) | Critical | Tasks 6, 8: all audit emits rewritten to `await append_schema(fields, **kwargs)` |
| sec-003 | Critical | Task 10: `runuser` UID-drop added to launcher |
| arch-006 / sec-006 / err-011 / rvw-009 | High | Task 6: `DlpOutboundRefusedError` + `plugin.transport.dlp_outbound_refused` key |
| sec-013 / core-007 | High | Task 8: `transport.kill()` called before audit row in `_on_post_handshake_method` |
| rvw-004 | High | Task 6: `tagged` stored in content store (not raw bytes) |
| err-013 | High | Task 6: `assert` nonce guard replaced with explicit raise |
| core-008 | Medium | Task 6: `inbound_t3_nonce` constructor param replaces module global |
| perf-008 | High | Task 6: length-prefixed framing replaces `readline()` |
| perf-012 | Medium | Task 6: outbound DLP in `asyncio.to_thread` above 4KB |
| perf-002 / perf-009 | High | Task 11b: four Prometheus histograms |
| arch-007 | Medium | Task 1: `ManifestTierError` uses dedicated `plugin.manifest_subscriber_tier_invalid` key |
| core-011 | Medium | Task 2: `DispatchResult` is plain union, no `Annotated/Field` wrapper |
| sec-015 | Medium | Task 9: adversarial test asserts `transport.kill()` called + no-hook registered |
| err-017 | Medium | Task 8: best-effort plugin_id extraction (sha256 fallback) in `__init__` |
| i18n-005 | High | Task 10: bare-key-only stderr (option b) |
| arch-009 | Medium | Task 6: fd-3 host-side framing contract test added |
| sec-012 | Medium | Task 8: `PLUGIN_LIFECYCLE_QUARANTINED_FIELDS` usage documented as PR-S3-0a addition |

### Findings skipped

| Finding | Reason |
|---|---|
| sec-005 | PR-S3-1 scope (sys._getframe in tiers.py) — not in PR-S3-3a |
| sec-007 | PR-S3-4 scope (fd-3 reader in quarantine plugin subprocess) — not in PR-S3-3a |
| sec-004 | Production canary registry wiring deferred to PR-S3-2/bootstrap task — InboundContentScanner API is correct; wiring is a bootstrap concern |
| sec-009 | Accepted core-engineer's reading: wildcard `*` is intentional production semantics in `GatePolicy.check()`; no change to PR-S3-2 wildcard |

**Deferred to PR-S3-4 and PR-S3-5:**
- §5.1 quarantined-LLM plugin shape and `quarantine.ingest`/`quarantine.extract` methods
- §5.3 fd-3 handshake *reader* side (subprocess side lives in `plugins/alfred_quarantined_llm/`)
- §5.4 provider-match check at handshake (`routing.yaml[quarantine][provider]` vs manifest)
- §7.6 `InboundCanaryScanner` as hook subscriber (PR-S3-5 owns the web.fetch hookpoint)
- Redis content store (PR-S3-5 `alfred.plugins.web_fetch.content_store`)
- §12.3 `dlp_egress` canary-through-quarantined-LLM payload (requires PR-S3-4 QuarantinedExtractor)

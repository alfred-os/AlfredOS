# Runbook: quarantined-LLM plugin (Slice 3)

**Status:** shipped in Slice 3 / PR-S3-4 (#TBD)
**Spec:** [§5–§7 of the Slice-3 design](../superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md)
**ADR:** [ADR-0017 Decision 4 + Decision 7](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md)
**Glossary:** [alfred_quarantined_llm](../glossary.md#alfred_quarantined_llm), [quarantine.extract](../glossary.md#quarantineextract), [ExtractionMode](../glossary.md#extractionmode), [TypedRefusalReason](../glossary.md#typedrefusalreason)

This runbook covers the production setup and debugging of the
`alfred_quarantined_llm` MCP plugin — the subprocess that is the sole
legitimate processor of T3 content in AlfredOS (spec §3.4, PRD §7.1). It is
written for operators deploying Slice 3. Container isolation (via `bwrap`
policy) ships in Slice 4 per [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md);
until then the subprocess runs with UID separation only.

## Plugin manifest contract

The plugin manifest is at `plugins/alfred_quarantined_llm/manifest.toml`.
Three fields are load-bearing:

| Field | Required value | Why |
|---|---|---|
| `alfred.manifest_version` | `1` | ADR-0017 Decision 7 — the `schema_version: Literal[1]` anchor that the audit row family pins |
| `plugin.subscriber_tier` | `"system"` | grants orchestrator-internal hookpoints (`security.quarantined.extract`); `"operator"` or `"user-plugin"` would deny these hookpoints at the capability gate |
| `plugin.sandbox_profile` | `"user-plugin"` | the subprocess runs under the OS-level user-plugin sandbox even though its subscriber tier is `"system"` — two-axis independence (spec §4.3) |

The plugin id on the wire is `"alfred.quarantined-llm"` (hyphen, not
underscore). Audit-graph join keys use this string verbatim; drift breaks
forensic queries.

A manifest presenting `manifest_version != 1` raises `ManifestVersionError`
before any capability-gate check, emitting a `plugin.lifecycle.load_refused`
audit row. A manifest with `subscriber_tier` set to any T0–T3 string raises
`ManifestTierError` — this is the tier-laundering guard (see
[docs/subsystems/security.md](../subsystems/security.md#two-axis-naming-invariant)).

## Provider configuration (`config/routing.yaml [quarantine]`)

```yaml
quarantine:
  provider: "anthropic"        # anthropic | deepseek | openai
  model: "claude-haiku-3-5"   # fast + cheap; adequate for structured extraction
  secret_id: "quarantine_provider_api_key"
```

`provider` drives which `ProviderCapability` flags the plugin advertises,
which determines the `ExtractionMode` the dispatch path selects:

| `provider` | `ProviderCapability` | `ExtractionMode` |
|---|---|---|
| `anthropic` | `NATIVE_CONSTRAINED_GENERATION` | `native_constrained` |
| `deepseek` (chat model) | `JSON_OBJECT_MODE` | `json_object_unconstrained` |
| `openai` or unknown model | none | `prompt_embedded_fallback` |

The quarantined provider **should** differ from the privileged provider
(defence-in-depth, spec §5.4). If both sides use the same provider, a
compromised provider API could see both T0–T2 orchestrator context and T3
raw content at the same time — the failure mode that the split exists to
prevent.

Changing `provider` or `secret_id` is a reviewer-gated configuration change
(`alfred config quarantined-provider <provider>`); it lands via the
state.git proposal flow (spec §11.1). `model` changes are lower blast-radius
but still flow through the same gate.

## Environment setup

### Env vars and secret broker

The secret broker's env backend resolves `ALFRED_<UPPERCASED_SECRET_ID>`.
For the default `secret_id: "quarantine_provider_api_key"`:

```
ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-ant-...
```

The literal key never appears in `config/routing.yaml` — the file holds only
the broker ID. The broker substitutes the key at subprocess spawn time,
delivering it over fd 3 (spec §5.3). See `.env.example` for the template.

### macOS development

On macOS, UID separation is not enforced in `ALFRED_ENV=development` mode.
The launcher skips `runuser` and spawns the plugin subprocess as the
invoking user. Set `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` alongside
`ALFRED_ENV=development` to skip the sandbox policy file check:

```
ALFRED_ENV=development
ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1
```

The supervisor emits a `supervisor.config_insecure` audit JSON line each
time the launcher runs in this mode. Treat the presence of that line in
production as a misconfiguration alert.

### Linux production

1. Create the `alfred-quarantine` OS user (single-use, no login shell):

```bash
# systemd-sysusers fragment — place in /etc/sysusers.d/alfred.conf
u alfred-quarantine - "AlfredOS quarantine LLM user" /nonexistent /usr/sbin/nologin
```

2. Set `ALFRED_PLUGIN_UID=alfred-quarantine` (default; only needed if you
   chose a different name).

3. Provision the sandbox policy directory. The launcher reads
   `<ALFRED_SANDBOX_POLICY_DIR>/<plugin_id>.policy`; it refuses to spawn if
   the file is absent (fail-closed). Default dir: `/etc/alfred/sandbox`.

```bash
mkdir -p /etc/alfred/sandbox
# Write the user-plugin bwrap policy for the quarantined-LLM plugin.
# The policy file format is defined by bin/alfred-plugin-launcher.sh.
# Slice 4 (ADR-0015) replaces this with the full bwrap container policy.
```

4. Confirm the setup by running the smoke test:

```bash
uv run pytest tests/smoke -k quarantine -v
```

## Audit-row debugging cookbook

### Filter quarantine.extract events

```bash
alfred audit log --event quarantine.extract --since 1h
```

Key fields in each row:

| Field | Meaning |
|---|---|
| `extraction_mode` | `native_constrained` / `json_object_unconstrained` / `prompt_embedded_fallback` / `refused` |
| `result` | `extracted` / `refused` / `protocol_violation` |
| `schema_name` | which `ExtractionSchema` subclass was used |
| `schema_version` | always `1` in Slice 3 |
| `correlation_id` | ties the extract row to the matching downgrade row |
| `trust_tier_of_trigger` | always `T3` for quarantine rows |

### Filter T3-derived downgrade events

A `quarantine.t3_derived_downgrade` row is written every time
`downgrade_to_orchestrator()` succeeds. Match it to the extraction via
`correlation_id`:

```bash
alfred audit log --event quarantine.t3_derived_downgrade --since 1h
```

Key fields: `source_tier` (`T3_derived`), `target_tier` (`T2`),
`downgrade_reason` (`structured_extraction_consumed`), `downgrade_explicit`
(`true`). The payload values are never in these rows — only provenance
metadata.

### Filter protocol violations

```bash
alfred audit log --event quarantine.protocol_violation --since 24h
```

A protocol violation means the plugin returned a response the host could not
parse as a valid `ExtractionResult`. Causes: unexpected `kind` field, non-
`ControlResult` response shape, or a plugin that has drifted from the wire
contract. Check the plugin version and manifest against the host version.

## TypedRefusal interpretation

When the extraction result is a `TypedRefusal`, the `reason` field is one of:

| Reason | Meaning | Operator action |
|---|---|---|
| `cannot_extract` | Retries exhausted — the model could not produce a schema-valid response | Check `schema_name` in the audit row; schema may be too complex for `prompt_embedded_fallback` mode; consider switching to a provider with `NATIVE_CONSTRAINED_GENERATION` |
| `refused_by_safety` | Provider safety filter blocked the extraction | The T3 content likely contains material the provider refuses; log the source URL (forensic; never re-fetch for inspection) |
| `ambiguous_input` | Input is schema-incompatible — content cannot be parsed into the declared schema | Review the `ExtractionSchema` definition; the schema may be too narrow for the input type |
| `provider_refused` | Structured provider-level refusal (not a safety filter) | Check provider status dashboard; may be a quota or policy change |
| `provider_unavailable` | Circuit breaker tripped or supervisor down | Check `supervisor.capability_gate_unavailable` audit rows; verify the quarantined-LLM subprocess is running |
| `dlp_outbound_refused` | Outbound DLP blocked the extraction result | The extraction result contained a pattern matching an active DLP rule; check `dlp.outbound_redacted` rows with matching `correlation_id` |
| `nonce_check_failed` | Handle-id nonce mismatch — the `ContentHandle` was already consumed or forged | Check for double-extract or replay attempts; the content store's single-use invariant fired (spec §7.2) |

## Failure modes

| Trigger | Behaviour | Observable signal |
|---|---|---|
| `manifest_version != 1` | `ManifestVersionError`; subprocess never starts | `plugin.lifecycle.load_refused` audit row |
| `subscriber_tier = "T3"` | `ManifestTierError`; subprocess never starts | `plugin.lifecycle.load_refused` audit row |
| Missing sandbox policy file (production) | Launcher exits non-zero; subprocess never starts | `plugin.lifecycle.load_refused` + structlog `plugin.launcher.policy_missing` |
| fd-3 key read fails (short read / framing error) | Subprocess exits with status 1 before MCP loop starts | `plugin.lifecycle.crashed` + `breaker_state=CLOSED` audit row |
| `provider_unavailable` (circuit breaker OPEN) | `TypedRefusal(reason="provider_unavailable")`; extractor returns immediately | `quarantine.extract` row with `result=refused`; `supervisor.breaker.tripped` row |
| `quarantine.extract` unexpected kind | `PluginProtocolViolation` raised; caller sees exception | `quarantine.protocol_violation` audit row emitted before raise |
| `downgrade_to_orchestrator` gate denied | `AlfredError` raised; no downgrade audit row | Gate's own `security.capability_gate.*` audit family |
| `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` in production | Refused unconditionally (sec-003) | Launcher exits non-zero; `supervisor.config_insecure` audit line if reached |

## Cross-references

- [PRD §7.1](../../PRD.md#71-security--prompt-injection-defense) — dual-LLM split design requirement.
- [Spec §5–§7](../superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md) — quarantined-LLM subprocess contract.
- [ADR-0017 Decision 7](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — `schema_version: Literal[1]` anchor.
- [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md) — Slice-4 container isolation.
- [docs/subsystems/security.md](../subsystems/security.md) — quarantine boundary public surface.
- Glossary: [alfred_quarantined_llm](../glossary.md#alfred_quarantined_llm), [quarantine.ingest](../glossary.md#quarantineingest), [quarantine.extract](../glossary.md#quarantineextract), [ExtractionMode](../glossary.md#extractionmode), [TypedRefusalReason](../glossary.md#typedrefusalreason), [QuarantinedExtractor](../glossary.md#quarantinedextractor), [dual-LLM split](../glossary.md#dual-llm-split).

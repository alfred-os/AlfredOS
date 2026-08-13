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

The plugin manifest is at `src/alfred/security/quarantine_child/manifest.toml`.
Three fields are load-bearing:

| Field | Required value | Why |
| --- | --- | --- |
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
  provider: "anthropic"        # anthropic | deepseek
  model: "claude-haiku-4-5"   # fast + cheap; adequate for structured extraction
  secret_id: "quarantine_provider_api_key"
```

This `routing.yaml` value does **not** drive runtime capability advertisement
— no loader reads it yet ("slice 4+"). The actual runtime source of truth is
the `ALFRED_QUARANTINE_PROVIDER` .env setting (`Settings.quarantine_provider`,
default `"anthropic"`), which determines which `ProviderCapability` flags the
plugin advertises, which in turn determines the `ExtractionMode` the dispatch
path selects:

| `ALFRED_QUARANTINE_PROVIDER` | Declared `ProviderCapability` | `ExtractionMode` |
| --- | --- | --- |
| `anthropic` | `NATIVE_CONSTRAINED_GENERATION` | `native_constrained` |
| `deepseek` (`deepseek-chat`) | `JSON_OBJECT_MODE`, `TOOL_USE` | `prompt_embedded_fallback` |
| `deepseek` (`deepseek-reasoner`, or any unknown model) | none | `prompt_embedded_fallback` |

Both DeepSeek rows land on `prompt_embedded_fallback` because dispatch selects
the mode on `NATIVE_CONSTRAINED_GENERATION` alone — neither `JSON_OBJECT_MODE`
nor `TOOL_USE` participates in that decision, so `deepseek-chat`'s two declared
capabilities are advertised but unused on the quarantine path. They are listed
here because this table's job is to state what each provider actually declares
(`_DEEPSEEK_MODEL_CAPABILITIES` in `src/alfred/providers/deepseek.py`); reading
"none" for `deepseek-chat` would be simply wrong.

`routing.yaml [quarantine].provider` stays as the alfred-config-proposal
target (the state.git reviewer-gate flow below) and as documentation of the
shipped default, but changing it alone does nothing until the loader lands.

The quarantined provider **should** differ from the privileged provider by
default (defence-in-depth, ADR-0064). If both sides use the same provider, a
compromised provider API could see both T0–T2 orchestrator context and T3
raw content at the same time — the failure mode that the split exists to
prevent. This is **opt-in**, not enforced by default: set
`ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=true` to make AlfredOS refuse
to boot on a same-provider collision. Left at its default (`false`),
same-provider is permitted — logged and audited once per boot, not blocked.
See [ADR-0064](../adr/0064-quarantine-provider-separation-is-opt-in.md) for
the full rationale (no PRD section states a "providers must differ"
invariant — do not cite "spec §5.4 / PRD §6.4").

**Which knob actually controls runtime behaviour today: `ALFRED_QUARANTINE_PROVIDER`,
and only that one.** It is a plain, ungated `.env` setting — set it, restart, done. The
reviewer-gated `alfred config quarantined-provider <provider>` flow described immediately
below is **aspirational**: that `state.git` proposal flow does not exist yet, and even
once it does it targets `routing.yaml [quarantine].provider`, which no loader reads
(see the "does **not** drive runtime capability advertisement" note above). Read the next
paragraph as the intended future shape, not as a step you can perform now — and do not
read it as a gate protecting the provider choice, because there is none. ADR-0064's
Alternatives section records why that flow was not adopted as the mechanism for this
decision.

Changing `routing.yaml [quarantine].provider` or `secret_id` is intended to be a
reviewer-gated configuration change (`alfred config quarantined-provider
<provider>`), landing via the state.git proposal flow (spec §11.1). `model`
changes are lower blast-radius but still flow through the same gate.

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

> **The key must match `ALFRED_QUARANTINE_PROVIDER`, and nothing checks that it does.**
> This is one shared variable serving both providers, so its correct content depends
> entirely on the current `ALFRED_QUARANTINE_PROVIDER` value:
>
> | `ALFRED_QUARANTINE_PROVIDER` | `ALFRED_QUARANTINE_PROVIDER_API_KEY` must be |
> | --- | --- |
> | `anthropic` (default) | an Anthropic key (`sk-ant-…`) |
> | `deepseek` | a **separate** DeepSeek key — not a copy of `ALFRED_DEEPSEEK_API_KEY` |
>
> It is never derived from, defaulted to, or forwarded from the privileged path's
> `ALFRED_DEEPSEEK_API_KEY` / `ALFRED_ANTHROPIC_API_KEY`. Reusing the privileged
> DeepSeek key here puts both halves of the dual-LLM split on one provider account —
> the exact posture [ADR-0064](../adr/0064-quarantine-provider-separation-is-opt-in.md)
> makes an explicit, opt-out-able choice rather than an accident.
>
> **There is no key-shape validation and a mismatch is NOT caught at boot.** Boot checks
> only that the variable is non-empty (`quarantine_provider_key_unset`); a key belonging to
> the other provider passes every startup check. It surfaces at the **first extraction**, as
> a generic `provider_unavailable` typed refusal — not as a boot error, and not with any
> message naming the key. The provider's own error text is deliberately withheld from that
> refusal and from the host-side log line: the quarantine child handles T3 (untrusted)
> content and provider error strings can echo request fragments, so carrying them across
> that boundary is a leak channel (see the `quarantine.child.provider_unavailable` log
> site in `src/alfred/security/quarantine_child/provider_dispatch.py`, which omits the
> exception message for exactly this reason). That redaction is working as intended, not a
> reporting bug. **Triage rule:** extractions failing immediately after a provider switch,
> with a healthy boot, means check this key first.

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
| --- | --- |
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
| --- | --- | --- |
| `cannot_extract` | Retries exhausted — the model could not produce a schema-valid response | Check `schema_name` in the audit row; schema may be too complex for `prompt_embedded_fallback` mode; consider switching to a provider with `NATIVE_CONSTRAINED_GENERATION` |
| `refused_by_safety` | Provider safety filter blocked the extraction | The T3 content likely contains material the provider refuses; log the source URL (forensic; never re-fetch for inspection) |
| `ambiguous_input` | Input is schema-incompatible — content cannot be parsed into the declared schema | Review the `ExtractionSchema` definition; the schema may be too narrow for the input type |
| `provider_refused` | Structured provider-level refusal (not a safety filter) | Check provider status dashboard; may be a quota or policy change |
| `provider_unavailable` | An infrastructure fault, not a model-output failure: a circuit breaker trip / supervisor down, an SDK outage, an un-brokered egress socket, or the attempt budget exhausted inside `bind()` (#472). All four collapse onto this one reason. | Check `supervisor.capability_gate_unavailable` audit rows and verify the quarantined-LLM subprocess is running. The `quarantine.child.provider_unavailable` structlog line marks each occurrence; its `remaining_budget_s` near zero points at the budget-exhaustion sub-case. The exception message is deliberately NOT logged (an SDK-origin error can echo T3 request fragments), so the sub-faults are not further discriminated in the log. |
| `dlp_outbound_refused` | TOMBSTONE — no live emit site uses this token; retained for forensic-history continuity. Post-stage DLP refusals now surface as `post_stage_refused`. | None — historical records only |
| `post_stage_refused` | A post-stage subscriber on `security.quarantined.extract` refused the validated payload (the DLP subscriber's canary trip is the canonical case). The `quarantine.extract` audit row's `refusing_hook_id` field carries the refusing subscriber's identity. | Inspect `subject.refusing_hook_id` on the `quarantine.extract` row to identify the refusing subscriber. For the DLP subscriber (`security.quarantined.extract.post.dlp`), check `dlp.outbound_redacted` rows with matching `correlation_id` |
| `nonce_check_failed` | Handle-id nonce mismatch — the `ContentHandle` was already consumed or forged | Check for double-extract or replay attempts; the content store's single-use invariant fired (spec §7.2) |

## Failure modes

| Trigger | Behaviour | Observable signal |
| --- | --- | --- |
| `manifest_version != 1` | `ManifestVersionError`; subprocess never starts | `plugin.lifecycle.load_refused` audit row |
| `subscriber_tier = "T3"` | `ManifestTierError`; subprocess never starts | `plugin.lifecycle.load_refused` audit row |
| Missing sandbox policy file (production) | Launcher exits non-zero; subprocess never starts | `plugin.lifecycle.load_refused` + structlog `plugin.launcher.policy_missing` |
| fd-3 key read fails (short read / framing error) | Subprocess exits with status 1 before MCP loop starts | `plugin.lifecycle.crashed` + `breaker_state=CLOSED` audit row |
| `provider_unavailable` (circuit breaker OPEN) | `TypedRefusal(reason="provider_unavailable")`; extractor returns immediately | `quarantine.extract` row with `result=refused`; `supervisor.breaker.tripped` row |
| `quarantine.extract` unexpected kind | `PluginProtocolViolation` raised; caller sees exception | `quarantine.protocol_violation` audit row emitted before raise |
| `downgrade_to_orchestrator` gate denied | `AlfredError` raised; no downgrade audit row | Gate's own `security.capability_gate.*` audit family |
| `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` in production | Refused unconditionally (sec-003) | Launcher exits non-zero; `supervisor.config_insecure` audit line if reached |

> **Child stderr diagnostics (#251).** When a spawn/extract failure above manifests
> as a torn or timed-out reply (e.g. the launcher refuses — "Missing sandbox policy
> file" / "fd-3 key read fails" rows), the host now drains the quarantined child's
> stderr and surfaces the child-side reason in the **`child_stderr` field** of a
> **`security.quarantine_child.child_stderr`** structlog event (logged at `error` on
> the `read_frame` failure path, alongside the `security.quarantine_child.read_frame_failed`
> event; at `warning` on teardown). Filter on the event name; read the reason from the
> `child_stderr` field. If the drain itself fails, look for the
> `security.quarantine_child.stderr_drain_failed` event (carries an `error_class`
> field). The `child_stderr` value is bounded (`…[truncated]` marks an over-cap clip),
> control/format-char-stripped (no forged log lines / terminal-escape / bidi spoof),
> and secret-redacted — so it may show sanitized T3-derived text; treat it as
> operational-log-tier, not audit.

> **Durable launcher-refusal audit row (#433, ADR-0051).** A launcher
> **sandbox** refusal — `kind="full"` quarantine spawn refused pre-`exec` (e.g.
> "Missing sandbox policy file" above) — now also persists a durable
> `supervisor.plugin.sandbox_refused` audit row, queryable via:
>
> ```bash
> alfred audit log --event supervisor.plugin.sandbox_refused --since 24h
> ```
>
> The row carries the closed-vocabulary `reason` field explaining *why* the
> launcher refused — e.g. `environment_not_set`, `sandbox_block_missing`,
> `policy_ref_*`, `bind_source_too_broad`, `interpreter_prefix_too_broad`.
> Previously operators had only the transient
> `security.quarantine_child.child_stderr` structlog line to go on; that line
> is still emitted, but for durable, queryable diagnosis of a launcher
> sandbox refusal, check the audit row first. A crash of the already-exec'd
> child (not a launcher refusal) does not produce this row — it remains
> `child_stderr`-only, per the launcher-vs-child authorship split above.

## Cross-references

- [PRD §7.1](../../PRD.md#71-security--prompt-injection-defense) — dual-LLM split design requirement.
- [Spec §5–§7](../superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md) — quarantined-LLM subprocess contract.
- [ADR-0017 Decision 7](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — `schema_version: Literal[1]` anchor.
- [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md) — Slice-4 container isolation.
- [docs/subsystems/security.md](../subsystems/security.md) — quarantine boundary public surface.
- Glossary: [alfred_quarantined_llm](../glossary.md#alfred_quarantined_llm), [quarantine.ingest](../glossary.md#quarantineingest), [quarantine.extract](../glossary.md#quarantineextract), [ExtractionMode](../glossary.md#extractionmode), [TypedRefusalReason](../glossary.md#typedrefusalreason), [QuarantinedExtractor](../glossary.md#quarantinedextractor), [dual-LLM split](../glossary.md#dual-llm-split).

# Slice 4 — design spec

> **Slice 4 = PRD §5 line 117 hybrid-isolation closure + comms-MCP rewrite + Slice-3 carryover closure.**
> Status: design — pre-`/review-pr`.
> Authoring date: 2026-06-06.
> Load-bearing precedents: [ADR-0014](../../adr/0014-pluggable-hooks-for-every-action.md), [ADR-0015](../../adr/0015-slice4-containerised-quarantined-llm.md), [ADR-0016](../../adr/0016-slice4-discord-tui-comms-mcp-rewrite.md), [ADR-0017](../../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md), [ADR-0018](../../adr/0018-state-git-proposal-writer-consolidation.md), [ADR-0020](../../adr/0020-supervisor-cli-access-via-postgres-and-state-git.md), [ADR-0021](../../adr/0021-merged-proposal-branch-dispatch-for-side-effecting-proposals.md).
> New ADRs landed by this spec (all in PR-S4-0a): ADR-0022 recoverable-carrier semantic for error-stage hookpoint dispatch; ADR-0023 mtime-polled hot-reload for `config/policies.yaml`; ADR-0024 comms-MCP wire contract.

---

## 0. Summary

Slice 4 closes the time-bounded relaxations Slice 3 took. The two non-negotiable PRD commitments — ADR-0015 (containerised quarantined-LLM) and ADR-0016 (Discord+TUI comms-MCP rewrite) — both land in this slice; both ADRs **flip their status from Proposed to Accepted at PR-S4-11 graduation** (mirroring the Slice-3 precedent that ADR status mirrors implementation reality). The slice also absorbs five Slice-3 carryover follow-ups (#174 daemon boot, #173 OutboundDlp into proposal-dispatch failure detail, #170 recoverable-carrier dispatch semantic, #159 hot-reload of `config/policies.yaml`, #153 operator-user-id attribution via a minimal CLI session-file login), closes two issues that were blocked on Slice-4 infrastructure (#152 comms-MCP identity-boundary real-entry test, #153 named above), and explicitly defers #167 per-kind `fail_closed` to Slice 5.

The slice ships as 12 PRs, mirroring the Slice-3 shape. PR-S4-0a/0b are foundations (docs+ADRs / migrations+infra); PR-S4-1 through PR-S4-7 are the carryover + sandbox tracks; PR-S4-8 through PR-S4-10 are the comms-MCP rewrite track; PR-S4-11 is the graduation PR. Discord (PR-S4-9) merges before TUI (PR-S4-10) so the in-process `CommsAdapter` Protocol can be deleted atomically with PR-S4-10's narrowing of the ADR-0009 caveat (the in-process adapters that ADR-0009 documented are then gone; ADR-0009 itself was already marked "Superseded by ADR-0016 (for new adapters)" in Slice 3 — Slice 4 removes the "for new adapters" qualifier, see §8.9).

The PRD §5 line 117 hybrid-isolation invariant — "Plugins declare a trust tier; official → in-process subprocess; third-party or agent-authored → containerized with declared capabilities" — is fully satisfied on Slice-4 graduation.

---

## 1. Scope

### 1.1 In-scope

Listed at the granularity the PR breakdown consumes; each item maps to a PR in §14.

1. **Daemon boot + production dispatch (#174).** `Supervisor(state_git_path=Settings.state_git_path)` is constructed at the production boot path. The merged-proposal dispatch loop runs in deployed AlfredOS instances. PR-S4-1.
2. **`OutboundDlp.scan` into `processed_proposals.failure_detail` (#173).** Threads `OutboundDlpProtocol` through `ProposalContext`; renames `_truncated_detail` → `_redacted_detail`; runs DLP scan then truncates the redacted result to 512 chars. PR-S4-2.
3. **Recoverable-carrier semantic for error-stage hookpoint dispatch (#170 / ADR-0022).** `alfred.hooks.invoke._run_error(...)` returns `ErrorOutcome = ReRaise() | SubstituteResult(payload, source_tier)`. Sibling sites (`alfred.memory.episodic.record`, `alfred.identity._ingest`, `alfred.security.quarantine.QuarantinedExtractor.extract`) migrate. Substituted T3 carriers refused with audit row. PR-S4-3.
4. **mtime-polled hot-reload for `config/policies.yaml` (#159 / ADR-0023).** `PolicyWatcher` polls at 1s default; `PoliciesV1` Pydantic model; `PoliciesSnapshot` immutable ref; consumers (`RateLimitConfig`, `HandleCapConfig`, `ContentStore`, quarantined-provider config) migrate to snapshot-ref deref pattern. Low-blast keys hot-reload; high-blast keys refuse with audit row. PR-S4-4.
5. **CLI operator session.** `alfred login --as <user>` / `alfred logout` / `alfred whoami`; session file at `~/.config/alfred/session` (mode 0600, short-lived token + canonical `user_id` + 12h expiry + host binding); `_resolve_operator(ctx) -> UserId` is the single helper every operator-attributed CLI command uses. Closes #153 by attributing `operator_user_id` from the session. PR-S4-5.
6. **Sandbox containerisation foundations (ADR-0015 launcher hardening).** Plugin manifest gains a `sandbox` block; `bin/alfred-plugin-launcher` resolves per-plugin policy at spawn time; production-refuse-without-policy + dev escape hatch refuse-in-production semantics; per-plugin policy declaration shape. PR-S4-6.
7. **Sandbox policy bytes (ADR-0015 per-OS policies).** Linux bwrap policy + macOS sandbox-exec policy + Windows stub policy; per-OS integration tests; adversarial sandbox-escape corpus entry. Quarantined-LLM plugin's manifest migrates from `kind: none` (Slice-3 UID-separated baseline) to `kind: full`. PR-S4-7.
8. **Comms-MCP foundations (ADR-0016 / ADR-0024 wire contract).** Wire-contract schemas; host-side `process_inbound_message` entrypoint; `IdentityResolver` callback wire type; `AlfredPluginSession` `inbound.message` notification handler; reference plugin upgraded; real identity-boundary test via the real entry path. Closes #152. PR-S4-8.
9. **Discord adapter as MCP plugin (ADR-0016 Discord).** `plugins/alfred_discord/` ships; embeds/attachments/polls T3-promotion happens at `StdioTransport.InboundContentScanner` (Slice-3-shipped class, extended by behaviour); rate-limit signalling per ADR-0024; per-platform identity binding via host-side `IdentityResolver` callback. Legacy `src/alfred/comms/discord/` stays dormant (AST-test forbids imports). PR-S4-9.
10. **TUI adapter as MCP plugin + in-process `CommsAdapter` Protocol deletion (ADR-0016 TUI + flag-day).** `plugins/alfred_tui/` ships; `alfred chat` spawns the TUI plugin via `bin/alfred-plugin-launcher`; `src/alfred/comms/` directory deleted; ADR-0009 caveat narrowed (the "for new adapters" qualifier is removed now that in-process adapters are gone — *not* a status flip; see §8.9 + docs-001 closure); AST test rewired to assert absence rather than non-import. PR-S4-10.
11. **Graduation.** `docs/subsystems/{security,comms,supervisor,policies}.md` updated for Slice-4 surface; `docs/glossary.md` final additions; operator migration runbook (`docs/runbooks/slice-4-graduation.md`); release-note candidate; required-check manifest updated. PR-S4-11.

### 1.2 Out-of-scope (explicitly deferred)

- **#167 per-kind `fail_closed` override on `HookpointMeta`.** Deferred because no current consumer demands the asymmetric policy. Revisit when a Slice-5 hookpoint's error stage routinely runs cleanup that should not fail-close.
- **Full step-up auth (PRD §7.1).** Out-of-band Discord/Telegram DM confirmation for high-blast actions. The minimal CLI session-file login lands here; the step-up auth orchestration is its own design and depends on the comms-MCP rewrite being in production.
- **Inter-persona bus + persona-system multi-persona behaviour.** PRD §5 / §6.8. Slice 5+.
- **Memory consolidation full pipeline + auto-retrieve.** Slice 2.5's episodic POC remains current; consolidation + semantic-facts + graph + vector retrieval pipeline is Slice 5+.
- **`alfred cost report` CLI.** Closed PR #110 confirmed Slice 4+ deferral. Roll into Slice 5.
- **Slice-3 broker-hardening backlog** (typed `SecretRef`, broker-side post-substitution invariant check, per-secret-ID canaries, audit-log secret-ID match assertion). Continues to be carried as the Slice-5 backlog; no Slice-4 PR touches the broker beyond what the session helper requires.
- **`watchdog` migration for `PolicyWatcher`.** Slice 4 ships mtime polling at 1s. The inotify/FSEvents/ReadDirectoryChangesW migration is Slice 5+ once an operator surfaces a real polling-latency complaint.
- **`alfred sandbox lint <plugin>` CLI.** Validates a third-party plugin's declared `sandbox.policy_ref` against the resolver without spawning. Useful once third-party plugins arrive; deferred.

### 1.3 Scope budget

Twelve PRs, mirroring Slice 3's PR count. The PR-S4-0 split rationale matches Slice 3's: 0a is docs/ADRs/constants (pure prose + `Final` frozensets, no runtime dispatch), 0b is migrations/infra/i18n (executable, runs Alembic + Postgres + mypy + pybabel + `docker compose build`). 0a must merge before 0b because the `audit_row_schemas.py` constants are the source of truth for the migration table.

The critical path through dependencies is seven PRs deep: `0a → 0b → 5 → 8 → 9 → 10 → 11`. After 0b merges, six independent threads can begin in parallel: PR-S4-1, PR-S4-3, PR-S4-4, PR-S4-5, PR-S4-6 (PR-S4-2 trails S4-1; PR-S4-7 trails S4-6). The comms-MCP track (5 → 8 → 9 → 10) carries the longest sequential chain because each PR depends on the prior one's contract surface.

---

## 2. Cross-cutting wire-format ADR section

### 2.1 `OutboundDlp.scan` placement on every Slice-4 wire

Slice 3 established that `OutboundDlp.scan` runs at the transport boundary, not in-handler. Slice 4 extends this discipline to three new wire surfaces. Each wire emits **two disjoint audit-row classes** — a *redaction-on-success* row (DLP found nothing or redacted patterns; the write proceeds) and a *refusal* row (DLP refuses the write entirely; the underlying operation aborts). This split closes the rev-002 / arch-004 / sec-005 finding that the original spec conflated the two outcomes.

| Wire | DLP application | Success row (always emitted) | Refusal row (refusal aborts write) |
|---|---|---|---|
| `processed_proposals.failure_detail` write (PR-S4-2) | Scan failure detail string before truncating to 512 chars | `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` (carries `dlp_redactions_count`; ≥0) | `DLP_OUTBOUND_REFUSED_FIELDS` (Slice-3 constant; reused — canary hit aborts write) |
| `comms-MCP outbound.message` (PR-S4-9 wire) | Scan outbound body + attachment metadata before serialising to JSON-RPC | (host-side existing `OUTBOUND_REDACTED_FIELDS` Slice-3 reused) | `DLP_OUTBOUND_REFUSED_FIELDS` |
| `operator.session.created` audit row (PR-S4-5) | Scan platform identifier fields (Discord snowflake / Telegram chat_id) before write | `OPERATOR_SESSION_CREATED_FIELDS` (DLP-clean assumption; auditor refuses write on redaction) | `DLP_OUTBOUND_REFUSED_FIELDS` |

In every refusal case the operation refuses to complete and the supervisor breaker increments. The dual-LLM split's "T3 content never reaches the privileged orchestrator" invariant remains the load-bearing security property; DLP refusal is the secondary defence layer for accidental egress.

---

## 3. Daemon boot + production dispatch (#174 + #173)

### 3.1 `alfred.cli.main` daemon entry

Slice 3's `Supervisor` exposes an opt-in `state_git_path` kwarg that wires the proposal dispatch loop into its `TaskGroup`. Until Slice 4, no production boot path constructs `Supervisor(state_git_path=…)`. Slice 4 closes this at the `alfred` CLI daemon entrypoint.

**Decision: the daemon entry is `alfred daemon start`.** This is a new CLI subcommand (not a flag on an existing command) that boots the full Slice-4 stack: identity resolver, persona registry, supervisor with dispatch loop, comms-MCP launcher, hot-reload watcher. `alfred daemon stop` and `alfred daemon status` ship alongside.

**Relationship to `alfred status`** (devex-004 closure): `alfred status` (Slice-1 shipped) is the operator's *general health overview* — settings, providers, memory, identity, persona, supervisor breaker. `alfred daemon status` is the *boot-process subset* — daemon PID, uptime, boot-id, last `daemon.boot.completed` audit, current task-group stack. The two have explicit cross-reference in their `--help` text: `alfred status` says "for daemon-specific status see `alfred daemon status`"; `alfred daemon status` says "for general health see `alfred status`".

The Slice-3 `alfred chat` TUI subcommand stays valid; in Slice 4 it spawns its own subprocess via `bin/alfred-plugin-launcher` (per §8.7).

`Supervisor` is constructed as (kwarg names match the current `src/alfred/supervisor/core.py` constructor — core-001 closure):

```python
supervisor = Supervisor(
    session_scope=session_scope,
    gate=real_gate,
    audit=audit_writer,
    state_git_path=settings.state_git_path,
    proposal_dispatch_interval_s=settings.proposal_dispatch_interval_s,
    # New in Slice 4:
    policies_ref=policies_ref,                       # §5
    operator_session_resolver=resolve_operator,      # §6
)
```

The Slice-4-introduced kwargs (`policies_ref`, `operator_session_resolver`) are additive; the Slice-3 kwargs are unchanged. PR-S4-1 adds the two new kwargs to the `Supervisor.__init__` signature.

**Boot sequence ordering** (core-002 closure): pre-`Supervisor` construction, **the daemon CLI entrypoint** (`alfred.cli.daemon` — host-side CLI, NOT `Supervisor.start()`) runs three probes in order — `(a) launcher policy-resolving probe, (b) snapshot-ref initialisation, (c) capability-gate sync handshake`. Failure of any probe raises before the `Supervisor` is constructed and before its `TaskGroup` opens; there is no partial-start state to drain. Only after the three probes succeed does the CLI construct `Supervisor` (which internally calls `Supervisor.start()` to open its TaskGroup) and emit `daemon.boot.completed`. The probe orchestration is CLI-side because `Supervisor.start()` is TaskGroup-first by current shape (core-007 closure — Slice-3 `Supervisor` has no pre-flight probe phase; PR-S4-1 adds the probes to the CLI layer, not to `Supervisor`). The launcher probe itself is a no-op stub in PR-S4-1 and gains real behaviour in PR-S4-6 (arch-001 closure).

### 3.2 `daemon.boot.completed` audit row

Emitted once at successful boot. Carries `boot_id` (uuid4), `started_at`, `state_git_head_sha`, `slice_version` (literal `"4"`), `policies_snapshot_hash`. A `daemon.boot.failed` row covers the negative path with `failure_reason: Literal[...]`.

### 3.3 `OutboundDlp.scan` into `processed_proposals.failure_detail` (#173)

Slice-3 review consensus flagged `_redacted_detail` in `src/alfred/state/dispatch_loop.py` as named-as-if-DLP-but-only-truncates. Slice 4 makes the name truthful.

**Change shape:**

1. Thread `OutboundDlpProtocol` through `ProposalContext` matching the `quarantine.py` extractor pattern (the in-tree precedent that Slice-3 review pointed to).
2. Rename `_truncated_detail` → `_redacted_detail` in source.
3. Body becomes: scan via `OutboundDlp.scan(detail)`, then `_truncated(redacted, max_len=512)`.
4. **Audit on both refusal AND on redactions-but-not-refusal** (sec-005 closure). `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` (new in §9) is emitted on every redact-and-truncate; it carries `dlp_redactions_count > 0` when redaction happened and `dlp_redactions_count == 0` when the detail passed clean. `DLP_OUTBOUND_REFUSED_FIELDS` (Slice-3 constant) is reserved for the *refusal* case where DLP says "do not write this row at all" — that path *aborts the write* and emits the refusal row. The two constants cover disjoint outcomes (rev-002 / arch-004 closure):
   - **DLP clean** → row written; `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` with `dlp_redactions_count=0`.
   - **DLP found redactable patterns** → row written with redactions; `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` with `dlp_redactions_count > 0`.
   - **DLP refuses the row** (e.g., canary hit) → row not written; `DLP_OUTBOUND_REFUSED_FIELDS` + supervisor breaker trips.
5. Add unit test: planted secret in detail → redacted token in stored row AND `dlp_redactions_count==1`.
6. Add adversarial corpus entries: `dispatch_loop_failure_detail_leak` (planted-secret-in-detail-redacted) AND `dispatch_loop_failure_detail_canary_refused` (planted-canary-aborts-write) under category `dlp_egress`, IngestionPath `proposal_dispatch_failure`.

**Out of scope for this PR:** the threading mechanics from `Supervisor` boot down through `ProposalContext`; the bounded `String(512)` column shape (untouched).

### 3.4 Daemon boot path interaction with sandbox launcher

The daemon construction of `Supervisor` precedes any plugin launch — including the quarantined-LLM plugin which becomes sandbox-required in PR-S4-7. The daemon boot path runs the **launcher policy-resolving probe** (see §3.1 boot-sequence ordering) before the `TaskGroup` opens. The probe shape is a stub in PR-S4-1 and gains real behaviour in PR-S4-6 (arch-001 closure — see §3.1).

Daemon refusals at boot are loud (err-005 closure):

- `failure_reason="launcher_not_policy_resolving"` — the launcher binary returns the Slice-3 stub signature.
- `failure_reason="environment_not_set"` — `Settings.environment` is not explicitly one of `Literal["development", "production", "test"]`. **`Settings.environment` is mandatory** (sec-003 closure); the boot path refuses if it is `None` or unrecognised. There is no implicit fallback to `development` or `production`. Operators set `ALFRED_ENVIRONMENT` at boot or via `/etc/alfred/environment`; absence is a hard error, not a default.
- `failure_reason="unsandboxed_env_in_production"` — `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` is set in the *daemon's own* environment AND `Settings.environment == "production"`. This is a stronger check than the per-spawn refusal in §7.4: a production daemon refuses to boot if its environment is configured to bypass sandboxing at all (err-005 closure).
- `failure_reason="snapshot_ref_init_failed"` — initial `policies.yaml` parse failed.
- `failure_reason="capability_gate_handshake_failed"` — `RealGate` cannot reach Postgres or state.git at boot.

Each refusal emits `DAEMON_BOOT_FAILED_FIELDS` and exits with non-zero status. The CLI prints the operator-translated error message (e.g., *"`ALFRED_ENVIRONMENT` is not set. Set it to `development`, `production`, or `test` before starting the daemon."* under `t("daemon.boot.environment_not_set")`).

---

## 4. Recoverable-carrier semantic for error-stage hookpoint dispatch (#170 / ADR-0022)

### 4.1 Context

ADR-0014 / §5.1 of the PRD defines four hook kinds: pre / post / error / cancel. The error chain runs when the action raises. CodeRabbit on PR #168 flagged that `_dispatch_error_chain` in `src/alfred/security/quarantine.py` does not honour `alfred.hooks.invoke`'s "first non-None wins" carrier-substitution semantic — an error subscriber that returns a substitute carrier has no way to propagate it back, because the caller's outer `raise exc` short-circuits.

The inline doc-comment in `quarantine.py` already documented the slice-scoped deferral ("Slice-4+ would honour `invoke`'s 'first non-None wins' carrier-substitution semantic"). Slice 4 lands the semantic.

### 4.2 `ErrorOutcome` discriminated union

```python
class ReRaise(BaseModel):
    """Original exception propagates."""
    model_config = ConfigDict(frozen=True)

class SubstituteResult[T](BaseModel):
    """Error subscriber produced a recovery payload that replaces the exception."""
    payload: T
    source_tier: Literal["T0", "T1", "T2", "T3"]
    subscriber_id: str
    model_config = ConfigDict(frozen=True)

type ErrorOutcome[T] = ReRaise | SubstituteResult[T]
```

The generic `T` lets each hookpoint type its substitute payload (e.g., `ExtractionResult` for `security.quarantined.extract`, `EpisodeRow` for `alfred.memory.episodic.record`).

### 4.3 `_run_error()` signature change

```python
# Before (Slice 3):
async def _run_error(
    hookpoint: HookpointName,
    exc: BaseException,
    ctx: HookContext,
) -> None: ...

# After (Slice 4):
async def _run_error[T](
    hookpoint: HookpointName,
    exc: BaseException,
    ctx: HookContext,
    carrier_type: type[T],
) -> ErrorOutcome[T]: ...
```

The caller pattern-matches the outcome:

```python
outcome = await alfred.hooks.invoke._run_error(
    hookpoint, exc, ctx, ExtractionResult,
)
match outcome:
    case ReRaise():
        raise exc
    case SubstituteResult(payload=p, source_tier=substitute_tier):
        # The action carries its own tier — the tier the surrounding flow
        # was operating at when the error happened. The substitute may only
        # MATCH OR LOWER this tier. ANY upward step (T2→T1, T1→T0, T3→anything)
        # is a trust upgrade and is refused.
        if substitute_tier > ctx.carrier_tier:        # tier comparison is strict total order T0<T1<T2<T3
            await self._audit.append_schema(
                CARRIER_SUBSTITUTION_REFUSED_FIELDS,
                hookpoint=hookpoint,
                attempted_source_tier=substitute_tier,
                carrier_tier=ctx.carrier_tier,
                reason="tier_upgrade_refused",
                refused_at=datetime.now(UTC),
            )
            raise exc
        await self._audit.append_schema(CARRIER_SUBSTITUTION_FIELDS, ...)
        return p
```

`mypy --strict` + a `Protocol` guard ensures every caller exhaustively pattern-matches.

### 4.4 Tier handling on substituted carriers

Substitute payloads must declare their source tier. The host caller refuses substitutes whose `source_tier` is **strictly greater than the surrounding carrier's declared tier** in the total order `T0 < T1 < T2 < T3` (Critical 5 closure — the Slice-3-drafted "refuse T3 only" rule silently permitted a T2 substitute on a T0/T1 hookpoint to upgrade the action's effective tier).

Examples:

- Surrounding action is at `T3` (e.g., `security.quarantined.extract`). Substitute may be `T3`, `T2`, `T1`, or `T0` — all are ≤ T3, all accepted.
- Surrounding action is at `T1` (e.g., `alfred.identity._ingest` on an operator-tier ingress). Substitute may be `T1` or `T0` — `T2` or `T3` are upgrades and refused.
- Surrounding action is at `T0` (e.g., a future T0 hookpoint). Substitute must be `T0`; any other value is refused.

The refused-substitution case emits `CARRIER_SUBSTITUTION_REFUSED_FIELDS` with `reason="tier_upgrade_refused"` and re-raises the original exception. The `CARRIER_SUBSTITUTION_REFUSED_FIELDS` audit-row constant gains a `carrier_tier` field (see §9) so forensics can see both sides of the refused upgrade.

The carrier-tier comparison uses a strict total order helper `TrustTier` in `src/alfred/security/trust_tiers.py` (Slice-3-shipped): `TrustTier("T0") < TrustTier("T3")` returns `True`. The `HookContext.carrier_tier` field is populated by the hookpoint declaration in `register_hookpoint(..., carrier_tier=...)`. **`HookpointMeta.carrier_tier` and `HookpointMeta.allow_error_substitution` are new required fields shipped in PR-S4-3, not PR-S4-0a** (rev-007 closure — these are runtime-type changes belonging in the carrier-substitution PR where they are consumed, not in the docs-foundation PR).

### 4.5 Sibling sites' migration

Four production hook-dispatch sites migrate to the new semantic in PR-S4-3:

1. `alfred.security.quarantine.QuarantinedExtractor.extract` — original Slice-3 site; the rewrite is the primary motivation.
2. `alfred.memory.episodic.record` — Slice-2.5-shipped site; already documented as the precedent that `quarantine.py` was deferring to. Now they align.
3. `alfred.identity._ingest` — Slice-3-shipped site; the T1/T3 ingress path.
4. `alfred.state.dispatch_loop._handle_dispatch_failure` — Slice-3-shipped site (touched by PR-S4-2 for DLP). Migration is mechanical because there is currently no error subscriber on this dispatch.

Slice-4 PR-S4-3 ships the migrations as part of the PR, not as follow-ups. A new `tests/integration/test_error_chain_substitution_propagates.py` exercises each site with a known-good substitute subscriber and asserts the substitute returns end-to-end.

### 4.6 Adversarial corpus entries

`tests/adversarial/payload_schema.py` gains category `carrier_substitution_tamper` with ID prefix `crf-` (per §11.1). Corpus entries:

- `crf-001 malicious_error_subscriber_attempts_tier_upgrade` — a subscriber returns `SubstituteResult(payload=fabricated_payload, source_tier="T3")` on a `T1` carrier. Must be refused with `CARRIER_SUBSTITUTION_REFUSED_FIELDS` carrying `reason="tier_upgrade_refused"`. Variants: T3 substitute on T0/T1/T2 carriers (three sub-cases); T2 substitute on T0/T1 carriers (two sub-cases); T1 substitute on T0 carrier (one sub-case).
- `crf-002 malformed_substitute_payload` — `SubstituteResult(payload=malformed_payload, source_tier="T0")` — substitute fails downstream validation; original exception raises (the substitute is well-typed enough to type-check but semantically invalid).
- `crf-003 wrong_type_substitute_payload` — `SubstituteResult(payload=truthy_but_wrong_type, source_tier="T0")` — type validation fails; original exception raises.
- `crf-004 meta_hookpoint_recursion_attempt` (test-005 / rev-004 closure) — a subscriber on `hooks.carrier_substituted` itself returns a `SubstituteResult`. Must be refused at registration (`register_hookpoint` rejects subscribers on observation-only meta-hookpoints) AND refused at dispatch time (defence-in-depth) with `CARRIER_SUBSTITUTION_REFUSED_FIELDS` carrying `reason="recursion_refused"`.

### 4.7 Hookpoint declaration

PR-S4-3 declares `hooks.carrier_substituted` and `hooks.carrier_substituted_refused` as **observation-only post-stage hookpoints** (rev-010 round-4 closure — round-3 added the §10 SSOT clarification but left this site reading "PR-S4-0a"; corrected). Subscribers may observe substitution events but cannot themselves substitute — substituting on these meta-hookpoints is refused at *registration time* by a Protocol guard in `register_hookpoint`. The `subscribable_tiers = SYSTEM_ONLY_TIERS` constraint stays.

Observation-only means the error chain on these hookpoints **does nothing** if a subscriber raises — the original event has already happened (a substitution was attempted; recording its observation cannot un-attempt it). Therefore the meta-hookpoints carry `fail_closed=False` (rev-004 closure — observation-only + `fail_closed=True` was semantically undefined; the choice resolves to `False` because there is no original action to close). §10 is updated accordingly.

The "no error-stage substitute on meta-hookpoints" rule is enforced by `HookpointMeta.allow_error_substitution: bool` (new in PR-S4-3, defaulting to `True` on every hookpoint except the two meta-hookpoints). `_run_error()` checks this flag before consulting subscribers.

---

## 5. mtime-polled hot-reload for `config/policies.yaml` (#159 / ADR-0023)

### 5.1 `PolicyWatcher` + polling cadence

Slice 4 ships mtime polling at a 1s default interval (configurable via `Settings.policy_poll_interval_seconds`, range `[0.5, 10.0]`). The polling task lives under the daemon's `asyncio.TaskGroup` started by `Supervisor`; it raises on cancellation and is restarted only by full daemon restart.

```python
class PolicyWatcher:
    def __init__(
        self,
        config_path: Path,
        snapshot_ref: PoliciesSnapshotRef,
        audit_writer: AuditWriter,
        poll_interval: float = 1.0,
    ): ...

    async def run(self) -> None:
        """Poll mtime; on change, parse-validate-swap."""
```

**Filesystem failure paths emit typed audit rows** (err-001 closure — log-and-continue at a security-relevant config source violates CLAUDE.md hard rule 7):

- File vanishes mid-poll → `CONFIG_RELOAD_REJECTED_FIELDS` with `reason="file_vanished"`, active snapshot unchanged. The watcher continues polling (vanishment is transient; the file may be re-created by an editor's write-then-rename).
- `os.stat()` raises (filesystem error) → `CONFIG_RELOAD_REJECTED_FIELDS` with `reason="stat_failed"` and `offending_key="<filesystem>"`. The watcher continues polling.
- Repeated stat failures (≥3 in a row across the polling cadence) → the watcher escalates to the supervisor breaker via `supervisor.config_watcher.degraded` (new hookpoint) and reduces polling frequency to 10× the configured interval until stat succeeds again. **Recovery** (err-006 closure): the watcher returns to normal cadence after ≥3 consecutive successful stat calls; the recovery emits `supervisor.config_watcher.recovered` audit row + matching hookpoint so operators see the state transition. The watcher's internal state is `Literal["normal", "degraded"]`; transitions in either direction are visible in the audit log.

**Polling implementation is mtime-gated** (perf-005 closure). The watcher calls `os.stat()` per poll tick and only reads + parses the YAML when `(new_mtime, new_size)` differs from the cached values. On unchanged mtime+size, the poll tick is `~0.1ms` (a syscall + a couple of int compares). Under steady-state (no edits) the watcher's CPU cost is negligible.

### 5.2 `PoliciesV1` Pydantic v2 model

```python
class RateLimitPolicies(BaseModel):
    web_fetch_per_user_per_hour: int
    web_fetch_per_session_total: int
    operator_daily_budget_usd: float
    model_config = ConfigDict(frozen=True)

class HandleCapPolicies(BaseModel):
    web_fetch_max_concurrent_handles_per_user: int
    model_config = ConfigDict(frozen=True)

class HighBlastPolicies(BaseModel):
    """Keys that REFUSE hot-reload; reviewer-gate only."""
    quarantined_provider_url: HttpUrl
    secret_broker_config_ref: str
    model_config = ConfigDict(frozen=True)

class PoliciesV1(BaseModel):
    schema_version: Literal[1]
    rate_limits: RateLimitPolicies
    handle_caps: HandleCapPolicies
    high_blast: HighBlastPolicies
    model_config = ConfigDict(frozen=True)
```

The high-blast block is parsed but never hot-reloaded. The `PolicyWatcher` validates the parsed model against the active snapshot's high-blast block; any diff in `HighBlastPolicies` triggers `CONFIG_RELOAD_REJECTED_FIELDS` with `reason="high_blast_change"`.

### 5.3 `PoliciesSnapshot` + `PoliciesSnapshotRef`

```python
class PoliciesSnapshot(BaseModel):
    policies: PoliciesV1
    loaded_at: datetime
    file_mtime: float
    file_sha256: str
    model_config = ConfigDict(frozen=True)

class PoliciesSnapshotRef:
    """Lock-free O(1) snapshot pointer, swappable atomically by the watcher.

    Implementation: a single `_current` attribute holding the active snapshot.
    `current()` returns it; under CPython that load is atomic by GIL semantics
    (no lock required). The async signature exists for typing symmetry with
    other async derefs; the call is non-blocking and never yields.
    """
    def __init__(self, initial: PoliciesSnapshot): ...

    def current(self) -> PoliciesSnapshot:
        """Lock-free single-attribute read. p99 < 1µs (perf-002 round-2 closure).

        Synchronous to avoid the async-await trampoline overhead (~200ns under
        CPython). Consumers call as `ref.current().rate_limits.foo`, not
        `await ref.current()`. The Slice-3 async/sync split in `Settings.*`
        established this discipline; the snapshot ref follows the same shape.
        """
        return self._current   # GIL-atomic load; no lock, no await

    async def swap(self, new: PoliciesSnapshot) -> None:
        """Two-phase commit with watcher-side short-circuit: skip if same SHA.

        Phase 0 — caller short-circuit (watcher-side, sec-007 round-3 closure):
        if `new.file_sha256 == self._current.file_sha256`, the watcher
        returns immediately without calling `swap()`. There is no audit row
        emit because nothing changed. Retries after transient errors that
        re-observe the same file content collapse to a no-op at the watcher,
        before the swap is attempted. This is the load-bearing idempotency
        mechanism; it does not rely on an AuditWriter dedupe surface (which
        Slice-3's AuditWriter does not expose).

        Phase 1 — emit CONFIG_RELOAD_FIELDS audit row carrying the new
        snapshot's `file_sha256` and the active-snapshot's `file_sha256` (the
        diff anchor). If the audit write fails, the swap aborts (the
        snapshot the watcher prepared is discarded; the active snapshot
        stays).

        Phase 2 — only on successful audit, atomic single-attribute assignment.
        New consumers see the new snapshot on their next `current()` call.
        """
        # err-004 closure: audit-then-swap, not swap-then-audit. A failed audit
        # write cannot leave the active snapshot diverged from the audit log.
        # err-010 closure: an audit-write failure raises; the watcher catches
        # in PolicyWatcher.run, emits CONFIG_RELOAD_REJECTED_FIELDS with
        # reason="audit_write_failed", and tries again on next mtime change.
        # No silent corruption: the active snapshot stays consistent with the
        # last successful audit row, and the rejection is loud.
```

The Ref's swap is atomic from the asyncio perspective (single attribute assignment under the GIL). In-flight coroutines that captured the old snapshot continue with the old value — acceptable per spec §7.10 baseline. **But long-lived loops must deref per iteration**, not once before the `while` (core-003 closure): the supervisor's `_proposal_dispatch_loop` and `PolicyWatcher.run` itself each call `ref.current()` (synchronous — perf-002 round-2 closure) *inside* the loop body. PR-S4-4 inspects each of these sites and inserts the per-iteration deref. `_capability_heartbeat_loop` is **not** a snapshot consumer (core-009).

### 5.4 Low-blast vs high-blast key partitioning

The model-level partition (`HighBlastPolicies` vs the other top-level blocks) is the single source of truth. A new top-level field in `PoliciesV1` lands in either the high-blast block (reviewer-gated, refuses hot-reload) or one of the low-blast blocks (hot-reloadable). No third option. PR-S4-0a notes this in `docs/subsystems/policies.md`.

### 5.5 Consumer migration

Four Slice-3-shipped consumers migrate to the snapshot-ref deref pattern in PR-S4-4:

1. `RateLimitConfig` (Slice-3 `src/alfred/web_fetch/rate_limits.py`).
2. `HandleCapConfig` (Slice-3 `src/alfred/web_fetch/handle_cap.py`).
3. `ContentStore` Redis quotas (Slice-3 `src/alfred/security/content_store.py`).
4. The quarantined-provider config consumer in `QuarantinedExtractor` (the Slice-3 plugin loads its config once at construction; the field that the hot-reload covers is the `provider` low-blast subfield, not the URL high-blast field).

**Forbidden idiom:**

```python
# BAD — captures old value
cap = ref.current().handle_caps.web_fetch_max_concurrent_handles_per_user
await something()
use(cap)
```

**Required idiom:**

```python
# GOOD — deref per use
snapshot = ref.current()
use(snapshot.handle_caps.web_fetch_max_concurrent_handles_per_user)
```

A pytest-time AST guard runs over the four consumer modules and refuses any name binding from `ref.current()` that crosses an `await` boundary. The guard is intentionally narrow — it does not enforce on every module, only on the four migrated consumers — because broader enforcement would have too many false positives.

**Long-lived loops** (core-003 + core-009 closure): three Slice-3-shipped loops deref the snapshot per iteration:

- `_proposal_dispatch_loop` in `src/alfred/supervisor/core.py:282` — already consumes Slice-3 config; PR-S4-4 migrates its deref to `policies_ref.current()`.
- `PolicyWatcher.run` (new in PR-S4-4) — its own deref pattern.
- The web-fetch consumer loops in `src/alfred/web_fetch/` — covered by the four-consumer migration above.

The `_capability_heartbeat_loop` (`src/alfred/supervisor/core.py:317`) is **not** a snapshot-ref consumer in Slice 4 — it reads capability-gate state from a different surface — and is listed here for the round-1 spec's correction (core-009 closure: the round-1 spec named it as a snapshot consumer in error).

### 5.6 Audit row families

| Constant | Fields |
|---|---|
| `CONFIG_RELOAD_FIELDS` | `file_path`, `prev_sha256`, `new_sha256`, `changed_keys` (list of dotted key paths), `loaded_at` |
| `CONFIG_RELOAD_REJECTED_FIELDS` | `file_path`, `attempted_sha256`, `reason` (`parse_failure` \| `high_blast_change` \| `validation_failure`), `offending_key` (no value — value omitted to avoid secret leak), `dlp_scan_result` |

Note `dlp_scan_result` carries one of `Literal["clean", "high_blast_change", "n_a"]`; it does not carry the failing payload.

### 5.7 Adversarial corpus entry

`tests/adversarial/payload_schema.py` gains category `config_reload_bypass`. Entries:

- `attacker_swaps_high_blast_via_filesystem` — write to `policies.yaml` with a different `high_blast.quarantined_provider_url`. Expected: `CONFIG_RELOAD_REJECTED_FIELDS` emitted; active snapshot unchanged.
- `attacker_swaps_low_blast_to_negative` — write to `policies.yaml` with `rate_limits.web_fetch_per_user_per_hour: -1`. Expected: `CONFIG_RELOAD_REJECTED_FIELDS` with `reason="validation_failure"`.
- `attacker_renames_field` — write to `policies.yaml` with an unknown top-level field. Expected: `CONFIG_RELOAD_REJECTED_FIELDS` with `reason="validation_failure"` (Pydantic extra-fields strict).

### 5.8 watchdog migration deferral

The Slice-4 mtime-polling implementation is intentionally simple. Migration to `watchdog` (which wraps inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows) is deferred to Slice 5+ unless an operator surfaces a real polling-latency complaint. The deferral note lives in ADR-0023's "Future work" section.

---

## 6. CLI operator session (#153 closure)

### 6.1 `OperatorSession` Pydantic model

```python
class OperatorSession(BaseModel):
    schema_version: Literal[1]
    user_id: UserId
    token: SecretStr           # 32 random bytes, base64url-encoded
    issued_at: datetime
    expires_at: datetime       # default issued_at + timedelta(hours=12)
    host: str                  # hostname binding (anti-replay across machines)
    machine_id_hash: str       # HMAC-SHA256(audit_hash_pepper, raw_machine_id) — see §6.5
    model_config = ConfigDict(frozen=True)
```

### 6.2 Session-file format + permissions

File at `~/.config/alfred/session`. Format is JSON serialisation of the `OperatorSession` model. The token field is stored verbatim; treating the file as a secret is the operator's responsibility (the file mode is the host-side defence).

**Mode and ownership are validated TOCTOU-safe** (sec-006 closure):

1. `open(path, O_RDONLY | O_NOFOLLOW)` — refuses to follow symlinks. Symlinking the session file to attacker-owned content is refused at open time, not stat time.
2. `fstat(fd)` on the open fd — validates `st_mode == 0600` AND `st_uid == os.getuid()` AND `st_gid == os.getgid()`. Mismatches refuse with `OPERATOR_SESSION_REFUSED_FIELDS(reason="bad_file_mode" | "bad_file_owner")`.
3. Only after `fstat` passes does the loader read the contents.

The stat-then-open pattern that the Slice-4 draft originally used is TOCTOU-vulnerable (attacker swaps the file between the two syscalls). The open-then-fstat pattern closes the window.

The session file lives outside `~/.config/alfred/settings.toml` so that operator settings (no secrets) and operator session (secret-bearing) have different rotation cadences. The settings file may be checked into operator dotfiles; the session file must not.

### 6.3 `alfred login / logout / whoami` UX

- `alfred login --as <user>` — looks up `<user>` via `alfred user show <user>`; refuses if user does not exist with the operator-translated message `t("login.user_not_found")` and the actionable suggestion `t("login.user_not_found_action_alfred_user_list")` ("Use `alfred user list` to see existing users or `alfred user add` to create one"); prompts for confirmation; writes the session file. If a session file already exists for a different user, prompts via `t("login.session_overwrite_confirm")` (devex-002 closure).
- `alfred login` (no `--as`) — runs `alfred user list` inline and prompts the operator to pick by number, then re-runs as `alfred login --as <chosen>`. Discoverability built-in (devex-002 closure).
- `alfred logout` — deletes the session file. Refuses with `t("logout.no_session")` if no session present.
- `alfred whoami` — reads the session; prints `user_id`, `expires_at` (locale-formatted via `babel.dates` per the active user's `language` — i18n-003 closure), host binding. Returns nonzero if no session or session is expired.

The session token is generated host-side and stored in the database (`operator_sessions` table). `_resolve_operator` validates against the row, checks expiry, checks host binding, checks machine-id binding. Mismatches emit `operator.session.refused` with `reason: Literal["expired", "host_mismatch", "machine_mismatch", "token_unknown", "user_revoked", "bad_file_mode", "bad_file_owner"]`.

### 6.4 `_resolve_operator(ctx) -> UserId` host helper

Lives at `src/alfred/identity/operator_session.py`. Every CLI command that emits an operator-attributed audit row consumes this helper via dependency injection (`OperatorResolver` Protocol). The helper raises one of:

- `OperatorSessionMissing` — no session file.
- `OperatorSessionExpired` — file present but `expires_at < now`.
- `OperatorSessionRevoked` — token not in `operator_sessions` table (revoked by `alfred logout` from elsewhere, or operator session DB cleanup).
- `OperatorSessionHostMismatch` — file's `host`/`machine_id` don't match this machine.

A pytest-time AST guard refuses any CLI command in `src/alfred/cli/` that emits an operator-attributed audit row without consuming `OperatorResolver`. The list of operator-attributed audit rows is enumerable from `audit_row_schemas.py` (every constant whose field-set includes `operator_user_id`).

**Performance budget + hard timeout** (perf-001 round-2 + err-008 closure): `_resolve_operator` reads the file + queries the `operator_sessions` row by token-hash + validates fields. The Postgres query is a single-row lookup on the **`uq_operator_sessions_token_hash` unique index** (created in PR-S4-0b migration 0011). **p99 budget: ≤ 5ms total** with index hit, breaking down as:

- File open + fstat + read + JSON parse: ≤ 1ms (local SSD).
- Postgres single-row index lookup: ≤ 2ms.
- Per-resolve audit-row write (none on the success path — audit fires only on session-changed events like create/revoke/refuse): 0ms steady-state.
- Field validation + return: ≤ 1ms.

**Hard timeout: 250ms** wraps the entire resolver call via `asyncio.wait_for(...)`. Beyond 250ms the resolver raises `OperatorSessionTimeout` and the CLI command refuses with `t("operator_session.refused.resolver_timeout")` rather than hanging silently (err-008 closure). 250ms is 50× the p99 budget — covers genuine DB slowness without becoming a silent hang.

The resolver does not cache — every CLI command call hits Postgres — because the cost is bounded and the security model (revoked-elsewhere session) requires DB hit. CLI commands are not on a sub-ms hot path. If a future cache becomes desirable, the budget puts it post-MVP.

### 6.5 Token rotation + expiry + host binding

- Token is 32 bytes from `secrets.token_urlsafe(32)`. Base64url-encoded as the storage form.
- Default expiry is 12 hours from `issued_at`. Operator can override via `--expires-in <duration>` on `alfred login` (clamped to `[1h, 7d]`; values outside the range refuse with `t("login.expires_in_out_of_range")`).
- Refresh: `alfred login --refresh` rotates the token (new urandom) and resets expiry without prompting for user identity. Requires a non-expired session.
- Host binding compares hostname (`socket.gethostname()`).
- **Machine-id binding** comes from a system-owned source per OS (sec-006 closure):
  - Linux: `/etc/machine-id` (system-owned, root-only-writable). If unreadable, falls back to `/var/lib/dbus/machine-id`. If both unreadable, the session is refused at creation with `t("login.no_machine_id")`.
  - macOS: `IOPlatformUUID` from `ioreg -rd1 -c IOPlatformExpertDevice` (system-managed). Cached at first read in `/var/db/alfred/machine-id` (root-writable; AlfredOS daemon writes once at first install).
  - Windows: `MachineGuid` from `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography` (system-managed).
  - Never written to a user-writable location. The session file carries `machine_id_hash` (HMAC, not the raw value) so even read access to the session file does not leak the machine fingerprint.
- Both host AND machine-id are checked; either mismatch refuses with the matching `OPERATOR_SESSION_REFUSED_FIELDS(reason=…)` row.

### 6.6 Audit row family

| Constant | Fields |
|---|---|
| `OPERATOR_SESSION_CREATED_FIELDS` | `user_id`, `issued_at`, `expires_at`, `host`, `machine_id_hash` (HMAC-SHA256, see §8.10), `via` (`Literal["login", "refresh"]`) |
| `OPERATOR_SESSION_REVOKED_FIELDS` | `user_id`, `revoked_at`, `via` (`Literal["logout", "admin_revoke", "expiry"]`) |
| `OPERATOR_SESSION_REFUSED_FIELDS` | `attempted_user_id`, `reason` (`Literal["expired", "host_mismatch", "machine_mismatch", "token_unknown", "user_revoked"]`), `host`, `machine_id_hash` |

Note `machine_id_hash` — the raw machine-id is not written to the audit log because it is a persistent host fingerprint that some operators consider sensitive. The sha256 lets cross-row correlation without leaking the raw value.

### 6.7 `alfred supervisor reset` attribution (closes #153)

The four `operator_user_id=None` placeholder sites in `src/alfred/cli/supervisor.py` (CR-149 round-4 finding) become `operator_user_id=await resolve_operator(ctx)`. The reset command grows a precondition check: if `_resolve_operator` raises any of the four `OperatorSession*` exceptions, the command refuses with the operator-translated message `t("supervisor.breaker.reset.refused.not_logged_in")` *("Not logged in. Run `alfred login --as <operator-user>` first.")* and emits `supervisor.breaker.reset.refused` with `reason="operator_session_missing"`. The English-string literal that the Slice-4 draft inlined moves into the i18n catalog (i18n-001 closure). The existing `BreakerResetProposal` writer is touched only to pass the real `operator_user_id`.

A new test asserts both the audit row AND the structlog `supervisor.breaker.reset.attempted` event carry the operator's id (not None).

### 6.8 Other CLI commands that gain operator attribution

In addition to `alfred supervisor reset`:

- `alfred config quarantined-provider` (Slice-3 shipped; currently writes a state.git proposal without operator attribution) — gains attribution in PR-S4-5.
- `alfred plugin grant <name>` / `revoke <name>` (Slice-3 shipped) — gains attribution.
- `alfred memory forget <fact-id>` (PRD §6.2 spec, may not be Slice-3-shipped) — out-of-scope for Slice 4 if not shipped.
- `alfred rollback <commit>` / `alfred memory rollback <commit>` — out-of-scope for Slice 4 if not shipped.

The AST guard list enumerates every operator-attributed audit-row constant; in practice this means every CLI command that emits a constant whose field-set includes `operator_user_id`. The implementation will discover the full list at PR-S4-5 time and threading is mechanical.

---

## 7. Sandbox containerisation (ADR-0015)

### 7.1 Plugin-manifest `sandbox` declaration

Every plugin manifest gains a top-level `sandbox` block. The block is required (no default); missing `sandbox` refuses plugin load with `plugin.load_refused` (Slice-3 shipped) carrying `reason="sandbox_block_missing"`.

```yaml
sandbox:
  kind: full | none | stub
  policy_ref: config/sandbox/<name>.<os>.<ext>  # required when kind=full; ignored otherwise
```

- `kind: full` → kernel-enforced isolation via per-OS policy file. Required for the quarantined-LLM plugin in Slice 4 (closes PRD §5 line 117). Required for any third-party or agent-authored plugin (PRD §5 invariant).
- `kind: none` → in-process subprocess; UID separation only. Allowed for first-party comms adapters (Discord, TUI in Slice 4) because they need broad network access and operate under existing trust assumptions. Not allowed for third-party plugins.
- `kind: stub` → Windows-only path. Plugin runs without sandbox enforcement; emits `supervisor.plugin.sandbox_stub_used` audit row; plugin is not marked PRD-compliant. Useful for development on Windows; refuses to run in production (`Settings.environment == "production"`).

The `policy_ref` is a relative path under the AlfredOS install tree. PR-S4-7 ships the canonical per-OS policy files for the quarantined-LLM plugin at `config/sandbox/quarantined-llm.linux.bwrap.policy`, `config/sandbox/quarantined-llm.macos.sb`, `config/sandbox/quarantined-llm.windows.stub.policy`.

### 7.2 `bin/alfred-plugin-launcher` policy resolution

The launcher (Slice-3 shipped as a stub) gains policy-resolving behaviour in PR-S4-6:

1. Read the plugin manifest for the target plugin.
2. Read the `sandbox` block; refuse if missing.
3. Read `Settings.environment` (`Literal["development", "production", "test"]`).
4. If `kind: full`: read `policy_ref`; refuse if missing on disk; refuse if the per-OS policy file does not match the launcher's host OS; spawn the plugin under the OS-specific sandbox runtime (bwrap / sandbox-exec / refuse-with-stub-policy on Windows).
5. If `kind: none`: spawn the plugin as a UID-separated subprocess (Slice-3 baseline behaviour).
6. If `kind: stub`: refuse in production; spawn unsandboxed in development with `supervisor.plugin.sandbox_stub_used` audit row.

**The launcher is a bash script** at `bin/alfred-plugin-launcher.sh` (Slice-3 shipped). PR-S4-6 extends the existing script with policy-resolving behaviour. The bash-shape is load-bearing: the launcher must complete its work *before* the plugin's Python interpreter starts, so a Python launcher would be a paradoxical chicken-and-egg. The script invariants from Slice 3 stay:

- Fail-closed without a sandbox policy file.
- UID-drop on Linux via `runuser`; refuse if `runuser` missing.
- Env scrubbing before `exec`.

PR-S4-6 adds policy-resolution by reading the plugin manifest (via a small Python one-shot — `python3 -c 'from alfred.plugins.manifest import read; print(read("'$PLUGIN_ID'").sandbox)'` — pre-launcher to extract the `sandbox.kind` and `policy_ref`). The plugin manifest read is the only Python AlfredOS code the launcher relies on; the launcher itself stays bash.

The launcher does **not** speak JSON-RPC stdio to the plugin (the plugin and the host speak MCP stdio after the launcher `exec`s away). The launcher speaks JSON over a fd to the host for audit/lifecycle events *only during the pre-exec phase* — once the plugin is launched, the launcher process is gone (replaced by the plugin via `exec`).

### 7.3 Production-refuse-without-policy semantics

`Settings.environment` is **mandatory** and must be one of `Literal["development", "production", "test"]` (sec-003 closure — silent fallback to development on a misconfigured production host is the wrong default). It is **dual-sourced with a deterministic precedence rule** (rev-008 closure — the round-1 spec said "single-sourced" then listed two sources, which was confusing wording):

- `ALFRED_ENVIRONMENT=<value>` env var (primary source; wins on conflict).
- `/etc/alfred/environment` file containing the value as its sole contents, trimmed (fallback source if env var unset).
- Disagreement between sources emits `daemon.boot.environment_source_conflict` audit row and uses the env-var value (the daemon still boots; the conflict is recorded for operator visibility).
- If neither source is set, the daemon refuses to boot (per §3.4 `failure_reason="environment_not_set"`). There is no fallback default — explicit operator declaration is required.

In production, every `kind: full` plugin must have a resolvable `policy_ref` matching the launcher's host OS. Mismatch refuses with `supervisor.plugin.sandbox_refused` carrying `reason="policy_ref_missing"` / `"policy_ref_os_mismatch"` / `"policy_ref_unreadable"`. The launcher does not fall back to less-restrictive isolation in production.

### 7.4 Dev escape hatch `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1`

Short-circuits the resolver, spawning the plugin unsandboxed under the calling UID. Only honoured when `Settings.environment == "development"`. In production, the launcher refuses to spawn AND prints the operator-translated message **to stderr** before exiting non-zero (devex-001 closure):

```
$ alfred daemon start  # with UNSANDBOXED=1 in env
[error] ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1 is set, but Settings.environment="production".
        The dev escape hatch is refused in production. Unset the env var
        or set ALFRED_ENVIRONMENT=development. See docs/runbooks/slice-4-graduation.md.
```

The message comes from `t("supervisor.sandbox.unsandboxed_refused_in_production")`. A `supervisor.plugin.sandbox_refused` audit row carrying `reason="unsandboxed_env_set_in_production"` also fires.

The escape hatch's purpose is to let plugin developers iterate without re-running the per-OS policy validation at every plugin restart. It is not a production feature.

### 7.5 Linux bwrap policy (`config/sandbox/quarantined-llm.linux.bwrap.policy`)

The Linux primary target. The policy is a declarative format (TOML or JSON; format choice deferred to PR-S4-7) that the launcher translates into bwrap CLI flags:

- `--ro-bind /usr/lib/alfred-quarantine /usr/lib/alfred-quarantine` — plugin binary mount.
- `--ro-bind /etc/ssl/certs /etc/ssl/certs` — TLS CA bundle.
- `--tmpfs /tmp` — writable scratch.
- `--unshare-pid --unshare-uts --unshare-cgroup --unshare-ipc` — namespace isolation.
- `--share-net` is **deliberately omitted** — the plugin's network access is brokered via an outbound proxy declared in the policy (the brokered proxy is the quarantined-LLM provider URL from `routing.yaml[quarantine]`); the plugin cannot connect anywhere else.
- `--die-with-parent` — supervisor death kills the plugin.

The launcher passes the provider key via fd 3 with the Slice-3-shipped 4-byte big-endian length-prefix framing. **Provider key handling discipline** (sec-004 round-3 closure — honest about the bash-launcher reality):

The actual chain on Slice 4 is:

1. **Supervisor (Python, host)** fetches the secret via the Slice-3 `SecretBroker.get("quarantined.provider_key")` API. Returns `str` (interned Python str — see limitation note below). The Supervisor opens a pipe with the read end at fd 3 of the launcher subprocess.
2. **Supervisor** writes the 4-byte big-endian length prefix + the key bytes to the pipe, then closes the write end. The launcher subprocess sees a complete fd-3 message available.
3. **Launcher (bash)** does NOT read the key itself. It passes fd 3 through to the spawned plugin via **bwrap's DEFAULT fd inheritance — NO CLI flag** (see the SUPERSEDING NOTE below; supersedes the `--keep-fd 3` / `--sync-fd 3` text retained here for history). The launcher does not buffer the bytes through bash variables — bash strings cannot reliably carry NUL bytes or be zeroized. Concrete invocation shape:

   ```bash
   exec bwrap [other policy flags] -- ${PLUGIN_BINARY}
   ```

   > **SUPERSEDING NOTE (#152 / #229).** The `--keep-fd 3` claim above (and the later `--sync-fd 3` correction) are BOTH wrong. Empirically proven in a docker `bwrap` repro against the production image (Debian Bookworm, bubblewrap 0.8.0) and 0.9.0: bwrap inherits open, non-CLOEXEC fds (fd 3) into the sandboxed child **by default — no flag**. `--sync-fd` is bwrap's *internal* sync fd and CONSUMES fd 3 if pointed at it (the child's `os.read(3)` raises EBADF). The translator emits NO fd flag; `keep_fds` is a validated declaration only (arch-2). ADR-0015's flag section owns the final truth.

   No `/dev/fd` mount is needed; the kernel handles the inheritance.
4. **Plugin (Python)** reads fd 3 inside its own process with the framing the Slice-3 plugin-side `read_fd3_secret()` helper provides; zeroizes its in-process buffer after use.

**Honest limitations** acknowledged in the spec rather than fabricated away:

- Step 1: Python `str` returned from `SecretBroker.get` is interned and not zeroizable. The Supervisor holds the key in a `str` between the broker fetch and the fd-3 write. This is a real residency window measured in microseconds. Mitigation: the Supervisor calls `gc.collect()` after the write; the str will be reclaimed at next GC. Future Slice-5 broker-hardening can add a `get_bytes(name) -> bytearray` API that returns a zeroizable buffer (already tracked in Slice-5 backlog).
- Step 3: the launcher (bash) never holds the bytes — the fd-inheritance pattern means the kernel pipes the bytes directly from Supervisor to plugin without bash touching them. Verified by `strace` test `sbx-2026-005`.
- **Process-level posture** (PR-S4-6 adds these to both the Supervisor and the launcher):
  - Supervisor disables core dumps at boot via `resource.setrlimit(RLIMIT_CORE, (0, 0))`.
  - Supervisor calls `mlockall(MCL_CURRENT | MCL_FUTURE)` on Linux best-effort; emits `supervisor.boot.mlock_unavailable` if it fails (no `CAP_IPC_LOCK`).
  - Launcher inherits these from the Supervisor parent.
  - Plugin (Python) calls them itself at process startup before broker key receipt.

The launcher process is itself short-lived (one `exec` per plugin spawn). The provider key never persists across spawns; the broker rotates the in-broker copy on each operator-issued rotation (no automatic Slice-4 rotation cadence).

fd 3 is closed after the write; the plugin process reads exactly the framed bytes and closes its read end.

An adversarial corpus entry pins the key-residency property: `sbx-2026-005 launcher_key_inheritance` runs the launcher under `strace`/`dtruss` and asserts the bash process never reads from fd 3, only the spawned plugin does.

### 7.6 macOS sandbox-exec policy (`config/sandbox/quarantined-llm.macos.sb`)

Scheme-like sandbox-exec syntax. Declares:

- `(deny default)` — fail-closed.
- `(allow file-read* (subpath "/usr/lib/alfred-quarantine"))` — binary read.
- `(allow file-read* (literal "/etc/ssl/cert.pem"))` — TLS CA.
- `(allow file-write* (subpath "/tmp/alfred-quarantine"))` — scratch.
- `(allow network* (remote tcp "host.docker.internal:443"))` — proxy. Real host/port resolved at policy-load time from `routing.yaml[quarantine].provider_url`.
- `(deny network-outbound (remote tcp "*"))` — explicit catch-all deny after the proxy allow.

sandbox-exec on macOS is best-effort (Apple has deprecated it but it still works). The policy is acknowledged as second-class in `docs/subsystems/security.md` per ADR-0015's "macOS and Windows policies are best-effort" stance.

### 7.7 Windows stub policy (`config/sandbox/quarantined-llm.windows.stub.policy`)

A TOML file containing:

```toml
schema_version = 1
isolation = "stub"
prd_compliant = false
notes = "Windows native sandbox not implemented; quarantined-LLM runs unsandboxed under the calling user. PRD §5 line 117 invariant NOT satisfied on Windows."
```

The launcher reads this and:

- In production → refuse with `supervisor.plugin.sandbox_refused` carrying `reason="windows_stub_in_production"`. AlfredOS does not claim PRD compliance on Windows for the quarantined-LLM.
- In development → spawn unsandboxed with loud `supervisor.plugin.sandbox_stub_used` audit row.

Operators running AlfredOS on Windows are directed to WSL2 + Linux bwrap policy. The CLAUDE.md `Deployment` table already notes Windows-native is post-MVP; this slice does not change that.

### 7.8 Quarantined-LLM manifest update

The Slice-3-shipped `plugins/alfred_quarantined_llm/manifest.yaml` currently declares `kind: none` (the UID-separated baseline). PR-S4-6 changes this to `kind: full` and adds `policy_ref` entries:

```yaml
sandbox:
  kind: full
  policy_refs:
    linux: config/sandbox/quarantined-llm.linux.bwrap.policy
    macos: config/sandbox/quarantined-llm.macos.sb
    windows: config/sandbox/quarantined-llm.windows.stub.policy
```

The `policy_refs` map keys by `Literal["linux", "macos", "windows"]`. The launcher resolves the entry matching `sys.platform`. Multiple-OS support is a one-time manifest change; subsequent OS additions need only add a new key.

### 7.9 First-party comms adapters declare `kind: none`

The Slice-4 Discord and TUI MCP plugins both declare `kind: none` because they need broad network access (Discord gateway) and PTY access (TUI). PRD §5 line 117's "official → in-process subprocess" half of the hybrid-isolation invariant allows this. **The carve-out applies because comms adapters are relays, not T3 consumers** — they ferry bytes from a platform to the stdio transport and back; T3-content consumption happens in the orchestrator and the quarantined LLM, which are protected by their own boundaries. Third-party comms adapters (post-MVP Slack, Telegram, voice, email) will require `kind: full` per the same invariant; the first-party carve-out narrows specifically to in-tree adapters whose source is in-repo and whose review path is the standard AlfredOS reviewer gate (rev-001 / arch-005 closure).

### 7.10 PRD §5 line 117 amendment

The Slice-3 wording:

> **Hybrid isolation.** Plugins declare a trust tier; official → in-process subprocess; third-party or agent-authored → containerized with declared capabilities (network allowlist, fs mounts, secret IDs). **Slice 3 relaxation:** the quarantined-LLM plugin runs as a dedicated-UID subprocess with env scrubbing rather than a container — a time-bounded deviation recorded in [ADR-0017](../../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md). Full containerisation lands in Slice 4 per [ADR-0015](../../adr/0015-slice4-containerised-quarantined-llm.md).

Becomes:

> **Hybrid isolation.** Plugins declare a trust tier and a sandbox kind. Official in-tree plugins that *relay* content but do not *consume* T3 (comms adapters, TUI) run as in-process subprocesses (`sandbox.kind: none`). Plugins that *consume* T3 content (the quarantined-LLM extractor; future agent-authored skills processing untrusted content), and all third-party plugins regardless of their consumed tiers, run with kernel-enforced isolation (`sandbox.kind: full`) declaring network allowlist, fs mounts, and secret IDs. The quarantined-LLM plugin runs under `sandbox.kind: full` from Slice 4 onwards, satisfying the kernel-namespace isolation invariant on Linux via [bwrap](https://github.com/containers/bubblewrap) and on macOS via [sandbox-exec](https://www.unix.com/man-page/all/1/sandbox-exec/) (best-effort). Windows-native sandbox is not supported; AlfredOS does not claim PRD compliance for the quarantined-LLM on Windows-native. See [ADR-0015](../../adr/0015-slice4-containerised-quarantined-llm.md) and [ADR-0017](../../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md).

The clarified amendment makes the consumer-vs-relay distinction explicit (arch-005 / rev-001 closure), removing the contradiction between "T3-content-consuming → containerised" and Discord/TUI's `kind: none`.

PR-S4-0a lands this amendment. **PRD edits are human-gated** per CLAUDE.md self-improvement rules (rev-003 closure) — PR-S4-0a's diff includes the amendment text but explicit human approval gates the merge. The other PR-S4-0a content (ADRs, audit constants, payload Literals) is reviewer-gateable. Paths in the blockquotes above are spec-relative (`../../adr/…`) so docs-check resolves them from this file's location; the actual PRD.md edit uses repo-root-relative paths (`docs/adr/…`) because PRD.md sits at the repo root.

### 7.11 Audit row family

| Constant | Fields |
|---|---|
| `SANDBOX_REFUSED_FIELDS` | `plugin_id`, `policy_ref`, `host_os`, `reason` (one of: `policy_ref_missing` \| `policy_ref_os_mismatch` \| `policy_ref_unreadable` \| `sandbox_block_missing` \| `windows_stub_in_production` \| `unsandboxed_env_set_in_production`), `environment` |
| `SANDBOX_STUB_USED_FIELDS` | `plugin_id`, `policy_ref`, `host_os`, `environment` (must be `development`) |

### 7.12 Adversarial corpus entry

`tests/adversarial/payload_schema.py` gains category `sandbox_escape`. The corpus entries cover:

- `bwrap_filesystem_escape` — quarantined plugin attempts to `open(2)` `/etc/passwd`. Expected: returns ENOENT / EACCES at syscall level; no `SANDBOX_REFUSED_FIELDS` emit because the kernel handled it.
- `bwrap_network_escape` — plugin attempts `connect(2)` to `1.1.1.1`. Expected: returns ENETUNREACH; no audit row.
- `bwrap_subprocess_escape` — plugin attempts `execve(2)` `/bin/sh`. Expected: returns EPERM.
- `macos_sandbox_escape_subset` — same three on macOS runners.
- `manifest_omits_sandbox_block` — plugin manifest without `sandbox`. Expected: `plugin.load_refused` with `reason="sandbox_block_missing"`.

---

## 8. Comms-MCP rewrite (ADR-0016 / ADR-0024)

### 8.1 Wire contract — methods + schemas

ADR-0024 defines the comms-MCP wire contract. Eight wire methods.

**Host → plugin (JSON-RPC request, response expected):**

| Method | Params | Result |
|---|---|---|
| `lifecycle.start` | `LifecycleStartRequest(adapter_id, credentials_ref, policies_snapshot_hash)` | `LifecycleStartResult(ok, plugin_version)` |
| `lifecycle.stop` | `LifecycleStopRequest(adapter_id, reason)` | `LifecycleStopResult(ok, flushed_messages)` |
| `adapter.health` | `AdapterHealthRequest(adapter_id)` | `HealthReport(ok, last_inbound_at, queue_depth, error_count)` |
| `outbound.message` | `OutboundMessageRequest(adapter_id, idempotency_key: UUID, target_platform_id, body, attachments_refs, addressing_mode: Literal["dm","mention","channel","thread"])` | `OutboundMessageResult` (discriminated union — see below) |

The `OutboundMessageResult` is a Pydantic discriminated union, not a flat product (comms-008 closure):

```python
class _OutboundDelivered(BaseModel):
    outcome: Literal["delivered"]
    platform_message_id: str
    model_config = ConfigDict(frozen=True)

class _OutboundRetryable(BaseModel):
    outcome: Literal["retryable_failure"]
    retry_after_seconds: int          # required when retryable
    error_class: str                  # short snake_case identifier
    model_config = ConfigDict(frozen=True)

class _OutboundTerminal(BaseModel):
    outcome: Literal["terminal_failure"]
    error_class: str                  # short snake_case identifier
    detail_redacted: str               # post-DLP, ≤256 chars
    model_config = ConfigDict(frozen=True)

OutboundMessageResult = Annotated[
    _OutboundDelivered | _OutboundRetryable | _OutboundTerminal,
    Field(discriminator="outcome"),
]
```

The discriminated union forecloses field-coupling bugs (no `platform_message_id` on a failure; no `retry_after_seconds` on a delivered) — the type system enforces the correct shape per outcome. `idempotency_key` (in the request) is generated by the host and carried verbatim in retries so the adapter can dedupe across plugin restarts.

`addressing_mode` carries the four wire `Literal` values that map onto PRD §6.8's three addressing concepts (comms-012 round-3 closure — explicit mapping table):

| Wire `Literal` value | PRD §6.8 addressing concept | Discord rendering | TUI rendering |
|---|---|---|---|
| `dm` | direct (1:1) | bot DM channel | TUI direct line |
| `mention` | direct (1:N with explicit addressee) | guild channel with `@bot` | not used (TUI is 1:1 by shape) |
| `channel` | default (group, addressee not explicit) | configured guild channel | not used |
| `thread` | group | DM-thread or guild-thread | not used |

PR-S4-9's routing rule in the Discord adapter: `dm` → ephemeral DM reply; `mention` → channel reply with `@user` prefix; `channel` → bare channel reply; `thread` → reply in the originating thread. PR-S4-10's TUI adapter only emits `dm`; the host's outbound routing rejects `mention/channel/thread` outbound to TUI with `COMMS_ADDRESSING_DRIFT_FIELDS` audit row + delivery refusal.

**Plugin → host (JSON-RPC notification, no response):**

| Method | Params |
|---|---|
| `inbound.message` | `InboundMessageNotification(adapter_id, platform_user_id, body, sub_payload_refs, received_at, addressing_signal: Literal["dm","mention","channel","thread"])` |
| `adapter.binding_request` | `BindingRequestNotification(adapter_id, platform_user_id, verification_phrase, platform_metadata)` |
| `adapter.rate_limit_signal` | `RateLimitSignal(adapter_id, retry_after_seconds, platform_endpoint)` |
| `adapter.crashed` | `CrashedNotification(adapter_id, error_class, detail)` |

`addressing_signal` from the plugin carries the platform's view of how the user addressed the persona; the host validates and re-emits it via `addressing_mode` on the outbound side. Mismatched signal (e.g., DM-signalled inbound followed by channel-mode outbound) emits `COMMS_ADDRESSING_DRIFT_FIELDS` for operator visibility but does not refuse — operators may legitimately route a DM reply into a channel.

Full Pydantic schemas land in ADR-0024 and a new module at `src/alfred/comms_mcp/protocol.py`. The module path `comms_mcp` deliberately differs from the soon-to-be-deleted `comms` directory so PR-S4-10's deletion is unambiguous — there is no path collision and no "same path, different contents" git diff to interpret.

The wire-format module is consumed by the host (`AlfredPluginSession`) and by each comms-adapter plugin. The plugins import via a published `alfred_comms_protocol` package that re-exports `alfred.comms_mcp.protocol` for out-of-tree consumption.

### 8.2 Host-side `process_inbound_message` entrypoint

Lives at `src/alfred/comms_mcp/inbound.py` (host-side; the about-to-be-deleted `src/alfred/comms/` is unrelated to this new module path — see §8.8 for the deletion mechanics).

```python
async def process_inbound_message(
    notification: InboundMessageNotification,
    *,
    identity_resolver: IdentityResolver,
    orchestrator: Orchestrator,
    audit_writer: AuditWriter,
) -> None:
    """Single host-side entry consuming inbound.message notifications.

    Order is load-bearing: resolution → tier-classify → ingest → dispatch.
    """
    resolved = await identity_resolver.resolve(
        adapter_id=notification.adapter_id,
        platform_user_id=notification.platform_user_id,
    )
    if resolved is None:
        # First-contact binding flow; identity not yet bound.
        await _emit_binding_request(notification, audit_writer)
        return
    canonical_user_id = resolved.canonical_user_id
    # Inbound body trust tier is T3 — platform-relayed content is
    # adversary-authorable even from a bound user (their account may be
    # compromised; they may be forwarding hostile content). Sub-payloads
    # (embeds, attachments, polls, link-unfurls, stickers, voice notes,
    # message components, forwarded messages, pinned-message references)
    # also stay T3 as ContentHandles emitted by the host-side
    # InboundContentScanner.
    #
    # The body is NOT auto-promoted to a lower tier. The quarantined extractor
    # produces a T3DerivedData structured payload (Slice-3 type) — this is
    # T3-tier-derived data that the privileged orchestrator may consume
    # structurally without crossing the dual-LLM boundary. The result type
    # carries source_tier="T3" verbatim (sec-001 re-raise closure — there is
    # no T3→T2 silent promotion; §4.4's tier-upgrade guard refuses any such
    # downgrade-to-T2 because it would be a tier upgrade from the surrounding
    # T3 carrier).
    #
    # Cost / throughput gate (sec-008 round-3 / perf-006 closure): every
    # inbound invocation passes through TWO gates:
    #
    #   (a) The Slice-2 BudgetGuard daily USD cap per canonical_user_id (PRD
    #       §7.4) — this is the long-window cap.
    #   (b) A NEW Slice-4 primitive: an in-process token-bucket rate-limiter
    #       per (canonical_user_id, persona) with a default capacity of 5
    #       tokens and a refill rate of 1 token / 5 seconds (configurable in
    #       `PoliciesV1.rate_limits.quarantined_extract_per_user_persona`).
    #       This is the burst-window cap. Implementation: a new module at
    #       `src/alfred/orchestrator/burst_limiter.py` shipped in PR-S4-8;
    #       this is honest new Slice-4 scope, not a citation of a
    #       non-existent Slice-3 primitive.
    #
    # Bursts beyond the bucket queue with backpressure to the comms-MCP
    # semaphore (§8.4) and emit `comms.inbound.budget_capped` audit row.
    # The bucket refuses to call quarantined_extract when empty; the inbound
    # message is dropped (not silently — `comms.inbound.dropped` audit row
    # fires) after 30s of being unable to acquire a token.
    extracted = await orchestrator.quarantined_extract(
        notification.body,
        canonical_user_id=canonical_user_id,
        source_tier="T3",
    )  # -> ExtractionResult(data: T3DerivedData, schema_version=1)
    ingested = await orchestrator.ingest(
        notification,
        canonical_user_id=canonical_user_id,
        body=extracted.data,           # T3DerivedData; source_tier="T3" preserved
        addressing_signal=notification.addressing_signal,
    )
    await orchestrator.dispatch(ingested)
```

The canonical `user_id` never appears in any wire frame outbound to the plugin. The `IdentityResolver` runs host-side; the resolution result stays host-side. PR-S4-8's adversarial test verifies this by capturing every stdio frame and asserting the canonical_id string never appears, *and* by asserting the resolver is consulted exactly once per inbound notification (positive assertion, not only the negative leakage check).

### 8.3 `IdentityResolver` callback wire type

Slice 3 placed the `IdentityResolver` host-side (spec §9.1). Slice 4 finalises the host-side callback wire type. The resolver takes `(adapter_id, platform_user_id)` and returns `ResolvedIdentity | None` where `None` means "first-contact: trigger binding flow."

```python
class ResolvedIdentity(BaseModel):
    canonical_user_id: UserId
    language: str  # BCP-47 from User.language
    permissions: PermissionTier  # Literal["read_only", "standard", "trusted", "operator"]
    model_config = ConfigDict(frozen=True)
```

No transport-level callback exists. The resolver is a host-side Python call; plugins never invoke it directly. Plugins emit `inbound.message`; the host invokes the resolver. This is the "callback wire type" ADR-0016 references — the wire is the notification flowing host-ward, not a host-callable surface plugins can invoke.

### 8.4 `AlfredPluginSession` inbound notification handler

Slice 3 shipped `AlfredPluginSession` with request handling but no notification routing. PR-S4-8 adds the notification dispatcher:

```python
class AlfredPluginSession:
    def __init__(
        self,
        ...,
        inbound_handler: InboundHandler,  # new in Slice 4
    ): ...

    async def _on_notification(self, notification: JsonRpcNotification) -> None:
        async with self._dispatch_semaphore:                          # core-008 closure
            try:
                match notification.method:
                    case "inbound.message":
                        payload = InboundMessageNotification.model_validate(notification.params)
                        await self._inbound_handler.process(payload)
                    case "adapter.binding_request":
                        payload = BindingRequestNotification.model_validate(notification.params)
                        await self._binding_handler.process(payload)
                    case "adapter.rate_limit_signal":
                        payload = RateLimitSignal.model_validate(notification.params)
                        await self._rate_limit_handler.process(payload)
                    case "adapter.crashed":
                        payload = CrashedNotification.model_validate(notification.params)
                        await self._crash_handler.process(payload)
                    case _:
                        # Unknown notification — typed audit row, then drop, then schedule
                        # a plugin restart. The drop is NOT silent.
                        await self._audit.append_schema(
                            COMMS_UNKNOWN_NOTIFICATION_FIELDS,
                            adapter_id=self._adapter_id,
                            method=notification.method,
                            method_redacted_params=_redact(notification.params),
                            observed_at=datetime.now(UTC),
                        )
                        # request_plugin_restart contract (err-007 / core-006 closure):
                        # this method is added to Supervisor in PR-S4-8 (see §14 task
                        # list). It writes a `supervisor.plugin_restart_requested`
                        # audit row, marks the adapter unhealthy, and returns; the
                        # supervisor's existing breaker loop spawns a fresh adapter
                        # on next tick. If the restart-request write ITSELF fails
                        # (Postgres down, etc.), the exception propagates — the outer
                        # except handles it via COMMS_HANDLER_FAILED_FIELDS below.
                        await self._supervisor.request_plugin_restart(
                            self._adapter_id, reason="unknown_notification",
                        )
            except Exception as exc:
                # err-007 closure: handler/dispatcher exceptions are loud, not
                # silent. The original exception propagates after the audit + the
                # adapter is marked unhealthy.
                await self._audit.append_schema(
                    COMMS_HANDLER_FAILED_FIELDS,
                    adapter_id=self._adapter_id,
                    notification_method=notification.method,
                    handler_class=type(exc).__qualname__ if False else "dispatcher",
                    error_class=type(exc).__qualname__,
                    detail_redacted=await self._outbound_dlp.scan(str(exc))[:512],
                    failed_at=datetime.now(UTC),
                )
                self._error_counter.increment()
                if self._error_counter.exceeds(threshold=3, window=timedelta(minutes=5)):
                    await self._supervisor.trip_breaker(
                        component_id=self._adapter_id,
                        reason="comms_handler_repeated_failures",
                    )
                raise   # propagates to AlfredPluginSession._read_loop
```

**Method dispatch + catch-and-continue contract** (err-009 round-3 + core-011 round-4 closure — *honest* this time about what exists on Slice-3 `AlfredPluginSession`): the Slice-3 class exposes `_on_post_handshake_method(method: str)` at `src/alfred/plugins/session.py:347`, not a `_read_loop` or `_on_notification` method (I asserted both in earlier rounds; neither exists). PR-S4-8 extends the existing method so it routes notification method-names to the four handler callbacks instead of inventing a parallel dispatch surface. The match block above moves into `_on_post_handshake_method`'s body.

The catch-and-continue contract lives at the **MCP transport reader** (Slice-3 `StdioTransport`), one level below the session. When a session method raises, the transport's reader logs via structlog (`event="comms.transport.method_failed"`) and continues to the next frame. The session is **not** torn down by a single bad notification — only an explicit `supervisor.tear_down_session` call kills the session. PR-S4-8 doesn't change this — it inherits the Slice-3 transport-level discipline. PR-S4-8's §13 task list (NOT §14 — core-006 round-4 closure on the forward-ref drift) adds the new `try` block to `_on_post_handshake_method` + the structlog `comms.transport.method_failed` event taxonomy entry.

The `InboundHandler` Protocol is `class InboundHandler(Protocol): async def process(self, notification) -> None: ...` and the concrete implementation is `process_inbound_message` bound with `IdentityResolver` + `Orchestrator` + `AuditWriter`. The four handlers (`InboundHandler`, `BindingHandler`, `RateLimitHandler`, `CrashHandler`) are constructed at `AlfredPluginSession` instantiation time and held as instance state — no per-notification handler resolution.

Handler callbacks are awaited sequentially per notification (no concurrent fan-out for a single message). The `async with self._dispatch_semaphore` block (perf-003 closure) is a **per-adapter** `asyncio.BoundedSemaphore(value=Settings.comms_max_in_flight_notifications, default=32)`. The cap is per-session, not process-wide — three adapter sessions each get their own 32-slot cap, so adapter A's rate-limit storm cannot starve adapter B (perf-003 closure on the per-adapter clarification). The semaphore is acquired-and-released via `async with`, guaranteeing release on exception (core-008 closure). Exceeding the limit applies backpressure to the stdio reader's pending-notifications queue, which in turn applies kernel-pipe backpressure to the plugin once the read-buffer is full.

**New host-side methods PR-S4-8 adds to `Supervisor`** (core-006 closure — these methods do not exist on Slice-3 `Supervisor`):

- `request_plugin_restart(adapter_id, reason)` — writes `supervisor.plugin_restart_requested` audit row, marks the adapter unhealthy in the breaker, returns. The next supervisor tick spawns a fresh adapter via the launcher.
- `trip_breaker(component_id, reason)` — extends the Slice-3 `Supervisor.trip_breaker` (which exists, per `src/alfred/supervisor/core.py`) with a new `reason="comms_handler_repeated_failures"` Literal entry.

PR-S4-8's §13 row enumerates these as task items (core-006 round-4 closure on the §14→§13 forward-ref drift).

### 8.5 `InboundContentScanner` extension for Discord sub-payloads

Slice 3 shipped `StdioTransport.InboundContentScanner` that tags raw stdio frames T3 at the transport boundary. The Discord adapter brings new content-types (embeds, attachments, polls) that need per-sub-payload T3 promotion. The scanner gains a data-driven classifier:

```python
class InboundContentScanner:
    def __init__(self, classifiers: Sequence[SubPayloadClassifier]): ...

    async def scan(self, frame: bytes) -> ScannedFrame:
        """Identify sub-payloads; emit ContentHandle for each T3-promoted sub-payload."""
```

PR-S4-9 ships `DiscordSubPayloadClassifier` as **host-side** code under `src/alfred/comms_mcp/classifiers/discord.py`. The classifier recognises Discord-shaped JSON sub-payloads and emits a `ContentHandle` for each. The handle replaces the field in the body so the orchestrator never sees the raw sub-payload.

The host owns a **required-classifier registry** keyed by adapter kind. Plugins may not opt out of required classifiers; they may only opt in *additional* classifiers from the host registry:

```yaml
# In a plugin manifest:
comms_mcp:
  adapter_kind: discord           # selects required classifier set host-side
  classifiers_optional: []        # plugin may opt in additional registered classifiers
```

The host's `REQUIRED_CLASSIFIERS_BY_KIND` table is owned in `src/alfred/comms_mcp/classifier_registry.py`:

| Adapter kind | Required classifier set |
|---|---|
| `discord` | `discord_sub_payloads` (embeds, attachments, polls, stickers, voice messages, message components, forwarded-message references, pinned-message references, link unfurls) |
| `tui` | (empty — plain-text plugin) |
| `telegram` (post-MVP) | `telegram_sub_payloads` (entities, attachments, forwards, polls) |

A plugin whose manifest declares `adapter_kind: discord` runs the `discord_sub_payloads` classifier set host-side regardless of what `classifiers_optional` lists. A plugin whose manifest declares an *unknown* `adapter_kind` is refused at load via `plugin.load_refused` with `reason="unknown_adapter_kind"`.

**Adapter-kind registration coherence** (sec-002 re-raise closure): the round-1 spec said "adapter-kind registration is reviewer-gated and travels in state.git, not the plugin manifest" — but the registry actually lives in `src/alfred/comms_mcp/classifier_registry.py` (Python source). Clarifying the authority chain:

1. The set of valid `adapter_kind` Literal values lives in `src/alfred/comms_mcp/protocol.py` as a `Final[frozenset[str]]` — same compile-time constant pattern as the Slice-3 `_PREFIX_TO_CATEGORY`.
2. Adding a new `adapter_kind` is a code change in `src/` and goes through the standard AlfredOS PR review (reviewer agent + human-approval-as-needed per CLAUDE.md self-improvement rules). There is no state.git path; the round-1 wording was wrong.
3. The matching `REQUIRED_CLASSIFIERS_BY_KIND` entry must land in the same PR as the new `adapter_kind` (enforced by a `tests/unit/comms_mcp/test_required_classifiers_complete.py` AST guard).
4. A PR adding an `adapter_kind` with an **empty** required set is refused at the AST guard — each new kind must justify either ≥1 required classifier (typical case) or an explicit `MARKER_NO_CLASSIFIERS_NEEDED: Final = "plain-text only, justified in PR description"` constant (TUI-style adapters).

This closes the bypass surface: introducing a malicious empty-classifier adapter-kind requires a PR that the AST guard refuses, the reviewer agent inspects, and a human approves.

Manifests never carry executable classifier code — that would be plugin code running host-side, which violates PRD §5 plugin-isolation invariants. Each entry in the required-classifier set names a host-side Python class registered via `@register_classifier(kind="discord", name="discord_sub_payloads")` at import time.

**Discord intent profiles** (comms-010 closure): a Discord bot may run with different gateway intent sets (e.g., `members_intent`, `message_content_intent`). The required-classifier set is keyed by `adapter_kind`, not by intent profile — all Discord bots run the same `discord_sub_payloads` set. Intent variations affect what the plugin *receives* from Discord; the host-side classification of received content stays uniform. If a future Discord variant ships with materially different sub-payloads (e.g., voice-only bots), it gets a new `adapter_kind` (`discord_voice`) and a new required-classifier-set entry.

### 8.6 Discord adapter — embeds / attachments / polls T3 promotion + persona-addressing

`plugins/alfred_discord/` ships with:

- The Discord gateway connection (uses `discord.py` or equivalent; library choice deferred to PR-S4-9; see §15).
- `adapter_kind: discord` in manifest, which activates the host-side required classifier set per §8.5.
- Identity binding: receives platform user info; emits `adapter.binding_request` for first-contact; receives `outbound.message` for replies.
- Rate-limit signal emission when Discord rate-limits the bot. The plugin emits `adapter.rate_limit_signal(retry_after_seconds=…)` and pauses outbound emit; the host's outbound queue honours the signal via `OutboundQueue.pause(adapter_id, retry_after_seconds)` and resumes automatically (comms-005 closure).
- Persona-addressing inference: the adapter maps Discord's three reception shapes onto `addressing_signal: Literal["dm","mention","channel","thread"]`:
  - **DM** — bot's DM channel: `addressing_signal="dm"`.
  - **Mention** in a guild channel: `addressing_signal="mention"`.
  - **Plain channel message** in a channel the bot is configured to listen to: `addressing_signal="channel"`.
  - **Thread message** (DM-thread, guild-thread): `addressing_signal="thread"`.
  The host validates the signal and uses it for orchestrator routing (PRD §6.8 addressing-mode resolver). The reverse direction (`outbound.message.addressing_mode`) tells the adapter how to render the reply.

The Discord-specific sub-payload promotion happens at the transport boundary, not in-adapter. The adapter emits the full Discord message JSON in `inbound.message.body`; the host-side `InboundContentScanner` runs the required classifier set and emits handles for sub-payloads before the body reaches `process_inbound_message`. The orchestrator sees:

- T3: `body.content` (the user's free-text — adversary-authorable; §8.2 bumps it to T3 by default and passes through `quarantined_extract`).
- T3 handles: every sub-payload kind in the required classifier set — `body.embeds.*`, `body.attachments.*`, `body.poll.*`, `body.stickers.*`, `body.voice_message.*`, `body.components.*`, `body.message_reference.*` (forwarded / replied-to / pinned references), and link unfurls.

PRD §6.1's "T3 for web previews, link unfurls, forwarded content" classification maps onto these handle kinds. Attachments and voice notes are T3 because they could be arbitrary user-uploaded content. Forwarded and pinned-message references are T3 because the original-message author is not the inbound user — adversary substitution risk.

**Per-adapter body field-name mapping** (comms-011 closure): Discord delivers the user's free-text under `body.content`. Telegram (post-MVP) delivers it under `body.text`. The host-side `InboundContentScanner` consults the adapter's `adapter_kind` to look up the body-field path in `BODY_FIELD_BY_KIND`:

```python
BODY_FIELD_BY_KIND: Final[Mapping[str, str]] = {
    "discord": "content",
    "tui": "content",            # TUI uses the same field for plain-text bodies
    "telegram": "text",          # post-MVP
}
```

The mapping lives in `src/alfred/comms_mcp/protocol.py` alongside the adapter-kind Literal. Adding a new adapter kind adds its body-field entry in the same PR; the AST guard from §8.5 also asserts every kind has an entry. The orchestrator-side ingest receives a normalised `body.text: str` field regardless of platform.

### 8.7 TUI adapter — `alfred chat` spawns via launcher

`plugins/alfred_tui/` ships with:

- A Textual-based TUI (Slice-1 baseline; rewrites as an MCP plugin).
- Manifest declaring `sandbox.kind: none` (operator-facing CLI, PTY access required).
- `inbound.message` emission for each user keystroke-batch.
- `outbound.message` consumption for orchestrator replies.

`alfred chat` becomes a thin CLI wrapper that spawns the TUI plugin via `bin/alfred-plugin-launcher`. The launcher hands the TUI plugin a stdio MCP boundary to the daemon (which must already be running per §3.1) — TUI without a running daemon refuses with the operator-facing message *"alfred chat needs the daemon. Start it with: `alfred daemon start`. If you expected a daemon to be running, check status with: `alfred daemon status`."* This string is `t("comms.tui.daemon_required_to_chat")` in §12.2 (devex-003 closure).

Daemon-mid-restart race: the launcher's daemon-handshake probe times out at 2.5 seconds. If the daemon was running and is now restarting, the probe fails with the same message above, telling the operator to retry. The TUI plugin does not wait-and-retry inside its own process — that would create silent foreground-wait UX. The operator retries from the shell (core-005 closure).

### 8.8 In-process `CommsAdapter` Protocol deletion

PR-S4-10 deletes `src/alfred/comms/` entirely. **No file at any path inside `src/alfred/comms/` survives the deletion** — the wire-format owner lives at `src/alfred/comms_mcp/protocol.py` (per §8.1) and never at `src/alfred/comms/protocol.py`. There is no path collision and no "same path, different contents" git diff.

The deletion covers:

- `src/alfred/comms/protocol.py` — the in-process Protocol; replaced by the unrelated `src/alfred/comms_mcp/protocol.py` (PR-S4-8 shipped).
- `src/alfred/comms/discord/` — the Slice-2 in-process Discord adapter; replaced by `plugins/alfred_discord/`.
- `src/alfred/comms/tui/` — the Slice-1 in-process TUI; replaced by `plugins/alfred_tui/`.
- All wiring code referencing the in-process Protocol.

The PR-S4-10 deletion has documented breakage scope. Every known consumer of the in-process Protocol gets migrated atomically in the PR (comms-006 closure):

| Consumer file | Migration shape |
|---|---|
| `tests/smoke/test_discord_gateway_smoke.py` (Slice-2-shipped — comms-009-r4 / rev-011 round-4 closure: round-2 named `test_discord_round_trip.py` which does not exist; the real file is `test_discord_gateway_smoke.py`) | Rewritten against MCP-plugin Discord; assertions stay |
| `tests/smoke/test_tui_e2e.py` (Slice-1-shipped) | Rewritten to spawn `plugins/alfred_tui/` via the launcher; assertions stay |
| `tests/smoke/test_slice4_graduation.py` (new; PR-S4-10 — see §14 criterion 7) | Compose-up + login + chat round-trip — covers the TUI plugin path |
| `src/alfred/identity/_ingest.py` | `adapter_name` references migrate to `adapter_id` from `InboundMessageNotification` |
| `src/alfred/cli/main.py` | `alfred chat` rewires to launcher spawn (§8.7) |
| `tests/unit/comms/test_no_direct_adapter_imports.py` | AST guard rewired to assert the `src/alfred/comms/` package is absent rather than not-imported |
| **(Pre-flight grep adds any further importers found at PR-S4-10 time)** | A `grep -rn 'from alfred.comms\|import alfred.comms' src/ tests/` immediately before the PR-S4-10 deletion captures the full consumer set; new entries get the appropriate migration shape and join this table in the PR description |

A pre-flight grep on `main` before PR-S4-10 ships re-verifies the consumer list. New consumers added after spec authoring are absorbed into PR-S4-10's task list.

The TUI plugin (`plugins/alfred_tui/`) keeps the Slice-1 Textual rendering layer; the rewrite is the MCP-stdio boundary plus the inversion of the in-process Protocol direction. Textual code under `plugins/alfred_tui/textual/` is largely a verbatim move from `src/alfred/comms/tui/textual/`.

### 8.9 ADR-0009 caveat narrowing + #152 closure

ADR-0009 already reads "Superseded by ADR-0016 (for new adapters); in-process adapters unchanged through Slice 3" since 2026-05-27 (PR-S3-0a). Slice 4 is not a status *flip* — there's nothing to flip from. PR-S4-10 *narrows* the caveat by removing the "for new adapters" qualifier (now that the in-process adapters are also gone) and updates the body's "in-process adapters unchanged through Slice 3" line to "in-process adapters removed in Slice 4 per PR-S4-10". This is a one-shot caveat update; no earlier PR may touch the ADR-0009 status header in this slice (docs-001 closure).

PR-S4-0a's reference to ADR-0009 stays as it is — the footnote was already updated to point at the comms-MCP rewrite in slice 3. PR-S4-0a's diff against ADR-0009 is zero.

Issue #152 closes via PR-S4-8's new `tests/integration/test_comms_mcp_identity_boundary_real.py`. The test sets up an `AlfredPluginSession` with the reference comms-test plugin, plants a malicious `inbound.message` notification carrying a forged `platform_metadata.canonical_user_id` field, and asserts (test-004 closure — these are positive + negative + binding-flow + persona-forgery):

1. The notification reaches `process_inbound_message` exactly once (positive assertion — a no-op resolver fails the test).
2. `IdentityResolver.resolve` is consulted exactly once with the platform identifiers from the notification (positive call-count assertion via spy).
3. The `IdentityResolver` runs host-side; the canonical id it returns is from the resolver state, not from `platform_metadata`.
4. The canonical id never appears in any captured stdio frame outbound to the plugin (planted-id-leakage assertion).
5. A `COMMS_INBOUND_T3_PROMOTION_FIELDS` audit row records the resolution.
6. The first-contact path (`resolved is None`) emits `COMMS_BINDING_REQUESTED_FIELDS` and never reaches `orchestrator.dispatch`.
7. An inter-persona forgery variant — a relay-message from persona A to persona B carrying T3 content as if it came from a T2 source — is refused at `quarantined_extract` and emits `COMMS_INBOUND_T3_PROMOTION_FIELDS.refused`.

### 8.10 Audit row family

| Constant | Fields |
|---|---|
| `COMMS_INBOUND_T3_PROMOTION_FIELDS` | `adapter_id`, `inbound_message_id` (uuid), `platform_user_id_hash`, `canonical_user_id`, `sub_payload_kinds` (frozenset of `Literal["embed","attachment","poll","link_unfurl","sticker","voice_message","component","forwarded_ref","pinned_ref"]`), `language`, `addressing_signal` |
| `COMMS_BINDING_REQUESTED_FIELDS` | `adapter_id`, `platform_user_id_hash`, `verification_phrase_hash`, `requested_at` |
| `COMMS_ADAPTER_CRASHED_FIELDS` | `adapter_id`, `error_class`, `detail_redacted` (post-DLP), `crashed_at` |
| `COMMS_RATE_LIMIT_SIGNAL_FIELDS` | `adapter_id`, `platform_endpoint`, `retry_after_seconds`, `signalled_at` |
| `COMMS_UNKNOWN_NOTIFICATION_FIELDS` | `adapter_id`, `method`, `method_redacted_params`, `observed_at` |
| `COMMS_HANDLER_FAILED_FIELDS` | `adapter_id`, `notification_method`, `handler_class`, `error_class`, `detail_redacted`, `failed_at` |
| `COMMS_ADDRESSING_DRIFT_FIELDS` | `adapter_id`, `inbound_signal`, `outbound_mode`, `canonical_user_id`, `observed_at` |

Note `platform_user_id_hash` and `verification_phrase_hash` — the raw values are not written to the audit log. The hash recipe (comms-004 round-2 + comms-007 + sec-010 round-3 closure — uses the real Slice-3 `SecretBroker.get(name) -> str` API at `src/alfred/security/secrets.py:396`):

```python
# AuditWriter constructor (PR-S4-0b extension):
pepper_str: str = secret_broker.get("audit.hash_pepper")    # Slice-3 broker API
pepper_bytes: bytes = pepper_str.encode("utf-8")

# Per-row hashing:
hash = hmac.new(
    key=pepper_bytes,
    msg=raw_value.encode("utf-8"),
    digestmod=hashlib.sha256,
).hexdigest()
```

The pepper is **broker-resident**: it lives in the encrypted broker vault (default: age-encrypted TOML per ADR-0005 + ADR-0012) under the secret name `audit.hash_pepper`. The `AuditWriter` fetches it at host startup and holds the bytes in-process for the daemon's lifetime. It is **not** a `Settings.audit_hash_pepper` field — that earlier round-1/round-2 phrasing was wrong (Settings fields are env/config-sourced).

**Bootstrap step in PR-S4-0b**: the migration adds the pepper to the operator's broker config; if missing at daemon boot, the daemon emits `daemon.boot.failed` with `failure_reason="audit_hash_pepper_missing"` and refuses to start, telling the operator to add the secret (the operator does this via the existing Slice-1 secret-broker config flow). There is no fallback to an empty pepper.

Rotating the pepper (via the operator's broker edit) invalidates cross-row correlation but does not lose data (a deliberate trade-off documented in `docs/subsystems/security.md`). The `machine_id_hash` field in §9 and all `*_hash` fields throughout §9/§8.10 use the same recipe.

A Slice-5 broker-hardening backlog item adds a custom-named accessor `secret_broker.fetch_audit_pepper()` plus per-secret access logging (currently the Slice-3 broker has no per-fetch audit). Slice 4 uses the generic `.get(name)`.

---

## 9. Audit-row schemas (Slice-4 additions)

PR-S4-0a adds these `Final` frozenset constants to `src/alfred/audit/audit_row_schemas.py`. Each constant's field list is exhaustive; downstream PRs may not extend or shrink.

| Constant | Fields | Defined in §, consumed in PR |
|---|---|---|
| `DAEMON_BOOT_FIELDS` | `boot_id`, `started_at`, `state_git_head_sha`, `slice_version`, `policies_snapshot_hash`, `environment` | §3.2 / PR-S4-1 |
| `DAEMON_BOOT_FAILED_FIELDS` | `boot_id`, `attempted_at`, `failure_reason`, `environment_source` | §3.2, §3.4 / PR-S4-1 |
| `DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS` | `boot_id`, `env_var_value`, `etc_file_value`, `resolved_value` | §7.3 / PR-S4-1 |
| `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` | `proposal_branch`, `dispatch_attempted_at`, `failure_class`, `redacted_detail`, `dlp_redactions_count` | §3.3 / PR-S4-2 (emitted on success AND on redactions-but-not-refusal — sec-005) |
| `CARRIER_SUBSTITUTION_FIELDS` | `hookpoint`, `subscriber_id`, `source_tier`, `carrier_tier`, `substituted_at` | §4.3 / PR-S4-3 |
| `CARRIER_SUBSTITUTION_REFUSED_FIELDS` | `hookpoint`, `subscriber_id`, `attempted_source_tier`, `carrier_tier`, `reason`, `refused_at` | §4.4 / PR-S4-3 (reason ∈ `tier_upgrade_refused` \| `recursion_refused`) |
| `CONFIG_RELOAD_FIELDS` | `file_path`, `prev_sha256`, `new_sha256`, `changed_keys`, `loaded_at` | §5.6 / PR-S4-4 |
| `CONFIG_RELOAD_REJECTED_FIELDS` | `file_path`, `attempted_sha256`, `reason` (`parse_failure` \| `high_blast_change` \| `validation_failure` \| `file_vanished` \| `stat_failed` \| `audit_write_failed`), `offending_key`, `dlp_scan_result` | §5.6 / PR-S4-4 (err-011 round-4 closure — `audit_write_failed` added per §5.3 swap path) |
| `OPERATOR_SESSION_CREATED_FIELDS` | `user_id`, `issued_at`, `expires_at`, `host`, `machine_id_hash`, `via` | §6.6 / PR-S4-5 |
| `OPERATOR_SESSION_REVOKED_FIELDS` | `user_id`, `revoked_at`, `via` | §6.6 / PR-S4-5 |
| `OPERATOR_SESSION_REFUSED_FIELDS` | `attempted_user_id`, `reason`, `host`, `machine_id_hash` | §6.6 / PR-S4-5 |
| `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS` | `component_id`, `reason`, `attempted_at` | §6.7 / PR-S4-5 |
| `SANDBOX_REFUSED_FIELDS` | `plugin_id`, `policy_ref`, `host_os`, `reason`, `environment` | §7.11 / PR-S4-6 |
| `SANDBOX_STUB_USED_FIELDS` | `plugin_id`, `policy_ref`, `host_os`, `environment` | §7.11 / PR-S4-7 |
| `COMMS_INBOUND_T3_PROMOTION_FIELDS` | `adapter_id`, `inbound_message_id`, `platform_user_id_hash`, `canonical_user_id`, `sub_payload_kinds`, `language`, `addressing_signal` | §8.10 / PR-S4-8 (all comms audit emits live host-side) |
| `COMMS_BINDING_REQUESTED_FIELDS` | `adapter_id`, `platform_user_id_hash`, `verification_phrase_hash`, `requested_at` | §8.10 / PR-S4-8 (CodeRabbit major #1 closure — uses `platform_user_id_hash` consistently with §8.10 row above, not the raw `platform_user_id` that the round-1 spec wrote) |
| `COMMS_ADAPTER_CRASHED_FIELDS` | `adapter_id`, `error_class`, `detail_redacted`, `crashed_at` | §8.10 / PR-S4-8 |
| `COMMS_RATE_LIMIT_SIGNAL_FIELDS` | `adapter_id`, `platform_endpoint`, `retry_after_seconds`, `signalled_at` | §8.10 / PR-S4-8 |
| `COMMS_UNKNOWN_NOTIFICATION_FIELDS` | `adapter_id`, `method`, `method_redacted_params`, `observed_at` | §8.4 / PR-S4-8 (Critical 6) |
| `COMMS_HANDLER_FAILED_FIELDS` | `adapter_id`, `notification_method`, `handler_class`, `error_class`, `detail_redacted`, `failed_at` | §8.4 / PR-S4-8 |
| `COMMS_ADDRESSING_DRIFT_FIELDS` | `adapter_id`, `inbound_signal`, `outbound_mode`, `canonical_user_id`, `observed_at` | §8.1 / PR-S4-8 |
| `COMMS_INBOUND_BUDGET_CAPPED_FIELDS` | `adapter_id`, `canonical_user_id`, `persona`, `tokens_available`, `wait_seconds`, `dropped`, `observed_at` | §8.2 / PR-S4-8 (sec-008 round-3 — BurstLimiter emit) |
| `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS` | `plugin_id`, `reason`, `requested_at`, `requester` | §8.4 / PR-S4-8 (core-010 round-3 closure — round-2 named the row in prose but never enumerated the field set) |

Per ADR-0024 every comms audit row is emitted by host code on receipt of a plugin notification — adapters are plugin processes and never write to the audit log directly. PR-S4-9 and PR-S4-10 ship adapter code that triggers these notifications; the audit-emit sites stay in PR-S4-8.

PR-S4-0a's test for the constants asserts every field name in every constant is a valid column in the `AuditEntry` model (no orphan fields). PR-S4-0b's Alembic migration adds the new columns if any.

---

## 10. Hookpoint surface (Slice-4 additions)

**Each hookpoint is registered by the PR named in its row's "Declared in PR" column** (arch-007 / rev-010 round-4 closure — the single source of truth is the table; the prose below the table reinforces it). PR-S4-0a does **not** register hookpoints; its scope is `audit_row_schemas.py` constants + `payload_schema.py` Literals. Each hookpoint declares its subscribable tiers exhaustively.

| Hookpoint | Declared in PR | `subscribable_tiers` | `fail_closed` | `carrier_tier` |
|---|---|---|---|---|
| `daemon.boot.completed` | PR-S4-1 | `SYSTEM_OPERATOR_TIERS` | `True` | `T0` |
| `daemon.boot.failed` | PR-S4-1 | `SYSTEM_OPERATOR_TIERS` | `True` | `T0` |
| `proposal.dispatch.failed` | PR-S4-1 | `SYSTEM_ONLY_TIERS` | `True` | `T0` |
| `hooks.carrier_substituted` | PR-S4-3 | `SYSTEM_ONLY_TIERS` | `False` (observation-only post-stage; see §4.7) | n/a (no carrier) |
| `hooks.carrier_substitution_refused` | PR-S4-3 | `SYSTEM_ONLY_TIERS` | `False` (observation-only post-stage; see §4.7) | n/a (no carrier) |
| `supervisor.config_reload` | PR-S4-4 | `SYSTEM_OPERATOR_TIERS` | `True` | `T0` |
| `supervisor.config_reload_rejected` | PR-S4-4 | `SYSTEM_ONLY_TIERS` | `True` | `T0` |
| `operator.session.created` | PR-S4-5 | `SYSTEM_ONLY_TIERS` | `True` | `T1` |
| `operator.session.revoked` | PR-S4-5 | `SYSTEM_ONLY_TIERS` | `True` | `T1` |
| `operator.session.refused` | PR-S4-5 | `SYSTEM_ONLY_TIERS` | `True` | `T1` |
| `supervisor.plugin.sandbox_refused` | PR-S4-6 | `SYSTEM_ONLY_TIERS` | `True` | `T0` |
| `supervisor.plugin.sandbox_stub_used` | PR-S4-7 | `SYSTEM_OPERATOR_TIERS` | `True` | `T0` |
| `comms.inbound.t3_promoted` | PR-S4-8 | `SYSTEM_ONLY_TIERS` | `True` | `T3` (the inbound body) |
| `comms.adapter.binding_requested` | PR-S4-9 | `SYSTEM_OPERATOR_TIERS` | `False` | `T3` (the requesting platform identity) |
| `comms.adapter.crashed` | PR-S4-8 | `SYSTEM_OPERATOR_TIERS` | `False` | `T0` (a daemon event) |
| `comms.adapter.rate_limit_signal` | PR-S4-9 | `SYSTEM_OPERATOR_TIERS` | `False` | `T0` (a daemon event) |

The `carrier_tier` column is the **surrounding action's** declared tier, consumed by §4.4's tier-upgrade refusal logic. Meta-hookpoints (`hooks.carrier_*`) have no carrier because they are observation-only and never substitute (sec-009 closure).

**Hookpoint-registration ownership** (rev-009 + arch-007 round-3 closure — three-way contradiction resolved):

- PR-S4-3 ships `HookpointMeta.carrier_tier: TrustTier` + `HookpointMeta.allow_error_substitution: bool` as new required fields on the `HookpointMeta` dataclass. PR-S4-3 itself registers only the two `hooks.carrier_*` meta-hookpoints (which carry `carrier_tier=None` since they're observation-only).
- Every other Slice-4 hookpoint is registered by its **owning PR** (the "Declared in PR" column above). PR-S4-3 must merge before any other hookpoint-registering PR — `PR-S4-3` is therefore an ancestor of PR-S4-1, PR-S4-4, PR-S4-5, PR-S4-6, PR-S4-7, PR-S4-8, PR-S4-9 in the §13 dependency table. The single new dependency edge is `PR-S4-3 → {1, 4, 5, 6, 7, 8, 9}`; the merge-order PR table is updated accordingly.
- A `tests/unit/hooks/test_carrier_tier_required.py` AST guard refuses any `register_hookpoint(...)` call that omits `carrier_tier=`. The guard runs against `src/` in `make check`.

PR-S4-0a does **not** register any hookpoints; its scope is `audit_row_schemas.py` + `payload_schema.py` (pure docs / constants).

All hookpoints use the Slice-3-shipped `SYSTEM_ONLY_TIERS` / `SYSTEM_OPERATOR_TIERS` constants from `src/alfred/hooks/registry.py`. The `fail_closed=True` posture matches Slice 3's default for security-sensitive hookpoints; the three `fail_closed=False` hookpoints are observation-only events where a subscriber crash should not fail-close the originating action (a comms adapter crash should not bring down the daemon; a rate-limit signal must propagate even if a subscriber misbehaves).

Issue #167 (per-kind `fail_closed` override) is explicitly deferred. The Slice-4 hookpoints carry uniform `fail_closed` across all kinds (pre / post / error / cancel).

**Hookpoint declaration ownership** (arch-007 round-3 closure — round-2 had three sites making overlapping claims; resolved to a single rule): every row's "Declared in PR" column is the **single source of truth** for which PR registers that hookpoint. PR-S4-3 ships only the `hooks.carrier_*` meta-hookpoints + the `HookpointMeta` field extensions. Other PRs register their own per §4.7. PR-S4-0a does not register hookpoints.

---

## 11. Adversarial corpus additions

### 11.1 New categories

`tests/adversarial/payload_schema.py` gains both Literal entries AND the `_PREFIX_TO_CATEGORY` / `_ID_PATTERN` dispatch-table extensions PR-S4-0a must ship together (Critical 7 closure). The Slice-3-shipped `_ID_PATTERN` is `^(pi|dlp|cap|cnry|ipp|hk|tl|de)-\d{4}-\d{3}$` — **prefix-YYYY-NNN, no snake_case suffix in the ID itself**. The Slice-4 extension adds prefixes only; the ID format stays exactly the same (test-006 closure — the round-1 fixup proposed `prefix-NNN_snake_case` which would have broken every existing payload):

```python
SLICE_4_CATEGORIES = frozenset({
    "sandbox_escape",
    "config_reload_bypass",
    "carrier_substitution_tamper",
    "operator_session_forgery",
    "comms_identity_boundary",  # for the #152 closure test
})

# Slice-4 additions to the existing _PREFIX_TO_CATEGORY dict:
_PREFIX_TO_CATEGORY.update({
    "sbx": "sandbox_escape",
    "crf": "carrier_substitution_tamper",   # crf = carrier-refusal/refused
    "csb": "config_reload_bypass",
    "osf": "operator_session_forgery",
    "cib": "comms_identity_boundary",
})

# _ID_PATTERN gains the new prefixes — preserving the prefix-YYYY-NNN format:
_ID_PATTERN = re.compile(
    r"^(pi|dlp|cap|cnry|ipp|hk|tl|de|sbx|crf|csb|osf|cib)-\d{4}-\d{3}$"
)
```

PR-S4-0a's test `tests/unit/adversarial/test_slice_4_categories.py` asserts every Slice-4 corpus YAML's `id:` field parses against this regex, every entry's prefix maps to the declared category, and every category has at least one entry shipped at slice graduation. Slice-4 corpus authors get a clear contract: pick a prefix from the table above; the ID is `<prefix>-2026-NNN` (year + zero-padded sequence). Human-readable summary lives in the YAML's `title:` field, not in the ID.

### 11.2 New `IngestionPath` extensions

```python
SLICE_4_INGESTION_PATHS = frozenset({
    "sandbox_policy_load",
    "operator_session_file",
    "mtime_poll",
    "inbound_notification_handler",
    "proposal_dispatch_failure",
    "comms_inbound_message",      # for the §8 inbound path
    "stdio_fd3_key_delivery",     # for the §7.5 fd-3 zeroization test
})
```

### 11.3 New `ExpectedOutcome` extensions

```python
SLICE_4_EXPECTED_OUTCOMES = frozenset({
    "sandbox_refused",
    "reload_rejected",
    "substitution_refused",
    "session_refused",
    "boundary_refused",   # already in Slice 3; reused for §8 tests
    "policy_swap_aborted_on_audit_failure",   # for the §5.3 swap-audit semantics
    "recursion_refused",                       # for the §4.6 crf-004 meta-hookpoint test
})
```

### 11.4 Test placement + attacker models

- Sandbox tests live under `tests/adversarial/sandbox_escape/`. **Attacker models** (test-003 + test-009 closure — round-1 named only one misconfigured-policy flag; round-2 expands to cover the full surface):
  - **Insider-author**: the plugin author intentionally writes a payload that escapes the sandbox. Test asserts the kernel refuses the syscall AND the resolver-misconfiguration bypass cannot be triggered by a manifest field.
  - **Runtime-compromised**: an injected payload running inside a sandboxed plugin attempts escape via `open`/`connect`/`execve`/`mount`. Test asserts the kernel refuses.
  - **Misconfigured-policy**: the operator ships a policy file with each of the following flags missing in turn — `--unshare-net`, `--die-with-parent`, `--ro-bind /` (rebinds root writable), `--share-net` (re-enables net), `--unshare-pid` — and a schema-version-downgrade variant. Each test asserts the launcher's policy validator rejects the policy at load time with `supervisor.plugin.sandbox_refused(reason="policy_invalid_<flag>")` rather than spawning with the relaxed policy.
- Config-reload tests under `tests/adversarial/config_reload_bypass/`. Includes TOCTOU (write-then-symlink between mtime check and read), parser-OOM (a YAML billion-laughs payload), mtime-stable revert (an attacker writes back the pre-attack version after a brief swap), AND mtime-skew (an attacker sets the file mtime backward to defeat the watcher) — test-005 closure.
- Carrier-substitution tests under `tests/adversarial/carrier_substitution_tamper/`. Includes `crf-004 meta_hookpoint_recursion_attempt` per §4.6 — test-005 closure.
- Operator-session tests under `tests/adversarial/operator_session_forgery/`.
- The comms identity-boundary test (#152 closure) lives in `tests/integration/` (not adversarial) because it tests a host-side contract, not a payload class — but it includes positive assertions per test-004 closure (see §8.9).

### 11.5 Cross-fork integration test gate — adds beyond the §14 §2 list

The §14 §2 merge-blocking gates are joined by these new integration tests landing per-PR:

- **PR-S4-3**: `tests/integration/test_error_chain_substitution_propagates.py` — merge-blocking from S4-3.
- **PR-S4-4**: `tests/integration/test_hot_reload_high_blast_refusal.py` — already covered in §5 (advisory-only); promoted to merge-blocking on the consumer-deref AST guard.
- **PR-S4-5**: `tests/integration/test_operator_session_lifecycle.py` — merge-blocking from S4-5.
- **PR-S4-6**: `tests/integration/test_launcher_policy_resolver.py` — merge-blocking from S4-6.
- **PR-S4-7**: `tests/integration/test_sandbox_escape_kernel_enforced.py` — merge-blocking from S4-7 (already in §14 §2).
- **PR-S4-8**: `tests/integration/test_comms_mcp_identity_boundary_real.py` — merge-blocking from S4-8 (already in §14 §2).
- **PR-S4-9**: `tests/integration/test_discord_addressing_modes.py` + `tests/integration/test_discord_subpayload_promotion.py` — merge-blocking from S4-9.
- **PR-S4-10**: `tests/integration/test_tui_round_trip.py` + AST guard on `src/alfred/comms/` deletion + `tests/smoke/test_slice4_graduation.py` (the graduation smoke covering compose-up + login + chat round-trip — ops-006) — merge-blocking from S4-10.

**Total: 10 merge-blocking integration tests** (matching the §14 §12 promotion list).

---

## 12. Migrations + i18n catalog

### 12.1 Alembic migrations 0011 – 0014

| Migration | Adds | PR |
|---|---|---|
| `0011_operator_sessions` | `operator_sessions` table — `(user_id, token_hash, issued_at, expires_at, host, machine_id_hash, revoked_at)` indexed `(user_id, expires_at)` | PR-S4-0b |
| `0012_policies_snapshot_history` | `policies_snapshot_history` table — `(snapshot_id, loaded_at, file_sha256, policies_json, swapped_from_snapshot_id)` optional rollback log | PR-S4-0b |
| `0013_audit_columns_slice_4` | Adds new audit columns referenced by `audit_row_schemas.py` Slice-4 constants if not already present | PR-S4-0b |
| `0014_sandbox_policy_registry` | `sandbox_policy_registry` table — `(plugin_id, policy_ref, host_os, last_resolved_at, resolution_result)` — observability for the launcher's policy resolution | PR-S4-0b |

Each migration carries a `downgrade()` path. `operator_sessions` downgrade drops the table (operators re-login). `policies_snapshot_history` downgrade drops the table (rollback history lost; current snapshot unaffected). `sandbox_policy_registry` downgrade drops the table (observability only; no operational state).

### 12.2 i18n catalog additions

`locale/en/LC_MESSAGES/alfred.po` gains keys (i18n-002 closure — exhaustive enumeration, not summary):

**Login / session lifecycle:**

- `login.prompt_confirm_overwrite` — overwrite-existing-session prompt.
- `login.session_overwrite_confirm` — the existing-session prompt body.
- `login.user_not_found` — `<user>` not in the registry.
- `login.user_not_found_action_alfred_user_list` — "Use `alfred user list` or `alfred user add`."
- `login.expires_in_out_of_range` — `--expires-in` outside `[1h, 7d]`.
- `login.no_machine_id` — machine-id unreadable on this host.
- `login.confirmed` — successful-login confirmation.
- `logout.no_session` — `alfred logout` with no session.
- `logout.confirmed` — successful logout.
- `whoami.no_session` — `alfred whoami` with no session.
- `whoami.expired` — session expired.
- `whoami.template` — output template (user_id, expires_at, host).

**Operator-session refusal reasons** (each `OPERATOR_SESSION_REFUSED_FIELDS.reason` Literal):

- `operator_session.refused.expired`
- `operator_session.refused.host_mismatch`
- `operator_session.refused.machine_mismatch`
- `operator_session.refused.token_unknown`
- `operator_session.refused.user_revoked`
- `operator_session.refused.bad_file_mode`
- `operator_session.refused.bad_file_owner`
- `operator_session.refused.resolver_timeout` (i18n-r3-001 closure — round-2 fixup added the key in §6.4 but missed enumerating it here)

**Supervisor reset refusals:**

- `supervisor.breaker.reset.refused.not_logged_in`
- `supervisor.breaker.reset.refused.operator_permissions_insufficient`

**Daemon boot:**

- `daemon.boot.environment_not_set`
- `daemon.boot.unsandboxed_in_production`
- `daemon.boot.launcher_not_policy_resolving`
- `daemon.boot.snapshot_ref_init_failed`
- `daemon.boot.capability_gate_handshake_failed`
- `daemon.boot.started` (success)
- `daemon.stop.confirmed`
- `daemon.status.template`

**Sandbox refusal reasons** (each `SANDBOX_REFUSED_FIELDS.reason` Literal):

- `supervisor.sandbox.refused.policy_ref_missing`
- `supervisor.sandbox.refused.policy_ref_os_mismatch`
- `supervisor.sandbox.refused.policy_ref_unreadable`
- `supervisor.sandbox.refused.sandbox_block_missing`
- `supervisor.sandbox.refused.windows_stub_in_production`
- `supervisor.sandbox.unsandboxed_refused_in_production`

**Config-reload notifications:**

- `supervisor.config_reload.applied`
- `supervisor.config_reload_rejected.parse_failure`
- `supervisor.config_reload_rejected.high_blast_change`
- `supervisor.config_reload_rejected.validation_failure`
- `supervisor.config_reload_rejected.file_vanished`
- `supervisor.config_reload_rejected.stat_failed`

**TUI:**

- `comms.tui.daemon_required_to_chat`

**Babel-formatted output** (i18n-003 closure): `alfred whoami` formats `expires_at` and `issued_at` via `babel.dates.format_datetime(dt, locale=user.language)`. `alfred daemon status` formats `started_at` and `uptime` the same way. Operator-facing timestamps are localised; audit-log timestamps stay ISO-8601 UTC (machine-readable invariant).

**Asymmetric `language` carry on audit rows** (i18n-004 closure): `COMMS_INBOUND_T3_PROMOTION_FIELDS` carries `language` because the inbound body is user-authored content that needs language-tagged storage per PRD §7.7. Platform-event rows (`COMMS_ADAPTER_CRASHED_FIELDS`, `COMMS_RATE_LIMIT_SIGNAL_FIELDS`, sandbox/operator-session rows) carry no `language` because their fields are machine-emitted facts, not user content. The asymmetry is intentional; future event types should follow the same rule (user-content rows tag language; machine-event rows do not).

CI runs `pybabel extract` + `pybabel compile --check`; catalog drift fails the build (existing Slice-1 discipline).

---

## 13. PR breakdown — 12 PRs (summary)

The full per-PR ordering, dependency table, and per-PR contracts live in the slice-index plan document (`docs/superpowers/plans/2026-06-06-slice-4-index.md`, authored after this spec is reviewed). The summary below sketches each PR's owned scope.

| PR | Slug | What it owns |
|---|---|---|
| PR-S4-0a | docs-adrs-foundations | ADR-0022/0023/0024 full bodies; **ADR-0015/0016 stay Proposed** (status flips to Accepted are deferred to PR-S4-11 per the slice-3 precedent that status mirrors implementation reality — arch-003 closure); ADR-0009 caveat narrowing scheduled in PR-S4-10 (no PR-S4-0a touch — docs-001 closure); PRD §5 line 117 amendment (human-gated per rev-003); `audit_row_schemas.py` Slice-4 constants; `payload_schema.py` Slice-4 Literal additions PLUS `_PREFIX_TO_CATEGORY` and `_ID_PATTERN` extensions (Critical 7 / test-006 — preserve `prefix-YYYY-NNN` format); `docs/glossary.md` Slice-4 additions (full list in §13.1 below — docs-003). **NOTE**: `HookpointMeta.carrier_tier` + `HookpointMeta.allow_error_substitution` fields are explicitly *not* part of PR-S4-0a — those are runtime-type changes belonging to PR-S4-3 where they are consumed (rev-007 closure). |
| PR-S4-0b | migrations-infra-i18n | Alembic 0011–0014; SQLAlchemy models; i18n catalog additions (full enumeration in §12.2 — i18n-002); **`Dockerfile` for `alfred-core` service** with `bubblewrap` apt-installed in the base (`docker-compose.yaml` flips from `image:` to `build:` for that service) — ops-001; `bin/alfred-setup.sh` updates (the spec previously referenced `bin/dev-setup.sh`; canonical name is `bin/alfred-setup.sh` per the existing file — ops-005). Sets `bin/alfred-setup.sh` to a real script if currently stub; CLAUDE.md command-table update for the canonical script-name follows in PR-S4-11. |
| PR-S4-1 | daemon-boot-dispatch | `alfred daemon start/stop/status` subcommands; `Supervisor(state_git_path=…)` construction with the §3.1 kwarg shape; pre-TaskGroup probe orchestration (launcher / snapshot-ref / cap-gate); `daemon.boot.*` audit rows; smoke test. Launcher probe is a stub here (real check lands in PR-S4-6 — arch-001). |
| PR-S4-2 | dlp-failure-detail | `OutboundDlpProtocol` threaded through `ProposalContext`; `_truncated_detail` → `_redacted_detail` rename + body rewrite; emits `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` on every write (not just refusal — sec-005); two adversarial entries (`dispatch_loop_failure_detail_leak`, `dispatch_loop_failure_detail_canary_refused`). |
| PR-S4-3 | carrier-substitution | ADR-0022 implementation; `_run_error` signature change; tier-comparison guard (Critical 5); four sibling-site migrations; adversarial corpus entries `crf-2026-001` through `crf-2026-004` including meta-hookpoint recursion (rev-004); **`HookpointMeta.carrier_tier` + `HookpointMeta.allow_error_substitution` field additions** (moved from PR-S4-0a per rev-007). **Implicit dependency** (rev-009 round-3 closure): every other hookpoint-registering PR depends on PR-S4-3 because their `register_hookpoint(...)` calls must populate the new `carrier_tier` field. PR-S4-3 is therefore an ancestor of PR-S4-1, PR-S4-4, PR-S4-5, PR-S4-6, PR-S4-7, PR-S4-8, PR-S4-9 (PR-S4-2 has no new hookpoints; PR-S4-10/11 inherit from upstream). |
| PR-S4-4 | policy-hot-reload | ADR-0023 implementation; `PolicyWatcher` mtime-gated polling (perf-005); `PoliciesV1` Pydantic v2; `PoliciesSnapshotRef` lock-free O(1) read (perf-002); four-consumer migration with per-iteration deref rule in long-lived loops (core-003); audit rows including file-vanished / stat-failed (err-001); swap-then-audit-fails two-phase commit (err-004); adversarial entries TOCTOU / parser-OOM / mtime-skew (test-005); runbook back-patches. |
| PR-S4-5 | cli-operator-session | `alfred login` (with bare-`alfred login` discoverability flow — devex-002) / `logout` / `whoami`; `OperatorSession` model + file format with open-then-fstat TOCTOU-safe load (sec-006); system-owned machine-id sources per OS (sec-006); `_resolve_operator` helper with ≤5ms p99 budget (perf-001) + AST guard; operator-attributed CLI command threading; `babel.dates` locale formatting for whoami timestamps (i18n-003); closes #153. |
| PR-S4-6 | sandbox-launcher | `bin/alfred-plugin-launcher` policy-resolving rewrite; mandatory `Settings.environment` with no-default (sec-003); production-refuse-without-policy; dev-escape-hatch refuses with operator-visible stderr (devex-001); quarantined-LLM manifest update; provider-key fd-3 delivery with broker auth + bytearray zeroization (sec-004). |
| PR-S4-7 | sandbox-policies | Linux bwrap policy; macOS sandbox-exec policy; Windows stub policy; per-OS integration tests with insider-author + misconfigured-policy attacker models (test-003); adversarial sandbox-escape corpus (`sbx-*`); **CI runner topology** — `ubuntu-latest` for `test_sandbox_escape_kernel_enforced.py` as merge-blocking, `macos-latest` advisory (ops-002). |
| PR-S4-8 | comms-mcp-foundations | ADR-0024 wire-contract implementation; `AlfredPluginSession.inbound_handler` + bounded-semaphore backpressure (perf-003); `process_inbound_message` with T3-default body (Critical 3); `IdentityResolver` callback wire; reference plugin upgrade; real identity-boundary test with positive resolver-consulted-once assertion + binding-flow case + inter-persona forgery variant (test-004 / Critical 6 via `COMMS_UNKNOWN_NOTIFICATION_FIELDS`); host-side classifier registry with required set per adapter kind (Critical 4). Closes #152. |
| PR-S4-9 | discord-mcp-adapter | `plugins/alfred_discord/`; `DiscordSubPayloadClassifier` host-side under `src/alfred/comms_mcp/classifiers/discord.py` (Critical 4) covering nine sub-payload kinds (comms-003); persona-addressing modes (DM/mention/channel/thread — comms-002); idempotency-keyed outbound with outcome tri-state (comms-001); rate-limit honour via `OutboundQueue.pause` (comms-005); HMAC-with-pepper hash recipe (comms-004). (CI smoke for compose-up + login + chat round-trip belongs to PR-S4-10 since `alfred chat` is the TUI plugin — ops-006-residual closure.) |
| PR-S4-10 | tui-mcp-adapter-flag-day | `plugins/alfred_tui/` keeping the Textual rendering layer (comms-006); `alfred chat` rewires to launcher spawn; **all consumer-break migrations enumerated in §8.8** (`tests/smoke/test_tui_e2e.py`, `tests/smoke/test_discord_gateway_smoke.py`, `src/alfred/identity/_ingest.py`, `src/alfred/cli/main.py`, `tests/unit/comms/test_no_direct_adapter_imports.py` — comms-006); `src/alfred/comms/` deletion (one shot, no path collision per §8.8 — Critical 1); **ADR-0009 caveat narrowing** (not a status flip — docs-001); `bin/alfred-setup.ps1` updated to direct Windows operators to WSL2 + note quarantined-LLM PRD non-compliance on Windows (ops-003). |
| PR-S4-11 | docs-glossary-graduation | `docs/subsystems/{security,comms,supervisor,policies}.md`; `docs/runbooks/slice-4-graduation.md` (full §13.2 outline below — devex-005); **CLAUDE.md "Where things live" tree + commands table updates** (docs-002) — adds `plugins/alfred_discord/`, `plugins/alfred_tui/`, `src/alfred/comms_mcp/`, `bin/alfred-plugin-launcher`; commands table gets `alfred daemon start\|stop\|status`, `alfred login/logout/whoami`; **README quickstart update** for`alfred chat` (now requires daemon — docs-004); **ADR-0015 and ADR-0016 status flips Proposed → Accepted** (arch-003 — flipping at graduation matches the slice-3 precedent of flipping when implementation reality matches); required-check manifest update; slice sign-off. |

### §13.1 `docs/glossary.md` Slice-4 additions (full enumeration — docs-003 closure)

PR-S4-0a ships the initial set (terms the spec defines); PR-S4-11 audits for any missed terms surfaced during implementation. Initial set:

- `PolicyWatcher` — the mtime-polled `config/policies.yaml` watcher.
- `PoliciesV1` / `PoliciesSnapshot` / `PoliciesSnapshotRef` — the Pydantic v2 model + frozen snapshot + lock-free swap pointer.
- `HighBlastPolicies` — keys that refuse hot-reload and require reviewer-gate.
- `OperatorSession` / `OperatorResolver` — the session model + DI Protocol.
- `SandboxPolicy` / `SandboxKind` — `kind: full | none | stub`.
- `CarrierSubstitution` / `ErrorOutcome` / `ReRaise` / `SubstituteResult` — the §4 carrier-substitution semantic.
- `InboundContentScanner` (Slice-3-shipped; extended) — sub-payload classifier dispatcher.
- `InboundHandler` / `BindingHandler` / `RateLimitHandler` / `CrashHandler` — the four `AlfredPluginSession` notification handlers.
- `ResolvedIdentity` / `IdentityResolver` (Slice-3-shipped; finalised) — host-side resolver returning canonical user.
- `DiscordSubPayloadClassifier` — host-side classifier for Discord-shaped JSON sub-payloads.
- `InboundT3Promotion` — the transport-boundary T3 tagging of platform-relayed content.
- `OutboundQueue` (Slice-3-shipped; extended) — host-side outbound queue with `pause(adapter_id, retry_after_seconds)`.
- `BODY_FIELD_BY_KIND` — per-adapter body-field-name map (docs-007 round-3 closure).
- `OperatorSessionTimeout` — exception raised by `_resolve_operator` when the 250ms hard timeout fires (docs-007 round-3 closure).
- `T3DerivedData` — Slice-3 NewType from `src/alfred/security/quarantine.py` re-listed here for visibility; `Orchestrator.quarantined_extract` returns `ExtractionResult` carrying `data: T3DerivedData` with `source_tier="T3"` invariantly (sec-001 round-3 residual closure).
- `BurstLimiter` — per-(canonical_user_id, persona) token-bucket primitive shipped in PR-S4-8 (sec-008 round-3 closure).

### §13.2 `docs/runbooks/slice-4-graduation.md` required sections (devex-005 closure)

PR-S4-11 authors the runbook with these sections (mirrors `docs/runbooks/slice-2-discord-smoke.md` structure):

1. **What changed since Slice 3** — high-level inventory.
2. **Pre-flight: operator-session setup** — `alfred user list` → `alfred login --as <user>`.
3. **Pre-flight: production environment declaration** — `ALFRED_ENVIRONMENT=production` env var or `/etc/alfred/environment`.
4. **Pre-flight: sandbox prerequisites** — `apt-get install bubblewrap` on Linux; macOS notes.
5. **First boot: `alfred daemon start`** — expected boot-time output; failure modes (the seven `daemon.boot.*` reasons).
6. **First chat: `alfred chat`** — what success looks like; daemon-required error.
7. **First Discord: configure adapter** — set `DISCORD_BOT_TOKEN` via secret broker; spawn flow.
8. **Hot-reload UX** — edit `config/policies.yaml`; observe audit row; high-blast vs low-blast.
9. **Operator-session expiry + refresh** — `alfred login --refresh`.
10. **Troubleshooting** — sandbox-refused / config-reload-rejected / session-refused reasons → fixes.
11. **Rollback paths** — per-PR-revertable matrix.
12. **Vocabulary** — a short glossary section listing the operator-facing terms used in this runbook (`PolicyWatcher`, `OperatorSession`, `SandboxPolicy`, `policies_snapshot_hash`, `daemon.boot.completed`, etc.) with one-line definitions and a pointer to `docs/glossary.md` for full definitions (devex-007 closure). Each term in the troubleshooting section gets an inline cross-link to its glossary entry on first use.

---

## 14. Slice graduation criteria

PR-S4-11 lands only when the following hold:

1. All twelve PRs (S4-0a through S4-10) merged to `main`.
2. The two merge-blocking integration tests are green on the merge-base CI:
   - `tests/integration/test_sandbox_escape_kernel_enforced.py`
   - `tests/integration/test_comms_mcp_identity_boundary_real.py`
3. The adversarial suite (`uv run pytest tests/adversarial`) passes on `main`.
4. `make check` is green.
5. `make docs-check` is green (no broken cross-links in PRD / CLAUDE.md / ADRs / runbooks / glossary).
6. The PR-S4-11 required-check manifest update lists the two merge-blocking tests as required status checks for future PRs against `main`.
7. The TUI plugin (`plugins/alfred_tui/`) is operator-verifiable: a fresh `docker compose up -d` + `alfred login --as <test_user>` + `alfred chat` flow reaches the orchestrator and round-trips a message. The flow is **scripted as `tests/smoke/test_slice4_graduation.py`** so regression detection is automatic, not operator-driven (ops-004 closure).
8. The Discord plugin (`plugins/alfred_discord/`) passes the `tests/smoke/test_discord_gateway_smoke.py` (Slice-2-shipped, rewritten for MCP-plugin shape in PR-S4-9 per §8.8 consumer-break matrix).
9. `src/alfred/comms/` does not exist; AST guard test (rewired in PR-S4-10) is green. `src/alfred/comms_mcp/` is present and houses the wire-format owner + classifier registry.
10. ADR-0015 and ADR-0016 status headers read "Accepted" (flipped in PR-S4-11 per arch-003 closure — not PR-S4-0a). ADR-0009 carries the narrowed caveat from PR-S4-10 ("in-process adapters removed in Slice 4 per PR-S4-10") — not a status flip per docs-001.
11. **100% line + branch coverage on every new trust-boundary file** (test-002 closure, mirrors CLAUDE.md hard rule 8):
    - `src/alfred/identity/operator_session.py` (PR-S4-5) — `_resolve_operator`, file-mode validation, machine-id binding.
    - `src/alfred/cli/operator_session.py` (PR-S4-5) — `alfred login/logout/whoami`.
    - `bin/alfred-plugin-launcher.sh` policy-resolver source (PR-S4-6) — the launcher is **bash** (sec-004 round-3 correction; round-2 wrongly called it Python). Coverage is measured via `bashcov` running against `tests/integration/test_launcher_policy_resolver.py`. The companion pre-launcher Python helper that reads the manifest gets coverage via `coverage.py --include="src/alfred/plugins/manifest_reader.py"`. **Threshold: 100% line + 95% branch on the bash side** (the 5% branch slack covers OS-specific code paths the test runner cannot exercise simultaneously); **100% line + 100% branch on the Python helper**. test-008 round-3 closure.
    - `src/alfred/comms_mcp/inbound.py` (PR-S4-8) — `process_inbound_message` and `_emit_binding_request`.
    - `src/alfred/comms_mcp/classifier_registry.py` (PR-S4-8 / PR-S4-9) — required-classifier resolution.
    - `src/alfred/policies/watcher.py` (PR-S4-4) — `PolicyWatcher.run`.
    - `src/alfred/policies/snapshot_ref.py` (PR-S4-4) — `PoliciesSnapshotRef.current/swap`.
    - `src/alfred/hooks/invoke.py:_run_error` (PR-S4-3) — `ErrorOutcome` dispatch.
    - `src/alfred/orchestrator/burst_limiter.py` (PR-S4-8) — `BurstLimiter` token-bucket per-(user, persona); refuses-on-empty + drop-on-timeout. test-r4-001 round-4 closure (round-3 introduced this trust-boundary primitive but didn't add it to the coverage list).
12. **Per-PR required-status-check promotion via `gh api`** for each merge-blocking gate listed in §11.5; **each gate is promoted in the PR that ships it** (ops-007 closure — not bulked into PR-S4-11). The `required-checks.json` manifest carries the full list at slice graduation. New required gates added during Slice 4, with their promoting PR:

- `test_error_chain_substitution_propagates` (ubuntu-latest) — promoted in PR-S4-3.
- `test_hot_reload_high_blast_refusal` (ubuntu-latest, promoted from advisory) — PR-S4-4.
- `test_operator_session_lifecycle` (ubuntu-latest) — PR-S4-5.
- `test_launcher_policy_resolver` (ubuntu-latest) — PR-S4-6.
- `test_sandbox_escape_kernel_enforced` (ubuntu-latest) — PR-S4-7.
- `test_comms_mcp_identity_boundary_real` (ubuntu-latest) — PR-S4-8.
- `test_discord_addressing_modes` + `test_discord_subpayload_promotion` (ubuntu-latest) — PR-S4-9.
- `test_tui_round_trip` (ubuntu-latest) — PR-S4-10.
- `test_slice4_graduation` (ubuntu-latest) — **PR-S4-10** (ops-006 closure — the smoke exercises `alfred chat` which is the TUI plugin shipped in PR-S4-10, not Discord shipped in PR-S4-9).
- This is **10 gates total**, matching the §11.5 list (test-007 closure — the round-1 list-of-7 was inconsistent with §11.5's list-of-8; the count is now 10 and §11.5 is updated accordingly).

A regression in any of these criteria before PR-S4-11 ships means PR-S4-11 holds. There is no partial graduation.

---

## 15. Open questions

These are flagged for the `/review-pr` panel and any reviewer with relevant subsystem context. Each becomes a Plan-time decision when the per-PR plans are written.

1. **`alfred daemon` vs `alfred-daemon` binary.** Slice 3 supervisor CLI lives at `alfred supervisor`. The Slice-4 daemon entry could be `alfred daemon start` (subcommand of the existing CLI) or a new `alfred-daemon` binary (separate executable, common Linux daemon convention). The spec assumes the former; the choice is reversible at PR-S4-1 time.
2. **`discord.py` vs alternative.** The Discord adapter library choice. `discord.py` is the de facto standard; `nextcord`, `disnake`, and `pycord` are forks. PR-S4-9 makes the decision; not load-bearing for the wire-contract design.
3. **Sandbox policy file format.** TOML vs JSON vs YAML vs a custom DSL. PR-S4-7 decides. TOML for Windows stub already chosen for legibility; Linux/macOS may differ from Windows.
4. **Token rotation interval default.** 12h is proposed; reasonable values are 4h-24h. Operator can override via `--expires-in`. The default is per-Slice-4 default; not load-bearing.
5. **Whether `PoliciesV1` is a single schema or splits across files.** The Pydantic model could load from a single `config/policies.yaml` or be sharded into `config/policies/{rate_limits,handle_caps,high_blast}.yaml`. Single-file is proposed (operator simpler); sharding is reversible.
6. ~~`alfred user show` flow for `alfred login --as <user>`.~~ Resolved in §6.3 by the bare-`alfred login` discoverability flow (devex-002).
7. **Hot-reload behaviour when daemon is mid-state-write.** Currently the snapshot ref is read-once-per-call; an in-flight state.git proposal write that captures a snapshot continues with the old config. Acceptable but reviewers may want this documented in `docs/subsystems/policies.md`.
8. ~~Discord embeds classifier handling of pinned message references.~~ Resolved in §8.6 — `body.message_reference.*` is in the required classifier set; pinned, forwarded, and replied-to refs all promote to T3.
9. **`comms.outbound.send` hookpoint.** Slice 4 ships hookpoints for inbound (`comms.inbound.t3_promoted`) but not for outbound message send. PRD §5.1 ("every unit of work is hookable") suggests outbound deserves one. Adding it expands scope; the absence is also defensible because outbound already passes through `OutboundDlp.scan` which has its own audit-emit path. Defer or include — Plan-time decision at PR-S4-8.
10. **Notification dispatcher concurrency cap default.** `Settings.comms_max_in_flight_notifications=32` is proposed; reasonable values are 16-128. Discord can burst ≥1000 inbound msgs/s during a popular event; the semaphore must apply backpressure without dropping. Tune at PR-S4-8 based on integration testing.
11. **bwrap cold-start budget.** ADR-0015 quotes 50-100ms for bwrap fork+exec on Linux. The Slice-3 quarantined-LLM cold-start budget is <500ms (slice-3 §7a.1). Slice-4 sandbox adds bwrap to that budget. Whether 100ms of bwrap fits inside 500ms depends on the underlying provider call (Anthropic API has its own ~100ms TTFT). PR-S4-7 measures and either confirms the budget holds or proposes a relaxation in the Slice-4 sandbox release notes (perf-004 carry-over).
12. **`--expires-in` default as a Settings field.** Slice 4 hardcodes the 12h default; per-operator override via CLI flag. A site-wide configurable `Settings.operator_session_default_expires_in_hours` (clamped `[1, 168]`) is a small follow-up (devex-006). Defer to Slice 5+ unless an operator surfaces it; not load-bearing.
13. **CI smoke runtime budget for `test_slice4_graduation.py`.** Compose-up + login + chat round-trip is typically 30-90s on GH runners. PR-S4-10 commits a soft budget of 120s and a hard budget of 240s (perf-007 closure). Beyond the hard budget the test fails with `pytest.fail` rather than timing out silently.
14. **`alfred-discord` service Dockerfile.** Slice 4 runs adapters as in-process subprocesses spawned by the daemon (no separate service container). The post-MVP container-per-adapter shape (PRD §6.7 sketch) is deferred (ops-008 closure). PR-S4-9 ships only the in-tree plugin code, not container infrastructure.

---

## 16. ADR mappings

| ADR | Title | Slice-4 disposition |
|---|---|---|
| [ADR-0008](../../adr/0008-llm-output-trust-tier.md) | LLM output trust tier | Already superseded by ADR-0017 (Slice-3); no Slice-4 change |
| [ADR-0009](../../adr/0009-comms-adapter-protocol-slice2-only.md) | CommsAdapter Protocol | Already reads "Superseded by ADR-0016 (for new adapters)" since 2026-05-27 — not a Slice-4 status flip; PR-S4-10 narrows the caveat to remove "for new adapters" once in-process adapters are deleted (docs-001) |
| [ADR-0014](../../adr/0014-pluggable-hooks-for-every-action.md) | Pluggable hooks for every action | Load-bearing precedent; Slice-4 adds carrier-substitution semantic in ADR-0022 |
| [ADR-0015](../../adr/0015-slice4-containerised-quarantined-llm.md) | Slice-4 containerised quarantined LLM | **Status flips Proposed → Accepted in PR-S4-11** (graduation, mirroring slice-3 precedent — arch-003); implementation in PR-S4-6 / PR-S4-7 |
| [ADR-0016](../../adr/0016-slice4-discord-tui-comms-mcp-rewrite.md) | Slice-4 Discord+TUI comms-MCP rewrite | **Status flips Proposed → Accepted in PR-S4-11** (graduation — arch-003); implementation in PR-S4-8 / PR-S4-9 / PR-S4-10 |
| [ADR-0017](../../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) | Slice-3 trust-tier completion | Slice-3 ADR; Slice-4 inherits the wire-format precedent |
| [ADR-0018](../../adr/0018-state-git-proposal-writer-consolidation.md) | state.git proposal writer | Slice-3 ADR; Slice-4 daemon construction wires the writer in production |
| [ADR-0020](../../adr/0020-supervisor-cli-access-via-postgres-and-state-git.md) | Supervisor CLI access | Slice-3 ADR; Slice-4's `alfred supervisor reset` updates closes the operator-attribution gap |
| [ADR-0021](../../adr/0021-merged-proposal-branch-dispatch-for-side-effecting-proposals.md) | Merged-proposal branch dispatch | Slice-3 ADR; Slice-4 daemon construction wires dispatch in production |
| ADR-0022 (new, PR-S4-0a) | Recoverable-carrier semantic for error-stage hookpoint dispatch | Full ADR body in PR-S4-0a; closes #170 |
| ADR-0023 (new, PR-S4-0a) | mtime-polled hot-reload for `config/policies.yaml` | Full ADR body in PR-S4-0a; closes #159 |
| ADR-0024 (new, PR-S4-0a) | Comms-MCP wire contract | Full ADR body in PR-S4-0a; consumed by PR-S4-8/9/10 |

---

## 17. References

### Issue closures

- #174 — daemon boot path wiring → §3.1, §3.2 (PR-S4-1).
- #173 — `OutboundDlp.scan` into `processed_proposals.failure_detail` → §3.3 (PR-S4-2).
- #170 — recoverable-carrier semantic → §4 / ADR-0022 (PR-S4-3).
- #159 — mtime-polled hot-reload → §5 / ADR-0023 (PR-S4-4).
- #153 — `operator_user_id` through `alfred supervisor reset` → §6.7 (PR-S4-5).
- #152 — comms-MCP identity-boundary real test → §8.9 (PR-S4-8).
- #167 — per-kind `fail_closed` → explicitly deferred to Slice 5 (§1.2).

### PRD anchors

- PRD §5 (architecture overview) — line 117 amendment text in §7.10.
- PRD §6.1 (multi-modal comms) — comms-MCP rewrite per §8.
- PRD §7.1 (security & prompt injection defense) — sandbox containerisation per §7; carrier substitution per §4.
- PRD §7.2 (multi-user identity & authorization) — operator-session CLI per §6.
- PRD §7.7 / §11.1 (operator override semantics + state.git widening discipline) — hot-reload high-blast partitioning per §5.4.

### Slice predecessors

- Slice 3 design: [`docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md`](./2026-05-30-slice-3-trust-tier-completion-design.md).
- Slice 3 index: [`docs/superpowers/plans/2026-05-31-slice-3-index.md`](../plans/2026-05-31-slice-3-index.md).
- Slice 2.5 hooks design: [`docs/superpowers/specs/2026-05-27-slice-2.5-hooks-design.md`](./2026-05-27-slice-2.5-hooks-design.md).

### Slice-3 backlog inherited

From slice-3 §8 ("Slice-4 backlog seeded from Slice-3"):

- Typed `SecretRef` objects in place of `{{secret:*}}` string templating.
- Broker-side post-substitution invariant check.
- Per-secret-ID canary tokens woven into the post-substitution bytes by the broker itself.
- Audit-log assertion that substituted secret-IDs match the manifest's declared set.

These remain explicitly Slice-5 backlog per §1.2 — the broker is not touched in Slice 4 beyond what the session helper requires.

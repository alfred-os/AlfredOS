# Issues #586 + #587 — real quarantine-provider dispatch, opt-in separation enforcement — design

Status: **DRAFT — brainstormed interactively with the requester, design approved
2026-08-12.** Ready for the `/review-plan` fleet pass (security-engineer
mandatory), given this touches the quarantine child — the dual-LLM trust
boundary.

Date: 2026-08-12. Branch: `worktree-587-quarantine-provider-dispatch`, off
`main` @ `0bce92a3` (independent of #410 PR3 / PR #585, not yet merged).
Related: #587 (quarantine child hardcoded to Anthropic), #586 (provider-
separation enforcement unwired), #340 (real quarantine child go-live, the
epic that built the code this touches).

## 0. How this was found

Found while preparing manual UAT for #410 PR3 (PR #585). The operator tried
to configure the quarantine role with a DeepSeek key (either to avoid a
second paid provider account, or by mistake) and hit two independent,
previously undocumented gaps:

1. `config/routing.yaml`'s `[quarantine].provider` field, and its closed set
   (`anthropic`, `deepseek` per `_ALLOWED_QUARANTINED_PROVIDERS` in
   `src/alfred/cli/_validators.py`), describe a configurable provider choice
   that **does not exist at runtime**. `routing.yaml` is not loaded by
   anything — its own loader is documented as "slice 4+" in
   `src/alfred/bootstrap/quarantine.py`'s docstring, not yet built. The
   quarantine child's actual model comes from a hardcoded Python constant
   (`_QUARANTINE_MODEL = "claude-haiku-4-5"` in
   `src/alfred/comms_mcp/daemon_runtime.py`), threaded to the sandboxed child
   via a spawn-env var (`ALFRED_QUARANTINE_MODEL`). There is no equivalent
   constant or env var for *provider* — `src/alfred/security/quarantine_child/brokered_egress.py`
   hardcodes `from alfred.providers.anthropic_native import AnthropicProvider`
   directly. Any non-Anthropic key placed in `ALFRED_QUARANTINE_PROVIDER_API_KEY`
   fails at the first real extraction call (Anthropic auth error), not at
   boot — a confusing, late failure.
2. `assert_provider_separation()` (`src/alfred/bootstrap/quarantine.py`) — the
   function meant to enforce the Slice-3 design spec §5.4 "the quarantined
   provider MUST differ from the privileged provider" policy (superseded by
   [ADR-0064](../../adr/0064-quarantine-provider-separation-is-opt-in.md);
   retained here as the historical policy this work supersedes, not as a live
   requirement) — is fully implemented and
   unit-tested but has **zero call sites in production code**. Nothing
   currently prevents (or would prevent, once provider selection is real)
   configuring the same provider for both roles.

The operator's explicit direction, given both gaps: implement real DeepSeek
quarantine support (closing #587), and when the separation check is wired up
(#586), it must be **opt-in**, not a hard block — "nobody at home should
have to" run two separate paid provider accounts; an enterprise that wants
the stricter posture can enable it.

## 1. Problem

Two related trust-boundary configuration gaps, both discovered together and
fixed in the same pass since they touch the same boot/spawn path:

- The quarantine child cannot actually use any provider other than
  Anthropic, despite documentation describing a choice.
- The one piece of code that would enforce the two roles use different
  providers exists, is tested, but was never wired into the real boot path
  — and per the operator's explicit direction, it should stay OFF by default
  when it is wired in, not become a new hard requirement.

## 2. Verified current-state anchors (confirmed against the tree, 2026-08-12)

- `src/alfred/providers/deepseek.py:230` `DeepSeekProvider` — already
  implements the full provider contract (`capabilities()`,
  `from_settings()`), registered via `@register_provider`. Its
  `from_settings()` signature (`api_key`, `base_url`, `model`, `http_client`,
  `max_retries`, `timeout`) is near-identical in shape to
  `AnthropicProvider.from_settings()` (`src/alfred/providers/anthropic_native.py:249`),
  including the SAME `http_client: httpx.AsyncClient | None` transport-
  injection seam `brokered_egress.py` already relies on for the sandboxed
  fd-brokered transport. **`DeepSeekProvider` is not referenced anywhere
  under `src/alfred/security/`** (confirmed via grep) — the class is ready
  to reuse, unused today.
- `src/alfred/providers/base.py:66` `register_provider` — a decorator
  asserting `capabilities()` exists at import time. **Not** a provider-id →
  class registry/factory. `src/alfred/providers/router.py`'s `ProviderRouter`
  is the privileged path's tiered-fallback router — architecturally separate
  from, and heavier than, the quarantine child wants (its own bootstrap
  module docstring explicitly favours minimal, cheap-to-import surface).
  Conclusion: the dispatch this design adds is a small, quarantine-local
  branch, not a shared registry — matching the existing pattern where
  `brokered_egress.py` already re-implements construction logic rather than
  sharing it with the privileged path.
- `src/alfred/comms_mcp/daemon_runtime.py:89` `_QUARANTINE_MODEL =
  "claude-haiku-4-5"` — the existing pattern for threading a quarantine-child
  config value: a Python constant, spawn-env-threaded
  (`ALFRED_QUARANTINE_MODEL` per the module's own docstring at `:80-84`),
  drift-guarded against `config/routing.yaml`'s `[quarantine].model` by a
  test (until the real loader lands). No equivalent exists for provider.
- `src/alfred/comms_mcp/daemon_runtime.py:301-339`
  `_resolve_quarantine_provider_key` (name approximate — verify against
  live file) — refuses boot with `quarantine_provider_key_unset` when the
  key secret is empty. Checks PRESENCE only, never provider identity.
- `src/alfred/bootstrap/quarantine.py:30` `assert_provider_separation(*,
  privileged_provider_id, quarantined_provider_id)` — raises `AlfredError`
  on a case/whitespace-normalised collision or either id being blank.
  6 passing unit tests (`tests/unit/security/test_bootstrap_quarantine_provider_separation.py`)
  prove the function's own logic. Zero call sites anywhere else in `src/`.
- `src/alfred/cli/_validators.py:376` `_ALLOWED_QUARANTINED_PROVIDERS:
  Final[frozenset[str]] = frozenset({"anthropic", "deepseek"})` — the
  closed set already excludes `openai`, despite `routing.yaml`'s comment
  mentioning three providers. This design's scope (Anthropic + DeepSeek
  only) matches what's already validated; OpenAI is out of scope (no
  OpenAI-native provider class exists in `src/alfred/providers/` today —
  adding one is materially more work than reusing `DeepSeekProvider`).
- `config/routing.yaml:19-27` `[quarantine]` block — `provider: "anthropic"`,
  `model: "claude-haiku-4-5"`, `secret_id: "quarantine_provider_api_key"`,
  `max_tokens_per_extraction: 8192`. Comments describe a state.git
  reviewer-gate for changing `provider`/`secret_id` — that gate is for the
  live `alfred config quarantined-provider` CLI (itself documented elsewhere
  in this same file as "vapourware" pending a devex fix), not for editing
  the file directly in a fresh checkout before first boot. Not relevant to
  this design since routing.yaml is not read at runtime at all yet; this
  design's new setting lives in `.env`/`Settings`, not routing.yaml.

## 3. Scope decisions (ratified interactively with the requester, 2026-08-12)

1. **Provider scope: Anthropic + DeepSeek only.** Matches
   `_ALLOWED_QUARANTINED_PROVIDERS`'s existing closed set. OpenAI support
   would require building a new provider class from scratch and is
   explicitly deferred.
2. **Provider-separation enforcement is OPT-IN, default OFF.** A home/
   self-hosted operator must never be forced into running two separate paid
   provider accounts. The mechanism must let an operator (e.g. an
   enterprise deployment) explicitly enable the stricter posture.
   `assert_provider_separation()`'s existing implementation and tests are
   reused as-is; only its call site and the gating setting are new.
3. **Full review rigor**, matching #410 PR3's process: `/review-plan` fleet
   (security-engineer mandatory) before implementation, subagent-driven TDD
   with task-scoped reviews, a final whole-branch review before merge — this
   is trust-boundary code (the quarantine child's provider construction, and
   a security-relevant boot-time assertion).
4. **The setup wizard (interactive `.env`/provider-key collection) is
   explicitly OUT of scope for this design.** Tracked separately; depends on
   this work landing first so the wizard has real choices to offer.

## 4. Architecture

Two independently-shippable pieces, same PR (they touch the same boot/spawn
call sites and reviewing them together is cheaper than sequencing):

**Piece A — real provider dispatch for the quarantine child (#587).**

- Add `ALFRED_QUARANTINE_PROVIDER` as a real setting (env var, `.env`-backed
  like `ALFRED_QUARANTINE_PROVIDER_API_KEY`), validated against the same
  closed set `_ALLOWED_QUARANTINED_PROVIDERS` already declares. Default:
  `"anthropic"` (byte-for-byte today's behaviour for every existing
  deployment that doesn't set it — additive, non-breaking).
- `daemon_runtime.py` resolves this alongside the existing model resolution,
  threads it to the spawned quarantine child via spawn env (mirroring
  `ALFRED_QUARANTINE_MODEL`'s existing pattern exactly — **as implemented**,
  `ALFRED_QUARANTINE_PROVIDER` is reused end-to-end, spawn env included; no
  collision with the operator-facing setting name, since it names the same
  value at both ends of the same trust boundary).
- `brokered_egress.py`'s provider-construction seam (currently a hardcoded
  `AnthropicProvider.from_settings(...)` call) becomes a small branch: read
  the threaded provider id, construct `AnthropicProvider` or
  `DeepSeekProvider` accordingly, both via their existing `from_settings()`
  factories over the SAME brokered `http_client` seam. `DeepSeekProvider`
  additionally needs a `base_url` (OpenAI-compatible endpoint) — reuse
  whatever constant/setting the privileged DeepSeek path already uses for
  this (`ALFRED_DEEPSEEK_BASE_URL` per `.env.example`), do not invent a
  second one.
- Unknown/invalid provider id refused at settings-parse time (extending the
  existing `validate_quarantined_provider`-shaped closed-set check), never
  surfacing as a runtime API-auth failure the way an unsupported value does
  today.

**Piece B — opt-in provider-separation enforcement (#586).**

- Add `ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION` (bool, default
  `false`) as a real setting.
- In `enforce_quarantine_provider_separation` in
  `src/alfred/cli/daemon/_comms_boot.py`, which `_start_async`
  (`src/alfred/cli/daemon/_commands.py`) calls UNCONDITIONALLY on every boot —
  OUTSIDE the `if settings.comms_enabled_adapters:` branch, and before
  `write_pidfile` / `Supervisor.start()` / the AF_UNIX control socket, so a
  refusal has no daemon-up side effects and no I/O has happened yet (it can
  never leak a partially-constructed secret broker or content store). When
  this setting is `true` the gate calls the existing
  `assert_provider_separation(privileged_provider_id=..., quarantined_provider_id=...)`
  — refuses boot on a collision, exactly as already implemented and tested —
  and re-raises it as `QuarantineProviderSeparationCollisionError` so
  `_start_async`'s except-cascade routes it through the audited `_refuse_boot`
  path rather than letting a bare `AlfredError` escape uncaught (the #368
  anti-pattern).
  (As implemented, after two moves. An earlier draft of this spec placed the
  call in `daemon_runtime.py`, next to the Piece A provider-id resolution; it
  first moved into `_build_comms_boot_graph`, on the reasoning that the boot
  graph is where the audited refusal cascade and the boot-scoped audit writer
  live. CodeRabbit then showed `_start_async` only calls that builder under
  `if settings.comms_enabled_adapters:` — so a daemon with the flag on,
  colliding providers and no enabled adapter booted CLEAN: the operator opted
  into a security posture, got a green boot, and the control never ran.
  Commit 7213f2f6 hoisted the check into the sibling
  `enforce_quarantine_provider_separation` and called it unconditionally.
  Whether comms is enabled can no longer decide whether a security gate
  applies; the resolvers stayed pure throughout.)
- When `false` (default) and the ids DO collide: boot proceeds (today's de
  facto behaviour, now intentional rather than accidental), but this must
  not be silent — emit an operator-facing warning (structured log line, or
  an audit row if a suitable boot-audit sink already exists on this path)
  noting the two roles share a provider and the stricter setting exists.
  No-silent-failures discipline (CLAUDE.md hard rule) applies even to an
  intentionally-permissive default.
- `routing.yaml`'s `[quarantine].provider` comment and `.env.example` get
  corrected to stop describing enforcement/configurability that doesn't
  exist, and to document the two new settings.

## 5. Data flow

```
.env: ALFRED_QUARANTINE_PROVIDER=deepseek
      ALFRED_QUARANTINE_PROVIDER_API_KEY=<key>
      ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=false   (default)
  -> _commands.py `_start_async`, on EVERY boot — comms-enabled or not, and
     BEFORE write_pidfile / Supervisor.start() / the AF_UNIX control socket:
       -> _comms_boot.py `enforce_quarantine_provider_separation` (pre-I/O):
            - ALWAYS: log the resolved posture (quarantine + privileged
              provider ids, require_separation) — the happy path leaves a
              breadcrumb too, not only a collision
            - IF require_separation: assert_provider_separation(privileged_id, quarantined_id)
                -> collision -> QuarantineProviderSeparationCollisionError
                     -> _start_async's except-cascade -> _refuse_boot
                        (exit 2, daemon.boot.failed
                         reason=quarantine_provider_separation_violated)
              ELSE IF ids collide: operator-facing warning + audit row
                     daemon.boot.quarantine_provider_separation_not_enforced,
                     boot continues
  -> _commands.py `if settings.comms_enabled_adapters:`  ── the fork ──
       │
       ├─ NO adapter enabled: the whole comms graph is skipped. The gate above
       │    already ran — that is precisely what hoisting it out bought
       │    (7213f2f6); before the hoist this arm ran no separation check at all.
       │
       └─ AT LEAST ONE adapter: _comms_boot.py `_build_comms_boot_graph`
            -> daemon_runtime.py boot resolution:
                 - resolve quarantine provider id (closed-set validated) + key
                   (existing presence check)
                 - spawn quarantine child; provider id + model threaded via spawn env
            -> quarantine_child/__main__.py: reads provider id from env
                 -> brokered_egress.py: branch on provider id
                      -> AnthropicProvider.from_settings(api_key, model, http_client=<brokered>, ...)
                      -> DeepSeekProvider.from_settings(api_key, base_url, model, http_client=<brokered>, ...)
                 -> extraction proceeds identically regardless of which provider
                    was constructed
  -> both arms rejoin: write_pidfile -> Supervisor.start() -> DaemonControlServer
     (AF_UNIX, 0600, SO_PEERCRED uid check) -> daemon.boot.completed
```

## 6. Error handling

- Unsupported `ALFRED_QUARANTINE_PROVIDER` value: `Settings.quarantine_provider`
  is a Pydantic `Literal["anthropic", "deepseek"]` — `Settings.__init__` wraps
  the resulting `pydantic.ValidationError` in `SettingsError`, and the daemon's
  `_load_settings_or_die` routes that to the audited `settings_invalid` boot
  refusal (exit 2 + a `daemon.boot.failed` row). Loud, at settings construction,
  never a runtime provider-auth failure — but the carrier is `SettingsError`
  (a `ValueError` subclass), not a bare `AlfredError`, so a caller/test
  catching `AlfredError` alone would miss it (CodeRabbit PR-review r1).
- `ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=true` + collision:
  `AlfredError` from the existing, unmodified `assert_provider_separation()`
  — this design adds only the call site and the gate, not new assertion
  logic.
- `false` (default) + collision: never silent — a loud warning, not a raise.
  This is the one genuinely new error-handling shape this design introduces;
  needs its own test asserting the warning fires (and that boot does NOT
  refuse) under this combination.
- Every other combination (different providers, or same-provider with the
  check disabled and no warning path triggered) is unchanged from today's
  behaviour or already covered by `assert_provider_separation()`'s existing
  6 tests.

## 7. Testing

- Unit: `DeepSeekProvider` and `AnthropicProvider` both constructible via
  the new dispatch branch for a given provider id; unsupported id refused
  at parse time (extend the existing validator test file); the new
  `ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION` setting's states each get a
  dedicated test against a real `alfred daemon start` in
  `tests/unit/cli/daemon/test_daemon_boot_egress_refuse.py`, exercising
  `enforce_quarantine_provider_separation` at its real `_start_async` call
  site: enabled+collision → audited refusal (exit 2), enabled+distinct →
  boots, disabled+collision → warn-and-boot. The 7213f2f6 hoist added a
  fourth: enabled+collision with NO comms adapter enabled → still refuses,
  pinning that the gate is not conditioned on comms being enabled. This is
  new coverage `assert_provider_separation()`'s own tests do not provide,
  since those only test the function in isolation, never a real call site.
- Integration: a real DeepSeek-configured quarantine child completes a real
  extraction end-to-end (mirroring whatever the existing Anthropic-path
  integration test already proves — same shape, different provider),
  proving the brokered-transport seam genuinely works for both providers,
  not just that the branch compiles.
- Regression: every existing quarantine-child integration test must still
  pass unmodified with the new default (`ALFRED_QUARANTINE_PROVIDER`
  unset/`"anthropic"`) — this design must be byte-for-byte non-breaking for
  every deployment that doesn't touch the two new settings.
- `alfred-security-engineer` sign-off required (dual-LLM trust-boundary
  construction path, plus a new boot-time security-relevant assertion call
  site).
- Adversarial corpus: likely not needed — this is a construction-time
  config path, not a new external-content attack surface — but let the
  `/review-plan` security-engineer make that call rather than assuming it
  here.

## 8. Documentation

- `config/routing.yaml`'s `[quarantine]` comment block: correct to describe
  what's actually enforced/configurable post-this-design, remove the
  false "bootstrap-time check... refuses to start" claim unless/until Piece
  B's opt-in is enabled, and note the two new `.env` settings.
- `.env.example`: document `ALFRED_QUARANTINE_PROVIDER` and
  `ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION` alongside the existing
  `ALFRED_QUARANTINE_PROVIDER_API_KEY` entry.
- README Quickstart's "two provider keys are required" callout: clarify
  that the SAME provider now works by default (no separate Anthropic
  account required to just try the software), with a pointer to the new
  opt-in setting for anyone who wants the stricter posture.
- No PRD edit is needed. An earlier revision of this section proposed a
  human-gated follow-up edit to PRD §6.4; that rested on the mistaken
  attribution corrected above. PRD §6.4 is the self-improvement reviewer
  gate's own cross-provider requirement and has nothing to say about
  quarantine/privileged separation — so there is no PRD wording to fix.
  ADR-0064 is the record instead.

## 9. Out of scope

- OpenAI quarantine-provider support (§3 item 1).
- The interactive setup wizard (§3 item 4) — separate, later piece; depends
  on this landing first.
- Any PRD.md edit (human-gated repo policy) — and, per §8 above, none is
  called for: no PRD section states a quarantine/privileged separation
  invariant.
- Any change to `assert_provider_separation()`'s own logic — reused as-is.
  (One BEHAVIOUR-PRESERVING exception landed during the review-fix wave: the
  normalised collision comparison was extracted into a `provider_ids_collide()`
  helper in the same module, so the opt-in refuse path and the default warn path
  share one definition of "same provider" instead of two hand-written copies. The
  function's contract, messages and existing tests are unchanged.)

## 10. Risks & residuals

- **The exact spawn-env variable name for provider** needs to avoid
  colliding with `ALFRED_QUARANTINE_PROVIDER` (the operator-facing `.env`
  setting) if the implementation ends up needing a distinct
  internal-spawn-only name — verify against `ALFRED_QUARANTINE_MODEL`'s
  existing precedent (same name used for both the setting and the spawn
  env, per `daemon_runtime.py`'s own docstring) before assuming a second
  name is needed.
- **The drift-guard test** that currently pins `_QUARANTINE_MODEL` against
  `routing.yaml`'s documented value will need either a matching pin for
  provider, or an explicit note that routing.yaml's `[quarantine].provider`
  field stays aspirational (not read) even after this design ships, to
  avoid a reader assuming routing.yaml is now the source of truth when the
  `.env` setting actually is.
- **This does not fix routing.yaml's loader gap** (still "slice 4+") — this
  design deliberately routes around it via the same `.env`-setting pattern
  the rest of the operator-facing config already uses, consistent with
  what actually ships today rather than waiting on the loader.

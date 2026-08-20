# ADR-0064: Quarantine/privileged provider separation is opt-in, default off

- **Status**: Accepted
- **Date**: 2026-08-12
- **Slice**: #586 / #587 (real quarantine-provider dispatch + opt-in provider-separation
  enforcement)
- **Supersedes**: docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md §5.4

## Context

The dual-LLM split (PRD §5, §7.1) routes untrusted T3 content through a
quarantined LLM, separate from the privileged orchestrator LLM. Whether the
two must use DIFFERENT providers (not just different roles/processing paths)
is a distinct question the PRD does not answer — no PRD section states a
"providers must differ" requirement, despite prior code comments
(`alfred.bootstrap.quarantine`, `config/routing.yaml`) citing "spec §5.4 /
PRD §6.4" for exactly that claim. PRD §6.4 covers the unrelated
self-improvement reviewer-gate's own cross-provider requirement; no other
PRD section fills the gap.

The Slice-3 design spec's own §5.4 IS a real, prior, deliberate decision on
this exact question, however — not a citation error to wave away. It
specifies: (a) AlfredOS refuses to bootstrap BY DEFAULT when the quarantine
and privileged providers collide; (b) relaxing that requires an explicit
`state.git` reviewer-gate proposal (`alfred config quarantined-provider
<provider>`), never a plain `.env` flag; (c) an approved relaxation emits a
RECURRING `supervisor.config_insecure` audit row at every restart, to keep
signalling the weakened posture rather than let it fade into an
unremarkable steady state. `assert_provider_separation()` was built and
tested against this spec, but never wired to a real call site until now.

Since #586 landed, running a home/self-hosted deployment with two paid
provider accounts (one per role) is understood to be an unreasonable
default cost — confirmed by direct operator instruction: "nobody at home
should have to" run two paid provider accounts. This ADR records the
resulting decision and what it supersedes.

## Decision

Provider separation between the quarantine and privileged LLMs is an
OPT-IN, defence-in-depth posture (`Settings.require_quarantine_provider_separation`,
default `False`) — REPLACING spec §5.4's default-refuse / reviewer-gated /
recurring-audit-signal mechanism with a simpler one:

- Default (`False`): same-provider is PERMITTED. A collision boots fine but
  is logged AND audited once per boot (not a recurring per-restart signal —
  see Consequences).
- Opt-in (`True`): boot REFUSES on a same-provider collision via
  `assert_provider_separation()`, audited through the normal
  `daemon.boot.failed` refusal path — but the escape hatch is a plain
  `.env` boolean, not a `state.git` reviewer-gated proposal.

A home/self-hosted operator is never forced into running two paid provider
accounts. An enterprise deployment that wants the stricter posture sets the
flag to `True`.

## Consequences

- **Weaker than spec §5.4 on three specific axes**, by deliberate choice:
  no default-refuse, no reviewer gate on the escape hatch, and a one-time
  per-boot audit signal instead of a recurring per-restart one. This ADR
  is the record of that trade-off — not an oversight.
- No PRD text needs to change — this ADR is the accurate record instead of
  a fabricated PRD citation.
- `config/routing.yaml`'s comment and `docs/runbooks/slice-3-quarantined-llm.md`
  are corrected (Task 6 Steps 1/3 of the #586/#587 plan) to cite this ADR
  instead of "spec §5.4 / PRD §6.4".
- The Slice-3 design spec's §5.4 itself gets a one-line "superseded by
  ADR-0064" pointer added at its top (this task, same commit) so the two
  documents do not silently contradict each other.
- `assert_provider_separation()`'s own docstring (`bootstrap/quarantine.py`)
  still carries the old citation — out of scope for this PR — tracked as
  follow-up doc-fix [#588](https://github.com/alfred-os/AlfredOS/issues/588).
  The function's BEHAVIOUR is likewise unchanged (design spec §9: reused
  as-is); the one edit its module did receive is the extraction of its
  normalised collision comparison into a `provider_ids_collide()` helper, so
  the opt-in refuse path and the default warn path below share a single
  definition of "same provider" rather than two hand-written copies that could
  drift. Same contract, same messages, same tests.
- **`require=true` checks the SETTING, not the runtime-resolved privileged
  provider — so it can pass while a real collision exists.** The check
  compares `Settings.primary_provider` against `Settings.quarantine_provider`.
  The general root cause: **`Settings.primary_provider` is not read by
  `build_router` under ANY configuration.** `build_router`
  (`src/alfred/cli/_bootstrap.py`) hardcodes DeepSeek as primary and wires
  Anthropic in as a live fallback whenever `anthropic_api_key` is configured;
  it never consults the `primary_provider` field at all, which is otherwise
  read only for the `alfred status` display string. So the check does not
  merely have a blind spot on the shipped defaults — it is comparing against a
  value that has no bearing on the privileged provider pair for ANY value an
  operator sets. Two consequences follow:
  - On the shipped defaults (`primary_provider="deepseek"`,
    `quarantine_provider="anthropic"`): `require=true` PASSES, yet the
    privileged router's Anthropic fallback is the same provider the quarantine
    child uses, so a fallback-served privileged turn and a quarantined
    extraction can land on one provider account.
  - For either of the two values `primary_provider` can now take — the field was
    closed to `Literal["anthropic", "deepseek"]` in this same PR
    (`src/alfred/config/settings.py`), so there is no open "custom value" domain
    left — the check reports on a setting the router ignores, so a "PASS" is a
    false assurance and a refusal would be a false alarm — in both directions the
    verdict is about config text, not about the providers the system actually
    dials.

  Accepted for now — narrowing it means changing `assert_provider_separation()`'s
  signature or `build_router`'s wiring, both of which the #586/#587 plan explicitly
  put out of scope (design spec §9).
  [Issue #590](https://github.com/alfred-os/AlfredOS/issues/590) is the tracking
  issue for narrowing the check to compare against `build_router`'s
  actually-resolved provider pair. Until it lands, read the opt-in flag as "the
  two configured provider SETTINGS differ", not as "no privileged path can ever
  reach the quarantine provider".
- **Directional trust (ADR-0053/ADR-0057) needs no bespoke code for the two new
  settings — verified, not assumed.** #586 asked for an explicit directional-trust
  check on `quarantine_provider` and `require_quarantine_provider_separation`
  during design; this bullet records the answer rather than leaving the ask
  silently unanswered. Both fields are ordinary `Settings` fields resolved through
  pydantic-settings' DEFAULT source precedence — `init` kwargs > `os.environ`
  (`ALFRED_*`) > `.env` > secrets file. `Settings.settings_customise_sources` IS
  overridden, but only to strip the `environment` key out of every non-init source
  (#469 Blocker 1); it does not touch these two fields or reorder the chain for
  them. So a `.env` value can only fill a gap the process environment left empty
  and can never override an `ALFRED_*` env var the launcher set. That is the
  `os.environ > .env` direction [ADR-0053](0053-three-layer-environment-precedence.md)
  §1 names as pydantic-settings' native behaviour and the direction
  [ADR-0057](0057-directional-trust-for-the-launcher-environment.md)'s
  directional-trust rule requires — obtained from the default precedence rather
  than from new code. (The `/etc/alfred/environment` middle layer is specific to
  `Settings.environment` and does not apply to these two fields; nothing about
  them needs it.) Note this makes the *setting* tamper-ordered; it does not change
  the limitation recorded in the bullet above about what the setting is compared
  against.

## Alternatives considered

- **Keep spec §5.4's mechanism as-is** (default-refuse, `state.git`
  reviewer-gated relaxation, recurring audit signal). Rejected: the
  `state.git` proposal flow for `quarantined-provider` doesn't exist yet
  (component-not-wired, matching this project's broader "even where a
  mechanism is documented, it may not be built" pattern), and a
  self-hoster would be hard-blocked from booting at all until either that
  flow ships or they configure two providers — unacceptable per the direct
  operator instruction above.
- **Hard-require separation always**, no opt-out. Rejected for the same
  reason.
- **Edit PRD.md to add the invariant.** PRD edits are human-gated in this
  repo; an ADR is the correct vehicle for a decision made during
  implementation, not a PRD edit made by an agent.

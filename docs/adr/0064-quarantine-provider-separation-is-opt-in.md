# ADR-0064: Quarantine/privileged provider separation is opt-in, default off

- **Status**: Accepted
- **Date**: 2026-08-12
- **Issue**: #586 / #587
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
  still carries the old citation — out of scope for this PR (design spec
  §9: reused as-is, unmodified) — filed as a follow-up doc-fix.

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

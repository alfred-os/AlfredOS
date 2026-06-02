# ADR-0018 — state.git proposal-writer consolidation + typed payloads

- **Status**: Proposed (Slice 3); to flip to Accepted on PR-S3-6 merge.
- **Date**: 2026-06-02
- **Slice**: 3 — `docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md`
- **Refines**: [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Decisions 2 and 3 (plugin transport + two-axis naming) describe *what* a grant proposal carries; this ADR describes *how and where* it is written.
- **Issue**: #134 (Stage 4 of 9 — Resolve the dual state.git writers)

## Context

PR-S3-2 shipped the async reviewer-gate proposal flow in
`src/alfred/security/capability_gate/proposals.py`. The
`_write_proposal_to_state_git` helper is a fail-loud
`NotImplementedError` stub by design: the gitpython integration was
explicitly deferred to PR-S3-6 alongside the CLI surface. CR-139
finding #5 ratified the stub shape so a caller could not silently
succeed against an unwritten branch.

PR-S3-6 then introduced `alfred.cli._state_git.StateGitProposalClient`
— a synchronous subprocess-driven writer the CLI surface (`alfred
plugin grant`, `alfred web allowlist`, `alfred config set`) uses to
queue the same `proposal/<type>-<id>` branches. The CLI is synchronous
and could not `await` the proposal-flow stub; bridging via
`asyncio.run` would conflate event-loop ownership with the CLI's
process model, so a second writer landed.

The result is **two writers pointed at the same trust boundary**:

1. **Sync** — `StateGitProposalClient.create_proposal(proposal_type,
   payload: dict[str, object])` shells `git` subprocesses, writes a
   single `proposal.json` at the repo root, and pushes
   `proposal/<type>-<hex>`. Payload shape: dict, untyped.
2. **Async stub** — `proposals._write_proposal_to_state_git(...)` is a
   fail-loud NotImplementedError. Its declared parameter list carries
   five fields (`plugin_id`, `subscriber_tier`, `hookpoint`,
   `content_tier`, `operator_user_id`) — schema B, distinct from the
   sync writer's schema A.

The audit-graph correlator joins CLI emits to reviewer-merge rows by
branch name. With two writers running on two payload shapes, a typo
on either side (e.g. `subscribe_tier` vs `subscriber_tier` at one
call site) would either silently drop a grant downstream or break the
correlator's join without surfacing the contract violation at the
emit site.

Three derived problems, one underlying finding:

- **arch-002 / R1** — two writers, one trust boundary; the silent
  divergence between schema A and schema B is exactly the kind of
  drift CLAUDE.md hard rule #7 ("no silent failures in security
  paths") forbids.
- **Untyped payload surface.** The sync writer takes `dict[str,
  object]`. Pydantic v2 at boundaries (per `docs/python-conventions.md`)
  is the project default for wire-shaped models; the proposal payload
  is the highest-blast wire surface in AlfredOS and was the last one
  not yet typed.
- **Parser-writer path mismatch.**
  `alfred.security.capability_gate._state_git_parser.parse_state_git_head`
  reads grant blobs from `policies/grants/` in the merged tree.
  Neither writer plants a file there; the sync writer drops
  `proposal.json` at the repo root, and the async stub raises. So
  even after a reviewer merges, the parser finds nothing. The
  reviewer-side merge-script that promotes the proposal payload into
  the grants tree exists only conceptually today; the writers must
  themselves emit the canonical on-disk shape so the round-trip works
  by construction, not by side-effecting merge scripting.

## Decision

**Decision 1 — Option A: consolidate around the sync subprocess writer.**

`StateGitProposalClient` becomes the single canonical writer.
`proposals.create_proposal_branch` (the async surface used by
proposal-flow callers) replaces its `NotImplementedError` stub with a
thin asyncio shim that constructs the typed Pydantic payload and
awaits `asyncio.to_thread(client.create_proposal, payload)`. The sync
writer remains the single seam that talks to git; the async surface
exists only so async callers do not have to spawn the thread bridge at
every call site.

**Why Option A over Option B (delete the async stub entirely).** The
proposal-flow callers expressed in `proposals.create_proposal_branch`
exist downstream of the capability gate, which is async-first by spec
§8.1. Forcing them to construct a sync bridge at the call site would
either inline the same `asyncio.to_thread` boilerplate three times
(R5 violation) or replicate the existing sync writer's argv-shaping
logic in the async module. Option A keeps the async surface narrow —
one shim, one place to swap implementations if a future PR replaces
subprocess git with gitpython or libgit2.

**Decision 2 — `StateGitProposalPayload` Pydantic models as the writer's input contract.**

`src/alfred/state/proposal_payloads.py` defines a frozen
`StateGitProposalPayload` base + three concrete subclasses, one per
proposal type Slice 3 produces:

- `PluginGrantProposal` — `plugin_id`, `subscriber_tier`, `hookpoint`,
  `content_tier`, `operator_user_id`. The two-axis naming rule (ADR-0017
  Decision 3) is enforced by the field names; a typo
  `subscribe_tier` vs `subscriber_tier` becomes a Pydantic
  `ValidationError` at the dispatcher, not a silently-skipped grant
  downstream.
- `WebAllowlistProposal` — `action` (literal `"add" | "remove"`),
  `domain`, `path_prefix`, `operator_user_id`.
- `ConfigSetProposal` — `config_key` (literal from the
  high-blast-key closed set), `value`, `operator_user_id`.

Each subclass is a frozen Pydantic v2 model (`model_config = ConfigDict(frozen=True, extra="forbid", strict=True)`) and exposes a
`proposal_type` class-var so the writer derives the branch prefix
from the model, not from a parallel string passed by the caller.

`StateGitProposalClient.create_proposal(payload:
StateGitProposalPayload)` is the new typed entry point; the existing
`(proposal_type, payload: dict)` shape stays as a thin compatibility
wrapper that constructs the matching model via a lookup table. The
wrapper is private (leading underscore) so new callers MUST construct
the typed model. Existing callers in `alfred.cli.{plugin,web,config}`
are updated in this PR to construct the typed model directly.

**Decision 3 — Plugin-grant proposals materialize
`policies/grants/<plugin_id>/<grant_id>.json` so `parse_state_git_head`
round-trips by construction.**

The on-disk shape for plugin-grant proposals is now the same nested
path the parser reads from the merged tree. JSON, not YAML — the
parser is already JSON-shaped and a format flip would broaden the
blast radius of this PR. The non-grant proposal types (web allowlist,
config set) keep the existing `proposal.json` at the repo root because
their merged-tree projections live in different tables (the web
allowlist row in `web_allowlist`, the config-set value in the
operator-config projection) — neither lands in `policies/grants/`.

Both writers (sync + async shim) construct the same on-disk shape via
the model's serialization. The async shim is therefore a one-line
`await asyncio.to_thread(self._sync_client.create_proposal, payload)` —
it does not duplicate the path-construction logic.

**Decision 4 — `parse_state_git_head` becomes recursive over the
`policies/grants/` tree.**

Plugin-grant proposals land at `policies/grants/<plugin_id>/<grant_id>.json`,
one nesting level below the parser's existing single-level scan. The
parser is extended to traverse subtrees so the round-trip works
without forcing all writers to flatten the path (which would lose the
per-plugin grouping operators rely on for `alfred plugin show <id>`).

## Consequences

**Positive.**

- One canonical writer for the highest-blast wire surface in
  AlfredOS. `arch-002 / R1` closes.
- Typed payload at the boundary; the typo-vs-silently-skipped failure
  mode becomes a Pydantic `ValidationError` at the dispatcher.
- `parse_state_git_head` round-trips a plugin-grant proposal by
  construction. The integration test seeded by this PR replaces the
  conceptual reviewer-side merge-script with a known-good
  reference.
- The async surface stays available for async callers. Future async
  callers (the reviewer-agent's auto-approve loop, the proposal-status
  poller) do not need to inline `asyncio.to_thread`.

**Negative / accepted trade-offs.**

- The sync writer's `(proposal_type, dict)` shape is no longer the
  public surface. Existing tests in `tests/unit/cli/test_state_git.py`
  that construct the dict directly are updated in this PR to construct
  the typed model. The compatibility wrapper exists for the few audit-
  trail integration tests that pre-date Stage 4; it MUST be removed in
  PR-S3-7 once the audit-graph e2e tests migrate too.
- Plugin-grant proposals add a directory level
  (`policies/grants/<plugin_id>/`) the parser now traverses. The
  per-plugin grouping is the deliberate choice — flattening would
  collapse `alfred plugin show` to a full-tree scan.
- The `_write_proposal_to_state_git` stub is replaced before the
  reviewer-agent's auto-approve loop lands. Stage 4 verifies the shim
  via unit + byte-equality tests; the e2e reviewer-agent round-trip
  ships in PR-S3-7.

**Out of scope (deferred to PR-S3-7).**

- The compatibility wrapper accepting `(proposal_type, dict)` is
  retained for one PR cycle to keep existing tests passing; PR-S3-7
  removes it.
- The reviewer-agent merge-script that promotes a merged proposal
  branch into `main`'s `policies/grants/` tree is not implemented
  here. Stage 4 verifies that *if* the proposal lands in
  `policies/grants/<plugin_id>/<grant_id>.json` on `main`, the parser
  round-trips it. The merge automation is PR-S3-7's responsibility.

## Alternatives considered

**Option B — delete the async stub entirely; require all callers to
use the sync writer via an explicit `asyncio.to_thread` bridge.**

Less surface area in `proposals.py`. Rejected because the proposal-
flow callers (the reviewer-agent loop, the in-flight grant-revoke
path) are async-first and would either replicate the bridge at every
call site (R5 violation) or invent a private async helper that
duplicates the shim. Option A's shim is the same code, located once.

**Option C — keep both writers but unify them around a shared
on-disk-shape helper; do not consolidate the writer surface.**

Rejected because the silent-divergence failure mode this ADR is
opened to close lives in the writer surface, not in the on-disk shape
alone. Two writers can drift on argument validation, on subprocess
failure handling, on the audit-row emit ordering, regardless of how
much shape they share. One writer + one shim is the only structure
where the trust-boundary review surface is unambiguous.

**Option D — YAML grant blobs instead of JSON.**

The finding's exemplar text named
`policies/grants/<plugin_id>/<grant_id>.yaml`. Rejected for this PR:
the parser already reads JSON, and `tests/unit/security/capability_gate/test_state_git_parser.py`
seeds JSON. A format flip would broaden the blast radius and force a
parallel review of the parser's exception handling for YAML-specific
failure modes (anchor cycles, type confusion in `yaml.safe_load`'s
auto-coercion). A future ADR can flip the format if YAML's reviewer
ergonomics ever outweigh the JSON consistency; for Stage 4 the format
choice is deliberately conservative.

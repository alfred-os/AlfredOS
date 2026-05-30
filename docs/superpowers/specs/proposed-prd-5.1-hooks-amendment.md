# Proposed PRD §5.1 amendment — core lifecycle methods are hookpoint producers

**Status**: Proposed for human approval
**Date**: 2026-05-27
**Slice**: 2.5

This is a proposed edit to `PRD.md` §5.1, NOT yet applied — requires human approval per CLAUDE.md self-improvement rule #4.

## Why

PRD §5.1 currently frames the hook surface in outer-wrapper terms: a fixed set of core-defined actions that plugins wrap. The Slice 2.5 design refinement establishes that core lifecycle methods are themselves hookpoint *producers*, declaring their extension points via the same `invoke()`/`invoking()` primitive that plugins use. There is no asymmetry between "core publishes hooks" and "plugins publish hooks" — a hookpoint is a named, string-keyed extension point, and any code (core or plugin) may both publish and subscribe.

The PRD must absorb this clarification to stay source-of-truth for §5.1's contract. Without it, downstream readers (subsystem engineers, plugin authors, future agents) will reasonably infer that hookpoints are a closed core-defined set — the opposite of what the design ships.

References:

- [ADR-0014 amendment](../../adr/0014-pluggable-hooks-for-every-action.md#amendment-slice-25) — the architectural decision and exact clarifying paragraph.
- [Slice 2.5 hooks design spec §1](2026-05-27-slice-2.5-hooks-design.md) — the motivating discussion and the `invoke()`/`invoking()` primitive.

## The proposed diff

Captured PRD §5.1 verbatim (lines 123-138) and shown as a unified diff. The change is **a single added sentence** appended to the "Plugin authors register hooks via the MCP protocol…" paragraph (PRD line 134). No other lines change.

```diff
--- a/PRD.md
+++ b/PRD.md
@@ -123,15 +123,15 @@
 ### 5.1 Hookable actions

 Plugins, the operator, and AlfredOS core components extend the system by registering **hooks** on actions other components take. The four hook kinds are:

 - **Pre-action** — observes or mutates the input before the action runs; may refuse the action (typed `HookRefusal`).
 - **Post-action** — observes or mutates the result after the action succeeds.
 - **Error** — observes the exception when the action raises; may swallow and replace with a synthesised result.
 - **Cancel** — runs cleanup on `asyncio.CancelledError`; cannot suppress the cancellation.

 Every action carries up to four hook chains, one per kind. Each chain is ordered by capability tier (**system**, **operator**, **user-plugin**) and by registration order within tier. Pre-action chains short-circuit on first refusal; the refusal is itself an event the error chain and the audit log observe.

-Plugin authors register hooks via the MCP protocol (a `hooks` block in the plugin manifest declares `(action, kind)` tuples) or via an in-process Python decorator for in-tree plugins. Both paths route through the same capability-gated registry; a plugin without the `hook.<action-name>` capability is refused at load time.
+Plugin authors register hooks via the MCP protocol (a `hooks` block in the plugin manifest declares `(action, kind)` tuples) or via an in-process Python decorator for in-tree plugins. Both paths route through the same capability-gated registry; a plugin without the `hook.<action-name>` capability is refused at load time. Core lifecycle methods publish hookpoints via the same `invoke()`/`invoking()` primitive plugins use — there is no asymmetry between core-publishes and plugin-publishes, and any code may both declare extension points and subscribe to them.

 Hooks coexist with the event bus: the event bus stays the observation-only surface for components that do not need to mutate or refuse, hooks are the synchronous in-band interception surface. Hooks coexist with the audit log: every hook invocation is itself auditable, keyed to the originating action's correlation ID.

 **Status — planned for Slice 2.5** (between Slice 2's identity/Discord/secret-broker scope and Slice 3's MCP-transport + T1/T3 rewrite). ADR-0014 records the decision, alternatives considered (event-bus-only, MCP-only, AOP decorators, retrofit into Slice 2, defer to Slice 3), and the performance + security consequences. Final slice placement is the architect's call at Slice-2 graduation planning.
```

## What stays unchanged

The following PRD §5.1 elements are explicitly **not** modified by this proposal — they are already correct:

- **The `(action, kind)` manifest tuple wording.** The manifest contract stays `(action, kind)` tuples; no field is renamed to `hook_subscriptions` or `hookpoints_published`. The refinement is about *who can publish* a hookpoint, not about how subscriptions are declared.
- **The four-kinds list.** Pre-action, post-action, error, cancel — unchanged. The four kinds are routing semantics on an invocation, not the structure-defining concept that needs revisiting.
- **The tier-ordering paragraph.** System → operator → user-plugin tier ordering, and registration order within tier, is unchanged. Core-published hookpoints route through the same tier-ordered chain.

## Approval checklist

For the human approver:

- [ ] Does the refinement contradict any other PRD section?
- [ ] Does it require a matching change elsewhere in PRD §5 or §6.3?
- [ ] Does the added sentence faithfully convey ADR-0014's amendment (core methods are hookpoint producers; symmetric publish/subscribe)? Paraphrase is acceptable so PRD prose stays dense.
- [ ] Is the diff applied to `PRD.md` cleanly when reviewed?

## How to apply (if approved by human reviewer)

If the human reviewer approves the proposed §5.1 amendment, apply it on a fresh branch:

```bash
cd /path/to/AlfredOS
git checkout -b apply-prd-5.1-amendment
# Apply the unified diff above to PRD.md manually (or extract and run
# git apply if the diff is verbatim in this file).
$EDITOR PRD.md  # paste the changed text into §5.1
git add PRD.md
git commit -m "docs(prd): apply §5.1 hooks-amendment per ADR-0014 (#104)

Reviewed-by: <name>
"
git push -u origin apply-prd-5.1-amendment
gh pr create \
  --title "docs(prd): apply §5.1 hooks-amendment per ADR-0014" \
  --body "Closes the proposed-PRD diff in docs/superpowers/specs/proposed-prd-5.1-hooks-amendment.md."
```

Once the apply-PR merges, archive this proposed-PRD file so future readers
do not mistake an applied amendment for a pending proposal:

```bash
git mv docs/superpowers/specs/proposed-prd-5.1-hooks-amendment.md \
       docs/superpowers/specs/applied/proposed-prd-5.1-hooks-amendment.md
```

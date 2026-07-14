# #432 — bind the launcher's audit-reason `case` lists to the Python vocabulary

**Status:** design, approved 2026-07-14
**Issue:** [#432](https://github.com/MrReasonable/AlfredOS/issues/432) — split out of the #431 (#428) review; flagged by the architect, cross-cutting, error, and devops lanes plus CodeRabbit.
**Predecessor:** [#431](https://github.com/MrReasonable/AlfredOS/pull/431) shipped the `case` list this design binds.
**Related drift-class issues:** #427 (kernel-enforcement helpers re-emit policies field-by-field), #422 (the 11-copy CI retry block).

## Problem

`bin/alfred-plugin-launcher.sh` is the **sole emitter** of `supervisor.plugin.sandbox_refused`
audit rows. No Python writes one — `src/alfred/` only registers the hookpoint
(`supervisor/core.py`, `hooks/_known_hookpoints.py`) and references the event in prose.

The launcher decides each row's `reason` field from a vocabulary it hand-copies from Python
in **two** places, and nothing binds either copy to its source:

| # | Copy | Lives in | Mirrors |
| --- | --- | --- | --- |
| 1 | schema-refusal `case` list | `bin/alfred-plugin-launcher.sh` L312 | the reasons `python3 -m alfred.plugins.manifest_reader --policy-to-bwrap-flags` can print |
| 2 | environment-key `case` list | `bin/alfred-plugin-launcher.sh` L164 | the keys `… --read-environment` can print |
| 3 | the "closed vocab" itself | `audit_row_schemas.py` L1187 | *nothing* — it is a prose comment |

A new `SandboxPolicyInvalid(reason=…)` added without updating copy 1 silently falls back to
the generic `policy_translate_failed` — the exact failure the #431 fix corrected, ready to
recur. That is the bug #432 was filed for.

### The vocabulary is already wrong

Auditing what the launcher can *actually* write against what the "closed vocab" comment
*claims* is closed found **seven** reasons that can land in a `sandbox_refused` audit row
while sitting outside the vocabulary that row is documented to be closed over:

| Missing reason | Reaches the audit row via |
| --- | --- |
| `fake_uname_in_production` | launcher L207, direct `printf` |
| `unknown_host_os` | launcher L220, direct `printf` |
| `uid_separation_unavailable` | launcher L242, direct `printf` |
| `interpreter_prefix_too_broad` | launcher L359, direct `printf` |
| `stub_kind_in_production` | launcher L412, direct `printf` |
| `policy_translate_failed` | launcher L321, the copy-1 `case` fallback — and raised twice in `sandbox_policy.py` |
| `environment_unrecognised` | launcher L169, via the copy-2 `case` (`${_env_err_key#daemon.boot.}`) |

So the comment is not merely unbound; it is materially incorrect, and `policy_translate_failed`
— the single most reachable refusal reason in the whole family — is among the omissions. A
frozenset promoted to code has to be **correct** to be worth binding against, so completing the
vocabulary is in scope here, not deferred.

**Five** vocabulary entries have no launcher emitter — `bwrap_unavailable`,
`bwrap_mode_userns_unavailable`, `policy_ref_os_mismatch` (documented only), plus
`provider_key_delivery_failed` and `sandbox_info_handshake_mismatch` (Python-side exception
defaults in `supervisor/fd3_key_delivery.py` and `plugins/session.py` that raise with those
reasons but are never written into a `sandbox_refused` row). They are retained as an explicit
**reserved** set — the binding does not require them to be launcher-emitted, but it *does*
require the frozenset to equal exactly (launcher-emittable ∪ reserved), so neither an orphan
typo nor a silent omission survives.

> **A note the plan review forced.** The `supervisor.plugin.sandbox_refused` row is never
> actually persisted: the launcher `printf`s it to **stderr**, which is drained into a
> `child_stderr` log field, and no `src/alfred/` code parses it into an `append_schema` write —
> the registered `fail_closed` T0 hookpoint is never dispatched. So this spec binds the reason
> vocabulary of a row that nothing yet reads. That is deliberately in scope to *correct and
> bind*, and deliberately out of scope to *wire up* — filed as **#433**. The frozenset's
> docstring must say so plainly rather than reading as an enforced runtime contract.

## Design

**One canonical set in code; each copy derived, never restated; the whole set bound both ways.**

This section was substantially rebuilt after the plan review found a Critical in the first
draft's guard: it parsed only the *first* arm of each bash `case` and skipped the `%s` reason
fields, so the two `*)` fallback assignments (`_AUDIT_REASON="policy_translate_failed"`,
`_env_err_key="daemon.boot.environment_not_set"`) were reasons the launcher can emit that **no
derivation saw**. Three lanes plus a cross-check converged on it. The rebuilt model below
resolves *every* `sandbox_refused` `printf` line's reason field — literal or `%s` — and fails
loud on any line it cannot account for.

### Production change

**`src/alfred/audit/audit_row_schemas.py`** — replace the prose `reason` closed-vocab comment
with a real constant beside the `SANDBOX_REFUSED_FIELDS` frozenset that already lives there
(same file, same idiom):

```python
SANDBOX_REFUSED_REASONS: Final[frozenset[str]] = frozenset({...})   # 20 launcher-emittable + 5 reserved = 25
```

The explanatory prose survives as a comment above the constant — the *why* notes
(`policy_ref_escapes_root` vs `policy_ref_unreadable`; what `provider_key_delivery_failed`
means) are not restatable from the names — **plus** the #433 caveat (this row is not yet
persisted) and an explicit label of which five reasons are reserved/unemitted.

**`bin/alfred-plugin-launcher.sh`** — the pointer comment currently reads
`Closed vocab source of truth: audit_row_schemas.py:1188`. A line number is itself a drift
vector (already off by one against the comment it names). It names the constant instead.

No behaviour changes. No new operator-facing strings, so no i18n surface. The launcher's
`case` lists are unchanged — the point of the test is that they are *already correct*, and
the test is what keeps them that way.

### The derivations

New file `tests/unit/plugins/test_sandbox_reason_vocab_sync.py` — it spans four files
(launcher, `sandbox_policy.py`, `manifest_reader.py`, `audit_row_schemas.py`) and so does not
belong inside the translator's own test module.

Every *derivable* fact is derived, never restated (a hand-kept copy would just be one more
drifting copy; an oracle that restates the implementation is the tautology trap this codebase
has hit twice — `domain_a_test_that_asks_the_code_if_the_code_is_right`). The one irreducible
human judgment — *which reasons are intentionally reserved with no emitter* — cannot be derived
from code (absence of an emitter is derivable; the *intent* is not), so it is named explicitly
and small, and pinned by an equality so it cannot drift silently.

- **flags-path reason set** — AST-walk `sandbox_policy.py` for every
  `SandboxPolicyInvalid(reason="…")` literal (7 today), plus AST-walk
  `_cmd_policy_to_bwrap_flags` in `manifest_reader.py` for every `_fail(...)` argument,
  resolving module-level string constants (declared as either `X = "…"` **or**
  `X: Final[str] = "…"` — the walk must handle `ast.AnnAssign` too, per ops-002) and the
  `exc.reason` passthrough. Strip the `supervisor.sandbox.refused.` prefix as bash does. Expect 9.
- **environment-key set** — AST-walk `_cmd_read_environment` for its `_fail(...)` arguments
  (`_ENV_NOT_SET_KEY`, `_ENV_UNRECOGNISED_KEY`). Expect 2.
- **bash `case` first-arm sets** — the `|`-alternatives of each `case`'s allow-list arm.
- **bash `case` fallback literals** — the `*)` arm's assigned literal
  (`_AUDIT_REASON="…"` / `_env_err_key="…"`). *This is the parse the first draft omitted.*
- **launcher-emittable set** — the load-bearing new primitive. Enumerate **every** line
  containing `"event":"supervisor.plugin.sandbox_refused"` (11 today) and resolve each line's
  `reason` field:
  - a literal → `{that literal}`;
  - `%s` fed by `${_AUDIT_REASON}` → schema-case first-arm ∪ its `*)` fallback literal;
  - `%s` fed by `${_env_err_key#daemon.boot.}` → env-case first-arm ∪ its `*)` fallback,
    prefix-stripped.
  If a line's reason field is a `%s` fed by a variable the resolver does not recognise, or the
  count of resolved lines ≠ the independent `grep`-style denominator of `sandbox_refused`
  `printf` lines, **fail loud** — this is the fix for the pinned-floor blind spot (a future
  12th emit site, or a printf folded into a `%s` helper under #422 pressure, can no longer be
  silently skipped while a `>= N` floor still passes).

### Assertions

1. `schema_case_first_arm == flags_path_reasons` — the #432 ask, exact equality: a new Python
   reason missing from the bash allow-list **and** a dead allow-list entry both fail.
2. `env_case_first_arm == environment_key_reasons` — the same binding for the second copy.
3. `launcher_emittable ⊆ SANDBOX_REFUSED_REASONS` — no path through the launcher (including
   both `*)` fallbacks, now resolved) can write a reason outside the vocabulary.
4. `SANDBOX_REFUSED_REASONS == launcher_emittable | _RESERVED_UNEMITTED` — binds the **whole**
   frozenset: an orphan/typo entry (in the set, emitted by nothing, not reserved) fails here,
   and so does a reserved reason accidentally dropped. `_RESERVED_UNEMITTED` is the named 5.
5. `schema_fallback_literal ∈ vocab` and `env_fallback_literal (stripped) ∈ vocab` — the direct,
   named guard for the exact Critical the review found: change a `*)` value to something
   out-of-vocab and this fails by name (belt-and-suspenders with #3).

### The guard's own blind spots, named and closed

- **Non-literal reasons.** An AST walk cannot see `SandboxPolicyInvalid(reason=some_var)`; it
  would make the derived set silently under-count and every binding pass vacuously. The walk
  **fails loud** on any `SandboxPolicyInvalid` raise site or `_fail(...)` argument that does not
  resolve to a literal or a module-level string constant.
- **Silent parse collapse.** Every derived set carries a floor assertion *with a message*, and
  the launcher-emittable derivation carries the independent-denominator check above, so a regex
  or AST walk that returns `set()` cannot pass — `set() ⊆ X` and `set() == set()` are the
  canonical vacuous greens (`domain_paper_only_gates`).
- **What it still cannot do**, stated not papered over: it binds the *lexical* vocabularies. It
  cannot prove the launcher reaches the right `case` arm at runtime, nor that the helper's last
  stderr line is the reason the helper meant, nor that the row is ever persisted (#433). Those
  are the job of the launcher integration tests and #433.

### Platform

Pure `Path.read_text` + `ast` — no subprocess, no bwrap, no `bin/` execution. It needs **no**
`skipif(win32)` (the #428 gotcha was a hermetic-`PATH` subprocess; there is none here) and runs
in the blocking Windows unit lane. The launcher path is resolved via `parents[3]` and read with
universal newlines, so CRLF checkouts are tolerated. Note the `src`-scoped `mypy`/`pyright`
gates do **not** cover this test file — it must still be internally well-typed, but no gate
enforces that, so the code must not rely on type-checking to catch a mistake.

## Definition of done

- `SANDBOX_REFUSED_REASONS` exists in `audit_row_schemas.py` with all 25 reasons; the *why*
  prose is preserved above it; the comment states the #433 not-yet-persisted caveat and names
  the five reserved/unemitted reasons; the constant is **not** added to `AUDIT_FIELDSET_ROSTER`
  (it is a reason set, not a field set, and does not end in `_FIELDS`).
- The launcher's pointer comment names the constant, not a line number.
- `tests/unit/plugins/test_sandbox_reason_vocab_sync.py` passes (five assertions + the vacuity
  floor), derives every copy, restates only the named reserved set, and parses **both** `case`
  arms including the `*)` fallback.
- Every assertion has been mutation-proved to bite, with each probe (a) asserting the mutation
  actually applied before running pytest and (b) recording *every* assertion that fails, not a
  predicted single one. The non-literal guard and the independent-denominator check are each
  shown to fire.
- `make check` green; the adversarial suite green (this touches the sandbox-policy blast radius).

## Out of scope (each filed)

- **#433** — actually persisting the `sandbox_refused` row (parse launcher stderr → `append_schema`,
  dispatch the hookpoint). This spec binds the vocabulary; #433 makes it govern a real write.
- **#434** — the `2>/dev/null` five-key collapse and the `policy_translate_failed` alarm/real
  conflation (a `reason_unclassified` for the `*)` arm). Both are behaviour changes that add or
  alter reasons; #432 is their prerequisite, not their home.
- **#435** — four launcher refusal paths that emit no row at all.
- **#436** — `sandbox_stub_used` writes an undeclared `reason` field.
- **#437** — `POLICY_REF` interpolated raw into audit JSON (latent injection).
- `_sandbox_i18n.py` — a copy of an *overlapping but different* set (operator message keys, not
  audit reasons; not a subset in either direction). Binding it would encode a contract that does
  not exist.
- Removing the five reserved/unemitted vocabulary entries.
- #430 (`/usr` hard-bind tightening) and #427 (kernel-enforcement field-by-field re-emit).

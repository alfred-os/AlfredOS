# #434 / #435 / #436 — make the launcher's sandbox audit-row contract honest, complete, and bound

**Status:** design, settled 2026-07-16. The `reason`-intent question (#436) was delegated to the
agent fleet (security / architect / devex) at the maintainer's direction; all three converged
independently on *intended — declare it*. The maintainer settled the PR split, the tainted-`plugin_id`
representation, the `bwrap_unavailable` scope, and the L234 reason name.
**Issues:** [#434](https://github.com/alfred-os/AlfredOS/issues/434) (reason mislabelling round 2),
[#435](https://github.com/alfred-os/AlfredOS/issues/435) (refusal paths emitting no row),
[#436](https://github.com/alfred-os/AlfredOS/issues/436) (undeclared `sandbox_stub_used` reason field).
All three split out of the #432 plan review.
**Predecessors:** #431/#428 (over-broad bind guard), #432 (`SANDBOX_REFUSED_REASONS` closed vocab +
its AST drift-guard), #437 (`policy_ref` charset guard), #433/#446 (the refusal-audit persist path,
ADR-0051).

## Problem

Three defects in one row family, all on `bin/alfred-plugin-launcher.sh` + the constants in
`src/alfred/audit/audit_row_schemas.py`. They are filed separately but are one contract:

1. **#434A — five distinct refusals collapse into one wrong reason.** `L273` runs
   `SANDBOX_JSON="$(_read_sandbox 2>/dev/null)"` and unconditionally emits
   `reason="sandbox_block_missing"`. `manifest_reader._cmd_read_sandbox` can fail with **five**
   distinct keys (`plugin.launcher_plugin_id_invalid`, `plugin.manifest_reader_no_source`,
   `plugin.manifest_unreadable`, `plugin.manifest_sandbox_block_missing`, `plugin.manifest_invalid`);
   the launcher's map covers all five because it binds to `manifest_reader`'s full CLI contract (the
   #432 AST guard derives the map from that same contract). **Only three are reachable via the
   launcher in practice**: `manifest_reader._plugin_id_is_safe` uses a charset byte-identical to the
   launcher's own `PLUGIN_ID` gate (`L123-128`), and `_read_sandbox` always calls the helper with
   either `--manifest-path` or the already-charset-validated `--plugin-id`, so `_cmd_read_sandbox`'s
   `manifest_path is None` branch — the one that emits `plugin.launcher_plugin_id_invalid` or
   `plugin.manifest_reader_no_source` — never runs from the launcher's own invocation. `2>/dev/null`
   still discards all five unrecoverably wherever they occur — so `manifest_unreadable` and
   `manifest_invalid` (a **planted-manifest tamper signal**) are recorded as the benign "you forgot
   `[sandbox]`". The launcher's own environment path (`L155-171`) already implements the correct
   capture-and-map pattern; this is a self-inconsistency with a ready-made fix in the same file.

2. **#434B — `policy_translate_failed` means three things.** It is simultaneously (a) a real
   `SandboxPolicyInvalid` reason for malformed TOML, (b) the schema-`case` `*)` fallback (`L336`) —
   the drift/crash **alarm** that fires on a traceback / ImportError / new-unbound-reason, and
   (c) an unconditional operator stderr key (`L317`). The alarm is recorded under a name that reads
   like a boring policy-authoring error.

3. **#435 — refusal paths emit no row at all.** The issue names four (at stale line numbers);
   **at HEAD `89962aac` there are six**, once the `bwrap` exec failure is counted.

4. **#436 — the `sandbox_stub_used` row contradicts its declared schema in both directions.**
   `L248` writes an **undeclared** `reason`; `SANDBOX_STUB_USED_FIELDS` declares a `policy_ref` that
   **two of three** emit sites omit. Nothing binds the constant to the producer.

### Why they are one PR, not three

Mechanically forced, not merely tidy. `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`
(the #432 binding) hardcodes `_SANDBOX_REFUSED_EVENT` and carries vacuity floors
(`len(_RESERVED_UNEMITTED) == 5`, vocab `>= 25`, emittable `>= 20`, emit-lines `>= 11`).
Issue #435 moves `bwrap_unavailable` out of the reserved set, hitting the `== 5` floor; #436 adds
a parallel resolver and its own floors to the same file. Split, they collide on the same lines.
Together, the floors are re-derived exactly once. ADR-0051's Follow-ups section already groups all
three as "sibling refinements on the same row family".

Single responsibility: **the launcher's sandbox audit-row reason contract is honest, complete, and
bound to a closed vocabulary.**

## Decisions

### D1 — one PR, three commits (maintainer)

Commit per issue, in dependency order: #434 (reason accuracy) → #435 (row completeness) → #436
(stub-row contract). #434 and #435 both widen `SANDBOX_REFUSED_REASONS`; the binding is satisfied
at each commit boundary.

### D2 — the tainted `plugin_id` at L126 uses a constant sentinel (maintainer)

The charset gate at `L123-128` exists *precisely* so "a malformed id can never reach a printf JSON
template (audit-stream integrity — CR on PR #140)", and #437's lesson is *refuse without echoing the
tainted value — emitting it into the row would BE the injection*. But today a probe with malformed
plugin ids produces **zero** audit trail.

The row therefore carries `"plugin_id":"<invalid>"` — a launcher-authored constant, never attacker
bytes. This fully respects the PR #140 invariant. `<` and `>` are outside the plugin-id charset, so
the sentinel can never collide with a real id. `reason` carries the semantics.

**Rejected — `"plugin_id":null` or omitting the key.** `launcher_refusal._validated_row` rejects any
non-`str` field value (`invalid_field_types`) and any absent non-optional field (`missing_fields`).
`_OPTIONAL_FIELDS` is `{"policy_ref"}` only. Adding `plugin_id` to it would weaken the parser for
*every* row on the most adversary-facing surface in the system, to buy cosmetics. The parser is
**unchanged** by this PR.

At `L126` neither `ALFRED_RESOLVED_ENVIRONMENT` nor `HOST_OS` is resolved yet, so the row carries
`environment="unset"`, `host_os="unknown"` — matching the existing `L169` environment-failure row's
precedent.

### D3 — `reason` on `sandbox_stub_used` is INTENDED; declare it (agent fleet, unanimous)

Three independent lines of evidence:

* **History.** `SANDBOX_STUB_USED_FIELDS` landed 2026-06-07 in `77591ff4` (PR-S4-0a, the
  "declare audit constants ahead of their consumers" PR) from a plan table describing **only** the
  `kind:stub` path. `reason` landed two days later in `43384614` (#152, the FAKE_UNAME
  production-bypass fix), whose commit message reads *"now with an honest sandbox_stub_used row"*.
  Two PRs in flight on different tracks; nothing bound them. Not copy-paste — parallel-PR drift.
* **Author intent, in the file.** `L245-247`: the row is auditable *"under the same closed vocabulary
  as the other stub paths"*. The author was writing a vocab-constrained reason and believed L412/L432
  already had one. **L248 is the correct site; L412 and L432 are the defect.**
* **Operator need.** Drop `reason` and L248 vs L432 become **byte-identical** on macOS (the primary
  dev platform) and on windows — not "hard to infer", *absent from the data*. The two causes have
  opposite remediation: L248 = "you're on a Mac, there is no UID-drop here" (benign); L432 =
  "**this manifest declares kind:stub**" (actionable). "Why is my plugin not sandboxed?" has exactly
  those two answers.

Dropping `reason` would commit the exact reason-conflation defect #434 exists to fix, in the same PR
that fixes it. Disqualifying.

### D4 — declare ≠ persist: `sandbox_stub_used` is deliberately NOT persisted (agent fleet, unanimous)

**The critical finding of this design.** `sandbox_refused` is safe to persist because a refusing
launcher exits **pre-`exec`** — no child exists, so the drained stderr is provably launcher-authored
(`launcher_refusal.py:11-13`). A `sandbox_stub_used` row asserts the **inverse**: *"I am about to
exec."* Its existence entails a live child sharing that stderr fd, with no delimiter between
launcher-authored prefix and child-authored suffix. **"Launcher-authored" is not establishable
in-band for this row, at all.**

Trace the #446 gate (`quarantine_child_io.py:580`, `refusal_candidate and not self._child_wrote_stdout`)
against a stub_used row:

| child | stdout | gate | outcome |
| --- | --- | --- | --- |
| honest — execs, does its job | writes stdout | **closed** | the real launcher-authored row is **discarded** |
| forging — execs, emits a forged row, dies at clean EOF | zero | **open** | the **forgery is accepted** |

The gate admits approximately **only forged** stub_used rows and rejects the honest ones — an
inverted oracle. The forging population is precisely the children running *uncontained*: the
least-contained child authoring the record that says it is uncontained.

Structurally reinforced: ADR-0051 Decision B anchors persistence to the `read_frame` **EOF-on-refusal**
arm, which exists only because a refused launcher produces no frame. A stub_used launcher `exec`s
successfully — there is no EOF, so `_log_child_stderr(failure=True)` never runs. **The ADR-0051
mechanism is blind to stub_used by construction.**

Therefore: this PR makes the contract **accurate and bound**; it wires **no** persistence. Wiring it
would need a success-path stderr drain — a new interception point, a new design, a new ADR — filed as
a follow-up. This is recorded on the constant's docstring so a future reader does not read the
declared schema as an invitation.

Declaring `reason` does **not** widen the forgery surface — a closed vocab strictly narrows it
(3 legal values instead of arbitrary strings). The widening would be any decision to persist.

**Corrects a standing assumption:** #440/#441/#442 ("the three other launcher producers adopt
`SandboxRefusalAuditor`") does **not** extend to `sandbox_stub_used` for free. Named here so the
assumption is not silently carried into those issues.

### D5 — `bwrap_unavailable` is wired (maintainer)

The launcher checks `command -v jq` and refuses (`L281-284`), but never checks `command -v bwrap` —
it just `exec`s it at `L393`. A missing bwrap means exec fails, `set -e` aborts, bash emits its own
127 error, and **no row is written**. Meanwhile `bwrap_unavailable` already sits in the vocab as
*reserved, no emitter*. Same class of gap as #435, reason already exists, mirrors the jq check a few
lines away. Wire it; move it reserved → emittable.

### D6 — L234 gets a new `runuser_unavailable` (maintainer)

`uid_separation_unavailable` (`L242`) means "this OS has no UID-drop mechanism at all" (non-Linux,
production). `L234` is a Linux host that **does** support UID-drop but is missing the util-linux
binary. Different remediation (`apt install util-linux` vs "you're on a Mac"). Reusing one token is
the wrong-but-plausible conflation #434 exists to kill.

### D7 — the stub-reason vocab derives from its refused twin by one rule

Every stub_used reason is the dev-side twin of the `sandbox_refused` reason on the **same launcher
branch**, stem-identical minus the `_in_production` suffix that no longer applies:

| launcher branch | production → `sandbox_refused` | dev/test → `sandbox_stub_used` |
| --- | --- | --- |
| non-Linux, no UID-drop (L241 / L248) | `uid_separation_unavailable` | `uid_separation_unavailable` |
| windows `kind:full` (L409 / L412) | `windows_stub_in_production` | `windows_stub` |
| `kind:stub` manifest (L429 / L432) | `stub_kind_in_production` | `stub_kind` |

That table is the invariant and is directly testable.

`uid_separation_unavailable` is deliberately **shared** across both vocabularies — same *cause*,
different *disposition*. `reason` names the cause; `event` names what Alfred did; `environment` names
why the disposition differs. Both rows read as clean sentences ("refused because UID separation was
unavailable" / "used a stub because UID separation was unavailable"), and
`grep reason=uid_separation_unavailable` returns every host that could not UID-separate — a coherent
query. **The binding must NOT assert the two vocabularies are disjoint.**

### D8 — `policy_ref` stays declared-but-optional (agent fleet, unanimous)

Genuinely conditional: present only at `L412`, the one site that resolved a policy. Identical shape to
`sandbox_refused`, whose parser already treats it as optional (`launcher_refusal.py:63`
`_OPTIONAL_FIELDS`, absent → canonicalized to `""`).

* **Not dropped from the fields** — `L412`'s `policy_ref` is the only field naming *which* stub policy
  resolved; for a windows `kind:full` stub that is the whole diagnostic.
* **No explicit `""` emitted from bash** — it adds a printf arg to a security-critical path, and both
  cases canonicalize identically anyway.
* **No stub_used `_OPTIONAL_FIELDS` constant** — that is more unwired scaffolding. Document optionality
  on the constant, matching the refused family's comment style.

### D9 — two operator-key strategies coexist: verbatim re-print, and deliberate synthesis

The launcher's *operator stderr key* and the row's *audit `reason`* are **separate namespaces**, and
two DIFFERENT strategies produce the operator key depending on what the failing helper handed back.
(An earlier draft of this decision assumed only the first strategy and rejected the second outright
— that assumption did not survive contact with the schema-case path, below.)

* **#434A's `_read_sandbox` capture** (the manifest-key path) re-prints the captured helper key
  VERBATIM — the environment path above already does this, and following the same pattern here means
  the five real `manifest_reader --read-sandbox` refusals add **zero** new i18n keys:
  `plugin.manifest_unreadable`, `plugin.manifest_reader_no_source`, `plugin.manifest_invalid` are
  already registered in `_sandbox_i18n.py:41-43`; `plugin.launcher_plugin_id_invalid` and
  `plugin.launcher_uid_drop_unavailable` in `_launcher_i18n.py:39,42`. It also avoids the
  `t(message_key=var)` indirection that makes keys pybabel-invisible. This path's own `*)` fallback
  reassigns the SAME variable to the fixed literal `supervisor.sandbox.refused.reason_unclassified`
  precisely so a crashing helper's own (unconstrained) stderr text can never reach this verbatim
  re-print — pinned by the anti-echo test added alongside this decision.

* **The schema-case path (`bin/alfred-plugin-launcher.sh:388`) SYNTHESISES** the operator key by
  interpolating the resolved reason (`printf 'supervisor.sandbox.refused.%s ...' "${_AUDIT_REASON}"
  ...`). This is deliberate, not a lapse: the value captured on this path (`_CAPTURED_REASON`) is a
  BARE `SandboxPolicyInvalid` reason, never a full i18n key, so there is nothing to re-print verbatim.
  Before this PR the operator key here was hardcoded to `policy_ref_unreadable` for every schema
  refusal (#428's defect); interpolating fixes that — and, as a direct consequence, makes every one
  of the schema case's nine literal reasons independently reachable as its own operator key. Six of
  those nine had no catalog entry yet (`kind_full_requires_keep_fd_3`, `policy_path_not_absolute`,
  `arch_variable_path_hard_bound`, `mount_shadows_earlier_mount`, `soft_bind_forbidden_path`,
  `bind_source_too_broad`) — not new REASONS, but latent i18n gaps the old hardcoded key had been
  masking. `test_every_schema_case_reason_has_a_registered_operator_key` binds all nine so that a
  future maintainer who "corrects" `L388` back to a hardcoded key — reinstating the verbatim-only
  rule this decision originally stated — would silently relabel six real refusals back to
  `policy_ref_unreadable` and reopen #428, and the binding would catch it.

`supervisor.sandbox.refused.jq_unavailable` and `…macos_full_not_yet_shipped` already existed in the
catalog before this PR — the operator keys were registered but the reasons and rows were never added.
That asymmetry is the drift in miniature.

**Nine new i18n keys ship** (each needs a `t()` anchor in `_sandbox_i18n.py`): the three genuinely new
operator keys — `supervisor.sandbox.refused.reason_unclassified`, `…bwrap_unavailable`,
`…sandbox_kind_unrecognised` — plus the six schema-case literals the interpolation above newly
surfaces.

## Design

### Commit 1 — #434, reason accuracy

**Part A.** Replace `2>/dev/null` at `L273` with the capture-and-map pattern from `L155-171`:
`mktemp` → `2>"${_SANDBOX_ERR_FILE}"` → `tail -n 1` → `case`-map → `rm -f` on **both** arms.

| captured key | audit `reason` |
| --- | --- |
| `plugin.launcher_plugin_id_invalid` | `plugin_id_charset_invalid` *(new)* |
| `plugin.manifest_reader_no_source` | `manifest_reader_no_source` *(new)* |
| `plugin.manifest_unreadable` | `manifest_unreadable` *(new)* |
| `plugin.manifest_sandbox_block_missing` | `sandbox_block_missing` *(exists)* |
| `plugin.manifest_invalid` | `manifest_invalid` *(new)* |
| anything else | `reason_unclassified` *(new)* |

The operator stderr line re-prints the captured key verbatim (D9) when it matches one of the five
recognised keys above; an empty or unrecognised capture instead falls back to the fixed
`supervisor.sandbox.refused.reason_unclassified` key (fail-closed either way — we still refuse).

**Part B.** The `*)` arm at `L336` sets `_AUDIT_REASON="reason_unclassified"` instead of
`policy_translate_failed`, so a drift/crash alarm is forensically distinguishable from a real
malformed-TOML refusal. `policy_translate_failed` remains the reason for the genuine
`SandboxPolicyInvalid` case. The operator stderr key at `L317` becomes reason-accurate.

### Commit 2 — #435, every refusal emits exactly one row

| line | today | new `reason` | operator key |
| --- | --- | --- | --- |
| L126 | charset gate, no row | `plugin_id_charset_invalid` *(new)*, `plugin_id="<invalid>"`, `environment="unset"`, `host_os="unknown"` | `plugin.launcher_plugin_id_invalid` (exists) |
| L234 | runuser missing, no row | `runuser_unavailable` *(new)* | `plugin.launcher_uid_drop_unavailable` (exists) |
| L283 | jq missing, no row | `jq_unavailable` *(new)* | `…jq_unavailable` (exists) |
| L393 | bwrap exec fails at 127, no row | `bwrap_unavailable` (reserved → emittable) | `…bwrap_unavailable` *(new key)* |
| L402 | macOS `kind:full`, no row | `macos_full_not_yet_shipped` *(new)* | `…macos_full_not_yet_shipped` (exists) |
| L437 | unknown kind → mislabelled `sandbox_block_missing` | `sandbox_kind_unrecognised` *(new)* | `…sandbox_kind_unrecognised` *(new key)* |

`L437` is a #434-class mislabel in its own right: an unknown/unparseable `kind` is currently recorded
as "you forgot `[sandbox]`". `L234`'s row carries `host_os="linux"` (that branch is Linux-only).
The `bwrap` check goes immediately before the `exec` at `L393`, after `EXTRA_BINDS` resolution, and
uses `command -v "${BWRAP}"` so a `BWRAP=` absolute-path override is honoured.

### Commit 3 — #436, the stub-row contract

* Add `reason` to `SANDBOX_STUB_USED_FIELDS`.
* Add `SANDBOX_STUB_USED_REASONS: Final[frozenset[str]] = frozenset({"uid_separation_unavailable",
  "windows_stub", "stub_kind"})` per D7, declared as a module-level `Final` constant. The module has
  no `__all__` — `AUDIT_FIELDSET_ROSTER`, its only name-tracking roster, is scoped to `*_FIELDS`
  constants (the AST guard's bidirectional walk), not `*_REASONS` ones — so this constant is bound
  only by the #432 reason-vocab drift guard, like its `SANDBOX_REFUSED_REASONS` sibling.
* `L412` emits `reason="windows_stub"`; `L432` emits `reason="stub_kind"` — `reason` becomes mandatory
  on all three sites.
* **Fix the false docstring** at `audit_row_schemas.py:1264` ("Emitted when a kind:stub plugin runs
  unsandboxed in a development environment"). It is wrong for **2 of 3** producers — it describes only
  `L432`, *the one site that legitimately has no reason*. The schema author modelled one path and the
  constant inherited that blind spot; all three agents flagged this independently as the root cause
  rather than a symptom. The replacement names all three producers, documents `policy_ref` optionality
  (D8), and records the D4 non-persistence decision with its rationale.
* **Extend the #432 AST binding** to key on the `sandbox_stub_used` event (see Testing). Without this,
  `SANDBOX_STUB_USED_REASONS` ships as #432's exact disease under a new name: a prose comment bound to
  nothing.

### Vocabulary arithmetic

`SANDBOX_REFUSED_REASONS`: **26 → 35**. Nine new (`plugin_id_charset_invalid`,
`manifest_reader_no_source`, `manifest_unreadable`, `manifest_invalid`, `reason_unclassified`,
`runuser_unavailable`, `jq_unavailable`, `macos_full_not_yet_shipped`, `sandbox_kind_unrecognised`);
`bwrap_unavailable` moves reserved → emittable. Emittable **21 → 31**; reserved **5 → 4**
(`policy_ref_os_mismatch`, `bwrap_mode_userns_unavailable`, `provider_key_delivery_failed`,
`sandbox_info_handshake_mismatch`). The module comment's prose counts ("Twenty-one reasons are
launcher-emittable. Five are RESERVED") must be updated with them — it is exactly the kind of
bound-to-nothing prose #432 exists to catch.

`SANDBOX_STUB_USED_REASONS`: new, 3 members. `SANDBOX_STUB_USED_FIELDS`: 4 → 5.

## Testing

Every security boundary needs 100% line **and** branch coverage (CLAUDE.md). The launcher is bash, so
its coverage is behavioural: one test per refusal path asserting the exact row.

* **`tests/unit/plugins/test_sandbox_reason_vocab_sync.py`** — extend the #432 binding:
  * Generalise the hardcoded `_SANDBOX_REFUSED_EVENT` to resolve **per event**, keyed on the event
    **name**, not the JSON byte-string (#432's own lesson: keying on the byte-string silently
    under-counts).
  * Bind `SANDBOX_STUB_USED_REASONS` to every `sandbox_stub_used` emit line.
  * Assert the D7 twin-table invariant.
  * **Must not** assert the two vocabularies are disjoint — `uid_separation_unavailable` is
    deliberately shared (D7).
  * Re-derive the vacuity floors once: `_RESERVED_UNEMITTED == 4`, vocab `>= 35`, emittable `>= 31`,
    refused emit-lines `>= 18`, stub emit-lines `== 3`.
* **`tests/unit/launcher/test_launcher_sandbox_flow.py` / `tests/unit/plugins/test_plugin_launcher_stub.py`** —
  one test per newly-rowed path (L126, L234, L283, L393, L402, L437), each parsing the emitted JSON and
  asserting `reason` + the full field set. Per-reason tests for the #434A five-key map, driven by a real
  failing `manifest_reader` (not a stub) so the key contract is exercised end-to-end.
* **`tests/unit/audit/test_launcher_refusal.py`** — every new reason round-trips through
  `parse_launcher_refusal_rows` and is accepted; the `<invalid>` sentinel row parses. The parser is
  otherwise unchanged; assert that (no `_OPTIONAL_FIELDS` widening).
* **`tests/unit/audit/test_slice_4_audit_row_fields.py`** — `SANDBOX_STUB_USED_FIELDS` includes `reason`.
* **`tests/unit/plugins/test_sandbox_i18n_keys.py` / `tests/unit/test_catalog_slice_4_keys.py`** — the
  nine new keys are registered and present in the catalog. Run the full i18n gate
  (`pybabel extract` → `update --no-fuzzy-matching` → `compile`); a line-shifting edit re-stales the
  `#:` refs, and per-task runs skip that check.
* **Adversarial** — extend `tests/adversarial/sandbox_escape/`: a forged `sandbox_stub_used` row on
  inherited stderr must **not** be persisted (D4's guarantee, asserted rather than assumed); a
  malformed `plugin_id` must never appear in any emitted row (D2).
* **Platform** — the bwrap check needs the privileged-Linux real-spawn lane; the L234 runuser path and
  the L248/L432 stub paths are exercised on the macOS + Windows unit legs.

## Definition of done

* All six #435 paths emit exactly one schema-valid, correctly-labelled row; the five #434A keys map
  distinctly; `reason_unclassified` distinguishes the alarm from the real refusal.
* `sandbox_stub_used` carries a mandatory closed-vocab `reason` at all three sites; the docstring names
  all three producers, `policy_ref` optionality, and the D4 non-persistence decision.
* The #432 binding covers both row families and would fail on any future drift in either.
* `make check` clean; adversarial suite green (the launcher is a security boundary — mandatory);
  both privileged real-spawn lanes green.
* #434, #435, #436 closed; the follow-ups below filed.

## Out of scope (each to be filed)

* **`sandbox_stub_used` persistence** — needs a success-path stderr drain, a new interception point,
  and its own ADR (D4). Dev/test-only by construction (production refuses all three stub branches), so
  it ranks below #440-#442.
* **The `IS_PRODUCTION` predicate split** — `L240` uses `IS_PRODUCTION`; `L407`/`L427` use a direct
  `= "production"` compare. Consistently derived today (`L174-175`), so no live bypass — but any future
  normalization (accepting `prod`/`PRODUCTION`) silently strands `L407`/`L427`, and those are the two
  paths that exec **unsandboxed**. Collapse to one predicate.
* **Blank `REASON` column** — `_row_reason` (`cli/audit.py:126`) returns `""` for rows without a reason;
  this is #381's defect in a third family.
* **`--reason` cannot filter sandbox reasons** — `_ReasonChoice` (`cli/audit.py:46`) is a closed set of
  five comms reasons; `alfred audit log --reason uid_separation_unavailable` raises `BadParameter`.
* **Stale docs** — `docs/subsystems/supervisor.md:299` says "Nine hookpoints" (there are ten), omits
  `sandbox_stub_used`, and misstates its `fail_closed`; `config/sandbox/README.md:69` frames stub_used
  as Windows-only, training macOS devs to misread 2 of 3 causes.
* **The registered-but-unpublished hookpoint** — `supervisor/core.py:1094` promises "an audit consumer
  can never miss" that a plugin ran without OS-level isolation; nothing publishes it. Blocked on the
  persistence follow-up.
* **`_in_production` suffix redundancy** — redundant with the `environment` field already in the row,
  and the reason only one of three tokens crosses families. Cosmetic; not this PR.

## Non-obligations, verified

* **No PRD change.** `PRD.md` contains zero occurrences of `stub_used`, `sandbox_refused`, or `_FIELDS`;
  §7 runs 7.1→7.7, so the Slice-4 plan table's `§7.11` citation is bogus. This row family has never been
  a PRD-level contract. (PRD/CLAUDE.md edits are human-gated; neither is needed.)
* **No new ADR, no ADR-0051 amendment.** Contract-only conformance to an existing decision — ADR-0051's
  Follow-ups already names #434/#435/#436 as one group, so landing this satisfies that line rather than
  contradicting it. The stub_used **persist** path is what would need an ADR; it is out of scope.
* **No `t()` work beyond the nine new keys.** The JSON row is a structured record, not operator prose,
  and the launcher is a bash child-subprocess stderr producer — neither is `t()` scope.

# #428 — refuse an over-broad bind source in the sandbox policy schema

**Status:** approved, revised after `/review-plan` (2026-07-13) · **Issue:** #428 · **Base:** `main` @ `7461df15`

> **Revision note.** The first draft of this spec was reviewed by the full plan-review
> fleet. It found two real bypasses the original rule missed (a soft-bind traversal to `/`,
> and procfs magic-links), several false factual claims in the prose, and an oracle that
> could not actually falsify. This revision folds all of that in. The load-bearing changes
> from the first draft are flagged **[rev]** inline.

## The hole

```python
SandboxPolicy(ro_binds=[("/", "/")], keep_fds=[3])   # ACCEPTED on main
```

It emits `--ro-bind / /` — the entire host filesystem, read-only, inside the sandbox that
runs the quarantined LLM: the one process in the system that handles raw **T3**
(adversary-controlled) content. Every containment property the adversarial corpus asserts
(`sbx-2026-003` host `/etc/passwd` unreadable, `-004` `/bin/sh` not exec-reachable, `-006`
`/proc/environ` unreadable) is defeated by that one line, and the schema does not object.
`rw_binds=[("/", "/")]` emits `--bind / /` and is strictly worse — the host root, writable.

**This is not reachable today.** The shipped policies are hand-authored and do not do this,
so this is operator-misconfiguration hardening, not a live vulnerability. But the schema's
job is to make a misconfigured policy fail *loudly* rather than silently produce a sandbox
that isn't one, and it already refuses far smaller sins (`kind_full_requires_keep_fd_3`, an
out-of-vocab `unshare` kind, a soft-bound `/etc/ssl/certs`).

There is precedent one layer down: `bin/alfred-plugin-launcher.sh` already refuses an
interpreter prefix that resolves to `/` (`interpreter_prefix_too_broad`), on the stated
grounds that it "would ro-bind the ENTIRE host root into the sandbox, re-exposing /etc,
/proc mounts etc. the policy omits." The policy schema has no such guard.

### The hole is wider than `/` — two bypasses the first draft missed **[rev]**

The review found the shallow-root case is only one of three ways a bind source can expose the
host root, and any rule that guards only `/` (or only shallow roots) leaves the other two open:

1. **Traversal to root through the SOFT field.** `ro_binds_try=[("/lib64/..", "/")]` is
   accepted on `main` and would remain accepted under a rule that only covers `ro_binds` +
   `rw_binds`. `_is_arch_variable("/lib64/..")` matches `/lib64` on the raw-component walk
   *before* the `..`, and `_restrict_soft_binds` then passes it because
   `_canonical("/lib64/..") == "/" == _canonical("/")`. It emits `--ro-bind-try /lib64/.. /`
   — the host root, soft-bound, into the T3 sandbox. On `main` it is only caught incidentally
   by `_refuse_a_mount_that_shadows_an_earlier_one` *when the policy also has an earlier
   mount*; a minimal policy with this as its first bind passes clean.

2. **procfs magic-links.** `/proc/self/root`, `/proc/1/root`, `/proc/<pid>/cwd` are magic
   symlinks that resolve to the host root (or an arbitrary process's root/cwd) when bwrap
   opens them. They are depth-3+ paths, so a depth-based breadth rule waves them straight
   through. `--ro-bind /proc/self/root /x` binds the host root. No shipped policy ever binds
   anything under `/proc` or `/sys`, so these are never legitimate bind sources.

## The twin hole, in the layer that actually execs

The launcher's `interpreter_prefix_too_broad` guard refuses only `""` and `/`. It computes
`_INTERP_PREFIX = dirname(dirname(realpath(EXECUTABLE)))`, so an operator-configured
interpreter at `/home/u/python` yields the prefix `/home` — **accepted** — and emits
`--ro-bind /home /home` into the same T3 sandbox. Same shape, same threat model, different
layer. Both are in scope here, behind **one** exported predicate: two encodings of the same
rule in two languages is the drift #422 was filed about.

Note the launcher *does* `realpath` its interpreter input, so it collapses on-disk symlinks
before the check; the schema does not `realpath` its bind sources (and must not — see
`_canonical`). The two layers therefore have different residuals; this is stated in "What
this guard cannot do" rather than papered over.

## The rule **[rev — now three tiers, not one]**

A bind **source** is refused when any of the following holds, checked against its
`_canonical` form. All three tiers raise `SandboxPolicyInvalid(reason="bind_source_too_broad")`.

| Tier | Refuses | Applies to |
| --- | --- | --- |
| 1 — resolves to host root | `_canonical(src) == "/"` (covers `/`, `/lib64/..`, `/usr/..`, `/lib/../..`) | **all** bind fields incl. `ro_binds_try` |
| 2 — pseudo-filesystem source | canonical first component ∈ {`proc`, `sys`} (covers `/proc`, `/proc/self/root`, `/sys/…`) | **all** bind fields incl. `ro_binds_try` |
| 3 — over-broad top-level root | a single-component root not in the allowlist | `ro_binds` + `rw_binds` only |

```python
_PERMITTED_TOP_LEVEL_BIND_ROOTS: Final[frozenset[str]] = frozenset({"/usr", "/lib"})
_PSEUDO_FS_TOP_LEVEL: Final[frozenset[str]] = frozenset({"proc", "sys"})

def is_over_broad_bind_source(path: str) -> bool:
    """HARD-field rule (tiers 1+2+3). Exported; the launcher calls this for the
    interpreter prefix, which is a hard --ro-bind. NOT for soft binds — see below."""
    canonical = _canonical(path)
    parts = PurePosixPath(canonical).parts          # ("/",) for "/"; ("/","proc","self","root") …
    if canonical == "/":                             # tier 1
        return True
    if len(parts) >= 2 and parts[1] in _PSEUDO_FS_TOP_LEVEL:   # tier 2
        return True
    if canonical in _PERMITTED_TOP_LEVEL_BIND_ROOTS:          # tier 3 allow
        return False
    return len(parts) <= 2                           # tier 3 refuse
```

**Why tier 3 is hard-fields-only, and why it cannot merge with tiers 1+2.** `ro_binds_try`
legitimately carries `/lib64` — a *single-component* (depth-1) arch-variable root. The tier-3
breadth floor would refuse it. So the soft field gets tiers 1+2 only (a source that
resolves to `/`, or lives under a pseudo-fs, is over-broad in *any* field), and keeps its
existing `_restrict_soft_binds` governance (identity bind of an arch-variable path) for
everything else. The soft-field check therefore uses a narrower internal predicate, not the
exported `is_over_broad_bind_source`.

**Why `_canonical` matters, stated correctly this time [rev — the first draft's claim that
all six respellings collapse to `/` was false].** `_canonical` collapses respellings so a
raw-string comparison cannot be walked past. Its actual outputs:

| Input | `_canonical` | Refused by | Reason |
| --- | --- | --- | --- |
| `/lib64/..` | `/` | tier 1 | resolves to root |
| `/usr/..` | `/` | tier 1 | resolves to root |
| `/etc/` , `//etc` , `/etc/.` | `/etc` | tier 3 | depth-1 root, not allowlisted |
| `/usr/../etc` | `/etc` | tier 3 | depth-1 root, not allowlisted |
| `/etc/ssl/certs/../..` | `/etc` | tier 3 | depth-1 root, not allowlisted |
| `/proc/self/root` | `/proc/self/root` | tier 2 | pseudo-fs source |

Only `/lib64/..` and `/usr/..` canonicalise to `/`. The `/etc` respellings canonicalise to
`/etc` and are refused by the breadth floor, not tier 1.

**Keying on the source** mirrors `_refuse_hard_bind_of_arch_variable_path` directly above it:
"bwrap cares about the source. So does this validator."

### The allowlist, and why `/usr` is on it

`/usr` and `/lib` are on the allowlist because both shipped policies hard-bind them. `/usr`
is broad — it leaves `/usr/bin/*` exec-reachable — and that residual is tracked in **#430**
("tighten the /usr hard-bind to the exact CPython prefix"), the live successor to the now-
closed #230. **[rev — the first draft cited #230, which is CLOSED and was never scoped to
this; #430 was filed to be the real tracker.]** When #430 lands and the policies drop `/usr`,
the sync test (below) forces the allowlist to shrink with them.

This is an **allowlist, not a denylist, and that is the point.** Tier 3 refuses `/etc`,
`/home`, `/root`, `/var`, `/boot`, `/run`, `/tmp` *and* `/data`, `/mnt/host` and every other
top-level root, FHS or not, that nobody has thought of yet. A denylist of the roots we
happened to enumerate is the exact pattern that shipped seven successive variants in #269.
Tier 2 (`/proc`, `/sys`) is a deliberate, named, two-entry exception to the "no denylist"
stance: those two pseudo-filesystems bear magic symlinks that resolve to the host root, they
are never a legitimate bind source, and no lexical breadth rule can catch a depth-3 path that
resolves to root. The allowlist still does the breadth work; tier 2 closes the one class the
breadth rule structurally cannot.

Deeper paths stay unconstrained, so every legitimate bind still parses: `/etc/ssl/certs`
(Discord's CA bundle), `/home/alfred/.egress/discord` (Discord's egress dir), and a
`~/.proto/...` interpreter prefix.

## What this guard CANNOT do

Stated here and, more importantly, **in the guard's own docstring**. Per #269: a docstring
claiming completeness is not documentation, it is the mechanism by which the next variant
ships, because it stops the next reader from looking further.

1. **Depth is a proxy for breadth, not breadth itself.** `/home/alfred` is depth-2 and holds
   the operator's entire home directory. `/var/lib/alfred` exposes `state.git`. Both parse
   clean. Tier 3 is a **floor, not a ceiling**.
2. **It is lexical, so an on-disk symlink defeats it.** A bind source that is a symlink on
   disk pointing at `/` (or at `/etc`) binds the target. This module must never touch the
   filesystem — that is what makes a policy's meaning independent of the machine that parsed
   it (see `_canonical`'s docstring) — so it structurally cannot resolve that. `realpath` is
   the launcher's job for the interpreter, and no layer `realpath`s a *policy* bind source.
3. **Tier 2 names only the pseudo-filesystems we know bear root-resolving magic-links today
   (`/proc`, `/sys`).** A future kernel pseudo-fs with the same property, or a bind-mount
   source that is itself a mountpoint onto something broad, is not caught. Assume variant N+1
   exists: this is a lexical rule deciding a filesystem fact, and the gap between those two
   has produced six distinct bugs in this file already.

### What actually holds — and its own blind spot **[rev — de-emphasised, per sec-003]**

`tests/integration/test_quarantined_llm_policy_kernel_enforced.py` runs real bwrap against
the **shipped** policy bytes and asserts host `/etc/passwd`, `/bin/sh` and `/proc/environ`
are unreachable. That is a real-execution **widening** detector — the one class of gate a
static rule cannot be. **But it only exercises the shipped bytes and only the three paths it
enumerates.** It does *not* run arbitrary misconfigured policies, which is exactly the threat
model of this issue. So for an over-broad *misconfiguration*, this static guard is the sole
line of defence, not a backstopped one. The honest claim is: the two mechanisms are
complementary for the *shipped* policies; for an *arbitrary* policy, only the static guard
runs, so its correctness (and the mutation-tested property below) is load-bearing. #427
separately tracks that the kernel-enforcement helper re-emits policies field-by-field.

## Components

### 1. `src/alfred/plugins/sandbox_policy.py`

- `_PERMITTED_TOP_LEVEL_BIND_ROOTS`, `_PSEUDO_FS_TOP_LEVEL`, and the exported
  `is_over_broad_bind_source` (tiers 1+2+3 — the hard-field rule the launcher calls).
- `_refuse_over_broad_bind_source`, a `model_validator(mode="after")` defined **after**
  `_require_absolute_paths` (Pydantic v2 runs `mode="after"` validators in definition order —
  **verified** — so absolute-path refusal has already run; a relative path never reaches this
  guard). It applies tiers 1+2 to `ro_binds` + `rw_binds` + `ro_binds_try` sources, and tier
  3 to `ro_binds` + `rw_binds` sources only. Raises
  `SandboxPolicyInvalid(reason="bind_source_too_broad")` with a detail naming the field, the
  pair, and the fix.
- Validator ordering note: for a source like `/lib64/..` in a *hard* field,
  `_refuse_hard_bind_of_arch_variable_path` runs first and raises `arch_variable_path_hard_bound`
  (it matches `/lib64` on the raw walk). So over-broad respelling *unit* tests that want to
  assert `bind_source_too_broad` must use non-arch-variable roots (`/usr/..`, `/etc`-based).
  `/lib64/..` in a *soft* field reaches tier 1 and gets `bind_source_too_broad`. Both are
  pinned by tests so the ordering is documented, not incidental.

### 2. `src/alfred/audit/audit_row_schemas.py`

Add `bind_source_too_broad` to the reason-vocabulary **comment block at lines 1188–1194**.
**[rev — this is an unenforced doc-comment, not the `SANDBOX_REFUSED_FIELDS` frozenset (which
holds field *names*, not reason *values*); the spec now names the exact edit site so the
implementer does not look for a set to extend.]** No test guards this comment; a "reason
strings are closed" test is out of scope for #428.

### 3. `src/alfred/plugins/manifest_reader.py`

A new `--check-bind-source <path>` mode: exit 0 if the path is an acceptable bind source
(`not is_over_broad_bind_source(path)`), else print a stable bare key and exit non-zero. This
is how the launcher reaches the single Python predicate rather than re-encoding the rule in
bash. The mode gets its own exit-code unit tests in `tests/unit/plugins/test_manifest_reader_cli.py`
(accept → exit 0; over-broad → non-zero; empty arg → non-zero, since
`is_over_broad_bind_source("")` returns True — `_canonical("")` is `.`, 0 parts, refused).

### 4. `bin/alfred-plugin-launcher.sh`

- The interp-prefix check becomes a call to `--check-bind-source "$_INTERP_PREFIX"`, replacing
  `[ -z "$_INTERP_PREFIX" ] || [ "$_INTERP_PREFIX" = "/" ]`. It keeps its existing
  `interpreter_prefix_too_broad` reason and catalog key — **no new i18n surface**. **[rev — the
  bash empty-string check is now redundant, not "still necessary": the Python predicate refuses
  `""` already. The bash may drop it; the mode is the sole authority.]** This adds a 5th
  `manifest_reader` subprocess on the opt-in quarantine/adapter spawn path only (~1.7–3.7 s cold
  import, measured; the launcher already invokes `manifest_reader` 4× and the import is proven
  loadable by then — no bootstrap-ordering risk). Folding it into the existing
  `--policy-to-bwrap-flags` call is a possible DRY/latency optimisation but is **out of scope**
  here; accept the extra subprocess.
- **Audit-reason misattribution fix (owns all six reasons).** `bin/alfred-plugin-launcher.sh:303`
  hardcodes `"reason":"policy_ref_unreadable"` into the audit JSON for *any* failure of the
  flags call. Every schema refusal — `kind_full_requires_keep_fd_3`, `soft_bind_forbidden_path`,
  `mount_shadows_earlier_mount`, `arch_variable_path_hard_bound`, `policy_path_not_absolute`, and
  the new `bind_source_too_broad` — is therefore audited under a reason that is not its own. The
  launcher captures the helper's stderr already (`BWRAP_FLAGS_RAW`, via `2>&1`). **[rev — it
  must `tail -n 1` that capture before matching, because the alfred cold-import can emit a
  stderr warning *ahead* of the bare reason (this is why the BUG-1 pin exists at L162); a
  whole-blob match would non-deterministically fall back.]** It then exact-matches the last
  line against the closed reason vocabulary and echoes it into the audit row's `reason` field
  when it matches, falling back to `policy_ref_unreadable` when it does not. The reading side
  is safe: the JSON `reason` is never catalog-rendered, and `SANDBOX_REFUSED_FIELDS` validates
  field *names*, so a new reason value breaks nothing. This fix re-attributes all six reasons,
  so its tests cover at least one pre-existing reason (e.g. `soft_bind_forbidden_path`) in
  addition to `bind_source_too_broad`.

### 5. Docs

- **Amend `docs/adr/0037-production-quarantine-sandbox-boundary.md`** to record the new
  structural invariant: policy bind *sources* are governed by a closed allowlist of permitted
  top-level roots (`{/usr, /lib}`), and a source at depth ≤ 1 outside it, or resolving to `/`,
  or under a pseudo-filesystem (`/proc`, `/sys`), is refused at parse time with reason
  `bind_source_too_broad`. Mirrors the #269 precedent of amending the standing ADR rather than
  minting a net-new one.
- Check `docs/subsystems/supervisor.md` for drift on the newly-surfaced reasons (it references
  sandbox refusal reasons) and update if the audit-fix changes what an operator sees.

## Tests

`sandbox_policy.py` is a security boundary: **100% line + branch coverage**.

### Existing tests this change breaks **[rev — the first draft did not acknowledge these]**

- `tests/unit/plugins/test_sandbox_policy_translator.py::test_a_genuine_near_miss_path_is_not_treated_as_arch_variable`
  requires `SandboxPolicy(ro_binds=[("/lib64-compat", "/lib64-compat")])` to *validate*. The
  new tier-3 rule refuses `/lib64-compat` (depth-1, not allowlisted). Deepen the near-miss
  source to `/opt/lib64-compat` so it still proves the arch-variable over-correction guard
  without tripping the new rule.
- The #269 property pools in the same file (`_HARD_SRCS`, `_LEGAL_HARD_SRCS`) inject `/x` and
  `/lib64-compat` as *accepted* depth-1 sources, weighted ×2. Both are now refused, which
  collapses the acceptance rate and breaks the anti-vacuity thresholds in
  `test_the_strategies_actually_reach_the_regions_the_properties_guard`. Deepen those pool
  entries to depth ≥ 2 spellings and re-measure the thresholds.

### The property, with an oracle that cannot borrow the answer **[rev — the first draft's oracle was not independent]**

There is **no fully allowlist-agnostic oracle** for an arbitrary allowlist: to decide `/usr`
acceptable but `/etc` not, any oracle must know the allowlist, and a hand-rolled `..`-stack
resolver is `posixpath.normpath` retyped (a shared bug in "what canonical means" hides in
both). So the property is split into three pieces, each independent in a way a single
reimplemented resolver is not:

1. **Allowlist-independent refuse-net (a real property).** Sample single-component roots from
   a broad pool that *deliberately excludes* `/usr` and `/lib` — `/etc /proc /sys /home /root
   /var /dev /boot /run /tmp /data /mnt /srv /banana …` — plus `/` itself, plus the
   traversal-to-root respellings (`/usr/..`, `/lib64/..`, `/lib/../..`), plus pseudo-fs deep
   paths (`/proc/self/root`, `/proc/1/root`). Assert **every** sample is refused with reason
   `bind_source_too_broad`. This needs no allowlist and no `normpath` in the oracle — the
   oracle is "these are all over-broad, full stop."
2. **Accept direction — example-based, tied to the sync test.** Unit assertions over the
   actual shipped roots and deeper legit paths (`/usr`, `/lib`, `/etc/ssl/certs`,
   `/home/alfred/.egress/discord`) validate cleanly. Not a property — the accept set is
   exactly the shipped set, which the sync test independently pins.
3. **Respelling verdicts — a hand-verified table.** A literal `input → expected verdict` table
   (each respelling's verdict written by hand, e.g. `("/usr/../etc", REFUSE)`,
   `("/etc/ssl/certs/../..", REFUSE)`, `("/lib64/..", REFUSE)`), asserted directly. A table
   cannot share an algorithm bug with the validator because it contains no algorithm.

### Mutation-test the property **[rev — the first draft's mutant set and killer inputs were wrong]**

Every mutant below MUST make a property fail; each kill goes in the PR body:

1. delete `_refuse_over_broad_bind_source` → refuse-net fails.
2. widen `_PERMITTED_TOP_LEVEL_BIND_ROOTS` to include `/etc` → refuse-net fails on `/etc`.
3. `len(parts) <= 2` → `< 2` (off-by-one: refuses `/` but accepts every depth-2 root) →
   refuse-net fails on `/etc`, `/proc`-less shallow roots. **The single most likely survivor;
   the first draft omitted it.**
4. `len(parts) <= 2` → `== 1` (same class) → refuse-net fails.
5. strip the `_canonical` call (raw-string compare) → killed by the **traversal** respellings
   (`/usr/../etc` raw-parts len 4 → not refused; `/lib64/..` raw len 3 → not refused), **not**
   by `/etc/` (which is refused either way — the first draft's stated killer was wrong). The
   pool must therefore contain the traversal respellings, or this mutant survives.
6. drop the tier-2 pseudo-fs check → killed by `/proc/self/root`.
7. drop the soft-field tier-1 coverage → killed by `ro_binds_try=[("/lib64/..", "/")]`.

Vacuity is measured — the fraction of generated examples reaching each assertion — so a green
tick cannot hide behind a strategy that filters everything away (the #269 `filter_too_much`
lesson).

### Sync test **[rev — field scope and anti-vacuity floor made explicit]**

`_PERMITTED_TOP_LEVEL_BIND_ROOTS` must equal exactly the set of depth-1 *canonical* bind
sources the shipped policies declare in **`ro_binds` + `rw_binds` only** — **excluding
`ro_binds_try`**, which legitimately carries the depth-1 arch-variable root `/lib64`. Reading
`ro_binds_try` would find `/lib64` and either fail the build or tempt an implementer to add
`/lib64` to the allowlist, re-opening the #269 root class. Read from the **non-recursive**
glob `config/sandbox/*.linux.bwrap.policy` (which excludes the `*.windows.stub.policy` files —
they carry keys `read_policy_toml` rejects — and does not descend into `_fixtures/`). Assert
the glob matched **≥ 2 files** (both named shipped policies) so it cannot pass vacuously on an
empty match. Assert exact set equality with `{/usr, /lib}`, with a comment that `/lib64`
(soft-only) is excluded by design. This is the "what feeds this, and what happens when it
grows a new case?" test — the only thing in #269's whole sequence that closed a *class*.

### Boundary test

No entry in `_ARCH_VARIABLE_PATHS` may canonicalise to `/`, so the soft field cannot become a
back door for the root even before tier-1 soft coverage.

### Launcher

A `/home`-prefix interpreter is refused with `interpreter_prefix_too_broad`; a `/usr` prefix
and a deep `~/.proto/...` prefix are both accepted. The audit row for a schema refusal now
carries that schema's own reason — tested for both `bind_source_too_broad` and one pre-
existing reason (`soft_bind_forbidden_path`).

### Adversarial **[rev — plumbing was underestimated]**

The refusal is a **parse-time `SandboxPolicyInvalid`, not kernel-observable** (like
`sbx-2026-008/009`), so it needs no bwrap real-spawn test. The deliverable is:

- a new payload `sbx-2026-016` (next free id; 015 is highest) with `ingestion_path:
  sandbox_policy_load`, `expected_outcome: refused`, non-empty `provenance`/`references` per
  `payload_schema.py`;
- its executable counterpart asserting
  `read_policy_toml('ro_binds=[["/","/"]]\nkeep_fds=[3]')` raises
  `SandboxPolicyInvalid(reason="bind_source_too_broad")`, plus a soft-field
  (`/lib64/..`) and a pseudo-fs (`/proc/self/root`) case;
- registration of `sbx-2026-016` in the appropriate `test_all_pr_*_payloads_load` id-tuple in
  `test_sbx_corpus_executable.py` (a payload not in a load-list is schema-validated but
  unexercised);
- **a new row in the `tests/adversarial/sandbox_escape/README.md` coverage matrix** (drift is a
  documented release-blocker) for the over-broad-bind-source vector → this PR /
  `bind_source_too_broad`;
- **registration of the new executable test node-id in `.github/workflows/adversarial.yml`'s
  hardcoded required-node list** (~L124–131) — an unregistered node is collected-but-unprotected,
  the exact silent-deletion hole that gate exists to close (the #245 paper-gate lesson).

`sandbox_policy_load` / `refused` are already in the `payload_schema.py` Literal vocab, so no
schema change. Density floor (`≥ 10`) is already met (15 payloads), so this is additive.

## i18n

`bind_source_too_broad` is a **machine audit-reason enum**, not an operator-facing string. It
is printed bare by `manifest_reader._fail()` into the audit JSON `reason` field; the operator-
facing rendered message stays `supervisor.sandbox.refused.policy_translate_failed` (the
existing catalog key). The four existing schema reasons work exactly this way and have no
catalog keys. **Do not** print the bare reason as a rendered operator stderr line — that would
turn it into an un-catalogued rendered key and break i18n HARD rule #1.

## Non-goals

- **#430** (tighten the `/usr` bind to the exact CPython prefix). `/usr` is allowlisted here
  precisely so this PR does not pre-empt that decision; #430 is its tracker.
- **#427** (kernel-enforcement helpers re-emit policies field-by-field).
- **#423** (a second `_ARCH_VARIABLE_PATHS` entry requires the skipped soft bind to be
  observable first).
- **#422** (extract the duplicated CI assert-RAN block). The "one predicate, two layers"
  design here is *why* we avoid a second copy of the rule; #422 is about CI-block duplication,
  a different axis.
- **Folding the 5th launcher subprocess into `--policy-to-bwrap-flags`** (a latency/DRY
  optimisation).
- **The issue's secondary `tmpfs` note.** Re-checked and **closed with no code**:
  `tmpfs = ["/lib64"]` *alongside* a `/lib64` bind is already refused by
  `_refuse_a_mount_that_shadows_an_earlier_one` (#426). With no `/lib64` bind there is nothing
  to mask — bwrap starts from an empty root, so a tmpfs at an unbound path creates an empty
  directory rather than hiding a real one. A tmpfs can only ever mask, never widen, so it is
  not a vector for this rule. This disposition gets posted on the issue.

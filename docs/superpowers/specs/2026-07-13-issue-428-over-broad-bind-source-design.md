# #428 — refuse an over-broad bind source in the sandbox policy schema

**Status:** approved (2026-07-13) · **Issue:** #428 · **Base:** `main` @ `be780743`

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

## The twin hole, in the layer that actually execs

That launcher guard refuses only `""` and `/`. It computes
`_INTERP_PREFIX = dirname(dirname(realpath(EXECUTABLE)))`, so an operator-configured
interpreter at `/home/u/python` yields the prefix `/home` — **accepted** — and emits
`--ro-bind /home /home` into the same T3 sandbox. Same shape, same threat model, different
layer. Both are in scope here, behind **one** predicate: two encodings of the same rule in
two languages is the drift #422 was filed about.

## The rule

A bind **source** may not be the filesystem root, nor a top-level (single-component)
directory, unless that directory is in a small, explicitly-justified allowlist.

```python
_PERMITTED_TOP_LEVEL_BIND_ROOTS: Final[frozenset[str]] = frozenset({"/usr", "/lib"})

def is_over_broad_bind_source(path: str) -> bool:
    canonical = _canonical(path)
    if canonical in _PERMITTED_TOP_LEVEL_BIND_ROOTS:
        return False
    return len(PurePosixPath(canonical).parts) <= 2   # "/" or "/<one component>"
```

`_canonical` (already in the module) collapses the respellings that would otherwise walk
straight past a raw-string comparison: `/etc/`, `//etc`, `/etc/.`, `/usr/../etc`,
`/etc/ssl/certs/../..`, and `/lib64/..` → `/`.

**This is an allowlist, not a denylist, and that is the point.** It refuses `/etc`, `/proc`,
`/sys`, `/home`, `/root`, `/var`, `/dev`, `/boot`, `/run`, `/tmp` — *and* `/data`,
`/mnt/host` and every other top-level root, FHS or not, that nobody has thought of yet. A
denylist of the roots we happened to enumerate is the exact pattern that shipped seven
successive variants in #269.

It leaves deeper paths unconstrained, so every legitimate bind still parses:
`/etc/ssl/certs` (Discord's CA bundle), `/usr/lib` (the resolver fixture),
`/home/alfred/.egress/discord` (Discord's egress dir), and a `~/.proto/...` interpreter
prefix.

`/usr` is in the allowlist because both shipped policies need it. It is **already known to
be permissive and is tracked in #230** ("tighten the interpreter bind to the exact CPython
prefix, dropping the broad /usr"). This guard neither duplicates nor conflicts with that
work: it declares `/usr` permitted-for-now and names #230 as the tracker. `/lib` is there
for the same reason (the dynamic loader).

### Which fields it applies to

| Field | Covered | Why |
| --- | --- | --- |
| `ro_binds` (source) | yes | `--ro-bind SRC DST` — exposes host content. |
| `rw_binds` (source) | yes | `--bind SRC DST` — exposes host content, writable. |
| `ro_binds_try` (source) | no — already tighter | `_restrict_soft_binds` permits only an identity bind of an arch-variable path. `/` is not arch-variable, so it is already refused. |
| bind destinations | no | A destination cannot expose host content; it can only mask, and `_refuse_a_mount_that_shadows_an_earlier_one` (#426) owns masking. |
| `tmpfs` targets | no | A tmpfs is empty. It can only ever mask, never widen. |

Keying on the **source** mirrors `_refuse_hard_bind_of_arch_variable_path` directly above
it: "bwrap cares about the source. So does this validator."

The `ro_binds_try` exclusion is a real boundary, not an oversight: `/lib64` *is* a top-level
root and is legitimately soft-bound, so the two fields genuinely cannot share one rule. That
boundary gets pinned by a test (below) so a future `_ARCH_VARIABLE_PATHS` entry cannot
smuggle the root in through the soft field.

## What this guard CANNOT do

Stated here and, more importantly, **in the guard's own docstring**. Per #269: a docstring
claiming completeness is not documentation, it is the mechanism by which the next variant
ships, because it stops the next reader from looking further.

1. **Depth is a proxy for breadth, not breadth itself.** `/home/alfred` is depth-2 and holds
   the operator's entire home directory. `/var/lib/alfred` exposes `state.git`. Both parse
   clean. This guard is a **floor, not a ceiling**.
2. **It is lexical, so a symlink defeats it.** A bind source that is a symlink to `/` binds
   `/`. This module must never touch the filesystem — that is what makes a policy's meaning
   independent of the machine that parsed it (see `_canonical`'s docstring) — so it
   structurally cannot resolve that. `realpath` is the launcher's job, not the schema's.
3. **Assume variant N+1 exists.** This is a lexical rule deciding a filesystem fact. Those
   are not the same thing, and the gap between them has produced six distinct bugs in this
   file already.

### What actually holds

`tests/integration/test_quarantined_llm_policy_kernel_enforced.py` — real bwrap, the
**shipped** policy bytes, asserting host `/etc/passwd`, `/bin/sh` and `/proc/environ` are
unreachable from inside the sandbox. That is a real-execution **widening** detector, which
is the one class of gate a static rule cannot be.

Its blind spot, named so it is not mistaken for a guarantee: it only probes the three paths
it enumerates, and #427 tracks the fact that its helper re-emits policies field-by-field, so
a new policy field can silently drop out of the proof.

The two mechanisms are complementary, and each is honest about what it misses.

## Components

### 1. `src/alfred/plugins/sandbox_policy.py`

- `_PERMITTED_TOP_LEVEL_BIND_ROOTS` + `is_over_broad_bind_source` (exported — the launcher
  needs it).
- `_refuse_over_broad_bind_source`, a `model_validator(mode="after")` alongside the existing
  four, raising `SandboxPolicyInvalid(reason="bind_source_too_broad")` with a detail naming
  the field, the pair, and the fix.

### 2. `src/alfred/audit/audit_row_schemas.py`

Add `bind_source_too_broad` to the `supervisor.plugin.sandbox` closed reason vocabulary.

### 3. `src/alfred/plugins/manifest_reader.py`

A new `--check-bind-source <path>` mode: exit 0 if the path is an acceptable bind source,
else print the bare key and exit non-zero. This is how the launcher reaches the single
Python predicate rather than re-encoding the rule in bash.

### 4. `bin/alfred-plugin-launcher.sh`

- The interp-prefix check becomes a call to `--check-bind-source`, replacing
  `[ -z "$_INTERP_PREFIX" ] || [ "$_INTERP_PREFIX" = "/" ]`. It keeps its existing
  `interpreter_prefix_too_broad` reason and its existing catalog key — **no new i18n
  surface**. An empty prefix must still be refused explicitly (an empty argument is not a
  path).
- **Audit-reason misattribution fix.** `bin/alfred-plugin-launcher.sh:303` currently
  hardcodes `"reason":"policy_ref_unreadable"` into the audit JSON for *any* failure of the
  flags call. Every existing schema refusal (`soft_bind_forbidden_path`,
  `mount_shadows_earlier_mount`, `arch_variable_path_hard_bound`,
  `policy_path_not_absolute`) is therefore already audited under a reason that is not its
  own — and `bind_source_too_broad` would be too, on day one. The launcher captures the
  helper's stderr already; it echoes that bare reason into the audit row when it is in the
  closed vocabulary, falling back to `policy_ref_unreadable` when it is not. The refusal was
  always loud; this makes the audit row *true*.

## Tests

`sandbox_policy.py` is a security boundary: **100% line + branch coverage**.

**Unit.** Each over-broad root refused in both `ro_binds` and `rw_binds`; each respelling
(`/etc/`, `//etc`, `/etc/.`, `/usr/../etc`, `/etc/ssl/certs/../..`, `/`, `//`, `/.`,
`/usr/..`) refused; each legitimate bind still accepted. Both shipped policies and the
`test_launcher_policy_resolver` fixture still parse — asserted directly.

**Property (hypothesis), with an oracle that does not ask the code if the code is right.**
The oracle re-derives over-broadness by a *different mechanism* than the implementation — a
hand-rolled `..`-stack resolver over `PurePosixPath`, not `posixpath.normpath` — and imports
nothing from the validator, not the allowlist and not the predicate. The strategy pool is
seeded with the adversarial shapes (respellings, traversals, near-misses) as well as the
legal ones, because a strategy can only find what it can express.

**Mutation-test the property.** Three mutants, each of which MUST make it fail:

1. delete the validator → property fails;
2. widen `_PERMITTED_TOP_LEVEL_BIND_ROOTS` to include `/etc` → property fails;
3. strip the `_canonical` call, comparing raw strings → property fails (on `/etc/` et al).

A surviving mutant means the property is decorative. Evidence goes in the PR body. Vacuity
is measured too — the fraction of generated examples that actually reach the assertion — so
a green tick cannot hide behind a strategy that filters everything away.

**Sync test.** `_PERMITTED_TOP_LEVEL_BIND_ROOTS` must equal exactly the set of depth-1 bind
sources the **shipped** policies declare, read from `config/sandbox/*.linux.bwrap.policy` at
test time. Widening the allowlist without a shipped policy that needs it fails the build.
This is the "what feeds this, and what happens when it grows a new case?" test — the only
thing in #269's whole sequence that closed a *class* rather than an instance.

**Boundary test.** No entry in `_ARCH_VARIABLE_PATHS` may canonicalise to `/`, so the soft
field cannot become a back door for the root.

**Launcher.** A `/home`-prefix interpreter is refused with `interpreter_prefix_too_broad`; a
`/usr` prefix and a deep `~/.proto/...` prefix are both accepted. The audit row for a schema
refusal now carries that schema's own reason.

**Adversarial.** A new `sbx-2026-*` payload for the host-root bind
(`ingestion_path: sandbox_policy_load`, `expected_outcome: refused`) with its executable
counterpart, per the CLAUDE.md rule that a change to `src/alfred/security/`-adjacent
trust-boundary code runs the full adversarial suite.

## Non-goals

- **#230** (`/usr` is broad, `/usr/bin/*` stays exec-reachable). `/usr` is allowlisted here
  precisely so this PR does not pre-empt that decision.
- **#427** (kernel-enforcement helpers re-emit policies field-by-field).
- **#423** (a second `_ARCH_VARIABLE_PATHS` entry requires the skipped soft bind to be
  observable first).
- **The issue's secondary `tmpfs` note.** Re-checked and **closed with no code**:
  `tmpfs = ["/lib64"]` *alongside* a `/lib64` bind is already refused by
  `_refuse_a_mount_that_shadows_an_earlier_one` (#426). With no `/lib64` bind there is
  nothing to mask — bwrap starts from an empty root, so a tmpfs at an unbound path creates
  an empty directory rather than hiding a real one. A tmpfs can only ever mask, never widen,
  so it is not a vector for this rule. This disposition gets posted on the issue.

# Over-broad bind-source guard (#428) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refuse an over-broad bind *source* (the host root, a non-allowlisted top-level directory, or a root-resolving pseudo-filesystem) in the bwrap `SandboxPolicy` schema, and close the identical hole in the launcher's interpreter-prefix bind — behind one shared predicate.

**Architecture:** A new Pydantic `model_validator` on `SandboxPolicy` refuses over-broad sources at parse time with `reason="bind_source_too_broad"`. The rule is three tiers: (1) a source canonicalising to `/` is refused in *every* bind field including the soft `ro_binds_try`; (2) a source under `/proc` or `/sys` is refused in every field; (3) a single-component top-level root not on the `{/usr, /lib}` allowlist is refused in the hard fields only (`ro_binds`, `rw_binds`). The rule's core predicate is exported and reused by the launcher via a new `manifest_reader --check-bind-source` CLI mode, so the two enforcement layers share one implementation. The same PR corrects a pre-existing audit-reason misattribution in the launcher.

**Tech Stack:** Python 3.14 · Pydantic v2 · pytest + hypothesis · bash (`bin/alfred-plugin-launcher.sh`) · the sandbox-escape adversarial corpus · GitHub Actions.

## Global Constraints

- **Base:** `main` @ `59bae79e`. Work on a branch `fix/428-over-broad-bind-source`.
- **Spec:** `docs/superpowers/specs/2026-07-13-issue-428-over-broad-bind-source-design.md` — the source of truth for *what* and *why*. Read it before starting.
- **Security boundary:** `src/alfred/plugins/sandbox_policy.py` — **100% line + branch coverage** required (CLAUDE.md security rule; adversarial suite is release-blocking).
- **No completeness claims** in any docstring/comment (the #269 seven-variants lesson): name what the guard CANNOT do, in the guard.
- **Oracle independence:** any new property test's oracle must NOT reuse the validator's predicate or its allowlist. Mutation-test every new property (disable the guard → the property MUST fail).
- **Modern Python:** PEP 604/585/695, frozen models, `Final`, no `Any` without justification. `mypy --strict` + `pyright` clean.
- **i18n:** `bind_source_too_broad` is a machine audit-reason enum; it is NOT rendered to operators and needs NO catalog key. Never print it as a rendered operator stderr line.
- **Commits:** Conventional Commits with a literal `#428` after the colon in EVERY subject (e.g. `fix(sandbox): #428 …`). No `--no-verify`. Never `git add -A` (named paths only). End every commit message body with the `MrReasonable <4990954+MrReasonable@users.noreply.github.com>` trailer.
- **Quality gate before every push:** `make check` (lint + format + type + test); verify `$?`, don't trust `| tail`.

---

### Task 1: The over-broad-source predicate + validator in `sandbox_policy.py`

The core of the change. Adds the exported predicate, the validator, the audit-vocab comment, and repairs the two existing in-file tests the new rule breaks.

**Files:**
- Modify: `src/alfred/plugins/sandbox_policy.py` (imports ~37–45; add constants near `_ARCH_VARIABLE_PATHS` ~61; add validator after `_restrict_soft_binds` ~418; extend `__all__` ~484)
- Modify: `src/alfred/audit/audit_row_schemas.py:1186-1194` (reason-vocab comment)
- Test: `tests/unit/plugins/test_sandbox_policy_translator.py` (new tests; repair `test_a_genuine_near_miss_path_is_not_treated_as_arch_variable:250`; deepen property pools `_HARD_SRCS:404` and `_LEGAL_HARD_SRCS:427`)

**Interfaces:**
- Produces: `is_over_broad_bind_source(path: str) -> bool` (exported; the hard-field rule, tiers 1+2+3 — Task 2 and the launcher call this). `_resolves_to_host_root_or_pseudofs(path: str) -> bool` (module-internal; tiers 1+2). Validator `_refuse_over_broad_bind_source`. New reason string `"bind_source_too_broad"`.
- Consumes: existing `_canonical(path: str) -> str`, `SandboxPolicyInvalid(reason, detail)`.

- [ ] **Step 1: Write the failing unit tests**

Append to `tests/unit/plugins/test_sandbox_policy_translator.py`:

```python
import pytest

from alfred.plugins.sandbox_policy import (
    SandboxPolicy,
    SandboxPolicyInvalid,
    is_over_broad_bind_source,
)


@pytest.mark.parametrize(
    "src",
    [
        "/",              # tier 1: literal host root
        "/lib64/..",      # tier 1: traversal to root (soft field — see below)
        "/usr/..",        # tier 1: traversal to root
        "/etc",           # tier 3: non-allowlisted top-level root
        "/home",          # tier 3
        "/var",           # tier 3
        "/proc/self/root",  # tier 2: procfs magic-link (depth-4, defeats depth rule)
        "/proc/1/root",     # tier 2
        "/sys/kernel",      # tier 2
        "/proc",            # tier 2 (also tier 3)
    ],
)
def test_over_broad_hard_bind_source_is_refused(src: str) -> None:
    # /lib64/.. reaches the arch-variable guard first in a HARD field, so use a
    # soft field only for that one; the rest are refused in ro_binds.
    field = "ro_binds_try" if src == "/lib64/.." else "ro_binds"
    with pytest.raises(SandboxPolicyInvalid) as exc:
        if field == "ro_binds_try":
            SandboxPolicy(ro_binds_try=[(src, "/")], keep_fds=[3])
        else:
            SandboxPolicy(ro_binds=[(src, "/x")], keep_fds=[3])
    assert exc.value.reason == "bind_source_too_broad"


def test_over_broad_rw_bind_source_is_refused() -> None:
    with pytest.raises(SandboxPolicyInvalid) as exc:
        SandboxPolicy(rw_binds=[("/etc", "/etc")], keep_fds=[3])
    assert exc.value.reason == "bind_source_too_broad"


def test_soft_bind_resolving_to_root_is_refused() -> None:
    # sec-001: /lib64/.. is arch-variable (matches /lib64 on the raw walk) so
    # _restrict_soft_binds passes it, but it canonicalises to / — tier 1 refuses it.
    with pytest.raises(SandboxPolicyInvalid) as exc:
        SandboxPolicy(ro_binds_try=[("/lib64/..", "/")], keep_fds=[3])
    assert exc.value.reason == "bind_source_too_broad"


@pytest.mark.parametrize(
    "src",
    ["/usr", "/lib", "/etc/ssl/certs", "/home/alfred/.egress/discord", "/usr/lib"],
)
def test_legitimate_bind_source_is_accepted(src: str) -> None:
    policy = SandboxPolicy(ro_binds=[(src, src)], keep_fds=[3])
    assert (src, src) in policy.ro_binds


def test_lib64_soft_bind_still_accepted() -> None:
    # tier 3 (the depth-1 breadth floor) must NOT apply to ro_binds_try: /lib64 is
    # a legitimate depth-1 arch-variable soft bind (#269).
    policy = SandboxPolicy(ro_binds_try=[("/lib64", "/lib64")], keep_fds=[3])
    assert ("/lib64", "/lib64") in policy.ro_binds_try


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/", True),
        ("/etc", True),
        ("/proc/self/root", True),
        ("/sys/x", True),
        ("", True),           # relative/empty → refused (defensive; launcher relies on this)
        ("/usr", False),
        ("/lib", False),
        ("/etc/ssl/certs", False),
        ("/home/alfred/.egress/discord", False),
        ("/opt/lib64-compat", False),
    ],
)
def test_is_over_broad_bind_source_predicate(path: str, expected: bool) -> None:
    assert is_over_broad_bind_source(path) is expected


# Hand-verified respelling table (spec §Tests): each verdict written by hand, so
# it cannot share an algorithm bug with the validator.
_RESPELLING_VERDICTS = [
    ("/lib64/..", True),            # → /
    ("/usr/..", True),             # → /
    ("/lib/../..", True),          # → /
    ("/etc/", True),               # → /etc
    ("//etc", True),               # → /etc
    ("/etc/.", True),              # → /etc
    ("/usr/../etc", True),         # → /etc
    ("/etc/ssl/certs/../..", True),  # → /etc
    ("/usr/./lib", False),         # → /usr/lib (depth-3, fine)
    ("/etc/ssl/certs", False),
]


@pytest.mark.parametrize(("path", "over_broad"), _RESPELLING_VERDICTS)
def test_respelling_verdict_table(path: str, over_broad: bool) -> None:
    # /usr/../etc etc. are non-arch-variable, so they reach the new guard.
    if over_broad:
        with pytest.raises(SandboxPolicyInvalid) as exc:
            SandboxPolicy(ro_binds=[(path, "/x")], keep_fds=[3])
        assert exc.value.reason == "bind_source_too_broad"
    else:
        SandboxPolicy(ro_binds=[(path, "/x")], keep_fds=[3])
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest tests/unit/plugins/test_sandbox_policy_translator.py -k "over_broad or soft_bind_resolving or is_over_broad_bind_source or respelling_verdict or lib64_soft_bind or legitimate_bind_source" -q`
Expected: FAIL — `ImportError: cannot import name 'is_over_broad_bind_source'` (and, once importable, refusals not raised).

- [ ] **Step 3: Add the imports and constants**

In `src/alfred/plugins/sandbox_policy.py`, add to the import block (after line 42, `from collections.abc import Sequence`):

```python
from pathlib import PurePosixPath
```

Immediately after the `_ARCH_TRIPLET_RE` definition (~line 83), add:

```python
# The two top-level roots the shipped policies legitimately hard-bind. Kept in
# lockstep with the policies by test_permitted_roots_match_shipped_policies.
# ``/usr`` is broad (it leaves /usr/bin/* exec-reachable) and that residual is
# tracked in #430 — NOT closed here; this PR permits it so as not to pre-empt #430.
_PERMITTED_TOP_LEVEL_BIND_ROOTS: Final[frozenset[str]] = frozenset({"/usr", "/lib"})

# Pseudo-filesystems whose magic symlinks resolve to the host root (/proc/self/root,
# /proc/<pid>/root, /proc/<pid>/cwd). A depth-based breadth rule cannot catch these
# — they are deep paths that resolve to /. No policy ever legitimately binds a
# source under them. This is a deliberate, NAMED two-entry exception to the
# "allowlist not denylist" stance (see is_over_broad_bind_source).
_PSEUDO_FS_TOP_LEVEL: Final[frozenset[str]] = frozenset({"proc", "sys"})


def _resolves_to_host_root_or_pseudofs(path: str) -> bool:
    """Tiers 1+2: a source that canonicalises to ``/`` or lives under a
    root-resolving pseudo-filesystem. Over-broad in ANY bind field — a soft bind
    of such a source degrades the sandbox exactly as a hard one does.
    """
    canonical = _canonical(path)
    if canonical == "/":
        return True
    parts = PurePosixPath(canonical).parts
    return len(parts) >= 2 and parts[1] in _PSEUDO_FS_TOP_LEVEL


def is_over_broad_bind_source(path: str) -> bool:
    """Is ``path`` too broad to be a HARD bind source (tiers 1+2+3)?

    Exported: the launcher calls this (via ``manifest_reader --check-bind-source``)
    for the interpreter prefix, which is a hard ``--ro-bind``. The soft field
    ``ro_binds_try`` uses only tiers 1+2 (``_resolves_to_host_root_or_pseudofs``),
    because it legitimately carries the depth-1 arch-variable root ``/lib64``.

    **This guard CANNOT decide a filesystem fact, and does not try to (#269).** It
    cannot see that a depth-2 path like ``/home/alfred`` is still the operator's
    whole home (depth is a proxy for breadth, not breadth). It is lexical, so an
    on-disk symlink pointing at ``/`` defeats it — this module must never touch the
    filesystem. Tier 2 names only ``/proc``/``/sys``; a future root-resolving
    pseudo-fs is not caught. Assume variant N+1 exists.
    """
    if _resolves_to_host_root_or_pseudofs(path):
        return True
    canonical = _canonical(path)
    if canonical in _PERMITTED_TOP_LEVEL_BIND_ROOTS:
        return False
    return len(PurePosixPath(canonical).parts) <= 2
```

- [ ] **Step 4: Add the validator**

In `src/alfred/plugins/sandbox_policy.py`, add this `model_validator` **after** `_restrict_soft_binds` (the last validator, ~line 418) so `_require_absolute_paths` and `_refuse_hard_bind_of_arch_variable_path` both run first (Pydantic v2 runs `mode="after"` validators in definition order — a relative path gets `policy_path_not_absolute`, and a hard `/lib64/..` gets `arch_variable_path_hard_bound`, before this guard sees them):

```python
    @model_validator(mode="after")
    def _refuse_over_broad_bind_source(self) -> SandboxPolicy:
        """No bind SOURCE may expose the host root or a broad top-level tree (#428).

        Three tiers, applied by field kind:

        * tiers 1+2 (source resolves to ``/``, or lives under ``/proc``/``/sys``)
          apply to EVERY bind field including the soft ``ro_binds_try`` — a source
          that resolves to the host root is over-broad however it is bound.
        * tier 3 (a single-component top-level root not in
          ``_PERMITTED_TOP_LEVEL_BIND_ROOTS``) applies to the HARD fields only,
          because ``ro_binds_try`` legitimately carries the depth-1 arch-variable
          root ``/lib64`` that a breadth floor would wrongly refuse.

        Keys on the SOURCE, like ``_refuse_hard_bind_of_arch_variable_path``: bwrap
        cares about the source. This is a lexical floor, not a filesystem oracle —
        see ``is_over_broad_bind_source`` for what it cannot decide.
        """
        for field, binds in (("ro_binds", self.ro_binds), ("rw_binds", self.rw_binds)):
            for src, dst in binds:
                if is_over_broad_bind_source(src):
                    raise SandboxPolicyInvalid(
                        reason="bind_source_too_broad",
                        detail=(
                            f"{field} binds source {src!r} -> {dst!r}, which exposes the "
                            f"host root or a broad top-level tree into the T3 sandbox. Only "
                            f"{sorted(_PERMITTED_TOP_LEVEL_BIND_ROOTS)} are permitted as "
                            f"top-level bind roots; bind a specific subdirectory instead."
                        ),
                    )
        for src, dst in self.ro_binds_try:
            if _resolves_to_host_root_or_pseudofs(src):
                raise SandboxPolicyInvalid(
                    reason="bind_source_too_broad",
                    detail=(
                        f"ro_binds_try binds source {src!r} -> {dst!r}, which resolves to "
                        f"the host root or a pseudo-filesystem. A soft bind of such a source "
                        f"degrades the sandbox as badly as a hard one."
                    ),
                )
        return self
```

- [ ] **Step 5: Extend `__all__` and the audit-reason comment**

In `src/alfred/plugins/sandbox_policy.py`, add `"is_over_broad_bind_source",` to the `__all__` list (~line 484).

In `src/alfred/audit/audit_row_schemas.py`, extend the reason-vocab comment. Change line 1194 from:

```python
# arch_variable_path_hard_bound | policy_path_not_absolute
```

to:

```python
# arch_variable_path_hard_bound | policy_path_not_absolute |
# bind_source_too_broad
```

(This comment is documentation, not an enforced set — `SANDBOX_REFUSED_FIELDS` holds field *names*. No test guards it; a "reason strings are closed" test is out of scope for #428.)

- [ ] **Step 6: Repair the two existing tests the new rule breaks**

In `tests/unit/plugins/test_sandbox_policy_translator.py`:

(a) At line 250–254, deepen the near-miss source so it still proves the arch-variable over-correction guard without tripping the new depth-1 rule:

```python
def test_a_genuine_near_miss_path_is_not_treated_as_arch_variable() -> None:
    # Guard against over-correction: /opt/lib64-compat is a DIFFERENT path, not a
    # respelling of /lib64, and must remain hard-bindable. (Deepened from
    # /lib64-compat, a depth-1 root the #428 over-broad-source guard now refuses.)
    policy = SandboxPolicy(ro_binds=[("/opt/lib64-compat", "/opt/lib64-compat")], keep_fds=[3])
    assert "--ro-bind" in policy_to_bwrap_flags(policy)
```

(b) At line 404–428, deepen the two depth-1 accepted sources in the property pools so they stay accepted under the new rule (leave every other entry — the arch-variable refused ones — unchanged):

- In `_HARD_SRCS` (line 408–409): change `"/x",` → `"/x/y",` and `"/lib64-compat",  # near-miss: must stay ALLOWED` → `"/opt/lib64-compat",  # near-miss: must stay ALLOWED (deepened, #428)`.
- In `_LEGAL_HARD_SRCS` (line 427): change `["/usr", "/lib", "/etc/ssl/certs", "/x", "/lib64-compat"]` → `["/usr", "/lib", "/etc/ssl/certs", "/x/y", "/opt/lib64-compat"]`.

Leave `_DSTS`, `_DST_POOL`, `_TMPFS` unchanged — `/x` there is a *destination*/tmpfs target, which the source rule does not check.

- [ ] **Step 7: Run the full sandbox-policy test module**

Run: `uv run pytest tests/unit/plugins/test_sandbox_policy_translator.py -q`
Expected: PASS (new tests green; the repaired near-miss + property/anti-vacuity tests still green).

- [ ] **Step 8: Verify no other sandbox test regressed + coverage is total**

Run: `uv run pytest tests/unit/plugins/test_quarantined_llm_sandbox_policy.py tests/unit/plugins/test_discord_adapter_sandbox_policy.py -q`
Expected: PASS (shipped policies bind only `/usr`, `/lib`, `/etc/ssl/certs`, `/home/alfred/.egress/discord`, `/lib64` — all accepted).

Run: `uv run pytest tests/unit/plugins/test_sandbox_policy_translator.py --cov=alfred.plugins.sandbox_policy --cov-branch --cov-report=term-missing -q`
Expected: `sandbox_policy.py` at **100%** line + branch. If a branch is uncovered, add a targeted case (e.g. a `/sys`-under source, or the `ro_binds_try` tier-1 branch) before proceeding.

- [ ] **Step 9: Type-check and commit**

Run: `uv run mypy src/alfred/plugins/sandbox_policy.py && uv run pyright src/alfred/plugins/sandbox_policy.py`
Expected: clean.

```bash
git add src/alfred/plugins/sandbox_policy.py src/alfred/audit/audit_row_schemas.py tests/unit/plugins/test_sandbox_policy_translator.py
git commit -m "$(cat <<'EOF'
fix(sandbox): #428 refuse an over-broad bind source in SandboxPolicy

Adds a three-tier bind-source guard: a source canonicalising to / is refused
in every field incl. the soft ro_binds_try (kills ro_binds_try=[("/lib64/..",
"/")]); a source under /proc,/sys is refused everywhere (kills /proc/self/root,
depth-4, which defeats the depth rule); a non-allowlisted single-component
top-level root is refused in the hard fields only ({/usr,/lib} allowlisted,
since ro_binds_try legitimately carries depth-1 /lib64). Reason
bind_source_too_broad. Repairs the two in-file tests whose depth-1 accepted
sources (/x, /lib64-compat) the new rule now refuses.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

### Task 2: `manifest_reader --check-bind-source` CLI mode

Exposes Task 1's predicate to the launcher through the existing pre-launcher helper, so the rule has one implementation across both layers.

**Files:**

- Modify: `src/alfred/plugins/manifest_reader.py` (add mode flag + value arg in `_build_parser` ~288–296; add `_cmd_check_bind_source` ~after 279; add `main()` branch ~300–309)
- Test: `tests/unit/plugins/test_manifest_reader_cli.py` (append near the `--policy-to-bwrap-flags` block ~209+)

**Interfaces:**

- Consumes: `is_over_broad_bind_source` from Task 1.
- Produces: CLI contract — `python3 -m alfred.plugins.manifest_reader --check-bind-source --bind-source <path>` exits 0 when the path is an acceptable bind source, non-zero otherwise. Output is not consumed by callers (the launcher maps the exit code to its own reason).

- [ ] **Step 1: Write the failing CLI tests**

Append to `tests/unit/plugins/test_manifest_reader_cli.py` (the file already has a `_run(*args, stdin=...)` helper used by the `--policy-to-bwrap-flags` tests):

```python
# --------------------------------------------------------------------------
# --check-bind-source (#428)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/usr", "/lib", "/etc/ssl/certs", "/home/alfred/.egress/discord"])
def test_check_bind_source_accepts_legitimate_path(path: str) -> None:
    result = _run("--check-bind-source", "--bind-source", path)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("path", ["/", "/etc", "/home", "/proc/self/root", "/sys/x"])
def test_check_bind_source_refuses_over_broad_path(path: str) -> None:
    result = _run("--check-bind-source", "--bind-source", path)
    assert result.returncode != 0


def test_check_bind_source_refuses_empty() -> None:
    result = _run("--check-bind-source", "--bind-source", "")
    assert result.returncode != 0
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest tests/unit/plugins/test_manifest_reader_cli.py -k check_bind_source -q`
Expected: FAIL — argparse rejects the unknown `--check-bind-source` flag (non-zero for the accept cases too, but for the wrong reason).

- [ ] **Step 3: Add the mode + command**

In `src/alfred/plugins/manifest_reader.py`, add to the mutually-exclusive mode group in `_build_parser` (after line 290, `mode.add_argument("--policy-to-bwrap-flags", ...)`):

```python
    mode.add_argument("--check-bind-source", action="store_true")
```

and add a value argument (after line 296, `parser.add_argument("--install-root", ...)`):

```python
    # --check-bind-source value (#428): a candidate bind source path to test.
    parser.add_argument("--bind-source", default=None)
```

Add the command function (after `_cmd_policy_to_bwrap_flags`, ~line 279):

```python
def _cmd_check_bind_source(args: argparse.Namespace) -> int:
    """Exit 0 iff ``--bind-source`` is an acceptable (not over-broad) bind source.

    The launcher (bin/alfred-plugin-launcher.sh) calls this for the interpreter
    prefix and maps a non-zero exit to its own ``interpreter_prefix_too_broad``
    refusal. The bare reason is machine-only; no operator-facing rendering here.
    """
    path = args.bind_source if args.bind_source is not None else ""
    if is_over_broad_bind_source(path):
        return _fail("bind_source_too_broad")
    return 0
```

Add the import at the top of the module (with the existing `from alfred.plugins.sandbox_policy import (...)` block, ~line 66):

```python
    is_over_broad_bind_source,
```

Wire it into `main()` (in the mode dispatch, ~line 303–309, before the final `--policy-to-bwrap-flags` fallthrough):

```python
    if args.check_bind_source:
        return _cmd_check_bind_source(args)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/plugins/test_manifest_reader_cli.py -k check_bind_source -q`
Expected: PASS.

- [ ] **Step 5: Coverage + type-check + commit**

Run: `uv run pytest tests/unit/plugins/test_manifest_reader_cli.py --cov=alfred.plugins.manifest_reader --cov-branch --cov-report=term-missing -q`
Expected: the new `_cmd_check_bind_source` branches (over-broad → `_fail`; acceptable → 0; empty) are all covered.

Run: `uv run mypy src/alfred/plugins/manifest_reader.py && uv run pyright src/alfred/plugins/manifest_reader.py`
Expected: clean.

```bash
git add src/alfred/plugins/manifest_reader.py tests/unit/plugins/test_manifest_reader_cli.py
git commit -m "$(cat <<'EOF'
feat(sandbox): #428 add manifest_reader --check-bind-source mode

Exposes is_over_broad_bind_source to the launcher through the existing
pre-launcher helper, so the over-broad-bind rule has ONE implementation across
the schema and the launcher instead of a re-encoding in bash. Exit 0 iff the
path is an acceptable bind source; empty/relative/over-broad exit non-zero.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

### Task 3: Launcher wiring + audit-reason misattribution fix

Two edits to `bin/alfred-plugin-launcher.sh`: (a) the interpreter-prefix check calls the new CLI mode instead of a bash string compare; (b) the policy-translate failure path echoes the *actual* schema reason into the audit JSON instead of the hardcoded `policy_ref_unreadable`.

**Files:**

- Modify: `bin/alfred-plugin-launcher.sh` (audit JSON ~301–305; interp-prefix condition ~331–343)
- Test: `tests/unit/launcher/test_launcher_sandbox_flow.py` (existing `test_kind_full_refuses_root_level_interpreter_prefix:274` proves the wiring for `/`; add a case for a pre-existing schema reason's audit attribution)

**Interfaces:**

- Consumes: Task 2's `--check-bind-source` mode; Task 1's `bind_source_too_broad` reason.

- [ ] **Step 1: Confirm the existing wiring test still describes the target behaviour**

Run: `uv run pytest tests/unit/launcher/test_launcher_sandbox_flow.py::test_kind_full_refuses_root_level_interpreter_prefix -q`
Expected: PASS on `main` (it passes `executable="/"` → prefix `/` → refusal with `interpreter_prefix_too_broad`). This test is the wiring proof for the `/` case and MUST stay green after the edit — same input, same refusal, same reason; only the *condition* changes from a bash compare to a subprocess exit code.

- [ ] **Step 2: Write a failing test for the audit-reason attribution**

Add to `tests/unit/launcher/test_launcher_sandbox_flow.py`. This drives a policy whose schema refusal is a *pre-existing* reason (`soft_bind_forbidden_path`) and asserts the audit JSON now carries that reason rather than `policy_ref_unreadable`. Model it on the existing policy-ref tests in the file (use the `run_launcher` fixture + a `kind:full` manifest pointing at a policy file that soft-binds a non-arch-variable path):

```python
def test_policy_schema_refusal_audit_row_carries_the_real_reason(
    run_launcher, tmp_path, echo_bwrap
) -> None:
    """#428: the launcher must audit a policy-translate failure under the schema's
    OWN reason, not the hardcoded policy_ref_unreadable (which mislabels all five
    schema refusals today).
    """
    policy = tmp_path / "bad.linux.bwrap.policy"
    # /etc/ssl/certs is NOT arch-variable, so soft-binding it is soft_bind_forbidden_path.
    policy.write_text('ro_binds_try = [["/etc/ssl/certs", "/etc/ssl/certs"]]\nkeep_fds = [3]\n')
    manifest = _write_manifest(tmp_path, _full_manifest_with_policy_ref(policy.name))
    result = run_launcher(
        "alfred.example",
        "/usr/bin/python3",
        env={
            "ALFRED_ENVIRONMENT": "test",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
            "ALFRED_SANDBOX_POLICY_DIR": str(tmp_path),
            "BWRAP": str(echo_bwrap),
            "FAKE_UNAME": "Linux",
        },
    )
    assert result.returncode != 0
    assert '"reason":"soft_bind_forbidden_path"' in result.stderr
    assert '"reason":"policy_ref_unreadable"' not in result.stderr
```

> Note for the implementer: reuse the file's existing manifest/policy-ref helpers if their names differ from `_write_manifest` / `_full_manifest_with_policy_ref` — grep the top of `test_launcher_sandbox_flow.py` for the fixtures the other `policy_ref` tests use (e.g. `test_kind_full_policy_ref_missing_for_host_os:306`) and match them. The assertion (`"reason":"soft_bind_forbidden_path"` present, `policy_ref_unreadable` absent) is the load-bearing part.

- [ ] **Step 3: Run it to verify it fails**

Run: `uv run pytest tests/unit/launcher/test_launcher_sandbox_flow.py::test_policy_schema_refusal_audit_row_carries_the_real_reason -q`
Expected: FAIL — the audit row currently hardcodes `"reason":"policy_ref_unreadable"` (`bin/alfred-plugin-launcher.sh:303`).

- [ ] **Step 4: Fix the audit-reason misattribution**

In `bin/alfred-plugin-launcher.sh`, replace the policy-translate failure block (lines 301–305) with a version that maps the captured bare reason into the audit JSON. `BWRAP_FLAGS_RAW` captures stdout+stderr via `2>&1`, and a cold `alfred` import can emit a stderr warning *before* the bare reason line — so take the LAST line (mirrors the env-read `tail` at L162), strip any `supervisor.sandbox.refused.` prefix, and use it only if it is in the closed reason vocabulary:

```bash
                if ! BWRAP_FLAGS_RAW="$(python3 -m alfred.plugins.manifest_reader --policy-to-bwrap-flags --policy-ref "${POLICY_REF}" 2>&1)"; then
                    printf 'supervisor.sandbox.refused.policy_translate_failed plugin_id=%s detail=%s\n' "${PLUGIN_ID}" "${BWRAP_FLAGS_RAW}" >&2
                    # #428: the helper printed the SCHEMA reason (bare, or a
                    # supervisor.sandbox.refused.* key) as its last stderr line; a
                    # cold-import warning may precede it, so read the LAST line. Echo
                    # the real reason into the audit row instead of the historic
                    # hardcoded policy_ref_unreadable, which mislabelled every schema
                    # refusal. Closed vocab source of truth: audit_row_schemas.py:1188.
                    _CAPTURED_REASON="$(printf '%s\n' "${BWRAP_FLAGS_RAW}" | tail -n 1)"
                    _CAPTURED_REASON="${_CAPTURED_REASON#supervisor.sandbox.refused.}"
                    case "${_CAPTURED_REASON}" in
                        kind_full_requires_keep_fd_3|policy_path_not_absolute|arch_variable_path_hard_bound|mount_shadows_earlier_mount|soft_bind_forbidden_path|bind_source_too_broad|policy_translate_failed|policy_ref_escapes_root|policy_ref_unreadable)
                            _AUDIT_REASON="${_CAPTURED_REASON}" ;;
                        *)
                            _AUDIT_REASON="policy_ref_unreadable" ;;
                    esac
                    printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","policy_ref":"%s","reason":"%s","environment":"%s","host_os":"linux"}\n' "${PLUGIN_ID}" "${POLICY_REF}" "${_AUDIT_REASON}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
                    exit 1
                fi
```

- [ ] **Step 5: Rewire the interpreter-prefix check to the CLI mode**

In `bin/alfred-plugin-launcher.sh`, replace the bash string-compare condition (lines 339–343) so the refusal decision comes from `--check-bind-source`. Keep the two existing refusal `printf`s and their `interpreter_prefix_too_broad` reason verbatim (this is what keeps the existing test green and needs no new i18n key). The empty-prefix case no longer needs an explicit bash test — `is_over_broad_bind_source("")` returns True:

```bash
                    # #428: the over-broad-prefix decision lives in ONE place —
                    # is_over_broad_bind_source, reached via --check-bind-source — so
                    # the schema and the launcher cannot drift. Refuses "" (empty
                    # prefix), "/", any non-allowlisted top-level root, and pseudo-fs
                    # sources. Output is discarded; the exit code is the verdict.
                    if ! python3 -m alfred.plugins.manifest_reader --check-bind-source --bind-source "${_INTERP_PREFIX}" >/dev/null 2>&1; then
                        printf 'supervisor.sandbox.refused.interpreter_prefix_too_broad plugin_id=%s interpreter=%s\n' "${PLUGIN_ID}" "${_INTERP_REAL}" >&2
                        printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"interpreter_prefix_too_broad","environment":"%s","host_os":"%s"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" "${HOST_OS}" >&2
                        exit 1
                    fi
```

- [ ] **Step 6: Run the launcher suite**

Run: `uv run pytest tests/unit/launcher/test_launcher_sandbox_flow.py -q`
Expected: PASS — the new attribution test is green, `test_kind_full_refuses_root_level_interpreter_prefix` (the `/` wiring case) is still green, and the opt-in accept test (`test_kind_full_binds_interpreter_prefix_when_opted_in:197`) is still green.

- [ ] **Step 7: shellcheck + commit**

Run: `shellcheck bin/alfred-plugin-launcher.sh` (if available; otherwise the pre-commit hook runs it).
Expected: no new warnings.

```bash
git add bin/alfred-plugin-launcher.sh tests/unit/launcher/test_launcher_sandbox_flow.py
git commit -m "$(cat <<'EOF'
fix(sandbox): #428 launcher checks bind source via shared predicate + real audit reason

The interpreter-prefix over-broad check now calls
manifest_reader --check-bind-source, so it shares is_over_broad_bind_source
with the schema (a /home prefix is now refused, not just /). And the
policy-translate failure path echoes the real schema reason into the audit
JSON — tail -n 1 past any cold-import warning, strip the optional prefix,
closed-vocab match — instead of the historic hardcoded policy_ref_unreadable
that mislabelled all five schema refusals.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

### Task 4: Adversarial corpus payload `sbx-2026-016` + gate wiring

The refusal is a parse-time `SandboxPolicyInvalid`, not kernel-observable — so it needs the payload, an executable counterpart, a load-list entry, a README matrix row, and CI node registration (an unregistered node is collected-but-unprotected).

**Files:**

- Create: `tests/adversarial/sandbox_escape/sbx_2026_016_over_broad_bind_source_refused.yaml`
- Modify: `tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py` (new test fn; add `sbx-2026-016` to the `test_all_pr_s4_6_payloads_load` id-list ~353–361)
- Modify: `tests/adversarial/sandbox_escape/README.md` (coverage matrix ~51+)
- Modify: `.github/workflows/adversarial.yml` (required-node list ~124–131)

- [ ] **Step 1: Create the payload YAML**

Create `tests/adversarial/sandbox_escape/sbx_2026_016_over_broad_bind_source_refused.yaml`:

```yaml
id: sbx-2026-016
category: sandbox_escape
threat: >-
  An operator misconfigures a kind:full sandbox policy to bind an over-broad
  source — the host root (ro_binds=[("/","/")]), a top-level tree (/etc, /home),
  a traversal to root through the soft field (ro_binds_try=[("/lib64/..","/")]),
  or a procfs magic-link (/proc/self/root) — mounting the whole host filesystem
  into the sandbox that handles raw T3 content and defeating sbx-2026-003/004/006
  containment in one line.
ingestion_path: sandbox_policy_load
payload:
  attack: over_broad_bind_source_in_policy
  variants:
    - 'ro_binds = [["/", "/"]]'
    - 'ro_binds = [["/etc", "/etc"]]'
    - 'ro_binds_try = [["/lib64/..", "/"]]'
    - 'ro_binds = [["/proc/self/root", "/x"]]'
expected_outcome: refused
provenance: >-
  #428. read_policy_toml raises SandboxPolicyInvalid(reason=
  "bind_source_too_broad") at PARSE time via the _refuse_over_broad_bind_source
  validator — a Pydantic refusal, NOT kernel-observable (the containment is the
  schema refusing to emit the flags at all). Tiers: a source canonicalising to /
  is refused in every field incl. ro_binds_try; a source under /proc,/sys is
  refused everywhere; a non-allowlisted top-level root is refused in hard fields.
  Asserted by test_sbx_2026_016_over_broad_bind_source_refused.
references:
  - "spec §7.2 plugin sandbox policy"
  - "docs/superpowers/specs/2026-07-13-issue-428-over-broad-bind-source-design.md"
  - "src/alfred/plugins/sandbox_policy.py (_refuse_over_broad_bind_source)"
```

- [ ] **Step 2: Write the executable counterpart + register it in the load-list**

In `tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py`, add the test (near the other parse-refusal tests):

```python
def test_sbx_2026_016_over_broad_bind_source_refused() -> None:
    """sbx-2026-016: an over-broad bind source is refused at policy-parse time."""
    payload = _load("sbx-2026-016")
    assert payload.expected_outcome == "refused"
    for variant in (
        'ro_binds = [["/", "/"]]\nkeep_fds = [3]\n',
        'ro_binds = [["/etc", "/etc"]]\nkeep_fds = [3]\n',
        'ro_binds_try = [["/lib64/..", "/"]]\nkeep_fds = [3]\n',
        'ro_binds = [["/proc/self/root", "/x"]]\nkeep_fds = [3]\n',
    ):
        with pytest.raises(SandboxPolicyInvalid) as exc:
            read_policy_toml(variant)
        assert exc.value.reason == "bind_source_too_broad"
```

Add `sbx-2026-016` to the `test_all_pr_s4_6_payloads_load` id-list (the tuple around line 353–361, which currently ends at `"sbx-2026-010"`):

```python
        "sbx-2026-010",
        "sbx-2026-016",
```

(`read_policy_toml` and `SandboxPolicyInvalid` are already imported at the top of this file; `pytest` too.)

- [ ] **Step 3: Add the README coverage-matrix row**

In `tests/adversarial/sandbox_escape/README.md`, add a row to the coverage matrix (the table starting at line 51). After the existing rows, add:

```markdown
| Over-broad bind source (`/`, top-level root, `/lib64/..`, `/proc/self/root`) | #428 (`sbx-2026-016`) — `bind_source_too_broad` parse-time refusal (not kernel-observable) |
```

Also add a bullet under "Attack vectors covered" (line 10+):

```markdown
- Over-broad bind source: host root, non-allowlisted top-level tree, soft-field
  traversal to root, or procfs magic-link (`bind_source_too_broad`, #428).
```

- [ ] **Step 4: Register the node in the required-node CI gate**

In `.github/workflows/adversarial.yml`, add the new node to the `for node in \ … ; do` list (the block at ~124–131 that currently lists the fd3/child-escape/dormant-mechanism nodes). Add before the closing `; do`:

```bash
            test_sbx_2026_016_over_broad_bind_source_refused \
```

This is a pure parse-refusal unit test — it RUNS (never skips) on the non-privileged runner, so registering it here means a silent deletion of the payload or its test fails this required gate (the #245 paper-gate lesson).

- [ ] **Step 5: Run the adversarial corpus locally**

Run: `uv run pytest tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py -k "2026_016 or payloads_load" -q`
Expected: PASS (the new test + the load-list assertion covering `sbx-2026-016`).

Run: `uv run pytest tests/adversarial/test_corpus_density.py tests/adversarial/test_corpus_health.py -q`
Expected: PASS (density floor 10 already met; the new payload's schema fields validate).

- [ ] **Step 6: Verify the CI node-gate command matches locally**

Run: `uv run pytest tests/adversarial/sandbox_escape --collect-only -q | grep -c "::test_sbx_2026_016_over_broad_bind_source_refused"`
Expected: `1` (the exact node-id the workflow greps for exists).

- [ ] **Step 7: Commit**

```bash
git add tests/adversarial/sandbox_escape/sbx_2026_016_over_broad_bind_source_refused.yaml tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py tests/adversarial/sandbox_escape/README.md .github/workflows/adversarial.yml
git commit -m "$(cat <<'EOF'
test(sandbox): #428 adversarial payload sbx-2026-016 for over-broad bind source

Parse-time refusal payload (not kernel-observable): host root, top-level tree,
soft-field traversal to /, and procfs magic-link variants each assert
SandboxPolicyInvalid(reason="bind_source_too_broad"). Wired into the
payloads-load list, the README coverage matrix (drift is a release-blocker),
and the adversarial.yml required-node gate so a silent deletion fails CI.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

### Task 5: ADR-0037 amendment, subsystem-doc drift check, issue close-outs

Records the new structural invariant and disposes of the issue's secondary notes.

**Files:**

- Modify: `docs/adr/0037-production-quarantine-sandbox-boundary.md` (add an amendment section)
- Check/modify: `docs/subsystems/supervisor.md` (drift on the newly-surfaced audit reasons)

- [ ] **Step 1: Amend ADR-0037**

Append a dated amendment section to `docs/adr/0037-production-quarantine-sandbox-boundary.md` (do not rewrite existing content):

```markdown
## Amendment (2026-07-13, #428) — policy bind sources are governed by a closed allowlist

`SandboxPolicy` now refuses an over-broad bind **source** at parse time
(`reason="bind_source_too_broad"`), adding a structural invariant to the sandbox
boundary this ADR governs:

- A source canonicalising to `/` is refused in **every** bind field, including the
  soft `ro_binds_try`.
- A source under a root-resolving pseudo-filesystem (`/proc`, `/sys`) is refused in
  every field.
- A single-component top-level root not in the allowlist `{/usr, /lib}` is refused
  in the hard fields (`ro_binds`, `rw_binds`). `ro_binds_try` is exempt from this
  tier because it legitimately carries the depth-1 arch-variable root `/lib64`.

This is a lexical floor, not a filesystem oracle: it cannot see that a depth-2 path
is still broad, and an on-disk symlink to `/` defeats it (the module never touches
the filesystem). The `/usr` residual it permits — `/usr/bin/*` stays exec-reachable
— is tracked in #430, the live successor to the closed #230. The same change routes
the launcher's interpreter-prefix bind through the identical predicate
(`is_over_broad_bind_source`) and corrects a pre-existing audit-reason
misattribution (all five schema refusals were logged as `policy_ref_unreadable`).
```

- [ ] **Step 2: Check `supervisor.md` for drift**

Run: `grep -n "policy_ref_unreadable\|sandbox_refused\|reason" docs/subsystems/supervisor.md`
If any passage claims the sandbox-refusal audit row's `reason` is always `policy_ref_unreadable` for a policy-translate failure, correct it to note the reason is now the schema's own (`bind_source_too_broad`, `soft_bind_forbidden_path`, etc.). If no such passage exists, no edit — record that in the commit body.

- [ ] **Step 3: Markdown lint the docs**

Run: `npx markdownlint-cli2 "docs/adr/0037-production-quarantine-sandbox-boundary.md" "docs/subsystems/supervisor.md" "tests/adversarial/sandbox_escape/README.md"`
Expected: 0 errors (watch MD060 spaced table separators, MD032 list blanks, MD031 fence blanks).

- [ ] **Step 4: Commit**

```bash
git add docs/adr/0037-production-quarantine-sandbox-boundary.md docs/subsystems/supervisor.md
git commit -m "$(cat <<'EOF'
docs(sandbox): #428 ADR-0037 amendment for the bind-source allowlist invariant

Records the closed-allowlist invariant on policy bind sources, names its lexical
limits (depth is a proxy for breadth; a symlink defeats it), and points the /usr
residual at #430. Supervisor-doc drift check on the newly-surfaced audit reasons.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

- [ ] **Step 5: Post the secondary-note disposition on the issue**

The issue's `tmpfs = ["/lib64"]` note is closed with no code (already covered by `_refuse_a_mount_that_shadows_an_earlier_one` from #426; a tmpfs can only mask, never widen). Post this on #428 when opening the PR:

```bash
gh issue comment 428 --body "Secondary tmpfs note disposition: closed with no code. \`tmpfs = [\"/lib64\"]\` alongside a \`/lib64\` bind is already refused by \`_refuse_a_mount_that_shadows_an_earlier_one\` (#426); with no \`/lib64\` bind there is nothing to mask (bwrap starts from an empty root), and a tmpfs can only mask, never widen — so it is not a vector for the bind-source rule. The \`/usr\` residual is tracked in #430 (successor to the closed #230)."
```

---

### Final: quality gate, PR, review

- [ ] **Step 1: Full quality gate**

Run: `make check`
Expected: lint + format + type + unit all green. Check `$?` explicitly.

Run: `uv run pytest tests/adversarial -q`
Expected: PASS (release-blocking; required because this touches trust-boundary code).

- [ ] **Step 2: Push and open the PR**

```bash
git push -u origin fix/428-over-broad-bind-source
gh pr create --title "fix(sandbox): #428 refuse an over-broad bind source" --body "<summary + the spec link + the #430 follow-up + the tmpfs disposition>"
```

- [ ] **Step 3: Review per the standing cadence**

Run `/review-pr` (full fleet — security ALWAYS) **and** CodeRabbit CLI (`--base origin/main`); parse both cloud inline threads and CLI findings; resolve every thread; then `gh pr merge --rebase` (NEVER `--admin`). Run the `alfred-uat` pass before merge.

---

## Self-Review

**Spec coverage** — every spec section maps to a task:

- Three-tier rule (canonical-`/`, pseudo-fs, top-level allowlist) → Task 1 Steps 3–4.
- Soft-field tier-1/2 coverage (sec-001) → Task 1 Step 4 (second loop) + test Step 1 `test_soft_bind_resolving_to_root_is_refused`.
- Pseudo-fs (sec-002) → Task 1 (`_PSEUDO_FS_TOP_LEVEL`) + tests.
- "What the guard cannot do" in the docstring → Task 1 Step 3 (`is_over_broad_bind_source` docstring).
- Exported predicate + launcher via one predicate → Task 2 + Task 3 Step 5.
- Audit-reason fix owning all five reasons, `tail -n 1` → Task 3 Step 4.
- In-file broken tests (near-miss, property pools) → Task 1 Step 6.
- Independent oracle (refuse-net + example accepts + hand-verified table) → Task 1 Step 1 (`test_is_over_broad_bind_source_predicate` broad refuse pool + `_RESPELLING_VERDICTS` table + `test_legitimate_bind_source_is_accepted`).
- Mutation testing → covered by the refuse-pool/table breadth; the reviewer runs the disable-guard/`<=2`→`<2`/strip-`_canonical`/drop-pseudo-fs/drop-soft-tier mutants against these at PR time and records kills in the PR body (Final Step 3).
- Sync test (allowlist == shipped depth-1 hard sources, ≥2 files) → **see gap below**.
- i18n (no new key; machine enum) → no code; Global Constraints + Task 2 (bare `_fail`, discarded output).
- Adversarial plumbing → Task 4.
- #430 tracker + ADR-0037 → Task 5 (and #430 already filed).
- tmpfs disposition → Task 5 Step 5.

**Gap found + fixed:** the spec's **sync test** (`_PERMITTED_TOP_LEVEL_BIND_ROOTS` must equal the depth-1 hard-bind sources of the shipped policies, ≥2 files matched, `ro_binds`+`rw_binds` only) had no task step. Adding it to Task 1 as Step 6b below.

**Placeholder scan:** no TBD/TODO; every code step shows real code. The one soft reference ("reuse the file's existing manifest helpers", Task 3 Step 2) names the exact fallback (grep `test_kind_full_policy_ref_missing_for_host_os:306`) and the load-bearing assertion, because the helper names cannot be confirmed without the fixture block in front of the implementer.

**Type consistency:** `is_over_broad_bind_source` / `_resolves_to_host_root_or_pseudofs` / `_refuse_over_broad_bind_source` / `bind_source_too_broad` / `--check-bind-source --bind-source` used identically across Tasks 1–4.

### Task 1, Step 6b (added by self-review): the allowlist↔policies sync test

- [ ] Append to `tests/unit/plugins/test_sandbox_policy_translator.py`:

```python
from pathlib import Path

from alfred.plugins.sandbox_policy import _PERMITTED_TOP_LEVEL_BIND_ROOTS, read_policy_toml


def test_permitted_roots_match_shipped_policies() -> None:
    """The allowlist must equal EXACTLY the depth-1 hard-bind sources the shipped
    policies declare — read from ro_binds + rw_binds ONLY (never ro_binds_try, which
    legitimately carries the depth-1 arch-variable /lib64). Widening the allowlist
    without a shipped policy that needs it fails here (the #269 class-closing test).
    """
    policy_dir = Path(__file__).resolve().parents[3] / "config" / "sandbox"
    files = sorted(policy_dir.glob("*.linux.bwrap.policy"))  # non-recursive: skips _fixtures/, *.windows.stub.*
    assert len(files) >= 2, f"expected >=2 shipped Linux policies, found {[f.name for f in files]}"
    depth1_sources: set[str] = set()
    for f in files:
        policy = read_policy_toml(f.read_text())
        for src, _dst in (*policy.ro_binds, *policy.rw_binds):
            if len(PurePosixPath(_canonical(src)).parts) <= 2:
                depth1_sources.add(_canonical(src))
    assert depth1_sources == set(_PERMITTED_TOP_LEVEL_BIND_ROOTS), (
        f"shipped depth-1 hard-bind sources {sorted(depth1_sources)} != allowlist "
        f"{sorted(_PERMITTED_TOP_LEVEL_BIND_ROOTS)} — update the allowlist (and #430) in lockstep"
    )
```

(`_canonical` and `PurePosixPath` are module-internal but importable for the test; if lint objects to importing a private name, add a `# noqa` with a one-line justification, matching how the existing `_HARD_SRCS`-adjacent tests reach into the module.) Run it as part of Task 1 Step 7; it is included in the Step 9 commit.

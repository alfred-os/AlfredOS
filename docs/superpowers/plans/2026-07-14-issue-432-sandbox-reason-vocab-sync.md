# #432 — Sandbox Audit-Reason Vocabulary Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `bin/alfred-plugin-launcher.sh` unable to write a `supervisor.plugin.sandbox_refused` audit-JSON row carrying a `reason` outside the Python closed vocabulary — through *any* emit path, including the two `*)` case fallbacks — and make that vocabulary correct.

**Architecture:** Promote the prose `reason` closed-vocab comment in `audit_row_schemas.py` to a real `SANDBOX_REFUSED_REASONS: Final[frozenset[str]]` (20 launcher-emittable + 5 reserved-unemitted = 25). Add one unit test that **derives** each copy of the vocabulary (AST-walking the Python raise sites and `_fail` calls; parsing both arms of the launcher's two `case` statements; resolving every `sandbox_refused` printf line's `reason` field against an independent denominator) and binds them. No derivable fact is restated; the one irreducible human judgment (which reasons are intentionally reserved) is named small and pinned by an equality.

**Tech Stack:** Python 3.14, `ast` + `inspect` from the stdlib, pytest. No new dependencies. Pure file reads — no subprocess, no bwrap.

**Spec:** [`docs/superpowers/specs/2026-07-14-issue-432-sandbox-reason-vocab-sync-design.md`](../specs/2026-07-14-issue-432-sandbox-reason-vocab-sync-design.md)

**Issue:** [#432](https://github.com/MrReasonable/AlfredOS/issues/432). Follow-ups filed by the plan review: #433 (row never persisted), #434 (reason mislabelling round 2), #435 (four no-row paths), #436 (`sandbox_stub_used` undeclared reason), #437 (`POLICY_REF` injection).

**Plan review:** This plan was rewritten after `/review-plan` found a **Critical** in the first draft — the guard parsed only the first `case` arm and skipped the `%s` reason fields, so the two `*)` fallback assignments were launcher-emittable reasons no derivation saw. Every fold below is traceable to a review finding.

## Global Constraints

- Every commit subject carries a literal `#432` **after** the colon (the `Conventional commit format` required check; a `(432)` scope does **not** satisfy it).
- `make check` green before every `git push`. Check `$?` — piping to `tail` masks the exit code.
- No `--no-verify`. If a hook fails, fix the issue.
- The new test file is **not** covered by the `src`-scoped `mypy`/`pyright` gates. It must still be internally well-typed (ruff lints it), but no gate enforces types on it — do not rely on type-checking to catch a mistake in it.
- The test must NOT need `@pytest.mark.skipif(sys.platform == "win32")` — it does no subprocess work — and it must NOT be listed in `tests/_posix_only_tests.py`; it runs in the blocking Windows unit lane.
- No new operator-facing strings → no `t()` calls, no `pybabel` catalog churn.
- `SANDBOX_REFUSED_REASONS` must **not** end in `_FIELDS` and must **not** be added to `AUDIT_FIELDSET_ROSTER` — it is a reason-value set, not a field set. The `_walk_slice_4_constants()` sweep in `tests/unit/audit/test_slice_4_audit_row_fields.py` filters on the `_FIELDS` suffix and `test_refusal_rows_have_reason_discriminator` asserts every roster entry has a `"reason"` member; a `*_REASONS` name is invisible to both, which is correct.
- All temporary mutations in Task 4 use **Python heredocs**, not `sed -i` (BSD vs GNU `-i` differ; the user host is darwin/BSD, CI is Linux/GNU). Every probe asserts the mutation applied before running pytest and asserts the file is clean after reverting.

## Subsystem coverage matrix

| Subsystem | Files touched | Owner agent |
| --- | --- | --- |
| Audit row schemas | `src/alfred/audit/audit_row_schemas.py` | `alfred-security-engineer` |
| Sandbox launcher | `bin/alfred-plugin-launcher.sh` (comment only) | `alfred-devops-engineer` |
| Tests | `tests/unit/plugins/test_sandbox_reason_vocab_sync.py` (new) | `alfred-test-engineer` |

## The 25 reasons

**20 launcher-emittable** (each reaches a `sandbox_refused` row) + **5 reserved-unemitted**.

| Reason | Emitted by | New to the vocab? |
| --- | --- | --- |
| `environment_not_set` | launcher L169 `%s` ← env `case` (first arm + `*)` fallback) | |
| `environment_unrecognised` | launcher L169 `%s` ← env `case` first arm | **NEW** |
| `fake_uname_in_production` | launcher L207 literal | **NEW** |
| `unknown_host_os` | launcher L220 literal | **NEW** |
| `uid_separation_unavailable` | launcher L242 literal | **NEW** |
| `unsandboxed_env_set_in_production` | launcher L256 literal | |
| `sandbox_block_missing` | launcher L275 literal | |
| `stub_kind_in_production` | launcher L412 literal | **NEW** |
| `windows_stub_in_production` | launcher L392 literal | |
| `policy_ref_missing` | launcher L293 literal | |
| `interpreter_prefix_too_broad` | launcher L359 literal | **NEW** |
| `policy_ref_unreadable` | launcher L321 `%s` ← schema `case` ← `manifest_reader` `_fail` | |
| `policy_ref_escapes_root` | launcher L321 `%s` ← schema `case` ← `manifest_reader` `_fail` | |
| `kind_full_requires_keep_fd_3` | launcher L321 `%s` ← schema `case` ← `SandboxPolicyInvalid` | |
| `policy_path_not_absolute` | ″ | |
| `arch_variable_path_hard_bound` | ″ | |
| `mount_shadows_earlier_mount` | ″ | |
| `soft_bind_forbidden_path` | ″ | |
| `bind_source_too_broad` | ″ | |
| `policy_translate_failed` | launcher L321 `%s` ← schema `case` first arm **and** its `*)` fallback | **NEW** |
| `policy_ref_os_mismatch` | *reserved — no emitter* | |
| `bwrap_unavailable` | *reserved — no emitter* | |
| `bwrap_mode_userns_unavailable` | *reserved — no emitter* | |
| `provider_key_delivery_failed` | *reserved — `ProviderKeyDeliveryError` default; not a `sandbox_refused` row* | |
| `sandbox_info_handshake_mismatch` | *reserved — `session.py` handshake; not a `sandbox_refused` row* | |

The 5 reserved reasons are retained deliberately. The plan review corrected the first draft's "3 unemitted" to **5**: `provider_key_delivery_failed` and `sandbox_info_handshake_mismatch` are Python exception-reason defaults that never write a `sandbox_refused` row. Whether they are stale or reserved is out of scope; the binding only requires the frozenset to equal exactly `emittable ∪ reserved`.

## File structure

| File | Responsibility |
| --- | --- |
| `src/alfred/audit/audit_row_schemas.py` | **Modify.** Replace the prose vocab comment with `SANDBOX_REFUSED_REASONS` (25). The *why*-prose survives above it; add the #433 caveat and the reserved-5 label. |
| `bin/alfred-plugin-launcher.sh` | **Modify (comment only).** The pointer comment names the constant instead of a line number. No behaviour change. |
| `tests/unit/plugins/test_sandbox_reason_vocab_sync.py` | **Create.** Derives every copy and binds the whole frozenset. Sole owner of the binding. |

---

### Task 1: `SANDBOX_REFUSED_REASONS` — the canonical vocabulary

**Files:**

- Modify: `src/alfred/audit/audit_row_schemas.py:1187-1200` (replace the prose vocab comment)
- Modify: `bin/alfred-plugin-launcher.sh:308` (pointer comment)
- Create: `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`

**Interfaces:**

- Consumes: nothing.
- Produces: `alfred.audit.audit_row_schemas.SANDBOX_REFUSED_REASONS: Final[frozenset[str]]` — the 25 reasons above. Tasks 2-3 bind against it.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`:

```python
"""#432 — bind the launcher's audit-reason vocabulary to the Python closed vocab.

``bin/alfred-plugin-launcher.sh`` is the SOLE emitter of
``supervisor.plugin.sandbox_refused`` audit-JSON rows — no Python writes one (``src/alfred``
only registers the hookpoint; nothing parses the launcher's stderr into an ``append_schema``
call — see #433). The launcher decides each row's ``reason`` from a vocabulary it hand-copies
from Python in two ``case`` statements, and until #432 nothing bound the copies to their source:
a new ``SandboxPolicyInvalid(reason=...)`` added without touching bash silently fell back to the
generic ``policy_translate_failed`` — the exact failure #431 corrected (#427 / #422 drift class).

Every DERIVABLE fact below is derived, never restated (a hand-kept copy would just be one more
drifting copy; an oracle that restates the implementation passes through broken code — see
``domain_a_test_that_asks_the_code_if_the_code_is_right``). The one irreducible human judgment —
WHICH reasons are intentionally reserved with no emitter — cannot be derived from code, so it is
named in ``_RESERVED_UNEMITTED`` and pinned by an equality so it cannot drift silently.
"""

from __future__ import annotations

from alfred.audit import audit_row_schemas

# The five vocabulary reasons with no launcher emitter. Absence of an emitter is derivable; the
# INTENT to reserve (vs an accidental orphan) is not — so it is named here, small, and pinned by
# test_frozenset_is_exactly_emittable_plus_reserved.
_RESERVED_UNEMITTED = frozenset(
    {
        "policy_ref_os_mismatch",  # documented; no code path emits it
        "bwrap_unavailable",  # documented; no code path emits it
        "bwrap_mode_userns_unavailable",  # documented; no code path emits it
        "provider_key_delivery_failed",  # ProviderKeyDeliveryError default; not a sandbox_refused row
        "sandbox_info_handshake_mismatch",  # session.py handshake; not a sandbox_refused row
    }
)


def test_sandbox_refused_reasons_constant_shape() -> None:
    """The vocabulary is a real frozenset[str] of 25, and contains every reserved reason."""
    reasons = audit_row_schemas.SANDBOX_REFUSED_REASONS
    assert isinstance(reasons, frozenset)
    assert all(isinstance(r, str) and r for r in reasons)
    assert len(reasons) == 25, f"expected 25 reasons, got {len(reasons)}: {sorted(reasons)}"
    missing_reserved = _RESERVED_UNEMITTED - reasons
    assert not missing_reserved, f"reserved reasons dropped from the vocab: {sorted(missing_reserved)}"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -v`

Expected: FAIL with `AttributeError: module 'alfred.audit.audit_row_schemas' has no attribute 'SANDBOX_REFUSED_REASONS'`.

- [ ] **Step 3: Add the constant**

In `src/alfred/audit/audit_row_schemas.py`, replace lines 1187-1200 — the whole `reason` closed-vocab comment block, from the line starting `# ``reason`` closed-vocab:` up to and including the `— sec-3).` line — with the following, keeping `SANDBOX_REFUSED_FIELDS` immediately after it, unchanged:

```python
# The CLOSED ``reason`` vocabulary for ``supervisor.plugin.sandbox_refused``.
#
# ``bin/alfred-plugin-launcher.sh`` is the sole producer of this row and is bound to this set by
# ``tests/unit/plugins/test_sandbox_reason_vocab_sync.py`` (#432) — adding a reason to either
# side without the other fails the build. Before #432 this was a prose comment bound to nothing,
# and seven reasons the launcher could actually write were missing from it.
#
# NOTE (#433): this row is not yet persisted. The launcher ``printf``s it to stderr, which is
# drained into a ``child_stderr`` log field; no ``src/alfred`` code parses it into an
# ``append_schema`` write, and the registered ``fail_closed`` T0 hookpoint is never dispatched.
# This set governs what the launcher WRITES; wiring it to a real audit write is #433.
#
# Twenty reasons are launcher-emittable. Five are RESERVED with no emitter and are retained
# deliberately (the binding requires the set to equal emittable ∪ reserved):
#   * ``policy_ref_os_mismatch``, ``bwrap_unavailable``, ``bwrap_mode_userns_unavailable`` —
#     documented, no code path emits them;
#   * ``provider_key_delivery_failed`` — the fd-3 partial-write / EAGAIN refusal from
#     ``alfred.supervisor.fd3_key_delivery`` (sec-3); defined there as a sandbox-refusal reason
#     but NOT emitted by the launcher, and (per #433) not yet written by any code;
#   * ``sandbox_info_handshake_mismatch`` — ``plugins/session.py`` handshake; likewise a defined
#     sandbox-refusal reason the launcher never emits (unwired — #433).
# ``policy_ref_escapes_root`` covers the path-traversal case the sandbox_escape adversarial
# README documents and is distinct from ``policy_ref_unreadable``; ``policy_translate_failed`` is
# both a real malformed-TOML reason AND the launcher's honest fallback for an unclassifiable
# helper stderr line (the alarm/real conflation is tracked in #434).
SANDBOX_REFUSED_REASONS: Final[frozenset[str]] = frozenset(
    {
        # Pre-flight: environment + host-OS resolution (launcher).
        "environment_not_set",
        "environment_unrecognised",
        "fake_uname_in_production",
        "unknown_host_os",
        "uid_separation_unavailable",
        # Sandbox block / kind gating (launcher).
        "sandbox_block_missing",
        "unsandboxed_env_set_in_production",
        "stub_kind_in_production",
        "windows_stub_in_production",
        # policy_ref resolution (launcher + manifest_reader).
        "policy_ref_missing",
        "policy_ref_unreadable",
        "policy_ref_escapes_root",
        # Policy schema refusals (sandbox_policy.SandboxPolicyInvalid).
        "kind_full_requires_keep_fd_3",
        "policy_path_not_absolute",
        "arch_variable_path_hard_bound",
        "mount_shadows_earlier_mount",
        "soft_bind_forbidden_path",
        "bind_source_too_broad",
        "policy_translate_failed",
        # Post-translation: bind widening (launcher).
        "interpreter_prefix_too_broad",
        # Reserved — no launcher emitter (see comment above).
        "policy_ref_os_mismatch",
        "bwrap_unavailable",
        "bwrap_mode_userns_unavailable",
        "provider_key_delivery_failed",
        "sandbox_info_handshake_mismatch",
    }
)
```

- [ ] **Step 4: Fix the launcher's pointer comment**

In `bin/alfred-plugin-launcher.sh`, the comment on line 308 currently ends:

```sh
                    # refusal. Closed vocab source of truth: audit_row_schemas.py:1188.
```

A line number is itself a drift vector — it is already off-by-one against the comment it names. Replace that one line with:

```sh
                    # refusal. Closed vocab: audit_row_schemas.SANDBOX_REFUSED_REASONS;
                    # both case lists + every emit path are bound to it by
                    # test_sandbox_reason_vocab_sync.py (#432).
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -v`

Expected: PASS (1 passed).

- [ ] **Step 6: Commit**

```bash
git add src/alfred/audit/audit_row_schemas.py bin/alfred-plugin-launcher.sh tests/unit/plugins/test_sandbox_reason_vocab_sync.py
git commit -m "feat(audit): #432 promote the sandbox reason vocab to a frozenset

The reason closed-vocab was a prose comment bound to nothing, and seven reasons the launcher
can write into a sandbox_refused row were missing from it. Promote it to SANDBOX_REFUSED_REASONS
(20 launcher-emittable + 5 reserved), document that the row is not yet persisted (#433)."
```

---

### Task 2: Derive the Python side (AST) and bind both `case` first arms

**Files:**

- Modify: `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`

**Interfaces:**

- Consumes: `SANDBOX_REFUSED_REASONS` (Task 1).
- Produces (module-private, used by Task 3): `_module_string_constants`, `_sandbox_policy_invalid_reasons`, `_fail_args_in`, `_flags_path_reasons`, `_read_environment_keys`, `_parse_case`.

- [ ] **Step 1: Add the AST + case-parsing helpers and the two equality tests**

Extend the import block at the top of the file to:

```python
from __future__ import annotations

import ast
import inspect
import re
import types
from pathlib import Path

from alfred.audit import audit_row_schemas
from alfred.plugins import manifest_reader, sandbox_policy

_LAUNCHER = Path(__file__).resolve().parents[3] / "bin" / "alfred-plugin-launcher.sh"
_SANDBOX_REFUSED_EVENT = "supervisor.plugin.sandbox_refused"
_REASON_KEY_PREFIX = "supervisor.sandbox.refused."
_ENV_KEY_PREFIX = "daemon.boot."
# `_fail(exc.reason)` re-emits whatever SandboxPolicyInvalid carried, so seeing it means every
# SandboxPolicyInvalid reason is reachable from that command.
_PASSTHROUGH = "exc.reason"
```

Then append:

```python
def _launcher_text() -> str:
    return _LAUNCHER.read_text(encoding="utf-8")


def _module_ast(module: types.ModuleType) -> ast.Module:
    return ast.parse(Path(inspect.getfile(module)).read_text(encoding="utf-8"))


def _module_string_constants(tree: ast.Module) -> dict[str, str]:
    """Module-level ``NAME = "literal"`` and ``NAME: Final[str] = "literal"`` bindings.

    Handles ``ast.AnnAssign`` so a ``Final[str]`` annotation (the repo's own convention) does
    not make the walk silently miss a constant (#432 review ops-002).
    """
    constants: dict[str, str] = {}
    for node in tree.body:
        target: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        elif isinstance(node, ast.AnnAssign):
            target = node.target
        if (
            isinstance(target, ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            constants[target.id] = node.value.value
    return constants


def _sandbox_policy_invalid_reasons() -> frozenset[str]:
    """Every reason literal raised as ``SandboxPolicyInvalid(reason=...)`` in sandbox_policy.py.

    Fails LOUD on a non-literal ``reason=``: an AST walk cannot see through a variable, so a
    non-literal would make this set silently UNDER-count and every binding below pass VACUOUSLY.
    Naming what the guard cannot do, in the guard, is the #269 / #431 lesson.
    """
    reasons: set[str] = set()
    non_literal: list[int] = []
    for node in ast.walk(_module_ast(sandbox_policy)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        called = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if called != "SandboxPolicyInvalid":
            continue
        keyword = next((kw for kw in node.keywords if kw.arg == "reason"), None)
        if (
            keyword is not None
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        ):
            reasons.add(keyword.value.value)
        else:
            non_literal.append(node.lineno)
    assert not non_literal, (
        f"SandboxPolicyInvalid(...) with a non-literal `reason` at sandbox_policy.py "
        f"line(s) {non_literal}. This AST guard cannot see the value, so the launcher bindings "
        f"would pass VACUOUSLY. Pass a string literal."
    )
    return frozenset(reasons)


def _fail_args_in(function_name: str) -> tuple[frozenset[str], bool]:
    """Resolve every ``_fail(...)`` argument inside ``function_name`` in manifest_reader.

    Returns (resolved i18n keys, saw the ``exc.reason`` passthrough). Resolves module-level
    string constants. Fails LOUD on an argument it cannot resolve — same vacuity reasoning.

    Known residual (named, not silently accepted): the walk is lexically scoped to the function
    body, so a ``_fail`` MOVED into a callee would under-count (#432 review err-004). Closing
    that would fight the per-command grouping this binding needs; it is left to a future guard.
    """
    tree = _module_ast(manifest_reader)
    constants = _module_string_constants(tree)
    function = next(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == function_name
        ),
        None,
    )
    assert function is not None, f"{function_name}() not found in manifest_reader.py"

    keys: set[str] = set()
    passthrough = False
    unresolved: list[str] = []
    for node in ast.walk(function):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_fail"
            and node.args
        ):
            continue
        arg = node.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            keys.add(arg.value)
        elif isinstance(arg, ast.Name) and arg.id in constants:
            keys.add(constants[arg.id])
        elif ast.unparse(arg) == _PASSTHROUGH:
            passthrough = True
        else:
            unresolved.append(ast.unparse(arg))
    assert not unresolved, (
        f"_fail() in {function_name}() called with unresolvable argument(s) {unresolved}. "
        f"This walk cannot resolve them, so the binding would UNDER-count. Use a string literal, "
        f"a module-level constant, or the `{_PASSTHROUGH}` passthrough."
    )
    return frozenset(keys), passthrough


def _flags_path_reasons() -> frozenset[str]:
    """Every reason ``manifest_reader --policy-to-bwrap-flags`` can print as its last stderr
    line — i.e. exactly the universe the launcher's schema ``case`` classifies."""
    keys, passthrough = _fail_args_in("_cmd_policy_to_bwrap_flags")
    assert passthrough, (
        "_cmd_policy_to_bwrap_flags() no longer re-emits `exc.reason`; the schema-refusal "
        "reasons may no longer reach the launcher. Re-derive this binding."
    )
    direct = {key.removeprefix(_REASON_KEY_PREFIX) for key in keys}
    return frozenset(direct | _sandbox_policy_invalid_reasons())


def _read_environment_keys() -> frozenset[str]:
    """The full ``daemon.boot.*`` i18n keys ``manifest_reader --read-environment`` can print."""
    keys, passthrough = _fail_args_in("_cmd_read_environment")
    assert not passthrough, "_cmd_read_environment() unexpectedly re-emits exc.reason"
    return keys


def _parse_case(subject: str) -> tuple[frozenset[str], str | None]:
    """Parse the launcher ``case "<subject>" in`` — return (first-arm alternatives, ``*)`` literal).

    Anchored on the case SUBJECT, never a line number (the shipped pointer comment already
    drifted off-by-one, the class of bug this file prevents). The ``*)`` arm's assigned string
    literal (the FALLBACK) is what the first-draft guard omitted — its value is a launcher-
    emittable reason.
    """
    text = _launcher_text()
    header = f'case "{subject}" in'
    idx = text.find(header)
    assert idx != -1, f"bash case header not found in the launcher: {header!r}"
    body = text[idx + len(header) :]
    esac = body.find("esac")
    assert esac != -1, f"no matching esac for case {subject!r}"
    body = body[:esac]

    first_arm: frozenset[str] | None = None
    fallback: str | None = None
    stray_arms: list[str] = []
    for arm in (a.strip() for a in body.split(";;") if a.strip()):
        pattern, _, arm_body = arm.partition(")")
        pattern = pattern.strip()
        if pattern == "*":
            # Anchor on an assignment (VAR="literal"), never a bare quoted string, so a stray
            # quoted word in a comment inside the `*)` arm cannot be mistaken for the fallback
            # (#432 re-review err-new-3 / sec-new-1). A `*)` arm with no assignment yields None,
            # which test_case_fallback_literals asserts against.
            matches = re.findall(r'[A-Za-z_]\w*="([^"]*)"', arm_body)
            fallback = matches[-1] if matches else None
        elif first_arm is None:
            first_arm = frozenset(alt.strip() for alt in pattern.split("|") if alt.strip())
        else:
            # A second allow-list arm is caught downstream by the equality tests, but with a
            # confusing "missing/dead entry" message; name it here (#432 PR-review CodeRabbit).
            stray_arms.append(pattern)
    assert not stray_arms, (
        f"case {subject!r} has arm(s) beyond the allow-list and `*)` fallback: {stray_arms}. "
        f"This parser understands exactly two arms; extend it."
    )
    assert first_arm, f"no allow-list arm parsed under case {subject!r}"
    return first_arm, fallback


def test_schema_case_classifies_exactly_the_flags_path_reasons() -> None:
    """The schema `case` allow-list == exactly the reasons the flags helper can emit (#432 ask).

    Equality (not superset) so it bites BOTH ways: a new SandboxPolicyInvalid reason missing from
    bash (which would silently fall back to the generic policy_translate_failed), AND a dead bash
    entry the helper can never print.
    """
    first_arm, _ = _parse_case("${_CAPTURED_REASON}")
    expected = _flags_path_reasons()
    assert len(expected) >= 9, f"vacuity floor: derived only {len(expected)} flags-path reasons"
    assert first_arm == expected, (
        "the launcher's schema `case` allow-list has drifted from the reasons "
        "`manifest_reader --policy-to-bwrap-flags` can emit.\n"
        f"  missing from the bash case (would fall back to the generic reason): "
        f"{sorted(expected - first_arm)}\n"
        f"  dead entries in the bash case (unreachable): {sorted(first_arm - expected)}"
    )


def test_environment_case_classifies_exactly_the_read_environment_keys() -> None:
    """The environment `case` allow-list == exactly the keys the --read-environment helper emits.

    A key missing here silently degrades to the fail-closed environment_not_set default — a real
    refusal reported as the wrong one. Same drift class as the schema case, second copy.
    """
    first_arm, _ = _parse_case("${_env_err_key}")
    expected = _read_environment_keys()
    assert len(expected) == 2, f"vacuity floor: derived {len(expected)} environment keys, want 2"
    assert first_arm == expected, (
        "the launcher's environment `case` allow-list has drifted from the keys "
        "`manifest_reader --read-environment` can emit.\n"
        f"  missing from the bash case (would degrade to environment_not_set): "
        f"{sorted(expected - first_arm)}\n"
        f"  dead entries in the bash case (unreachable): {sorted(first_arm - expected)}"
    )
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -v`

Expected: PASS, **3 passed**. Note (honest): these two bindings hold today, so writing them cannot be made to fail by writing them — a lexical binding that already holds has no genuine red-before-green. The failing-first evidence for them is the mutation suite in Task 4 (probes 2 and 3), which is the correct place to prove a drift-guard bites. Faking a red by temporarily breaking the launcher would prove the same thing less honestly.

- [ ] **Step 3: Verify the derivations resolve what we expect**

Run:

```bash
uv run python -c "
import tests.unit.plugins.test_sandbox_reason_vocab_sync as m
print('SandboxPolicyInvalid reasons:', sorted(m._sandbox_policy_invalid_reasons()))
print('flags-path:', sorted(m._flags_path_reasons()))
print('env keys:', sorted(m._read_environment_keys()))
print('schema case:', sorted(m._parse_case('\${_CAPTURED_REASON}')[0]), 'fallback=', m._parse_case('\${_CAPTURED_REASON}')[1])
print('env case:', sorted(m._parse_case('\${_env_err_key}')[0]), 'fallback=', m._parse_case('\${_env_err_key}')[1])
"
```

Expected: 7 `SandboxPolicyInvalid` reasons; flags-path and schema-case both the same 9; env keys and env-case both the 2 `daemon.boot.*`; schema `fallback= policy_translate_failed`; env `fallback= daemon.boot.environment_not_set`.

- [ ] **Step 4: Commit**

```bash
git add tests/unit/plugins/test_sandbox_reason_vocab_sync.py
git commit -m "test(sandbox): #432 bind both case allow-lists to the Python reason sets

AST-derive every SandboxPolicyInvalid(reason=...) literal and every _fail() key, and assert each
launcher case allow-list equals its Python source exactly. Fails loud on a non-literal reason or
an unresolvable _fail arg (which the walk cannot see and which would pass vacuously)."
```

---

### Task 3: Resolve every emit line and bind the whole frozenset

**Files:**

- Modify: `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`

**Interfaces:**

- Consumes: everything from Tasks 1-2.
- Produces: `_launcher_emittable_reasons` (used only by these tests).

- [ ] **Step 1: Add the emit-line resolver and the closing assertions**

This is the load-bearing new primitive the review demanded: it walks **every** `sandbox_refused` printf line (an independent denominator) and resolves each `reason` field — literal or `%s` — including the `*)` fallbacks, failing loud on any line it cannot account for.

Append to `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`:

```python
def _launcher_emittable_reasons() -> frozenset[str]:
    """Every reason any path through the launcher can write into a sandbox_refused row.

    Walks every line carrying the sandbox_refused event (the independent denominator) and
    resolves its `reason` field:
      * a literal -> {that literal};
      * `%s` fed by ${_AUDIT_REASON}      -> schema case first arm ∪ its `*)` fallback;
      * `%s` fed by ${_env_err_key#...}   -> env case first arm ∪ its `*)` fallback (prefix-stripped).
    A `%s` fed by an unrecognised variable, or a line with no `reason` field, FAILS LOUD — so a
    future 12th emit site (or a printf folded into a `%s` helper under #422 pressure) cannot be
    silently skipped while a `>= N` floor still passes (#432 review ops-001 / err-003).
    """
    schema_first, schema_fallback = _parse_case("${_CAPTURED_REASON}")
    env_first, env_fallback = _parse_case("${_env_err_key}")

    schema_set = set(schema_first)
    if schema_fallback is not None:
        schema_set.add(schema_fallback)
    env_set = {key.removeprefix(_ENV_KEY_PREFIX) for key in env_first}
    if env_fallback is not None:
        env_set.add(env_fallback.removeprefix(_ENV_KEY_PREFIX))

    # Independent denominator: every `printf` line that mentions the event, matched on the event
    # NAME rather than the exact JSON byte-string `"event":"..."`. Keying the count on the compact
    # byte-string would let a FUTURE emit line that reformats the JSON (a space after a colon, a
    # reordered field) slip the count entirely while `>= 11` still passed — the silent-under-count
    # class this guard prevents (#432 PR-review err-438-01 / CodeRabbit). Every counted line must
    # then resolve, or fail loud.
    emit_lines = [
        line
        for line in _launcher_text().splitlines()
        if "printf" in line and _SANDBOX_REFUSED_EVENT in line
    ]

    emittable: set[str] = set()
    unresolved: list[str] = []
    for line in emit_lines:
        match = re.search(r'"reason":\s*"([^"]*)"', line)
        if match is None:
            unresolved.append(f"no reason field: {line.strip()[:90]}")
            continue
        reason = match.group(1)
        if reason != "%s":
            emittable.add(reason)
        elif "_AUDIT_REASON" in line:
            emittable |= schema_set
        elif "_env_err_key" in line:
            emittable |= env_set
        else:
            unresolved.append(f"unrecognised %s reason source: {line.strip()[:90]}")
    assert not unresolved, (
        "sandbox_refused printf line(s) whose reason could not be resolved — a new emit site or "
        "a renamed feed variable. Extend the resolver; do NOT let it silently under-count:\n"
        + "\n".join(unresolved)
    )
    assert len(emit_lines) >= 11, (
        f"vacuity floor: only {len(emit_lines)} sandbox_refused emit lines found (expected >= 11)"
    )
    return frozenset(emittable)


def test_every_reason_the_launcher_can_emit_is_in_the_closed_vocab() -> None:
    """NO path through the launcher can write a `reason` outside the vocabulary."""
    emittable = _launcher_emittable_reasons()
    unknown = emittable - audit_row_schemas.SANDBOX_REFUSED_REASONS
    assert not unknown, (
        f"the launcher can write {sorted(unknown)} into a {_SANDBOX_REFUSED_EVENT} audit row, "
        f"but they are absent from SANDBOX_REFUSED_REASONS (a CLOSED vocabulary). Add them."
    )


def test_frozenset_is_exactly_emittable_plus_reserved() -> None:
    """Bind the WHOLE frozenset: it must equal exactly (launcher-emittable ∪ reserved).

    Catches an ORPHAN (in the set, emitted by nothing, not reserved — a typo) that the subset
    test above cannot, AND a reserved reason accidentally dropped (#432 review arch-001 / rev-001).
    """
    emittable = _launcher_emittable_reasons()
    assert not (emittable & _RESERVED_UNEMITTED), (
        f"reserved reasons are actually launcher-emittable: {sorted(emittable & _RESERVED_UNEMITTED)} "
        f"— move them out of _RESERVED_UNEMITTED."
    )
    expected = emittable | _RESERVED_UNEMITTED
    actual = audit_row_schemas.SANDBOX_REFUSED_REASONS
    assert actual == expected, (
        "SANDBOX_REFUSED_REASONS is not exactly (launcher-emittable ∪ reserved).\n"
        f"  orphan (in the frozenset, neither emittable nor reserved): {sorted(actual - expected)}\n"
        f"  missing (emittable or reserved, not in the frozenset): {sorted(expected - actual)}"
    )


def test_case_fallback_literals_are_in_the_closed_vocab() -> None:
    """The `*)` fallback of each case writes a reason directly — it must be in the vocab.

    The direct, named guard for the exact Critical the review found: change a `*)` value to
    something out-of-vocab and this fails by name (belt-and-suspenders with the ⊆ test).
    """
    _, schema_fallback = _parse_case("${_CAPTURED_REASON}")
    _, env_fallback = _parse_case("${_env_err_key}")
    assert schema_fallback is not None, "schema case `*)` arm has no assigned literal"
    assert env_fallback is not None, "environment case `*)` arm has no assigned literal"
    fallbacks = {schema_fallback, env_fallback.removeprefix(_ENV_KEY_PREFIX)}
    unknown = fallbacks - audit_row_schemas.SANDBOX_REFUSED_REASONS
    assert not unknown, (
        f"a case `*)` fallback writes {sorted(unknown)} into a sandbox_refused row, absent from "
        f"SANDBOX_REFUSED_REASONS."
    )


def test_derived_vocabularies_are_not_vacuous() -> None:
    """`set() == set()` / `set() <= X` are the canonical vacuous greens — floor every derived set.

    A parse that silently returns nothing reports green while gating nothing
    (``domain_paper_only_gates``). Each floor carries a message.
    """
    assert len(_sandbox_policy_invalid_reasons()) >= 7, "SandboxPolicyInvalid literal floor"
    assert len(_flags_path_reasons()) >= 9, "flags-path floor"
    assert len(_read_environment_keys()) == 2, "env-key floor"
    assert len(_launcher_emittable_reasons()) >= 20, "launcher-emittable floor"
    assert len(_RESERVED_UNEMITTED) == 5, "reserved floor"
    assert len(audit_row_schemas.SANDBOX_REFUSED_REASONS) >= 25, "vocab floor"
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -v`

Expected: PASS, **7 passed** (2 from Task 1's shape test + Task 2's two, plus these four... count: shape(1) + schema(1) + env(1) + every-reason(1) + frozenset-exactly(1) + fallback-literals(1) + not-vacuous(1) = 7).

- [ ] **Step 3: Commit**

```bash
git add tests/unit/plugins/test_sandbox_reason_vocab_sync.py
git commit -m "test(sandbox): #432 resolve every emit line and bind the whole frozenset

Walk every sandbox_refused printf line against an independent denominator, resolving each reason
field including both case *) fallbacks, and fail loud on any unaccounted line. Assert no emit
path writes outside the vocab, the *) fallbacks are in-vocab, and the frozenset equals exactly
(launcher-emittable ∪ reserved) so an orphan or dropped reserved reason fails."
```

---

### Task 4: Mutation-verify every assertion, then run the gates

A binding that cannot fail is worse than none — it reports green while gating nothing. This codebase has shipped a tautological oracle twice, and this plan's *first draft* shipped a guard with the bug it fixes. So every assertion is proved to bite before the PR opens, and — per the review — **each probe asserts the mutation actually applied** (a Python heredoc that silently no-ops would fake the verification), and records **every** assertion that fails, not a predicted single one.

**Files:** no production changes. Temporary mutations, each reverted with `git checkout --`.

**Interfaces:** consumes everything from Tasks 1-3; produces the PR mutation-evidence block.

For every probe: apply via Python heredoc → `grep` to assert it applied → `uv run pytest ... -q` → record the failing tests → `git checkout --` → `grep` to assert it reverted.

- [ ] **Step 1: Probe 1 — the Critical fix (schema `*)` fallback out of vocab)**

```bash
python3 - <<'PY'
from pathlib import Path
p = Path("bin/alfred-plugin-launcher.sh"); s = p.read_text()
new = s.replace('_AUDIT_REASON="policy_translate_failed" ;;', '_AUDIT_REASON="mutation_probe_unlisted" ;;', 1)
assert new != s, "MUTATION DID NOT APPLY — search string not found"
p.write_text(new)
PY
grep -q 'mutation_probe_unlisted' bin/alfred-plugin-launcher.sh || { echo "MUTATION MISSING"; exit 1; }
uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -q
git checkout -- bin/alfred-plugin-launcher.sh
grep -q 'mutation_probe_unlisted' bin/alfred-plugin-launcher.sh && { echo "REVERT FAILED"; exit 1; } || echo "reverted clean"
```

Expected FAILs: `test_every_reason_the_launcher_can_emit_is_in_the_closed_vocab` (mutation_probe_unlisted ∉ vocab), `test_frozenset_is_exactly_emittable_plus_reserved` (orphan in emittable), `test_case_fallback_literals_are_in_the_closed_vocab` (named). `test_schema_case_classifies...` stays green (first arm unchanged). **This is the proof the `*)` arm is now covered** — the exact hole the review found.

- [ ] **Step 2: Probe 2 — schema allow-list drift (the #432 core)**

```bash
python3 - <<'PY'
from pathlib import Path
p = Path("bin/alfred-plugin-launcher.sh"); s = p.read_text()
new = s.replace('|policy_ref_escapes_root|policy_ref_unreadable)', '|policy_ref_escapes_root)', 1)
assert new != s, "MUTATION DID NOT APPLY"
p.write_text(new)
PY
grep -q '|policy_ref_escapes_root|policy_ref_unreadable)' bin/alfred-plugin-launcher.sh && { echo "MUTATION MISSING"; exit 1; } || true
uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -q
git checkout -- bin/alfred-plugin-launcher.sh
```

Expected FAILs: `test_schema_case_classifies...` (`missing from the bash case: policy_ref_unreadable`), `test_frozenset_is_exactly_emittable_plus_reserved` (emittable drops it), `test_derived_vocabularies_are_not_vacuous` (launcher-emittable 19 < 20). Removing an allow-list entry ripples into the emittable set by design — record all three.

- [ ] **Step 3: Probe 3 — environment allow-list drift**

```bash
python3 - <<'PY'
from pathlib import Path
p = Path("bin/alfred-plugin-launcher.sh"); s = p.read_text()
new = s.replace('daemon.boot.environment_unrecognised | daemon.boot.environment_not_set)',
                'daemon.boot.environment_not_set)', 1)
assert new != s, "MUTATION DID NOT APPLY"
p.write_text(new)
PY
grep -q 'daemon.boot.environment_unrecognised | daemon.boot.environment_not_set)' bin/alfred-plugin-launcher.sh && { echo "MUTATION MISSING"; exit 1; } || true
uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -q
git checkout -- bin/alfred-plugin-launcher.sh
```

Expected FAILs: `test_environment_case_classifies...` (`missing: environment_unrecognised`), `test_frozenset_is_exactly_emittable_plus_reserved`, `test_derived_vocabularies_are_not_vacuous` (emittable 19 < 20).

- [ ] **Step 4: Probe 4 — drop a reason from the frozenset**

```bash
python3 - <<'PY'
from pathlib import Path
p = Path("src/alfred/audit/audit_row_schemas.py"); s = p.read_text()
new = s.replace('        "policy_translate_failed",\n', '', 1)
assert new != s, "MUTATION DID NOT APPLY"
p.write_text(new)
PY
grep -q '"policy_translate_failed",' src/alfred/audit/audit_row_schemas.py && { echo "MUTATION MISSING"; exit 1; } || true
uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -q
git checkout -- src/alfred/audit/audit_row_schemas.py
```

Expected FAILs — **five** tests (`policy_translate_failed` is also the schema `*)` fallback literal, so `test_case_fallback_literals` fails too; the re-review caught the first draft under-listing this): `test_sandbox_refused_reasons_constant_shape` (24 != 25), `test_every_reason_the_launcher_can_emit...` (policy_translate_failed emittable but ∉ vocab), `test_frozenset_is_exactly_emittable_plus_reserved` (missing), `test_case_fallback_literals_are_in_the_closed_vocab` (the schema `*)` fallback is now out-of-vocab), `test_derived_vocabularies_are_not_vacuous` (vocab 24 < 25). This is the exact defect that shipped in main before #432.

- [ ] **Step 5: Probe 5 — orphan in the frozenset (only the equality catches it)**

```bash
python3 - <<'PY'
from pathlib import Path
p = Path("src/alfred/audit/audit_row_schemas.py"); s = p.read_text()
new = s.replace('        "policy_translate_failed",\n',
                '        "policy_translate_failed",\n        "bogus_orphan_reason",\n', 1)
assert new != s, "MUTATION DID NOT APPLY"
p.write_text(new)
PY
grep -q 'bogus_orphan_reason' src/alfred/audit/audit_row_schemas.py || { echo "MUTATION MISSING"; exit 1; }
uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -q
git checkout -- src/alfred/audit/audit_row_schemas.py
```

Expected FAILs: `test_sandbox_refused_reasons_constant_shape` (26 != 25) and `test_frozenset_is_exactly_emittable_plus_reserved` (`orphan: bogus_orphan_reason`). Crucially `test_every_reason...` (⊆) stays green — proving the union-equality catches an orphan that a subset check cannot (the architect's arch-001 point).

- [ ] **Step 6: Probe 6 — the non-literal reason guard fires**

```bash
python3 - <<'PY'
from pathlib import Path
p = Path("src/alfred/plugins/sandbox_policy.py"); s = p.read_text()
old = '            raise SandboxPolicyInvalid(\n                reason="kind_full_requires_keep_fd_3",'
new = '            _r = "kind_full_requires_keep_fd_3"\n            raise SandboxPolicyInvalid(\n                reason=_r,'
s2 = s.replace(old, new, 1)
assert s2 != s, "MUTATION DID NOT APPLY"
p.write_text(s2)
PY
grep -q 'reason=_r,' src/alfred/plugins/sandbox_policy.py || { echo "MUTATION MISSING"; exit 1; }
uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -q
git checkout -- src/alfred/plugins/sandbox_policy.py
```

Expected: every test that calls `_sandbox_policy_invalid_reasons()` (via `_flags_path_reasons`) ERRORs with the loud `AssertionError: SandboxPolicyInvalid(...) with a non-literal 'reason' at sandbox_policy.py line(s) [...]` — **not** a silent pass. A guard that skipped the unresolvable site would still report 6 reasons and go green while enforcing nothing.

- [ ] **Step 7: Probe 7 — the independent denominator refuses a silent skip**

```bash
python3 - <<'PY'
from pathlib import Path
p = Path("bin/alfred-plugin-launcher.sh"); s = p.read_text()
new = s.replace('"reason":"fake_uname_in_production"', '"reason":"%s"', 1)
assert new != s, "MUTATION DID NOT APPLY"
p.write_text(new)
PY
grep -q '"reason":"%s"' bin/alfred-plugin-launcher.sh || { echo "MUTATION MISSING"; exit 1; }
uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -q
git checkout -- bin/alfred-plugin-launcher.sh
```

Expected: `_launcher_emittable_reasons()` raises the loud `unrecognised %s reason source` assertion (the L207 line now has a `%s` reason fed by no known variable), ERRORing every test that calls it. Under the *old* pinned-floor design this new-shaped emit line would have been silently skipped with the floor still passing — this proves ops-001 is closed.

- [ ] **Step 8: Confirm the tree is clean after all probes**

```bash
git status --porcelain
```

Expected: **empty**. If anything is listed, a `git checkout --` was missed — revert before continuing. (Never run a write-implementer subagent concurrently with these mutations; its `git checkout`/`stash` would revert them tree-wide.)

- [ ] **Step 9: Run the full quality gates**

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy src/ && uv run pyright src/
uv run pytest tests/unit -q
uv run pytest tests/adversarial -q
make check; echo "make check exit: $?"
```

Expected: all green; `make check` exit `0` (check `$?` — a `| tail` masks it). The adversarial suite runs because this changes the sandbox-refusal audit vocabulary — the blast radius the `sbx-2026-*` payloads assert against — even though `src/alfred/security/` itself is untouched.

- [ ] **Step 10: Confirm the platform assumptions hold**

```bash
grep -n "subprocess\|skipif\|os.fork\|bwrap" tests/unit/plugins/test_sandbox_reason_vocab_sync.py || echo "clean: no subprocess/skip markers"
grep -rn "test_sandbox_reason_vocab_sync" tests/_posix_only_tests.py || echo "clean: not in posix-only list"
```

Expected: both `clean: …`. The file is pure `read_text` + `ast`, so it runs on the Windows unit lane.

- [ ] **Step 11: Assemble the PR mutation-evidence block**

No code change. Record, for each of the seven probes: what was mutated, the assert-applied check, and the exact set of tests that failed (from the `-q` output). A reviewer must see that every assertion was shown to bite without re-running the probes. Note that most probes trip more than one assertion (corroboration) — list all of them per probe, matching the "Expected FAILs" above against the real output; if the real set differs, the guard's coupling changed and this evidence must be updated to match.

---

## Definition of done

- [ ] `SANDBOX_REFUSED_REASONS` exists in `audit_row_schemas.py` with all 25 reasons; the *why*-prose survives above it, including the #433 not-yet-persisted caveat and the reserved-5 label; it is **not** in `AUDIT_FIELDSET_ROSTER`.
- [ ] The launcher's pointer comment names the constant, not a line number. No launcher behaviour change.
- [ ] `tests/unit/plugins/test_sandbox_reason_vocab_sync.py` passes (7 tests), derives every copy, parses **both** case arms including `*)`, resolves every emit line against an independent denominator, and restates only the named `_RESERVED_UNEMITTED`.
- [ ] All seven mutation probes were run; each asserted the mutation applied and reverted; each produced its documented failure set; `git status --porcelain` is empty afterwards.
- [ ] `make check` exits 0; the adversarial suite is green.
- [ ] The test carries no `skipif(win32)` and is absent from `tests/_posix_only_tests.py`.
- [ ] PR opened with the mutation-evidence block; full `/review-pr` fleet (security lane included) plus CodeRabbit, both run; the five follow-ups (#433-#437) linked.

## Self-review

**Spec coverage.** Every spec section maps to a task: the production change → Task 1; the AST derivations + both case-arm parses → Task 2; the emit-line resolver, the independent denominator, the ⊆ / exact-union / fallback-literal / vacuity assertions → Task 3; the mutation proofs (each assertion, the non-literal guard, the denominator) → Task 4. The spec's out-of-scope items (#433-#437, `_sandbox_i18n.py`, the reserved 5, #430/#427) appear in no implementation task, which is correct.

**Placeholder scan.** No TBD/TODO. Every code step carries literal code; every command carries expected output.

**Type consistency.** `_module_string_constants(ast.Module) -> dict[str, str]`, `_sandbox_policy_invalid_reasons() -> frozenset[str]`, `_fail_args_in(str) -> tuple[frozenset[str], bool]`, `_flags_path_reasons() -> frozenset[str]`, `_read_environment_keys() -> frozenset[str]`, `_parse_case(str) -> tuple[frozenset[str], str | None]`, `_launcher_emittable_reasons() -> frozenset[str]`. Each defined once and used with those signatures downstream. `_parse_case` and `_fail_args_in` are the tuple-returning ones; every call site unpacks them correctly (`first_arm, fallback` / `keys, passthrough`), and Task 2/3 tests that only need the first arm discard the fallback with `first_arm, _ = _parse_case(...)`.

**Review findings folded (traceability).** Critical (`*)` fallback unparsed) → Task 3 resolver + Task 4 probe 1. ops-001/err-003 pinned floors → the independent denominator + probe 7. test/rev-003 mutation-probe errors → Task 4's assert-applied + record-all-failures discipline, corrected expected sets. arch-001/rev-001 orphan + 5-not-3 → the exact-union assertion + probe 5 + the reserved-5 constant. ops-002 `Final[str]` → `_module_string_constants` handles `ast.AnnAssign`. err-004 `_fail`-in-callee → named as a residual in the `_fail_args_in` docstring. #433 (row never persisted) → the constant's comment + DoD. mypy/pyright-not-on-tests → Global Constraints. The spec/plan contradiction on Python emitters is resolved: the plan's reason table marks `provider_key_delivery_failed` / `sandbox_info_handshake_mismatch` as reserved, matching the spec.

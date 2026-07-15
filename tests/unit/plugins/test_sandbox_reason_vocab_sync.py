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

# The five vocabulary reasons with no launcher emitter. Absence of an emitter is derivable; the
# INTENT to reserve (vs an accidental orphan) is not — so it is named here, small, and pinned by
# test_frozenset_is_exactly_emittable_plus_reserved.
_RESERVED_UNEMITTED = frozenset(
    {
        "policy_ref_os_mismatch",  # documented; no code path emits it
        "bwrap_unavailable",  # documented; no code path emits it
        "bwrap_mode_userns_unavailable",  # documented; no code path emits it
        "provider_key_delivery_failed",  # ProviderKeyDeliveryError default; not a refused row
        "sandbox_info_handshake_mismatch",  # session.py handshake; not a sandbox_refused row
    }
)


def test_sandbox_refused_reasons_constant_shape() -> None:
    """The vocabulary is a real frozenset[str] of 26, and contains every reserved reason."""
    reasons = audit_row_schemas.SANDBOX_REFUSED_REASONS
    assert isinstance(reasons, frozenset)
    assert all(isinstance(r, str) and r for r in reasons)
    assert len(reasons) == 26, f"expected 26 reasons, got {len(reasons)}: {sorted(reasons)}"
    missing_reserved = _RESERVED_UNEMITTED - reasons
    assert not missing_reserved, (
        f"reserved reasons dropped from the vocab: {sorted(missing_reserved)}"
    )


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
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        if (
            isinstance(target, ast.Name)
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
        ):
            constants[target.id] = value.value
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
            # A second allow-list arm would be caught downstream by the equality tests, but with
            # a confusing "missing/dead entry" message; name it here so the failure points at the
            # real cause — this two-arm parser needs extending (#432 review CodeRabbit).
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


def _launcher_emittable_reasons() -> frozenset[str]:
    """Every reason any path through the launcher can write into a sandbox_refused row.

    Walks every line carrying the sandbox_refused event (the independent denominator) and
    resolves its `reason` field:
      * a literal -> {that literal};
      * `%s` fed by ${_AUDIT_REASON}    -> union of the schema case first arm and its `*)` arm;
      * `%s` fed by ${_env_err_key#...} -> union of the env case first arm and its `*)` arm
        (prefix-stripped).
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

    # Independent denominator: every ``printf`` line that mentions the event, matched on the
    # event NAME rather than the exact JSON byte-string ``"event":"..."``. Keying the count on
    # the compact byte-string would let a FUTURE emit line that reformats the surrounding JSON
    # (a space after a colon, a reordered field) slip the count entirely while ``>= 11`` still
    # passed — the very silent-under-count class this guard exists to prevent (#432 review
    # err-438-01 / CodeRabbit). Every counted line must then resolve to a reason, or fail loud.
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
    """Bind the WHOLE frozenset: it must equal exactly the union of launcher-emittable and reserved.

    Catches an ORPHAN (in the set, emitted by nothing, not reserved — a typo) that the subset
    test above cannot, AND a reserved reason accidentally dropped (#432 review arch-001 / rev-001).
    """
    emittable = _launcher_emittable_reasons()
    overlap = emittable & _RESERVED_UNEMITTED
    assert not overlap, (
        f"reserved reasons are actually launcher-emittable: {sorted(overlap)} "
        f"— move them out of _RESERVED_UNEMITTED."
    )
    expected = emittable | _RESERVED_UNEMITTED
    actual = audit_row_schemas.SANDBOX_REFUSED_REASONS
    orphan = actual - expected
    missing = expected - actual
    assert actual == expected, (
        "SANDBOX_REFUSED_REASONS is not exactly the union of launcher-emittable and reserved.\n"
        f"  orphan (in the frozenset, neither emittable nor reserved): {sorted(orphan)}\n"
        f"  missing (emittable or reserved, not in the frozenset): {sorted(missing)}"
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

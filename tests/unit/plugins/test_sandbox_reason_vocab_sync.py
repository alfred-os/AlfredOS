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
import json
import re
import types
from pathlib import Path

import pytest

from alfred.audit import audit_row_schemas
from alfred.plugins import manifest_reader, sandbox_policy

_LAUNCHER = Path(__file__).resolve().parents[3] / "bin" / "alfred-plugin-launcher.sh"
_SANDBOX_REFUSED_EVENT = "supervisor.plugin.sandbox_refused"
_REASON_KEY_PREFIX = "supervisor.sandbox.refused."
_ENV_KEY_PREFIX = "daemon.boot."
# `_fail(exc.reason)` re-emits whatever SandboxPolicyInvalid carried, so seeing it means every
# SandboxPolicyInvalid reason is reachable from that command.
_PASSTHROUGH = "exc.reason"

# The four vocabulary reasons with no launcher emitter. Absence of an emitter is derivable; the
# INTENT to reserve (vs an accidental orphan) is not — so it is named here, small, and pinned by
# test_frozenset_is_exactly_emittable_plus_reserved.
_RESERVED_UNEMITTED = frozenset(
    {
        "policy_ref_os_mismatch",  # documented; no code path emits it
        "bwrap_mode_userns_unavailable",  # documented; no code path emits it
        "provider_key_delivery_failed",  # ProviderKeyDeliveryError default; not a refused row
        "sandbox_info_handshake_mismatch",  # session.py handshake; not a sandbox_refused row
    }
)


def test_sandbox_refused_reasons_constant_shape() -> None:
    """The vocabulary is a real frozenset[str] of 35, and contains every reserved reason."""
    reasons = audit_row_schemas.SANDBOX_REFUSED_REASONS
    assert isinstance(reasons, frozenset)
    assert all(isinstance(r, str) and r for r in reasons)
    assert len(reasons) == 35, f"expected 35 reasons, got {len(reasons)}: {sorted(reasons)}"
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


def _extract_case_body(subject: str) -> str:
    """The body of the launcher's ``case "<subject>" in`` block, between the header and its
    matching ``esac``.

    Shared by ``_parse_case`` (allow-list + ``*)``) and ``_parse_mapping_case`` (N arms, each
    assigning a distinct literal). Anchored on the case SUBJECT, never a line number — the
    shipped pointer comment already drifted off-by-one, which is the class of bug this file
    prevents.
    """
    text = _launcher_text()
    header = f'case "{subject}" in'
    idx = text.find(header)
    assert idx != -1, f"bash case header not found in the launcher: {header!r}"
    body = text[idx + len(header) :]
    esac = body.find("esac")
    assert esac != -1, f"no matching esac for case {subject!r}"
    return body[:esac]


def _parse_case(subject: str) -> tuple[frozenset[str], str | None]:
    """Parse the launcher ``case "<subject>" in`` — return (first-arm alternatives, ``*)`` literal).

    Anchored on the case SUBJECT, never a line number (the shipped pointer comment already
    drifted off-by-one, the class of bug this file prevents). The ``*)`` arm's assigned string
    literal (the FALLBACK) is what the first-draft guard omitted — its value is a launcher-
    emittable reason.
    """
    body = _extract_case_body(subject)

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


def _parse_mapping_case(subject: str, var: str) -> dict[str, str]:
    """Parse a launcher ``case "<subject>" in`` whose arms each assign ``var="literal"``.

    ``_parse_case`` above understands exactly two arms (an allow-list + ``*)``) and hard-fails
    on a third. #434A's key->reason map is structurally different: N arms, each assigning a
    DISTINCT literal. Returns {arm-pattern: assigned literal}, with the ``*)`` arm keyed ``"*"``.

    Fails LOUD on an arm that does not assign ``var`` — an unassigned arm means the map has a
    hole the launcher would fall through, and a silently-skipped arm makes the binding
    UNDER-count (the #432 vacuity lesson).

    Also fails LOUD on a DUPLICATE arm pattern (#452 review CodeRabbit-major): a naive
    ``mapping[pattern] = value`` keeps the LAST assignment, but bash's ``case`` matches the
    FIRST matching arm. A dict build that silently overwrites would validate a mapping the
    shell never actually executes — a hole in this drift-guard's own trust. An actual duplicate
    in the launcher is itself a bug, so this refuses to silently pick either value; the launcher
    must be fixed, not the parser.
    """
    body = _extract_case_body(subject)

    mapping: dict[str, str] = {}
    unassigned: list[str] = []
    duplicates: list[str] = []
    for arm in (a.strip() for a in body.split(";;") if a.strip()):
        pattern, _, arm_body = arm.partition(")")
        pattern = pattern.strip()
        if not pattern:
            continue
        match = re.search(rf'{re.escape(var)}="([^"]*)"', arm_body)
        if match is None:
            unassigned.append(pattern)
        elif pattern in mapping:
            duplicates.append(pattern)
        else:
            mapping[pattern] = match.group(1)
    assert not unassigned, (
        f"case {subject!r} has arm(s) that never assign {var}: {unassigned}. "
        f"Each arm must assign a literal or the binding under-counts."
    )
    assert not duplicates, (
        f"case {subject!r} has duplicate arm pattern(s) {duplicates}. bash's case matches the "
        f"FIRST arm; a dict build that silently keeps the LAST would validate a mapping the "
        f"shell never executes. Fix the launcher's case (remove or merge the duplicate)."
    )
    assert mapping, f"no arms parsed under case {subject!r}"
    return mapping


def test_parse_mapping_case_fails_loud_on_a_duplicate_arm_pattern(monkeypatch) -> None:
    """Direct unit test of the parser's own contract (#452 review CodeRabbit-major).

    The real launcher has no duplicate arm today, so this exercises a synthetic case body via
    a monkeypatched ``_launcher_text`` rather than waiting for a real drift to prove the guard
    works. Before the fix, ``mapping["a"] = "two"`` would win silently (bash would actually run
    the FIRST arm, "one") and this parser would never notice.
    """
    fake_case = 'case "${_x}" in\n    a) _V="one" ;;\n    a) _V="two" ;;\nesac\n'
    monkeypatch.setattr(
        "tests.unit.plugins.test_sandbox_reason_vocab_sync._launcher_text",
        lambda: fake_case,
    )
    with pytest.raises(AssertionError, match="duplicate arm pattern"):
        _parse_mapping_case("${_x}", "_V")


def _read_sandbox_keys() -> frozenset[str]:
    """The full ``plugin.*`` i18n keys ``manifest_reader --read-sandbox`` can print."""
    keys, passthrough = _fail_args_in("_cmd_read_sandbox")
    assert not passthrough, "_cmd_read_sandbox() unexpectedly re-emits exc.reason"
    return keys


def test_sandbox_case_maps_exactly_the_read_sandbox_keys() -> None:
    """The #434A key->reason map covers exactly the keys --read-sandbox can emit.

    Equality, not superset, so it bites BOTH ways: a new manifest_reader refusal key missing
    from bash (which would degrade to reason_unclassified — a real refusal reported as an
    alarm), AND a dead bash arm the helper can never print.
    """
    mapping = _parse_mapping_case("${_sandbox_err_key}", "_SANDBOX_REASON")
    arms = frozenset(mapping) - {"*"}
    expected = _read_sandbox_keys()
    assert len(expected) == 5, f"vacuity floor: derived {len(expected)} read-sandbox keys, want 5"
    assert arms == expected, (
        "the launcher's #434A sandbox `case` has drifted from the keys "
        "`manifest_reader --read-sandbox` can emit.\n"
        f"  missing from the bash case (would degrade to reason_unclassified): "
        f"{sorted(expected - arms)}\n"
        f"  dead entries in the bash case (unreachable): {sorted(arms - expected)}"
    )


def test_sandbox_case_maps_only_into_the_closed_vocab() -> None:
    """Every reason the #434A map can assign is a vocabulary member."""
    mapping = _parse_mapping_case("${_sandbox_err_key}", "_SANDBOX_REASON")
    unknown = frozenset(mapping.values()) - audit_row_schemas.SANDBOX_REFUSED_REASONS
    assert not unknown, (
        f"the #434A sandbox case maps to {sorted(unknown)}, absent from SANDBOX_REFUSED_REASONS."
    )


def test_sandbox_case_distinguishes_the_tamper_signals() -> None:
    """The named defect: manifest_unreadable / manifest_invalid are TAMPER signals and must NOT
    collapse into the benign sandbox_block_missing (#434A). Mutation-resistant: asserts the
    three map to three DISTINCT reasons, so re-pointing any one at another fails."""
    mapping = _parse_mapping_case("${_sandbox_err_key}", "_SANDBOX_REASON")
    tamper = {
        mapping["plugin.manifest_unreadable"],
        mapping["plugin.manifest_invalid"],
        mapping["plugin.manifest_sandbox_block_missing"],
    }
    assert len(tamper) == 3, (
        f"the tamper signals collapsed into {sorted(tamper)} — #434A's exact defect."
    )


def test_schema_case_classifies_exactly_the_flags_path_reasons() -> None:
    """The schema `case` allow-list == exactly the reasons the flags helper can emit (#432 ask).

    Equality (not superset) so it bites BOTH ways: a new SandboxPolicyInvalid reason missing from
    bash (which would degrade to reason_unclassified), AND a dead bash entry the helper can never
    print.
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
        (prefix-stripped);
      * `%s` fed by ${_SANDBOX_REASON}  -> the #434A mapping-case's resolved values (its `*)` arm
        assigns the same variable, so its fallback is already folded into the mapping — no
        separate union needed here).
    A `%s` fed by an unrecognised variable, or a line with no `reason` field, FAILS LOUD — so a
    future 19th emit site (or a printf folded into a `%s` helper under #422 pressure) cannot be
    silently skipped while a `>= N` floor still passes (#432 review ops-001 / err-003).
    """
    schema_first, schema_fallback = _parse_case("${_CAPTURED_REASON}")
    env_first, env_fallback = _parse_case("${_env_err_key}")
    sandbox_map = _parse_mapping_case("${_sandbox_err_key}", "_SANDBOX_REASON")
    sandbox_set = set(sandbox_map.values())

    schema_set = set(schema_first)
    if schema_fallback is not None:
        schema_set.add(schema_fallback)
    env_set = {key.removeprefix(_ENV_KEY_PREFIX) for key in env_first}
    if env_fallback is not None:
        env_set.add(env_fallback.removeprefix(_ENV_KEY_PREFIX))

    # Independent denominator: every ``printf`` line that mentions the event, matched on the
    # event NAME rather than the exact JSON byte-string ``"event":"..."``. Keying the count on
    # the compact byte-string would let a FUTURE emit line that reformats the surrounding JSON
    # (a space after a colon, a reordered field) slip the count entirely while ``>= 18`` still
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
        elif "_SANDBOX_REASON" in line:
            emittable |= sandbox_set
        else:
            unresolved.append(f"unrecognised %s reason source: {line.strip()[:90]}")
    assert not unresolved, (
        "sandbox_refused printf line(s) whose reason could not be resolved — a new emit site or "
        "a renamed feed variable. Extend the resolver; do NOT let it silently under-count:\n"
        + "\n".join(unresolved)
    )
    assert len(emit_lines) >= 18, (
        f"vacuity floor: only {len(emit_lines)} sandbox_refused emit lines found (expected >= 18)"
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


def test_schema_case_fallback_is_the_unclassified_alarm() -> None:
    """#434B: the schema `*)` arm is the drift/crash ALARM (a traceback, an ImportError, a
    new unbound reason). It must NOT reuse `policy_translate_failed`, which is ALSO a real
    malformed-TOML refusal — that conflation made the alarm read as a routine
    policy-authoring error and hid it.
    """
    _, schema_fallback = _parse_case("${_CAPTURED_REASON}")
    assert schema_fallback == "reason_unclassified", (
        f"the schema case `*)` fallback is {schema_fallback!r}; #434B requires the distinct "
        f"`reason_unclassified` so the alarm is forensically separable from the real refusal."
    )
    assert "policy_translate_failed" in _parse_case("${_CAPTURED_REASON}")[0], (
        "policy_translate_failed must REMAIN in the allow-list — it is a real "
        "SandboxPolicyInvalid reason for malformed TOML, not only the old fallback."
    )


def _kind_case_fallback_arm() -> str:
    """The body of the launcher's sandbox-kind ``*)`` arm.

    NOT reusable via ``_parse_mapping_case``: that helper requires EVERY arm to assign the named
    variable, and this case's ``full)`` / ``none)`` / ``stub)`` arms do the real launcher work
    instead. Parse just the fallback arm.
    """
    text = _launcher_text()
    header = 'case "${SANDBOX_KIND}" in'
    idx = text.find(header)
    assert idx != -1, f"bash case header not found in the launcher: {header!r}"
    body = text[idx + len(header) :]
    # The kind case is the launcher's LAST case and its arms nest further cases, so anchor the
    # fallback on the `*)` arm marker rather than the first `esac`.
    marker = "\n    *)"
    arm_idx = body.find(marker)
    assert arm_idx != -1, "the sandbox-kind case has no `*)` fallback arm — it must fail closed"
    return body[arm_idx:]


def test_sandbox_kind_fallback_is_not_mislabelled_as_block_missing() -> None:
    """#435 / #434-class: the sandbox-kind `*)` arm recorded an unrecognised kind as
    `sandbox_block_missing` — a different condition ("no [sandbox] block") with a different fix.

    Text-bound, and the limit is named here rather than left implicit: manifest.py declares
    `kind: Literal["full","none","stub"]`, so parse_manifest rejects anything else upstream and
    this arm is unreachable from a VALID manifest — it is the fail-closed default against
    helper/jq drift (a compromised/stubbed `manifest_reader --read-sandbox`, or a `SANDBOX_KIND`
    jq-extraction bug). This guard proves WHICH reason the arm writes; it does not drive the arm.

    #452 review test-002: an earlier version of this docstring claimed "no test can [drive the
    arm], short of stubbing the helper" — true as stated, but presented as if that made the arm
    untestable, which is false: this PR already pays the PATH-shadowed-`python3` cost elsewhere
    (see the anti-echo test in test_launcher_sandbox_flow.py). The behavioural companion,
    `test_launcher_sandbox_flow.test_unrecognised_sandbox_kind_refused_via_stubbed_helper`,
    stubs `python3` to return `{"kind":"bogus"}` and drives this exact arm end-to-end.
    """
    arm = _kind_case_fallback_arm()
    assert '"reason":"sandbox_kind_unrecognised"' in arm, (
        "the sandbox-kind `*)` fallback does not write sandbox_kind_unrecognised"
    )
    assert "sandbox_block_missing" not in arm, (
        "the sandbox-kind `*)` fallback still mislabels an unrecognised kind as "
        "sandbox_block_missing — #435's named defect."
    )


def test_derived_vocabularies_are_not_vacuous() -> None:
    """`set() == set()` / `set() <= X` are the canonical vacuous greens — floor every derived set.

    A parse that silently returns nothing reports green while gating nothing
    (``domain_paper_only_gates``). Each floor carries a message.
    """
    assert len(_sandbox_policy_invalid_reasons()) >= 7, "SandboxPolicyInvalid literal floor"
    assert len(_flags_path_reasons()) >= 9, "flags-path floor"
    assert len(_read_environment_keys()) == 2, "env-key floor"
    assert len(_launcher_emittable_reasons()) >= 31, "launcher-emittable floor"
    assert len(_RESERVED_UNEMITTED) == 4, "reserved floor"
    assert len(audit_row_schemas.SANDBOX_REFUSED_REASONS) >= 35, "vocab floor"


# ---------------------------------------------------------------------------
# #452 review test-001 — every emit-line JSON TEMPLATE must itself be well-formed.
#
# Every guard above binds the launcher's *reasons* to the Python vocabulary. None of them
# reads the printf FORMAT STRING as JSON — they match on substrings (`"reason":\s*"([^"]*)"`)
# that survive even when the surrounding template is broken. Named mutant (from the PR #452
# review): drop the closing brace from one row's printf template. The row becomes unparseable
# and is silently discarded at ``launcher_refusal.py``'s ``except ValueError: continue`` — yet
# a behavioural test asserting only ``"some_reason" in result.stderr`` stays green, because that
# substring is present whether or not the JSON around it is well-formed (worse: it is ALSO
# satisfied by an unrelated printf on the same stderr stream that happens to share the reason
# word — the macOS test's original defect). This guard reads every template STATICALLY, so a
# malformed one fails here regardless of which behavioural test happens to reach that line.
# ---------------------------------------------------------------------------

_TRAILING_LITERAL_NEWLINE = "\\n"  # the 2 literal characters \ and n, not an actual newline


def _sandbox_event_printf_templates(event: str) -> list[str]:
    """Every printf format-string literal (its first single-quoted argument) on a line
    carrying ``event`` — parsed textually, since these are bash ``printf`` calls, not Python.

    Keyed on the event NAME rather than the compact JSON byte-string, matching the sibling
    emit-line walks above (#432 review err-438-01 / CodeRabbit): a future line that reformats
    its JSON must not silently drop out of this guard's denominator.
    """
    templates: list[str] = []
    for line in _launcher_text().splitlines():
        if "printf" not in line or event not in line:
            continue
        match = re.search(r"printf\s+'([^']*)'", line)
        assert match is not None, (
            f"printf line carrying {event!r} has no single-quoted format-string literal this "
            f"parser can extract: {line.strip()[:120]}"
        )
        template = match.group(1)
        assert template.endswith(_TRAILING_LITERAL_NEWLINE), (
            f"printf template for {event!r} does not end with the expected literal "
            f"trailing \\n: {template!r}"
        )
        templates.append(template[: -len(_TRAILING_LITERAL_NEWLINE)])
    return templates


def _assert_templates_are_well_formed_json(event: str, templates: list[str]) -> None:
    """Substitute a placeholder for every ``%s`` and feed the result through ``json.loads``.

    A placeholder, not the real runtime values, because this guard runs at COLLECTION time
    against the launcher's SOURCE TEXT — it proves the template's fixed structure (braces,
    quoting, commas) is sound independent of what any caller ever substitutes in.
    """
    malformed: list[str] = []
    for template in templates:
        candidate = template.replace("%s", "PLACEHOLDER")
        try:
            json.loads(candidate)
        except json.JSONDecodeError as exc:
            malformed.append(f"{template!r}: {exc}")
    assert not malformed, (
        f"the following {event!r} printf templates are not well-formed JSON once %s is "
        f"substituted with a placeholder:\n" + "\n".join(malformed)
    )


def test_every_sandbox_refused_json_template_is_well_formed() -> None:
    """The named #452 mutant: drop a closing brace from any ``sandbox_refused`` row's printf
    template and this fails, independent of which behavioural test happens to exercise that
    row — unlike a substring assertion, which the mutant survives."""
    templates = _sandbox_event_printf_templates(_SANDBOX_REFUSED_EVENT)
    assert len(templates) >= 18, f"vacuity floor: only {len(templates)} templates found"
    _assert_templates_are_well_formed_json(_SANDBOX_REFUSED_EVENT, templates)


def test_every_sandbox_stub_used_json_template_is_well_formed() -> None:
    """Sibling of the guard above for the ``sandbox_stub_used`` event's three producers."""
    templates = _sandbox_event_printf_templates(_SANDBOX_STUB_USED_EVENT)
    assert len(templates) == 3, f"vacuity floor: expected 3 templates, got {len(templates)}"
    _assert_templates_are_well_formed_json(_SANDBOX_STUB_USED_EVENT, templates)


# ---------------------------------------------------------------------------
# #436 — bind the stub_used row's `reason` to a closed vocabulary of its own.
#
# `supervisor.plugin.sandbox_stub_used` is the sibling row for the disposition
# where the launcher proceeds to exec WITHOUT OS-level isolation (dev/test
# only). It has THREE producers, not one allow-list `case` — so this binding
# is structurally simpler than the sandbox_refused guards above: it derives
# the emitted reasons straight off the printf lines (no case-mapping to
# resolve) and pins them against the new SANDBOX_STUB_USED_REASONS constant.
# ---------------------------------------------------------------------------

_SANDBOX_STUB_USED_EVENT = "supervisor.plugin.sandbox_stub_used"


def _stub_used_emit_lines() -> list[str]:
    """Every printf line carrying the stub_used event — keyed on the event NAME, not the
    compact JSON byte-string, so a future line that reformats its JSON cannot slip the count
    (#432's own silent-under-count lesson)."""
    return [
        line
        for line in _launcher_text().splitlines()
        if "printf" in line and _SANDBOX_STUB_USED_EVENT in line
    ]


def test_every_stub_used_reason_is_in_the_closed_vocab() -> None:
    """#436: the stub row's `reason` was undeclared — live field-vocabulary drift of exactly
    the class #432 closes for the sandbox_refused sibling. Bind it."""
    lines = _stub_used_emit_lines()
    assert len(lines) == 3, f"vacuity floor: expected 3 stub_used emit lines, got {len(lines)}"
    reasons: set[str] = set()
    missing_reason: list[str] = []
    for line in lines:
        match = re.search(r'"reason":\s*"([^"]*)"', line)
        if match is None:
            missing_reason.append(line.strip()[:90])
        else:
            reasons.add(match.group(1))
    assert not missing_reason, (
        "sandbox_stub_used printf line(s) with no `reason` field — #436 makes it MANDATORY on "
        "all three sites. A row without one names no cause at all: it says a plugin ran "
        "unsandboxed but not why, leaving an operator to infer the branch from which fields "
        "happen to be present — and on macOS the kind:none and kind:stub branches are both "
        "reachable, so that inference has nothing to work with:\n" + "\n".join(missing_reason)
    )
    unknown = reasons - audit_row_schemas.SANDBOX_STUB_USED_REASONS
    assert not unknown, (
        f"the launcher writes {sorted(unknown)} into a {_SANDBOX_STUB_USED_EVENT} row, absent "
        f"from SANDBOX_STUB_USED_REASONS (a CLOSED vocabulary)."
    )


def test_stub_used_vocab_is_exactly_what_the_launcher_emits() -> None:
    """Equality, so an ORPHAN (declared, emitted by nothing) is caught too — #432's arch-001."""
    emitted = {
        match.group(1)
        for line in _stub_used_emit_lines()
        if (match := re.search(r'"reason":\s*"([^"]*)"', line))
    }
    assert emitted == audit_row_schemas.SANDBOX_STUB_USED_REASONS, (
        "SANDBOX_STUB_USED_REASONS is not exactly what the launcher emits.\n"
        f"  orphan (declared, never emitted): "
        f"{sorted(audit_row_schemas.SANDBOX_STUB_USED_REASONS - emitted)}\n"
        f"  missing (emitted, not declared): "
        f"{sorted(emitted - audit_row_schemas.SANDBOX_STUB_USED_REASONS)}"
    )


def test_stub_and_refused_vocabs_are_deliberately_not_disjoint() -> None:
    """D7: `uid_separation_unavailable` is a member of BOTH vocabularies, and that is correct
    — `reason` names the CAUSE, `event` names the disposition (refused vs proceeded anyway),
    `environment` names why they differ. This test exists so a future reviewer cannot
    'tidy' the overlap away without confronting the decision.
    """
    shared = audit_row_schemas.SANDBOX_STUB_USED_REASONS & audit_row_schemas.SANDBOX_REFUSED_REASONS
    assert shared == {"uid_separation_unavailable"}, (
        f"the vocab overlap changed to {sorted(shared)}. The two families share exactly one "
        f"cause; see D7 in the design spec before altering this."
    )

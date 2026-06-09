"""Go-live gate: the quarantined LLM must NOT be wired to a live spawn path
while sandbox egress is unrestricted (PR #231 finding-5 / #230).

The shipped Linux sandbox policy deliberately does NOT ``--unshare-net`` — the
quarantined LLM needs its own provider HTTPS egress and the simple
``SandboxPolicy`` schema cannot yet express a provider-only allowlist. That is
an accepted, documented gap (ADR-0015 Consequences, ``config/sandbox/README.md``,
``sbx-2026-005``) tracked as release-blocker #230.

The deferral is SOUND only while a precondition holds: **no production code
path spawns the ``alfred.quarantined-llm`` plugin via the launcher.** Today the
quarantined LLM is not driven end-to-end (the only launcher invocations in
``src/`` are the daemon ``--self-test`` probe and tests), so the open egress
contains nothing live.

That precondition is currently guarded only by prose + human memory + the
regression guards that flip red if someone *adds* ``unshare net`` (the WRONG
direction). There is no gate that BLOCKS wiring a live spawn while egress is
open. THIS test is that gate:

    It fails the moment a production spawn path for ``alfred.quarantined-llm``
    is added to ``src/`` without the egress allowlist landing first — forcing
    #230 to land before the quarantined LLM goes live.

When #230 lands the provider-only egress allowlist (``--unshare-net`` + a
filtered forwarder), the spawn-wiring PR removes the
``# SECURITY-GATE #230`` marker below and updates / deletes this test. Until
then a new live spawn path makes this test go red — by design.

Why AST, not regex (PR #231 CR finding, must-fix)
-------------------------------------------------
The first cut of this gate matched on a SINGLE SOURCE LINE — a spawn primitive
and the launcher path (or plugin id) had to appear on the same line — and it
SKIPPED ``cli/daemon/_daemon_probes.py`` WHOLESALE to allowlist the sanctioned
``--self-test`` probe. Both choices made the gate bypassable:

* a real wiring via a multiline call, a local variable, or any indirection
  put the primitive and the target on different lines → invisible;
* a live spawn added *inside* ``_daemon_probes.py`` (the file-wide skip) was
  invisible regardless.

This rewrite walks the ``src/alfred`` AST instead:

* spawn CALL SITES are ``ast.Call`` nodes whose callee resolves to a
  subprocess / exec / posix-spawn primitive (alias-resolved);
* a spawn TARGETS THE LAUNCH iff the launcher basename or the quarantined-LLM
  plugin id appears as a string literal anywhere in the ENCLOSING FUNCTION
  BODY, or via a module-level constant referenced from that body whose
  assignment carries such a literal (so ``str(_LAUNCHER_PATH)`` is caught);
* the sanctioned probe is allowlisted BY CALL SHAPE — a spawn whose argv
  contains the literal ``"--self-test"`` — NOT by filename, so a NEW live spawn
  added to ``_daemon_probes.py`` (without ``--self-test``) is STILL caught.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SRC = _REPO_ROOT / "src" / "alfred"
_REAL_POLICY = _REPO_ROOT / "config" / "sandbox" / "quarantined-llm.linux.bwrap.policy"

# SECURITY-GATE #230: the spawn-wiring PR that drives the quarantined LLM live
# MUST land the egress allowlist (--unshare-net + provider-only forwarder)
# FIRST. When it does, that PR (a) makes the real policy unshare ``net`` and
# (b) updates/removes this gate. Until then, no live spawn path may exist.

# The quarantined-LLM plugin id whose launcher spawn would consume the open
# egress. A production subprocess/exec that drives the launcher with this id is
# the live-spawn path the gate blocks.
_QUARANTINED_PLUGIN_ID = "alfred.quarantined-llm"

# The bash launcher basename. A spawn that drives this script — directly, via a
# ``str(_LAUNCHER_PATH)`` constant, or any in-function indirection — stands up a
# live quarantined-LLM process. The daemon ``--self-test`` probe drives the
# launcher too, but only for its self-check; it is allowlisted by CALL SHAPE
# (see ``_SELF_TEST_FLAG``), never by filename.
_LAUNCHER_BASENAME = "alfred-plugin-launcher.sh"

# The sanctioned-probe allowlist marker: a spawn whose argv carries this literal
# is the daemon ``--self-test`` self-check (no plugin id, no provider key, no T3
# content). Allowlisting by this literal — not by file — keeps a NEW live spawn
# added to ``_daemon_probes.py`` (without it) in scope of the gate.
_SELF_TEST_FLAG = "--self-test"


# ---------------------------------------------------------------------------
# Spawn-primitive recognition (alias-resolved).
# ---------------------------------------------------------------------------

# Attribute-form spawn primitives, keyed by (module, attr-prefix). The attr is
# matched by PREFIX so ``os.execvp``/``os.spawnlp``/``os.posix_spawnp`` and
# ``asyncio.create_subprocess_exec``/``…_shell`` are all covered.
_MODULE_SPAWN_ATTRS: dict[str, tuple[str, ...]] = {
    "subprocess": ("run", "Popen", "call", "check_call", "check_output"),
    "os": ("exec", "spawn", "posix_spawn"),
    "asyncio": ("create_subprocess_",),
}

# Bare callables that, when imported from ``subprocess``, are spawn primitives
# (``from subprocess import Popen as P`` → ``P(...)``). Imported-name → canonical.
_SUBPROCESS_BARE_NAMES: frozenset[str] = frozenset(
    {"run", "Popen", "call", "check_call", "check_output"}
)


def _attr_is_spawn(module: str, attr: str) -> bool:
    prefixes = _MODULE_SPAWN_ATTRS.get(module)
    if prefixes is None:
        return False
    return any(attr == p or attr.startswith(p) for p in prefixes)


@dataclass(frozen=True)
class _ModuleAliases:
    """Import aliases that let us resolve spawn callees in one module.

    ``module_alias`` maps a local name back to the real module it aliases
    (``import subprocess as sp`` → ``{"sp": "subprocess"}``). ``bare_spawn``
    is the set of local names bound to a bare subprocess spawn primitive
    (``from subprocess import Popen as P`` → ``{"P"}``).
    """

    module_alias: dict[str, str]
    bare_spawn: frozenset[str]


def _collect_aliases(tree: ast.Module) -> _ModuleAliases:
    module_alias: dict[str, str] = {}
    bare_spawn: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _MODULE_SPAWN_ATTRS:
                    module_alias[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module == "subprocess":
                for alias in node.names:
                    if alias.name in _SUBPROCESS_BARE_NAMES:
                        bare_spawn.add(alias.asname or alias.name)
            elif node.module in _MODULE_SPAWN_ATTRS:
                # ``from asyncio import create_subprocess_exec`` etc.
                for alias in node.names:
                    if _attr_is_spawn(node.module, alias.name):
                        bare_spawn.add(alias.asname or alias.name)
    return _ModuleAliases(module_alias=module_alias, bare_spawn=frozenset(bare_spawn))


def _call_is_spawn(call: ast.Call, aliases: _ModuleAliases) -> bool:
    """True iff ``call``'s callee resolves to a subprocess/exec spawn primitive."""
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        module = aliases.module_alias.get(func.value.id, func.value.id)
        return _attr_is_spawn(module, func.attr)
    if isinstance(func, ast.Name):
        return func.id in aliases.bare_spawn
    return False


# ---------------------------------------------------------------------------
# Target recognition: does a spawn drive the launcher / quarantined LLM?
# ---------------------------------------------------------------------------


def _string_constants(node: ast.AST) -> list[str]:
    """All ``str`` constant values anywhere under ``node``."""
    return [
        sub.value
        for sub in ast.walk(node)
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str)
    ]


def _literal_targets_launch(values: list[str]) -> bool:
    """True iff any literal names the launcher basename or quarantined-LLM id.

    Substring match: the launcher basename appears inside a ``Path(...) /
    "alfred-plugin-launcher.sh"`` segment and the plugin id may be embedded in a
    larger argv token.
    """
    return any(_LAUNCHER_BASENAME in value or _QUARANTINED_PLUGIN_ID in value for value in values)


def _module_launch_constants(tree: ast.Module) -> frozenset[str]:
    """Names of module-level constants whose assignment carries a launch literal.

    Catches ``_LAUNCHER_PATH = Path(...) / "alfred-plugin-launcher.sh"`` so a
    ``str(_LAUNCHER_PATH)`` reference inside a spawn's enclosing function counts
    as targeting the launch even though the basename literal never appears in
    that function's body.
    """
    names: set[str] = set()
    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            value = node.value
        if value is None or not _literal_targets_launch(_string_constants(value)):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                names.add(target.id)
    return frozenset(names)


def _references_launch_constant(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    launch_constants: frozenset[str],
) -> bool:
    """True iff the function body references a module launch-constant by name."""
    if not launch_constants:
        return False
    return any(isinstance(sub, ast.Name) and sub.id in launch_constants for sub in ast.walk(func))


def _call_argv_has_self_test(call: ast.Call) -> bool:
    """True iff the spawn's own argv carries the sanctioned ``--self-test`` flag.

    Allowlist BY CALL SHAPE: only the literal in THIS call's positional args
    (incl. a list/tuple argv) counts — not a stray occurrence elsewhere in the
    function. That keeps the allowlist scoped to the sanctioned probe call and
    a NEW non-self-test spawn in the same file still in scope.
    """
    return _SELF_TEST_FLAG in _string_constants(call)


# ---------------------------------------------------------------------------
# The detector.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _SpawnFinding:
    """A spawn-of-the-launcher site that is NOT the sanctioned self-test probe."""

    rel_path: str
    lineno: int


def find_live_quarantined_spawns(src_text: str, rel_path: str) -> list[_SpawnFinding]:
    """Return non-allowlisted launcher/quarantined-LLM spawn sites in one module.

    A site is reported iff:

    1. it is an ``ast.Call`` to a subprocess/exec/posix-spawn primitive
       (alias-resolved);
    2. the launcher basename or quarantined-LLM plugin id is reachable from the
       enclosing function — as a string literal in the function body, or via a
       module-level constant the body references whose assignment carries such a
       literal; AND
    3. the call's own argv does NOT carry the sanctioned ``--self-test`` flag.

    Spawn calls at module scope (no enclosing function) are evaluated against
    their own subtree's literals only — a launch spawn at import time is just as
    much a live wiring and is still caught.
    """
    tree = ast.parse(src_text)
    launch_constants = _module_launch_constants(tree)
    aliases = _collect_aliases(tree)

    findings: list[_SpawnFinding] = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body_literals = _string_constants(func)
        body_targets_launch = _literal_targets_launch(body_literals) or _references_launch_constant(
            func, launch_constants
        )
        for call in ast.walk(func):
            if not isinstance(call, ast.Call) or not _call_is_spawn(call, aliases):
                continue
            call_targets_launch = body_targets_launch or _literal_targets_launch(
                _string_constants(call)
            )
            if not call_targets_launch:
                continue
            if _call_argv_has_self_test(call):
                continue
            findings.append(_SpawnFinding(rel_path=rel_path, lineno=call.lineno))
    return findings


def _python_sources() -> list[Path]:
    return sorted(p for p in _SRC.rglob("*.py") if "__pycache__" not in p.parts)


_GATE_FAILURE_HINT = (
    "egress is unrestricted (#230); land the egress allowlist + bind-tightening "
    "before wiring a live quarantined-LLM spawn"
)


# ---------------------------------------------------------------------------
# The gate.
# ---------------------------------------------------------------------------


def test_no_live_quarantined_llm_spawn_while_egress_open() -> None:
    """No ``src/alfred`` module stands up a live quarantined-LLM spawn.

    This is the inert-policy precondition the #230 egress deferral relies on.
    A future PR that wires a live quarantined-LLM spawn — driving the launcher
    or the plugin id from production code via ANY shape (multiline call,
    variable, alias, indirection) — trips this gate UNLESS it is the sanctioned
    ``--self-test`` probe. The spawn-wiring PR must instead land #230's egress
    allowlist and update this gate.
    """
    offenders: list[str] = []
    for src in _python_sources():
        rel = src.relative_to(_SRC).as_posix()
        for finding in find_live_quarantined_spawns(src.read_text(encoding="utf-8"), rel):
            offenders.append(f"{finding.rel_path}:{finding.lineno}")

    assert not offenders, (
        "A live quarantined-LLM spawn path was added while sandbox "
        f"{_GATE_FAILURE_HINT}. Offending sites:\n  " + "\n  ".join(offenders)
    )


def test_gate_is_anchored_to_the_open_egress_state() -> None:
    """The gate only makes sense while egress is open — pin that linkage.

    If a future edit lands ``unshare net`` in the real policy (egress closed),
    this gate's premise no longer holds and the gate + #230 references should be
    revisited. Asserting the open-egress state here ties the gate's lifetime to
    the condition it guards: when egress closes, this assertion forces a
    deliberate update rather than leaving a stale gate behind.
    """
    body = _REAL_POLICY.read_text(encoding="utf-8")
    # The policy is TOML; a closed-egress policy would list "net" in unshare.
    assert re.search(r'unshare\s*=\s*\[[^\]]*"net"', body) is None, (
        "the real policy now unshares net (egress closed) — #230 may have landed; "
        "revisit this go-live gate and the quarantined-LLM spawn wiring"
    )


@pytest.mark.parametrize(
    "doc",
    [
        _REAL_POLICY,
        _REPO_ROOT / "config" / "sandbox" / "README.md",
    ],
)
def test_open_egress_is_documented_against_230(doc: Path) -> None:
    """The egress gap is documented + #230-referenced where the gate points."""
    text = doc.read_text(encoding="utf-8")
    assert "#230" in text


# ---------------------------------------------------------------------------
# Anti-false-negative proofs: the detector must catch bypasses the regex gate
# missed, and must NOT flag the sanctioned probe.
# ---------------------------------------------------------------------------


# The real sanctioned probe, in full (alias-free, constant-driven launcher path,
# argv carries ``--self-test``). The detector MUST NOT flag this.
_SANCTIONED_PROBE_SRC = """
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Final

_LAUNCHER_PATH: Final[Path] = (
    Path(__file__).resolve().parents[4] / "bin" / "alfred-plugin-launcher.sh"
)


async def _launcher_self_test_impl() -> str:
    proc = await asyncio.create_subprocess_exec(
        str(_LAUNCHER_PATH),
        "--self-test",
        stdout=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    stdout, _ = await proc.communicate()
    return stdout.decode().strip()
"""


# A live spawn split across multiple lines — the spawn primitive and the
# launcher path live on DIFFERENT lines, so the old same-line regex missed it.
_MULTILINE_LAUNCHER_SPAWN_SRC = """
import subprocess

_LAUNCHER = "/opt/alfred/bin/alfred-plugin-launcher.sh"


def drive_quarantined_llm() -> None:
    subprocess.Popen(
        [
            _LAUNCHER,
            "alfred.quarantined-llm",
            "--provider-key",
        ]
    )
"""


# A live spawn that names the quarantined-LLM id via a local variable, with the
# primitive aliased — defeats both the same-line and the literal-callee regex.
_INDIRECT_ALIASED_SPAWN_SRC = """
from subprocess import Popen as _P

_PLUGIN = "alfred.quarantined-llm"


def go() -> None:
    argv = ["/some/launcher", _PLUGIN]
    _P(argv)
"""


# A NEW live spawn added INSIDE the daemon-probes shape but WITHOUT
# ``--self-test`` — the file the old gate skipped wholesale. Must be caught.
_DAEMON_PROBES_NON_SELFTEST_SRC = """
import asyncio
from pathlib import Path

_LAUNCHER_PATH = Path("/opt/alfred/bin/alfred-plugin-launcher.sh")


async def sneaky_probe() -> None:
    await asyncio.create_subprocess_exec(
        str(_LAUNCHER_PATH),
        "alfred.quarantined-llm",
    )
"""


# A spawn that has nothing to do with the launcher — must NOT be flagged.
_UNRELATED_SPAWN_SRC = """
import subprocess


def ls() -> None:
    subprocess.run(["ls", "-la"])
"""


# The class-var plugin id with NO spawn anywhere (mirrors
# ``security/quarantine.py``) — must NOT be flagged.
_PLUGIN_ID_NO_SPAWN_SRC = """
class _Quarantine:
    _PLUGIN_ID = "alfred.quarantined-llm"

    def describe(self) -> str:
        return self._PLUGIN_ID
"""


def test_detector_does_not_flag_the_sanctioned_self_test_probe() -> None:
    assert find_live_quarantined_spawns(_SANCTIONED_PROBE_SRC, "probe.py") == [], (
        "the sanctioned --self-test probe must be allowlisted by call shape"
    )


def test_detector_catches_multiline_launcher_spawn() -> None:
    findings = find_live_quarantined_spawns(_MULTILINE_LAUNCHER_SPAWN_SRC, "evil.py")
    assert len(findings) == 1, "a multiline launcher spawn must be caught"


def test_detector_catches_indirect_aliased_quarantined_spawn() -> None:
    findings = find_live_quarantined_spawns(_INDIRECT_ALIASED_SPAWN_SRC, "evil.py")
    assert len(findings) == 1, (
        "an aliased spawn naming the quarantined-LLM id via a variable must be caught"
    )


def test_detector_catches_non_selftest_spawn_in_daemon_probes_shape() -> None:
    findings = find_live_quarantined_spawns(
        _DAEMON_PROBES_NON_SELFTEST_SRC, "cli/daemon/_daemon_probes.py"
    )
    assert len(findings) == 1, (
        "a NEW spawn in the daemon-probes file WITHOUT --self-test must be "
        "caught — the gate must not skip the file wholesale"
    )


def test_detector_ignores_unrelated_spawn() -> None:
    assert find_live_quarantined_spawns(_UNRELATED_SPAWN_SRC, "ls.py") == []


def test_detector_ignores_plugin_id_constant_without_spawn() -> None:
    assert find_live_quarantined_spawns(_PLUGIN_ID_NO_SPAWN_SRC, "quarantine.py") == []

"""Go-live gate: the quarantined-LLM child stays egress-free; the real-LLM
provider egress (#230) lands behind the gateway proxy, never by re-opening the
child's network (PR #231 finding-5 / #230; re-pivoted PR-S4-11c-2b0; egress
CLOSED for the echo child in Spec C G7-1 / #333).

The shipped Linux sandbox policy now ``--unshare-net``s. The deterministic-echo
child (PR-S4-11c-2b0) runs with NO provider client and NO socket of its own, so
it needs ZERO outbound network and runs in an EMPTY network namespace — closing
the #230 egress hole for the component that exists today (ADR-0015 Consequences,
``config/sandbox/README.md``, ``sbx-2026-005``, now an enforced-containment
payload). The 2c real-LLM child (a separate follow-on, still tracked by #230)
DOES make a provider call, but reaches the provider PROVIDER-ONLY through the
gateway L7 CONNECT proxy (the core is connectivity-free; the gateway is the sole
external I/O plane — Spec C), NOT by dropping ``net`` from this policy.

**Re-pivot history.** Originally this gate asserted "no production path spawns
``alfred.quarantined-llm`` AT ALL", because every spawn of this plugin made a
provider HTTPS call — so a live spawn == a live process consuming the then-open
egress while holding T3 + the provider key. PR-S4-11c-2b0 broke that 1:1: it
stood up the spawn SUBSTRATE live (``security/quarantine_child_io.py`` ->
kind=full launcher -> bwrap) but the spawned child runs a DETERMINISTIC ECHO loop
with NO provider client and NO network egress. Spec C G7-1 then ``--unshare-net``s
that child, so its egress is now kernel-closed as well as import-graph-clean.
(2b0 was a PRECURSOR shipping the spawn substrate; the substrate IS a live
``src/alfred`` spawn site, so the gate's disposition must account for it.)

So the gate enforces the SHARP invariant it always meant — **the live quarantined
child carries no network egress** — with two release-blocking invariants:

* ``test_quarantined_child_has_no_module_scope_egress_import`` — the LIVE child
  module imports no network-egress module (httpx / anthropic / openai / socket /
  …) at module scope. This is the teeth: it stays GREEN for the 2b echo child and
  goes RED the moment 2c wires a real client INTO the child instead of routing
  through the gateway proxy. The kernel ``--unshare-net`` and this import-graph
  invariant are INDEPENDENT layers — neither alone is trusted.
* ``test_only_sanctioned_quarantined_llm_spawn_site`` — the ONLY live
  launcher/quarantined-LLM spawn from ``src/alfred`` is the single sanctioned
  no-egress substrate site (``security/quarantine_child_io.py``) plus the
  ``--self-test`` probe. A SECOND spawn site, or a spawn driving a different
  child, trips the gate.

The detector (``find_live_quarantined_spawns``) is UNCHANGED — its six
anti-false-negative proofs still hold; only the disposition of its findings is
"only the sanctioned site, and only while the child stays egress-free".

When #230 lands the 2c real-LLM child, it lands behind the gateway provider-only
egress proxy and the import-graph invariant relaxes for the proxy-routed path.
Until then, a network-capable child OR a second live spawn makes this gate go red
— by design.

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

# SECURITY-GATE #230: Spec C G7-1 made the real policy unshare ``net`` (the 2b
# deterministic-echo child needs no egress), so the child's egress is now kernel-
# closed AND import-graph-clean. A NETWORK-CAPABLE quarantined-LLM spawn (the 2c
# real-LLM child) MUST reach its provider PROVIDER-ONLY through the gateway L7
# CONNECT proxy (never by re-opening this namespace); the import-graph invariant
# below keeps the live child honest until that proxy-routed path lands behind #230.

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
    "egress for the live quarantined child is kernel-closed via --unshare-net "
    "(Spec C G7-1); the real-LLM (#230) child must route provider egress through "
    "the gateway proxy, never by re-opening the child's network"
)


# ---------------------------------------------------------------------------
# The gate.
# ---------------------------------------------------------------------------


# PR-S4-11c-2b0 re-pivot (security-engineer adjudication), extended by Spec C G7-1:
# the gate moved from "no live spawn AT ALL" to "no live spawn that can reach the
# network." 2b0 stood up the quarantined-LLM spawn substrate LIVE
# (``security/quarantine_child_io.py`` -> kind=full launcher -> bwrap); the spawned
# child runs a DETERMINISTIC ECHO loop with NO provider client and NO network
# egress (verified below), and G7-1 ``--unshare-net``s it so its egress is now
# kernel-closed too. The gate allowlists EXACTLY that one sanctioned spawn site AND
# enforces the load-bearing invariant that the child's reachable import graph
# carries no egress-capable import — so 2c (which wires the real LLM client) trips
# the gate RED again unless it routes provider egress through the gateway proxy
# (#230), never by re-opening the child's network.
_SANCTIONED_SPAWN_SITE = "security/quarantine_child_io.py"

# The quarantined-LLM child entry module + the network-egress imports a real-LLM
# child would pull in. The live echo loop (``_run_mcp_server``) imports none of
# these at module scope. As of #340 PR1, ``provider_dispatch`` itself is
# egress-free too — it drives an INJECTED provider and imports no httpx/SDK; the
# egress-capable import lands in PR2's ``_build_provider`` (the real-client
# construction), which this gate will assert against at go-live.
# PR-S4-11c-2b0 (ADR-0030): the child moved INTO the wheel under
# ``src/alfred/security/quarantine_child/__main__.py`` — the egress-import
# invariant follows it to its new home.
_CHILD_ENTRY_MODULE = (
    _REPO_ROOT / "src" / "alfred" / "security" / "quarantine_child" / "__main__.py"
)
_EGRESS_CAPABLE_MODULES: frozenset[str] = frozenset(
    {
        "httpx",
        "anthropic",
        "openai",
        "requests",
        "aiohttp",
        "socket",
        "http.client",
        "urllib.request",
    }
)


def _module_scope_imports(src_text: str) -> set[str]:
    """Return every module name imported at MODULE SCOPE (not inside a function).

    A lazy in-function import (the dead ``handle_extract`` -> ``provider_dispatch``
    path) is intentionally NOT reported: it is unreachable from the live echo loop
    (``_run_mcp_server`` never calls ``handle_extract`` in 2b), so it cannot drive
    egress. 2c making the LLM call reachable would either add a module-scope
    network import here OR move the dispatch onto the loop path — both surface.
    """
    tree = ast.parse(src_text)
    names: set[str] = set()
    for node in tree.body:  # top-level statements only — module scope
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            names.add(node.module)
    return names


def test_quarantined_child_has_no_module_scope_egress_import() -> None:
    """The LIVE quarantined-LLM child imports no network-egress module at scope.

    The load-bearing invariant after the 2b0 re-pivot: the deterministic-echo
    child has NO reachable provider/HTTP client, so a live spawn under open egress
    (#230) cannot exfiltrate T3 + the fd-3 key over the network — there is no code
    to do it. This goes RED the moment 2c wires a real Anthropic/DeepSeek client at
    module scope (or otherwise makes ``provider_dispatch``/``httpx`` reachable from
    the loop) while egress is still open — forcing #230 to land before 2c.
    """
    src = _CHILD_ENTRY_MODULE.read_text(encoding="utf-8")
    scope_imports = _module_scope_imports(src)
    egress_imports = scope_imports & _EGRESS_CAPABLE_MODULES
    assert not egress_imports, (
        "the quarantined-LLM child gained a module-scope network-egress import "
        f"({sorted(egress_imports)}) while sandbox {_GATE_FAILURE_HINT}. The live "
        "child must stay egress-free until #230's egress allowlist lands (2c)."
    )


def test_only_sanctioned_quarantined_llm_spawn_site() -> None:
    """The ONLY live quarantined-LLM spawn is the sanctioned no-egress substrate.

    Re-pivoted for PR-S4-11c-2b0 (see ``_SANCTIONED_SPAWN_SITE``); the spawn-site
    detector is egress-state-independent, so this gate holds regardless of the
    child's netns. The gate tolerates EXACTLY the ``security/quarantine_child_io.py``
    spawn — the substrate that stands up the deterministic-echo child (whose
    egress-free invariant ``test_quarantined_child_has_no_module_scope_egress_import``
    enforces) — and the ``--self-test`` probe. ANY OTHER live launcher/quarantined-
    LLM spawn from ``src/alfred`` trips the gate: a second spawn site, or a spawn
    that drives a different (egress-making) child, must route the new child's
    provider egress through the gateway proxy (#230) first. The detector
    (``find_live_quarantined_spawns``) is unchanged — only the disposition of its
    findings narrows from "none allowed" to "only the sanctioned site".
    """
    offenders: list[str] = []
    for src in _python_sources():
        rel = src.relative_to(_SRC).as_posix()
        for finding in find_live_quarantined_spawns(src.read_text(encoding="utf-8"), rel):
            if finding.rel_path == _SANCTIONED_SPAWN_SITE:
                continue  # the sanctioned no-egress substrate spawn (2b0)
            offenders.append(f"{finding.rel_path}:{finding.lineno}")

    assert not offenders, (
        "A NON-sanctioned live quarantined-LLM spawn path was added while sandbox "
        f"{_GATE_FAILURE_HINT}. Only {_SANCTIONED_SPAWN_SITE} (the deterministic-"
        "echo substrate) is allowlisted. Offending sites:\n  " + "\n  ".join(offenders)
    )


def test_sanctioned_spawn_site_actually_exists() -> None:
    """Anti-rot: the allowlisted spawn site must genuinely BE a detected spawn.

    Guards against the allowlist silently outliving the thing it allowlists — if
    ``security/quarantine_child_io.py`` ever stops being a detected
    quarantined-LLM spawn (refactor / removal), the allowlist entry is dead and
    must be revisited rather than masking a future real spawn elsewhere.
    """
    site = _SRC / "security" / "quarantine_child_io.py"
    findings = find_live_quarantined_spawns(
        site.read_text(encoding="utf-8"), _SANCTIONED_SPAWN_SITE
    )
    assert findings, (
        f"{_SANCTIONED_SPAWN_SITE} is no longer a detected quarantined-LLM spawn — "
        "the allowlist entry is stale; revisit the go-live gate."
    )


def test_gate_is_anchored_to_the_closed_egress_state() -> None:
    """Spec C G7-1 (#333): the deterministic-echo quarantine child unshares net.

    The echo child needs ZERO network, so --unshare-net closes the #230 egress hole
    NOW. The 2c real-LLM child (separate follow-on, still #230) re-opens a
    PROVIDER-ONLY path via the gateway L7 proxy — NOT a relaxation of this gate.
    Anchoring on the closed-egress state ties this gate's lifetime to the condition
    it guards: if a future edit dropped ``net`` from the unshare set the assertion
    forces a deliberate review rather than silently re-opening the child's egress.
    """
    body = _REAL_POLICY.read_text(encoding="utf-8")
    assert re.search(r'unshare\s*=\s*\[[^\]]*"net"', body) is not None, (
        "the quarantine policy must now unshare net (egress closed, Spec C G7-1)"
    )


@pytest.mark.parametrize(
    "doc",
    [
        _REAL_POLICY,
        _REPO_ROOT / "config" / "sandbox" / "README.md",
    ],
)
def test_open_egress_is_documented_against_230(doc: Path) -> None:
    """The egress posture is documented + #230-referenced where the gate points.

    Spec C G7-1 closed the echo child's egress (``--unshare-net``); the remaining
    #230 reference now documents the 2c real-LLM provider-only path (via the
    gateway L7 proxy). Both the policy and the README must keep that #230 anchor so
    the still-open 2c work stays visible where the gate points.
    """
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

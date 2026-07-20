"""Spawn-topology gate + an IMPORT-TIME egress backstop for the quarantined-LLM child.

(PR #231 finding-5 / #230; re-pivoted PR-S4-11c-2b0; egress CLOSED in Spec C G7-1 /
#333; real-LLM cutover in #340 PR2b-golive.)

**This module was renamed in #340 PR2b-golive.** It was
``test_quarantined_llm_not_yet_spawned_while_egress_open.py``, a name that asserted a
property it had stopped proving — the child IS spawned now, and its egress is closed by
the kernel rather than by the absence of a spawn. A reader who trusted the old filename
without opening the file would have credited this gate with the broad
"cannot reach the network" claim. The name now describes the two invariants below.

.. warning::

   **This gate is weaker than it was, and weaker than the rest of this docstring
   once implied. Read this before treating it as evidence at sign-off.**

   Until #340 PR2b-golive the child was a deterministic-echo stub with no
   provider client at all, and this module's headline invariant — "the live child
   module imports no network-egress module at module scope" — was a faithful
   proxy for "the child cannot reach the network."

   That is no longer true. The golive child DOES construct a real Anthropic
   client and DOES call a provider. It stayed green here only because every
   egress-capable import in ``quarantine_child/__main__.py`` is now LAZY
   (``import socket`` inside ``main()``; ``brokered_egress`` /
   ``provider_dispatch`` imported inside ``main()`` / ``_build_provider`` /
   ``handle_extract``), and :func:`_module_scope_imports` only inspects
   ``tree.body``. The pre-golive prose predicted this test "goes RED the moment
   2c wires a real client INTO the child"; 2c landed and it did not.

   What it still enforces is narrow but real: no egress-capable import may appear
   at MODULE SCOPE in the child entry module. What it no longer enforces is the
   broad claim it was written for. The load-bearing containment for the golive
   child is elsewhere and is independently gated — the kernel ``--unshare-net``
   (``test_quarantined_llm_policy_kernel_enforced.py``, ``sbx-2026-005``) plus
   the fd-4 SCM_RIGHTS broker being the child's only reachability.

   **Not covered anywhere, by this module or any other: the child's egress
   imports at ANY scope.** A lazily imported ``httpx`` / ``openai`` / raw
   ``socket`` on a path other than the sanctioned brokered one is invisible to
   this gate (module scope only) AND to
   ``tests/unit/security/test_quarantine_child_import_closure.py`` (which walks
   the module-scope closure for PRIVILEGED-module reachability, a different
   question). Do not read the pair as covering each other: until #340 PR2b-golive
   that unit test deferred the egress-capability question here, while this module
   disclaims it — a circular deferral in which neither side checked. Both
   docstrings now say so plainly.

   Rebuilding this gate around the golive posture — asserting the child's
   egress-capable imports are exactly the sanctioned brokered ones, at any scope —
   is tracked in **#465**. It is a trust-boundary change and wants its own
   security review rather than a quiet edit inside a sign-off-gated PR.

The shipped Linux sandbox policy ``--unshare-net``s the child into an EMPTY
network namespace (ADR-0015 Consequences, ``config/sandbox/README.md``,
``sbx-2026-005``, an enforced-containment payload). Since golive that namespace
is MORE load-bearing, not less: the child holds a live provider key and T3
content, and reaches the provider PROVIDER-ONLY through a gateway socket the core
pre-connects and hands over via SCM_RIGHTS on fd 4 (the core is
connectivity-free; the gateway is the sole external I/O plane — Spec C). Dropping
``net`` from this policy would let that child dial out directly, past the
chokepoint.

**Re-pivot history.** Originally this gate asserted "no production path spawns
``alfred.quarantined-llm`` AT ALL", because every spawn of this plugin made a
provider HTTPS call — so a live spawn == a live process consuming the then-open
egress while holding T3 + the provider key. PR-S4-11c-2b0 broke that 1:1: it
stood up the spawn SUBSTRATE live (``security/quarantine_child_io.py`` ->
kind=full launcher -> bwrap) while the spawned child was still a DETERMINISTIC
ECHO loop with no provider client and no network egress. Spec C G7-1 then
``--unshare-net``d that child. #340 PR2b-golive closed the sequence by replacing
the echo loop with the real-LLM child — restoring the original 1:1 (a live spawn
IS a live provider-calling process) but with the egress now kernel-closed and
routed through the fd-4 broker, which is what makes it safe.
(2b0 was a PRECURSOR shipping the spawn substrate; the substrate IS a live
``src/alfred`` spawn site, so the gate's disposition must account for it.)

The gate ships two release-blocking invariants:

* ``test_quarantined_child_has_no_module_scope_egress_import`` — the LIVE child
  module imports no network-egress module (httpx / anthropic / openai / socket /
  …) at module scope. This WAS the teeth. Post-golive it is the narrow residue
  described in the warning above: the real client is imported lazily, so this
  now only catches an import-time egress surface, not the broad "child cannot
  reach the network" claim. The kernel ``--unshare-net`` and this import-graph
  invariant remain INDEPENDENT layers — neither alone is trusted, and the kernel
  layer now carries the weight.
* ``test_only_sanctioned_quarantined_llm_spawn_site`` — the ONLY live
  launcher/quarantined-LLM spawn from ``src/alfred`` is the single sanctioned
  substrate site (``security/quarantine_child_io.py``) plus the ``--self-test``
  probe. A SECOND spawn site, or a spawn driving a different child, trips the
  gate. This invariant is UNAFFECTED by the golive cutover — it is about spawn
  topology, not the child's egress posture, and remains fully load-bearing.

The detector (``find_live_quarantined_spawns``) is UNCHANGED — its six
anti-false-negative proofs still hold; the disposition of its findings is "only
the sanctioned site".

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

# SECURITY-GATE #230: Spec C G7-1 made the real policy unshare ``net``, so the
# child's egress is kernel-closed. Since #340 PR2b-golive the shipped child IS the
# network-capable real-LLM child, and it reaches its provider PROVIDER-ONLY through
# the gateway L7 CONNECT proxy via the fd-4 SCM_RIGHTS-brokered socket — never by
# re-opening this namespace. The kernel layer is the enforcement; the import-graph
# invariant below is now a narrow import-time backstop (see the module warning).

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
# (``security/quarantine_child_io.py`` -> kind=full launcher -> bwrap). #340
# PR2b-golive then replaced the echo child that substrate spawns with the real-LLM
# child, whose provider egress runs over the fd-4 SCM_RIGHTS-brokered gateway
# socket inside a ``--unshare-net`` namespace.
#
# THIS allowlist is unaffected by that cutover: it is about spawn TOPOLOGY — how
# many live launcher spawn sites exist and what they drive — not about the child's
# egress posture. Exactly one sanctioned site plus the ``--self-test`` probe; a
# second site or a spawn driving a different child still trips the gate RED.
_SANCTIONED_SPAWN_SITE = "security/quarantine_child_io.py"

# The quarantined-LLM child entry module + the network-egress imports a real-LLM
# child would pull in at MODULE SCOPE.
#
# HISTORY, corrected: this comment used to promise that the egress-capable import
# "lands in PR2's ``_build_provider`` … which this gate will assert against at
# go-live." That did not happen. #340 PR2b-golive landed ``_build_provider`` with
# the real client, but imported ``brokered_egress`` LAZILY inside it, so the
# module-scope check never saw it and this gate stayed green through the cutover.
# The prediction is recorded here rather than deleted because a gate that
# quietly outlived its own stated trigger is worth leaving visible.
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

    A lazy in-function import is NOT reported. Pre-golive that was sound: the
    only lazy egress path (``handle_extract`` -> ``provider_dispatch``) was dead
    code the echo loop never called, so it could not drive egress.

    **Since #340 PR2b-golive that reasoning no longer holds** — ``handle_extract``
    IS on the live path, and ``main()`` lazily imports ``socket`` and
    ``brokered_egress``. The scope restriction is therefore now a deliberate
    narrowing of what this gate covers, not a proof of unreachability. See the
    module docstring's warning; the golive child's containment is enforced by the
    kernel netns + fd-4 broker, gated elsewhere.
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

    Pre-golive this stood for "the child has NO reachable provider/HTTP client",
    which was true of the echo stub. **It does not mean that any more** — see the
    module docstring's warning: the golive child builds a real Anthropic client
    behind LAZY imports, so this assertion passes while the broad claim is false.

    What it still buys, and why it is kept rather than deleted: a module-scope
    egress import in the child entry module would be a fresh, un-brokered egress
    surface reachable at import time — before ``main()``'s boot ordering, before
    the fd-4 reconstruction, and outside the brokered path entirely. Keeping it
    RED-on-regression is cheap and still catches that specific shape.
    """
    src = _CHILD_ENTRY_MODULE.read_text(encoding="utf-8")
    scope_imports = _module_scope_imports(src)
    egress_imports = scope_imports & _EGRESS_CAPABLE_MODULES
    assert not egress_imports, (
        "the quarantined-LLM child gained a module-scope network-egress import "
        f"({sorted(egress_imports)}) while sandbox {_GATE_FAILURE_HINT}. Provider "
        "egress must run through the fd-4 brokered gateway socket, constructed "
        "inside main()/_build_provider — never opened at import time."
    )


def test_only_sanctioned_quarantined_llm_spawn_site() -> None:
    """The ONLY live quarantined-LLM spawn is the single sanctioned substrate.

    Re-pivoted for PR-S4-11c-2b0 (see ``_SANCTIONED_SPAWN_SITE``); the spawn-site
    detector is egress-state-independent, so this gate holds regardless of the
    child's netns — and so, unlike its sibling above, it was NOT weakened by the
    #340 golive cutover. The gate tolerates EXACTLY the
    ``security/quarantine_child_io.py`` spawn — the substrate that stands up the
    quarantine child — and the ``--self-test`` probe. ANY OTHER live
    launcher/quarantined-LLM spawn from ``src/alfred`` trips the gate: a second
    spawn site, or a spawn that drives a different child, must route that child's
    provider egress through the gateway proxy first. The detector
    (``find_live_quarantined_spawns``) is unchanged — only the disposition of its
    findings narrows from "none allowed" to "only the sanctioned site".
    """
    offenders: list[str] = []
    for src in _python_sources():
        rel = src.relative_to(_SRC).as_posix()
        for finding in find_live_quarantined_spawns(src.read_text(encoding="utf-8"), rel):
            if finding.rel_path == _SANCTIONED_SPAWN_SITE:
                continue  # the single sanctioned quarantine-child substrate spawn
            offenders.append(f"{finding.rel_path}:{finding.lineno}")

    assert not offenders, (
        "A NON-sanctioned live quarantined-LLM spawn path was added while sandbox "
        f"{_GATE_FAILURE_HINT}. Only {_SANCTIONED_SPAWN_SITE} (the quarantine-child "
        "substrate) is allowlisted. Offending sites:\n  " + "\n  ".join(offenders)
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
    """Spec C G7-1 (#333): the quarantine child unshares net.

    Since #340 PR2b-golive this is the gate's strongest remaining teeth. The child
    now holds a live provider key and T3 content and DOES call a provider, reaching
    it only via the SCM_RIGHTS-brokered gateway socket on fd 4 — so the empty
    network namespace is what makes that broker the sole route out. Anchoring on
    the closed-egress state ties this gate's lifetime to the condition it guards:
    dropping ``net`` from the unshare set forces a deliberate review instead of
    silently handing the child a path past the gateway chokepoint.
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

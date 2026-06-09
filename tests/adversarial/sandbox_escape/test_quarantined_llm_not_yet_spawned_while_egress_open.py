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
"""

from __future__ import annotations

import re
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

# A spawn that drives the bash launcher. We match a python source line that
# names the launcher script AND a subprocess/exec primitive — the only way a
# live quarantined-LLM process gets stood up. The daemon ``--self-test`` probe
# is the single sanctioned launcher invocation and is allowlisted by filename.
_LAUNCHER_BASENAME = "alfred-plugin-launcher.sh"
_SPAWN_PRIMITIVE = re.compile(
    r"subprocess\.(run|Popen|call|check_call|check_output)"
    r"|os\.exec|create_subprocess_(exec|shell)"
)

# Sanctioned launcher callers in ``src/`` that are NOT a live quarantined-LLM
# spawn. Keyed by path relative to ``src/alfred``. The daemon probe runs the
# launcher's ``--self-test`` self-check (no plugin id, no provider key, no T3
# content) — it never stands up the quarantined LLM.
_ALLOWLISTED_LAUNCHER_CALLERS = frozenset(
    {
        "cli/daemon/_daemon_probes.py",
    }
)


def _python_sources() -> list[Path]:
    return sorted(p for p in _SRC.rglob("*.py") if "__pycache__" not in p.parts)


def test_no_production_spawn_path_for_quarantined_llm() -> None:
    """No ``src/`` module spawns the quarantined LLM via the launcher.

    This is the inert-policy precondition the #230 egress deferral relies on.
    A future PR that wires a live quarantined-LLM spawn — driving the launcher
    from production code — trips this gate UNLESS it is the sanctioned
    self-test probe. The spawn-wiring PR must instead land #230's egress
    allowlist and update this gate.
    """
    offenders: list[str] = []
    for src in _python_sources():
        rel = src.relative_to(_SRC).as_posix()
        if rel in _ALLOWLISTED_LAUNCHER_CALLERS:
            continue
        text = src.read_text(encoding="utf-8")
        if _LAUNCHER_BASENAME not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            # Skip comments + docstring-ish prose — a spawn is executable code.
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if _LAUNCHER_BASENAME in line and _SPAWN_PRIMITIVE.search(line):
                offenders.append(f"{rel}:{lineno}: {stripped}")

    assert not offenders, (
        "A production spawn path for the launcher was added while sandbox egress "
        "is UNRESTRICTED (#230). Land the provider-only egress allowlist "
        "(--unshare-net + filtered forwarder) FIRST, then update this gate. "
        "Offending lines:\n  " + "\n  ".join(offenders)
    )


def test_quarantined_plugin_id_not_driven_into_a_live_spawn() -> None:
    """No ``src/`` module pairs the quarantined-LLM plugin id with a spawn.

    Complementary to the launcher-basename gate: catches a live spawn that
    constructs the launcher path indirectly but still names the quarantined-LLM
    plugin id alongside a subprocess/exec primitive on the same line.
    """
    offenders: list[str] = []
    for src in _python_sources():
        rel = src.relative_to(_SRC).as_posix()
        if rel in _ALLOWLISTED_LAUNCHER_CALLERS:
            continue
        text = src.read_text(encoding="utf-8")
        if _QUARANTINED_PLUGIN_ID not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if _QUARANTINED_PLUGIN_ID in line and _SPAWN_PRIMITIVE.search(line):
                offenders.append(f"{rel}:{lineno}: {stripped}")

    assert not offenders, (
        "A live spawn naming the quarantined-LLM plugin id was added while "
        "sandbox egress is UNRESTRICTED (#230). Land the egress allowlist first. "
        "Offending lines:\n  " + "\n  ".join(offenders)
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

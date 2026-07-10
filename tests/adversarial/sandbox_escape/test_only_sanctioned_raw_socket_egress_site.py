"""Ratchet: control_fd_broker.py is the SOLE in-core site that connects an INET socket AND passes a
descriptor via sendmsg(SCM_RIGHTS) in the same module (#340 PR2a, ADR-0050).

Pinned on the CONJUNCTION (sec-001): a `.connect(...)` / `create_connection(...)` call, AND a
`sendmsg(..., SCM_RIGHTS, ...)` call, in the SAME module — either half alone is a bad discriminator.
`sendmsg(SCM_RIGHTS)` alone would not distinguish an egress site from a receiver (the docker probe
in Task 4 RECEIVES a passed fd via `recvmsg`, never `sendmsg`s one). `.connect`/`create_connection`
alone is pervasive in-core (SQLAlchemy/psycopg connection-pool `.connect()` calls are unrelated to
raw-socket egress) — so the connect matcher is DELIBERATELY loose (any `.connect`/
`create_connection` call, no AF_INET/AF_INET6-socket-construction companion check; see
`_has_inet_connect` docstring for why that companion check would be dead code) and the conjunction
with `sendmsg(SCM_RIGHTS)` is what does the real narrowing: none of the in-core DB-connect call
sites also `sendmsg` an SCM_RIGHTS ancillary, so the broader match does not false-positive today.

A documented AST residual in the ADR-0042 tradition: an obfuscated raw-socket egress evading the
match (e.g. via `getattr`-indirection or a C-extension call) is the accepted static-analysis gap,
backstopped by the quarantine child's empty network namespace (Spec C G7-1, `--unshare-net`). A NEW
file matching the conjunction outside the sanctioned broker trips this red.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SRC_ROOT = Path(__file__).resolve().parents[3] / "src" / "alfred"
_SANCTIONED = {"egress/control_fd_broker.py"}
_MIN_SRC_FILES = 100  # floor so a broken _SRC_ROOT fails loud, not vacuously


def _has_scm_rights_sendmsg(tree: ast.AST) -> bool:
    """True iff the module calls ``<obj>.sendmsg(...)`` with an SCM_RIGHTS ancillary attribute
    referenced anywhere inside that call's arguments."""
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "sendmsg"
            and any(
                isinstance(sub, ast.Attribute) and sub.attr == "SCM_RIGHTS"
                for sub in ast.walk(node)
            )
        ):
            return True
    return False


def _has_inet_connect(tree: ast.AST) -> bool:
    """True iff the module calls ``.connect(...)`` or ``create_connection(...)`` anywhere.

    [#340 PR2a fold-log L-1] Deliberately NOT additionally gated on an AF_INET/AF_INET6
    socket-construction companion: the conjunction with ``_has_scm_rights_sendmsg`` at the test
    level is what narrows the match (see module docstring) — an AF_INET-companion check here would
    be unreachable dead code, since every candidate that matters is already disambiguated by the
    sendmsg(SCM_RIGHTS) pairing.
    """
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"connect", "create_connection"}
        for node in ast.walk(tree)
    )


def test_only_sanctioned_raw_socket_egress_site() -> None:
    files = sorted(_SRC_ROOT.rglob("*.py"))
    assert len(files) >= _MIN_SRC_FILES, f"src scan too small ({len(files)}) — _SRC_ROOT broken?"
    offenders: list[str] = []
    for path in files:
        rel = path.relative_to(_SRC_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if _has_scm_rights_sendmsg(tree) and _has_inet_connect(tree) and rel not in _SANCTIONED:
            offenders.append(rel)
    assert not offenders, (
        "new raw-socket-egress site(s) outside the sanctioned broker (ADR-0050): "
        f"{offenders}. Route gateway reachability through egress/control_fd_broker.py."
    )


def test_sanctioned_site_actually_matches_the_conjunction() -> None:
    """Anti-rot [#340 PR2a fold-log M-4]: the sanctioned site must genuinely trip BOTH matcher
    halves of the conjunction.

    Without this, a future refactor that renames ``create_connection``/``sendmsg`` in
    ``control_fd_broker.py`` (or otherwise moves the calls out of AST-visible shape) would silently
    make the ratchet vacuously permissive — it would pass because NOTHING matches the conjunction
    any more, not because the invariant holds. Mirrors
    ``test_sanctioned_spawn_site_actually_exists`` in the sibling quarantined-LLM-spawn guard
    (``test_quarantined_llm_not_yet_spawned_while_egress_open.py``).
    """
    site = _SRC_ROOT / "egress" / "control_fd_broker.py"
    tree = ast.parse(site.read_text(encoding="utf-8"))
    assert _has_scm_rights_sendmsg(tree), (
        "the sanctioned site no longer trips the sendmsg(SCM_RIGHTS) matcher — the allowlist entry "
        "is stale; revisit the ratchet"
    )
    assert _has_inet_connect(tree), (
        "the sanctioned site no longer trips the connect matcher — the allowlist entry is stale; "
        "revisit the ratchet"
    )

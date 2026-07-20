"""#340 PR2b-golive — the POSIX-only per-test ``skipif`` guards are win32-exact.

Companion to ``test_posix_only_collect_ignore.py``: that module pins the
whole-file ``collect_ignore`` list, this one pins the *per-test* guards used on
MIXED files (some tests portable, some POSIX-only) — the shape
``tests/_posix_only_tests.py`` mandates for exactly those files.

Why this exists: the Windows unit leg is a BLOCKING gate with an assert-RAN floor
(#246 Phase B, #245 discipline), so an over-broad guard is not a harmless
over-skip — it silently hollows the gate. A predicate written as
``sys.platform != "linux"`` reads plausibly and would skip the guarded test on
macOS *and* Windows while still looking guarded in review. The win32 branch of
every such predicate never executes on a dev box or the Linux/macOS CI legs, so
nothing else would catch it.

Two properties, both checkable from a POSIX host:

* **win32-exact** (AST, repo-wide) — a ``POSIX-only:`` guard may only use a
  predicate that is true on Windows and FALSE everywhere else.
* **still runs here** (runtime) — the guards added for the brokered-egress /
  fd-broker surfaces evaluate to ``False`` on this host, so they are guarding
  Windows rather than quietly disabling themselves on POSIX.
"""

from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path
from typing import Final

import pytest

_TESTS_ROOT: Final = Path(__file__).resolve().parents[2]  # tests/

# The only predicates a `POSIX-only:` guard may use. Both are true on Windows and
# false on every POSIX host; `ast.unparse` normalises string quoting to single.
# `hasattr(socket, "AF_UNIX")` is the capability-shaped equivalent of the platform
# check — CPython exposes AF_UNIX on POSIX only.
_SANCTIONED_PREDICATES: Final[frozenset[str]] = frozenset(
    {
        "sys.platform == 'win32'",
        "not hasattr(socket, 'AF_UNIX')",
    }
)

# Guards added by #340 PR2b-golive, as (module, test function name). These became
# visible only once the Windows leg got past COLLECTION (the socket.CMSG_SPACE
# module-scope hoist, since fixed), so they had never actually executed there.
_GUARDED: Final[tuple[tuple[str, str], ...]] = (
    (
        "tests.unit.egress.test_control_fd_broker",
        "test_send_one_blocked_sendmsg_is_bounded_not_indefinite",
    ),
    (
        "tests.unit.egress.test_control_fd_broker",
        "test_send_one_on_a_torn_down_control_channel_still_raises_the_typed_error",
    ),
    (
        "tests.unit.security.test_brokered_egress_transport",
        "test_build_child_client_verifies_tls_against_the_system_store",
    ),
    (
        "tests.unit.security.test_brokered_egress_transport",
        "test_build_child_client_is_single_use_no_keepalive_no_retry",
    ),
    (
        "tests.unit.security.test_brokered_provider_source",
        "test_factory_build_resolves_read_timeout",
    ),
)


def _posix_only_skipif_predicates() -> list[tuple[Path, int, str]]:
    """Every ``skipif`` whose reason marks it POSIX-only, as (file, lineno, predicate).

    Walks all ``ast.Call`` nodes rather than just decorator lists so the
    ``pytestmark = pytest.mark.skipif(...)`` and ``pytestmark = [..., skipif]``
    module-level forms are covered by the same pass.
    """
    found: list[tuple[Path, int, str]] = []
    for path in sorted(_TESTS_ROOT.rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "skipif"):
                continue
            reason = next(
                (
                    kw.value.value
                    for kw in node.keywords
                    if kw.arg == "reason" and isinstance(kw.value, ast.Constant)
                ),
                None,
            )
            if not (isinstance(reason, str) and reason.startswith("POSIX-only")):
                continue
            if not node.args:  # a reason-only skipif cannot gate anything
                found.append((path, node.lineno, "<no predicate>"))
                continue
            found.append((path, node.lineno, ast.unparse(node.args[0])))
    return found


def test_posix_only_guards_use_a_win32_exact_predicate() -> None:
    """A `POSIX-only:` guard must not skip on any POSIX host (anti-gate-hollowing)."""
    guards = _posix_only_skipif_predicates()
    # Anti-vacuity: this assertion is worthless if the walk found nothing.
    assert len(guards) > 100, f"expected the repo's many POSIX-only guards, found {len(guards)}"
    offenders = [
        f"{path.relative_to(_TESTS_ROOT)}:{lineno} -> {pred}"
        for path, lineno, pred in guards
        if pred not in _SANCTIONED_PREDICATES
    ]
    assert not offenders, (
        "POSIX-only skipif guards must use a win32-exact predicate "
        f"(one of {sorted(_SANCTIONED_PREDICATES)}); an over-broad predicate silently "
        "hollows the blocking Windows gate (#246 Phase B). Offenders: " + "; ".join(offenders)
    )


@pytest.mark.skipif(sys.platform == "win32", reason="asserts the guards are INACTIVE off Windows")
@pytest.mark.parametrize(("module_name", "test_name"), _GUARDED)
def test_added_guards_are_inactive_on_this_posix_host(module_name: str, test_name: str) -> None:
    """The #340 guards must leave their tests RUNNING on POSIX, not disable them everywhere.

    ``skipif`` evaluates its predicate at decoration time, so the stored arg is already
    the resolved bool — ``False`` here proves the guarded test is collected and executed
    on this host, which is what keeps the Linux/macOS legs the real signal for these
    POSIX-only surfaces.
    """
    module = importlib.import_module(module_name)
    func = getattr(module, test_name)
    skipifs = [mark for mark in getattr(func, "pytestmark", []) if mark.name == "skipif"]
    assert skipifs, f"{module_name}::{test_name} lost its win32 guard"
    for mark in skipifs:
        assert mark.args[0] is False, (
            f"{module_name}::{test_name} is being SKIPPED on {sys.platform} — "
            "the guard is over-broad, not win32-exact"
        )

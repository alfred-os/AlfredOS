"""Every literal-key ``t()`` call passes the kwargs its catalog template needs.

``alfred.i18n.t`` swallows ``KeyError`` / ``IndexError`` from ``str.format`` and
returns the UNSUBSTITUTED template (see :func:`alfred.i18n.translator.t`). That
fallback is deliberate — a missing kwarg must not turn an operator message into a
traceback — but it converts a developer error into a silent operator-facing leak:
the operator reads a literal ``{detail}`` where the reason should be.

UAT reproduced exactly that on the #340 golive branch::

    PoliciesSnapshotRef initialisation failed: {detail}. Refusing to boot.
    Inspect config/policies.yaml for parse errors and re-run `alfred daemon start`.

The refusal named a placeholder instead of a reason, so the operator learned
nothing about WHY the boot was refused.

``tests/unit/cli/test_i18n_key_coverage.py`` already carries an i18n-002
placeholder-leak guard, but it is a HAND-MAINTAINED fingerprint list scoped to the
CLI ``config`` / ``web`` surfaces — the daemon-boot keys were never in it, which is
why both leaks shipped. This test is the CLOSURE guard: it walks every ``t()`` call
with a literal key under ``src/alfred`` AND the top-level ``plugins/`` tree — the
actual plugin packages (``alfred_tui``, ``alfred_discord``, et al.; production code
only, ``tests/`` directories excluded) — resolves the msgstr from the shipped
catalog, and asserts the template's ``{placeholder}`` set is covered by the call's
keyword arguments. Nothing has to be added by hand when a new key lands.

**Two directories are both named "plugins".** ``src/alfred/plugins/`` (walked as
part of the ``src/alfred`` root) and the top-level ``plugins/`` directory (the
actual plugin packages, walked as its own root) are unrelated. ``_ANCHOR_MODULES``
entries are keyed by ``(root_label, path_relative_to_that_root)`` — see ``_ROOTS``
— rather than a bare path string, so the two cannot collide: an anchor under
``src/alfred/plugins/`` and an anchor under the top-level ``plugins/`` tree can
share the same relative-path text without meaning the same file.

**Why the anchor modules are exempt.** The ``_*_reserve.py`` / ``_*_i18n.py``
modules call ``t(key)`` with no kwargs ON PURPOSE — they exist so ``pybabel
extract`` sees a static reference for keys whose real call site is elsewhere (or
not yet written). Their return values are discarded and never reach an operator,
so an unsubstituted template there is inert. They are exempted by MODULE, not by
key, so a real call site that forgets its kwargs still fails even when an anchor
for the same key exists.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Final

import pytest

from alfred.i18n import t

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_SRC: Final[Path] = _REPO_ROOT / "src" / "alfred"
_PLUGINS: Final[Path] = _REPO_ROOT / "plugins"

#: Roots this guard walks, each tagged with a label used to key
#: ``_ANCHOR_MODULES`` (see below) and to look a root back up by label in
#: ``test_every_exempt_anchor_module_exists``.
_ROOTS: Final[tuple[tuple[str, Path], ...]] = (
    ("src", _SRC),
    ("plugins", _PLUGINS),
)

#: Modules whose ``t()`` calls are pybabel-visibility ANCHORS, not operator output.
#: Every entry discards the returned string. See the module docstring. Keyed by
#: ``(root_label, path_relative_to_that_root)`` so the existing
#: ``("src", "plugins/_launcher_i18n.py")`` / ``("src", "plugins/_sandbox_i18n.py")``
#: entries — which live under ``src/alfred/plugins/`` — cannot collide with a
#: future anchor under the unrelated, top-level ``plugins/`` tree (label
#: ``"plugins"``).
_ANCHOR_MODULES: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("src", "i18n/_339_pr4b_broker_reserve.py"),
        ("src", "i18n/_deferred_key_anchors.py"),
        ("src", "i18n/_slice_4_reserve.py"),
        ("src", "i18n/_spec_b_reserve.py"),
        ("src", "i18n/_spec_c_reserve.py"),
        ("src", "plugins/_launcher_i18n.py"),
        ("src", "plugins/_sandbox_i18n.py"),
    }
)

#: ``str.format`` field names: ``{name}``, ``{name!r}``, ``{name:>8}``. Positional
#: (``{}`` / ``{0}``) fields are not used in this catalog and are ignored — the
#: leading-identifier requirement filters them out.
_FIELD: Final[re.Pattern[str]] = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)[^}]*\}")


def _is_test_path(rel: str) -> bool:
    """True if the root-relative posix path ``rel`` has a ``tests`` component.

    ``src/alfred`` has no ``tests`` subdirectory today, so this is a no-op for that
    root. It matters for the top-level ``plugins/`` tree: ``plugins/alfred_tui/
    tests/`` holds test code, not operator output, and must not be walked.
    """
    return "tests" in Path(rel).parts


def _t_calls() -> list[tuple[Path, int, str, set[str], bool]]:
    """Yield ``(path, lineno, key, kwarg_names, has_double_star)`` per literal ``t()`` call.

    Walks both ``_ROOTS``: ``src/alfred`` and the top-level ``plugins/`` tree, where
    the actual plugin packages live (``alfred_tui`` uses a ``src/`` sublayout;
    ``alfred_discord``, ``alfred_web_fetch``, etc. are flat) — production code only.
    """
    found: list[tuple[Path, int, str, set[str], bool]] = []
    for label, root in _ROOTS:
        for path in sorted(root.rglob("*.py")):
            rel = path.relative_to(root).as_posix()
            if _is_test_path(rel) or (label, rel) in _ANCHOR_MODULES:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if not isinstance(node.func, ast.Name) or node.func.id != "t":
                    continue
                if not node.args or not isinstance(node.args[0], ast.Constant):
                    continue
                key = node.args[0].value
                if not isinstance(key, str):
                    continue
                names = {kw.arg for kw in node.keywords if kw.arg is not None}
                has_star = any(kw.arg is None for kw in node.keywords)
                found.append((path, node.lineno, key, names, has_star))
    return found


def test_the_walker_finds_the_daemon_boot_call_sites() -> None:
    """Guard the guard: an AST walk that silently matched nothing would pass vacuously.

    Both boot-probe refusals are the sites UAT caught, so pinning them by name proves
    the walker reaches ``src/alfred/cli/daemon/_commands.py`` and unpacks its kwargs.
    ``tui.turn_timeout`` is pinned the same way for the ``plugins/`` root: it lives in
    ``plugins/alfred_tui/src/alfred_tui/textual/app.py`` (PR #594), so its presence
    proves the walker reaches the top-level ``plugins/`` tree too, not just
    ``src/alfred``.
    """
    keys = {key for _, _, key, _, _ in _t_calls()}
    assert "daemon.boot.snapshot_ref_init_failed" in keys
    assert "daemon.boot.capability_gate_handshake_failed" in keys
    assert "tui.turn_timeout" in keys
    assert len(keys) > 100, "walker collected implausibly few keys — check the glob"


@pytest.mark.parametrize("anchor", sorted(_ANCHOR_MODULES))
def test_every_exempt_anchor_module_exists(anchor: tuple[str, str]) -> None:
    """A renamed/deleted anchor must not silently widen the exemption to nothing.

    Without this, a stale entry would sit in ``_ANCHOR_MODULES`` forever and a future
    module reusing the old path would inherit an exemption nobody granted.
    """
    label, rel = anchor
    root = dict(_ROOTS)[label]
    assert (root / rel).is_file(), f"exempt anchor module no longer exists: {label}:{rel}"


def test_no_t_call_omits_a_kwarg_its_template_requires() -> None:
    """Every literal-key ``t()`` call covers its template's placeholders.

    Fails with the full offender list rather than the first one so a catalog-wide
    regression is fixed in one pass.
    """
    offenders: list[str] = []
    for path, lineno, key, names, has_star in _t_calls():
        if has_star:
            # ``t(key, **mapping)`` — the keys are not statically known. Not a leak
            # signal we can decide here; the runtime fallback still applies.
            continue
        rendered = t(key)
        if rendered == key:
            # No catalog entry (or an empty msgstr). Key-presence is a different
            # guard's job (test_catalog_*_keys.py); silence here avoids double-reporting.
            continue
        required = set(_FIELD.findall(rendered))
        missing = required - names
        if missing:
            # Repo-root-relative (not root-relative): unambiguous between
            # ``src/alfred/plugins/`` and the unrelated top-level ``plugins/`` tree.
            offenders.append(
                f"{path.relative_to(_REPO_ROOT).as_posix()}:{lineno} t({key!r}) "
                f"missing kwargs {sorted(missing)}"
            )
    assert not offenders, (
        "t() call sites whose catalog template needs kwargs they do not pass. "
        "alfred.i18n.t swallows the KeyError and returns the RAW template, so each of "
        "these renders a literal {placeholder} to an operator:\n  " + "\n  ".join(offenders)
    )

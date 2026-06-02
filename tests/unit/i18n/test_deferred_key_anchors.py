"""Verify every deferred-key anchor is present in the compiled .mo catalog.

R7 (PR-S3-6 polish): :mod:`alfred.i18n._deferred_key_anchors` exists
solely to keep deferred CLI surfaces' spec §11.5 i18n keys alive in
the catalog while their live :func:`t` call sites are unimplemented.
If the anchor module drifts out of sync with the catalog — a key is
added to the anchor list but missing from ``locale/en/LC_MESSAGES/alfred.po``,
or removed from the catalog without dropping the anchor — the
deferred PR's preview build will surface the bare key string to the
operator.

This test parses the anchor source for the literal ``t("…")``
arguments, then asserts each one resolves to a non-bare-key translation
via the actual production :func:`alfred.i18n.t` resolver. That doubles
as a smoke test for the resolver itself: a broken locale-dir lookup or
a stale compiled ``.mo`` fails the assertion the same way a missing
msgid does.

Why parse the source instead of calling :func:`_anchor_deferred_keys`
directly: the helper returns the *rendered* strings, not the keys.
For an entry whose msgstr is missing the renderer returns the bare
key, which would silently pass an equality check. Parsing the AST
recovers the literal msgid arguments so the assertion compares
"key X is missing" against the production resolver's actual output.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from alfred.i18n import set_language, t

ANCHOR_MODULE = (
    Path(__file__).resolve().parents[3] / "src" / "alfred" / "i18n" / "_deferred_key_anchors.py"
)


def _extract_anchored_msgids(source_path: Path) -> tuple[str, ...]:
    """Walk the anchor module's AST and return every ``t("…")`` first-arg literal.

    Only literal-string first arguments are returned; the anchor module
    is designed to contain nothing but literal-string calls so the
    extractor (pybabel) can see them. A non-literal slipping in is a
    bug — the calling test then sees an empty tuple and fails loudly
    (an empty anchor list defeats the module's purpose).
    """
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Name) and node.func.id == "t"):
            continue
        if not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            found.append(first.value)
    return tuple(found)


_ANCHORED_KEYS: tuple[str, ...] = _extract_anchored_msgids(ANCHOR_MODULE)


@pytest.fixture(autouse=True)
def _pin_english() -> None:
    """Pin the resolver to en-US.

    Other tests in the suite swap the active language. Without an
    explicit reset the presence check could run against a catalog
    that genuinely lacks the key (e.g. a partial future fr-FR
    catalog) and fail for an unrelated reason.
    """
    set_language("en-US")


def test_anchor_module_has_entries() -> None:
    """Loud failure if the anchor list was deleted without dropping the module.

    An empty anchor list is a contradiction-in-terms: the module's
    only reason to exist is to anchor at least one deferred key.
    Catching the empty case here means a future cleanup that drops
    the last entry must also delete the module + this test, instead
    of leaving a load-bearing-but-empty file behind.
    """
    assert _ANCHORED_KEYS, (
        "alfred.i18n._deferred_key_anchors contains no literal t(...) calls. "
        "Either drop the module entirely (and this test) or restore the "
        "anchor calls — an empty anchor list defeats the module's purpose."
    )


@pytest.mark.parametrize("anchored_key", _ANCHORED_KEYS)
def test_anchored_key_present_in_compiled_catalog(anchored_key: str) -> None:
    """Each anchored key resolves to a real translation, not the bare key.

    :func:`alfred.i18n.t` falls back to the input key when the message
    is missing from the compiled ``.mo``. That fallback is the exact
    failure mode this anchor module is designed to prevent — an
    operator on a preview build of the deferred PR seeing ``cli.plugin
    .list.column.plugin_id`` instead of ``plugin_id``. Asserting
    ``result != anchored_key`` catches it before the operator does.

    The compiled catalog must be up-to-date for this test to pass.
    ``make check`` runs ``pybabel compile`` as part of the i18n gate,
    so the standard developer flow keeps this honest.
    """
    rendered = t(anchored_key)
    assert rendered != anchored_key, (
        f"i18n key {anchored_key!r} is anchored in "
        f"alfred.i18n._deferred_key_anchors but missing from the compiled "
        f"catalog. Add the msgid to locale/en/LC_MESSAGES/alfred.po + run "
        f"`pybabel compile -d locale -D alfred`."
    )
    assert rendered.strip(), (
        f"i18n key {anchored_key!r} resolved to whitespace — msgstr is "
        f"present but empty. Populate the msgstr in "
        f"locale/en/LC_MESSAGES/alfred.po."
    )

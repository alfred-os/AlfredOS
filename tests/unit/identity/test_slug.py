"""Unit tests for ``alfred.identity.slug.derive_slug``.

Covers the documented pipeline: NFKC → unidecode → lowercase → non-alphanum
collapse → trim/collapse hyphens → 63-char truncate → empty-fallback.

Collision suffixing is intentionally NOT exercised here — that lives in
``IdentityResolver.add`` (PR A T11) because it needs a database session to
detect collisions. ``derive_slug`` is a pure transformation.
"""

from __future__ import annotations

import pytest

from alfred.identity.slug import derive_slug


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Alice O'Connor", "alice-o-connor"),
        ("José Núñez", "jose-nunez"),
        ("田中", "tian-zhong"),
        ("___bob---", "bob"),
        ("🌟🎉", "user"),
        ("___", "user"),
        ("operator", "operator"),
        ("Bruce Wayne", "bruce-wayne"),
        ("Ａlice", "alice"),  # noqa: RUF001 — fullwidth A (U+FF21) is the NFKC test input
        ("alice---bob", "alice-bob"),
        ("  Alice  ", "alice"),
        ("a" * 100, "a" * 63),
    ],
)
def test_derive_slug(raw: str, expected: str) -> None:
    assert derive_slug(raw) == expected


def test_derive_slug_truncates_before_collision_suffix() -> None:
    """The 63-char cap applies to the canonical slug itself.

    Collision suffixing (e.g. ``-2``) is appended *after* ``derive_slug``
    returns, by ``IdentityResolver.add`` (PR A T11). This test pins the
    pre-suffix length so the resolver can reason about its own budget.
    """
    assert len(derive_slug("a" * 100)) == 63

"""Canonical user_id derivation: name → slug.

Pure, deterministic, side-effect-free pipeline. Collision detection and
suffixing (``-2``, ``-3``, …) live in ``IdentityResolver.add`` because they
require a database session; this module never does I/O.

Pipeline:

1. **NFKC** — Unicode normalisation so visually-equivalent codepoints
   (e.g. fullwidth U+FF21 vs ASCII U+0041) collapse.
2. **unidecode** — ASCII transliteration. ``José`` → ``Jose``; ``田中`` →
   ``Tian Zhong``; emoji → ``""``.
3. **lowercase** — slugs are case-insensitive.
4. **non-alphanum → ``-``** — any run of characters outside ``[a-z0-9]``
   becomes a single hyphen.
5. **trim / collapse hyphens** — leading and trailing hyphens removed; the
   regex in step 4 already collapses internal runs.
6. **truncate to 63 chars** — Postgres ``citext`` columns have no inherent
   limit but a CHECK constraint enforces ≤ 63 (see PR A T6 / T7).
7. **empty-fallback** — if the pipeline yields the empty string (emoji-only
   input, all-punctuation input), return ``"user"``.

The 63-char cap is enforced *before* any collision suffix is appended, so
``IdentityResolver.add`` can budget the suffix room independently.
"""

from __future__ import annotations

import re
import unicodedata

from unidecode import unidecode

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_SLUG_MAX = 63
_EMPTY_FALLBACK = "user"


def derive_slug(name: str) -> str:
    """Derive a canonical slug from ``name``. Pure function; see module docstring."""
    step1 = unicodedata.normalize("NFKC", name)
    step2 = unidecode(step1)
    step3 = step2.lower()
    step4 = _SLUG_RE.sub("-", step3)
    step5 = step4.strip("-")
    if not step5:
        return _EMPTY_FALLBACK
    return step5[:_SLUG_MAX]

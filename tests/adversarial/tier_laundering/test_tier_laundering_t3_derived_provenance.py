"""Adversarial tier_laundering — T3DerivedData provenance survival.

Verifies that the ``T3DerivedData`` ``NewType`` survives serialisation
round-trips and that the type-level provenance label is not accidentally
erased by routine dict operations. Spec §3.7, §12.2, §12.3.

``NewType`` is a Slice-3 lightweight discriminant: at runtime the value
IS the underlying ``dict[str, object]``. The discriminant lives in the
type system — callers receiving ``T3DerivedData`` are obliged to treat
the dict as provenance-marked, and the CI grep gate
(``scripts/check_tag_t3.py``) rejects ``cast(TaggedContent[`` patterns
that erase the closely-related ``TaggedContent`` generics. The
``cast(dict, t3_data)`` erasure is an acknowledged gap in the current
gate; this module documents the gap rather than silently passing.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from alfred.security.quarantine import T3DerivedData


def test_t3_derived_data_newtype_is_preserved_by_assignment() -> None:
    """Assigning a ``T3DerivedData`` to a new binding preserves the type label.

    NewType is a Slice-3 lightweight discriminant. At runtime it is a
    plain ``dict``. This test documents the design intent: callers that
    receive ``T3DerivedData`` must treat it as provenance-marked. Spec §3.7.
    """
    data: T3DerivedData = T3DerivedData({"title": "Article", "url": "https://x.com"})
    # NewType at runtime is just the underlying type.
    assert isinstance(data, dict)
    # The value is preserved through assignment.
    copy: T3DerivedData = T3DerivedData(dict(data))
    assert copy == data
    # And the keys we put in are exactly the keys we get out.
    assert set(copy.keys()) == {"title", "url"}


def test_t3_derived_data_survives_json_round_trip() -> None:
    """``T3DerivedData`` survives a JSON serialisation round-trip.

    The ``NewType`` survives because the caller re-wraps with
    ``T3DerivedData()`` after deserialisation. This is the pattern that
    PR-S3-4's DB write/read round-trip must follow. Spec §12.3.
    """
    original: T3DerivedData = T3DerivedData(
        {"title": "Test", "summary": "A summary of the article."}
    )
    serialised = json.dumps(original)
    raw_dict: dict[str, object] = json.loads(serialised)
    restored: T3DerivedData = T3DerivedData(raw_dict)
    assert restored == original
    assert isinstance(restored, dict)
    # The summary field round-tripped intact (no truncation, no escaping
    # drift, no key reordering invariants violated).
    assert restored["summary"] == "A summary of the article."


def test_t3_derived_data_cast_tagged_content_erasure_is_rejected_by_ci_rule(
    tmp_path: Path,
) -> None:
    """``cast(TaggedContent[`` erasure is caught by the CI grep gate.

    The current gate (``scripts/check_tag_t3.py``) catches
    ``cast(TaggedContent[`` patterns; this test pins that detection so
    the gate's pattern set cannot regress without a failing test.

    The closely-related ``cast(dict, t3_data)`` erasure (which would
    drop the ``T3DerivedData`` NewType to a plain dict) is an
    acknowledged gap — the current grep pattern set does NOT detect it.
    Closing that gap is tracked as a Slice-3 follow-on: either expand
    ``_VIOLATIONS`` in ``scripts/check_tag_t3.py`` to include
    ``cast(\\s*dict\\s*,`` adjacent to a ``T3DerivedData`` binding, or
    introduce a NewType-aware AST pass. This test documents the gap
    rather than silently passing.

    Spec §3.7.
    """
    repo_root = Path(__file__).parent.parent.parent.parent

    # File 1: cast(TaggedContent[ — the gate MUST flag this.
    tagged_erasure = tmp_path / "tagged_erasure.py"
    tagged_erasure.write_text(
        "from typing import cast\n"
        "from alfred.security.tiers import TaggedContent, T2\n"
        "x = cast(TaggedContent[T2], some_t3_object)\n"
    )
    result = subprocess.run(  # noqa: S603 — sys.executable + literal script path under our control
        [sys.executable, "scripts/check_tag_t3.py", str(tagged_erasure)],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
        check=False,
    )
    assert result.returncode != 0, (
        f"Expected CI rule to flag cast(TaggedContent[; got 0.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )

    # File 2: cast(dict, t3_data — acknowledged gap. The grep gate does
    # NOT currently catch this; we assert the known behaviour so a future
    # gate extension flips the assertion (and the implementer updates the
    # test). The honest negative encodes the gap rather than hiding it.
    dict_erasure = tmp_path / "dict_erasure.py"
    dict_erasure.write_text(
        "from typing import cast\n"
        "from alfred.security.quarantine import T3DerivedData\n"
        "data: T3DerivedData = T3DerivedData({'title': 'x'})\n"
        "erased = cast(dict, data)  # This erases T3 provenance\n"
    )
    result = subprocess.run(  # noqa: S603 — sys.executable + literal script path under our control
        [sys.executable, "scripts/check_tag_t3.py", str(dict_erasure)],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
        check=False,
    )
    # KNOWN-GAP assertion: the current pattern set does NOT match
    # `cast(dict,`. If a future PR extends scripts/check_tag_t3.py to
    # detect this pattern, this assertion flips to `!= 0` and the
    # implementer updates the test (the strict-equality `== 0` plus the
    # KNOWN-GAP comment is the contract record).
    assert result.returncode == 0, (
        "KNOWN GAP: cast(dict, t3_data) is not yet detected by the CI rule. "
        "If this assertion fails because the gate was extended, update the "
        "assertion to `!= 0` and delete this comment block. "
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )

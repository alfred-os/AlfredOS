"""Coverage for ``scripts/check_tag_t3.py`` ``TaggedContent[T3](...)`` rule.

sec-S3-002: ``tag_t3_with_nonce`` checks the per-process nonce; the
Pydantic field validator on ``tier`` does NOT. A caller who bypasses
``tag_t3_with_nonce`` and constructs ``TaggedContent[T3](...)`` directly
slips raw T3 content past the gate. The CI grep gate refuses that
pattern in any non-approved file.

The pre-existing rules (``tag(T3, ...)``, ``cast(TaggedContent[...]``,
``# type: ignore`` on a ``TaggedContent`` line) are covered by
``tests/adversarial/tier_laundering/test_tier_laundering_cast_bypass.py``
and by structural-conformance tests under
``tests/unit/security/test_tag_t3_capability_gate.py``; this module
covers the new subscript-construction rule and the four shapes the AST
detector recognises.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# Repo root is four parents up: tests/unit/security/<file> -> tests/unit ->
# tests -> repo root.
_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_SCRIPT: Path = _REPO_ROOT / "scripts" / "check_tag_t3.py"


def _run(*args: Path) -> subprocess.CompletedProcess[str]:
    """Invoke the gate script under the current Python with ``args`` paths."""
    return subprocess.run(  # noqa: S603 - sys.executable + literal script path under our control
        [sys.executable, str(_SCRIPT), *(str(a) for a in args)],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        check=False,
    )


# ---------------------------------------------------------------------------
# Each shape the new detector recognises gets its own test so a future
# regression that re-narrows the detector to e.g. the bare-name form
# trips a single, named test rather than burying the failure in a
# parametrised id.
# ---------------------------------------------------------------------------


def test_bare_subscript_construction_is_flagged(tmp_path: Path) -> None:
    """``TaggedContent[T3](...)`` — the canonical bypass shape."""
    bad = tmp_path / "attacker.py"
    bad.write_text(
        "from alfred.security.tiers import TaggedContent, T3\n"
        "x = TaggedContent[T3](content='evil', source='wire', tier=T3)\n"
    )
    result = _run(bad)
    assert result.returncode != 0, (
        f"Expected gate to flag bare TaggedContent[T3](...); got 0.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "TaggedContent[T3](...) direct subscript" in result.stderr


def test_qualified_call_target_is_flagged(tmp_path: Path) -> None:
    """``tiers.TaggedContent[T3](...)`` — qualified module attribute target."""
    bad = tmp_path / "attacker.py"
    bad.write_text(
        "from alfred.security import tiers\n"
        "x = tiers.TaggedContent[tiers.T3](content='evil', source='wire', tier=tiers.T3)\n"
    )
    result = _run(bad)
    assert result.returncode != 0
    assert "TaggedContent[T3](...) direct subscript" in result.stderr


def test_qualified_subscript_slice_is_flagged(tmp_path: Path) -> None:
    """``TaggedContent[tiers.T3](...)`` — qualified attribute on the slice."""
    bad = tmp_path / "attacker.py"
    bad.write_text(
        "from alfred.security.tiers import TaggedContent\n"
        "from alfred.security import tiers\n"
        "x = TaggedContent[tiers.T3](content='evil', source='wire', tier=tiers.T3)\n"
    )
    result = _run(bad)
    assert result.returncode != 0
    assert "TaggedContent[T3](...) direct subscript" in result.stderr


def test_clean_file_passes(tmp_path: Path) -> None:
    """A file with no T3 patterns exits 0 — sanity check the gate isn't trip-happy."""
    clean = tmp_path / "innocent.py"
    clean.write_text(
        "from alfred.security.tiers import TaggedContent, T2\n"
        "x = TaggedContent[T2](content='hi', source='tui', tier=T2)\n"
    )
    result = _run(clean)
    assert result.returncode == 0, (
        f"Expected clean file to pass; got {result.returncode}.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_authorised_homes_are_exempt() -> None:
    """The script tolerates the real ``src/alfred/security/tiers.py`` body.

    The file's ``tag_t3_with_nonce`` function legitimately constructs
    ``TaggedContent[T3](...)``. The ``_APPROVED_PATHS`` exemption in
    the gate covers this; if the exemption silently breaks, the
    repo-wide invocation below trips.
    """
    result = _run(_REPO_ROOT / "src" / "alfred" / "security" / "tiers.py")
    assert result.returncode == 0, (
        f"Expected authorised home to pass; got {result.returncode}.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_other_subscripted_type_is_not_flagged(tmp_path: Path) -> None:
    """``OtherType[T3](...)`` and ``TaggedContent[OtherTier](...)`` do not trip.

    The detector is shape-specific: the subscripted callable must be
    ``TaggedContent`` AND the type argument must be ``T3``. A different
    callable or a different tier argument is none of this rule's
    business — those shapes are covered (or not) by other gates.
    """
    benign = tmp_path / "benign.py"
    benign.write_text(
        "class OtherType:\n"
        "    def __class_getitem__(cls, item):\n"
        "        return cls\n"
        "class T3: pass\n"
        "class T2: pass\n"
        "class TaggedContent:\n"
        "    def __class_getitem__(cls, item):\n"
        "        return cls\n"
        "x = OtherType[T3]()\n"
        "y = TaggedContent[T2]()\n"
    )
    result = _run(benign)
    assert result.returncode == 0, (
        f"Expected non-matching subscripts to pass; got {result.returncode}.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )

"""Adversarial tier_laundering corpus — cast-bypass + gc out-of-scope.

These tests require Python-level code execution and cannot be expressed
as YAML payloads alone. Spec §3.8, §12.2.

Per spec §12.2 fixture allocation:
- ``cast(TaggedContent[T2], t3_value)`` bypass → this module
- ``gc.get_objects()`` out-of-scope acknowledgement → this module
- Wire-format tier-confusion YAML existence cross-check → this module
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import cast

import yaml

from alfred.security.tiers import (
    T2,
    T3,
    CapabilityGateNonce,
    TaggedContent,
    tag_t3_with_nonce,
)


def test_cast_t2_of_t3_value_does_not_change_runtime_tier() -> None:
    """``cast(TaggedContent[T2], t3_value)`` is a type-system lie.

    At runtime, ``cast()`` is a no-op — the object's ``.tier`` attribute
    is unchanged. This confirms runtime tier tracking is robust against
    the cast bypass: the orchestrator reading ``.tier.name`` still sees
    "T3". The CI grep gate (``scripts/check_tag_t3.py``) catches the
    pattern at commit time. Spec §3.8.
    """
    nonce = CapabilityGateNonce()
    t3_value = tag_t3_with_nonce(
        "injected content",
        source="web.fetch",
        caller_token=nonce,
        _authorized_nonce=nonce,
    )
    assert t3_value.tier is T3

    # cast() is a type-system annotation with no runtime effect in CPython.
    # The bypass is the point of the test — we deliberately lie to the type
    # checker by claiming a TaggedContent[T2] value, then assert the lie does
    # not propagate to runtime state. The string-form generic suppresses the
    # mypy "type variable" complaint while keeping ruff and pyright happy.
    cast_result: TaggedContent[T2] = cast("TaggedContent[T2]", t3_value)
    # Runtime tier is STILL T3 despite the cast annotation.
    assert cast_result.tier is T3
    assert cast_result.tier.name == "T3"
    # T2 is imported solely to make the cast target name resolvable at
    # type-check time; this assertion proves the symbol is reachable.
    assert T2.name == "T2"


def test_ci_rule_rejects_cast_tagged_content(tmp_path: Path) -> None:
    """The CI grep gate flags ``cast(TaggedContent[`` in src/ files.

    Asserts the ``scripts/check_tag_t3.py`` script exits non-zero for a
    file containing ``cast(TaggedContent[``. Spec §3.3.
    """
    repo_root = Path(__file__).parent.parent.parent.parent

    bad_file = tmp_path / "attacker.py"
    bad_file.write_text(
        "from typing import cast\n"
        "from alfred.security.tiers import TaggedContent, T2\n"
        "x = cast(TaggedContent[T2], some_t3_object)\n"
    )

    result = subprocess.run(  # noqa: S603 — sys.executable + literal script path under our control
        [sys.executable, "scripts/check_tag_t3.py", str(bad_file)],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
        check=False,
    )
    assert result.returncode != 0, (
        f"Expected CI rule to reject cast(TaggedContent[; got 0.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_gc_traversal_out_of_scope_acknowledged() -> None:
    """The ``gc.get_objects()`` traversal attack is documented as out-of-scope.

    Asserts the YAML payload ``tl-2026-003`` exists, carries
    ``out_of_scope=true``, and has a non-empty ``out_of_scope_rationale``.
    Spec §3.2 threat-model limits.
    """
    yaml_path = Path(__file__).parent / "tl_gc_traversal_out_of_scope.yaml"
    assert yaml_path.exists(), "Missing adversarial payload tl_gc_traversal_out_of_scope.yaml"
    payload = yaml.safe_load(yaml_path.read_text())
    assert payload.get("out_of_scope") is True, (
        "gc.get_objects() payload must be marked out_of_scope=true"
    )
    rationale = (payload.get("out_of_scope_rationale") or "").strip()
    assert rationale, "gc.get_objects() payload must have a non-empty out_of_scope_rationale"


def test_wire_format_tier_confusion_yaml_exists() -> None:
    """The wire-format tier-confusion payload YAML exists in the corpus."""
    yaml_path = Path(__file__).parent / "tl_wire_tier_confusion.yaml"
    assert yaml_path.exists()
    payload = yaml.safe_load(yaml_path.read_text())
    assert payload["category"] == "tier_laundering"
    assert payload["ingestion_path"] == "wire_format_deser"

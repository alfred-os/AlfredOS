"""Tests for T1/T3 tier classes, nonce-gated tag(T3,...) factory,
and wire-format serializer/parser.

Depends on: PR-S3-0a audit_row_schemas.py (for T3_BOUNDARY_REFUSAL_FIELDS),
PR-S3-0b i18n catalog (security.tag_t3_unauthorized key).
"""

from __future__ import annotations

import re
import typing
from pathlib import Path

import pytest

from alfred.security.tiers import (
    _APPROVED_TIERS,
    T0,
    T1,
    T2,
    T3,
    AnyTaggedContent,
    CapabilityGateNonce,
    TaggedContent,
    TrustTier,
    tag,
    tag_t3_with_nonce,
)


def test_t1_class_name() -> None:
    assert T1.name == "T1"
    assert issubclass(T1, TrustTier)


def test_t3_class_name() -> None:
    assert T3.name == "T3"
    assert issubclass(T3, TrustTier)


def test_approved_tiers_contains_all_four() -> None:
    assert frozenset({T0, T1, T2, T3}) == _APPROVED_TIERS


def test_any_tagged_content_protocol_accepts_t0() -> None:
    """TaggedContent[T0] satisfies AnyTaggedContent structurally."""

    def _observer(c: AnyTaggedContent) -> str:
        return c.tier.name

    tagged = TaggedContent[T0](content="sys", source="test", tier=T0)
    assert _observer(tagged) == "T0"


def test_any_tagged_content_protocol_accepts_t2() -> None:
    tagged = TaggedContent[T2](content="hello", source="test", tier=T2)
    # AnyTaggedContent is a Protocol — structural typing, no cast needed
    result: AnyTaggedContent = tagged
    assert result.tier.name == "T2"


def test_any_tagged_content_has_no_content_mutation() -> None:
    """AnyTaggedContent is read-only: no setattr."""
    tagged = TaggedContent[T2](content="hello", source="test", tier=T2)
    result: AnyTaggedContent = tagged
    with pytest.raises((AttributeError, TypeError, ValueError)):
        result.content = "mutated"  # type: ignore[misc]


def test_tag_t1_returns_tagged_content_t1() -> None:
    """tag(T1, ...) routes through the shared body and returns a T1 envelope."""
    tc = tag(T1, "operator input", source="tui")
    assert tc.tier is T1
    assert tc.content == "operator input"


def test_tag_t1_type_roundtrip() -> None:
    """Wire-format round trip via the T1 overload preserves the tier name."""
    tc = tag(T1, "x", source="tui")
    dumped = tc.model_dump()
    assert dumped["tier"] == "T1"


def test_tag_t1_overload_is_registered() -> None:
    """A static @overload signature for tag(type[T1], ...) is registered.

    ``typing.get_overloads`` returns every @overload-decorated stub for
    a function. Spec §3.1 pins the typed overload as part of the public
    surface — without it, callers of tag(T1, ...) lose the
    TaggedContent[T1] return type and observers downstream lose static
    provenance.
    """
    overloads = typing.get_overloads(tag)
    overload_tier_params: list[type[TrustTier]] = []
    for ovl in overloads:
        hints = typing.get_type_hints(ovl)
        tier_hint = hints.get("tier")
        # ``tier`` is annotated as ``type[T_X]`` — the inner arg is the tier.
        if tier_hint is None:
            continue
        args = typing.get_args(tier_hint)
        if args:
            overload_tier_params.append(args[0])
    assert T1 in overload_tier_params, (
        f"tag() overloads must include a type[T1] variant; saw {overload_tier_params}"
    )


# ---------------------------------------------------------------------------
# tag(T3, ...) capability-gated factory — spec §3.2
# ---------------------------------------------------------------------------


def test_tag_t3_without_nonce_raises() -> None:
    """tag_t3_with_nonce with caller_token=None refuses construction.

    The error message contains the i18n key ``security.tag_t3_unauthorized``
    (the t() helper returns the key itself when the catalog entry is the
    untranslated source — see locale/en/LC_MESSAGES/alfred.po). Spec §3.2.
    """
    with pytest.raises(ValueError, match=re.escape("security.tag_t3_unauthorized")):
        tag_t3_with_nonce(
            "fetched html",
            source="web.fetch",
            caller_token=None,
        )


def test_tag_t3_with_wrong_nonce_raises() -> None:
    """A nonce that is a DIFFERENT OBJECT is rejected by the identity check.

    Two ``CapabilityGateNonce()`` instances pass an ``==`` test (they have
    no attributes) but fail the ``is`` check the gate uses. Spec §3.2.
    """
    nonce_a = CapabilityGateNonce()
    nonce_b = CapabilityGateNonce()  # different object
    with pytest.raises(ValueError, match=re.escape("security.tag_t3_unauthorized")):
        tag_t3_with_nonce(
            "x",
            source="test",
            caller_token=nonce_b,
            _authorized_nonce=nonce_a,
        )


def test_tag_t3_with_correct_nonce_succeeds() -> None:
    """The holder of the live nonce reference can tag T3 content. Spec §3.2."""
    nonce = CapabilityGateNonce()
    tc = tag_t3_with_nonce(
        "fetched html",
        source="web.fetch",
        caller_token=nonce,
        _authorized_nonce=nonce,
    )
    assert tc.tier is T3
    assert tc.content == "fetched html"


def test_tag_t3_imported_nonce_is_same_object() -> None:
    """Importing a module-level nonce yields the SAME object (CPython
    reference semantics) — this is the expected DI pattern.

    This documents why import-based forgery fails: importing a module-level
    nonce gives you the live reference, so two authorised modules sharing
    the same nonce holder pass the ``is`` check. An *unauthorised* module
    that constructs its own ``CapabilityGateNonce`` gets a different object
    and fails. Spec §3.2 threat model.
    """
    nonce = CapabilityGateNonce()
    # Simulate an authorised module holding the same reference.
    authorized_module_ref = nonce  # same object in same process
    assert authorized_module_ref is nonce  # passes `is` check
    # Simulate an unauthorised module constructing its own nonce.
    attacker_nonce = CapabilityGateNonce()
    assert attacker_nonce is not nonce  # fails `is` check


def test_tag_via_overload_t3_is_always_refused() -> None:
    """Direct callers using ``tag(T3, ...)`` (without the nonce) are refused.

    The shared ``tag()`` body routes T3 through ``tag_t3_with_nonce`` with
    ``caller_token=None``, which always raises. Only authorised call sites
    that invoke ``tag_t3_with_nonce`` directly (with their injected nonce)
    can tag T3 content. Spec §3.2.
    """
    with pytest.raises(ValueError, match=re.escape("security.tag_t3_unauthorized")):
        tag(T3, "fetched html", source="web.fetch")


# ---------------------------------------------------------------------------
# Bootstrap nonce factory — spec §3.2
# ---------------------------------------------------------------------------


def test_nonce_factory_sets_module_nonce() -> None:
    """Bootstrap factory sets the module-level authorised nonce.

    The nonce returned by the factory IS the live module-level reference
    (``alfred.security.tiers._AUTHORIZED_T3_NONCE``), not a copy. This
    pins the DI invariant: the factory's caller and the gate read the
    SAME object. Spec §3.2.
    """
    from alfred.bootstrap.nonce_factory import create_and_register_t3_nonce
    from alfred.security import tiers as tiers_mod

    # Reset to None, then bootstrap. The setter is the bootstrap seam
    # exposed for both production and tests; no global mutation here.
    tiers_mod._set_authorized_t3_nonce(None)
    nonce = create_and_register_t3_nonce()
    assert tiers_mod._AUTHORIZED_T3_NONCE is nonce


def test_orchestrator_type_signature_accepts_t1(monkeypatch: pytest.MonkeyPatch) -> None:
    """The orchestrator's handle_user_message signature accepts TaggedContent[T1].

    This test imports the function signature via ``inspect.signature`` to
    assert the annotation was widened, without running the full orchestrator.
    Spec §3.1 final paragraph: T1 (operator-via-TUI) ingress paths must
    reach the orchestrator; T3 stays excluded as the load-bearing invariant.
    """
    import inspect

    from alfred.orchestrator.core import Orchestrator

    sig = inspect.signature(Orchestrator.handle_user_message)
    content_param = sig.parameters.get("content")
    assert content_param is not None
    # The annotation should mention T1 (either as a string or resolved type)
    annotation = str(content_param.annotation)
    assert "T1" in annotation, (
        f"Expected 'T1' in orchestrator content annotation; got: {annotation}"
    )


# ---------------------------------------------------------------------------
# CI grep gate: scripts/check_tag_t3.py — spec §3.7-3.8
# ---------------------------------------------------------------------------

# Repo root resolved relative to this test file so the suite runs on any
# checkout / CI runner. test file lives at tests/unit/security/...
_REPO_ROOT = Path(__file__).parent.parent.parent.parent


def test_check_tag_t3_script_rejects_unauthorized_call(tmp_path: Path) -> None:
    """The CI script flags any non-approved src/ file containing ``tag(T3``.

    Spec §3.2 and §3.3.
    """
    import subprocess
    import sys

    # Write a violating file
    bad_file = tmp_path / "fake_orchestrator.py"
    bad_file.write_text("from alfred.security.tiers import T3, tag\ntag(T3, 'x')\n")

    result = subprocess.run(  # noqa: S603 — sys.executable + literal script path under our control
        [sys.executable, "scripts/check_tag_t3.py", str(bad_file)],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        check=False,
    )
    assert result.returncode != 0, (
        f"Expected non-zero exit for unauthorized tag(T3 call; got 0.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_check_tag_t3_script_allows_clean_file(tmp_path: Path) -> None:
    """A file with no disallowed pattern passes — using tag_t3_with_nonce is fine."""
    import subprocess
    import sys

    # A clean file: no `tag(T3,`, no `cast(TaggedContent[`, no TaggedContent + type-ignore.
    clean_file = tmp_path / "clean_module.py"
    clean_file.write_text(
        "from alfred.security.tiers import tag_t3_with_nonce\n"
        "# This module uses tag_t3_with_nonce with an injected nonce.\n"
        "# It contains no forbidden pattern, so the gate accepts it.\n"
    )
    result = subprocess.run(  # noqa: S603 — sys.executable + literal script path under our control
        [sys.executable, "scripts/check_tag_t3.py", str(clean_file)],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        check=False,
    )
    assert result.returncode == 0, (
        f"Expected 0 for clean file; got {result.returncode}.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_check_tag_t3_script_exempts_authorised_homes(tmp_path: Path) -> None:
    """The authorised homes (tiers.py, quarantine.py) are exempt by path.

    Per the PR-S3-1 briefing the authorised callers list is EXACTLY:
      - src/alfred/security/tiers.py   (the ``tag`` overload bodies)
      - src/alfred/security/quarantine.py (the downgrade boundary)
      - tests/unit/security/**         (tests assert the gate's behaviour)

    A synthetic path ending in ``src/alfred/security/tiers.py`` exercises the
    suffix-based exemption — even when the file contains a literal
    ``tag(T3,`` call site (which only those approved homes may contain).
    Spec §3.7-3.8.
    """
    import subprocess
    import sys

    nested = tmp_path / "src" / "alfred" / "security"
    nested.mkdir(parents=True)
    home = nested / "tiers.py"
    home.write_text(
        "from alfred.security.tiers import T3\n"
        "# Synthetic stand-in for the real tiers.py — the gate exempts this path.\n"
        "x = tag(T3, 'authorised use of the factory')\n"
    )
    result = subprocess.run(  # noqa: S603 — sys.executable + literal script path under our control
        [sys.executable, "scripts/check_tag_t3.py", str(home)],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        check=False,
    )
    assert result.returncode == 0, (
        f"Expected 0 for authorised home suffix; got {result.returncode}.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_check_tag_t3_script_clean_on_real_src_tree() -> None:
    """The script returns 0 when scanning the actual ``src/alfred/`` tree.

    This is the load-bearing assertion: shipping CI runs the script against
    the real source tree. If any non-approved file ever contains a
    ``tag(T3,`` or ``cast(TaggedContent[`` line, this test fires.
    """
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "scripts/check_tag_t3.py", "src/alfred"],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        check=False,
    )
    assert result.returncode == 0, (
        f"Expected 0 on real src/alfred tree; got {result.returncode}.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_check_tag_t3_script_rejects_cast_bypass(tmp_path: Path) -> None:
    """The CI script flags cast(TaggedContent[ in non-test src/ files.

    Spec §3.3.
    """
    import subprocess
    import sys

    bad_file = tmp_path / "bad_module.py"
    bad_file.write_text(
        "from typing import cast\n"
        "from alfred.security.tiers import TaggedContent, T2\n"
        "x = cast(TaggedContent[T2], some_t3_value)\n"
    )
    result = subprocess.run(  # noqa: S603 — sys.executable + literal script path under our control
        [sys.executable, "scripts/check_tag_t3.py", str(bad_file)],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        check=False,
    )
    assert result.returncode != 0, (
        f"Expected non-zero exit for cast(TaggedContent[ bypass; got 0.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )

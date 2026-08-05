"""Regression guard for the CPython gh-105936 frozen+slots dataclass bug.

CPython 3.14.0-3.14.4 generate a broken ``__setattr__``/``__delattr__`` for
``@dataclass(frozen=True, slots=True)``: assigning an *unknown* attribute raised
``TypeError: super(type, obj): obj must be an instance or subtype of type`` instead of
the correct ``FrozenInstanceError`` / ``AttributeError``. Measured broken on 3.14.0 and
3.14.4, fixed on 3.14.5 and 3.14.6. The fix (CPython GH-144021, reaching 3.14 via
GH-148469) was also backported to 3.13 (GH-148476), so this is long-standing, not a
3.14-only regression.

``pyproject.toml`` declares only a series-level ``requires-python = ">=3.14"`` — a
patch-level specifier there is what Dependabot cannot resolve (ADR-0061). The real floor,
held at 3.14.6 because that is the only patch any CI lane exercises, is enforced at
import by ``alfred._python_floor`` instead. This test locks the *behaviour* in and fails
loud if a future change ever reintroduces a buggy interpreter under that floor.

Ref: https://github.com/python/cpython/issues/105936
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, dataclass

import pytest


@dataclass(frozen=True, slots=True)
class _FrozenSlotted:
    value: int


class TestFrozenSlotsDataclassRegressionGuard:
    """The enforced 3.14.6 floor restores correct frozen+slots assignment semantics."""

    def test_unknown_attribute_assignment_is_not_the_gh105936_typeerror(self) -> None:
        instance = _FrozenSlotted(value=1)
        with pytest.raises((FrozenInstanceError, AttributeError)) as exc_info:
            instance.unknown = 2  # type: ignore[attr-defined]
        # The gh-105936 bug surfaced as a TypeError mentioning super(type, obj); the
        # correct behaviour raises FrozenInstanceError/AttributeError instead.
        assert not isinstance(exc_info.value, TypeError)
        assert "super(type, obj)" not in str(exc_info.value)

    def test_existing_field_assignment_still_raises_frozen_instance_error(self) -> None:
        instance = _FrozenSlotted(value=1)
        with pytest.raises(FrozenInstanceError):
            instance.value = 2  # type: ignore[misc]

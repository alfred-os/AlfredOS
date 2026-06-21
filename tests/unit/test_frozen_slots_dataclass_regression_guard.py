"""Regression guard for the CPython gh-135228 frozen+slots dataclass bug.

CPython 3.14.0-3.14.5 regressed ``@dataclass(frozen=True, slots=True)``: assigning an
*unknown* attribute raised ``TypeError: super(type, obj): obj must be an instance or
subtype of type`` instead of the correct ``FrozenInstanceError`` / ``AttributeError``.
That is why ``pyproject.toml`` pins ``requires-python = ">=3.14.6"`` — 3.14.6 restores the
correct behaviour. This test locks that behaviour in and fails loud if a future change
ever reintroduces a buggy interpreter under the project's floor.

Ref: https://github.com/python/cpython/issues/135228
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, dataclass

import pytest


@dataclass(frozen=True, slots=True)
class _FrozenSlotted:
    value: int


class TestFrozenSlotsDataclassRegressionGuard:
    """The 3.14.6 floor restores correct frozen+slots assignment semantics."""

    def test_unknown_attribute_assignment_is_not_the_gh135228_typeerror(self) -> None:
        instance = _FrozenSlotted(value=1)
        with pytest.raises((FrozenInstanceError, AttributeError)) as exc_info:
            instance.unknown = 2  # type: ignore[attr-defined]
        # The gh-135228 bug surfaced as a TypeError mentioning super(type, obj); the
        # correct behaviour raises FrozenInstanceError/AttributeError instead.
        assert not isinstance(exc_info.value, TypeError)
        assert "super(type, obj)" not in str(exc_info.value)

    def test_existing_field_assignment_still_raises_frozen_instance_error(self) -> None:
        instance = _FrozenSlotted(value=1)
        with pytest.raises(FrozenInstanceError):
            instance.value = 2  # type: ignore[misc]

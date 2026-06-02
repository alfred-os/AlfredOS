"""Regression guard: ``DevGate`` has been removed from ``src/`` in PR-S3-7.

Spec §15.1 (flag-day): ``DevGate`` is removed from
``src/alfred/hooks/capability.py`` and from the
``alfred.hooks`` public surface. Production code never touches
``DevGate`` again; the deny-path semantics it carried in Slice-2.5
are preserved via :class:`alfred.security.capability_gate._gate.RealGate`
with an empty grant snapshot (the production fail-closed default).

These tests pin the removal at the import boundary so a future
refactor that re-introduces ``DevGate`` in ``src/`` fails the suite at
the cheapest possible level (no fixtures, no gate instantiation).
"""

from __future__ import annotations

import pytest


def test_devgate_not_importable_from_alfred_hooks() -> None:
    """``DevGate`` must not be importable from ``alfred.hooks``.

    Spec §15.1: the public surface drops ``DevGate``. The
    :data:`alfred.hooks.__all__` set is the spec'd contract; absence
    here is equivalent to absence from ``src/``.
    """
    with pytest.raises(ImportError):
        from alfred.hooks import DevGate  # type: ignore[attr-defined]  # noqa: F401


def test_devgate_not_importable_from_capability_module() -> None:
    """``DevGate`` must not be importable from ``alfred.hooks.capability``.

    Catches the bypass where a refactor re-introduces the class but
    forgets to re-export it via ``__init__``. The flag-day removal
    deletes the class definition itself, not just the export.
    """
    with pytest.raises(ImportError):
        from alfred.hooks.capability import DevGate  # type: ignore[attr-defined]  # noqa: F401

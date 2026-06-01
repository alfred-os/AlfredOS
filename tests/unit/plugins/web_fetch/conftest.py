"""Per-package fixtures for ``tests/unit/plugins/web_fetch/``.

Provides the ``fresh_registry_allow_system`` fixture without importing
``tests.unit.hooks.conftest`` as a pytest plugin (that path triggers
``pluggy``'s duplicate-registration error when the hooks conftest is
already loaded via ``tests/unit/hooks/`` collection).

The fixture mirrors the shape in ``tests/unit/hooks/conftest.py`` —
fresh :class:`HookRegistry` with ``allow_system=True`` and
``strict_declarations=False`` — but is defined locally so each test
package owns its own copy of the registry-swap discipline.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from alfred.hooks.capability import DevGate
from alfred.hooks.registry import HookRegistry, get_registry, set_registry


@pytest.fixture
def fresh_registry_allow_system() -> Iterator[HookRegistry]:
    """Yield a brand-new :class:`HookRegistry` with ``allow_system=True``.

    Captures the pre-test registry at fixture entry; restores it on
    teardown so the module-level singleton is bit-for-bit identical
    after the test. ``strict_declarations=False`` so a test body can
    register-then-subscribe without tripping the strict-declaration
    contract on un-declared hookpoints.
    """
    prior = get_registry()
    registry = HookRegistry(
        gate=DevGate(allow_system=True),
        strict_declarations=False,
    )
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)

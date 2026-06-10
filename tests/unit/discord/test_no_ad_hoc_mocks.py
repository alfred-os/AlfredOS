"""AST guard: every Discord test input is built through the shared factory (test-1).

Closure test-1 mandates a single sanctioned construction site for Discord-shaped
test inputs (``discord_mock_factory`` in ``tests/conftest.py``, backed by the
typed doubles in ``tests/support/discord_mocks.py``). Scattering ad-hoc
``Mock(spec=discord.Message)`` constructions — each re-deciding which attributes
matter — is exactly the drift this guard forbids.

The guard walks every test module under ``tests/*/discord/`` and ``tests/unit/
plugins/alfred_discord/`` and refuses:

1. a call to ``unittest.mock.Mock`` / ``MagicMock`` whose ``spec=``/``spec_set=``
   argument names a ``discord.*`` attribute (the ad-hoc-mock anti-pattern);
2. a DIRECT call to a ``DiscordMock*`` constructor (those must go through the
   factory so default-attribute decisions live in one place).

The doubles' own definition module (``tests/support/discord_mocks.py``) and the
factory are exempt — they ARE the sanctioned construction site.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

_TESTS_ROOT = Path(__file__).resolve().parents[2]

# Directories whose test modules must obey the no-ad-hoc-mocks rule.
_GUARDED_DIRS = (
    _TESTS_ROOT / "unit" / "discord",
    _TESTS_ROOT / "unit" / "plugins" / "alfred_discord",
)

_MOCK_FACTORIES = frozenset({"Mock", "MagicMock", "NonCallableMock"})


def _guarded_files() -> Iterator[Path]:
    for directory in _GUARDED_DIRS:
        if not directory.exists():
            continue
        yield from directory.rglob("test_*.py")


def _is_discord_spec_mock(call: ast.Call) -> bool:
    """True if ``call`` is ``Mock(spec=discord.X)`` / ``MagicMock(spec_set=...)``."""
    func = call.func
    if isinstance(func, ast.Attribute):
        name: str | None = func.attr
    elif isinstance(func, ast.Name):
        name = func.id
    else:
        name = None
    if name not in _MOCK_FACTORIES:
        return False
    for kw in call.keywords:
        if kw.arg not in {"spec", "spec_set"}:
            continue
        value = kw.value
        # discord.Message / discord.User / ... attribute access.
        if (
            isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            and value.value.id == "discord"
        ):
            return True
    return False


def _is_direct_double_construction(call: ast.Call) -> bool:
    """True if ``call`` directly constructs a ``DiscordMock*`` type (bypassing the factory)."""
    func = call.func
    if isinstance(func, ast.Name) and func.id.startswith("DiscordMock"):
        return func.id != "DiscordMockFactory"
    return False


def test_no_ad_hoc_discord_mocks() -> None:
    violations: list[str] = []
    for path in _guarded_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _is_discord_spec_mock(node):
                violations.append(
                    f"{path.relative_to(_TESTS_ROOT)}:{node.lineno} ad-hoc Mock(spec=discord.*)"
                )
            if _is_direct_double_construction(node):
                violations.append(
                    f"{path.relative_to(_TESTS_ROOT)}:{node.lineno} "
                    "direct DiscordMock* construction — use discord_mock_factory"
                )
    assert not violations, "Discord mocks must go through discord_mock_factory:\n" + "\n".join(
        violations
    )


def test_guard_actually_scans_files() -> None:
    # Defence: an empty scan would make the guard vacuously pass.
    assert any(_guarded_files()), "no guarded Discord test files found — guard is mis-targeted"

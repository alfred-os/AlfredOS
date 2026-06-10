"""AST guard: every Discord test input is built through the shared factory (test-1).

Closure test-1 mandates a single sanctioned construction site for Discord-shaped
test inputs (``discord_mock_factory`` in ``tests/conftest.py``, backed by the
typed doubles in ``tests/support/discord_mocks.py``). Scattering ad-hoc
``Mock(spec=discord.Message)`` constructions — each re-deciding which attributes
matter — is exactly the drift this guard forbids.

The guard walks every test module under ``tests/*/discord/``,
``tests/unit/plugins/alfred_discord/`` and ``tests/integration/`` and refuses:

1. a call to ``unittest.mock.Mock`` / ``MagicMock`` whose ``spec=``/``spec_set=``
   argument resolves to a ``discord`` symbol — whether spelled
   ``discord.Message`` (attribute), ``discord.abc.Messageable`` (nested
   attribute), or a bare ``Message`` imported via ``from discord import Message``
   (M5: the bare-Name and nested-attribute escapes the original guard missed);
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
    _TESTS_ROOT / "integration",
)

_MOCK_FACTORIES = frozenset({"Mock", "MagicMock", "NonCallableMock"})

# Narrow, documented exemption: the LEGACY ``alfred.comms.discord.DiscordAdapter``
# integration test predates closure test-1's factory convention and targets the
# dormant ``src/alfred/comms/`` package that PR-S4-10 DELETES (spec §8.8). It is
# unrelated to the new ``plugins/alfred_discord`` adapter and is not migrated to
# the factory — it is removed wholesale in S4-10. Every OTHER integration test is
# guarded.
_LEGACY_EXEMPT = frozenset({_TESTS_ROOT / "integration" / "test_discord_adapter_integration.py"})


def _guarded_files() -> Iterator[Path]:
    for directory in _GUARDED_DIRS:
        if not directory.exists():
            continue
        for path in directory.rglob("test_*.py"):
            if path in _LEGACY_EXEMPT:
                continue
            yield path


def _discord_bound_names(tree: ast.AST) -> set[str]:
    """Names in ``tree`` that resolve to a ``discord`` symbol.

    Resolves ``import discord`` / ``import discord as d`` (the module name) and
    ``from discord import Message[, abc]`` / ``from discord.abc import Messageable``
    (each imported symbol). The returned set is the root names a ``spec=`` value
    must be checked against — closing the bare-Name escape (M5).
    """
    bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # ``import discord`` / ``import discord.abc`` / ``import discord as d``
                if alias.name == "discord" or alias.name.startswith("discord."):
                    bound.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "discord" or module.startswith("discord."):
                # ``from discord import Message`` → the symbol (or its alias) is
                # discord-bound.
                for alias in node.names:
                    bound.add(alias.asname or alias.name)
    return bound


def _root_name(value: ast.expr) -> str | None:
    """The leftmost ``Name`` of an attribute chain, or the bare ``Name`` id.

    ``discord.Message`` → ``"discord"``; ``discord.abc.Messageable`` →
    ``"discord"``; bare ``Message`` → ``"Message"``. Anything else → ``None``.
    """
    if isinstance(value, ast.Name):
        return value.id
    if isinstance(value, ast.Attribute):
        return _root_name(value.value)
    return None


def _is_discord_spec_mock(call: ast.Call, *, discord_names: set[str]) -> bool:
    """True if ``call`` is a ``Mock``/``MagicMock`` whose spec resolves to discord."""
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
        root = _root_name(kw.value)
        # ``discord.Message`` / ``discord.abc.Messageable`` (root "discord"), or a
        # bare ``Message`` imported from discord (root in the bound-name set).
        if root is not None and root in discord_names:
            return True
    return False


def _is_direct_double_construction(call: ast.Call) -> bool:
    """True if ``call`` directly constructs a ``DiscordMock*`` type (bypassing the factory)."""
    func = call.func
    if isinstance(func, ast.Name) and func.id.startswith("DiscordMock"):
        return func.id != "DiscordMockFactory"
    return False


def _violations_in_source(source: str) -> list[int]:
    """Line numbers of ad-hoc-discord-mock violations in ``source`` (self-check seam)."""
    tree = ast.parse(source)
    discord_names = _discord_bound_names(tree) | {"discord"}
    lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_discord_spec_mock(node, discord_names=discord_names):
            lines.append(node.lineno)
    return lines


def test_no_ad_hoc_discord_mocks() -> None:
    violations: list[str] = []
    for path in _guarded_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        discord_names = _discord_bound_names(tree) | {"discord"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _is_discord_spec_mock(node, discord_names=discord_names):
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


def test_guard_catches_attribute_spec() -> None:
    src = "from unittest.mock import Mock\nimport discord\nm = Mock(spec=discord.Message)\n"
    assert _violations_in_source(src) == [3]


def test_guard_catches_nested_attribute_spec() -> None:
    # M5: ``discord.abc.Messageable`` — a NESTED attribute the original guard missed.
    src = "from unittest.mock import Mock\nimport discord\nm = Mock(spec=discord.abc.Messageable)\n"
    assert _violations_in_source(src) == [3]


def test_guard_catches_bare_name_from_import() -> None:
    # M5: ``from discord import Message; Mock(spec=Message)`` — a bare Name the
    # original guard missed.
    src = "from unittest.mock import Mock\nfrom discord import Message\nm = Mock(spec=Message)\n"
    assert _violations_in_source(src) == [3]


def test_guard_catches_aliased_module_spec() -> None:
    src = "from unittest.mock import Mock\nimport discord as d\nm = Mock(spec=d.Message)\n"
    assert _violations_in_source(src) == [3]


def test_guard_ignores_non_discord_spec() -> None:
    src = "from unittest.mock import Mock\nfrom datetime import datetime\nm = Mock(spec=datetime)\n"
    assert _violations_in_source(src) == []

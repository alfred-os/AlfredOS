"""Spec §9.2/§9.3 invariant guard — Discord ``_ALLOWLIST_FIELDS`` unchanged.

comms-004: The eight refused rich-media field types are frozen through
Slice 3. T3-promotion of the rich-media subset is Slice 4 only. This
test guards against accidental simplification or removal during the
comms-MCP stub introduction.

Plan deviation (documented): the plan's reference code reads
``DiscordAdapter._ALLOWLIST_FIELDS`` as a CLASS attribute. The actual
in-repo definition (Slice 2) lives at module level as
``alfred.comms.discord._ALLOWLIST_FIELDS``: see
``src/alfred/comms/discord.py:326`` — a ``Final[tuple[str, ...]]``
used by the module-level ``_non_empty_content_fields()`` helper. The
guard tests the SAME constant either way; reading via the module path
matches reality. If a future refactor moves the constant onto
``DiscordAdapter`` as a ``ClassVar``, switch the import accordingly —
the assertion target is unchanged.

Depends on: ``src/alfred/comms/discord.py`` (Slice 2 shipped).
"""

from __future__ import annotations

import pytest


def _load_discord_allowlist() -> tuple[str, ...] | None:
    """Return the live Discord adapter's allowlist, or ``None`` if unavailable.

    The constant is imported via ``importlib`` so the
    ``Final[tuple[str, ...]]`` declaration stays the single source of
    truth — mypy refuses a top-level rebinding of a ``Final`` name
    inside an ``except ImportError`` branch (rightly so), and a
    runtime lookup sidesteps that without weakening the production
    constant's ``Final`` typing.

    CR-149: the exception arm narrows to
    :class:`ModuleNotFoundError` AND verifies ``e.name`` names the
    discord adapter module specifically. A real import regression
    inside the adapter — e.g. a ``ModuleNotFoundError`` from one of
    *its* dependencies, or any other ``ImportError`` shape — now
    propagates instead of silently triggering the
    ``HAS_DISCORD=False`` skip. Without this narrowing, a refactor
    that breaks an internal Discord adapter import would convert
    every spec §9.2/§9.3 invariant assertion into a SKIPPED test,
    defeating the Slice-2 allowlist guard (CLAUDE.md hard rule #3).
    """
    try:
        import importlib

        module = importlib.import_module("alfred.comms.discord")
    except ModuleNotFoundError as exc:
        # Only treat the "alfred.comms.discord module itself does not
        # exist" case as "Discord adapter not yet shipped". Any other
        # ModuleNotFoundError (e.g. ``ModuleNotFoundError: discord``
        # raised from inside the adapter) is a real regression and
        # MUST propagate.
        if exc.name == "alfred.comms.discord":
            return None
        raise
    fields = getattr(module, "_ALLOWLIST_FIELDS", None)
    if fields is None:
        return None
    return tuple(fields)


_DISCORD_ALLOWLIST_FIELDS = _load_discord_allowlist()
HAS_DISCORD = _DISCORD_ALLOWLIST_FIELDS is not None


# Spec §9.2 + §9.3: the Slice-2 frozen rich-media refusal set. Any
# change to this tuple must go through a spec change (T3-promotion of
# the rich-media subset is Slice 4 only).
_EXPECTED_ALLOWLIST_FIELDS: tuple[str, ...] = (
    "embeds",
    "attachments",
    "stickers",
    "reference",
    "poll",
    "components",
    "activity",
    "application",
)


@pytest.mark.skipif(
    not HAS_DISCORD,
    reason="DiscordAdapter not yet imported (pre-Slice 2 merge)",
)
def test_discord_allowlist_fields_unchanged_in_slice3() -> None:
    """``_ALLOWLIST_FIELDS`` must equal the Slice-2 frozen set through Slice 3.

    Spec §9.2 and §9.3: T3-promotion of the rich-media subset is
    deferred to Slice 4. Any modification to ``_ALLOWLIST_FIELDS``
    before that must go through a spec change.
    """
    # ``HAS_DISCORD`` skip-guard above guarantees the constant is loaded.
    assert _DISCORD_ALLOWLIST_FIELDS is not None
    assert _DISCORD_ALLOWLIST_FIELDS == _EXPECTED_ALLOWLIST_FIELDS, (
        f"_ALLOWLIST_FIELDS changed. Expected {_EXPECTED_ALLOWLIST_FIELDS!r}, "
        f"got {_DISCORD_ALLOWLIST_FIELDS!r}. "
        "Per spec §9.2/§9.3, T3-promotion of rich-media is Slice 4 only."
    )


@pytest.mark.skipif(
    not HAS_DISCORD,
    reason="DiscordAdapter not yet imported (pre-Slice 2 merge)",
)
def test_discord_allowlist_fields_count_is_eight() -> None:
    """The Slice-2 contract pins the count at eight.

    Spec §9.2 explicitly enumerates eight refused rich-media fields.
    A separate count check catches an accidental ordering-preserving
    swap (e.g. ``embeds`` → ``embed``) that the tuple-equality check
    would also catch — but the count check signals the count contract
    independent of the field-name vocabulary.
    """
    assert _DISCORD_ALLOWLIST_FIELDS is not None
    assert len(_DISCORD_ALLOWLIST_FIELDS) == 8, (
        f"_ALLOWLIST_FIELDS has {len(_DISCORD_ALLOWLIST_FIELDS)} entries; "
        "spec §9.2 pins exactly eight rich-media refusal field types "
        "through Slice 3."
    )

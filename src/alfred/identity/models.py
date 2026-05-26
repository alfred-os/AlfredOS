"""AlfredOS identity ORMs (User + PlatformIdentity).

Closed-domain enums for ``authorization`` and ``platform`` ride alongside the
ORMs (rather than living in a separate module) so call sites import a single
symbol per concept.
"""

from __future__ import annotations

from enum import StrEnum


class Authorization(StrEnum):
    """Per-user authorization tier.

    Snake_case on the wire (DB column TEXT CHECK + Pydantic value); kebab-case
    on the CLI surface (the Typer custom type normalises). The enum stays in
    the schema permanently — dropping/re-adding across a Postgres CHECK is a
    destructive migration that breaks rollback symmetry (spec §2 line 223).
    """

    READ_ONLY = "read_only"
    STANDARD = "standard"
    TRUSTED = "trusted"
    OPERATOR = "operator"


class Platform(StrEnum):
    """Platform that owns the ``platform_id`` half of an identity binding.

    Slice 2 ships TUI + Discord; Telegram lands in Slice 4 by extending this
    enum (additive CHECK-constraint migration, no destructive rewrite).
    """

    TUI = "tui"
    DISCORD = "discord"


# ORMs land in Task 6.

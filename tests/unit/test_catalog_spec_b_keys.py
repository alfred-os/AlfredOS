"""Every Spec-B (#288) ``t()`` key resolves to a non-bare value.

Mirrors ``test_catalog_slice_4_keys.py``. G6-2a ships the gateway.adapter.*
operator-facing status-reason keys ahead of their G6-2b ``alfred status``
consumer; the reserve file (``alfred.i18n._spec_b_reserve``) keeps pybabel from
marking them obsolete, and this test enforces no orphan key in the catalog —
in BOTH directions (correction #9): every enumerated key resolves, and no
``gateway.adapter.*``-prefixed msgid exists in the catalog outside SPEC_B_KEYS.
"""

from __future__ import annotations

import re
from pathlib import Path

from alfred.i18n import t

SPEC_B_KEYS: tuple[str, ...] = (
    "gateway.adapter.status.up",
    "gateway.adapter.status.down",
    "gateway.adapter.status.crashed",
    "gateway.adapter.status.breaker_open",
    "gateway.adapter.status_rejected.malformed_frame",
    "gateway.adapter.status_rejected.epoch_mismatch",
    "gateway.adapter.status_rejected.unknown_method",
)

# Every Spec-B operator-facing catalog key carries this prefix; the reverse-drift
# scan keys off it (matches the bidirectional discipline in the Slice-4 test).
_SPEC_B_PREFIX = "gateway.adapter."


def test_every_spec_b_key_resolves_non_bare() -> None:
    for key in SPEC_B_KEYS:
        value = t(key)
        assert value, f"{key!r} resolved to an empty string"
        assert value != key, f"{key!r} fell through to its own key (missing catalog entry)"


def test_no_duplicate_keys_in_spec_b_enumeration() -> None:
    assert len(set(SPEC_B_KEYS)) == len(SPEC_B_KEYS), "duplicate key in SPEC_B_KEYS"


def test_no_orphan_spec_b_msgids_in_po_outside_enumeration() -> None:
    """Reverse drift (correction #9): every ``gateway.adapter.*`` msgid in
    alfred.po is in SPEC_B_KEYS.

    The forward direction (enumeration resolves) is checked above; a .po-only
    addition would slip through without this. Scans active (non-commented)
    msgids only — historical ``#~ msgid`` lines are skipped.
    """
    po_path = Path("locale/en/LC_MESSAGES/alfred.po")
    po_text = po_path.read_text(encoding="utf-8")
    msgid_pattern = re.compile(r'^msgid\s+"([^"]+)"', re.MULTILINE)
    all_active_msgids = set(msgid_pattern.findall(po_text))

    spec_b_msgids_in_po = {m for m in all_active_msgids if m.startswith(_SPEC_B_PREFIX)}
    enumeration = set(SPEC_B_KEYS)

    orphans_in_po = spec_b_msgids_in_po - enumeration
    missing_from_po = enumeration - spec_b_msgids_in_po
    assert not orphans_in_po, (
        f"gateway.adapter.* msgids in .po not in SPEC_B_KEYS: {sorted(orphans_in_po)}"
    )
    assert not missing_from_po, (
        f"SPEC_B_KEYS missing from .po: {sorted(missing_from_po)}"
    )

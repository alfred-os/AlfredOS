"""Every quarantine-child-IO i18n key resolves to a distinct, real body (#237).

PR-S4-11c-2b0: ``alfred.security.quarantine_child_io`` raises
:class:`QuarantineChildSpawnError` with operator-facing ``t()`` strings on each
fail-closed boundary (CLAUDE.md hard rule #7). If a key were missing from the
catalog the operator would see the raw msgid; if pybabel fuzzy-matched a
neighbouring msgstr onto a new msgid, the operator would see the WRONG message and
a bare ``t(key) != key`` assertion would still pass (the i18n-001 failure mode).

This test pins, per key:

* the key resolves to a non-bare, fully-substituted string (no surviving
  ``{placeholder}`` — these messages take no format args, so a leak would mean a
  catalog typo); and
* the resolved body carries a key-specific FINGERPRINT substring, so a
  pybabel fuzzy-copy of a sibling msgstr (read_frame body landing on spawn_failed,
  say) fails loudly instead of silently shipping the wrong sentence.
"""

from __future__ import annotations

import pytest

from alfred.i18n import t

# (key, fingerprint) — the fingerprint is a key-specific substring of the canonical
# English body in ``locale/en/LC_MESSAGES/alfred.po``. Editing the copy means
# editing the fingerprint too (intentional: a copy change is a deliberate act).
_FINGERPRINTS: tuple[tuple[str, str], ...] = (
    ("security.quarantine_child.stdin_unavailable", "no stdin to write"),
    ("security.quarantine_child.stdout_unavailable", "no stdout to read"),
    ("security.quarantine_child.read_frame_failed", "reply failed"),
    ("security.quarantine_child.spawn_failed", "could not be spawned"),
    ("security.quarantine_child.provider_key_delivery_failed", "over fd 3 failed"),
)


@pytest.mark.parametrize(("key", "fingerprint"), _FINGERPRINTS)
def test_quarantine_child_io_key_resolves_with_fingerprint(key: str, fingerprint: str) -> None:
    rendered = t(key)
    assert rendered != key, f"{key} has no catalog entry (operator would see the raw msgid)"
    assert "{" not in rendered and "}" not in rendered, (
        f"{key} rendered with an unsubstituted placeholder: {rendered!r}"
    )
    assert fingerprint in rendered, (
        f"{key} resolved to the WRONG body (pybabel fuzzy-swap?): {rendered!r} "
        f"does not contain {fingerprint!r}"
    )


def test_all_quarantine_child_io_keys_have_distinct_bodies() -> None:
    """No two keys share a msgstr — guards against a copy-paste / fuzzy collision."""
    bodies = [t(key) for key, _ in _FINGERPRINTS]
    assert len(set(bodies)) == len(bodies), f"duplicate quarantine-child i18n bodies: {bodies}"

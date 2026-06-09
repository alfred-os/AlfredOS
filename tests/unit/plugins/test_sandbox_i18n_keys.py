"""Every sandbox-launcher bare key resolves in the catalog (PR-S4-6 K/L).

``bin/alfred-plugin-launcher.sh`` and ``manifest_reader.py`` emit bare i18n
keys on stderr; the supervisor renders them from the catalog. If a key were
left out of the catalog the operator would see the raw msgid. This test pins
that every key in the pybabel-visible registry resolves to a real (non-bare)
string, and that the bash launcher's emitted keys are all in the registry so
``pybabel update`` cannot silently orphan them.
"""

from __future__ import annotations

import re
from pathlib import Path

from alfred.i18n import t
from alfred.plugins._sandbox_i18n import _SANDBOX_VISIBLE_KEYS

_LAUNCHER = Path(__file__).resolve().parents[3] / "bin" / "alfred-plugin-launcher.sh"


def test_every_registry_key_resolves_non_bare() -> None:
    bare = [key for key in _SANDBOX_VISIBLE_KEYS if t(key) == key]
    assert not bare, f"sandbox i18n keys without a catalog entry: {bare}"


def test_launcher_emitted_sandbox_refused_keys_are_registered() -> None:
    # Every ``supervisor.sandbox.refused.<x>`` bare key the launcher prints on
    # stderr must be in the registry OR the reserved SLICE_4 set — otherwise a
    # ``pybabel update`` orphans it and the operator sees a raw msgid.
    from tests.unit.test_catalog_slice_4_keys import SLICE_4_KEYS

    launcher_text = _LAUNCHER.read_text(encoding="utf-8")
    emitted = set(re.findall(r"supervisor\.sandbox\.refused\.[a-z_]+", launcher_text))
    known = set(_SANDBOX_VISIBLE_KEYS) | set(SLICE_4_KEYS)
    missing = emitted - known
    assert not missing, f"launcher emits unregistered sandbox keys: {sorted(missing)}"

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


def test_interpreter_prefix_too_broad_renders_with_emitter_kwargs() -> None:
    # The launcher emits this refusal (#250) with `plugin_id` + `interpreter`; the
    # catalog msgstr must substitute BOTH with no residual placeholder, else the
    # supervisor `.format` KeyErrors at the worst possible moment — a security
    # refusal. Render with the emitter's actual kwargs and assert full substitution.
    rendered = t(
        "supervisor.sandbox.refused.interpreter_prefix_too_broad",
        plugin_id="alfred.quarantined-llm",
        interpreter="/python",
    )
    assert rendered != "supervisor.sandbox.refused.interpreter_prefix_too_broad"
    assert "{" not in rendered and "}" not in rendered
    assert "alfred.quarantined-llm" in rendered and "/python" in rendered

"""Every declared config-reload / config-watcher catalog key is invoked (rev-002).

i18n hard-rule closure: every operator-facing string emitted from
``src/alfred/policies/`` routes through ``t()``. This guard asserts that each
``supervisor.config_reload.*`` / ``supervisor.config_watcher.*`` catalog key
appears in at least one ``t(...)`` call site under ``src/alfred/policies/``.
"""

from __future__ import annotations

import ast
from pathlib import Path

_POLICIES_DIR = Path(__file__).resolve().parents[3] / "src" / "alfred" / "policies"

# The catalog keys PR-S4-0b reserved for this PR (plus the three this PR adds:
# audit_write_failed, config_watcher.degraded, config_watcher.recovered).
_REQUIRED_KEYS: frozenset[str] = frozenset(
    {
        "supervisor.config_reload.applied",
        "supervisor.config_reload.rejected.parse_failure",
        "supervisor.config_reload.rejected.high_blast_change",
        "supervisor.config_reload.rejected.validation_failure",
        "supervisor.config_reload.rejected.file_vanished",
        "supervisor.config_reload.rejected.stat_failed",
        "supervisor.config_reload.rejected.audit_write_failed",
        "supervisor.config_watcher.degraded",
        "supervisor.config_watcher.recovered",
    }
)


def _t_string_literals() -> set[str]:
    found: set[str] = set()
    for py in _POLICIES_DIR.rglob("*.py"):
        tree = ast.parse(py.read_text(), filename=str(py))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "t"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                found.add(node.args[0].value)
    return found


def test_every_config_reload_key_has_a_t_call_site() -> None:
    invoked = _t_string_literals()
    missing = _REQUIRED_KEYS - invoked
    assert not missing, (
        "config-reload/config-watcher catalog keys with no t() call site under "
        f"src/alfred/policies/: {sorted(missing)}"
    )

"""Shared scrubbed child-env builder for the comms-plugin launch surfaces.

PR-S4-11a Wave 1 (#237) promotes the env-allowlist + spec-env overlay that
:mod:`alfred.cli._launcher_spawn` shipped (review F2) into ONE place so the new
daemon-hosted :class:`alfred.plugins.comms_stdio_transport.CommsStdioTransport`
and the foreground ``alfred chat`` launcher share a single allowlist — a key
added (or, worse, a secret-bearing key leaked) in one site can never drift from
the other.

Two consumers, one allowlist, two postures:

* **Foreground launcher** (``alfred chat`` TUI, :mod:`alfred.cli._launcher_spawn`)
  keeps its ``sandbox_kind == "none"`` FULL-passthrough branch — the operator IS
  the trusted user and their Textual app needs the inherited session env. It
  imports :data:`_SCRUBBED_ENV_ALLOWLIST` + :func:`_spec_env` from here for the
  adversary-facing (``kind != "none"``) branch only.
* **Daemon-hosted comms transport** uses :func:`comms_child_env` — the SCRUBBED
  allowlist for ALL sandbox kinds. There is no operator at the keyboard, and the
  daemon may spawn an adversary-facing relay (the Discord adapter, ``kind="full"``,
  open egress per #230); an operator's exported ``DISCORD_BOT_TOKEN`` /
  ``ANTHROPIC_API_KEY`` must never cross into it. This is a deliberate tightening
  vs the foreground path.

This module reads the host env ONLY through the allowlisted per-key
``os.environ[name]`` subscript guarded by a ``name in os.environ`` membership —
never a blanket ``dict(os.environ)``. The whole-module AST guard in
``tests/unit/plugins/test_comms_child_env_ast_scrub.py`` is the release-blocker
against any future blanket-env read here.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from alfred.cli._launcher_spawn import PluginLaunchSpec

#: Env keys forwarded verbatim into a scrubbed child. These are the launcher's
#: OWN operational controls (it reads them to resolve the per-OS sandbox policy +
#: UID drop — see ``bin/alfred-plugin-launcher.sh`` ``ENVIRONMENT``) plus the
#: locale + PATH the child interpreter needs. NO secret-bearing key
#: (``ANTHROPIC_API_KEY``, ``DISCORD_BOT_TOKEN``, ...) is on this list — that is
#: the whole point of the scrub.
_SCRUBBED_ENV_ALLOWLIST: tuple[str, ...] = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    # Launcher control surface (parent env -> launcher).
    "ALFRED_ENVIRONMENT",
    "ALFRED_SANDBOX_POLICY_DIR",
    "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED",
    "ALFRED_PLUGIN_UID",
    "FAKE_UNAME",
)


def _spec_env(spec: PluginLaunchSpec, base: dict[str, str]) -> dict[str, str]:
    """Overlay the spec-derived keys (manifest, adapter id, import roots) onto ``base``.

    Mutates and returns ``base`` so callers can thread it through after seeding
    it from whatever env posture they own (scrubbed allowlist here; the
    foreground ``kind="none"`` full passthrough in the launcher).
    """
    base["ALFRED_PLUGIN_MANIFEST_PATH"] = str(spec.manifest_path)
    base["ALFRED_PLUGIN_ADAPTER_ID"] = spec.adapter_id
    existing = base.get("PYTHONPATH", "")
    roots = [str(p) for p in spec.import_roots]
    base["PYTHONPATH"] = os.pathsep.join(p for p in (*roots, existing) if p)
    return base


def _scrubbed_base() -> dict[str, str]:
    """Seed a child env from the explicit allowlist — never ``dict(os.environ)``.

    Per-key ``os.environ[name]`` reads gated by ``name in os.environ`` are the
    sanctioned scrub primitive; the AST guard forbids any blanket read.
    """
    return {name: os.environ[name] for name in _SCRUBBED_ENV_ALLOWLIST if name in os.environ}


def comms_child_env(spec: PluginLaunchSpec) -> dict[str, str]:
    """Build the SCRUBBED, allowlisted child env for a daemon-hosted comms plugin.

    The daemon comms path scrubs for ALL sandbox kinds (#237) — ``spec.sandbox_kind``
    is intentionally NOT consulted here. The foreground launcher's ``kind="none"``
    full-passthrough exception lives in :mod:`alfred.cli._launcher_spawn`, not here:
    the daemon has no operator at the keyboard whose session env it should inherit.
    """
    return _spec_env(spec, _scrubbed_base())


__all__ = [
    "comms_child_env",
]

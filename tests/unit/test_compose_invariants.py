"""Invariant assertions for ``docker-compose.yaml`` security properties.

devops-010: pins that alfred-discord never gets SETUID or alfred_state_git,
and that alfred-core always has both. These invariants are load-bearing:

- SETUID in alfred-discord would let the Discord adapter impersonate
  alfred-quarantine, bypassing the process-boundary isolation (spec §5.2).
- alfred_state_git in alfred-discord would expose state.git grant files to
  the comms adapter, widening the trust surface (spec §11.1).
- alfred-redis without ``--maxmemory`` never evicts: volatile-lru only
  triggers at the memory ceiling, so an unbounded Redis grows until OOMKill
  (devops-002).

``docker compose config --quiet`` only checks YAML validity — it does not
assert these security properties. The tests below close that gap.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

COMPOSE_PATH = Path(__file__).parent.parent.parent / "docker-compose.yaml"


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    return yaml.safe_load(COMPOSE_PATH.read_text())


def _volume_strings(volumes: list[Any]) -> list[str]:
    out: list[str] = []
    for v in volumes:
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            out.append(f"{v.get('source', '')}:{v.get('target', '')}")
    return out


def test_alfred_discord_has_no_setuid(compose: dict[str, Any]) -> None:
    """alfred-discord must NOT have cap_add: SETUID (spec §5.2)."""
    discord = compose.get("services", {}).get("alfred-discord", {})
    cap_add = discord.get("cap_add", []) or []
    assert "SETUID" not in cap_add, (
        "alfred-discord must not have SETUID capability — this would let it "
        "impersonate alfred-quarantine and bypass the process isolation."
    )


def test_alfred_discord_has_no_state_git_volume(compose: dict[str, Any]) -> None:
    """alfred-discord must NOT have alfred_state_git mounted (spec §11.1)."""
    discord = compose.get("services", {}).get("alfred-discord", {})
    volumes = discord.get("volumes", []) or []
    assert not any("alfred_state_git" in v for v in _volume_strings(volumes)), (
        "alfred-discord must not mount alfred_state_git — this would expose "
        "state.git grant files to the comms adapter, widening the trust surface."
    )


def test_alfred_core_has_setuid(compose: dict[str, Any]) -> None:
    """alfred-core must have cap_add: SETUID for plugin-launcher (spec §5.2)."""
    core = compose.get("services", {}).get("alfred-core", {})
    cap_add = core.get("cap_add", []) or []
    assert "SETUID" in cap_add, (
        "alfred-core requires SETUID capability for alfred-plugin-launcher to "
        "perform the UID-drop to alfred-quarantine at subprocess spawn."
    )


def test_alfred_core_has_state_git_volume(compose: dict[str, Any]) -> None:
    """alfred-core must mount alfred_state_git at /var/lib/alfred (spec §11.1).

    Enforces both the source volume name AND the mount target — name-only
    matching would pass a misconfigured compose that mounts the volume at
    the wrong path (e.g. /tmp/state) and silently break the seed script
    (``bin/alfred-state-git-seed.sh`` defaults STATE_GIT_PATH to
    /var/lib/alfred/state.git).
    """
    core = compose.get("services", {}).get("alfred-core", {})
    volumes = core.get("volumes", []) or []
    assert any("alfred_state_git:/var/lib/alfred" in v for v in _volume_strings(volumes)), (
        "alfred-core requires alfred_state_git mounted at /var/lib/alfred "
        "for state.git ops (spec §11.1). Wrong target would break the "
        "STATE_GIT_PATH default in bin/alfred-state-git-seed.sh."
    )


def test_alfred_redis_has_maxmemory(compose: dict[str, Any]) -> None:
    """alfred-redis command must include --maxmemory (devops-002).

    Without --maxmemory the volatile-lru policy never evicts: eviction only
    triggers at the memory ceiling. An unbounded Redis grows until OOMKill.
    """
    redis_svc = compose.get("services", {}).get("alfred-redis", {})
    command = redis_svc.get("command", "") or ""
    assert "--maxmemory" in command, (
        "alfred-redis must declare --maxmemory so volatile-lru can evict. "
        "Without it Redis grows unbounded and OOMs under load (devops-002)."
    )

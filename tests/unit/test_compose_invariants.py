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
    volume_entries = _volume_strings(volumes)
    # Exact membership, not substring: a mis-mount like
    # `alfred_state_git:/var/lib/alfred_backup` would silently pass
    # a substring check and break STATE_GIT_PATH (CR-round-2 fix).
    assert "alfred_state_git:/var/lib/alfred" in volume_entries, (
        "alfred-core requires alfred_state_git mounted at exactly "
        "/var/lib/alfred (no trailing path) for state.git ops "
        "(spec §11.1). Wrong target would break the STATE_GIT_PATH "
        "default in bin/alfred-state-git-seed.sh."
    )


def test_alfred_core_has_bwrap_apparmor_profile(compose: dict[str, Any]) -> None:
    """alfred-core must carry the custom AppArmor profile for the bwrap userns (#290).

    The dual-LLM quarantine child runs under bubblewrap, which builds an
    unprivileged user namespace. On userns-restricted hosts the kernel only
    permits that under an AppArmor profile carrying ``userns,``; alfred-core
    points at the custom ``alfred-bwrap`` profile via ``security_opt``. Pinning
    it here stops a refactor from silently dropping the line and re-breaking the
    spawn (the #290 failure mode).
    """
    core = compose.get("services", {}).get("alfred-core", {})
    security_opt = core.get("security_opt", []) or []
    assert "apparmor=alfred-bwrap" in security_opt, (
        "alfred-core requires security_opt 'apparmor=alfred-bwrap' so the bwrap "
        "quarantine child can build its user namespace on a userns-restricted "
        "host (#290). Without it the dual-LLM spawn refuses with "
        "'No permissions to create new namespace'."
    )


def test_alfred_core_has_bwrap_seccomp_profile(compose: dict[str, Any]) -> None:
    """alfred-core must carry the custom seccomp profile for the bwrap userns (#290).

    Docker's default seccomp profile blocks the namespace syscalls
    (clone/clone3/unshare) bwrap needs absent CAP_SYS_ADMIN. The custom profile
    is the minimal delta — NOT seccomp=unconfined. Pinning it complements the
    AppArmor assertion: both layers must stay in place for the spawn to work.
    """
    core = compose.get("services", {}).get("alfred-core", {})
    security_opt = core.get("security_opt", []) or []
    assert "seccomp=docker/seccomp/alfred-bwrap.json" in security_opt, (
        "alfred-core requires security_opt "
        "'seccomp=docker/seccomp/alfred-bwrap.json' so bwrap's namespace "
        "syscalls are permitted for the non-root quarantine child (#290). This "
        "is the least-privilege alternative to seccomp=unconfined."
    )


def test_bwrap_security_opt_scoped_to_core(compose: dict[str, Any]) -> None:
    """Only alfred-core gets the bwrap security_opt profiles (#290 isolation).

    alfred-discord has no SETUID and never spawns the launcher (it must not be
    able to impersonate the quarantine UID — see test_alfred_discord_has_no_setuid).
    The G6-0 gateway is a pure relay (no SETUID yet). Granting either the
    userns-enabling AppArmor profile would needlessly widen its posture, so the
    profiles are scoped to the one service that actually spawns the bwrap child.
    """
    services = compose.get("services", {})
    for name in ("alfred-discord", "alfred-gateway"):
        security_opt = services.get(name, {}).get("security_opt", []) or []
        assert not any("alfred-bwrap" in entry for entry in security_opt), (
            f"{name} must NOT carry the alfred-bwrap security_opt profiles — they "
            "are scoped to alfred-core, the only service that spawns the bwrap "
            "quarantine child (#290)."
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


def test_alfred_gateway_service_exists(compose: dict[str, Any]) -> None:
    gw = compose.get("services", {}).get("alfred-gateway")
    assert gw is not None, "alfred-gateway service must exist (Spec B G6-0)."
    assert gw.get("command") == ["gateway", "start"]
    assert gw.get("restart") == "unless-stopped"


def test_alfred_gateway_has_no_setuid(compose: dict[str, Any]) -> None:
    """G6-0: the gateway is still a pure relay — SETUID arrives in G6-1, not here."""
    gw = compose.get("services", {}).get("alfred-gateway", {})
    assert "SETUID" not in (gw.get("cap_add", []) or []), (
        "alfred-gateway must NOT have SETUID in G6-0; it moves in G6-1 with ADR-0036."
    )


def test_alfred_gateway_has_no_state_git_volume(compose: dict[str, Any]) -> None:
    gw = compose.get("services", {}).get("alfred-gateway", {})
    entries = _volume_strings(gw.get("volumes", []) or [])
    assert not any("alfred_state_git" in v for v in entries), (
        "alfred-gateway must not mount alfred_state_git — the relay has no grant files."
    )


def test_alfred_gateway_has_alfred_run_volume(compose: dict[str, Any]) -> None:
    gw = compose.get("services", {}).get("alfred-gateway", {})
    entries = _volume_strings(gw.get("volumes", []) or [])
    assert "alfred_run:/home/alfred/.run" in entries, (
        "alfred-gateway must mount alfred_run at /home/alfred/.run for its sockets."
    )


def test_alfred_run_mounted_only_by_gateway(compose: dict[str, Any]) -> None:
    """G6-0: only alfred-gateway mounts alfred_run (core joins in G6-0b)."""
    services = compose.get("services", {})
    mounters = {
        name
        for name, svc in services.items()
        if any("alfred_run" in v for v in _volume_strings(svc.get("volumes", []) or []))
    }
    assert mounters == {"alfred-gateway"}, (
        f"alfred_run must be mounted only by alfred-gateway in G6-0; got {mounters}."
    )


def test_alfred_gateway_publishes_no_host_port(compose: dict[str, Any]) -> None:
    """The /metrics endpoint stays compose-internal — no host port published."""
    gw = compose.get("services", {}).get("alfred-gateway", {})
    assert not (gw.get("ports") or []), (
        "alfred-gateway must publish no host port — /metrics is compose-internal only."
    )


def test_alfred_gateway_has_healthcheck(compose: dict[str, Any]) -> None:
    gw = compose.get("services", {}).get("alfred-gateway", {})
    hc = gw.get("healthcheck", {})
    assert hc.get("test") == ["CMD", "alfred", "gateway", "healthcheck"]

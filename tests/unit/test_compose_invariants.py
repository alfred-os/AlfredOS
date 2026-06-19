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


def test_setuid_allowed_set_is_core_and_gateway(compose: dict[str, Any]) -> None:
    """G6-1 (ADR-0036): cap_add SETUID is granted to EXACTLY {alfred-core, alfred-gateway}.

    The positive allowed-set is the devops-010 reframe: rather than asserting each service
    individually, pin the whole set so a NEW service silently gaining SETUID fails loud, and
    so the privilege concentration is auditable in one place. Adapters never get SETUID.
    """
    services = compose.get("services", {})
    with_setuid = {
        name for name, svc in services.items() if "SETUID" in (svc.get("cap_add", []) or [])
    }
    assert with_setuid == {"alfred-core", "alfred-gateway"}, (
        f"SETUID must be granted to exactly {{alfred-core, alfred-gateway}}; got {with_setuid}."
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


def test_bwrap_security_opt_set_is_core_and_gateway(compose: dict[str, Any]) -> None:
    """G6-1 (ADR-0036): the alfred-bwrap AppArmor/seccomp profiles are carried by EXACTLY
    {alfred-core, alfred-gateway} — the two bwrap-spawning hosts. alfred-core spawns the
    quarantine child (#290); the gateway spawns bwrap adapter children (capability granted in
    G6-1, used in G6-2). Adapters (alfred-discord) must NEVER carry them — an adapter that
    could build the userns sandbox could impersonate the quarantine UID (see
    test_alfred_discord_has_no_setuid).
    """
    services = compose.get("services", {})
    with_bwrap_profiles = {
        name
        for name, svc in services.items()
        if any("alfred-bwrap" in entry for entry in (svc.get("security_opt", []) or []))
    }
    assert with_bwrap_profiles == {"alfred-core", "alfred-gateway"}, (
        f"the alfred-bwrap profiles must be scoped to exactly {{alfred-core, alfred-gateway}}; "
        f"got {with_bwrap_profiles}. Adapters must never carry them (#290 / ADR-0036)."
    )


def test_alfred_core_is_not_privileged(compose: dict[str, Any]) -> None:
    """alfred-core must NOT run privileged (#290 broad-grant regression guard).

    The whole point of the #290 fix is least-privilege: custom AppArmor + seccomp
    profiles + cap_add SETUID, NEVER `privileged: true`. A future change that
    flips privileged on would silently grant the core every capability + drop
    confinement — far broader than the userns exemption the spawn needs.
    """
    core = compose.get("services", {}).get("alfred-core", {})
    assert core.get("privileged") is not True, (
        "alfred-core must NOT set `privileged: true` — the bwrap quarantine "
        "child spawns under least-privilege custom AppArmor + seccomp profiles "
        "plus cap_add SETUID (#290), never full privilege."
    )


def test_alfred_core_has_no_unconfined_security_opt(compose: dict[str, Any]) -> None:
    """alfred-core must NOT carry any *=unconfined security_opt (#290 guard).

    `seccomp=unconfined` / `apparmor=unconfined` (or the bare `unconfined`
    shorthand) is the sledgehammer the #290 design explicitly rejected in favour
    of the custom least-privilege profiles. Pinning the negative stops a future
    refactor from "fixing" a spawn failure by disabling confinement wholesale.
    """
    core = compose.get("services", {}).get("alfred-core", {})
    security_opt = core.get("security_opt", []) or []
    offenders = [
        entry
        for entry in security_opt
        if entry.strip() == "unconfined" or entry.strip().endswith("=unconfined")
    ]
    assert not offenders, (
        f"alfred-core must NOT carry any *=unconfined security_opt; found {offenders}. "
        "The #290 design uses custom least-privilege AppArmor + seccomp profiles, "
        "never seccomp=unconfined / apparmor=unconfined."
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


def test_alfred_gateway_has_setuid_and_sandbox_profiles(compose: dict[str, Any]) -> None:
    """G6-1 (ADR-0036): the gateway gains SETUID + the alfred-bwrap AppArmor/seccomp profiles
    so it can spawn bwrap-sandboxed adapter children (capability granted; hosting lands G6-2)."""
    gw = compose.get("services", {}).get("alfred-gateway", {})
    assert "SETUID" in (gw.get("cap_add", []) or []), (
        "alfred-gateway must have cap_add: SETUID in G6-1 (ADR-0036) to host bwrap adapters."
    )
    security_opt = gw.get("security_opt", []) or []
    assert "apparmor=alfred-bwrap" in security_opt
    assert "seccomp=docker/seccomp/alfred-bwrap.json" in security_opt


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


def test_alfred_run_mounted_only_by_core_and_gateway(compose: dict[str, Any]) -> None:
    """G6-0b: alfred_run is shared by exactly {alfred-core, alfred-gateway} (the socket
    dir for the gateway↔core link). No other service may mount it."""
    services = compose.get("services", {})
    mounters = {
        name
        for name, svc in services.items()
        # Match the volume SOURCE exactly (the part before ``:``), not as a substring, so a
        # future volume whose name merely CONTAINS ``alfred_run`` (e.g. ``alfred_runtime``)
        # cannot silently satisfy or break this invariant.
        if any(
            v.split(":", 1)[0] == "alfred_run"
            for v in _volume_strings(svc.get("volumes", []) or [])
        )
    }
    assert mounters == {"alfred-core", "alfred-gateway"}, (
        f"alfred_run must be mounted only by core+gateway; got {mounters}."
    )


def test_alfred_core_is_long_running_daemon(compose: dict[str, Any]) -> None:
    """alfred-core runs `daemon start` with a restart policy (Spec B G6-0b)."""
    core = compose.get("services", {}).get("alfred-core", {})
    assert core.get("command") == ["daemon", "start"]
    assert core.get("restart") == "unless-stopped"


def test_alfred_core_shares_alfred_run(compose: dict[str, Any]) -> None:
    """alfred-core mounts alfred_run so the gateway can dial comms-tui.sock."""
    core = compose.get("services", {}).get("alfred-core", {})
    assert "alfred_run:/home/alfred/.run" in _volume_strings(core.get("volumes", []) or [])


def test_alfred_core_enables_tui_adapter(compose: dict[str, Any]) -> None:
    """alfred-core enables the socket-backed alfred_tui adapter (binds comms-tui.sock)."""
    core = compose.get("services", {}).get("alfred-core", {})
    env = core.get("environment", {}) or {}
    assert "alfred_tui" in str(env.get("ALFRED_COMMS_ENABLED_ADAPTERS", ""))


def test_alfred_core_sets_environment(compose: dict[str, Any]) -> None:
    """alfred-core pins the ALFRED_ENVIRONMENT default chain (hard boot req for the daemon).

    Pin the exact ``${ALFRED_ENVIRONMENT:-production}`` default chain, not just key presence:
    the daemon refuse-boots without ALFRED_ENVIRONMENT, and the deployed stack must default to
    ``production`` while still honouring an operator override — so a drift that drops the
    fallback (or flips the default) is caught here.
    """
    core = compose.get("services", {}).get("alfred-core", {})
    env = core.get("environment", {}) or {}
    assert env.get("ALFRED_ENVIRONMENT") == "${ALFRED_ENVIRONMENT:-production}"


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

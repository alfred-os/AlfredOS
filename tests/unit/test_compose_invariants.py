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

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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


def test_alfred_discord_service_is_deleted(compose: dict[str, Any]) -> None:
    """Spec B G6-7-8 (#309): the standalone alfred-discord service is gone — Discord is
    a gateway-hosted bwrap child. No standalone process, no secrets.toml bind-mount."""
    assert "alfred-discord" not in compose.get("services", {})


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


def test_alfred_core_has_discord_token_env(compose: dict[str, Any]) -> None:
    """#309 GAP-4: alfred-core carries ALFRED_DISCORD_BOT_TOKEN so the core broker
    resolves the Discord credential (env-fallback) for spawn-grant -> fd-3."""
    core = compose.get("services", {}).get("alfred-core", {})
    env = core.get("environment", {}) or {}
    assert "ALFRED_DISCORD_BOT_TOKEN" in env


def test_alfred_core_has_quarantine_provider_key_env(compose: dict[str, Any]) -> None:
    """#340 PR2b-golive: alfred-core forwards ALFRED_QUARANTINE_PROVIDER_API_KEY.

    The golive boot refuses when this is unset and tells the operator to set it. Without
    the forward the remedy is unreachable — no `.env` value would enter the container,
    and alfred-core mounts neither a secrets.toml nor any bind-mount that could carry
    one — so the stack would crash-loop under `restart: unless-stopped` with a refusal
    naming a fix that cannot work. Refusing without the key is intended; refusing with no
    reachable remedy is the bug this pins.
    """
    core = compose.get("services", {}).get("alfred-core", {})
    env = core.get("environment", {}) or {}
    assert "ALFRED_QUARANTINE_PROVIDER_API_KEY" in env


def test_quarantine_provider_key_defaults_to_empty_not_required(
    compose: dict[str, Any],
) -> None:
    """The forward uses the ``:-`` default so `docker compose config` stays usable.

    Mirrors ALFRED_ANTHROPIC_API_KEY. A bare ``${VAR}`` (the ALFRED_DEEPSEEK_API_KEY
    shape) makes compose WARN on every invocation for a keyless checkout; the empty
    default keeps the refusal where it belongs — a loud, actionable AlfredOS boot
    refusal — rather than compose-level noise before the app ever starts.
    """
    core = compose.get("services", {}).get("alfred-core", {})
    env = core.get("environment", {}) or {}
    assert env["ALFRED_QUARANTINE_PROVIDER_API_KEY"] == "${ALFRED_QUARANTINE_PROVIDER_API_KEY:-}"


def test_quarantine_provider_key_never_reaches_the_gateway(compose: dict[str, Any]) -> None:
    """ADR-0036: the quarantine provider key is a core-only secret, like the Discord token.

    The gateway hosts adapters and brokers egress; it must never hold a provider
    credential. Pinned alongside the existing no-secret-on-gateway invariant so a future
    'just add it everywhere' edit fails loudly.
    """
    gw = compose.get("services", {}).get("alfred-gateway", {})
    env = gw.get("environment", {}) or {}
    assert "ALFRED_QUARANTINE_PROVIDER_API_KEY" not in env


def test_alfred_gateway_hosts_discord(compose: dict[str, Any]) -> None:
    """Spec B G6-7-8 (#309): the gateway is configured to host the Discord adapter."""
    gw = compose.get("services", {}).get("alfred-gateway", {})
    env = gw.get("environment", {}) or {}
    assert "alfred_discord" in str(env.get("ALFRED_COMMS_ENABLED_ADAPTERS", ""))


def test_no_secret_env_or_mount_on_gateway(compose: dict[str, Any]) -> None:
    """The gateway holds NO platform secret — neither env nor bind-mount (ADR-0036).

    The gateway must mount ONLY the approved set (alfred_run socket dir) — any
    unexpected mount could carry a secret (e.g. a bind-mounted directory containing
    secrets.toml).  Pinned exactly so additions require an explicit review.
    """
    gw = compose.get("services", {}).get("alfred-gateway", {})
    env = gw.get("environment", {}) or {}
    assert "ALFRED_DISCORD_BOT_TOKEN" not in env
    assert "ALFRED_SECRETS_FILE" not in env
    # Exact-set assertion: the gateway must mount ONLY the approved named volumes.
    # A bind-mounted directory could silently carry secrets.toml (the _PREFER_FILE path),
    # so we pin the approved mounts rather than just filtering for the filename.
    # G7-4: alfred_discord_egress added here (gateway-only Discord egress socket dir;
    # devops-001 — the core must NEVER mount it, enforced by
    # test_discord_egress_volume_gateway_only).
    approved_mounts = {
        "alfred_run:/home/alfred/.run",
        "alfred_discord_egress:/home/alfred/.egress",
    }
    actual_mounts = set(_volume_strings(gw.get("volumes", []) or []))
    assert actual_mounts == approved_mounts, (
        f"Gateway mounts deviated from approved set: {actual_mounts!r}"
    )


def test_alfred_core_comms_adapters_stay_tui_only(compose: dict[str, Any]) -> None:
    """The CORE must NOT host Discord — adding alfred_discord trips
    CommsMultiAdapterUnsupportedFailure + a second stdio-spawned Discord (dual-spawn).
    Discord is gateway-hosted + forwarded; the core stays alfred_tui-only (#309)."""
    core = compose.get("services", {}).get("alfred-core", {})
    enabled = str(core.get("environment", {}).get("ALFRED_COMMS_ENABLED_ADAPTERS", ""))
    assert "alfred_discord" not in enabled
    assert "alfred_tui" in enabled


def test_two_custom_networks_defined(compose: dict[str, Any]) -> None:
    """G7-0 (Spec C §3): the two egress-plane networks exist."""
    networks = compose.get("networks", {})
    assert set(networks) >= {"alfred_internal", "alfred_external"}, (
        "Spec C requires custom networks alfred_internal + alfred_external; "
        f"got {sorted(networks)}."
    )


def test_alfred_internal_is_internal_true(compose: dict[str, Any]) -> None:
    """G7-3 (Spec C §3, §6): alfred_internal must be internal:true (no route to the internet).

    This is the kernel enforcement-of-record for the connectivity-free core.
    """
    internal = compose.get("networks", {}).get("alfred_internal", {}) or {}
    assert internal.get("internal") is True, (
        "alfred_internal must set 'internal: true' so attached services have no "
        f"route to the internet; got {internal!r}."
    )


def _service_networks(compose: dict[str, Any], service: str) -> set[str]:
    svc = compose.get("services", {}).get(service, {}) or {}
    nets = svc.get("networks", []) or []
    # Compose allows networks as a list OR a mapping; set() over either yields the
    # network-name set (set(dict) is its keys).
    return set(nets)


def test_gateway_joins_both_networks(compose: dict[str, Any]) -> None:
    """G7-0 (Spec C §3): the gateway is the bridge — it joins both networks."""
    nets = _service_networks(compose, "alfred-gateway")
    assert nets >= {"alfred_internal", "alfred_external"}, (
        f"alfred-gateway must join both networks (it is the egress chokepoint); got {sorted(nets)}."
    )


def test_datastores_join_internal_only(compose: dict[str, Any]) -> None:
    """G7-0 (Spec C §3): datastores never touch alfred_external."""
    for service in ("alfred-postgres", "alfred-redis"):
        nets = _service_networks(compose, service)
        assert nets == {"alfred_internal"}, (
            f"{service} must join alfred_internal ONLY (never alfred_external); got {sorted(nets)}."
        )


def test_core_joins_internal(compose: dict[str, Any]) -> None:
    """G7-0 (Spec C §3): the core is on alfred_internal (reaches datastores + the gateway)."""
    nets = _service_networks(compose, "alfred-core")
    assert "alfred_internal" in nets, f"alfred-core must join alfred_internal; got {sorted(nets)}."


def test_only_gateway_on_external(compose: dict[str, Any]) -> None:
    """G7-3 (Spec C §3): alfred_external carries ONLY the gateway — the core has left.

    A GENERIC guard: any future service silently joining alfred_external fails here.
    """
    services = compose.get("services", {})
    on_external = {n for n in services if "alfred_external" in _service_networks(compose, n)}
    assert on_external == {"alfred-gateway"}, (
        "Only alfred-gateway may join alfred_external (the connectivity-free core has "
        f"left it); got {sorted(on_external)}. A new service on alfred_external breaks the "
        "connectivity-free invariant."
    )


def test_core_not_on_external(compose: dict[str, Any]) -> None:
    """G7-3 (Spec C §11): the connectivity-free flip — core must NOT be on alfred_external."""
    nets = _service_networks(compose, "alfred-core")
    assert "alfred_external" not in nets, (
        f"alfred-core must NOT join alfred_external (connectivity-free core); got {sorted(nets)}."
    )


def test_core_joins_internal_only(compose: dict[str, Any]) -> None:
    """G7-3 (Spec C §3, sec-001/test-002): the core is on EXACTLY alfred_internal.

    The subset check (test_core_joins_internal) + external-absent (test_core_not_on_external)
    do not catch a future THIRD internet-reachable network on the core; the exact-set does
    (mirroring test_datastores_join_internal_only). The core is the subject of the invariant.
    """
    nets = _service_networks(compose, "alfred-core")
    assert nets == {"alfred_internal"}, (
        f"alfred-core must join alfred_internal ONLY (connectivity-free core); got {sorted(nets)}."
    )


def test_no_service_uses_host_network_mode(compose: dict[str, Any]) -> None:
    """G7-3 (sec-001): network_mode: host bypasses the custom networks entirely — forbid it."""
    for name, svc in (compose.get("services", {}) or {}).items():
        assert "network_mode" not in (svc or {}), (
            f"{name} sets network_mode (bypasses alfred_internal/alfred_external isolation)."
        )


def test_core_depends_on_gateway(compose: dict[str, Any]) -> None:
    """G7-3 (Spec C §11, arch-001): the isolated core waits for the gateway egress plane."""
    depends = (compose.get("services", {}).get("alfred-core", {}) or {}).get("depends_on", {}) or {}
    assert (
        isinstance(depends, dict)
        and depends.get("alfred-gateway", {}).get("condition") == "service_healthy"
    ), (
        "alfred-core must depend_on alfred-gateway with condition=service_healthy so the "
        f"egress proxy/relay listeners are up before first CONNECT; got depends_on={depends!r}."
    )


# ---------------------------------------------------------------------------
# G7-1b (Spec C §4.1): the egress forward-proxy flip — the core routes provider
# egress through the gateway L7 CONNECT proxy, which never host-publishes its port.
# ---------------------------------------------------------------------------

_EGRESS_PROXY_PORT = 8889


def _container_port(mapping: Any) -> str:
    """The CONTAINER-side port of a Compose ``ports`` entry, in EITHER mapping form.

    Short form is a string (``"8889:8889"`` / ``"127.0.0.1:8889:8889/tcp"``) — the part after
    the last ``:``, stripped of any ``/proto``. Long form is a dict with a ``target`` key — the
    container port directly. Handling both closes the bypass where a long-form mapping evades a
    string-only split (CR).
    """
    if isinstance(mapping, dict):
        return str(mapping.get("target", ""))
    return str(mapping).split(":")[-1].split("/")[0]


def test_egress_proxy_port_never_host_published(compose: dict[str, Any]) -> None:
    """G7-1b rider 1: NO service host-publishes the egress proxy container port.

    Defense-in-depth across ALL services (the existing
    ``test_alfred_gateway_publishes_no_host_port`` is the primary gateway guard): inspect the
    CONTAINER side of every ``ports`` mapping in BOTH the short (string) and long (dict) Compose
    forms, so a ``"8889:8889"`` OR a ``{target: 8889, published: 8889}`` on any service fails
    loud. The egress proxy must stay compose-internal (the destination allowlist is the security
    control during the pre-internal:true window, closed structurally at G7-3).
    """
    for name, svc in (compose.get("services", {}) or {}).items():
        for mapping in svc.get("ports", []) or []:
            assert _container_port(mapping) != str(_EGRESS_PROXY_PORT), (
                f"{name} host-publishes the egress proxy container port "
                f"{_EGRESS_PROXY_PORT}; the egress proxy must stay compose-internal "
                "(Spec C G7-1b rider 1)."
            )


def test_core_routes_egress_through_gateway_proxy(compose: dict[str, Any]) -> None:
    """G7-1b: alfred-core routes provider egress through the gateway L7 CONNECT proxy."""
    env = compose["services"]["alfred-core"].get("environment", {}) or {}
    # Assert the EXACT default-chain value, not a substring — a drift to e.g.
    # ``alfred-gateway:9999`` or a wrapped host would dial a port/host the proxy does not bind.
    # (The compose fixture loads raw YAML, so the value is the ``${VAR:-default}`` literal, not
    # the shell-resolved URL — hence the full default-chain string here.)
    expected = f"${{ALFRED_EGRESS_PROXY_URL:-http://alfred-gateway:{_EGRESS_PROXY_PORT}}}"
    assert env.get("ALFRED_EGRESS_PROXY_URL") == expected, (
        "alfred-core must set ALFRED_EGRESS_PROXY_URL pointing at the gateway proxy "
        f"({expected}) so the connectivity-free core dials it for egress."
    )


def test_core_and_gateway_share_the_deepseek_base_url(compose: dict[str, Any]) -> None:
    """G7-1b: BOTH the core (which dials the provider) and the gateway (which allowlists it)
    must carry the SAME ALFRED_DEEPSEEK_BASE_URL value, so an operator override reaches both —
    else the core would dial a host the gateway's allowlist denies (a silent egress mismatch)."""
    services = compose.get("services", {})
    values = {}
    for name in ("alfred-core", "alfred-gateway"):
        env = services.get(name, {}).get("environment", {}) or {}
        assert "ALFRED_DEEPSEEK_BASE_URL" in env, (
            f"{name} must set ALFRED_DEEPSEEK_BASE_URL so the core's dialled host and the "
            "gateway's allowlist stay in lock-step under an operator override."
        )
        values[name] = str(env["ALFRED_DEEPSEEK_BASE_URL"])
    # Same default chain on both, not just present-on-both — divergent defaults would still
    # split the dialled host from the allowlisted one.
    assert values["alfred-core"] == values["alfred-gateway"], (
        f"alfred-core and alfred-gateway must share the SAME ALFRED_DEEPSEEK_BASE_URL; "
        f"got core={values['alfred-core']!r} gateway={values['alfred-gateway']!r}."
    )


def test_gateway_derives_egress_allowlist_from_same_provider_config(
    compose: dict[str, Any],
) -> None:
    """G7-1b: the gateway derives its destination allowlist from the SAME provider config the
    core uses, so an operator base_url override reaches BOTH (else a silent allowlist
    mismatch). The gateway therefore carries the proxy PORT + the DeepSeek base URL — neither
    is a secret, so this does not breach ``test_no_secret_env_or_mount_on_gateway``.
    """
    env = compose["services"]["alfred-gateway"].get("environment", {}) or {}
    assert "ALFRED_EGRESS_PROXY_PORT" in env, (
        "alfred-gateway must set ALFRED_EGRESS_PROXY_PORT so the proxy binds the port the "
        "core dials."
    )
    assert "ALFRED_DEEPSEEK_BASE_URL" in env, (
        "alfred-gateway must set ALFRED_DEEPSEEK_BASE_URL so it derives the SAME egress "
        "allowlist as the core (no silent mismatch on a base_url override)."
    )


# ---------------------------------------------------------------------------
# G7-2c (Spec C §4.3): tool-egress relay wiring — core dials the right gateway
# relay port, relay-plane keys are confined to the right services, and the relay
# port is never host-published.
# ---------------------------------------------------------------------------

_RELAY_PORT = 8890

_COMPOSE_DEFAULT_RE = re.compile(r"^\$\{[^:]+:-([^}]*)\}$")


def _compose_default(raw: str) -> str:
    """Extract the ``default`` from a ``${VAR:-default}`` Compose literal.

    The compose fixture loads raw YAML, so env values are the ``${VAR:-default}``
    strings, not the shell-resolved values.  This extracts the fallback so tests
    compare apples to apples: two matching defaults mean the stack wires
    consistently when operator overrides are absent.
    """
    m = _COMPOSE_DEFAULT_RE.match(raw)
    return m.group(1) if m else raw


def test_relay_port_matches_core_relay_url(compose: dict[str, Any]) -> None:
    """G7-2c: the core's ALFRED_EGRESS_RELAY_URL port == the gateway's ALFRED_EGRESS_RELAY_PORT.

    A mismatch — core dials a port the gateway does not bind — is a silent
    black-hole: tool calls succeed in the test suite (the synthetic driver stubs
    the relay) but fail at runtime (no listener).  The two compose default values
    must agree; an operator who overrides them must set both consistently.
    """
    core_env = compose["services"]["alfred-core"].get("environment", {}) or {}
    gw_env = compose["services"]["alfred-gateway"].get("environment", {}) or {}

    raw_url = core_env.get("ALFRED_EGRESS_RELAY_URL", "")
    raw_port = gw_env.get("ALFRED_EGRESS_RELAY_PORT", "")

    assert raw_url, "alfred-core must set ALFRED_EGRESS_RELAY_URL (G7-2c)."
    assert raw_port, "alfred-gateway must set ALFRED_EGRESS_RELAY_PORT (G7-2c)."

    default_url = _compose_default(str(raw_url))
    default_port_str = _compose_default(str(raw_port))

    parsed = urlparse(default_url)
    assert parsed.port is not None, (
        f"ALFRED_EGRESS_RELAY_URL default {default_url!r} has no port component (G7-2c)."
    )
    url_port = str(parsed.port)

    assert url_port == default_port_str, (
        f"Port mismatch: ALFRED_EGRESS_RELAY_URL default dials :{url_port} but "
        f"ALFRED_EGRESS_RELAY_PORT default binds :{default_port_str}. "
        "The core would dial a port the gateway does not bind (G7-2c)."
    )


def test_relay_env_keys_on_correct_services(compose: dict[str, Any]) -> None:
    """G7-2c: relay-plane env keys are confined to the correct services.

    Positives:
    - ``ALFRED_EGRESS_RELAY_URL`` on the core (it is the relay *client*).
    - ``ALFRED_TOOL_EGRESS_ALLOWLIST`` + ``ALFRED_CANARY_TOKENS`` on the gateway
      (gateway-only — NOT symmetric like ``ALFRED_DEEPSEEK_BASE_URL``; the core
      runs its own 3-way allowlist + core DLP).

    Negatives lock against drift: a core-side ``ALFRED_CANARY_TOKENS`` would
    shadow the gateway's canary seeding at the wrong layer; a gateway-side
    ``ALFRED_EGRESS_RELAY_URL`` would configure the gateway as its own relay
    client (nonsense).
    """
    core_env = compose["services"]["alfred-core"].get("environment", {}) or {}
    gw_env = compose["services"]["alfred-gateway"].get("environment", {}) or {}

    # Positive: relay URL belongs on the core (the relay *client*)
    assert "ALFRED_EGRESS_RELAY_URL" in core_env, (
        "alfred-core must declare ALFRED_EGRESS_RELAY_URL so the relay client seam "
        "picks up the gateway address (G7-2c)."
    )
    # Positive: gateway-only keys belong on the gateway
    assert "ALFRED_TOOL_EGRESS_ALLOWLIST" in gw_env, (
        "alfred-gateway must declare ALFRED_TOOL_EGRESS_ALLOWLIST (gateway-only; "
        "the core runs a separate 3-way allowlist) — G7-2c."
    )
    assert "ALFRED_CANARY_TOKENS" in gw_env, (
        "alfred-gateway must declare ALFRED_CANARY_TOKENS (gateway-only DLP seeding) — G7-2c."
    )
    assert "ALFRED_EGRESS_RELAY_PORT" in gw_env, (
        "alfred-gateway must declare ALFRED_EGRESS_RELAY_PORT (relay listener port; "
        "mirrors ALFRED_EGRESS_PROXY_PORT) — G7-2c."
    )
    # Negative: relay URL must NOT be on the gateway (it is the relay *server*)
    assert "ALFRED_EGRESS_RELAY_URL" not in gw_env, (
        "alfred-gateway must NOT carry ALFRED_EGRESS_RELAY_URL — the gateway IS the "
        "relay listener; the URL belongs only on the core (G7-2c)."
    )
    # Negative: gateway-only keys must NOT be on the core
    assert "ALFRED_TOOL_EGRESS_ALLOWLIST" not in core_env, (
        "alfred-core must NOT carry ALFRED_TOOL_EGRESS_ALLOWLIST — this is a "
        "gateway-only key (G7-2c)."
    )
    assert "ALFRED_CANARY_TOKENS" not in core_env, (
        "alfred-core must NOT carry ALFRED_CANARY_TOKENS — this is a gateway-only key (G7-2c)."
    )
    assert "ALFRED_EGRESS_RELAY_PORT" not in core_env, (
        "alfred-core must NOT declare ALFRED_EGRESS_RELAY_PORT as an env key — the core "
        "dials the full ALFRED_EGRESS_RELAY_URL; the port lives only on the gateway (G7-2c)."
    )


def test_relay_port_never_host_published(compose: dict[str, Any]) -> None:
    """G7-2c: NO service host-publishes the tool-egress relay container port (8890).

    Mirrors ``test_egress_proxy_port_never_host_published`` (8889 guard) exactly:
    inspect the CONTAINER side of every ``ports`` mapping in both the short (string)
    and long (dict) Compose forms across ALL services.  The relay listener must stay
    compose-internal — exposing it would allow any host process to inject
    tool-call responses directly into the framed relay wire, bypassing the
    gateway's DLP and canary checks.
    """
    for name, svc in (compose.get("services", {}) or {}).items():
        for mapping in svc.get("ports", []) or []:
            assert _container_port(mapping) != str(_RELAY_PORT), (
                f"{name} host-publishes the tool-egress relay container port "
                f"{_RELAY_PORT}; the relay must stay compose-internal (G7-2c)."
            )


# ---------------------------------------------------------------------------
# G7-4 (Spec C §4.4 / devops-001): Discord adapter egress volume + allowlist env
# are gateway-ONLY.  The connectivity-free core must never touch either.
# ---------------------------------------------------------------------------


def test_discord_egress_volume_gateway_only(compose: dict[str, Any]) -> None:
    """G7-4 / devops-001: alfred_discord_egress is mounted by the gateway and NOT the core.

    The Discord egress socket dir is the gateway's egress plane for the hosted Discord
    adapter.  Mounting it on the core would give the connectivity-free core a path to the
    Discord network socket, breaking the Spec-C structural isolation invariant.
    """
    gw = _volume_strings(compose["services"]["alfred-gateway"].get("volumes", []) or [])
    core = _volume_strings(compose["services"]["alfred-core"].get("volumes", []) or [])
    # Exact source match (mirrors the alfred_run invariant): a future volume whose name
    # merely CONTAINS ``alfred_discord_egress`` (e.g. ``alfred_discord_egress_backup``) must
    # neither satisfy the gateway mount nor false-trip the core-isolation guard.
    assert any(v.split(":", 1)[0] == "alfred_discord_egress" for v in gw), (
        "alfred-gateway must mount alfred_discord_egress (G7-4 Discord adapter egress socket dir)."
    )
    assert not any(v.split(":", 1)[0] == "alfred_discord_egress" for v in core), (
        "devops-001: alfred_discord_egress must NOT be mounted on alfred-core — "
        "the connectivity-free core must never reach the Discord egress socket (Spec C / G7-4)."
    )


def test_discord_egress_allowlist_env_gateway_only(compose: dict[str, Any]) -> None:
    """G7-4 / devops-001: ALFRED_DISCORD_EGRESS_ALLOWLIST is on the gateway and NOT the core.

    The allowlist controls which Discord endpoints the gateway's L7-proxy permits.
    Placing it on the core would be meaningless (the core has no egress socket) and would
    signal a future wiring mistake; keeping it gateway-only is the structural guard.
    """
    gw_env = compose["services"]["alfred-gateway"].get("environment", {}) or {}
    core_env = compose["services"]["alfred-core"].get("environment", {}) or {}
    assert "ALFRED_DISCORD_EGRESS_ALLOWLIST" in gw_env, (
        "alfred-gateway must declare ALFRED_DISCORD_EGRESS_ALLOWLIST "
        "(Discord L7-proxy allowlist; empty default = built-in discord.com"
        " + *.discord.gg set) — G7-4."
    )
    assert "ALFRED_DISCORD_EGRESS_ALLOWLIST" not in core_env, (
        "alfred-core must NOT carry ALFRED_DISCORD_EGRESS_ALLOWLIST — "
        "Discord allowlist enforcement is gateway-only (devops-001 / G7-4)."
    )


# ---------------------------------------------------------------------------
# #470 Task 6: core metrics port env + healthcheck, never host-published.
# Mirrors the gateway's existing ALFRED_GATEWAY_METRICS_PORT / healthcheck pair
# (test_alfred_gateway_has_healthcheck, test_alfred_gateway_publishes_no_host_port).
# ---------------------------------------------------------------------------

_CORE_METRICS_PORT = 9465


def test_alfred_core_publishes_no_host_port(compose: dict[str, Any]) -> None:
    """CR-B: alfred-core publishes NO host ports at all — the strong form of the guard.

    Pinning only the literal 9465 leaves a hole: ``ALFRED_CORE_METRICS_PORT`` is
    operator-overridable, so a compose that published ``${ALFRED_CORE_METRICS_PORT}`` (or any
    other port the core happens to be listening on) would sail past a literal-9465 check while
    exposing the unauthenticated /metrics surface to the host. The core is connectivity-free
    and has no inbound host-facing plane at all (ADR-0040), so "no ports key" is both the
    accurate invariant and the one an override cannot evade. Mirrors
    ``test_alfred_gateway_publishes_no_host_port``.
    """
    core = compose.get("services", {}).get("alfred-core", {})
    assert not (core.get("ports") or []), (
        "alfred-core must publish no host port — /metrics is compose-internal only (#470)."
    )


def test_core_metrics_port_never_host_published(compose: dict[str, Any]) -> None:
    """Defense-in-depth across ALL services (mirrors the egress-proxy/relay-port guards):
    the core metrics port must stay compose-internal — Prometheus scrapes it over
    alfred_internal, never via a host-published mapping. Retained ALONGSIDE the
    alfred-core-specific guard above, which cannot speak for the other services."""
    for name, svc in (compose.get("services", {}) or {}).items():
        for mapping in svc.get("ports", []) or []:
            assert _container_port(mapping) != str(_CORE_METRICS_PORT), (
                f"{name} host-publishes the core metrics port {_CORE_METRICS_PORT}; it must stay "
                "compose-internal (#470)."
            )


def test_alfred_core_has_metrics_healthcheck(compose: dict[str, Any]) -> None:
    """alfred-core must probe `alfred daemon healthcheck` (mirrors the gateway's
    `alfred gateway healthcheck` pin in test_alfred_gateway_has_healthcheck)."""
    core = compose["services"]["alfred-core"]
    assert core.get("healthcheck", {}).get("test") == ["CMD", "alfred", "daemon", "healthcheck"]


def test_alfred_core_sets_core_metrics_port(compose: dict[str, Any]) -> None:
    """alfred-core must forward ALFRED_CORE_METRICS_PORT with the ${VAR:-9465} default
    chain — the daemon boot metrics seam (resolve_metrics_port) falls back to 9465
    absent the env var, so the compose default must agree (#470)."""
    env = compose["services"]["alfred-core"].get("environment", {}) or {}
    assert env.get("ALFRED_CORE_METRICS_PORT") == "${ALFRED_CORE_METRICS_PORT:-9465}"


# ---------------------------------------------------------------------------
# #470 PR2 Task 1: bundle an internal-only Prometheus into the compose stack.
# Mirrors the connectivity-free-core invariants above — the observability
# services must never reach alfred_external, and Prometheus must not expose
# an admin/lifecycle surface an unauthenticated caller could use to reload
# config or wipe the TSDB.
# ---------------------------------------------------------------------------


def test_observability_services_internal_only(compose):
    # Task 3 (#470 PR2): Grafana landed alongside Prometheus — both must stay off
    # alfred_external so neither has a route to the internet, even though nothing in
    # either's own config asks for one.
    for name in ("alfred-prometheus", "alfred-grafana"):
        nets = _service_networks(compose, name)
        assert nets == {"alfred_internal"}, (
            f"{name} must join alfred_internal ONLY; got {sorted(nets)}"
        )


def test_prometheus_has_no_admin_or_lifecycle_api(compose):
    cmd = compose["services"]["alfred-prometheus"].get("command", []) or []
    joined = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
    assert "--web.enable-admin-api" not in joined
    assert "--web.enable-lifecycle" not in joined


# rev.4 (sec-001): the "no remote_write" hardening invariant (plan line 27, spec §6.1) is
# enumerated but the command-flag test above only checks the compose `command:` array —
# remote_write/remote_read are BLOCKS in ops/prometheus/prometheus.yml, unchecked, which is
# this repo's paper-only-gate pattern (enumerated invariant, no guard). internal:true is the
# kernel-level backstop (egress can't reach a public host), so this is defense-in-depth, but
# the guard must exist. Assert over the PARSED config file. (yaml + Path are already imported
# at module scope above — no need to re-import locally.)
def test_prometheus_config_has_no_remote_write():
    cfg = yaml.safe_load((COMPOSE_PATH.parent / "ops/prometheus/prometheus.yml").read_text())
    assert "remote_write" not in cfg, "Prometheus must not remote_write (would be external egress)"
    assert "remote_read" not in cfg, "Prometheus must not remote_read"


# ---------------------------------------------------------------------------
# #470 PR2 Task 2 (rev.4 arch-002): the literal `alfred-core:9465` / `alfred-gateway:9464`
# scrape targets in ops/prometheus/prometheus.yml are static_configs — Prometheus cannot
# env-expand them — so they must be hand-kept in lockstep with the compose
# ALFRED_*_METRICS_PORT `${VAR:-default}` chains. Task 5's e2e catches prometheus.yml
# drifting FROM 9465; nothing previously caught the compose default drifting FROM
# prometheus.yml (the other direction). Reuses the `_compose_default` helper already
# defined above (G7-2c) rather than a second ad hoc regex.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# #470 PR2 Task 3: bundle the default-on, internal-only Grafana service. The
# admin credential is guarded by three layers (spec §6.2a): (1) `.env.example`
# present-but-empty + bin/alfred-setup.sh present-and-non-empty seed; (2)
# compose reads it with `:-` so no `docker compose` verb aborts; (3) the
# entrypoint preflight refuses to start Grafana when the value is unset,
# empty, or the literal `admin`. Only layer 3 holds for the operator who
# skipped setup — its RUNTIME behaviour is proven by the real-execution suite
# at tests/integration/test_grafana_password_fail_closed.py, not here (a
# lexical assertion cannot decide what a third-party binary does).
# ---------------------------------------------------------------------------


def test_grafana_password_uses_soft_default_not_required(compose: dict[str, Any]) -> None:
    env = compose["services"]["alfred-grafana"].get("environment", {}) or {}
    val = str(env.get("GF_SECURITY_ADMIN_PASSWORD", ""))
    assert val.startswith("${GF_SECURITY_ADMIN_PASSWORD:-"), (
        "must use :- (never :?) or it aborts default `up`"
    )


def test_grafana_publishes_only_loopback(compose: dict[str, Any]) -> None:
    ports = compose["services"]["alfred-grafana"].get("ports", []) or []
    # non-vacuity: a future switch to `expose:` (no host mapping) must not silently pass this test.
    assert ports, "alfred-grafana must publish at least one port mapping"
    for m in ports:
        s = m if isinstance(m, str) else f"{m.get('published', '')}"
        # ruff flags "0.0.0.0" as S104 (possible bind-all), but this is a STRING comparison
        # against a compose port mapping's text, not a bind-address construction — nothing
        # here binds a socket.
        assert "127.0.0.1" in s and not s.startswith("0.0.0.0"), (  # noqa: S104
            "Grafana must bind loopback only"
        )


# rev.3 (PR #480 CR): the `:-` arm alone does NOT fail closed — Grafana ignores an empty env
# value and falls back to defaults.ini `admin_password = admin`. Pin the preflight guard's
# SHAPE here; its RUNTIME behaviour is proven by
# tests/integration/test_grafana_password_fail_closed.py (a lexical assertion cannot decide
# what a third-party binary does).
def test_grafana_entrypoint_guards_the_admin_password(compose: dict[str, Any]) -> None:
    ep = compose["services"]["alfred-grafana"].get("entrypoint")
    joined = " ".join(ep) if isinstance(ep, list) else str(ep or "")
    assert "GF_SECURITY_ADMIN_PASSWORD" in joined, "entrypoint must preflight the admin password"
    assert "exit 78" in joined, "the guard must refuse (EX_CONFIG), not warn"
    assert "exec /run.sh" in joined, "the pass path must hand off to Grafana's real entrypoint"


def test_scrape_target_ports_match_compose_defaults(compose: dict[str, Any]) -> None:
    prom = yaml.safe_load((COMPOSE_PATH.parent / "ops/prometheus/prometheus.yml").read_text())
    targets = {
        sc["job_name"]: sc["static_configs"][0]["targets"][0] for sc in prom["scrape_configs"]
    }
    core_env = compose["services"]["alfred-core"].get("environment", {}) or {}
    core_port = _compose_default(str(core_env.get("ALFRED_CORE_METRICS_PORT", "")))
    assert targets["alfred-core"] == f"alfred-core:{core_port}", (
        f"prometheus.yml's alfred-core scrape target {targets['alfred-core']!r} must match "
        f"compose's ALFRED_CORE_METRICS_PORT default ({core_port!r}); a Prometheus "
        "static_configs target cannot env-expand, so a compose default bump silently "
        "blinds the scrape unless this file is edited in lockstep."
    )
    # gateway pair is likewise hardcoded — pin it symmetrically with the core arm above
    # (resolve the compose default, don't hand-assert a literal) so a future
    # ALFRED_GATEWAY_METRICS_PORT bump is caught the same way a core port bump is.
    gateway_env = compose["services"]["alfred-gateway"].get("environment", {}) or {}
    gateway_port = _compose_default(str(gateway_env.get("ALFRED_GATEWAY_METRICS_PORT", "")))
    assert targets["alfred-gateway"] == f"alfred-gateway:{gateway_port}", (
        f"prometheus.yml's alfred-gateway scrape target {targets['alfred-gateway']!r} must "
        f"match compose's ALFRED_GATEWAY_METRICS_PORT default ({gateway_port!r})."
    )

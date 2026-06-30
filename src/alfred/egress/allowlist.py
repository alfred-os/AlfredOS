"""Provider egress destination allowlist + IP guards (Spec C §4.1, epic #333).

Pure helpers — NO httpx, NO provider-SDK imports (the import-guard ignores this
file). The gateway L7 CONNECT proxy enforces this set; the in-core EgressClient
references it. The set is derived from LIVE provider config so it cannot drift
from a second hard-coded list.

NOTE on Anthropic: the SDK has no base_url override Setting today, so
ANTHROPIC_DEFAULT_HOST mirrors the SDK default. The anthropic SDK DOES read the
ANTHROPIC_BASE_URL env var; if an operator sets it the gateway would deny the
(non-allowlisted) host — the SAFE failure direction (deny, not leak). If an
anthropic_base_url Setting is ever added, derive this host from it (mirror
DeepSeek) to keep the no-drift property. [rev: arch-009, prov-006, devops-008]
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

EgressDestination = tuple[str, int]
ANTHROPIC_DEFAULT_HOST = "api.anthropic.com"
_DEFAULT_HTTPS_PORT = 443


def host_port_from_url(url: str, *, default_port: int = _DEFAULT_HTTPS_PORT) -> EgressDestination:
    parts = urlsplit(url)
    host = parts.hostname
    if host is None:
        raise ValueError(f"egress allowlist: URL {url!r} has no host")
    # ``is not None`` (not ``or``): an explicit port must be preserved verbatim so
    # the allowlist derives from live config without silently coercing e.g. ``:0``
    # to the default — the no-drift invariant.
    return (host, parts.port if parts.port is not None else default_port)


def is_literal_ip(host: str) -> bool:
    """True if ``host`` is a literal IPv4/IPv6 address (accepts a bracketed IPv6)."""
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def is_globally_routable(host_or_ip: str) -> bool:
    """True iff ``host_or_ip`` parses as an IP that is globally routable.

    Rejects loopback / link-local / private / reserved / multicast. A non-IP
    string returns False (the proxy only calls this on the RESOLVED address).
    """
    try:
        return ipaddress.ip_address(host_or_ip.strip("[]")).is_global
    except ValueError:
        return False


def provider_egress_allowlist(deepseek_base_url: str) -> frozenset[EgressDestination]:
    """Allowed provider egress destinations: the DeepSeek base_url host + the Anthropic
    SDK default. G7-4 adds the Discord hosts.

    Takes the base-URL STRING (not a ``Settings``) so the gateway can derive the allowlist
    WITHOUT constructing the secret-requiring ``Settings`` model — the gateway holds no
    provider API key (ADR-0036), so loading ``Settings`` there would fail / pull in secrets.
    The core passes ``settings.deepseek_base_url``; the gateway reads the public
    ``ALFRED_DEEPSEEK_BASE_URL`` env var (compose threads it to both, keeping the two
    derivations in lock-step).

    The Discord adapter has its OWN disjoint allowlist (``discord_egress_allowlist``) —
    provider egress is never merged with it."""
    return frozenset(
        {
            host_port_from_url(deepseek_base_url),
            (ANTHROPIC_DEFAULT_HOST, _DEFAULT_HTTPS_PORT),
        }
    )


Match = Callable[[str, int, frozenset[EgressDestination]], bool]


def exact_match(host: str, port: int, allow: frozenset[EgressDestination]) -> bool:
    """The provider matcher — identical to the prior ``(host, port) in allowlist``."""
    return (host, port) in allow


def suffix_match(host: str, port: int, suffix_bases: frozenset[EgressDestination]) -> bool:
    """Anchored suffix match: ``host == base`` (apex) or ``host`` ends with ``"." + base``.

    Never a bare ``endswith`` — that would match ``evildiscord.gg`` against ``discord.gg``.
    The port must match the base entry's port.
    """
    for base_host, base_port in suffix_bases:
        if port == base_port and (host == base_host or host.endswith("." + base_host)):
            return True
    return False


@dataclass(frozen=True, slots=True)
class DiscordEgressAllowlist:
    exact: frozenset[EgressDestination]
    suffix_bases: frozenset[EgressDestination]


_DISCORD_EXACT: frozenset[EgressDestination] = frozenset({("discord.com", _DEFAULT_HTTPS_PORT)})
_DISCORD_SUFFIX: frozenset[EgressDestination] = frozenset({("discord.gg", _DEFAULT_HTTPS_PORT)})


def discord_egress_allowlist(extra: str = "") -> DiscordEgressAllowlist:
    """The Discord-only egress set: ``discord.com`` exact + ``*.discord.gg`` (incl. the
    dynamic ``resume_gateway_url``) suffix. ``extra`` (the public
    ``ALFRED_DISCORD_EGRESS_ALLOWLIST`` env, comma ``host[:port]``) adds exact entries
    (e.g. ``cdn.discordapp.com`` when attachment fetch is enabled). Gateway reads the env,
    never ``Settings`` (ADR-0036)."""
    exact = set(_DISCORD_EXACT)
    for token in (t.strip() for t in extra.split(",") if t.strip()):
        host, sep, port_str = token.rpartition(":")
        if sep and port_str.isascii() and port_str.isdigit():
            exact.add((host.lower(), int(port_str)))
        else:
            exact.add((token.lower(), _DEFAULT_HTTPS_PORT))
    return DiscordEgressAllowlist(exact=frozenset(exact), suffix_bases=_DISCORD_SUFFIX)


__all__ = [
    "ANTHROPIC_DEFAULT_HOST",
    "DiscordEgressAllowlist",
    "EgressDestination",
    "Match",
    "discord_egress_allowlist",
    "exact_match",
    "host_port_from_url",
    "is_globally_routable",
    "is_literal_ip",
    "provider_egress_allowlist",
    "suffix_match",
]

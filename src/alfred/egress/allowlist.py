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
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from alfred.config.settings import Settings

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


def provider_egress_allowlist(settings: Settings) -> frozenset[EgressDestination]:
    """Allowed provider egress destinations from live config (DeepSeek base_url
    host + the Anthropic SDK default). G7-4 adds the Discord hosts."""
    return frozenset(
        {
            host_port_from_url(settings.deepseek_base_url),
            (ANTHROPIC_DEFAULT_HOST, _DEFAULT_HTTPS_PORT),
        }
    )


__all__ = [
    "ANTHROPIC_DEFAULT_HOST",
    "EgressDestination",
    "host_port_from_url",
    "is_globally_routable",
    "is_literal_ip",
    "provider_egress_allowlist",
]

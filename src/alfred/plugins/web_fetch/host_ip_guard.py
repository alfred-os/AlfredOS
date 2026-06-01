"""Host-side IP allowlist guard (sec-pr-s3-5-003 / H3 SSRF defence).

The three-way URL allowlist
(:class:`alfred.plugins.web_fetch.allowlist.AllowlistIntersection`)
matches on the URL netloc — the *name* the caller asked for. It does NOT
match on the resolved IP, so a DNS-rebinding upstream that hands back an
internal address for an allowlisted hostname (``example.com →
169.254.169.254``) would slip past unless the dispatcher pre-resolves the
hostname and refuses internal IPs explicitly. This module is that
explicit refusal.

Threat model (spec §7.4, sec-pr-s3-5-003):

* **DNS rebinding** — attacker controls DNS for an allowlisted domain
  and returns ``10.0.0.1`` / ``169.254.169.254`` / ``127.0.0.1`` so the
  fetcher hits an internal address.
* **Cloud metadata SSRF** — the AWS / Azure / GCP metadata service lives
  at ``169.254.169.254`` (link-local). A successful GET hands back IAM
  credentials.
* **RFC1918 internal endpoints** — ``10.0.0.0/8``, ``172.16.0.0/12``,
  ``192.168.0.0/16`` cover the canonical private-network ranges.
* **IPv6 link-local** — ``fe80::/10`` is the IPv6 equivalent of the
  IPv4 link-local block; the same metadata / internal-endpoint risk
  applies.
* **Multicast / reserved** — refused as the "everything else internal"
  catch-all so a future internal address class is not silently allowed.

The loopback exception (``127.0.0.0/8`` / ``::1``) covers the
documented test-fixture path: ``TlsPolicy.requires_tls`` returns
``False`` for ``http://localhost`` / ``http://127.0.0.1`` so local
integration harnesses can speak plain HTTP. We allow loopback ONLY
when:

  1. The URL's hostname IS itself a loopback host (literal
     ``127.0.0.1`` / ``localhost`` / ``::1``), AND
  2. The URL scheme is plain ``http`` (no production HTTPS to
     loopback).

This is stricter than reading ``TlsPolicy.requires_tls`` alone — a
``https://127.0.0.1/`` URL is refused so a production misconfig pointing
at localhost surfaces loud. The two-gate AND defends against the
DNS-rebinding-to-loopback case (``http://example.com/`` resolving to
``127.0.0.1`` is still refused because the URL hostname is not
literally loopback).

Design choices:

* **Synchronous ``socket.getaddrinfo``** — resolution latency for the
  Slice-3 traffic volume (single-digit fetches per minute) is dominated
  by the network round-trip that follows; an async resolver would add
  complexity without measurable benefit. If the traffic profile changes
  later, swap to ``loop.getaddrinfo`` via the same helper.
* **Refuse on ANY internal IP in the resolution set** — DNS rebinding
  can ship a multi-record response (one public IP to pass a "first IP"
  check, one RFC1918 IP for the actual connection). The classifier
  iterates every IP and refuses on the first internal hit.
* **Fail-closed on DNS error** — ``socket.gaierror`` means we cannot
  prove the target is external; refuse rather than let the network
  call resolve later.

The classifier uses :mod:`ipaddress` so the IP-class logic is the same
the Python stdlib documents (no hand-rolled bit-masks).
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Final
from urllib.parse import urlparse

import structlog

from alfred.plugins.web_fetch.errors import WebFetchInternalIPRefused
from alfred.plugins.web_fetch.tls_policy import TlsPolicy

log = structlog.get_logger(__name__)

# Loopback host-names mirrored from :mod:`tls_policy` — kept as a local
# constant rather than imported so the guard's URL-host check stays
# independent of any future TlsPolicy refactor. ``frozenset`` so a
# module-level mutation cannot relax the policy at runtime.
_LOOPBACK_URL_HOSTS: Final[frozenset[str]] = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
    }
)


def classify_ip_refusal(ip_str: str) -> str | None:
    """Return a refusal reason string if ``ip_str`` is an internal address.

    Returns ``None`` if the address is public (safe to fetch). The
    reason vocabulary is closed — ``rfc1918`` / ``link_local`` /
    ``loopback`` / ``multicast`` / ``reserved`` — so audit consumers
    can pivot on the attack class.

    Args:
        ip_str: IPv4 or IPv6 string. Must parse via :func:`ipaddress.ip_address`.

    Returns:
        The refusal reason string, or ``None`` for public IPs.

    Raises:
        ValueError: if ``ip_str`` is not a valid IP. Callers should
            treat this as a refusal (a malformed IP cannot be proved
            safe); :func:`check_url_host_ips` does so.
    """
    addr = ipaddress.ip_address(ip_str)

    # RFC1918 + link-local sit BOTH under ``is_private`` in ipaddress,
    # so we check the more specific predicates first to keep the reason
    # strings precise (auditors pivot on these).
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        # Covers 169.254.0.0/16 (IPv4) and fe80::/10 (IPv6) — the
        # cloud-metadata + IPv6 link-local SSRF surface.
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified or addr.is_reserved:
        # ``is_unspecified`` covers ``0.0.0.0`` / ``::``; ``is_reserved``
        # catches everything stdlib has tagged as the "do not route"
        # catch-all so a future internal class is not silently allowed.
        return "reserved"
    if addr.is_private:
        # RFC1918 — what's left under ``is_private`` after the more
        # specific predicates above.
        return "rfc1918"
    return None


def check_url_host_ips(url: str, tls_policy: TlsPolicy) -> None:
    """Resolve ``url`` and refuse if any resolved IP is internal.

    The fail-closed defence against DNS-rebinding / cloud-metadata SSRF.
    Called by the dispatcher AFTER the three-way allowlist passes (URL
    matched a permitted name) and BEFORE the subprocess dispatch.

    The loopback exception is structural: a URL whose hostname is
    literally ``127.0.0.1`` / ``localhost`` / ``::1`` AND whose scheme
    is ``http`` is the documented test-fixture path; loopback resolved
    IPs are allowed for that one shape only.

    Args:
        url: The URL the dispatcher is about to fetch. Must be already-
            validated against the three-way allowlist; this function is
            the IP-level second pass.
        tls_policy: The per-session :class:`TlsPolicy`. The loopback
            exception consults ``requires_tls`` so the policy's
            loopback host list is the single source of truth.

    Raises:
        WebFetchInternalIPRefused: if ANY resolved IP is internal (and
            the loopback exception does not apply), if the URL has no
            hostname, or if DNS resolution fails.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        # No hostname → cannot prove the target is external. Refuse
        # rather than let ``getaddrinfo`` default to localhost.
        raise WebFetchInternalIPRefused(
            url=url,
            resolved_ip="",
            reason="no_hostname",
        )

    # Compute the loopback-exception eligibility ONCE so the per-IP
    # loop below can reuse it. The exception applies only when ALL three
    # conditions hold: the URL host is a literal loopback name, the URL
    # scheme is plain ``http`` (no production HTTPS to loopback), AND
    # the TlsPolicy agrees the host doesn't require TLS (single source
    # of truth for the loopback set — a future TlsPolicy change to that
    # set propagates here automatically).
    url_host_is_loopback = hostname in _LOOPBACK_URL_HOSTS
    scheme_is_http_not_https = parsed.scheme == "http"
    tls_policy_agrees_no_tls = not tls_policy.requires_tls(url)
    loopback_exempt = url_host_is_loopback and scheme_is_http_not_https and tls_policy_agrees_no_tls

    try:
        # Port 0 is fine — we only care about the address. The full
        # tuple shape is ``(family, type, proto, canonname, sockaddr)``;
        # the address is ``sockaddr[0]`` for both IPv4 and IPv6.
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        # DNS failure fails closed. The structlog event lets an operator
        # correlate a refusal with the DNS state at the time.
        log.warning(
            "web_fetch.ip_guard.dns_failure",
            url=url,
            hostname=hostname,
            detail=str(exc),
        )
        raise WebFetchInternalIPRefused(
            url=url,
            resolved_ip="",
            reason="dns_failure",
        ) from exc

    for info in infos:
        sockaddr = info[4]
        # ``sockaddr[0]`` is the address string for both AF_INET and
        # AF_INET6 shapes per stdlib docs, but the typeshed stub types
        # it as ``str | int`` because the same tuple position holds the
        # AF_UNIX path field. We're only ever passed AF_INET / AF_INET6
        # results here (``getaddrinfo(host, None, type=SOCK_STREAM)``);
        # coerce to ``str`` so the downstream type narrowing on
        # :class:`WebFetchInternalIPRefused.resolved_ip` stays clean.
        ip_str = str(sockaddr[0])
        try:
            reason = classify_ip_refusal(ip_str)
        except ValueError as exc:
            # A malformed IP from the resolver cannot be proved safe.
            # Treat as a reserved refusal so the audit row carries the
            # closed-vocabulary tag.
            log.warning(
                "web_fetch.ip_guard.unparseable_ip",
                url=url,
                ip=ip_str,
                detail=str(exc),
            )
            raise WebFetchInternalIPRefused(
                url=url,
                resolved_ip=ip_str,
                reason="reserved",
            ) from exc

        if reason is None:
            continue
        if reason == "loopback" and loopback_exempt:
            # Documented test-fixture path. The structlog event keeps
            # the loopback decision auditable without raising.
            log.debug(
                "web_fetch.ip_guard.loopback_exempt",
                url=url,
                resolved_ip=ip_str,
            )
            continue
        raise WebFetchInternalIPRefused(
            url=url,
            resolved_ip=ip_str,
            reason=reason,
        )


__all__ = [
    "check_url_host_ips",
    "classify_ip_refusal",
]

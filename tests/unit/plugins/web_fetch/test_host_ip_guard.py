"""Unit tests for the host-side IP-guard (sec-pr-s3-5-003 / H3 SSRF defence).

The IP guard refuses URLs whose hostname resolves to a private / loopback /
link-local / multicast / reserved address. It closes the DNS-rebinding /
cloud-metadata SSRF / RFC1918 internal-IP attacks that the three-way URL
allowlist alone does not block — an upstream that resolves ``example.com``
to ``169.254.169.254`` (AWS metadata) or ``10.0.0.1`` would otherwise
bypass the allowlist's name-only matching.

Trust-boundary discipline (CLAUDE.md hard rule): the IP guard is the
last refusal before the network call; the table-driven tests here pin
every classification branch + the loopback-with-http-only exception so
the 100% line+branch coverage gate stays honest.
"""

from __future__ import annotations

import socket
from typing import Any

import pytest

from alfred.plugins.web_fetch.errors import WebFetchInternalIPRefused
from alfred.plugins.web_fetch.host_ip_guard import (
    check_url_host_ips,
    classify_ip_refusal,
)
from alfred.plugins.web_fetch.tls_policy import TlsPolicy

# Opt every test in this module out of the autouse ``getaddrinfo`` stub
# in :mod:`tests.unit.plugins.web_fetch.conftest` — these tests patch
# ``getaddrinfo`` themselves with the specific shape they need.
pytestmark = pytest.mark.no_getaddrinfo_stub


def _fake_getaddrinfo(ip: str) -> Any:
    """Return a ``getaddrinfo``-shaped result that yields exactly ``ip``.

    ``getaddrinfo`` returns ``[(family, type, proto, canonname, sockaddr)]``
    tuples. The IP guard reads ``sockaddr[0]`` for the address string —
    that's the only field it touches — so the rest of the tuple is filled
    with zeros that ``ipaddress`` will not see.
    """

    family = socket.AF_INET6 if ":" in ip else socket.AF_INET

    def _fake(host: str, port: int | None, *args: Any, **kwargs: Any) -> Any:
        # ``sockaddr`` shape differs by family: ``(addr, port)`` for IPv4
        # and ``(addr, port, flowinfo, scope_id)`` for IPv6. We only read
        # ``sockaddr[0]`` so the shapes both work.
        if family == socket.AF_INET6:
            sockaddr: tuple[Any, ...] = (ip, 0, 0, 0)
        else:
            sockaddr = (ip, 0)
        return [(family, socket.SOCK_STREAM, 0, "", sockaddr)]

    return _fake


# ---------------------------------------------------------------------------
# classify_ip_refusal — pure function, table-driven.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ip", "expected_reason"),
    [
        # RFC 1918 — all three blocks.
        ("10.0.0.1", "rfc1918"),
        ("10.255.255.254", "rfc1918"),
        ("172.16.0.1", "rfc1918"),
        ("172.31.255.254", "rfc1918"),
        ("192.168.0.1", "rfc1918"),
        # Link-local / cloud-metadata.
        ("169.254.169.254", "link_local"),  # AWS / Azure metadata
        ("169.254.0.1", "link_local"),
        ("fe80::1", "link_local"),
        # Loopback.
        ("127.0.0.1", "loopback"),
        ("127.255.255.254", "loopback"),
        ("::1", "loopback"),
        # Multicast.
        ("224.0.0.1", "multicast"),
        ("ff02::1", "multicast"),
        # Reserved / unspecified.
        ("0.0.0.0", "reserved"),  # noqa: S104 -- IP-classification test, not bind address
        ("::", "reserved"),
    ],
)
def test_classify_ip_refusal_internal_targets(ip: str, expected_reason: str) -> None:
    """Every internal-IP class is classified and named distinctly.

    The ``reason`` string is what the audit row records under
    ``dlp_scan_result`` so audit consumers can pivot by attack class
    (rfc1918 vs link_local vs loopback). Distinct strings per class
    keep the forensic vocabulary precise.
    """
    assert classify_ip_refusal(ip) == expected_reason


@pytest.mark.parametrize(
    "ip",
    [
        "8.8.8.8",  # public DNS
        "1.1.1.1",  # public DNS
        "93.184.216.34",  # example.com (when resolved)
        "2001:4860:4860::8888",  # public IPv6 (Google DNS)
    ],
)
def test_classify_ip_refusal_public_addresses_pass(ip: str) -> None:
    """Public addresses return ``None`` — no refusal reason."""
    assert classify_ip_refusal(ip) is None


# ---------------------------------------------------------------------------
# check_url_host_ips — integration entry point used by the dispatcher.
# ---------------------------------------------------------------------------


def test_internal_ip_refused_rfc1918(monkeypatch: pytest.MonkeyPatch) -> None:
    """A URL whose hostname resolves to an RFC1918 address is refused.

    DNS-rebinding shape: the URL ``https://example.com/foo`` would pass
    the three-way allowlist (allowlist matches on the URL netloc, not the
    resolved IP), but if the upstream resolver hands back ``10.0.0.1``
    the request would still hit an internal address. The IP guard is the
    defence.
    """
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("10.0.0.1"))
    with pytest.raises(WebFetchInternalIPRefused) as excinfo:
        check_url_host_ips("https://example.com/foo", TlsPolicy())
    assert excinfo.value.resolved_ip == "10.0.0.1"
    assert excinfo.value.url == "https://example.com/foo"
    assert excinfo.value.reason == "rfc1918"


def test_internal_ip_refused_aws_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    """AWS / Azure metadata endpoint (169.254.169.254) is refused.

    The canonical cloud-metadata SSRF target — a successful request to
    169.254.169.254 on AWS hands back IAM credentials for whatever role
    the host has. Refusing all of 169.254.0.0/16 covers AWS + Azure +
    GCP metadata.
    """
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("169.254.169.254"))
    with pytest.raises(WebFetchInternalIPRefused) as excinfo:
        check_url_host_ips("https://example.com/", TlsPolicy())
    assert excinfo.value.resolved_ip == "169.254.169.254"
    assert excinfo.value.reason == "link_local"


def test_internal_ip_refused_link_local_v6(monkeypatch: pytest.MonkeyPatch) -> None:
    """IPv6 link-local (``fe80::/10``) is refused — covers IPv6 SSRF surface."""
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("fe80::1"))
    with pytest.raises(WebFetchInternalIPRefused) as excinfo:
        check_url_host_ips("https://example.com/", TlsPolicy())
    assert excinfo.value.resolved_ip == "fe80::1"
    assert excinfo.value.reason == "link_local"


def test_external_ip_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A public IP passes the guard — no exception raised.

    The guard is one check among several (allowlist + rate limit + DLP
    happen elsewhere); a pass here just means the IP-class branch did
    not refuse.
    """
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("8.8.8.8"))
    # No raise: control returns normally.
    check_url_host_ips("https://dns.google/", TlsPolicy())


def test_loopback_allowed_when_tls_not_required(monkeypatch: pytest.MonkeyPatch) -> None:
    """``http://127.0.0.1/`` passes — TlsPolicy.requires_tls returns False.

    The loopback exception covers test fixtures and local integrations
    that speak plain HTTP against localhost. The two conditions are
    AND-ed: the scheme must be ``http`` (no production loopback HTTPS)
    AND the URL hostname must be in the loopback set. Both gates check.
    """
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    check_url_host_ips("http://127.0.0.1:8080/", TlsPolicy())


def test_loopback_refused_when_tls_required(monkeypatch: pytest.MonkeyPatch) -> None:
    """``https://127.0.0.1/`` is REFUSED — prevents loopback prod misuse.

    Even though the hostname is a literal loopback host, the
    ``https://`` scheme means this is not the documented test-fixture
    path; refuse so a production misconfig pointing at localhost over
    HTTPS surfaces loud.
    """
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    with pytest.raises(WebFetchInternalIPRefused) as excinfo:
        check_url_host_ips("https://127.0.0.1/", TlsPolicy())
    assert excinfo.value.reason == "loopback"


def test_loopback_refused_when_url_host_is_not_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``http://example.com/`` resolving to 127.0.0.1 is REFUSED.

    The DNS-rebinding-to-loopback case: the URL is plain HTTP but
    points at ``example.com`` — only literal-loopback URL hosts get the
    test-fixture exemption. A resolved-IP loopback with a non-loopback
    URL host is an attack shape (DNS rebinding pointing the host at
    the local Redis / Postgres / metadata service).
    """
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    with pytest.raises(WebFetchInternalIPRefused):
        check_url_host_ips("http://example.com/", TlsPolicy())


def test_mixed_resolution_refuses_if_any_ip_is_internal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``getaddrinfo`` returns a mix of public + internal IPs, refuse.

    A DNS rebinding attack can ship a multi-record response (one public
    address to pass a naive "first IP" check, one RFC1918 address for
    the actual connection). The guard MUST refuse on ANY internal
    address in the resolution set.
    """

    def _mixed(host: str, port: int | None, *args: Any, **kwargs: Any) -> Any:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _mixed)
    with pytest.raises(WebFetchInternalIPRefused) as excinfo:
        check_url_host_ips("https://example.com/", TlsPolicy())
    # The refusal names the offending IP — not the public one that
    # accompanied it.
    assert excinfo.value.resolved_ip == "10.0.0.1"


def test_url_without_hostname_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """A URL with no hostname (e.g. ``file:///etc/passwd``) is refused.

    Defence-in-depth: the upstream allowlist should have already rejected
    a non-HTTP scheme, but the IP guard refuses to call ``getaddrinfo``
    on an empty hostname rather than let it default to localhost.
    """
    with pytest.raises(WebFetchInternalIPRefused) as excinfo:
        check_url_host_ips("file:///etc/passwd", TlsPolicy())
    assert excinfo.value.reason == "no_hostname"


def test_unparseable_resolved_ip_refuses_as_reserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resolver that returns a non-IP string is refused as ``reserved``.

    Defence-in-depth: ``socket.getaddrinfo`` should always return a
    valid IP string in ``sockaddr[0]``, but a wrapper / mock / future
    stub that returns something else (``"not-an-ip"``) MUST refuse —
    we cannot classify the string as safe, so the closed vocabulary
    falls into ``reserved`` as the catch-all internal-IP class.
    """

    def _fake_bad_ip(host: str, port: int | None, *args: Any, **kwargs: Any) -> Any:
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("not-an-ip", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_bad_ip)
    with pytest.raises(WebFetchInternalIPRefused) as excinfo:
        check_url_host_ips("https://example.com/", TlsPolicy())
    assert excinfo.value.reason == "reserved"
    assert excinfo.value.resolved_ip == "not-an-ip"


def test_dns_resolution_failure_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """A DNS failure (``socket.gaierror``) refuses fail-closed.

    A resolver that returns NXDOMAIN cannot be safely passed through —
    a future retry might resolve to an internal IP. Refuse at the guard
    so the dispatcher's network call never happens.
    """

    def _gaierror(host: str, port: int | None, *args: Any, **kwargs: Any) -> Any:
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _gaierror)
    with pytest.raises(WebFetchInternalIPRefused) as excinfo:
        check_url_host_ips("https://nonexistent.example.invalid/", TlsPolicy())
    assert excinfo.value.reason == "dns_failure"

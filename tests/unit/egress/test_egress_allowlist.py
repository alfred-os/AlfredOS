from __future__ import annotations

import pytest

from alfred.egress.allowlist import (
    ANTHROPIC_DEFAULT_HOST,
    host_port_from_url,
    is_globally_routable,
    is_literal_ip,
    provider_egress_allowlist,
)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://api.deepseek.com/v1", ("api.deepseek.com", 443)),
        ("https://api.deepseek.com:8443/v1", ("api.deepseek.com", 8443)),
        ("http://localhost:11434/v1", ("localhost", 11434)),
        (
            "https://api.deepseek.com:0/v1",
            ("api.deepseek.com", 0),
        ),  # explicit :0 not coerced to 443
    ],
)
def test_host_port_from_url(url: str, expected: tuple[str, int]) -> None:
    assert host_port_from_url(url) == expected


@pytest.mark.parametrize(
    ("host", "literal"),
    [
        ("1.2.3.4", True),
        ("::1", True),
        ("[2606:4700::1111]", True),
        ("2606:4700:4700::1111", True),
        ("api.anthropic.com", False),
        ("localhost", False),
    ],
)
def test_is_literal_ip(host: str, literal: bool) -> None:  # noqa: FBT001 — parametrized expected value
    assert is_literal_ip(host) is literal


@pytest.mark.parametrize(
    ("ip", "ok"),
    [
        ("1.1.1.1", True),
        ("127.0.0.1", False),
        ("169.254.169.254", False),  # link-local (cloud metadata)
        ("10.0.0.5", False),
        ("::1", False),
        ("0.0.0.0", False),  # noqa: S104 — test datum (unspecified / "this host"), not a bind addr
        ("100.64.0.1", False),  # CGNAT shared address space (RFC 6598)
        ("192.0.2.1", False),  # TEST-NET-1 documentation range
        ("::ffff:127.0.0.1", False),  # IPv4-mapped loopback — must NOT slip through
        ("not-an-ip", False),
    ],
)
def test_is_globally_routable(ip: str, ok: bool) -> None:  # noqa: FBT001 — parametrized expected value
    assert is_globally_routable(ip) is ok


def test_host_port_from_url_without_host_raises() -> None:
    with pytest.raises(ValueError, match="no host"):
        host_port_from_url("not-a-url")


def test_provider_allowlist_from_settings() -> None:
    class _S:
        deepseek_base_url = "https://api.deepseek.com/v1"

    allow = provider_egress_allowlist(_S())  # type: ignore[arg-type]
    assert (ANTHROPIC_DEFAULT_HOST, 443) in allow
    assert ("api.deepseek.com", 443) in allow

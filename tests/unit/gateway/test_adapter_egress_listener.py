"""Unit tests for the gateway Discord-adapter AF_UNIX egress listener (Spec C G7-4, #333).

FIX-2: build_adapter_egress_proxy() returns ONLY the proxy (no socket, no eager bind).
FIX-8: tests assert matcher BEHAVIOUR, not match.__name__.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from alfred.egress.errors import EgressAdapterProxyUnavailableError, IOPlaneUnavailableError


def test_adapter_error_is_io_plane_subtype() -> None:
    """EgressAdapterProxyUnavailableError is a subtype of IOPlaneUnavailableError."""
    assert issubclass(EgressAdapterProxyUnavailableError, IOPlaneUnavailableError)


def test_build_returns_proxy_with_correct_unix_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """build_adapter_egress_proxy() returns a proxy whose _unix_path is DISCORD_EGRESS_SOCKET_PATH.

    FIX-2: No eager bind — the socket path must NOT exist at construction time.
    """
    import alfred.gateway.adapter_egress_listener as m

    sock_path = tmp_path / "discord" / "egress.sock"
    monkeypatch.setattr(m, "DISCORD_EGRESS_SOCKET_PATH", sock_path)

    proxy = m.build_adapter_egress_proxy()

    # FIX-2: no eager bind — the path must NOT exist yet (bind happens inside serve())
    assert not sock_path.exists(), "eager bind must NOT happen in build_adapter_egress_proxy()"
    assert proxy._unix_path == sock_path


def test_build_matcher_allows_discord_exact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The matcher allows discord.com (exact set)."""
    import alfred.gateway.adapter_egress_listener as m

    monkeypatch.setattr(m, "DISCORD_EGRESS_SOCKET_PATH", tmp_path / "d1" / "e.sock")
    proxy = m.build_adapter_egress_proxy()

    assert proxy._match("discord.com", 443, proxy._allowlist) is True


def test_build_matcher_allows_discord_gg_suffix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The matcher allows *.discord.gg hosts (suffix-base set)."""
    import alfred.gateway.adapter_egress_listener as m

    monkeypatch.setattr(m, "DISCORD_EGRESS_SOCKET_PATH", tmp_path / "d2" / "e.sock")
    proxy = m.build_adapter_egress_proxy()

    # apex of the suffix base
    assert proxy._match("discord.gg", 443, proxy._allowlist) is True
    # dynamic resume_gateway_url host
    assert proxy._match("gateway-us-east1-b.discord.gg", 443, proxy._allowlist) is True


def test_build_matcher_denies_unknown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The matcher denies non-allowlisted destinations (default-deny)."""
    import alfred.gateway.adapter_egress_listener as m

    monkeypatch.setattr(m, "DISCORD_EGRESS_SOCKET_PATH", tmp_path / "d3" / "e.sock")
    proxy = m.build_adapter_egress_proxy()

    assert proxy._match("evil.com", 443, proxy._allowlist) is False
    # bare endswith guard — evildiscord.gg must NOT match *.discord.gg
    assert proxy._match("evildiscord.gg", 443, proxy._allowlist) is False


def test_build_matcher_denies_wrong_port(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The matcher denies a port mismatch even on an allowlisted host."""
    import alfred.gateway.adapter_egress_listener as m

    monkeypatch.setattr(m, "DISCORD_EGRESS_SOCKET_PATH", tmp_path / "d4" / "e.sock")
    proxy = m.build_adapter_egress_proxy()

    assert proxy._match("discord.com", 80, proxy._allowlist) is False


def test_build_extra_allowlist_adds_exact_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """extra_allowlist adds exact-match entries (e.g. cdn.discordapp.com)."""
    import alfred.gateway.adapter_egress_listener as m

    monkeypatch.setattr(m, "DISCORD_EGRESS_SOCKET_PATH", tmp_path / "d5" / "e.sock")
    proxy = m.build_adapter_egress_proxy(extra_allowlist="cdn.discordapp.com")

    assert proxy._match("cdn.discordapp.com", 443, proxy._allowlist) is True
    assert proxy._match("evil.com", 443, proxy._allowlist) is False


@pytest.mark.asyncio
async def test_serve_maps_oserror_to_adapter_error() -> None:
    """serve_adapter_egress_failclosed maps an OSError from serve to
    EgressAdapterProxyUnavailableError."""
    from alfred.gateway.adapter_egress_listener import serve_adapter_egress_failclosed

    class _BoomProxy:
        """Minimal duck-type satisfying _EgressProxyLike: serve raises OSError."""

        async def serve(self, shutdown_event: asyncio.Event) -> None:
            del shutdown_event
            raise OSError("EADDRINUSE")

    with pytest.raises(EgressAdapterProxyUnavailableError):
        await serve_adapter_egress_failclosed(_BoomProxy(), asyncio.Event())

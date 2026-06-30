import pytest

from alfred.egress.allowlist import (
    DiscordEgressAllowlist,
    discord_egress_allowlist,
    exact_match,
    provider_egress_allowlist,
    suffix_match,
)


def test_discord_default_set():
    al = discord_egress_allowlist()
    assert isinstance(al, DiscordEgressAllowlist)
    assert ("discord.com", 443) in al.exact
    assert ("discord.gg", 443) in al.suffix_bases  # apex + subdomains via suffix


def test_exact_match_equiv_prior_membership():
    allow = frozenset({("api.anthropic.com", 443)})
    assert exact_match("api.anthropic.com", 443, allow) is True
    assert exact_match("api.anthropic.com", 80, allow) is False
    assert exact_match("evil.api.anthropic.com", 443, allow) is False


@pytest.mark.parametrize(
    "host,ok",
    [
        ("discord.gg", True),  # apex
        ("gateway.discord.gg", True),  # subdomain
        ("gateway-us-east1-b.discord.gg", True),  # dynamic resume host
        ("evildiscord.gg", False),  # near-miss: no dot boundary
        ("discord.gg.evil.com", False),  # near-miss: suffix not at end
        ("gateway.discord.gg.attacker.com", False),
        ("discord.gg.", False),  # trailing dot
    ],
)
def test_suffix_match_anchored(host, ok):
    bases = frozenset({("discord.gg", 443)})
    assert suffix_match(host, 443, bases) is ok


def test_suffix_match_port_checked():
    bases = frozenset({("discord.gg", 443)})
    assert suffix_match("gateway.discord.gg", 8080, bases) is False


def test_discord_extra_parses_both_branches_and_lowercases():
    al = discord_egress_allowlist(
        "cdn.discordapp.com:443, media.discordapp.net, CDN.Discordapp.com"
    )
    assert ("cdn.discordapp.com", 443) in al.exact  # host:port branch
    assert ("media.discordapp.net", 443) in al.exact  # bare-host branch -> default 443
    # "CDN.Discordapp.com" (no port) lowercases and collapses with the :443 entry above
    assert ("CDN.Discordapp.com", 443) not in al.exact
    assert al.suffix_bases == frozenset({("discord.gg", 443)})  # extra never widens suffix


def test_provider_and_discord_disjoint():
    prov = provider_egress_allowlist("https://api.deepseek.com/v1")
    disc = discord_egress_allowlist()
    disc_hosts = {h for h, _ in disc.exact} | {h for h, _ in disc.suffix_bases}
    prov_hosts = {h for h, _ in prov}
    assert disc_hosts.isdisjoint(prov_hosts)

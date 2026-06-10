"""sec-2: the in-plugin DLP-lite scrubs secrets before they cross stdio (#206).

Closure sec-2 (HIGH): ``_OutboundTerminal.detail_redacted`` and
``CrashedNotification.detail`` route their exception text through an in-plugin
regex-only scrubber (no broker fetch — bundled patterns) so the adapter NEVER
sends a raw ``str(exc)`` over stdio. The host re-scans on receive as
defence-in-depth, but the plugin closes the leak window at source.

This test plants an ``sk-``-shaped API key (and a Discord bot-token shape) in a
synthetic exception and asserts the scrubbed output the plugin would put on the
wire contains neither.
"""

from __future__ import annotations

from plugins.alfred_discord.dlp_lite import scrub_in_plugin

# Planted synthetic secret SHAPES (not real credentials) the scrubber must catch.
_API_KEY_SHAPE = "sk-ABCDEFGHIJKLMNOPQRSTUVWX0123"
# A Discord bot-token-shaped triple (three dot-joined base64url segments).
# Assembled from segments at runtime so the synthetic shape is never a single
# source literal — otherwise GitHub push-protection flags the (fake) fixture as a
# real Discord bot token. The runtime value is identical to the dot-joined form.
_BOT_CREDENTIAL_SHAPE = ".".join(
    ("MTk4NjIyNDgzNDcxOTI1MjQ4", "GaBcDe", "7xY9zAbCdEfGhIjKlMnOpQrStUv")
)


def test_api_key_shape_redacted() -> None:
    scrubbed = scrub_in_plugin(f"connection failed: token {_API_KEY_SHAPE} rejected")
    assert _API_KEY_SHAPE not in scrubbed
    assert "REDACTED" in scrubbed


def test_bot_token_shape_redacted() -> None:
    scrubbed = scrub_in_plugin(f"auth error with {_BOT_CREDENTIAL_SHAPE} at gateway")
    assert _BOT_CREDENTIAL_SHAPE not in scrubbed
    assert "REDACTED" in scrubbed


def test_clean_text_passes_through_unchanged() -> None:
    clean = "channel was deleted before send (HTTP 404)"
    assert scrub_in_plugin(clean) == clean


def test_multiple_secrets_all_redacted() -> None:
    text = f"both {_API_KEY_SHAPE} and {_BOT_CREDENTIAL_SHAPE} leaked"
    scrubbed = scrub_in_plugin(text)
    assert _API_KEY_SHAPE not in scrubbed
    assert _BOT_CREDENTIAL_SHAPE not in scrubbed

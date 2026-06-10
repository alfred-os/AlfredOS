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

from plugins.alfred_discord.dlp_lite import _REDACTED as _REDACTED_MARKER
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


def test_bot_token_with_leading_base64url_punctuation_redacted() -> None:
    """L4: a base64url token may begin with ``-``/``_``; a ``\\b`` anchor would
    not fire on a leading ``-`` (``-`` is a non-word char, so ``\\b`` needs a
    preceding word char). The token must still be redacted regardless of the
    character immediately before its first segment.
    """
    leading_dash_token = ".".join(
        ("-Tk5ODYyMjQ4MzQ3MTkyNTI0OA", "GaBcDe", "7xY9zAbCdEfGhIjKlMnOpQrStUv")
    )
    scrubbed = scrub_in_plugin(leading_dash_token)
    # The ENTIRE token (including its leading ``-``) must be consumed: with the
    # token alone on the line, the scrubbed output is exactly the marker. A
    # ``\b``-anchored pattern leaves the leading ``-`` (``-[REDACTED…]``), so the
    # output would NOT equal the bare marker — that is the leak this guards.
    assert scrubbed == _REDACTED_MARKER
    assert leading_dash_token not in scrubbed


def test_bot_token_with_trailing_base64url_punctuation_redacted() -> None:
    """L4 (mirror): a base64url token may END with ``-``/``_``; a trailing ``\\b``
    anchor would not fire after a ``-``/``_`` (both are non-word chars, so ``\\b``
    needs a following word char). The token must still be redacted regardless of
    the character immediately after its last segment — the symmetric leak to the
    leading-anchor case.
    """
    trailing_dash_token = ".".join(
        ("MTk4NjIyNDgzNDcxOTI1MjQ4", "GaBcDe", "7xY9zAbCdEfGhIjKlMnOpQrStU-")
    )
    scrubbed = scrub_in_plugin(trailing_dash_token)
    # With the token alone on the line, the scrubbed output is exactly the marker.
    # A ``\b``-anchored trailing boundary leaves the final ``-`` on the wire
    # (``[REDACTED…]-``) — that is the leak this guards.
    assert scrubbed == _REDACTED_MARKER
    assert trailing_dash_token not in scrubbed


def test_bot_token_redacted_when_immediately_followed_by_base64url_char() -> None:
    """A token directly abutted by a base64url char (no separator) must still be
    fully redacted; a trailing ``\\b`` would fire only at a non-word boundary, so
    a ``-`` or ``_`` butting the token would leave bytes on the wire.
    """
    token = ".".join(("MTk4NjIyNDgzNDcxOTI1MjQ4", "GaBcDe", "7xY9zAbCdEfGhIjKlMnOpQrStUv"))
    scrubbed = scrub_in_plugin(f"{token}-trailing")
    assert token not in scrubbed
    assert "REDACTED" in scrubbed

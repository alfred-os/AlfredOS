"""Unit coverage for the Discord-gateway smoke's subprocess-output redaction (CR #4, #288).

The smoke in ``tests/smoke/test_discord_gateway_smoke.py`` runs against a REAL Discord
bot token. Its assertion-failure message must NEVER embed raw ``stdout`` / ``stderr`` —
a regression that printed the token bytes would leak them into CI logs, contradicting
the module's never-log-token posture (CLAUDE.md hard rule #6).

The smoke module is module-level skipped without the token env var, so these unit tests
exercise the pure redaction helper directly (it carries no skip mark) to PIN the
never-log-token behaviour on every run, not only when a token is configured.
"""

from __future__ import annotations

from tests.smoke.test_discord_gateway_smoke import _redact_subprocess_output


def test_redaction_drops_token_shaped_bytes() -> None:
    """A Discord-bot-token-shaped string is NOT echoed verbatim in the summary."""
    # A realistic Discord bot token shape (assembled, never a real secret): three
    # dot-separated base64-ish segments.
    token = ".".join(["MTk4NjIyNDgzNDcxOTI1MjQ4", "Cl2FMQ", "fakefakefakefakefakefakefake"])
    summary = _redact_subprocess_output(token)
    assert token not in summary
    # The summary is still meaningful (length-only / redacted), not empty.
    assert summary != ""


def test_redaction_summary_is_length_only_for_arbitrary_output() -> None:
    """Arbitrary subprocess output collapses to a non-leaking length-only summary."""
    payload = "discord_bot_token=MTk4NjIyNDgzNDcxOTI1MjQ4.secret.value extra noise"
    summary = _redact_subprocess_output(payload)
    assert payload not in summary
    # The byte length is a safe, useful diagnostic and is surfaced.
    assert str(len(payload)) in summary


def test_redaction_of_empty_output_is_safe() -> None:
    """Empty output redacts to a safe, non-crashing summary."""
    summary = _redact_subprocess_output("")
    assert isinstance(summary, str)
    assert "0" in summary

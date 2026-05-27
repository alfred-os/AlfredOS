"""Tests for the shared import-violation helper.

See :mod:`tests.unit._shared.import_violation` for the helper. Both PR C's
env-read scan and PR D1's adapter-import scan exercise this through their
own failure paths; these tests pin the rendering itself.
"""

from __future__ import annotations

from pathlib import Path

from tests.unit._shared.import_violation import ImportViolation, _remediation_message


class TestRemediationMessage:
    def test_env_read_category_includes_adr_pointer(self) -> None:
        v = ImportViolation(
            file=Path("src/alfred/foo.py"),
            lineno=12,
            symbol='os.environ["ALFRED_DEEPSEEK_API_KEY"]',
            category="env_read",
        )
        msg = _remediation_message([v])
        assert "src/alfred/foo.py:12" in msg
        assert "ALFRED_DEEPSEEK_API_KEY" in msg
        assert "ADR-0012" in msg
        assert "broker.get" in msg

    def test_adapter_import_category_includes_adr_pointer(self) -> None:
        v = ImportViolation(
            file=Path("src/alfred/comms/discord.py"),
            lineno=42,
            symbol="DiscordAdapter",
            category="adapter_import",
        )
        msg = _remediation_message([v])
        assert "src/alfred/comms/discord.py:42" in msg
        assert "DiscordAdapter" in msg
        assert "ADR-0009" in msg
        assert "CommsAdapter" in msg

    def test_multiple_violations_each_get_a_stanza(self) -> None:
        vs = [
            ImportViolation(file=Path("a.py"), lineno=1, symbol="x", category="env_read"),
            ImportViolation(file=Path("b.py"), lineno=2, symbol="y", category="adapter_import"),
        ]
        msg = _remediation_message(vs)
        # Two stanzas, both categories represented.
        assert "a.py:1" in msg
        assert "b.py:2" in msg
        assert "ADR-0012" in msg
        assert "ADR-0009" in msg
        assert "2 total" in msg

    def test_empty_violations_returns_no_violations_message(self) -> None:
        msg = _remediation_message([])
        assert "0 total" in msg
        assert "(none)" in msg

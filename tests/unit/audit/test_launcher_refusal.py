"""Unit tests for the pure launcher sandbox-refusal stderr parser (#433)."""

from __future__ import annotations

import json

import pytest

from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_FIELDS
from alfred.audit.launcher_refusal import parse_launcher_refusal_rows


def _row_json(**overrides: str) -> bytes:
    row = {
        "event": "supervisor.plugin.sandbox_refused",
        "plugin_id": "alfred.quarantined-llm",
        "reason": "sandbox_block_missing",
        "environment": "development",
        "host_os": "linux",
    }
    row.update(overrides)
    return (json.dumps(row) + "\n").encode("utf-8")


def test_single_valid_row_parsed_and_canonicalized() -> None:
    (row,) = parse_launcher_refusal_rows(_row_json())
    assert row.plugin_id == "alfred.quarantined-llm"
    assert row.reason == "sandbox_block_missing"
    assert row.host_os == "linux"
    assert row.environment == "development"
    assert row.policy_ref == ""  # absent -> canonicalized
    assert set(row.as_subject().keys()) == SANDBOX_REFUSED_FIELDS


def test_policy_ref_present_preserved() -> None:
    (row,) = parse_launcher_refusal_rows(_row_json(policy_ref="policies/sandbox/full.toml"))
    assert row.policy_ref == "policies/sandbox/full.toml"


def test_interleaved_human_lines_ignored() -> None:
    raw = (
        b"supervisor.sandbox.refused.sandbox_block_missing plugin_id=x\n"
        + _row_json()
        + b"policy-resolving\n"
    )
    assert len(parse_launcher_refusal_rows(raw)) == 1


def test_multiple_rows_in_order() -> None:
    raw = _row_json(reason="unknown_host_os") + _row_json(reason="policy_ref_missing")
    assert [r.reason for r in parse_launcher_refusal_rows(raw)] == [
        "unknown_host_os",
        "policy_ref_missing",
    ]


def test_blank_lines_skipped() -> None:
    raw = b"\n   \n" + _row_json() + b"\n\n"
    assert len(parse_launcher_refusal_rows(raw)) == 1


def test_malformed_json_line_dropped() -> None:
    raw = b'{"event":"supervisor.plugin.sandbox_refused", NOT JSON\n' + _row_json()
    assert len(parse_launcher_refusal_rows(raw)) == 1


def test_unknown_event_ignored() -> None:
    raw = (
        json.dumps({"event": "supervisor.plugin.sandbox_stub_used", "plugin_id": "x"}) + "\n"
    ).encode()
    assert parse_launcher_refusal_rows(raw) == ()


def test_out_of_vocab_reason_dropped() -> None:
    assert parse_launcher_refusal_rows(_row_json(reason="totally_made_up")) == ()


def test_missing_required_field_dropped() -> None:
    # A row missing a NON-optional field (host_os) is dropped (branch coverage).
    raw = (
        json.dumps(
            {
                "event": "supervisor.plugin.sandbox_refused",
                "plugin_id": "x",
                "reason": "sandbox_block_missing",
                "environment": "development",
            }
        )
        + "\n"
    ).encode()
    assert parse_launcher_refusal_rows(raw) == ()


def test_extra_unknown_key_dropped() -> None:
    assert parse_launcher_refusal_rows(_row_json(smuggled="oops")) == ()


def test_non_dict_json_ignored() -> None:
    assert parse_launcher_refusal_rows(b'["x"]\n42\n') == ()


def test_non_utf8_bytes_do_not_raise() -> None:
    assert len(parse_launcher_refusal_rows(b"\xff\xfe bad\n" + _row_json())) == 1


def test_empty_returns_empty() -> None:
    assert parse_launcher_refusal_rows(b"") == ()


def test_row_is_frozen() -> None:
    (row,) = parse_launcher_refusal_rows(_row_json())
    with pytest.raises((AttributeError, TypeError)):
        row.reason = "x"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# sec-001/arch-001 (#433 follow-up): the parser is fed potentially
# CHILD-authored stderr on the crash path (the drain gate in
# quarantine_child_io.py is defense in depth, not the only line of defense).
# These cases prove the parser itself never raises on adversarial JSON shapes
# and never persists a value carrying control/format characters.
# ---------------------------------------------------------------------------


def _raw_object(payload: dict[str, object]) -> bytes:
    return (json.dumps(payload) + "\n").encode("utf-8")


def test_reason_as_list_dropped_no_raise() -> None:
    """A non-hashable ``reason`` (a JSON array) must be dropped, never raise.

    Before the type-validation step existed, ``payload.get("reason") not in
    SANDBOX_REFUSED_REASONS`` raised ``TypeError: unhashable type: 'list'`` —
    the CR-major-6/9 finding. This must return no rows and must not raise.
    """
    raw = _raw_object(
        {
            "event": "supervisor.plugin.sandbox_refused",
            "plugin_id": "alfred.quarantined-llm",
            "reason": ["not", "a", "string"],
            "environment": "development",
            "host_os": "linux",
        }
    )
    assert parse_launcher_refusal_rows(raw) == ()


@pytest.mark.parametrize("bad_value", [None, 42, {"nested": "object"}])
def test_non_string_field_value_dropped(bad_value: object) -> None:
    """Any present field value that isn't a ``str`` (null/number/dict) is dropped."""
    raw = _raw_object(
        {
            "event": "supervisor.plugin.sandbox_refused",
            "plugin_id": bad_value,
            "reason": "sandbox_block_missing",
            "environment": "development",
            "host_os": "linux",
        }
    )
    assert parse_launcher_refusal_rows(raw) == ()


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "linux\ninjected line",  # LF — forged log line
        "\x1b[31mred\x1b[0m",  # ANSI escape
        "‮evil",  # RIGHT-TO-LEFT OVERRIDE (bidi display-spoof)
    ],
)
def test_unsafe_field_value_dropped(unsafe_value: str) -> None:
    """A present field value carrying a control/format char is dropped, not persisted."""
    raw = _raw_object(
        {
            "event": "supervisor.plugin.sandbox_refused",
            "plugin_id": "alfred.quarantined-llm",
            "reason": "sandbox_block_missing",
            "environment": "development",
            "host_os": unsafe_value,
        }
    )
    assert parse_launcher_refusal_rows(raw) == ()


# ---------------------------------------------------------------------------
# #435: every vocab reason must round-trip, and D2's <invalid> sentinel must
# parse — the parser charset-checks nothing but Cc/Cf, so a strict prose
# marker like "<invalid>" is accepted as a plain str.
# ---------------------------------------------------------------------------


def test_every_vocab_reason_round_trips() -> None:
    """Every member of the closed vocab must survive the parser — a reason the launcher can
    write but the parser drops is a silently-lost audit row.
    """
    from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_REASONS

    for reason in sorted(SANDBOX_REFUSED_REASONS):
        line = json.dumps(
            {
                "event": "supervisor.plugin.sandbox_refused",
                "plugin_id": "alfred.example",
                "reason": reason,
                "environment": "production",
                "host_os": "linux",
            }
        )
        rows = parse_launcher_refusal_rows(line.encode() + b"\n")
        assert len(rows) == 1, f"the parser dropped the vocab reason {reason!r}"
        assert rows[0].reason == reason


def test_the_invalid_sentinel_row_parses() -> None:
    """D2: the charset-refusal row carries the `<invalid>` sentinel. It must parse — the
    parser charset-checks nothing, only Cc/Cf, so the sentinel is accepted as a plain str.
    """
    line = json.dumps(
        {
            "event": "supervisor.plugin.sandbox_refused",
            "plugin_id": "<invalid>",
            "reason": "plugin_id_charset_invalid",
            "environment": "unset",
            "host_os": "unknown",
        }
    )
    rows = parse_launcher_refusal_rows(line.encode() + b"\n")
    assert len(rows) == 1
    assert rows[0].plugin_id == "<invalid>"


def test_parser_optional_fields_not_widened() -> None:
    """D2 depends on the parser staying strict: plugin_id must NOT become optional. A row
    omitting it must still be dropped loudly, not canonicalized to "".
    """
    from alfred.audit.launcher_refusal import _OPTIONAL_FIELDS

    assert frozenset({"policy_ref"}) == _OPTIONAL_FIELDS, (
        "widening _OPTIONAL_FIELDS weakens every row on the most adversary-facing surface "
        "in the system — D2 chose the <invalid> sentinel precisely to avoid this."
    )

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

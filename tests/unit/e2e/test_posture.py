"""Self-test of the boot-posture oracles' pure decision logic (#500 fix wave).

Mirrors test_health_classifier.py: prove the extracted predicates work in isolation, on a
synthetic input, since the full e2e lane (tests/e2e/test_first_run_boot.py::test_core_is_healthy)
cannot run on this (non-Linux, no apparmor) host — this is the local proof for those branches.
"""

from __future__ import annotations

from tests.e2e._posture import _is_egress_chokepoint_ok, _is_gate_seeded

# --- _is_egress_chokepoint_ok ------------------------------------------------------------


def test_internal_only_is_ok() -> None:
    # Exactly one attached network, and it is the internal one — the connectivity-free posture.
    assert _is_egress_chokepoint_ok(["myproject_alfred_internal"]) is True


def test_internal_plus_external_is_not_ok() -> None:
    # Two attachments (internal + external) — the strict len==1 check rejects it.
    names = ["myproject_alfred_internal", "myproject_alfred_external"]
    assert _is_egress_chokepoint_ok(names) is False


def test_internal_plus_bridge_is_not_ok() -> None:
    # CodeRabbit regression: a core also attached to a routable `bridge` would have an egress
    # route; the old "has internal AND not external" check passed it — the strict len==1 rejects it.
    assert _is_egress_chokepoint_ok(["myproject_alfred_internal", "bridge"]) is False


def test_neither_network_is_not_ok() -> None:
    # Exactly one network, but not the internal one — never joining the intended network must
    # not read as "ok" just because it also didn't join the external one.
    assert _is_egress_chokepoint_ok(["bridge"]) is False


# --- _is_gate_seeded ----------------------------------------------------------------------


def test_empty_stdout_is_not_seeded() -> None:
    assert _is_gate_seeded("") is False


def test_whitespace_only_stdout_is_not_seeded() -> None:
    assert _is_gate_seeded("   \n") is False


def test_zero_count_is_not_seeded() -> None:
    # isdigit() True, but int(...) > 0 False — the second conjunct must be exercised too.
    assert _is_gate_seeded("0") is False


def test_positive_count_is_seeded() -> None:
    assert _is_gate_seeded("3") is True


def test_positive_count_with_surrounding_whitespace_is_seeded() -> None:
    # psql -tAc output is typically newline-terminated; strip() must run before isdigit().
    assert _is_gate_seeded("3\n") is True


def test_non_digit_stdout_is_not_seeded() -> None:
    # A psql error (e.g. relation-does-not-exist) prints prose, not a bare integer.
    assert _is_gate_seeded('ERROR:  relation "plugin_grants" does not exist') is False

"""Tests for the Slice-4 audit-row constants in audit_row_schemas.py.

These tests act as the AST-walk guard the ``SLICE_4_FIELDSET_NAMES``
roster's doc-comment promises: every Slice-4 ``*_FIELDS`` constant has
the correct shape (frozenset of non-empty strings), carries its required
forensic-join keys (``correlation_id`` / ``boot_id`` / equivalents), and
honours the i18n hard rule (BCP-47 ``language`` on every comms inbound
family that surfaces user-attributed bytes).

Drift from this contract — a missed roster entry, a typo'd field name,
an empty frozenset, an accidentally-removed join key, a comms inbound
field set without ``language`` — fails CI immediately. Without these
tests the constants would ship as silent vocabulary surface that
breaks downstream PRs only when their consumers wire up.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from alfred.audit import audit_row_schemas

# ---------------------------------------------------------------------------
# Roster integrity
# ---------------------------------------------------------------------------


def test_slice_4_fieldset_names_count() -> None:
    """Roster must contain exactly 25 entries (Slice-4 contract surface size).

    Adding a new Slice-4 ``*_FIELDS`` constant requires bumping this assertion
    AND extending ``SLICE_4_FIELDSET_NAMES`` in the same commit. The number
    is intentionally pinned so a roster omission surfaces here. PR-S4-2
    (#173) added ``PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS`` — the 24th;
    G0 (Spec A) added ``COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS`` — the 25th.
    """
    assert len(audit_row_schemas.SLICE_4_FIELDSET_NAMES) == 25


def test_slice_4_roster_matches_module_attrs() -> None:
    """Every name in the roster resolves to a frozenset[str] on the module."""
    missing: list[str] = []
    bad_type: list[str] = []
    bad_member: list[tuple[str, object]] = []
    for name in audit_row_schemas.SLICE_4_FIELDSET_NAMES:
        if not hasattr(audit_row_schemas, name):
            missing.append(name)
            continue
        value = getattr(audit_row_schemas, name)
        if not isinstance(value, frozenset):
            bad_type.append(name)
            continue
        for item in value:
            if not isinstance(item, str) or not item:
                bad_member.append((name, item))
    assert missing == [], f"roster names missing from module: {missing}"
    assert bad_type == [], f"roster names not frozenset: {bad_type}"
    assert bad_member == [], f"non-str / empty members: {bad_member}"


def test_slice_4_roster_no_duplicates() -> None:
    """Roster is order-stable AND unique — duplicates would mask a real omission."""
    names = audit_row_schemas.SLICE_4_FIELDSET_NAMES
    assert len(set(names)) == len(names)


_SLICE_4_SECTION_MARKER = "Slice-4 audit-row constants (PR-S4-0a foundations)"


def _slice_4_section_lineno() -> int:
    """Line number where the Slice-4 section begins.

    Used to bound the AST walk so we don't false-positive on Slice-3 constants
    that ALSO match ``*_FIELDS: Final[frozenset[str]] = frozenset(...)``.
    """
    src = Path(inspect.getfile(audit_row_schemas)).read_text()
    for i, line in enumerate(src.splitlines(), start=1):
        if _SLICE_4_SECTION_MARKER in line:
            return i
    pytest.fail(f"section marker not found: {_SLICE_4_SECTION_MARKER!r}")


def _walk_slice_4_constants() -> dict[str, ast.AnnAssign]:
    """Return every Slice-4 ``*_FIELDS`` constant assignment node found in the
    source AFTER the section header.

    Walks ``Final[frozenset[str]] = frozenset({...})`` annotations only;
    other module-level assignments are skipped.
    """
    src = Path(inspect.getfile(audit_row_schemas)).read_text()
    tree = ast.parse(src)
    section_lineno = _slice_4_section_lineno()
    found: dict[str, ast.AnnAssign] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.AnnAssign):
            continue
        if not isinstance(node.target, ast.Name):
            continue
        if node.lineno < section_lineno:
            continue
        # Slice-4 contract: <name>: Final[frozenset[str]] = frozenset({...})
        name = node.target.id
        if not name.endswith("_FIELDS"):
            continue
        found[name] = node
    return found


def test_slice_4_constants_ast_walk_matches_roster_both_directions() -> None:
    """AST-walk the Slice-4 section and assert BIDIRECTIONAL roster integrity.

    Catches:
    - "added a new constant, forgot to add to the roster" (assigned - roster)
    - "added a roster name, forgot to add the constant" (roster - assigned)
    - Slice-4 constant introduced WITHOUT the section marker (defensive — the
      section-marker line must exist for the walk to bound correctly).

    A self-referential roster pin (e.g. ``len(roster) == 23``) cannot catch
    the forward direction; this bidirectional walk does.
    """
    assigned = set(_walk_slice_4_constants())
    roster = set(audit_row_schemas.SLICE_4_FIELDSET_NAMES)

    missing_from_roster = assigned - roster
    assert missing_from_roster == set(), (
        f"Slice-4 ``*_FIELDS`` constants assigned in source but missing from "
        f"SLICE_4_FIELDSET_NAMES roster: {missing_from_roster}"
    )

    missing_from_source = roster - assigned
    assert missing_from_source == set(), (
        f"SLICE_4_FIELDSET_NAMES roster names not assigned in Slice-4 source "
        f"section: {missing_from_source}"
    )


def test_slice_4_constants_have_frozenset_shape() -> None:
    """Every Slice-4 ``*_FIELDS`` constant has the ``Final[frozenset[str]] =
    frozenset({...})`` shape its docstring promises.

    Catches typos like ``frozen_set``, accidental ``set(...)`` literal (mutable),
    accidental tuple/list assignment, or a missing ``Final`` annotation.
    """
    bad: list[str] = []
    for name, node in _walk_slice_4_constants().items():
        # Check annotation: Final[frozenset[str]]
        ann = node.annotation
        if not (
            isinstance(ann, ast.Subscript)
            and isinstance(ann.value, ast.Name)
            and ann.value.id == "Final"
        ):
            bad.append(f"{name}: annotation not Final[...]")
            continue
        inner = ann.slice
        if not (
            isinstance(inner, ast.Subscript)
            and isinstance(inner.value, ast.Name)
            and inner.value.id == "frozenset"
        ):
            bad.append(f"{name}: annotation not Final[frozenset[...]]")
            continue
        # Check RHS: frozenset({...})
        rhs = node.value
        if not (
            isinstance(rhs, ast.Call)
            and isinstance(rhs.func, ast.Name)
            and rhs.func.id == "frozenset"
        ):
            bad.append(f"{name}: assignment RHS not frozenset(...)")
            continue
    assert bad == [], f"Slice-4 constants with wrong shape: {bad}"


# ---------------------------------------------------------------------------
# Forensic join-key discipline
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("constant_name", "required_key"),
    [
        # ``correlation_id`` is the dispatch-cycle join key — the
        # PROPOSAL_DISPATCH_FAILURE_REDACTED row joins back to its
        # processed/cycle siblings via this field (Slice-3 precedent).
        ("PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS", "correlation_id"),
        # The scan-failed sibling (#173 err-003) joins back via the same
        # dispatch-cycle correlation id.
        ("PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS", "correlation_id"),
        # Daemon-boot uses boot_id as its join key (multiple boot rows
        # share boot_id across the boot lifecycle).
        ("DAEMON_BOOT_FIELDS", "boot_id"),
        ("DAEMON_BOOT_FAILED_FIELDS", "boot_id"),
        ("DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS", "boot_id"),
        # Carrier substitution uses (hookpoint, subscriber_id) as the
        # composite join key.
        ("CARRIER_SUBSTITUTION_FIELDS", "subscriber_id"),
        ("CARRIER_SUBSTITUTION_REFUSED_FIELDS", "subscriber_id"),
        # Operator-session rows join via user_id (success) or
        # attempted_user_id + resolved_user_id (refused).
        ("OPERATOR_SESSION_CREATED_FIELDS", "user_id"),
        ("OPERATOR_SESSION_REVOKED_FIELDS", "user_id"),
        ("OPERATOR_SESSION_REFUSED_FIELDS", "attempted_user_id"),
        ("OPERATOR_SESSION_REFUSED_FIELDS", "resolved_user_id"),
        # Comms families key off (adapter_id, inbound_message_id).
        ("COMMS_INBOUND_T3_PROMOTION_FIELDS", "inbound_message_id"),
    ],
)
def test_join_key_present(constant_name: str, required_key: str) -> None:
    """Every Slice-4 constant carries its declared forensic join key."""
    value = getattr(audit_row_schemas, constant_name)
    assert required_key in value, f"{constant_name} missing required join key {required_key!r}"


# ---------------------------------------------------------------------------
# Closed-vocab discriminator discipline
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "constant_name",
    [
        "CARRIER_SUBSTITUTION_REFUSED_FIELDS",
        "CONFIG_RELOAD_REJECTED_FIELDS",
        "OPERATOR_SESSION_REFUSED_FIELDS",
        "SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS",
        "SANDBOX_REFUSED_FIELDS",
        "COMMS_ADAPTER_CRASHED_FIELDS",
        "COMMS_HANDLER_FAILED_FIELDS",
        "SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS",
    ],
)
def test_refusal_rows_have_reason_discriminator(constant_name: str) -> None:
    """Every refusal / failure / restart row carries a closed-vocab
    ``reason`` discriminator (or its named equivalent for daemon-boot:
    ``failure_reason``).

    Without a closed discriminator, downstream alert / runbook / SLO
    bucketing has no enumerated surface and vocabulary drifts.
    """
    value = getattr(audit_row_schemas, constant_name)
    assert "reason" in value, f"{constant_name} missing 'reason' discriminator field"


def test_daemon_boot_failed_has_failure_reason() -> None:
    """``DAEMON_BOOT_FAILED_FIELDS`` uses ``failure_reason`` (boot-specific name)."""
    assert "failure_reason" in audit_row_schemas.DAEMON_BOOT_FAILED_FIELDS


# ---------------------------------------------------------------------------
# i18n hard rule — language on user-attributed comms inbound rows
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "constant_name",
    [
        # The T3 promotion row promotes user-authored bytes; the language
        # tag is needed by every downstream consumer that surfaces the
        # user's prose back to them.
        "COMMS_INBOUND_T3_PROMOTION_FIELDS",
        # The binding-request DM is rendered back to the user; render in
        # the user's language (i18n hard rule).
        "COMMS_BINDING_REQUESTED_FIELDS",
        # The rate-limit budget-capped row surfaces a user-visible
        # "you were rate-limited" message; render in the user's locale.
        "COMMS_INBOUND_BUDGET_CAPPED_FIELDS",
    ],
)
def test_user_attributed_comms_rows_carry_language(constant_name: str) -> None:
    """User-attributed comms inbound rows MUST carry BCP-47 ``language``.

    The header comment on the Slice-4 constants block asserts this; the
    test enforces it.
    """
    value = getattr(audit_row_schemas, constant_name)
    assert "language" in value, (
        f"{constant_name} missing 'language' field — required by i18n hard rule "
        f"for user-attributed comms inbound surface"
    )


# ---------------------------------------------------------------------------
# Field-set size sanity
# ---------------------------------------------------------------------------


def test_no_oversized_field_sets() -> None:
    """No Slice-4 ``*_FIELDS`` constant exceeds 10 fields.

    Rule of thumb: a row with more than 10 fields is too coarse — split
    into a sibling row keyed off the same forensic-join field, or push
    detail into a structured nested column.
    """
    oversized = {
        name: len(getattr(audit_row_schemas, name))
        for name in audit_row_schemas.SLICE_4_FIELDSET_NAMES
        if len(getattr(audit_row_schemas, name)) > 10
    }
    assert oversized == {}, f"field sets >10 fields (too coarse): {oversized}"


def test_no_empty_field_sets() -> None:
    """An empty frozenset would emit a row with no fields — silent contract."""
    empty = [
        name
        for name in audit_row_schemas.SLICE_4_FIELDSET_NAMES
        if len(getattr(audit_row_schemas, name)) == 0
    ]
    assert empty == [], f"empty frozenset Slice-4 constants: {empty}"

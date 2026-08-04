"""The launcher must NAME a sub-floor interpreter, never guess (#568).

`:241` imports `alfred`, so the #568 floor guard fires there pre-exec. The old
`*)` arm rewrote any unrecognised capture to `environment_not_set` — wrong
subsystem, wrong remedy, and persisted to the SIGNED sandbox_refused row
(CLAUDE.md hard rule 7). Mirrors the `reason_unclassified` exemplar at `:440`.
"""

from __future__ import annotations

from alfred._python_floor import REFUSAL_KEY
from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_REASONS


def test_the_floor_reason_is_in_the_closed_vocabulary() -> None:
    assert "interpreter_below_floor" in SANDBOX_REFUSED_REASONS


def test_the_refusal_key_maps_onto_the_vocabulary() -> None:
    """The guard's bare key and the audit reason must not drift apart."""
    assert REFUSAL_KEY.removeprefix("daemon.boot.") in SANDBOX_REFUSED_REASONS


def test_the_environment_arm_recognises_the_floor_key() -> None:
    """The floor key must be a REAL case arm, not merely present somewhere in the file.

    The prior version of this test asserted ``REFUSAL_KEY in source`` against the WHOLE
    launcher script, so it would still pass if the key were demoted to a comment while the
    case arm itself fell through to the `*)` fallback — nothing tied the key to the branch
    that actually classifies it (CodeRabbit round 2). Reuses the launcher's own case-block
    parser (DRY — this file does not re-derive case-parsing logic) to bind the environment
    case's floor-guard arm to `REFUSAL_KEY` directly, then pins the fact independently: the
    arm must resolve to the `interpreter_below_floor` audit reason after the `daemon.boot.`
    prefix-strip the launcher applies before writing the sandbox_refused row.
    """
    from tests.unit.plugins.test_sandbox_reason_vocab_sync import _parse_environment_case

    _, floor_arm, _ = _parse_environment_case()
    assert floor_arm is not None, (
        "no floor-guard arm found in the launcher's environment case — a sub-floor "
        "interpreter would fall through to the `*)` fallback instead of being named"
    )
    assert floor_arm == REFUSAL_KEY, (
        f"the environment case's floor-guard arm is {floor_arm!r}, not {REFUSAL_KEY!r} — "
        f"the key is not bound to a real case arm (e.g. demoted to a comment), so a "
        f"sub-floor interpreter would fall through to the `*)` fallback instead of being "
        f"named"
    )
    assert floor_arm.removeprefix("daemon.boot.") == "interpreter_below_floor", (
        "the floor-guard arm no longer resolves to the interpreter_below_floor audit "
        "reason after the daemon.boot. prefix-strip"
    )


def test_the_environment_arm_does_not_guess() -> None:
    """The `*)` fallback must alarm, not invent `environment_not_set`.

    Binds the `*)` arm's ASSIGNED LITERAL via the launcher's own case-block parser (DRY — the
    same reuse as `test_the_environment_arm_recognises_the_floor_key` above), rather than a
    substring search over the whole case-statement span. A substring-over-span check is not
    bound to the `*)` arm specifically: it would still pass if the fallback assigned the wrong
    reason while an unrelated comment elsewhere in the same case block happened to mention
    `reason_unclassified` (round-3 CodeRabbit finding — the sibling assertion above was hardened
    in round 2 and this one was left unbound).
    """
    from tests.unit.plugins.test_sandbox_reason_vocab_sync import _parse_environment_case

    _, _, fallback = _parse_environment_case()
    assert fallback == "daemon.boot.reason_unclassified", (
        f"the environment-capture `*)` arm assigns {fallback!r}, not "
        f"'daemon.boot.reason_unclassified' — an unclassifiable capture is a drift/crash alarm; "
        f"mirror the `:440` exemplar rather than guessing a specific reason."
    )

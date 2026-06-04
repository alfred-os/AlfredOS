"""Unit tests for the canonical hookpoint manifest module (issue #151)."""

from __future__ import annotations

from alfred.hooks._known_hookpoints import KNOWN_HOOKPOINTS, all_known_hookpoints


def test_manifest_is_non_empty() -> None:
    assert len(KNOWN_HOOKPOINTS) > 0
    for subsystem, names in KNOWN_HOOKPOINTS.items():
        assert isinstance(subsystem, str)
        assert len(names) > 0, f"subsystem {subsystem!r} has empty hookpoint tuple"
        for name in names:
            assert isinstance(name, str)


def test_all_known_hookpoints_returns_flat_tuple() -> None:
    flat = all_known_hookpoints()
    assert isinstance(flat, tuple)
    expected_count = sum(len(names) for names in KNOWN_HOOKPOINTS.values())
    assert len(flat) == expected_count


def test_no_duplicate_hookpoint_names_across_subsystems() -> None:
    flat = all_known_hookpoints()
    assert len(flat) == len(set(flat)), (
        f"duplicate hookpoint names across subsystems: "
        f"{[name for name in flat if flat.count(name) > 1]}"
    )


def test_grant_hookpoints_present() -> None:
    """Slice-3's plugin.grant.* family — the #149 CR-1 use case."""
    flat = all_known_hookpoints()
    for name in (
        "plugin.grant.requested",
        "plugin.grant.approved",
        "plugin.grant.denied",
        "plugin.grant.revoked",
    ):
        assert name in flat, f"{name} missing from manifest"


def test_web_fetch_hookpoint_present() -> None:
    assert "tool.web.fetch" in all_known_hookpoints()


def test_identity_hookpoints_present() -> None:
    flat = all_known_hookpoints()
    assert "identity.t1_ingress" in flat
    assert "identity.t1_downgrade" in flat


def test_supervisor_lifecycle_hookpoints_present() -> None:
    flat = all_known_hookpoints()
    for name in (
        "plugin.lifecycle.loaded",
        "plugin.lifecycle.crashed",
        "plugin.lifecycle.quarantined",
    ):
        assert name in flat


def test_supervisor_breaker_hookpoints_present() -> None:
    """Supervisor's breaker + action-timeout family (core-010 emits these
    from ``Supervisor._register_hookpoints`` alongside the lifecycle
    three). Pinned explicitly so a refactor that drops one fails this
    test rather than silently shrinking the manifest."""
    flat = all_known_hookpoints()
    for name in (
        "supervisor.breaker.tripped",
        "supervisor.breaker.reset",
        "supervisor.action_timeout",
    ):
        assert name in flat, f"{name} missing from manifest"

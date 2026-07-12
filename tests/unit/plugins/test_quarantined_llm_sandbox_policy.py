"""Quarantined-LLM sandbox-policy bytes — the arch-portable `/lib64` bind (#269).

Sibling of ``test_discord_adapter_sandbox_policy.py`` (which pins the Discord
adapter's policy bytes); the quarantined LLM's policy bytes had unit coverage
only at the *manifest* level (``test_quarantined_llm_manifest.py``) and at the
*kernel* level (``tests/integration/test_quarantined_llm_policy_kernel_enforced.py``)
— never at the translated-flag level. #269 is exactly the bug that gap let
through, so the flag-level contract is pinned here.

**#269 — the arm64 real-spawn failure.** The policy bound ``/lib64`` with a HARD
``--ro-bind``, emitted unconditionally. ``/lib64`` holds the dynamic linker on
x86-64 (``ld-linux-x86-64.so.2``) but does NOT exist on arm64 — the aarch64
loader lives at ``/lib/ld-linux-aarch64.so.1``, under the already-bound ``/lib``.
So on aarch64 bwrap died at launch with ``Can't find source path /lib64``, the
dual-LLM child never emitted a frame, and the host surfaced it as a truncated
``read_frame_failed``. Binding it SOFTLY (``--ro-bind-try``: bind iff present,
else skip) makes the SAME policy bytes portable across both arches without
weakening isolation — the mount stays read-only, and an absent source was
unreachable anyway.

These tests pin:

* ``/lib64`` is a SOFT bind (``ro_binds_try`` → ``--ro-bind-try``) and never
  survives as a hard ``--ro-bind`` (which is the arm64 launch failure);
* ``/usr`` + ``/lib`` stay HARD binds — they always exist, so a missing one is a
  real error that must fail loud, not be silently skipped into a broken sandbox;
* the containment posture the dual-LLM split rests on is unchanged (no ``/etc``,
  empty netns, pid/uts/cgroup/ipc unshared, dies with parent, fd 3 kept).
"""

from __future__ import annotations

from pathlib import Path

from alfred.plugins.sandbox_policy import policy_to_bwrap_flags, read_policy_toml


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _linux_policy_text() -> str:
    return (_repo_root() / "config" / "sandbox" / "quarantined-llm.linux.bwrap.policy").read_text(
        encoding="utf-8"
    )


def _hard_ro_bind_sources(flags: list[str]) -> list[str]:
    return [flags[i + 1] for i, flag in enumerate(flags) if flag == "--ro-bind"]


def test_lib64_is_a_soft_bind_so_the_child_spawns_on_arm64() -> None:
    """``/lib64`` translates to ``--ro-bind-try``, never a hard ``--ro-bind`` (#269)."""
    policy = read_policy_toml(_linux_policy_text())
    # Pin EXACTLY, not membership — a soft bind silently skips a missing source, so
    # it is a quieter hiding place than a hard one, and `in` would let a future
    # `["/etc", "/etc"]` soft bind slip past unnoticed.
    assert list(policy.ro_binds_try) == [("/lib64", "/lib64")]
    assert ("/lib64", "/lib64") not in policy.ro_binds

    flags = policy_to_bwrap_flags(policy)
    i = flags.index("--ro-bind-try")
    assert flags[i : i + 3] == ["--ro-bind-try", "/lib64", "/lib64"]
    # THE regression guard: a hard /lib64 bind is what killed the aarch64 spawn.
    assert "/lib64" not in _hard_ro_bind_sources(flags)


def test_interpreter_trees_stay_hard_binds() -> None:
    """``/usr`` + ``/lib`` must fail LOUD if absent — they are never arch-variable.

    Soft-binding these would trade a loud launch failure for a silently
    degraded sandbox (a child that cannot link, or worse, one whose expected
    read-only tree simply is not there). Only genuinely arch-variable paths
    belong in ``ro_binds_try``.
    """
    policy = read_policy_toml(_linux_policy_text())
    hard = _hard_ro_bind_sources(policy_to_bwrap_flags(policy))
    assert "/usr" in hard
    assert "/lib" in hard


def test_no_shipped_linux_policy_hard_binds_lib64() -> None:
    """STRUCTURAL guard: NO shipped Linux policy may hard-bind ``/lib64`` (#269).

    The per-policy tests above are enumerated by hand, so a THIRD
    ``config/sandbox/*.linux.bwrap.policy`` could ship a hard ``--ro-bind /lib64``
    and reintroduce the arm64 launch failure with zero coverage. This globs the
    shipped set instead, so the guard grows automatically with the policies.
    """
    policies = sorted((_repo_root() / "config" / "sandbox").glob("*.linux.bwrap.policy"))
    assert policies, "no shipped Linux bwrap policies found — the glob is wrong"
    for path in policies:
        policy = read_policy_toml(path.read_text(encoding="utf-8"))
        hard = _hard_ro_bind_sources(policy_to_bwrap_flags(policy))
        assert "/lib64" not in hard, (
            f"{path.name} hard-binds /lib64 — this kills the bwrap launch on arm64 "
            f"('Can't find source path /lib64'). Declare it in ro_binds_try instead."
        )


def test_containment_posture_unchanged_by_the_soft_bind() -> None:
    """The dual-LLM containment the soft bind sits inside is untouched (#269)."""
    policy = read_policy_toml(_linux_policy_text())
    flags = policy_to_bwrap_flags(policy)
    joined = " ".join(flags)

    # No host /etc reaches the most adversary-facing process in the system.
    assert "/etc" not in _hard_ro_bind_sources(flags)
    assert not [src for src, _dst in policy.ro_binds_try if src.startswith("/etc")]
    # Empty netns (Spec C G7-1) + the rest of the namespace isolation.
    for namespace in ("net", "pid", "uts", "cgroup", "ipc"):
        assert f"--unshare-{namespace}" in flags
    assert "--die-with-parent" in joined
    # fd 3 (the provider-key channel) is still the declared, validated channel.
    assert 3 in policy.keep_fds

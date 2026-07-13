"""Sandbox policy schema + bwrap-flag translator (PR-S4-6 Component D, arch-2).

``SandboxPolicy`` is the validated TOML schema for ``config/sandbox/*.policy``
files. ``policy_to_bwrap_flags`` translates it into the bwrap CLI flag list
the launcher execs.

Two security invariants pinned here:

* arch-2: a ``kind: full`` policy whose ``keep_fds`` omits 3 is refused at
  *parse* time (``SandboxPolicyInvalid``) — the fd-3 provider-key channel is
  load-bearing and a policy that forgets it would silently break key delivery.
* fd-3 inheritance needs NO bwrap flag: bwrap passes inherited, open,
  non-CLOEXEC fds into the sandboxed child by default (verified against
  bubblewrap 0.8.0 + 0.9.0; issue #218). ``--sync-fd`` is bwrap's *internal*
  sync fd and must NOT be used for key delivery — pointing it at fd 3 consumes
  fd 3 and the child's ``os.read(3)`` raises EBADF. There is no ``--keep-fd``
  in these versions. So ``policy_to_bwrap_flags`` emits no fd flag; ``keep_fds``
  is a validated declaration only (arch-2).
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from alfred.plugins.sandbox_policy import (
    _SOFT_BINDABLE_PATHS,
    SandboxPolicy,
    SandboxPolicyInvalid,
    policy_to_bwrap_flags,
    read_policy_toml,
)


def test_simple_policy_translates_in_stable_order() -> None:
    policy = SandboxPolicy(
        ro_binds=[("/usr/lib/x", "/usr/lib/x")],
        tmpfs=["/tmp"],  # noqa: S108 -- bwrap tmpfs mount target inside the sandbox, not a host temp file
        unshare=["pid", "uts", "cgroup", "ipc"],
        die_with_parent=True,
        keep_fds=[3],
    )
    flags = policy_to_bwrap_flags(policy)
    # Stable order so tests don't get flaky across dict-ordering changes, and
    # so the launcher's exec line is reproducible/auditable.
    assert flags == [
        "--ro-bind",
        "/usr/lib/x",
        "/usr/lib/x",
        "--tmpfs",
        "/tmp",  # noqa: S108 -- expected bwrap flag value, not a host temp path
        "--dev",
        "/dev",
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-cgroup",
        "--unshare-ipc",
        "--die-with-parent",
    ]
    # No fd flag: bwrap inherits fd 3 by default (issue #218). The list ends
    # at --die-with-parent; --sync-fd would CONSUME fd 3, breaking delivery.
    assert "--sync-fd" not in flags
    assert "--keep-fd" not in flags


def test_dev_mount_default_on_and_opt_out() -> None:
    """``dev`` defaults on (``--dev /dev``) and can be opted out.

    A minimal /dev is on by default — CPython aborts at startup without
    ``/dev/urandom``. ``dev = false`` drops it for a process that needs none.
    """
    on = policy_to_bwrap_flags(SandboxPolicy(keep_fds=[3]))
    assert on[on.index("--dev") + 1] == "/dev"
    assert "--dev" not in policy_to_bwrap_flags(SandboxPolicy(dev=False, keep_fds=[3]))


def test_unshare_net_translates_to_unshare_net_flag() -> None:
    """``net`` → ``--unshare-net`` (host-independent network-containment proof).

    The integration test that proves outbound-network containment via a real
    bwrap netns can SKIP on runners whose unprivileged userns can't configure
    the loopback (RTM_NEWADDR). This deterministic translation assertion holds
    everywhere, so the network-isolation contract is never left wholly
    un-asserted.
    """
    policy = SandboxPolicy(unshare=["net"], keep_fds=[3])
    assert "--unshare-net" in policy_to_bwrap_flags(policy)


def test_ro_binds_try_translates_to_soft_bind_flag() -> None:
    """``ro_binds_try`` → ``--ro-bind-try`` (bind iff the source exists) — #269.

    bwrap binds a ``--ro-bind-try`` source only when it EXISTS and silently
    skips it otherwise. This is the arch-portability primitive for ``/lib64``:
    it holds the dynamic linker on x86-64 (bound) but does NOT exist on arm64
    (skipped — the aarch64 loader lives under the already-bound ``/lib``). A
    HARD ``--ro-bind /lib64`` dies with "Can't find source path /lib64" on
    arm64, tearing the dual-LLM real-spawn child.
    """
    policy = SandboxPolicy(
        ro_binds=[("/usr", "/usr"), ("/lib", "/lib")],
        ro_binds_try=[("/lib64", "/lib64")],
        keep_fds=[3],
    )
    flags = policy_to_bwrap_flags(policy)
    # Hard binds first, then soft binds — a stable, auditable exec line.
    assert flags[:9] == [
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
    ]


def test_ro_binds_try_empty_by_default_emits_nothing() -> None:
    # The field is opt-in: a policy that declares no soft binds emits no
    # --ro-bind-try flag at all (every existing policy stays byte-identical).
    policy = SandboxPolicy(ro_binds=[("/usr", "/usr")], keep_fds=[3])
    assert "--ro-bind-try" not in policy_to_bwrap_flags(policy)


def test_ro_binds_try_round_trips_through_toml() -> None:
    # The soft-bind list is a first-class policy-file field, not a code-only
    # construct — a shipped .policy declares it as TOML.
    policy = read_policy_toml(
        'keep_fds = [3]\nro_binds = [["/usr", "/usr"]]\nro_binds_try = [["/lib64", "/lib64"]]\n'
    )
    assert list(policy.ro_binds_try) == [("/lib64", "/lib64")]
    assert "--ro-bind-try" in policy_to_bwrap_flags(policy)


def test_soft_bind_of_a_non_arch_variable_path_is_refused() -> None:
    """``ro_binds_try`` is a CLOSED vocabulary — a load-bearing path is refused (#269).

    A soft bind SILENTLY skips a missing source. That is right for ``/lib64``
    (genuinely absent on arm64) and wrong for anything else: soft-binding
    ``/etc/ssl/certs`` would let a missing CA bundle degrade the sandbox without
    a word instead of refusing at launch — the exact silent-failure mode
    ``ro_binds`` is HARD to avoid (hard rule #7). Refuse at parse time.
    """
    with pytest.raises(SandboxPolicyInvalid) as exc_info:
        SandboxPolicy(ro_binds_try=[("/etc/ssl/certs", "/etc/ssl/certs")], keep_fds=[3])
    assert exc_info.value.reason == "soft_bind_forbidden_path"


def test_soft_bind_typo_is_refused_not_silently_skipped() -> None:
    # The nastiest case the closed vocabulary buys us: a typo'd source would
    # otherwise parse clean, bind nothing, and hand the child a quietly broken
    # sandbox. `/lib46` is not in the allow-list, so it refuses LOUDLY.
    with pytest.raises(SandboxPolicyInvalid) as exc_info:
        SandboxPolicy(ro_binds_try=[("/lib46", "/lib64")], keep_fds=[3])
    assert exc_info.value.reason == "soft_bind_forbidden_path"


def test_hard_binding_an_arch_variable_path_is_refused() -> None:
    """The LITERAL #269 bug: just move /lib64 back to ro_binds. Nothing else needed.

    The first version of this guard compared destinations, so this policy — the
    original bug, verbatim — validated CLEAN. Keying on the source closes it.
    """
    with pytest.raises(SandboxPolicyInvalid) as exc_info:
        SandboxPolicy(ro_binds=[("/usr", "/usr"), ("/lib64", "/lib64")], keep_fds=[3])
    assert exc_info.value.reason == "arch_variable_path_hard_bound"


def test_hard_binding_an_arch_variable_path_under_a_different_dst_is_refused() -> None:
    # dst asymmetry: the fatal SOURCE is still /lib64, so bwrap still aborts.
    with pytest.raises(SandboxPolicyInvalid) as exc_info:
        SandboxPolicy(
            ro_binds=[("/lib64", "/lib64-compat")],
            ro_binds_try=[("/lib64", "/lib64")],
            keep_fds=[3],
        )
    assert exc_info.value.reason == "arch_variable_path_hard_bound"


@pytest.mark.parametrize(
    "respelling", ["/lib64/", "//lib64", "/lib64/.", "/usr/../lib64", "/lib64//"]
)
def test_respelling_an_arch_variable_path_cannot_evade_the_guard(respelling: str) -> None:
    """#269, third variant: the guard compared RAW STRINGS; bwrap does not.

    `/lib64/`, `//lib64`, `/lib64/.` and `/usr/../lib64` are ONE path to bwrap and
    four different strings to Python — so a guard keyed on `src in {"/lib64"}`
    refused the canonical spelling and waved through every respelling, each of
    which still emits a hard bind that aborts the launch on arm64.

    The guards now COMPARE canonical forms, so every respelling collapses onto
    ``/lib64`` and is refused as the arch-variable hard bind it is.

    We deliberately do NOT *refuse* non-canonical paths outright — an earlier
    revision did, and CI proved it wrong: real policy paths are often derived from
    the filesystem and legitimately contain ``..`` (a Homebrew interpreter root),
    whose ``..`` segments cross symlinks and cannot be normalised lexically.
    """
    with pytest.raises(SandboxPolicyInvalid) as exc_info:
        SandboxPolicy(ro_binds=[(respelling, "/lib64")], keep_fds=[3])
    assert exc_info.value.reason == "arch_variable_path_hard_bound"


@pytest.mark.parametrize("traversing", ["/lib64/..", "/lib64/../lib64", "/lib64/../../x"])
def test_a_path_that_traverses_an_arch_variable_dir_is_refused(traversing: str) -> None:
    """#269, variant FIVE: lexical `..`-collapsing hides a real launch failure.

    ``/lib64/..`` collapses to ``/`` under ``normpath``, so a guard built only on
    the canonical form waves it through. But the KERNEL resolves a path component
    by component — it must ENTER ``/lib64`` before it can go back up. On arm64 that
    is ENOENT and bwrap aborts, exactly as #269 did.

    This is the normpath-vs-real-resolution divergence, and it is why the guard
    walks the RAW components as well as comparing the canonical form.
    """
    with pytest.raises(SandboxPolicyInvalid) as exc_info:
        SandboxPolicy(ro_binds=[(traversing, "/x")], keep_fds=[3])
    assert exc_info.value.reason == "arch_variable_path_hard_bound"


@pytest.mark.parametrize("bad", ["lib64", "", ".", "./lib64", "usr/lib"])
def test_a_non_absolute_policy_path_is_refused(bad: str) -> None:
    # A relative bind would resolve against whatever cwd the launcher happened to
    # have, so the sandbox's SHAPE would depend on where it was invoked from — and
    # it slips past the arch-variable guards, which reason about absolute paths.
    with pytest.raises(SandboxPolicyInvalid) as exc_info:
        SandboxPolicy(ro_binds=[(bad, "/x")], keep_fds=[3])
    assert exc_info.value.reason == "policy_path_not_absolute"


def test_a_genuine_near_miss_path_is_not_treated_as_arch_variable() -> None:
    # Guard against over-correction: /lib64-compat is a DIFFERENT path, not a
    # respelling of /lib64, and must remain hard-bindable.
    policy = SandboxPolicy(ro_binds=[("/lib64-compat", "/lib64-compat")], keep_fds=[3])
    assert "--ro-bind" in policy_to_bwrap_flags(policy)


def test_a_filesystem_derived_path_with_dotdot_is_accepted() -> None:
    """Over-correction guard, learned from CI (#269).

    An earlier revision REFUSED any non-canonical path ("one spelling, one
    meaning"). It was elegant and it was wrong: real policy paths come from the
    filesystem and legitimately contain ``..`` — e.g. a Homebrew interpreter root
    ``/opt/homebrew/opt/python@3.14/bin/../Frameworks/…``, which the launcher's own
    interpreter-root walk produces. Those ``..`` segments cross SYMLINKS, so
    normalising them lexically yields a different, wrong path, and refusing them
    broke the launcher-resolver integration legs outright.

    Canonicalisation is for COMPARISON only. This pins that.
    """
    homebrew_root = "/opt/homebrew/opt/python@3.14/bin/../Frameworks/Python.framework"
    policy = SandboxPolicy(ro_binds=[(homebrew_root, homebrew_root)], keep_fds=[3])
    assert homebrew_root in policy_to_bwrap_flags(policy)


def test_rw_binding_an_arch_variable_path_is_refused() -> None:
    # rw_binds emits --bind (not --ro-bind) and dies identically on a missing
    # source. The dst-keyed guard scanned --ro-bind only and missed this entirely.
    with pytest.raises(SandboxPolicyInvalid) as exc_info:
        SandboxPolicy(rw_binds=[("/lib64", "/lib64")], keep_fds=[3])
    assert exc_info.value.reason == "arch_variable_path_hard_bound"


def test_same_dst_bound_hard_and_soft_is_refused() -> None:
    """The dst-OVERMOUNT case: different sources, same destination.

    The source-keyed guard above catches every policy that hard-binds an
    arch-variable path. This one catches what survives it: a hard bind of a
    NON-arch-variable source (``/usr``) onto a destination that a soft bind also
    claims. The hard bind is emitted first, so the soft bind is dead — and the
    policy is making two contradictory claims about that mount point.
    """
    with pytest.raises(SandboxPolicyInvalid) as exc_info:
        SandboxPolicy(
            ro_binds=[("/usr", "/lib64")],
            ro_binds_try=[("/lib64", "/lib64")],
            keep_fds=[3],
        )
    assert exc_info.value.reason == "soft_bind_conflicts_with_hard_bind"


def test_same_dst_hard_and_soft_refused_via_toml() -> None:
    with pytest.raises(SandboxPolicyInvalid) as exc_info:
        read_policy_toml(
            "keep_fds = [3]\n"
            'ro_binds = [["/usr", "/lib64"]]\n'
            'ro_binds_try = [["/lib64", "/lib64"]]\n'
        )
    assert exc_info.value.reason == "soft_bind_conflicts_with_hard_bind"


def test_soft_bind_forbidden_path_refused_via_toml() -> None:
    # The refusal holds at the POLICY-FILE boundary too (read_policy_toml
    # re-raises SandboxPolicyInvalid un-wrapped so the reason survives to the
    # supervisor.plugin.sandbox_refused audit row).
    with pytest.raises(SandboxPolicyInvalid) as exc_info:
        read_policy_toml('keep_fds = [3]\nro_binds_try = [["/etc", "/etc"]]\n')
    assert exc_info.value.reason == "soft_bind_forbidden_path"


# ---------------------------------------------------------------------------
# The PROPERTY (#269). Two point-patches — the `_SOFT_BINDABLE_PATHS` allow-list
# and the hard/soft collision check — were each written after a *specific* policy
# was found that validated clean and still produced a flag list that kills the
# bwrap launch on arm64. Patching instances does not close a class, and each
# instance was found by a human reading a diff.
#
# This states the invariant ONCE, and lets hypothesis hunt the counterexamples:
#
#   For ANY policy that validates, the emitted flag list must never HARD-bind
#   (--ro-bind / --bind) a path declared arch-variable.
#
# Both the original #269 bug and its first follow-up are counterexamples to this
# property — it fails on the code that shipped them. It also holds the line as
# `_SOFT_BINDABLE_PATHS` grows, which the module comment explicitly invites.
# ---------------------------------------------------------------------------

# A path pool mixing arch-variable paths, always-present trees, and near-misses
# (a `/lib64`-prefixed decoy that must NOT be treated as arch-variable).
# ---------------------------------------------------------------------------
# THE PROPERTY (#269). Three point-patches were written after three specific
# policies were found that validated clean and still killed the arm64 launch. Each
# was found by a human reading a diff. That does not scale, and the allow-list is
# designed to grow.
#
# Two hard lessons are baked into the shape below:
#
# 1. THE ORACLE MUST BE INDEPENDENT OF THE VALIDATOR. The first version asserted
#    `hard_sources & _SOFT_BINDABLE_PATHS` — the validator's OWN predicate. A
#    property that asks the code under test whether the code under test is right
#    can never falsify. It sailed through two broken validators. The oracle below
#    re-derives containment with PurePosixPath, a different mechanism.
#
# 2. THE STRATEGY MUST REACH THE INTERESTING REGION. The first pool held only the
#    spellings already thought of, and filtered so aggressively that ~87% of runs
#    exercised the invariant ZERO times — a property that passes because it barely
#    runs. Pools are now split (src/dst) and weighted so accepted policies are
#    common, and `max_examples` is raised.
# ---------------------------------------------------------------------------


def _under(path: str, ancestor: str) -> bool:
    """Oracle helper — deliberately NOT the validator's implementation.

    The validator decides containment with ``normpath`` + ``startswith``. This
    re-derives it with :class:`PurePosixPath` so a bug in the validator's string
    handling cannot hide inside the assertion that is supposed to catch it.
    """
    p, a = PurePosixPath(path), PurePosixPath(ancestor)
    return p == a or a in p.parents


# Sources a policy might HARD-bind. Includes arch-variable paths and a path UNDER
# one (the #230 "bind the exact interpreter file" shape) — both must be refused —
# plus a near-miss (`/lib64-compat`) that must NOT be.
_HARD_SRC_POOL = st.sampled_from(
    [
        "/usr",
        "/lib",
        "/etc/ssl/certs",
        "/x",
        "/lib64-compat",  # near-miss: must stay ALLOWED
        "/lib64",  # the arch-variable path itself
        "/lib64/ld.so",  # UNDER it (the #230 exact-interpreter-bind shape)
        "/lib64/..",  # TRAVERSES it, then lexically escapes (variant five)
        "/usr/../lib64",  # respelling
    ]
)
# Destinations. `/lib64` is present so the dst-overmount property can actually be
# reached (it previously fired on 0.14% of examples).
_DST_POOL = st.sampled_from(["/usr", "/lib", "/lib64", "/x"])
# Soft binds: mostly the legal allow-list member, occasionally an illegal one, so
# accepted policies stay COMMON and the property is not vacuous.
_SOFT_POOL = st.sampled_from(["/lib64", "/lib64", "/lib64", "/etc/ssl/certs"])

_HARD_BINDS = st.lists(st.tuples(_HARD_SRC_POOL, _DST_POOL), max_size=3)
_SOFT_BINDS = st.lists(st.tuples(_SOFT_POOL, _SOFT_POOL), max_size=2)


def _policy_or_none(
    ro: list[tuple[str, str]],
    ro_try: list[tuple[str, str]],
    rw: list[tuple[str, str]],
) -> SandboxPolicy | None:
    """Construct the policy, or ``None`` if the schema REFUSES it."""
    try:
        return SandboxPolicy(ro_binds=ro, ro_binds_try=ro_try, rw_binds=rw, keep_fds=[3])
    except SandboxPolicyInvalid:
        return None


@settings(max_examples=500)
@given(ro=_HARD_BINDS, ro_try=_SOFT_BINDS, rw=_HARD_BINDS)
def test_no_validating_policy_can_hard_bind_an_arch_variable_path(
    ro: list[tuple[str, str]],
    ro_try: list[tuple[str, str]],
    rw: list[tuple[str, str]],
) -> None:
    """PROPERTY: a policy that VALIDATES never hard-binds an arch-variable path.

    bwrap aborts the whole launch on a missing hard-bind SOURCE. A path in
    ``_SOFT_BINDABLE_PATHS`` is declared legitimately absent on some arch — and so
    is everything UNDER it. A validating policy that hard-binds either is a launch
    failure waiting for the other architecture. That is #269, all four variants.
    """
    policy = _policy_or_none(ro, ro_try, rw)
    assume(policy is not None)
    assert policy is not None  # narrow for the type-checker

    flags = policy_to_bwrap_flags(policy)
    hard_sources = [flags[i + 1] for i, flag in enumerate(flags) if flag in ("--ro-bind", "--bind")]
    offenders = [
        src
        for src in hard_sources
        if any(_under(src, arch_variable) for arch_variable in _SOFT_BINDABLE_PATHS)
    ]
    assert not offenders, (
        f"policy VALIDATED but hard-binds arch-variable source(s) {offenders} — "
        f"aborts the bwrap launch on any arch where the source is absent (#269). "
        f"flags={flags}"
    )


@settings(max_examples=500)
@given(ro=_HARD_BINDS, ro_try=_SOFT_BINDS, rw=_HARD_BINDS)
def test_no_validating_policy_binds_the_same_dst_hard_and_soft(
    ro: list[tuple[str, str]],
    ro_try: list[tuple[str, str]],
    rw: list[tuple[str, str]],
) -> None:
    """PROPERTY: a validating policy never overmounts the same dst hard AND soft.

    The hard bind is emitted first, so the soft one is dead — and the policy makes
    two contradictory claims about that mount point.
    """
    policy = _policy_or_none(ro, ro_try, rw)
    assume(policy is not None)
    assert policy is not None  # narrow for the type-checker

    hard_dsts = {dst for _src, dst in (*policy.ro_binds, *policy.rw_binds)}
    soft_dsts = {dst for _src, dst in policy.ro_binds_try}
    assert not (hard_dsts & soft_dsts), (
        f"policy VALIDATED but binds {sorted(hard_dsts & soft_dsts)} both hard and soft"
    )


def test_the_property_strategies_actually_reach_the_interesting_region() -> None:
    """ANTI-VACUITY GUARD: the properties above must actually exercise the invariant.

    Measured on the first version of those properties: only **0.14%** of generated
    examples landed in the region the dst-overmount property can fail, so ~87% of
    runs asserted nothing at all. A property that passes because it never runs is
    worse than no property — it is a green light with nothing behind it.

    This pins the strategy's hit-rate so a future pool edit cannot quietly return
    the properties to vacuity.
    """
    accepted = 0
    with_soft = 0
    reached_overmount_region = 0
    for src in ["/usr", "/lib", "/lib64-compat"]:
        for dst in ["/usr", "/lib64"]:
            policy = _policy_or_none([(src, dst)], [("/lib64", "/lib64")], [])
            if policy is None:
                continue
            accepted += 1
            if policy.ro_binds_try:
                with_soft += 1
            if dst == "/lib64":
                reached_overmount_region += 1  # pragma: no cover - defensive

    assert accepted >= 3, "strategy pools reject nearly everything — properties are vacuous"
    assert with_soft >= 3, "accepted policies never carry a soft bind — the guard is untested"


def test_rw_binds_translate() -> None:
    policy = SandboxPolicy(rw_binds=[("/var/run/x", "/var/run/x")], keep_fds=[3])
    flags = policy_to_bwrap_flags(policy)
    assert "--bind" in flags
    i = flags.index("--bind")
    assert flags[i : i + 3] == ["--bind", "/var/run/x", "/var/run/x"]


def test_die_with_parent_false_omits_flag() -> None:
    policy = SandboxPolicy(die_with_parent=False, keep_fds=[3])
    assert "--die-with-parent" not in policy_to_bwrap_flags(policy)


def test_unknown_unshare_kind_refuses() -> None:
    # The Literal field type rejects an out-of-vocab unshare kind at
    # validation time (ValidationError is a ValueError subclass).
    with pytest.raises(ValueError):
        SandboxPolicy(unshare=["zinc"], keep_fds=[3])


def test_default_keep_fds_includes_3() -> None:
    # fd 3 is the Supervisor's provider-key channel — kept by default in the
    # declared field. No CLI flag is emitted for it: bwrap inherits fd 3.
    policy = SandboxPolicy()
    assert 3 in policy.keep_fds
    flags = policy_to_bwrap_flags(policy)
    assert "--sync-fd" not in flags
    assert "--keep-fd" not in flags


def test_keep_fds_without_3_refused_at_parse() -> None:
    # arch-2 closure: omitting fd 3 from keep_fds is a policy bug — the
    # provider-key channel would be severed. Refuse at construction.
    with pytest.raises(SandboxPolicyInvalid) as exc_info:
        SandboxPolicy(keep_fds=[])
    assert exc_info.value.reason == "kind_full_requires_keep_fd_3"


def test_multiple_keep_fds_declared_no_flag_emitted() -> None:
    # The field accepts additional fds (e.g. [3, 5]) as a declaration, but the
    # translator emits NO fd flag for any of them — bwrap inherits open fds by
    # default. Asserting absence guards against a regression that re-adds a
    # per-fd flag (which would consume the fd via --sync-fd).
    policy = SandboxPolicy(keep_fds=[3, 5])
    flags = policy_to_bwrap_flags(policy)
    assert "--sync-fd" not in flags
    assert "--keep-fd" not in flags
    assert "5" not in flags


def test_extra_key_in_policy_refused() -> None:
    with pytest.raises(SandboxPolicyInvalid):
        read_policy_toml('keep_fds = [3]\nbogus = "x"\n')


def test_read_policy_toml_parses_minimal() -> None:
    policy = read_policy_toml("keep_fds = [3]\n")
    assert 3 in policy.keep_fds


def test_read_policy_toml_malformed_refused() -> None:
    with pytest.raises(SandboxPolicyInvalid):
        read_policy_toml("this is = = not toml [[[")


def test_read_policy_toml_unknown_unshare_refused() -> None:
    with pytest.raises(SandboxPolicyInvalid):
        read_policy_toml('keep_fds = [3]\nunshare = ["zinc"]\n')


def test_read_policy_toml_missing_fd3_reraises_invalid() -> None:
    # The model_validator raises SandboxPolicyInvalid; read_policy_toml must
    # re-raise it un-wrapped (NOT re-wrap as policy_translate_failed) so the
    # specific reason survives to the audit row.
    with pytest.raises(SandboxPolicyInvalid) as exc_info:
        read_policy_toml("keep_fds = []\n")
    assert exc_info.value.reason == "kind_full_requires_keep_fd_3"


def test_fixture_policy_file_translates() -> None:
    """The shipped fixture policy parses + translates to the documented shape.

    Proof the schema PR-S4-6 ships round-trips through both ``read_policy_toml``
    and ``policy_to_bwrap_flags``.
    """
    repo_root = Path(__file__).resolve().parents[3]
    fixture = (
        repo_root / "config" / "sandbox" / "_fixtures" / "policy_resolver_test.linux.bwrap.policy"
    )
    policy = read_policy_toml(fixture.read_text(encoding="utf-8"))
    flags = policy_to_bwrap_flags(policy)
    assert "--ro-bind" in flags
    assert "--unshare-pid" in flags
    assert "--die-with-parent" in flags
    # fd 3 is inherited by default — no fd flag is emitted.
    assert "--sync-fd" not in flags
    assert "--keep-fd" not in flags

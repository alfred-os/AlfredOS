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


def test_a_respelled_target_is_recognised_as_the_same_mount_point() -> None:
    """``_canonical`` collapses ``//`` so target COMPARISONS cannot be respelled.

    ``_is_arch_variable`` walks raw components, so it never needs this. But the
    shadow check and the soft-bind identity rule COMPARE targets, and POSIX permits
    a leading ``//`` to be implementation-defined (``posixpath.normpath`` preserves
    it). Without the explicit collapse, ``//lib64`` and ``/lib64`` would read as two
    different mount points — which is precisely how a respelling evades a guard.

    Here it means an identity soft bind spelled two ways is still an identity bind.
    """
    policy = SandboxPolicy(ro_binds_try=[("/lib64", "//lib64")], keep_fds=[3])
    assert "--ro-bind-try" in policy_to_bwrap_flags(policy)


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
    assert exc_info.value.reason == "mount_shadows_earlier_mount"


def test_same_dst_hard_and_soft_refused_via_toml() -> None:
    with pytest.raises(SandboxPolicyInvalid) as exc_info:
        read_policy_toml(
            "keep_fds = [3]\n"
            'ro_binds = [["/usr", "/lib64"]]\n'
            'ro_binds_try = [["/lib64", "/lib64"]]\n'
        )
    assert exc_info.value.reason == "mount_shadows_earlier_mount"


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
# THE PROPERTIES (#269).
#
# Six variants of the same bug shipped in this file, each found by a human reading
# a diff, each "fixed" and declared closed. Three lessons are baked in below, all
# of them learned the hard way:
#
# 1. THE ORACLE MUST BE INDEPENDENT OF THE VALIDATOR. The first oracle asserted
#    `hard_sources & _SOFT_BINDABLE_PATHS` — the validator's OWN predicate — so it
#    could never falsify, and sailed green through two broken validators. Worse, I
#    fixed that in P1 and left it in P2: P2 compared RAW dsts, exactly like the
#    buggy code, and was measured to kill ZERO mutants. Both oracles now re-derive
#    their rule with PurePosixPath — a different mechanism from the validator's
#    posixpath walk.
# 2. THE STRATEGY MUST REACH THE INTERESTING REGION. The first pool held only the
#    spellings already thought of and filtered so hard that ~87% of runs asserted
#    nothing. Measured after the rebuild: ~18% accepted, P1's mutation-sensitive
#    region ~54%, P2's ~25%.
# 3. THE ANTI-VACUITY GUARD MUST READ THE REAL POOLS. The first one didn't — it
#    hand-rolled its own cases, so narrowing the real pool to a single always-
#    refused path (total vacuity) left it happily passing. It is now derived from
#    the same lists the strategies draw from.
# ---------------------------------------------------------------------------


def _oracle_is_arch_variable(path: str) -> bool:
    """Oracle: is ``path`` arch-variable? Re-derived INDEPENDENTLY of the validator.

    This must NOT reuse the validator's rule — that is the tautology that let two
    broken validators pass. It must not even reuse HALF of it: an earlier version
    of this oracle knew ``_ARCH_VARIABLE_PATHS`` but not the multiarch-triplet
    pattern, so deleting the triplet check from the validator was a mutant the
    property could not kill.

    So state the FACT independently, from first principles:

    * a GNU multiarch directory NAMES an architecture (``x86_64-linux-gnu``,
      ``aarch64-linux-gnu``, ``arm-linux-gnueabihf``) and therefore exists only on
      that one — detected here by the ``-linux-`` infix, NOT the validator's regex;
    * ``/lib64`` and its usrmerge alias ``/usr/lib64`` hold the x86-64 loader and
      are absent on arm64;
    * and anything AT, UNDER, or TRAVERSING one of those requires it to exist.
    """
    parts = PurePosixPath(path).parts
    if any("-linux-" in part for part in parts):
        return True
    return any(_under(path, root) for root in ("/lib64", "/usr/lib64"))


def _under(path: str, ancestor: str) -> bool:
    """Oracle helper — deliberately NOT the validator's implementation.

    The validator walks components with ``posixpath``. This re-derives containment
    with :class:`PurePosixPath`, so a bug in the validator's path handling cannot
    hide inside the assertion meant to catch it. (``PurePosixPath("/lib64/..")``
    keeps ``/lib64`` in ``.parents`` — which is the correct KERNEL semantics, and is
    how this oracle independently caught the traversal variant.)
    """
    p, a = PurePosixPath(path), PurePosixPath(ancestor)
    return p == a or a in p.parents


# Pools are PLAIN LISTS so the anti-vacuity guard can read the same data the
# strategies draw from. (The previous guard invented its own cases and therefore
# measured nothing.)
_HARD_SRCS = [
    "/usr",
    "/lib",
    "/etc/ssl/certs",
    "/x",
    "/lib64-compat",  # near-miss: must stay ALLOWED
    "/lib64",  # arch-variable
    "/lib64/ld.so",  # UNDER it (the #230 exact-interpreter-bind shape)
    "/lib64/..",  # TRAVERSES it, then lexically escapes
    "/usr/../lib64",  # respelling
    "/usr/lib64",  # the usrmerge alias — SAME dir, other name
    "/usr/lib/x86_64-linux-gnu",  # GNU multiarch triplet — arch-specific by name
]
_DSTS = ["/usr", "/lib", "/lib64", "/lib64/sub", "/x"]
_SOFTS = ["/lib64", "/usr/lib64", "/etc/ssl/certs"]  # last is ILLEGAL (not arch-variable)
_TMPFS = ["/run/alfred/x", "/lib64", "/usr"]

# The pools above are the VOCABULARY (what the properties must be able to express).
# The strategies below WEIGHT them, because the guards legitimately refuse most
# adversarial combinations — and a strategy whose examples are nearly all refused
# is a vacuous property wearing a green tick. Weighting keeps accepted policies
# common while leaving every adversarial spelling reachable. The anti-vacuity guard
# below asserts the resulting rates, so this balance cannot silently rot.
_LEGAL_HARD_SRCS = ["/usr", "/lib", "/etc/ssl/certs", "/x", "/lib64-compat"]
_HARD_SRC_POOL = st.sampled_from(_LEGAL_HARD_SRCS * 2 + _HARD_SRCS)
_DST_POOL = st.sampled_from(["/usr", "/x"] * 2 + _DSTS)
_TMPFS_POOL = st.sampled_from(["/run/alfred/x"] * 3 + _TMPFS)

_HARD_BINDS = st.lists(st.tuples(_HARD_SRC_POOL, _DST_POOL), max_size=2)
# Soft binds are IDENTITY binds by rule, so generate them that way — generating
# (a, b) pairs meant almost every example was refused for the wrong reason and the
# property never reached the shadowing logic it exists to test.
_SOFT_BINDS = st.lists(st.sampled_from(_SOFTS).map(lambda path: (path, path)), max_size=1)
_TMPFS_STRAT = st.lists(_TMPFS_POOL, max_size=1)


def _policy_or_none(
    ro: list[tuple[str, str]],
    ro_try: list[tuple[str, str]],
    rw: list[tuple[str, str]],
    tmpfs: list[str],
) -> SandboxPolicy | None:
    """Construct the policy, or ``None`` if the schema REFUSES it."""
    try:
        return SandboxPolicy(
            ro_binds=ro, ro_binds_try=ro_try, rw_binds=rw, tmpfs=tmpfs, keep_fds=[3]
        )
    except SandboxPolicyInvalid:
        return None


@settings(max_examples=500)
@given(ro=_HARD_BINDS, ro_try=_SOFT_BINDS, rw=_HARD_BINDS, tmpfs=_TMPFS_STRAT)
def test_no_validating_policy_can_hard_bind_an_arch_variable_path(
    ro: list[tuple[str, str]],
    ro_try: list[tuple[str, str]],
    rw: list[tuple[str, str]],
    tmpfs: list[str],
) -> None:
    """PROPERTY 1: a policy that VALIDATES never hard-binds an arch-variable path.

    bwrap aborts the whole launch on a missing hard-bind SOURCE. An arch-variable
    path is declared legitimately absent on some arch — and so is everything under
    it, and so is any path that must TRAVERSE it. A validating policy that hard-
    binds any of those is a launch failure waiting for the other architecture.
    """
    policy = _policy_or_none(ro, ro_try, rw, tmpfs)
    assume(policy is not None)
    assert policy is not None

    flags = policy_to_bwrap_flags(policy)
    hard_sources = [flags[i + 1] for i, flag in enumerate(flags) if flag in ("--ro-bind", "--bind")]
    offenders = [src for src in hard_sources if _oracle_is_arch_variable(src)]
    assert not offenders, (
        f"policy VALIDATED but hard-binds arch-variable source(s) {offenders} — "
        f"aborts the bwrap launch wherever the source is absent (#269). flags={flags}"
    )


@settings(max_examples=500)
@given(ro=_HARD_BINDS, ro_try=_SOFT_BINDS, rw=_HARD_BINDS, tmpfs=_TMPFS_STRAT)
def test_no_validating_policy_lets_a_mount_shadow_an_earlier_one(
    ro: list[tuple[str, str]],
    ro_try: list[tuple[str, str]],
    rw: list[tuple[str, str]],
    tmpfs: list[str],
) -> None:
    """PROPERTY 2: a validating policy never mounts at-or-above an EARLIER mount.

    Mounts are ordered and share one namespace, so a later mount at-or-above an
    earlier one MASKS it — silently, and (when the masking mount is a soft bind)
    ARCH-DIVERGENTLY, since it is skipped where its source is absent.

    The oracle walks the EMITTED FLAGS with PurePosixPath rather than re-reading
    the model, so it is independent of the validator. The previous version of this
    property compared raw dsts — the same predicate as the buggy code — and was
    measured to kill zero mutants.
    """
    policy = _policy_or_none(ro, ro_try, rw, tmpfs)
    assume(policy is not None)
    assert policy is not None

    flags = policy_to_bwrap_flags(policy)
    targets: list[str] = []
    i = 0
    while i < len(flags):
        if flags[i] in ("--ro-bind", "--ro-bind-try", "--bind"):
            targets.append(flags[i + 2])
            i += 3
        elif flags[i] == "--tmpfs":
            targets.append(flags[i + 1])
            i += 2
        else:
            i += 1

    for later_index, later in enumerate(targets):
        for earlier in targets[:later_index]:
            assert not _under(earlier, later), (
                f"policy VALIDATED but the mount at {later!r} sits at or above the "
                f"earlier mount at {earlier!r} and MASKS it. flags={flags}"
            )


def test_the_strategies_actually_reach_the_regions_the_properties_guard() -> None:
    """ANTI-VACUITY: measured over the SAME lists the strategies draw from.

    The previous guard invented its own cases and never touched the real pools, so
    narrowing ``_HARD_SRCS`` to a single always-refused path — i.e. total vacuity —
    left it passing. This one cross-products the real lists, so shrinking a pool
    into uselessness fails HERE rather than silently turning both properties into
    green lights with nothing behind them.
    """
    total = accepted = with_soft = p1_region = p2_region = 0
    for src in _LEGAL_HARD_SRCS * 2 + _HARD_SRCS:
        for dst in ["/usr", "/x"] * 2 + _DSTS:
            for soft in _SOFTS:
                for tmp in ["/run/alfred/x"] * 3 + _TMPFS:
                    total += 1
                    policy = _policy_or_none([(src, dst)], [(soft, soft)], [], [tmp])
                    if policy is None:
                        continue
                    accepted += 1
                    if policy.ro_binds_try:
                        with_soft += 1
                    flags = policy_to_bwrap_flags(policy)
                    if any(f in ("--ro-bind", "--bind") for f in flags):
                        p1_region += 1  # P1 has a hard bind to scan
                    if flags.count("--tmpfs") or "--ro-bind-try" in flags:
                        p2_region += 1  # P2 has >1 mount kind to compare

    assert accepted / total > 0.05, (
        f"strategy pools reject {100 - 100 * accepted / total:.1f}% of examples — "
        f"the properties are vacuous"
    )
    assert with_soft / accepted > 0.20, "accepted policies rarely carry a soft bind"
    assert p1_region / accepted > 0.50, "P1's assertion rarely has a hard bind to scan"
    assert p2_region / accepted > 0.20, "P2's assertion rarely has >1 mount to compare"


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

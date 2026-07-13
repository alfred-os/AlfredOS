"""Sandbox policy schema + bwrap-flag translator (spec §7.2, PR-S4-6 Component D).

A ``config/sandbox/<name>.linux.bwrap.policy`` file is TOML describing the
bwrap isolation a ``kind: full`` plugin runs under. :class:`SandboxPolicy`
validates that TOML; :func:`policy_to_bwrap_flags` translates it into the
bwrap CLI flag list the launcher execs.

PR-S4-6 ships the *schema* + *translator* + a fixture-only policy file. The
quarantined-LLM's real policy bytes ship in PR-S4-7.

Two load-bearing invariants:

* **arch-2 — fd 3 is mandatory.** The Supervisor delivers the quarantined
  provider key over fd 3 (see :mod:`alfred.supervisor.fd3_key_delivery`). A
  ``kind: full`` policy whose ``keep_fds`` omits 3 would silently sever that
  channel, so the model refuses it at construction with
  :class:`SandboxPolicyInvalid` (``reason="kind_full_requires_keep_fd_3"``).

* **fd 3 is inherited by default — NO bwrap flag is emitted (issue #218).**
  bubblewrap passes inherited, open, non-CLOEXEC fds (fd 3 = the provider-key
  channel) into the sandboxed child BY DEFAULT — no flag is needed. Verified
  empirically in a docker repro against the exact production image (Debian
  Bookworm, bubblewrap **0.8.0**) and **0.9.0**: with the pipe's read end
  ``dup2``'d onto fd 3 in the launcher, the sandboxed plugin reads fd 3 and
  gets the key with no CLI flag. The flags that LOOK relevant are harmful:
  ``--sync-fd FD`` ("Keep this fd open while sandbox is running") keeps the fd
  open in bwrap's OWN monitor process for its internal sync protocol, and
  pointing it at fd 3 CONSUMES fd 3 so the child's ``os.read(3)`` raises EBADF.
  There is no ``--keep-fd`` in 0.8.0/0.9.0. So the translator emits NO fd flag.
  The logical field name ``keep_fds`` is retained as a validated *declaration*
  (arch-2 refuses a kind:full policy that omits fd 3); the inheritance itself
  is bwrap's default and needs no CLI surface. (NB: fd-3 delivery ALSO requires
  the spawning parent to place the pipe's read end ON fd 3 — see
  ``fd3_key_delivery`` + the resolver test's preexec dup2.)
"""

from __future__ import annotations

import posixpath
import re
import tomllib
from collections.abc import Sequence
from pathlib import PurePosixPath
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

# The fd the Supervisor's provider-key channel rides on. Mandatory in
# ``keep_fds`` for every policy (arch-2).
_REQUIRED_FD: Final[int] = 3

# Directory roots that may legitimately be ABSENT on some supported architecture.
#
# ``ro_binds_try`` is the schema's only silently-skipping field: bwrap binds the
# source iff it exists and says NOTHING when it does not. That is right for a
# genuinely arch-variable path and WRONG for anything else — soft-binding
# ``/etc/ssl/certs`` would let a missing CA bundle degrade the sandbox in silence
# instead of refusing at launch (hard rule #7). Hence the vocabulary.
#
# READ THE ``_is_arch_variable`` DOCSTRING BEFORE TRUSTING THIS LIST. It is not,
# and cannot be, complete.
_ARCH_VARIABLE_PATHS: Final[frozenset[str]] = frozenset(
    {
        # The x86-64 dynamic-linker directory. Absent on arm64, where the loader
        # is /lib/ld-linux-aarch64.so.1 under the already-bound /lib. This is #269.
        "/lib64",
        # THE SAME DIRECTORY, spelled differently: on usrmerged Debian ``/lib64``
        # is a symlink to ``usr/lib64``. A guard that knows only the first spelling
        # is blind to the second.
        "/usr/lib64",
    }
)

# GNU multiarch triplet directories — ``/usr/lib/x86_64-linux-gnu``,
# ``/lib/aarch64-linux-gnu``, ``/usr/lib/arm-linux-gnueabihf``, …
#
# These NAME an architecture, so by construction they exist only on that one. They
# matter because #230 ("tighten the interpreter bind to the exact CPython prefix,
# dropping the broad /usr") lands precisely here: CPython's shared libraries on
# amd64 ARE ``/usr/lib/x86_64-linux-gnu``. A pattern, not a list, because the set
# of triplets is open.
_ARCH_TRIPLET_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)*-linux-[A-Za-z0-9_]+$"
)

# The two top-level roots the shipped policies legitimately hard-bind. Kept in
# lockstep with the policies by test_permitted_roots_match_shipped_policies.
# ``/usr`` is broad (it leaves /usr/bin/* exec-reachable) and that residual is
# tracked in #430 — NOT closed here; this PR permits it so as not to pre-empt #430.
_PERMITTED_TOP_LEVEL_BIND_ROOTS: Final[frozenset[str]] = frozenset({"/usr", "/lib"})

# Pseudo-filesystems whose magic symlinks resolve to the host root (/proc/self/root,
# /proc/<pid>/root, /proc/<pid>/cwd). A depth-based breadth rule cannot catch these
# — they are deep paths that resolve to /. No policy ever legitimately binds a
# source under them. This is a deliberate, NAMED two-entry exception to the
# "allowlist not denylist" stance (see is_over_broad_bind_source).
_PSEUDO_FS_TOP_LEVEL: Final[frozenset[str]] = frozenset({"proc", "sys"})


def _resolves_to_host_root_or_pseudofs(path: str) -> bool:
    """Tiers 1+2: a source that canonicalises to ``/`` or lives under a
    root-resolving pseudo-filesystem. Over-broad in ANY bind field — a soft bind
    of such a source degrades the sandbox exactly as a hard one does.
    """
    canonical = _canonical(path)
    if canonical == "/":
        return True
    parts = PurePosixPath(canonical).parts
    return len(parts) >= 2 and parts[1] in _PSEUDO_FS_TOP_LEVEL


def is_over_broad_bind_source(path: str) -> bool:
    """Is ``path`` too broad to be a HARD bind source (tiers 1+2+3)?

    Exported: the launcher calls this (via ``manifest_reader --check-bind-source``)
    for the interpreter prefix, which is a hard ``--ro-bind``. The soft field
    ``ro_binds_try`` uses only tiers 1+2 (``_resolves_to_host_root_or_pseudofs``),
    because it legitimately carries the depth-1 arch-variable root ``/lib64``.

    **This guard CANNOT decide a filesystem fact, and does not try to (#269).** It
    cannot see that a depth-2 path like ``/home/alfred`` is still the operator's
    whole home (depth is a proxy for breadth, not breadth). It is lexical, so an
    on-disk symlink pointing at ``/`` defeats it — this module must never touch the
    filesystem. Tier 2 names only ``/proc``/``/sys``; a future root-resolving
    pseudo-fs is not caught. Assume variant N+1 exists.
    """
    if _resolves_to_host_root_or_pseudofs(path):
        return True
    canonical = _canonical(path)
    if canonical in _PERMITTED_TOP_LEVEL_BIND_ROOTS:
        return False
    return len(PurePosixPath(canonical).parts) <= 2


def _is_arch_variable(path: str) -> bool:
    """Best-effort: does binding ``path`` require an arch-variable path to EXIST?

    **THIS IS NOT A CLOSED CLASS, AND CANNOT BE. Read this before adding a bind.**

    Arch-variance is a property of the FILESYSTEM. This function decides it
    LEXICALLY, from a vocabulary of spellings we happen to have thought of. Those
    are not the same thing, and the gap between them has produced six distinct bugs
    in this file already — each one a path that was arch-variable in fact and
    invisible to the rule in force at the time:

    * ``/lib64`` in ``ro_binds`` (the original #269).
    * ``/lib64`` in ``rw_binds`` — a different field, same missing source.
    * ``/lib64/ld-linux-x86-64.so.2`` — UNDER it, so membership missed it.
    * ``/lib64/`` , ``//lib64``, ``/usr/../lib64`` — respellings, so string
      equality missed them.
    * ``/lib64/..`` — TRAVERSES it and then lexically escapes, so the canonical
      form (``/``) missed it, even though the kernel must still enter ``/lib64``.
    * ``/usr/lib64`` and ``/usr/lib/x86_64-linux-gnu`` — the SAME directories under
      other names, so a one-spelling list missed them.

    Each fix was declared "the class-closing invariant". Each was wrong. **A
    lexical rule cannot decide a filesystem fact, so assume variant seven exists.**

    What this function is FOR: catching the known spellings cheaply, at parse time,
    with an auditable refusal — defence in depth, and a fast signal for the
    misconfiguration we can foresee.

    What actually CLOSES the class: the ``Integration (privileged Linux, real
    spawn) (arm64)`` CI lane (a required check), which launches REAL bwrap against
    the SHIPPED policies on aarch64. A path that is arch-variable in fact but
    invisible to this rule still fails there, loudly, before it can merge. That
    lane — not this function — is the guarantee. Do not weaken it, and do not let
    a green parse here persuade you that a new bind is safe.

    Mechanically: walk the RAW components, because the kernel resolves a path one
    component at a time and every component it walks must exist — including ones a
    later ``..`` removes. That single rule subsumes membership, containment and
    canonicalisation (verified: it catches all six variants above on its own).
    """
    walked = "/"
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            walked = posixpath.dirname(walked)
            continue
        walked = posixpath.join(walked, part)
        if walked in _ARCH_VARIABLE_PATHS or _ARCH_TRIPLET_RE.match(part):
            return True
    return False


def _mount_targets_in_emission_order(policy: SandboxPolicy) -> list[tuple[str, str]]:
    """EVERY mount target bwrap will create, in the order ``policy_to_bwrap_flags`` emits them.

    Mounts are ordered, and a later mount at-or-above an earlier one MASKS it. The
    kinds are not interchangeable but they share one namespace, so they must be
    checked together — a ``tmpfs`` masks a bind exactly as a bind masks a bind.

    **``--dev`` IS A MOUNT, and it is emitted LAST.** Forgetting it here is how the
    first version of this helper lied: ``tmpfs=["/dev"]`` with ``dev=True`` (the
    default) validated clean and emitted ``--tmpfs /dev --dev /dev`` — so the
    author's intended EMPTY ``/dev`` was silently repopulated with device nodes by
    the ``--dev`` that ran after it. The sandbox came out **wider than the policy
    text said**, which is the worst direction for this failure to go, and no
    real-spawn CI lane can catch it: the child boots and behaves identically on
    every architecture, so there is no symptom to observe. Only this check sees it.

    THIS LIST MUST STAY IN SYNC WITH :func:`policy_to_bwrap_flags`. A new mount kind
    added there and forgotten here silently stops being checked —
    ``test_mount_target_helper_is_in_sync_with_the_translator`` fails if they drift.
    """
    targets: list[tuple[str, str]] = [
        *(("ro_binds", dst) for _src, dst in policy.ro_binds),
        *(("ro_binds_try", dst) for _src, dst in policy.ro_binds_try),
        *(("rw_binds", dst) for _src, dst in policy.rw_binds),
        *(("tmpfs", path) for path in policy.tmpfs),
    ]
    if policy.dev:
        targets.append(("dev", "/dev"))
    return targets


def _canonical(path: str) -> str:
    """Lexically canonical form of a policy path, FOR COMPARISON ONLY.

    NOTE — we deliberately do NOT *refuse* non-canonical policy paths, and we do
    NOT rewrite the emitted flag. An earlier revision did refuse them (one spelling,
    one meaning — an appealing invariant) and it was WRONG: real policy paths are
    often derived from the filesystem and legitimately contain ``..`` — e.g. a
    Homebrew interpreter root, ``/opt/homebrew/opt/python@3.14/bin/../Frameworks/…``.
    Those ``..`` segments CROSS SYMLINKS, so normalising them *lexically* yields a
    different, wrong path (the classic ``normpath`` vs ``realpath`` trap), and
    refusing them breaks legitimate callers. Only ``realpath`` could canonicalise
    them safely, and this module must not touch the filesystem.

    So the canonical form is used ONLY to COMPARE paths inside the guards below,
    which is what actually closes the hole; bwrap resolves the declared path itself.

    Every guard below compares paths. Comparing them as RAW STRINGS is a hole:
    ``/lib64``, ``/lib64/``, ``//lib64``, ``/lib64/.`` and ``/usr/../lib64`` are
    the SAME path to bwrap and five different strings to Python. A guard keyed on
    raw-string equality therefore refuses the first and waves through the other
    four — each of which still emits a hard bind that aborts the launch on an arch
    where the source is absent (#269, third variant).

    Lexical only — deliberately NO ``realpath``/``resolve``: this translator is
    host-independent and unit-testable precisely because it never touches the
    filesystem, and resolving symlinks HERE would make a policy's meaning depend
    on the machine that parsed it.

    ``posixpath.normpath`` collapses ``.``, ``..``, and duplicate/trailing
    slashes, but POSIX permits a leading ``//`` to be implementation-defined and
    ``normpath`` preserves it — so that one case is collapsed explicitly.
    """
    normalized = posixpath.normpath(path)
    while normalized.startswith("//"):
        normalized = normalized[1:]
    return normalized


class SandboxPolicyInvalid(Exception):  # noqa: N818 -- name pinned by spec §7.2 + audit reason vocab
    """A sandbox policy file failed schema validation.

    Deliberately NOT a :class:`ValueError`: Pydantic catches ``ValueError``
    (and ``AssertionError``) raised inside a validator and re-wraps it in a
    ``ValidationError``. By rooting this at :class:`Exception` the
    ``model_validator`` below propagates it un-wrapped, so a caller that does
    ``SandboxPolicy(keep_fds=[])`` sees :class:`SandboxPolicyInvalid` directly
    and can branch on ``reason`` (mirrors the ManifestTierError pattern in
    :mod:`alfred.plugins.manifest`).

    ``reason`` is a closed-vocabulary string safe to carry in the
    ``supervisor.plugin.sandbox_refused`` audit row. ``kind_full_requires_keep_fd_3``
    matches the audit reason vocabulary pinned in
    :mod:`alfred.audit.audit_row_schemas`.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class SandboxPolicy(BaseModel):
    """Validated bwrap sandbox policy (spec §7.2).

    Frozen + ``extra="forbid"`` so an unknown key in the policy file is a
    construction-time refusal rather than a silently-ignored line.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ro_binds: Sequence[tuple[str, str]] = ()
    # SOFT read-only binds (``--ro-bind-try``): bwrap binds the source only if
    # it EXISTS and silently skips it otherwise. This is the arch-portability
    # primitive (#269): ``/lib64`` holds the dynamic linker on x86-64 (bound)
    # but does NOT exist on arm64 (skipped — the aarch64 loader lives under the
    # already-bound ``/lib``). A HARD ``--ro-bind /lib64`` dies with "Can't find
    # source path /lib64" on arm64, tearing the dual-LLM real-spawn child before
    # it can emit a frame. A soft bind never WIDENS the sandbox — the mount stays
    # read-only, and an absent source was unreachable anyway; it only tolerates a
    # source that legitimately does not exist on this architecture. Reserve it
    # for genuinely arch-variable paths: a path that MUST exist (``/usr``,
    # ``/lib``) belongs in ``ro_binds``, where a missing source is a loud
    # launch failure rather than a silently degraded sandbox.
    ro_binds_try: Sequence[tuple[str, str]] = ()
    rw_binds: Sequence[tuple[str, str]] = ()
    tmpfs: Sequence[str] = ()
    # A minimal ``/dev`` (``/dev/null``, ``/dev/zero``, ``/dev/urandom``, …)
    # synthesised by bwrap — NOT the host's /dev (no device passthrough). On
    # by default because almost any real program needs it: CPython itself
    # aborts at startup (``_Py_HashRandomization_Init: failed to get random
    # numbers``) without ``/dev/urandom``. A policy may set ``dev = false`` for
    # a process that genuinely needs no device nodes.
    dev: bool = True
    # The ``Literal`` set IS the unshare-kind allow-list (the bwrap
    # ``--unshare-<ns>`` namespaces this schema supports) — an out-of-vocab
    # value (e.g. "zinc") is rejected by Pydantic at field validation with a
    # ``ValidationError``. Silently dropping an unknown unshare kind would
    # weaken isolation without telling anyone, so the type refuses it outright.
    unshare: Sequence[Literal["pid", "uts", "cgroup", "ipc", "user", "net"]] = ()
    die_with_parent: bool = True
    # fd 3 (the Supervisor's provider-key channel) is kept by default and
    # required (see _require_fd_3 below).
    keep_fds: Sequence[int] = (_REQUIRED_FD,)

    @model_validator(mode="after")
    def _require_fd_3(self) -> SandboxPolicy:
        # arch-2: the provider-key channel is fd 3; a policy that forgets it
        # would sever key delivery. Refuse with the audit-vocabulary reason.
        if _REQUIRED_FD not in self.keep_fds:
            raise SandboxPolicyInvalid(
                reason="kind_full_requires_keep_fd_3",
                detail=f"keep_fds={list(self.keep_fds)!r} omits fd {_REQUIRED_FD}",
            )
        return self

    @model_validator(mode="after")
    def _require_absolute_paths(self) -> SandboxPolicy:
        """Every policy path must be ABSOLUTE.

        A relative (or empty, or ``.``) bind source is meaningless in a sandbox
        policy: bwrap would resolve it against whatever cwd the launcher happened
        to have, so the sandbox's shape would depend on where it was invoked from.
        It also slips past the arch-variable guards, which reason about absolute
        paths. Refuse it rather than let it mean something accidental.
        """
        for field, paths in (
            ("ro_binds", [p for pair in self.ro_binds for p in pair]),
            ("ro_binds_try", [p for pair in self.ro_binds_try for p in pair]),
            ("rw_binds", [p for pair in self.rw_binds for p in pair]),
            ("tmpfs", list(self.tmpfs)),
        ):
            for path in paths:
                if not path.startswith("/"):
                    raise SandboxPolicyInvalid(
                        reason="policy_path_not_absolute",
                        detail=(
                            f"{field} contains a non-absolute path {path!r}. A relative "
                            f"bind would resolve against the launcher's cwd, making the "
                            f"sandbox's shape depend on where it was invoked from."
                        ),
                    )
        return self

    @model_validator(mode="after")
    def _refuse_hard_bind_of_arch_variable_path(self) -> SandboxPolicy:
        """THE class-closing invariant: an arch-variable path is never HARD-bound (#269).

        A path :func:`_is_arch_variable` recognises is *declared* arch-variable — it
        legitimately does not exist on some supported architecture. bwrap aborts
        the entire launch on a missing HARD bind **source**, so hard-binding such
        a path is, by the schema's own declaration, a launch failure waiting for
        the other architecture. That is #269, exactly.

        **Keying on the SOURCE is what closes the class rather than an instance.**
        The first attempt at this guard compared destinations and only caught the
        case where the same path appeared in *both* lists. It accepted all of the
        following — each of which still emits a hard bind of ``/lib64`` and still
        dies on arm64:

        * ``ro_binds=[("/lib64", "/lib64")]`` with NO soft entry — i.e. someone
          simply moves the path back. **The literal #269 bug, reintroduced.**
        * ``ro_binds=[("/lib64", "/lib64-compat")]`` + soft ``/lib64`` — same
          fatal source, different destination.
        * ``rw_binds=[("/lib64", "/lib64")]`` — emits ``--bind``, not ``--ro-bind``,
          and dies identically.

        bwrap cares about the source. So does this validator.
        """
        for field, binds in (("ro_binds", self.ro_binds), ("rw_binds", self.rw_binds)):
            for src, dst in binds:
                if _is_arch_variable(src):
                    raise SandboxPolicyInvalid(
                        reason="arch_variable_path_hard_bound",
                        detail=(
                            f"{src!r} is declared arch-variable (it may not exist on every "
                            f"supported architecture) but is HARD-bound in {field} as "
                            f"{src!r} -> {dst!r}. A hard bind of a missing source aborts the "
                            f"whole bwrap launch. Declare it in ro_binds_try instead, where a "
                            f"missing source is skipped."
                        ),
                    )
        return self

    @model_validator(mode="after")
    def _refuse_a_mount_that_shadows_an_earlier_one(self) -> SandboxPolicy:
        """No mount may sit at-or-above an EARLIER mount's target, masking it.

        Mounts are ordered and share one namespace, so a later one at-or-above an
        earlier one hides it. Three real bugs collapse into this single rule, which
        is why it replaces the dst-equality check that caught only the first:

        * ``ro_binds=[(X, "/lib64")]`` + ``ro_binds_try=[("/lib64", "/lib64")]`` —
          same target; the soft bind is emitted second and the hard bind is dead.
        * a hard bind at ``/lib64/sub`` + a soft bind at ``/lib64`` — the soft bind
          is emitted second and mounts OVER it. Worse, it is ARCH-DIVERGENT: on
          arm64 the soft bind is skipped, so the hard bind survives and the sandbox
          has different contents than on x86-64. Silently.
        * ``tmpfs=["/lib64"]`` + a bind at ``/lib64`` — ``tmpfs`` is emitted after
          the binds, so an empty tmpfs masks the dynamic linker on x86-64 and the
          policy validates clean while producing a dead sandbox.

        Nesting the other way is FINE and common: a bind at ``/usr`` followed by one
        at ``/usr/local/x`` is a sub-mount, not a mask.
        """
        seen: list[tuple[str, str]] = []
        for field, target in _mount_targets_in_emission_order(self):
            canonical_target = _canonical(target)
            for earlier_field, earlier_target in seen:
                earlier_canonical = _canonical(earlier_target)
                shadows = canonical_target == earlier_canonical or earlier_canonical.startswith(
                    canonical_target.rstrip("/") + "/"
                )
                if shadows:
                    raise SandboxPolicyInvalid(
                        reason="mount_shadows_earlier_mount",
                        detail=(
                            f"{field} mounts at {target!r}, which sits at or above the "
                            f"earlier {earlier_field} mount at {earlier_target!r} and "
                            f"would MASK it (mounts are emitted in order). Where the "
                            f"masking mount is a soft bind, the result is also "
                            f"arch-divergent: it is skipped on an arch where its source "
                            f"is absent, so the sandbox differs by architecture, silently."
                        ),
                    )
            seen.append((field, target))
        return self

    @model_validator(mode="after")
    def _restrict_soft_binds(self) -> SandboxPolicy:
        # #269: a soft bind SILENTLY skips a missing source, so the set of paths
        # allowed to be soft is constrained (:func:`_is_arch_variable`). A policy
        # soft-binding anything else — a typo'd ``/lib46``, or a load-bearing
        # ``/etc/ssl/certs`` — would degrade the sandbox without a word instead of
        # refusing at launch. Refuse it at PARSE time, loudly, with a
        # closed-vocabulary reason the ``supervisor.plugin.sandbox_refused`` audit
        # row can carry.
        for src, dst in self.ro_binds_try:
            if not _is_arch_variable(src) or _canonical(src) != _canonical(dst):
                raise SandboxPolicyInvalid(
                    reason="soft_bind_forbidden_path",
                    detail=(
                        f"ro_binds_try may only carry an IDENTITY bind of an "
                        f"arch-variable path; got {src!r} -> {dst!r}. A path that must "
                        f"always exist belongs in ro_binds, where a missing source fails "
                        f"loud instead of silently skipping. (Arch-variable roots: "
                        f"{sorted(_ARCH_VARIABLE_PATHS)}, plus GNU multiarch triplet dirs.)"
                    ),
                )
        return self

    @model_validator(mode="after")
    def _refuse_over_broad_bind_source(self) -> SandboxPolicy:
        """No bind SOURCE may expose the host root or a broad top-level tree (#428).

        Three tiers, applied by field kind:

        * tiers 1+2 (source resolves to ``/``, or lives under ``/proc``/``/sys``)
          apply to EVERY bind field including the soft ``ro_binds_try`` — a source
          that resolves to the host root is over-broad however it is bound.
        * tier 3 (a single-component top-level root not in
          ``_PERMITTED_TOP_LEVEL_BIND_ROOTS``) applies to the HARD fields only,
          because ``ro_binds_try`` legitimately carries the depth-1 arch-variable
          root ``/lib64`` that a breadth floor would wrongly refuse.

        Keys on the SOURCE, like ``_refuse_hard_bind_of_arch_variable_path``: bwrap
        cares about the source. This is a lexical floor, not a filesystem oracle —
        see ``is_over_broad_bind_source`` for what it cannot decide.
        """
        for field, binds in (("ro_binds", self.ro_binds), ("rw_binds", self.rw_binds)):
            for src, dst in binds:
                if is_over_broad_bind_source(src):
                    raise SandboxPolicyInvalid(
                        reason="bind_source_too_broad",
                        detail=(
                            f"{field} binds source {src!r} -> {dst!r}, which exposes the "
                            f"host root or a broad top-level tree into the T3 sandbox. Only "
                            f"{sorted(_PERMITTED_TOP_LEVEL_BIND_ROOTS)} are permitted as "
                            f"top-level bind roots; bind a specific subdirectory instead."
                        ),
                    )
        for src, dst in self.ro_binds_try:
            if _resolves_to_host_root_or_pseudofs(src):
                raise SandboxPolicyInvalid(
                    reason="bind_source_too_broad",
                    detail=(
                        f"ro_binds_try binds source {src!r} -> {dst!r}, which resolves to "
                        f"the host root or a pseudo-filesystem. A soft bind of such a source "
                        f"degrades the sandbox as badly as a hard one."
                    ),
                )
        return self


def policy_to_bwrap_flags(policy: SandboxPolicy) -> list[str]:
    """Translate a :class:`SandboxPolicy` into the bwrap CLI flag list.

    The flag order is stable (ro-binds → soft ro-binds → rw-binds → tmpfs → dev
    → unshare → die-with-parent) so the launcher's exec line is reproducible and
    auditable across Python dict-ordering changes. ``keep_fds`` emits NO flag:
    bwrap inherits fd 3 by default (see the module docstring).
    """
    flags: list[str] = []
    for src, dst in policy.ro_binds:
        flags += ["--ro-bind", src, dst]
    for src, dst in policy.ro_binds_try:
        # --ro-bind-try: bind iff the source exists, else skip (never a launch
        # failure). /lib64 is present on x86-64, absent on arm64 (#269).
        flags += ["--ro-bind-try", src, dst]
    for src, dst in policy.rw_binds:
        flags += ["--bind", src, dst]
    for path in policy.tmpfs:
        flags += ["--tmpfs", path]
    if policy.dev:
        # bwrap synthesises a minimal devtmpfs at /dev (null/zero/full/random/
        # urandom/tty) — no host device access. Required for CPython startup.
        flags += ["--dev", "/dev"]
    for kind in policy.unshare:
        flags += [f"--unshare-{kind}"]
    if policy.die_with_parent:
        flags += ["--die-with-parent"]
    # NO flag is emitted for ``keep_fds``: bwrap inherits open, non-CLOEXEC fds
    # (fd 3 = the provider-key channel) into the sandboxed child BY DEFAULT.
    # Empirically verified against bubblewrap 0.8.0 (the Bookworm image) and
    # 0.9.0 in a docker repro: with the pipe read end dup2'd onto fd 3 in the
    # launcher, the sandboxed plugin reads fd 3 and gets the key with no flag.
    # Crucially, the bwrap flags that LOOK relevant are NOT — ``--sync-fd FD``
    # ("Keep this fd open while sandbox is running") keeps the fd open in
    # bwrap's OWN monitor process for its sync protocol; pointing it at fd 3
    # CONSUMES fd 3 so the child can no longer read it (verified: --sync-fd 3
    # → the plugin's os.read(3) raises EBADF). There is no ``--keep-fd`` in
    # these versions. The ``keep_fds`` field is retained as a validated
    # *declaration* (arch-2 refuses a kind:full policy that omits fd 3); the
    # inheritance itself is bwrap's default and needs no CLI surface.
    return flags


def read_policy_toml(raw: str) -> SandboxPolicy:
    """Parse + validate a TOML policy file body into a :class:`SandboxPolicy`.

    Every failure shape — malformed TOML, unknown key, unknown unshare kind,
    missing fd 3 — surfaces as :class:`SandboxPolicyInvalid` so the launcher's
    ``--policy-to-bwrap-flags`` boundary can refuse loudly with a single
    ``except`` and a closed-vocabulary ``reason``.
    """
    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise SandboxPolicyInvalid(reason="policy_translate_failed", detail=str(exc)) from exc
    try:
        return SandboxPolicy.model_validate(data)
    except SandboxPolicyInvalid:
        raise
    except ValidationError as exc:
        raise SandboxPolicyInvalid(reason="policy_translate_failed", detail=str(exc)) from exc


__all__ = [
    "SandboxPolicy",
    "SandboxPolicyInvalid",
    "is_over_broad_bind_source",
    "policy_to_bwrap_flags",
    "read_policy_toml",
]

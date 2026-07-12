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

import tomllib
from collections.abc import Sequence
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

# The fd the Supervisor's provider-key channel rides on. Mandatory in
# ``keep_fds`` for every policy (arch-2).
_REQUIRED_FD: Final[int] = 3

# The CLOSED allow-list of paths that may be SOFT-bound (``ro_binds_try``, #269).
#
# ``ro_binds_try`` is the schema's ONLY silently-skipping field: bwrap binds the
# source iff it exists and says NOTHING when it does not. That is exactly right
# for a genuinely arch-variable path (``/lib64`` exists on x86-64, never on
# arm64) and exactly WRONG for anything else — an unconstrained field would let a
# typo (``/lib46``) or a load-bearing bind (``/etc/ssl/certs``, an egress socket
# dir) degrade the sandbox in silence instead of refusing at launch. That silent
# degradation is the failure mode ``ro_binds`` is HARD precisely to avoid
# (CLAUDE.md hard rule #7: no silent failures in security paths).
#
# So the field is constrained exactly as ``unshare`` is — by a closed vocabulary
# the type refuses to leave (see the ``unshare`` Literal below: "silently
# dropping an unknown unshare kind would weaken isolation without telling
# anyone"). To soft-bind a NEW path, add it HERE, with the arch that lacks it and
# why its absence is expected. That one-line edit IS the security review.
_SOFT_BINDABLE_PATHS: Final[frozenset[str]] = frozenset({"/lib64"})


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
    def _refuse_hard_and_soft_bind_of_same_path(self) -> SandboxPolicy:
        # #269 follow-up: the allow-list alone does NOT catch this. `/lib64` is
        # legal in `ro_binds_try`, so a policy listing it in BOTH lists validates
        # clean — and then `policy_to_bwrap_flags` emits the HARD `--ro-bind
        # /lib64` FIRST, which is precisely the launch failure #269 removed
        # ("bwrap: Can't find source path /lib64" on arm64). The soft entry that
        # follows is dead code. The policy would sail past a validator that says
        # it is fine and resurrect the original bug.
        #
        # A path is EITHER always-present (hard) OR arch-variable (soft). Never
        # both — that is a contradiction in the policy's own claim about the path,
        # so refuse it at parse time rather than let the hard bind quietly win.
        hard_dsts = {dst for _src, dst in self.ro_binds}
        for _src, dst in self.ro_binds_try:
            if dst in hard_dsts:
                raise SandboxPolicyInvalid(
                    reason="soft_bind_conflicts_with_hard_bind",
                    detail=(
                        f"{dst!r} is bound BOTH hard (ro_binds) and soft (ro_binds_try). "
                        f"The hard bind is emitted first and fails the whole launch where "
                        f"the source is absent, so the soft bind is dead — declare the path "
                        f"in exactly one list."
                    ),
                )
        return self

    @model_validator(mode="after")
    def _restrict_soft_binds(self) -> SandboxPolicy:
        # #269: a soft bind SILENTLY skips a missing source, so the set of paths
        # allowed to be soft is closed (:data:`_SOFT_BINDABLE_PATHS`). A policy
        # soft-binding anything else — a typo'd ``/lib46``, or a load-bearing
        # ``/etc/ssl/certs`` — would degrade the sandbox without a word instead of
        # refusing at launch. Refuse it at PARSE time, loudly, with a
        # closed-vocabulary reason the ``supervisor.plugin.sandbox_refused`` audit
        # row can carry.
        for src, dst in self.ro_binds_try:
            if src not in _SOFT_BINDABLE_PATHS or dst not in _SOFT_BINDABLE_PATHS:
                raise SandboxPolicyInvalid(
                    reason="soft_bind_forbidden_path",
                    detail=(
                        f"ro_binds_try may only carry arch-variable paths "
                        f"{sorted(_SOFT_BINDABLE_PATHS)}; got {src!r} -> {dst!r}. "
                        f"A path that must always exist belongs in ro_binds, where a "
                        f"missing source fails loud instead of silently skipping."
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
    "policy_to_bwrap_flags",
    "read_policy_toml",
]

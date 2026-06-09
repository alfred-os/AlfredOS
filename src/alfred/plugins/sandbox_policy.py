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

* **--sync-fd, not --keep-fd (issue #218).** Debian Bookworm ships bubblewrap
  0.8.0 whose flag for "keep this fd open while the sandbox runs" is
  ``--sync-fd FD``. ``--keep-fd`` is the upstream 0.9.0+ rename. The launcher
  runs against the Bookworm image, so the translator emits ``--sync-fd``. The
  logical field name ``keep_fds`` is retained as documented shorthand; only
  the CLI surface uses the version-correct flag.
"""

from __future__ import annotations

import tomllib
from collections.abc import Sequence
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

# The fd the Supervisor's provider-key channel rides on. Mandatory in
# ``keep_fds`` for every policy (arch-2).
_REQUIRED_FD: Final[int] = 3


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


def policy_to_bwrap_flags(policy: SandboxPolicy) -> list[str]:
    """Translate a :class:`SandboxPolicy` into the bwrap CLI flag list.

    The flag order is stable (binds → tmpfs → dev → unshare → die-with-parent →
    sync-fd) so the launcher's exec line is reproducible and auditable across
    Python dict-ordering changes.
    """
    flags: list[str] = []
    for src, dst in policy.ro_binds:
        flags += ["--ro-bind", src, dst]
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
    for fd in policy.keep_fds:
        # --sync-fd, not --keep-fd: Bookworm bubblewrap 0.8.0 naming (#218).
        flags += ["--sync-fd", str(fd)]
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

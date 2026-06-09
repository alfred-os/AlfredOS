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

from pathlib import Path

import pytest

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

"""Go-live gate: the shipped quarantined-LLM bwrap policy declares fd 4 (the
SCM_RIGHTS control channel, #340 golive) and binds the narrow public-CA trust
store for the child's TLS verify path — WITHOUT widening `/etc` exposure.

Companion to ``tests/unit/plugins/test_quarantined_llm_sandbox_policy.py``
(which pins the #269 arch-portable `/lib64` soft bind and the pre-golive `no
/etc` posture). This module pins the golive-specific additions on top of that
posture, not a replacement for it:

* ``keep_fds`` now DECLARES fd 4 alongside fd 3 — the golive child (Task 6)
  reconstructs fd 4 as the SCM_RIGHTS control channel over which the host
  (Task 8, ``control_fd=True``) passes brokered gateway sockets; a policy that
  omitted 4 from the declaration would not itself sever the fd (bwrap inherits
  open, non-CLOEXEC fds by default — see ``sandbox_policy.py``'s module
  docstring), but ``keep_fds`` is the auditable, validated declaration of what
  must survive, so it must track the real channel set.
* the narrowest possible CA carve-out — ``/etc/ssl/certs`` ONLY, added to the
  HARD ``ro_binds`` (never ``ro_binds_try``: the schema's own
  ``_restrict_soft_binds`` validator refuses a non-arch-variable path there,
  and a load-bearing CA bundle degrading the sandbox in silence on a missing
  source would be exactly the #7 hard-rule violation the soft field exists to
  prevent). This is the child's TLS verify path once it terminates TLS
  in-child (Task 6) over a broker-passed socket (Task 8/Task 3's
  ``brokered_egress.py``); it is NOT a bare ``/etc`` bind — the #428
  over-broad-bind class this repo has fixed before.
* ``net`` stays unshared (the Spec C G7-1 closed-egress anchor is untouched by
  this task — the golive child reaches its provider via a broker-passed
  socket over fd 4, never by re-opening this network namespace).
"""

from __future__ import annotations

from pathlib import Path

from alfred.plugins.sandbox_policy import read_policy_toml

_POLICY = (
    Path(__file__).resolve().parents[3]
    / "config"
    / "sandbox"
    / "quarantined-llm.linux.bwrap.policy"
)


def test_keep_fds_includes_control_fd() -> None:
    """fd 3 (provider-key channel) AND fd 4 (SCM_RIGHTS control channel) are both
    declared survivors — the golive child needs both."""
    policy = read_policy_toml(_POLICY.read_text())
    assert 3 in policy.keep_fds
    assert 4 in policy.keep_fds


def test_net_stays_unshared() -> None:
    """The closed-egress anchor (Spec C G7-1) is never dropped by this task."""
    policy = read_policy_toml(_POLICY.read_text())
    assert "net" in policy.unshare


def test_ca_bind_is_narrow_not_etc() -> None:
    """The CA carve-out is `/etc/ssl/certs` ONLY — never a bare `/etc` bind."""
    body = _POLICY.read_text()
    assert "/etc/ssl/certs" in body
    policy = read_policy_toml(body)
    # The narrow CA path is present as a HARD bind (not the soft field, which
    # the schema's own _restrict_soft_binds validator would refuse it from).
    assert ("/etc/ssl/certs", "/etc/ssl/certs") in policy.ro_binds
    # Never a bare /etc bind, in EITHER bind field (#428 over-broad-bind class).
    assert not any(row == ("/etc", "/etc") for row in policy.ro_binds)
    assert not any(row == ("/etc", "/etc") for row in policy.ro_binds_try)


def test_ca_bind_is_the_only_new_etc_subpath() -> None:
    """No OTHER /etc subpath rides in on this change — the carve-out is exactly
    one path, not a foothold for a wider /etc bind later."""
    policy = read_policy_toml(_POLICY.read_text())
    all_binds = (*policy.ro_binds, *policy.ro_binds_try)
    etc_sources = [src for src, _dst in all_binds if src.startswith("/etc")]
    assert etc_sources == ["/etc/ssl/certs"]

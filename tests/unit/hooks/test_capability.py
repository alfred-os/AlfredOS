"""Tests for ``alfred.hooks.capability`` — the two-gate security primitive.

The capability gate is the load-bearing security seam between a hook
subscriber's *requested* trust tier and the runtime's *granted* trust
tier. Slice 2.5 ships the Protocol (the seam every gate implementation
must honour) plus a dev-time default (:class:`DevGate`) that returns
predictable answers without persisting state or reading the environment.

Invariants pinned here — these are CLAUDE.md hard rules, not stylistic
preferences:

* **Hard rule #4 (capability layer)** — never bypass the gate. The deny
  paths assert against the *real* :class:`DevGate` refusal, never a
  stub or "always allow" double. The unknown-tier and ``system``-without-
  ``allow_system`` branches MUST return ``False`` and the test verifies
  that directly.
* **Hard rule #7 (no silent failures)** — an unknown / typo'd / case-
  mismatched tier string is a *loud* refusal-via-fail-closed default,
  not an exception-swallowed pass. The parametrize over ``"root"``, ``""``,
  ``"SYSTEM"`` and ``"None"`` pins every deny branch.
* **sec-007 (no env flag)** — ``allow_system`` is constructor-only. The
  env-isolation test sets ``ALFRED_HOOKS_ALLOW_SYSTEM`` via monkeypatch
  before constructing ``DevGate()`` (no arg) and asserts ``system`` is
  STILL denied. Task-4 will add an AST-scan regression guard against
  ``os`` import in ``capability.py``; this test is the behavioural pin.
* **Structural subtyping** — :class:`DevGate` satisfies the
  :class:`CapabilityGate` Protocol structurally. Pinning
  ``isinstance(DevGate(), CapabilityGate)`` lets dispatcher code in
  Task-10 type-narrow on ``CapabilityGate`` without a registry of
  concrete subclasses.
* **Keyword-only contract** — both the constructor's ``allow_system``
  parameter and the ``check`` method's ``plugin_id`` / ``hookpoint`` /
  ``requested_tier`` parameters are keyword-only. Positional invocation
  raises :class:`TypeError`. The spec contract reads ``*,`` for a reason:
  a caller cannot accidentally swap, say, ``plugin_id`` and ``hookpoint``
  via positional args.
"""

from __future__ import annotations

import dataclasses

import pytest

from alfred.hooks.capability import CapabilityGate, DevGate


def test_default_devgate_refuses_system() -> None:
    """``DevGate()`` (no constructor arg) denies the ``system`` tier.

    The default-deny on ``system`` is the operator-tier guardrail: a hook
    cannot escalate to system-level capability just by asking. Granting
    ``system`` requires explicit constructor opt-in via ``allow_system``.
    """
    gate = DevGate()
    assert gate.check(plugin_id="p", hookpoint="h", requested_tier="system") is False


def test_default_devgate_grants_operator() -> None:
    """``DevGate()`` always grants the ``operator`` tier.

    ``operator`` is the AlfredOS default tier for first-party hooks; the
    dev-time gate grants it unconditionally so local development does
    not require a fixture grant for every operator-tier subscriber.
    """
    gate = DevGate()
    assert gate.check(plugin_id="p", hookpoint="h", requested_tier="operator") is True


def test_default_devgate_grants_user_plugin() -> None:
    """``DevGate()`` always grants the ``user-plugin`` tier.

    ``user-plugin`` is the bundled-plugin tier — the comms adapters,
    integrations, and personas the user has explicitly installed. The
    dev-time gate grants it unconditionally so a third-party plugin
    author can iterate without re-wiring the gate.
    """
    gate = DevGate()
    assert gate.check(plugin_id="p", hookpoint="h", requested_tier="user-plugin") is True


def test_devgate_with_allow_system_grants_system() -> None:
    """``DevGate(allow_system=True)`` grants the ``system`` tier.

    The constructor-only opt-in is the only way for ``system`` to flip
    to ``True``. Task-4's AST-scan regression guards against adding an
    env-read or runtime setter; this test pins the positive grant path
    through the legitimate constructor seam.
    """
    gate = DevGate(allow_system=True)
    assert gate.check(plugin_id="p", hookpoint="h", requested_tier="system") is True


@pytest.mark.parametrize("unknown_tier", ["root", "", "SYSTEM", "None"])
def test_devgate_refuses_unknown_tier_fail_closed(unknown_tier: str) -> None:
    """Unknown / typo'd / case-mismatched tier strings deny (fail-closed).

    Empty string, alternate-case variants of known tiers, and unknown
    tier names ALL deny — even with ``allow_system=True`` set. The
    default-deny on an unrecognised input is the CLAUDE.md hard-rule-#7
    "no silent failures" contract: a typo'd tier in a hook decorator
    surfaces as an immediate refusal, not as silently-granted access.
    """
    gate = DevGate(allow_system=True)
    assert gate.check(plugin_id="p", hookpoint="h", requested_tier=unknown_tier) is False


def test_devgate_satisfies_capability_gate_protocol() -> None:
    """``DevGate`` is structurally a :class:`CapabilityGate`.

    The Protocol is ``@runtime_checkable`` so dispatcher code (Task-10)
    can type-narrow with ``isinstance`` without a registry of concrete
    gate classes. Both the deny-by-default and allow-system-True
    constructions satisfy the structural check — the structural
    membership is independent of the gate's internal flag state.
    """
    assert isinstance(DevGate(), CapabilityGate)
    assert isinstance(DevGate(allow_system=True), CapabilityGate)


def test_check_rejects_positional_args() -> None:
    """``DevGate().check`` is keyword-only on every parameter.

    The verbatim spec §0 signature reads ``check(self, *, plugin_id,
    hookpoint, requested_tier) -> bool`` — the ``*,`` is the contract.
    A caller cannot accidentally swap ``plugin_id`` and ``hookpoint``
    via positional args; the type system enforces the boundary.
    """
    gate = DevGate()
    with pytest.raises(TypeError):
        gate.check("p", "h", "operator")  # type: ignore[misc]


def test_constructor_rejects_positional_args() -> None:
    """``DevGate(...)`` is keyword-only on ``allow_system``.

    The same ``*,`` discipline applies to the constructor: a future
    addition of a second flag could not be silently confused with
    ``allow_system`` via positional args.
    """
    with pytest.raises(TypeError):
        DevGate(True)  # type: ignore[misc]  # noqa: FBT003 -- asserting that positional bool is rejected is the point of this test.


def test_devgate_does_not_read_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sec-007: ``allow_system`` is constructor-only — never env-driven.

    Setting ``ALFRED_HOOKS_ALLOW_SYSTEM=true`` in the environment must
    NOT cause ``DevGate()`` (with no constructor arg) to grant
    ``system``. The behavioural pin here complements the AST-scan
    regression guard Task-4 lands against ``os`` imports in
    ``capability.py``.
    """
    monkeypatch.setenv("ALFRED_HOOKS_ALLOW_SYSTEM", "true")
    monkeypatch.setenv("ALFRED_ALLOW_SYSTEM", "1")
    gate = DevGate()
    assert gate.check(plugin_id="p", hookpoint="h", requested_tier="system") is False


def test_capability_gate_protocol_has_check_plugin_load() -> None:
    """:class:`CapabilityGate` Protocol exposes ``check_plugin_load``.

    PR-S3-2 (spec §8.2) extends the Protocol with the
    ``check_plugin_load`` method so the supervisor can refuse a plugin at
    handshake time when no subscriber-tier grant exists. The signature is
    keyword-only on ``plugin_id`` / ``manifest_tier`` and every gate
    implementation MUST honour it — the Protocol membership is the only
    way the supervisor's type-narrowing finds the method.
    """
    import inspect

    from alfred.hooks.capability import CapabilityGate

    assert "check_plugin_load" in dir(CapabilityGate)
    sig = inspect.signature(CapabilityGate.check_plugin_load)
    assert "plugin_id" in sig.parameters
    assert "manifest_tier" in sig.parameters


def test_capability_gate_protocol_has_check_content_clearance() -> None:
    """:class:`CapabilityGate` Protocol exposes ``check_content_clearance``.

    PR-S3-2 (spec §8.2) extends the Protocol with
    ``check_content_clearance`` — the orthogonal content-trust axis. The
    quarantined-LLM plugin host and StdioTransport are the only
    authorised callers for ``content_tier="T3"``; every other caller
    receives a refusal. The Protocol signature is the gate-side contract
    every implementation must honour.
    """
    import inspect

    from alfred.hooks.capability import CapabilityGate

    assert "check_content_clearance" in dir(CapabilityGate)
    sig = inspect.signature(CapabilityGate.check_content_clearance)
    assert "plugin_id" in sig.parameters
    assert "hookpoint" in sig.parameters
    assert "content_tier" in sig.parameters


def test_devgate_check_plugin_load_returns_true_by_default() -> None:
    """``DevGate.check_plugin_load`` is fail-open for Slice-3 co-existence.

    Spec §8.4: ``DevGate`` implements the two new Protocol methods to
    fail-open (returning ``True``) so Slice-2.5 tests that pre-date the
    Protocol extension still pass. PR-S3-7 flag-day removes ``DevGate``;
    until then the fail-open stub is deliberate, not an oversight.
    """
    from alfred.hooks.capability import DevGate

    gate = DevGate()
    assert (
        gate.check_plugin_load(plugin_id="test.plugin", manifest_tier="operator")
        is True
    )


def test_devgate_check_content_clearance_returns_true_by_default() -> None:
    """``DevGate.check_content_clearance`` is fail-open for Slice-3 co-existence.

    Same rationale as ``check_plugin_load``: the two new Protocol methods
    are fail-open stubs on ``DevGate`` for backward compatibility with
    Slice-2.5 dispatch tests. Spec §8.4; PR-S3-7 removes ``DevGate`` on
    flag-day.
    """
    from alfred.hooks.capability import DevGate

    gate = DevGate()
    assert (
        gate.check_content_clearance(
            plugin_id="test.plugin",
            hookpoint="tool.web.fetch",
            content_tier="T3",
        )
        is True
    )


def test_devgate_satisfies_extended_capability_gate_protocol() -> None:
    """``DevGate`` with the two new methods still satisfies :class:`CapabilityGate`.

    The Protocol is ``@runtime_checkable`` so the structural membership
    check runs at runtime. After Task-2 adds ``check_plugin_load`` and
    ``check_content_clearance`` to both the Protocol and ``DevGate``, the
    ``isinstance`` check below MUST still pass — otherwise dispatcher
    code that type-narrows on :class:`CapabilityGate` loses ``DevGate``
    coverage for the new methods.
    """
    from alfred.hooks.capability import CapabilityGate, DevGate

    assert isinstance(DevGate(), CapabilityGate)


def test_devgate_is_frozen_and_rejects_post_init_mutation() -> None:
    """sec-007 (frozen-mutation): ``DevGate`` is a frozen dataclass.

    A caller cannot bypass the gate at runtime via
    ``setattr(gate, "allow_system", True)`` because the dataclass is
    ``frozen=True``. This is the language-level pin behind the sec-007
    "constructor-only" contract — privacy on the attribute name is no
    longer load-bearing because mutation is impossible at any
    visibility.

    The check covers both the default-deny and the constructor-opted-in
    constructions: the frozen-ness is an instance property, independent
    of the initial ``allow_system`` value.
    """
    gate = DevGate()
    with pytest.raises(dataclasses.FrozenInstanceError):
        gate.allow_system = True  # type: ignore[misc]
    # Still denies system post-attempt — the bypass produced no effect.
    assert gate.check(plugin_id="p", hookpoint="h", requested_tier="system") is False

    permitted = DevGate(allow_system=True)
    with pytest.raises(dataclasses.FrozenInstanceError):
        permitted.allow_system = False  # type: ignore[misc]
    # The grant survives the failed mutation.
    assert permitted.check(plugin_id="p", hookpoint="h", requested_tier="system") is True

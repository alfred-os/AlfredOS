"""#338 PR2 Task 4 — the FOLD-2 refuse-boot arms + the Task-3-review must-carry arm.

``_build_comms_boot_graph`` (called from the ``_commands.py:654``-ish try) now
assembles a REAL, egress-proxied ``ProviderRouter`` and a REAL ``Orchestrator`` for
the ``RealTurnOrchestratorAdapter`` (the deterministic-echo adapter is gone). Three
faults that were previously UNCAUGHT (exit 1, no audit row — the #368 anti-pattern)
must now refuse boot audited (exit 2):

* ``IOPlaneUnavailableError`` — ``build_router``'s ``EgressClient.from_settings``
  raises when ``ALFRED_EGRESS_PROXY_URL`` is unset/blank. REACHABLE via a real boot
  (the field is optional).
* ``UnknownSecretError`` — the same ``build_router`` call's
  ``secret_broker.get("deepseek_api_key")`` raises when the key is unprovisioned.
  UNREACHABLE via a real ``_start_async`` boot TODAY (FOLD-R15): ``deepseek_api_key``
  is a REQUIRED ``Settings`` field, so the earlier required-field ``SettingsError``
  guard trips first. Tested as defense-in-depth via (a) a direct ``build_router``
  plumbing check and (b) the arm itself (mirroring the existing "unreachable-today"
  ``SecretBrokerConfigError`` sibling test's monkeypatch-the-call pattern).
* ``IdentityResolutionError`` — ``build_orchestrator`` -> ``Orchestrator.__init__``
  synchronously calls ``identity_resolver.get_operator()`` (``core.py:308``), which
  raises when zero or more than one operator user exists
  (``identity/resolver.py:191/197``). REACHABLE via a real boot (a fresh install
  with no seeded operator, or a corrupt multi-operator state). Tested for BOTH the
  zero- and multi-operator messages — both hit the SAME ``except`` arm.
"""

from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.security.quarantine import declare_hookpoints
from tests.helpers.gates import make_quarantined_extract_chain_gate

from .conftest import FakeAuditWriter

_ENABLED_ADAPTER = "alfred_comms_test"


@pytest.fixture
def quarantine_registry() -> Any:
    """Install a scoped registry granting the system-tier DLP grant.

    Mirrors the identical fixture in ``test_daemon_comms_spawn.py`` — the daemon
    boot path constructs a REAL ``QuarantinedExtractor`` (inside
    ``_build_comms_inbound_extractor``), which refuses to construct without an
    active post-stage DLP subscriber registration on the
    ``security.quarantined.extract`` chain (PRD §7.1). Never an always-allow shim
    (CLAUDE.md hard rule #2).
    """
    prior = get_registry()
    registry = HookRegistry(
        gate=make_quarantined_extract_chain_gate(),
        strict_declarations=False,
    )
    try:
        set_registry(registry)
        declare_hookpoints(registry)
        yield registry
    finally:
        set_registry(prior)


def _boot_failed_reasons(audit: FakeAuditWriter) -> set[str]:
    rows = audit.rows_for("DAEMON_BOOT_FAILED_FIELDS")
    return {r["subject"]["failure_reason"] for r in rows if isinstance(r["subject"], dict)}


# ── (a) IOPlaneUnavailableError — REACHABLE via _start_async ──────────────────────


def test_boot_refuses_when_egress_proxy_unset(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """An unset ``ALFRED_EGRESS_PROXY_URL`` on a comms-enabled boot refuses (exit 2).

    ``egress_proxy_url`` is an OPTIONAL ``Settings`` field (unlike
    ``deepseek_api_key``), so no earlier required-field guard intercepts this —
    ``build_router``'s ``EgressClient.from_settings`` is the first thing to raise.
    """
    del quarantine_registry  # installed via fixture side effect
    del patch_quarantine_child_spawn  # in-proc fake child-IO; no real bwrap spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    # boot_success_env sets a dummy proxy URL for every OTHER comms boot test;
    # unset it here to drive exactly the fault this test targets.
    monkeypatch.delenv("ALFRED_EGRESS_PROXY_URL", raising=False)

    result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code == 2
    reasons = _boot_failed_reasons(boot_success_env)
    assert "egress_plane_unavailable" in reasons
    # No completion row was ever written — the refusal happened before the daemon
    # was genuinely up (FIX 1's ordering invariant).
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []
    # The operator-facing message names the missing env var.
    assert "ALFRED_EGRESS_PROXY_URL" in result.output


# ── (b) UnknownSecretError — UNREACHABLE via _start_async (FOLD-R15); defense-in-depth ──


def test_build_router_propagates_unknown_secret_error() -> None:
    """Plumbing check: ``build_router`` does not swallow a broker key-lookup fault.

    Drives ``build_router`` DIRECTLY with a broker whose ``deepseek_api_key`` lookup
    raises ``UnknownSecretError`` — proving the exception the ``_commands.py`` arm
    depends on actually propagates out of ``build_router`` uncaught.
    """
    from alfred.cli._bootstrap import build_router
    from alfred.config.settings import Settings
    from alfred.security.secrets import UnknownSecretError

    class _RaisingBroker:
        def get(self, name: str) -> str:
            raise UnknownSecretError(f"{name} is not set")

        def has(self, name: str) -> bool:
            return False

    settings = Settings(
        environment="test",
        deepseek_api_key="sk-test",
        egress_proxy_url="http://proxy.invalid:3128",
    )

    with pytest.raises(UnknownSecretError):
        build_router(_RaisingBroker(), settings)


def test_boot_refuses_on_router_secret_missing(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
) -> None:
    """The ``router_secret_missing`` arm fires an audited refusal (exit 2).

    FOLD-R15: this fault is UNREACHABLE via a real ``_start_async`` boot (the
    earlier required-field ``SettingsError`` guard on ``deepseek_api_key`` always
    trips first), so — mirroring the existing "unreachable-today"
    ``SecretBrokerConfigError`` sibling test
    (``test_boot_refuses_audited_on_comms_graph_broker_config_error``) — this drives
    the fault by monkeypatching ``_build_comms_boot_graph`` itself (the call the new
    arm wraps) to raise ``UnknownSecretError`` directly, rather than by unsetting
    the key (which would refuse earlier, for a DIFFERENT reason, never reaching this
    arm).
    """
    del quarantine_registry  # installed via fixture side effect
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')

    from alfred.security.secrets import UnknownSecretError

    async def _raise_unknown_secret(*_a: Any, **_k: Any) -> Any:
        raise UnknownSecretError(
            "deepseek_api_key (env ALFRED_DEEPSEEK_API_KEY, file key 'deepseek_api_key') is not set"
        )

    monkeypatch.setattr(
        "alfred.cli.daemon._commands._build_comms_boot_graph", _raise_unknown_secret
    )

    result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code == 2
    reasons = _boot_failed_reasons(boot_success_env)
    assert "router_secret_missing" in reasons
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []


# ── (c) IdentityResolutionError — REACHABLE via _start_async ──────────────────────


class _RaisingOperatorResolver:
    """Stub ``IdentityResolverLike`` whose ``get_operator()`` always raises.

    Mirrors ``conftest.py``'s ``_FakeOperatorResolver`` shape (``version_counter``
    is read by ``build_budget_guard`` BEFORE ``Orchestrator.__init__`` calls
    ``get_operator()``), but raises instead of returning a canned operator — driving
    the exact fault ``Orchestrator.__init__`` (``core.py:308``) surfaces for a
    zero-operator or multi-operator identity store.
    """

    def __init__(self, message: str) -> None:
        from alfred.identity import IdentityVersionCounter

        self.version_counter = IdentityVersionCounter()
        self._message = message

    def get_operator(self) -> Any:
        from alfred.identity.errors import IdentityResolutionError

        raise IdentityResolutionError(self._message)


@pytest.mark.parametrize(
    "message",
    [
        "No operator user exists. Run `alfred user add --authorization operator` to bootstrap one.",
        "Multiple operator users exist (alice, bob). This is a corrupt state; demote all but "
        "one via `alfred user set --authorization trusted <slug>`.",
    ],
    ids=["zero_operator", "multiple_operator"],
)
def test_boot_refuses_on_identity_resolution_error(
    message: str,
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """Both the zero-operator and multi-operator faults refuse the SAME way (exit 2).

    ``get_operator()`` raises ``IdentityResolutionError`` with a different message
    for each case (``identity/resolver.py:191`` vs ``:197``), but the ``_commands.py``
    ``except`` arm does not distinguish them — both hit the audited
    ``operator_not_seeded`` refusal.
    """
    del quarantine_registry  # installed via fixture side effect
    del patch_quarantine_child_spawn  # in-proc fake child-IO; no real bwrap spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    # Override the boot_success_env seam (normally a canned-operator fake) with one
    # that raises, driving the exact Orchestrator.__init__ fault under test.
    monkeypatch.setattr(
        "alfred.cli._bootstrap.install_identity_factories_for_settings",
        lambda _settings: _RaisingOperatorResolver(message),
    )

    result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code == 2
    reasons = _boot_failed_reasons(boot_success_env)
    assert "operator_not_seeded" in reasons
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []
    # The operator-facing message names the concrete remedy.
    assert "alfred user add" in result.output

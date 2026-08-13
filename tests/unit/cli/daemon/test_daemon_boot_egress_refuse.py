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

import sys
from typing import Any

import pytest
import structlog.testing
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.security.quarantine import declare_hookpoints
from tests.helpers.gates import make_quarantined_extract_chain_gate

from .conftest import FakeAuditWriter
from .test_daemon_comms_spawn import _patch_comms_seams

_ENABLED_ADAPTER = "alfred_comms_test"

# The three tests below drive a FULL, successful `alfred daemon start`. A completed
# boot unconditionally binds the daemon control plane's 0600 AF_UNIX socket
# (`_commands.py` -> `DaemonControlServer.start()` -> `bind_owner_only_unix_socket`),
# and CPython does not expose `socket.AF_UNIX` on Windows at all — so they crash there
# with an AttributeError no amount of plugin-layer mocking can avoid. The other seven
# tests in this file refuse the boot inside `_build_comms_boot_graph`, well before any
# POSIX syscall, so they keep running on Windows and this file stays MIXED (per-test
# skipif, NOT the tests/_posix_only_tests.py whole-file registry). Same guard, same
# reason as the three structurally identical full-boot tests in
# test_daemon_boot_t3_nonce.py. Windows dev of this Linux-only surface is via WSL2.
#
# The Windows equivalents were investigated, not assumed (#586/#587 review), and
# they DO exist — this guard is about what is BUILT, not about what is possible.
#
# Blocking the control plane specifically, today: CPython compiles out the
# `sockaddr_un` marshalling on Windows behind the same `#ifdef` that drops the
# `socket.AF_UNIX` constant (upstream gh-77589 is still open; its PR gh-137420
# targets 3.16 and omits asyncio, while this repo pins 3.14), and
# `asyncio.start_unix_server` — the API `DaemonControlServer` actually calls — is
# defined only under `hasattr(socket, "AF_UNIX")`, so it is absent there
# regardless. Named pipes are the true analogue and CAN carry the equivalent
# contract: a DACL for the 0600 owner-only property, `GetNamedPipeClientProcessId`
# for the `SO_PEERCRED` peer check.
#
# Porting the control plane alone would buy nothing while the sandbox backend
# beneath it is unbuilt, though. #471 Phase 2 scopes the real Windows security
# model: AppContainer for containment (omitting the `internetClient` capability is
# the direct analogue of bwrap's `--unshare-net`) plus `WSADuplicateSocket` +
# `DuplicateHandle` for the fd-4 broker (reproducing the SCM_RIGHTS contract —
# hand over an already-connected socket the child never dials). Until that lands,
# `kind:full` refuses in production on native Windows, so the quarantined child
# these tests boot cannot run there at all. Native Windows is an explicit PRD
# non-goal (PRD.md:602); the supported path is WSL2, which reports `uname -s` as
# Linux and therefore takes the full bwrap path unchanged.
_posix_boot_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: daemon boot brings up AF_UNIX comms sockets + os.getuid-based peer auth",
)


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


# ── (d) QuarantineProviderSeparationCollisionError — #586 opt-in enforcement ───────


def test_boot_refuses_when_separation_required_and_providers_collide(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """require_quarantine_provider_separation=True + same provider -> refuse boot,
    AUDITED (arch-002/sec-001/test-001 — this is the fix, not just 'raises AlfredError'):
    proves _commands.py's except-cascade catches the new exception type and routes
    it through _refuse_boot, not that SOME AlfredError propagates unhandled."""
    del quarantine_registry  # installed via fixture side effect
    del patch_quarantine_child_spawn  # in-proc fake child-IO; no real bwrap spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    # Settings.primary_provider defaults "deepseek"; force quarantine_provider to
    # collide with it (Settings.quarantine_provider otherwise defaults "anthropic").
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    monkeypatch.setenv("ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION", "true")

    with structlog.testing.capture_logs() as logs:
        result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code == 2
    reasons = _boot_failed_reasons(boot_success_env)
    assert "quarantine_provider_separation_violated" in reasons
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []
    # The refusal must NAME the colliding ids somewhere in the boot record (review fix).
    # The t() operator message names the env vars to change but not their values, and
    # DAEMON_BOOT_FAILED_FIELDS is a closed schema carrying only the reason token — so
    # the log line is the ONLY place the actual collision appears. Its require=False
    # WARN sibling below already logs both; this pins the refuse path to parity.
    violated = [
        e for e in logs if e["event"] == "daemon.boot.quarantine_provider_separation_violated"
    ]
    assert len(violated) == 1, f"expected one loud violation log, got {logs!r}"
    assert violated[0]["privileged_provider"] == "deepseek", violated
    assert violated[0]["quarantine_provider"] == "deepseek", violated
    # The operator-facing message must be the t() catalogue string, NOT str(exc).
    # assert_provider_separation()'s own message names routing.yaml [quarantine] as the
    # remedy and cites "spec §5.4" — a remedy that does nothing (routing.yaml is not read
    # at runtime) and a citation ADR-0064 supersedes. Whitespace-collapsed because the CLI
    # renderer hard-wraps to the terminal width, so a raw substring can straddle a newline.
    flat = " ".join(result.output.split())
    assert "spec §5.4" not in flat, flat
    assert "PRD §6.4" not in flat, flat
    assert "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION" in flat, flat
    assert "ALFRED_QUARANTINE_PROVIDER=" in flat, flat
    assert "0064" in flat, flat


def test_boot_refuses_blank_primary_provider_as_settings_invalid_not_collision(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """A blank ``primary_provider`` is INVALID CONFIG, never a "collision" (CodeRabbit r2).

    ``assert_provider_separation`` checks blank ids BEFORE the collision test and raises
    its own distinct ``AlfredError`` for them — which ``_comms_boot``'s
    ``except AlfredError`` relabelled as ``QuarantineProviderSeparationCollisionError``,
    so an operator who merely left ``ALFRED_PRIMARY_PROVIDER`` empty was told the two
    halves of the dual-LLM split collided and sent to change the WRONG env var.

    The oracle is the NEGATIVE assertion as much as the positive one: exit 2 alone would
    pass under the old mislabel, so this pins that the collision reason is ABSENT.
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    monkeypatch.setenv("ALFRED_PRIMARY_PROVIDER", "")
    # The separation check is what used to mislabel it, so arm that path explicitly.
    monkeypatch.setenv("ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION", "true")
    _patch_comms_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code == 2, result.output
    reasons = _boot_failed_reasons(boot_success_env)
    assert "settings_invalid" in reasons, reasons
    assert "quarantine_provider_separation_violated" not in reasons, reasons
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []
    # ...and the operator-facing copy names the field that is actually wrong, so the
    # accurate reason token is not undone by a message that still says "collision".
    flat = " ".join(result.output.split())
    assert "primary_provider" in flat, flat


@_posix_boot_only
def test_boot_proceeds_when_separation_required_and_providers_differ(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """require=True + the (default) distinct providers -> boots fine, no refusal."""
    del quarantine_registry
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    monkeypatch.setenv("ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION", "true")
    # primary_provider="deepseek" / quarantine_provider="anthropic" — the defaults —
    # already differ; no override needed.
    _patch_comms_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code == 0, result.output
    assert _boot_failed_reasons(boot_success_env) == set()
    # ...and the DEFAULT provider reached the spawn (the anthropic axis of the same
    # end-to-end chain the deepseek test below pins).
    assert len(patch_quarantine_child_spawn) == 1, patch_quarantine_child_spawn
    spawn_kwargs = patch_quarantine_child_spawn[0].spawn_kwargs
    assert spawn_kwargs["provider"] == "anthropic", spawn_kwargs
    assert spawn_kwargs["base_url"] is None, spawn_kwargs


@_posix_boot_only
def test_happy_path_boot_logs_the_resolved_quarantine_provider(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """devex-002: the NON-collision boot says which quarantine provider it resolved.

    Before this line the only boot-time signal about the quarantine provider was a
    COLLISION (the refusal log, or the not-enforced warning) — an operator whose config
    was correct got nothing at all, and so had no way to confirm from the boot record
    that ``ALFRED_QUARANTINE_PROVIDER`` had been read, let alone which value won.

    Deliberately exercised on the arm where NEITHER collision branch runs (providers
    differ, separation not required): that is precisely the path that used to be silent,
    so a regression that moved the log inside either branch fails here.
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    # Defaults: primary_provider="deepseek", quarantine_provider="anthropic" (differ),
    # ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION unset -> False.
    _patch_comms_seams(monkeypatch)

    with structlog.testing.capture_logs() as logs:
        result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code == 0, result.output
    resolved = [e for e in logs if e["event"] == "comms.comms_boot.quarantine_provider_resolved"]
    assert len(resolved) == 1, f"expected one resolved line, got {logs!r}"
    # Pin the VALUES, not just the event name: an event that fired with the wrong /
    # missing provider would be worse than silence (it would read as confirmation).
    assert resolved[0]["quarantine_provider"] == "anthropic", resolved
    assert resolved[0]["privileged_provider"] == "deepseek", resolved
    assert resolved[0]["require_separation"] is False, resolved
    # Oracle guard: neither collision branch ran, so this line is the ONLY quarantine
    # provider signal on this boot — the exact gap devex-002 named.
    assert not [
        e
        for e in logs
        if e["event"] == "comms.comms_boot.quarantine_provider_separation_not_enforced"
    ], logs


@_posix_boot_only
def test_boot_proceeds_with_warning_when_separation_not_required_and_providers_collide(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """Default (require=False) + same provider -> boots, but WARNS AND audits
    (CLAUDE.md hard rule #7 — no silent failures; not just a log line, also a
    durable audit row via _emit_or_quarantine, since the security-relevant fact
    would otherwise leave no queryable trace)."""
    del quarantine_registry
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    # ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION left unset -> default False.
    _patch_comms_seams(monkeypatch)

    with structlog.testing.capture_logs() as logs:
        result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code == 0, result.output
    warned = [
        e
        for e in logs
        if e["event"] == "comms.comms_boot.quarantine_provider_separation_not_enforced"
    ]
    assert len(warned) == 1, f"expected one loud not-enforced warning, got {logs!r}"
    warn_rows = boot_success_env.rows_for(
        "DAEMON_BOOT_QUARANTINE_PROVIDER_SEPARATION_WARNED_FIELDS"
    )
    assert len(warn_rows) == 1, warn_rows
    # sec-r2-001's oracle: the row must actually carry boot_id (not just exist),
    # or a regression back to the boot_id-less shape would ship green.
    assert warn_rows[0]["subject"]["boot_id"], warn_rows
    # #587 end-to-end: the operator's ALFRED_QUARANTINE_PROVIDER=deepseek must survive
    # the WHOLE chain (`.env` -> Settings -> _comms_boot -> _build_comms_inbound_extractor
    # -> spawn), not just the daemon_runtime-unit hop. prov-001 was a value that resolved
    # correctly and then never reached the spawn — closing that at boot level too means a
    # broken hop ANYWHERE in the chain fails a test.
    assert len(patch_quarantine_child_spawn) == 1, patch_quarantine_child_spawn
    spawn_kwargs = patch_quarantine_child_spawn[0].spawn_kwargs
    # Literal expected values, NOT re-derived through _resolve_quarantine_* — an oracle
    # that reused the resolver would pass even if the resolver itself were wrong.
    assert spawn_kwargs["provider"] == "deepseek", spawn_kwargs
    assert spawn_kwargs["base_url"] == "https://api.deepseek.com/v1", spawn_kwargs
    assert spawn_kwargs["model"] == "deepseek-chat", spawn_kwargs


def test_boot_refuses_audited_when_deepseek_base_url_is_blank(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """``ALFRED_DEEPSEEK_BASE_URL=`` refuses boot AUDITED (exit 2), not uncaught (exit 1).

    A blank base_url is reachable operator misconfiguration, and it is invisible to
    ``build_child_client``'s ``base_url is None`` guard: ``AsyncOpenAI(base_url="")``
    constructs fine and fails only per call, where the quarantine dispatch retry loop
    LAUNDERS it into a generic ``cannot_extract`` — a boot-time misconfiguration wearing
    a runtime-failure costume (CLAUDE.md hard rule #7).

    The oracle is the AUDIT ROW, not just the exit code: an uncaught ``ValueError`` out
    of ``_resolve_quarantine_base_url`` would exit 1 with NO ``daemon.boot.failed`` row
    (the #368 anti-pattern this file exists to pin). Refusing at Settings construction
    routes it to the pre-existing ``settings_invalid`` refusal instead.
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    monkeypatch.setenv("ALFRED_DEEPSEEK_BASE_URL", "")
    _patch_comms_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code == 2, result.output
    assert "settings_invalid" in _boot_failed_reasons(boot_success_env)
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []


def test_boot_refuses_audited_when_deepseek_model_is_blank(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """``ALFRED_DEEPSEEK_MODEL=`` refuses boot AUDITED (exit 2), not uncaught (exit 1).

    The twin of the blank-``base_url`` case above, and the regression pin for a
    5-source-corroborated round-2 finding: ``_resolve_quarantine_model``'s own blank
    guard raises a bare ``ValueError`` that NOTHING in the boot cascade catches —
    ``_build_comms_boot_graph`` re-raises unchanged, none of ``_commands.py``'s ~9 typed
    arms is ``ValueError``/``Exception``, and ``start_daemon`` catches only
    ``_BootRefusedError``. This scenario was empirically reproduced crashing
    ``alfred daemon start`` with exit 1 and ZERO ``daemon.boot.failed`` rows — the #368
    anti-pattern this whole file exists to pin.

    ``Settings._reject_blank_deepseek_model`` is the fix: refusing at Settings
    CONSTRUCTION routes it to the pre-existing audited ``settings_invalid`` refusal, and
    protects the privileged ``build_router`` DeepSeek path in the same stroke (a
    boot-path-local fix would not have).

    The oracle is the AUDIT ROW, not just the exit code: an uncaught ``ValueError`` also
    ends the process, but with no record an operator can read.
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    monkeypatch.setenv("ALFRED_DEEPSEEK_MODEL", "")
    _patch_comms_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code == 2, result.output
    assert "settings_invalid" in _boot_failed_reasons(boot_success_env)
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []

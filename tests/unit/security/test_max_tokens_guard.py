"""#340 PR2b golive Task 15: ``max_tokens > 0`` fail-loud at BOTH quarantine boundaries.

A ``max_tokens <= 0`` MUST fail LOUD at the config-load / spawn-env boundary and at the
child's ``_build_provider`` — it must NEVER launder into a ``cannot_extract`` typed
refusal (the HARD #7 silent-failure shape). The anti-launder mechanism: if a non-positive
budget reached :func:`dispatch_extraction`, the ``CompletionRequest(max_tokens=...)`` ``>0``
validator raises a :class:`pydantic.ValidationError` that the retry loop catches as
RETRY-ELIGIBLE — N doomed attempts, then ``cannot_extract`` — masking a config
misconfiguration as an extraction refusal. Both guards fire BEFORE any provider call so a
bad value never reaches that retry loop:

* HOST (``_resolve_quarantine_model_config``, ``comms_mcp.daemon_runtime``): SYNCHRONOUS,
  PRE-spawn, so the child is never spawned on a bad budget. Mirrors the
  :class:`QuarantineProviderKeyUnsetError` §20.2 PRIMARY refuse-boot.
* CHILD (``_build_provider``, ``security.quarantine_child.__main__``): the §20.2 SECONDARY
  refuse-boot (defence-in-depth) — raises :class:`QuarantineChildBootError` at boot, so the
  request loop that calls :func:`dispatch_extraction` is never entered.

The runtime-order proof that the child guard fires AFTER ``emit_hello`` and BEFORE ``ready``
(so the loop is never reached) lives in ``test_quarantine_child_boot_ordering.py`` alongside
the sibling empty-key refuse-boot proof.
"""

from __future__ import annotations

import pytest
import structlog.testing

import alfred.comms_mcp.daemon_runtime as daemon_runtime_mod
from alfred.comms_mcp.daemon_runtime import (
    QuarantineMaxTokensInvalidError,
    _resolve_quarantine_model_config,
)
from alfred.errors import AlfredError
from alfred.security.quarantine_child import __main__ as child_main
from alfred.security.quarantine_child.brokered_egress import (
    QuarantineChildBootError,
    _ProviderFactory,
)

# --------------------------------------------------------------------------- #
# HOST boundary — _resolve_quarantine_model_config (pre-spawn refuse-boot).
# --------------------------------------------------------------------------- #


def test_host_resolve_returns_model_and_budget_when_positive() -> None:
    """A positive budget resolves to ``(model, max_tokens)`` unchanged (the production path)."""
    model, max_tokens = _resolve_quarantine_model_config()
    assert model == daemon_runtime_mod._QUARANTINE_MODEL
    assert max_tokens == daemon_runtime_mod._QUARANTINE_MAX_TOKENS_PER_EXTRACTION
    assert max_tokens > 0  # the shipped constant is well above the floor


@pytest.mark.parametrize("bad", [0, -1, -8192])
def test_host_resolve_refuses_nonpositive_budget(monkeypatch: pytest.MonkeyPatch, bad: int) -> None:
    """A <=0 budget raises the loud refuse-boot error BEFORE the spawn (never cannot_extract)."""
    monkeypatch.setattr(daemon_runtime_mod, "_QUARANTINE_MAX_TOKENS_PER_EXTRACTION", bad)
    with pytest.raises(QuarantineMaxTokensInvalidError):
        _resolve_quarantine_model_config()


def test_host_refuse_error_is_alfred_error() -> None:
    """The refuse is an :class:`AlfredError` so the CLI boot except arm catches it (exit 2)."""
    assert issubclass(QuarantineMaxTokensInvalidError, AlfredError)


def test_host_refuse_names_the_bad_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """The error text carries the offending budget — non-secret routing config, actionable."""
    monkeypatch.setattr(daemon_runtime_mod, "_QUARANTINE_MAX_TOKENS_PER_EXTRACTION", 0)
    with pytest.raises(QuarantineMaxTokensInvalidError) as exc_info:
        _resolve_quarantine_model_config()
    assert "0" in str(exc_info.value)


def test_host_refuse_logs_loud_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The refuse emits a LOUD (error-level) structlog event before raising.

    Uses ``structlog.testing.capture_logs`` (not pytest ``caplog``) because the module
    logs via structlog, which does not route through stdlib logging here.
    """
    monkeypatch.setattr(daemon_runtime_mod, "_QUARANTINE_MAX_TOKENS_PER_EXTRACTION", -5)
    with (
        structlog.testing.capture_logs() as captured,
        pytest.raises(QuarantineMaxTokensInvalidError),
    ):
        _resolve_quarantine_model_config()
    assert any(
        entry.get("event") == "comms.daemon_runtime.quarantine_max_tokens_invalid"
        and entry.get("log_level") == "error"
        for entry in captured
    ), captured


# --------------------------------------------------------------------------- #
# CHILD boundary — _build_provider (secondary refuse-boot, defence-in-depth).
# --------------------------------------------------------------------------- #


def test_child_build_provider_returns_factory_when_positive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A positive spawn-env budget builds a real ``_ProviderFactory`` (no socket, no network)."""
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-test-model")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    factory = child_main._build_provider("sk-quarantine-key")
    assert isinstance(factory, _ProviderFactory)
    assert factory.max_tokens == 8192


@pytest.mark.parametrize("bad", ["0", "-1", "-8192"])
def test_child_build_provider_refuses_nonpositive_budget(
    monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    """A <=0 spawn-env budget raises :class:`QuarantineChildBootError` at boot (not cannot_extract).

    The guard fires with a NON-empty key, proving the budget check is INDEPENDENT of the
    empty-key guard: a real key + a bad budget still refuses boot before any provider call.
    """
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-test-model")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", bad)
    with pytest.raises(QuarantineChildBootError):
        child_main._build_provider("sk-quarantine-key")


def test_child_build_provider_error_names_the_bad_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The child boot-refuse names the offending budget — host-set routing config, non-secret."""
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-test-model")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "0")
    with pytest.raises(QuarantineChildBootError) as exc_info:
        child_main._build_provider("sk-quarantine-key")
    assert "0" in str(exc_info.value)

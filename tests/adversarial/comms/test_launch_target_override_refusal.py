"""G6-7-7 launch-target override refusal adversarial test (RELEASE-BLOCKING, #309).

Spec B G6-7-7 (#309). The launch-target override (Task 1) is a TEST-ONLY redirect
that lets a docker-only e2e (Task 4) point an adapter at a probe child. The hard
security property: a constructor-injected ``override_map`` is honored ONLY in a
``{"development", "test"}`` environment and is a FAIL-CLOSED / default-DENY refusal
anywhere else — so a probe redirect can NEVER take effect on a production (or
unknown / unset / staging) gateway. This is the negative half of that seam, driven
end-to-end through a REAL :class:`GatewayAdapterSupervisor` + a REAL
:class:`GatewayAdapterChildFactory`.

The concrete required gate is the discrete ``Comms ... adversarial`` step in the
REQUIRED ``python`` job of ``.github/workflows/ci.yml``
(``uv run pytest tests/adversarial/comms``) — the #245 paper-gate lesson: the
env-allowlist refusal property must hold on the required NON-ROOT gate, in-process,
not only on the privileged Linux lane. No bwrap, no launcher, no real credential is
spawned here — the refusal fires in :func:`_resolve_launch_target` BEFORE any spawn.

What this proves, parametrized over ``ALFRED_ENVIRONMENT`` ∈
{``production``, ``staging``, ``""`` (empty), unset, ``"unknown"``} — every value
that resolves OUTSIDE the ``{"development", "test"}`` allowlist:

* the REAL factory's :func:`_resolve_launch_target` raises
  :class:`LaunchTargetOverrideRefusedError`, which IS a
  :class:`GatewayAdapterSpawnError` (the load-bearing subclass relation — the
  supervisor's ``except (GatewayAdapterSpawnError, AdapterCredentialError)`` arm at
  ``adapter_supervisor.py:483`` catches it);
* the SUPERVISOR audits it: the override refusal is NOT an ``AdapterCredentialError``,
  so it takes the ``else: spawn_error = exc`` branch (``:504``) →
  ``_apply(HANDSHAKE_FAILED, error_class=type(spawn_error).__name__,
  detail=str(spawn_error))`` (``:507``) → ``EMIT_CRASHED`` →
  :meth:`AdapterStatusEmitter.emit_crashed` — a ``gateway.adapter.crashed`` frame with
  ``error_class="LaunchTargetOverrideRefusedError"`` and a CONTENT-FREE ``detail``;
* NO probe is spawned — the refusal precedes ``_spawn_in_fd3_window`` and the
  ``runner_factory``, so the injected spy ``popen_factory`` (and ``runner_factory``)
  are NEVER invoked;
* CANARY ABSENCE (sec-003): a high-entropy canary embedded in the rejected override
  TARGET MODULE appears in NO emitted status frame, NO captured structlog line, and
  NOT in ``str(exc)`` / ``exc.args`` — mirroring the value-sentinel sweep in
  ``test_gateway_credential_corpus.py::test_b_value_sentinel_appears_only_on_the_fd3_sink``.

NO module-level ``pytest.mark.asyncio``: ``asyncio_mode = "auto"`` (pyproject.toml)
already collects every ``async def test_*`` as an asyncio test (mirrors
``test_gateway_credential_corpus.py``).
"""

from __future__ import annotations

import secrets

import pytest
import structlog.testing

from alfred.gateway.adapter_child_factory import (
    GatewayAdapterChildFactory,
    LaunchTargetOverrideRefusedError,
)
from alfred.gateway.adapter_status_emitter import AdapterStatusEmitter
from alfred.gateway.adapter_supervisor import (
    GatewayAdapterSpawnError,
    GatewayAdapterSupervisor,
)

# A HIGH-ENTROPY canary embedded in the override TARGET module string. If the refusal
# path ever interpolated the rejected module into an audit row / log / exception, this
# 32-hex token would surface in the sweep below. Generated per process run so a literal
# match anywhere is unambiguous (no incidental collision with fixture text).
_CANARY: str = secrets.token_hex(16)
_OVERRIDE_MODULE: str = f"alfred.gateway.discord_probe_CANARY_{_CANARY}"
_OVERRIDE_PLUGIN_ID: str = "alfred.discord_probe"
_ADAPTER_ID: str = "discord"
_EPOCH: str = "0123456789abcdef0123456789abcdef"

# Every value that resolves OUTSIDE the ``{"development", "test"}`` allowlist. The
# ``None`` sentinel means "ALFRED_ENVIRONMENT unset" (delenv). ``"staging"``, ``""`` and
# ``"unknown"`` all resolve to ``EnvironmentLoadResult.value is None`` (unrecognised /
# empty); ``"production"`` resolves to ``"production"`` — none is allowlisted.
_REFUSED_ENVIRONMENTS: list[str | None] = ["production", "staging", "", None, "unknown"]


class _RecordingEmitterSink:
    """Records every ``(method, params)`` the emitter writes (the status sink seam)."""

    def __init__(self) -> None:
        self.frames: list[tuple[str, dict[str, object]]] = []

    async def emit(self, method: str, params: dict[str, object]) -> None:
        self.frames.append((method, params))

    def methods(self) -> list[str]:
        return [m for m, _ in self.frames]


class _NeverInvokedPopen:
    """A spy ``popen_factory`` that fails LOUDLY if the spawn window is ever entered.

    The override refusal fires in :func:`_resolve_launch_target`, which runs BEFORE
    :meth:`GatewayAdapterChildFactory._spawn_in_fd3_window` (the only caller of
    ``popen_factory``). A single invocation means a probe child was about to be forked
    despite the refusal — the exact security regression this test guards.
    """

    def __init__(self) -> None:
        self.calls: int = 0

    def __call__(self, *args: object, **kwargs: object) -> object:  # pragma: no cover
        self.calls += 1
        raise AssertionError(
            "popen_factory invoked: a probe child was spawned despite the override refusal"
        )


def _never_invoked_runner_factory(**_kwargs: object) -> object:  # pragma: no cover
    """A ``runner_factory`` that fails LOUDLY if a runner is ever built.

    The refusal precedes the runner build (``adapter_child_factory.py:423``), so this
    must never run — a call means the spawn proceeded past the refusal.
    """
    raise AssertionError("runner_factory invoked: the spawn proceeded past the override refusal")


class _UnusedCredentialClient:
    """The at-spawn credential acquirer — never reached (the refusal precedes delivery)."""

    async def acquire_and_deliver(  # pragma: no cover
        self, *, adapter_id: str, host_restart_seq: int, write_fd: int, epoch: str
    ) -> None:
        raise AssertionError("acquire_and_deliver invoked: refusal should precede delivery")


async def _instant_sleep(_seconds: float) -> None:  # pragma: no cover
    """A no-op sleep seam (a first-attempt refusal re-raises before any backoff)."""


def _set_environment(monkeypatch: pytest.MonkeyPatch, environment: str | None) -> None:
    """Set the REAL ``ALFRED_ENVIRONMENT`` for one case (drive the real env read).

    Adversarial discipline: this drives the REAL :func:`load_environment` read inside
    :func:`_resolve_launch_target` — we do NOT patch the env gate to "always refuse".
    ``None`` deletes the var (the unset case).
    """
    if environment is None:
        monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    else:
        monkeypatch.setenv("ALFRED_ENVIRONMENT", environment)


@pytest.mark.parametrize("environment", _REFUSED_ENVIRONMENTS)
async def test_override_refused_outside_allowlist_supervisor_audits_no_spawn_no_leak(
    environment: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Override refuses + supervisor audits + no probe spawned + canary never leaks.

    Drives a REAL supervisor whose REAL factory carries a canary-bearing override under
    a non-allowlisted environment. Asserts the four security properties end-to-end.
    """
    _set_environment(monkeypatch, environment)

    spy_popen = _NeverInvokedPopen()
    factory = GatewayAdapterChildFactory(
        runner_factory=_never_invoked_runner_factory,  # type: ignore[arg-type]
        popen_factory=spy_popen,  # type: ignore[arg-type]
        override_map={_ADAPTER_ID: (_OVERRIDE_PLUGIN_ID, _OVERRIDE_MODULE)},
    )

    class _Seam:
        async def is_available(self, *, adapter_id: str) -> bool:
            return True

    sink = _RecordingEmitterSink()
    supervisor = GatewayAdapterSupervisor(
        child_factory=factory,
        cred_seam=_Seam(),
        credential_client=_UnusedCredentialClient(),
        emitter=AdapterStatusEmitter(sink=sink),
        epoch_source=lambda: _EPOCH,
        sleep=_instant_sleep,
    )

    # 1. The first-attempt spawn surfaces the refusal LOUD (fail-closed boot refusal).
    #    structlog.testing.capture_logs() sweeps every log line the path emits.
    with (
        structlog.testing.capture_logs() as logs,
        pytest.raises(GatewayAdapterSpawnError) as excinfo,
    ):
        await supervisor.supervise_one(_ADAPTER_ID)

    exc = excinfo.value
    # The subclass relation is load-bearing — the supervisor's spawn-error arm catches
    # GatewayAdapterSpawnError, and the factory raises the LaunchTargetOverrideRefusedError
    # subclass.
    assert isinstance(exc, LaunchTargetOverrideRefusedError)
    assert isinstance(exc, GatewayAdapterSpawnError)

    # 2. The SUPERVISOR audited the refusal: a content-free ``crashed`` frame with the
    #    refusal's class name (the ``else: spawn_error = exc`` arm → EMIT_CRASHED).
    crashed = [params for method, params in sink.frames if method == "gateway.adapter.crashed"]
    assert len(crashed) == 1, sink.methods()
    crash_frame = crashed[0]
    assert crash_frame["error_class"] == "LaunchTargetOverrideRefusedError"
    assert crash_frame["adapter_id"] == _ADAPTER_ID
    # Content-free detail: it carries adapter_id / env / allowlist text but NEVER the
    # rejected override module string (proven by the canary sweep below). NO ``up`` was
    # ever emitted (the refusal precedes the handshake).
    assert "gateway.adapter.up" not in sink.methods()

    # 3. NO probe was spawned: the refusal precedes ``_spawn_in_fd3_window`` and the
    #    ``runner_factory`` (both spies raise AssertionError if invoked).
    assert spy_popen.calls == 0

    # 4. CANARY ABSENCE (sec-003) — the high-entropy module canary appears NOWHERE:
    #    not in any emitted status frame, not in any captured structlog line, and not
    #    in the exception's str / args.
    assert _CANARY not in repr(sink.frames)
    assert _CANARY not in repr(logs)
    assert _CANARY not in str(exc)
    assert _CANARY not in repr(exc.args)
    # Defensive belt-and-braces: the full override module string is equally absent.
    assert _OVERRIDE_MODULE not in repr(sink.frames)
    assert _OVERRIDE_MODULE not in repr(logs)
    assert _OVERRIDE_MODULE not in str(exc)

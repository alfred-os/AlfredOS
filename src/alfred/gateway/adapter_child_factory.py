"""``GatewayAdapterChildFactory`` — the real bwrap adapter-child factory (G6-5 Task 4).

Spec B G6-5 (#288), the keystone trust-boundary unit. The gateway's real
:class:`alfred.gateway.adapter_supervisor._AdapterChildFactoryLike`: it spawns one
comms-adapter child through the bwrap launcher, delivers the platform credential over
LITERAL fd 3, runs the comms handshake, and returns an
:class:`alfred.gateway.adapter_supervisor._AdapterChildLike` whose ``wait_until_exit``
the supervisor races against a planned stop.

**The spawn sequence (GAP-2 / H1 / M3).**

1. ``os.pipe()`` — the read-end becomes the child's literal fd 3, the write-end stays
   in the parent for the supervisor's :class:`_DeliverCredential` hook.
2. The COPIED fd-3-clobber window (verbatim from
   :func:`alfred.security.quarantine_child_io.spawn_quarantine_child_io`, per the
   GAP-2 ruling — COPY not factor, so the most-adversary-facing merged module + its
   per-file 100% gate stay untouched): ``os.dup2(read_fd, 3)`` opens the window,
   a SYNCHRONOUS :class:`subprocess.Popen` (``pass_fds=(3,)``) forks the child WITHOUT
   driving the event loop, and the ``finally`` restores the parent's prior fd 3 and
   drops the read-end (window CLOSES). There is ZERO ``await`` inside the window — the
   loop's epoll/kqueue selector fd is commonly fd 3, so an ``await`` here would poll a
   clobbered selector -> ``OSError: [Errno 22]``. A shared property test pins this.
3. AFTER the window closes / BEFORE the handshake: ``await deliver_credential(write_fd)``.
   The factory NEVER touches the credential (L3) — the supervisor's hook (the
   :class:`alfred.gateway.adapter_credential_client.GatewayAdapterCredentialClient`)
   owns the round-trip + the atomic ``writev`` + zeroing + closing ``write_fd``.
4. Wrap the live ``Popen`` in :class:`GatewayAdapterStdioTransport` (no-op ``spawn``),
   build a :class:`alfred.plugins.comms_runner.CommsPluginRunner`, and
   ``await runner.start_and_handshake()`` (its ``spawn()`` no-ops; the handshake runs).
5. Return a :class:`_GatewayAdapterChild` whose ``wait_until_exit`` blocks via
   ``run_in_executor(None, proc.wait)`` (cancellation-safe — the executor wait keeps
   running on cancel; the child reaps on its OWN ``aclose`` teardown, not the cancelled
   task) and maps the exit to ``(error_class, detail)``.

**Error contract (the supervisor's implementer contract).** A
:class:`alfred.gateway.core_link.CredentialLegDownError` or an
:class:`alfred.comms_mcp.adapter_credential_resolver.AdapterCredentialError` raised by
the hook propagates UNWRAPPED — re-wrapping either as
:class:`alfred.gateway.adapter_supervisor.GatewayAdapterSpawnError` would defeat the
supervisor's AWAITING_CORE arm. Only a GENUINE spawn / handshake fault (launcher Popen
fault, handshake failure) raises ``GatewayAdapterSpawnError`` — and ALWAYS after the
half-spawned child is ``_terminate_and_reap``-ed (H1a), else it wedges on ``os.read(3)``.

**Payload-blind + never-log-secret (CLAUDE.md hard rules #5/#6).** The factory parses
no payload and logs no credential or body — it never even sees the credential (it only
creates the pipe + invokes the hook). The scrubbed allowlist env (never
``dict(os.environ)``) keeps an operator's exported ``DISCORD_BOT_TOKEN`` /
``ANTHROPIC_API_KEY`` out of the adversary-facing ``kind="full"`` child.

**Session/runner construction stays the daemon's (the boot graph owns it).** The real
:class:`CommsPluginRunner` needs a full :class:`AlfredPluginSession` + handlers (the
inbound/binding/crash/rate-limit handlers + the credential resolver), which are
daemon-boot-graph dependencies. So the factory takes a ``runner_factory`` closure that
builds the session-bearing runner over the transport; the factory itself stays free of
the boot graph (Task 5 wires the real closure into :mod:`alfred.gateway.process`).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import subprocess
import sys
from typing import TYPE_CHECKING, Final, Protocol

import structlog

from alfred.config._environment_loader import EnvironmentSource, resolve_environment
from alfred.gateway.adapter_stdio_transport import GatewayAdapterStdioTransport
from alfred.gateway.adapter_supervisor import (
    GatewayAdapterSpawnError,
    _AdapterChildLike,
    _DeliverCredential,
)
from alfred.i18n import t
from alfred.plugins._comms_child_env import _scrubbed_base

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

log = structlog.get_logger(__name__)

# The environment SOURCES trusted to honor a launch-target override (#469 Blocker-1).
# A ``.env`` file is the lowest, gap-fill-only layer of ``resolve_environment`` and is
# writable by anything with repo/CWD access — an operator's stray dev ``.env`` (or a
# hostile one dropped by a compromised dependency) must NEVER unlock the override on a
# production gateway merely by shadowing the value. Only a source with an explicit,
# operator-controlled trust boundary (the process's own env var, or the root-owned
# ``/etc`` file) may honor the override, even when the resolved VALUE is a legitimate
# ``development``/``test`` string.
_OVERRIDE_TRUSTED_SOURCES: Final[frozenset[EnvironmentSource]] = frozenset(
    {EnvironmentSource.ENV_VAR, EnvironmentSource.ETC_FILE}
)

# The environments in which a constructor-injected launch-target override is honored
# (Spec B G6-7-7 / #309). Anywhere else an injected override is a fail-closed refusal —
# default-DENY so a probe redirect can NEVER take effect on a production gateway.
_OVERRIDE_ALLOWED_ENVIRONMENTS: Final[frozenset[str]] = frozenset({"development", "test"})

# The default adapter_id -> (launcher plugin id, ``python -m`` module) map. An id
# outside this set is a fail-closed spawn refusal (no dynamic manifest lookup — the
# gateway hosts a fixed, audited set of first-party adapters). ``plugin_id`` matches
# the manifest ``[plugin] id`` so the launcher resolves the ``kind="full"`` sandbox
# policy; ``module`` is the ``python -m`` entrypoint (``plugins/alfred_discord/server.py``
# has the ``__main__`` block + wires the fd-3 ``Fd3TokenSource`` into ``DiscordLifecycle``).
#
# Spec B G6-7-7 (#309) de-stale: this map is no longer STRICTLY fixed. A TEST-ONLY,
# constructor-injected ``override_map`` (resolved by :func:`_resolve_launch_target`) can
# redirect an entry to a probe target — but ONLY in a development/test environment
# resolved from a TRUSTED source (``_OVERRIDE_TRUSTED_SOURCES`` above — the process's
# own env var or the root-owned ``/etc`` file; #469 Blocker-1 ADR-0053). A ``.env``-sourced
# ``development``/``test`` value does NOT satisfy this gate. Outside that allowlist an
# injected override is a fail-closed refusal, so a probe redirect can never take effect
# on a production gateway; production with no override resolves this map exactly as before.
_ADAPTER_LAUNCH_TARGETS: Final[Mapping[str, tuple[str, str]]] = {
    "discord": ("alfred.discord", "plugins.alfred_discord.server"),
}


class LaunchTargetOverrideRefusedError(GatewayAdapterSpawnError):
    """A launch-target override was injected outside a development/test environment.

    Spec B G6-7-7 (#309), FAIL-CLOSED / default-DENY. The override map is honored ONLY
    in ``{"development", "test"}`` **and only when that value came from a trusted
    source** (:data:`_OVERRIDE_TRUSTED_SOURCES` — the ``ALFRED_ENVIRONMENT`` env var
    or the root-owned ``/etc`` file; #469 Blocker-1 ADR-0053). An injected override
    anywhere else (incl. ``production``, ``staging``, an unset / unrecognised
    environment, OR a ``.env``-sourced ``development``/``test`` value — ``.env`` is the
    lowest, CWD-writable layer and can never satisfy this gate) is this loud
    refusal. It MUST subclass :class:`GatewayAdapterSpawnError` (load-bearing): the
    supervisor's spawn-error arm catches ``GatewayAdapterSpawnError`` and audits it via
    ``_apply(HANDSHAKE_FAILED, error_class=type(spawn_error).__name__,
    detail=str(spawn_error))`` — the factory itself owns no audit writer.

    CONTENT-FREE (sec-003/sec-101): ``str(...)`` flows verbatim into that audit row, so
    the message carries ONLY the ``adapter_id``, the active environment string, and the
    allowlist — NEVER the rejected override module string (which would be a canary leak
    into the audit log).
    """


def _resolve_launch_target(
    adapter_id: str,
    *,
    override_map: Mapping[str, tuple[str, str]] | None,
    etc_path: Path | None = None,
) -> tuple[str, str]:
    """Resolve ``adapter_id`` to its ``(plugin_id, module)`` launch target.

    Spec B G6-7-7 (#309) + #469 Blocker-1 trust-floor. Two paths:

    * ``override_map is None`` (production / no override injected) — the pre-G6-7-7
      behaviour, byte-for-byte: return :data:`_ADAPTER_LAUNCH_TARGETS`\\ ``[adapter_id]``
      if present, else raise the SAME closed-static-map :class:`GatewayAdapterSpawnError`.
      The environment is NOT read on this path (no override means no gate to apply).
    * ``override_map is not None`` (an override was injected) — read the active
      environment via :func:`resolve_environment`. The override is honored ONLY when
      BOTH hold: the resolved value is in ``{"development", "test"}`` AND its
      ``source`` is trusted (:data:`_OVERRIDE_TRUSTED_SOURCES` — the process's own
      ``ALFRED_ENVIRONMENT`` env var or the root-owned ``/etc`` file). A ``.env``-sourced
      ``development``/``test`` value does NOT satisfy the gate (#469 Blocker-1): ``.env``
      is the lowest, gap-fill-only, CWD-writable layer, so honoring it would let a stray
      or hostile CWD ``.env`` unlock the override on a production gateway. When honored
      and ``adapter_id`` is in the override map, return its probe target; if it is not,
      FALL THROUGH to the production default (the override only redirects ids it names).
      Any other outcome (value outside the allowlist, OR an untrusted source, incl.
      ``production``, ``staging``, unset / unrecognised, or a ``.env``-sourced dev value)
      raises :class:`LaunchTargetOverrideRefusedError` — FAIL-CLOSED / default-DENY.

    ``etc_path`` is a seam threaded straight to :func:`resolve_environment` so tests can
    point the ``/etc`` layer at a ``tmp_path`` without touching a real
    ``/etc/alfred/environment``; ``None`` (the default) reads the real file.
    """
    if override_map is None:
        return _production_launch_target(adapter_id)

    resolved = resolve_environment(etc_path=etc_path)
    environment = resolved.value
    honor = (
        environment in _OVERRIDE_ALLOWED_ENVIRONMENTS
        and resolved.source in _OVERRIDE_TRUSTED_SOURCES
    )
    if not honor:
        # FAIL-CLOSED: an override was injected but either the resolved value is not
        # allowlisted, or it came from an untrusted source (``.env``) — #469 Blocker-1.
        # The message is CONTENT-FREE — built from a ``t()`` callsite with kwargs (not
        # f-string interpolation, i18n-001) — and carries NO override module string
        # (sec-003/sec-101): it lands verbatim in the supervisor audit row.
        allowed = ", ".join(sorted(_OVERRIDE_ALLOWED_ENVIRONMENTS))
        raise LaunchTargetOverrideRefusedError(
            t(
                "gateway.adapter.launch_target.override_refused",
                adapter_id=adapter_id,
                environment="" if environment is None else environment,
                allowed=allowed,
            )
        )

    override = override_map.get(adapter_id)
    if override is not None:
        return override
    # Allowlisted env, but this id is not in the override map — production default.
    return _production_launch_target(adapter_id)


def _production_launch_target(adapter_id: str) -> tuple[str, str]:
    """Return the production launch target for ``adapter_id`` or raise the closed-map error.

    The pre-G6-7-7 lookup, factored out so both the no-override path and the
    allowlisted-but-not-in-override-map fall-through share one closed-static-map refusal.
    """
    target = _ADAPTER_LAUNCH_TARGETS.get(adapter_id)
    if target is None:
        raise GatewayAdapterSpawnError(
            f"no launch target for adapter_id={adapter_id!r} (closed static map)"
        )
    return target


# The literal fd the credential is delivered over (ADR-0015 #218). The child reads
# ``os.read(3)`` directly — a hard-coded convention, not an env-named fd.
_CREDENTIAL_FD: Final[int] = 3

# The default exit ``error_class`` the supervisor's crash arm stamps when the child
# process exits without a more specific signal (mirrors the supervisor's own default).
_CHILD_EXITED_ERROR_CLASS: Final[str] = "AdapterChildExited"


class _RunnerLike(Protocol):
    """The session-bearing runner the factory drives over the spawned child.

    Satisfied by :class:`alfred.plugins.comms_runner.CommsPluginRunner` (and the
    gateway's :class:`alfred.gateway.inbound_forward_runner.GatewayInboundForwardRunner`).
    The factory ``await``s ``start_and_handshake`` to bring the child to ``up``; the
    steady-state ``pump`` is driven by the SUPERVISED child lifetime
    (:meth:`_GatewayAdapterChild.wait_until_exit`), NOT the factory — but the runner MUST
    expose it so the supervised lifetime can own the pump (Spec B G6-7-3 / #309: without
    a driven pump a hosted child's ``inbound.message`` reaches nothing — the
    production-unwired trap).
    """

    async def start_and_handshake(self) -> None: ...

    async def pump(self) -> None: ...


def _launcher_path() -> str:
    """Resolve the bwrap launcher path (env override, else the in-tree script).

    Mirrors :func:`alfred.security.quarantine_child_io._launcher_path` — the gateway is
    a SECOND bwrap-launcher host (ADR-0015 annotation). The repo root is three parents
    up from ``src/alfred/gateway/``.
    """
    from pathlib import Path

    default = Path(__file__).resolve().parents[3] / "bin" / "alfred-plugin-launcher.sh"
    return os.environ.get("ALFRED_PLUGIN_LAUNCHER", str(default))


def _child_python() -> str:
    """Resolve the bwrap exec interpreter (ADR-0030 bound-interpreter contract).

    Production leaves ``ALFRED_GATEWAY_ADAPTER_CHILD_PYTHON`` unset -> ``sys.executable``
    (the gateway runs under the pip-installed /usr CPython covered by the policy's /usr
    ro-bind). Dev/CI overrides to a real interpreter binary under a bound prefix (a
    uv-venv ``sys.executable`` is a symlink outside any bound path and would fail
    ``execvp`` under bwrap), mirroring :func:`quarantine_child_io._child_python`.
    """
    return os.environ.get("ALFRED_GATEWAY_ADAPTER_CHILD_PYTHON", sys.executable)


def _child_env() -> dict[str, str]:
    """Build the SCRUBBED adapter child env (allowlist only — never ``dict(os.environ)``).

    The adapter child is adversary-facing (``kind="full"``); it gets the scrubbed
    allowlist (:func:`alfred.plugins._comms_child_env._scrubbed_base`) — which already
    forwards ``ALFRED_ENVIRONMENT`` (the launcher refuses ``environment_not_set``) and
    the locale/PATH the interpreter needs — plus the opt-in interpreter-prefix bind flag
    so the launcher ro-binds the bound interpreter's install prefix into the sandbox
    (ADR-0030; generic /usr-interpreter plugins never set it, so the launcher never
    widens their namespace). NO secret-bearing key is on the allowlist — the credential
    crosses ONLY over fd 3 (CLAUDE.md hard rule #6).
    """
    env = _scrubbed_base()
    env["ALFRED_SANDBOX_BIND_INTERP_PREFIX"] = "1"
    return env


async def _terminate_and_reap(process: subprocess.Popen[bytes]) -> None:
    """SIGTERM the child + await its exit off-loop (best-effort, never raises).

    The same terminate-on-fail discipline as
    :func:`alfred.security.quarantine_child_io._terminate_and_reap`: a half-spawned
    child blocks on ``os.read(3)`` until the credential arrives, so a pre-handshake
    fault MUST reap it before the loud raise (H1a) — else it wedges. ``Popen.wait``
    blocks, so it runs in an executor; every fault is suppressed (we are tearing down).
    """
    if process.returncode is None and process.poll() is None:
        with contextlib.suppress(ProcessLookupError, OSError):
            process.terminate()
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, process.wait)
    except Exception as exc:
        # Best-effort teardown (never raises), but LOUD not silent (#414, hard
        # rule #7): a reap gone wrong surfaces its error class instead of
        # vanishing. Mirrors the security-child sibling
        # (``security.quarantine_child.reap_failed``) + ``gateway.adapter.spawn_failed``.
        # ``except Exception`` (not ``BaseException``) so cooperative cancellation
        # still propagates; the emit is ``suppress``-wrapped so a structlog-emit
        # failure during teardown cannot escape either.
        with contextlib.suppress(Exception):
            log.warning("gateway.adapter.reap_failed", error_class=type(exc).__name__)


class _GatewayAdapterChild:
    """A spawned + handshaked adapter child the supervisor awaits + reaps (H1 b/c).

    Wraps the live :class:`subprocess.Popen` + its :class:`GatewayAdapterStdioTransport`
    + the :class:`_RunnerLike` (Spec B G6-7-3 / #309). :meth:`wait_until_exit` DRIVES the
    runner's pump (the supervised steady state) until the child's stdout reaches EOF
    (the child exiting), THEN reaps the process exit code off-loop; :meth:`aclose` is the
    supervisor's restart/crash/shutdown teardown — it terminates + reaps the Popen and
    closes the transport pipes (idempotent).
    """

    def __init__(
        self,
        *,
        process: subprocess.Popen[bytes],
        transport: GatewayAdapterStdioTransport,
        runner: _RunnerLike,
    ) -> None:
        self._process = process
        self._transport = transport
        # Spec B G6-7-3 (#309): the supervised lifetime OWNS the pump. The factory built
        # the runner + ran its handshake, but in the pre-G6-7-3 factory the runner was
        # DROPPED — so ``pump()`` never ran and a hosted child's ``inbound.message``
        # reached nothing (the production-unwired trap). Holding the runner here and
        # driving its pump in :meth:`wait_until_exit` keeps "the supervised lifetime owns
        # the pump" literally true: the pump returns on the child's stdout EOF (= the
        # child exiting) and a planned-stop cancellation of ``wait_until_exit`` cancels
        # the pump (the runner's ``finally`` closes the transport — cancellation-safe).
        self._runner = runner
        self._closed = False

    async def wait_until_exit(self) -> tuple[str, str]:
        """Drive the pump until the child's stdout EOFs, then reap the exit code.

        The supervised steady state (Spec B G6-7-3 / #309). ``await self._runner.pump()``
        runs the single-reader pump that FORWARDS each ``inbound.message`` to the core; it
        returns when the child's stdout reaches a clean EOF (the child exiting) or on a
        transport crash. THEN the blocking ``Popen.wait`` reaps the exit code in the
        default executor so the loop is never blocked.

        CANCELLATION-SAFE (H1c): if the awaiting task is cancelled (a planned stop), the
        pump's own cancellation-safe teardown closes the transport; the child is reaped via
        :meth:`aclose` on the supervisor's teardown path, NOT the cancelled task. The detail
        is the closed-vocab exit code only (payload-blind, #5); the emitter does the
        REDACT-then-bound.

        PUMP-FAULT REAP (CR-1, Spec B G6-7-3 / #309): the pump's normal terminal arms (EOF /
        crash / malformed / shutdown) all RETURN, so a non-``CancelledError`` exception
        escaping ``pump()`` is the defensive "a bug or an unhandled transport fault escaped"
        case. Were it to propagate, the live Popen child would LEAK (no reap) — violating the
        H1 "no leaked sandbox child" discipline (CLAUDE.md hard rule #7). So we
        :func:`_terminate_and_reap` the child and RETURN a bounded, payload-blind crash tuple
        so the supervisor's crash arm restarts/breakers it instead of an exception escaping
        ``supervise_one``. A ``CancelledError`` still propagates (``aclose`` owns the reap).
        """
        # Drive the pump (forward the child's inbound) until its stdout EOFs / crashes. The
        # pump owns its own transport-close on every terminal arm; we then reap the code.
        try:
            await self._runner.pump()
        except asyncio.CancelledError:
            # A planned-stop cancellation propagates and is reaped via ``aclose`` on the
            # supervisor's teardown path (NOT here — ``aclose`` owns the reap on cancel).
            raise
        except Exception:
            # An UNEXPECTED pump fault (a bug / unhandled transport fault — every normal
            # pump arm RETURNS). Reap the still-live child so it never leaks (H1 / hard
            # rule #7), then return a bounded, payload-blind crash tuple (NEVER the
            # exception text, #5) so the supervisor treats it as a child exit and
            # restarts/breakers it rather than letting the fault escape ``supervise_one``.
            await _terminate_and_reap(self._process)
            return (_CHILD_EXITED_ERROR_CLASS, "exit_code=pump_failed")
        loop = asyncio.get_running_loop()
        returncode = await loop.run_in_executor(None, self._process.wait)
        return (_CHILD_EXITED_ERROR_CLASS, f"exit_code={returncode}")

    async def aclose(self) -> None:
        """Terminate + reap the Popen and close the transport (idempotent — H1b).

        The supervisor's restart/crash/shutdown teardown: reap the child so a
        bwrap process never leaks across a crash-loop, then close the transport pipes
        (clean EOF for any still-live child). A no-op on a second call.
        """
        if self._closed:
            return
        self._closed = True
        await _terminate_and_reap(self._process)
        await self._transport.close()


class GatewayAdapterChildFactory:
    """The real ``_AdapterChildFactoryLike``: bwrap spawn + fd-3 credential + handshake.

    Construct one per gateway process. ``runner_factory`` builds the session-bearing
    :class:`CommsPluginRunner` over the transport (the daemon boot graph supplies it —
    Task 5); ``popen_factory`` is injectable ONLY so the unit tests substitute a
    synchronous fake (production always uses :class:`subprocess.Popen`).

    ``override_map`` (Spec B G6-7-7 / #309) is a TEST-ONLY launch-target redirect: a
    later docker-only e2e (Task 4) injects ``{"discord": (probe_plugin_id, probe_module)}``
    so the forwarded-inbound bridge can be proved against a probe child without touching
    the production Discord adapter. It defaults to ``None`` (production never injects one);
    when injected it is honored ONLY in a development/test environment resolved from a
    TRUSTED source (ADR-0053: the ``ALFRED_ENVIRONMENT`` env var or ``/etc``, never
    ``.env``) and is a fail-closed :class:`LaunchTargetOverrideRefusedError` anywhere else
    (see :func:`_resolve_launch_target`).
    """

    def __init__(
        self,
        *,
        runner_factory: Callable[..., _RunnerLike],
        popen_factory: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        override_map: Mapping[str, tuple[str, str]] | None = None,
    ) -> None:
        self._runner_factory = runner_factory
        self._popen_factory = popen_factory
        self._override_map = override_map

    async def spawn_and_handshake(
        self, *, adapter_id: str, epoch: str, deliver_credential: _DeliverCredential
    ) -> _AdapterChildLike:
        """Spawn the adapter child, deliver its credential over fd 3, run the handshake.

        The sequence (module docstring): resolve the launch target -> COPIED fd-3-clobber
        window (no ``await`` inside) -> restore fd 3 -> ``await deliver_credential(write_fd)``
        (UNWRAPPED credential exceptions) -> wrap the Popen + build the runner ->
        ``await runner.start_and_handshake()`` -> return the child. Any pre-handshake
        fault reaps the child before raising ``GatewayAdapterSpawnError`` (H1a).
        """
        del epoch  # the epoch is bound into the credential round-trip by the hook, not here
        plugin_id, module = _resolve_launch_target(adapter_id, override_map=self._override_map)

        process, write_fd = self._spawn_in_fd3_window(plugin_id=plugin_id, module=module)

        # The credential hook runs AFTER the window closes / BEFORE the handshake. A
        # CredentialLegDownError / AdapterCredentialError propagates UNWRAPPED (the
        # supervisor's AWAITING_CORE arm depends on the distinct type), but the
        # half-spawned child — already blocked on ``os.read(3)`` — MUST be reaped first
        # so it does not wedge (H1a). The hook owns closing ``write_fd``.
        try:
            await deliver_credential(write_fd)
        except BaseException:
            await _terminate_and_reap(process)
            raise

        transport = GatewayAdapterStdioTransport(process=process, adapter_id=adapter_id)
        try:
            # Build the runner INSIDE the reap-wrapped block (H1a / credential-leak fix):
            # the child has ALREADY spawned + received its credential over fd 3 by now, so
            # ANY runner_factory failure — the fail-loud ``_unwired_runner_factory`` default,
            # or a genuine runner-construction fault — must terminate-and-reap the live
            # credentialed child before propagating, exactly like a handshake fault. Were
            # this OUTSIDE the try, a runner_factory raise would leak a running sandbox child
            # holding its delivered credential (CLAUDE.md hard rules #6/#7).
            runner = self._runner_factory(transport=transport, adapter_id=adapter_id)
            await runner.start_and_handshake()
        except GatewayAdapterSpawnError:
            # Already the typed fail-closed error (incl. the unwired-runner default) — reap +
            # re-raise (do not double-wrap).
            await _terminate_and_reap(process)
            raise
        except BaseException as exc:
            # A genuine runner-construction / handshake fault (PluginError, a torn wire,
            # cancellation): reap the child (the runner closed the transport on its own
            # failure path; reaping is idempotent) and raise the typed fail-closed error
            # (H1a). The cause chain is preserved; no payload/credential is carried into the
            # message (#5/#6).
            await _terminate_and_reap(process)
            raise GatewayAdapterSpawnError(
                f"adapter handshake failed (adapter_id={adapter_id!r})"
            ) from exc

        return _GatewayAdapterChild(process=process, transport=transport, runner=runner)

    def _spawn_in_fd3_window(
        self, *, plugin_id: str, module: str
    ) -> tuple[subprocess.Popen[bytes], int]:
        """Run the COPIED synchronous fd-3-clobber spawn window; return ``(proc, write_fd)``.

        GAP-2: this is the ~15-line dup2->Popen->restore discipline copied VERBATIM from
        :func:`alfred.security.quarantine_child_io.spawn_quarantine_child_io` (with the
        identical load-bearing ``[Errno 22]`` / ``pass_fds=(3,)`` / save-restore comments),
        so the most-adversary-facing merged module + its per-file 100% gate stay
        UNTOUCHED. A shared property test pins both windows to the same invariants. A
        Popen ``OSError`` is a fail-closed spawn refusal (no child to reap — none forked).
        """
        read_fd, write_fd = os.pipe()
        os.set_inheritable(read_fd, True)  # noqa: FBT003 - os.set_inheritable bool is positional only

        # Save any prior parent fd 3 so a clobber is reversible, then dup the pipe
        # read-end onto LITERAL fd 3.
        saved_fd3: int | None = None
        with contextlib.suppress(OSError):
            saved_fd3 = os.dup(_CREDENTIAL_FD)
        process: subprocess.Popen[bytes] | None = None
        try:
            # --- fd-3-clobber window OPENS. NO ``await`` until it CLOSES below. ---
            os.dup2(read_fd, _CREDENTIAL_FD)
            argv = [
                _launcher_path(),
                plugin_id,
                _child_python(),
                "-m",
                module,
            ]
            try:
                # SYNCHRONOUS spawn (no ``await``): ``Popen`` forks the child without
                # running the event loop, so the loop never polls its (temporarily
                # clobbered) selector fd. ``os.dup2(read_fd, 3)`` clobbers fd 3
                # PROCESS-WIDE, and the loop's epoll/kqueue selector fd is commonly fd 3;
                # an ``await`` here would poll the loop's OWN dead selector ->
                # ``OSError: [Errno 22] Invalid argument``. The child inherits the dup'd
                # fd 3 at fork via ``pass_fds=(3,)``; ``close_fds`` defaults True and
                # keeps every other inherited fd out of the adversary-facing child.
                process = self._popen_factory(
                    argv,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=_child_env(),
                    pass_fds=(_CREDENTIAL_FD,),
                )
            except OSError as exc:
                log.error("gateway.adapter.spawn_failed", error_class=type(exc).__name__)
                # No child forked — nothing to reap. Close the write end (the hook never
                # runs) before raising so the descriptor does not leak.
                with contextlib.suppress(OSError):
                    os.close(write_fd)
                raise GatewayAdapterSpawnError(
                    f"adapter launcher spawn failed (plugin_id={plugin_id!r})"
                ) from exc
        finally:
            # --- fd-3-clobber window CLOSES (no ``await`` ran above). ---
            # Restore the parent's prior fd 3 (or close the dup we installed) and drop
            # the parent's copy of the read-end — the child has its own via pass_fds.
            if saved_fd3 is not None:
                os.dup2(saved_fd3, _CREDENTIAL_FD)
                os.close(saved_fd3)
            else:
                with contextlib.suppress(OSError):
                    os.close(_CREDENTIAL_FD)
            with contextlib.suppress(OSError):
                os.close(read_fd)

        return process, write_fd


__all__ = [
    "GatewayAdapterChildFactory",
    "LaunchTargetOverrideRefusedError",
    "_GatewayAdapterChild",
]

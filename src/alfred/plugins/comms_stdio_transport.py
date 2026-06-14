"""``CommsStdioTransport`` — line-delimited JSON-RPC pipe to a comms plugin.

PR-S4-11a Wave 1 (#237). The keystone the daemon comms runtime needs: today no
host-side line-delimited comms transport exists, so a plugin -> host
``inbound.message`` notification can never reach ``process_inbound_message``.
This is the dumb duplex pipe that carries those frames.

**Deliberately thin.** Unlike :class:`alfred.plugins.stdio_transport.StdioTransport`
(the length-prefixed orchestrator <-> tool wire that applies DLP, secret
substitution, T3 tagging, and the inbound canary scan), this transport does NONE
of that. The trust-boundary work for comms lives upstream in
``process_inbound_message`` + the ``ScannedOutboundBody`` NewType (ADR-0025
invariant): a comms transport that re-implemented DLP here would create a second,
divergent scan point. Its ONLY security duty is a frame-size bound
(:data:`_MAX_COMMS_LINE_BYTES`, mirroring the stdio transport's DoS bound) and
LOUD failure on a broken or malformed wire (CLAUDE.md hard rule #7).

**Wire shape.** Line-delimited JSON-RPC: one ``json.dumps(frame) + "\\n"`` per
frame in each direction, matching the reference plugin
(``plugins/alfred_comms_test/main.py``) and the ``alfred_web_fetch`` /
``alfred_quarantined_llm`` plugins. This is a DIFFERENT framing + conversation
shape from the length-prefixed :class:`StdioTransport`; the two are not
interchangeable, so the patterns below are mirrored, not reused.

**Minimal surface — no ``request()``.** The runner
(:class:`alfred.plugins.comms_runner.CommsPluginRunner`) does the handshake via
:meth:`send` + :meth:`read_frame`, then owns the single reader for the pump. A
transport-level ``request()`` that also read the stream would be a dual-reader
footgun once the pump owns the reader, so it is deliberately absent.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shlex
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Final

import structlog

from alfred.i18n import t
from alfred.plugins._comms_child_env import comms_child_env

# The per-frame DoS bound + the loud-failure type live in the shared leaf module
# ``comms_wire`` (Spec A G2 / ADR-0032) so the seq/ack codec can import them
# without closing a codec<->transport import cycle (architect F6). Re-exported
# here (kept in ``__all__``) so existing importers see no churn.
from alfred.plugins.comms_seq_codec import (
    SeqFrame,
    decode_seq_frame,
    encode_seq_frame,
)
from alfred.plugins.comms_wire import _MAX_COMMS_LINE_BYTES, CommsProtocolError

if TYPE_CHECKING:
    from alfred.cli._launcher_spawn import PluginLaunchSpec

#: Override for the launcher path (tests + bespoke deployments point this
#: elsewhere). Matches :data:`alfred.cli._launcher_spawn._LAUNCHER_ENV_VAR` so a
#: single env var drives both the foreground and daemon launch surfaces.
_LAUNCHER_ENV_VAR: Final[str] = "ALFRED_PLUGIN_LAUNCHER"


def _repo_root() -> Path:
    """Resolve the in-tree repo root that ships ``bin/`` and ``plugins/``.

    This module lives at ``src/alfred/plugins/`` so the repo root is three
    parents up. Mirrors :func:`alfred.cli._launcher_spawn.repo_root`; resolved
    here (not imported) so the ``plugins`` package never imports the ``cli``
    package — ``cli._launcher_spawn`` already imports ``plugins._comms_child_env``,
    and a back-import would close an import cycle.
    """
    return Path(__file__).resolve().parents[3]


def _comms_launcher_path() -> str:
    return os.environ.get(
        _LAUNCHER_ENV_VAR, str(_repo_root() / "bin" / "alfred-plugin-launcher.sh")
    )


log = structlog.get_logger(__name__)

# close()-cooperative-wait timeout in seconds. Past this the transport escalates
# terminate() -> kill(). Matches :data:`StdioTransport._CLOSE_TIMEOUT_S`.
_CLOSE_TIMEOUT_S: Final[float] = 5.0


class CommsStdioTransport:
    """A line-delimited JSON-RPC duplex pipe to a comms-plugin subprocess.

    The transport owns ``self._proc`` after :meth:`spawn`. It is NOT a state
    machine beyond the spawned/closed guard — the conversation sequencing (handshake
    then single-reader pump) is the runner's job.
    """

    def __init__(
        self,
        *,
        adapter_id: str,
        spec: PluginLaunchSpec,
        max_line_bytes: int = _MAX_COMMS_LINE_BYTES,
    ) -> None:
        self._adapter_id = adapter_id
        self._spec = spec
        self._max_line_bytes = max_line_bytes
        self._proc: asyncio.subprocess.Process | None = None
        # Spec A G2 (#237): out-of-band seq/ack framing, OFF by default. The
        # runner flips this ON (via enable_seq_ack) only when BOTH peers
        # advertised support at the lifecycle.start handshake (version-gate).
        # When OFF the wire is byte-for-byte the existing ADR-0025 plain frame.
        self._seq_ack_enabled = False
        self._send_seq = 0  # this transport's per-direction monotonic send seq
        # Spec A G3-2 (#237) C2 — DEFENSIVE symmetry with the socket sibling: there
        # is no second writer on the stdio carrier in G3-2 (the daemon-spawned
        # adapters never carry the lifecycle-send — only the socket carrier is
        # registered with the broadcaster), so the lock is uncontended here. It
        # future-proofs Spec B and keeps the two transports' send contract identical.
        # Spans encode -> write -> drain -> seq-increment; the reader never takes it.
        self._send_lock = asyncio.Lock()
        # NOTE: the transport emits ``a=0`` as a PLACEHOLDER ack. It deliberately
        # does NOT track a received-seq high-water: a ``max(seq seen)`` ack would
        # falsely ack past gaps, contradicting the CONTIGUOUS-ack semantics
        # (ADR-0032 Decision 3). The real contiguous ack is computed by the pure
        # ``SeqDedupWindow.cumulative_ack()`` and wired as the ack source by the
        # G3 relay. G2's transport carries a placeholder; it consumes no ack.

    def enable_seq_ack(self) -> None:
        """Turn the out-of-band seq/ack header ON (post-handshake, version-gated).

        Idempotent flip the runner calls once the ``lifecycle.start`` negotiation
        confirmed BOTH peers speak ``AlfredSeqAck/1``. Until then the transport
        emits/reads the plain ADR-0025 frame (G2 default-OFF).
        """
        self._seq_ack_enabled = True

    async def spawn(self) -> None:
        """Spawn the plugin through the launcher with a SCRUBBED child env.

        The argv is the REAL PR-S4-6 launcher contract: positional
        ``<plugin_id> <executable> [args...]`` with the manifest path delivered
        on ``ALFRED_PLUGIN_MANIFEST_PATH`` (set by :func:`comms_child_env`). No
        ``pass_fds``, no provider-key pipe — comms needs no LLM key, so the fd-3
        hazard the orchestrator transport guards against does not apply here.

        The child's stdout ``StreamReader`` ``limit`` is pinned to
        :data:`_max_line_bytes` so an over-bound line fails fast at the reader
        rather than buffering unboundedly.

        Guards against a double spawn — a second call with a live ``self._proc``
        is a programming error, raised loudly.
        """
        if self._proc is not None:
            raise RuntimeError(
                f"CommsStdioTransport.spawn() called twice for adapter {self._adapter_id!r}"
            )
        cmd = [
            *shlex.split(_comms_launcher_path()),
            self._spec.plugin_id,
            sys.executable,
            "-m",
            self._spec.module,
        ]
        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=comms_child_env(self._spec),
            limit=self._max_line_bytes,
        )

    async def send(self, frame: Mapping[str, object]) -> None:
        """Write one ``json.dumps(frame) + "\\n"`` frame to the plugin's stdin.

        Loud on a broken pipe (the child died mid-conversation): the
        ``BrokenPipeError`` / ``ConnectionResetError`` propagates so the runner's
        crash arm routes an ``adapter.crashed`` and the breaker can trip
        (CLAUDE.md hard rule #7). Raises ``RuntimeError`` if called before
        :meth:`spawn` (explicit guard, not ``assert`` — survives ``python -O``).
        """
        if self._proc is None or self._proc.stdin is None:
            raise RuntimeError(
                f"CommsStdioTransport.send() called before spawn() for adapter {self._adapter_id!r}"
            )
        body = json.dumps(frame).encode()
        # Spec A G3-2 (#237) C2 (defensive symmetry): serialise the whole
        # encode -> write -> drain -> seq-increment critical section. Uncontended on
        # stdio in G3-2 (no second writer), but keeps the send contract identical to
        # the socket sibling and future-proofs Spec B.
        async with self._send_lock:
            if self._seq_ack_enabled:
                payload = encode_seq_frame(
                    body,
                    seq=self._send_seq,
                    # PLACEHOLDER (ADR-0032 Decision 3) — NOT a high-water; the G3 relay
                    # wires SeqDedupWindow.cumulative_ack() as the real ack source.
                    ack=0,
                    max_unit_bytes=self._max_line_bytes,
                )
                self._send_seq += 1
            else:
                payload = body + b"\n"
            try:
                self._proc.stdin.write(payload)
                await self._proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                log.warning(
                    "comms.transport.send_broken_pipe",
                    adapter_id=self._adapter_id,
                )
                raise

    async def read_frame(self) -> Mapping[str, object] | None:
        """Read one line-delimited frame; ``None`` on clean EOF.

        Returns the decoded JSON object, or ``None`` when the child closed its
        stdout cleanly (empty read). Raises :class:`CommsProtocolError` on an
        over-bound line, non-JSON bytes, or a non-object top-level JSON value.
        Raises ``RuntimeError`` if called before :meth:`spawn`.
        """
        if self._proc is None or self._proc.stdout is None:
            raise RuntimeError(
                f"CommsStdioTransport.read_frame() called before spawn() for adapter "
                f"{self._adapter_id!r}"
            )
        try:
            line = await self._proc.stdout.readline()
        except (ValueError, asyncio.LimitOverrunError) as exc:
            # The StreamReader's own limit (set to ``_max_line_bytes`` at spawn)
            # tripped on an over-bound line. Surface it as a protocol error
            # rather than a raw ValueError so the runner's malformed-frame arm
            # handles it uniformly.
            log.warning("comms.transport.frame_too_large", adapter_id=self._adapter_id)
            raise CommsProtocolError(
                t("comms.transport.malformed_frame", adapter_id=self._adapter_id)
            ) from exc
        if not line:
            # Clean EOF — the child closed stdout. The runner ends the pump.
            return None
        if len(line) > self._max_line_bytes:
            # Belt-and-braces: a line at exactly the reader limit can slip through
            # readline() without raising; enforce the bound explicitly too.
            log.warning("comms.transport.frame_too_large", adapter_id=self._adapter_id)
            raise CommsProtocolError(
                t("comms.transport.malformed_frame", adapter_id=self._adapter_id)
            )
        if self._seq_ack_enabled:
            # Spec A G2 (#237): strip the out-of-band header; the inner payload
            # continues through the existing json.loads path unchanged. G2
            # CONSUMES NO seq/ack here — it does not dedup, advance an ack, or
            # store a high-water (the relay, G3, is where seq/ack are consumed).
            # ``decode_seq_frame`` is magic-gated, so a plain (un-upgraded peer)
            # line still decodes via the SeqFrame(seq=None, ...) fallback
            # (mixed-wire safety). It is fail-loud (CommsProtocolError) on a
            # malformed header, surfacing through the SAME arm as a malformed
            # plain frame — no new error handling needed.
            frame_unit: SeqFrame = decode_seq_frame(line, max_unit_bytes=self._max_line_bytes)
            line = frame_unit.payload
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as exc:
            log.warning("comms.transport.malformed_frame", adapter_id=self._adapter_id)
            raise CommsProtocolError(
                t("comms.transport.malformed_frame", adapter_id=self._adapter_id)
            ) from exc
        if not isinstance(decoded, dict):
            # A JSON-RPC frame is always a top-level object. A list / scalar is
            # a protocol violation, not a frame the dispatcher can route.
            log.warning("comms.transport.non_object_frame", adapter_id=self._adapter_id)
            raise CommsProtocolError(
                t("comms.transport.malformed_frame", adapter_id=self._adapter_id)
            )
        return decoded

    async def close(self) -> None:
        """Gracefully shut the subprocess down; idempotent.

        Closes stdin (clean EOF for the child), waits up to
        :data:`_CLOSE_TIMEOUT_S` for exit, then escalates to ``terminate()`` ->
        ``kill()``. A no-op if :meth:`spawn` was never called or the child is
        already reaped. Mirrors :meth:`StdioTransport.close`'s escalation shape.
        """
        proc = self._proc
        if proc is None:
            return
        if proc.returncode is not None:
            # Already reaped — idempotent fast path.
            return
        if proc.stdin is not None:
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                proc.stdin.close()
        try:
            await asyncio.wait_for(proc.wait(), timeout=_CLOSE_TIMEOUT_S)
            return
        except TimeoutError:
            # Child ignored the cooperative close — escalate. Suppress
            # ProcessLookupError: the child can exit between the wait timeout and
            # the signal (a concurrent SIGCHLD reaps it), and a raise here would
            # surface out of the runner's ``finally`` during a supervisor
            # TaskGroup cancellation. Mirrors :meth:`StdioTransport.kill`.
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=_CLOSE_TIMEOUT_S)
        except TimeoutError:
            # Still wedged after SIGTERM — SIGKILL is uncatchable. Same
            # exit-during-escalation race as terminate() above.
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(proc.wait(), timeout=_CLOSE_TIMEOUT_S)


__all__ = [
    "CommsProtocolError",
    "CommsStdioTransport",
]

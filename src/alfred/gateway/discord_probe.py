"""TEST-ONLY: the G6-7-7 real-spawn probe adapter (Spec B, #309).

Reachable ONLY via the ``ALFRED_ENVIRONMENT``-gated launch-target override
(``alfred.gateway.adapter_child_factory._resolve_launch_target``); NEVER a
production adapter. It is absent from the production ``_ADAPTER_LAUNCH_TARGETS``
map and from every grant seeder / enabled-adapters config by design (Task 1's
guard test ``test_probe_not_in_production_map`` pins this).

WHY a PACKAGED module under ``src/alfred/`` and not ``plugins/``: it must ship in
the wheel (``[tool.hatch.build.targets.wheel] packages = ["src/alfred"]``) so it
is importable inside a ``kind="full"`` bwrap sandbox via the bound interpreter
prefix. A ``plugins/`` module would ``ModuleNotFoundError`` under bwrap, making
Task 4's real spawn vacuous. The launcher resolves the bwrap POLICY via the
SEPARATE plugin id ``alfred.discord_probe`` (``plugin_id.replace(".", "_")`` ->
``plugins/alfred_discord_probe/manifest.toml``) and execs THIS module string with
``python -m alfred.gateway.discord_probe``.

What it does, in load-bearing order (mirrors the gateway adapter stdio wire):

1. Read frames from stdin until the ``lifecycle.start`` request arrives; reply
   ``ok=True`` + ``plugin_version`` with NO ``seq_ack`` key — staying plain
   ADR-0025. Echoing ``seq_ack`` would flip the host's version-gate ON and every
   subsequent host->probe frame would arrive ``A1``-wrapped, which this plain
   ``json.loads`` loop cannot parse. The host DROPS any notification emitted
   BEFORE this ack (``comms_runner`` ``pre_handshake_frame_ignored``), so the ack
   MUST come first.
2. Read the fd-3 credential (the host delivered it BEFORE ``lifecycle.start``).
3. Emit a CONTENT-FREE ``fd3-received`` ack — proof the fd-3 delivery happened,
   carrying ONLY ``{"adapter_id": "discord", "received": true}`` and NEVER the
   credential bytes nor any value derived from them. This is Task 4's positive
   control for fd-3 delivery.
4. Emit EXACTLY ONE ``inbound.message`` notification carrying the scripted
   :data:`_PROBE_INBOUND_ID` / :data:`_PROBE_PLATFORM_USER_ID` / :data:`_PROBE_CONTENT`
   sentinels, validated against :class:`InboundMessageNotification` before send.
5. Block reading stdin until EOF (the host closes the probe's stdin to signal
   done), THEN exit 0 — keeping the child ALIVE so Task 4 can read the live
   child's ``/proc/<pid>/environ`` to prove the credential is not in the env.

The probe performs NO real Discord login: a real login in a hermetic spawn would
raise and reap the child pre-pump, defeating the proof. The credential is read
off fd 3 and acknowledged content-free; it is never used to authenticate.

NO operator-facing ``t()`` strings: the probe runs in a bwrap subprocess and
communicates ONLY via wire frames, never logs. The credential is never logged.

CROSS-TASK CONTRACT: Task 4 (``tests/.../test_*_real_spawn*``) imports the
``_PROBE_*`` module constants below and asserts/seeds against them — the scrubbed
child env cannot carry a per-test sentinel, so the probe owns fixed high-entropy
constants and Task 4's fresh testcontainer Postgres guarantees no pre-existing
``(discord, _PROBE_INBOUND_ID)`` idempotency row. Keep them STABLE.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Final

from alfred.comms_mcp.protocol import InboundMessageNotification

# The host runner sends the ``lifecycle.start`` request with this id
# (``comms_runner._LIFECYCLE_START_ID``); the probe echoes it on the result frame.
_LIFECYCLE_START_ID: Final[int] = 0
_METHOD_LIFECYCLE_START: Final[str] = "lifecycle.start"

# Plugin -> host notification methods.
_NOTIFY_INBOUND: Final[str] = "inbound.message"
# CONTENT-FREE fd-3 delivery ack. Namespaced so it never collides with a wire
# method; Task 4 keys its positive control on this exact method name.
_NOTIFY_FD3_RECEIVED: Final[str] = "alfred.discord_probe/fd3_received"

# The adapter kind the override redirects ``"discord"`` to this probe FOR — the
# probe announces "discord" so the host's BODY_FIELD_BY_KIND["discord"]="content"
# scanner + the spawn-binding adapter_id line up with the real adapter it stands in
# for. (The PLUGIN id ``alfred.discord_probe`` is the SEPARATE bwrap-policy key.)
_ADAPTER_ID: Final[str] = "discord"
_PLUGIN_VERSION: Final[str] = "0.0.1-g6-7-7-probe"

# Bytes to read off fd 3 in one shot. The host delivers a short credential
# reference / token-shaped blob; 4 KiB is comfortably larger than any real one.
_FD3_READ_SIZE: Final[int] = 4096

# ---------------------------------------------------------------------------
# CROSS-TASK CONTRACT — fixed high-entropy sentinels (Task 4 imports these).
# ---------------------------------------------------------------------------

# The Spec-A G0 dedup key Task 4 asserts on the ``(discord, inbound_id)``
# idempotency row. Fixed (the scrubbed child env carries no per-test sentinel);
# high-entropy + namespaced so it cannot collide with a real Discord snowflake or
# another adapter's id, and <= the InboundId 255-char bound.
_PROBE_INBOUND_ID: Final[str] = "g6_7_7_probe_5f3c9a1e7b2d4806c1ad9e4f70b8a3d2"

# A fixed Discord-shaped platform id. Task 4 seeds a bound Discord user with THIS
# platform id so the forwarded inbound resolves to it.
_PROBE_PLATFORM_USER_ID: Final[str] = "discord:probe-9b4e2c7a51f0"

# A fixed sentinel body content string Task 4 can assert reached the core dispatch.
_PROBE_CONTENT: Final[str] = "g6-7-7 real-spawn probe sentinel content"

__all__ = [
    "_PROBE_CONTENT",
    "_PROBE_INBOUND_ID",
    "_PROBE_PLATFORM_USER_ID",
]


def _build_handshake_reply(req_id: object) -> dict[str, object]:
    """Build the ``lifecycle.start`` result frame.

    NO ``seq_ack`` member — the probe stays plain ADR-0025 (see module docstring).
    """
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {"ok": True, "plugin_version": _PLUGIN_VERSION},
    }


def _build_fd3_received_ack() -> dict[str, object]:
    """Build the CONTENT-FREE fd-3 delivery ack notification.

    Carries ONLY ``adapter_id`` + a boolean ``received`` flag — NEVER the
    credential bytes nor any value derived from them.
    """
    return {
        "jsonrpc": "2.0",
        "method": _NOTIFY_FD3_RECEIVED,
        "params": {"adapter_id": _ADAPTER_ID, "received": True},
    }


def _build_inbound_notification() -> dict[str, object]:
    """Build the single scripted ``inbound.message`` notification frame.

    The ``params`` are validated against :class:`InboundMessageNotification`
    before they cross the wire so a drift between this probe and the real wire
    model surfaces here (a loud ``ValidationError``) rather than as a silent
    malformed frame Task 4's host would reject. ``body`` mirrors the real Discord
    adapter's body shape for the host scanner: ``content`` is
    ``BODY_FIELD_BY_KIND["discord"]`` and ``language`` is the BCP-47 tag the
    downstream ``t3_promoted`` row carries (i18n rule #3).
    """
    params: dict[str, object] = {
        "adapter_id": _ADAPTER_ID,
        "inbound_id": _PROBE_INBOUND_ID,
        "platform_user_id": _PROBE_PLATFORM_USER_ID,
        "body": {"content": _PROBE_CONTENT, "language": "en"},
        "sub_payload_refs": [],
        "received_at": datetime.now(UTC).isoformat(),
        "addressing_signal": "dm",
    }
    # Local validation: structure must satisfy the real wire model. Raises loudly
    # on drift; the validated copy is discarded — the wire carries ``params`` as-is
    # (JSON-serialisable: the ISO8601 string survives a round-trip the model's
    # datetime field would otherwise re-render).
    InboundMessageNotification.model_validate(params)
    return {"jsonrpc": "2.0", "method": _NOTIFY_INBOUND, "params": params}


async def _read_until_lifecycle_start(reader: asyncio.StreamReader) -> object:
    """Read line-delimited frames until the ``lifecycle.start`` request; return its id.

    Frames before ``lifecycle.start`` (none expected on a conformant host) are
    ignored; an EOF before the request is a hard failure (the host vanished).
    """
    while True:
        line = await reader.readline()
        if not line:
            msg = "stdin EOF before lifecycle.start request"
            raise RuntimeError(msg)
        frame = json.loads(line)
        if isinstance(frame, Mapping) and frame.get("method") == _METHOD_LIFECYCLE_START:
            return frame.get("id", _LIFECYCLE_START_ID)


async def _block_until_eof(reader: asyncio.StreamReader) -> None:
    """Read and discard stdin until EOF (the host's done signal), then return."""
    while True:
        line = await reader.readline()
        if not line:
            return


async def _run_probe(
    reader: asyncio.StreamReader,
    write: Callable[[Mapping[str, object]], None],
    *,
    read_credential: Callable[[], bytes],
) -> None:
    """The probe's wire logic, in load-bearing order (see module docstring).

    Separated from :func:`_main` so the unit test can drive it with an in-memory
    ``StreamReader``, a recording ``write``, and a fake ``read_credential`` —
    without touching real fd 3 or real stdin/stdout.
    """
    # 1. Handshake FIRST: ack lifecycle.start before any notification.
    req_id = await _read_until_lifecycle_start(reader)
    write(_build_handshake_reply(req_id))

    # 2. Read the fd-3 credential (delivered before lifecycle.start). It is NEVER
    #    logged, echoed, or used to derive any emitted value. An EMPTY read means no
    #    credential was delivered (fd-3 closed with no bytes) — FAIL CLOSED so the
    #    e2e's fd-3-delivery proof cannot pass vacuously.
    credential = read_credential()
    if not credential:
        raise RuntimeError(
            "discord_probe: fd-3 credential empty — no credential delivered (fail-closed)"
        )

    # 3. Content-free fd-3 delivery ack (Task 4's positive control).
    write(_build_fd3_received_ack())

    # 4. Exactly ONE scripted inbound.message.
    write(_build_inbound_notification())

    # 5. Block until the host closes our stdin, then return (exit 0). Keeping the
    #    child alive lets Task 4 read /proc/<pid>/environ to prove the credential
    #    is not in the environment.
    await _block_until_eof(reader)


def _read_fd3_credential() -> bytes:  # pragma: no cover - entrypoint (docker-only e2e)
    """Read the credential off LITERAL fd 3 until the host closes the write end.

    The host writes the credential to the probe's fd 3 (the launcher's fd-3 key
    channel) and closes it; an empty read signals that close. Runs ONLY in the
    real subprocess (``_main``) — the unit test injects a fake reader.
    """
    chunks: list[bytes] = []
    while True:
        chunk = os.read(3, _FD3_READ_SIZE)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


async def _main() -> None:  # pragma: no cover - process entrypoint (exercised by Task 4)
    """Wire real stdin/stdout + fd-3 and run :func:`_run_probe`."""
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_event_loop()
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    writer_transport, _writer_protocol = await loop.connect_write_pipe(
        asyncio.BaseProtocol, sys.stdout.buffer
    )

    def _emit(frame: Mapping[str, object]) -> None:
        writer_transport.write((json.dumps(frame) + "\n").encode())

    await _run_probe(reader, _emit, read_credential=_read_fd3_credential)


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    asyncio.run(_main())

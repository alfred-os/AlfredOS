#!/usr/bin/env python3
"""THROWAWAY probe (#288, G6-0b) — DELETE after G6-0b is decided.

Decisive single-question probe: does the bwrap-sandboxed quarantine child spawn
+ complete a real ingest->extract round-trip when run under the PRODUCTION
posture of the ``alfred-core`` image — the non-root ``alfred`` user with only
``cap_add: [SETUID]`` (NOT root, NOT ``--privileged``) on x86-64 Linux?

This is the gap the existing ``test_quarantine_child_real_spawn.py`` proof does
NOT cover: that proof runs pytest under ``sudo`` (``geteuid()==0``) and provisions
a hermetic proto python via ``ALFRED_QUARANTINE_CHILD_PYTHON``. Production runs
neither as root nor with that provisioning — it runs as ``alfred`` with
``sys.executable`` = the image venv python and the default per-OS bwrap policy.
G6-0b enables comms on a daemon-ified core; if THIS spawn refuses at boot under
``restart: unless-stopped`` the default deployment crash-loops.

The probe drives the SAME production machinery the real-spawn test uses
(``spawn_quarantine_child_io`` -> ``QuarantineStdioTransport`` ingest/extract),
but with NO postgres/redis/daemon and NO audit layer — it isolates the spawn.
It does NOT set ``ALFRED_QUARANTINE_CHILD_PYTHON`` (leaving the production default
``sys.executable``), so the answer reflects real production behaviour.

Prints exactly one machine-greppable result line and sets the exit code:

* ``QUARANTINE_SPAWN_PROBE_RESULT=OK``           -> exit 0 (child spawned + echoed)
* ``QUARANTINE_SPAWN_PROBE_RESULT=FAILED:<why>`` -> exit 1 (refused / wrong reply)
"""

from __future__ import annotations

import asyncio
import os
import sys
import traceback

_PROBE_BODY = "g6-0b probe body — does the real bwrap child echo this back?"
_RESULT_PREFIX = "QUARANTINE_SPAWN_PROBE_RESULT="


def _emit(result: str) -> int:
    """Print the single greppable result line; return the process exit code."""
    print(f"{_RESULT_PREFIX}{result}", flush=True)
    return 0 if result == "OK" else 1


def _assert_non_root_posture() -> str | None:
    """Refuse to "prove" anything if we are accidentally root.

    The whole point is the NON-root + SETUID posture. A root run would silently
    succeed for the wrong reason and give a false-positive answer, so bail loud.
    """
    if os.geteuid() == 0:
        return "running as root (euid 0) — probe must run as the non-root alfred user"
    if os.uname().sysname != "Linux":
        return f"not Linux (sysname={os.uname().sysname}) — production posture is x86-64 Linux"
    return None


async def _run_round_trip() -> str:
    """Spawn the real bwrap child + drive one ingest->extract round-trip.

    Returns ``"OK"`` on a verified echo, else ``"FAILED:<reason>"``.

    Drives the child-IO seam DIRECTLY with the production wire constants rather
    than ``QuarantineStdioTransport`` — the transport's ``dispatch`` insists on a
    nonce-tagged ``QuarantineStagingMap`` entry (T3 tagging machinery that is
    irrelevant to the spawn question), so the probe stays at the wire layer the
    transport itself uses (``_frame`` / ``_decode_result_payload``). What it
    proves is identical: the bwrapped child genuinely spawned, read the wire, and
    echoed the body back (the 2b deterministic-echo loop sets
    ``result.data.text = context``).
    """
    # Imported here so the module loads even if the import surface changes; an
    # import error is reported as a clear FAILED reason rather than a traceback
    # before the result line.
    from alfred.security.quarantine_child_io import (
        QuarantineChildSpawnError,
        spawn_quarantine_child_io,
    )
    from alfred.security.quarantine_transport import (
        _EXTRACT_METHOD,
        _INGEST_METHOD,
        _decode_result_payload,
        _frame,
    )

    child_io = None
    try:
        # The 2b deterministic-echo child reads + scrubs the provider key but
        # makes NO LLM call, so a placeholder key is correct here (mirrors the
        # real-spawn integration test). This is the REAL bwrap spawn: it execs
        # bin/alfred-plugin-launcher.sh (kind=full -> bwrap) and delivers the key
        # over fd 3.
        child_io = await spawn_quarantine_child_io(provider_key="g6-0b-probe-placeholder-key")
    except QuarantineChildSpawnError as exc:
        return f"FAILED:spawn_refused:{type(exc).__name__}:{exc}"
    except Exception as exc:  # noqa: BLE001 - probe must report ANY spawn failure verbatim
        return f"FAILED:spawn_raised:{type(exc).__name__}:{exc}"

    handle_id = "g6-0b-probe-handle"
    try:
        # Same wire the transport ships: ingest the body inline, then extract
        # against the opaque handle. The bwrapped child caches the ingest body
        # and echoes it back on extract.
        child_io.write_frame(_frame(_INGEST_METHOD, {"handle_id": handle_id, "context": _PROBE_BODY}))
        child_io.write_frame(
            _frame(
                _EXTRACT_METHOD,
                {
                    "handle_id": handle_id,
                    "schema_json": '{"type":"object","properties":{"text":{"type":"string"}}}',
                    "schema_version": 1,
                },
            )
        )
        raw = await child_io.read_frame()
    except QuarantineChildSpawnError as exc:
        # A truncated/wedged reply frame -> the child crashed mid-round-trip
        # (the launcher refused inside bwrap, the policy was inert, the userns
        # setup was denied, etc.).
        return f"FAILED:round_trip_refused:{type(exc).__name__}:{exc}"
    except Exception as exc:  # noqa: BLE001 - report ANY round-trip failure verbatim
        return f"FAILED:round_trip_raised:{type(exc).__name__}:{exc}"
    finally:
        if child_io is not None:
            await child_io.aclose()

    try:
        payload = _decode_result_payload(raw)
    except Exception as exc:  # noqa: BLE001 - a torn reply decodes loud, report it
        return f"FAILED:decode_raised:{type(exc).__name__}:{exc}"

    data = payload.get("data") if isinstance(payload, dict) else None
    echoed = data.get("text") if isinstance(data, dict) else None
    if echoed == _PROBE_BODY:
        return "OK"
    return f"FAILED:echo_mismatch:got={echoed!r} payload={payload!r}"


def main() -> int:
    posture_problem = _assert_non_root_posture()
    if posture_problem is not None:
        return _emit(f"FAILED:bad_posture:{posture_problem}")

    # Surface the exact spawn-relevant posture so the run log is self-explaining.
    print(
        f"[probe] euid={os.geteuid()} sysname={os.uname().sysname} "
        f"machine={os.uname().machine} sys.executable={sys.executable} "
        f"ALFRED_ENVIRONMENT={os.environ.get('ALFRED_ENVIRONMENT')!r} "
        f"ALFRED_QUARANTINE_CHILD_PYTHON={os.environ.get('ALFRED_QUARANTINE_CHILD_PYTHON')!r}",
        flush=True,
    )

    try:
        result = asyncio.run(_run_round_trip())
    except Exception:  # noqa: BLE001 - never let an unexpected error hide the result line
        traceback.print_exc()
        result = "FAILED:probe_harness_raised"
    return _emit(result)


if __name__ == "__main__":
    raise SystemExit(main())

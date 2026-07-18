"""Boot-handshake frames for the quarantined-LLM child (#443 PR2).

Two unsolicited, outbound child->host frames emitted during child boot, BEFORE the
JSON-RPC request loop is entered. They let the host verify — INSIDE
``spawn_quarantine_child_io`` — that a real child exec'd and initialized, instead of
inferring it late (at first extraction) from a ``read_frame`` failure shape:

* ``HELLO_FRAME`` — emitted before ``_build_provider`` (a raw ``sys.stdout.buffer``
  write in the child; the asyncio writer does not exist that early). Provenance:
  "a real, exec'd child is running." The host keys its launcher-vs-child audit
  discriminator (``_child_wrote_stdout``) on the FIRST stdout byte, so this frame is
  what proves exec at the boot barrier.
* ``READY_FRAME`` — emitted after the child's asyncio streams are built, before the
  request loop. Liveness: "initialized and serving."

Both use the SAME 4-byte big-endian length prefix as the JSON-RPC wire
(``struct.pack(">I", len(body)) + body``), so the host reads them with the existing
``read_frame`` — no special-casing, and the host never parses the body (the security
property is byte-arrival + frame-count, not content). Stdlib-only (``json``,
``struct``, ``sys``) so the child's minimal import surface (ADR-0030 import-closure
gate) is preserved; both the child and the diagnostic probe call ``emit_hello``.
"""

from __future__ import annotations

import json
import struct
import sys

_HELLO_METHOD = "boot.hello"
_READY_METHOD = "boot.ready"


def _boot_frame(method: str) -> bytes:
    body = json.dumps({"jsonrpc": "2.0", "method": method}).encode("utf-8")
    return struct.pack(">I", len(body)) + body


HELLO_FRAME: bytes = _boot_frame(_HELLO_METHOD)
READY_FRAME: bytes = _boot_frame(_READY_METHOD)


def emit_hello() -> None:
    """Write the boot ``hello`` frame to fd 1 via a RAW buffered write + flush (#443).

    Shared by BOTH the quarantine child (`__main__.main`) and the diagnostic probe
    (`_brokered_probe.main`) — the emitter bodies were byte-identical, so this is the
    single definition (rev-002 DRY; also unifies the name — no per-module
    `_write_boot_hello`/`_emit_boot_hello`). A raw write because at the child's hello
    point the asyncio writer does not exist yet; safe because both callers pin logging
    to stderr before calling it, keeping fd 1 byte-pure. Stdlib-only, so the child's
    import closure (ADR-0030) is unchanged.
    """
    sys.stdout.buffer.write(HELLO_FRAME)
    sys.stdout.buffer.flush()


__all__ = ["HELLO_FRAME", "READY_FRAME", "emit_hello"]

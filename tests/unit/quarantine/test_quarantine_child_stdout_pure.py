"""The quarantine child's stdout carries ONLY wire frames (PR-S4-11c-2b0 BUG-1).

The bwrapped quarantine child writes length-prefixed JSON-RPC reply frames on
**stdout** (fd 1). If anything it imports logs to stdout — notably the i18n
translator's import-time "translations disabled" warning, which fires on a
pip-installed alfred whose catalog is absent — the warning bytes prepend the
reply frame and corrupt the wire the host transport reads.

This drives the REAL child as a subprocess over real fd 0/1/3/4 (no bwrap, no LLM),
with the i18n catalog forced absent, and asserts stdout decodes to exactly three
clean frames — hello boot frame, ready boot frame, and the reply frame — with NO
extra bytes around them — proving nothing leaked onto fd 1 (#443).

#340 PR2b golive: the deterministic-echo cut is gone; the loop's extract branch now
calls ``handle_extract`` -> imports ``provider_dispatch`` (the lazy extract-path
import that loads the translator, whose missing-catalog warning is the leak this
guards). To keep this a UNIT-level proof WITHOUT a live provider, the drive extracts
a MISSING handle: ``handle_extract`` imports ``provider_dispatch`` (loading the
translator — the property under test) then SHORT-CIRCUITS empty content to a
``typed_refusal`` reply BEFORE any provider call or fd-4 brokering (spec §8). So the
translator genuinely loads on the extract path here, and ``main()``'s
``configure_stderr_logging()`` pin (also asserted structurally by
``test_stdout_protocol_logging_pinned.py``) must keep its warning off fd 1. The child
reconstructs its fd-4 control socket at boot; the drive supplies one end of a real
``socketpair`` so that reconstruction + the extract-branch drain succeed. The live
provider round-trip is the Task 14 docker/TLS-stub proof.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

# Force the missing-catalog case BEFORE the translator imports (so its
# import-time warning genuinely fires), then exec the child's real ``main()`` over
# real stdio. ``provider_dispatch`` (lazy-imported on the extract path) loads the
# translator AFTER main() has pinned logging to stderr — the path under test.
_FORCE_NO_LOCALE_THEN_RUN_CHILD = (
    "import asyncio, sys, pathlib, importlib.resources;"
    "pathlib.Path.is_dir = lambda self: False;"
    "importlib.resources.files = lambda name: (_ for _ in ()).throw(ModuleNotFoundError());"
    "import alfred.security.quarantine_child.__main__ as _c;"
    "asyncio.run(_c.main())"
)


def _frame(method: str, params: dict[str, object]) -> bytes:
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params}).encode("utf-8")
    return struct.pack(">I", len(body)) + body


def _provider_key_fd3_bytes(key: str) -> bytes:
    raw = key.encode("utf-8")
    return struct.pack(">I", len(raw)) + raw


def test_child_stdout_is_pure_wire_frame_when_locale_absent() -> None:
    """stdout decodes to exactly three clean frames — hello, ready, typed_refusal reply.

    Nothing leaks onto fd 1 even though the extract path imports ``provider_dispatch``
    (loading the translator) before short-circuiting empty content.
    """
    # Extract a MISSING handle (never ingested): handle_extract imports
    # provider_dispatch (loading the translator — the leak this guards) then
    # short-circuits empty content to a typed_refusal BEFORE any provider call.
    stdin_bytes = _frame(
        "quarantine.extract",
        {"handle_id": "never-ingested", "schema_json": "{}", "schema_version": 1},
    )

    # The provider key is delivered on fd 3 (spec §5.3). Use a pipe and remap its
    # read end onto fd 3 in the child via ``dup2`` in a preexec hook, since the
    # child reads fd 3 by literal number (``pass_fds`` keeps the fd open but does
    # not renumber it). Write the framed key then close the write end so the
    # child's blocking ``os.read(3, ...)`` sees the key then EOF.
    fd3_read, fd3_write = os.pipe()
    os.write(fd3_write, _provider_key_fd3_bytes("sk-fake-test-key"))
    os.close(fd3_write)

    # The child reconstructs its one-way control channel from fd 4 at boot (#340
    # PR2a). Supply one end of a real AF_UNIX socketpair so that reconstruction — and
    # the extract-branch drain (a MSG_DONTWAIT recv that returns EAGAIN on this empty,
    # connected socket) — succeed without a live gateway. The other end is held by the
    # test so the child end stays connected (not reset).
    control_parent, control_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    def _remap_inherited_fds() -> None:  # pragma: no cover - runs in the child process
        os.dup2(fd3_read, 3)
        os.dup2(control_child.fileno(), 4)

    # _build_provider reads the spawn-env model/max_tokens (Task 8 delivers these
    # live). A non-empty fd-3 key + these vars let the child boot past _build_provider.
    env = {
        "PYTHONPATH": str(REPO_ROOT / "src"),
        "PATH": "/usr/bin:/bin",
        "ALFRED_QUARANTINE_MODEL": "claude-test-model",
        "ALFRED_QUARANTINE_MAX_TOKENS": "8192",
    }
    try:
        proc = subprocess.run(  # noqa: S603 — sys.executable + repo-owned inline driver
            [sys.executable, "-c", _FORCE_NO_LOCALE_THEN_RUN_CHILD],
            input=stdin_bytes,
            capture_output=True,
            env=env,
            pass_fds=(fd3_read, control_child.fileno(), 3, 4),
            preexec_fn=_remap_inherited_fds,
            check=False,
            timeout=30,
        )
    finally:
        os.close(fd3_read)
        control_parent.close()
        control_child.close()

    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")

    # stdout must contain THREE length-prefixed frames: hello, ready, typed_refusal reply.
    # No warning bytes or extra content.
    out = proc.stdout
    assert len(out) >= 4, f"stdout too short to be a framed reply: {out!r}"

    # Parse first frame (hello boot frame)
    frame_offset = 0
    length1 = struct.unpack(">I", out[frame_offset : frame_offset + 4])[0]
    frame_body1 = out[frame_offset + 4 : frame_offset + 4 + length1]
    boot_hello = json.loads(frame_body1)
    assert boot_hello["method"] == "boot.hello"
    frame_offset += 4 + length1

    # Parse second frame (ready boot frame)
    length2 = struct.unpack(">I", out[frame_offset : frame_offset + 4])[0]
    frame_body2 = out[frame_offset + 4 : frame_offset + 4 + length2]
    boot_ready = json.loads(frame_body2)
    assert boot_ready["method"] == "boot.ready"
    frame_offset += 4 + length2

    # Parse third frame (typed_refusal reply — empty-content short-circuit, spec §8)
    length3 = struct.unpack(">I", out[frame_offset : frame_offset + 4])[0]
    frame_body3 = out[frame_offset + 4 : frame_offset + 4 + length3]
    reply = json.loads(frame_body3)
    assert reply["result"]["kind"] == "typed_refusal"
    assert reply["result"]["reason"] == "cannot_extract"

    # Verify no extra bytes
    expected_total = frame_offset + 4 + length3
    assert len(out) == expected_total, (
        f"stdout has {len(out) - expected_total} extra byte(s) — "
        f"a log line leaked onto fd 1: {out!r}"
    )

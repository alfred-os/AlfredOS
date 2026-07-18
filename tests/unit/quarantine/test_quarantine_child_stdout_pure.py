"""The quarantine child's stdout carries ONLY wire frames (PR-S4-11c-2b0 BUG-1).

The bwrapped quarantine child writes length-prefixed JSON-RPC reply frames on
**stdout** (fd 1). If anything it imports logs to stdout — notably the i18n
translator's import-time "translations disabled" warning, which fires on a
pip-installed alfred whose catalog is absent — the warning bytes prepend the
reply frame and corrupt the wire the host transport reads.

This drives the REAL child as a subprocess over real fd 0/1/3 (no bwrap, no LLM),
with the i18n catalog forced absent, and asserts stdout decodes to exactly three
clean frames — hello boot frame, ready boot frame, and the ``extracted`` reply
frame — with NO extra bytes around them — proving nothing leaked onto fd 1 (#443).

In the 2b deterministic-echo cut the loop never imports ``provider_dispatch``
(the lazy extract-path import that loads the translator), so the warning does not
fire on this path; the stdout-purity guard nonetheless pins the wire contract, and
``main()``'s ``configure_stderr_logging()`` pin (asserted by
``test_stdout_protocol_logging_pinned.py``) keeps it safe for the 2c real-client
cut, which DOES load the translator on the extract path.
"""

from __future__ import annotations

import json
import os
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
    """stdout decodes to exactly one clean reply frame — nothing leaks onto fd 1."""
    context = "hello over the wire"
    stdin_bytes = _frame("quarantine.ingest", {"handle_id": "h1", "context": context}) + _frame(
        "quarantine.extract",
        {"handle_id": "h1", "schema_json": "{}", "schema_version": 1},
    )

    # The provider key is delivered on fd 3 (spec §5.3). Use a pipe and remap its
    # read end onto fd 3 in the child via ``dup2`` in a preexec hook, since the
    # child reads fd 3 by literal number (``pass_fds`` keeps the fd open but does
    # not renumber it). Write the framed key then close the write end so the
    # child's blocking ``os.read(3, ...)`` sees the key then EOF.
    fd3_read, fd3_write = os.pipe()
    os.write(fd3_write, _provider_key_fd3_bytes("sk-fake-test-key"))
    os.close(fd3_write)

    def _remap_fd3_to_three() -> None:  # pragma: no cover - runs in the child process
        os.dup2(fd3_read, 3)

    env = {"PYTHONPATH": str(REPO_ROOT / "src"), "PATH": "/usr/bin:/bin"}
    try:
        proc = subprocess.run(  # noqa: S603 — sys.executable + repo-owned inline driver
            [sys.executable, "-c", _FORCE_NO_LOCALE_THEN_RUN_CHILD],
            input=stdin_bytes,
            capture_output=True,
            env=env,
            pass_fds=(fd3_read, 3),
            preexec_fn=_remap_fd3_to_three,
            check=False,
            timeout=30,
        )
    finally:
        os.close(fd3_read)

    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")

    # stdout must contain THREE length-prefixed frames: hello, ready, extracted reply.
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

    # Parse third frame (extracted reply)
    length3 = struct.unpack(">I", out[frame_offset : frame_offset + 4])[0]
    frame_body3 = out[frame_offset + 4 : frame_offset + 4 + length3]
    reply = json.loads(frame_body3)
    assert reply["result"]["kind"] == "extracted"
    assert reply["result"]["data"]["text"] == context

    # Verify no extra bytes
    expected_total = frame_offset + 4 + length3
    assert len(out) == expected_total, (
        f"stdout has {len(out) - expected_total} extra byte(s) — "
        f"a log line leaked onto fd 1: {out!r}"
    )

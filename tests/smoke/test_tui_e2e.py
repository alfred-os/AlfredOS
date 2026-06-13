"""TUI end-to-end smoke — placeholder pending the real socket-dial PTY smoke (#237).

History
-------

Through Slice 2/3 this file drove the in-process :class:`AlfredTuiApp` (Textual)
via ``app.run_test()`` + ``Pilot``. PR-S4-10 (the TUI flag-day) made the TUI an
out-of-process MCP plugin (``plugins/alfred_tui/``) and this smoke became a
launcher-spawn + stdio round-trip: spawn ``alfred_tui.server`` through
``bin/alfred-plugin-launcher.sh`` and drive the ADR-0024 wire lifecycle over the
child's stdin/stdout.

PR-S4-237-2 (ADR-0031 **Shape A**) RETIRED that shape: ``alfred chat`` no longer
launcher-spawns the TUI over stdio. It runs the TUI IN-PROCESS as one asyncio
program co-hosting Textual + the comms wire, and DIALS the running daemon's 0600
unix socket (``alfred_tui.cohost.run_cohosted`` → ``dial_comms_socket``); the
``serve()`` entry now co-hosts rather than reading stdio. So the launcher-spawn
stdio smoke tests a deployment shape that no longer exists.

The replacement — a REAL end-to-end ``alfred chat`` turn that boots ``alfred
daemon start``, dials the socket from a foreground PTY, types a line, and asserts
the daemon's stubbed ``ack`` paints into the conversation log — is a dedicated PTY
smoke deferred to PR-4 of the #237 graduation epic (real PTY + real daemon +
real socket). The host-side legs that DO have coverage now:

  * the in-process plugin inbound/outbound round-trip + host invariants —
    ``tests/integration/test_tui_round_trip.py``;
  * the client dialer + co-host serve loop + teardown —
    ``tests/unit/plugins/test_comms_socket_transport.py`` (``dial_comms_socket``)
    and ``plugins/alfred_tui/tests/test_cohost.py``;
  * the ``alfred chat`` dial-failure → daemon-required mapping —
    ``tests/unit/cli/test_chat_daemon_required.py``.

Skip-vs-pass discipline (smoke-layer invariant): rather than silently delete the
smoke gate, this module reports SKIPPED with the reason naming the gap and the
PR-4 follow-up, so the smoke report keeps the missing real-PTY e2e visible.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.smoke


@pytest.mark.smoke
def test_tui_real_chat_turn_pending_pr4_pty_smoke() -> None:
    """Placeholder: the real ``alfred chat`` socket-dial PTY smoke lands in PR-4.

    ADR-0031 Shape A retired the launcher-spawn + stdio smoke this module used to
    drive (``alfred_tui.server`` no longer speaks stdio — it dials the daemon's
    socket and co-hosts Textual). The real PTY + real daemon + real socket e2e
    turn (asserting the stubbed ``ack`` paints into the conversation log) is the
    PR-4 follow-up of the #237 graduation epic.
    """
    pytest.skip(
        "TUI e2e smoke flips to a real socket-dial PTY turn in PR-4 (#237); the "
        "retired launcher-spawn stdio shape no longer exists under ADR-0031 Shape A."
    )

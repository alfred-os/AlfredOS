"""Unit modules pytest must not COLLECT on native Windows (#246 Phase B).

AlfredOS has a Linux-only runtime (bwrap / ``runuser`` / ``AF_UNIX`` sockets /
POSIX fds / ``os.getuid`` family / ``resource``). The modules listed here are
**wholly** POSIX/Linux-only — every test in them either crashes at import
(a POSIX-only import) or fails at runtime on Windows (a POSIX syscall,
``socket.AF_UNIX`` — which CPython does not expose on Windows — or the bash
launcher). ``collect_ignore`` prevents collection entirely, which is the only
mechanism that works for the import-crashers **and** the cleanest for
whole-file-runtime cases (no per-test ``skipif`` churn on a file where nothing
runs on Windows anyway). Windows' documented dev path for these is WSL2/Linux,
where they run in full; the Linux and macOS CI legs also run them, so native
Windows loses no unique signal.

Mixed files (some tests portable, some POSIX) are NOT listed here — those carry
per-test ``@pytest.mark.skipif(sys.platform == "win32", …)`` so their portable
tests keep running on Windows.

Kept as a pure function so the win32 branch — which never executes on a
non-Windows dev box or the Linux CI legs — is unit-testable locally (see
``tests/unit/meta/test_posix_only_collect_ignore.py``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

# Paths relative to the tests/ root. Grouped by why the whole file is POSIX-only.
POSIX_ONLY_TEST_FILES: Final[tuple[str, ...]] = (
    # --- Import-time crashes (a module-level POSIX import/attr) ------------------
    # `import resource` (RLIMIT_CORE) at module top in BOTH the test and the
    # production module it imports (src/alfred/supervisor/process_posture.py).
    "unit/supervisor/test_process_posture.py",
    # `os.uname().sysname` in a module-level constant; the tests also exec the
    # bash launcher/runuser/`/bin/echo`. Its ~6 portable read_text()+grep tests
    # are lost on Windows too, an accepted no-op (tracked bytes; spec §2).
    "unit/plugins/test_plugin_launcher_stub.py",
    # `os.getuid()` inside skipif decorators evaluated at import; POSIX file
    # mode/owner semantics (already whole-module skipif win32 off-Windows).
    "unit/identity/test_operator_session_file_load.py",
    # --- bash/bwrap/runuser launcher (POSIX subprocess sandbox) ------------------
    "unit/launcher/test_launcher_sandbox_flow.py",
    "unit/launcher/test_launcher_chain_fixture_export.py",
    "unit/launcher/test_fd_leak.py",
    # --- AF_UNIX sockets / daemon control plane (Linux-only IPC) -----------------
    # socket.AF_UNIX is not exposed by CPython on Windows.
    "unit/cli/daemon/test_daemon_control_server.py",
    "unit/cli/daemon/test_daemon_control_boot.py",
    "unit/cli/daemon/test_daemon_control_roundtrip.py",
    "unit/cli/daemon/test_daemon_stop_signals_supervisor.py",
    "unit/cli/daemon/test_daemon_status_renders.py",
    "unit/cli/daemon/test_daemon_status_no_daemon.py",
    "unit/cli/daemon/test_status_daemon_render.py",
    "unit/cli/daemon/test_daemon_idempotency_store_wired.py",
    "unit/cli/daemon/test_comms_boot_graph_status_observer.py",
    "unit/cli/daemon/test_daemon_environment_source_conflict.py",
    "unit/gateway/test_relay_wire_contract.py",
    "unit/gateway/test_process_e2e.py",
    "unit/plugins/test_comms_test_plugin_smoke.py",
    # --- POSIX file mode / pidfile ----------------------------------------------
    "unit/cli/daemon/test_daemon_pidfile_mode.py",
    # --- Other wholly-POSIX modules (machine-id / watcher / quarantine child) ---
    "unit/identity/test_replay_on_different_machine.py",
    "unit/policies/test_watcher_first_tick_immediate.py",
    "unit/quarantine/test_quarantine_child_stdout_pure.py",
)


def collect_ignore_for(platform: str, tests_root: Path) -> list[str]:
    """Absolute paths pytest must ignore when collecting on ``platform``.

    Returns the POSIX-only modules as absolute paths under ``tests_root`` when
    ``platform`` is ``"win32"``, else an empty list. ``platform`` is normally
    ``sys.platform``; passing it explicitly keeps the win32 branch testable off
    Windows.
    """
    if platform != "win32":
        return []
    return [str(tests_root / rel) for rel in POSIX_ONLY_TEST_FILES]

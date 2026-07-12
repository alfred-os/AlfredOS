"""POSIX-only unit modules pytest must not COLLECT on Windows (#246 Phase B).

Three unit modules import POSIX-only facilities at import time, so they crash
during collection on Windows — before pytest can apply any module-level
``skipif`` (which is evaluated only after the module imports). The docker
auto-skip hook cannot help either: it runs in ``pytest_collection_modifyitems``,
also after import. ``tests/conftest.py`` feeds this list to pytest's
``collect_ignore_glob`` so the modules are never imported on Windows.

Kept as a pure function so the win32 branch — which never executes on a
non-Windows dev box or the Linux CI legs — is unit-testable locally (see
``tests/unit/meta/test_posix_only_collect_ignore.py``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

# Paths relative to the tests/ root. Each is POSIX-runtime and crashes Windows
# collection at import time:
POSIX_ONLY_TEST_FILES: Final[tuple[str, ...]] = (
    # `import resource` (RLIMIT_CORE) at module top in BOTH the test and the
    # production module it imports (src/alfred/supervisor/process_posture.py).
    # `resource` is POSIX-only → ModuleNotFoundError at import on Windows.
    "unit/supervisor/test_process_posture.py",
    # `os.uname().sysname` in a module-level constant → AttributeError on
    # Windows. Mixed file: most tests exec the bash launcher/runuser/`/bin/echo`
    # (POSIX); its ~6 portable read_text()+grep tests are lost on Windows too, an
    # accepted no-op (they read tracked bytes → identical on every OS; spec §2).
    "unit/plugins/test_plugin_launcher_stub.py",
    # `os.getuid()` inside two skipif decorators evaluated at import →
    # AttributeError on Windows; POSIX file mode/owner semantics (the module is
    # already whole-module skipif win32 for the non-Windows platforms).
    "unit/identity/test_operator_session_file_load.py",
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

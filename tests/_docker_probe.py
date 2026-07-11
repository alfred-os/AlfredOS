"""Shared Docker-daemon availability probe for the test suite.

DRY home for the two probes that previously lived inline in
``tests/smoke/test_slice4_graduation.py`` and
``tests/integration/test_alfred_core_image_bwrap.py``. The root
``tests/conftest.py`` collection hook also consumes it to auto-skip
``docker``-marked tests on a daemon-less runner (the macOS / Windows CI
legs), which is what lets ``tests/unit`` run on those platforms instead of
erroring at Testcontainers fixture setup.

The probe is bounded (a misconfigured Docker context can make the CLI hang)
and cached so a session pays the subprocess cost once. Tests that exercise
the probe itself must call ``docker_unavailable_reason.cache_clear()`` first.
"""

from __future__ import annotations

import shutil
import subprocess
from functools import lru_cache

_PROBE_TIMEOUT_S = 10.0


@lru_cache(maxsize=1)
def docker_unavailable_reason() -> str | None:
    """Return ``None`` when a Docker daemon is reachable, else a short reason.

    The reason string keeps flaky-daemon vs absent-daemon distinguishable in
    CI logs (PR #217 error-reviewer closure). Probes the SERVER (not just the
    client) via ``docker version --format {{.Server.Version}}`` so a present
    CLI with no daemon still reports unavailable.
    """
    if shutil.which("docker") is None:
        return "docker binary not on PATH"
    try:
        proc = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            check=False,
            timeout=_PROBE_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return f"docker version probe timed out after {_PROBE_TIMEOUT_S:.0f}s (daemon hung?)"
    except OSError as exc:
        return f"docker version probe raised OSError: {exc}"
    if proc.returncode != 0:
        return (
            f"docker version probe exit {proc.returncode}: {proc.stderr.decode(errors='replace')!r}"
        )
    return None


def docker_available() -> bool:
    """``True`` iff a Docker daemon is reachable (thin wrapper over the reason)."""
    return docker_unavailable_reason() is None

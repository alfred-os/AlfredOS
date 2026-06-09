"""Integration test: ``alfred-core`` image actually ships a working ``bwrap``.

PR #213 reviewer-fleet convergence (devops + test + security): the
unit-test suite at ``tests/unit/test_dockerfile_bubblewrap_present.py``
only string-greps the Dockerfile. A typo, mirror change, or distro pin
to a pre-0.5.0 bwrap would all silently pass static checks and break
PR-S4-6 round-2 closure 5's fd-3 provider-key inheritance at production
spawn time.

This integration test builds the ``alfred-core`` image and asserts:

1. ``bwrap --version`` exits 0 (the binary is on PATH).
2. The version string starts with ``bubblewrap`` (not a stub /
   uninstalled).
3. ``bwrap --help`` mentions at least one ``--*-fd`` flag from the
   fd-handling family — the PR-S4-6 launcher needs SOME mechanism for
   passing the provider key into the sandbox via fd. Bookworm bwrap
   0.8.0 ships ``--bind-fd`` / ``--ro-bind-fd`` / ``--keep-fd`` (which
   the launcher uses for the fd-3 provider-key pattern). A future
   bwrap that strips ALL fd-handling flags would silently break that
   pattern; this test catches it.

The build + 3 ``docker run`` invocations cost ~30 s on a warm cache.
Marker: ``integration`` + ``docker``. Skips gracefully when docker is
unavailable (e.g. macOS CI matrix step that doesn't expose docker).
"""

# ruff: noqa: S603, S607
# Test-controlled invocations of `docker` from the integration suite.
# S603 (subprocess-call-from-untrusted-input) and S607 (partial-executable-path)
# do not apply: every argv is a tuple literal authored in this test module;
# nothing crosses an untrusted boundary.

from __future__ import annotations

import shutil
import subprocess

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.docker]


def _docker_unavailable_reason() -> str | None:
    """Return None when docker is usable, else a short reason string.

    PR #217 error-reviewer closure: surface WHY docker is unreachable
    so flaky-daemon vs absent-daemon are distinguishable in CI logs.
    """
    if shutil.which("docker") is None:
        return "docker binary not on PATH"
    try:
        proc = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return "docker version probe timed out after 10s (daemon hung?)"
    except OSError as exc:
        return f"docker version probe raised OSError: {exc}"
    if proc.returncode != 0:
        return (
            f"docker version probe exit {proc.returncode}: {proc.stderr.decode(errors='replace')!r}"
        )
    return None


_IMAGE_TAG = "alfred-os-test:slice-4-comp-f"
_DOCKERFILE = "docker/alfred-core.Dockerfile"


@pytest.fixture(scope="module")
def alfred_core_image() -> str:
    """Build the ``alfred-core`` image once per module; yield the image tag."""
    reason = _docker_unavailable_reason()
    if reason is not None:
        pytest.skip(f"docker daemon unavailable: {reason}")
    build = subprocess.run(
        [
            "docker",
            "build",
            "-t",
            _IMAGE_TAG,
            "-f",
            _DOCKERFILE,
            ".",
        ],
        capture_output=True,
        check=False,
        timeout=900,  # cold build can take >5 minutes on slow CI
    )
    if build.returncode != 0:
        stdout = build.stdout.decode(errors="replace")
        stderr = build.stderr.decode(errors="replace")
        # PR #217 test-engineer closure: distinguish builder-stage (uv sync)
        # vs runtime-stage (apt-get bubblewrap) failures so the operator
        # sees the right thing to fix first.
        combined = stdout + stderr
        if "uv sync" in combined:
            stage_hint = "BUILDER STAGE (uv sync)"
        elif "apt-get install" in combined and "bubblewrap" in combined:
            stage_hint = "RUNTIME STAGE (apt-get bubblewrap)"
        else:
            stage_hint = "UNKNOWN STAGE"
        pytest.fail(f"docker build failed [{stage_hint}]:\nstdout:\n{stdout}\nstderr:\n{stderr}")
    return _IMAGE_TAG


@pytest.fixture(scope="module", autouse=True)
def _cleanup_image_after_module() -> object:
    """Remove the built image after the module finishes.

    PR #217 test-engineer closure: avoid disk leak on persistent CI
    runners. Ephemeral runners short-circuit the cleanup via early
    exit; the ``docker rmi -f`` is best-effort and never fails the
    test session.
    """
    yield
    subprocess.run(
        ["docker", "rmi", "-f", _IMAGE_TAG],
        capture_output=True,
        check=False,
        timeout=30,
    )


def _run_in_image(tag: str, *cmd: str) -> subprocess.CompletedProcess[bytes]:
    """Run a command inside the image; return the completed process.

    Uses the same non-root ``alfred`` user the container declares so the
    test exercises the same UID the launcher will use in production.
    """
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/bin/sh",
            tag,
            "-c",
            " ".join(cmd),
        ],
        capture_output=True,
        check=False,
        timeout=30,
    )


def test_bwrap_binary_runs_in_alfred_core_image(
    alfred_core_image: str,
) -> None:
    """``bwrap --version`` exits 0 inside the built image."""
    result = _run_in_image(alfred_core_image, "bwrap", "--version")
    assert result.returncode == 0, (
        f"bwrap --version failed in {alfred_core_image}; "
        f"stderr: {result.stderr.decode(errors='replace')!r}"
    )


def test_bwrap_version_is_bubblewrap_not_stub(
    alfred_core_image: str,
) -> None:
    """``bwrap --version`` output names ``bubblewrap`` (not a stub binary).

    PR #217 error-reviewer closure: assert ``returncode == 0`` BEFORE
    parsing stdout so a broken bwrap surfaces as the real exit-code +
    stderr signal rather than a confusing string-mismatch assertion.
    """
    result = _run_in_image(alfred_core_image, "bwrap", "--version")
    assert result.returncode == 0, (
        f"bwrap --version exited {result.returncode}; "
        f"stderr: {result.stderr.decode(errors='replace')!r}"
    )
    stdout = result.stdout.decode(errors="replace").lower()
    assert "bubblewrap" in stdout, f"bwrap --version output does not name bubblewrap: {stdout!r}"


def test_bwrap_provides_keep_fd_for_fd3_inheritance(
    alfred_core_image: str,
) -> None:
    """``bwrap --help`` lists ``--keep-fd`` — the load-bearing flag.

    PR-S4-6's launcher inherits fd 3 (the provider key) into the
    sandbox. ``--keep-fd FD`` ("Do not close fd FD") keeps the
    inherited fd open for the sandboxed child to read; it is present
    since bubblewrap 0.5.0 and still current in 0.9.0. ``--sync-fd`` is
    a DIFFERENT flag — bwrap's internal sync-protocol fd — which bwrap
    consumes/closes and must NOT be used for key delivery (corrects the
    issue #218 misdiagnosis; see ADR-0015).

    Asserts BOTH the inheritance flag AND at least one bind-family
    flag so a future bwrap that strips them silently breaks the build,
    not first-spawn production.
    """
    result = _run_in_image(alfred_core_image, "bwrap", "--help")
    assert result.returncode == 0, (
        f"bwrap --help exited {result.returncode}; "
        f"stderr: {result.stderr.decode(errors='replace')!r}"
    )
    help_text = result.stdout.decode(errors="replace")
    assert "--keep-fd" in help_text, (
        "bwrap missing --keep-fd — PR-S4-6 fd-3 provider-key "
        f"inheritance contract cannot hold. help text:\n{help_text}"
    )
    # bind-fd family corroborates the fd-handling vocabulary; one being
    # present without the other suggests a custom bwrap fork.
    bind_flags = ("--bind", "--ro-bind", "--dev-bind")
    found_bind = [f for f in bind_flags if f in help_text]
    assert found_bind, (
        f"bwrap missing all of {bind_flags}; launcher needs bind-mount "
        "vocabulary for policy file mounts"
    )

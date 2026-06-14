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
3. fd 3 is INHERITED into the sandbox with NO bwrap CLI flag. The
   launcher passes the provider key over fd 3 by relying on bwrap's
   default fd inheritance (open, non-CLOEXEC fds flow into the child).
   This test proves it empirically: it spawns ``bwrap ... -- python -c
   'os.read(3, ...)'`` with the read end of a pipe placed on fd 3 and a
   known marker written to it, then asserts the sandboxed process reads
   that marker. No ``--sync-fd`` / ``--keep-fd`` flag is used (#218 /
   ADR-0015 — ``--sync-fd`` is bwrap's internal sync fd and would
   CONSUME fd 3). A future bwrap that broke default fd inheritance would
   fail this test at build time, not at production first-spawn.

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


# The marker the sandboxed child must read back off fd 3. 16 bytes mirrors a
# real provider-key length (the docker-bwrap repro that root-caused #229 used
# ``key=len16``). ASCII-only so it survives the shell here-string round-trip.
_FD3_MARKER = "fd3-key-marker16"


def test_bwrap_inherits_fd3_into_sandbox_without_flag(
    alfred_core_image: str,
) -> None:
    """fd 3 is inherited into the bwrap sandbox with NO CLI flag (#218).

    PR-S4-6's launcher delivers the quarantined provider key over fd 3 by
    relying on bwrap's DEFAULT fd inheritance: open, non-CLOEXEC fds flow
    into the sandboxed child. No ``--sync-fd`` / ``--keep-fd`` flag is used
    (``--sync-fd`` is bwrap's internal sync fd and would CONSUME fd 3, so the
    child's ``os.read(3)`` would raise EBADF — root-caused in PR #229 against
    bubblewrap 0.8.0 (the Bookworm image) and 0.9.0).

    This is the empirical, image-level proof of that contract: a marker is
    written onto fd 3, ``bwrap`` is exec'd with the production-shaped
    isolation flags (binds + unshares + ``--dev`` + ``--die-with-parent``) and
    NO fd flag, and the sandboxed ``python`` reads the marker back off fd 3.
    """
    # Inside the container: open fd 3 onto a here-string carrying the marker,
    # then exec bwrap (no fd flag) running python that reads fd 3 and echoes
    # it. bwrap's default inheritance must carry fd 3 through to the child.
    #   exec 3< <(printf %s MARKER)   -- place the read end on fd 3
    #   bwrap <isolation flags> -- python -c 'os.write(1, os.read(3, 64))'
    # ``/lib64`` is bound ONLY when it exists: amd64 Debian keeps its dynamic
    # linker (``ld-linux-x86-64.so.2``) under ``/lib64`` and python3 cannot exec
    # without it, but arm64 Debian has NO ``/lib64`` — its linker lives in
    # ``/lib`` (already bound). An unconditional ``--ro-bind /lib64`` fails on
    # arm64 with "Can't find source path /lib64". This mirrors the production
    # launcher, which binds ``/usr`` (and only existing prefixes), never a
    # hard-coded ``/lib64`` — so the test stays arch-portable across the CI
    # matrix instead of being amd64-only.
    inner = (
        f"exec 3< <(printf %s {_FD3_MARKER}); "
        "bwrap "
        "--ro-bind /usr /usr --ro-bind /lib /lib "
        "$([ -e /lib64 ] && printf -- '--ro-bind /lib64 /lib64 ') "
        "--ro-bind /bin /bin --proc /proc --dev /dev "
        "--unshare-pid --unshare-uts --unshare-ipc --unshare-cgroup "
        "--die-with-parent "
        "-- python3 -c "
        "'import os,sys; sys.stdout.write(os.read(3, 64).decode())'"
    )
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            # bwrap needs an unprivileged userns; ubuntu-latest's default
            # seccomp/apparmor can block it. --privileged keeps this proof
            # host-independent (it only exercises bwrap's fd inheritance,
            # not isolation strength — that is the resolver test's job).
            "--privileged",
            "--entrypoint",
            "/bin/bash",
            alfred_core_image,
            "-c",
            inner,
        ],
        capture_output=True,
        check=False,
        timeout=60,
    )
    stdout = result.stdout.decode(errors="replace")
    stderr = result.stderr.decode(errors="replace")
    assert result.returncode == 0, (
        f"bwrap fd-3 inheritance run exited {result.returncode}; stderr: {stderr!r}"
    )
    assert _FD3_MARKER in stdout, (
        "sandboxed process did not read the fd-3 marker back — bwrap's default "
        f"fd inheritance is broken (no flag should be needed). stdout: {stdout!r} "
        f"stderr: {stderr!r}"
    )

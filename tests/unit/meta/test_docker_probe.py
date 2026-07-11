"""Unit tests for the shared Docker-availability probe."""

from __future__ import annotations

import subprocess
from collections.abc import Iterator

import pytest

from tests import _docker_probe
from tests._docker_probe import docker_available, docker_unavailable_reason


@pytest.fixture(autouse=True)
def _clear_probe_cache() -> Iterator[None]:
    """The probe is lru_cache'd; clear on BOTH sides so a monkeypatched value from
    one test can't bleed into the smoke/integration probes later in the session."""
    docker_unavailable_reason.cache_clear()
    yield
    docker_unavailable_reason.cache_clear()


def test_reason_when_binary_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_docker_probe.shutil, "which", lambda _name: None)
    assert docker_unavailable_reason() == "docker binary not on PATH"
    docker_unavailable_reason.cache_clear()
    assert docker_available() is False


def test_reason_none_when_daemon_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_docker_probe.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(
        _docker_probe.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 0, b"27.0.0", b""),
    )
    assert docker_unavailable_reason() is None
    docker_unavailable_reason.cache_clear()
    assert docker_available() is True


def test_reason_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_docker_probe.shutil, "which", lambda _name: "/usr/bin/docker")

    def _raise_timeout(*_a: object, **_k: object) -> object:
        raise subprocess.TimeoutExpired(cmd=["docker"], timeout=10.0)

    monkeypatch.setattr(_docker_probe.subprocess, "run", _raise_timeout)
    reason = docker_unavailable_reason()
    assert reason is not None
    assert "timed out" in reason


def test_reason_on_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_docker_probe.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(
        _docker_probe.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 1, b"", b"Cannot connect"),
    )
    reason = docker_unavailable_reason()
    assert reason is not None
    assert "exit 1" in reason


def test_reason_on_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_docker_probe.shutil, "which", lambda _name: "/usr/bin/docker")

    def _raise_oserror(*_a: object, **_k: object) -> object:
        raise OSError("boom")

    monkeypatch.setattr(_docker_probe.subprocess, "run", _raise_oserror)
    reason = docker_unavailable_reason()
    assert reason is not None
    assert "OSError" in reason

"""Verify Settings.policies_path defaults + override behaviour (CR #6, #174).

The daemon boot snapshot-ref probe resolves the policies file from
``Settings.policies_path`` (anchored at the documented ``/etc/alfred``
runtime-config root) rather than a fragile CWD-relative
``config/policies.yaml`` read.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from alfred.config.settings import Settings


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Linux-only: hardcoded /etc/alfred runtime-config root "
    "(AlfredOS is a Linux-only runtime; the default anchors at a POSIX "
    "absolute path)",
)
def test_policies_path_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default anchors at /etc/alfred/policies.yaml — never CWD-relative."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    monkeypatch.delenv("ALFRED_POLICIES_PATH", raising=False)
    settings = Settings()
    assert settings.policies_path == Path("/etc/alfred/policies.yaml")
    assert settings.policies_path.is_absolute()


def test_policies_path_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """ALFRED_POLICIES_PATH env var overrides the default (dev checkout case)."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    monkeypatch.setenv("ALFRED_POLICIES_PATH", str(tmp_path / "alt-policies.yaml"))
    settings = Settings()
    assert settings.policies_path == tmp_path / "alt-policies.yaml"

"""Executable counterparts to the sbx-2026-* sandbox-escape payloads (PR-S4-6).

The YAML payloads are density- + schema-validated elsewhere, but neither
EXERCISES the runtime defence. This module loads each PR-S4-6 payload and
drives the REAL launcher / manifest parser / fd-3 delivery / session
handshake, asserting the declared ``expected_outcome`` actually fires at the
trust boundary — not just a Pydantic refusal at parse time.

PR-S4-7 ships the kernel-observable bwrap-escape payloads (filesystem,
network, process-fork); those need the real policy bytes to be meaningful.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from alfred.plugins.errors import (
    ManifestSandboxMissingError,
    SandboxInfoHandshakeMismatch,
)
from alfred.plugins.manifest import parse_manifest
from alfred.plugins.manifest_reader import PolicyRefEscapesRoot, resolve_policy_ref
from alfred.plugins.session import AlfredPluginSession
from alfred.supervisor.fd3_key_delivery import (
    ProviderKeyDeliveryError,
    deliver_provider_key_via_fd3,
)
from tests.adversarial.payload_schema import AdversarialPayload

_DIR = Path(__file__).parent
_REPO_ROOT = Path(__file__).resolve().parents[3]
_LAUNCHER = _REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"
_HAS_JQ = shutil.which("jq") is not None


def _load(payload_id: str) -> AdversarialPayload:
    path = next(_DIR.glob(f"{payload_id.replace('-', '_')}*.yaml"))
    return AdversarialPayload.model_validate(yaml.safe_load(path.read_text()))


def _run_launcher(manifest_body: str, *, environment: str, tmp_path: Path) -> tuple[int, str]:
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(manifest_body)
    stub = tmp_path / "stub.sh"
    stub.write_text("#!/bin/sh\nexit 0\n")
    stub.chmod(0o755)
    proc = subprocess.run(  # noqa: S603 — repo-owned launcher script path
        [str(_LAUNCHER), "attacker.example", str(stub)],
        capture_output=True,
        text=True,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(_REPO_ROOT / "src"),
            "ALFRED_ENVIRONMENT": environment,
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
            "FAKE_UNAME": "Linux",
        },
        check=False,
    )
    return proc.returncode, proc.stderr


def test_sbx_2026_001_sandbox_block_missing(tmp_path: Path) -> None:
    payload = _load("sbx-2026-001")
    assert payload.expected_outcome == "refused"
    # Parser-level: the missing block raises the dedicated error.
    with pytest.raises(ManifestSandboxMissingError):
        parse_manifest(payload.payload["manifest_toml"])
    # Launcher-level (the real subprocess): refuses with the audit reason.
    if _HAS_JQ:
        rc, stderr = _run_launcher(
            payload.payload["manifest_toml"], environment="production", tmp_path=tmp_path
        )
        assert rc != 0
        assert "sandbox_block_missing" in stderr


@pytest.mark.skipif(not _HAS_JQ, reason="jq required for the launcher branch")
def test_sbx_2026_002_kind_stub_in_production(tmp_path: Path) -> None:
    payload = _load("sbx-2026-002")
    assert payload.expected_outcome == "refused"
    rc, stderr = _run_launcher(
        payload.payload["manifest_toml"], environment="production", tmp_path=tmp_path
    )
    assert rc != 0
    assert "windows_stub_in_production" in stderr


def test_sbx_2026_007_policy_ref_traversal_refused(tmp_path: Path) -> None:
    payload = _load("sbx-2026-007")
    assert payload.expected_outcome == "refused"
    (tmp_path / "config" / "sandbox").mkdir(parents=True)
    with pytest.raises(PolicyRefEscapesRoot) as exc_info:
        resolve_policy_ref(payload.payload["policy_ref"], install_root=tmp_path)
    assert exc_info.value.reason == "policy_ref_escapes_root"


def test_sbx_2026_008_fd3_partial_write_refused() -> None:
    payload = _load("sbx-2026-008")
    assert payload.expected_outcome == "refused"
    from unittest.mock import patch

    read_fd, write_fd = os.pipe()
    try:
        # Simulate a short write: writev returns fewer bytes than the frame.
        with patch(
            "alfred.supervisor.fd3_key_delivery.os.writev",
            return_value=struct.calcsize(">I"),  # only the prefix made it
        ):
            with pytest.raises(ProviderKeyDeliveryError) as exc_info:
                deliver_provider_key_via_fd3(write_fd=write_fd, key="sk-truncated")
            assert exc_info.value.reason == "provider_key_delivery_failed"
    finally:
        os.close(read_fd)
        with pytest.raises(OSError):
            os.close(write_fd)  # already closed by the refusal path


@pytest.mark.asyncio
async def test_sbx_2026_009_sandbox_info_lie_quarantined() -> None:
    payload = _load("sbx-2026-009")
    assert payload.expected_outcome == "quarantined"
    audit = MagicMock()
    audit.calls = []

    async def _append(**kwargs):
        audit.calls.append(kwargs)

    audit.append_schema = AsyncMock(side_effect=_append)
    gate = MagicMock()
    gate.check_plugin_load = MagicMock(return_value=True)
    transport = MagicMock()
    transport.kill = AsyncMock(return_value=True)

    manifest = """
[alfred]
manifest_version = 1
[plugin]
id = "attacker.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
[sandbox]
kind = "none"
"""
    session = await AlfredPluginSession.create(
        manifest_raw=manifest, audit_writer=audit, gate=gate, transport=transport
    )
    await session._on_handshake_complete()
    with pytest.raises(SandboxInfoHandshakeMismatch):
        await session._on_post_handshake_method(
            "sandbox_info",
            {"effective_sandbox_kind": payload.payload["reported_effective_sandbox_kind"]},
        )
    transport.kill.assert_awaited_once()
    assert audit.calls[-1]["event"] == "plugin.lifecycle.quarantined"


def test_all_pr_s4_6_payloads_load() -> None:
    # Every PR-S4-6 sbx payload schema-validates + carries the sbx prefix.
    ids = [
        "sbx-2026-001",
        "sbx-2026-002",
        "sbx-2026-007",
        "sbx-2026-008",
        "sbx-2026-009",
    ]
    for pid in ids:
        payload = _load(pid)
        assert payload.id == pid
        assert payload.category == "sandbox_escape"

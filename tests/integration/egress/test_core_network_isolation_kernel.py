"""G7-3 (Spec C §4.2, ADR-0042): the kernel enforcement-of-record for the
connectivity-free core.

The static compose-invariant tests prove the compose file DECLARES the isolation
(alfred-core on alfred_internal-only; alfred_internal internal:true). This proves the
Docker `internal: true` PRIMITIVE actually blocks egress + DNS while leaving the internal
plane reachable — the two together close the chain "the core cannot egress."

Deterministic by construction (required-lane flake discipline, rev-003): reuses the
already-present `postgres:16` image (no anonymous Docker Hub pull), drives probes with
bash primitives, bounds every probe with `timeout`, and tears down in a finally.
"""

from __future__ import annotations

import shutil
import subprocess
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None,
    reason=(
        "docker CLI required for the connectivity-free-core kernel proof "
        "(Integration lane / local OrbStack)"
    ),
)

_IMAGE = "postgres:16"  # already pulled by testcontainers in the Integration lane


def _run(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
    )


def test_internal_network_blocks_egress_and_dns() -> None:
    suffix = uuid.uuid4().hex[:10]
    net = f"alfred_g73_isolation_{suffix}"
    sibling = f"alfred_g73_sibling_{suffix}"

    created_net = _run("network", "create", "--internal", net)
    assert created_net.returncode == 0, f"network create failed: {created_net.stderr}"
    try:
        sib = _run(
            "run", "-d", "--name", sibling, "--network", net,
            "--entrypoint", "sleep", _IMAGE, "300",
        )
        assert sib.returncode == 0, f"sibling start failed: {sib.stderr}"

        # One probe container, three checks. Each line prints a stable marker.
        script = (
            'if timeout 5 bash -c "echo > /dev/tcp/1.1.1.1/443" 2>/dev/null; '
            "then echo EXTERNAL_CONNECT_OK; else echo EXTERNAL_CONNECT_BLOCKED; fi; "
            "if getent hosts api.deepseek.com >/dev/null 2>&1; "
            "then echo EXTERNAL_DNS_OK; else echo EXTERNAL_DNS_BLOCKED; fi; "
            f"if getent hosts {sibling} >/dev/null 2>&1; "
            "then echo SIBLING_DNS_OK; else echo SIBLING_DNS_BLOCKED; fi"
        )
        probe = _run(
            "run", "--rm", "--network", net,
            "--entrypoint", "bash", _IMAGE, "-c", script,
        )
        out = probe.stdout
        assert "EXTERNAL_CONNECT_BLOCKED" in out, f"core could reach the internet: {out!r}"
        assert "EXTERNAL_DNS_BLOCKED" in out, f"core could resolve an external name (DNS hole): {out!r}"
        assert "SIBLING_DNS_OK" in out, f"internal plane over-blocked (sibling unreachable): {out!r}"
    finally:
        _run("rm", "-f", sibling, timeout=30)
        _run("network", "rm", net, timeout=30)

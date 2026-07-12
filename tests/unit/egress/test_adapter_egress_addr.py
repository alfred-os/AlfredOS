import sys

import pytest

from alfred.egress.adapter_egress_addr import (
    DISCORD_EGRESS_SHIM_PORT,
    DISCORD_EGRESS_SOCKET_PATH,
    discord_proxy_url,
)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Linux-only: DISCORD_EGRESS_SOCKET_PATH is a hardcoded Linux-container "
    "path; WindowsPath str() renders it with backslashes",
)
def test_socket_path_is_gateway_only_not_runtime_dir():
    # devops-001: the egress socket must NOT live under ~/.run/alfred (the alfred_run
    # volume, which is mounted into BOTH core and gateway).
    assert ".run/alfred" not in str(DISCORD_EGRESS_SOCKET_PATH)
    assert str(DISCORD_EGRESS_SOCKET_PATH).endswith("/discord/egress.sock")


def test_proxy_url_uses_shim_port_and_http_scheme():
    assert discord_proxy_url() == f"http://127.0.0.1:{DISCORD_EGRESS_SHIM_PORT}"

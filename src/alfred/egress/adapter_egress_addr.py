"""Single source of truth for the Discord egress bridge address (Spec C G7-4, #333).

The socket lives on a GATEWAY-ONLY volume (``alfred_discord_egress``), NEVER on
``alfred_run`` / ``runtime_dir()`` (``~/.run/alfred``) — that volume is mounted into BOTH
the connectivity-free core AND the gateway, and an AF_UNIX *pathname* socket is
filesystem-namespace-scoped (NOT gated by ``internal:true``), so a socket there would let
the core reach the Discord egress proxy and reopen G7-3 / HARD-#9 (devops-001).

ONE constant each for the path (gateway bind / bwrap target / shim connect) and the shim
port (shim listen / bot ``proxy=`` URL) so the three sites can never skew.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

# Gateway-only mount (see docker-compose.yaml: alfred_discord_egress -> /home/alfred/.egress,
# mounted into alfred-gateway ONLY). The bwrap policy rw-binds the parent dir into the child
# (--bind, not --ro-bind; connect(2) on a UNIX-domain socket requires write permission on the
# socket file — a read-only bind fails EACCES; see FIX-5 in ADR-0043).
DISCORD_EGRESS_SOCKET_PATH: Final[Path] = Path("/home/alfred/.egress/discord/egress.sock")
DISCORD_EGRESS_SHIM_PORT: Final[int] = 8891


def discord_proxy_url() -> str:
    """The in-child shim URL discord.py dials (scheme pinned to ``http://``)."""
    return f"http://127.0.0.1:{DISCORD_EGRESS_SHIM_PORT}"


__all__ = ["DISCORD_EGRESS_SHIM_PORT", "DISCORD_EGRESS_SOCKET_PATH", "discord_proxy_url"]

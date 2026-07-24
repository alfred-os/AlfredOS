"""Isolated env-file for the e2e boot lane.

Written under a temp dir and passed to compose via ``--env-file`` so a local run NEVER
runs ``cp .env.example .env`` over an operator's real ``.env`` or shares their volumes
(test-004). Keys are self-identifying sentinels (sec-002).
"""

from __future__ import annotations

import secrets
from pathlib import Path

E2E_PROJECT_NAME = "alfred-e2e"
DUMMY_KEY_SENTINEL = "sk-DUMMY-e2e-not-a-real-key"


def write_e2e_env_file(dest_dir: Path) -> Path:
    """Write ``<dest_dir>/e2e.env`` (per-run random GF password + dummy keys); return it."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    env_path = dest_dir / "e2e.env"
    lines = (
        f"GF_SECURITY_ADMIN_PASSWORD={secrets.token_hex(24)}",
        f"ALFRED_DEEPSEEK_API_KEY={DUMMY_KEY_SENTINEL}",
        f"ALFRED_QUARANTINE_PROVIDER_API_KEY={DUMMY_KEY_SENTINEL}",
    )
    env_path.write_text("\n".join(lines) + "\n")
    env_path.chmod(0o600)
    return env_path

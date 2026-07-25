"""Isolated env-file for the e2e boot lane.

Written under a temp dir and passed to compose via ``--env-file`` so a local run NEVER
runs ``cp .env.example .env`` over an operator's real ``.env`` or shares their volumes
(test-004). Keys are self-identifying sentinels (sec-002).
"""

from __future__ import annotations

import secrets
from pathlib import Path

E2E_PROJECT_PREFIX = "alfred-e2e"
DUMMY_KEY_SENTINEL = "sk-DUMMY-e2e-not-a-real-key"


def new_project_name() -> str:
    """A per-run-unique isolated compose project name.

    Unique per run so concurrent/re-entrant LOCAL runs never share Docker Compose labels — one
    run's ``down -v`` would otherwise tear down another's containers/volumes (CR). Mirrors the
    smoke suite's suffixed-project pattern.
    """
    return f"{E2E_PROJECT_PREFIX}-{secrets.token_hex(4)}"


def scrub_env_secrets(text: str, env_file: Path) -> str:
    """Redact this env-file's injected values (per-run Grafana password + dummy sentinel keys)
    from captured text before it lands in a failure-uploaded artifact (sec-003)."""
    for line in env_file.read_text().splitlines():
        _, sep, value = line.partition("=")
        value = value.strip()
        if sep and value:
            text = text.replace(value, "***REDACTED***")
    return text


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

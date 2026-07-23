"""Verify `.env.example` ships a safe, uncommented ALFRED_ENVIRONMENT (#469 Task 6).

sec-002 gates production safety refusals on ALFRED_ENVIRONMENT. `.env.example`
is auto-copied to `.env` by `bin/alfred-setup.sh` on first run, and
docker-compose reads it as `${ALFRED_ENVIRONMENT:-production}` — so an
uncommented non-production value here would silently downgrade the compose
stack for every fresh operator. This test pins the line to exactly
`ALFRED_ENVIRONMENT=production`, uncommented, so a future edit can't
regress that safety property without failing CI.
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_ENV_EXAMPLE_PATH = _REPO_ROOT / ".env.example"


def test_env_example_environment_is_production() -> None:
    """`.env.example`'s ALFRED_ENVIRONMENT line is uncommented `production`."""
    lines = _ENV_EXAMPLE_PATH.read_text(encoding="utf-8").splitlines()
    # M-8 (final-review): a bare `next(...)` with no default raises an opaque
    # `StopIteration` (pytest reports it as an unhandled error, not a readable
    # assertion failure) if a future edit removes the ALFRED_ENVIRONMENT line
    # entirely. `default=None` + an explicit assert gives a clear failure message
    # naming exactly what went missing.
    environment_line = next(
        (entry for entry in lines if entry.strip().startswith("ALFRED_ENVIRONMENT=")),
        None,
    )
    assert environment_line is not None, (
        "no ALFRED_ENVIRONMENT= line found in .env.example — "
        "sec-002 depends on it shipping uncommented and set to production"
    )
    assert environment_line.strip() == "ALFRED_ENVIRONMENT=production"

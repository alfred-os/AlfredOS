"""README <-> setup.sh credential-gate consistency (#501).

An operator following the README quickstart must set every credential the gate requires.
#501 fixed a drift where the README documented only ALFRED_QUARANTINE_PROVIDER_API_KEY while
the gate ALSO rejects a missing/placeholder ALFRED_DEEPSEEK_API_KEY, so a literal
README-follower hit exit 1 having provisioned nothing. Durable drift-net: every credential
the gate flags must appear in README.md. Parse-only — no bash, no Docker.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests._setup_script_helpers import slice_shell_step

_SETUP_SH = Path("bin/alfred-setup.sh")
_README = Path("README.md")
_GATE_STEP = "Validating .env credentials"
# A credential the gate REQUIRES is one named in an ``add_config_problem "..."`` message: its
# absence/placeholder is what pushes it into the accumulated failure report. Match ANY
# ALFRED_* token on those lines (not just *_API_KEY) so a future non-API credential (e.g. a
# token) added to the gate is caught by the drift-net too (test-review M1).
_CRED_RE = re.compile(r"ALFRED_[A-Z0-9_]+")


def _gate_required_credentials() -> set[str]:
    block = slice_shell_step(_SETUP_SH, _GATE_STEP)
    creds: set[str] = set()
    for line in block.splitlines():
        # Only actual `add_config_problem "..."` CALLS name a required credential — skip comment
        # lines (a `#`-prefixed line that merely mentions the helper) so a documented rationale
        # can't be misread as a gate requirement (CodeRabbit).
        if line.lstrip().startswith("#"):
            continue
        if "add_config_problem" in line:
            creds.update(_CRED_RE.findall(line))
    return creds


def test_gate_requires_at_least_the_two_known_keys() -> None:
    # Anti-vacuous floor: if the slice/marker heuristic ever matches nothing, the consistency
    # test would pass trivially. Pin the known floor.
    assert {"ALFRED_DEEPSEEK_API_KEY", "ALFRED_QUARANTINE_PROVIDER_API_KEY"} <= (
        _gate_required_credentials()
    )


def test_readme_documents_every_gate_required_credential() -> None:
    readme = _README.read_text()
    missing = sorted(c for c in _gate_required_credentials() if c not in readme)
    assert not missing, (
        f"README.md does not document credential(s) the setup.sh gate requires: {missing}. "
        f"A first-run operator following the README would hit the gate's exit 1. Document them "
        f"in the quickstart (#501)."
    )

"""Shared helper for AST-scan boundary-enforcement tests.

Two tests share this helper:

* ``tests/unit/security/test_no_direct_env_reads.py`` (PR C) — env-read
  category; remediation pointer at ADR-0012.
* ``tests/unit/comms/test_no_direct_adapter_imports.py`` (PR D1) — adapter-
  import category; remediation pointer at ADR-0009.

Failure-message shape is identical across both so a developer who sees one
recognises the other. te-004 deliverable.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Literal, NamedTuple


class ImportViolation(NamedTuple):
    """One offending AST hit located during a boundary-enforcement scan."""

    file: Path
    lineno: int
    symbol: str
    category: Literal["env_read", "adapter_import"]


def _remediation_message(violations: Sequence[ImportViolation]) -> str:
    """Render a multi-line failure message for a set of import violations.

    Format: a header line, one stanza per violation (``file:line: 'symbol' —
    remediation``), and a trailing one-line summary count. The remediation
    pointer is category-specific:

    * ``env_read`` → "secrets must be read via ``broker.get(...)``; see ADR-0012".
    * ``adapter_import`` → "consume the ``CommsAdapter`` Protocol from
      ``src/alfred/comms/adapter.py``; see ADR-0009".
    """
    if not violations:
        return "Import violations found:\n  (none)\n  0 total"
    lines = ["Import violations found:"]
    for v in violations:
        if v.category == "env_read":
            hint = "secrets must be read via `broker.get(...)`; see ADR-0012"
        else:  # adapter_import
            hint = (
                "consume the `CommsAdapter` Protocol from "
                "`src/alfred/comms/adapter.py`; see ADR-0009"
            )
        lines.append(f"  {v.file}:{v.lineno}: '{v.symbol}' — {hint}")
    lines.append(f"  {len(violations)} total")
    return "\n".join(lines)

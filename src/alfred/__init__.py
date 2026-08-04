"""AlfredOS.

The CPython floor is enforced HERE, at package import, because `pyproject.toml`
declares a series-level `requires-python` so Dependabot can resolve it (#568,
ADR-0061). Keep this module's import closure minimal: it is inside the
ADR-0030-bounded quarantine-child reachable surface, and
`tests/unit/security/test_quarantine_child_import_closure.py` measures it.
"""

from __future__ import annotations

import sys

from alfred._python_floor import enforce, enforce_implementation

enforce(sys.version_info[:3])
enforce_implementation(sys.implementation.name)

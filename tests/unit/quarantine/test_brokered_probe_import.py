"""Module-scope coverage proof for the wheel-co-located probe child (#340 PR2a).

``_brokered_probe.py`` lives under ``src/alfred/security/quarantine_child/``, which
the release-blocking ``--include='src/alfred/security/*' --fail-under=100`` CI gate
globs (``.github/workflows/ci.yml``). Coverage's ``source`` discovers the file
whether or not anything imports it, so an UNIMPORTED module under that glob reads
as 0% covered and fails the gate outright.

The probe's function BODIES (``_write_verdict``, ``_probe_once``, ``main``, the
``if __name__`` guard) are correctly ``# pragma: no cover`` — they are subprocess
entry points only exercisable under the docker bwrap empty-netns (Task 7), mirroring
the ``__main__.py`` subprocess-entry precedent
(``tests/unit/quarantine/test_quarantine_child_loop.py``'s sibling import test). But
the MODULE SCOPE (imports, the ``_CONTROL_FD`` / ``_LITERAL_IP`` constants, the
``def`` statements themselves) is ordinary import-time code with no fd or network
dependency, so a plain import exercises — and covers — it.

This test also proves the sec-007-style import-hygiene contract holds for this
module: importing it must NOT construct the fd-4 socket (that happens only inside
``main()``), so the import must complete promptly with no hang — a hang here would
wedge every future test run, mypy invocation, and IDE language server that imports
the package.
"""

from __future__ import annotations

import alfred.security.quarantine_child._brokered_probe as _brokered_probe


def test_brokered_probe_module_imports_without_touching_fd_4() -> None:
    """Importing the probe module succeeds and exposes ``main`` — no fd-4 socket built."""
    assert hasattr(_brokered_probe, "main")
    assert hasattr(_brokered_probe, "_probe_once")
    assert hasattr(_brokered_probe, "_write_verdict")

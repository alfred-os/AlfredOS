"""Guard the _boot_audit extraction seam (#256 PR-1).

Pins the two invariants a careless move could silently break: the exit-code
contract (2 = refused, 3 = audit-unwritable), and that ``start_daemon`` (in
``_commands``) still catches a ``_BootRefusedError`` RAISED in ``_boot_audit`` —
which holds only if the re-import kept a SINGLE class definition. A second
definition would make ``start_daemon``'s identity-``except`` miss the refusal and
crash with a raw traceback instead of ``typer.Exit`` (a fail-loud regression on
the exit-code contract, sec-004).
"""

from __future__ import annotations

import pytest
import typer

from alfred.cli.daemon import _boot_audit, _commands


def test_exit_code_contract_unchanged() -> None:
    assert _boot_audit._EXIT_REFUSED == 2
    assert _boot_audit._EXIT_AUDIT_UNWRITABLE == 3
    assert _boot_audit._BootRefusedError(_boot_audit._EXIT_REFUSED).code == 2
    assert _boot_audit._BootRefusedError(_boot_audit._EXIT_AUDIT_UNWRITABLE).code == 3


def test_start_daemon_catches_boot_audit_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    # Behavioural single-definition guard: start_daemon catches _BootRefusedError
    # by class identity. Raise the _boot_audit-defined class through the real
    # start_daemon path; if the re-import had produced a second definition,
    # start_daemon would NOT catch it and this would surface the raw exception.
    async def _refuse() -> None:
        raise _boot_audit._BootRefusedError(_boot_audit._EXIT_REFUSED)

    monkeypatch.setattr(_commands, "_start_async", _refuse)
    try:
        _commands.start_daemon()
    except typer.Exit as exit_:
        assert exit_.exit_code == 2
    else:
        raise AssertionError("start_daemon did not raise typer.Exit on refusal")

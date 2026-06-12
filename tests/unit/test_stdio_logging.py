"""``alfred._stdio_logging`` pins stdlib logging to stderr (PR-S4-11c-2b0 BUG-1).

Two AlfredOS subprocess entrypoints speak a machine-readable protocol on stdout:
``alfred.plugins.manifest_reader`` (its stdout is captured by the launcher as
bwrap flags) and ``alfred.security.quarantine_child.__main__`` (its stdout carries
length-prefixed JSON-RPC frames). A stray log line on fd 1 corrupts both wires —
it once became the bwrap exec target. :func:`configure_stderr_logging` makes the
log destination correct *by construction* rather than relying on stdlib's
``lastResort`` default, which any imported module can repoint at stdout.
"""

from __future__ import annotations

import logging
import sys

import pytest

from alfred._stdio_logging import configure_stderr_logging


@pytest.fixture(autouse=True)
def _restore_root_logging() -> object:
    """Snapshot + restore root-logger handlers/level (global mutable state)."""
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    yield
    root.handlers = saved_handlers
    root.setLevel(saved_level)


def test_log_event_goes_to_stderr_not_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    """After configuration, a WARNING lands on stderr; stdout stays empty."""
    configure_stderr_logging()
    logging.getLogger("alfred.test.stdio").warning("locale missing")

    captured = capsys.readouterr()
    assert captured.out == "", "log leaked onto stdout — would corrupt the wire / bwrap flags"
    assert "locale missing" in captured.err


def test_root_handler_is_pinned_to_stderr() -> None:
    """The helper installs a stderr handler and leaves NO handler on stdout.

    (The assertion is "a stderr handler exists + nothing points at stdout" rather
    than "every handler is stderr": pytest's own log-capture plugin installs a
    root handler whose stream is neither, and that is fine — only a *stdout*
    handler would corrupt the entrypoint's machine-readable output.)
    """
    configure_stderr_logging()
    root = logging.getLogger()
    stderr_handlers = [
        h for h in root.handlers if isinstance(h, logging.StreamHandler) and h.stream is sys.stderr
    ]
    assert stderr_handlers, "configure_stderr_logging installed no stderr StreamHandler"
    assert not any(getattr(h, "stream", None) is sys.stdout for h in root.handlers), (
        "a root handler still points at stdout — would corrupt the wire / bwrap flags"
    )


def test_removes_preexisting_stdout_handler() -> None:
    """A handler already pointing at stdout is stripped (the only corrupting stream)."""
    root = logging.getLogger()
    stdout_handler = logging.StreamHandler(sys.stdout)
    root.addHandler(stdout_handler)

    configure_stderr_logging()

    assert stdout_handler not in root.handlers, "a pre-existing stdout handler survived"
    assert not any(getattr(h, "stream", None) is sys.stdout for h in root.handlers)


def test_idempotent_does_not_stack_stderr_handlers() -> None:
    """Repeated calls do not pile up duplicate stderr handlers."""
    configure_stderr_logging()
    after_first = sum(
        1
        for h in logging.getLogger().handlers
        if isinstance(h, logging.StreamHandler) and h.stream is sys.stderr
    )
    configure_stderr_logging()
    after_second = sum(
        1
        for h in logging.getLogger().handlers
        if isinstance(h, logging.StreamHandler) and h.stream is sys.stderr
    )
    assert after_first == after_second, "a second call stacked another stderr handler"


def test_custom_level_is_applied() -> None:
    """The ``level`` kwarg sets the root level (covers the non-default branch)."""
    configure_stderr_logging(level=logging.ERROR)
    assert logging.getLogger().level == logging.ERROR

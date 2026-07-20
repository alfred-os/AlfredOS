"""Boot-ordering + no-echo BEHAVIOURAL gates for the child cutover (#340 PR2b golive).

Override A (rev.2 point 1 / R.2.5): the boot-order proof is a BEHAVIOURAL runtime
call-order spy, NOT a lexical ``src.index()`` assertion. A string-order test cannot
decide runtime order, ignores the pre-``emit_hello`` fd-3 read surface, and would pass
on wrong code (e.g. code that lexically ordered the calls but guarded the wrong one).
These tests drive the child's REAL ``main()`` with the stdio / fd-4 / provider seams
monkeypatched to RECORD their call order, then pin the two security-load-bearing
orderings from §20.3.2:

* the happy path fires ``emit_hello`` -> ``_build_provider`` -> fd-4 control-socket
  reconstruction -> ``_write_boot_ready`` -> the loop, in that runtime order
  (provenance before the factory; the control channel up before the liveness frame
  can lie); and
* attribution: a refuse in the ``[hello, ready)`` window is CHILD-authored
  (``emit_hello`` already fired, so the host sees a hello and will NOT forge a launcher
  ``sandbox_refused`` row), while a pre-``emit_hello`` fd-3 framing refuse writes ZERO
  stdout (a launcher-attributed EOF the host's sec-001 gate reads correctly, never a
  forged row).

Plus the ``_DeterministicProvider`` / ``_echo_extracted_frame`` deletion (an absence
assertion — §16 / §19-B1 must-not-regress: the echo path is gone).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import pytest
import structlog

import alfred.security.quarantine_child.__main__ as child_main
from alfred.security.quarantine_child.brokered_egress import QuarantineChildBootError

_MAIN = Path(child_main.__file__)


def test_pin_structlog_to_stderr_routes_output_to_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    """``_pin_structlog_to_stderr`` configures structlog with a stderr PrintLoggerFactory.

    structlog's DEFAULT PrintLogger writes to stdout, which would corrupt the child's
    fd-1 wire the moment ``drain_leftovers`` (or any child code) emits a structlog line.
    ``structlog.configure`` is monkeypatched so the assertion runs WITHOUT globally
    reconfiguring structlog for the rest of the session (which would break other tests'
    log capture).
    """
    captured: dict[str, Any] = {}

    def _fake_configure(**kwargs: Any) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(structlog, "configure", _fake_configure)
    child_main._pin_structlog_to_stderr()

    factory = captured["logger_factory"]
    assert isinstance(factory, structlog.PrintLoggerFactory)
    assert factory._file is sys.stderr  # the factory's loggers write to stderr, not stdout


def test_no_deterministic_echo_symbols_remain() -> None:
    """The deterministic-echo path is DELETED — no symbol survives, even in a comment.

    §16 / §19-B1 must-not-regress: the cutover removes the host-independent echo so raw
    T3 reaches the REAL provider path. A lingering ``_DeterministicProvider`` /
    ``_echo_extracted_frame`` (even a stale reference) would mean the swap was partial.
    """
    src = _MAIN.read_text(encoding="utf-8")
    assert "_DeterministicProvider" not in src
    assert "_echo_extracted_frame" not in src


def _patch_stdio_seam(monkeypatch: pytest.MonkeyPatch, loop: asyncio.AbstractEventLoop) -> None:
    """Neutralise the asyncio stdin/stdout pipe binding + the spawn-env reads.

    ``sys.stdin`` / ``sys.stdout`` are not real OS pipes under pytest capture, so the
    two ``connect_*_pipe`` coroutines are replaced with fakes returning placeholder
    ``(transport, protocol)`` pairs; ``asyncio.StreamReader`` / ``StreamWriter``
    construct fine against them (no I/O at construction). The write transport carries a
    no-op ``is_closing()`` so ``StreamWriter.__del__`` does not raise on a bare
    ``object()`` at GC time. The spawn-env vars a real ``_build_provider`` / extract
    branch would read are set so nothing KeyErrors.
    """

    class _FakeTransport:
        def is_closing(self) -> bool:
            return True  # __del__ short-circuits: `if not self._transport.is_closing()`

        def close(self) -> None:
            pass

    async def _fake_connect_read(protocol_factory: Any, pipe: Any) -> tuple[object, object]:
        return (_FakeTransport(), object())

    async def _fake_connect_write(protocol_factory: Any, pipe: Any) -> tuple[object, object]:
        return (_FakeTransport(), object())

    monkeypatch.setattr(loop, "connect_read_pipe", _fake_connect_read)
    monkeypatch.setattr(loop, "connect_write_pipe", _fake_connect_write)
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-test-model")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")


# The fd-4 reconstruction step these two tests drive calls ``socket.AF_UNIX`` inside
# ``__main__``, which CPython does not define on Windows. The dependency is INDIRECT — it
# lives in the code under test, not in the test body — which is why the repo's direct-use
# scanner (a test that builds a socket AND calls os.dup/os.close) does not flag this module
# and why a static pass classified it as portable. Guard it explicitly rather than widen the
# scanner: SCM_RIGHTS fd passing has no Win32 equivalent, and the launcher REFUSES
# ``kind:full`` on Windows in production (``windows_stub_in_production``, ADR-0015), so there
# is no native-Windows path for this boot sequence to be correct on. Real Windows containment
# is #230.
_posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: fd-4 reconstruction uses socket.AF_UNIX (absent on Windows CPython)",
)


@_posix_only
async def test_boot_fires_hello_build_fd4_ready_in_runtime_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: ``emit_hello`` -> ``_build_provider`` -> fd-4 reconstruct -> ``ready``.

    A behavioural spy: each boot step appends a marker to a shared list at RUNTIME, so
    the assertion pins the order the code actually EXECUTES (not the order the lines are
    written). Proves §20.3.2: provenance before the factory, the fd-4 control socket up
    before the liveness ``ready`` frame is written.
    """
    calls: list[str] = []
    import socket as _socket_mod

    monkeypatch.setattr(child_main, "configure_stderr_logging", lambda: None)
    monkeypatch.setattr(child_main, "_pin_structlog_to_stderr", lambda: None)
    monkeypatch.setattr(child_main, "_read_provider_key_from_fd3", lambda: "sk-quarantine-key")
    monkeypatch.setattr(child_main, "emit_hello", lambda: calls.append("hello"))

    def _fake_build(key: str) -> object:
        calls.append("build_provider")
        return object()  # dummy factory — BrokeredProviderSource only stores it

    monkeypatch.setattr(child_main, "_build_provider", _fake_build)

    def _fake_socket(*_a: Any, **_k: Any) -> object:
        calls.append("fd4")
        return object()  # dummy control_end — BrokeredProviderSource only stores it

    monkeypatch.setattr(_socket_mod, "socket", _fake_socket)

    async def _fake_ready(writer: Any) -> None:
        calls.append("ready")

    monkeypatch.setattr(child_main, "_write_boot_ready", _fake_ready)

    async def _fake_loop(source: Any, *, reader: Any, writer: Any) -> None:
        calls.append("loop")

    monkeypatch.setattr(child_main, "_run_mcp_server", _fake_loop)

    loop = asyncio.get_running_loop()
    _patch_stdio_seam(monkeypatch, loop)

    await child_main.main()

    assert calls == ["hello", "build_provider", "fd4", "ready", "loop"]


async def test_fd3_framing_refuse_precedes_hello_with_zero_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pre-``emit_hello`` fd-3 framing refuse writes ZERO stdout (launcher-attributed).

    ``_read_provider_key_from_fd3`` exits (``SystemExit``) on a framing error BEFORE
    ``emit_hello`` runs, so the child produces no provenance byte. The host's sec-001
    gate reads the resulting zero-stdout EOF as a LAUNCHER refusal — correct attribution,
    NOT a forged ``sandbox_refused`` row (§20.3.2). Asserted by proving ``emit_hello``
    never fired.
    """
    hello_fired: list[str] = []
    monkeypatch.setattr(child_main, "configure_stderr_logging", lambda: None)
    monkeypatch.setattr(child_main, "_pin_structlog_to_stderr", lambda: None)
    monkeypatch.setattr(child_main, "emit_hello", lambda: hello_fired.append("hello"))

    def _framing_exit() -> str:
        raise SystemExit(1)  # the framing-error exit _read_provider_key_from_fd3 takes

    monkeypatch.setattr(child_main, "_read_provider_key_from_fd3", _framing_exit)

    with pytest.raises(SystemExit):
        await child_main.main()
    assert hello_fired == []  # zero stdout before ready — a launcher-attributed EOF


@_posix_only
async def test_fd4_reconstruction_failure_refuses_after_hello_and_before_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broken fd-4 control socket refuses boot AFTER hello, BEFORE ready (§20.3.2).

    Unlike the empty-key refuse-boot (§20.2, a real ``QuarantineChildBootError``
    raised by ``_build_provider``), the fd-4 control-socket reconstruction has NO
    explicit if/else in ``main()`` — a broken/absent fd 4 just lets
    ``socket.socket(fileno=4, ...)`` raise and propagate naturally. Coverage.py's
    branch metric can't see a "branch" here (there is no conditional bytecode to
    flag), so removing the stale ``# pragma: no cover`` alone would NOT catch a
    future refactor that wraps this call in a swallow-and-continue and lets
    ``ready`` lie about a dead control channel. Only a call-order behavioural spy
    — mirroring ``test_empty_key_refuses_after_hello_and_before_ready`` — pins the
    actual security property: ``emit_hello`` already fired (child-authored refuse,
    not a forged launcher row) and neither ``_write_boot_ready`` nor the loop ran.
    """
    calls: list[str] = []
    import socket as _socket_mod

    monkeypatch.setattr(child_main, "configure_stderr_logging", lambda: None)
    monkeypatch.setattr(child_main, "_pin_structlog_to_stderr", lambda: None)
    monkeypatch.setattr(child_main, "_read_provider_key_from_fd3", lambda: "sk-quarantine-key")
    monkeypatch.setattr(child_main, "emit_hello", lambda: calls.append("hello"))

    def _fake_build(key: str) -> object:
        calls.append("build_provider")
        return object()  # dummy factory — BrokeredProviderSource only stores it

    monkeypatch.setattr(child_main, "_build_provider", _fake_build)

    def _broken_socket(*_a: Any, **_k: Any) -> object:
        raise OSError("Bad file descriptor")  # a closed/absent inherited fd 4

    monkeypatch.setattr(_socket_mod, "socket", _broken_socket)

    async def _fake_ready(writer: Any) -> None:
        calls.append("ready")

    monkeypatch.setattr(child_main, "_write_boot_ready", _fake_ready)

    async def _fake_loop(source: Any, *, reader: Any, writer: Any) -> None:
        calls.append("loop")

    monkeypatch.setattr(child_main, "_run_mcp_server", _fake_loop)

    loop = asyncio.get_running_loop()
    _patch_stdio_seam(monkeypatch, loop)

    with pytest.raises(OSError):
        await child_main.main()

    assert calls == ["hello", "build_provider"]  # ready + loop never reached


async def test_empty_key_refuses_after_hello_and_before_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """§20.2 secondary refuse-boot: an empty key raises strictly AFTER hello, BEFORE ready.

    Drives the REAL ``_build_provider`` (an empty fd-3 key makes ``_ProviderFactory``
    refuse boot). ``emit_hello`` must already have fired (so the host sees a hello and
    treats the refuse as CHILD-authored, never forging a launcher row), and neither
    ``_write_boot_ready`` nor the loop may run (a dead-LLM child must not lie live;
    HARD #7). The order list therefore ends at ``["hello"]``.
    """
    order: list[str] = []
    monkeypatch.setattr(child_main, "configure_stderr_logging", lambda: None)
    monkeypatch.setattr(child_main, "_pin_structlog_to_stderr", lambda: None)
    monkeypatch.setattr(child_main, "_read_provider_key_from_fd3", lambda: "")  # empty key
    monkeypatch.setattr(child_main, "emit_hello", lambda: order.append("hello"))

    async def _fake_ready(writer: Any) -> None:
        order.append("ready")

    async def _fake_loop(source: Any, *, reader: Any, writer: Any) -> None:
        order.append("loop")

    monkeypatch.setattr(child_main, "_write_boot_ready", _fake_ready)
    monkeypatch.setattr(child_main, "_run_mcp_server", _fake_loop)
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-test-model")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")

    with pytest.raises(QuarantineChildBootError):
        await child_main.main()
    assert order == ["hello"]  # hello fired; ready + loop never reached


@pytest.mark.parametrize("bad_budget", ["0", "-1"])
async def test_nonpositive_max_tokens_refuses_after_hello_and_before_ready(
    monkeypatch: pytest.MonkeyPatch, bad_budget: str
) -> None:
    """§20.2 secondary refuse-boot: a <=0 ``max_tokens`` raises AFTER hello, BEFORE ready.

    Drives the REAL ``_build_provider`` with a NON-empty key + a non-positive
    ``ALFRED_QUARANTINE_MAX_TOKENS``, so the max_tokens guard (Task 15) — not the empty-key
    guard — refuses boot. ``emit_hello`` must already have fired (so the host sees a hello
    and treats the refuse as CHILD-authored, never forging a launcher row), and neither
    ``_write_boot_ready`` nor the request loop may run. Because the loop is never entered,
    :func:`dispatch_extraction` is never reached — a bad budget can NEVER launder into a
    ``cannot_extract`` typed refusal (HARD #7). The order list therefore ends at ``["hello"]``.
    """
    order: list[str] = []
    monkeypatch.setattr(child_main, "configure_stderr_logging", lambda: None)
    monkeypatch.setattr(child_main, "_pin_structlog_to_stderr", lambda: None)
    monkeypatch.setattr(child_main, "_read_provider_key_from_fd3", lambda: "sk-quarantine-key")
    monkeypatch.setattr(child_main, "emit_hello", lambda: order.append("hello"))

    async def _fake_ready(writer: Any) -> None:
        order.append("ready")

    async def _fake_loop(source: Any, *, reader: Any, writer: Any) -> None:
        order.append("loop")

    monkeypatch.setattr(child_main, "_write_boot_ready", _fake_ready)
    monkeypatch.setattr(child_main, "_run_mcp_server", _fake_loop)
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-test-model")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", bad_budget)

    with pytest.raises(QuarantineChildBootError):
        await child_main.main()
    assert order == ["hello"]  # hello fired; ready + loop never reached

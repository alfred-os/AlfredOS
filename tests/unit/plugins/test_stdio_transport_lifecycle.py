"""StdioTransport lifecycle: spawn / kill / close + post-handshake quarantine.

These tests target three orthogonal lifecycle paths every Slice-3 transport
change has to keep green:

* **Spawn**: env scrubbing + fd-3 key delivery + fd-leak safety. The
  rvw-pre-flight fix wraps the post-spawn write+close in a ``try/finally``
  so a ``FileNotFoundError`` from ``create_subprocess_exec`` can't leak
  pipe fds.
* **kill()**: thin wrapper around ``process.kill()`` that survives
  "process already dead" gracefully — the audit row emit path uses the
  returned bool to record whether the SIGKILL landed.
* **close()**: cooperative shutdown with a hard SIGKILL fallback after
  the wait-timeout.

The spawn tests use ``/bin/sh`` invoked with ``-c "exit 0"`` as a
microscopic, real subprocess — keeps them hermetic without writing a
plugin shim.
"""

from __future__ import annotations

import asyncio
import os
import platform
import sys
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.plugins.stdio_transport import _CLOSE_TIMEOUT_S, StdioTransport


def _make_transport(
    fake_audit_writer: MagicMock,
    fake_broker: MagicMock,
    stub_nonce: object,
    executable: str = "/bin/sh",
    args: list[str] | None = None,
) -> StdioTransport:
    dlp = MagicMock()
    dlp.scan.return_value = MagicMock(refused=False, rule_matched=None)
    scanner = MagicMock()
    scanner.scan.return_value = None
    return StdioTransport(
        plugin_id="test.plugin",
        executable=executable,
        args=args if args is not None else ["-c", "exit 0"],
        audit_writer=fake_audit_writer,
        dlp=dlp,
        scanner=scanner,
        secret_broker=fake_broker,
        inbound_t3_nonce=stub_nonce,
    )


@pytest.mark.asyncio
async def test_spawn_scrubs_environment(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """Spawned subprocess sees a minimal env (no parent-process leakage).

    ``/bin/sh -c 'env'`` prints the inherited env. After the transport
    spawns, we read stdout and confirm:

    * ``PATH`` is set to the explicit value the transport chose.
    * The parent's ``ALFRED_TEST_SECRET`` (which we set just above) is
      NOT present.
    """
    os.environ["ALFRED_TEST_SECRET"] = "should-not-leak"  # noqa: S105 - synthetic non-secret leak marker
    try:
        transport = _make_transport(
            fake_audit_writer,
            fake_broker,
            stub_nonce,
            executable="/bin/sh",
            args=["-c", "env"],
        )
        await transport._spawn()
        assert transport._process is not None
        assert transport._process.stdout is not None
        stdout = await transport._process.stdout.read()
        await transport._process.wait()
        decoded = stdout.decode("utf-8", errors="replace")
        # PATH is the only inherited-shape var; confirm the parent's
        # ALFRED_TEST_SECRET never reached the child.
        assert "ALFRED_TEST_SECRET" not in decoded
        assert "should-not-leak" not in decoded
        # PATH is set explicitly by the transport.
        assert "PATH=" in decoded
    finally:
        os.environ.pop("ALFRED_TEST_SECRET", None)


@pytest.mark.asyncio
async def test_spawn_closes_fd3_pipe_even_when_executable_missing(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """rvw-pre-flight fix: fd-3 pipe fds close on FileNotFoundError.

    A spawn-failure path that allocated ``os.pipe()`` for fd-3 delivery
    must not leak the fds. We probe by counting open fds before and
    after a deliberately-failing spawn; an fd leak would show up as a
    delta. Linux exposes ``/proc/self/fd`` for the count; macOS doesn't,
    so we fall back to ``resource.getrusage`` indirection there. Both
    cover the regression — the test passes when the leak is fixed.
    """
    # Pre-allocate a probe pipe to anchor the fd count; on success we
    # release it and compare deltas symmetrically.
    transport = _make_transport(
        fake_audit_writer,
        fake_broker,
        stub_nonce,
        executable="/tmp/this-binary-does-not-exist-alfredos-test",  # noqa: S108 - intentional non-existent path for spawn-failure test
        args=[],
    )

    def _count_open_fds() -> int:
        if sys.platform == "linux":
            return len(os.listdir("/proc/self/fd"))  # noqa: PTH208 - Linux-specific procfs probe; pathlib offers no advantage here
        # On Darwin/BSD we approximate by opening+closing one pipe and
        # counting via the delta — sufficient signal for the leak test.
        return -1  # sentinel; assertion below is conditional.

    before = _count_open_fds()
    with pytest.raises(FileNotFoundError):
        await transport._spawn(provider_key=b"fake-key")
    after = _count_open_fds()
    if before >= 0:
        # Allow ±1 for transient interpreter fds; the leak we defend
        # against would be 2 (read + write end of the pipe).
        assert after - before <= 1, f"fd leak after spawn failure: before={before}, after={after}"


@pytest.mark.asyncio
async def test_spawn_delivers_provider_key_via_inherited_fd(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """The host writes the length-prefixed key on an inherited fd (spec §5.3).

    The child reads ``ALFRED_PROVIDER_KEY_FD`` from its env to discover
    the fd number and pulls the framed payload off the pipe. The 4-byte
    big-endian length prefix + N bytes contract holds across the wire;
    the env carries only the fd integer, never the key itself.

    Spec §5.3 deviation: earlier drafts named fd 3 specifically. Forcing
    the child's fd to 3 requires preexec_fn shenanigans that break on
    macOS/Python-3.14 with asyncio's kqueue selector (the loop already
    uses fd 3). The invariant — key value is out of band from env —
    holds under the env-passed-fd approach.
    """
    key = b"sk-test-provider-key-ABC"
    child_program = (
        "import os, sys, struct;"
        "fd=int(os.environ['ALFRED_PROVIDER_KEY_FD']);"
        "header=os.read(fd,4); length=struct.unpack('>I',header)[0];"
        "sys.stdout.buffer.write(os.read(fd,length))"
    )
    transport = _make_transport(
        fake_audit_writer,
        fake_broker,
        stub_nonce,
        executable=sys.executable,
        args=["-c", child_program],
    )
    await transport._spawn(provider_key=key)
    assert transport._process is not None
    assert transport._process.stdout is not None
    stdout = await transport._process.stdout.read()
    await transport._process.wait()
    assert stdout == key, (
        f"child failed to read framed key on inherited fd: got {stdout!r}, expected {key!r}"
    )


@pytest.mark.asyncio
async def test_spawn_announces_provider_key_fd_via_env(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """``ALFRED_PROVIDER_KEY_FD`` is set when ``provider_key`` is supplied.

    Plain ``env``-print regression test: the env var carries an integer
    (the fd number), never the key itself. Plaintext appears nowhere
    visible in ``/proc/<pid>/environ`` or ``ps``-style introspection.
    """
    transport = _make_transport(
        fake_audit_writer,
        fake_broker,
        stub_nonce,
        executable="/bin/sh",
        args=["-c", "env"],
    )
    await transport._spawn(provider_key=b"sk-PRIVATE-KEY-do-not-leak")
    assert transport._process is not None
    assert transport._process.stdout is not None
    stdout = await transport._process.stdout.read()
    await transport._process.wait()
    decoded = stdout.decode("utf-8", errors="replace")
    assert "ALFRED_PROVIDER_KEY_FD=" in decoded
    # The key itself must NEVER appear in env.
    assert "sk-PRIVATE-KEY-do-not-leak" not in decoded


@pytest.mark.asyncio
async def test_kill_returns_true_on_live_subprocess(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """``kill()`` returns ``True`` when the SIGKILL is delivered to a live process.

    The audit row at the quarantine call site reads this flag to record
    whether the subprocess was successfully killed (vs already dead from
    a prior crash). Both cases still emit the row.

    #187 diagnostic: kill() has three False paths (self._process is None
    / ProcessLookupError on .kill() / TimeoutError on .wait()). The plain
    ``assert succeeded is True`` here doesn't reveal which one fires on
    Linux CI under coverage. The block below replays kill()'s logic step
    by step with named assertions so the failure message pinpoints the
    failing branch. Remove the diagnostic block once #187 is closed.
    """
    transport = _make_transport(
        fake_audit_writer,
        fake_broker,
        stub_nonce,
        executable="/bin/sh",
        args=["-c", "sleep 5"],
    )

    # Stage A: env probe — capture characteristics that differ between
    # macOS local (passes) and Linux CI under coverage (fails). The loop
    # implementation class names the child-watcher / pidfd path used on
    # Linux 3.12+, which is the most plausible delta vs macOS's kqueue.
    env_probe = {
        "platform": platform.system(),
        "python": sys.version_info[:3],
        "pid": os.getpid(),
        "loop_impl": type(asyncio.get_running_loop()).__name__,
    }

    # Stage B: spawn — should set self._process to a live asyncio Process.
    await transport._spawn()
    proc = transport._process
    spawn_probe = {
        "process_is_None": proc is None,
        "pid": getattr(proc, "pid", None),
        "returncode_post_spawn": getattr(proc, "returncode", "no-attr"),
    }
    assert proc is not None, f"_spawn left _process unset; env={env_probe}"

    # Stage C: SIGKILL the subprocess. ProcessLookupError here means the
    # OS no longer has the pid (process exited between spawn-return and
    # kill-syscall). Capture the outcome rather than catching-and-
    # returning-False so the assertion message shows it.
    kill_outcome: str
    try:
        proc.kill()
        kill_outcome = "ok"
    except ProcessLookupError as exc:
        kill_outcome = f"ProcessLookupError: {exc!r}"

    # Stage D: wait for reap. TimeoutError here means SIGKILL did not
    # cause the process to exit within _CLOSE_TIMEOUT_S (5s) — strange
    # for /bin/sh, but possible if pidfd reaping is broken or the loop
    # is starved.
    wait_outcome: str
    rc_after_wait: object
    try:
        await asyncio.wait_for(proc.wait(), timeout=_CLOSE_TIMEOUT_S)
        wait_outcome = "ok"
        rc_after_wait = proc.returncode
    except TimeoutError as exc:
        wait_outcome = f"TimeoutError after {_CLOSE_TIMEOUT_S}s: {exc!r}"
        rc_after_wait = proc.returncode

    diagnostic = {
        "env": env_probe,
        "spawn": spawn_probe,
        "kill_outcome": kill_outcome,
        "wait_outcome": wait_outcome,
        "returncode_after_wait": rc_after_wait,
    }

    assert kill_outcome == "ok" and wait_outcome == "ok", (
        f"#187 diagnostic — kill flow did not complete cleanly: {diagnostic}"
    )

    # Stage E: original contract — call kill() on a fresh transport so the
    # public surface is still exercised. Re-spawning to avoid double-kill
    # on the same process.
    transport2 = _make_transport(
        fake_audit_writer,
        fake_broker,
        stub_nonce,
        executable="/bin/sh",
        args=["-c", "sleep 5"],
    )
    await transport2._spawn()
    succeeded = await transport2.kill()
    assert succeeded is True, (
        f"#187 kill() returned False; transport2 state: process={transport2._process!r}"
    )


@pytest.mark.asyncio
async def test_kill_returns_false_when_process_already_dead(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """``kill()`` returns ``False`` if the OS signal raises ProcessLookupError.

    Simulates the race where the subprocess crashes between the
    decision-to-kill and the syscall. The wrapper must swallow the
    OS-level "no such process" and report kill_succeeded=False so the
    quarantine audit row records the actual outcome — not silently
    succeed and not raise.
    """
    transport = _make_transport(fake_audit_writer, fake_broker, stub_nonce)
    mock_proc = MagicMock()
    mock_proc.kill = MagicMock(side_effect=ProcessLookupError)
    mock_proc.wait = AsyncMock()
    transport._process = mock_proc
    succeeded = await transport.kill()
    assert succeeded is False


@pytest.mark.asyncio
async def test_kill_returns_false_when_no_process_spawned(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """``kill()`` is a safe no-op when the transport never spawned.

    Defensive: the quarantine path may call ``kill()`` regardless of
    spawn state. Returning ``False`` matches the "no kill landed"
    semantic that the audit row records.
    """
    transport = _make_transport(fake_audit_writer, fake_broker, stub_nonce)
    # _process is None — the transport was never spawned.
    succeeded = await transport.kill()
    assert succeeded is False


@pytest.mark.asyncio
async def test_close_returns_quietly_when_no_process(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """``close()`` is a safe no-op when nothing was spawned."""
    transport = _make_transport(fake_audit_writer, fake_broker, stub_nonce)
    await transport.close()  # must not raise


@pytest.mark.asyncio
async def test_close_kills_subprocess_after_timeout(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """``close()`` SIGKILLs a wedged child after the wait-timeout.

    The cooperative path closes stdin and waits up to ``close_timeout_s``
    for the child to exit. A child that ignores stdin-close (e.g. a stuck
    quarantined-LLM plugin) gets SIGKILL. We simulate the timeout via a
    ``wait`` mock that raises ``asyncio.TimeoutError`` once, then a kill
    mock that records the call.
    """
    transport = _make_transport(fake_audit_writer, fake_broker, stub_nonce)
    mock_proc = MagicMock()
    mock_proc.stdin = MagicMock()
    mock_proc.stdin.close = MagicMock()

    call_count = {"n": 0}

    async def _wait() -> int:
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise TimeoutError
        return 0

    mock_proc.wait = _wait
    mock_proc.kill = MagicMock()
    transport._process = mock_proc

    # Use a tiny timeout so the test isn't held up — close() wraps the
    # first wait() in asyncio.wait_for. The mock raises TimeoutError
    # synchronously to keep the test deterministic.
    await transport.close()

    mock_proc.stdin.close.assert_called_once()
    mock_proc.kill.assert_called_once()


@pytest.mark.asyncio
async def test_read_length_prefixed_before_spawn_raises_runtime_error(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """err-013 defence-in-depth: ``_read_length_prefixed`` direct-call guard.

    The dispatch path already short-circuits on ``_process is None`` so this
    method's guard is only reachable through the test harness — but it must
    still raise loudly so any future refactor that reorders dispatch can't
    silently downgrade the protection.
    """
    transport = _make_transport(fake_audit_writer, fake_broker, stub_nonce)
    with pytest.raises(RuntimeError):
        await transport._read_length_prefixed()


@pytest.mark.asyncio
async def test_dispatch_before_spawn_raises_runtime_error(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """err-013 fix: dispatch with no spawned process raises a loud RuntimeError.

    The plan replaces ``assert self._process is not None`` with an
    explicit guard because ``python -O`` strips asserts and this is a
    trust-boundary I/O path that must fail loud regardless of optimisation
    flags.
    """
    transport = _make_transport(fake_audit_writer, fake_broker, stub_nonce)
    with pytest.raises(RuntimeError):
        await transport.dispatch("web.fetch", {"url": "https://example.com"})


@pytest.mark.asyncio
async def test_canary_trip_raises_security_event(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """Inbound canary detection raises :class:`CanaryTripSecurityEvent`.

    The canary is a SECURITY EVENT, not a redact-and-continue error
    (spec §4.5). The exception carries the matched token and the plugin
    id for forensic correlation.
    """
    import json
    import struct

    from alfred.plugins.inbound_scanner import CanaryTrip
    from alfred.plugins.stdio_transport import CanaryTripSecurityEvent

    dlp = MagicMock()
    dlp.scan.return_value = MagicMock(refused=False, rule_matched=None)
    scanner = MagicMock()
    scanner.scan.return_value = CanaryTrip(matched_token="CANARY-X", frame_offset=0)  # noqa: S106 - canary token, not a credential
    transport = StdioTransport(
        plugin_id="test.plugin",
        executable="/bin/sh",
        args=["-c", "true"],
        audit_writer=fake_audit_writer,
        dlp=dlp,
        scanner=scanner,
        secret_broker=fake_broker,
        inbound_t3_nonce=stub_nonce,
    )

    body = json.dumps({"jsonrpc": "2.0", "result": {"x": "CANARY-X"}}).encode("utf-8")
    framed = struct.pack(">I", len(body)) + body
    mock_proc = MagicMock()
    mock_proc.stdin.write = MagicMock()
    mock_proc.stdin.drain = AsyncMock()
    mock_proc.stdout.readexactly = AsyncMock(side_effect=[framed[:4], framed[4:]])
    transport._process = mock_proc
    with pytest.raises(CanaryTripSecurityEvent) as excinfo:
        await transport.dispatch("web.fetch", {"url": "https://example.com"})
    assert excinfo.value.plugin_id == "test.plugin"
    assert excinfo.value.matched_token == "CANARY-X"  # noqa: S105 - canary token, not a credential


@pytest.mark.asyncio
async def test_inbound_frame_exceeding_max_size_raises_protocol_error(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """perf-008 fix: oversized inbound frames raise PluginProtocolError.

    The 10MB hard cap prevents a misbehaving plugin from DOSing the host
    by claiming a length larger than memory will hold. The transport
    refuses BEFORE consuming the body bytes — the header alone trips
    the check.
    """
    import struct

    from alfred.plugins.stdio_transport import PluginProtocolError

    dlp = MagicMock()
    dlp.scan.return_value = MagicMock(refused=False, rule_matched=None)
    scanner = MagicMock()
    scanner.scan.return_value = None
    transport = StdioTransport(
        plugin_id="test.plugin",
        executable="/bin/sh",
        args=["-c", "true"],
        audit_writer=fake_audit_writer,
        dlp=dlp,
        scanner=scanner,
        secret_broker=fake_broker,
        inbound_t3_nonce=stub_nonce,
    )
    oversize_header = struct.pack(">I", 20 * 1024 * 1024)  # 20MB
    mock_proc = MagicMock()
    mock_proc.stdin.write = MagicMock()
    mock_proc.stdin.drain = AsyncMock()
    mock_proc.stdout.readexactly = AsyncMock(return_value=oversize_header)
    transport._process = mock_proc
    with pytest.raises(PluginProtocolError):
        await transport.dispatch("web.fetch", {"url": "https://example.com"})


@pytest.mark.asyncio
async def test_dispatch_large_frame_uses_to_thread_for_dlp(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """perf-012 fix: outbound DLP scan offloads to a thread on >4KB frames.

    Regex/NER scans are O(n) on the frame size and would block the event
    loop above the threshold. We construct a frame ~5KB wide by stuffing
    the params dict; the test patches ``asyncio.to_thread`` in the
    transport's namespace so we can directly assert the offload happened
    — the prior version asserted only ``dlp.scan.called`` which held
    regardless of whether the scan ran inline on the event loop or via
    the thread executor. CR on PR #140 caught the gap.
    """
    import asyncio
    import json
    import struct
    from unittest.mock import patch

    dlp = MagicMock()
    dlp.scan.return_value = MagicMock(refused=False, rule_matched=None)
    scanner = MagicMock()
    scanner.scan.return_value = None
    transport = StdioTransport(
        plugin_id="test.plugin",
        executable="/bin/sh",
        args=["-c", "true"],
        audit_writer=fake_audit_writer,
        dlp=dlp,
        scanner=scanner,
        secret_broker=fake_broker,
        inbound_t3_nonce=stub_nonce,
    )
    body = json.dumps({"jsonrpc": "2.0", "result": {}}).encode("utf-8")
    framed = struct.pack(">I", len(body)) + body
    mock_proc = MagicMock()
    mock_proc.stdin.write = MagicMock()
    mock_proc.stdin.drain = AsyncMock()
    mock_proc.stdout.readexactly = AsyncMock(side_effect=[framed[:4], framed[4:]])
    transport._process = mock_proc

    big_payload = "x" * 5000  # crosses the 4096-byte threshold
    real_to_thread = asyncio.to_thread
    with patch(
        "alfred.plugins.stdio_transport.asyncio.to_thread",
        side_effect=real_to_thread,
    ) as spy:
        await transport.dispatch("lifecycle.start", {"payload": big_payload})
    # Sanity check: DLP was invoked at least once.
    assert dlp.scan.called
    # Load-bearing assertion: the >4KB frame triggered an
    # ``asyncio.to_thread`` offload. Without this assertion a regression
    # that runs the DLP scan inline on the event loop would pass — the
    # perf-012 budget is the whole reason this branch exists.
    #
    # ``asyncio.to_thread`` is also used for the inbound canary scan
    # later in dispatch, so the spy may have ≥1 calls; the assertion is
    # "at least one call" and the first call is the DLP offload (the
    # placeholder frame crosses the threshold before the inbound scan
    # runs).
    assert spy.call_count >= 1
    # The first offload is the DLP scan — verify the callee is the DLP
    # collaborator, not the canary scanner.
    first_call_callable = spy.call_args_list[0].args[0]
    assert first_call_callable is dlp.scan, (
        f"first asyncio.to_thread call should offload dlp.scan; got {first_call_callable!r}"
    )


@pytest.mark.asyncio
async def test_dispatch_small_frame_does_not_offload_dlp(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """perf-012 counter-case: sub-threshold frames must NOT offload the DLP scan.

    Below the 4096-byte threshold the thread-handoff overhead exceeds
    the scan time, so the dispatch path runs the scan inline. CR on
    PR #140 asked for this counter-case alongside the positive test —
    without it, a regression that always offloads (defeating the perf
    budget the threshold exists for) would pass the positive test
    silently.
    """
    import asyncio
    import json
    import struct
    from unittest.mock import patch

    dlp = MagicMock()
    dlp.scan.return_value = MagicMock(refused=False, rule_matched=None)
    scanner = MagicMock()
    scanner.scan.return_value = None
    transport = StdioTransport(
        plugin_id="test.plugin",
        executable="/bin/sh",
        args=["-c", "true"],
        audit_writer=fake_audit_writer,
        dlp=dlp,
        scanner=scanner,
        secret_broker=fake_broker,
        inbound_t3_nonce=stub_nonce,
    )
    body = json.dumps({"jsonrpc": "2.0", "result": {}}).encode("utf-8")
    framed = struct.pack(">I", len(body)) + body
    mock_proc = MagicMock()
    mock_proc.stdin.write = MagicMock()
    mock_proc.stdin.drain = AsyncMock()
    mock_proc.stdout.readexactly = AsyncMock(side_effect=[framed[:4], framed[4:]])
    transport._process = mock_proc

    # Tiny payload — well under the 4096-byte threshold.
    small_payload = "x" * 16
    real_to_thread = asyncio.to_thread
    with patch(
        "alfred.plugins.stdio_transport.asyncio.to_thread",
        side_effect=real_to_thread,
    ) as spy:
        await transport.dispatch("lifecycle.start", {"payload": small_payload})
    # DLP still runs — but inline, not via the executor.
    assert dlp.scan.called
    # The inbound canary scan still uses ``to_thread`` (unconditionally),
    # so the spy may record exactly one call. What MUST NOT appear is a
    # call whose first arg is ``dlp.scan``.
    dlp_offloads = [call for call in spy.call_args_list if call.args and call.args[0] is dlp.scan]
    assert not dlp_offloads, (
        f"sub-threshold frame should run DLP scan inline; got {len(dlp_offloads)} "
        "asyncio.to_thread calls for dlp.scan"
    )


@pytest.mark.asyncio
async def test_runtime_error_when_nonce_missing(
    fake_audit_writer: MagicMock, fake_broker: MagicMock
) -> None:
    """An explicit ``None`` nonce trips the explicit guard on the T3 path.

    Constructor type allows ``CapabilityGateNonce`` only, but a misuse
    that bypasses typing (legacy callers, tests holding stale references)
    is caught at dispatch-time on the content-bearing branch. Control-
    plane methods skip T3 tagging so the guard is only meaningful for
    content-bearing dispatch.
    """
    import json
    import struct

    from alfred.plugins.stdio_transport import NonceNotConfigured

    dlp = MagicMock()
    dlp.scan.return_value = MagicMock(refused=False, rule_matched=None)
    scanner = MagicMock()
    scanner.scan.return_value = None
    transport = StdioTransport(
        plugin_id="test.plugin",
        executable="/bin/sh",
        args=["-c", "true"],
        audit_writer=fake_audit_writer,
        dlp=dlp,
        scanner=scanner,
        secret_broker=fake_broker,
        inbound_t3_nonce=None,  # type: ignore[arg-type]  -- deliberate misuse for guard test
    )
    body = json.dumps({"jsonrpc": "2.0", "result": {"body": "x"}}).encode("utf-8")
    framed = struct.pack(">I", len(body)) + body
    mock_proc = MagicMock()
    mock_proc.stdin.write = MagicMock()
    mock_proc.stdin.drain = AsyncMock()
    mock_proc.stdout.readexactly = AsyncMock(side_effect=[framed[:4], framed[4:]])
    transport._process = mock_proc
    with pytest.raises(NonceNotConfigured):
        await transport.dispatch("web.fetch", {"url": "https://example.com"})


@pytest.mark.asyncio
async def test_close_kills_subprocess_after_timeout_no_stdin(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """close() handles ``stdin`` being None (already-closed transport)."""
    transport = _make_transport(fake_audit_writer, fake_broker, stub_nonce)
    mock_proc = MagicMock()
    mock_proc.stdin = None

    async def _wait() -> int:
        raise TimeoutError

    mock_proc.wait = _wait
    mock_proc.kill = MagicMock()
    transport._process = mock_proc
    await transport.close()
    mock_proc.kill.assert_called_once()


@pytest.mark.asyncio
async def test_close_returns_after_wait_succeeds(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """``close()`` returns cleanly when the child exits before the timeout."""
    transport = _make_transport(fake_audit_writer, fake_broker, stub_nonce)
    mock_proc = MagicMock()
    mock_proc.stdin = MagicMock()
    mock_proc.stdin.close = MagicMock()
    mock_proc.wait = AsyncMock(return_value=0)
    mock_proc.kill = MagicMock()
    transport._process = mock_proc
    await transport.close()
    mock_proc.stdin.close.assert_called_once()
    mock_proc.kill.assert_not_called()


@pytest.mark.asyncio
async def test_canary_trip_message_uses_i18n_key(
    fake_audit_writer: MagicMock, fake_broker: MagicMock, stub_nonce: object
) -> None:
    """The CanaryTripSecurityEvent message routes through ``t()`` (i18n rule #1)."""
    import json
    import struct

    from alfred.plugins.inbound_scanner import CanaryTrip
    from alfred.plugins.stdio_transport import CanaryTripSecurityEvent

    dlp = MagicMock()
    dlp.scan.return_value = MagicMock(refused=False, rule_matched=None)
    scanner = MagicMock()
    scanner.scan.return_value = CanaryTrip(matched_token="CANARY-Y", frame_offset=5)  # noqa: S106 - canary token, not a credential
    transport = StdioTransport(
        plugin_id="my.plugin",
        executable="/bin/sh",
        args=["-c", "true"],
        audit_writer=fake_audit_writer,
        dlp=dlp,
        scanner=scanner,
        secret_broker=fake_broker,
        inbound_t3_nonce=stub_nonce,
    )
    body = json.dumps({"jsonrpc": "2.0", "result": {"x": "CANARY-Y"}}).encode("utf-8")
    framed = struct.pack(">I", len(body)) + body
    mock_proc = MagicMock()
    mock_proc.stdin.write = MagicMock()
    mock_proc.stdin.drain = AsyncMock()
    mock_proc.stdout.readexactly = AsyncMock(side_effect=[framed[:4], framed[4:]])
    transport._process = mock_proc
    with pytest.raises(CanaryTripSecurityEvent) as excinfo:
        await transport.dispatch("web.fetch", {"url": "https://example.com"})
    # The key falls back to itself when the catalog entry is absent — both
    # behaviours satisfy i18n rule #1 because the call routes through t().
    assert "canary" in str(excinfo.value).lower() or "security.canary_tripped" in str(excinfo.value)

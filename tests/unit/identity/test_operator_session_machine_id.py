"""Per-OS machine-id providers + HMAC hash (PR-S4-5 Task 8).

The machine-id is system-owned per OS; the session file stores only the
HMAC keyed by the HKDF-derived machine-id subkey (sec-3) — never the raw
value. Tests mock each OS source so they run on any CI runner.
"""

from __future__ import annotations

import hashlib
import hmac
import sys
from pathlib import Path
from typing import Any

import pytest

from alfred.identity.operator_session import (
    LinuxMachineIdProvider,
    MacosMachineIdProvider,
    OperatorSessionNoMachineId,
    compute_machine_id_hash,
    derive_machine_id_hash_subkey,
    select_machine_id_provider,
)

_PEPPER = b"0" * 64


async def test_linux_primary_readable(tmp_path: Path) -> None:
    primary = tmp_path / "machine-id"
    primary.write_bytes(b"abc123\n")
    provider = LinuxMachineIdProvider(primary=primary, fallback=tmp_path / "absent")
    assert await provider.read_raw() == b"abc123"


async def test_linux_fallback_when_primary_missing(tmp_path: Path) -> None:
    fallback = tmp_path / "dbus-machine-id"
    fallback.write_bytes(b"fallbackid\n")
    provider = LinuxMachineIdProvider(primary=tmp_path / "absent", fallback=fallback)
    assert await provider.read_raw() == b"fallbackid"


async def test_linux_both_missing_refuses(tmp_path: Path) -> None:
    provider = LinuxMachineIdProvider(primary=tmp_path / "a", fallback=tmp_path / "b")
    with pytest.raises(OperatorSessionNoMachineId):
        await provider.read_raw()


async def test_linux_empty_primary_falls_through_to_fallback(tmp_path: Path) -> None:
    """CR-227 round-2 finding 3: an empty/whitespace primary is unreadable.

    An empty ``/etc/machine-id`` must NOT be hashed (the empty value would be
    a CONSTANT across every host with an empty source, defeating replay
    protection). The provider falls through to ``/var/lib/dbus/machine-id``.
    """
    primary = tmp_path / "machine-id"
    primary.write_bytes(b"   \n\t  ")  # whitespace-only -> strips to b""
    fallback = tmp_path / "dbus-machine-id"
    fallback.write_bytes(b"realfallback\n")
    provider = LinuxMachineIdProvider(primary=primary, fallback=fallback)
    assert await provider.read_raw() == b"realfallback"


async def test_linux_all_empty_refuses_never_hashes_constant(tmp_path: Path) -> None:
    """When EVERY source is empty/whitespace the provider RAISES, never hashes b\"\"."""
    primary = tmp_path / "machine-id"
    primary.write_bytes(b"")
    fallback = tmp_path / "dbus-machine-id"
    fallback.write_bytes(b"\n  \n")
    provider = LinuxMachineIdProvider(primary=primary, fallback=fallback)
    with pytest.raises(OperatorSessionNoMachineId):
        await provider.read_raw()


async def test_macos_cache_hit(tmp_path: Path) -> None:
    cache = tmp_path / "machine-id"
    cache.write_bytes(b"CACHED-UUID\n")
    provider = MacosMachineIdProvider(cache=cache)
    assert await provider.read_raw() == b"CACHED-UUID"


async def test_macos_cache_miss_spawns_ioreg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "machine-id"

    class _FakeProc:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return (b'    "IOPlatformUUID" = "DEAD-BEEF-UUID"\n', b"")

    async def _fake_exec(*_args: Any, **_kwargs: Any) -> _FakeProc:
        return _FakeProc()

    monkeypatch.setattr("alfred.identity.operator_session.create_subprocess_exec", _fake_exec)
    provider = MacosMachineIdProvider(cache=cache)
    assert await provider.read_raw() == b"DEAD-BEEF-UUID"
    # The cache was populated for the next read.
    assert cache.read_bytes() == b"DEAD-BEEF-UUID"


async def test_macos_cache_write_failure_is_best_effort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CR-227 round-2 finding 4: an unwritable cache dir must NOT break login.

    The cache WRITE is best-effort — on ``OSError`` (read-only fs, permission
    denied) the provider logs and continues with the in-memory ``ioreg``
    value. The cache READ stays authoritative when present; only the write
    degrades gracefully.
    """
    import alfred.identity.operator_session as _osmod

    cache = tmp_path / "absent"

    class _Proc:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return (b'    "IOPlatformUUID" = "LIVE-UUID"\n', b"")

    async def _fake_exec(*_args: Any, **_kwargs: Any) -> _Proc:
        return _Proc()

    monkeypatch.setattr("alfred.identity.operator_session.create_subprocess_exec", _fake_exec)

    # Make the cache write fail (read-only / unwritable).
    def _boom(*_a: Any, **_k: Any) -> None:
        raise OSError("read-only file system")

    monkeypatch.setattr(_osmod.Path, "write_bytes", _boom)

    provider = MacosMachineIdProvider(cache=cache)
    # Login still resolves to the live value despite the failed cache write.
    assert await provider.read_raw() == b"LIVE-UUID"


async def test_macos_ioreg_nonzero_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _FailProc:
        returncode = 1

        async def communicate(self) -> tuple[bytes, bytes]:
            return (b"", b"boom")

    async def _fake_exec(*_args: Any, **_kwargs: Any) -> _FailProc:
        return _FailProc()

    monkeypatch.setattr("alfred.identity.operator_session.create_subprocess_exec", _fake_exec)
    provider = MacosMachineIdProvider(cache=tmp_path / "absent")
    with pytest.raises(OperatorSessionNoMachineId):
        await provider.read_raw()


async def test_macos_no_uuid_line_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """ioreg succeeds but the output lacks an IOPlatformUUID line -> refuse."""

    class _Proc:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return (b"some other ioreg line\n", b"")

    async def _fake_exec(*_args: Any, **_kwargs: Any) -> _Proc:
        return _Proc()

    monkeypatch.setattr("alfred.identity.operator_session.create_subprocess_exec", _fake_exec)
    provider = MacosMachineIdProvider(cache=tmp_path / "absent")
    with pytest.raises(OperatorSessionNoMachineId, match="not found"):
        await provider.read_raw()


async def test_compute_machine_id_hash_deterministic() -> None:
    raw = b"machine-raw"

    class _Stub:
        async def read_raw(self) -> bytes:
            return raw

    digest = await compute_machine_id_hash(provider=_Stub(), pepper=_PEPPER)
    expected = hmac.new(derive_machine_id_hash_subkey(_PEPPER), raw, hashlib.sha256).hexdigest()
    assert digest == expected
    assert len(digest) == 64


def test_select_provider_per_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.platform", "linux")
    assert isinstance(select_machine_id_provider(), LinuxMachineIdProvider)
    monkeypatch.setattr("sys.platform", "darwin")
    assert isinstance(select_machine_id_provider(), MacosMachineIdProvider)


def test_select_provider_unsupported_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.platform", "sunos")
    with pytest.raises(OperatorSessionNoMachineId):
        select_machine_id_provider()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="On Windows winreg imports; this arm asserts the non-Windows refusal.",
)
async def test_windows_provider_winreg_unavailable_refuses() -> None:
    """On a non-Windows host, ``import winreg`` raises -> NoMachineId."""
    from alfred.identity.operator_session import WindowsMachineIdProvider

    with pytest.raises(OperatorSessionNoMachineId, match="winreg unavailable"):
        await WindowsMachineIdProvider().read_raw()

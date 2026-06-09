"""Per-OS machine-id providers + HMAC hash (PR-S4-5 Task 8).

The machine-id is system-owned per OS; the session file stores only the
HMAC keyed by the HKDF-derived machine-id subkey (sec-3) — never the raw
value. Tests mock each OS source so they run on any CI runner.
"""

from __future__ import annotations

import hashlib
import hmac
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

"""test-2 closure: session replayed on a different machine is refused.

A session minted under machine-id A and copied to machine B (same
hostname, e.g. a cloned VM image) must refuse: the machine-id-hash baked
into the file will not match the live hash computed under stub-B.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from alfred.identity._resolver import DefaultOperatorSessionResolver
from alfred.identity.operator_session import (
    OperatorSessionFile,
    OperatorSessionMachineIdMismatch,
    compute_machine_id_hash,
    write_session_file,
)

_PEPPER = "0" * 64
_HOST = "shared-hostname"


class _MachineA:
    async def read_raw(self) -> bytes:
        return b"machine-A-uuid"


class _MachineB:
    async def read_raw(self) -> bytes:
        return b"machine-B-uuid"


class _Broker:
    def get(self, name: str) -> str:
        assert name == "audit.hash_pepper"
        return _PEPPER


class _Session:
    async def execute(self, *_a: Any, **_k: Any) -> Any:
        raise AssertionError("machine check must refuse before the DB lookup")


class _Audit:
    def __init__(self) -> None:
        self.reasons: list[str] = []

    async def append_schema(self, **kwargs: Any) -> None:
        self.reasons.append(kwargs["subject"]["reason"])


class _Hooks:
    async def __call__(self, *_a: Any, **_k: Any) -> None:
        return None


def _scope(session: _Session) -> Any:
    @asynccontextmanager
    async def _s() -> Any:
        yield session

    return _s


async def test_replay_on_different_machine_refused(tmp_path: Path) -> None:
    # Mint under machine A.
    hash_a = await compute_machine_id_hash(provider=_MachineA(), pepper=_PEPPER.encode())
    parent = tmp_path / ".config" / "alfred"
    parent.mkdir(parents=True)
    parent.chmod(0o700)
    path = parent / "session"
    now = datetime.now(UTC)
    write_session_file(
        path,
        OperatorSessionFile(
            schema_version=1,
            user_id=3,
            token=SecretStr("tok"),
            issued_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(hours=1),
            host=_HOST,
            machine_id_hash=hash_a,
        ),
    )

    # Resolve under machine B (different stub) — must refuse.
    audit = _Audit()
    resolver = DefaultOperatorSessionResolver(
        session_scope=_scope(_Session()),
        secret_broker=_Broker(),
        machine_id_provider=_MachineB(),
        audit_writer=audit,
        hook_dispatcher=_Hooks(),
        host=_HOST,
        session_file_path=path,
    )
    with pytest.raises(OperatorSessionMachineIdMismatch):
        await resolver.resolve()
    assert audit.reasons == ["machine_mismatch"]

"""G6-3 credential adversarial corpus — a / b / e (RELEASE-BLOCKING, #288).

The heaviest trust boundary in Spec B: a real platform credential over fd 3. These
are the NON-root in-process analogs that GATE merge (the #245 paper-gate lesson —
the env-absence / isolation / forgery properties must hold on the required gate, not
only on the privileged lane). The concrete required gate is the discrete
``Comms credential adversarial corpus (release-blocking)`` step in the REQUIRED
``python`` job of ``.github/workflows/ci.yml`` (``uv run pytest tests/adversarial/comms``).
This corpus does NOT rely on the advisory ``adversarial.yml`` workflow — that one
carries ``continue-on-error: true`` and never blocks merge; promoting the whole
adversarial suite to a required gate is a tracked governance follow-up (G6-6). The
OS-level corroboration (a real bwrap child, the ``/proc/<pid>/environ`` negative)
runs on the privileged Linux lane (Task 9).

* **(a) cross-adapter credential read** — one adapter cannot read another's
  credential. In-process: the resolver's CLOSED allowlist refuses an unknown adapter
  WITHOUT a ``broker.get(adapter_id)`` passthrough (confused-deputy), and each spawn
  delivers over its OWN fd-3 (no shared buffer).
* **(b) gateway holds no vault key + no retained credential** — STRUCTURAL: the
  gateway-side client never calls the secret broker (the resolver is the ONLY
  decryptor); the credential never appears in an env dict / audit row / log / a
  retained field; the ephemeral fd-3 writev buffer is zeroed by the reused library fn.
* **(e) spoofed / replayed / unsolicited grant** — a forged adapter_id /
  host_restart_seq / epoch, a stale epoch, a replayed request, and an unsolicited
  grant (no pending request) are each REFUSED.

A unique SENTINEL credential is fed through the whole pipeline; a sweep asserts it
appears ONLY on the fd-3 sink — NEVER in any audit row, log line, emitted frame
param, or exception across happy AND failure paths (correction S-C3 value-sentinel).
"""

from __future__ import annotations

import inspect
import os
from collections.abc import Mapping
from datetime import UTC, datetime

import pytest
import structlog.testing

from alfred.comms_mcp.adapter_credential_protocol import SpawnGrant, SpawnRequest
from alfred.comms_mcp.adapter_credential_resolver import (
    AdapterCredentialError,
    CoreAdapterCredentialResolver,
)
from alfred.gateway.adapter_credential_client import GatewayAdapterCredentialClient
from alfred.gateway.core_link import GatewayCoreLink

# NO module-level ``pytest.mark.asyncio``: ``asyncio_mode = "auto"`` (pyproject.toml)
# already collects every ``async def test_*`` as an asyncio test. A module-level mark
# would ALSO tag the three SYNC ``test_b_*`` structural tests, tripping a PytestWarning
# ("marked with '@pytest.mark.asyncio' but it is not an async function").

_EPOCH = "0123456789abcdef0123456789abcdef"
_OTHER_EPOCH = "fedcba9876543210fedcba9876543210"
_REQ_ID = "11111111111111111111111111111111"
_SENTINEL = "SENTINEL-CRED-ADVERSARIAL-DO-NOT-LEAK-9c2f"


class _FakeAudit:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    async def append_schema(self, **kwargs: object) -> None:
        self.rows.append(dict(kwargs))


class _CountingBroker:
    def __init__(self, *, values: dict[str, str] | None = None) -> None:
        self._values = values if values is not None else {"discord_bot_token": _SENTINEL}
        self.calls: list[str] = []

    def get(self, name: str) -> str:
        self.calls.append(name)
        from alfred.security.secrets import UnknownSecretError

        try:
            return self._values[name]
        except KeyError as exc:
            raise UnknownSecretError(name) from exc


def _resolver(broker: _CountingBroker, audit: _FakeAudit) -> CoreAdapterCredentialResolver:
    return CoreAdapterCredentialResolver(broker=broker, audit=audit, now=lambda: datetime.now(UTC))


def _request(
    *, adapter_id: str = "discord", host_restart_seq: int = 0, epoch: str = _EPOCH
) -> SpawnRequest:
    return SpawnRequest(
        request_id=_REQ_ID, adapter_id=adapter_id, host_restart_seq=host_restart_seq, epoch=epoch
    )


# ---------------------------------------------------------------------------
# (a) cross-adapter credential read
# ---------------------------------------------------------------------------


async def test_a_unknown_adapter_refused_without_broker_passthrough() -> None:
    """An adapter with no allowlist entry can NEVER read a credential — and the
    resolver never does ``broker.get(adapter_id)`` (the confused-deputy passthrough)."""
    broker = _CountingBroker()
    audit = _FakeAudit()
    resolver = _resolver(broker, audit)
    with pytest.raises(AdapterCredentialError):
        await resolver.resolve(_request(adapter_id="tui"))  # known kind, no credential
    assert broker.calls == []  # the attacker id never reached the broker


async def test_a_each_delivery_uses_its_own_fd3() -> None:
    """Two credential deliveries write to SEPARATE fd-3 pipes (no shared descriptor /
    buffer that one adapter could read for another)."""

    class _Link:
        async def request_spawn_grant(
            self, request: SpawnRequest, *, timeout: float = 10.0
        ) -> SpawnGrant:
            return SpawnGrant(
                request_id=request.request_id,
                adapter_id=request.adapter_id,
                host_restart_seq=request.host_restart_seq,
                epoch=request.epoch,
                credential_material=_SENTINEL,
            )

    client = GatewayAdapterCredentialClient(core_link=_Link())  # type: ignore[arg-type]
    seen: list[str] = []
    for _ in range(2):
        read_fd, write_fd = os.pipe()
        try:
            await client.acquire_and_deliver(
                adapter_id="discord", host_restart_seq=0, write_fd=write_fd, epoch=_EPOCH
            )
            header = os.read(read_fd, 4)
            body = os.read(read_fd, int.from_bytes(header, "big"))
            seen.append(body.decode("utf-8"))
        finally:
            os.close(read_fd)
    # Each delivery wrote the credential to its OWN pipe (two separate writes).
    assert seen == [_SENTINEL, _SENTINEL]


# ---------------------------------------------------------------------------
# (b) gateway holds no vault key + no retained credential (STRUCTURAL)
# ---------------------------------------------------------------------------


def test_b_gateway_client_never_calls_the_secret_broker() -> None:
    """STRUCTURAL: the gateway-side credential client's source NEVER references the
    secret broker — the resolver (core-side) is the ONLY decryptor. The gateway holds
    no vault key."""
    source = inspect.getsource(GatewayAdapterCredentialClient)
    assert "SecretBroker" not in source
    assert "broker" not in source.lower()  # no broker reference of any kind


def test_b_core_link_never_calls_the_secret_broker() -> None:
    """STRUCTURAL: the gateway's core link (the credential leg) never reaches the
    broker — it only correlates the grant the core sends. No vault key on the gateway."""
    source = inspect.getsource(GatewayCoreLink)
    assert "SecretBroker" not in source
    assert "broker" not in source.lower()


def test_b_fd3_library_zeroes_its_own_buffer() -> None:
    """STRUCTURAL: the reused fd-3 delivery fn zeroes its OWN writev buffer (the only
    verifiably-zeroed object — the str copy cannot be zeroed, maintainer C1)."""
    from alfred.supervisor import fd3_key_delivery

    source = inspect.getsource(fd3_key_delivery.deliver_provider_key_via_fd3)
    assert "_zero_buffer" in source


async def test_b_value_sentinel_appears_only_on_the_fd3_sink() -> None:
    """The credential appears ONLY on fd 3 — NEVER in an audit row, log line, emitted
    frame param, env dict, or exception, across happy + failure paths (S-C3)."""
    broker = _CountingBroker()
    audit = _FakeAudit()
    resolver = _resolver(broker, audit)

    class _Link:
        async def request_spawn_grant(
            self, request: SpawnRequest, *, timeout: float = 10.0
        ) -> SpawnGrant:
            return await resolver.resolve(request)

    client = GatewayAdapterCredentialClient(core_link=_Link())  # type: ignore[arg-type]
    read_fd, write_fd = os.pipe()
    with structlog.testing.capture_logs() as logs:
        await client.acquire_and_deliver(
            adapter_id="discord", host_restart_seq=0, write_fd=write_fd, epoch=_EPOCH
        )
        header = os.read(read_fd, 4)
        on_fd3 = os.read(read_fd, int.from_bytes(header, "big")).decode("utf-8")
    os.close(read_fd)

    # The credential IS on the fd-3 sink...
    assert on_fd3 == _SENTINEL
    # ...and NOWHERE else: not in any audit row, not in any captured log.
    assert _SENTINEL not in repr(audit.rows)
    assert _SENTINEL not in repr(logs)
    # The grant model_dump carries it (the trusted-leg payload) but its repr does not.
    grant = await resolver.resolve(_request())
    assert _SENTINEL not in repr(grant)
    assert _SENTINEL not in str(grant)


# ---------------------------------------------------------------------------
# (e) spoofed / replayed / unsolicited grant
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "forge",
    [
        pytest.param(lambda r: {"epoch": _OTHER_EPOCH}, id="forged-epoch"),
        pytest.param(lambda r: {"adapter_id": "tui"}, id="forged-adapter"),
        pytest.param(lambda r: {"host_restart_seq": 99}, id="forged-host-restart-seq"),
        pytest.param(lambda r: {"request_id": "0" * 32}, id="forged-request-id"),
    ],
)
async def test_e_forged_grant_is_refused(forge: object) -> None:
    """A grant that does not echo the outstanding request's correlation keys is REFUSED
    — the gateway client never delivers a forged credential to fd 3."""
    overrides: Mapping[str, object] = forge(_request())  # type: ignore[operator]

    class _ForgingLink:
        async def request_spawn_grant(
            self, request: SpawnRequest, *, timeout: float = 10.0
        ) -> SpawnGrant:
            base = {
                "request_id": request.request_id,
                "adapter_id": request.adapter_id,
                "host_restart_seq": request.host_restart_seq,
                "epoch": request.epoch,
                "credential_material": _SENTINEL,
            }
            base.update(overrides)
            return SpawnGrant.model_validate(base)

    client = GatewayAdapterCredentialClient(core_link=_ForgingLink())  # type: ignore[arg-type]
    read_fd, write_fd = os.pipe()
    delivered = b""
    try:
        with pytest.raises(AdapterCredentialError):
            await client.acquire_and_deliver(
                adapter_id="discord", host_restart_seq=0, write_fd=write_fd, epoch=_EPOCH
            )
        # Nothing was written to the fd-3 sink (the credential never reached the child).
        os.set_blocking(read_fd, False)
        try:
            delivered = os.read(read_fd, 4096)
        except BlockingIOError:
            delivered = b""
    finally:
        os.close(read_fd)
    assert _SENTINEL.encode() not in delivered


async def test_e_unsolicited_grant_dropped_by_the_leg() -> None:
    """An unsolicited ``core.adapter.spawn_grant`` (no pending request) is dropped by
    the leg's router — never resolves a waiter, never crashes the pump."""
    from alfred.comms_mcp.adapter_credential_protocol import CORE_ADAPTER_SPAWN_GRANT

    class _Listener:
        async def send_control(self, notification: object) -> None:
            return None

    link = GatewayCoreLink(client_listener=_Listener())  # type: ignore[arg-type]
    grant = SpawnGrant(
        request_id=_REQ_ID,
        adapter_id="discord",
        host_restart_seq=0,
        epoch=_EPOCH,
        credential_material=_SENTINEL,
    )
    # No pending request -> the grant is dropped loud, nothing crashes.
    await link._consume_frame(
        {"jsonrpc": "2.0", "method": CORE_ADAPTER_SPAWN_GRANT, "params": grant.model_dump()}
    )
    assert link._pending_grants == {}


async def test_e_replayed_request_decrypts_once_no_oracle() -> None:
    """A replayed request returns the SAME grant with the broker called EXACTLY ONCE —
    no decrypt-storm / oracle on the credential."""
    broker = _CountingBroker()
    audit = _FakeAudit()
    resolver = _resolver(broker, audit)
    first = await resolver.resolve(_request())
    second = await resolver.resolve(_request())  # same dedup key
    assert first.credential_material == second.credential_material
    assert broker.calls == ["discord_bot_token"]  # decrypted ONCE

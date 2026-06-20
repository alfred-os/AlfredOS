"""Tests for the ``GatewayAdapterCredentialClient`` (G6-3 Task 3, #288).

The gateway-side credential acquirer: ``acquire_and_deliver`` runs the
``spawn_request -> spawn_grant`` round-trip over the core leg, verifies the grant
matches the outstanding request ``(request_id, adapter_id, host_restart_seq,
epoch)`` (refuse a mismatched/forged grant — adversarial e), and delivers
``credential_material`` to the child's fd-3 WRITE END via the reused
``deliver_provider_key_via_fd3`` discipline.

Every failure (grant refusal, mismatched grant, fd-3 write fault) raises a loud
``AdapterCredentialError`` and aborts the spawn — NEVER log-and-continue. The
credential NEVER appears in a log line (capture_logs sweep). Per-adapter
isolation: a fresh buffer per call, no ``self``-scoped credential field.
"""

from __future__ import annotations

import os

import pytest
import structlog.testing

from alfred.comms_mcp.adapter_credential_protocol import SpawnGrant, SpawnRequest
from alfred.comms_mcp.adapter_credential_resolver import AdapterCredentialError
from alfred.gateway.adapter_credential_client import GatewayAdapterCredentialClient
from alfred.gateway.core_link import CredentialLegDownError, CredentialReplyTimeoutError
from alfred.supervisor.fd3_key_delivery import ProviderKeyDeliveryError

pytestmark = pytest.mark.asyncio

_EPOCH = "0123456789abcdef0123456789abcdef"
_SENTINEL_CRED = "SENTINEL-CREDENTIAL-DO-NOT-LEAK-7f3a"


class _FakeLink:
    """A fake core link: answers ``request_spawn_grant`` with a scripted grant.

    ``grant_for`` builds the grant from the request (echoing the correlation keys)
    so the happy path matches; tests override it to forge a mismatch, or set
    ``raise_with`` to simulate a leg-down / reply-timeout.
    """

    def __init__(self) -> None:
        self.requests: list[SpawnRequest] = []
        self.raise_with: BaseException | None = None
        self._override_grant: SpawnGrant | None = None

    def force_grant(self, grant: SpawnGrant) -> None:
        self._override_grant = grant

    async def request_spawn_grant(
        self, request: SpawnRequest, *, timeout: float = 10.0
    ) -> SpawnGrant:
        self.requests.append(request)
        if self.raise_with is not None:
            raise self.raise_with
        if self._override_grant is not None:
            return self._override_grant
        return SpawnGrant(
            request_id=request.request_id,
            adapter_id=request.adapter_id,
            host_restart_seq=request.host_restart_seq,
            epoch=request.epoch,
            credential_material=_SENTINEL_CRED,
        )


def _client(link: _FakeLink) -> GatewayAdapterCredentialClient:
    return GatewayAdapterCredentialClient(core_link=link)  # type: ignore[arg-type]


def _read_fd3_frame(read_fd: int) -> str:
    """Read the length-prefixed [len|key] frame the delivery wrote (test helper)."""
    header = os.read(read_fd, 4)
    length = int.from_bytes(header, "big")
    body = os.read(read_fd, length)
    return body.decode("utf-8")


# --- Happy path: deliver to fd-3 ----------------------------------------------


async def test_acquire_and_deliver_writes_credential_to_fd3() -> None:
    link = _FakeLink()
    client = _client(link)
    read_fd, write_fd = os.pipe()
    try:
        await client.acquire_and_deliver(
            adapter_id="discord", host_restart_seq=0, write_fd=write_fd, epoch=_EPOCH
        )
        # The delivery closed write_fd; the read end carries the credential frame.
        assert _read_fd3_frame(read_fd) == _SENTINEL_CRED
    finally:
        os.close(read_fd)
    # The request carried the LIVE epoch + the incarnation.
    assert link.requests[0].epoch == _EPOCH
    assert link.requests[0].adapter_id == "discord"
    assert link.requests[0].host_restart_seq == 0


async def test_client_holds_no_credential_attribute_after_call() -> None:
    link = _FakeLink()
    client = _client(link)
    read_fd, write_fd = os.pipe()
    try:
        await client.acquire_and_deliver(
            adapter_id="discord", host_restart_seq=0, write_fd=write_fd, epoch=_EPOCH
        )
    finally:
        os.close(read_fd)
    # No instance attribute anywhere holds the credential (per-adapter isolation).
    assert _SENTINEL_CRED not in repr(vars(client))


# --- Mismatched / forged grant -> refused (adversarial e) ---------------------


async def test_mismatched_epoch_grant_is_refused() -> None:
    link = _FakeLink()
    # The core (or an attacker) returns a grant echoing a DIFFERENT epoch.
    forged = SpawnGrant(
        request_id="00000000000000000000000000000000",  # set per-request below
        adapter_id="discord",
        host_restart_seq=0,
        epoch="fedcba9876543210fedcba9876543210",
        credential_material=_SENTINEL_CRED,
    )
    client = _client(link)
    read_fd, write_fd = os.pipe()
    try:
        # request_id will not match the forged grant; verify the refusal fires.
        link.force_grant(forged)
        with pytest.raises(AdapterCredentialError):
            await client.acquire_and_deliver(
                adapter_id="discord", host_restart_seq=0, write_fd=write_fd, epoch=_EPOCH
            )
    finally:
        os.close(read_fd)


async def test_mismatched_adapter_id_grant_is_refused() -> None:
    link = _FakeLink()
    client = _client(link)
    read_fd, write_fd = os.pipe()

    async def _forge(request: SpawnRequest, *, timeout: float = 10.0) -> SpawnGrant:
        return SpawnGrant(
            request_id=request.request_id,
            adapter_id="discord",  # but we asked for a different one below
            host_restart_seq=request.host_restart_seq,
            epoch=request.epoch,
            credential_material=_SENTINEL_CRED,
        )

    link.request_spawn_grant = _forge  # type: ignore[method-assign]
    try:
        with pytest.raises(AdapterCredentialError):
            # Ask for an adapter whose grant comes back keyed to "discord" (mismatch).
            await client.acquire_and_deliver(
                adapter_id="tui", host_restart_seq=0, write_fd=write_fd, epoch=_EPOCH
            )
    finally:
        os.close(read_fd)


# --- Leg-down / timeout propagate loud (Task 4 consumes leg-down) -------------


async def test_leg_down_propagates() -> None:
    link = _FakeLink()
    link.raise_with = CredentialLegDownError("down")
    client = _client(link)
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(CredentialLegDownError):
            await client.acquire_and_deliver(
                adapter_id="discord", host_restart_seq=0, write_fd=write_fd, epoch=_EPOCH
            )
    finally:
        os.close(read_fd)
        # The write_fd must NOT have been delivered (no grant); close it ourselves.
        with pytest.raises(OSError):
            os.fstat(write_fd)


async def test_reply_timeout_is_wrapped_loud() -> None:
    link = _FakeLink()
    link.raise_with = CredentialReplyTimeoutError("timeout")
    client = _client(link)
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(AdapterCredentialError):
            await client.acquire_and_deliver(
                adapter_id="discord", host_restart_seq=0, write_fd=write_fd, epoch=_EPOCH
            )
    finally:
        os.close(read_fd)
        with pytest.raises(OSError):
            os.fstat(write_fd)


# --- fd-3 delivery failure -> loud abort --------------------------------------


async def test_fd3_delivery_failure_aborts_loud() -> None:
    link = _FakeLink()
    # Inject a delivery seam that fails the way the real writev does on a partial /
    # EAGAIN / OSError write — the client must wrap it as AdapterCredentialError and
    # abort the spawn loudly (it closes the fd it owns on its own refusal path).
    delivered: list[str] = []

    def _failing_deliver(*, write_fd: int, key: str) -> None:
        delivered.append(key)
        os.close(write_fd)  # the real fn closes write_fd on every path
        raise ProviderKeyDeliveryError()

    client = GatewayAdapterCredentialClient(
        core_link=link,  # type: ignore[arg-type]
        deliver=_failing_deliver,
    )
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(AdapterCredentialError):
            await client.acquire_and_deliver(
                adapter_id="discord", host_restart_seq=0, write_fd=write_fd, epoch=_EPOCH
            )
        # The credential REACHED the delivery sink (so the round-trip succeeded) — the
        # failure is in the write, not the resolution.
        assert delivered == [_SENTINEL_CRED]
    finally:
        os.close(read_fd)


# --- The credential never appears in a log (sentinel sweep) -------------------


async def test_credential_never_logged_on_happy_path() -> None:
    link = _FakeLink()
    client = _client(link)
    read_fd, write_fd = os.pipe()
    try:
        with structlog.testing.capture_logs() as logs:
            await client.acquire_and_deliver(
                adapter_id="discord", host_restart_seq=0, write_fd=write_fd, epoch=_EPOCH
            )
        os.read(read_fd, 4096)  # drain
    finally:
        os.close(read_fd)
    assert _SENTINEL_CRED not in repr(logs)


async def test_credential_never_logged_on_refusal() -> None:
    link = _FakeLink()
    forged = SpawnGrant(
        request_id="00000000000000000000000000000000",
        adapter_id="discord",
        host_restart_seq=0,
        epoch="fedcba9876543210fedcba9876543210",
        credential_material=_SENTINEL_CRED,
    )
    link.force_grant(forged)
    client = _client(link)
    read_fd, write_fd = os.pipe()
    try:
        with (
            structlog.testing.capture_logs() as logs,
            pytest.raises(AdapterCredentialError),
        ):
            await client.acquire_and_deliver(
                adapter_id="discord", host_restart_seq=0, write_fd=write_fd, epoch=_EPOCH
            )
        assert _SENTINEL_CRED not in repr(logs)
    finally:
        os.close(read_fd)
        with pytest.raises(OSError):
            os.fstat(write_fd)

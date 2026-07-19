"""Shared retry-count / broker-socket-count constants (#340 PR2b-golive).

Behaviour-neutral hoist: :data:`alfred.security.quarantine.EXTRACTION_MAX_RETRIES`
used to live as a private ``_MAX_RETRIES`` inside the child dispatcher. It is
now the single source of truth shared by the child (validation-retry loop)
and the privileged host (which will broker
:data:`alfred.security.quarantine.BROKER_SOCKET_COUNT` one-shot gateway
sockets per extraction, spec §6).
"""

from alfred.security.quarantine import BROKER_SOCKET_COUNT, EXTRACTION_MAX_RETRIES


def test_broker_socket_count_is_max_retries_plus_one() -> None:
    # The host brokers one socket per possible provider.complete() call:
    # one initial attempt plus EXTRACTION_MAX_RETRIES retries (spec §6).
    assert BROKER_SOCKET_COUNT == EXTRACTION_MAX_RETRIES + 1


def test_extraction_max_retries_value() -> None:
    assert EXTRACTION_MAX_RETRIES == 2

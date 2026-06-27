from __future__ import annotations

import pytest

from alfred.egress.errors import (
    EgressDeniedError,
    EgressRelayUnavailableError,
    IOPlaneUnavailableError,
)
from alfred.errors import AlfredError


def test_io_plane_unavailable_is_alfred_error_with_reason() -> None:
    err = IOPlaneUnavailableError(detail="connect timeout to alfred-gateway:8889")
    assert isinstance(err, AlfredError)
    assert err.reason == "io_plane_unavailable"
    assert "connect timeout" in str(err)


def test_relay_unavailable_is_an_io_plane_subtype_with_distinct_reason() -> None:
    err = EgressRelayUnavailableError(detail="address already in use")
    # A subtype of IOPlaneUnavailableError (generic I/O-plane handling still applies)…
    assert isinstance(err, IOPlaneUnavailableError)
    assert isinstance(err, AlfredError)
    # …but with a DISTINCT audit token + its own relay-specific message.
    assert err.reason == "egress_relay_unavailable"
    assert err.detail == "address already in use"
    assert "address already in use" in str(err)


def test_egress_denied_carries_destination_and_deny_reason() -> None:
    err = EgressDeniedError(
        destination="evil.example:443", deny_reason="destination_not_allowlisted"
    )
    assert isinstance(err, AlfredError)
    assert err.reason == "egress_denied"  # class-level audit token, never shadowed
    assert err.destination == "evil.example:443"
    assert err.deny_reason == "destination_not_allowlisted"
    assert "evil.example:443" in str(err)


@pytest.mark.parametrize(
    "make",
    [
        lambda: IOPlaneUnavailableError(detail="x"),
        lambda: EgressRelayUnavailableError(detail="x"),
        lambda: EgressDeniedError(destination="h:1", deny_reason="r"),
    ],
)
def test_errors_render_a_nonempty_message(make) -> None:
    assert str(make())

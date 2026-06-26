from __future__ import annotations

import pytest

from alfred.egress.errors import EgressDeniedError, IOPlaneUnavailableError
from alfred.errors import AlfredError


def test_io_plane_unavailable_is_alfred_error_with_reason() -> None:
    err = IOPlaneUnavailableError(detail="connect timeout to alfred-gateway:8889")
    assert isinstance(err, AlfredError)
    assert err.reason == "io_plane_unavailable"
    assert "connect timeout" in str(err)


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
        lambda: EgressDeniedError(destination="h:1", deny_reason="r"),
    ],
)
def test_errors_render_a_nonempty_message(make) -> None:
    assert str(make())

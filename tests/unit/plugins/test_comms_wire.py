"""The shared comms-wire constants leaf module (Spec A G2 / ADR-0032) (#237).

``comms_wire`` holds the per-frame DoS bound + the loud-failure type that the
comms transports AND the seq/ack codec all import — a leaf module that breaks the
codec<->transport import cycle (architect F6). These cases pin the relocated
values + the re-export contract so a future refactor cannot quietly fork them.
"""

from __future__ import annotations

from alfred.plugins import (
    comms_seq_codec,
    comms_socket_transport,
    comms_stdio_transport,
)
from alfred.plugins.comms_wire import _MAX_COMMS_LINE_BYTES, CommsProtocolError


def test_bound_is_the_ten_mib_dos_cap() -> None:
    assert _MAX_COMMS_LINE_BYTES == 10 * 1024 * 1024


def test_protocol_error_is_an_alfred_error() -> None:
    from alfred.errors import AlfredError

    assert issubclass(CommsProtocolError, AlfredError)


def test_transports_reexport_the_same_objects() -> None:
    """Existing importers (stdio/socket) re-export the IDENTICAL bound + class."""
    assert comms_stdio_transport._MAX_COMMS_LINE_BYTES is _MAX_COMMS_LINE_BYTES
    assert comms_stdio_transport.CommsProtocolError is CommsProtocolError
    assert comms_socket_transport.CommsProtocolError is CommsProtocolError
    assert comms_socket_transport._MAX_COMMS_LINE_BYTES is _MAX_COMMS_LINE_BYTES


def test_no_import_cycle_when_importing_the_codec() -> None:
    """The codec imports the bound from comms_wire, not the transport."""
    assert comms_seq_codec._MAX_COMMS_LINE_BYTES is _MAX_COMMS_LINE_BYTES

"""Executable proof for de-2026-015 — the gateway L7 forward-proxy refuses a
literal-IP CONNECT (Spec C §4.1; §9 class 5). Drives the REAL EgressForwardProxy
`_serve_connection` with an in-memory literal-IP CONNECT and asserts the 403 +
`literal_ip_target` audit reason — elevating the unit-level
test_egress_proxy.py::test_connect_literal_ip_denied into the release-blocking
adversarial corpus. Harness mirrors tests/unit/gateway/test_egress_proxy.py.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import yaml

from alfred.egress.allowlist import exact_match, is_literal_ip
from alfred.gateway.egress_proxy import EgressForwardProxy
from tests.adversarial.payload_schema import AdversarialPayload

_YAML = Path(__file__).parent / "de_egress_literal_ip_connect_refused.yaml"
_ALLOWLIST = frozenset({("api.anthropic.com", 443)})


class _CaptureWriter:
    """In-memory StreamWriter stand-in (mirrors test_egress_proxy._CaptureWriter)."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.closed = False
        self.eof = False

    def write(self, data: bytes) -> None:
        self.buf += data

    async def drain(self) -> None:
        return None

    def write_eof(self) -> None:
        self.eof = True

    def close(self) -> None:
        self.closed = True


def _reader_with(payload: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return reader


def _load() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_YAML.read_text()))


def test_de_2026_015_schema_valid_and_target_is_literal_ip() -> None:
    payload = _load()
    assert payload.id == "de-2026-015"
    assert payload.out_of_scope is False
    assert payload.expected_outcome == "refused"
    # `payload.payload` is typed `str | dict`; these entries always use a mapping.
    # Narrow it (convention parity with test_de_egress_content_type_laundering.py).
    assert isinstance(payload.payload, dict)
    # The guard precondition: the payload's target genuinely IS a literal IP.
    assert is_literal_ip(payload.payload["literal_ip_target"]) is True


@pytest.mark.asyncio
async def test_de_2026_015_literal_ip_connect_refused() -> None:
    payload = _load()
    assert isinstance(payload.payload, dict)
    audit: list[tuple[str, dict[str, object]]] = []

    async def _never_open(_ip: str, _port: int) -> tuple[asyncio.StreamReader, _CaptureWriter]:
        raise AssertionError("upstream must not open for a literal-IP CONNECT")

    proxy = EgressForwardProxy(
        allowlist=_ALLOWLIST,
        match=exact_match,
        bind_host="127.0.0.1",
        port=0,
        audit=lambda event, fields: audit.append((event, fields)),
        resolve=lambda _h: "1.1.1.1",
        open_upstream=_never_open,  # type: ignore[arg-type]
    )
    writer = _CaptureWriter()
    request = (str(payload.payload["connect_request"]) + "\r\n\r\n").encode()
    await asyncio.wait_for(
        proxy._serve_connection(_reader_with(request), writer),  # type: ignore[arg-type]
        timeout=5,
    )
    assert b"403" in writer.buf, "a literal-IP CONNECT must be refused with 403"
    # Self-distinguishing: `_deny` writes the reason into the status line, so this
    # separates the literal-IP deny from a generic not-allowlisted 403 (both 403).
    assert b"literal_ip_target" in writer.buf
    assert any(f.get("reason") == "literal_ip_target" for _, f in audit), (
        "the refusal must audit reason=literal_ip_target"
    )
    # No executor-drain teardown: the literal-IP path denies at _authorize BEFORE
    # any off-loop resolve, so no worker thread accumulates (unlike the resolve
    # path that test_egress_proxy's autouse fixture drains).

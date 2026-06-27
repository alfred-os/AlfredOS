"""Framed-transport envelopes + frame helpers for the core↔gateway tool-egress relay.

Spec C §4.2 mode-(b), epic #333. The connectivity-free core cannot open external
sockets, so for inspectable tool egress it hands a redacted :class:`EgressRequest`
to the gateway's :class:`alfred.gateway.egress_relay.EgressRelay` over a
**length-prefixed JSON-frame protocol on ``asyncio.start_server``** (the architect's
round-2 ruling — NOT HTTP POST, and NOT the payload-blind CONNECT proxy): the
core relay client speaks raw asyncio frames, so there is no second in-core httpx
construction site, and the parse surface is one ``extra="forbid"`` model rather
than a hand-rolled HTTP/1.1 server (no Content-Length / Transfer-Encoding
smuggling). The gateway re-runs DLP, enforces the SSRF chain, originates the real
TLS, and returns an :class:`EgressResponse`.

This module is the ONE wire-bytes definition shared by both ends (the gateway
server in B4 and the in-core client in C1), so the framing can never drift. It is
pure (Pydantic + asyncio stream helpers) — NO httpx, so it is not on the in-core
HTTP-egress import-guard allowlist.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict

# 4-byte big-endian unsigned length prefix → frames up to 4 GiB are *representable*;
# the per-read ``max_len`` bound (a small cap the caller chooses) is what actually
# protects against an unbounded/oversized read.
_LENGTH_PREFIX_BYTES = 4


class FrameTooLargeError(ValueError):
    """A frame's declared length exceeds the caller's ``max_len`` bound.

    Subclasses :class:`ValueError` so a generic parse-fault catch still works, but
    is a distinct type so the gateway can map it to a ``MALFORMED_ENVELOPE`` deny
    and a test can assert the no-unbounded-read property precisely. Raised on the
    length PREFIX alone — the oversized payload is never read.
    """


class EgressRequest(BaseModel):
    """The redacted tool-egress request the core sends the gateway (mode-b).

    ``body`` is the **already-redacted** request body (the core ran its DLP pass
    first); the gateway re-runs the secret-independent DLP stages on it. ``egress_id``
    is the deterministic idempotency key (internal correlation only — it is NOT
    forwarded upstream by default; §5 honest at-most-once contract).
    """

    method: str
    url: str
    headers: Mapping[str, str]
    body: str
    egress_id: str
    model_config = ConfigDict(frozen=True, extra="forbid")


class EgressResponse(BaseModel):
    """The upstream response the gateway returns to the core.

    ``body`` is **raw T3** and may be arbitrary bytes (web responses are not
    necessarily UTF-8 — PDFs, images, deliberately-mangled encodings). It is a
    ``bytes`` field serialised as **base64** on the JSON frame so it round-trips
    byte-exact (a naive ``bytes.decode("utf-8")`` would raise/corrupt on binary).
    The core mints a ``ContentHandle`` from these exact bytes (C2), so the wire
    representation MUST be lossless.
    """

    status: int
    headers: Mapping[str, str]
    body: bytes
    model_config = ConfigDict(
        frozen=True, extra="forbid", ser_json_bytes="base64", val_json_bytes="base64"
    )


class _RawToolRequest(BaseModel):
    """The in-core PRE-redaction tool request (consumed by the C1/C2 relay client).

    Modelled as empty/optional-body defence-in-depth infrastructure (ARCH-3): the
    live GET-only ``web.fetch`` consumer sends no body, so ``body`` defaults to
    ``""`` and only the synthetic body-sending driver populates it. ``idempotent``
    is the manifest-declared idempotency flag that gates the H3 in-doubt
    auto-refire — default ``False`` means an in-doubt egress REFUSES rather than
    blindly re-firing.
    """

    method: str
    url: str
    headers: Mapping[str, str]
    body: str = ""
    idempotent: bool = False
    model_config = ConfigDict(frozen=True, extra="forbid")


async def read_frame(reader: asyncio.StreamReader, *, max_len: int) -> bytes:
    """Read one length-prefixed frame, bounding the payload at ``max_len``.

    Reads the 4-byte big-endian length prefix first and refuses (``FrameTooLargeError``)
    a declared length over ``max_len`` BEFORE reading any payload bytes — so a
    crafted oversized prefix can never trigger an unbounded read. A truncated
    prefix or body (EOF mid-frame) raises :class:`asyncio.IncompleteReadError`.
    The per-read TIMEOUT is the caller's responsibility (mirrors
    ``egress_proxy._read_connect_target``'s bounded-read discipline).
    """
    prefix = await reader.readexactly(_LENGTH_PREFIX_BYTES)
    length = int.from_bytes(prefix, "big")
    if length > max_len:
        raise FrameTooLargeError(
            f"egress relay frame declares {length} bytes, exceeding max_len {max_len}"
        )
    return await reader.readexactly(length)


async def write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    """Write one length-prefixed frame (4-byte big-endian length + payload), then drain."""
    writer.write(len(payload).to_bytes(_LENGTH_PREFIX_BYTES, "big") + payload)
    await writer.drain()


__all__ = [
    "EgressRequest",
    "EgressResponse",
    "FrameTooLargeError",
    "_RawToolRequest",
    "read_frame",
    "write_frame",
]

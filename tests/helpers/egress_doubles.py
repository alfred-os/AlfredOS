"""Shared in-memory doubles for egress relay tests.

Extracted from both ``tests/integration/egress/conftest.py`` and
``tests/adversarial/dlp_egress/conftest.py``, which previously maintained
duplicated copies of these four classes.  The canonical type annotations live
here; each directory-scoped conftest imports the classes and builds its own
``fake_external_world`` pytest fixture around them (fixtures are directory-
scoped, so they cannot be shared via import, but the *classes* can).

The ``_FakeClient`` / ``_FakeResponse`` shapes mirror the unit-test doubles in
``tests/unit/gateway/test_egress_relay.py``.  The contract is:

* ``_FakeClient.build_request`` builds an ``httpx.Request``.
* ``_FakeClient.send`` increments ``fire_count`` and returns the canned
  response — so every relay round-trip counts as one upstream hit.
* ``_FakeClient.aclose`` is a no-op.
* ``_FakeResponse`` has ``status_code``, ``headers``, ``is_redirect``,
  ``async aiter_bytes() -> AsyncIterator[bytes]``, and ``async aclose()``.

Three extra test doubles are also provided here so they are not duplicated
across test modules:

* ``_await_relay_ready`` — probes until the relay's listener accepts a
  TCP connection; used in every integration/adversarial test that starts
  a loopback ``EgressRelay``.
* ``_CapturingAuditWriter`` — records every ``append_schema`` call into
  ``rows``; used by adversarial dlp_egress tests that assert audit rows.
* ``_NullAuditWriter`` — discards every ``append_schema`` call; used by
  barrier and contention tests where audit content is not under test.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx


class _FireCounter:
    """Shareable mutable fire counter.

    A plain integer would not be visible to both the fake client and the test
    body because each closure would rebind the local.  We use a class with a
    single ``value`` attribute so all closures hold the SAME reference.
    """

    def __init__(self) -> None:
        self.value: int = 0


@dataclass
class _CannedResponse:
    """Holder for the upstream response the fake client will return.

    Mutable so the test body can change the canned response between rounds
    (e.g. a TTL-prune scenario sets a new body after the sweep, proving
    re-fire uses the new canned response, not the old ledger replay).
    """

    status_code: int = 200
    headers: dict[str, str] = field(default_factory=lambda: {"content-type": "text/plain"})
    body: bytes = b"fake-upstream-body"


class _FakeResponse:
    """Minimal upstream-response double.

    The relay reads the response body via ``aiter_bytes()`` and calls
    ``aclose()`` on teardown.  The body is yielded as a SINGLE chunk so
    the relay's byte-cap comparison is simple.
    """

    def __init__(self, canned: _CannedResponse) -> None:
        self.status_code = canned.status_code
        self.headers = canned.headers
        self._body = canned.body
        self.is_redirect = False

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        yield self._body

    async def aclose(self) -> None:
        return None


class _FakeClient:
    """In-memory upstream double.

    ``build_request`` constructs an ``httpx.Request`` (the relay passes it
    back to ``send``); ``send`` INCREMENTS ``fire_count`` and returns the
    current canned response — so every relay round-trip counts as one upstream
    hit, regardless of dedup/ledger state.  ``aclose`` is a no-op.
    """

    def __init__(self, fire_counter: _FireCounter, canned: _CannedResponse) -> None:
        self._fire_counter = fire_counter
        self._canned = canned

    def build_request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        content: Any,
    ) -> httpx.Request:
        return httpx.Request(method, url, headers=headers, content=content)

    async def send(
        self,
        request: httpx.Request,
        *,
        follow_redirects: bool,
        stream: bool = False,
    ) -> _FakeResponse:
        self._fire_counter.value += 1
        return _FakeResponse(self._canned)

    async def aclose(self) -> None:
        return None


def make_fake_external_world() -> tuple[
    Callable[[], _FakeClient],
    _FireCounter,
    _CannedResponse,
]:
    """Return ``(open_client_factory, fire_counter, canned_response)``.

    * ``open_client_factory`` — a zero-argument callable returning a fresh
      ``_FakeClient`` bound to the shared ``fire_counter`` and
      ``canned_response``; inject as the relay's ``open_client`` seam.
    * ``fire_counter`` — a ``_FireCounter`` whose ``.value`` increments each
      time the relay's ``send`` is called; tests assert on this to prove the
      upstream was (or was not) hit.
    * ``canned_response`` — a ``_CannedResponse`` whose fields can be mutated
      between test rounds.

    Used by the ``fake_external_world`` pytest fixture in both
    ``tests/integration/egress/conftest.py`` and
    ``tests/adversarial/dlp_egress/conftest.py``.  The fixture itself stays
    directory-scoped (pytest constraint); only the construction logic is shared.
    """
    fire_counter = _FireCounter()
    canned = _CannedResponse()

    def _factory() -> _FakeClient:
        return _FakeClient(fire_counter, canned)

    return _factory, fire_counter, canned


async def _await_relay_ready(port: int, serve_task: asyncio.Task[Any]) -> None:
    """Probe until the relay's listener accepts a TCP connection.

    A fixed sleep on a busy runner can race the bind; probing eliminates
    the race.  The relay reaps the benign probe as a ``FrameTooLargeError``
    / ``MALFORMED_ENVELOPE`` deny, harmless to the test assertions.

    Raises ``AssertionError`` if the relay does not become ready within
    2.5 seconds (500 x 5 ms) or if ``serve_task`` exits early with an
    error.
    """
    for _ in range(500):
        if serve_task.done():
            await serve_task  # re-raise a bind error rather than spinning
        try:
            _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.005)
            continue
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), timeout=1)
        return
    raise AssertionError("EgressRelay did not become ready within 2.5 s")


async def _await_bound_port(relay: Any, serve_task: asyncio.Task[Any]) -> int:
    """Poll until ``relay`` reports its OS-assigned bound port (``port=0`` bind).

    Eliminates the close-then-rebind free-port TOCTOU: bind the relay to port 0,
    then read the actual port back off ``relay.bound_port`` once :meth:`serve`
    has bound it. Re-raises a bind error if ``serve_task`` exits early.

    Raises ``AssertionError`` if the relay does not report a port within
    2.5 seconds (500 x 5 ms).
    """
    for _ in range(500):
        if serve_task.done():
            await serve_task  # re-raise a bind error rather than spinning
        port: int | None = relay.bound_port
        if port is not None:
            return port
        await asyncio.sleep(0.005)
    raise AssertionError("EgressRelay did not report a bound port within 2.5 s")


class _CapturingAuditWriter:
    """AuditWriter stub that captures every ``append_schema`` call into ``rows``.

    Used by adversarial dlp_egress tests that assert on the audit rows
    emitted by ``RelayEgressClient`` on refusal paths.  Stores the full
    call kwargs (including ``subject``) so tests can assert payload-blind
    field shapes.
    """

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def append_schema(self, **kwargs: Any) -> None:
        self.rows.append(dict(kwargs))


class _NullAuditWriter:
    """AuditWriter stub that discards every ``append_schema`` call.

    Used by barrier and contention tests where audit content is not the
    property under test — the egress idempotency ledger is.
    """

    async def append_schema(self, **_kw: Any) -> None:
        return None


__all__ = [
    "_CannedResponse",
    "_CapturingAuditWriter",
    "_FakeClient",
    "_FakeResponse",
    "_FireCounter",
    "_NullAuditWriter",
    "_await_bound_port",
    "_await_relay_ready",
    "make_fake_external_world",
]

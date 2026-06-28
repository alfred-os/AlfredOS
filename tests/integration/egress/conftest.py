"""Shared fixtures for ``tests/integration/egress/`` (Spec C G7-2c-2, #333).

``fake_external_world``
    Epic-wide fixture that substitutes the relay's injectable ``open_client``
    seam with a deterministic in-memory double.  Every test in the G7-2c-2 and
    C5 suites that needs to count upstream fires or control canned responses
    uses this single shared fixture rather than constructing their own doubles.

The ``_FakeClient`` / ``_FakeResponse`` shapes mirror the unit-test doubles in
``tests/unit/gateway/test_egress_relay.py`` (the relay's own ``_FakeClient``
and ``_FakeResponse``); the contract is: ``build_request`` builds an
``httpx.Request``, ``send`` increments ``fire_count`` and returns the canned
response (an ``_FakeResponse``), ``aclose`` is a no-op; the response has
``status_code``, ``headers``, ``async aiter_bytes()``, and ``async aclose()``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

# ---------------------------------------------------------------------------
# Fire counter — a mutable reference (list[int]) so the inner closures and the
# test body share the same object (no aliasing issue with plain int).
# ---------------------------------------------------------------------------


class _FireCounter:
    """Shareable mutable fire counter.

    A plain integer would not be visible to both the fake client and the test
    body because each closure would rebind the local.  We use a class with a
    single ``value`` attribute so all closures hold the SAME reference.
    """

    def __init__(self) -> None:
        self.value: int = 0


# ---------------------------------------------------------------------------
# Canned response holder — allows a single test to swap the response body
# (e.g. Scenario C sets a different body after TTL prune).
# ---------------------------------------------------------------------------


@dataclass
class _CannedResponse:
    """Holder for the upstream response the fake client will return.

    Mutable so the test body can change the canned response between rounds
    (e.g. C sets a new body after the TTL prune, proving re-fire uses the
    new canned response, not the old ledger replay).
    """

    status_code: int = 200
    headers: dict[str, str] = field(default_factory=lambda: {"content-type": "text/plain"})
    body: bytes = b"fake-upstream-body"


# ---------------------------------------------------------------------------
# Fake response — mirrors _FakeResponse in test_egress_relay.py
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Fake client — mirrors _FakeClient in test_egress_relay.py
# ---------------------------------------------------------------------------


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
        return httpx.Request(method, url, headers=headers, content=content)  # type: ignore[arg-type]

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


# ---------------------------------------------------------------------------
# fake_external_world fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_external_world() -> tuple[
    Callable[[], _FakeClient],  # open_client_factory — inject as the relay's open_client seam
    _FireCounter,  # shared fire counter
    _CannedResponse,  # mutable canned response holder
]:
    """Yield ``(open_client_factory, fire_counter, canned_response)``.

    * ``open_client_factory`` — a zero-argument callable returning a fresh
      ``_FakeClient`` bound to the shared ``fire_counter`` and
      ``canned_response``; inject it as the relay's ``open_client`` seam.
    * ``fire_counter`` — a ``_FireCounter`` whose ``.value`` increments each
      time the relay's ``send`` is called; tests assert on this to prove the
      upstream was (or was not) hit.
    * ``canned_response`` — a ``_CannedResponse`` whose fields can be mutated
      between test rounds (Scenario C swaps the body after TTL prune).

    Epic-wide (G7-2c-2 barrier test + C5 contention suite) — a single,
    deterministic shared fixture so the counter and canned response are never
    duplicated across test modules.
    """
    fire_counter = _FireCounter()
    canned = _CannedResponse()

    def _factory() -> _FakeClient:
        return _FakeClient(fire_counter, canned)

    return _factory, fire_counter, canned


__all__ = ["fake_external_world"]

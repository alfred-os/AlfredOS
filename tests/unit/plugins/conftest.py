"""Shared fixtures for ``tests/unit/plugins/``.

``fake_audit_writer`` / ``fake_broker`` / ``stub_nonce`` are the structural
stand-ins for the production ``AuditWriter`` / ``SecretBroker`` /
``CapabilityGateNonce`` collaborators of :class:`StdioTransport`. They live
in this conftest because every Slice-3 plugin-host test file consumes them
and inlining the same MagicMock setup in each test would diverge over time
(field-name typo on one site silently shadowing the real field on another).

Fixture intent:

* ``fake_audit_writer`` exposes ``append_schema`` as an async mock that
  records the last ``event`` string and every captured kwargs dict. The
  StdioTransport calls ``append_schema`` (not ``append``) so the schema-
  validation contract from PR-S3-0a is exercised.
* ``fake_broker`` exposes an awaitable ``substitute`` returning the input
  params unchanged by default; individual tests override the return value
  for substitution-correctness assertions.
* ``stub_nonce`` installs a fresh :class:`CapabilityGateNonce` as the
  module-level authorised slot for the duration of the test (mirrors
  ``tests/unit/security/conftest.py::authorized_t3_nonce``). Acquired
  under ``_NONCE_LOCK`` so the fixture is race-safe against any
  bootstrap path that might run in parallel.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.security import tiers as _tiers
from alfred.security.tiers import CapabilityGateNonce


@pytest.fixture
def fake_audit_writer() -> MagicMock:
    """``MagicMock`` whose ``append_schema`` records calls on ``.calls``.

    The StdioTransport always emits via ``append_schema`` with the
    ``schema_name`` kwarg (CR-138 R3 pattern, Cluster 4 fix). The fake
    records every kwargs dict on ``.calls`` and exposes ``.last_event``
    for succinct assertions in DLP refusal tests.
    """
    writer = MagicMock()
    writer.calls = []
    writer.last_event = None

    async def _capture(**kwargs: Any) -> None:
        writer.calls.append(kwargs)
        writer.last_event = kwargs.get("event")

    writer.append_schema = AsyncMock(side_effect=_capture)
    return writer


@pytest.fixture
def fake_broker() -> MagicMock:
    """SecretBroker stand-in with awaitable ``substitute`` returning input.

    The default identity-return semantics let dispatch tests skip secret-
    substitution noise; the DLP-ordering test overrides
    ``substitute.return_value`` (or ``.side_effect``) to assert the
    placeholder-vs-substituted invariant (arch-001).
    """
    broker = MagicMock()
    broker.substitute = AsyncMock(side_effect=lambda params: params)
    return broker


@pytest.fixture
def stub_nonce() -> Iterator[CapabilityGateNonce]:
    """Install a fresh authorised :class:`CapabilityGateNonce` for the test.

    Mirrors ``tests/unit/security/conftest.py::authorized_t3_nonce``: the
    fixture saves the previous slot value, installs a fresh nonce, yields
    it for the test to pass as ``inbound_t3_nonce``, then restores the
    previous slot on teardown. The save/install/restore sequence runs
    inside :data:`alfred.bootstrap.nonce_factory._NONCE_LOCK` so it stays
    race-safe against any concurrent bootstrap path.

    The yielded nonce is the *same object* the gate's identity check
    (``caller_token is _AUTHORIZED_T3_NONCE``) accepts. A MagicMock would
    fail that check and route every T3 tag through the refusal path.
    """
    with _NONCE_LOCK:
        previous = _tiers._AUTHORIZED_T3_NONCE
        nonce = CapabilityGateNonce()
        _tiers._set_authorized_t3_nonce(nonce)
    try:
        yield nonce
    finally:
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(previous)

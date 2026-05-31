"""Shared fixtures for ``tests/unit/plugins/``.

``fake_audit_writer`` / ``fake_broker`` / ``stub_nonce`` are the structural
stand-ins for the production ``AuditWriter`` / ``SecretBroker`` /
``CapabilityGateNonce`` collaborators of :class:`StdioTransport`. They live
in this conftest because every Slice-3 plugin-host test file consumes them
and inlining the same MagicMock setup in each test would diverge over time
(field-name typo on one site silently shadowing the real field on another).

Fixture intent:

* ``fake_audit_writer`` exposes ``append_schema`` as an async mock that
  records the last ``event`` string. The StdioTransport calls
  ``append_schema`` (not ``append``) so the schema-validation contract from
  PR-S3-0a is exercised.
* ``fake_broker`` exposes an awaitable ``substitute`` returning the input
  params unchanged by default; individual tests override the return value
  for substitution-correctness assertions.
* ``stub_nonce`` returns the real :class:`CapabilityGateNonce` so identity
  comparisons inside ``tag_t3_with_nonce`` reach the production gate
  surface. A MagicMock would short-circuit the gate's ``is`` check.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.bootstrap import nonce_factory
from alfred.security.tiers import CapabilityGateNonce


@pytest.fixture
def fake_audit_writer() -> MagicMock:
    """``MagicMock`` whose ``append_schema`` records ``event`` on ``.last_event``.

    The StdioTransport always emits via ``append_schema`` with
    ``schema_name`` kwarg (CR-138 R3 pattern, Cluster 4 fix). The fake
    records every kwargs dict on ``.calls`` and exposes ``.last_event`` for
    succinct assertions in DLP refusal tests.
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
    ``substitute.return_value`` to assert the placeholder-vs-substituted
    invariant (arch-001).
    """
    broker = MagicMock()
    broker.substitute = AsyncMock(side_effect=lambda params: params)
    return broker


@pytest.fixture
def stub_nonce() -> CapabilityGateNonce:
    """Authorised :class:`CapabilityGateNonce` for transport construction.

    Uses :func:`nonce_factory.create_and_register_t3_nonce` when no nonce
    has been registered yet, otherwise reads the registered nonce — both
    are the live module-level "authorised" singleton, so ``tag_t3_with_nonce``
    accepts it. The MagicMock alternative would fail the ``is`` check inside
    the capability gate.
    """
    try:
        return nonce_factory.get_authorized_t3_nonce()
    except Exception:
        return nonce_factory.create_and_register_t3_nonce()

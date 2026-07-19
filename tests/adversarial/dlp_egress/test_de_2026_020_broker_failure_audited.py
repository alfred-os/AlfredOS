"""Executable counterpart to ``de_2026_020_broker_failure_audited.yaml``.

de-2026-020. Pins the HARD rule #7 audit-completeness invariant for the #340
SCM_RIGHTS gateway-socket broker (``control_fd_broker.py``, ADR-0050): a
``ControlFdBrokerError`` refusal on the quarantine egress path MUST produce a
durable, signed ``egress.broker.refused`` row via
:meth:`~alfred.egress.broker_audit.EgressBrokerAuditor.record_broker_failure`
— and the write itself must never be silently swallowed.

Two properties under test:

* :func:`test_control_fd_broker_failure_is_durably_audited` — drives a REAL
  ``ControlFdBrokerError`` (an actual ECONNREFUSED against a closed loopback
  port, exactly like ``test_broker_connected_socket_unreachable_is_loud`` in
  ``tests/unit/egress/test_control_fd_broker.py``) through to
  ``record_broker_failure`` and asserts exactly one payload-blind
  ``egress.broker.refused`` row lands, carrying the closed-vocab reason and the
  destination the broker actually dialled.
* :func:`test_broker_failure_audit_write_failure_propagates_not_swallowed` —
  a broker-failure audit write that itself fails (the writer's
  ``append_schema`` raises) must re-raise to the caller, never disappear. A
  regression that wrapped this write in a bare ``except Exception: pass``
  would let a denied brokered-egress attempt pass with zero forensic trail —
  exactly the HARD #7 violation this corpus entry exists to catch. The
  fail-closed hookpoint must also never dispatch when the row was never
  persisted (mirrors ``test_append_schema_failure_propagates_not_swallowed``
  in ``tests/unit/egress/test_broker_audit.py``, run here as an independent,
  release-blocking corpus assertion rather than relying solely on that unit
  test surviving future refactors).

[L-7] Both tests are PURE UNIT tests (a real loopback socket + an in-memory
audit-writer double, no bwrap, no real gateway) and carry no bwrap-skip
marker — they run, never skip, on every CI leg (mirrors
``test_brokered_fd_dormant_mechanism.py``'s L-7 note for the sibling
sbx-2026-015 payload covering this same ControlFdBrokerError mechanism).
"""

from __future__ import annotations

import importlib
import socket
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from alfred.audit.audit_row_schemas import (
    EGRESS_BROKER_REFUSED_FIELDS,
    EGRESS_BROKER_REFUSED_REASONS,
)
from alfred.egress.broker_audit import EgressBrokerAuditor
from alfred.egress.control_fd_broker import (
    ControlFdBrokerError,
    broker_connected_socket,
    make_control_socketpair,
)
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.egress_doubles import _CapturingAuditWriter

_PAYLOAD_PATH = Path(__file__).parent / "de_2026_020_broker_failure_audited.yaml"


class _Cfg:
    """Minimal ``EgressProxyConfig``-shaped stub.

    Mirrors ``tests/unit/egress/test_control_fd_broker.py``'s ``_Cfg``.
    """

    def __init__(self, url: str | None) -> None:
        self.egress_proxy_url = url


def _load_payload() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_PAYLOAD_PATH.read_text()))


@pytest.fixture
def _fake_invoke(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Sidestep the real hookpoint-dispatch registry's strict-declaration check.

    The ``egress.broker.connected`` / ``egress.broker.refused`` hookpoints are
    not yet declared anywhere in production — golive's ``broker_sockets``
    wiring is what declares them (this auditor ships dormant, per
    ``broker_audit.py``'s module docstring). Without this fixture,
    ``EgressBrokerAuditor._write``'s ``invoke(...)`` dispatch raises
    ``HookError`` (undeclared hookpoint in strict mode) AFTER the audit row
    has already been persisted — a real production wiring bug this corpus
    entry is not testing. Patches ``alfred.hooks.invoke.invoke`` at its
    source submodule (not the dotted-string form) — ``alfred.hooks``'s
    ``__init__.py`` re-exports ``invoke``, rebinding the *package* attribute
    to the already-imported function object, so a dotted-string patch would
    silently miss the call site ``broker_audit.py`` actually imports from.
    Mirrors ``tests/unit/egress/test_broker_audit.py``'s own ``_fake_invoke``
    fixture (Task 2 precedent).
    """
    invoked: list[dict[str, Any]] = []

    async def _invoke(name: str, ctx: object, **kwargs: Any) -> object:
        invoked.append({"name": name, **kwargs})
        return ctx

    invoke_module = importlib.import_module("alfred.hooks.invoke")
    monkeypatch.setattr(invoke_module, "invoke", _invoke)
    return invoked


def test_payload_schema_valid() -> None:
    payload = _load_payload()
    assert payload.id == "de-2026-020"
    assert payload.category == "dlp_egress"
    assert payload.expected_outcome == "audit_row_emitted"
    assert payload.ingestion_path == "stdio_fd3_key_delivery"
    # Drift guard: the probe's declared reason must stay a member of the
    # CLOSED vocabulary the production code and this driver both bind to.
    payload_fields = payload.payload
    assert isinstance(payload_fields, dict)
    assert payload_fields["probe"]["reason"] in EGRESS_BROKER_REFUSED_REASONS


@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_control_fd_broker_failure_is_durably_audited(
    _fake_invoke: list[dict[str, Any]],
) -> None:
    """A REAL ``ControlFdBrokerError`` (gateway_unreachable) → exactly one
    durable, payload-blind ``egress.broker.refused`` row.

    Fold-log M2 precedent (``test_broker_connected_socket_unreachable_is_loud``):
    bind-then-close a local loopback port rather than dialling a TEST-NET-3
    address — a closed 127.0.0.1 port refuses the connect immediately
    (ECONNREFUSED), where a blackholed address would block for the full
    10s connect timeout and make this test slow/flaky.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    _, closed_port = probe.getsockname()
    probe.close()  # nothing listens on this port now — connecting refuses immediately
    destination = f"127.0.0.1:{closed_port}"

    parent, child = make_control_socketpair()
    try:
        with pytest.raises(ControlFdBrokerError) as exc_info:
            await broker_connected_socket(
                parent_end=parent, proxy_config=_Cfg(f"http://{destination}")
            )
        assert exc_info.value.reason == "gateway_unreachable"

        audit_writer = _CapturingAuditWriter()
        await EgressBrokerAuditor(audit_writer).record_broker_failure(  # type: ignore[arg-type]
            destination=destination, reason=exc_info.value.reason
        )
    finally:
        parent.close()
        child.close()

    refused = [row for row in audit_writer.rows if row.get("event") == "egress.broker.refused"]
    assert len(refused) == 1, f"Expected 1 audit row, got {len(refused)}: {refused}"
    row = refused[0]
    assert row["trust_tier_of_trigger"] == "T0"
    assert row["result"] == "refused"
    assert row["subject"]["reason"] == "gateway_unreachable"
    assert row["subject"]["reason"] in EGRESS_BROKER_REFUSED_REASONS
    assert row["subject"]["destination"] == destination
    # Payload-blind: only the three closed-vocab fields, never socket bytes
    # (the broker passes a bare fd — HARD #5 — so there is nothing else to leak).
    assert set(row["subject"].keys()) == EGRESS_BROKER_REFUSED_FIELDS, (
        f"Audit row subject keys must equal {EGRESS_BROKER_REFUSED_FIELDS!r}; "
        f"got {set(row['subject'].keys())!r}"
    )
    # The fail-closed hookpoint dispatched exactly once, for the right event —
    # a durable row with no hookpoint dispatch (or vice versa) would be a
    # partial, inconsistent audit trail.
    assert len(_fake_invoke) == 1
    assert _fake_invoke[0]["name"] == "egress.broker.refused"
    assert _fake_invoke[0]["fail_closed"] is True


@pytest.mark.asyncio
async def test_broker_failure_audit_write_failure_propagates_not_swallowed(
    _fake_invoke: list[dict[str, Any]],
) -> None:
    """A failing audit write for a ``ControlFdBrokerError``-shaped refusal
    must re-raise to the caller, never be silently absorbed (HARD #7).

    Uses the exception's ``.reason`` directly (rather than re-triggering the
    real network failure again) — the property under test here is
    ``record_broker_failure``'s own fail-loud discipline on a broken writer,
    independent of how the ``ControlFdBrokerError`` was raised.
    """
    boom_reason = ControlFdBrokerError("gateway_unreachable").reason

    class _BoomAuditWriter:
        async def append_schema(self, **_kw: Any) -> None:
            raise RuntimeError("audit store unavailable")

    with pytest.raises(RuntimeError, match="audit store unavailable"):
        await EgressBrokerAuditor(_BoomAuditWriter()).record_broker_failure(  # type: ignore[arg-type]
            destination="gateway:8889", reason=boom_reason
        )

    # The fail-closed hookpoint must never dispatch when the row was never
    # persisted — a silent swallow would otherwise let this slip through as
    # "the hookpoint ran, so something was recorded."
    assert _fake_invoke == []

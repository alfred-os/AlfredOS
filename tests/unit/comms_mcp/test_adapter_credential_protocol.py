"""Tests for the G6-3 credential wire frames (#288, the heaviest trust boundary).

The credential round-trip rides the trusted gateway<->core leg as a request/response
pair: ``gateway.adapter.spawn_request`` (gateway -> core) and
``core.adapter.spawn_grant`` (core -> gateway). The grant carries the PLAINTEXT
platform credential over the trusted leg ONLY; these tests pin the structural
invariants that keep the credential out of every observable surface:

* exact field-set locks on both frames (a smuggled / typo'd field is a loud
  ``ValidationError`` — ``extra="forbid"``);
* the credential field is NOT in any audit field-set (the credential can never
  reach an audit row by construction — maintainer C1 / SEC-1);
* the grant is structurally un-loggable: ``credential_material`` is ``repr=False``
  and ``__repr__`` / ``__str__`` elide it, so ``log.info(frame)`` / f-strings /
  exception args are safe-by-default (correction S-C3);
* a grant with an extra field is rejected (``extra="forbid"`` proof);
* ``model_dump`` round-trips (the codec the real Pydantic transport uses).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.audit.audit_row_schemas import (
    CORE_ADAPTER_SPAWN_GRANT_FIELDS,
    GATEWAY_ADAPTER_AWAITING_CORE_FIELDS,
    GATEWAY_ADAPTER_SPAWN_ABORTED_FIELDS,
    GATEWAY_ADAPTER_SPAWN_REQUEST_FIELDS,
)
from alfred.comms_mcp.adapter_credential_protocol import (
    CORE_ADAPTER_SPAWN_GRANT,
    GATEWAY_ADAPTER_SPAWN_REQUEST,
    SpawnGrant,
    SpawnRequest,
)

_EPOCH = "0123456789abcdef0123456789abcdef"
_REQ_ID = "11111111111111111111111111111111"
_SENTINEL_CRED = "SENTINEL-CREDENTIAL-DO-NOT-LEAK-7f3a"


def _request() -> SpawnRequest:
    return SpawnRequest(request_id=_REQ_ID, adapter_id="discord", host_restart_seq=0, epoch=_EPOCH)


def _grant() -> SpawnGrant:
    return SpawnGrant(
        request_id=_REQ_ID,
        adapter_id="discord",
        host_restart_seq=0,
        epoch=_EPOCH,
        credential_material=_SENTINEL_CRED,
    )


def test_method_constants_are_namespaced() -> None:
    assert GATEWAY_ADAPTER_SPAWN_REQUEST == "gateway.adapter.spawn_request"
    assert CORE_ADAPTER_SPAWN_GRANT == "core.adapter.spawn_grant"


def test_spawn_request_field_set_is_locked() -> None:
    assert set(SpawnRequest.model_fields) == {
        "request_id",
        "adapter_id",
        "host_restart_seq",
        "epoch",
    }


def test_spawn_grant_field_set_is_locked() -> None:
    assert set(SpawnGrant.model_fields) == {
        "request_id",
        "adapter_id",
        "host_restart_seq",
        "epoch",
        "credential_material",
    }


def test_request_rejects_extra_field() -> None:
    with pytest.raises(ValidationError):
        SpawnRequest(
            request_id=_REQ_ID,
            adapter_id="discord",
            host_restart_seq=0,
            epoch=_EPOCH,
            smuggled="x",  # type: ignore[call-arg]
        )


def test_grant_rejects_extra_field() -> None:
    with pytest.raises(ValidationError):
        SpawnGrant(
            request_id=_REQ_ID,
            adapter_id="discord",
            host_restart_seq=0,
            epoch=_EPOCH,
            credential_material=_SENTINEL_CRED,
            smuggled="x",  # type: ignore[call-arg]
        )


def test_request_refuses_unknown_adapter_kind() -> None:
    with pytest.raises(ValidationError):
        SpawnRequest(request_id=_REQ_ID, adapter_id="not-a-kind", host_restart_seq=0, epoch=_EPOCH)


def test_request_refuses_negative_host_restart_seq() -> None:
    with pytest.raises(ValidationError):
        SpawnRequest(request_id=_REQ_ID, adapter_id="discord", host_restart_seq=-1, epoch=_EPOCH)


def test_request_refuses_malformed_epoch() -> None:
    with pytest.raises(ValidationError):
        SpawnRequest(
            request_id=_REQ_ID, adapter_id="discord", host_restart_seq=0, epoch="too-short"
        )


def test_grant_requires_non_empty_credential() -> None:
    with pytest.raises(ValidationError):
        SpawnGrant(
            request_id=_REQ_ID,
            adapter_id="discord",
            host_restart_seq=0,
            epoch=_EPOCH,
            credential_material="",
        )


# --- The credential never reaches an audit row (maintainer C1 / SEC-1) --------


def test_credential_material_absent_from_every_audit_field_set() -> None:
    for fields in (
        GATEWAY_ADAPTER_SPAWN_REQUEST_FIELDS,
        CORE_ADAPTER_SPAWN_GRANT_FIELDS,
        GATEWAY_ADAPTER_AWAITING_CORE_FIELDS,
        GATEWAY_ADAPTER_SPAWN_ABORTED_FIELDS,
    ):
        assert "credential_material" not in fields


def test_spawn_request_audit_field_set() -> None:
    assert (
        frozenset({"adapter_id", "host_restart_seq", "epoch", "occurred_at", "result"})
        == GATEWAY_ADAPTER_SPAWN_REQUEST_FIELDS
    )


def test_spawn_grant_audit_field_set() -> None:
    assert (
        frozenset({"adapter_id", "host_restart_seq", "epoch", "occurred_at", "result", "duplicate"})
        == CORE_ADAPTER_SPAWN_GRANT_FIELDS
    )


# --- The grant is structurally un-loggable (correction S-C3) ------------------


def test_grant_repr_elides_credential() -> None:
    grant = _grant()
    assert _SENTINEL_CRED not in repr(grant)


def test_grant_str_elides_credential() -> None:
    grant = _grant()
    assert _SENTINEL_CRED not in str(grant)


def test_grant_fstring_elides_credential() -> None:
    grant = _grant()
    assert _SENTINEL_CRED not in f"{grant}"
    assert _SENTINEL_CRED not in f"{grant!r}"


def test_grant_repr_still_shows_routing_metadata() -> None:
    # The non-secret routing keys MUST remain visible so a leg log can triage.
    grant = _grant()
    rendered = repr(grant)
    assert "discord" in rendered
    assert _REQ_ID in rendered


# --- model_dump round-trips (the real Pydantic codec) -------------------------


def test_grant_model_dump_round_trips() -> None:
    grant = _grant()
    dumped = grant.model_dump()
    assert dumped["credential_material"] == _SENTINEL_CRED
    assert SpawnGrant.model_validate(dumped) == grant


def test_request_model_dump_round_trips() -> None:
    request = _request()
    assert SpawnRequest.model_validate(request.model_dump()) == request

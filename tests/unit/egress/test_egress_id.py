"""Egress-id + body-hash: deterministic, injective, collision-free (Spec C §5).

The egress-id is the dedup key for the side-effecting-egress ledger (G7-2). It
MUST be deterministic (a replay re-derives the same id), injective (two distinct
logical calls never collide — else a replay mis-attributes one call's stored
response to another), and free of the classic separator-concatenation collision
(``turn=1,call=23`` must not equal ``turn=12,call=3``). A frozen golden vector
makes a hash-algo / field-order change fail loud rather than silently re-namespace
every prior ledger row.
"""

from __future__ import annotations

import hypothesis.strategies as st
import pytest
from hypothesis import assume, given

from alfred.egress.egress_id import (
    EgressIdIntegrityError,
    TurnEgressContext,
    compute_body_hash,
    compute_egress_id,
    compute_request_descriptor,
)

_CTX = TurnEgressContext(adapter_id="discord", inbound_id="msg-1", session_id="sess-1")


def test_determinism_same_inputs_same_id() -> None:
    assert compute_egress_id(_CTX, call_index=0) == compute_egress_id(_CTX, call_index=0)


def test_distinct_call_index_distinct_id() -> None:
    assert compute_egress_id(_CTX, call_index=0) != compute_egress_id(_CTX, call_index=1)


def test_no_separator_collision() -> None:
    # The classic concatenation bug: (inbound=1, session=23) must NOT collide
    # with (inbound=12, session=3) under a naive separator-free concat.
    a = TurnEgressContext(adapter_id="discord", inbound_id="1", session_id="23")
    b = TurnEgressContext(adapter_id="discord", inbound_id="12", session_id="3")
    assert compute_egress_id(a, call_index=0) != compute_egress_id(b, call_index=0)


def test_field_shift_collision_is_avoided() -> None:
    # A second collision class: shifting a boundary between adapter_id and
    # inbound_id must not produce the same id (length-prefixing prevents it).
    a = TurnEgressContext(adapter_id="ab", inbound_id="c", session_id="s")
    b = TurnEgressContext(adapter_id="a", inbound_id="bc", session_id="s")
    assert compute_egress_id(a, call_index=0) != compute_egress_id(b, call_index=0)


def test_golden_vector_is_stable() -> None:
    # A frozen golden so a hash-algo / field-order change fails loud, not silently
    # re-namespaces every prior ledger row.
    assert compute_egress_id(_CTX, call_index=0) == (
        "45d149b85ee05d2853e8b2bd6262409b86c6fd74c14778961e72146a9722a6b3"
    )


def test_egress_id_is_sha256_hex() -> None:
    # 64 lowercase hex chars — the ledger PK is String(64) (MEM-4); a width change
    # here would silently overflow that column.
    egress_id = compute_egress_id(_CTX, call_index=0)
    assert len(egress_id) == 64
    assert all(c in "0123456789abcdef" for c in egress_id)


@given(
    a=st.text(min_size=1),
    b=st.text(min_size=1),
    c=st.text(min_size=1),
    i=st.integers(min_value=0),
    a2=st.text(min_size=1),
    b2=st.text(min_size=1),
    c2=st.text(min_size=1),
    i2=st.integers(min_value=0),
)
def test_injective(a: str, b: str, c: str, i: int, a2: str, b2: str, c2: str, i2: int) -> None:
    assume((a, b, c, i) != (a2, b2, c2, i2))
    id1 = compute_egress_id(
        TurnEgressContext(adapter_id=a, inbound_id=b, session_id=c), call_index=i
    )
    id2 = compute_egress_id(
        TurnEgressContext(adapter_id=a2, inbound_id=b2, session_id=c2), call_index=i2
    )
    assert id1 != id2


def test_body_hash_of_redacted_is_deterministic() -> None:
    assert compute_body_hash("redacted") == compute_body_hash("redacted")
    assert compute_body_hash("a") != compute_body_hash("b")


def test_body_hash_is_sha256_hex() -> None:
    digest = compute_body_hash("redacted")
    assert len(digest) == 64
    assert all(ch in "0123456789abcdef" for ch in digest)


# ---------------------------------------------------------------------------
# compute_request_descriptor (C6 / G7-2.5 Task 1)
# ---------------------------------------------------------------------------


def test_request_descriptor_is_deterministic() -> None:
    """C6-T1: identical inputs produce the same 64-char hex digest."""
    a = compute_request_descriptor(method="GET", url="https://x.test/a", schema_id="m.S:v1")
    b = compute_request_descriptor(method="GET", url="https://x.test/a", schema_id="m.S:v1")
    assert a == b and len(a) == 64


def test_request_descriptor_distinguishes_method_url_and_schema() -> None:
    """C6-T2: changing method OR url OR schema_id yields a different descriptor."""
    base = {"method": "GET", "url": "https://x.test/a", "schema_id": "m.S:v1"}
    # CR-8: a method change (GET vs POST) must produce a different descriptor — a
    # POST replayed at a GET's egress-id slot must fire EgressIdIntegrityError.
    assert compute_request_descriptor(**base) != compute_request_descriptor(
        **{**base, "method": "POST"}
    )
    assert compute_request_descriptor(**base) != compute_request_descriptor(
        **{**base, "url": "https://x.test/b"}
    )
    assert compute_request_descriptor(**base) != compute_request_descriptor(
        **{**base, "schema_id": "m.S:v2"}
    )


def test_request_descriptor_no_field_boundary_collision() -> None:
    """C6-T3: length-prefixing prevents separator-collision across url/schema_id boundary."""
    # ("GET","https://x.test/ab","") must NOT collide with ("GET","https://x.test/a","b").
    assert compute_request_descriptor(
        method="GET", url="https://x.test/ab", schema_id=""
    ) != compute_request_descriptor(method="GET", url="https://x.test/a", schema_id="b")


def test_integrity_error_carries_no_hash_oracle() -> None:
    # The mismatch surface must not be a body-content oracle: the error carries
    # the egress-id (already public) but never a body or hash value.
    err = EgressIdIntegrityError(egress_id="abc123")
    assert err.egress_id == "abc123"
    assert err.reason == "egress_id_integrity_mismatch"
    assert "abc123" in str(err)
    # Structural no-oracle guard: the error exposes no body/hash attribute, so a
    # future refactor that threads a hash into it fails this test loudly.
    assert not hasattr(err, "body_hash")
    assert not hasattr(err, "response")
    # The only constructor argument is the already-public egress-id.
    with pytest.raises(TypeError):
        EgressIdIntegrityError(egress_id="x", body_hash="leak")  # type: ignore[call-arg]

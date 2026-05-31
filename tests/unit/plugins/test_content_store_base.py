"""ContentStoreBase Protocol + InMemoryContentStore — PR-S3-3a Task 5 (spec §7.2, §7.3).

The content store holds T3 bytes keyed by ``ContentHandle.id``. The
orchestrator only holds the ``ContentHandle`` itself; it never
dereferences the bytes directly.

**rvw-004 / CR R3 fix — critical.** The store persists the
``TaggedContent[T3]`` *wrapper* (which carries nonce + provenance), not
raw bytes. Persisting raw bytes would lose the nonce and silently
downgrade T3 → untagged on retrieval — a tier-laundering vulnerability.
The Protocol signatures mandate ``TaggedContent[T3]``; the in-memory
stub uses the same signature.

The Redis-backed production store (PR-S3-5
``alfred.plugins.web_fetch.content_store``) implements the same Protocol;
the in-memory stub is used by ``StdioTransport`` until PR-S3-5 merges and
by every unit test that doesn't want testcontainers.
"""

from __future__ import annotations

import datetime

from alfred.plugins.content_store_base import ContentStoreBase, InMemoryContentStore
from alfred.security.quarantine import ContentHandle
from alfred.security.tiers import T3, TaggedContent

# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _make_handle(handle_id: str, source_url: str = "https://example.com") -> ContentHandle:
    return ContentHandle(
        id=handle_id,
        source_url=source_url,
        fetch_timestamp=datetime.datetime.now(datetime.UTC),
    )


def _make_tagged(content: str = "test content") -> TaggedContent[T3]:
    # Tests construct TaggedContent[T3] directly to exercise the store
    # contract. The production tag_t3_with_nonce path is exercised by
    # tests/unit/security/test_tag_t3_capability_gate.py and is out of
    # scope here — this module tests storage round-trip behaviour, not
    # the T3 tagging gate.
    return TaggedContent[T3](content=content, source="test", tier=T3, metadata={})


# ---------------------------------------------------------------------------
# Round-trip behaviour.
# ---------------------------------------------------------------------------


def test_put_and_get_round_trip_preserves_tagged_content() -> None:
    store = InMemoryContentStore()
    handle = _make_handle("round-trip-uuid")
    tagged = _make_tagged("hello world")
    store.put(handle, tagged)
    retrieved = store.get(handle.id)
    # rvw-004 fix: get() returns the SAME TaggedContent[T3] wrapper that
    # was put. Raw bytes would lose the tier+nonce provenance.
    assert retrieved is tagged


def test_get_missing_returns_none() -> None:
    store = InMemoryContentStore()
    assert store.get("nonexistent") is None


def test_delete_removes_entry() -> None:
    store = InMemoryContentStore()
    handle = _make_handle("del-uuid")
    store.put(handle, _make_tagged())
    store.delete(handle.id)
    assert store.get(handle.id) is None


def test_delete_missing_is_idempotent() -> None:
    # Deleting an unknown id is a no-op so the supervisor can clean up
    # speculatively without checking existence first.
    store = InMemoryContentStore()
    store.delete("never-existed")
    assert store.get("never-existed") is None


def test_multiple_handles_isolated() -> None:
    store = InMemoryContentStore()
    h1 = _make_handle("uuid-1")
    h2 = _make_handle("uuid-2")
    t1 = _make_tagged("first")
    t2 = _make_tagged("second")
    store.put(h1, t1)
    store.put(h2, t2)
    assert store.get(h1.id) is t1
    assert store.get(h2.id) is t2


def test_put_overwrites_previous_value_for_same_id() -> None:
    store = InMemoryContentStore()
    handle = _make_handle("same-id")
    first = _make_tagged("first")
    second = _make_tagged("second")
    store.put(handle, first)
    store.put(handle, second)
    assert store.get(handle.id) is second


# ---------------------------------------------------------------------------
# Protocol structural conformance — InMemoryContentStore satisfies
# ContentStoreBase. The Redis store in PR-S3-5 must also satisfy it.
# ---------------------------------------------------------------------------


def test_in_memory_store_satisfies_protocol() -> None:
    # ContentStoreBase is runtime_checkable so supervisor bootstrap and
    # test fixtures can isinstance-check the wired store.
    assert isinstance(InMemoryContentStore(), ContentStoreBase)


def test_content_store_protocol_has_put_get_delete() -> None:
    assert hasattr(ContentStoreBase, "put")
    assert hasattr(ContentStoreBase, "get")
    assert hasattr(ContentStoreBase, "delete")

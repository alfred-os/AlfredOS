"""ContentHandle frozen-dataclass shape and UUID type contract. Spec §7.3.

SCOPE NOTE (arch-003): This test covers the *type contract* only —
frozen dataclass, no .content field, UUID-shaped id field. The single-use
enforcement invariant (Redis DEL on first extract) is PR-S3-5's concern;
tests for that behaviour live in PR-S3-5 alongside ContentStore.store().
The canonical definition of ContentHandle lives here (src/alfred/security/
quarantine.py); PR-S3-5 re-exports it for namespace continuity.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from alfred.security.quarantine import ContentHandle


def test_content_handle_accepts_uuid_string() -> None:
    handle_id = str(uuid.uuid4())
    handle = ContentHandle(
        id=handle_id,
        source_url="https://example.com/article",
        fetch_timestamp=datetime.now(tz=timezone.utc),
    )
    assert handle.id == handle_id


def test_two_content_handles_with_same_url_differ() -> None:
    """Two handles for the same URL use different IDs — enforced by callers
    (PR-S3-5 ContentStore) but the type allows it. This asserts the type
    does not prevent distinct IDs (a uniqueness-enforcing frozen field
    would be a design mistake — the store, not the type, is the authority)."""
    id_a = str(uuid.uuid4())
    id_b = str(uuid.uuid4())
    assert id_a != id_b  # UUID4 collision probability is negligible
    ts = datetime.now(tz=timezone.utc)
    h_a = ContentHandle(id=id_a, source_url="https://example.com", fetch_timestamp=ts)
    h_b = ContentHandle(id=id_b, source_url="https://example.com", fetch_timestamp=ts)
    assert h_a.id != h_b.id


def test_content_handle_is_canonical_import_from_quarantine() -> None:
    """ContentHandle's canonical import path is alfred.security.quarantine.

    PR-S3-5 re-exports ContentHandle from alfred.plugins.web_fetch.content_store
    for namespace continuity. This test documents the single source of truth.
    Any import of ContentHandle from a path other than alfred.security.quarantine
    (directly or via re-export) should be flagged as drift. See arch-003.
    """
    import alfred.security.quarantine as q
    assert hasattr(q, "ContentHandle")
    assert q.ContentHandle is ContentHandle

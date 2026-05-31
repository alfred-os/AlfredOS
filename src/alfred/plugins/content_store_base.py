"""ContentStoreBase Protocol + InMemoryContentStore stub (spec §7.2, §7.3).

The content store holds T3 bytes keyed by ``ContentHandle.id``. The
orchestrator only holds the :class:`alfred.security.quarantine.ContentHandle`
itself; it never dereferences the bytes directly. The quarantined-LLM
plugin (PR-S3-4) and the web-fetch plugin (PR-S3-5) are the legitimate
consumers — they call ``get(handle.id)`` to retrieve the wrapped T3 value.

**Storage contract (rvw-004 / CR R3 fix — critical).** The store persists
the :class:`alfred.security.tiers.TaggedContent[T3]` *wrapper*, which
carries the nonce + provenance, NOT raw bytes. Persisting raw bytes would
lose the nonce and silently downgrade T3 → untagged on retrieval — a
tier-laundering vulnerability. The Protocol signatures mandate
``TaggedContent[T3]``; the in-memory stub mirrors that contract.

The Redis-backed production store ships in PR-S3-5
(``alfred.plugins.web_fetch.content_store``). This module's
:class:`InMemoryContentStore` is the stub used:

* by ``StdioTransport`` until PR-S3-5 wires the Redis store, and
* by every unit test that wants to avoid testcontainers.

Both implementations satisfy the same :class:`ContentStoreBase` Protocol,
so the supervisor wires whichever the operator configured without
touching call-site code.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from alfred.security.quarantine import ContentHandle
from alfred.security.tiers import T3, TaggedContent


@runtime_checkable
class ContentStoreBase(Protocol):
    """Protocol for T3 content stores keyed by ``ContentHandle.id``.

    Storage contract: the store persists the ``TaggedContent[T3]``
    wrapper (which carries nonce + provenance), not raw bytes.
    Retrieval via :meth:`get` must return the same wrapper so callers
    that re-tag elsewhere can validate the nonce on read-back. Persisting
    raw bytes would lose the nonce and silently downgrade T3 → untagged
    on retrieval, opening a tier-laundering vulnerability (rvw-004).

    Implementations:

    * :class:`InMemoryContentStore` (this module) — unit-test + Slice-3
      pre-Redis usage; no TTL, no single-use, no cross-process visibility.
    * Redis-backed production store — PR-S3-5; provides TTL + atomic
      single-use ``DEL`` on first successful extract.

    ``runtime_checkable`` so supervisor bootstrap can
    ``isinstance(store, ContentStoreBase)`` check without importing a
    concrete class.
    """

    def put(self, handle: ContentHandle, tagged_content: TaggedContent[T3]) -> None:
        """Store ``tagged_content`` under ``handle.id``.

        ``tagged_content`` MUST be the full ``TaggedContent[T3]`` wrapper;
        passing the raw bytes would lose the provenance contract.
        """
        ...

    def get(self, handle_id: str) -> TaggedContent[T3] | None:
        """Retrieve the ``TaggedContent[T3]`` value for ``handle_id``.

        Returns ``None`` if the id is unknown, expired, or has been
        consumed by a single-use store. The orchestrator must treat
        ``None`` as a recoverable miss, not a security event.
        """
        ...

    def delete(self, handle_id: str) -> None:
        """Delete the entry for ``handle_id``.

        Idempotent: deleting an unknown id is a no-op so the supervisor
        can clean up speculatively without checking existence first.
        """
        ...


class InMemoryContentStore:
    """In-memory content store for unit tests + Slice-3 pre-Redis usage.

    Not production-safe: no TTL, no single-use enforcement, no
    cross-process visibility. The Redis store in PR-S3-5 provides
    production semantics. Use this only:

    * inside the unit-test suite (where each test wants a fresh,
      hermetic store), and
    * in Slice-3 bootstrap before PR-S3-5 ships the Redis store.
    """

    def __init__(self) -> None:
        self._store: dict[str, TaggedContent[T3]] = {}

    def put(self, handle: ContentHandle, tagged_content: TaggedContent[T3]) -> None:
        self._store[handle.id] = tagged_content

    def get(self, handle_id: str) -> TaggedContent[T3] | None:
        return self._store.get(handle_id)

    def delete(self, handle_id: str) -> None:
        # ``pop`` with a default makes the operation idempotent — no
        # KeyError on unknown ids. Matches the Protocol contract.
        self._store.pop(handle_id, None)


__all__ = [
    "ContentStoreBase",
    "InMemoryContentStore",
]

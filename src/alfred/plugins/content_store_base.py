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

**Production guard (sec-S3-003).** ``InMemoryContentStore`` is NOT
production-safe (no TTL, no single-use, no cross-process visibility);
a bootstrap that forgets to inject the Redis store would silently get
the unsafe stub. The constructor consults ``ALFRED_ENV`` and refuses
to instantiate outside ``{"", "development", "test"}`` — the same
"unset / explicit dev / test" allowlist used elsewhere in the tree, but
extended to permit ``"test"`` so the pytest suite can construct stubs
without monkeypatching. This is loud rather than silent: a misconfigured
production host trips ``RuntimeError`` at bootstrap rather than running
under a stub store that drops single-use semantics on the floor.

This module is NOT on the capability-gate ``_FORBIDDEN_ALFRED_ENV_READERS``
list (sec-007); the env read here is the bootstrap-time safety check for
the development/test stub, not a gate-construction decision.
"""

from __future__ import annotations

import os
from typing import Final, Protocol, runtime_checkable

from alfred.errors import AlfredError
from alfred.i18n import t
from alfred.security.quarantine import ContentHandle
from alfred.security.tiers import T3, TaggedContent

# Allowlist of ``ALFRED_ENV`` values that may construct the stub store.
# Unset / empty mirrors the gate-factory convention (a missing env var
# in a developer's shell is the development default). ``"test"`` is the
# pytest fixture environment.
_DEV_TEST_ENVIRONMENTS: Final[frozenset[str]] = frozenset({"", "development", "test"})


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


class InMemoryContentStoreProductionError(AlfredError):
    """SECURITY EVENT: ``InMemoryContentStore`` constructed in a non-dev/test env.

    sec-S3-003. The in-memory stub lacks production-safety properties
    (no TTL, no single-use, no cross-process visibility). A bootstrap
    that forgets to inject the Redis store would silently fall back to
    this stub; the constructor's ``ALFRED_ENV`` check raises this
    exception instead.

    The fix is to inject the Redis-backed
    :class:`alfred.plugins.web_fetch.content_store` ContentStore (PR-S3-5)
    via the supervisor's bootstrap. ``StdioTransport.__init__`` accepts a
    ``content_store=`` kwarg specifically so the right store is wired
    explicitly per environment.
    """


class InMemoryContentStore:
    """In-memory content store for unit tests + Slice-3 pre-Redis usage.

    Not production-safe: no TTL, no single-use enforcement, no
    cross-process visibility. The Redis store in PR-S3-5 provides
    production semantics. Use this only:

    * inside the unit-test suite (where each test wants a fresh,
      hermetic store), and
    * in Slice-3 bootstrap before PR-S3-5 ships the Redis store.

    sec-S3-003: the constructor refuses to run when ``ALFRED_ENV`` is
    set to anything outside :data:`_DEV_TEST_ENVIRONMENTS`. A misconfigured
    production host trips ``InMemoryContentStoreProductionError`` at
    bootstrap rather than silently running under the stub.
    """

    def __init__(self) -> None:
        # Direct ``os.environ`` read is fine here — this module is NOT on
        # the sec-007 capability-gate forbidden-readers list (see
        # tests/unit/security/test_default_strict_declarations_invariant.py).
        # The read is the bootstrap-time stub-store safety check, not a
        # gate-construction decision.
        env = os.environ.get("ALFRED_ENV", "").strip()
        if env not in _DEV_TEST_ENVIRONMENTS:
            raise InMemoryContentStoreProductionError(
                t(
                    "plugin.content_store.inmemory_not_production_safe",
                    env=repr(env),
                )
            )
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
    "InMemoryContentStoreProductionError",
]

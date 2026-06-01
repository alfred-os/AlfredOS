"""Redis-backed ``ContentStore`` for web.fetch (spec §7.2, §7.3).

Key namespace: ``alfred:content:{handle_id}`` — value is the raw
response body. TTL formula::

    ttl = action_deadline_seconds
        + max_extraction_retries * per_retry_budget_seconds
        + slack_seconds

The Slice-3 defaults (30 + 2*10 + 30 = 80s) give the quarantined-LLM
extract chain enough time to complete two retries while bounding the
T3-leakage window. Operators can tune the four knobs per-call when a
specific allowed_domain needs a longer or shorter window.

Single-use semantics:

* :meth:`ContentStore.extract` issues a single ``GETDEL`` round-trip
  against Redis. ``GETDEL`` (Redis 6.2+) atomically fetches and
  removes the key — no other client can observe the value between the
  read and the delete. A GET+DEL pipeline would not give this
  guarantee; the integration test
  ``tests/integration/test_redis_compose_service.py``
  (``test_content_handle_single_use_delete``) pins this primitive so
  future drift to a pipeline-based approach surfaces in CI.

* A second extract — or extract against an unknown id — raises
  :class:`ContentHandleExpired`. The same typed error fires for
  TTL-expired handles so an attacker cannot distinguish "double-extract
  attempt" from "TTL fired" by observing the error shape. The audit
  row records ``result="content_expired"`` for both.

``ContentHandle`` is re-exported from
:mod:`alfred.security.quarantine` — there is exactly one definition
in the tree (CR-138 finding #4 pinned the tz-aware constructor on the
canonical class). Duplicating it here would let the two definitions
drift on future refactors.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Final, cast
from urllib.parse import urlparse

import redis.asyncio as aioredis
import structlog

from alfred.errors import AlfredError
from alfred.i18n import t

# Re-export so plugin-host callers stay decoupled from the quarantine
# module's path. ``alfred.plugins.web_fetch`` owns the public surface
# downstream code imports against.
from alfred.security.quarantine import ContentHandle

_log = structlog.get_logger(__name__)

_KEY_PREFIX: Final[str] = "alfred:content:"


def _sanitize_url_for_log(url: str) -> str:
    """Return ``scheme://host/path`` (no query / fragment / userinfo).

    CR-146 major: ``write`` runs for every fetch and the debug log
    capturing ``source_url`` would persist signed query params,
    userinfo (``user:password@host``), and bearer-style tokens in
    operator-visible logs. The full URL is still preserved on the
    in-memory :class:`ContentHandle` and on the audit-row path; only
    this log breadcrumb is sanitized.

    Falls back to ``"<sanitize_failed>"`` rather than risk silently
    leaking the raw URL into the log if ``urlparse`` raises.
    """
    # ``urlparse(...).port`` lazily parses the port and raises
    # ``ValueError`` on a non-numeric port. Wrap the whole attribute
    # read so the sanitizer cannot leak the raw URL via an uncaught
    # ValueError on a malformed port.
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if parsed.port is not None:
            host = f"{host}:{parsed.port}"
        path = parsed.path or ""
        scheme = parsed.scheme or ""
    except (ValueError, TypeError, AttributeError):
        return "<sanitize_failed>"
    if not scheme or not host:
        return "<sanitize_failed>"
    return f"{scheme}://{host}{path}"


# TTL-formula defaults pinned in code so a missing operator override
# never surprises with a different effective TTL. Spec §7.2.
_DEFAULT_ACTION_DEADLINE_SECONDS: Final[int] = 30
_DEFAULT_MAX_EXTRACTION_RETRIES: Final[int] = 2
_DEFAULT_PER_RETRY_BUDGET_SECONDS: Final[int] = 10
_DEFAULT_SLACK_SECONDS: Final[int] = 30


class ContentHandleExpired(AlfredError):  # noqa: N818 -- name pinned by spec §7.2
    """The content handle has been consumed or its TTL has fired.

    Unified error for both shapes — see module docstring. Carries the
    ``handle_id`` so the audit-row writer can attribute the miss without
    string-parsing the message.
    """

    def __init__(self, handle_id: str) -> None:
        super().__init__(t("web.fetch.error.content_handle_expired", handle_id=handle_id))
        self.handle_id = handle_id


class ContentStore:
    """Redis-backed content store for web.fetch T3 response bodies.

    The store is intentionally narrow — write, extract, delete, close.
    Tier wrapping (``TaggedContent[T3]``) lives one layer up in the
    fetch dispatcher (PR-S3-5 later tasks): the dispatcher tags the
    body via ``tag_t3_with_nonce`` before handing it to the
    quarantined extractor, but the bytes-in-flight inside Redis are
    raw — keying T3 provenance off ``ContentHandle`` itself is what
    closes the tier-laundering shape (every consumer of a handle
    treats the dereferenced bytes as T3 unconditionally).

    Connection lifecycle: the store owns a single
    :class:`redis.asyncio.Redis` client constructed at first use. The
    plugin host is expected to keep one ``ContentStore`` for the
    process lifetime; per-request construction would open a new TCP
    handshake per fetch (perf-006). ``close()`` is idempotent so
    supervisor SIGKILL paths can call it defensively.

    All public methods are ``async`` because the only legitimate caller
    runs inside the asyncio event loop of the plugin host (no sync
    bootstrap path exists).
    """

    def __init__(self, *, redis_url: str) -> None:
        self._redis_url = redis_url
        self._client: aioredis.Redis | None = None

    @property
    def redis_url(self) -> str:
        """The Redis URL this store was constructed against.

        Public because the ``InboundCanaryScanner`` (Task 5) reads it
        to open its own connection for the read-only peek path —
        keying off the same URL keeps the canary scan and the extract
        consistent without giving the scanner direct access to the
        store's internal client.
        """
        return self._redis_url

    async def _get_client(self) -> aioredis.Redis:
        if self._client is None:
            # ``decode_responses=False`` so the body round-trips as raw
            # bytes. T3 content is binary-safe (HTML, JSON, octet-stream)
            # and a UTF-8 decode at the Redis layer would mangle
            # non-ASCII payloads or raise on invalid sequences.
            self._client = aioredis.from_url(self._redis_url, decode_responses=False)
        return self._client

    async def write(
        self,
        *,
        body: bytes,
        source_url: str,
        action_deadline_seconds: int = _DEFAULT_ACTION_DEADLINE_SECONDS,
        max_extraction_retries: int = _DEFAULT_MAX_EXTRACTION_RETRIES,
        per_retry_budget_seconds: int = _DEFAULT_PER_RETRY_BUDGET_SECONDS,
        slack_seconds: int = _DEFAULT_SLACK_SECONDS,
    ) -> ContentHandle:
        """Write ``body`` to Redis under a freshly minted handle and return
        the opaque :class:`ContentHandle`.

        Args:
            body: The raw response bytes. T3 by construction; the
                dispatcher must call ``tag_t3_with_nonce`` before handing
                the body to any downstream consumer that reads it.
            source_url: For audit attribution only; recorded in
                ``ContentHandle.source_url``. The orchestrator does NOT
                treat this as readable content.
            action_deadline_seconds: Upper bound on the per-action
                quarantine extract — defaults to 30 (spec §7a).
            max_extraction_retries: Retry budget for the quarantined-LLM
                extract; defaults to 2.
            per_retry_budget_seconds: Per-retry timeout; defaults to 10.
            slack_seconds: Extra TTL beyond the extract budget so a
                slow handoff does not lose the handle mid-flight;
                defaults to 30.
        """
        handle_id = str(uuid.uuid4())
        ttl = (
            action_deadline_seconds
            + (max_extraction_retries * per_retry_budget_seconds)
            + slack_seconds
        )
        # CR-146 major: PRD §7.2 makes these knobs operator-tunable, but
        # nothing prevented a misconfig from computing ``ttl <= 0``. A
        # zero or negative TTL would either make Redis ``SET ... EX``
        # fail at the wire (turning a config error into a confusing
        # runtime exception) or — depending on the Redis client
        # version — create a key that expires immediately, which would
        # corrupt the quarantine-extract path before any consumer
        # could observe the handle. Fail at write-time with a clear
        # error so the operator sees the bad config at boot rather than
        # at first fetch.
        if ttl <= 0:
            msg = (
                "web.fetch content-store TTL must be positive; computed "
                f"{ttl}s from action_deadline={action_deadline_seconds}, "
                f"max_extraction_retries={max_extraction_retries}, "
                f"per_retry_budget={per_retry_budget_seconds}, "
                f"slack={slack_seconds}. Operators tune these via "
                "config/policies.yaml `web_fetch.content_store.*`."
            )
            raise ValueError(msg)
        key = f"{_KEY_PREFIX}{handle_id}"
        client = await self._get_client()
        await client.set(key, body, ex=ttl)
        # devex-005: normalise structlog event names under the
        # ``web_fetch.`` prefix so log consumers can filter by subsystem
        # without per-module exceptions.
        #
        # CR-146 major: log a sanitized URL shape so signed query
        # params / userinfo never land in the persistent debug log.
        # Full URL stays on the in-memory ``ContentHandle`` and the
        # audit row.
        _log.debug(
            "web_fetch.content_store.written",
            handle_id=handle_id,
            ttl_seconds=ttl,
            source_url=_sanitize_url_for_log(source_url),
            body_bytes=len(body),
        )
        return ContentHandle(
            id=handle_id,
            source_url=source_url,
            fetch_timestamp=datetime.now(tz=UTC),
        )

    async def extract(self, handle_id: str) -> bytes:
        """Atomically ``GETDEL`` the content body.

        Single-use: a successful extract removes the key in the same
        round-trip. A second call against the same handle id raises
        :class:`ContentHandleExpired`.

        Args:
            handle_id: The opaque id minted by :meth:`write`.

        Raises:
            ContentHandleExpired: handle is unknown, already extracted,
                or TTL-expired. Same typed error for all three cases —
                see the module docstring.
        """
        key = f"{_KEY_PREFIX}{handle_id}"
        client = await self._get_client()
        # ``GETDEL`` is atomic across clients (Redis 6.2+). Pinned by
        # integration test ``test_content_handle_single_use_delete``.
        # The redis-py type stub returns ``bytes | str | None`` (because
        # the same client can be constructed with ``decode_responses=True``);
        # this store hard-pins ``decode_responses=False`` in ``_get_client``
        # so the runtime shape is always ``bytes | None``. The cast keeps
        # the rest of the function honest about that narrower contract.
        body = cast("bytes | None", await client.getdel(key))
        if body is None:
            # Loud audit signal on miss — the orchestrator decides
            # whether the miss is recoverable (retry the fetch) or a
            # security event (canary scanner already quarantined the
            # handle). The error itself does not distinguish; the
            # caller's context does.
            # devex-005: normalised structlog event prefix.
            _log.info("web_fetch.content_store.getdel_miss", handle_id=handle_id)
            raise ContentHandleExpired(handle_id)
        _log.debug(
            "web_fetch.content_store.extracted",
            handle_id=handle_id,
            body_bytes=len(body),
        )
        return body

    async def delete(self, handle_id: str) -> None:
        """Idempotent delete (quarantine path).

        Called by the canary scanner on a trip to quarantine the handle
        before raising :class:`alfred.plugins.web_fetch.errors.WebFetchCanaryTripped`,
        and by supervisor cleanup paths on plugin SIGKILL. Idempotent so
        the caller does not need to check existence first — deleting an
        unknown id is a no-op.
        """
        key = f"{_KEY_PREFIX}{handle_id}"
        client = await self._get_client()
        await client.delete(key)

    async def close(self) -> None:
        """Idempotent close — drop the underlying Redis client.

        The supervisor's SIGKILL path calls this defensively; calling it
        more than once must not raise.
        """
        if self._client is not None:
            client = self._client
            self._client = None
            await client.aclose()


__all__ = [
    "ContentHandle",
    "ContentHandleExpired",
    "ContentStore",
]

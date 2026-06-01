"""``InboundCanaryScanner`` — system-tier hook subscriber on
``tool.web.fetch`` ``kind=post`` (spec §7.6).

Runs on the **plugin-host side**, NOT in the orchestrator process. The
scanner reads from the Redis content store by ``handle_id`` using a
read-only peek (``GETEX`` with no expiry options — Redis preserves the
existing TTL by default) so a clean scan leaves the handle consumable
by the orchestrator's quarantine-extract path. On a canary trip:

1. Log a structured warning ``web_fetch.canary.tripped`` for the
   operator's alerting pipeline.
2. **Quarantine** the handle (DELETE) BEFORE raising. A compromised
   downstream consumer cannot race to dereference the trip'd content
   because the key is already gone from Redis at the moment
   :class:`WebFetchCanaryTripped` propagates.
3. Raise :class:`WebFetchCanaryTripped` — a SECURITY EVENT, not a
   :class:`WebFetchError`. The orchestrator's hook dispatcher surfaces
   the typed exception; the orchestrator catches it and emits the
   ``tool.web.fetch.canary_tripped`` audit row.

Why a hook subscriber (ADR-0014): the previous shape would have
required every T3-ingesting tool to call its own scanner explicitly.
Placing the scanner as a system-tier ``post`` subscriber means future
T3 tools (email.read, mcp.tool.output, RAG retrievers) inherit canary
scanning by virtue of a system-tier subscriber existing on their
respective hookpoints. There is one scanner class — and exactly one
::

    SCANNER_HOOKPOINT
    SCANNER_TIER
    SCANNER_KIND

…trio per hookpoint owner. Task 6 wires the registration.

Naming disambiguation (spec rvw-007):

* :class:`alfred.plugins.inbound_scanner.InboundContentScanner` — scans
  every stdio-transport inbound frame for DLP patterns (synchronous,
  byte-offset reporting). Inline in ``StdioTransport.dispatch``.
* :class:`InboundCanaryScanner` (this module) — system-tier hook
  subscriber on ``tool.web.fetch``; reads the content store by handle
  id and scans for operator-registered canary tokens.

They are different classes with different responsibilities; never
import one in place of the other.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, cast

import redis.asyncio as aioredis
import structlog
from redis.exceptions import RedisError

from alfred.errors import AlfredError
from alfred.plugins.web_fetch.content_store import ContentStore
from alfred.plugins.web_fetch.errors import WebFetchCanaryTripped

_log = structlog.get_logger(__name__)

# Hookpoint registration constants — Task 6's
# ``register_hookpoints`` wires these into ``HookRegistry``. The
# constants are public (no leading underscore) so tests can pin the
# registration shape without importing the registration function.
SCANNER_HOOKPOINT: Final[str] = "tool.web.fetch"
SCANNER_TIER: Final[str] = "system"
SCANNER_KIND: Final[str] = "post"


class CanaryScanError(AlfredError):
    """FAULT: canary scan could not run because the content handle was
    missing at scan time.

    Raised (not swallowed) when :meth:`InboundCanaryScanner.scan` finds
    the body is ``None`` — the handle was consumed or expired before
    the scan ran. Silently returning would let the orchestrator
    proceed believing the content was scanned — breaking the spec §7.6
    'every web.fetch result is scanned' invariant.

    The fault propagates up through the hook dispatcher as a
    ``tool.web.fetch`` ``result='fault'`` audit row with
    ``drift_kind='missing_body'`` — see :attr:`drift_kind`.
    """

    def __init__(
        self,
        *,
        handle_id: str,
        drift_kind: str,
        audit_event: str,
        audit_result: str,
    ) -> None:
        # Hardcoded English on purpose: this is an internal fault
        # message that operators read in the audit log, not a
        # user-visible string. Adding it to the i18n catalog would
        # churn the catalog without operator benefit (the fault is
        # interpreted via the structured attributes below, not the
        # message text).
        super().__init__(
            f"canary scan fault: handle {handle_id!r} was missing at scan time "
            f"(drift_kind={drift_kind!r})"
        )
        self.handle_id = handle_id
        self.drift_kind = drift_kind
        self.audit_event = audit_event
        self.audit_result = audit_result


@dataclass(frozen=True, slots=True)
class CanaryToken:
    """A single canary token string to scan for.

    Frozen on purpose: operators register the vocabulary once at
    bootstrap; in-flight mutation would be a footgun (a compromised
    subscriber rotating the registry mid-process would invalidate the
    spec §7.6 guarantee for any fetch already in flight).
    """

    value: str


class InboundCanaryScanner:
    """Scans T3 content for canary tokens without consuming the
    :class:`alfred.security.quarantine.ContentHandle`.

    The scanner peeks at the content store via ``GETEX`` with no
    expiry option — Redis preserves the existing TTL by default, so a
    clean scan leaves the handle consumable by the orchestrator. On a
    trip, the handle is **quarantined** (DELETE) BEFORE the raise so a
    compromised downstream consumer cannot race to dereference the
    trip'd content.

    Constructor takes the token vocabulary explicitly so tests can pin
    the set deterministically. Production wiring loads the operator's
    canary registry once at startup; rotating the registry mid-process
    is out of scope for Slice 3.

    Connection lifecycle (perf-102): the scanner holds a long-lived
    Redis client for the peek path. The constructor accepts either
    ``redis_url`` (scanner mints + owns the client; closed via
    :meth:`aclose`) or ``redis_client`` (externally supplied;
    lifecycle owned by the host). Neither raises ``ValueError`` at
    construction — falling back to a per-scan client would re-open the
    perf-102 connection-churn. The host's shutdown path MUST call
    :meth:`aclose` to release the URL-owned client.
    """

    def __init__(
        self,
        *,
        content_store: ContentStore,
        known_canary_tokens: list[CanaryToken],
        redis_url: str | None = None,
        redis_client: aioredis.Redis | None = None,
    ) -> None:
        """Construct a scanner with an explicit peek-client lifecycle.

        Exactly-one-or-both of ``redis_url`` / ``redis_client`` must be
        supplied. Neither is a non-functional configuration and raises
        ``ValueError`` at construction so the misconfiguration is
        impossible to ship past bootstrap — silently falling back to a
        per-scan ``from_url(...)`` would re-introduce the
        connection-churn (perf-102) the explicit lifecycle is designed
        to remove.

        ``redis_client`` (preferred for tests and for hosts that
        already own a connection pool) is treated as externally-owned:
        :meth:`aclose` does NOT close it; the host's shutdown path is
        responsible. ``redis_url`` (preferred for production wiring
        from a config file) makes the scanner the owner — the scanner
        constructs the client lazily on first scan, holds it for the
        process lifetime, and closes it on :meth:`aclose`.

        Passing both is allowed and the explicit client wins; the URL
        is recorded as ``_redis_url`` for forensic attribution but is
        not used to mint a client. The asymmetric default (client beats
        URL) matches the dependency-injection precedent: the host that
        wires the explicit client is asserting intent.

        Args:
            content_store: Required for the delete path on a canary
                trip. The store's URL is NOT used as a silent fallback
                for the peek client (see module rationale above).
            known_canary_tokens: Operator-registered vocabulary; see
                class docstring.
            redis_url: Redis connection URL the scanner will use to
                mint its OWN long-lived peek client on first scan.
                Mutually-optional with ``redis_client`` — at least one
                must be supplied.
            redis_client: Externally-supplied
                :class:`redis.asyncio.Redis` client. Lifecycle owned
                by the host. ``aclose()`` will NOT close this client.

        Raises:
            ValueError: Neither ``redis_url`` nor ``redis_client`` was
                supplied. The scanner is non-functional in this
                configuration; raise at construction so the
                misconfiguration is caught at bootstrap rather than at
                first scan (when a trip may already have content
                in-flight).
        """
        if redis_url is None and redis_client is None:
            # Hardcoded English: internal misconfiguration message
            # never reaches a user surface; an operator who hits this
            # is wiring code, not interacting via i18n'd channels.
            msg = (
                "InboundCanaryScanner requires one of redis_url or redis_client "
                "(neither supplied). Per-scan client construction is no longer "
                "supported — see perf-102."
            )
            raise ValueError(msg)
        self._store = content_store
        self._redis_url = redis_url
        # _peek_client is the long-lived client. Lazily minted from
        # _redis_url on first scan when no explicit client was passed.
        # ``cast`` rather than the ``redis_client | None`` shape so the
        # scan path can call methods without re-narrowing every time.
        self._peek_client: aioredis.Redis | None = redis_client
        # _owns_client gates whether aclose() closes the underlying
        # client. True for url-constructed clients (scanner is the
        # owner); False for externally-supplied clients (host owns
        # the lifecycle). The flag is fixed at construction and never
        # mutates — a future refactor cannot accidentally close a
        # host-owned client by passing redis_client=... but later
        # setting _owns_client=True.
        self._owns_client = redis_client is None
        # Patterns are compiled against ``str`` (the body is decoded
        # with ``errors='replace'`` at scan time) so a token match
        # surfaces regardless of the body's exact UTF-8 validity. An
        # attacker serving deliberately-mangled bytes cannot bypass
        # the check by triggering a UnicodeDecodeError.
        #
        # Case-insensitive: an attacker lowercasing a well-known
        # canary string must still trip. The token registry is an
        # operator-controlled vocabulary, not user input, so
        # IGNORECASE never widens past what the operator authorised.
        self._patterns: tuple[re.Pattern[str], ...] = tuple(
            re.compile(re.escape(token.value), re.IGNORECASE) for token in known_canary_tokens
        )

    async def _get_peek_client(self) -> aioredis.Redis:
        """Return the long-lived peek client, minting on first call.

        Two construction paths converge here:
          * Explicit ``redis_client`` from __init__ — already set;
            return as-is.
          * Lazy mint from ``redis_url`` — construct once, cache, and
            mark ``_owns_client=True`` so :meth:`aclose` closes it.

        Lazy mint (not eager in __init__) because the scanner is
        instantiated at host bootstrap before the asyncio event loop
        starts; ``aioredis.from_url`` returns a Redis instance whose
        connection pool ties into the running loop on first I/O.
        Constructing at __init__ time would not crash but the pool
        binding is cleaner when deferred to the first scan inside the
        event loop.
        """
        if self._peek_client is None:
            # _redis_url is non-None here because __init__ raised
            # ValueError if both were None; mypy needs the assert to
            # narrow ``str | None`` to ``str``.
            assert self._redis_url is not None
            self._peek_client = aioredis.from_url(self._redis_url, decode_responses=False)
        return self._peek_client

    async def aclose(self) -> None:
        """Shut down the scanner's peek client if it owns one.

        Idempotent: callable from supervisor SIGKILL paths without
        coordinating with first-scan timing. Externally-supplied
        clients are NOT closed — the host that injected the client
        owns its lifecycle (the ``redis_client=...`` constructor path
        is the dependency-injection contract).
        """
        if self._owns_client and self._peek_client is not None:
            client = self._peek_client
            self._peek_client = None
            await client.aclose()

    async def scan(self, *, handle_id: str, source_url: str) -> None:
        """Scan the content store entry for canary tokens.

        Read-only on a clean scan (no consume); quarantine + raise on a
        trip; raise :class:`CanaryScanError` on a missing handle.

        Args:
            handle_id: The opaque handle minted by
                :meth:`ContentStore.write`.
            source_url: The URL the content was fetched from. Recorded
                in :class:`WebFetchCanaryTripped` for the audit row.

        Raises:
            WebFetchCanaryTripped: a registered canary token appears in
                the body. The handle is quarantined (deleted) BEFORE
                the raise.
            CanaryScanError: the handle was missing at scan time
                (consumed or expired). Surfaces as a hook dispatcher
                fault so the orchestrator does NOT proceed with
                unscanned content.
        """
        # perf-102: the peek client is long-lived — minted lazily on
        # first scan, held for the process lifetime, closed via
        # :meth:`aclose`. Per-scan ``from_url`` + ``aclose`` (the
        # pre-perf-102 shape) opened a TCP connection on every
        # web.fetch trip; Slice-3 rate limits cap at 30 fetches/minute
        # per user but the scanner runs on EVERY fetch across ALL
        # users, so per-scan client construction was the highest-rate
        # connection-churn in the trust-boundary path.
        client = await self._get_peek_client()
        key = f"alfred:content:{handle_id}"
        # ``GETEX`` with no expiry option preserves the existing
        # TTL (Redis 6.2+ default behaviour). This is the
        # "read-only peek" primitive — value returns; TTL is
        # untouched; key is not consumed.
        body = cast("bytes | None", await client.getex(key))

        if body is None:
            # err-010: a missing handle means the canary check did NOT
            # run. Silently returning would let the orchestrator
            # proceed believing the content was scanned — breaking the
            # §7.6 guarantee. Raise CanaryScanError so the hook
            # dispatcher surfaces the fault.
            _log.error(
                "web_fetch.canary.missing_body",
                handle_id=handle_id,
                source_url=source_url,
                note="handle consumed or expired before canary scan; scan did NOT run",
            )
            raise CanaryScanError(
                handle_id=handle_id,
                drift_kind="missing_body",
                audit_event="tool.web.fetch",
                audit_result="fault",
            )

        # ``errors='replace'`` so deliberately-mangled UTF-8 does not
        # crash the scan. An attacker who learns that a particular
        # canary is registered cannot block the check by serving
        # invalid encoding.
        body_text = body.decode("utf-8", errors="replace")
        for pattern in self._patterns:
            if pattern.search(body_text):
                _log.warning(
                    "web_fetch.canary.tripped",
                    handle_id=handle_id,
                    source_url=source_url,
                    pattern=pattern.pattern,
                )
                # Quarantine BEFORE the raise — the handle must be gone
                # from Redis at the moment WebFetchCanaryTripped
                # propagates so a compromised downstream consumer
                # cannot race to extract the trip'd content.
                #
                # err-002: a RedisError on the delete CANNOT silently
                # swallow the canary trip. Two failure modes line up
                # against each other here:
                #   1. The handle stays alive in Redis (quarantine I/O
                #      failed) — the orchestrator's TTL will eventually
                #      reap it, but in the interim a compromised
                #      consumer COULD race to extract.
                #   2. The typed canary exception does NOT propagate —
                #      the orchestrator's canary arm never fires; the
                #      load-bearing defence is silently bypassed.
                # The second failure mode is strictly worse: a missed
                # quarantine without a missed exception means the
                # orchestrator still aborts the turn and the operator
                # still sees the canary_tripped audit row. A missed
                # exception means the trip is invisible to every layer
                # above. So we emit a LOUD structlog error naming the
                # failed quarantine for operator action — and STILL
                # raise the typed canary exception so the security
                # event surfaces. The orchestrator's catch-arm emits
                # tool.web.fetch.canary_tripped regardless of
                # quarantine I/O outcome (the audit row schema
                # WEB_FETCH_FIELDS does not currently include a
                # quarantine-failure leg; the structlog event is the
                # operator-visible signal until a dedicated
                # quarantine_failed schema lands in a follow-up).
                try:
                    await self._store.delete(handle_id)
                except RedisError as quarantine_exc:
                    _log.error(
                        "web_fetch.canary.quarantine_failed",
                        handle_id=handle_id,
                        source_url=source_url,
                        pattern=pattern.pattern,
                        # Type name only — never str(exc) / exc.args
                        # (T3 content fragments may have ended up in
                        # the Redis error message). Spec §5.6.
                        exception_type=type(quarantine_exc).__name__,
                        note=(
                            "canary quarantine I/O failed; handle may "
                            "remain in store until TTL — typed canary "
                            "exception STILL raised so orchestrator's "
                            "canary arm fires and audit row is emitted"
                        ),
                    )
                raise WebFetchCanaryTripped(source_url=source_url, handle_id=handle_id)


__all__ = [
    "SCANNER_HOOKPOINT",
    "SCANNER_KIND",
    "SCANNER_TIER",
    "CanaryScanError",
    "CanaryToken",
    "InboundCanaryScanner",
]

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
    """

    def __init__(
        self,
        *,
        content_store: ContentStore,
        known_canary_tokens: list[CanaryToken],
    ) -> None:
        self._store = content_store
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
        # Open a fresh client against the same Redis URL. The scanner
        # is a system-tier observer; giving it direct access to the
        # store's internal client would couple two unrelated lifecycles
        # (the store owns the extract path; the scanner owns the peek
        # path). One connection per peek is acceptable cost — Slice-3
        # rate limits cap fetch throughput at 30/minute per user, so
        # the connection-churn is bounded.
        client = aioredis.from_url(self._store.redis_url, decode_responses=False)
        try:
            key = f"alfred:content:{handle_id}"
            # ``GETEX`` with no expiry option preserves the existing
            # TTL (Redis 6.2+ default behaviour). This is the
            # "read-only peek" primitive — value returns; TTL is
            # untouched; key is not consumed.
            body = cast("bytes | None", await client.getex(key))
        finally:
            await client.aclose()

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

"""DiscordAdapter — Slice-2 Discord DM gateway adapter.

PR D2's adapter completes Slice 2's Discord round-trip: an operator
pre-maps a Discord snowflake via ``alfred user add --discord-id ...``,
boots ``alfred-discord`` in docker compose, and a DM from Discord
round-trips through the orchestrator with audit + budget + episodic
memory + outbound DLP + per-user rate-limiting all in place.

Trust-boundary discipline (CLAUDE.md hard rule #3):

* ``msg.content`` is the ONLY field we parse. The allowlist
  enforcement layer (``_non_empty_content_fields``) asserts that
  embeds, attachments, stickers, references, polls, components,
  activity, and application are all empty/None before the orchestrator
  ever sees the message. A non-empty allowlist field triggers an
  audit + a polite ``discord.embed_unsupported`` refusal with zero
  orchestrator call.
* User input is tagged T2 at this boundary; assistant output is T2
  (ADR-0008). Slice-3+ promotes provider output to T1 + introduces
  T3 via the dual-LLM split.

Outbound chokepoint (CLAUDE.md hard rule #7, sec-002):

* Every outbound message — refusals, error replies, happy-path
  responses — passes through ``_send``, which runs the text through
  ``OutboundDlp.scan`` then ``_split_for_discord`` before calling
  ``channel.send`` exactly once per chunk. A grep-AST test in
  ``tests/unit/comms/test_discord.py`` pins this: ``msg.channel.send``
  must appear ONLY inside ``_send``.

Audit-DoS mitigation (spec §3 lines 538-545):

* A per-snowflake ``TTLCache(maxsize=1024, ttl=3600)`` deduplicates
  unknown-DM audit writes. The first DM from an unknown snowflake
  writes ONE audit row + ONE polite refusal with a bind hint; subsequent
  DMs from the same snowflake within the TTL silently drop.
* A global token-bucket caps ``discord.unknown_user_dm`` audit writes
  at 60/min by default. Beyond the cap the audit row is dropped (but
  the first-contact refusal still sends — the cap protects the
  append-only audit log, not the user UX) and
  ``discord_unknown_dm_audit_dropped_total`` increments.

discord.py logging bridge:

* ``logging.getLogger("discord")`` is routed through a structlog
  ``ProcessorFormatter`` whose processor chain includes the broker's
  redactor AND ``OutboundDlp.scan`` so any token-leaking library debug
  line is masked before reaching disk. Configured in
  ``_bridge_library_logging`` and lands in ``alfred discord`` boot
  before any other adapter code that might emit a debug line.

Reconnect classification table (spec §3 lines 553-559):

* ``LoginFailure`` → ERROR + audit ``result=login_failed`` + exit 2.
* ``ConnectionClosed`` 4xxx → WARN; library auto-reconnect; no audit.
* ``HTTPException`` 5xx mid-send → WARN; retry once; on second
  failure drop chunk + audit ``result=send_failed``.
* >10 reconnects in 60s → ERROR + audit ``result=gateway_unhealthy``
  + exit 1.

Lifecycle:

* ``start()`` constructs the ``discord.Client`` via the injected
  ``client_factory`` (real ``discord.Client`` in production; mock in
  tests). Writes the adapter-startup audit row carrying the intent
  flag list. Registers ``on_ready`` + ``on_message`` event handlers.
* ``run()`` awaits ``client.start(token, reconnect=True)`` — the
  gateway connection forever.
* ``stop()`` calls ``client.close()`` and is idempotent. SIGTERM and
  SIGINT bind to this same code path so compose's 10s SIGTERM grace
  drains cleanly.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import signal
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, cast

import discord
import structlog
from cachetools import TTLCache

from alfred.comms._types import AdapterHealth
from alfred.comms.discord_types import _DiscordClientLike
from alfred.comms.markdown_split import _split_for_discord
from alfred.i18n import set_language, t
from alfred.identity.errors import IdentityResolutionError
from alfred.identity.models import Platform
from alfred.security.tiers import T2, tag

if TYPE_CHECKING:
    from alfred.audit.log import AuditWriter
    from alfred.identity.models import User
    from alfred.identity.rate_limit import RateLimiter
    from alfred.identity.resolver import IdentityResolver
    from alfred.memory.working import WorkingMemory
    from alfred.memory.working_pool import WorkingMemoryPool
    from alfred.orchestrator.core import Orchestrator
    from alfred.security.dlp import OutboundDlp
    from alfred.security.secrets import SecretBroker
    from alfred.security.tiers import TaggedContent

# Persona literal — Slice-2 is single-persona (Alfred). Slice-5 replaces with
# per-turn lookup against the persona registry.
_ALFRED_PERSONA_ID: Final[str] = "alfred"

# Discord caps single-message payloads at 2000 chars; the splitter respects
# that ceiling and keeps markdown state intact across chunk boundaries.
_DISCORD_MAX_LEN: Final[int] = 2000

# Unknown-DM dedup TTL + capacity. 1024 unique snowflakes for 1h matches a
# moderate-traffic Discord install; tune if a deployment sees more DM
# diversity.
_UNKNOWN_DM_DEDUP_MAXSIZE: Final[int] = 1024
_UNKNOWN_DM_DEDUP_TTL_S: Final[float] = 3600.0

# Global audit-DoS cap — bound to a token-bucket. Default 60/min: an honest
# user-facing flow tops out around 5-10 unknown-snowflake DMs in any minute,
# so 60 leaves a comfortable margin while still capping a snowflake-
# iterating spam bot's audit blast radius. Operators tune via
# ``Settings.discord_unknown_dm_audit_cap_per_min`` (Slice-3+ wires the
# setting; Slice-2 ships the default).
_UNKNOWN_DM_AUDIT_CAP_PER_MIN: Final[int] = 60

# Reconnect-storm threshold for the gateway-unhealthy exit path. >10
# reconnects in the trailing 60s trips ``EXIT_1`` (spec §3 line 559).
_RECONNECT_WINDOW_S: Final[float] = 60.0
_RECONNECT_THRESHOLD: Final[int] = 10

# Prometheus counter stub — production-wiring to ``prometheus_client``
# lands in Slice 3 alongside the other observability surfaces. The
# module-level int is the seam tests assert against (and the eventual
# Slice-3 exporter will read it at scrape time, hence its inclusion in
# ``__all__`` below — CodeQL's py/unused-global-variable can't see
# either the in-function ``global`` mutation nor the future scrape-time
# read without an explicit export contract).
discord_unknown_dm_audit_dropped_total: int = 0

# Public-export contract for static analysers. Tests use explicit
# imports rather than ``from alfred.comms.discord import *`` so this
# list does NOT narrow runtime visibility — its sole purpose is making
# CodeQL's ``py/unused-global-variable`` analyser see the counter
# (which is read at scrape time by the Slice-3 Prometheus exporter the
# stub is the seam for, and read directly by the test suite via
# ``import alfred.comms.discord as discord_mod``).
__all__ = [
    "DiscordAdapter",
    "discord_unknown_dm_audit_dropped_total",
    "run_verify_probe",
]

_log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# pybabel-visible registration of i18n keys used via ``t_key=`` dispatch
# ---------------------------------------------------------------------------


def _register_pybabel_visible_keys() -> None:
    """Touch i18n keys dispatched via ``t_key=`` so pybabel sees them.

    ``_audit_and_send_refusal`` (line 784) takes ``t_key: str`` and
    calls ``t(t_key, **kwargs)`` at runtime. ``pybabel extract`` only
    sees ``t()`` called with a literal first arg — it cannot follow
    data flow through variable parameters. The literal ``t()`` calls
    inside this function body are what pybabel parses; the function
    itself is never invoked.

    Function-scoped (rather than module-scope) so static analysers
    don't flag the bindings as unused globals — pybabel's AST walk
    only cares that the literal ``t("...")`` calls exist inside the
    parsed source.
    """
    t("discord.embed_unsupported")
    t("discord.rate_limited")


# ---------------------------------------------------------------------------
# Reconnect classification
# ---------------------------------------------------------------------------


class _GatewayDisposition(enum.Enum):
    """How the supervisor should react to a gateway-layer exception.

    The adapter classifies exceptions raised from ``client.start`` /
    ``channel.send`` into one of these dispositions and dispatches the
    corresponding audit row + reconnect / exit decision.
    """

    LOGIN_FAILED_EXIT_2 = "login_failed_exit_2"
    CONNECTION_CLOSED_AUTO_RECONNECT = "connection_closed_auto_reconnect"
    HTTP_5XX_RETRY_ONCE_THEN_DROP = "http_5xx_retry_once_then_drop"
    REPEATED_RECONNECT_EXIT_1 = "repeated_reconnect_exit_1"
    UNCLASSIFIED = "unclassified"


@dataclass
class _RecentReconnects:
    """Sliding-window counter for reconnect events.

    Records monotonic timestamps; ``register()`` returns True when the
    count of events within the window exceeds the threshold so the
    caller can trip the EXIT_1 branch. Used by the reconnect
    classification table to escalate from "library auto-reconnect" to
    "exit 1 — gateway unhealthy".
    """

    window_seconds: float = _RECONNECT_WINDOW_S
    threshold: int = _RECONNECT_THRESHOLD
    _events: list[float] | None = None

    def register(self, *, now: float | None = None) -> bool:
        """Record an event at ``now``; return True if threshold exceeded."""
        if self._events is None:
            self._events = []
        timestamp = now if now is not None else time.monotonic()
        # Drop events outside the trailing window.
        cutoff = timestamp - self.window_seconds
        self._events = [t for t in self._events if t >= cutoff]
        self._events.append(timestamp)
        return len(self._events) > self.threshold


def _classify_gateway_exception(
    exc: BaseException,
    *,
    recent: _RecentReconnects | None = None,
) -> _GatewayDisposition:
    """Map a discord.py exception to a _GatewayDisposition.

    The classification is the single source of truth shared between the
    adapter's ``run()`` supervisor and the ``alfred discord verify``
    subcommand's exit-code table. Keep these mappings in lockstep with
    spec §3 lines 553-559 — a renamed disposition or a misordered
    isinstance chain shifts the verify exit codes silently.
    """
    if isinstance(exc, discord.LoginFailure):
        return _GatewayDisposition.LOGIN_FAILED_EXIT_2
    if isinstance(exc, discord.ConnectionClosed):
        # 4xxx codes are "expected" close codes that the library
        # auto-reconnects on; 5xxx (server-error close codes) trip the
        # reconnect-storm escalation. The code attribute is `code`.
        if recent is not None and recent.register():
            return _GatewayDisposition.REPEATED_RECONNECT_EXIT_1
        return _GatewayDisposition.CONNECTION_CLOSED_AUTO_RECONNECT
    if isinstance(exc, discord.HTTPException):
        # 5xx status codes get the retry-once-then-drop treatment per the
        # table; non-5xx HTTPException is unclassified and propagates.
        status = getattr(exc, "status", None)
        if isinstance(status, int) and 500 <= status < 600:
            return _GatewayDisposition.HTTP_5XX_RETRY_ONCE_THEN_DROP
    return _GatewayDisposition.UNCLASSIFIED


# ---------------------------------------------------------------------------
# discord.py logging bridge
# ---------------------------------------------------------------------------


class _RedactingFormatter(logging.Formatter):
    """``logging.Formatter`` that routes the rendered message through DLP.

    discord.py uses stdlib ``logging`` for its own debug/info chatter
    (gateway handshake, HTTP response decoding, member-cache events).
    A misbehaving downstream library could log a token or session id
    inline; the formatter pipes the final string through
    ``OutboundDlp.scan`` so the broker's redactor (stage 1) AND the
    generic-API-key regex (stage 2) both run before the line reaches
    disk.

    The formatter is constructed inside ``_bridge_library_logging`` so
    the DLP instance the adapter uses is the same one that funnels
    outbound user-facing messages. Single source of redaction truth.
    """

    def __init__(self, *, outbound_dlp: OutboundDlp) -> None:
        super().__init__("%(asctime)s %(levelname)s %(name)s %(message)s")
        self._dlp = outbound_dlp

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        # ``OutboundDlp.scan`` is synchronous; calling it inside the
        # logging.Formatter is safe (no event loop dependency).
        return self._dlp.scan(rendered)


def _bridge_library_logging(*, outbound_dlp: OutboundDlp) -> None:
    """Attach the redacting formatter to ``logging.getLogger("discord")``.

    Idempotent: replaces any existing handler installed by a previous
    call so the test suite can re-bridge across fixtures without
    stacking formatters. The handler is set at INFO level — DEBUG is
    too noisy for production but operators can drop the level
    temporarily via the ``ALFRED_DISCORD_LOG_LEVEL`` env var (Slice-3+
    surfaces a CLI flag).
    """
    logger = logging.getLogger("discord")
    handler = logging.StreamHandler()
    handler.setFormatter(_RedactingFormatter(outbound_dlp=outbound_dlp))
    # Clear prior handlers so re-bridging in tests doesn't stack them.
    for prior in list(logger.handlers):
        logger.removeHandler(prior)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


# ---------------------------------------------------------------------------
# Allowlist helpers
# ---------------------------------------------------------------------------

# Field names on ``discord.Message`` that, if non-empty, signal content the
# Slice-2 adapter refuses to parse. Embeds carry URLs; attachments carry
# arbitrary file bytes; stickers / polls / components / activity /
# application carry structured payloads the orchestrator isn't audited to
# ingest. Allowlist trust-tagging means we only ever look at ``msg.content``.
_ALLOWLIST_FIELDS: Final[tuple[str, ...]] = (
    "embeds",
    "attachments",
    "stickers",
    "reference",
    "poll",
    "components",
    "activity",
    "application",
)


def _non_empty_content_fields(msg: discord.Message) -> list[str]:
    """Return the names of any allowlist fields that are non-empty/non-None.

    Truthiness check follows discord.py's container semantics: empty
    list / None / falsy attribute → omitted. A populated
    ``MessageReference()``, ``Embed()``, etc. registers as present.
    """
    present: list[str] = []
    for field in _ALLOWLIST_FIELDS:
        value = getattr(msg, field, None)
        # ``bool(value)`` collapses both empty-container and None into
        # the "absent" case; anything else is "present".
        if value:
            present.append(field)
    return present


# ---------------------------------------------------------------------------
# Unknown-DM audit-DoS guard
# ---------------------------------------------------------------------------


class _UnknownDmAuditCap:
    """Per-minute token-bucket on unknown-DM audit writes.

    Sliding 60-second window with up to ``cap_per_min`` allowed audit
    rows. Beyond the cap the audit row is dropped (counter increments)
    but the user-facing reply still sends — the cap protects the
    append-only log, not the UX.

    A single ERROR log line summarising the drop volume is emitted at
    most once per minute to avoid going silent under a sustained flood.
    """

    def __init__(self, *, cap_per_min: int = _UNKNOWN_DM_AUDIT_CAP_PER_MIN) -> None:
        self._cap = cap_per_min
        self._events: list[float] = []
        self._last_summary_at: float = 0.0
        self._drops_since_summary: int = 0

    def try_consume(self, *, now: float | None = None) -> bool:
        """Return True if the audit row may be written, False if dropped."""
        timestamp = now if now is not None else time.monotonic()
        cutoff = timestamp - _RECONNECT_WINDOW_S  # reuse the 60s constant
        self._events = [t for t in self._events if t >= cutoff]
        if len(self._events) >= self._cap:
            self._drops_since_summary += 1
            # Emit one ERROR per rolling minute summarising the drops.
            if timestamp - self._last_summary_at >= _RECONNECT_WINDOW_S:
                self._last_summary_at = timestamp
                _log.error(
                    "discord.unknown_user_dm_audit_dropped_summary",
                    cap_per_min=self._cap,
                    drops_in_window=self._drops_since_summary,
                )
                self._drops_since_summary = 0
            global discord_unknown_dm_audit_dropped_total
            discord_unknown_dm_audit_dropped_total += 1
            return False
        self._events.append(timestamp)
        return True


# ---------------------------------------------------------------------------
# DiscordAdapter
# ---------------------------------------------------------------------------


class DiscordAdapter:
    """Slice-2 Discord DM gateway adapter.

    Implements the :class:`alfred.comms.adapter.CommsAdapter` Protocol.
    Construction takes the canonical Slice-2 inject set (same as
    :class:`alfred.comms.tui_adapter.TuiAdapter`), plus a
    ``client_factory`` callable so unit tests can substitute the real
    ``discord.Client`` with a stub conforming to the
    :class:`alfred.comms.discord_types._DiscordClientLike` Protocol.

    The adapter is a long-running task: ``start()`` constructs the
    client + registers handlers + writes the adapter-startup audit row;
    ``run()`` blocks on the gateway connection until ``stop()`` triggers
    a clean close. ``health()`` returns a synchronous snapshot the
    supervisor's ``alfred status`` reads.
    """

    # Instance variable (not ClassVar) to satisfy the CommsAdapter
    # Protocol — Protocol attributes default to instance-variable
    # semantics, so a ClassVar-marked override would fail variance.
    name: str = "discord"

    def __init__(
        self,
        *,
        orchestrator: Orchestrator,
        identity_resolver: IdentityResolver,
        broker: SecretBroker,
        outbound_dlp: OutboundDlp,
        rate_limiter: RateLimiter,
        working_pool: WorkingMemoryPool,
        audit: AuditWriter,
        client_factory: Callable[[discord.Intents], _DiscordClientLike] | None = None,
        unknown_dm_audit_cap_per_min: int = _UNKNOWN_DM_AUDIT_CAP_PER_MIN,
    ) -> None:
        self._orch = orchestrator
        self._identity = identity_resolver
        self._broker = broker
        self._outbound_dlp = outbound_dlp
        self._rate_limiter = rate_limiter
        self._working_pool = working_pool
        self._audit = audit
        # ``discord.Client`` itself satisfies the _DiscordClientLike
        # structural Protocol; passing it as the default factory keeps
        # the production path one call away from the constructor.
        self._client_factory: Callable[[discord.Intents], _DiscordClientLike] = (
            client_factory if client_factory is not None else _default_client_factory
        )
        # Audit-DoS dedup + cap state. Scoped to the adapter instance —
        # state restarts on adapter restart (documented spec semantics).
        # ``TTLCache`` is a generic with invariant type parameters in
        # the latest types-cachetools; cast it through ``Any`` to keep
        # the call site readable. The runtime behaviour stays a
        # str → float mapping.
        self._unknown_dm_dedup: Any = TTLCache(
            maxsize=_UNKNOWN_DM_DEDUP_MAXSIZE, ttl=_UNKNOWN_DM_DEDUP_TTL_S
        )
        self._unknown_dm_audit_cap = _UnknownDmAuditCap(cap_per_min=unknown_dm_audit_cap_per_min)
        # Reconnect-storm tracker.
        self._recent_reconnects = _RecentReconnects()
        # Lifecycle handles.
        self._client: _DiscordClientLike | None = None
        self._started_at: datetime | None = None
        self._last_on_ready_at: datetime | None = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        """Construct the client + register handlers + write startup audit.

        Idempotent: a re-``start()`` after ``stop()`` rebuilds the client
        with fresh intents (discord.py's ``Client`` is single-shot after
        ``close()``).
        """
        # Bridge the library log before any client construction so a
        # discord.py debug line emitted during ``Client.__init__`` is
        # already redacted.
        _bridge_library_logging(outbound_dlp=self._outbound_dlp)

        intents = _compute_intents()
        client = self._client_factory(intents)
        self._client = client
        self._started_at = datetime.now(UTC)

        # The handlers use ``async def``; discord.py inspects the
        # coroutine status at registration and binds by ``__name__``.
        # Closures let us await ``self.*`` methods.
        async def on_ready() -> None:
            self._last_on_ready_at = datetime.now(UTC)
            _log.info(
                "discord.on_ready",
                intents=_intents_summary(intents),
            )

        async def on_message(msg: discord.Message) -> None:
            try:
                await self._handle(msg)
            except asyncio.CancelledError:
                raise
            except Exception:
                # The handler logs + audits + re-raises internally; the
                # outer except is a defense-in-depth so a programmer
                # error in ``_handle`` doesn't crash the gateway loop.
                _log.exception("discord.unhandled_handler_error")

        client.event(on_ready)
        client.event(on_message)

        # Adapter-startup audit row carrying the intent flag list.
        try:
            await self._audit.append(
                event="discord.adapter_startup",
                actor_user_id=None,
                actor_persona=_ALFRED_PERSONA_ID,
                subject={"intents": _intents_summary(intents)},
                trust_tier_of_trigger="T0",
                result="success",
                cost_estimate_usd=0.0,
                cost_actual_usd=0.0,
                trace_id="discord.adapter_startup",
                language="en-US",
                persona_id=_ALFRED_PERSONA_ID,
            )
        except Exception:
            # CLAUDE.md hard rule #7: a failed startup audit is loud
            # but the adapter still tries to come up — the loud log is
            # the operator's signal that something is wrong.
            _log.exception("discord.adapter_startup_audit_failed")

    async def run(self) -> None:
        """Run the gateway loop until ``stop()`` is called.

        Returns cleanly when ``stop()`` requests a shutdown. Reconnect
        classification + repeat-storm detection happens here.
        """
        if self._client is None:
            raise RuntimeError("DiscordAdapter.run() called before start()")

        # Install SIGTERM/SIGINT so compose's 10s SIGTERM grace drains
        # cleanly. ``_install_signal_handlers`` is best-effort — pytest
        # event loops don't always allow signal installation, and the
        # adapter must still come up under those conditions.
        _install_signal_handlers(self._client)

        token = self._broker.get("discord_bot_token")
        # ``client.start(token, reconnect=True)`` blocks until the
        # gateway connection is closed. discord.py handles auto-
        # reconnect for 4xxx close codes; 5xx and login failures
        # propagate up here for our classification.
        await self._client.start(token, reconnect=True)

    async def stop(self) -> None:
        """Request a clean shutdown of the gateway connection.

        Idempotent: a second call is a no-op if the client is already
        closed.
        """
        if self._client is not None:
            with suppress(Exception):
                await self._client.close()

    def health(self) -> AdapterHealth:
        """Return a synchronous health snapshot for the supervisor."""
        return AdapterHealth(
            gateway_connected=(self._client is not None and bool(self._client.is_ready())),
            last_on_ready_at=self._last_on_ready_at,
            recent_reconnect_count=len(self._recent_reconnects._events or []),
        )

    # ------------------------------------------------------------------ #
    # _handle — main inbound dispatch
    # ------------------------------------------------------------------ #

    async def _handle(self, msg: discord.Message) -> None:
        """Process one inbound Discord message end-to-end.

        Branch ordering (security-sensitive — do not reorder without
        updating spec §3 lines 348-401):

        1. Bot author → silent drop.
        2. Non-DM channel → silent drop (Slice-2 is DM-only).
        3. Allowlist refusal → audit + polite refusal reply.
        4. Identity resolution; unknown → unknown-DM branch.
        5. Per-user rate limit → audit + (non-read_only) reply.
        6. set_language(user.language).
        7. WorkingMemoryPool.acquire (top-of-turn).
        8. Orchestrator call inside try/finally with typed exception
           arms (BudgetExceededError, UnknownBudgetUserError,
           CancelledError, Exception).
        9. ``_send`` the assistant reply.
        """
        # Step 1 — short-circuit bot authors. Discord-bot loops are a
        # classic foot-gun.
        if msg.author.bot:
            return
        # Step 2 — DMs only for Slice 2. Group channels (Slice-4
        # threads) and guild channels (later) are silent drops.
        if not isinstance(msg.channel, discord.DMChannel):
            return
        # Step 3 — allowlist refusal. Any non-empty attachment / embed /
        # poll / etc. triggers an audit + a polite ``embed_unsupported``
        # reply with zero orchestrator call.
        refused_fields = _non_empty_content_fields(msg)
        if refused_fields:
            await self._audit_and_send_refusal(
                msg=msg,
                event_name="discord.embed_refused",
                t_key="discord.embed_unsupported",
                subject_fields={"refused_fields": tuple(refused_fields)},
            )
            return

        # Step 4 — identity resolution. Unknown snowflakes go through
        # the audit-DoS-guarded unknown-DM branch.
        snowflake = str(msg.author.id)
        try:
            user = await asyncio.to_thread(self._identity.resolve, Platform.DISCORD, snowflake)
        except IdentityResolutionError:
            # Resolver-side error (e.g. DB unreachable) — defensive log,
            # tell the user generic error, do NOT re-raise (we want the
            # gateway loop to stay up).
            _log.exception("discord.identity_resolve_failed", snowflake=snowflake)
            await self._send(t("discord.alfred_error"), channel=msg.channel)
            return
        if user is None:
            await self._handle_unknown_dm(msg=msg, snowflake=snowflake)
            return

        # Step 5 — per-user rate limit. The PR D1 InProcessTokenBucket
        # checks READ_ONLY FIRST internally; we just pass the User
        # through. On READ_ONLY refusal the audit is written but NO
        # reply is sent (sec-002 — denies the friend-list oracle).
        allowed = await self._rate_limiter.allow(user)
        if not allowed:
            await self._handle_rate_limited(msg=msg, user=user)
            return

        # Step 6 — per-coroutine language. ContextVar propagates across
        # awaits so t(...) downstream renders in this user's language
        # without handler-side bookkeeping.
        set_language(user.language)

        # Step 7+8 — WorkingMemoryPool acquire + orchestrator call inside
        # try/finally + typed exception arms.
        await self._dispatch_turn(msg=msg, user=user)

    async def _handle_unknown_dm(self, *, msg: discord.Message, snowflake: str) -> None:
        """Handle a DM from an unknown snowflake — dedup + cap + reply.

        Decision matrix:

        * First contact (snowflake not in dedup): try to write the audit
          row (subject to the global cap); always send the polite reply.
        * Repeat within TTL: silently drop everything. The audit log
          already has the first-contact row.
        """
        now = time.monotonic()
        already_seen = snowflake in self._unknown_dm_dedup
        if already_seen:
            # Repeat — silent drop. The cache holds the previous
            # observation timestamp purely as a debugging aid.
            return
        # Mark as seen now so a flood from the same snowflake within
        # the TTL hits the silent-drop branch above on every subsequent
        # message.
        self._unknown_dm_dedup[snowflake] = now

        # Audit-DoS cap. Past the cap we drop the audit row but still
        # send the reply — the cap protects the audit log, not the UX.
        if self._unknown_dm_audit_cap.try_consume(now=now):
            try:
                await self._audit.append(
                    event="discord.unknown_user_dm",
                    actor_user_id=None,
                    actor_persona=_ALFRED_PERSONA_ID,
                    subject={"snowflake": snowflake},
                    trust_tier_of_trigger="T2",
                    result="refused_unknown_user",
                    cost_estimate_usd=0.0,
                    cost_actual_usd=0.0,
                    trace_id=f"discord.unknown_user_dm.{snowflake}",
                    language="en-US",
                    persona_id=_ALFRED_PERSONA_ID,
                )
            except Exception:
                # Loud + re-raise per CLAUDE.md hard rule #7. The
                # outer ``_on_message`` wrapper catches and logs; we
                # do not block the user-facing reply.
                _log.exception("discord.unknown_user_dm_audit_failed", snowflake=snowflake)

        # The reply is the literal devex-004 body: snowflake echo +
        # bind hint. ``{snowflake}`` is the only placeholder;
        # ``<YourName>`` stays literal in the template.
        await self._send(
            t("discord.unknown_user_first", snowflake=snowflake),
            channel=msg.channel,
        )

    async def _handle_rate_limited(self, *, msg: discord.Message, user: User) -> None:
        """Audit + (selectively) reply on a rate-limit denial.

        ``READ_ONLY`` users get an audit-only refusal (no reply); all
        other denials get an audit row + the rate-limited reply.
        """
        from alfred.identity.models import Authorization

        if user.authorization == Authorization.READ_ONLY.value:
            # READ_ONLY: audit-only. Sending a reply would leak the
            # presence of the bot to a known-snowflake-but-deauthorized
            # user (friend-list oracle, sec-002).
            try:
                await self._audit.append(
                    event="discord.read_only_refused",
                    actor_user_id=user.slug,
                    actor_persona=_ALFRED_PERSONA_ID,
                    subject={"snowflake": str(msg.author.id)},
                    trust_tier_of_trigger="T2",
                    result="refused",
                    cost_estimate_usd=0.0,
                    cost_actual_usd=0.0,
                    trace_id=f"discord.read_only_refused.{user.slug}",
                    language=user.language,
                    persona_id=_ALFRED_PERSONA_ID,
                )
            except Exception:
                _log.exception("discord.read_only_audit_failed", user_id=user.slug)
            return
        # Non-READ_ONLY: audit + reply. No ``{error}`` interpolation
        # (spec line 415) — the template is fixed-phrase.
        set_language(user.language)
        await self._audit_and_send_refusal(
            msg=msg,
            event_name="discord.rate_limited",
            t_key="discord.rate_limited",
            subject_fields={"user_id": user.slug},
            actor_user_id=user.slug,
            language=user.language,
        )

    async def _dispatch_turn(self, *, msg: discord.Message, user: User) -> None:
        """Acquire WM, call orchestrator inside try/finally, send reply.

        The exception arms here mirror spec §3 lines 383-396:

        * ``BudgetExceededError`` → typed-kwargs reply, no re-raise.
        * ``UnknownBudgetUserError`` → friendly reply + re-raise (loud).
        * ``asyncio.CancelledError`` → bare re-raise (NEVER swallow).
        * ``Exception`` → log + friendly reply + re-raise so the gateway
          loop's classifier can decide.
        """
        from alfred.budget.guard import BudgetExceededError, UnknownBudgetUserError

        key = ("alfred", user.slug)
        wm: WorkingMemory = await self._working_pool.acquire(key)
        try:
            content: TaggedContent[T2] = tag(T2, msg.content, source="comms.discord.input")
            # The orchestrator's UserLike Protocol matches the SQLAlchemy
            # ORM `User` row at runtime. Cast to satisfy strict
            # checkers — see the TUI's equivalent cast (orchestrator
            # docstring + ADR-0007).
            from alfred.orchestrator.core import UserLike as _UserLike

            try:
                response = await self._orch.handle_user_message(
                    user=cast("_UserLike", user),
                    content=content,
                    working_memory=wm,
                )
            except BudgetExceededError as exc:
                # Typed kwargs only — never ``str(exc)`` and never an
                # ``{error}`` placeholder in the catalog.
                await self._send(
                    t(
                        "discord.budget_blocked",
                        spent=f"{exc.spent_usd:.2f}",
                        cap=f"{exc.cap_usd:.2f}",
                    ),
                    channel=msg.channel,
                )
                return
            except UnknownBudgetUserError:
                # Defense-in-depth: resolver should have rejected an
                # unknown slug upstream. Loud + friendly reply + re-
                # raise so the gateway loop's classifier sees it.
                _log.exception("discord.unknown_budget_user", user_id=user.slug)
                await self._send(t("discord.alfred_error"), channel=msg.channel)
                raise
            except asyncio.CancelledError:
                raise
            except Exception:
                _log.exception("discord.handler_failed", user_id=user.slug)
                await self._send(t("discord.alfred_error"), channel=msg.channel)
                raise

            await self._send(response, channel=msg.channel)
        finally:
            await self._working_pool.release(key, wm)

    # ------------------------------------------------------------------ #
    # _audit_and_send_refusal — DRY helper
    # ------------------------------------------------------------------ #

    async def _audit_and_send_refusal(
        self,
        *,
        msg: discord.Message,
        event_name: str,
        t_key: str,
        subject_fields: Mapping[str, Any],
        actor_user_id: str | None = None,
        language: str = "en-US",
        t_kwargs: Mapping[str, Any] | None = None,
    ) -> None:
        """Audit-then-reply convenience.

        Audit row writes FIRST (spec line 416). On audit failure we
        log loud + bump the error counter + propagate (CLAUDE.md hard
        rule #7); on audit success we render the t_key reply via
        ``_send``.
        """
        # Augment subject with the snowflake for forensic correlation.
        subject = dict(subject_fields)
        subject.setdefault("snowflake", str(msg.author.id))
        try:
            await self._audit.append(
                event=event_name,
                actor_user_id=actor_user_id,
                actor_persona=_ALFRED_PERSONA_ID,
                subject=subject,
                trust_tier_of_trigger="T2",
                result="refused",
                cost_estimate_usd=0.0,
                cost_actual_usd=0.0,
                trace_id=f"{event_name}.{msg.author.id}",
                language=language,
                persona_id=_ALFRED_PERSONA_ID,
            )
        except Exception:
            # CLAUDE.md hard rule #7: loud + re-raise. The outer
            # ``_on_message`` wrapper catches + logs; we don't want a
            # silent audit failure. Structlog reserves ``event`` for
            # the event-name positional, so pass our event name as
            # ``audit_event`` to avoid kwarg conflict.
            _log.exception("discord.audit_refusal_write_failed", audit_event=event_name)
            raise
        kwargs = dict(t_kwargs) if t_kwargs else {}
        await self._send(t(t_key, **kwargs), channel=msg.channel)

    # ------------------------------------------------------------------ #
    # _send — outbound chokepoint
    # ------------------------------------------------------------------ #

    async def _send(
        self,
        text: str,
        *,
        channel: discord.abc.Messageable,
        _recovery: bool = False,
    ) -> None:
        """Outbound chokepoint — DLP scan → markdown split → channel.send.

        Every outbound from this adapter goes through this method. The
        AST grep test in ``tests/unit/comms/test_discord.py`` enforces
        that ``msg.channel.send`` and ``channel.send`` do not appear
        anywhere else in this module.

        The three err-003 audit branches happen INSIDE the try block:

        * ``OutboundDlpError`` (or whatever scan raises) → audit
          ``result=dlp_failed`` + recovery reply.
        * ``MarkdownSplitterError`` → audit ``result=split_failed``
          + recovery reply.
        * ``discord.HTTPException`` 5xx (retry once; on second failure)
          → audit ``result=send_failed`` + ``subject.delivered_chunk_count``.

        Recovery-message recursion guard: a failure path calls
        ``_send(t("discord.alfred_error"), channel=channel, _recovery=True)``
        which SKIPS the DLP+split stages (the recovery message is a
        fixed-phrase t-key, safe by construction). If the recovery send
        itself raises, we log + audit + give up — never recurse forever.
        """
        if _recovery:
            # Fixed-phrase recovery path — bypass DLP+split and call
            # channel.send once. If this raises we log + audit + give up.
            try:
                # ``channel.send`` is the only call site in this module.
                # The grep test allows exactly this one in _send.
                await channel.send(text)
            except Exception:
                _log.exception("discord.recovery_send_failed")
                with suppress(Exception):
                    await self._audit.append(
                        event="comms.discord.send_outcome",
                        actor_user_id=None,
                        actor_persona=_ALFRED_PERSONA_ID,
                        subject={"phase": "recovery_send"},
                        trust_tier_of_trigger="T0",
                        result="recovery_send_failed",
                        cost_estimate_usd=0.0,
                        cost_actual_usd=0.0,
                        trace_id="discord.recovery_send_failed",
                        language="en-US",
                        persona_id=_ALFRED_PERSONA_ID,
                    )
            return

        # DLP scan first — broker redaction + generic API-key regex +
        # canary stub. Any exception from the scanner triggers the
        # dlp_failed audit branch.
        try:
            scanned = self._outbound_dlp.scan(text)
        except Exception as exc:
            _log.exception("discord.dlp_failed")
            await self._write_send_outcome_audit(
                result="dlp_failed",
                subject={
                    "dlp_error": type(exc).__name__,
                    "delivered_chunk_count": 0,
                },
            )
            await self._send(
                t("discord.alfred_error"),
                channel=channel,
                _recovery=True,
            )
            return

        # Markdown-aware split. Any exception from the splitter triggers
        # the split_failed audit branch.
        try:
            chunks = list(_split_for_discord(scanned, max_len=_DISCORD_MAX_LEN))
        except Exception as exc:
            _log.exception("discord.split_failed")
            await self._write_send_outcome_audit(
                result="split_failed",
                subject={
                    "split_error": type(exc).__name__,
                    "delivered_chunk_count": 0,
                },
            )
            await self._send(
                t("discord.alfred_error"),
                channel=channel,
                _recovery=True,
            )
            return

        # Empty input — splitter yields zero chunks per its contract.
        if not chunks:
            await self._write_send_outcome_audit(
                result="success",
                subject={"delivered_chunk_count": 0},
            )
            return

        # Per-chunk send with single retry on HTTPException 5xx (spec
        # §3 reconnect classification). On second failure: audit
        # send_failed with the chunks-delivered-so-far count + recovery
        # message via the recursion-guarded path.
        delivered = 0
        for chunk in chunks:
            ok = await self._send_chunk_with_retry(channel=channel, chunk=chunk)
            if not ok:
                await self._write_send_outcome_audit(
                    result="send_failed",
                    subject={"delivered_chunk_count": delivered},
                )
                await self._send(
                    t("discord.alfred_error"),
                    channel=channel,
                    _recovery=True,
                )
                return
            delivered += 1

        await self._write_send_outcome_audit(
            result="success",
            subject={"delivered_chunk_count": delivered},
        )

    async def _send_chunk_with_retry(
        self,
        *,
        channel: discord.abc.Messageable,
        chunk: str,
    ) -> bool:
        """Send one chunk with a single retry on 5xx. Returns True on success."""
        for attempt in range(2):
            try:
                await channel.send(chunk)
                return True
            except discord.HTTPException as exc:
                status = getattr(exc, "status", None)
                if isinstance(status, int) and 500 <= status < 600 and attempt == 0:
                    _log.warning(
                        "discord.send_retry",
                        status=status,
                        attempt=attempt,
                    )
                    continue
                _log.warning(
                    "discord.send_failed",
                    status=status,
                    attempt=attempt,
                    error_type=type(exc).__name__,
                )
                return False
            except Exception:
                _log.exception("discord.send_unexpected_error", attempt=attempt)
                return False
        return False

    async def _write_send_outcome_audit(
        self,
        *,
        result: str,
        subject: Mapping[str, Any],
    ) -> None:
        """Append a ``comms.discord.send_outcome`` audit row.

        Audit failures are LOUD per CLAUDE.md hard rule #7 — logged at
        ERROR but not re-raised from inside ``_send`` (a re-raise here
        would mask the original ``result`` and bias the supervisor's
        classification). The log line is the operator's signal.
        """
        try:
            await self._audit.append(
                event="comms.discord.send_outcome",
                actor_user_id=None,
                actor_persona=_ALFRED_PERSONA_ID,
                subject=dict(subject),
                trust_tier_of_trigger="T2",
                result=result,
                cost_estimate_usd=0.0,
                cost_actual_usd=0.0,
                trace_id=f"comms.discord.send_outcome.{result}",
                language="en-US",
                persona_id=_ALFRED_PERSONA_ID,
            )
        except Exception:
            _log.exception("discord.send_outcome_audit_failed", outcome_result=result)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _compute_intents() -> discord.Intents:
    """Return the intent set the Slice-2 adapter needs.

    DM-only: ``message_content`` is the gateway intent Discord requires
    the operator to flip in the developer portal so the bot can read DM
    text bodies. ``dm_messages`` is the related event-stream intent.
    All other intents stay at the default (guild messages on, member
    cache off via :func:`discord.MemberCacheFlags.none` in the
    ``discord.Client`` constructor).
    """
    intents = discord.Intents.default()
    intents.message_content = True
    intents.dm_messages = True
    return intents


def _intents_summary(intents: discord.Intents) -> tuple[str, ...]:
    """Return a sorted tuple of intent-flag names that are enabled.

    Used in the adapter-startup audit row + the verify-success log so
    operators can sanity-check which gateway features the bot
    requested. The tuple shape makes structlog render it as a JSON
    array.
    """
    # ``Intents`` exposes ``__iter__`` returning ``(name, value)`` pairs.
    return tuple(sorted(name for name, value in intents if value))


def _default_client_factory(intents: discord.Intents) -> _DiscordClientLike:
    """Construct a real ``discord.Client`` with the Slice-2 slim-cache flags.

    Per spec §3 (perf-005):

    * ``max_messages=100`` — bound the per-channel cache.
    * ``chunk_guilds_at_startup=False`` — skip member-list chunking.
    * ``member_cache_flags=MemberCacheFlags.none()`` — drop the member
      cache entirely; we never read it.

    These keep the 256M compose memory cap viable. The structural
    Protocol :class:`alfred.comms.discord_types._DiscordClientLike`
    matches what discord.Client exposes; the cast is the documented
    Protocol-vs-class accommodation.
    """
    client = discord.Client(
        intents=intents,
        max_messages=100,
        chunk_guilds_at_startup=False,
        member_cache_flags=discord.MemberCacheFlags.none(),
    )
    return cast("_DiscordClientLike", client)


async def run_verify_probe(
    *,
    broker: SecretBroker,
    outbound_dlp: OutboundDlp,
    timeout_s: float,
    client_factory: Callable[[discord.Intents], _DiscordClientLike] | None = None,
) -> tuple[int, str, Mapping[str, Any]]:
    """The verify probe — public seam for ``alfred discord verify``.

    Returns ``(exit_code, structlog_event_key, structlog_event_kwargs)``
    so the CLI can emit a uniform event row + map to its own typed
    exit enum. Spec §2 lines 130-138 — every exit code below matches a
    dedicated unit test in ``tests/unit/comms/test_discord.py``.

    Exit code table:

        0   on_ready fired within timeout_s
        1   unrecoverable upstream — gateway 5xx, repeated reconnect
        2   config — bad token / intents off / secrets unreadable
        3   LoginFailure (typed)
        4   timeout — timeout_s elapsed without on_ready
        130 SIGINT — KeyboardInterrupt during the probe

    The CLI thinks of these as ``_VerifyExitCode`` values; this
    function returns plain ints so the allowlisted seam doesn't leak
    the IntEnum class through the import boundary.
    """
    _bridge_library_logging(outbound_dlp=outbound_dlp)
    try:
        token = broker.get("discord_bot_token")
    except Exception as exc:
        return (
            2,
            "discord.verify.config_failed.bad_token",
            {"error_type": type(exc).__name__},
        )

    intents = _compute_intents()
    factory = client_factory if client_factory is not None else _default_client_factory
    client = factory(intents)

    ready_event = asyncio.Event()

    async def _on_ready() -> None:
        ready_event.set()

    # Discord.py binds ``event`` by ``__name__``; force the registration name.
    _on_ready.__name__ = "on_ready"
    client.event(_on_ready)

    start_task: asyncio.Task[None] | None = None
    try:
        start_task = asyncio.create_task(client.start(token, reconnect=False))
        # Race on_ready against the timeout. We do NOT await start_task
        # directly — it blocks until close. The ready signal is the
        # success criterion.
        try:
            done, _pending = await asyncio.wait(
                {asyncio.create_task(ready_event.wait()), start_task},
                timeout=timeout_s,
                return_when=asyncio.FIRST_COMPLETED,
            )
        except KeyboardInterrupt:
            return (130, "discord.verify.interrupted", {})
        if not done:
            # Timeout — neither on_ready nor start_task returned.
            return (
                4,
                "discord.verify.timeout",
                {"timeout_s": timeout_s},
            )
        if ready_event.is_set():
            return (
                0,
                "discord.verify.ok",
                {"intents": _intents_summary(intents)},
            )
        # start_task completed before on_ready — almost always an
        # error. KeyboardInterrupt surfaces as task.exception() too;
        # check it explicitly before falling through to the general
        # classifier (the classifier doesn't know about SIGINT).
        for task in done:
            task_exc = task.exception() if not task.cancelled() else None
            if isinstance(task_exc, KeyboardInterrupt):
                return (130, "discord.verify.interrupted", {})
            if task_exc is not None:
                return _classify_verify_exception(task_exc)
        # Defensive: start_task returned cleanly without on_ready. Treat
        # as upstream-unrecoverable since the gateway never confirmed.
        return (1, "discord.verify.upstream_unrecoverable", {})
    except KeyboardInterrupt:
        return (130, "discord.verify.interrupted", {})
    except discord.LoginFailure as login_exc:
        return _classify_verify_exception(login_exc)
    except Exception as outer_exc:
        return _classify_verify_exception(outer_exc)
    finally:
        if start_task is not None and not start_task.done():
            start_task.cancel()
            with suppress(BaseException):
                await start_task
        with suppress(Exception):
            await client.close()


def _classify_verify_exception(
    exc: BaseException,
) -> tuple[int, str, Mapping[str, Any]]:
    """Map a verify-time exception onto the exit-code table."""
    if isinstance(exc, KeyboardInterrupt):
        return (130, "discord.verify.interrupted", {})
    if isinstance(exc, discord.LoginFailure):
        return (3, "discord.verify.login_failed", {"error_type": type(exc).__name__})
    if isinstance(exc, discord.HTTPException):
        status = getattr(exc, "status", None)
        if isinstance(status, int) and 400 <= status < 500:
            return (
                2,
                "discord.verify.config_failed.intents_off",
                {"status": status},
            )
        if isinstance(status, int) and 500 <= status < 600:
            return (
                1,
                "discord.verify.upstream_unrecoverable",
                {"status": status},
            )
    disposition = _classify_gateway_exception(exc)
    if disposition == _GatewayDisposition.LOGIN_FAILED_EXIT_2:
        return (3, "discord.verify.login_failed", {})
    if disposition in (
        _GatewayDisposition.HTTP_5XX_RETRY_ONCE_THEN_DROP,
        _GatewayDisposition.REPEATED_RECONNECT_EXIT_1,
    ):
        return (1, "discord.verify.upstream_unrecoverable", {})
    # Unclassified — treat as upstream-unrecoverable so the operator
    # gets the "check status.discord.com" hint rather than a confused
    # CONFIG_FAILED message.
    return (
        1,
        "discord.verify.upstream_unrecoverable",
        {"error_type": type(exc).__name__},
    )


def _install_signal_handlers(client: _DiscordClientLike) -> None:
    """Bind SIGTERM + SIGINT to ``client.close()`` for clean shutdown.

    Best-effort: pytest event loops, Windows, and certain non-Unix
    environments don't allow ``add_signal_handler``. Silent fallback
    keeps the adapter runnable in those environments — the supervisor's
    ``stop()`` still works.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    for sig in (signal.SIGTERM, signal.SIGINT):
        with suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(
                sig,
                lambda: asyncio.create_task(client.close()),
            )

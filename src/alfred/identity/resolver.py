"""The :class:`IdentityResolver` — the only legitimate accessor for ``User``
and ``PlatformIdentity``.

Responsibilities
----------------

* **Lookup** — ``resolve(platform, platform_id) -> User | None`` with an
  in-process LRU cache backed by a 60-second TTL and an
  :class:`IdentityVersionCounter` for cross-process invalidation (the
  ``LISTEN/NOTIFY`` listener task in T12 calls :meth:`IdentityVersionCounter.bump`
  whenever any AlfredOS process mutates an identity row).
* **Mutation** — ``add`` / ``bind`` / ``unbind`` / ``remove`` / ``set_``.
  Every successful mutator bumps the version counter exactly once and, on
  Postgres, emits a ``NOTIFY alfred_identity_changed`` so peer processes
  invalidate their caches. On SQLite the NOTIFY is a no-op (the unit-test
  layer uses SQLite; the integration test in T13 covers the Postgres path).
* **Security invariants** — (1) only one operator may exist concurrently;
  ``--replace-operator <existing>`` atomically demotes the old and promotes
  the new in one transaction. (2) :meth:`remove` refuses to soft-delete the
  last remaining operator.

Design notes
------------

* The class deliberately uses **sync** sessions. Callers from async paths
  (PR B orchestrator, PR D2 Discord adapter) wrap calls in
  :func:`asyncio.to_thread` — see docs/python-conventions.md §async.
  Mixing sync + async sessions through the same factory was the failure
  mode that bit Slice 1's adversarial run (memory note `adversarial-async`).
* ``set_`` has a trailing underscore because ``set`` shadows the built-in.
  The CLI exposes it as ``alfred user set`` (no underscore).
* The LRU is keyed on ``(platform, platform_id)``. The TTL backstop runs
  on every ``resolve`` regardless of cache hit — a counter we missed (e.g.
  listener was disconnected) shouldn't let stale entries live forever.
* :meth:`_notify` is dialect-aware via ``session.bind.dialect.name``. The
  Postgres branch calls ``pg_notify`` from inside the same transaction the
  caller is using, so the NOTIFY is emitted only on COMMIT.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from babel import Locale, UnknownLocaleError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from alfred.identity.errors import (
    IdentityResolutionError,
    LastOperatorRemovalRefusedError,
    OperatorAlreadyExistsError,
)
from alfred.identity.models import Authorization, Platform, PlatformIdentity, User
from alfred.identity.slug import derive_slug
from alfred.identity.version_counter import IdentityVersionCounter

if TYPE_CHECKING:
    from sqlalchemy.orm import Session, sessionmaker

    from alfred.identity.rate_limit import RateLimiter


_LOG = logging.getLogger(__name__)

# Postgres ``LISTEN/NOTIFY`` channel name. Listener task in T12 subscribes
# to the same constant. Keep in sync with ``src/alfred/identity/listener.py``.
_NOTIFY_CHANNEL = "alfred_identity_changed"

# Default daily spend cap when ``add`` is called without an explicit value.
# Chosen low enough that an accidentally-created user can't burn the budget;
# operators tune via ``alfred user set --daily-budget``.
_DEFAULT_DAILY_BUDGET_USD = 5.0

# Default LRU cap. The cache holds (platform, platform_id) -> _CacheEntry;
# at 256 entries we use ~tens of KB of process memory while covering the
# active-user working set of a typical Slice-2 deployment many times over.
_DEFAULT_CACHE_MAX_ENTRIES = 256

# TTL backstop. Even if the version counter is stuck (listener disconnected,
# bug in the bump path), no cached entry survives longer than this. The
# value is intentionally short — 60 seconds means an operator-initiated
# language change becomes visible to every cached resolver inside a minute.
_DEFAULT_CACHE_TTL_S = 60.0


@dataclass(frozen=True)
class _CacheEntry:
    """A single LRU entry.

    ``version_seen`` is the value of :meth:`IdentityVersionCounter.current`
    at the moment we cached the row; on subsequent reads we compare against
    the current value to detect that a peer mutated identity state. The
    counter is purely in-process — the listener task in T12 is what couples
    it to cross-process NOTIFY events.

    ``cached_at`` uses ``time.monotonic`` rather than wall-clock so a system
    clock adjustment can't accidentally extend or shorten the TTL.
    """

    user: User
    version_seen: int
    cached_at: float


class IdentityResolver:
    """The only legitimate accessor for ``User`` + ``PlatformIdentity``.

    See module docstring for the contract. Construct one per process; the
    in-process LRU is per-instance.
    """

    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        version_counter: IdentityVersionCounter,
        rate_limiter: RateLimiter,
        cache_max_entries: int = _DEFAULT_CACHE_MAX_ENTRIES,
        cache_ttl_s: float = _DEFAULT_CACHE_TTL_S,
    ) -> None:
        self._session_factory = session_factory
        self._counter = version_counter
        # Stored for symmetry with the dependency graph PR B builds; the
        # resolver itself never invokes the limiter. The orchestrator does.
        self._rate_limiter = rate_limiter
        self._cache: OrderedDict[tuple[str, str], _CacheEntry] = OrderedDict()
        self._cache_max_entries = cache_max_entries
        self._cache_ttl_s = cache_ttl_s

    # ------------------------------------------------------------------ #
    # Public read surface
    # ------------------------------------------------------------------ #

    def resolve(self, platform: Platform, platform_id: str) -> User | None:
        """Return the live ``User`` bound to (``platform``, ``platform_id``) or ``None``.

        Cache logic: a hit is served iff the entry is younger than the TTL
        AND the version counter has not advanced since we cached it. Either
        a TTL expiry or a counter bump triggers a re-fetch.
        """
        key = (platform.value, platform_id)
        entry = self._cache.get(key)
        now = time.monotonic()
        if (
            entry is not None
            and (now - entry.cached_at) < self._cache_ttl_s
            and entry.version_seen >= self._counter.current()
        ):
            # LRU promote
            self._cache.move_to_end(key)
            return entry.user

        user = self._fetch_user_for_binding(platform, platform_id)
        if user is None:
            # Drop any stale cache entry — a successful unbind can land here.
            self._cache.pop(key, None)
            return None
        self._cache_put(key, user)
        return user

    def get_operator(self) -> User:
        """Return the single live operator user.

        Raises :class:`IdentityResolutionError` if zero or more than one
        operator exists — the CLI surfaces a friendly hint pointing at
        ``alfred user add --authorization operator`` or
        ``alfred user set --replace-operator`` respectively.
        """
        with self._session_factory() as session:
            operators = (
                session.execute(
                    select(User).where(
                        User.authorization == Authorization.OPERATOR.value,
                        User.deleted_at.is_(None),
                    )
                )
                .scalars()
                .all()
            )
        if not operators:
            raise IdentityResolutionError(
                "No operator user exists. Run `alfred user add --authorization operator` "
                "to bootstrap one."
            )
        if len(operators) > 1:
            slugs = ", ".join(sorted(u.slug for u in operators))
            raise IdentityResolutionError(
                f"Multiple operator users exist ({slugs}). This is a corrupt state; "
                "demote all but one via `alfred user set --authorization trusted <slug>`."
            )
        return operators[0]

    def show(self, *, slug: str) -> User | None:
        """Return the user with the given slug (including soft-deleted), or ``None``."""
        with self._session_factory() as session:
            return session.execute(select(User).where(User.slug == slug)).scalar_one_or_none()

    def list_(self, *, include_deleted: bool = False) -> Sequence[User]:
        """Return all users, ordered by slug.

        ``include_deleted=True`` includes soft-deleted rows for audit /
        history surfaces. Defaults to live-only because that's what every
        operator-facing CLI command wants.
        """
        with self._session_factory() as session:
            stmt = select(User).order_by(User.slug)
            if not include_deleted:
                stmt = stmt.where(User.deleted_at.is_(None))
            return session.execute(stmt).scalars().all()

    # ------------------------------------------------------------------ #
    # Public mutation surface — every method bumps the counter on success
    # ------------------------------------------------------------------ #

    def add(
        self,
        *,
        display_name: str,
        authorization: Authorization,
        language: str = "en-US",
        daily_budget_usd: float = _DEFAULT_DAILY_BUDGET_USD,
        slug_override: str | None = None,
        replace_operator: str | None = None,
        rate_limit_per_min: int | None = None,
        rate_limit_per_day: int | None = None,
    ) -> User:
        """Create a new ``User``.

        ``slug_override`` lets the CLI surface a ``--slug`` flag for cases
        where derivation produces something operationally awkward. Defaults
        to deriving from ``display_name``.

        ``replace_operator`` is the atomic demote-then-promote escape hatch
        for the operator upper-bound: pass the slug of the existing operator
        to demote them to ``trusted`` in the same transaction that creates
        the new operator. Without it, attempting to add a second operator
        raises :class:`OperatorAlreadyExistsError`.
        """
        self._validate_language(language)
        self._validate_budget(daily_budget_usd)
        slug_seed = slug_override if slug_override is not None else derive_slug(display_name)

        with self._session_factory.begin() as session:
            self._enforce_operator_upper_bound(
                session,
                target_authorization=authorization,
                replace_operator_slug=replace_operator,
            )
            final_slug = self._next_available_slug(session, slug_seed)
            user = User(
                slug=final_slug,
                display_name=display_name,
                authorization=authorization.value,
                daily_budget_usd=daily_budget_usd,
                language=language,
                rate_limit_per_min=rate_limit_per_min,
                rate_limit_per_day=rate_limit_per_day,
            )
            session.add(user)
            session.flush()
            self._notify(session, event="add", slug=final_slug)

        self._counter.bump()
        return user

    def bind(self, *, user_slug: str, platform: Platform, platform_id: str) -> PlatformIdentity:
        """Bind ``(platform, platform_id)`` to the user with ``user_slug``.

        Raises :class:`IdentityResolutionError` if the user already has a
        live binding for ``platform`` (partial-unique index) or if the
        ``(platform, platform_id)`` pair is already in use by another user
        (global UNIQUE).
        """
        try:
            with self._session_factory.begin() as session:
                user = session.execute(
                    select(User).where(User.slug == user_slug, User.deleted_at.is_(None))
                ).scalar_one_or_none()
                if user is None:
                    raise IdentityResolutionError(
                        f"No live user with slug '{user_slug}' to bind to."
                    )
                # Python-side pre-check for the (user, platform) live-uniqueness
                # invariant. SQLite has no partial-unique-index support so we
                # cannot rely on the DB to surface a constraint error there;
                # Postgres has the partial index and would also raise. The
                # explicit check makes the error message deterministic across
                # both dialects.
                existing = session.execute(
                    select(PlatformIdentity).where(
                        PlatformIdentity.user_id == user.id,
                        PlatformIdentity.platform == platform.value,
                        PlatformIdentity.deleted_at.is_(None),
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    raise IdentityResolutionError(
                        f"User '{user_slug}' is already bound on platform '{platform.value}'. "
                        "Unbind the existing binding first."
                    )
                identity = PlatformIdentity(
                    user_id=user.id,
                    platform=platform.value,
                    platform_id=platform_id,
                )
                session.add(identity)
                session.flush()
                self._notify(session, event="bind", slug=user_slug)
        except IntegrityError as exc:
            # The (platform, platform_id) global UNIQUE is enforced by the
            # DB on both SQLite and Postgres. Wrap so callers get our typed
            # error rather than a SQLAlchemy exception.
            raise IdentityResolutionError(
                f"Platform binding ({platform.value}, {platform_id}) is already in use."
            ) from exc

        self._counter.bump()
        return identity

    def unbind(self, *, user_slug: str, platform: Platform) -> None:
        """Soft-delete the live binding for ``user_slug`` on ``platform``.

        Soft-delete (not row delete) keeps audit-log foreign keys intact —
        history that references the binding survives operator action.
        """
        with self._session_factory.begin() as session:
            user = session.execute(
                select(User).where(User.slug == user_slug, User.deleted_at.is_(None))
            ).scalar_one_or_none()
            if user is None:
                raise IdentityResolutionError(f"No live user with slug '{user_slug}'.")
            binding = session.execute(
                select(PlatformIdentity).where(
                    PlatformIdentity.user_id == user.id,
                    PlatformIdentity.platform == platform.value,
                    PlatformIdentity.deleted_at.is_(None),
                )
            ).scalar_one_or_none()
            if binding is None:
                raise IdentityResolutionError(
                    f"User '{user_slug}' has no live binding on platform '{platform.value}'."
                )
            binding.deleted_at = func.now()
            self._notify(session, event="unbind", slug=user_slug)

        self._counter.bump()

    def remove(self, *, slug: str) -> None:
        """Soft-delete the user with ``slug``.

        Refuses if the user is the only remaining operator
        (:class:`LastOperatorRemovalRefusedError`) — the CLI surfaces a
        friendly message telling the operator to promote someone else first.
        """
        with self._session_factory.begin() as session:
            user = session.execute(
                select(User).where(User.slug == slug, User.deleted_at.is_(None))
            ).scalar_one_or_none()
            if user is None:
                raise IdentityResolutionError(f"No live user with slug '{slug}'.")
            if user.authorization == Authorization.OPERATOR.value:
                remaining = session.execute(
                    select(func.count()).where(
                        User.authorization == Authorization.OPERATOR.value,
                        User.deleted_at.is_(None),
                        User.id != user.id,
                    )
                ).scalar_one()
                if remaining == 0:
                    raise LastOperatorRemovalRefusedError(slug)
            user.deleted_at = func.now()
            self._notify(session, event="remove", slug=slug)

        self._counter.bump()

    def set_(
        self,
        *,
        slug: str,
        display_name: str | None = None,
        authorization: Authorization | None = None,
        language: str | None = None,
        daily_budget_usd: float | None = None,
        rate_limit_per_min: int | None | Literal["unset"] = None,
        rate_limit_per_day: int | None | Literal["unset"] = None,
        replace_operator: str | None = None,
    ) -> User:
        """Mutate a live user in place.

        ``None`` means "do not change". For nullable columns where the CLI
        needs a way to *clear* the value (rate limits), pass the sentinel
        string ``"unset"`` — it maps to ``NULL`` in the DB.

        ``replace_operator`` mirrors :meth:`add`: when ``authorization`` is
        being set to ``OPERATOR`` and another operator already exists, pass
        their slug to atomically demote-then-promote in one transaction.
        """
        if language is not None:
            self._validate_language(language)
        if daily_budget_usd is not None:
            self._validate_budget(daily_budget_usd)

        with self._session_factory.begin() as session:
            user = session.execute(
                select(User).where(User.slug == slug, User.deleted_at.is_(None))
            ).scalar_one_or_none()
            if user is None:
                raise IdentityResolutionError(f"No live user with slug '{slug}'.")
            if authorization is not None and authorization == Authorization.OPERATOR:
                self._enforce_operator_upper_bound(
                    session,
                    target_authorization=authorization,
                    replace_operator_slug=replace_operator,
                    promoting_user_id=user.id,
                )
            if display_name is not None:
                user.display_name = display_name
            if authorization is not None:
                user.authorization = authorization.value
            if language is not None:
                user.language = language
            if daily_budget_usd is not None:
                user.daily_budget_usd = daily_budget_usd
            if rate_limit_per_min == "unset":
                user.rate_limit_per_min = None
            elif rate_limit_per_min is not None:
                user.rate_limit_per_min = rate_limit_per_min
            if rate_limit_per_day == "unset":
                user.rate_limit_per_day = None
            elif rate_limit_per_day is not None:
                user.rate_limit_per_day = rate_limit_per_day
            self._notify(session, event="set", slug=slug)

        self._counter.bump()
        return user

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _fetch_user_for_binding(self, platform: Platform, platform_id: str) -> User | None:
        """Single-query join for the cache-miss path."""
        with self._session_factory() as session:
            return session.execute(
                select(User)
                .join(PlatformIdentity, PlatformIdentity.user_id == User.id)
                .where(
                    PlatformIdentity.platform == platform.value,
                    PlatformIdentity.platform_id == platform_id,
                    PlatformIdentity.deleted_at.is_(None),
                    User.deleted_at.is_(None),
                )
            ).scalar_one_or_none()

    def _cache_put(self, key: tuple[str, str], user: User) -> None:
        """Insert into the LRU and evict the oldest entry if we're full."""
        self._cache[key] = _CacheEntry(
            user=user,
            version_seen=self._counter.current(),
            cached_at=time.monotonic(),
        )
        self._cache.move_to_end(key)
        while len(self._cache) > self._cache_max_entries:
            self._cache.popitem(last=False)

    def _enforce_operator_upper_bound(
        self,
        session: Session,
        *,
        target_authorization: Authorization,
        replace_operator_slug: str | None,
        promoting_user_id: int | None = None,
    ) -> None:
        """Refuse a second concurrent operator unless ``replace_operator_slug`` is set.

        If the caller passed ``replace_operator_slug``, demote that operator
        to ``trusted`` in the same session. The caller's commit ships both
        changes atomically.

        ``promoting_user_id`` is set by :meth:`set_` when an existing user
        is being promoted — they're already counted in ``operators`` so we
        ignore the row.
        """
        if target_authorization != Authorization.OPERATOR:
            return
        existing = (
            session.execute(
                select(User).where(
                    User.authorization == Authorization.OPERATOR.value,
                    User.deleted_at.is_(None),
                )
            )
            .scalars()
            .all()
        )
        # Exclude the user being promoted in-place via set_().
        if promoting_user_id is not None:
            existing = [u for u in existing if u.id != promoting_user_id]
        if not existing:
            return
        if replace_operator_slug is None:
            target = existing[0]
            raise OperatorAlreadyExistsError(
                existing_slug=target.slug,
                existing_display_name=target.display_name,
            )
        # Atomic demote-then-promote — find the named operator and downgrade
        # them inside the caller's transaction so the upcoming insert/update
        # doesn't trip the upper bound.
        to_demote = next((u for u in existing if u.slug == replace_operator_slug), None)
        if to_demote is None:
            raise IdentityResolutionError(
                f"--replace-operator '{replace_operator_slug}' is not the current operator."
            )
        to_demote.authorization = Authorization.TRUSTED.value

    def _next_available_slug(self, session: Session, seed: str) -> str:
        """Find the first ``seed`` / ``seed-2`` / ``seed-3`` not taken.

        Consults *every* row (including soft-deleted) because ``users.slug``
        is column-level UNIQUE — soft-deleted rows continue to hold their
        slug.
        """
        existing = set(
            session.execute(select(User.slug).where(User.slug.like(f"{seed}%"))).scalars().all()
        )
        if seed not in existing:
            return seed
        suffix = 2
        while f"{seed}-{suffix}" in existing:
            suffix += 1
        return f"{seed}-{suffix}"

    def _notify(self, session: Session, *, event: str, slug: str) -> None:
        """Dialect-aware ``NOTIFY`` emit.

        Postgres: ``pg_notify(channel, payload)`` inside the caller's
        transaction so the NOTIFY ships on COMMIT (matches the documented
        Postgres LISTEN/NOTIFY semantics — see ADR-0010).

        SQLite: no-op. The unit-test layer uses SQLite; the integration
        test (T13) exercises the Postgres path against a real instance.
        """
        bind = session.get_bind()
        dialect_name = bind.dialect.name
        if dialect_name == "postgresql":
            payload = f"{event}:{slug}"
            session.execute(func.pg_notify(_NOTIFY_CHANNEL, payload))
        else:
            # On non-Postgres backends the cross-process invalidation path
            # collapses to "the in-process counter bump is enough". Log at
            # DEBUG so test runs that wanted NOTIFY (e.g. someone wired
            # SQLite by accident in T13) leave a breadcrumb.
            _LOG.debug(
                "identity NOTIFY skipped on dialect=%s event=%s slug=%s",
                dialect_name,
                event,
                slug,
            )

    @staticmethod
    def _validate_language(language: str) -> None:
        """Reject malformed BCP-47 tags at the resolver boundary.

        Babel accepts gettext-style ``en_US``; BCP-47 uses ``en-US``. We
        accept either on the wire and normalise to Babel's format for
        parsing. Failure raises :class:`ValueError` with a message the CLI
        surfaces verbatim.
        """
        try:
            Locale.parse(language.replace("-", "_"))
        except (UnknownLocaleError, ValueError) as exc:
            raise ValueError(f"Invalid BCP-47 language tag '{language}': {exc}") from exc

    @staticmethod
    def _validate_budget(daily_budget_usd: float) -> None:
        """Reject non-positive / NaN budgets.

        Mirrors the DB CHECK (``daily_budget_usd > 0``) so the CLI fails
        before the round-trip. NaN is rejected explicitly because
        ``NaN > 0`` returns ``False`` and would otherwise pass through —
        but the DB CHECK would also accept it on SQLite, so this is the
        only defence at the unit-test layer.
        """
        if daily_budget_usd != daily_budget_usd:  # NaN check — NaN != NaN.
            raise ValueError("daily_budget_usd cannot be NaN.")
        if daily_budget_usd <= 0:
            raise ValueError(f"daily_budget_usd must be > 0 (got {daily_budget_usd}).")


# --------------------------------------------------------------------------- #
# Cross-process invalidation — IdentityListener
# --------------------------------------------------------------------------- #

# Type aliases for the listener's injection seams. The notify callback is
# fire-and-forget (the listener bumps its counter + logs); ``listen_loop`` owns
# the inner-loop coroutine that consumes connection events and dispatches them.
_ConnectFactory = Callable[[], object]
_NotifyCallback = Callable[[Mapping[str, object]], None]
_ListenLoop = Callable[[object, _NotifyCallback, asyncio.Event], Awaitable[None]]


class IdentityListener:
    """Background asyncio task that subscribes to ``alfred_identity_changed``.

    On every received NOTIFY the listener bumps the supplied
    :class:`IdentityVersionCounter`, which in turn invalidates the
    per-process :class:`IdentityResolver` LRU and (in PR B) the
    ``BudgetGuard`` cache.

    The listen loop is wrapped in an **exponential-backoff reconnect
    supervisor**: a raised :class:`ConnectionError` triggers a sleep of
    ``backoff_s`` (starting at ``backoff_start_s``, doubling per failure,
    capped at ``backoff_max_s``) before reconnecting. The backoff resets
    to ``backoff_start_s`` after any iteration that returned cleanly
    without raising — that handles graceful close-and-resubscribe paths
    distinctly from the disconnect-storm path.

    CLAUDE.md hard rule #7 — no silent failures in security paths —
    is what makes this supervisor load-bearing rather than nice-to-have.
    A silently-dropped listener would age out cross-process invalidations
    and let stale operator/authorization rows linger in caches across
    every other AlfredOS process.

    The ``connect_factory`` and ``listen_loop`` parameters exist as test
    injection seams; production callers leave them ``None`` and pick up
    :meth:`_default_connect` + :meth:`_default_listen_loop`, which wrap
    ``psycopg.AsyncConnection``. The integration test in T13 exercises
    the real psycopg path; this class's unit test exercises only the
    supervisor's reconnect arithmetic with test doubles.
    """

    def __init__(
        self,
        *,
        dsn: str,
        version_counter: IdentityVersionCounter,
        backoff_start_s: float = 1.0,
        backoff_max_s: float = 60.0,
        connect_factory: _ConnectFactory | None = None,
        listen_loop: _ListenLoop | None = None,
    ) -> None:
        self._dsn = dsn
        self._version_counter = version_counter
        self._backoff_start = backoff_start_s
        self._backoff_max = backoff_max_s
        self._connect_factory: _ConnectFactory = connect_factory or self._default_connect
        self._listen_loop: _ListenLoop = listen_loop or self._default_listen_loop
        # The stop event is created in ``run`` so the listener can be
        # constructed outside a running loop and started later.
        self._stop_event: asyncio.Event | None = None
        self._reconnect_count = 0

    @property
    def reconnect_count(self) -> int:
        """Total number of forced reconnects since construction (observability)."""
        return self._reconnect_count

    async def run(self) -> None:
        """Supervisor loop. Returns on clean stop or on graceful inner-loop exit."""
        self._stop_event = asyncio.Event()
        backoff = self._backoff_start
        while not self._stop_event.is_set():
            try:
                conn = self._connect_factory()
                await self._listen_loop(conn, self._on_notify, self._stop_event)
            except ConnectionError as exc:
                self._reconnect_count += 1
                _LOG.warning(
                    "identity_listener_disconnected",
                    extra={
                        "reconnect_count": self._reconnect_count,
                        "backoff_s": backoff,
                        "error": str(exc),
                    },
                )
                # Sleep ``backoff`` seconds, but wake immediately if stop()
                # is called during the sleep — never block shutdown waiting
                # for a long backoff to expire.
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=backoff)
                    return
                except TimeoutError:
                    pass
                backoff = min(backoff * 2, self._backoff_max)
            else:
                # Inner loop returned cleanly without raising. Either stop()
                # was set (loop exits next iteration) or the connection
                # closed gracefully and we should resubscribe with a fresh
                # backoff. Reset so a later disconnect storm starts at 1s,
                # not wherever the previous storm left us.
                backoff = self._backoff_start

    def stop(self) -> None:
        """Signal the supervisor to exit at the next event boundary."""
        if self._stop_event is not None:
            self._stop_event.set()

    def _on_notify(self, payload: Mapping[str, object]) -> None:
        """Bump the version counter for every NOTIFY receipt.

        The payload shape is informational only — the bump is what
        invalidates downstream caches. We log at DEBUG so operators can
        correlate cache misses with received NOTIFYs without paying log
        volume in steady state.
        """
        self._version_counter.bump()
        _LOG.debug("identity_notify_received", extra={"payload": dict(payload)})

    async def _default_connect(self) -> object:
        """Default connection factory — async psycopg3 connection.

        Returned as a coroutine so ``_default_listen_loop`` can ``async with``
        it directly. The real connection details (DSN-from-Settings,
        connection pool) belong in the wire-up code that constructs the
        listener (T15); this is the minimum viable factory.
        """
        import psycopg  # local import — psycopg is heavy and only needed at production wire-up

        return await psycopg.AsyncConnection.connect(self._dsn, autocommit=True)

    async def _default_listen_loop(
        self,
        conn: object,
        notify_callback: _NotifyCallback,
        stop_event: asyncio.Event,
    ) -> None:
        """Default psycopg3 LISTEN loop.

        Implementation detail: psycopg3's ``AsyncConnection.notifies()`` is
        an async iterator. Wrapped in an ``async with`` so the connection
        closes on exit (clean or exceptional). Payload parsing tolerates an
        empty payload (``NOTIFY channel`` without a body) and a JSON body.

        The integration test (T13) exercises this path against a real
        Postgres; the unit test for ``IdentityListener`` swaps in a test
        double via the ``listen_loop`` constructor parameter and never runs
        this method.
        """
        # ``conn`` is opaque to the supervisor; the concrete type is the
        # psycopg3 ``AsyncConnection`` returned by ``_default_connect``.
        async with conn as c:  # type: ignore[attr-defined]  # reason: psycopg3 AsyncConnection supports async-with; opaque here for test-double symmetry
            await c.execute(f"LISTEN {_NOTIFY_CHANNEL}")
            async for notify in c.notifies():
                if stop_event.is_set():
                    return
                payload: Mapping[str, object] = json.loads(notify.payload) if notify.payload else {}
                notify_callback(payload)

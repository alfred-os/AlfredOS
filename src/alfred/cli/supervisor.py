"""alfred supervisor CLI — status + circuit-breaker reset.

T1-tier commands per spec §3.6 and §10.8:

* ``alfred supervisor status`` — read-only; lists all supervised components
  and their circuit-breaker states.
* ``alfred supervisor reset <component> --confirm`` — calls
  :meth:`Supervisor.reset_breaker`; requires ``--confirm`` gate.

All operator-facing output routes through :func:`alfred.i18n.t` per CLAUDE.md
i18n rule #1. The audit row for ``reset`` carries ``operator_user_id`` per
``SUPERVISOR_BREAKER_RESET_FIELDS`` (see
:mod:`alfred.audit.audit_row_schemas` shipped in PR-S3-0a).
"""

from __future__ import annotations

import asyncio
import datetime as dt
import os
import uuid
from typing import Annotated, TypedDict

import structlog
import typer
from sqlalchemy import create_engine, select
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.orm import sessionmaker

from alfred.i18n import t

supervisor_app = typer.Typer(help=t("cli.supervisor.help"), no_args_is_help=True)
_log = structlog.get_logger(__name__)


def _resolve_operator_user_id() -> str | None:
    """Best-effort Slice-3 operator attribution for audit rows.

    CR-149 round-4 / round-10 (review comment 3338654106 / 3339361789)
    flagged the unconditional ``operator_user_id=None`` on the breaker-reset
    path as a PRD §10.8 forensic gap. The Heavy-lift framing assumed a real
    authenticated CLI session — but a meaningful Slice-3 increment exists
    today: the OS account that invoked the CLI.

    Resolution order (first match wins):

    1. ``ALFRED_OPERATOR_USER_ID`` env var — the explicit override an
       operator (or an orchestration script) can set. Takes precedence so
       a shared CI account can identify which human triggered the action.
    2. ``getlogin()`` — the controlling-terminal user. Survives ``sudo`` /
       ``su`` to identify the *originating* operator rather than the
       elevated account; matches the audit semantic "who is the human".
    3. ``getpwuid(getuid())`` — the effective UID's account name. Used
       when the process has no controlling terminal (cron, systemd,
       container entrypoint). Identifies the runtime account if no
       human session is available.
    4. ``None`` — every probe failed; the row still emits with NULL so
       CLAUDE.md hard rule #7 (no silent skip) holds.

    Limitations (documented; tracked in #153 for the authenticated form):

    * The resolved id is **not authenticated**. Any process running under
      that OS account can claim it. Operators sharing an OS account
      cannot be disambiguated.
    * Replacing this with an authenticated-session value (mTLS / OIDC /
      signed token) is Slice-4 work and lives in #153. This function's
      return value becomes that session's resolved id once the wiring
      lands; the call sites do not change.
    """
    explicit = os.environ.get("ALFRED_OPERATOR_USER_ID")
    if explicit:
        return explicit
    try:
        # ``getlogin`` reads the controlling terminal — returns the
        # original operator across ``sudo`` / ``su``. Raises OSError
        # in environments without a TTY (cron, systemd, container
        # bootstrap without ``-t``).
        return os.getlogin()
    except OSError:
        pass
    try:
        # Fallback: effective UID's pwd entry. ``pwd`` is POSIX-only;
        # the import lives inside the try so the module imports cleanly
        # on Windows even though the CLI surface targets POSIX hosts.
        import pwd

        return pwd.getpwuid(os.getuid()).pw_name
    except (ImportError, KeyError, OSError):
        # CLAUDE.md hard rule #7: every probe failed, but the row still
        # emits with NULL so the audit log records the attempt — the
        # presence of the row IS the forensic signal.
        return None


def _emit_breaker_reset_attempt_audit(*, component_id: str) -> None:
    """Emit a fail-loud audit-row stand-in BEFORE calling ``reset_breaker``.

    sec-pr-s3-6-04: a crash inside :meth:`Supervisor.reset_breaker` (e.g.
    Postgres connection lost mid-transaction) previously left no
    forensic trail at all -- the only audit row the path emitted lived
    inside the supervisor itself, post-write. By logging the attempt
    BEFORE we cross into the supervisor we guarantee an audit-graph
    breadcrumb pointing at the operator intent regardless of whether
    the reset actually lands.

    Fields mirror :data:`SUPERVISOR_BREAKER_RESET_FIELDS` so the eventual
    PR-S3-7 wiring (an ``AuditWriter`` instance reachable from the sync
    CLI bootstrap) can simply replace the structlog call with
    ``await audit_writer.append_schema(...)`` without restructuring the
    emit site.

    CR-149 round-10: ``operator_user_id`` is now sourced via
    :func:`_resolve_operator_user_id` (OS-account attribution — env var,
    then ``getlogin``, then ``getpwuid``). The id is unauthenticated, so
    operators sharing an OS account cannot be disambiguated; the
    authenticated-session refinement is tracked in #153. The OS-account
    form is still materially better than ``None`` for incident response —
    a security team grepping the audit log now has a starting point.

    The structlog redactor in :mod:`alfred.cli._bootstrap` runs in front
    of every output processor so any accidental secret-shaped string in
    ``component_id`` is masked before render.

    perf-001: :mod:`alfred.audit.audit_row_schemas` is imported lazily
    inside the function body because the parent package's ``__init__``
    eagerly loads :class:`alfred.memory.models.AuditEntry`, pulling the
    SQLAlchemy ORM (~140 ms) into every ``alfred --help`` invocation
    that imports this sub-app. Deferring the constant lookup to the
    actual emit path keeps the typer surface light.
    """
    from alfred.audit.audit_row_schemas import SUPERVISOR_BREAKER_RESET_FIELDS

    # ``correlation_id`` ties the attempt row to the eventual
    # supervisor-side reset row (when PR-S3-7 wires the live emit) so
    # the audit-graph forensic traversal can join the two halves.
    correlation_id = str(uuid.uuid4())
    # CR-149 sec-pr-s3-6-cr-149: the attempt row is emitted BEFORE
    # ``reset_breaker`` runs, so we do not yet know the breaker's
    # actual state. The previous shape unconditionally wrote
    # ``old_state="OPEN"`` and ``new_state="CLOSED"`` into the
    # forensic trail, which is a false transition the moment the
    # component does not exist or the reset later fails. Spec §10.8
    # requires auditable operator actions, not invented state.
    # ``None`` (rendered as JSON ``null`` by the structlog renderer)
    # is the explicit "not yet known" sentinel; PR-S3-7 will read the
    # live breaker via ``Supervisor.get_breaker_state`` and emit a
    # second, terminal row carrying the real transition after the
    # reset succeeds. Until then the attempt row stays honest: we
    # observed an operator-initiated reset attempt against
    # ``component_id``; the transition is unknown.
    _log.info(
        "supervisor.breaker.reset.attempted",
        schema_name="SUPERVISOR_BREAKER_RESET_FIELDS",
        component_id=component_id,
        old_state=None,
        new_state=None,
        trip_count=None,
        operator_user_id=_resolve_operator_user_id(),
        correlation_id=correlation_id,
        # ``schema_fields`` round-trips the declared field set so a
        # log-grepping audit collector can validate the row at parse
        # time and surface schema drift if ``SUPERVISOR_BREAKER_RESET_FIELDS``
        # gains a key without this emitter being updated.
        schema_fields=sorted(SUPERVISOR_BREAKER_RESET_FIELDS),
    )


def _get_supervisor() -> object:
    """Return the live :class:`Supervisor` instance.

    Imported lazily so the CLI bootstrap does not construct a supervisor
    for read-only commands like ``alfred status``. Tests patch this
    function with an :class:`unittest.mock.AsyncMock`.

    Depends on PR-S3-3b: ``alfred.supervisor.core.Supervisor.get_instance``.
    Until that singleton accessor ships, this raises :class:`RuntimeError`
    so :func:`supervisor_status` can surface the friendly "supervisor not
    running" hint instead of a raw traceback.
    """
    # Deferred import — Supervisor depends on Postgres + async bootstrap.
    # The CLI is synchronous (Typer); we run the async call via asyncio.run.
    from alfred.supervisor.core import Supervisor

    get_instance = getattr(Supervisor, "get_instance", None)
    if get_instance is None:
        # PR-S3-3b ships the singleton accessor; until then surface the
        # not-running path rather than constructing a half-wired supervisor.
        msg = "Supervisor.get_instance not yet available; wired in PR-S3-3b."
        raise RuntimeError(msg)
    return get_instance()


class BreakerStateRow(TypedDict):
    """Renderer-facing row shape for ``alfred supervisor status``.

    ADR-0020 + spec §3.1: the field set matches what
    :func:`supervisor_status` already consumes from each row, so the
    Postgres swap is a pure data-source change. ``component`` is the
    legacy renderer key; the Postgres column is ``component_id``. The
    helper translates one to the other on the read path so the rendering
    code does not have to know whether the source is a placeholder, a
    mock, or live Postgres rows.
    """

    component: str
    state: str  # CLOSED | OPEN | HALF_OPEN (renderer maps to localised label)
    trip_count: int
    last_trip_at: dt.datetime | None


def _resolve_database_url() -> str:
    """Return the sync-driver Postgres URL the supervisor CLI reads from.

    CR-156 (#154 round-7 BLOCKER #1): the previous shape read
    ``DATABASE_URL`` directly and handed the verbatim string to
    SQLAlchemy. The default operator deployment exports the
    async-driver form (``postgresql+asyncpg://...`` — Slice-1's
    ``Settings.database_url`` shape), and ``alfred supervisor status``
    crashed with ``ModuleNotFoundError: No module named 'asyncpg'``
    inside SQLAlchemy because the CLI bundle ships ``psycopg`` only.
    Routing through :func:`alfred.cli._bootstrap.sync_db_url` reuses
    the exact driver-rewrite contract every other sync CLI surface
    already honours (identity resolver, audit writer): rewrite
    ``+asyncpg`` → ``+psycopg`` in place, insert ``+psycopg`` when no
    driver token is present, pass any other explicit driver through.

    Settings has a default ``database_url``, so this function does NOT
    raise on a missing env var — the operator hits the default
    (``postgresql+asyncpg://alfred:alfred@localhost:5432/alfred``)
    which then gets rewritten to ``postgresql+psycopg://...`` here.
    Postgres-unreachable surfaces at the engine-construction or query
    layer as :class:`OperationalError`, which the handler arm in
    :func:`supervisor_status` maps to ``postgres_unavailable``.

    Settings load failure (``placeholder_api_key`` and similar
    fail-loud config errors) is handled by
    :func:`load_settings_or_die`, which calls ``typer.Exit(2)``
    directly — the typed exception flow is consistent with every
    other CLI bootstrap path.
    """
    from alfred.cli._bootstrap import load_settings_or_die, sync_db_url

    return sync_db_url(load_settings_or_die())


def _list_breaker_states() -> list[BreakerStateRow]:
    """Read every row from the ``circuit_breakers`` Postgres table.

    ADR-0020 + spec §3.2: the CLI is synchronous (Typer), so we use a
    sync SQLAlchemy session bound to a sync engine constructed from
    ``DATABASE_URL``. No supervisor handle — the CLI never reaches the
    daemon process; the freshness contract is "rows reflect the
    supervisor's last ``CircuitBreaker.save_to_db`` write" per the
    runbook.

    Failure modes:

    * ``DATABASE_URL`` unset → resolver returns the Settings default URL
      (``+asyncpg`` rewritten to ``+psycopg``) per CR-156 round-7
      BLOCKER #1; no exception is raised here. If the default points
      at an unreachable Postgres, that surfaces below as
      :class:`OperationalError`.
    * Postgres unreachable / connection refused → :class:`OperationalError`
      (SQLAlchemy). Handler arm in :func:`supervisor_status` maps to
      ``postgres_unavailable`` + exit 1.
    * Settings fail-loud (placeholder API key, schema mismatch)
      → ``typer.Exit(2)`` raised by :func:`load_settings_or_die`
      inside the resolver; propagates as a fail-loud bootstrap error.
    * Row decode fails (schema drift) → propagates as a programmer bug.

    The engine is disposed in a ``finally`` so the connection pool is
    released even when ``__enter__`` on the session raises (the typical
    ``OperationalError`` shape). The expire-on-commit flag is False
    because the helper returns plain dicts immediately after read; ORM
    instances are not retained across the session boundary.
    """
    # Lazy import: ``CircuitBreakerState`` pulls SQLAlchemy ORM + the rest
    # of ``alfred.memory.models`` (~140 ms cold start) per perf-001. Defer
    # the cost so ``alfred --help`` stays light.
    from alfred.memory.models import CircuitBreakerState

    engine = create_engine(_resolve_database_url(), pool_pre_ping=True)
    try:
        # ``sessionmaker`` is conventionally bound to a PascalCase name in
        # SQLAlchemy docs, but ruff's ``N806`` (uppercase-local) is correct
        # for our house style: this is a local sessionmaker factory, not a
        # class. The lowercase name reflects that.
        session_factory = sessionmaker(bind=engine, expire_on_commit=False)
        with session_factory() as session:
            orm_rows = session.execute(select(CircuitBreakerState)).scalars().all()
            return [
                BreakerStateRow(
                    component=row.component_id,
                    state=row.state,
                    trip_count=row.trip_count,
                    last_trip_at=row.last_trip_at,
                )
                for row in orm_rows
            ]
    finally:
        # Release the connection pool even on the OperationalError path
        # — leaving the engine pinned across CLI invocations would leak
        # sockets in unit tests that exercise the failure arm repeatedly.
        engine.dispose()


@supervisor_app.command("status")
def supervisor_status() -> None:
    """List all supervised components and their circuit-breaker states.

    Spec §11.3 + ADR-0020: ``alfred supervisor status`` is a read-only
    sync SQLAlchemy read against the ``circuit_breakers`` Postgres
    table. Freshness contract: rows reflect the supervisor's last
    ``CircuitBreaker.save_to_db`` write — see the Slice-3 runbook for
    the lag model.

    Discovery path: ``quarantine_unavailable`` error →
    ``alfred supervisor status`` →
    ``alfred supervisor reset <component> --confirm``.

    Failure-mode dispatch (in order of frequency):

    * :class:`OperationalError` (Postgres unreachable) → localised
      ``postgres_unavailable`` hint + exit 1.
    * :class:`RuntimeError` (``DATABASE_URL`` unset, raised by
      :func:`_resolve_database_url`) → same hint, same exit code. The
      two distinct failures share one operator action: check the
      stack.
    * Empty result set → localised ``no_components_yet`` hint + exit 0.
      Materially distinct from ``postgres_unavailable``: the supervisor
      is alive and the read path works, there is just nothing to show
      yet.

    Anything else (``KeyError``, ``AttributeError``, ...) is a programmer
    bug and propagates so the operator sees a full traceback. CLAUDE.md
    hard rule #7 forbids silent failure on T1 surfaces.
    """
    try:
        rows = _list_breaker_states()
    except ProgrammingError as exc:
        # CR-156 round-7 BLOCKER #4: the only realistic operator scenario
        # for ``ProgrammingError`` on this read path is an un-migrated
        # database — ``circuit_breakers`` does not exist yet. The arm
        # routes the typed failure through a localised hint naming the
        # remediation (run the migrations) instead of dumping a raw
        # SQLAlchemy traceback. We map every ``ProgrammingError`` shape
        # to this hint rather than parsing ``exc.orig`` for "UndefinedTable":
        # the diagnostic for any other ProgrammingError shape (rare) is
        # still "the schema doesn't match the model" which the same
        # remediation addresses.
        typer.echo(t("cli.supervisor.status.schema_not_initialised"), err=True)
        raise typer.Exit(code=1) from exc
    except OperationalError as exc:
        # Postgres unreachable (connection refused, DNS, etc.) — surface
        # the same operator-targeted message we use for the
        # ``DATABASE_URL`` unset disposition below. The operator action
        # in both cases is identical: check the stack.
        typer.echo(t("cli.supervisor.status.postgres_unavailable"), err=True)
        raise typer.Exit(code=1) from exc
    except RuntimeError as exc:
        # Defensive net: any RuntimeError below the typed envelope routes
        # through the same operator key as the OperationalError arm. The
        # resolver itself no longer raises (it returns the Settings
        # default when the env var is unset; see CR-156 round-7
        # BLOCKER #1), so this arm is residual coverage rather than the
        # primary missing-env-var path.
        typer.echo(t("cli.supervisor.status.postgres_unavailable"), err=True)
        raise typer.Exit(code=1) from exc
    if not rows:
        typer.echo(t("cli.supervisor.status.no_components_yet"))
        return
    # CR-156 round-7 MEDIUM #9 + CR round-1 i18n follow-up: measure
    # column widths at render time so a long component id does not push
    # the state column out of alignment AND so non-English locales do
    # not overflow the state/trip_count columns. The prior shape pinned
    # state=9 ("HALF_OPEN", English) and trip_count=10 ("TRIP COUNT",
    # English) unconditionally — both broke alignment for any locale
    # whose state label or column header is longer than the English
    # form (e.g. Japanese "ハーフオープン" exceeds 9 chars; the German
    # "AUSGELÖST" exceeds 9). Each numeric width below is now max(
    # localised-header, localised-data, observed-row-data) so every
    # locale gets a correctly-aligned table.
    #
    # rvw-010 CJK-width caveat still applies — Python's len() counts
    # code points, not display cells, so wide-cell CJK glyphs still
    # under-pad in monospaced terminals. The Slice 4 swap to
    # ``rich.table.Table`` handles display-width / code-point-width
    # divergence properly.
    state_label_keys = (
        "cli.supervisor.status.breaker_state.open",
        "cli.supervisor.status.breaker_state.closed",
        "cli.supervisor.status.breaker_state.half_open",
        "cli.supervisor.status.breaker_state.unknown",
    )
    state_header = t("cli.supervisor.status.column.state")
    trip_header = t("cli.supervisor.status.column.trip_count")
    widths = {
        "component": max(
            len(t("cli.supervisor.status.column.component")),
            max((len(str(r.get("component", ""))) for r in rows), default=0),
        ),
        "state": max(len(state_header), *(len(t(k)) for k in state_label_keys)),
        "trip_count": max(
            len(trip_header),
            max((len(str(r.get("trip_count", 0))) for r in rows), default=0),
        ),
        "last_trip_at": max(
            len(t("cli.supervisor.status.column.last_trip_at")),
            max((len(str(r.get("last_trip_at") or "-")) for r in rows), default=0),
        ),
    }
    header = "  ".join(
        [
            t("cli.supervisor.status.column.component").ljust(widths["component"]),
            state_header.ljust(widths["state"]),
            trip_header.ljust(widths["trip_count"]),
            t("cli.supervisor.status.column.last_trip_at").ljust(widths["last_trip_at"]),
        ]
    )
    typer.echo(header)
    for row in rows:
        state_raw = str(row.get("state", ""))
        # Map the breaker-state enum to a localised label so the table is
        # readable in every operator language.
        #
        # CR-149: an unknown enum value now renders an explicit
        # ``unknown`` label rather than silently mapping to ``closed``.
        # The prior shape lied about breaker health on a T1 operator
        # surface: a new or corrupt enum value would surface as the
        # localised CLOSED string, hiding a tripped / unsupported
        # state from the operator. Spec §11.3 is operator-facing
        # status; CLAUDE.md hard rule #7 requires failing loud.
        state_key_map = {
            "OPEN": "cli.supervisor.status.breaker_state.open",
            "CLOSED": "cli.supervisor.status.breaker_state.closed",
            "HALF_OPEN": "cli.supervisor.status.breaker_state.half_open",
        }
        state_label = t(state_key_map.get(state_raw, "cli.supervisor.status.breaker_state.unknown"))
        last_trip = str(row.get("last_trip_at") or "-")
        typer.echo(
            f"{row.get('component', '')!s:<{widths['component']}}  "
            f"{state_label:<{widths['state']}}  "
            f"{row.get('trip_count', 0)!s:<{widths['trip_count']}}  "
            f"{last_trip:<{widths['last_trip_at']}}"
        )
    # CR-156 round-7 MEDIUM #14: freshness footer makes the staleness
    # contract visible inline. Operators reading the table know how
    # current the data is without consulting the runbook.
    typer.echo(t("cli.supervisor.status.freshness_footer"))


@supervisor_app.command("reset")
def supervisor_reset(
    component_id: Annotated[str, typer.Argument(help=t("cli.supervisor.reset.usage"))],
    confirm: Annotated[
        bool,
        typer.Option(
            "--confirm",
            # CR-149 round-10 (3339423484): ``confirm_prompt`` is the
            # runtime refusal body and still carries ``{component}``,
            # ``{trip_count}``, and ``{last_trip_at}`` placeholders.
            # ``--help`` renders the help string verbatim, so wiring
            # the runtime key here surfaced unresolved template fields
            # to operators running ``alfred supervisor reset --help``.
            # The dedicated ``confirm_help`` key carries a static
            # placeholder-free body for the ``--help`` surface; the
            # runtime path below keeps the templated body.
            help=t("cli.supervisor.reset.confirm_help"),
        ),
    ] = False,
) -> None:
    """Reset a circuit breaker from OPEN to CLOSED.

    Spec §10.8: operator-tier T1 command; requires ``--confirm``; emits a
    ``supervisor.breaker.reset`` audit row with ``operator_user_id``
    attribution. The ``--confirm`` gate prevents accidental resets in
    scripts — a supervisor reset clears a tripped circuit breaker,
    potentially re-enabling a quarantined-LLM plugin that failed 3+ times
    in 5 minutes.
    """
    if not confirm:
        # devex-004 + i18n-004: the catalog entry for confirm_prompt requires
        # {component}, {trip_count}, {last_trip_at}. We pass safe placeholders
        # for trip_count / last_trip_at until PR-S3-7 wires
        # Supervisor.get_breaker_state.
        typer.echo(
            t(
                "cli.supervisor.reset.confirm_prompt",
                component=component_id,
                trip_count="-",
                last_trip_at="-",
            ),
            err=True,
        )
        # i18n-004 fix: previously a hardcoded English f-string. Now routed
        # through t() so the rerun hint translates with the operator language.
        typer.echo(
            t("cli.supervisor.reset.rerun_hint", component=component_id),
            err=True,
        )
        raise typer.Exit(code=1)

    # CR-149: probe the supervisor BEFORE emitting the attempt-row.
    # The previous shape called ``_get_supervisor()`` outside any
    # exception handler, so a missing / unreachable supervisor raised
    # a raw traceback instead of the localised "supervisor not
    # running" hint the ``status`` command already uses. Spec §11.3
    # makes ``reset`` an operator surface, not a debug surface — the
    # error path here mirrors :func:`supervisor_status` exactly. The
    # attempt-row is emitted only AFTER the probe succeeds so a
    # supervisor that was never reachable does not generate a misleading
    # forensic breadcrumb (the operator never actually crossed the
    # boundary; rolling a fake row would invent state per CR-149
    # finding #14's pattern).
    try:
        supervisor = _get_supervisor()
    except (RuntimeError, ConnectionError, TimeoutError) as exc:
        typer.echo(t("cli.supervisor.status.no_supervisor_running"), err=True)
        raise typer.Exit(code=1) from exc

    # sec-pr-s3-6-04: emit the forensic-attempt audit row BEFORE crossing
    # into the supervisor. A crash inside ``reset_breaker`` (Postgres
    # connection lost mid-transaction, breaker-state lock contention,
    # ...) previously left no trail at all. The order here is
    # load-bearing: attempt-row first, reset call second; if the audit
    # emission itself fails, the reset is aborted (the structlog stream
    # is the operator's last forensic backstop and silently skipping
    # the row would violate CLAUDE.md hard rule #7).
    _emit_breaker_reset_attempt_audit(component_id=component_id)

    # CR-149 round-10: ``operator_user_id`` now sources from
    # :func:`_resolve_operator_user_id` (OS-account attribution — env
    # var, then getlogin, then getpwuid). Unauthenticated; the
    # authenticated-session refinement is tracked in #153. Operators
    # sharing an OS account cannot be disambiguated, but the OS form is
    # materially better than ``None`` for incident response.
    #
    # err-001 / cross-cutting R4: narrow the except shape to
    # ``SupervisorError`` (every supervisor-domain failure mode the
    # spec models) plus ``ConnectionError`` / ``asyncio.TimeoutError``
    # (the two connection-shape failures that surface inside
    # ``asyncio.run`` when the supervisor IPC drops mid-call). A bare
    # ``except Exception`` would mask programmer bugs
    # (typed-method-signature drift, ``KeyError`` from a refactored
    # payload) -- those MUST propagate so the bug is loud.
    #
    # The lazy import lives at the top of the try-block so the
    # except-clause narrowing has the type bound; an ImportError here
    # surfaces as a non-zero exit through the same localised path.
    try:
        from alfred.supervisor.errors import (
            NoSuchComponentError,
            SupervisorError,
        )
    except ImportError as exc:
        # Defensive: a broken supervisor namespace must not deny the
        # operator the localised error -- fall back to the generic key.
        typer.echo(
            t(
                "cli.supervisor.reset.unexpected_error",
                component=component_id,
                error_type="ImportError",
            ),
            err=True,
        )
        raise typer.Exit(code=1) from exc

    try:
        asyncio.run(
            supervisor.reset_breaker(  # type: ignore[attr-defined]  # PR-S3-3b ships the singleton
                component_id=component_id,
                operator_user_id=_resolve_operator_user_id(),
            )
        )
    except NoSuchComponentError as exc:
        # CR-149 round-7: typed-exception dispatch. The previous shape
        # branched on English substrings in ``str(exc).lower()`` to
        # decide whether to render the operator-targeted
        # ``component_not_found`` hint, which silently broke under
        # non-English operator languages and catalog copy-edits — the
        # exact CLAUDE.md hard rule #7 silent-skip shape on a T1
        # surface. :class:`NoSuchComponentError` is a typed
        # :class:`SupervisorError` subclass raised by
        # :meth:`Supervisor.reset_breaker` when the operator-supplied
        # ``component_id`` is not registered, so the dispatch now
        # routes off the class — locale-immune by construction.
        typer.echo(
            t(
                "cli.supervisor.reset.component_not_found",
                component=component_id,
            ),
            err=True,
        )
        raise typer.Exit(code=1) from exc
    except SupervisorError as exc:
        # Every other supervisor-domain failure surfaces through the
        # generic ``unexpected_error`` key. The ``NoSuchComponentError``
        # arm above runs first because MRO lookup tries the most
        # specific class match before falling through to the parent
        # ``SupervisorError`` branch.
        typer.echo(
            t(
                "cli.supervisor.reset.unexpected_error",
                component=component_id,
                error_type=type(exc).__name__,
            ),
            err=True,
        )
        raise typer.Exit(code=1) from exc
    except (ConnectionError, TimeoutError) as exc:
        # Connection-shape failures route through the generic
        # unexpected_error key -- the operator's next step is to check
        # whether the supervisor process is alive, not to retry with a
        # different component id.
        typer.echo(
            t(
                "cli.supervisor.reset.unexpected_error",
                component=component_id,
                error_type=type(exc).__name__,
            ),
            err=True,
        )
        raise typer.Exit(code=1) from exc

    typer.echo(t("cli.supervisor.reset.success", component=component_id))

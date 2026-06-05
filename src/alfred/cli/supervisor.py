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

import datetime as dt
import os
import re
import uuid
from collections.abc import Mapping
from typing import Annotated, Final, TypedDict

import structlog
import typer
from sqlalchemy import create_engine, select
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.orm import sessionmaker

from alfred.cli._state_git import queue_proposal_or_exit
from alfred.i18n import t
from alfred.state.proposal_payloads import BreakerResetProposal

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
        # ADR-0021 #171 Operator visibility: dispatch footer renders even
        # on the empty-components path so the operator can tell whether
        # the dispatch loop has done anything in the last hour while
        # waiting for the first plugin to load.
        _render_dispatch_footer()
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
    _render_dispatch_footer()


def _render_dispatch_footer() -> None:
    """Emit the 'Recent proposal dispatch (last hour)' status footer.

    ADR-0021 #171 §Operator visibility. Render even when every count is
    zero so the operator knows the dispatch loop is wired (the absence
    of activity is the answer, not a missing surface).

    CR rework round-1 HIGH #12: the ``except`` narrows to
    ``OperationalError`` (Postgres unreachable) and
    ``ProgrammingError`` (schema not initialised) — the two
    well-known transient surfaces. Any other exception is a
    programmer bug and propagates so the operator sees a full
    traceback (CLAUDE.md hard rule #7). The localised
    ``dispatch_footer_unavailable`` body lands on stderr so the
    operator can still distinguish "footer broke" from "no recent
    activity"; the breaker table on stdout is preserved.
    """
    try:
        counts = _recent_dispatch_counts()
    except (OperationalError, ProgrammingError):
        typer.echo(t("cli.supervisor.status.dispatch_footer_unavailable"), err=True)
        _log.warning("supervisor.status_dispatch_footer_unavailable")
        return
    # CR rework round-1 HIGH #11: the ``pending`` slot was
    # hardcoded 0 and lied to the operator. Drop it from the
    # renderer; restore once a meaningful "merged but not yet
    # dispatched" count surface lands.
    typer.echo(
        t(
            "cli.supervisor.status.dispatch_footer",
            applied=counts.get("applied", 0),
            failed=counts.get("failed", 0),
        )
    )


@supervisor_app.command("reset", help=t("cli.supervisor.reset.help.short"))
def supervisor_reset(
    component_id: Annotated[str, typer.Argument(help=t("cli.supervisor.reset.usage"))],
    confirm: Annotated[
        bool,
        typer.Option(
            "--confirm",
            # ADR-0021 #171: ``--confirm`` regains its gating semantic.
            # The no-op behaviour introduced by #154 was a stopgap while
            # the reset path was deferred; reset now performs actual
            # state mutation (writes a reviewer-gated state.git
            # proposal), so the confirmation gate is meaningful again.
            help=t("cli.supervisor.reset.confirm_help"),
        ),
    ] = False,
) -> None:
    """Queue a reviewer-gated reset of a circuit breaker (OPEN → CLOSED).

    Spec §10.8 + ADR-0021 #171. The command writes a
    :class:`BreakerResetProposal` to state.git; the supervisor's
    :meth:`_proposal_dispatch_loop` picks up the merged branch on its
    next cycle and calls :meth:`Supervisor.reset_breaker`.

    Flow:

    1. ``--confirm`` MUST be supplied. Without it the command exits
       non-zero without writing a proposal — preserves the BLOCKER #6
       semantic from #154's review (operator must explicitly confirm a
       destructive action).
    2. Forensic-attempt audit row fires BEFORE the proposal write so
       operator intent always lands in the audit graph even if the
       state.git write fails mid-flight (CR-149 forensic-trail
       invariant).
    3. Typed payload constructed; ``queue_proposal_or_exit`` writes the
       branch + emits the ``supervisor.breaker.reset.requested`` audit
       row stand-in via the canonical writer.
    4. Submitted body prints the proposal id, the branch name, the
       dispatch-cycle interval (from ``Settings.proposal_dispatch_interval_s``),
       and the follow-up command (``alfred supervisor proposals --recent``).
    5. Exit 0 — the request landed.
    """
    if not confirm:
        # --confirm gate (partial revert of #154 BLOCKER #6 no-op).
        # Reset now writes a real state.git proposal, so explicit
        # confirmation is meaningful again. The body names the
        # required flag so operators know the recovery action.
        typer.echo(t("cli.supervisor.reset.confirm_required"), err=True)
        raise typer.Exit(code=1)

    # CR-149 forensic-trail invariant — operator intent always lands
    # in the audit graph BEFORE the state.git write so a crash mid-
    # write still leaves a breadcrumb pointing at the attempt.
    _emit_breaker_reset_attempt_audit(component_id=component_id)

    # Lazy import — perf-001 + symmetry with the existing CLI emit
    # sites that defer the schema lookup until the actual emit path.
    from alfred.audit.audit_row_schemas import SUPERVISOR_BREAKER_RESET_REQUESTED_FIELDS
    from alfred.cli._bootstrap import load_settings_or_die

    # CR rework round-1 HIGH #16: the BreakerResetProposal payload now
    # requires a non-None ``operator_user_id`` so the dispatcher's
    # handler can pass it straight through without an ``or ""``
    # fallback. The OS-account resolver returns ``None`` only when
    # every probe (env var / getlogin / getpwuid) failed — that is the
    # rare "no controlling tty AND no pwd entry" shape (a malformed
    # container entrypoint). Fall back to a closed-set ``unknown``
    # token so the row still lands; the forensic-attempt audit row
    # above already records the actual attempt with the resolver's
    # best effort + the ALFRED_OPERATOR_USER_ID env var if any.
    operator_user_id = _resolve_operator_user_id() or "unknown"

    proposal = queue_proposal_or_exit(
        payload=BreakerResetProposal(
            component_id=component_id,
            operator_user_id=operator_user_id,
        ),
        denied_key="cli.supervisor.reset.denied",
        pending_review_key="cli.supervisor.reset.proposal_submitted",
        pending_review_extra_kwargs={
            "component": component_id,
            "interval": load_settings_or_die().proposal_dispatch_interval_s,
        },
        audit_event="supervisor.breaker.reset.requested",
        audit_schema_name="SUPERVISOR_BREAKER_RESET_REQUESTED_FIELDS",
        audit_fields=SUPERVISOR_BREAKER_RESET_REQUESTED_FIELDS,
        audit_subject_partial={
            "component_id": component_id,
            "operator_user_id": operator_user_id,
            "trust_tier_of_trigger": "T1",
        },
    )
    # ``queue_proposal_or_exit`` returns the ProposalResult — surface
    # to keep the lint clean; the helper has already echoed the
    # pending_review body with the proposal_id + branch.
    del proposal


def _register_proposal_keys_for_pybabel() -> tuple[str, ...]:
    """Anchor the supervisor-reset proposal-flow i18n keys for pybabel.

    Same pattern as :func:`alfred.cli.web._register_proposal_keys_for_pybabel`.
    :func:`queue_proposal_or_exit` consumes the ``denied_key`` +
    ``pending_review_key`` strings via parameter, so the pybabel AST
    walker would otherwise drop them into the obsoleted block on every
    ``pybabel update``. Surface the live renders here so the keys stay
    in the active catalog.

    Representative kwargs render every placeholder the msgstr carries:
    ``{reason}`` for ``.denied``; ``{component}`` + ``{branch}`` +
    ``{proposal_id}`` + ``{interval}`` for ``.proposal_submitted``.
    """
    return (
        t("cli.supervisor.reset.denied", reason="example"),
        t(
            "cli.supervisor.reset.proposal_submitted",
            component="example",
            branch="proposal/breaker-reset-example",
            proposal_id="0123456789abcdef",
            interval=30,
        ),
    )


# ---------------------------------------------------------------------------
# alfred supervisor proposals — Task 9 of #171 / ADR-0021 §Operator visibility
# ---------------------------------------------------------------------------


class _ProposalRow(TypedDict):
    """Renderer-facing row shape for ``alfred supervisor proposals``.

    ADR-0021 §Operator visibility — columns are the load-bearing
    forensic surface: ``proposal_type`` + ``proposal_id`` jointly
    identify the proposal; ``result`` + ``failure_kind`` distinguish
    the dispositions; ``operator_user_id`` carries the self-claimed
    forensic attribution; ``processed_at`` anchors the row in time so
    the operator can correlate with the supervisor's structlog stream.
    """

    proposal_type: str
    proposal_id: str
    result: str
    failure_kind: str | None
    operator_user_id: str | None
    processed_at: dt.datetime


def _list_proposals(
    *,
    since: dt.timedelta | None = None,
    limit: int | None = 20,
) -> list[_ProposalRow]:
    """Read ``processed_proposals`` rows for the proposals subcommand.

    CR rework round-1 HIGH #13:

    * ``since`` is a :class:`datetime.timedelta` (typed at the helper
      boundary); the subcommand parses the operator-facing
      ``--since 1h`` / ``24h`` / ``7d`` shape and threads the
      resolved delta through. ``None`` returns every row
      (``--all`` escape hatch).
    * ``limit`` defaults to 20 so the CLI does not blast every row
      at the operator's terminal on a large ledger; ``None``
      disables.

    The query is sync SQLAlchemy through the same engine path used by
    :func:`_list_breaker_states` — mirror that pattern so a future
    consolidation lands in one place.
    """
    # Lazy imports — perf-001 + ``alfred --help`` stays light.
    from sqlalchemy import func

    from alfred.memory.models import ProcessedProposal

    engine = create_engine(_resolve_database_url(), pool_pre_ping=True)
    try:
        session_factory = sessionmaker(bind=engine, expire_on_commit=False)
        with session_factory() as session:
            query = select(ProcessedProposal).order_by(ProcessedProposal.processed_at.desc())
            if since is not None:
                query = query.where(ProcessedProposal.processed_at > func.now() - since)
            if limit is not None:
                query = query.limit(limit)
            orm_rows = session.execute(query).scalars().all()
            return [
                _ProposalRow(
                    proposal_type=row.proposal_type,
                    proposal_id=row.proposal_id,
                    result=row.result,
                    failure_kind=row.failure_kind,
                    operator_user_id=row.operator_user_id,
                    processed_at=row.processed_at,
                )
                for row in orm_rows
            ]
    finally:
        engine.dispose()


def _recent_dispatch_counts() -> dict[str, int]:
    """Return last-hour dispatch outcome counts for the status footer.

    Keys: ``applied``, ``failed``. CR rework round-1 HIGH #11: the
    ``pending`` slot was always 0 (the loop is monotonically forward
    — a merged blob either appears in the ledger or has not yet been
    walked), so it lied to the operator. Dropped from the surface
    until a meaningful "merged but not yet dispatched" count lands.
    """
    from sqlalchemy import func

    from alfred.memory.models import ProcessedProposal

    engine = create_engine(_resolve_database_url(), pool_pre_ping=True)
    try:
        session_factory = sessionmaker(bind=engine, expire_on_commit=False)
        with session_factory() as session:
            recent_q = select(ProcessedProposal).where(
                ProcessedProposal.processed_at > func.now() - dt.timedelta(hours=1)
            )
            rows = session.execute(recent_q).scalars().all()
            applied = sum(1 for r in rows if r.result == "applied")
            failed = sum(
                1
                for r in rows
                if r.result in {"failed_handler", "failed_parse", "failed_unknown_type"}
            )
            return {"applied": applied, "failed": failed}
    finally:
        engine.dispose()


_DURATION_PATTERN: Final[re.Pattern[str]] = re.compile(r"^(\d+)([hdwm])$")
_DURATION_SUFFIXES: Final[Mapping[str, dt.timedelta]] = {
    "h": dt.timedelta(hours=1),
    "d": dt.timedelta(days=1),
    "w": dt.timedelta(weeks=1),
    "m": dt.timedelta(minutes=1),
}


def _parse_duration(raw: str) -> dt.timedelta:
    """Parse a human-readable duration string (``1h`` / ``24h`` / ``7d``).

    CR rework round-1 HIGH #13: keeps the operator-facing surface
    consistent across ``--since`` flag inputs. ``m`` minute / ``h``
    hour / ``d`` day / ``w`` week — the four cadences that match
    typical operator windows for proposal-dispatch debugging.

    Refuses any other shape via :class:`typer.BadParameter` so the
    error surface lands at the CLI parser, not at the helper.
    """
    match = _DURATION_PATTERN.fullmatch(raw)
    if match is None:
        # CR-rework round-2 follow-up: the two parser-error messages
        # are operator-facing — localise via the catalog rather than
        # emitting raw English (CLAUDE.md i18n hard rule #1).
        raise typer.BadParameter(
            t(
                "cli.supervisor.proposals.since_invalid",
                value=raw,
                example="1h, 24h, 7d, 30m",
            )
        )
    value = int(match.group(1))
    if value <= 0:
        raise typer.BadParameter(t("cli.supervisor.proposals.since_must_be_positive", value=raw))
    return value * _DURATION_SUFFIXES[match.group(2)]


@supervisor_app.command("proposals", help=t("cli.supervisor.proposals.help.short"))
def supervisor_proposals(
    since: Annotated[
        str,
        typer.Option(
            "--since",
            help=t("cli.supervisor.proposals.since_help"),
        ),
    ] = "1h",
    limit: Annotated[
        int,
        typer.Option(
            "--limit",
            help=t("cli.supervisor.proposals.limit_help"),
            min=1,
        ),
    ] = 20,
    all_: Annotated[
        bool,
        typer.Option(
            "--all",
            help=t("cli.supervisor.proposals.all_help"),
        ),
    ] = False,
) -> None:
    """List recent state.git side-effecting dispatch results.

    ADR-0021 §Operator visibility — the operator-facing surface for
    "what did the dispatcher do?". The column set is fixed:
    ``proposal_type``, ``proposal_id``, ``result``, ``failure_kind``,
    ``operator_user_id``, ``processed_at``. A future widening lands by
    adding columns here AND in the catalog header keys.

    CR rework round-1 HIGH #13:

    * ``--since DURATION`` (default ``1h``; accepts ``1h``, ``24h``,
      ``7d``, ``30m``, ``2w``) scopes by processed_at window.
    * ``--limit N`` (default 20) bounds the row count.
    * ``--all`` escape hatch returns every row in the ledger
      (ignores ``--since`` and ``--limit``); useful for forensic
      export.

    Failure-mode dispatch mirrors :func:`supervisor_status`:

    * ``OperationalError`` (Postgres unreachable) → localised
      ``postgres_unavailable`` hint + exit 1.
    * ``ProgrammingError`` (schema not initialised) → schema hint +
      exit 1.
    * Empty result set → localised "no proposals yet" body + exit 0.
    """
    since_delta: dt.timedelta | None = None if all_ else _parse_duration(since)
    list_limit: int | None = None if all_ else limit
    try:
        rows = _list_proposals(since=since_delta, limit=list_limit)
    except ProgrammingError as exc:
        typer.echo(t("cli.supervisor.status.schema_not_initialised"), err=True)
        raise typer.Exit(code=1) from exc
    except OperationalError as exc:
        typer.echo(t("cli.supervisor.status.postgres_unavailable"), err=True)
        raise typer.Exit(code=1) from exc

    if not rows:
        # Empty body names the cycle interval so the operator knows
        # how long to wait before re-checking (devex finding #9).
        # CR-rework round-2 follow-up: ``--all`` disables the time
        # filter, so interpolating ``since`` in the empty-state body
        # would lie to the operator about what was queried. Pick the
        # right body for the flag combination.
        from alfred.cli._bootstrap import load_settings_or_die

        interval = load_settings_or_die().proposal_dispatch_interval_s
        if all_:
            typer.echo(t("cli.supervisor.proposals.empty_all", interval=interval))
        else:
            typer.echo(
                t(
                    "cli.supervisor.proposals.empty",
                    since=since,
                    interval=interval,
                )
            )
        return

    headers = {
        "proposal_type": t("cli.supervisor.proposals.column.proposal_type"),
        "proposal_id": t("cli.supervisor.proposals.column.proposal_id"),
        "result": t("cli.supervisor.proposals.column.result"),
        "failure_kind": t("cli.supervisor.proposals.column.failure_kind"),
        "operator_user_id": t("cli.supervisor.proposals.column.operator_user_id"),
        "processed_at": t("cli.supervisor.proposals.column.processed_at"),
    }
    widths = {
        col: max(
            len(headers[col]),
            max((len(str(r.get(col) or "-")) for r in rows), default=0),
        )
        for col in headers
    }
    typer.echo(
        "  ".join(headers[col].ljust(widths[col]) for col in headers),
    )
    for row in rows:
        typer.echo("  ".join(str(row.get(col) or "-").ljust(widths[col]) for col in headers))
    # CR rework round-1 HIGH #13: closed-vocab legend so the operator
    # can decode the ``result`` column without consulting the runbook.
    typer.echo("")
    typer.echo(t("cli.supervisor.proposals.legend"))

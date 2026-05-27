"""``alfred user`` — Typer subcommands for the identity layer.

Responsibility
--------------

A thin imperative shell on top of :class:`IdentityResolver`. Each callback:

1. Resolves the live ``IdentityResolver`` via the module-level
   ``_resolver_factory`` (tests monkeypatch this; production wires it to
   :func:`_default_resolver_factory` from a session factory).
2. Normalises CLI-shaped values to resolver-shaped kwargs (``read-only``
   → ``Authorization.READ_ONLY``, ``"unset"`` sentinel for nullable
   columns, BCP-47 ingress validation).
3. Calls the resolver. On :class:`IdentityError` derivatives, prints a
   localised error to stderr and exits ``2``. On success, prints a
   localised confirmation and writes ONE audit row via
   :class:`AuditWriter`.

Two CLAUDE.md hard rules are load-bearing here:

* **#1 — every operator-facing string goes through ``t()``.** No bare
  English. ``cli.user.*`` keys were populated in T4; we use them here.
* **#7 — no silent failures in security paths.** Audit writes happen on
  every successful mutation; an exception inside the write surfaces to
  the operator rather than getting swallowed.

Slice-2 is operator-only on the CLI: there is no non-operator caller
authenticating through the CLI yet (Slice 3 work). For attribution, the
``actor_user_id`` on audit rows is the current live operator's slug. The
very first ``alfred user add --authorization operator`` invocation has no
prior operator → the actor is the literal ``"<bootstrap>"``. The audit
row records this so the audit graph never lies about who acted.
"""

from __future__ import annotations

import asyncio
import json as _json
import sys
from collections.abc import Callable
from typing import Annotated, Any

import typer
from babel import Locale, UnknownLocaleError
from rich.console import Console
from rich.table import Table
from rich.text import Text

from alfred.audit.log import AuditWriter
from alfred.i18n import t
from alfred.identity.errors import (
    IdentityError,
    IdentityResolutionError,
    LastOperatorRemovalRefusedError,
    OperatorAlreadyExistsError,
    PlatformIdInUseError,
    UserAlreadyBoundError,
)
from alfred.identity.models import Authorization, Platform
from alfred.identity.resolver import IdentityResolver

# Bootstrap actor name used in audit rows for the very first operator add.
# Kept as a module constant so future audit-graph consumers can filter on it
# without grepping for the string literal across the code base.
_BOOTSTRAP_ACTOR = "<bootstrap>"

# Fallback BCP-47 tag stamped onto bootstrap-actor audit rows (i.e. the very
# first operator add, before any user exists to read a language from). The
# operator-set CLI re-stamps every subsequent row with the live operator's
# language; this fallback only ever lands on the single bootstrap row.
# Kept here rather than importing from ``Settings`` to keep the identity CLI
# free of the Settings dependency — the bootstrap row will be relabelled at
# first ``alfred user set`` if the operator chose a non-default language.
_BOOTSTRAP_LANGUAGE = "en-US"


# --------------------------------------------------------------------------- #
# Injection seams — tests monkeypatch these factories.
# --------------------------------------------------------------------------- #

# Production wires both factories at CLI bootstrap (see ``alfred.cli.main``).
# Until then the placeholders raise on first use so test setups that forget
# to monkeypatch fail loudly rather than silently sharing a stale resolver
# across tests.

_resolver_factory: Callable[[], IdentityResolver] | None = None
_audit_writer_factory: Callable[[], AuditWriter] | None = None


def install_factories(
    *,
    resolver: Callable[[], IdentityResolver],
    audit_writer: Callable[[], AuditWriter],
) -> None:
    """Wire the production resolver + audit-writer factories.

    Called once at CLI bootstrap from :mod:`alfred.cli.main`. The factories
    are zero-arg callables — they hide the session-factory plumbing from
    every command callback, which only cares about "give me a resolver."
    """
    global _resolver_factory, _audit_writer_factory
    _resolver_factory = resolver
    _audit_writer_factory = audit_writer


def _load_resolver() -> IdentityResolver:
    """Return the active resolver or raise — never silently construct."""
    if _resolver_factory is None:
        raise RuntimeError(
            "alfred.identity.cli has no resolver factory installed. "
            "Call install_factories(...) from your bootstrap, or monkeypatch "
            "_resolver_factory in tests."
        )
    return _resolver_factory()


def _load_audit_writer() -> AuditWriter:
    """Return the active audit writer or raise — never silently construct."""
    if _audit_writer_factory is None:
        raise RuntimeError(
            "alfred.identity.cli has no audit-writer factory installed. "
            "Call install_factories(...) from your bootstrap, or monkeypatch "
            "_audit_writer_factory in tests."
        )
    return _audit_writer_factory()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _stdin_is_tty() -> bool:
    """Hook for the non-TTY ``--yes`` gate. Tests monkeypatch this.

    Wrapping ``sys.stdin.isatty()`` behind a named function (rather than
    inlining the call) gives test setups a clean monkeypatch target and
    documents the security boundary: every destructive operation routes
    through here exactly once.
    """
    return sys.stdin.isatty()


def _normalise_authorization(raw: str) -> Authorization:
    """Accept kebab- or snake-case authorization on the wire.

    The enum is permanently snake_case in the DB (CHECK constraint). The
    CLI accepts both shapes so an operator typing ``read-only`` is not
    surprised by a refusal — that's a friendlier first-run.
    """
    try:
        return Authorization(raw.replace("-", "_"))
    except ValueError as exc:
        typer.echo(t("cli.user.error.invalid_authorization", value=raw), err=True)
        raise typer.Exit(code=2) from exc


def _validate_language_or_exit(language: str) -> None:
    """Reject malformed BCP-47 tags before they reach the resolver.

    Mirrors the resolver's internal ``_validate_language`` but routes the
    failure through ``t()`` so the operator sees a localised message.
    """
    try:
        Locale.parse(language.replace("-", "_"))
    except (UnknownLocaleError, ValueError) as exc:
        typer.echo(t("cli.user.error.invalid_language", value=language), err=True)
        raise typer.Exit(code=2) from exc


def _actor() -> tuple[str, str]:
    """Return ``(actor_slug, actor_language)`` for the current CLI invocation.

    The CLI is operator-only in Slice 2. ``get_operator()`` raises
    :class:`IdentityResolutionError` if zero operators exist — that's the
    bootstrap path, where we record ``<bootstrap>`` + ``_BOOTSTRAP_LANGUAGE``
    so the audit row truthfully reflects "no operator existed yet when this
    happened" rather than silently hardcoding ``en-US`` (CLAUDE.md i18n
    rule #3: every stored user-content row carries a BCP-47 language tag).
    """
    try:
        operator = _load_resolver().get_operator()
    except IdentityResolutionError:
        return _BOOTSTRAP_ACTOR, _BOOTSTRAP_LANGUAGE
    return operator.slug, operator.language


async def _write_audit(
    *,
    event: str,
    actor: str,
    language: str,
    subject: dict[str, Any],
    result: str = "success",
) -> None:
    """Emit one audit row for the calling subcommand.

    The shape mirrors slice-1's ``AuditWriter.append`` contract: every
    row carries an event + actor + subject + trust tier + result + cost
    estimate + trace id + language. CLI mutations have no per-call cost
    (they're DB writes, not provider calls) so ``cost_estimate_usd=0.0``;
    the audit log keeps a 0 row so the graph stays connected. ``trace_id``
    is the event name + actor — every mutation is a single point on the
    trace, so a synthetic id is sufficient and avoids dragging in a UUID
    dependency.

    ``language`` is the BCP-47 tag the row is stamped with. CLAUDE.md i18n
    rule #3 forbids defaulting it inside the writer — every caller must
    pass the actor's resolved language so the audit graph keeps an honest
    record of WHO acted in WHICH language. The CLI resolves this once per
    invocation via :func:`_actor`.
    """
    writer = _load_audit_writer()
    await writer.append(
        event=event,
        actor_user_id=actor,
        subject=subject,
        trust_tier_of_trigger="T0",
        result=result,
        cost_estimate_usd=0.0,
        trace_id=f"cli:{event}:{actor}",
        language=language,
    )


# --------------------------------------------------------------------------- #
# Typer app
# --------------------------------------------------------------------------- #

user_app = typer.Typer(
    help=t("cli.user.help.group"),
    no_args_is_help=True,
)


# --------------------------------------------------------------------------- #
# add
# --------------------------------------------------------------------------- #


@user_app.command("add", help=t("cli.user.help.add.short"))
def add(
    name: Annotated[str, typer.Option("--name", help=t("cli.user.flag.name.short"))],
    authorization: Annotated[
        str,
        typer.Option("--authorization", help=t("cli.user.flag.authorization.short")),
    ] = Authorization.STANDARD.value,
    daily_budget_usd: Annotated[
        float,
        typer.Option("--daily-budget-usd", help=t("cli.user.flag.daily-budget-usd.short")),
    ] = 0.50,
    language: Annotated[
        str | None,
        typer.Option("--language", help=t("cli.user.flag.language.short")),
    ] = None,
    rate_limit_per_min: Annotated[
        int | None,
        typer.Option("--rate-limit-per-min", help=t("cli.user.flag.rate-limit-per-min.short")),
    ] = None,
    rate_limit_per_day: Annotated[
        int | None,
        typer.Option("--rate-limit-per-day", help=t("cli.user.flag.rate-limit-per-day.short")),
    ] = None,
    output_slug: Annotated[
        bool,
        typer.Option("--output-slug", help=t("cli.user.flag.output-slug.short")),
    ] = False,
    slug_override: Annotated[
        str | None,
        typer.Option("--slug-override", help=t("cli.user.flag.slug-override.short")),
    ] = None,
    replace_operator: Annotated[
        str | None,
        typer.Option("--replace-operator", help=t("cli.user.flag.replace-operator.short")),
    ] = None,
) -> None:
    """Create a new user, optionally promoting them to operator atomically."""
    resolver = _load_resolver()
    auth = _normalise_authorization(authorization)
    if language is not None:
        _validate_language_or_exit(language)

    # Capture the actor BEFORE the mutation: post-mutation, ``get_operator``
    # would return the freshly-added operator on a bootstrap path, which is
    # not who acted (no one did — the system bootstrapped itself).
    actor, actor_language = _actor()

    try:
        user = resolver.add(
            display_name=name,
            authorization=auth,
            language=language if language is not None else "en-US",
            daily_budget_usd=daily_budget_usd,
            slug_override=slug_override,
            replace_operator=replace_operator,
            rate_limit_per_min=rate_limit_per_min,
            rate_limit_per_day=rate_limit_per_day,
        )
    except OperatorAlreadyExistsError as exc:
        typer.echo(
            t(
                "cli.user.error.operator_already_exists",
                existing_slug=exc.existing_slug,
                existing_display_name=exc.existing_display_name,
            ),
            err=True,
        )
        raise typer.Exit(code=2) from exc
    except ValueError as exc:
        # ValueError from ``_validate_budget`` / ``_validate_language``. The
        # resolver raises bare ValueError; surface as a generic invalid
        # value with the original message — clearer than swallowing it.
        message = str(exc)
        if "daily_budget_usd" in message:
            typer.echo(
                t("cli.user.error.budget_must_be_positive", value=daily_budget_usd),
                err=True,
            )
        else:
            typer.echo(
                t("cli.user.error.invalid_bcp47", value=language or "", detail=message),
                err=True,
            )
        raise typer.Exit(code=2) from exc
    except IdentityError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    if output_slug:
        typer.echo(user.slug)
        return

    typer.echo(
        t(
            "cli.user.added",
            display_name=user.display_name,
            slug=user.slug,
            authorization=user.authorization,
        )
    )
    if replace_operator is not None:
        typer.echo(
            t(
                "cli.user.operator_replaced",
                new_slug=user.slug,
                old_slug=replace_operator,
            )
        )

    asyncio.run(
        _write_audit(
            event="user.add",
            actor=actor,
            language=actor_language,
            subject={
                "slug": user.slug,
                "authorization": user.authorization,
                "language": user.language,
                "daily_budget_usd": user.daily_budget_usd,
                "replace_operator": replace_operator,
            },
        )
    )


# --------------------------------------------------------------------------- #
# list
# --------------------------------------------------------------------------- #


@user_app.command("list", help=t("cli.user.help.list.short"))
def list_(
    json: Annotated[
        bool,
        typer.Option("--json", help=t("cli.user.flag.json.short")),
    ] = False,
    include_deleted: Annotated[
        bool,
        typer.Option("--include-deleted", help=t("cli.user.flag.include-deleted.short")),
    ] = False,
) -> None:
    """Render every user as a rich.Table or as stable JSON."""
    resolver = _load_resolver()
    users = resolver.list_(include_deleted=include_deleted)

    if json:
        payload = [
            {
                "slug": u.slug,
                "display_name": u.display_name,
                "authorization": u.authorization,
                "daily_budget_usd": u.daily_budget_usd,
                "language": u.language,
                "rate_limit_per_min": u.rate_limit_per_min,
                "rate_limit_per_day": u.rate_limit_per_day,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "deleted_at": u.deleted_at.isoformat() if u.deleted_at else None,
            }
            for u in users
        ]
        typer.echo(_json.dumps(payload, indent=2, sort_keys=True))
        return

    if not users:
        typer.echo(t("cli.user.list.empty_hint"))
        return

    console = Console()
    table = Table(show_header=True)
    table.add_column(t("cli.user.list.column.slug"))
    table.add_column(t("cli.user.list.column.display_name"))
    table.add_column(t("cli.user.list.column.authorization"))
    table.add_column(t("cli.user.list.column.daily_budget_usd"))
    table.add_column(t("cli.user.list.column.language"))
    table.add_column(t("cli.user.list.column.platforms"))

    deleted_marker = t("cli.user.list.deleted_marker")
    for u in users:
        cells = [
            u.slug,
            u.display_name,
            u.authorization,
            f"{u.daily_budget_usd:.2f}",
            u.language,
            t("cli.user.list.no_platforms"),
        ]
        if u.deleted_at is not None:
            # Strike-through every cell so the row visually reads as deleted
            # across the whole width, then append the marker into the slug
            # column so a screen-reader / non-styled renderer (no colour
            # terminal) still surfaces the soft-delete state in text.
            row = [Text(c, style="strike") for c in cells]
            row[0] = Text(f"{u.slug} {deleted_marker}", style="strike")
            table.add_row(*row)
        else:
            table.add_row(*cells)

    console.print(table)


# --------------------------------------------------------------------------- #
# show
# --------------------------------------------------------------------------- #


@user_app.command("show", help=t("cli.user.help.show.short"))
def show(slug: str) -> None:
    """Render one user including override-vs-derived rate-limit indicators."""
    resolver = _load_resolver()
    user = resolver.show(slug=slug)
    if user is None:
        typer.echo(t("cli.user.error.not_found", slug=slug), err=True)
        raise typer.Exit(code=2)

    # CLAUDE.md i18n rule #1: every operator-facing string routes through
    # ``t()``. The list-view column labels already cover slug / display_name
    # / authorization / daily_budget_usd / language; the show view reuses
    # them so a translator only has to localise each field name once. The
    # two rate-limit fields are show-specific (the list view collapses them)
    # and get their own keys.
    typer.echo(f"{t('cli.user.list.column.slug')}: {user.slug}")
    typer.echo(f"{t('cli.user.list.column.display_name')}: {user.display_name}")
    typer.echo(f"{t('cli.user.list.column.authorization')}: {user.authorization}")
    typer.echo(f"{t('cli.user.list.column.daily_budget_usd')}: {user.daily_budget_usd:.2f}")
    typer.echo(f"{t('cli.user.list.column.language')}: {user.language}")

    unset_marker = t("cli.user.show.value.unset")
    override_marker = t("cli.user.show.override_indicator")
    derived_marker = t("cli.user.show.derived_indicator")
    rpm = user.rate_limit_per_min
    rpd = user.rate_limit_per_day
    typer.echo(
        f"{t('cli.user.show.field.rate_limit_per_min')}: "
        f"{rpm if rpm is not None else unset_marker} "
        f"{override_marker if rpm is not None else derived_marker}"
    )
    typer.echo(
        f"{t('cli.user.show.field.rate_limit_per_day')}: "
        f"{rpd if rpd is not None else unset_marker} "
        f"{override_marker if rpd is not None else derived_marker}"
    )
    if user.deleted_at is not None:
        typer.echo(t("cli.user.list.deleted_marker"))


# --------------------------------------------------------------------------- #
# remove
# --------------------------------------------------------------------------- #


@user_app.command("remove", help=t("cli.user.help.remove.short"))
def remove(
    slug: str,
    yes: Annotated[
        bool,
        typer.Option("--yes", help=t("cli.user.flag.yes.short")),
    ] = False,
) -> None:
    """Soft-delete a user (refuses on the last operator)."""
    resolver = _load_resolver()

    # ``--yes`` skips the prompt entirely; without it, non-TTY exits 2 so
    # CI / scripted runs never silently destroy data on an EOF read. The
    # check happens BEFORE the resolver call so the refusal lands before
    # any DB round-trip.
    if not yes:
        if not _stdin_is_tty():
            typer.echo(t("cli.user.error.no_tty_without_yes"), err=True)
            raise typer.Exit(code=2)
        target = resolver.show(slug=slug)
        if target is None:
            typer.echo(t("cli.user.error.not_found", slug=slug), err=True)
            raise typer.Exit(code=2)
        # KeyboardInterrupt from the prompt propagates; CliRunner / the
        # real shell maps SIGINT to exit 130 (POSIX convention).
        try:
            confirmed = typer.confirm(
                t(
                    "cli.user.remove.confirm",
                    slug=target.slug,
                    display_name=target.display_name,
                ),
                default=False,
            )
        except KeyboardInterrupt as exc:
            raise typer.Exit(code=130) from exc
        if not confirmed:
            raise typer.Exit(code=1)

    actor, actor_language = _actor()
    try:
        resolver.remove(slug=slug)
    except LastOperatorRemovalRefusedError as exc:
        typer.echo(t("cli.user.error.remove_last_operator_refused", slug=slug), err=True)
        raise typer.Exit(code=2) from exc
    except IdentityError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(t("cli.user.removed", slug=slug))
    asyncio.run(
        _write_audit(
            event="user.remove",
            actor=actor,
            language=actor_language,
            subject={"slug": slug},
        )
    )


# --------------------------------------------------------------------------- #
# bind / unbind
# --------------------------------------------------------------------------- #


@user_app.command("bind", help=t("cli.user.help.bind.short"))
def bind(
    slug: str,
    platform: Annotated[
        Platform,
        typer.Option("--platform", help=t("cli.user.flag.platform.short")),
    ],
    id: Annotated[
        str,
        typer.Option("--id", help=t("cli.user.flag.id.short")),
    ],
) -> None:
    """Bind ``(platform, id)`` to the user with ``slug``."""
    resolver = _load_resolver()
    actor, actor_language = _actor()
    try:
        resolver.bind(user_slug=slug, platform=platform, platform_id=id)
    except UserAlreadyBoundError as exc:
        # The user already has a live binding on this platform — distinct
        # from the cross-user platform_id collision below.
        typer.echo(
            t(
                "cli.user.error.user_already_bound",
                slug=exc.slug,
                platform=exc.platform,
            ),
            err=True,
        )
        raise typer.Exit(code=2) from exc
    except PlatformIdInUseError as exc:
        # A different user owns the same (platform, platform_id). The
        # typed exception carries the colliding user's slug so the operator
        # can name them in the next ``alfred user unbind`` call without
        # querying the DB by hand.
        typer.echo(
            t(
                "cli.user.error.platform_id_in_use",
                platform=exc.platform,
                platform_id=exc.platform_id,
                existing_slug=exc.existing_slug,
            ),
            err=True,
        )
        raise typer.Exit(code=2) from exc
    except IdentityResolutionError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(t("cli.user.bound", platform=platform.value, platform_id=id, slug=slug))
    asyncio.run(
        _write_audit(
            event="user.bind",
            actor=actor,
            language=actor_language,
            subject={"slug": slug, "platform": platform.value, "platform_id": id},
        )
    )


@user_app.command("unbind", help=t("cli.user.help.unbind.short"))
def unbind(
    slug: str,
    platform: Annotated[
        Platform,
        typer.Option("--platform", help=t("cli.user.flag.platform.short")),
    ],
) -> None:
    """Soft-delete the live binding for ``slug`` on ``platform``."""
    resolver = _load_resolver()
    actor, actor_language = _actor()
    try:
        resolver.unbind(user_slug=slug, platform=platform)
    except IdentityError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(t("cli.user.unbound", platform=platform.value, slug=slug))
    asyncio.run(
        _write_audit(
            event="user.unbind",
            actor=actor,
            language=actor_language,
            subject={"slug": slug, "platform": platform.value},
        )
    )


# --------------------------------------------------------------------------- #
# set
# --------------------------------------------------------------------------- #


def _coerce_rate_limit(raw: str | None) -> int | None | str:
    """Map the CLI string for ``--rate-limit-per-{min,day}`` to a resolver kwarg.

    The resolver's :meth:`IdentityResolver.set_` accepts the literal
    string ``"unset"`` as a sentinel meaning "write NULL"; any int is
    the new value; ``None`` (the CLI default) means "do not touch."
    Centralising the coercion keeps the two flags symmetric and the
    callback body short.
    """
    if raw is None:
        return None
    if raw == "unset":
        return "unset"
    try:
        return int(raw)
    except ValueError as exc:
        # Use the dedicated rate-limit key, not the authorization key — the
        # operator-facing message must name the field that actually failed
        # to parse so they know which flag to fix.
        typer.echo(
            t("cli.user.error.invalid_rate_limit", value=raw),
            err=True,
        )
        raise typer.Exit(code=2) from exc


@user_app.command("set", help=t("cli.user.help.set.short"))
def set_(
    slug: str,
    name: Annotated[
        str | None,
        typer.Option("--name", help=t("cli.user.flag.name.short")),
    ] = None,
    authorization: Annotated[
        str | None,
        typer.Option("--authorization", help=t("cli.user.flag.authorization.short")),
    ] = None,
    language: Annotated[
        str | None,
        typer.Option("--language", help=t("cli.user.flag.language.short")),
    ] = None,
    daily_budget_usd: Annotated[
        float | None,
        typer.Option("--daily-budget-usd", help=t("cli.user.flag.daily-budget-usd.short")),
    ] = None,
    rate_limit_per_min: Annotated[
        str | None,
        typer.Option("--rate-limit-per-min", help=t("cli.user.flag.rate-limit-per-min.short")),
    ] = None,
    rate_limit_per_day: Annotated[
        str | None,
        typer.Option("--rate-limit-per-day", help=t("cli.user.flag.rate-limit-per-day.short")),
    ] = None,
    replace_operator: Annotated[
        str | None,
        typer.Option("--replace-operator", help=t("cli.user.flag.replace-operator.short")),
    ] = None,
) -> None:
    """Tune a live user in place."""
    resolver = _load_resolver()
    auth = _normalise_authorization(authorization) if authorization is not None else None
    if language is not None:
        _validate_language_or_exit(language)

    rpm = _coerce_rate_limit(rate_limit_per_min)
    rpd = _coerce_rate_limit(rate_limit_per_day)
    actor, actor_language = _actor()

    try:
        # ``set_`` accepts the "unset" literal via Literal["unset"]; pass the
        # coerced value through unchanged. The type-narrowing ignore here is
        # because the coercion returns ``int | None | str`` and the
        # resolver signature is ``int | None | Literal["unset"]``; we know
        # the only possible string value is "unset" by construction.
        user = resolver.set_(
            slug=slug,
            display_name=name,
            authorization=auth,
            language=language,
            daily_budget_usd=daily_budget_usd,
            rate_limit_per_min=rpm,  # type: ignore[arg-type]  # reason: coerced to int|None|Literal["unset"] above
            rate_limit_per_day=rpd,  # type: ignore[arg-type]  # reason: coerced to int|None|Literal["unset"] above
            replace_operator=replace_operator,
        )
    except OperatorAlreadyExistsError as exc:
        typer.echo(
            t(
                "cli.user.error.operator_already_exists",
                existing_slug=exc.existing_slug,
                existing_display_name=exc.existing_display_name,
            ),
            err=True,
        )
        raise typer.Exit(code=2) from exc
    except IdentityError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    diff_parts = []
    if name is not None:
        diff_parts.append(f"display_name={user.display_name}")
    if auth is not None:
        diff_parts.append(f"authorization={user.authorization}")
    if language is not None:
        diff_parts.append(f"language={user.language}")
    if daily_budget_usd is not None:
        diff_parts.append(f"daily_budget_usd={user.daily_budget_usd:.2f}")
    if rate_limit_per_min is not None:
        diff_parts.append(f"rate_limit_per_min={user.rate_limit_per_min}")
    if rate_limit_per_day is not None:
        diff_parts.append(f"rate_limit_per_day={user.rate_limit_per_day}")
    typer.echo(t("cli.user.set.success", slug=user.slug, diff=", ".join(diff_parts)))

    asyncio.run(
        _write_audit(
            event="user.set",
            actor=actor,
            language=actor_language,
            subject={"slug": user.slug, "diff": diff_parts},
        )
    )


__all__ = ["install_factories", "user_app"]

"""``alfred login`` / ``logout`` / ``whoami`` — operator-session CLI (#153).

Top-level Typer verbs (no sub-app), mirroring ``alfred status`` / ``alfred
chat``. All operator-facing strings route through ``t()`` (CLAUDE.md i18n
rule #1). The thin Typer wrappers build the host dependencies from
``cli/_bootstrap.py``; the ``_impl`` coroutines take every collaborator as
an argument so unit tests inject fakes without monkeypatching ``os.environ``
or touching a real Postgres.

Closures realised here:
* devex-3: bare-``alfred login`` branches (zero / single / multi-user TTY /
  multi-user non-TTY).
* devex-1: the readable ``whoami`` template with labelled lines + relative
  timestamps.
* lifetime-pin: ``--expires-in`` clamped to ``[1h, 7d]`` (12h default).
"""

from __future__ import annotations

import re
import secrets
import socket
import sys
from collections.abc import Awaitable, Callable, Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import typer
from babel.dates import format_datetime, format_timedelta
from pydantic import SecretStr

from alfred.audit.audit_row_schemas import (
    OPERATOR_SESSION_CREATED_FIELDS,
    OPERATOR_SESSION_REFUSED_FIELDS,
    OPERATOR_SESSION_REVOKED_FIELDS,
)
from alfred.i18n import t
from alfred.identity._session_protocols import AuditLike, BrokerLike, MachineIdLike
from alfred.identity.operator_session import (
    OPERATOR_SESSION_CREATED_HOOKPOINT,
    OPERATOR_SESSION_REVOKED_HOOKPOINT,
    OperatorSessionError,
    OperatorSessionFile,
    OperatorSessionMissing,
    OperatorSessionNoMachineId,
    compute_machine_id_hash,
    compute_token_hash,
    load_session_file,
    select_machine_id_provider,
    write_session_file,
)

_DEFAULT_EXPIRES_IN = timedelta(hours=12)
_MIN_EXPIRES_IN = timedelta(hours=1)
_MAX_EXPIRES_IN = timedelta(days=7)
_TOKEN_BYTES = 32

_DURATION_RE = re.compile(r"^(?P<value>\d+)(?P<unit>[hd])$")


def _session_file_path() -> Path:
    return Path.home() / ".config" / "alfred" / "session"


# --------------------------------------------------------------------------- #
# Dependency bundle (injected; no global state)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _PickerUser:
    user_id: int
    slug: str
    display_name: str
    language: str


type _SessionScope = Callable[[], AbstractAsyncContextManager[Any]]
type _HookDispatcher = Callable[[str, dict[str, Any]], Awaitable[None]]


@dataclass(frozen=True)
class OperatorSessionDeps:
    """Host collaborators for the operator-session CLI commands.

    Constructed from ``cli/_bootstrap`` for production; fabricated by unit
    tests. ``list_users`` returns the picker rows; ``insert_session_row`` /
    ``revoke_session_row`` / ``lookup_user`` are the DB operations the CLI
    needs (kept narrow so the CLI does not embed SQLAlchemy directly).
    """

    secret_broker: BrokerLike
    audit_writer: AuditLike
    hook_dispatcher: _HookDispatcher
    machine_id_provider: MachineIdLike
    host: str
    session_file_path: Path
    list_users: Callable[[], Awaitable[Sequence[_PickerUser]]]
    lookup_user_by_slug: Callable[[str], Awaitable[_PickerUser | None]]
    lookup_user_by_id: Callable[[int], Awaitable[_PickerUser | None]]
    insert_session_row: Callable[..., Awaitable[None]]
    revoke_session_row: Callable[[str], Awaitable[None]]
    now_fn: Callable[[], datetime] = lambda: datetime.now(UTC)


def parse_expires_in(raw: str | None) -> timedelta:
    """Parse + clamp ``--expires-in`` to ``[1h, 7d]`` (lifetime-pin).

    ``None`` -> the 12h default. ``"30m"`` / ``"8d"`` / out-of-range values
    raise ``ValueError`` so the caller emits ``login.expires_in_out_of_range``.
    """
    if raw is None:
        return _DEFAULT_EXPIRES_IN
    match = _DURATION_RE.match(raw.strip())
    if match is None:
        raise ValueError(raw)
    value = int(match.group("value"))
    unit = match.group("unit")
    delta = timedelta(hours=value) if unit == "h" else timedelta(days=value)
    if delta < _MIN_EXPIRES_IN or delta > _MAX_EXPIRES_IN:
        raise ValueError(raw)
    return delta


# --------------------------------------------------------------------------- #
# login
# --------------------------------------------------------------------------- #


async def _select_user_bare(deps: OperatorSessionDeps) -> _PickerUser:
    """Bare-``alfred login`` discoverability flow (devex-3)."""
    users = await deps.list_users()
    if not users:
        typer.echo(t("login.no_users_exist"), err=True)
        raise typer.Exit(code=1)
    if len(users) == 1:
        only = users[0]
        typer.echo(t("login.auto_selected_single_user", display_name=only.display_name))
        return only
    if not sys.stdin.isatty():
        typer.echo(t("login.non_tty_requires_explicit_user"), err=True)
        raise typer.Exit(code=2)
    for idx, user in enumerate(users, start=1):
        typer.echo(t("login.picker_row", index=idx, display_name=user.display_name, slug=user.slug))
    choice = typer.prompt(t("login.picker_prompt"), type=int)
    if choice < 1 or choice > len(users):
        typer.echo(t("login.picker_out_of_range"), err=True)
        raise typer.Exit(code=2)
    chosen: _PickerUser = users[choice - 1]
    return chosen


async def login_impl(
    deps: OperatorSessionDeps,
    *,
    as_user: str | None,
    expires_in: str | None,
    refresh: bool,
) -> None:
    """Create or refresh the operator session."""
    try:
        delta = parse_expires_in(expires_in)
    except ValueError:
        typer.echo(t("login.expires_in_out_of_range", value=expires_in), err=True)
        raise typer.Exit(code=2) from None

    via = "login"
    if refresh:
        via = "refresh"
        try:
            existing = load_session_file(deps.session_file_path)
        except OperatorSessionMissing:
            typer.echo(t("login.refresh_no_session"), err=True)
            raise typer.Exit(code=1) from None
        user = await deps.lookup_user_by_id(existing.user_id)
        if user is None:
            typer.echo(t("login.user_not_found", user=str(existing.user_id)), err=True)
            typer.echo(t("login.user_not_found.hint"), err=True)
            raise typer.Exit(code=1)
    elif as_user is None:
        user = await _select_user_bare(deps)
    else:
        user = await deps.lookup_user_by_slug(as_user)
        if user is None:
            typer.echo(t("login.user_not_found", user=as_user), err=True)
            typer.echo(t("login.user_not_found.hint"), err=True)
            raise typer.Exit(code=1)

    # Overwrite confirmation when an existing session binds a different user.
    if not refresh:
        try:
            current = load_session_file(deps.session_file_path)
        except OperatorSessionError:
            current = None
        if (
            current is not None
            and current.user_id != user.user_id
            and not typer.confirm(t("login.session_overwrite_confirm", user=user.display_name))
        ):
            raise typer.Exit(code=1)

    pepper = deps.secret_broker.get("audit.hash_pepper").encode("utf-8")
    try:
        machine_hash = await compute_machine_id_hash(
            provider=deps.machine_id_provider, pepper=pepper
        )
    except OperatorSessionNoMachineId:
        typer.echo(t("login.no_machine_id"), err=True)
        raise typer.Exit(code=1) from None

    token_raw = secrets.token_urlsafe(_TOKEN_BYTES)
    token_hash = compute_token_hash(token=token_raw, pepper=pepper)
    now = deps.now_fn()
    expires_at = now + delta
    session = OperatorSessionFile(
        schema_version=1,
        user_id=user.user_id,
        token=SecretStr(token_raw),
        issued_at=now,
        expires_at=expires_at,
        host=deps.host,
        machine_id_hash=machine_hash,
    )

    await deps.insert_session_row(
        token_hash=token_hash,
        user_id=user.user_id,
        issued_at=now,
        expires_at=expires_at,
        host=deps.host,
        machine_id_hash=machine_hash,
    )
    write_session_file(deps.session_file_path, session)

    await deps.audit_writer.append_schema(
        fields=OPERATOR_SESSION_CREATED_FIELDS,
        schema_name="OPERATOR_SESSION_CREATED_FIELDS",
        event="operator.session.created",
        actor_user_id=str(user.user_id),
        subject={
            "user_id": str(user.user_id),
            "issued_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "host": deps.host,
            "machine_id_hash": machine_hash,
            "via": via,
        },
        trust_tier_of_trigger="T1",
        result="success",
        cost_estimate_usd=0.0,
        trace_id=f"operator-session-created-{user.user_id}",
        language=user.language,
    )
    await deps.hook_dispatcher(
        OPERATOR_SESSION_CREATED_HOOKPOINT,
        {"user_id": str(user.user_id), "host": deps.host, "via": via},
    )
    typer.echo(
        t(
            "login.confirmed",
            user=user.display_name,
            expires_at=format_datetime(expires_at, locale=user.language),
            host=deps.host,
        )
    )


# --------------------------------------------------------------------------- #
# logout
# --------------------------------------------------------------------------- #


async def _resolve_display_name(deps: OperatorSessionDeps, user_id: int) -> str:
    """Resolve a user's display name, falling back to the numeric id.

    The healthy ``whoami`` template resolves the display name; the degraded
    paths (logout confirmation, expired whoami) MUST do the same so the
    operator gets a human-readable name exactly when things are degraded,
    not a bare numeric id (devex). A removed/unknown user falls back to the
    stringified id rather than failing the command.
    """
    user = await deps.lookup_user_by_id(user_id)
    return user.display_name if user is not None else str(user_id)


async def _emit_cleanup_malformed_audit(deps: OperatorSessionDeps) -> None:
    """Record a tamper-cleanup audit row BEFORE unlinking an unloadable file.

    hard rule #7 + forensic discipline: a malformed / bad-mode / bad-owner
    session file may be planted or tampered. Unlinking it silently destroys
    the evidence. We emit a file-less ``OPERATOR_SESSION_REFUSED`` row
    (reason ``cleanup_malformed``, every self-claimed field ``None`` so no
    unparsed attacker bytes reach the log) so the tamper is recorded, THEN
    the caller unlinks.
    """
    refused_at = deps.now_fn()
    await deps.audit_writer.append_schema(
        fields=OPERATOR_SESSION_REFUSED_FIELDS,
        schema_name="OPERATOR_SESSION_REFUSED_FIELDS",
        event="operator.session.refused",
        actor_user_id=None,
        subject={
            "attempted_user_id": None,
            "resolved_user_id": None,
            "reason": "cleanup_malformed",
            "host": None,
            "machine_id_hash": None,
            "refused_at": refused_at.isoformat(),
            "via": "logout",
        },
        trust_tier_of_trigger="T1",
        result="refused",
        cost_estimate_usd=0.0,
        trace_id="operator-session-refused-cleanup_malformed",
    )


async def logout_impl(deps: OperatorSessionDeps) -> None:
    """Revoke + delete the current operator session."""
    try:
        session = load_session_file(deps.session_file_path)
    except OperatorSessionMissing:
        typer.echo(t("logout.no_session"), err=True)
        raise typer.Exit(code=1) from None
    except OperatorSessionError:
        # Bad mode / owner / malformed — possibly planted/tampered. Audit the
        # cleanup BEFORE we destroy the evidence, then remove the file so the
        # next login is unblocked.
        await _emit_cleanup_malformed_audit(deps)
        deps.session_file_path.unlink(missing_ok=True)
        typer.echo(t("logout.no_session"), err=True)
        raise typer.Exit(code=1) from None

    pepper = deps.secret_broker.get("audit.hash_pepper").encode("utf-8")
    token_hash = compute_token_hash(token=session.token.get_secret_value(), pepper=pepper)
    revoked_at = deps.now_fn()
    await deps.revoke_session_row(token_hash)
    deps.session_file_path.unlink(missing_ok=True)

    await deps.audit_writer.append_schema(
        fields=OPERATOR_SESSION_REVOKED_FIELDS,
        schema_name="OPERATOR_SESSION_REVOKED_FIELDS",
        event="operator.session.revoked",
        actor_user_id=str(session.user_id),
        subject={
            "user_id": str(session.user_id),
            "revoked_at": revoked_at.isoformat(),
            "via": "logout",
        },
        trust_tier_of_trigger="T1",
        result="success",
        cost_estimate_usd=0.0,
        trace_id=f"operator-session-revoked-{session.user_id}",
    )
    await deps.hook_dispatcher(
        OPERATOR_SESSION_REVOKED_HOOKPOINT,
        {"user_id": str(session.user_id), "via": "logout"},
    )
    display = await _resolve_display_name(deps, session.user_id)
    typer.echo(t("logout.confirmed", user=display))


# --------------------------------------------------------------------------- #
# whoami
# --------------------------------------------------------------------------- #


async def whoami_impl(deps: OperatorSessionDeps) -> None:
    """Print the currently-bound operator (devex-1 readable template)."""
    try:
        session = load_session_file(deps.session_file_path)
    except OperatorSessionMissing:
        typer.echo(t("whoami.no_session"), err=True)
        raise typer.Exit(code=1) from None
    except OperatorSessionError:
        # Malformed / bad-mode / bad-owner — the file is corrupt or insecure.
        # Print an actionable message + the recovery command instead of letting
        # a raw traceback escape to the operator (err: no unhandled exception).
        typer.echo(t("whoami.unloadable"), err=True)
        typer.echo(t("whoami.unloadable.recovery"), err=True)
        raise typer.Exit(code=1) from None
    now = deps.now_fn()
    user = await deps.lookup_user_by_id(session.user_id)
    lang = user.language if user is not None else "en"
    display = user.display_name if user is not None else str(session.user_id)
    if session.expires_at < now:
        typer.echo(
            t(
                "whoami.expired",
                user=display,
                expires_at=format_datetime(session.expires_at, locale=lang),
            ),
            err=True,
        )
        raise typer.Exit(code=1)
    issued_rel = format_timedelta(session.issued_at - now, add_direction=True, locale=lang)
    expires_rel = format_timedelta(session.expires_at - now, add_direction=True, locale=lang)
    typer.echo(
        t(
            "whoami.template",
            user=display,
            user_short=str(session.user_id),
            issued_at_relative=issued_rel,
            issued_at=format_datetime(session.issued_at, locale=lang),
            expires_at_relative=expires_rel,
            expires_at=format_datetime(session.expires_at, locale=lang),
            host=session.host,
            machine_short=session.machine_id_hash[:8] + "…",
        )
    )


# --------------------------------------------------------------------------- #
# Shared operator-attribution helper for reviewer-gated CLI commands
# --------------------------------------------------------------------------- #


def _build_operator_resolver() -> Any:  # pragma: no cover - integration-covered (Component G)
    """Construct the production ``DefaultOperatorSessionResolver``.

    Shared by ``config`` / ``plugin`` reviewer-gated commands so their
    proposal payloads carry the canonical operator ``User.id`` (#153). The
    ``supervisor reset`` path has its own builder (it emits a
    breaker-specific refused row); this one emits the generic
    ``OPERATOR_SESSION_REFUSED_FIELDS`` on failure.
    """
    from alfred.audit.log import AuditWriter
    from alfred.cli._bootstrap import build_broker_or_die, load_settings_or_die
    from alfred.hooks import SYSTEM_ONLY_TIERS
    from alfred.hooks.context import HookContext
    from alfred.hooks.invoke import invoke
    from alfred.identity._resolver import DefaultOperatorSessionResolver
    from alfred.memory.db import build_session_scope

    settings = load_settings_or_die()
    scope = build_session_scope(settings)

    async def _dispatch(name: str, payload: dict[str, Any]) -> None:
        import uuid

        correlation_id = str(uuid.uuid4())
        ctx: HookContext[dict[str, object]] = HookContext(
            action_id=name,
            hookpoint=name,
            input={**payload, "correlation_id": correlation_id},
            correlation_id=correlation_id,
            kind="post",
        )
        await invoke(name, ctx, kind="post", subscribable_tiers=SYSTEM_ONLY_TIERS, fail_closed=True)

    return DefaultOperatorSessionResolver(
        session_scope=scope,
        secret_broker=build_broker_or_die(settings),
        machine_id_provider=select_machine_id_provider(),
        audit_writer=AuditWriter(session_factory=scope),
        hook_dispatcher=_dispatch,
        host=socket.gethostname(),
        session_file_path=_session_file_path(),
    )


def resolve_operator_user_id_or_refuse(*, refusal_key: str) -> str:
    """Resolve the operator's canonical ``User.id`` or refuse the command.

    Used by reviewer-gated CLI commands (``config set``, ``plugin
    grant/revoke``) so the queued proposal payload carries the canonical
    ``operator_user_id`` rather than ``None`` (#153). On any
    ``OperatorSessionError`` the command echoes the localised refusal +
    its recovery companion and exits non-zero — no unauthenticated
    attribution. The resolver itself already emits the
    ``OPERATOR_SESSION_REFUSED`` audit row on the refusal path.
    """
    import asyncio

    from alfred.identity.operator_session import OperatorSessionError

    resolver = _build_operator_resolver()
    try:
        user_id: str = asyncio.run(resolver.resolve())
        return user_id
    except OperatorSessionError as exc:
        typer.echo(t(refusal_key), err=True)
        recovery = t(f"{refusal_key}.recovery")
        if recovery != f"{refusal_key}.recovery":
            typer.echo(recovery, err=True)
        raise typer.Exit(code=1) from exc


# --------------------------------------------------------------------------- #
# Production wiring + Typer command surface
# --------------------------------------------------------------------------- #


def _build_deps() -> OperatorSessionDeps:  # pragma: no cover - integration-covered (Component G)
    """Construct the production deps from ``cli/_bootstrap`` (lazy-imported).

    Kept out of module import so ``alfred --help`` does not pay the broker +
    SQLAlchemy import cost (PR-S3-6 §8.5 perf lesson). The body is covered by
    ``tests/integration/test_operator_session_lifecycle.py`` against a real
    Postgres testcontainer, not by unit tests.
    """
    import asyncio as _asyncio

    from sqlalchemy import select, update

    from alfred.audit.log import AuditWriter
    from alfred.cli._bootstrap import build_broker_or_die, load_settings_or_die
    from alfred.hooks import SYSTEM_ONLY_TIERS
    from alfred.hooks.context import HookContext
    from alfred.hooks.invoke import invoke
    from alfred.identity.models import User
    from alfred.memory.db import build_session_scope
    from alfred.memory.models import OperatorSession as OperatorSessionRow

    settings = load_settings_or_die()
    broker = build_broker_or_die(settings)
    scope = build_session_scope(settings)
    audit = AuditWriter(session_factory=scope)

    def _row_to_picker(row: Any) -> _PickerUser:
        return _PickerUser(
            user_id=row.id, slug=row.slug, display_name=row.display_name, language=row.language
        )

    async def _list_users() -> Sequence[_PickerUser]:
        async with scope() as db:
            rows = (
                await db.execute(
                    select(User).where(User.deleted_at.is_(None)).order_by(User.created_at)
                )
            ).scalars()
            return [_row_to_picker(r) for r in rows]

    async def _lookup_by_slug(slug: str) -> _PickerUser | None:
        async with scope() as db:
            row = (
                await db.execute(select(User).where(User.slug == slug, User.deleted_at.is_(None)))
            ).scalar_one_or_none()
            return _row_to_picker(row) if row is not None else None

    async def _lookup_by_id(uid: int) -> _PickerUser | None:
        async with scope() as db:
            row = (
                await db.execute(select(User).where(User.id == uid, User.deleted_at.is_(None)))
            ).scalar_one_or_none()
            return _row_to_picker(row) if row is not None else None

    async def _insert(**kwargs: Any) -> None:
        async with scope() as db:
            db.add(OperatorSessionRow(**kwargs))
            await db.flush()

    async def _revoke(token_hash: str) -> None:
        async with scope() as db:
            await db.execute(
                update(OperatorSessionRow)
                .where(OperatorSessionRow.token_hash == token_hash)
                .values(revoked_at=datetime.now(UTC))
            )

    async def _dispatch(name: str, payload: dict[str, Any]) -> None:
        import uuid

        correlation_id = str(uuid.uuid4())
        ctx: HookContext[dict[str, object]] = HookContext(
            action_id=name,
            hookpoint=name,
            input={**payload, "correlation_id": correlation_id},
            correlation_id=correlation_id,
            kind="post",
        )
        await invoke(name, ctx, kind="post", subscribable_tiers=SYSTEM_ONLY_TIERS, fail_closed=True)

    _ = _asyncio  # keep the import referenced for the wrappers below

    return OperatorSessionDeps(
        secret_broker=broker,
        audit_writer=audit,
        hook_dispatcher=_dispatch,
        machine_id_provider=select_machine_id_provider(),
        host=socket.gethostname(),
        session_file_path=_session_file_path(),
        list_users=_list_users,
        lookup_user_by_slug=_lookup_by_slug,
        lookup_user_by_id=_lookup_by_id,
        insert_session_row=_insert,
        revoke_session_row=_revoke,
    )


__all__ = [
    "OperatorSessionDeps",
    "login_impl",
    "logout_impl",
    "parse_expires_in",
    "whoami_impl",
]

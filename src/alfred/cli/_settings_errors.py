"""Value-free renderers for a ``Settings()`` construction failure.

Two operator-facing surfaces need to say "your config is broken, here's which field,
fix it in .env" without ever repeating what an operator actually typed:

* the daemon-boot path (``alfred.cli.daemon._commands``'s ``_load_settings_or_die``,
  distinct from this module despite the near-identical name) — its message lands on
  stderr, which for a daemon running as a service commonly reaches durable
  container/system logs (journald, ``docker logs``).
* the interactive CLI path (``alfred.cli._bootstrap.load_settings_or_die``, used by
  every OTHER top-level command — ``status``, ``chat``, ``login``, ``supervisor *``,
  ``user *``, ``operator-session *``) — its message reaches the operator's own
  terminal, which is not the same as "safe": shell history, tmux/``script(1)``
  scrollback capture, and any ``| tee`` wrapper all persist it just as durably as a
  log file.

Both surfaces used to interpolate ``str(exc)`` (or a hand-rolled equivalent)
somewhere on their generic-failure arm. Pydantic's ``ValidationError.__str__()``
embeds ``input_value=<raw input>`` verbatim — so the day ``Settings.primary_provider``
became a ``Literal["anthropic", "deepseek"]`` (#589, closing a CodeRabbit
Major/Security finding that the field reached several boot-log lines raw), a
credential pasted into ``ALFRED_PRIMARY_PROVIDER`` started failing validation for the
FIRST time — and got echoed in full by the interactive path's ``str(exc)`` fallback,
which nobody had touched. ``Settings.quarantine_provider`` (an earlier ``Literal`` in
that same PR) had carried the identical exposure since it was first added. This
module is the fix: the ONE place either surface may read a ``SettingsError``'s cause,
and the contract is absolute — never ``.msg``, never ``.input``, only ``.loc`` (the
field path pydantic itself attributes the failure to) and, for a rejected ``Literal``
specifically, ``.ctx['expected']`` (the SCHEMA's own list of accepted values — never
derived from what the operator typed).

Lives at ``alfred.cli`` (not nested under ``.daemon``) and carries zero
provider/SQLAlchemy/memory imports on purpose: ``alfred.cli.daemon._commands`` is
under a 100%-line+branch coverage gate (``ci.yml``) and this module EXTENDS that
gate rather than moving into the ungated ``alfred.cli._bootstrap`` — every branch
here is a decision about whether an operator-supplied value reaches an output sink,
exactly the class of code that gate exists to hold at 100%. Staying import-light also
means ``alfred.cli._bootstrap`` (which DOES carry the heavy provider/memory/
orchestrator imports ``_commands.py`` avoids via a lazy in-function import) can import
this module at its own top level with zero extra weight.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from pydantic import ValidationError
from pydantic_core import ErrorDetails

from alfred.i18n import t

if TYPE_CHECKING:
    from alfred.config.settings import SettingsError

__all__ = [
    "SettingsFieldFault",
    "cli_settings_error_lines",
    "daemon_boot_settings_message",
    "settings_error_field",
]

#: Pydantic error types whose ``ctx['expected']`` is derived from the SCHEMA (the
#: Literal's own declared members), never from operator input — the only ``ctx``
#: content this module ever dereferences. A ``value_error``'s ``ctx`` can carry the
#: raw exception args (the exact leak this module exists to close), so ``ctx`` is
#: only READ when the error type is a member of this set — fetched unconditionally
#: (below), but never touched otherwise. ``enum`` has the identical ctx shape and
#: belongs here the day a Settings field first uses one; omitted while untested (no
#: such field exists yet).
_CHOICE_ERROR_TYPES: Final[frozenset[str]] = frozenset({"literal_error"})


@dataclass(frozen=True, slots=True)
class SettingsFieldFault:
    """The DLP-safe half of a rejected ``Settings`` field.

    ``path`` — pydantic's dotted ``loc``, or a deliberately-authored
    ``PydanticCustomError`` type slug when ``loc`` is empty (a model-level
    validator — #410 PR1). ``choices`` — the rendered accepted-value set for a
    rejected ``Literal``, else ``None``. Neither field can ever carry the value that
    was actually rejected; that is this type's whole contract.
    """

    path: str
    choices: str | None


def settings_error_field(exc: SettingsError) -> SettingsFieldFault | None:
    """Extract the DLP-safe fault (field path + optional accepted choices) from a
    chained pydantic ``ValidationError``.

    ``ValidationError.errors()[].loc`` is the field path pydantic itself attributes
    the failure to — safe to surface, unlike ``.msg``/``.input``, either of which can
    carry the invalid VALUE (a custom validator's ``ValueError`` text can embed it,
    e.g. a ``database_url`` failure quoting the DSN). ``loc`` is excluded from that
    risk: it names WHERE validation failed, never what value was there.
    ``Settings.__init__`` chains the original exception via ``raise
    SettingsError(str(exc)) from exc``, so ``exc.__cause__`` is the real
    ``ValidationError`` on a genuine ``Settings()`` construction failure. Returns
    ``None`` when no such chain exists (e.g. a test double raising ``SettingsError``
    directly with no ``from``) or the cause is not a ``ValidationError`` — the caller
    falls back to the fully generic message rather than guess — except for a
    model-level (``loc=()``) error whose TYPE is a deliberately-authored
    ``PydanticCustomError`` slug, which is returned as the DLP-safe category
    (#410 PR1).

    Fetches ``ctx`` unconditionally (``include_context=True``) rather than issuing a
    second, separately-flagged read: pydantic populates ``ctx`` purely from the
    validator's OWN raised context (a ``Literal``'s declared members, a custom
    validator's exception args, ...) — the security boundary is not whether ``ctx``
    is present in the fetched dict, it's that :func:`_literal_choices` below only
    ever DEREFERENCES ``ctx['expected']`` when the error type is a member of
    ``_CHOICE_ERROR_TYPES``. ``include_input`` stays ``False`` unconditionally — the
    one flag this whole module exists to never flip.
    """
    cause = exc.__cause__
    if not isinstance(cause, ValidationError):
        return None
    errors = cause.errors(include_url=False, include_context=True, include_input=False)
    if not errors:
        return None
    first = errors[0]
    loc = first["loc"]
    if not loc:
        # #410 PR1 (fleet finding H-3): a model-level validator reports loc=(). A
        # DELIBERATELY-SLUGGED PydanticCustomError (e.g. the db-pool budget
        # validator's "db_pool_connection_budget_exceeded") carries its category in
        # the error TYPE — a value-free identifier authored as a string literal in
        # settings.py, safe to surface under the same never-a-value contract as the
        # field path below. Pydantic's own wrappers for bare `raise
        # ValueError/AssertionError` arrive as the generic "value_error"/
        # "assertion_error" types, which name nothing — those (and only those) still
        # degrade to the generic message.
        error_type = first["type"]
        if error_type in {"value_error", "assertion_error"}:
            return None
        return SettingsFieldFault(path=error_type, choices=None)
    return SettingsFieldFault(
        path=".".join(str(part) for part in loc),
        choices=_literal_choices(first),
    )


def _literal_choices(error: ErrorDetails) -> str | None:
    """Render the accepted-value set for a rejected ``Literal`` error dict, else
    ``None``.

    Gated on ``error["type"]`` FIRST, before ``ctx`` is ever dereferenced —
    ``literal_error``'s ``ctx['expected']`` is pydantic's own rendering of the
    ``Literal``'s declared members, fixed at class-definition time, so it can never
    contain what the operator typed. No other error type's ``ctx`` is ever read
    through this function.
    """
    if error["type"] not in _CHOICE_ERROR_TYPES:
        return None
    ctx = error.get("ctx")
    if ctx is None:
        return None
    expected = ctx.get("expected")
    if not isinstance(expected, str):
        return None
    return expected


def _placeholder_api_key_message(exc: SettingsError) -> str | None:
    """The one branch both operator-facing surfaces share verbatim.

    Matched on substring rather than exact equality because pydantic decorates the
    message with loc/path context. ``None`` when this is not the placeholder-key
    case, so callers can chain it before the field-path logic.
    """
    if "placeholder_api_key" in str(exc):
        return t("error.placeholder_api_key")
    return None


def daemon_boot_settings_message(exc: SettingsError) -> str:
    """Pick the curated operator-facing message for a post-env ``Settings()``
    failure on the DAEMON-BOOT path (``alfred.cli.daemon._commands``'s own
    bootstrap helper).

    NEVER interpolates ``str(exc)`` or any value — only the field's dotted PATH,
    and, for a rejected ``Literal``, its accepted values. This message does NOT land
    in the audit row — ``_refuse_boot``'s fixed subject shape only ever carries
    ``boot_id`` / ``attempted_at`` / ``failure_reason`` / ``environment_source``; the
    message itself reaches ``typer.echo(..., err=True)`` (stderr), which for a
    daemon running as a background service is commonly captured into durable
    container/system logs (journald, ``docker logs``). DLP: a ``database_url``/DSN
    validation failure's ``str(exc)`` can echo a password, and CLAUDE.md hard rule
    #1 (never log secrets) applies to that stderr/log sink just as much as to a
    structlog line. ``daemon.boot.settings_invalid`` names the fix + the
    ``alfred daemon start`` / ``docker compose up -d`` re-run — not ``/etc/alfred``
    (the environment was already resolved by the time this runs; the fault is in
    some OTHER Settings field).

    When the field name is safely recoverable, the curated
    ``daemon.boot.settings_invalid_field`` variant names it; when it's a rejected
    ``Literal`` specifically, ``daemon.boot.settings_invalid_field_choices`` also
    lists the accepted values (#589 devex-001 — the plain field-name message left an
    operator who mistyped a closed-set value with no clue what the accepted values
    even were, unlike the CLI-level ``validate_quarantined_provider`` validator,
    which already listed them).
    """
    placeholder = _placeholder_api_key_message(exc)
    if placeholder is not None:
        return placeholder
    fault = settings_error_field(exc)
    if fault is None:
        return t("daemon.boot.settings_invalid")
    if fault.choices is None:
        return t("daemon.boot.settings_invalid_field", field=fault.path)
    return t("daemon.boot.settings_invalid_field_choices", field=fault.path, choices=fault.choices)


def cli_settings_error_lines(exc: SettingsError) -> tuple[str, ...]:
    """Render the operator-facing block for a post-env ``Settings()`` failure on the
    INTERACTIVE CLI path (``alfred.cli._bootstrap.load_settings_or_die`` — every
    top-level command except ``alfred daemon start``: ``status``, ``chat``,
    ``login``, ``supervisor *``, ``user *``, ``operator-session *``).

    Returns lines rather than one string because the CLI surface has always been
    two-line by design (a message plus ``hint.copy_env_example``) while the
    daemon-boot surface is one-line — a single ``str`` return would force one of the
    two callers to reshape it.

    Same never-echo contract as :func:`daemon_boot_settings_message`, and the SAME
    underlying leak this fixes: before this module existed, the generic branch here
    was ``t("error.config_invalid", detail=str(exc))`` — pydantic's
    ``ValidationError.__str__()`` embeds ``input_value=<raw input>`` verbatim, so
    ``ALFRED_PRIMARY_PROVIDER=<a credential>`` + ``alfred status`` printed that
    credential in full to stdout (shell history, terminal scrollback, any
    ``| tee``).

    Deliberate behaviour change from the old generic branch: ``hint.copy_env_example``
    ("copy .env.example … fill in ALFRED_DEEPSEEK_API_KEY") now fires ONLY when no
    field could be named at all. Once a specific field is recoverable, that hint is
    active misdirection — the operator's ``.env`` already has every key populated;
    ONE value in it is wrong.
    """
    placeholder = _placeholder_api_key_message(exc)
    if placeholder is not None:
        return (placeholder,)
    fault = settings_error_field(exc)
    if fault is None:
        return (t("error.config_invalid"), t("hint.copy_env_example"))
    if fault.choices is None:
        return (t("error.config_invalid_field", field=fault.path),)
    return (t("error.config_invalid_field_choices", field=fault.path, choices=fault.choices),)

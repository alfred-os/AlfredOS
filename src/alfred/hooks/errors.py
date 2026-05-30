"""Hook subsystem error taxonomy — see spec §3.1.

Three exception classes rooted at :class:`alfred.errors.AlfredError`:

* :class:`HookError` — the hook-subsystem root. The dispatcher in Task-10
  catches this for the swallow-vs-re-raise decision; the orchestrator's
  PR-B ``except`` arm catches the broader :class:`AlfredError`.
* :class:`HookRefusal` — a deliberate refusal by a pre-hook (DLP policy,
  capability denial, trust-tier mismatch). Keyword-only ``__init__``
  stores all four audit-attribution fields verbatim. The user-visible
  message is built through :func:`alfred.i18n.t` so operator output
  respects the active locale (i18n rule #1).
* :class:`HookSubscriberError` — wraps an unexpected exception from a
  registered subscriber. The actual ``raise ... from exc`` site lives
  in Task-10's ``_run_chain``; this slice ships the class plus the
  :meth:`HookSubscriberError.from_subscriber` constructor so the
  call-site only has to supply the subscriber name, correlation id, and
  the upstream exception. The message is built via :func:`alfred.i18n.t`
  against the ``hooks.subscriber_error`` catalog entry.

Conventions pinned by ``tests/unit/hooks/test_errors.py``:

* Hard rule (CLAUDE.md security #7): no silent failures in security
  paths — the catalog-key resolution test asserts a *rendered* string,
  not the bare-key fallback the translator returns for missing entries.
* Hard rule (CLAUDE.md i18n #1): every operator-facing string goes
  through ``t()`` — every constructor and helper here renders via ``t()``
  before passing the message up to :class:`HookError.__init__`.
* Hard rule (CLAUDE.md i18n #4): the three msgid/msgstr pairs land
  atomically with this source file. Because ``pybabel update`` only
  keeps msgids that have a live ``t("key", ...)`` call-site in the
  source, all three keys are referenced from real call-sites in this
  module (``HookRefusal.__init__``,
  :func:`subscriber_must_be_async_message`, and
  :meth:`HookSubscriberError.from_subscriber`) — Task-7's decorator and
  Task-10's dispatcher will import the helpers so the call-sites stay
  rooted here, not duplicated.

Forward-compat: Task-7 (the decorator) raises
:class:`HookSubscriberError` against the ``hooks.subscriber_must_be_async``
catalog entry when a sync function is registered. The helper
:func:`subscriber_must_be_async_message` renders that key in this
module so pybabel keeps it as a live catalog entry without Task-7
having landed yet.
"""

from __future__ import annotations

from alfred.errors import AlfredError
from alfred.i18n import t


class HookError(AlfredError):
    """Root of the hook subsystem error hierarchy.

    The dispatcher catches this in Task-10's ``_run_chain`` to decide
    swallow-vs-re-raise per stage; downstream code catching
    :class:`AlfredError` picks up hook errors uniformly.
    """


class HookRefusal(HookError):  # noqa: N818  -- spec §3.1 names this class without an Error suffix; rename would break the PRD/spec/plan contract and every test that constructs HookRefusal(...).
    """A pre-hook deliberately refused the action.

    Raised by a pre-hook to abort the action body cleanly (DLP block,
    capability denied, trust-tier mismatch, persona refusal). The audit
    row in Task-10 reads ``hook_id``, ``action_id``, ``reason``, and
    ``correlation_id`` directly off the attribute — they are part of the
    type's structural contract, not just message-format inputs.

    The keyword-only signature mirrors the verbatim spec §3.1 contract
    so a caller cannot accidentally swap, say, ``action_id`` and
    ``hook_id`` via positional args.
    """

    # Explicit attribute typing so mypy --strict sees the public fields
    # the dispatcher / audit writer rely on, distinct from any hidden
    # state on the Exception base.
    hook_id: str
    action_id: str
    reason: str
    correlation_id: str

    def __init__(
        self,
        *,
        hook_id: str,
        action_id: str,
        reason: str,
        correlation_id: str,
    ) -> None:
        # Store the four fields BEFORE building the message so a debugger
        # stopped in `t()` would still see them on `self`. Note the
        # catalog template (locale/en/LC_MESSAGES/alfred.po →
        # `hooks.refusal`) deliberately does NOT embed `correlation_id`
        # in the operator-facing message — the id stays on the
        # attribute for the audit row only. The test
        # `test_hook_refusal_does_not_leak_correlation_id_into_message`
        # pins that no-leak.
        self.hook_id = hook_id
        self.action_id = action_id
        self.reason = reason
        self.correlation_id = correlation_id
        message = t(
            "hooks.refusal",
            hook_id=hook_id,
            action_id=action_id,
            reason=reason,
        )
        super().__init__(message)


def subscriber_must_be_async_message(*, name: str) -> str:
    """Render the ``hooks.subscriber_must_be_async`` operator-facing string.

    Task-7's :func:`@hook` decorator calls this when a sync function is
    registered. The call-site reads:

    .. code-block:: python

        from alfred.hooks.errors import (
            HookSubscriberError,
            subscriber_must_be_async_message,
        )
        raise HookSubscriberError(subscriber_must_be_async_message(name=fn.__name__))

    Living in :mod:`alfred.hooks.errors` rather than the decorator's
    module keeps every hook-subsystem catalog key co-located with the
    error taxonomy — pybabel sees one source-of-truth file for the
    ``hooks.*`` msgids.
    """
    return t("hooks.subscriber_must_be_async", name=name)


class HookSubscriberError(HookError):
    """Wraps an unexpected exception from a registered hook subscriber.

    The intended usage in Task-10's ``_run_chain`` is::

        try:
            await subscriber(context)
        except Exception as exc:
            raise HookSubscriberError.from_subscriber(
                name=subscriber.__name__,
                correlation_id=context.correlation_id,
            ) from exc

    The ``raise ... from exc`` preserves ``__cause__`` so the audit
    row's "see the audit log" pointer can follow the chained traceback
    to the original exception. The plain ``HookSubscriberError(msg)``
    constructor is also supported for cases that already have a
    rendered message in hand (e.g. Task-7's decorator passes
    :func:`subscriber_must_be_async_message`'s output).
    """

    @classmethod
    def from_subscriber(
        cls,
        *,
        name: str,
        correlation_id: str,
    ) -> HookSubscriberError:
        """Build a subscriber-error with the standard rendered message.

        Wrappers in Task-10 use this so the catalog key is referenced
        in exactly one place; the call-site only knows the subscriber
        name and the correlation id.
        """
        message = t(
            "hooks.subscriber_error",
            name=name,
            correlation_id=correlation_id,
        )
        return cls(message)

"""Typed errors raised by the identity layer.

Rooted at ``AlfredError`` so CLI top-level dispatch (and orchestrator
``except`` arms in PR B) can catch them uniformly without swallowing
unrelated exceptions. ``OperatorSlugCollisionError`` is also a subclass of
``alembic.util.exc.CommandError`` so the Alembic runner surfaces it as a
normal migration failure (exit 1) rather than a crash.
"""

from __future__ import annotations

from alembic.util.exc import CommandError

from alfred.errors import AlfredError


class IdentityError(AlfredError):
    """Base for identity-layer failures."""


class IdentityResolutionError(IdentityError):
    """Raised when ``IdentityResolver.resolve`` is forced to fail loudly.

    Used by ``get_operator()`` when zero or >1 operator users exist — adapter
    startup surfaces a friendly hint pointing at ``alfred user add
    --authorization operator``.
    """


class OperatorAlreadyExistsError(IdentityError):
    """Raised when ``add(--authorization operator)`` or ``set(--authorization operator)``
    would produce a second concurrent operator.

    The CLI catches this and either (a) exits 2 with ``cli.user.error.operator_already_exists``
    if no ``--replace-operator`` was passed, or (b) re-runs the operation as
    a demote-then-promote in one transaction if it was.
    """

    def __init__(self, existing_slug: str, existing_display_name: str) -> None:
        self.existing_slug = existing_slug
        self.existing_display_name = existing_display_name
        super().__init__(
            f"Operator '{existing_slug}' ({existing_display_name}) already exists; "
            f"pass --replace-operator {existing_slug} to swap atomically."
        )


class LastOperatorRemovalRefusedError(IdentityError):
    """Raised when ``remove(slug)`` would leave the deployment with zero operators."""

    def __init__(self, slug: str) -> None:
        self.slug = slug
        super().__init__(
            f"Refused to remove the last operator '{slug}'. Promote another user to operator first."
        )


class OperatorSlugCollisionError(CommandError):
    """Raised by migration 0004's slug pre-check if a literal user_id in episodes
    or audit_log slug-collides with an existing non-operator users row.

    Subclasses ``alembic.util.exc.CommandError`` so the migration runner reports
    it as a normal command failure (exit 1) rather than a crash, and the
    ``alembic upgrade head`` CLI surfaces the message to the operator.
    """

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


class PlatformIdInUseError(IdentityResolutionError):
    """Raised when ``bind(platform, platform_id, ...)`` collides with another
    user's live binding for the same ``(platform, platform_id)`` pair.

    Carries the colliding user's slug so the CLI can name them in the
    operator-facing error message instead of leaving the operator to query
    the DB by hand. The Slice-1 resolver wrapped every constraint failure
    in a bare :class:`IdentityResolutionError`; promoting this case to a
    typed subclass lets the CLI ``except`` on type rather than substring-
    matching the exception message (which was brittle and locale-sensitive).
    """

    def __init__(self, *, platform: str, platform_id: str, existing_slug: str) -> None:
        self.platform = platform
        self.platform_id = platform_id
        self.existing_slug = existing_slug
        super().__init__(
            f"Platform binding ({platform}, {platform_id}) is already bound to user "
            f"'{existing_slug}'. Run `alfred user unbind {existing_slug} --platform "
            f"{platform}` first."
        )


class UserAlreadyBoundError(IdentityResolutionError):
    """Raised when ``bind(user_slug=..., platform=..., ...)`` is called on a
    user who already has a live binding for the same platform.

    Carries the user's slug + the platform name so the CLI can render a
    localised message naming both — distinct from the
    :class:`PlatformIdInUseError` case, which is about a different user
    holding the same external platform identifier.
    """

    def __init__(self, *, slug: str, platform: str) -> None:
        self.slug = slug
        self.platform = platform
        super().__init__(f"User '{slug}' is already bound on platform '{platform}'. Unbind first.")


class OperatorSlugCollisionError(CommandError):
    """Raised by migration 0004's slug pre-check if a literal user_id in episodes
    or audit_log slug-collides with an existing non-operator users row.

    Subclasses ``alembic.util.exc.CommandError`` so the migration runner reports
    it as a normal command failure (exit 1) rather than a crash, and the
    ``alembic upgrade head`` CLI surfaces the message to the operator.
    """

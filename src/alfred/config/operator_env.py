"""The operator's display name, resolved from the environment (#592).

ONE expression, TWO readers that MUST agree:

* Alembic migration ``0004`` seeds ``users.display_name`` AND the row
  ``platform_identities(platform='tui', platform_id=<display name>)`` from it —
  note the platform_id is the DISPLAY NAME, not ``derive_slug(...)`` of it;
* the TUI plugin stamps it on every inbound ``platform_user_id``, which is the
  value the host resolves that same row by.

They were two hand-copied expressions, and the TUI's was a THIRD, unrelated one:
``os.environ.get("USER")``. Docker's ``USER`` *directive* sets the process uid; it
does not inject a ``USER`` env var, so every containerised ``alfred chat``
authenticated as ``"unknown-operator"`` — a value nothing has ever bound — and the
operator's first message fell into the unbuilt Slice-5 binding flow and stopped.

Sharing one function is the point: it is not deduplication, it is the only shape in
which a test can prove the seeder and the client agree. ``docker-compose.yaml``
forwards ``ALFRED_OPERATOR_NAME: ${ALFRED_OPERATOR_NAME:-operator}`` to alfred-core,
which is the process both the ``run --rm alfred-core migrate`` and the ``run --rm
alfred-core chat`` invocations run inside — so both readers see the same value.

Blank normalisation: Compose's ``${ALFRED_OPERATOR_NAME:-operator}`` treats an EMPTY
value as unset; ``os.environ.get(name, default)`` does not. Normalising here makes the
Python layer agree with the Compose layer instead of diverging on the one input an
operator most easily produces (a bare ``ALFRED_OPERATOR_NAME=`` line in ``.env``),
which would otherwise seed ``display_name=''`` and slug ``'user'`` via
``derive_slug``'s empty-fallback. Because BOTH readers call this function, the
normalisation cannot itself create a mismatch.
"""

from __future__ import annotations

import os
from typing import Final

OPERATOR_NAME_ENV_VAR: Final[str] = "ALFRED_OPERATOR_NAME"
DEFAULT_OPERATOR_NAME: Final[str] = "operator"


def operator_display_name() -> str:
    """``$ALFRED_OPERATOR_NAME``, or ``"operator"`` when unset/blank/whitespace."""
    return os.environ.get(OPERATOR_NAME_ENV_VAR, "").strip() or DEFAULT_OPERATOR_NAME

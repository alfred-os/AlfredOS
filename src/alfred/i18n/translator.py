"""AlfredOS translator (Babel + gettext)."""

from __future__ import annotations

import gettext
import importlib.resources
import logging
import sys
from contextvars import ContextVar
from pathlib import Path

_DOMAIN = "alfred"
_LOG = logging.getLogger(__name__)

# Package-internal catalog directory. The wheel build force-includes the
# compiled ``locale/`` tree here (see pyproject.toml
# ``[tool.hatch.build.targets.wheel.force-include]``: ``locale`` → ``alfred/_locale``)
# so a ``pip install``ed alfred carries its catalogs INSIDE the package and the
# bwrap ``kind="full"`` ``/usr`` ro-bind reaches them without widening the
# sandbox. The name is underscore-prefixed so it never collides with a real
# BCP-47 ``locale`` submodule and is obviously private.
_PACKAGE_LOCALE_RESOURCE = "_locale"


def _installed_package_locale_dir() -> Path | None:
    """Return the in-package ``alfred/_locale`` dir if the wheel shipped it.

    Uses :func:`importlib.resources.files` so the lookup is correct regardless
    of how ``alfred`` was installed (editable, wheel, zip-unsafe excluded — the
    catalogs are real files). In a source checkout ``files("alfred")`` points at
    ``src/alfred`` where ``_locale`` does NOT exist (it is created only at
    wheel-build time), so this returns ``None`` and the dev candidate below
    wins; in a wheel install it resolves to the force-included catalog tree.

    Any resolution error (missing package metadata, non-path traversable
    backend) degrades to ``None`` rather than raising — a catalog probe must
    never wedge import of the translator.
    """
    try:
        resource = importlib.resources.files("alfred") / _PACKAGE_LOCALE_RESOURCE
    except (ModuleNotFoundError, TypeError):  # pragma: no cover - defensive
        return None
    candidate = Path(str(resource))
    return candidate if candidate.is_dir() else None


def _resolve_locale_dir() -> Path | None:
    """Find the first existing ``locale/`` directory across known candidates.

    The catalog ships in three physically different layouts depending on how the
    package is invoked:

    * **Development (editable install / source checkout)** — the repo root sits
      three ``parents`` up from this file (``src/alfred/i18n/translator.py``)
      and contains the canonical ``locale/`` tree.
    * **Container (``docker/alfred-core.Dockerfile``)** — the Dockerfile copies
      ``locale/`` to ``/app/locale`` next to the venv, not inside it. The old
      ``parents[3] / "locale"`` resolved to ``/app/.venv/lib/python3.12/locale``
      (devops-1 finding on PR #89), which never existed and silently degraded
      every catalog lookup to its key.
    * **Wheel install (pip install alfred under ``/usr``)** — the catalogs ship
      INSIDE the package at ``alfred/_locale`` via the wheel force-include, so
      :func:`_installed_package_locale_dir` resolves them. This is the layout the
      bwrapped quarantine child runs under (PR-S4-11c-2b0, ADR-0030): a missing
      catalog there previously DISABLED translations (operators saw raw keys).

    Returns the first existing candidate, or ``None`` if none are found (caller
    logs a warning and falls back to ``NullTranslations``).
    """
    candidates = [
        # 1. Source-checkout layout. Three parents up: translator.py → i18n →
        #    alfred → src → <repo>. Matches `uv run pytest` from the worktree
        #    and any editable install pointing at the source tree. Checked first
        #    so a dev worktree never accidentally prefers a stale installed copy.
        Path(__file__).resolve().parents[3] / "locale",
        # 2. Container layout. Hardcoded by the Dockerfile so any change here
        #    must be matched in docker/alfred-core.Dockerfile.
        Path("/app/locale"),
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    # 3. Wheel-installed layout. The catalogs ship inside the package at
    #    ``alfred/_locale`` (force-include). Resolved last so dev/container
    #    layouts keep winning, but reached for a pip-installed alfred — which
    #    has neither a source-checkout ``parents[3]/locale`` nor ``/app/locale``.
    return _installed_package_locale_dir()


def _warn_locale_missing_on_stderr() -> None:
    """Emit the missing-catalog warning, pinned to ``sys.stderr``.

    BUG-1 (PR-S4-11c-2b0): this warning fires at *import* time — before any
    entrypoint configures logging — and ``translator`` is imported transitively
    by the ``manifest_reader`` CLI whose **stdout** the launcher captures as
    bwrap flags (``--policy-to-bwrap-flags``), and by the quarantine child whose
    **stdout** carries length-prefixed JSON-RPC frames. A warning that reaches
    fd 1 corrupts both wires (it became the bwrap exec target under a
    pip-installed alfred with no shipped catalogs). stdlib's ``lastResort``
    already targets stderr, but it is global mutable state any caller can
    repoint at stdout; pinning our own :class:`logging.StreamHandler` to
    ``sys.stderr`` here makes the destination deterministic and independent of
    whatever root config the process later installs. We do NOT raise — a missing
    catalog must never wedge the CLI; the ``t()`` fallback returns the key so
    operators still see a recognisable string and developers see what to add.
    """
    record = _LOG.makeRecord(
        _LOG.name,
        logging.WARNING,
        __file__,
        0,
        "AlfredOS locale directory not found; translations disabled.",
        (),
        None,
    )
    handler = logging.StreamHandler(sys.stderr)
    handler.emit(record)


_LOCALE_DIR = _resolve_locale_dir()
if _LOCALE_DIR is None:  # pragma: no cover - import-time branch: the catalog always
    # resolves under the test/CI tree, so this arm is unreachable in the
    # coverage-counted process. ``_warn_locale_missing_on_stderr`` is unit-tested
    # directly, and the wiring is exercised in a forced-missing-locale SUBPROCESS
    # by tests/unit/quarantine/test_quarantine_child_stdout_pure.py (#237).
    _warn_locale_missing_on_stderr()

# Per-coroutine active language. ContextVar (not a plain module global) so
# concurrent handlers — Slice-2 Discord DMs, CLI commands under
# ``asyncio.gather`` — each see their own language. asyncio propagates
# ContextVars across ``await`` automatically; no handler-side bookkeeping
# required. The ``_translators`` cache below stays a module-level dict
# because ``gettext.translation`` is idempotent on ``(domain, localedir,
# languages)`` — sharing the cache across coroutines is safe and saves
# disk I/O.
_active_lang: ContextVar[str] = ContextVar("alfred_active_lang", default="en-US")
_translators: dict[str, gettext.NullTranslations] = {}


def _bcp47_to_gettext(tag: str) -> str:
    return tag.replace("-", "_").split(".")[0]


def active_babel_locale() -> str:
    """Return the ACTIVE language as a Babel-compatible locale identifier.

    Babel's ``Locale.parse`` wants the underscore form (``en_US``) and raises
    ``ValueError`` on the BCP-47 hyphen form (``en-US``) that :func:`set_language` and
    ``users.language`` carry. Callers formatting numbers/dates for operator output need
    the converted tag, so expose the same normalizer :func:`_load` already uses rather
    than each call site re-deriving it (and getting it wrong).
    """
    return _bcp47_to_gettext(_active_lang.get())


def _load(lang: str) -> gettext.NullTranslations:
    if lang in _translators:
        return _translators[lang]
    trans: gettext.NullTranslations
    if _LOCALE_DIR is None:
        trans = gettext.NullTranslations()
    else:
        try:
            trans = gettext.translation(
                _DOMAIN, localedir=str(_LOCALE_DIR), languages=[_bcp47_to_gettext(lang), "en"]
            )
        except FileNotFoundError:
            trans = gettext.NullTranslations()
    _translators[lang] = trans
    return trans


def set_language(lang: str) -> None:
    """Activate the given BCP-47 language tag for subsequent ``t()`` calls.

    Implemented as a ``ContextVar.set()`` so each coroutine sees its own
    language — asyncio propagates ContextVars across ``await`` automatically,
    so multi-user Slice-2 handlers (Discord DMs, CLI commands running under
    ``asyncio.gather``) do not cross-contaminate via a shared module global.
    """
    _active_lang.set(lang)


def t(key: str, /, **vars: object) -> str:
    """Return the translated string for `key`, substituting `vars`.

    Missing keys return the key itself — a deliberate fallback so a developer
    sees what catalog entry to add.
    """
    translator = _load(_active_lang.get())
    raw = translator.gettext(key)
    if raw == key:
        # Not found; return key as-is so missing entries are visible during development.
        return key
    try:
        return raw.format(**vars)
    except (KeyError, IndexError):
        # If substitution fails (missing variable), return the unsubstituted template.
        return raw

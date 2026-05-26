"""AlfredOS translator (Babel + gettext)."""

from __future__ import annotations

import gettext
import logging
from pathlib import Path

_DOMAIN = "alfred"
_LOG = logging.getLogger(__name__)


def _resolve_locale_dir() -> Path | None:
    """Find the first existing ``locale/`` directory across known candidates.

    The catalog ships in two physically different layouts depending on how the
    package is invoked:

    * **Development (editable install / source checkout)** — the repo root sits
      three ``parents`` up from this file (``src/alfred/i18n/translator.py``)
      and contains the canonical ``locale/`` tree.
    * **Container (``docker/alfred-core.Dockerfile``)** — the Dockerfile copies
      ``locale/`` to ``/app/locale`` next to the venv, not inside it. The old
      ``parents[3] / "locale"`` resolved to ``/app/.venv/lib/python3.12/locale``
      (devops-1 finding on PR #89), which never existed and silently degraded
      every catalog lookup to its key.

    Returns the first existing candidate, or ``None`` if none are found (caller
    logs a warning and falls back to ``NullTranslations``).
    """
    candidates = [
        # 1. Source-checkout layout. Three parents up: translator.py → i18n →
        #    alfred → src → <repo>. Matches `uv run pytest` from the worktree
        #    and any editable install pointing at the source tree.
        Path(__file__).resolve().parents[3] / "locale",
        # 2. Container layout. Hardcoded by the Dockerfile so any change here
        #    must be matched in docker/alfred-core.Dockerfile.
        Path("/app/locale"),
        # 3. Installed-package fallback. If ``alfred`` is ``pip install``ed
        #    without package_data (the current case — see pyproject.toml),
        #    ``parents[3]`` lands inside the venv at a useless path.
        #    ``parents[2]`` is the directory holding the ``alfred`` package
        #    (``site-packages``) — that's where a future install layout that
        #    drops ``locale/`` as a sibling of the package would put it.
        #    ``parents[1]`` (the prior value) only worked if catalogs were
        #    copied INTO the package; pyproject.toml doesn't do that today.
        Path(__file__).resolve().parents[2] / "locale",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


_LOCALE_DIR = _resolve_locale_dir()
if _LOCALE_DIR is None:
    # Logged once at import time. We do NOT raise — a missing catalog should
    # never wedge the CLI; the t() fallback returns the key so operators still
    # see a recognisable string and developers see what to add. The warning is
    # surfaced through stdlib logging (not structlog) because translator.py is
    # imported before _configure_logging() runs in cli/main.py.
    _LOG.warning("AlfredOS locale directory not found; translations disabled.")

_active_lang: str = "en-US"
_translators: dict[str, gettext.NullTranslations] = {}


def _bcp47_to_gettext(tag: str) -> str:
    return tag.replace("-", "_").split(".")[0]


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
    """Activate the given BCP-47 language tag for subsequent t() calls."""
    global _active_lang
    _active_lang = lang


def t(key: str, /, **vars: object) -> str:
    """Return the translated string for `key`, substituting `vars`.

    Missing keys return the key itself — a deliberate fallback so a developer
    sees what catalog entry to add.
    """
    translator = _load(_active_lang)
    raw = translator.gettext(key)
    if raw == key:
        # Not found; return key as-is so missing entries are visible during development.
        return key
    try:
        return raw.format(**vars)
    except (KeyError, IndexError):
        # If substitution fails (missing variable), return the unsubstituted template.
        return raw

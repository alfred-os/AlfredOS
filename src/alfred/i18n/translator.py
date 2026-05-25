"""AlfredOS translator (Babel + gettext)."""

from __future__ import annotations

import gettext
from pathlib import Path

_DOMAIN = "alfred"
_LOCALE_DIR = Path(__file__).resolve().parents[3] / "locale"
_active_lang: str = "en-US"
_translators: dict[str, gettext.NullTranslations] = {}


def _bcp47_to_gettext(tag: str) -> str:
    return tag.replace("-", "_").split(".")[0]


def _load(lang: str) -> gettext.NullTranslations:
    if lang in _translators:
        return _translators[lang]
    trans: gettext.NullTranslations
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

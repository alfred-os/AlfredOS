"""Verify web.fetch i18n keys are present in the catalog (spec §11.5, §7.10).

These keys are the operator-facing error / SECURITY EVENT strings raised by
``src/alfred/plugins/web_fetch/errors.py`` and ``content_store.py``. They are
load-bearing because every operator-facing string in AlfredOS MUST route
through :func:`alfred.i18n.t` (CLAUDE.md i18n hard rule #1). A missing entry
returns the bare key as the user-facing message — which is both an i18n
violation and a UX regression (the operator sees ``web.fetch.error.tls_failure``
instead of the actual TLS failure detail).

Adding a new ``t(...)`` call in this subsystem requires adding the msgid to
``locale/en/LC_MESSAGES/alfred.po`` and listing it here. The
:data:`_WEB_FETCH_KEYS` tuple is therefore the canonical contract — if the
table grows in code without a matching entry here, the catalog drift gate
(``pybabel extract`` in pre-commit) will surface it before merge.

``security.canary_tripped`` is included because :class:`WebFetchCanaryTripped`
shares the key with ``stdio_transport.py`` (same SECURITY EVENT family);
spec §7.6 / §12.4 treats it as part of the web.fetch trust-boundary surface.
"""

from __future__ import annotations

import pytest

# Canonical web.fetch i18n keys. Order mirrors errors.py declaration order
# so a reviewer scanning the two side-by-side can spot a missing entry
# without re-sorting. ``content_handle_expired`` is the content_store.py
# entry; ``security.canary_tripped`` is the cross-subsystem SECURITY EVENT.
_WEB_FETCH_KEYS: tuple[str, ...] = (
    "web.fetch.error.content_handle_expired",
    "web.fetch.error.domain_not_allowed",
    "web.fetch.error.redirect_refused",
    "web.fetch.error.tls_failure",
    "web.fetch.error.rate_limited",
    "web.fetch.error.mime_type_not_allowed",
    "web.fetch.error.size_limit_exceeded",
    "security.canary_tripped",
)


@pytest.mark.parametrize("key", _WEB_FETCH_KEYS)
def test_i18n_key_resolves(key: str) -> None:
    """Key must resolve to a non-empty translated string (not the bare key).

    :func:`alfred.i18n.t` returns the bare key when the catalog has no
    msgstr — that fallback is deliberate so missing entries are visible
    during development, but it must never ship. The assertion below pins
    the contract: every web.fetch key has a non-empty msgstr in the
    compiled ``.mo`` catalog.

    The ``**kwargs`` carries placeholders for every key in the table —
    keys that don't reference a given placeholder simply ignore it; keys
    that DO reference one (e.g. ``redirect_refused`` needs ``status_code``
    + ``redirect_target``) get the value they need. Passing the union
    avoids per-key kwarg tables which would drift faster than this single
    fixture.
    """
    from alfred.i18n import t

    result = t(
        key,
        # Placeholders used by one or more keys in _WEB_FETCH_KEYS. Adding
        # a new key with a new placeholder requires extending this dict.
        domain="example.com",
        url="https://example.com/",
        detail="test",
        bucket="per_domain",
        mime_type="application/pdf",
        size=1000,
        limit=5000,
        handle_id="wf_test_handle",
        status_code=301,
        redirect_target="https://internal.example.com/",
    )
    # If key is missing from catalog, t() returns the bare key string.
    # A properly defined key returns a translated string that is NOT the
    # bare key. Empty msgstr also surfaces as the bare key per gettext
    # convention.
    assert result != key, (
        f"i18n key {key!r} is missing from catalog "
        "or has an empty msgstr — add/fill it in locale/en/LC_MESSAGES/"
        "alfred.po and run `pybabel compile -d locale -D alfred` "
        "(CLAUDE.md i18n hard rule #1; spec §11.5)"
    )
    assert result.strip(), (
        f"i18n key {key!r} resolved to a whitespace-only string — "
        "msgstr is present but empty after substitution; fix the "
        "msgstr in locale/en/LC_MESSAGES/alfred.po."
    )

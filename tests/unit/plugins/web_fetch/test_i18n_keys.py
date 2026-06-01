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
    # Slice-3 retrospective fix i18n-003 — TlsPolicy.__post_init__ refusal
    # message. Lives in tls_policy.py rather than errors.py because the
    # raise happens at policy-construction time (config validation), not
    # at fetch time. The key is in the web.fetch.tls.* namespace to keep
    # the policy-validation surface distinct from the operational
    # WebFetchError tree.
    "web.fetch.tls.skip_refused_in_non_dev",
    # C3 / i18n-001 — fetch_dispatcher.py unexpected-dispatch-shape
    # WebFetchError carrier. The Python type name of the bad result
    # flows through ``{shape}``; the operator-facing wording is in the
    # catalog.
    "web.fetch.error.unexpected_dispatch_shape",
    # C4 / i18n-002 — fetch_dispatcher.py generic WebFetchError fallback
    # when the plugin returns a structured error envelope without a
    # known ``type`` tag. The plugin-supplied detail flows through
    # ``{message}``.
    "web.fetch.error.plugin_returned_message",
    # sec-pr-s3-5-003 / H3 — host-IP allowlist guard against DNS-rebinding
    # / cloud-metadata SSRF. The exception carries ``{url}`` and
    # ``{resolved_ip}`` placeholders; the refusal-class reason
    # vocabulary (rfc1918 / link_local / loopback / multicast /
    # reserved / dns_failure / no_hostname) is the audit-row pivot.
    "web.fetch.error.internal_ip_refused",
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
        # i18n-003 — TlsPolicy refusal carries the offending env name so
        # the operator sees what the process actually read.
        env="staging",
        # C3 / C4 — unexpected-dispatch-shape carries the Python type
        # name; the plugin-returned-message carrier surfaces the
        # plugin-side detail string verbatim through ``{message}``.
        shape="ExtractionResult",
        message="DNS resolution failed",
        # sec-pr-s3-5-003 — internal_ip_refused carries the resolved
        # IP through ``{resolved_ip}`` so operators can correlate with
        # what the resolver returned at refusal time.
        resolved_ip="10.0.0.1",
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


# devex-003 — operator-facing refusal messages MUST name the remediation
# lever, not just the problem. An operator who sees "rate limit exceeded"
# without knowing where the cap is configured cannot act; the message has
# diagnosed the symptom but withheld the fix. The contract below pins the
# substring that identifies the config knob — if a future i18n re-phrase
# drops the pointer, the test surfaces it before merge.
#
# Each key maps to a tuple of substrings that must all appear in the
# rendered message. ``config/policies.yaml`` anchors the file the operator
# edits; the YAML path (``web_fetch.<knob>``) anchors which line.
_REMEDIATION_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "web.fetch.error.rate_limited",
        ("config/policies.yaml", "web_fetch.rate_limits"),
    ),
    (
        "web.fetch.error.mime_type_not_allowed",
        ("config/policies.yaml", "web_fetch.allowed_mime_types"),
    ),
    (
        "web.fetch.error.size_limit_exceeded",
        ("config/policies.yaml", "web_fetch.size_limit_bytes"),
    ),
)


@pytest.mark.parametrize(("key", "hints"), _REMEDIATION_HINTS)
def test_error_message_names_remediation_lever(key: str, hints: tuple[str, ...]) -> None:
    """Refusal message points at the config knob the operator can tune.

    The operator-facing surface for a web.fetch refusal is the only
    actionable signal an operator gets — the message must answer both
    "what happened" AND "where do I change it". Naming the YAML file +
    the specific knob lets the operator jump straight to the edit;
    naming only the symptom forces them to dig through PRD / runbook /
    source. devex-003 review finding (Slice-3 PR-S3-5).
    """
    from alfred.i18n import t

    result = t(
        key,
        # Union of placeholders used by the three keys under test.
        bucket="per_domain",
        mime_type="application/pdf",
        size=1000,
        limit=5000,
    )
    for hint in hints:
        assert hint in result, (
            f"i18n key {key!r} renders without remediation hint {hint!r} — "
            f"operator-facing refusal must name where the lever lives "
            f"(devex-003). Got: {result!r}"
        )

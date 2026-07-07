"""Verify web.fetch i18n keys are present, correct, and fully substituted.

These keys are the operator-facing error / SECURITY EVENT strings raised by
``src/alfred/plugins/web_fetch/errors.py`` and ``content_store.py``. They are
load-bearing because every operator-facing string in AlfredOS MUST route
through :func:`alfred.i18n.t` (CLAUDE.md i18n hard rule #1). A missing entry
returns the bare key as the user-facing message — which is both an i18n
violation and a UX regression (the operator sees ``web.fetch.error.tls_failure``
instead of the actual TLS failure detail).

**Why per-key fingerprints, not just ``result != key``** (i18n-004 / H5
review finding, corroborated by test-engineer-001).

The earlier shape of this test asserted only that ``t(key) != key``. That
caught a missing msgstr but it did NOT catch a pybabel **fuzzy-match
wrong-msgstr swap** — a real-world failure mode where the build tool
copies a similar-looking neighbouring msgstr onto a new msgid. The first
occurrence of this in the slice was ``web.fetch.error.redirect_refused``:
pybabel populated it with the ``tls_failure`` body, the assertion still
passed (the result was non-empty and not the bare key), and the broken
string only surfaced when an operator hit a real redirect.

The per-key fingerprint table below pins each key to a distinctive
substring that the *correct* msgstr must contain. A fuzzy-match swap
between two keys puts the wrong body under a msgid; the fingerprint
specific to the swapped-FROM key is absent from the swapped-TO render;
the test fails. Coupled with the placeholder-leak check (no ``{`` /
``}`` survives substitution), this defends against both pybabel drift
and accidentally-untemplated msgstr.

Adding a new ``t(...)`` call in this subsystem requires three edits:
adding the msgid to ``locale/en/LC_MESSAGES/alfred.po`` with a REAL
msgstr (not a pybabel fuzzy-copy of a neighbour), running
``pybabel update`` + ``pybabel compile``, and adding a row to
:data:`_FINGERPRINTS` below.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

import pytest

# Per-key fingerprint table. Each entry pins:
#   - the placeholder kwargs the msgstr template needs (so str.format
#     succeeds and no ``{name}`` literal survives in the output);
#   - one or more EXPECTED SUBSTRINGS — at least one must appear in the
#     rendered result, anchoring the test to *this* msgstr's semantics
#     and not a fuzzy-match neighbour's.
#
# Substrings are matched case-insensitively (against ``result.lower()``)
# so a future capitalisation re-phrase ("TLS" → "tls") doesn't fail the
# test for a non-substantive reason. The substrings themselves are
# already lowercase below.
#
# The fingerprint vocabulary deliberately points at the load-bearing
# nouns of each msgstr — what a reviewer scanning a wrong fuzzy-swap
# would notice missing. e.g. ``rate_limited`` fingerprints on
# "rate limit" and "web_fetch.rate_limits": both anchor the message
# semantically AND structurally to the rate-limit subsystem; the
# tls_failure body contains neither, so a fuzzy swap surfaces.
_FINGERPRINTS: Final[dict[str, tuple[Mapping[str, object], tuple[str, ...]]]] = {
    # PR4b-audit (#339, #347 blocker 2): the action-deadline timeout body is
    # intentionally payload-blind (no egress_id / destination_host) — audit
    # hygiene, see WebFetchActionTimeout's docstring. Fingerprint anchors on
    # "deadline" so a fuzzy swap with a neighbouring body surfaces.
    "web.fetch.error.action_timeout": ({}, ("deadline",)),
    "web.fetch.error.content_handle_expired": (
        {"handle_id": "wf_test_handle"},
        ("handle", "expired"),
    ),
    "web.fetch.error.domain_not_allowed": (
        {"domain": "example.com"},
        ("allowlist", "domain"),
    ),
    # G7-2.5 Task K (#333): ``web.fetch.error.redirect_refused`` was removed —
    # ``WebFetchRedirectRefused`` is deleted (no live raiser after the re-home);
    # redirects are now refused gateway-side
    # (``EgressRelayDenyReason.UPSTREAM_REDIRECT_REFUSED``), so the in-core key is
    # obsolete.
    "web.fetch.error.rate_limited": (
        {"bucket": "per_domain"},
        ("rate limit", "per_domain"),
    ),
    # G7-2.5 Task K (#333): ``web.fetch.error.mime_type_not_allowed`` and
    # ``web.fetch.error.size_limit_exceeded`` were removed —
    # ``WebFetchMimeTypeNotAllowed`` / ``WebFetchSizeLimitExceeded`` are deleted
    # (no live raiser after the re-home; the MIME/size refusals are now
    # ``TypedRefusal(cannot_extract)`` from the C2 D1 ``response_inspection`` seam),
    # so their attacker-``{mime_type}``-interpolating t() keys are obsolete.
    "security.canary_tripped": (
        {"url": "https://example.com/"},
        ("canary",),
    ),
    # G7-2.5 Task 7 (#333): ``web.fetch.error.internal_ip_refused`` was removed —
    # ``WebFetchInternalIPRefused`` class is deleted; the SSRF guard now lives in
    # the gateway egress relay (``EgressRelayDenyReason.RESOLVED_IP_NOT_GLOBAL``);
    # the connectivity-free core (Spec C) no longer resolves DNS or raises this
    # in-core exception.
    # G7-2.5 Task 7 (#333): ``web.fetch.error.tls_failure`` was removed —
    # ``WebFetchTlsError`` class is deleted; TLS now originates at the gateway
    # relay (G7-2b), so the in-core TLS exception no longer exists.
    # G7-2.5 Task 7 (#333): ``web.fetch.tls.skip_refused_in_non_dev`` was
    # removed — ``tls_policy.py`` (its only t() call site) is deleted; TLS now
    # originates at the gateway, so the in-core TlsPolicy refusal no longer exists.
    # G7-2.5 Task 6 (#333): ``web.fetch.error.unexpected_dispatch_shape`` and
    # ``web.fetch.error.plugin_returned_message`` were removed — the re-homed
    # dispatcher no longer drives a plugin subprocess (no ControlResult /
    # dispatch-shape arms), so those t() call sites (and their catalog entries)
    # are gone.
    # G7-2.5 Task 6 (#333): ``web.fetch.error.dispatch_param_invalid`` was
    # removed — the re-homed dispatcher no longer constructs
    # ``WebFetchDispatchParams`` (no host-side param-validation arm), so its
    # t() call site (and catalog entry) are gone.
    "web.fetch.error.url_secret_refused": (
        # G7-2.5 Task 6 (#333) — the re-homed dispatcher's refuse-on-secret
        # arm: the outbound DLP redacted the request URL, so it carries a
        # secret. Payload-blind (NO url / NO secret in the surface) — the
        # message names the symptom + the audit-log invocation that surfaces
        # the closed-vocabulary tag.
        {},
        ("secret", "dlp"),
    ),
    # #339 PR4b-broker Task 3 (ADR-0048): Step 1b's raw-secret-in-header
    # defence. Payload-blind (NO header name / NO secret in the surface) — the
    # message names the symptom + the actionable fix (use the broker instead
    # of sending the raw value) + (PR #403 review) the same audit-log
    # breadcrumb the substitution-refusal msgstr carries, for consistency.
    "web.fetch.error.header_secret_refused": (
        {},
        ("header", "broker"),
    ),
    # #339 PR4b-broker Task 3 (ADR-0048): Step 1c's off-allowlist /
    # unprovisioned {{secret:*}} substitution refusal. Payload-blind (NO
    # secret name in the surface — see the FIX-8 `from None` no-leak test in
    # test_fetch_dispatcher.py) — the message names the symptom + points at
    # the audit-log breadcrumb (PR #403 review: the earlier "ask an operator
    # to allowlist it" wording was a dead end — no operator lever for the
    # auth-secret allowlist exists this release, and "allowlist" collides
    # with the unrelated `alfred web allowlist add` domain command).
    "web.fetch.error.secret_substitution_refused": (
        {},
        ("audit log", "permitted"),
    ),
}


@pytest.mark.parametrize("key", sorted(_FINGERPRINTS.keys()))
def test_i18n_key_resolves_with_fingerprint(key: str) -> None:
    """Key resolves to a non-empty, fully-substituted, semantically-correct string.

    Three checks, each defending a different failure mode:

    1. ``result != key`` — guards against a missing/empty msgstr (gettext
       falls back to the bare key when there is no translation).
    2. No ``{`` or ``}`` survives in the output — guards against an
       msgstr that references a placeholder we forgot to supply or one
       that the template authored with the wrong name. The earlier
       ``except (KeyError, IndexError)`` swallow in :func:`alfred.i18n.t`
       returns the un-substituted template on missing kwargs, so a
       surviving ``{`` reveals a placeholder mismatch even when the
       runtime doesn't raise.
    3. At least one fingerprint substring is present — guards against
       a pybabel fuzzy-match wrong-msgstr swap (the i18n-004 / H5
       failure mode this test was rewritten to catch).

    Together they pin the key to its own msgstr, not just to *some*
    non-empty msgstr.
    """
    from alfred.i18n import t

    placeholders, fingerprints = _FINGERPRINTS[key]
    result = t(key, **placeholders)

    # (1) Catalog presence: missing msgid OR empty msgstr surfaces as the
    # bare key per gettext convention.
    assert result != key, (
        f"i18n key {key!r} is missing from catalog or has an empty msgstr — "
        "add/fill it in locale/en/LC_MESSAGES/alfred.po and run "
        "`pybabel compile -d locale -D alfred` "
        "(CLAUDE.md i18n hard rule #1; spec §11.5)"
    )
    assert result.strip(), (
        f"i18n key {key!r} resolved to a whitespace-only string — "
        "msgstr is present but empty after substitution; fix the "
        "msgstr in locale/en/LC_MESSAGES/alfred.po."
    )

    # (2) Placeholder-leak guard: ``t()`` returns the unsubstituted
    # template on KeyError/IndexError. A surviving ``{`` / ``}`` reveals
    # either a placeholder we didn't provide above (missing test kwarg)
    # or a typo in the catalog template (e.g. ``{handel_id}``).
    assert "{" not in result and "}" not in result, (
        f"i18n key {key!r} rendered with un-substituted placeholders — "
        f"either the test kwargs in _FINGERPRINTS[{key!r}] are missing a "
        f"placeholder, or the msgstr template references a name that "
        f"errors.py doesn't pass. Got: {result!r}"
    )

    # (3) Fingerprint check — the canonical defence against pybabel
    # fuzzy-match wrong-msgstr swap (i18n-004 / H5). At least one
    # distinctive substring from the *correct* msgstr must appear.
    lowered = result.lower()
    assert any(fp in lowered for fp in fingerprints), (
        f"i18n key {key!r} rendered without any expected fingerprint — "
        f"pybabel fuzzy-match may have swapped the wrong msgstr onto "
        f"this key (i18n-004). Expected one of {fingerprints!r}; "
        f"got: {result!r}"
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
# edits; the YAML path (``web_fetch.<knob>``) anchors which line. Not every
# lever is a YAML knob, though: the two #339 PR4b-broker entries below name a
# non-YAML remediation lever instead — an architectural fix (use the broker)
# for the header case, or the audit-log breadcrumb (`alfred audit log
# --event tool.web.fetch`) for the substitution case — since
# ``WEB_FETCH_AUTH_SECRET_ALLOWLIST`` ships as a closed, empty, non-operator-
# configurable Python constant in #339 (no YAML surface, and no operator
# lever, exists to point at this release; PR #403 review dropped the earlier
# "ask an operator to allowlist it" wording, which named a lever that does
# not exist and collided with the unrelated `alfred web allowlist add`
# domain-allowlist command).
_REMEDIATION_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "web.fetch.error.rate_limited",
        ("config/policies.yaml", "web_fetch.rate_limits"),
    ),
    # G7-2.5 Task K (#333): the mime_type_not_allowed / size_limit_exceeded
    # remediation pins were removed with their (now-deleted) error classes —
    # the MIME/size refusals are gateway-/D1-side TypedRefusals, not in-core keys.
    (
        "web.fetch.error.header_secret_refused",
        ("broker",),
    ),
    (
        "web.fetch.error.secret_substitution_refused",
        ("audit log",),
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

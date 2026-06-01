"""Plugin error hierarchy — PR-S3-3a Task 1 (spec §4, ADR-0017 Decision 6).

The hierarchy is the single import surface for every Slice-3 plugin module that
needs to raise or catch a plugin-domain error. ``PluginError`` is the root and
descends from :class:`alfred.errors.AlfredError` so the CLI top-level dispatch
catches it uniformly without swallowing unrelated exceptions.

The intermediate parents (``ManifestError``, ``PluginTransportError``,
``PluginInvocationError``) exist so callers can ``except ManifestError`` and
catch every manifest-rejection shape without re-listing each leaf. Spec §10
expects these intermediates to be stable across Slice 3 PRs.

``QuarantinedUnavailable`` lives here per ADR-0017 Decision 6 (resolves the
spec §5.5 vs §10.1 contradiction) — the supervisor re-exports it for
ergonomic import in PR-S3-3b but the *definition* is here.
"""

from __future__ import annotations

import pytest

from alfred.errors import AlfredError
from alfred.plugins.errors import (
    DlpOutboundRefusedError,
    ManifestError,
    ManifestTierError,
    ManifestVersionError,
    PluginError,
    PluginInvocationError,
    PluginProtocolViolation,
    PluginTransportError,
    QuarantinedUnavailable,
)

# ---------------------------------------------------------------------------
# Root identity — every plugin error must descend from AlfredError so the
# CLI top-level dispatch and orchestrator catch arms catch them uniformly.
# ---------------------------------------------------------------------------


def test_plugin_error_is_alfred_error() -> None:
    assert issubclass(PluginError, AlfredError)


# ---------------------------------------------------------------------------
# Intermediate parents — callers should be able to ``except ManifestError``
# or ``except PluginTransportError`` and catch every leaf shape underneath.
# ---------------------------------------------------------------------------


def test_manifest_error_is_plugin_error() -> None:
    assert issubclass(ManifestError, PluginError)


def test_plugin_transport_error_is_plugin_error() -> None:
    assert issubclass(PluginTransportError, PluginError)


def test_plugin_invocation_error_is_plugin_error() -> None:
    assert issubclass(PluginInvocationError, PluginError)


def test_quarantined_unavailable_is_plugin_error() -> None:
    # ADR-0017 Decision 6: QuarantinedUnavailable lives in plugins/errors.py,
    # not supervisor/errors.py. Supervisor re-exports for ergonomic import.
    assert issubclass(QuarantinedUnavailable, PluginError)


# ---------------------------------------------------------------------------
# Manifest leaves — both descend from ManifestError so callers can catch the
# parent without enumerating leaf cases.
# ---------------------------------------------------------------------------


def test_manifest_version_error_is_manifest_error() -> None:
    assert issubclass(ManifestVersionError, ManifestError)


def test_manifest_tier_error_is_manifest_error() -> None:
    assert issubclass(ManifestTierError, ManifestError)


# ---------------------------------------------------------------------------
# Transport leaves — both descend from PluginTransportError.
# ---------------------------------------------------------------------------


def test_plugin_protocol_violation_is_transport_error() -> None:
    assert issubclass(PluginProtocolViolation, PluginTransportError)


def test_dlp_outbound_refused_is_transport_error() -> None:
    # arch-006 / err-011: DLP refusal is a distinct transport leaf so operators
    # reading audit logs can tell DLP refusals apart from sandbox failures and
    # manifest rejections.
    assert issubclass(DlpOutboundRefusedError, PluginTransportError)


# ---------------------------------------------------------------------------
# Constructor contract — leaves carry the structured attributes the audit log
# and downstream catch sites depend on.
# ---------------------------------------------------------------------------


def test_manifest_version_error_carries_got_and_expected() -> None:
    exc = ManifestVersionError(got=2, expected=1)
    assert exc.got == 2
    assert exc.expected == 1
    assert "2" in str(exc) or len(str(exc)) > 0


def test_manifest_version_error_default_expected_is_one() -> None:
    # Slice-3 pins manifest_version to 1 (ADR-0017 Decision 7).
    exc = ManifestVersionError(got=99)
    assert exc.expected == 1


def test_manifest_tier_error_uses_distinct_i18n_key() -> None:
    # arch-007: ManifestTierError must NOT reuse the version-mismatch i18n key.
    # The two errors have different numeric/string formatting semantics across
    # languages, and the tier value MUST be carried on the exception attribute.
    exc = ManifestTierError("T3")
    assert exc.tier == "T3"
    # The message must not claim the cause was a version-integer mismatch.
    assert "version" not in str(exc).lower() or "T3" in str(exc)


def test_dlp_outbound_refused_carries_plugin_id_and_rule() -> None:
    exc = DlpOutboundRefusedError(plugin_id="alfred.test", rule_matched="secret_pattern")
    assert exc.plugin_id == "alfred.test"
    assert exc.rule_matched == "secret_pattern"


def test_plugin_protocol_violation_carries_method_and_plugin_id() -> None:
    exc = PluginProtocolViolation(method="alfred/hooks.register", plugin_id="alfred.bad")
    assert exc.method == "alfred/hooks.register"
    assert exc.plugin_id == "alfred.bad"


def test_quarantined_unavailable_carries_reason() -> None:
    exc = QuarantinedUnavailable(reason="subprocess crashed")
    assert exc.reason == "subprocess crashed"


def test_plugin_invocation_error_carries_method_and_detail() -> None:
    exc = PluginInvocationError(method="web.fetch", detail="upstream timeout")
    assert exc.method == "web.fetch"
    assert exc.detail == "upstream timeout"


# ---------------------------------------------------------------------------
# Catchability — every error is a real BaseException so callers can use it in
# pytest.raises without typing gymnastics.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc_cls,kwargs",
    [
        (ManifestVersionError, {"got": 2}),
        (ManifestTierError, {"tier": "T3"}),
        (PluginProtocolViolation, {"method": "x", "plugin_id": "y"}),
        (DlpOutboundRefusedError, {"plugin_id": "p", "rule_matched": "r"}),
        (QuarantinedUnavailable, {"reason": "down"}),
        (PluginInvocationError, {"method": "m", "detail": "d"}),
    ],
)
def test_every_leaf_can_be_raised_and_caught_as_plugin_error(
    exc_cls: type[PluginError], kwargs: dict[str, object]
) -> None:
    with pytest.raises(PluginError):
        raise exc_cls(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# i18n-001 — three error leaves previously bypassed t(). After the
# retrospective fix, every message resolves via the catalog. These tests
# pin that the catalog-resolved message carries the operator-facing
# prefix from locale/en/LC_MESSAGES/alfred.po, so a regression that
# reverts to raw f-strings shows up immediately.
# ---------------------------------------------------------------------------


def test_plugin_invocation_error_message_resolves_via_catalog() -> None:
    exc = PluginInvocationError(method="web.fetch", detail="upstream timeout")
    msg = str(exc)
    # The catalog prefix is the operator-facing wording from
    # locale/en/LC_MESSAGES/alfred.po. A raw f-string regression would
    # start with the lower-case "plugin invocation failed" wording.
    assert msg.startswith("Plugin invocation failed"), msg
    assert "web.fetch" in msg
    assert "upstream timeout" in msg


def test_quarantined_unavailable_message_resolves_via_catalog() -> None:
    exc = QuarantinedUnavailable(reason="subprocess crashed")
    msg = str(exc)
    assert msg.startswith("Quarantined LLM unavailable"), msg
    assert "subprocess crashed" in msg


def test_plugin_protocol_violation_message_resolves_via_catalog() -> None:
    exc = PluginProtocolViolation(method="alfred/hooks.register", plugin_id="alfred.bad")
    msg = str(exc)
    # Catalog wording mentions the plugin id + the disallowed method.
    assert "alfred.bad" in msg
    assert "alfred/hooks.register" in msg
    # Negative: the previous raw-f-string wording was lower-case "protocol
    # violation from"; the catalog-rendered version is sentence-cased.
    assert not msg.startswith("protocol violation from"), msg

"""Public ``alfred.plugins`` surface is stable across PR-S3-3a → downstream PRs.

Downstream consumers (PR-S3-3b supervisor, PR-S3-4 quarantined LLM,
PR-S3-5 web.fetch, every plugin author writing against the SDK)
import from ``alfred.plugins`` directly. A renamed or dropped symbol
is a breaking change that must go through an ADR per the module
docstring.

These tests pin:

* Every symbol in ``__all__`` is importable from the package.
* Every symbol resolves to the same object the leaf module exposes
  (no shadow re-export).
* ``__all__`` has no duplicate entries.
* The exact set of public names matches the PR contract.

Sort ordering is left to ``ruff``'s ``RUF022`` rule (it uses its own
"natural sort" semantics — uppercase-snake before mixed-case — which
diverges from :func:`sorted`'s ASCII order; reproducing that here
would be a hard-coded re-implementation of an external lint rule).

A new symbol added to the package's public surface lands in three
places (the leaf module's ``__all__``, this package's ``__all__``,
and a check below) — the friction is intentional, downstream
consumers depending on these names should not see them disappear
silently.
"""

from __future__ import annotations

import importlib

import alfred.plugins as pkg


def test_all_listed_symbols_importable() -> None:
    """Every symbol named in ``__all__`` actually exists on the package."""
    for name in pkg.__all__:
        assert hasattr(pkg, name), f"alfred.plugins.__all__ names {name!r} but it is not exported"


def test_no_duplicate_entries() -> None:
    """``__all__`` has no duplicate entries.

    A duplicate is a silent re-export attempt that would obscure a
    real surface change in code review.
    """
    assert len(pkg.__all__) == len(set(pkg.__all__))


def test_re_exports_are_same_object_as_leaf() -> None:
    """Each re-exported symbol is the SAME object the leaf module exposes.

    A regression that accidentally re-binds a name (e.g. wraps a
    Protocol with ``runtime_checkable`` at the package level after the
    leaf already did so) would create two distinct ``isinstance``
    targets and break downstream type-narrowing.
    """
    leaf_modules: dict[str, list[str]] = {
        "alfred.plugins.transport": ["ControlResult", "DispatchResult", "PluginTransport"],
        "alfred.plugins.errors": [
            "DlpOutboundRefusedError",
            "ManifestError",
            "ManifestTierError",
            "ManifestVersionError",
            "PluginError",
            "PluginInvocationError",
            "PluginProtocolViolation",
            "PluginTransportError",
            "QuarantinedUnavailable",
        ],
        "alfred.plugins.manifest": ["PluginManifest", "parse_manifest"],
        "alfred.plugins.session": ["AlfredPluginSession"],
        "alfred.plugins.inbound_scanner": ["CanaryTrip", "InboundContentScanner"],
        "alfred.plugins.content_store_base": [
            "ContentStoreBase",
            "InMemoryContentStore",
            "InMemoryContentStoreProductionError",
        ],
        "alfred.plugins.stdio_transport": [
            "CanaryTripSecurityEvent",
            "NonceNotConfigured",
            "PluginProtocolError",
            "StdioTransport",
        ],
        "alfred.plugins._observability": [
            "DISPATCH_DURATION",
            "INBOUND_SCANNER_SCAN_DURATION",
            "OUTBOUND_DLP_SCAN_DURATION",
            "PLUGIN_SPAWN_DURATION",
        ],
    }
    for module_path, names in leaf_modules.items():
        module = importlib.import_module(module_path)
        for name in names:
            assert getattr(pkg, name) is getattr(module, name), (
                f"alfred.plugins.{name} is not the same object as {module_path}.{name}"
            )


def test_expected_surface_present() -> None:
    """Pin the exact set of public names this PR ships.

    PR-S3-3a's contract with PR-S3-3b/4/5 is this exact set. A future
    PR that lands a new symbol should update this set deliberately
    (and bump the contract version in CHANGELOG); a typo'd or
    accidentally-removed name should NOT update this set silently.
    """
    expected = frozenset(
        {
            "DISPATCH_DURATION",
            "INBOUND_SCANNER_SCAN_DURATION",
            "OUTBOUND_DLP_SCAN_DURATION",
            "PLUGIN_SPAWN_DURATION",
            "AlfredPluginSession",
            "CanaryTrip",
            "CanaryTripSecurityEvent",
            "ContentStoreBase",
            "ControlResult",
            "DispatchResult",
            "DlpOutboundRefusedError",
            "InMemoryContentStore",
            "InMemoryContentStoreProductionError",
            "InboundContentScanner",
            "ManifestError",
            "ManifestTierError",
            "ManifestVersionError",
            "NonceNotConfigured",
            "PluginError",
            "PluginInvocationError",
            "PluginManifest",
            "PluginProtocolError",
            "PluginProtocolViolation",
            "PluginTransport",
            "PluginTransportError",
            "QuarantinedUnavailable",
            "StdioTransport",
            "parse_manifest",
        }
    )
    assert frozenset(pkg.__all__) == expected

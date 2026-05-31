"""AlfredOS plugin transport layer (spec §4, ADR-0017).

PR-S3-3a lands the full surface: the error hierarchy, the
``PluginTransport`` Protocol, the ``PluginManifest`` parser, the
``InboundContentScanner``, the ``ContentStoreBase`` Protocol + in-memory
stub, the ``StdioTransport`` implementation, and the
``AlfredPluginSession`` handshake/lifecycle orchestrator.

Every symbol exported here is a stable contract for downstream PRs
(PR-S3-3b supervisor, PR-S3-4 quarantined LLM, PR-S3-5 web.fetch). Adding
new symbols to ``__all__`` is fine; removing or renaming one is a
breaking change that must go through an ADR.

The :data:`__all__` list is kept in ``ruff``'s ``RUF022`` natural sort
order (uppercase-snake first, then alphabetical) so a missing entry
surfaces visually in code review and the sort-check catches unsorted
additions on the lint pass.

Re-exports use *relative* imports (per the PR-S3-1 CR R2 finding —
relative-from-`__init__` keeps the public surface decoupled from the
package path, lets the package be vendored under a different name
without rewrites, and makes it impossible for a downstream consumer
to import an internal that we did not re-export by name).
"""

from __future__ import annotations

from ._observability import (
    DISPATCH_DURATION,
    INBOUND_SCANNER_SCAN_DURATION,
    OUTBOUND_DLP_SCAN_DURATION,
    PLUGIN_SPAWN_DURATION,
)
from .content_store_base import ContentStoreBase, InMemoryContentStore
from .errors import (
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
from .inbound_scanner import CanaryTrip, InboundContentScanner
from .manifest import PluginManifest, parse_manifest
from .session import AlfredPluginSession
from .stdio_transport import (
    CanaryTripSecurityEvent,
    NonceNotConfigured,
    PluginProtocolError,
    StdioTransport,
)
from .transport import ControlResult, DispatchResult, PluginTransport

__all__ = [
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
]

"""AlfredOS plugin transport layer (spec §4, ADR-0017).

PR-S3-3a lands the foundation pieces — error hierarchy, ``PluginTransport``
Protocol, ``PluginManifest`` parser, ``InboundContentScanner``, and the
``ContentStoreBase`` Protocol with an in-memory stub. Subsequent PR-S3-3a
tasks layer ``StdioTransport`` and ``AlfredPluginSession`` on top.

Every symbol exported here is a stable contract for downstream PRs
(PR-S3-3b supervisor, PR-S3-4 quarantined LLM, PR-S3-5 web.fetch). Adding
new symbols to ``__all__`` is fine; removing or renaming one is a breaking
change that must go through an ADR.
"""

from __future__ import annotations

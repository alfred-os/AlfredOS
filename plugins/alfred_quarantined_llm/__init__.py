"""Quarantined-LLM plugin package (PR-S3-4, spec §5.1).

The quarantined LLM is the privileged-host subprocess that ingests T3
content via ``quarantine.ingest`` and emits structured ``ExtractionResult``
values via ``quarantine.extract``. It is the ONLY component allowed to
process raw T3 content; the orchestrator never sees the bytes.

This ``__init__.py`` is a package marker. The MCP entry point lives in
:mod:`plugins.alfred_quarantined_llm.quarantine_plugin`. The provider-
dispatch helpers (capability-branched ``native_constrained`` /
``json_object_unconstrained`` / ``prompt_embedded_fallback`` paths) live
in :mod:`plugins.alfred_quarantined_llm.provider_dispatch` and are
module-private (consumed by the plugin entry point only — orchestrator-
side callers go through :class:`alfred.plugins.quarantine_extractor.
QuarantinedExtractor`).
"""

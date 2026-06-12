"""Quarantined-LLM child package (PR-S3-4, spec §5.1; #237 / ADR-0030).

The quarantined LLM is the privileged-host subprocess that ingests T3
content via ``quarantine.ingest`` and emits structured ``ExtractionResult``
values via ``quarantine.extract``. It is the ONLY component allowed to
process raw T3 content; the orchestrator never sees the bytes.

**Wheel co-location (PR-S4-11c-2b0, ADR-0030).** This package ships IN the
installed ``alfred`` wheel (``src/alfred/security/quarantine_child``) so its
code is reachable under the bwrap ``kind="full"`` policy's ``/usr`` ro-bind
(site-packages) — the prior repo-root ``plugins/alfred_quarantined_llm`` home
was wheel-excluded and unreachable inside the sandbox. The child is spawned via
``python -m alfred.security.quarantine_child`` (``__main__.py``).

This ``__init__.py`` is a package marker. The MCP entry point lives in
:mod:`alfred.security.quarantine_child.__main__`. The provider-dispatch helpers
(capability-branched ``native_constrained`` / ``json_object_unconstrained`` /
``prompt_embedded_fallback`` paths) live in
:mod:`alfred.security.quarantine_child.provider_dispatch` and are module-private
(consumed by the child entry point only — orchestrator-side callers go through
:class:`alfred.security.quarantine.QuarantinedExtractor`).
"""

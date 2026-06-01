"""Provider dispatch for the quarantined-LLM extractor (PR-S3-4 Task 4).

Slice-3 skeleton: this module exposes :func:`dispatch_extraction` as the
single seam between :func:`plugins.alfred_quarantined_llm.quarantine_
plugin.handle_extract` and the capability-branched provider routing.

Task 4 lands the bare delegation contract — the function exists, is
async, accepts the documented kwargs, and returns the result-shape
:class:`alfred.security.quarantine.ExtractionResult` serialises to
(``{"kind": "extracted", ...}`` or ``{"kind": "typed_refusal",
"reason": ...}``).

Task 5 (next commit) replaces the stub body with the three-branch
capability dispatch (NATIVE_CONSTRAINED_GENERATION → Anthropic tool-use
shape; JSON_OBJECT_MODE → DeepSeek response_format; neither →
prompt_embedded_fallback) plus the ``sanitize_validator_error`` helper
and the retry-exhaustion contract. Keeping the seam stable in Task 4
means Task 5 is a pure body-swap; the entry-point doesn't move.

Module-private to the plugin package. Orchestrator-side callers go
through :class:`alfred.plugins.quarantine_extractor.QuarantinedExtractor`,
which dispatches over StdioTransport rather than importing this module.
"""

from __future__ import annotations

from typing import Any


async def dispatch_extraction(
    *,
    content: bytes,
    schema_json: str,
    schema_version: int,
    provider: Any,
) -> dict[str, Any]:
    """Dispatch a structured extraction via the quarantined LLM.

    Task 4 stub — raises :class:`NotImplementedError` so callers that
    accidentally invoke the unhardened dispatcher fail loudly. Task 5
    replaces this body with the capability-branched implementation.

    The signature is fixed in Task 4 so:

    * :func:`handle_extract` can bind to the final shape without churn
      across the Task 4/5 boundary.
    * Tests can monkeypatch this symbol (e.g. the Task 4 skeleton tests
      patch it to a fake to scope to the cache-lookup-and-delegate
      contract).

    All parameters are keyword-only to match the audit-row vocabulary
    the orchestrator-side caller assembles (``extraction_mode``,
    ``schema_version``, etc. all flow from here).
    """
    raise NotImplementedError(
        "dispatch_extraction: Task 5 lands the capability-branched implementation "
        "(native_constrained / json_object_unconstrained / prompt_embedded_fallback)."
    )

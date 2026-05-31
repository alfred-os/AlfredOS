"""Pydantic v2 schema for adversarial-corpus payload YAML files.

Source of truth for the field shape is
`.rulesync/skills/alfred-adversarial-corpus/SKILL.md` lines 57-65 (required
fields) and lines 49-53 (per-category id prefix). This module is imported by
`tests/adversarial/conftest.py` to validate every YAML file under
`tests/adversarial/<category>/`. Schema failures fail collection
loudly (see `pytest.UsageError` usage in conftest) so corpus regressions never
ship green.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Per-category id prefix -> canonical category name. Keep in lock-step with the
# `Category` Literal below and with the SKILL.md naming table.
_PREFIX_TO_CATEGORY: dict[str, str] = {
    "pi": "prompt_injection",
    "dlp": "dlp",
    "cap": "capability_bypass",
    "cnry": "canary",
    "ipp": "inter_persona",
    "hk": "hooks",
    "tl": "tier_laundering",  # Slice 3 — T3 content posing as T2, cast bypasses
    "de": "dlp_egress",  # Slice 3 — T3-origin credential exfiltration paths
}

# Anchored regex matching `<prefix>-YYYY-NNN`. NNN is zero-padded to three
# digits per SKILL.md "Numbering monotonic per year per category."
_ID_PATTERN = re.compile(r"^(pi|dlp|cap|cnry|ipp|hk|tl|de)-\d{4}-\d{3}$")

Category = Literal[
    "prompt_injection",
    "dlp",
    "capability_bypass",
    "canary",
    "inter_persona",
    "hooks",
    "tier_laundering",  # Slice 3: T3->T2 cast bypasses, wire-format confusion, nonce forgery
    "dlp_egress",  # Slice 3: T3-origin exfiltration (distinct from dlp — see spec §12.1)
]

IngestionPath = Literal[
    "web.fetch",
    "email.read",
    "mcp.tool.output",
    "file.read",
    "inter_persona.relay",
    # Slice 3 additions (spec §12.2):
    "stdio_transport.outbound",  # frames written to subprocess stdin
    "stdio_transport.inbound",  # frames read from subprocess stdout
    "cast_bypass",  # cast(TaggedContent[T2], t3_value) type-level attack
    "wire_format_deser",  # malformed JSON-RPC tier field on the wire
    "capability_gate",  # capability-gate bypass attempt
    "secret_broker",  # secret leaked via env or manifest
]

ExpectedOutcome = Literal[
    "neutralized",
    "caught_by_dlp",
    "refused",
    "quarantined",
    # Slice 3 additions (spec §12.2):
    "boundary_refused",  # tag(T3, ...) from unauthorised caller disposition
    # asserts a specific named audit row exists (e.g. manifest-broadening-capped):
    "audit_row_emitted",
]


class AdversarialPayload(BaseModel):
    """A single adversarial-corpus payload as loaded from YAML.

    `frozen=True` so payloads are hashable + immutable (python-conventions §3).
    `extra="forbid"` so a typo in a field name is a collection-time error, not
    a silent miss. Cross-field validators enforce the prefix<->category
    relationship that SKILL.md naming describes.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., description="`<prefix>-YYYY-NNN` per SKILL.md naming")
    category: Category
    threat: str = Field(..., min_length=1)
    ingestion_path: IngestionPath
    payload: str | dict[str, Any]
    expected_outcome: ExpectedOutcome
    provenance: str = Field(..., min_length=1)
    references: tuple[str, ...] = Field(..., min_length=1)
    # Optional acknowledgement that the attack is outside the current threat
    # model. Used for spec §3.2-style limits (e.g. arbitrary code execution in
    # the privileged orchestrator process bypasses every type-level gate). A
    # payload with ``out_of_scope=True`` must carry a non-empty rationale so
    # auditors can see WHY the gate doesn't defend, not just THAT it doesn't.
    out_of_scope: bool = False
    out_of_scope_rationale: str | None = None

    @field_validator("id")
    @classmethod
    def _validate_id_format(cls, value: str) -> str:
        if not _ID_PATTERN.match(value):
            allowed = "|".join(_PREFIX_TO_CATEGORY)
            msg = (
                f"invalid payload id {value!r}: must match "
                f"`<prefix>-YYYY-NNN` where prefix is one of ({allowed}); "
                "see .rulesync/skills/alfred-adversarial-corpus/SKILL.md naming"
            )
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _validate_prefix_matches_category(self) -> AdversarialPayload:
        prefix = self.id.split("-", 1)[0]
        expected = _PREFIX_TO_CATEGORY[prefix]
        if self.category != expected:
            msg = (
                f"id prefix {prefix!r} implies category {expected!r} but "
                f"payload declared category={self.category!r}; rename the id "
                "or move the file (see SKILL.md naming table)."
            )
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _validate_out_of_scope_has_rationale(self) -> AdversarialPayload:
        """An out-of-scope payload must carry a non-empty rationale.

        The pair (``out_of_scope``, ``out_of_scope_rationale``) is how
        Slice-3 tier-laundering payloads acknowledge spec §3.2 threat-model
        limits (e.g. arbitrary code execution defeats every type-level gate).
        Marking ``out_of_scope=True`` without a rationale would convert a
        forensic acknowledgement into a silent hand-wave — exactly what
        adversarial corpora exist to prevent.
        """
        if self.out_of_scope and not (self.out_of_scope_rationale or "").strip():
            msg = (
                f"payload {self.id!r} has out_of_scope=True but no "
                "out_of_scope_rationale — every out-of-scope acknowledgement "
                "must carry the WHY (spec §3.2 threat-model limits)."
            )
            raise ValueError(msg)
        if not self.out_of_scope and self.out_of_scope_rationale is not None:
            msg = (
                f"payload {self.id!r} carries out_of_scope_rationale but "
                "out_of_scope=False — drop the rationale field or flip the "
                "flag (these two fields move together)."
            )
            raise ValueError(msg)
        return self

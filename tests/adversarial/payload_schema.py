"""Pydantic v2 schema for adversarial-corpus payload YAML files.

Source of truth for the field shape is
`.rulesync/skills/alfred-adversarial-corpus/SKILL.md` lines 57-65 (required
fields) and lines 49-53 (per-category id prefix). This module is imported by
`tests/adversarial/conftest.py` to validate every YAML file under
`tests/adversarial/<category>/payloads/`. Schema failures fail collection
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
}

# Anchored regex matching `<prefix>-YYYY-NNN`. NNN is zero-padded to three
# digits per SKILL.md "Numbering monotonic per year per category."
_ID_PATTERN = re.compile(r"^(pi|dlp|cap|cnry|ipp)-\d{4}-\d{3}$")

Category = Literal[
    "prompt_injection",
    "dlp",
    "capability_bypass",
    "canary",
    "inter_persona",
]

IngestionPath = Literal[
    "web.fetch",
    "email.read",
    "mcp.tool.output",
    "file.read",
    "inter_persona.relay",
]

ExpectedOutcome = Literal[
    "neutralized",
    "caught_by_dlp",
    "refused",
    "quarantined",
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

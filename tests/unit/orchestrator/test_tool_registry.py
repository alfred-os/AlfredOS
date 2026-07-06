from typing import ClassVar, Literal

import pytest

from alfred.orchestrator.tool_registry import (
    FIRST_PARTY_LE_T2_TOOL_ALLOWLIST,
    ExternalToolSpec,
    InternalToolSpec,
    ToolRegistry,
    ToolTierClaimError,
    arguments_conform,
)
from alfred.providers.base import ToolDefinition
from alfred.security.quarantine import ExtractionSchema


class _Schema(ExtractionSchema):
    schema_version: ClassVar[Literal[1]] = 1
    text: str


def _ext(name: str) -> ExternalToolSpec:
    async def _d(_inv: object) -> object:  # dispatch stub; not called here
        raise AssertionError("not dispatched")

    return ExternalToolSpec(
        name=name,
        definition=ToolDefinition(name=name, description="d", input_schema={"type": "object"}),
        extraction_schema=_Schema,
        dispatch=_d,  # type: ignore[arg-type]
    )


def _int(name: str) -> InternalToolSpec:
    async def _d(_inv: object) -> str:
        return "ok"

    return InternalToolSpec(
        name=name,
        definition=ToolDefinition(name=name, description="d", input_schema={"type": "object"}),
        dispatch=_d,  # type: ignore[arg-type]
    )


def test_registry_get_and_definitions() -> None:
    reg = ToolRegistry([_ext("web.fetch"), _int("clock.now")])
    assert reg.get("web.fetch") is not None
    assert reg.get("nope") is None
    names = {d.name for d in reg.definitions()}
    assert names == {"web.fetch", "clock.now"}


def test_internal_le_t2_tool_must_be_on_allowlist() -> None:
    # sec-001: an internal (≤T2) spec whose name is NOT on the hardcoded
    # first-party allowlist is rejected at construction — no trust-the-manifest.
    assert "rogue.tool" not in FIRST_PARTY_LE_T2_TOOL_ALLOWLIST
    with pytest.raises(ToolTierClaimError):
        ToolRegistry([_int("rogue.tool")])


def test_external_t3_tool_needs_no_allowlist_entry() -> None:
    # web.fetch is T3 → the default (quarantine) path → allowlist irrelevant.
    assert "web.fetch" not in FIRST_PARTY_LE_T2_TOOL_ALLOWLIST
    ToolRegistry([_ext("web.fetch")])  # no raise


def test_allowlist_contains_only_the_demo_tool() -> None:
    assert frozenset({"clock.now"}) == FIRST_PARTY_LE_T2_TOOL_ALLOWLIST


def test_arguments_conform_required_presence() -> None:
    schema = {"type": "object", "required": ["url"], "properties": {"url": {"type": "string"}}}
    assert arguments_conform({"url": "https://x"}, schema) is True
    assert arguments_conform({}, schema) is False


def test_duplicate_tool_name_rejected() -> None:
    with pytest.raises(ValueError):
        ToolRegistry([_ext("web.fetch"), _ext("web.fetch")])

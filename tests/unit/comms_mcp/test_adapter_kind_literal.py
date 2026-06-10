"""``adapter_kind`` frozenset immutability + ``BODY_FIELD_BY_KIND`` coverage (Task 2)."""

from __future__ import annotations

from types import MappingProxyType

import pytest

from alfred.comms_mcp.protocol import BODY_FIELD_BY_KIND, adapter_kind


def test_adapter_kind_is_frozenset() -> None:
    assert isinstance(adapter_kind, frozenset)


def test_adapter_kind_immutable() -> None:
    with pytest.raises(AttributeError):
        adapter_kind.add("malicious")  # type: ignore[attr-defined]


def test_adapter_kind_contains_reference_plugin() -> None:
    assert "alfred_comms_test" in adapter_kind


def test_adapter_kind_contains_discord() -> None:
    # PR-S4-9: the Discord adapter kind lands with its BODY_FIELD_BY_KIND +
    # REQUIRED_CLASSIFIERS_BY_KIND entries in the same PR (the §8.5 AST-guard
    # rule). Previously asserted absent; now asserted present.
    assert "discord" in adapter_kind


def test_body_field_for_discord_is_content() -> None:
    assert BODY_FIELD_BY_KIND["discord"] == "content"


def test_body_field_by_kind_is_mapping_proxy() -> None:
    assert isinstance(BODY_FIELD_BY_KIND, MappingProxyType)


def test_body_field_by_kind_keys_match_adapter_kind() -> None:
    assert set(BODY_FIELD_BY_KIND.keys()) == adapter_kind


def test_body_field_for_reference_plugin_is_content() -> None:
    assert BODY_FIELD_BY_KIND["alfred_comms_test"] == "content"

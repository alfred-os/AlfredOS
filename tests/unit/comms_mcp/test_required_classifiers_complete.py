"""``REQUIRED_CLASSIFIERS_BY_KIND`` completeness + empty-set marker (Tasks 10-11).

sec-002 round-3: every ``adapter_kind`` member MUST have a
``REQUIRED_CLASSIFIERS_BY_KIND`` entry — a plugin cannot opt out of the
host-owned required classifier set. An empty classifier set is permitted
ONLY when justified by a ``MARKER_NO_CLASSIFIERS_NEEDED`` entry (the
plain-text / TUI exception per spec §8.5).

Task 11 mirrors the ``cib-2026-004`` adversarial corpus entry as a
structural AST guard: it parses the live registry source and refuses any
adapter-kind addition that lands an empty classifier set without a marker.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import MappingProxyType

from alfred.comms_mcp.classifier_registry import (
    MARKER_NO_CLASSIFIERS_NEEDED,
    REQUIRED_CLASSIFIERS_BY_KIND,
)
from alfred.comms_mcp.protocol import adapter_kind

_REGISTRY_SRC = (
    Path(__file__).resolve().parents[3] / "src" / "alfred" / "comms_mcp" / "classifier_registry.py"
)


def test_every_adapter_kind_has_an_entry() -> None:
    missing = adapter_kind - set(REQUIRED_CLASSIFIERS_BY_KIND.keys())
    assert missing == set(), f"Adapter kinds without classifier entry: {missing}"


def test_empty_entry_requires_marker() -> None:
    for kind, classifiers in REQUIRED_CLASSIFIERS_BY_KIND.items():
        if not classifiers:
            assert kind in MARKER_NO_CLASSIFIERS_NEEDED, (
                f"Adapter kind {kind!r} has empty classifier set but no "
                f"MARKER_NO_CLASSIFIERS_NEEDED justification."
            )


def test_registry_is_mapping_proxy() -> None:
    assert isinstance(REQUIRED_CLASSIFIERS_BY_KIND, MappingProxyType)
    assert isinstance(MARKER_NO_CLASSIFIERS_NEEDED, MappingProxyType)


def test_discord_requires_sub_payload_classifier() -> None:
    # PR-S4-9: the Discord adapter kind requires the host-owned
    # discord_sub_payloads classifier — a plugin cannot opt out of it.
    assert REQUIRED_CLASSIFIERS_BY_KIND["discord"] == frozenset({"discord_sub_payloads"})


def test_every_required_classifier_is_registered_after_import() -> None:
    # The required table is only meaningful if each named classifier is actually
    # registered. Re-run the canonical import-time registration against the live
    # registry (idempotent no-op on the already-registered class) so this guard
    # is order-independent of a sibling suite test that reloads the registry
    # module and drops classifiers registered by other modules. A dangling
    # required entry — a name the scanner would fail to resolve with
    # UnknownClassifierError at dispatch — is refused here.
    from alfred.comms_mcp.classifier_registry import is_registered, register_classifier
    from alfred.comms_mcp.classifiers.discord import DiscordSubPayloadClassifier

    register_classifier(kind="discord", name="discord_sub_payloads")(DiscordSubPayloadClassifier)

    for kind, names in REQUIRED_CLASSIFIERS_BY_KIND.items():
        for name in names:
            assert is_registered(kind=kind, name=name), (
                f"required classifier {name!r} for kind {kind!r} is not registered; "
                f"import alfred.comms_mcp.classifiers.<module> at boot"
            )


# ----- Task 11: structural AST guard (cib-2026-004 mirror) ------------------


def _empty_kinds_without_marker(source: str) -> set[str]:
    """Adapter kinds assigned an empty classifier set with no marker entry.

    Parses ``REQUIRED_CLASSIFIERS_BY_KIND`` and ``MARKER_NO_CLASSIFIERS_NEEDED``
    literal dict assignments out of ``source`` and returns the offending set.
    An empty set is ``frozenset()`` (a ``Call`` with no args).
    """
    tree = ast.parse(source)
    required: dict[str, bool] = {}  # kind -> is_empty
    markers: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        name = _assign_name(node)
        mapping_node = _mapping_proxy_dict(node.value)
        if mapping_node is None:
            continue
        if name == "REQUIRED_CLASSIFIERS_BY_KIND":
            for key, value in zip(mapping_node.keys, mapping_node.values, strict=True):
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    required[key.value] = _is_empty_frozenset(value)
        elif name == "MARKER_NO_CLASSIFIERS_NEEDED":
            for key in mapping_node.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    markers.add(key.value)
    return {kind for kind, is_empty in required.items() if is_empty and kind not in markers}


def _assign_name(node: ast.Assign) -> str | None:
    if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    return None


def _mapping_proxy_dict(value: ast.expr) -> ast.Dict | None:
    """If ``value`` is ``MappingProxyType({...})``, return the inner dict node."""
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "MappingProxyType"
        and value.args
        and isinstance(value.args[0], ast.Dict)
    ):
        return value.args[0]
    return None


def _is_empty_frozenset(value: ast.expr) -> bool:
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "frozenset"
        and not value.args
    )


def test_live_registry_has_no_unjustified_empty_set() -> None:
    source = _REGISTRY_SRC.read_text(encoding="utf-8")
    assert _empty_kinds_without_marker(source) == set()


def test_guard_catches_synthetic_empty_set_bypass() -> None:
    # cib-2026-004: a malicious PR adds an adapter kind with an empty
    # classifier set and no marker. The guard must flag it.
    synthetic = (
        "from types import MappingProxyType\n"
        "REQUIRED_CLASSIFIERS_BY_KIND = MappingProxyType({\n"
        "    'alfred_comms_test': frozenset(),\n"
        "    'malicious': frozenset(),\n"
        "})\n"
        "MARKER_NO_CLASSIFIERS_NEEDED = MappingProxyType({\n"
        "    'alfred_comms_test': 'plain-text only',\n"
        "})\n"
    )
    assert _empty_kinds_without_marker(synthetic) == {"malicious"}

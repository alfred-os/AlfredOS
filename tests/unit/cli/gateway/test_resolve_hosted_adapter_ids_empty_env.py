"""#499: the gateway resolver reads ALFRED_COMMS_ENABLED_ADAPTERS with NO provider key.

Proves the whole chain — compose default -> shell env -> pydantic-settings JSON-decode ->
`_resolve_hosted_adapter_ids` -> canonical ids — end to end WITHOUT a provider key or
environment (the ADR-0036 posture #499 delivers), that the path-traversal guard is intact
(single- AND multi-segment), and that a real id resolves to its canonical kind.
"""

from __future__ import annotations

import pytest

from alfred.cli.gateway._commands import _resolve_hosted_adapter_ids
from alfred.config.settings import SettingsError


def _key_free_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALFRED_DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)


def test_resolve_hosted_adapter_ids_empty_is_no_op(monkeypatch: pytest.MonkeyPatch) -> None:
    """`ALFRED_COMMS_ENABLED_ADAPTERS=[]` -> `[]` with NO ALFRED_DEEPSEEK_API_KEY / ENVIRONMENT."""
    _key_free_env(monkeypatch)
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", "[]")

    assert _resolve_hosted_adapter_ids() == []


def test_resolve_hosted_adapter_ids_real_id_maps_to_canonical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A REAL id from env, no key: `["alfred_discord"]` -> `["discord"]` (canonical).

    Unlike the stubbed reconciliation tests, this drives real env-decode + validation +
    `_resolve_adapter_kind` (spec item 3 — the key-free positive resolve).
    """
    _key_free_env(monkeypatch)
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", '["alfred_discord"]')

    assert _resolve_hosted_adapter_ids() == ["discord"]


@pytest.mark.parametrize("traversal", ['["../../etc"]', '[".."]'])
def test_resolve_hosted_adapter_ids_rejects_traversal(
    traversal: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Traversal ids are refused BEFORE `_resolve_adapter_kind` reads a manifest.

    Both the multi-segment (`../../etc`, caught by the charset regex) AND the single-segment
    (`..`, caught by the FIX-3 branch) — so deleting either guard reds this. The
    `_resolve_adapter_kind` read sink has no sink-local re-check, so the construction-time
    validator is the sole guard; this locks it in after the decoupling.
    """
    _key_free_env(monkeypatch)
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", traversal)

    with pytest.raises(SettingsError):
        _resolve_hosted_adapter_ids()

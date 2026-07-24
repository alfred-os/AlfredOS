"""#469 Blocker 2 comms-003: a positive-boot proof that the real ``Settings()`` env-parsing
path resolves an empty ``ALFRED_COMMS_ENABLED_ADAPTERS`` to ``[]``.

Closes the gap between the compose-level interpolation proof
(``tests/integration/test_gateway_hosted_adapters_compose_interpolation.py``, which proves
Compose resolves the shipped default to the literal string ``"[]"``) and the resolver-level
unit tests in ``test_gateway_start_adapter_ids.py`` / ``test_hosted_adapter_id_reconciliation.py``
(which stub ``Settings`` entirely and never exercise pydantic-settings' own env-var parsing).
This test constructs a REAL ``Settings()`` against that exact env-var string, proving the
whole chain — compose default -> shell env -> pydantic-settings JSON-decode ->
``_resolve_hosted_adapter_ids`` -> ``[]`` — end to end.

This is a regression-lock, not a new-behaviour test: the code default was already
``comms_enabled_adapters: tuple[str, ...] = Field(default=())`` before this task (only
``docker-compose.yaml``'s fallback was misaligned with it), so this test is expected to
pass unmodified — it pins the already-correct resolver behaviour the compose fix now
actually reaches on a stock deploy.
"""

from __future__ import annotations

import pytest

from alfred.cli.gateway._commands import _resolve_hosted_adapter_ids


def test_resolve_hosted_adapter_ids_empty_is_no_op(monkeypatch: pytest.MonkeyPatch) -> None:
    """``ALFRED_COMMS_ENABLED_ADAPTERS=[]`` (the compose default's resolved value) -> ``[]``.

    ``_resolve_hosted_adapter_ids`` constructs a real ``Settings()``, which additionally
    requires ``environment`` and ``deepseek_api_key`` (both mandatory, unrelated fields) —
    set here to the same minimal values ``tests/unit/cli/gateway/test_adapter_egress_mount.py``
    uses so this test isolates the one behaviour under test.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", "[]")

    assert _resolve_hosted_adapter_ids() == []

"""#340 PR2b golive Task 7: the HOST pre-spawn refuse-boot on an unset key.

``_resolve_provider_key`` is the §20.2 PRIMARY defense (host, pre-spawn,
SYNCHRONOUS): it resolves the quarantined child's provider key from the secret
broker and REFUSES (raises :class:`QuarantineProviderKeyUnsetError`) when the
broker holds no ``quarantine_provider_api_key``. The go-live child now makes a
REAL provider call, so a surviving non-empty ``_PROVIDER_KEY_PLACEHOLDER`` would
build a real client on a bogus key — a SILENT dead-LLM. Deleting the placeholder
+ failing loud (CLAUDE.md hard rule #7 / §20.3.1 must-not-regress) is the fix.

The refuse is raised BEFORE the single ``await spawn_quarantine_child_io(...)`` in
``_build_comms_inbound_extractor``, so the fd-3 clobber window never opens on the
refuse path — the function stays synchronous (no ``await``) by design.
"""

from __future__ import annotations

import pytest
import structlog.testing

import alfred.comms_mcp.daemon_runtime as daemon_runtime_mod
from alfred.comms_mcp.daemon_runtime import (
    QuarantineProviderKeyUnsetError,
    _resolve_provider_key,
)
from alfred.errors import AlfredError

_SECRET_ID = "quarantine_provider_api_key"  # noqa: S105 - broker lookup id, not a credential


class _Broker:
    """Minimal :class:`SecretBroker`-shaped double for the two seams used.

    Records the ``get`` call so a test can prove the resolver reads the SAME
    secret id it probed with ``has`` (no id drift between the presence check and
    the fetch).
    """

    def __init__(self, *, present: bool, value: str = "real-quarantine-key") -> None:
        self._present = present
        self._value = value
        self.get_calls: list[str] = []

    def has(self, name: str) -> bool:
        return self._present and name == _SECRET_ID

    def get(self, name: str) -> str:
        self.get_calls.append(name)
        if not self._present or name != _SECRET_ID:  # pragma: no cover - guard
            raise AssertionError(f"unexpected get({name!r})")
        return self._value


def test_resolve_provider_key_returns_broker_value_when_set() -> None:
    """A configured ``quarantine_provider_api_key`` is returned verbatim."""
    broker = _Broker(present=True, value="configured-key")
    assert _resolve_provider_key(broker) == "configured-key"
    # The fetch reads the same id the presence check used (no drift).
    assert broker.get_calls == [_SECRET_ID]


def test_resolve_provider_key_refuses_when_unset() -> None:
    """An unset key raises the loud refuse-boot error (never a placeholder)."""
    broker = _Broker(present=False)
    with pytest.raises(QuarantineProviderKeyUnsetError):
        _resolve_provider_key(broker)
    # The refuse path never fetches a value — it raises off the ``has`` probe.
    assert broker.get_calls == []


def test_resolve_provider_key_error_is_alfred_error() -> None:
    """The refuse is an :class:`AlfredError` so the CLI top-level dispatch catches it."""
    assert issubclass(QuarantineProviderKeyUnsetError, AlfredError)


def test_resolve_provider_key_names_the_secret_id_in_the_error() -> None:
    """The raised error carries the broker secret id — actionable forensics.

    The value is a closed broker-lookup id, never a secret, so it is safe to
    carry in the exception text.
    """
    broker = _Broker(present=False)
    with pytest.raises(QuarantineProviderKeyUnsetError) as exc_info:
        _resolve_provider_key(broker)
    assert _SECRET_ID in str(exc_info.value)


def test_resolve_provider_key_logs_loud_error_when_unset() -> None:
    """The unset path emits a LOUD (error-level) structlog event before raising.

    Uses ``structlog.testing.capture_logs`` (not pytest ``caplog``) because the
    module logs via structlog, which does not route through stdlib logging here.
    """
    broker = _Broker(present=False)
    with (
        structlog.testing.capture_logs() as captured,
        pytest.raises(QuarantineProviderKeyUnsetError),
    ):
        _resolve_provider_key(broker)
    assert any(
        entry.get("event") == "comms.daemon_runtime.quarantine_provider_key_unset"
        and entry.get("log_level") == "error"
        for entry in captured
    ), captured


def test_no_placeholder_constant_remains() -> None:
    """§20.3.1 must-not-regress: the non-empty fallback placeholder is DELETED.

    A surviving ``_PROVIDER_KEY_PLACEHOLDER`` would let boot build a real
    provider client on a bogus key = a silent dead-LLM. The refuse-boot replaces
    it, so the constant must not exist on the module.
    """
    assert not hasattr(daemon_runtime_mod, "_PROVIDER_KEY_PLACEHOLDER")

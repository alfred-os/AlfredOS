"""Structural-satisfaction proof for the security config Protocol (#351).

The identity-return function is a COMPILE-TIME proof (never called at runtime): mypy
--strict accepts ``Settings -> CommsAdapterGrantsConfig`` iff ``Settings`` satisfies the
Protocol, so a real ``Settings`` can be passed wherever ``CommsAdapterGrantsConfig`` is
required — and a future ``Settings.comms_enabled_adapters`` rename fails the type-check
instead of silently drifting. The stub test proves the DIP win: the builder works against
a trivial double, not just a full ``Settings``.

Validator-coupling note (#351): the SECURITY invariant that each enabled adapter id is
charset/traversal/containment/manifest-exists checked lives in
``_validate_comms_enabled_adapters`` and is covered by the retained real-``Settings`` test
``test_comms_adapter_grants.py``. This proof deliberately uses only the default-empty
adapter set so it exercises the DIP seam WITHOUT depending on / re-testing the validator.
"""

from __future__ import annotations

from alfred.config.settings import Settings
from alfred.security._config_protocols import CommsAdapterGrantsConfig
from alfred.security.capability_gate._comms_adapter_grants import comms_adapter_load_grants


def _settings_satisfies(settings: Settings) -> CommsAdapterGrantsConfig:
    # Compile-time proof only; mypy --strict type-checks the return. Needs no
    # Settings() construction (avoids env/secret requirements).
    return settings


class _StubCfg:
    """A trivial config double — NOT a Settings — supplying the one field the builder reads."""

    def __init__(self, *, comms_enabled_adapters: tuple[str, ...]) -> None:
        self.comms_enabled_adapters = comms_enabled_adapters


def test_plain_stub_satisfies_comms_adapter_grants_config() -> None:
    """The DIP win: a trivial stub — not a full Settings — satisfies the Protocol."""
    cfg: CommsAdapterGrantsConfig = _StubCfg(comms_enabled_adapters=())
    assert cfg.comms_enabled_adapters == ()


def test_comms_adapter_load_grants_accepts_a_plain_stub() -> None:
    """comms_adapter_load_grants consumes CommsAdapterGrantsConfig — a stub drives the seam.

    Uses the default-empty adapter set: the builder returns () without reading any manifest,
    proving the seam consumes the narrow Protocol without depending on the validator surface.
    """
    assert comms_adapter_load_grants(_StubCfg(comms_enabled_adapters=())) == ()

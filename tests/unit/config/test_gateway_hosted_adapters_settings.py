"""#499: the shared adapter-id validator + the gateway's key-free hosted-adapters model.

`validate_comms_adapter_ids` is THE single source of truth for comms-adapter-id path-safety;
`GatewayHostedAdaptersSettings` is the gateway's key-free read of the allowlist (ADR-0036).
"""

from __future__ import annotations

import json
import sys

import pytest

from alfred.config.settings import (
    GatewayHostedAdaptersSettings,
    SettingsError,
    validate_comms_adapter_ids,
)

# The full bad-id corpus the SoT validator must reject, one entry per rejection branch.
_BAD_IDS = ["../../etc", "..", ".", "has space", "no_such_adapter"]


def test_validate_accepts_real_adapter_ids() -> None:
    # A real in-repo plugin-package id (plugins/alfred_discord/manifest.toml exists).
    assert validate_comms_adapter_ids(("alfred_discord",)) == ("alfred_discord",)
    assert validate_comms_adapter_ids(()) == ()


@pytest.mark.parametrize("bad", _BAD_IDS)
def test_validate_rejects_bad_ids(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_comms_adapter_ids((bad,))


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="symlink creation needs privilege on Windows; the containment branch is "
    "coverage-measured on Linux CI",
)
def test_validate_rejects_symlink_escape(tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fire the `is_relative_to` containment branch — the SOLE guard on the gateway path.

    A charset-clean id whose `plugins/<id>/manifest.toml` symlinks OUT of `plugins/` is the
    only way to reach this branch (the charset regex blocks `/`). This closes the
    pre-existing uncovered line ci.yml:715-729 cites as why settings.py is off the 100% gate.
    """
    from pathlib import Path

    root = Path(str(tmp_path))
    outside = root / "outside"
    outside.mkdir()
    (outside / "manifest.toml").write_text("", encoding="utf-8")
    plugins = root / "plugins"
    plugins.mkdir()
    (plugins / "escape").symlink_to(outside)  # plugins/escape -> root/outside
    monkeypatch.setenv("ALFRED_REPO_ROOT", str(root))

    with pytest.raises(ValueError):
        validate_comms_adapter_ids(("escape",))


def test_gateway_model_resolves_empty_without_provider_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole point of #499: read the allowlist with NO provider key and NO environment."""
    monkeypatch.delenv("ALFRED_DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", "[]")

    assert GatewayHostedAdaptersSettings().comms_enabled_adapters == ()  # type: ignore[no-untyped-call]


def test_gateway_model_accepts_real_id_without_provider_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ALFRED_DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", '["alfred_discord"]')

    assert GatewayHostedAdaptersSettings().comms_enabled_adapters == ("alfred_discord",)  # type: ignore[no-untyped-call]


def test_gateway_model_rejects_traversal_as_settings_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A traversal-shaped id lifts to SettingsError so start_gateway's config arm catches it."""
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", '[".."]')
    with pytest.raises(SettingsError):
        GatewayHostedAdaptersSettings()  # type: ignore[no-untyped-call]


def test_gateway_model_rejects_malformed_json_as_settings_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-JSON ALFRED_COMMS_ENABLED_ADAPTERS is a config fault, not a raw traceback.

    pydantic-settings JSON-decodes the tuple field inside __init__; a malformed value must
    lift to SettingsError (the fail-loud posture start_gateway's config arm depends on).
    """
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", "[unclosed")
    with pytest.raises(SettingsError):
        GatewayHostedAdaptersSettings()  # type: ignore[no-untyped-call]


@pytest.mark.parametrize("bad", _BAD_IDS)
def test_both_models_reject_the_same_bad_ids(bad: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Behavioural equivalence over the FULL corpus: both models delegate to one rule.

    Not tautological, and not single-input: a divergence on ANY branch (e.g. the is_file
    check) between the two field validators would red here — the drift the SoT guards against.
    """
    from alfred.config.settings import Settings

    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", json.dumps([bad]))
    with pytest.raises(SettingsError):
        Settings()  # type: ignore[no-untyped-call]
    with pytest.raises(SettingsError):
        GatewayHostedAdaptersSettings()  # type: ignore[no-untyped-call]

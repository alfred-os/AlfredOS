"""``Settings.comms_enabled_adapters`` (PR-S4-11b Wave 3, #237).

The daemon-spawned comms-adapter allowlist. Each entry must be a charset-clean
id AND name a real ``plugins/<id>/manifest.toml`` — a bad entry fails boot
loudly (no silent skip). Default ``()`` keeps existing boot byte-for-byte
unchanged.
"""

from __future__ import annotations

import pytest

from alfred.config.settings import Settings, SettingsError

# The reference comms plugin ships a real manifest at
# ``plugins/alfred_comms_test/manifest.toml`` (verified by the substrate test).
_REAL_ADAPTER_ID = "alfred_comms_test"


@pytest.fixture(autouse=True)
def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide the minimum required Settings env so the field under test loads."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    monkeypatch.delenv("ALFRED_COMMS_ENABLED_ADAPTERS", raising=False)


def test_default_is_empty() -> None:
    assert Settings().comms_enabled_adapters == ()


def test_accepts_real_adapter_id() -> None:
    settings = Settings(comms_enabled_adapters=(_REAL_ADAPTER_ID,))
    assert settings.comms_enabled_adapters == (_REAL_ADAPTER_ID,)


def test_rejects_nonexistent_manifest() -> None:
    # A charset-clean id with no ``plugins/<id>/manifest.toml`` must fail loudly.
    with pytest.raises(SettingsError):
        Settings(comms_enabled_adapters=("no_such_adapter",))


def test_rejects_bad_charset() -> None:
    # ``/`` is outside ``[A-Za-z0-9._-]`` — a path-traversal-shaped id is refused
    # before any filesystem probe.
    with pytest.raises(SettingsError):
        Settings(comms_enabled_adapters=("../etc/passwd",))


def test_rejects_empty_string_entry() -> None:
    with pytest.raises(SettingsError):
        Settings(comms_enabled_adapters=("",))


@pytest.mark.parametrize("traversal_id", [".", ".."])
def test_rejects_dot_and_dotdot(traversal_id: str) -> None:
    """FIX 3: ``.`` and ``..`` are charset-clean under ``[A-Za-z0-9._-]`` but
    are single-segment path-traversal probes (``.`` → ``plugins/manifest.toml``,
    ``..`` → ``plugins/../manifest.toml``). ``/`` is already blocked so they are
    capped, but they are a real defence-in-depth gap (``is_file()`` follows
    symlinks), so the validator REFUSES them explicitly."""
    with pytest.raises(SettingsError):
        Settings(comms_enabled_adapters=(traversal_id,))


def test_rejects_dotdot_even_when_escape_target_exists(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FIX 3 (load-bearing): ``..`` is refused on its OWN merits, not because the
    escape target happens not to exist.

    Point the validator's repo root at a tmp tree where ``plugins/../manifest.toml``
    (i.e. the tmp-root ``manifest.toml``) DOES exist. Without the explicit
    ``.``/``..`` refusal, ``is_file()`` would follow the ``..`` segment and ACCEPT
    the id — a single-segment traversal escaping ``plugins/``. The explicit
    refusal must reject it regardless."""
    import alfred.config.settings as settings_mod

    fake_root = tmp_path / "repo"
    (fake_root / "plugins").mkdir(parents=True)
    # The file ``plugins/../manifest.toml`` resolves to — make it real so the
    # naive ``is_file()`` probe would otherwise pass.
    (fake_root / "manifest.toml").write_text("# escape target", encoding="utf-8")
    monkeypatch.setattr(settings_mod, "_REPO_ROOT", fake_root)

    with pytest.raises(SettingsError):
        Settings(comms_enabled_adapters=("..",))


def test_resolved_manifest_path_stays_under_plugins() -> None:
    """FIX 3: a valid adapter's resolved manifest path stays under ``plugins/``.

    Belt-and-braces on the containment invariant the ``.``/``..`` refusal
    protects: the reference adapter resolves to ``plugins/<id>/manifest.toml``,
    not an escape outside ``plugins/``."""
    from alfred.config.settings import _REPO_ROOT

    settings = Settings(comms_enabled_adapters=(_REAL_ADAPTER_ID,))
    plugins_root = (_REPO_ROOT / "plugins").resolve()
    for adapter_id in settings.comms_enabled_adapters:
        resolved = (_REPO_ROOT / "plugins" / adapter_id / "manifest.toml").resolve()
        assert resolved.is_relative_to(plugins_root)

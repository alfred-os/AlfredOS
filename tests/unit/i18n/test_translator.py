"""Tests for the AlfredOS i18n translator."""

from __future__ import annotations

from pathlib import Path

import pytest

from alfred.i18n import set_language, t
from alfred.i18n.translator import (
    _installed_package_locale_dir,
    _resolve_locale_dir,
    _warn_locale_missing_on_stderr,
)


@pytest.fixture(autouse=True)
def _reset_language() -> None:
    set_language("en-US")


class TestTranslator:
    def test_returns_message_for_known_key_in_english(self) -> None:
        # The catalog defines status.primary_provider as "primary provider: {provider}".
        assert t("status.primary_provider", provider="deepseek") == "primary provider: deepseek"

    def test_returns_key_as_fallback_for_unknown_message(self) -> None:
        # Missing-message strategy: return the key so the developer sees what to add.
        assert t("missing.key.example") == "missing.key.example"

    def test_substitutes_kwargs_into_message(self) -> None:
        assert "1.50" in t("status.daily_budget", amount="1.50")

    def test_set_language_switches_active_catalog(self) -> None:
        # Switching to a language with no catalog falls back to English.
        set_language("fr-FR")
        # English catalog still wins because no fr-FR catalog exists yet.
        assert "primary provider" in t("status.primary_provider", provider="deepseek")


class TestLocaleResolver:
    """Coverage for the multi-candidate locale-dir resolver.

    Closes devops-1 on PR #89: the prior ``Path(__file__).parents[3] / "locale"``
    resolved to ``/app/.venv/lib/python3.12/locale`` once the package was
    installed into a venv. The resolver now walks a candidate list and returns
    the first existing dir; these tests prove the walk and the empty-list
    fallback behaviour.
    """

    def test_finds_real_locale_dir_in_dev_layout(self) -> None:
        # The worktree itself satisfies candidate 1 (parents[3] / "locale").
        resolved = _resolve_locale_dir()
        assert resolved is not None
        assert (resolved / "en" / "LC_MESSAGES" / "alfred.mo").is_file()

    def test_returns_none_when_no_candidate_exists(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Drive the REAL `_resolve_locale_dir()` down its None-fallback branch
        # by patching `Path.is_dir` to always return False. The previous shape
        # of this test asserted a local fake_resolve() instead of the
        # production function, so a real regression in the production resolver
        # would have slipped through unnoticed.
        monkeypatch.setattr(Path, "is_dir", lambda _self: False)
        assert _resolve_locale_dir() is None


class TestInstalledPackageLocaleDir:
    """The wheel-installed catalog candidate (BUG-2, PR-S4-11c-2b0).

    The wheel force-includes ``locale/`` at ``alfred/_locale`` so a pip-installed
    alfred carries its catalogs. ``_installed_package_locale_dir`` resolves that
    in-package dir via ``importlib.resources.files``; in a source checkout it
    points at ``src/alfred/_locale`` (which does not exist), so it returns None and
    the dev candidate wins.
    """

    def test_returns_none_in_source_checkout(self) -> None:
        # The source tree has no ``src/alfred/_locale`` (it is created only at
        # wheel-build time), so the in-package candidate is absent here and the
        # dev ``parents[3]/locale`` candidate is what actually resolves.
        assert _installed_package_locale_dir() is None

    def test_resolves_when_package_locale_present(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Simulate the wheel layout: a real ``alfred/_locale`` dir. Patch
        # importlib.resources.files("alfred") to point at a temp package root so
        # the candidate resolves to an existing dir without mutating the worktree.
        pkg_root = tmp_path / "alfred"
        (pkg_root / "_locale" / "en" / "LC_MESSAGES").mkdir(parents=True)
        import alfred.i18n.translator as translator_mod

        monkeypatch.setattr(translator_mod.importlib.resources, "files", lambda _name: pkg_root)
        resolved = _installed_package_locale_dir()
        assert resolved == pkg_root / "_locale"

    def test_degrades_to_none_on_resolution_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A backend that raises (e.g. ModuleNotFoundError) must degrade to None,
        # never wedge translator import.
        import alfred.i18n.translator as translator_mod

        def _boom(_name: str) -> object:
            raise ModuleNotFoundError("no such package")

        monkeypatch.setattr(translator_mod.importlib.resources, "files", _boom)
        assert _installed_package_locale_dir() is None


class TestMissingCatalogWarning:
    """The import-time missing-catalog warning is pinned to stderr (BUG-1)."""

    def test_warning_goes_to_stderr_not_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        _warn_locale_missing_on_stderr()
        captured = capsys.readouterr()
        assert captured.out == "", "the missing-catalog warning leaked onto stdout"
        assert "translations disabled" in captured.err

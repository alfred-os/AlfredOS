"""sbx-2026-027 — a writable `.env` may tighten the sandbox, never loosen it (ADR-0057).

Release-blocking. Drives the REAL ``manifest_reader --read-environment`` — the launcher's sole
source for ``IS_PRODUCTION`` — rather than asserting on the resolver in isolation, because the
property that matters is what the *launcher* is told.

Both directions are asserted. The loosening refusal is the security invariant; the tightening
acceptance is what makes #486's documented path work, and pinning it stops a future
over-correction from silently reverting to "the launcher never reads `.env`" and reopening #486.
"""

from __future__ import annotations

import pytest

from alfred.plugins import manifest_reader

_UNTRUSTED_SOURCE_KEY = "daemon.boot.environment_untrusted_source"


@pytest.fixture
def dotenv_only(tmp_path, monkeypatch):
    """A bare-host install configured ONLY through a CWD `.env` — #486's configuration.

    ``chdir`` is load-bearing: ``resolve_environment`` reads `.env` CWD-relative, so without it
    a real repo-root `.env` decides the result and the test passes on the wrong path.
    """

    def _configure(dotenv_value: str) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text(f"ALFRED_ENVIRONMENT={dotenv_value}\n")
        monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
        monkeypatch.setenv("ALFRED_ETC_ENV_FILE", str(tmp_path / "no-such-etc-file"))

    return _configure


@pytest.mark.parametrize("loosening", ["development", "test"])
def test_dotenv_cannot_loosen_the_launcher_environment(loosening: str, dotenv_only, capsys) -> None:
    """THE invariant: a `.env` can never select a laxer environment for the launcher."""
    dotenv_only(loosening)

    rc = manifest_reader.main(["--read-environment"])

    assert rc != 0, (
        f"the launcher accepted a `.env`-sourced {loosening!r} — IS_PRODUCTION would flip "
        "false on a production host, unlocking the unsandboxed-exec and FAKE_UNAME gates"
    )
    captured = capsys.readouterr()
    assert captured.out.strip() == "", (
        "a refused resolution printed a value on stdout; the launcher consumes stdout verbatim, "
        "so ANY value here is honoured"
    )
    assert captured.err.strip().splitlines()[-1] == _UNTRUSTED_SOURCE_KEY, (
        "the refusal must carry its OWN closed-vocabulary reason, not degrade to a generic one"
    )


def test_dotenv_may_tighten_to_production(dotenv_only, capsys) -> None:
    """The tightening direction IS honoured — this is what fixes #486's documented path."""
    dotenv_only("production")

    rc = manifest_reader.main(["--read-environment"])

    assert rc == 0
    assert capsys.readouterr().out.strip() == "production"


def test_a_trusted_source_still_selects_development(tmp_path, monkeypatch, capsys) -> None:
    """Non-vacuity control: the refusal is about the SOURCE, not the value.

    Without this, a guard that simply refused every `development` would pass the test above
    while breaking every legitimate development deployment.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=production\n")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    monkeypatch.setenv("ALFRED_ETC_ENV_FILE", str(tmp_path / "no-such-etc-file"))

    rc = manifest_reader.main(["--read-environment"])

    assert rc == 0
    assert capsys.readouterr().out.strip() == "development"

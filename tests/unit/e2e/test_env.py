"""Unit tests for the isolated e2e env-file writer."""

from __future__ import annotations

from pathlib import Path

from tests.e2e import _env


def _read(env_path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in env_path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            out[k] = v
    return out


def test_writes_gf_password_and_sentinel_keys(tmp_path: Path) -> None:
    values = _read(_env.write_e2e_env_file(tmp_path))
    assert values["ALFRED_DEEPSEEK_API_KEY"] == _env.DUMMY_KEY_SENTINEL
    assert values["ALFRED_QUARANTINE_PROVIDER_API_KEY"] == _env.DUMMY_KEY_SENTINEL
    assert len(values["GF_SECURITY_ADMIN_PASSWORD"]) >= 32


def test_gf_password_is_per_run_random(tmp_path: Path) -> None:
    a = _read(_env.write_e2e_env_file(tmp_path / "a"))["GF_SECURITY_ADMIN_PASSWORD"]
    b = _read(_env.write_e2e_env_file(tmp_path / "b"))["GF_SECURITY_ADMIN_PASSWORD"]
    assert a != b


def test_dummy_key_is_not_the_env_example_placeholder(tmp_path: Path) -> None:
    assert _env.DUMMY_KEY_SENTINEL != "sk-..."


def test_new_project_name_is_unique_and_prefixed() -> None:
    a, b = _env.new_project_name(), _env.new_project_name()
    prefix = f"{_env.E2E_PROJECT_PREFIX}-"
    assert a.startswith(prefix) and b.startswith(prefix)
    assert a != b  # per-run-unique so concurrent runs never share Compose labels


def test_scrub_env_secrets_redacts_every_injected_value(tmp_path: Path) -> None:
    env_file = _env.write_e2e_env_file(tmp_path)
    values = _read(env_file)
    gf = values["GF_SECURITY_ADMIN_PASSWORD"]
    text = f"grafana logged pw={gf} and key={_env.DUMMY_KEY_SENTINEL} in the boot output"
    scrubbed = _env.scrub_env_secrets(text, env_file)
    assert gf not in scrubbed
    assert _env.DUMMY_KEY_SENTINEL not in scrubbed
    assert "***REDACTED***" in scrubbed


def test_scrub_env_secrets_leaves_non_secret_text_intact(tmp_path: Path) -> None:
    env_file = _env.write_e2e_env_file(tmp_path)
    assert _env.scrub_env_secrets("no secrets here", env_file) == "no secrets here"

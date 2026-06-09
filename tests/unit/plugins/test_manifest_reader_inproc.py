"""In-process coverage for ``manifest_reader.main`` (PR-S4-6 Component C).

The subprocess tests in ``test_manifest_reader_cli.py`` prove the real
``python3 -m`` CLI invocation the bash launcher uses. Those run in a child
process so ``coverage`` cannot see them. THESE tests call ``main(argv=...)``
in-process so every branch is measured for the 100% trust-boundary floor.
"""

from __future__ import annotations

import json

import pytest

from alfred.plugins import manifest_reader

_FULL_MANIFEST = """[alfred]
manifest_version = 1
[plugin]
id = "alfred.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
[sandbox]
kind = "full"
[sandbox.policy_refs]
linux = "config/sandbox/foo.linux.bwrap.policy"
"""

_NO_SANDBOX_MANIFEST = """[alfred]
manifest_version = 1
[plugin]
id = "alfred.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
"""


# --------------------------------------------------------------------------
# --read-sandbox
# --------------------------------------------------------------------------


def test_read_sandbox_manifest_path_ok(tmp_path, capsys) -> None:
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(_FULL_MANIFEST)
    rc = manifest_reader.main(["--read-sandbox", "--manifest-path", str(manifest)])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["kind"] == "full"


def test_read_sandbox_plugin_id_ok(tmp_path, capsys, monkeypatch) -> None:
    plugin_dir = tmp_path / "alfred_example"
    plugin_dir.mkdir()
    (plugin_dir / "manifest.toml").write_text(_FULL_MANIFEST)
    monkeypatch.setenv("ALFRED_PLUGINS_DIR", str(tmp_path))
    rc = manifest_reader.main(["--read-sandbox", "--plugin-id", "alfred.example"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["kind"] == "full"


def test_read_sandbox_plugin_id_default_dir(monkeypatch, capsys) -> None:
    # No ALFRED_PLUGINS_DIR → falls back to the default "plugins" root and
    # resolves the real shipped quarantined-llm manifest.
    monkeypatch.delenv("ALFRED_PLUGINS_DIR", raising=False)
    rc = manifest_reader.main(["--read-sandbox", "--plugin-id", "alfred.quarantined-llm"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["kind"] == "full"


def test_read_sandbox_missing_block(tmp_path, capsys) -> None:
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(_NO_SANDBOX_MANIFEST)
    rc = manifest_reader.main(["--read-sandbox", "--manifest-path", str(manifest)])
    assert rc == 1
    assert "plugin.manifest_sandbox_block_missing" in capsys.readouterr().err


def test_read_sandbox_invalid_manifest(tmp_path, capsys) -> None:
    manifest = tmp_path / "manifest.toml"
    manifest.write_text("not = = toml [[[")
    rc = manifest_reader.main(["--read-sandbox", "--manifest-path", str(manifest)])
    assert rc == 1
    assert "plugin.manifest_invalid" in capsys.readouterr().err


def test_read_sandbox_unreadable(tmp_path, capsys) -> None:
    rc = manifest_reader.main(["--read-sandbox", "--manifest-path", str(tmp_path / "nope.toml")])
    assert rc == 1
    assert "plugin.manifest_unreadable" in capsys.readouterr().err


def test_read_sandbox_no_source(capsys) -> None:
    rc = manifest_reader.main(["--read-sandbox"])
    assert rc == 1
    assert "plugin.manifest_reader_no_source" in capsys.readouterr().err


def test_read_sandbox_unsafe_plugin_id(capsys) -> None:
    rc = manifest_reader.main(["--read-sandbox", "--plugin-id", "../../etc/passwd"])
    assert rc == 1
    assert "plugin.launcher_plugin_id_invalid" in capsys.readouterr().err


def test_read_sandbox_empty_plugin_id(capsys) -> None:
    rc = manifest_reader.main(["--read-sandbox", "--plugin-id", ""])
    assert rc == 1
    assert "plugin.manifest_reader_no_source" in capsys.readouterr().err


# --------------------------------------------------------------------------
# --read-environment
# --------------------------------------------------------------------------


def test_read_environment_env_var(monkeypatch, capsys) -> None:
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.delenv("ALFRED_ETC_ENV_FILE", raising=False)
    rc = manifest_reader.main(["--read-environment"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "test"


def test_read_environment_file(tmp_path, monkeypatch, capsys) -> None:
    env_file = tmp_path / "environment"
    env_file.write_text("production\n")
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_ETC_ENV_FILE", str(env_file))
    rc = manifest_reader.main(["--read-environment"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "production"


def test_read_environment_unset(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_ETC_ENV_FILE", str(tmp_path / "absent"))
    rc = manifest_reader.main(["--read-environment"])
    assert rc == 1
    assert "daemon.boot.environment_not_set" in capsys.readouterr().err


def test_read_environment_unrecognised(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "staging")
    monkeypatch.setenv("ALFRED_ETC_ENV_FILE", str(tmp_path / "absent"))
    rc = manifest_reader.main(["--read-environment"])
    assert rc == 1
    assert "daemon.boot.environment_unrecognised" in capsys.readouterr().err


# --------------------------------------------------------------------------
# --policy-to-bwrap-flags
# --------------------------------------------------------------------------


def test_policy_to_bwrap_flags_ok(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", _StdinStub("keep_fds = [3]\n"))
    rc = manifest_reader.main(["--policy-to-bwrap-flags"])
    assert rc == 0
    lines = capsys.readouterr().out.splitlines()
    assert "--sync-fd" in lines
    assert "3" in lines


def test_policy_to_bwrap_flags_invalid(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", _StdinStub("keep_fds = []\n"))
    rc = manifest_reader.main(["--policy-to-bwrap-flags"])
    assert rc == 1
    assert "kind_full_requires_keep_fd_3" in capsys.readouterr().err


def test_policy_to_bwrap_flags_confined_ref(tmp_path, monkeypatch, capsys) -> None:
    # sec-2: --policy-ref is confined to the policy root, then read.
    root = tmp_path / "config" / "sandbox"
    root.mkdir(parents=True)
    (root / "foo.linux.bwrap.policy").write_text("keep_fds = [3]\n")
    monkeypatch.delenv("ALFRED_SANDBOX_POLICY_DIR", raising=False)
    rc = manifest_reader.main(
        [
            "--policy-to-bwrap-flags",
            "--policy-ref",
            "config/sandbox/foo.linux.bwrap.policy",
            "--install-root",
            str(tmp_path),
        ]
    )
    assert rc == 0
    assert "--sync-fd" in capsys.readouterr().out.splitlines()


def test_policy_to_bwrap_flags_ref_escapes_root(tmp_path, monkeypatch, capsys) -> None:
    (tmp_path / "config" / "sandbox").mkdir(parents=True)
    monkeypatch.delenv("ALFRED_SANDBOX_POLICY_DIR", raising=False)
    rc = manifest_reader.main(
        [
            "--policy-to-bwrap-flags",
            "--policy-ref",
            "config/sandbox/../../etc/passwd",
            "--install-root",
            str(tmp_path),
        ]
    )
    assert rc == 1
    assert "policy_ref_escapes_root" in capsys.readouterr().err


def test_policy_to_bwrap_flags_ref_default_install_root(tmp_path, monkeypatch, capsys) -> None:
    # No --install-root → cwd. Run with cwd pointed at tmp_path.
    root = tmp_path / "config" / "sandbox"
    root.mkdir(parents=True)
    (root / "foo.linux.bwrap.policy").write_text("keep_fds = [3]\n")
    monkeypatch.delenv("ALFRED_SANDBOX_POLICY_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    rc = manifest_reader.main(
        ["--policy-to-bwrap-flags", "--policy-ref", "config/sandbox/foo.linux.bwrap.policy"]
    )
    assert rc == 0
    assert "--sync-fd" in capsys.readouterr().out.splitlines()


# --------------------------------------------------------------------------
# argument handling
# --------------------------------------------------------------------------


def test_no_mode_exits_nonzero() -> None:
    with pytest.raises(SystemExit) as exc_info:
        manifest_reader.main([])
    assert exc_info.value.code != 0


class _StdinStub:
    """Minimal stdin replacement whose ``read()`` returns canned text."""

    def __init__(self, text: str) -> None:
        self._text = text

    def read(self) -> str:
        return self._text

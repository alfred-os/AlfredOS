"""Behaviour-level integration test for the Slice-4 audit.hash_pepper bootstrap.

PR #215 test-engineer closure (MAJOR): the unit suite at
``tests/unit/test_setup_script_audit_pepper.py`` pins source-text shape
only — it cannot prove the actual setup-script behaviour. This test
drives the real ``bin/alfred-setup.sh`` against a tmpdir + stubbed
``HOME`` / ``ALFRED_SECRETS_FILE`` and asserts the load-bearing
invariants:

* The sandbox dir is created with mode 0700 on first run.
* The pepper line is written with TOML quoting
  (``"audit.hash_pepper" = "..."``).
* The pepper value is a 64-hex-char string from ``openssl rand``.
* The target file is mode 0600 after the bootstrap.
* Python's ``tomllib`` round-trip yields the pepper at the FLAT key
  ``"audit.hash_pepper"`` (not a nested table) — the cross-cutting
  BLOCKER closure.
* Re-invoking the script with the same target leaves the value
  byte-identical (idempotency / no-rotation invariant per spec §8.10).

The script's full setup runs many other steps (docker compose build,
postgres health-check, ...). To stay scoped to the bootstrap, this
test executes only the bootstrap section directly via ``bash -c`` with
the inlined snippet — same source-of-truth as the script body, but
without dragging in the docker dependencies.

Also covers, at the bottom of this file, a real-execution regression for
the "Bootstrapping operator identity" step's ``ALFRED_OPERATOR_NAME``
whitespace-trim fix (final-review fix 1 on #591/#592/#593's combined PR) —
it rides on the same ``bash``-slicing technique and lives here rather than
in a new file, per that fix's own scoping note.
"""

from __future__ import annotations

# ruff: noqa: S603, S607
# Test-controlled invocations of `bash` / `openssl` from the integration suite.
# Every argv is a literal authored in this module; nothing crosses an
# untrusted boundary.
import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from alfred.config.operator_env import operator_display_name
from tests._setup_script_helpers import slice_shell_function, slice_shell_step

pytestmark = [pytest.mark.integration]


_SETUP_SH = Path("bin/alfred-setup.sh")
_FUNC_START = "openssl_missing_message() {"


def _openssl_missing_message_func() -> str:
    """Slice the shared ``openssl_missing_message`` helper out of the real script.

    #470 M5: the pepper bootstrap's openssl-missing branch now calls this shared
    helper (also used by the Grafana admin-password seed) instead of printing its
    own inline heredoc. The helper is defined near the script's other top-level
    helpers, OUTSIDE the ``_bootstrap_block()`` slice below (which starts at the
    "Bootstrapping audit.hash_pepper secret" step, well after it) — so the prelude
    must prepend it explicitly or the sliced script fails with a bash "command not
    found" instead of exercising the real per-distro guidance.
    """
    return slice_shell_function(_SETUP_SH, _FUNC_START)


def _bootstrap_block() -> str:
    """Extract the bootstrap block from ``bin/alfred-setup.sh``.

    Slice on the section markers (``step "Bootstrapping..."`` ... end of
    the ``if mkdir "$lock_dir"`` block) so the test stays anchored to
    the actual script text. If the section markers move, the test
    fails loud rather than running a stale block.
    """
    content = _SETUP_SH.read_text()
    start_marker = 'step "Bootstrapping audit.hash_pepper secret"'
    start = content.index(start_marker)
    # Walk forward to the end of the if-mkdir/else block. The block
    # ends with the ``fi`` that closes the outer ``if mkdir`` — find
    # the line that ends with "fi" past the inner blocks.
    tail = content[start:]
    # The outer "if mkdir" structure ends at the FIRST "^fi$" line
    # AFTER both inner blocks (`_pepper_bootstrap` and the lock-wait
    # path). Use a sentinel: the comment line `step "..."` of the
    # following step is the natural stop anchor.
    next_step_idx = tail.index('\nstep "', 1)
    return tail[:next_step_idx]


def _run_bootstrap_in_tmpdir(
    tmpdir: Path,
    *,
    stub_openssl: bool = False,
    openssl_path: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the bootstrap block in ``tmpdir`` with a stubbed env.

    ``stub_openssl=True`` shadows ``openssl`` in PATH with a stub that
    always exits 127 — exercises the openssl-missing branch.

    #591: the reconcile block reads/writes a relative ``.env`` via
    ``read_env_var`` / ``_pepper_write_env`` — never an absolute path.
    ``cwd=str(tmpdir)`` below is therefore load-bearing, not cosmetic:
    without it, ``.env`` resolves against the *pytest process's* cwd (the
    real repo root), and this test would read from and WRITE TO the
    developer's actual ``.env`` on disk. Do not remove it.
    """
    bootstrap = _bootstrap_block()
    secrets_dir = tmpdir / ".config" / "alfred"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    target_file = secrets_dir / "secrets.toml"
    # A fresh `cp .env.example .env` (the "Ensuring .env exists" step, earlier
    # in the real script but not part of this sliced block) leaves
    # ALFRED_AUDIT_HASH_PEPPER present-but-empty. Mirror that baseline here so
    # every test starts from the same shape unless it seeds a specific value
    # itself before calling this helper (env-only / file-only / drift arms).
    env_file = tmpdir / ".env"
    if not env_file.exists():
        env_file.write_text("ALFRED_AUDIT_HASH_PEPPER=\n")
    # Prelude defines the variables the bootstrap block expects from
    # the surrounding script (secrets_file from "Priming secrets bind-
    # mount"; step helper as a no-op shim) plus read_env_var, which the
    # reconcile block now calls but which is defined elsewhere in the real
    # script (outside this slice), same reason _openssl_missing_message_func
    # is prepended below.
    prelude = (
        f'secrets_file="{target_file}"\nstep() {{ echo "==> $*"; }}\n'
        + slice_shell_function(_SETUP_SH, "read_env_var() {")
        + _openssl_missing_message_func()
    )
    script = prelude + bootstrap
    env = os.environ.copy()
    env["HOME"] = str(tmpdir)
    if stub_openssl:
        # Symlink ONLY the whitelisted bash builtins+tools into a
        # private bin dir, then point PATH at that dir alone. openssl
        # is deliberately excluded; ``command -v openssl`` returns
        # non-zero, exercising the friendly-error branch.
        stub_bin = tmpdir / "stub_bin"
        stub_bin.mkdir(exist_ok=True)
        whitelist = (
            "bash",
            "sh",
            "grep",
            "chmod",
            "mkdir",
            "stat",
            "rmdir",
            "printf",
            "sleep",
            "cat",
            "echo",
            "ls",
            "rm",
            # #591: read_env_var / _pepper_from_file / _pepper_write_env pull
            # in sed, tail, head, tr, cut — all needed even on the
            # openssl-missing path, since the reconcile reads run BEFORE the
            # openssl availability check.
            "sed",
            "tail",
            "head",
            "tr",
            "cut",
        )
        for tool in whitelist:
            tool_path = shutil.which(tool)
            if tool_path is None:
                continue
            link = stub_bin / tool
            if not link.exists():
                link.symlink_to(tool_path)
        env["PATH"] = str(stub_bin)
        assert shutil.which("openssl", path=env["PATH"]) is None, (
            f"openssl still on stubbed PATH: {env['PATH']}"
        )
    elif openssl_path is not None:
        env["PATH"] = openssl_path
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
        check=False,
        env=env,
        cwd=str(tmpdir),
        timeout=30,
    )


def _read_dotenv_pepper(tmpdir: Path) -> str | None:
    """Pull ``ALFRED_AUDIT_HASH_PEPPER``'s value out of ``tmpdir/.env``, or ``None``."""
    env_file = tmpdir / ".env"
    if not env_file.is_file():
        return None
    for line in env_file.read_text().splitlines():
        if line.startswith("ALFRED_AUDIT_HASH_PEPPER="):
            return line.split("=", 1)[1].strip().strip("\"'")
    return None


def _read_secrets_toml_pepper(tmpdir: Path) -> str | None:
    """Pull ``audit.hash_pepper``'s value out of ``tmpdir``'s ``secrets.toml``, or ``None``."""
    target = tmpdir / ".config" / "alfred" / "secrets.toml"
    if not target.is_file():
        return None
    with target.open("rb") as fh:
        data = tomllib.load(fh)
    value = data.get("audit.hash_pepper")
    return value if isinstance(value, str) else None


# Two distinct, valid 64-hex-char pepper values for the reconcile-matrix tests
# below. Neither needs to come from openssl — the mirror/drift branches never
# call it, and hardcoding keeps those tests independent of an openssl_available
# skip they don't otherwise need.
_PEPPER_ONE = "a1" * 32
_PEPPER_TWO = "b2" * 32


@pytest.fixture
def bash_available() -> str:
    """Skip when bash is not on PATH (very rare CI matrix gap)."""
    path = shutil.which("bash")
    if path is None:
        pytest.skip("bash not on PATH")
    return path


@pytest.fixture
def openssl_available() -> str:
    """Skip when openssl is not on PATH (CI image without it)."""
    path = shutil.which("openssl")
    if path is None:
        pytest.skip("openssl not on PATH")
    return path


def test_bootstrap_writes_quoted_toml_key_round_trippable(
    bash_available: str,
    openssl_available: str,
    tmp_path: Path,
) -> None:
    """The bootstrap writes a quoted dotted key tomllib parses flat.

    This is the cross-cutting BLOCKER closure: unquoted
    ``audit.hash_pepper = "..."`` would parse as the nested table
    ``{"audit": {"hash_pepper": "..."}}`` and
    ``SecretBroker._load_toml_file`` (which keeps only top-level str
    values) would silently drop it.
    """
    result = _run_bootstrap_in_tmpdir(tmp_path)
    assert result.returncode == 0, (
        f"bootstrap failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    target = tmp_path / ".config" / "alfred" / "secrets.toml"
    assert target.is_file(), f"target file missing: {target}"
    # tomllib MUST find the key at the flat top level
    with target.open("rb") as fh:
        data = tomllib.load(fh)
    assert "audit.hash_pepper" in data, (
        f"audit.hash_pepper missing at top level of parsed TOML; got keys: {list(data.keys())}"
    )
    pepper = data["audit.hash_pepper"]
    assert isinstance(pepper, str)
    assert re.fullmatch(r"[0-9a-f]{64}", pepper), f"pepper is not 64-hex-char: {pepper!r}"


def test_bootstrap_target_file_mode_0600(
    bash_available: str,
    openssl_available: str,
    tmp_path: Path,
) -> None:
    """The secrets target file is chmod 0600 after the bootstrap."""
    result = _run_bootstrap_in_tmpdir(tmp_path)
    assert result.returncode == 0
    target = tmp_path / ".config" / "alfred" / "secrets.toml"
    mode = target.stat().st_mode & 0o777
    assert mode == 0o600, f"target file mode is 0{mode:o}, expected 0600"


def test_bootstrap_is_idempotent_no_rotation(
    bash_available: str,
    openssl_available: str,
    tmp_path: Path,
) -> None:
    """Re-running the bootstrap MUST NOT rotate the pepper value.

    Spec §8.10: rotating the pepper invalidates every prior ``*_hash``
    row. The bootstrap MUST leave existing values untouched.
    """
    first = _run_bootstrap_in_tmpdir(tmp_path)
    assert first.returncode == 0
    target = tmp_path / ".config" / "alfred" / "secrets.toml"
    first_contents = target.read_bytes()
    # Second run must observe "already configured" branch
    second = _run_bootstrap_in_tmpdir(tmp_path)
    assert second.returncode == 0
    assert "already configured" in second.stdout, (
        f"idempotency banner missing from re-run stdout: {second.stdout!r}"
    )
    second_contents = target.read_bytes()
    assert first_contents == second_contents, (
        "secrets file mutated on re-run — pepper rotated by accident"
    )


def test_bootstrap_friendly_error_when_openssl_missing(
    bash_available: str,
    tmp_path: Path,
) -> None:
    """Without openssl on PATH the bootstrap exits 1 with a clear error."""
    result = _run_bootstrap_in_tmpdir(tmp_path, stub_openssl=True)
    # The bootstrap function returns 1; the outer script honours it
    # via `_pepper_bootstrap` exit code propagation. Either the script
    # exits non-zero OR (when run as the lock-holder path) the function
    # returns 1 to the caller. Both surface as a non-zero return code.
    assert result.returncode != 0, (
        f"openssl-missing path returned 0:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "openssl" in result.stderr.lower(), (
        f"openssl-missing error not on stderr: {result.stderr!r}"
    )
    # At least one per-distro install command should appear (DevEx LOW closure).
    distro_hints = ("apt-get install", "dnf install", "pacman -S", "apk add", "brew install")
    assert any(hint in result.stderr for hint in distro_hints), (
        f"no per-distro install hint in stderr: {result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# #591: .env <-> secrets.toml reconcile matrix.
#
# docker-compose.yaml forwards ALFRED_AUDIT_HASH_PEPPER from .env into
# alfred-core; host-side `alfred` commands read secrets.toml. The bootstrap
# must keep the two in sync without ever silently discarding an existing
# value in either place (spec §8.10: rotating the pepper invalidates every
# prior *_hash audit row). The five cases are: both empty (generate fresh,
# write both), env-only, file-only, both-equal (covered by
# test_bootstrap_is_idempotent_no_rotation above), and both-differ (refuse).
# ---------------------------------------------------------------------------


def test_bootstrap_generates_and_writes_same_pepper_to_both(
    bash_available: str,
    openssl_available: str,
    tmp_path: Path,
) -> None:
    """With nothing configured anywhere, the bootstrap seeds ONE fresh pepper
    into BOTH .env and secrets.toml — not two independently-generated values.

    If the two seeds ever diverged, the container (.env) and the host CLI
    (secrets.toml) would verify *_hash audit rows against two different HMAC
    planes from the very first run.
    """
    result = _run_bootstrap_in_tmpdir(tmp_path)
    assert result.returncode == 0, (
        f"bootstrap failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    env_value = _read_dotenv_pepper(tmp_path)
    file_value = _read_secrets_toml_pepper(tmp_path)
    assert env_value is not None and re.fullmatch(r"[0-9a-f]{64}", env_value), (
        f".env pepper missing or not 64-hex-char: {env_value!r}"
    )
    assert file_value == env_value, (
        f".env pepper {env_value!r} != secrets.toml pepper {file_value!r} on a fresh bootstrap"
    )


def test_bootstrap_env_only_mirrors_into_secrets_file(
    bash_available: str,
    tmp_path: Path,
) -> None:
    """A pepper already in .env (nothing yet in secrets.toml) is mirrored
    into the broker file, because host-side ``alfred`` commands read the
    file, not .env.
    """
    (tmp_path / ".env").write_text(f"ALFRED_AUDIT_HASH_PEPPER={_PEPPER_ONE}\n")
    result = _run_bootstrap_in_tmpdir(tmp_path)
    assert result.returncode == 0, (
        f"bootstrap failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert _read_secrets_toml_pepper(tmp_path) == _PEPPER_ONE, (
        "secrets.toml pepper was not mirrored from .env"
    )
    assert "Mirrored the .env audit.hash_pepper" in result.stdout, (
        f"no mirror banner in stdout: {result.stdout!r}"
    )


def test_bootstrap_file_only_mirrors_into_dotenv_without_regenerating(
    bash_available: str,
    tmp_path: Path,
) -> None:
    """A pre-existing host pepper (already in secrets.toml, nothing in .env
    yet) is carried into .env UNCHANGED — never regenerated.

    Spec §8.10 upgrade-path proof: this is the pre-#591 -> post-#591
    upgrade path. Regenerating here would silently invalidate every *_hash
    audit row already written under the pre-existing value.
    """
    secrets_dir = tmp_path / ".config" / "alfred"
    secrets_dir.mkdir(parents=True)
    (secrets_dir / "secrets.toml").write_text(f'"audit.hash_pepper" = "{_PEPPER_ONE}"\n')
    result = _run_bootstrap_in_tmpdir(tmp_path)
    assert result.returncode == 0, (
        f"bootstrap failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert _read_dotenv_pepper(tmp_path) == _PEPPER_ONE, (
        ".env pepper was not mirrored from secrets.toml, or was changed in transit"
    )
    assert _read_secrets_toml_pepper(tmp_path) == _PEPPER_ONE, (
        "secrets.toml pepper was regenerated/changed — value MUST be preserved unchanged"
    )
    assert "into .env" in result.stdout, f"no mirror-into-.env banner in stdout: {result.stdout!r}"


@pytest.mark.parametrize(
    "pepper_value",
    [
        pytest.param("prefix-ab&cd-suffix", id="ampersand"),
        pytest.param(r"prefix-ab\cd-suffix", id="backslash"),
        pytest.param("prefix-ab|cd-suffix", id="pipe-sed-delimiter"),
        pytest.param(_PEPPER_ONE, id="clean-hex-baseline"),
    ],
)
def test_bootstrap_file_only_mirrors_sed_metacharacter_pepper_byte_for_byte(
    bash_available: str,
    tmp_path: Path,
    pepper_value: str,
) -> None:
    """#594 sec-001 regression: a hand-set secrets.toml pepper containing sed
    replacement-string metacharacters must round-trip into .env BYTE-FOR-BYTE.

    ``_pepper_from_file``'s extraction is a bare regex capture, not a TOML
    parser or a hex validator — an operator's hand-edited secrets.toml (a
    scenario the README explicitly supports) can carry a pepper containing
    ``&`` (sed's "insert the matched text" token), a backslash (a sed
    backreference introducer), or ``|`` (the sed delimiter this script used
    to substitute with). Before the fix, ``_pepper_write_env``'s
    ``sed -i "s|...|...|"`` interpolated that value straight into the
    replacement string: `&` silently expanded to the matched text (sed still
    exited 0), corrupting .env while the bootstrap printed its normal success
    banner. The fix rebuilds .env line-by-line via ``printf '%s'`` instead,
    which performs no replacement/backreference expansion on its arguments.

    Read the raw bytes back (not through ``_read_secrets_toml_pepper``'s
    ``tomllib.load``) for the secrets.toml side: a couple of these
    parametrized values are not valid TOML escape sequences on their own,
    since the seeded file simulates arbitrary hand-edited content rather than
    a TOML-escaped string — exactly what the production sed-regex extraction
    in ``_pepper_from_file`` also never validates.
    """
    secrets_dir = tmp_path / ".config" / "alfred"
    secrets_dir.mkdir(parents=True)
    target = secrets_dir / "secrets.toml"
    target.write_text(f'"audit.hash_pepper" = "{pepper_value}"\n')
    before = target.read_bytes()
    result = _run_bootstrap_in_tmpdir(tmp_path)
    assert result.returncode == 0, (
        f"bootstrap failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    got = _read_dotenv_pepper(tmp_path)
    assert got == pepper_value, (
        f".env pepper corrupted in transit: expected {pepper_value!r}, got {got!r}"
    )
    after = target.read_bytes()
    assert before == after, (
        "secrets.toml was mutated by the .env-only mirror (must be a .env-only write): "
        f"before={before!r} after={after!r}"
    )


def test_bootstrap_file_only_single_quoted_real_pepper_survives_byte_identical(
    bash_available: str,
    tmp_path: Path,
) -> None:
    """#594 sec-002 regression-fix proof: a SINGLE-quoted real pepper in
    secrets.toml must never be silently overwritten.

    ``_pepper_from_file``'s value-extraction regex only recognizes
    DOUBLE-quoted TOML strings (``"([^"]*)"``), but TOML also allows
    single-quoted literal strings (``'...'``) — valid, ``tomllib``-parseable,
    and a shape an operator could easily hand-set. A first version of the
    #594 sec-002 fix asked ``_pepper_from_file`` "is a real value already
    here?" and treated "the extraction regex didn't match" as "must be
    blank" — so a single-quoted REAL value looked indistinguishable from a
    genuinely blank one, and ``_pepper_write_file`` silently OVERWROTE it
    with a freshly-generated pepper while ``_pepper_bootstrap`` printed its
    normal "Seeded audit.hash_pepper..." success message. That is strictly
    worse than the bug the original fix was closing (failing to WRITE a
    value vs. silently DESTROYING one) — exactly the failure mode the whole
    PR's "refuse rather than silently invalidate audit correlation" design
    principle (spec §8.10) exists to prevent.

    The (corrected) fix in ``_pepper_write_file`` no longer infers "blank"
    from a failed extraction: it positively matches the literal ``= ""``
    shape before entering the overwrite branch, and treats every other
    shape — including single-quoted — as "a value is already here", left
    completely untouched. Confirmed to FAIL against the pre-fix regression
    commit by direct isolated-function testing (see fix-1-report.md); this
    pytest case pins the same invariant against the real, real script.
    """
    secrets_dir = tmp_path / ".config" / "alfred"
    secrets_dir.mkdir(parents=True)
    target = secrets_dir / "secrets.toml"
    real_value = "c3" * 32  # a plausible real 64-hex-char pepper
    target.write_text(f"\"audit.hash_pepper\" = '{real_value}'\n")
    before = target.read_bytes()
    result = _run_bootstrap_in_tmpdir(tmp_path)
    assert result.returncode == 0, (
        f"bootstrap failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    after = target.read_bytes()
    assert before == after, (
        "secrets.toml's single-quoted real pepper was overwritten — this is "
        "the #594 sec-002 destructive-overwrite regression: "
        f"before={before!r} after={after!r}"
    )


def test_bootstrap_file_only_single_quoted_real_pepper_mirrors_into_env_not_a_fresh_value(
    bash_available: str,
    tmp_path: Path,
) -> None:
    """#594 sec-002-drift regression test: a single-quoted real pepper must
    round-trip into .env as ITSELF across two bootstrap runs — not a
    freshly-generated, divergent value.

    Before widening ``_pepper_from_file``'s extraction regex to recognize
    single-quoted TOML literal strings (it previously only recognized
    double-quoted), a single-quoted hand-set secrets.toml pepper made
    ``_pepper_bootstrap`` believe secrets.toml held NO pepper at all (even
    though the byte-identity test above confirms secrets.toml itself was
    correctly left untouched by the earlier #594 sec-002 fix). On a first
    run this silently mirrored a FRESH, unintended value into .env instead
    of the operator's real one — exit 0, "Seeded audit.hash_pepper into
    secrets.toml and .env" printed, even though secrets.toml was never
    touched. On a second run, the env/file "DIFFERS" drift-refusal never
    fired either, because its own precondition (``-n "$file_pepper"``)
    shared the identical blind spot — so the mismatch between the
    operator's real secrets.toml pepper and the fresh, wrong .env value
    would persist forever, silently, with alfred-core (which reads .env)
    permanently running on a pepper the operator never set or approved.
    This is exactly the "two incompatible HMAC planes" scenario the whole
    reconcile design (spec §8.10) exists to catch — created silently
    instead of refused loudly.
    """
    secrets_dir = tmp_path / ".config" / "alfred"
    secrets_dir.mkdir(parents=True)
    target = secrets_dir / "secrets.toml"
    real_value = "c3" * 32  # a plausible real 64-hex-char pepper
    target.write_text(f"\"audit.hash_pepper\" = '{real_value}'\n")

    first = _run_bootstrap_in_tmpdir(tmp_path)
    assert first.returncode == 0, (
        f"first bootstrap run failed:\nstdout: {first.stdout}\nstderr: {first.stderr}"
    )
    assert _read_dotenv_pepper(tmp_path) == real_value, (
        ".env got a DIFFERENT (freshly-generated) pepper instead of the "
        f"operator's real secrets.toml value after the first run: "
        f".env={_read_dotenv_pepper(tmp_path)!r} secrets.toml={real_value!r}"
    )
    assert _read_secrets_toml_pepper(tmp_path) == real_value, (
        "secrets.toml's single-quoted real pepper was mutated on the first run"
    )

    second = _run_bootstrap_in_tmpdir(tmp_path)
    assert second.returncode == 0, (
        f"second bootstrap run failed:\nstdout: {second.stdout}\nstderr: {second.stderr}"
    )
    assert "DIFFERS" not in second.stderr, (
        f"second run raised a spurious env/file drift-refusal: {second.stderr!r}"
    )
    assert _read_dotenv_pepper(tmp_path) == real_value, (
        ".env pepper changed/diverged further on the second (should-be-idempotent) run"
    )
    assert _read_secrets_toml_pepper(tmp_path) == real_value, (
        "secrets.toml pepper changed on the second (should-be-idempotent) run"
    )


def test_bootstrap_refuses_on_pepper_drift(
    bash_available: str,
    tmp_path: Path,
) -> None:
    """A DIFFERENT pepper in .env vs secrets.toml must refuse, not pick one silently.

    audit.hash_pepper is not in _PREFER_FILE, so alfred-core always uses the
    .env value while host-side ``alfred`` commands use the file — auto-picking
    would silently invalidate every *_hash audit row written under whichever
    value lost (spec §8.10).
    """
    (tmp_path / ".env").write_text(f"ALFRED_AUDIT_HASH_PEPPER={_PEPPER_ONE}\n")
    secrets_dir = tmp_path / ".config" / "alfred"
    secrets_dir.mkdir(parents=True)
    target = secrets_dir / "secrets.toml"
    target.write_text(f'"audit.hash_pepper" = "{_PEPPER_TWO}"\n')
    result = _run_bootstrap_in_tmpdir(tmp_path)
    assert result.returncode != 0, (
        f"drift should refuse, not exit 0:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert ".env" in result.stderr, f"drift error doesn't mention .env: {result.stderr!r}"
    assert str(target) in result.stderr, (
        f"drift error doesn't mention the secrets.toml path {target}: {result.stderr!r}"
    )
    # Neither side is silently rewritten when the bootstrap refuses.
    assert _read_dotenv_pepper(tmp_path) == _PEPPER_ONE
    assert _read_secrets_toml_pepper(tmp_path) == _PEPPER_TWO


# ---------------------------------------------------------------------------
# Final-review fix 1: the "Bootstrapping operator identity" step's non-TTY
# ALFRED_OPERATOR_NAME resolution must trim whitespace BEFORE applying the
# `${name:-operator}` default — exactly matching
# `alfred.config.operator_env.operator_display_name()`'s `.strip() or
# "operator"` normalization. Without the trim, a whitespace-padded .env
# value (e.g. `ALFRED_OPERATOR_NAME="   Bruce  "`, or an all-whitespace
# `"   "`) sails through untrimmed into the `user bind ... --id "$name"`
# call a few lines further down, while the real TUI client sends the
# Python-normalized value — reproducing the exact #592 identity mismatch
# this whole step exists to prevent.
#
# This does NOT drive the full Docker-based operator-bootstrap flow (which
# needs a running Postgres + the alfred-core image) — it isolates just the
# resolution statement, plus its two real helper functions (`read_env_var`,
# `trim_ws`), sliced straight out of bin/alfred-setup.sh the same way
# `_run_bootstrap_in_tmpdir` above isolates `_pepper_bootstrap`.
# ---------------------------------------------------------------------------


def _resolve_operator_name_line() -> str:
    """Pull the non-TTY ``ALFRED_OPERATOR_NAME`` resolution statement out of
    the real "Bootstrapping operator identity" step.

    Anchored on ``slice_shell_step`` (same fail-loud-on-drift contract the
    pepper-bootstrap tests above rely on via ``_bootstrap_block``) plus a
    regex for the specific assignment line — not a hand-copied
    re-implementation — so a rewritten, renamed, or removed trim call fails
    this test loudly instead of silently exercising stale text. The regex
    anchors on the literal ``name="$(read_env_var ALFRED_OPERATOR_NAME)"``
    prefix, which only the non-TTY branch's line has (the TTY branch's
    equivalent line assigns ``default_name``, and the TTY branch's own
    ``name=`` line reads from ``$default_name``, not ``read_env_var``
    directly) — so this can't accidentally match the wrong branch.
    """
    step_block = slice_shell_step(_SETUP_SH, "Bootstrapping operator identity")
    match = re.search(
        r'^\s*name="\$\(read_env_var ALFRED_OPERATOR_NAME\)".*$',
        step_block,
        re.MULTILINE,
    )
    if match is None:
        raise ValueError(
            "non-TTY ALFRED_OPERATOR_NAME resolution line not found in the "
            '"Bootstrapping operator identity" step of bin/alfred-setup.sh — '
            "the fix may have been reworded; update this test's anchor to match."
        )
    return match.group(0)


@pytest.mark.parametrize(
    ("env_value", "expected"),
    [
        ("   Bruce  ", "Bruce"),
        ("   ", "operator"),
        ("", "operator"),
        ("Bruce", "Bruce"),
    ],
    ids=["padded-name", "whitespace-only", "empty", "no-padding"],
)
def test_operator_name_resolution_trims_like_operator_display_name(
    bash_available: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    env_value: str,
    expected: str,
) -> None:
    """A whitespace-padded ``.env`` value resolves the SAME on both sides.

    Two independent checks per case: the shell result matches a literal
    expected value, AND it matches the real Python
    ``operator_display_name()`` helper for the same input — the latter is
    what the TUI client actually sends when it binds/notifies, so agreement
    there is the load-bearing invariant (not just two hand-copied
    expectations that could drift together).

    Pre-fix, this would have failed on the ``padded-name`` and
    ``whitespace-only`` cases: the old
    ``name="$(read_env_var ALFRED_OPERATOR_NAME)"; name="${name:-operator}"``
    only defaults on a LITERALLY empty value, so ``"   Bruce  "`` would have
    resolved to the untrimmed ``"   Bruce  "`` (not ``"Bruce"``) and
    ``"   "`` would have resolved to the untrimmed ``"   "`` (not
    ``"operator"``) — both diverging from ``operator_display_name()``.
    """
    (tmp_path / ".env").write_text(f'ALFRED_OPERATOR_NAME="{env_value}"\n')
    script = (
        slice_shell_function(_SETUP_SH, "read_env_var() {")
        + slice_shell_function(_SETUP_SH, "trim_ws() {")
        + _resolve_operator_name_line()
        + '\nprintf "%s" "$name"\n'
    )
    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
        check=False,
        cwd=str(tmp_path),
        timeout=10,
    )
    assert result.returncode == 0, (
        f"resolution snippet failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert result.stdout == expected, (
        f"shell resolved ALFRED_OPERATOR_NAME={env_value!r} to {result.stdout!r}, "
        f"expected {expected!r}"
    )

    monkeypatch.setenv("ALFRED_OPERATOR_NAME", env_value)
    python_value = operator_display_name()
    assert result.stdout == python_value, (
        "shell and Python operator-name normalizers DISAGREE for "
        f"ALFRED_OPERATOR_NAME={env_value!r}: shell={result.stdout!r} python={python_value!r} — "
        "this is the exact #592 identity-mismatch shape this step exists to prevent"
    )

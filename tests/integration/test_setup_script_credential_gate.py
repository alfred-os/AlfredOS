"""Behaviour-level test for ``bin/alfred-setup.sh``'s .env credential gate.

UAT drove a stock first run — `cp .env.example .env && bin/alfred-setup.sh` — and the
script exited 1 on the DeepSeek `sk-...` placeholder shipped in `.env.example` itself.
The quarantine-key warning, added precisely because a keyless stack now REFUSE-BOOTS,
sat further down the script and was therefore UNREACHABLE on the one run it existed for.
The operator fixed the DeepSeek key, re-ran, and only then met the second required key.

A source-text assertion cannot catch that: both checks were present in the file the whole
time. Only ORDER made one dead. So this test runs the real block under `bash` and asserts
on what an operator actually sees.

It also pins the compose-precedence correction. The old text told an operator whose key
was exported in the shell but absent from `.env` that "docker compose reads .env, so the
stack will still refuse to boot". That is false — compose gives the shell environment
precedence over `.env`, so that stack boots. Verified directly::

    $ cat .env                       # FOO=from_dotenv
    $ FOO=from_shell docker compose config | grep FOO
          FOO: from_shell

Telling an operator their working setup is broken costs more than saying nothing.
"""

from __future__ import annotations

# ruff: noqa: S603, S607
# Test-controlled `bash` invocations from the integration suite. Every argv is a literal
# authored in this module; nothing crosses an untrusted boundary.
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]

_ROOT = Path(__file__).resolve().parents[2]
_SETUP_SH = _ROOT / "bin" / "alfred-setup.sh"
_ENV_EXAMPLE = _ROOT / ".env.example"

_BLOCK_START = 'step "Validating .env credentials"'
_BLOCK_END = 'echo ".env credentials OK."'


def _credential_gate_block() -> str:
    """Slice the credential gate out of the real script, with the helpers it needs.

    Anchored on the section markers so a moved/renamed block fails loud here rather than
    silently running a stale copy. The helper prelude (`warn` / `step` / `read_env_var`)
    is sliced from the script too, not retyped, so the test can never drift from the
    definitions the script actually uses.
    """
    content = _SETUP_SH.read_text()
    prelude_start = content.index("step() {")
    prelude_end = content.index(_BLOCK_START)
    block_end = content.index(_BLOCK_END) + len(_BLOCK_END)
    prelude = content[prelude_start:prelude_end]
    # Drop everything in the prelude that needs docker/jq — we want the pure helpers.
    prelude = prelude[: prelude.index('step "Checking prerequisites"')]
    body = content[content.index(_BLOCK_START) : block_end]
    return "set -euo pipefail\n" + prelude + body


def _run_gate(
    tmp_path: Path, env_text: str, extra_env: dict[str, str] | None = None
) -> tuple[int, str, str]:
    """Run the sliced credential gate in ``tmp_path`` against ``env_text`` as ``.env``."""
    (tmp_path / ".env").write_text(env_text)
    script = tmp_path / "gate.sh"
    script.write_text(_credential_gate_block())
    proc = subprocess.run(
        ["bash", str(script)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
        # Start from a clean slate so a real key in the developer's own shell cannot
        # leak in and flip the shell-precedence branch under test.
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", **(extra_env or {})},
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_the_slice_markers_still_match_the_script() -> None:
    """Guard the guard — a silently-empty slice would make every test below vacuous."""
    block = _credential_gate_block()
    assert "ALFRED_DEEPSEEK_API_KEY" in block
    assert "ALFRED_QUARANTINE_PROVIDER_API_KEY" in block
    assert "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION" in block
    assert "read_env_var" in block


def test_stock_first_run_reports_both_missing_credentials(tmp_path: Path) -> None:
    """The exact UAT scenario: `.env.example` copied verbatim.

    Both problems must appear in ONE report. Before the fix the run died on the DeepSeek
    placeholder and never mentioned the quarantine key at all.
    """
    code, _out, err = _run_gate(tmp_path, _ENV_EXAMPLE.read_text())

    assert code == 1, "a stock .env.example copy must not pass the credential gate"
    assert "ALFRED_DEEPSEEK_API_KEY" in err
    assert "ALFRED_QUARANTINE_PROVIDER_API_KEY" in err, (
        "the quarantine-key problem is STILL unreachable on a stock first run — this is "
        "the exact ordering bug the gate was restructured to fix"
    )
    assert "sk-..." in err, "the DeepSeek problem must name the placeholder it found"


def test_the_stock_report_is_actionable(tmp_path: Path) -> None:
    """Each problem states what to do next, and the run says what state it left behind."""
    _code, _out, err = _run_gate(tmp_path, _ENV_EXAMPLE.read_text())
    assert "platform.deepseek.com" in err
    assert "refuse to boot" in err.lower()
    assert "Nothing was changed" in err, (
        "a setup script that exits must tell the operator what state they are in"
    )


def test_only_the_quarantine_key_missing_is_reported_alone(tmp_path: Path) -> None:
    """A second-run operator who fixed DeepSeek sees only what is still wrong."""
    code, _out, err = _run_gate(
        tmp_path, "ALFRED_DEEPSEEK_API_KEY=sk-real\nALFRED_QUARANTINE_PROVIDER_API_KEY=\n"
    )
    assert code == 1
    assert "ALFRED_QUARANTINE_PROVIDER_API_KEY" in err
    assert "ALFRED_DEEPSEEK_API_KEY" not in err


def test_both_keys_present_passes(tmp_path: Path) -> None:
    """The happy path is quiet and exits 0."""
    code, out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\nALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n",
    )
    assert code == 0, err
    assert "ALFRED_QUARANTINE_PROVIDER_API_KEY is configured in .env." in out
    assert ".env credentials OK." in out


def test_shell_only_quarantine_key_is_not_reported_as_a_boot_failure(tmp_path: Path) -> None:
    """The item-2 correction: shell-set + .env-absent BOOTS. Do not claim otherwise.

    docker compose gives the shell environment precedence over `.env`, so this operator's
    stack starts. The old warning asserted it "will still refuse to boot".
    """
    code, out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n",
        extra_env={"ALFRED_QUARANTINE_PROVIDER_API_KEY": "sk-from-shell"},
    )
    combined = out + err

    assert code == 0, f"a shell-exported key must not fail the gate: {combined!r}"
    assert "refuse to boot" not in combined.lower(), (
        "the gate still tells an operator whose stack boots fine that it will not boot"
    )
    # The real caveat — durability across terminals — is still worth saying.
    assert "precedence" in combined
    assert "durable" in combined


def test_empty_env_file_reports_both(tmp_path: Path) -> None:
    """An operator who wrote their own `.env` from scratch gets the same complete report."""
    code, _out, err = _run_gate(tmp_path, "")
    assert code == 1
    assert "ALFRED_DEEPSEEK_API_KEY" in err
    assert "ALFRED_QUARANTINE_PROVIDER_API_KEY" in err


# --------------------------------------------------------------------------- #
# #587: ALFRED_QUARANTINE_PROVIDER is a CLOSED SET the gate was blind to.
#
# The gate validated the quarantine KEY while ignoring the setting that decides
# which key is even correct, so a typo (`Anthropic`, `openai`, a quoted value)
# passed setup and surfaced as a settings_invalid crash-loop.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "bad",
    [
        "openai",
        "Anthropic",
        "DeepSeek",
        "gpt-4",
        "none",
        "not-a-real-secret-quarantine-provider-test-placeholder",
    ],
)
def test_out_of_closed_set_quarantine_provider_is_reported(tmp_path: Path, bad: str) -> None:
    """An out-of-set value fails the gate, in the SAME accumulated report as everything else.

    Case variants are pinned deliberately: ``Settings.quarantine_provider`` is a
    ``Literal["anthropic", "deepseek"]`` with no case/whitespace normalisation, so
    ``Anthropic`` really does refuse boot. A gate that accepted it would be worse than
    no gate — it would actively certify a value that crash-loops. The credential-shaped
    row (CodeRabbit) covers the actual incident this parametrize doesn't otherwise
    exercise: ALFRED_QUARANTINE_PROVIDER_API_KEY sits right next to this variable in
    .env, so a credential pasted onto the wrong line is a plausible mistake.
    """
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        f"ALFRED_QUARANTINE_PROVIDER={bad}\n",
    )
    assert code == 1, f"{bad!r} must not pass the gate"
    assert "ALFRED_QUARANTINE_PROVIDER" in err
    # Actionable: names the admissible set...
    assert "anthropic" in err and "deepseek" in err
    # ...but the offending value itself must NEVER be reprinted — the report must not
    # become the leak it exists to prevent (CodeRabbit).
    assert bad not in err, err


@pytest.mark.parametrize("good", ["anthropic", "deepseek"])
def test_supported_quarantine_provider_passes(tmp_path: Path, good: str) -> None:
    """Oracle guard: both real values pass.

    Without this the refusal test above would stay green under a check that rejected
    every value and hard-blocked every operator who set the knob at all.
    """
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        f"ALFRED_QUARANTINE_PROVIDER={good}\n",
    )
    assert code == 0, err


def test_unset_quarantine_provider_passes(tmp_path: Path) -> None:
    """Unset is the shipped default (``anthropic``), not a problem to report."""
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\nALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n",
    )
    assert code == 0, err
    assert "ALFRED_QUARANTINE_PROVIDER is" not in err


def test_shell_set_quarantine_provider_beats_a_valid_dotenv_value(tmp_path: Path) -> None:
    """The gate must check the value the STACK will use, not the one `.env` happens to hold.

    docker compose gives the shell environment precedence over `.env` (the same precedence
    the quarantine-key branch documents). A gate reading `.env` alone would certify the
    dotenv value and wave through a broken shell override — so this pins the direction:
    a bad shell value fails even though `.env` is valid.
    """
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        "ALFRED_QUARANTINE_PROVIDER=deepseek\n",
        extra_env={"ALFRED_QUARANTINE_PROVIDER": "openai"},
    )
    assert code == 1, "a bad shell override must fail even with a valid .env value"
    # Stronger than asserting the raw value: the gate no longer reprints it at all
    # (CodeRabbit), so the discriminator is that it names WHICH source it read from —
    # proving it actually preferred the shell over .env, not just that it read
    # something bad.
    assert "shell environment" in err, err


def test_explicitly_empty_shell_quarantine_provider_does_not_fall_back_to_dotenv(
    tmp_path: Path,
) -> None:
    """An EXPORTED-BUT-EMPTY shell var is the compose default, not "consult .env" (CodeRabbit r2).

    docker-compose.yaml forwards ``ALFRED_QUARANTINE_PROVIDER:
    ${ALFRED_QUARANTINE_PROVIDER:-anthropic}``. Under compose an explicitly-empty shell var
    still WINS over ``.env`` and the container therefore receives the ``anthropic`` default —
    ``.env`` is never consulted. The gate's ``${VAR:-$(read_env_var VAR)}`` collapsed that
    case into "unset" (``:-`` fires on empty as well as unset) and validated the ``.env``
    value instead: a value the stack will not use.

    Discriminating by construction: ``.env`` holds an OUT-OF-SET value, so the two behaviours
    give opposite verdicts. Under the old ``:-`` the gate read ``openai`` from ``.env`` and
    exited 1; under ``${VAR+x}`` it resolves the compose default and exits 0. (The same
    scenario with a VALID ``.env`` value passes either way, so it could not tell fixed from
    broken and is deliberately not the pin here.)
    """
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        "ALFRED_QUARANTINE_PROVIDER=openai\n",
        extra_env={"ALFRED_QUARANTINE_PROVIDER": ""},
    )
    assert code == 0, (
        "an explicitly-empty shell var means the container takes the anthropic default; "
        f"the gate must not validate the unused .env value. stderr: {err}"
    )
    assert "openai" not in err, err


def test_the_report_never_echoes_the_offending_provider_value(tmp_path: Path) -> None:
    """A dedicated oracle for the anti-echo property (CodeRabbit), not a side condition
    of some other test. ``ALFRED_QUARANTINE_PROVIDER_API_KEY`` sits directly beside
    ``ALFRED_QUARANTINE_PROVIDER`` in ``.env`` — a credential pasted onto the wrong line
    is a plausible mistake, and the gate must never copy it into setup output, shell
    scrollback, or a CI log.
    """
    credential = "sk-not-a-real-secret-pasted-onto-the-wrong-env-line"
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        f"ALFRED_QUARANTINE_PROVIDER={credential}\n",
    )
    assert code == 1
    assert credential not in err, err
    # Actionable without the echo: names the field, the source, and the accepted set.
    assert "ALFRED_QUARANTINE_PROVIDER" in err
    assert ".env" in err
    assert "anthropic" in err and "deepseek" in err


# --------------------------------------------------------------------------- #
# #586: ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION is an opt-in REFUSE-BOOT
# posture, newly forwarded to alfred-core by this PR, and the gate was blind to it.
# An operator who enabled the strict posture with one provider for both roles
# passed setup cleanly and only met the crash-loop on `docker compose up -d`.
# --------------------------------------------------------------------------- #


def test_required_separation_with_colliding_providers_is_reported(tmp_path: Path) -> None:
    """The headline scenario this whole check exists for."""
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        "ALFRED_QUARANTINE_PROVIDER=deepseek\n"
        "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=true\n",
    )
    assert code == 1
    assert "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION" in err
    assert "crash-loop" in err.lower()


def test_required_separation_with_distinct_providers_passes(tmp_path: Path) -> None:
    """Oracle guard: the check does not block a genuinely non-colliding, opted-in config."""
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        "ALFRED_QUARANTINE_PROVIDER=anthropic\n"
        "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=true\n",
    )
    assert code == 0, err


def test_required_separation_unset_with_colliding_providers_passes(tmp_path: Path) -> None:
    """The default (unset) posture is warn-only at boot, not refuse — the setup-time
    check mirrors that: no ``require`` line means no collision problem to report,
    even though the providers collide."""
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        "ALFRED_QUARANTINE_PROVIDER=deepseek\n",
    )
    assert code == 0, err


def test_explicit_false_separation_with_colliding_providers_passes(tmp_path: Path) -> None:
    """An explicit ``false`` is the same permitted-but-warned posture as unset."""
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        "ALFRED_QUARANTINE_PROVIDER=deepseek\n"
        "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=false\n",
    )
    assert code == 0, err


def test_dotenv_primary_provider_does_not_change_the_verdict(tmp_path: Path) -> None:
    """The load-bearing test for this whole check's design.

    docker-compose.yaml does not forward ``ALFRED_PRIMARY_PROVIDER`` to ``alfred-core``
    at all (no ``env_file:``, not in the ``environment:`` block, no ``.env`` bind-mount)
    — so under the deployment this script sets up, ``Settings.primary_provider`` ALWAYS
    resolves to its ``deepseek`` default, whatever ``.env`` says. A naive gate that read
    ``ALFRED_PRIMARY_PROVIDER`` from ``.env`` would get this scenario backwards: it would
    see ``anthropic`` here and wave the collision through, while the real container still
    compares ``deepseek`` (its fixed default) against ``ALFRED_QUARANTINE_PROVIDER=
    deepseek`` and crash-loops. This pins that the gate models the CONTAINER's value, not
    the .env value.
    """
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        "ALFRED_QUARANTINE_PROVIDER=deepseek\n"
        "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=true\n"
        "ALFRED_PRIMARY_PROVIDER=anthropic\n",
    )
    assert code == 1, (
        "a .env-only ALFRED_PRIMARY_PROVIDER=anthropic must NOT clear the collision — "
        f"the container never sees it and still dials deepseek. stderr: {err}"
    )


def test_dotenv_primary_provider_does_not_cause_a_false_failure(tmp_path: Path) -> None:
    """The other direction of the test above: a genuinely non-colliding .env-only
    ALFRED_PRIMARY_PROVIDER must not be treated as if it changed the container's fixed
    ``deepseek`` privileged provider — only ALFRED_QUARANTINE_PROVIDER can clear this."""
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        "ALFRED_QUARANTINE_PROVIDER=anthropic\n"
        "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=true\n"
        "ALFRED_PRIMARY_PROVIDER=anthropic\n",
    )
    assert code == 0, err


@pytest.mark.parametrize("truthy", ["true", "True", "TRUE", "1", "yes", "y", "on", "t"])
def test_required_separation_accepts_pydantics_full_truthy_set(tmp_path: Path, truthy: str) -> None:
    """Every spelling pydantic's bool coercion accepts as True must arm the check —
    a gate that only recognised "true" would silently pass an operator who wrote "1"
    or "yes" straight into a crash-loop."""
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        "ALFRED_QUARANTINE_PROVIDER=deepseek\n"
        f"ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION={truthy}\n",
    )
    assert code == 1, f"{truthy!r} must arm the collision check. stderr: {err}"


@pytest.mark.parametrize("falsy", ["false", "False", "0", "no", "off", "f", "n"])
def test_required_separation_accepts_pydantics_full_falsy_set(tmp_path: Path, falsy: str) -> None:
    """The complementary closed-set pin: every accepted False spelling stays warn-only."""
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        "ALFRED_QUARANTINE_PROVIDER=deepseek\n"
        f"ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION={falsy}\n",
    )
    assert code == 0, err


def test_whitespace_padded_separation_flag_is_reported_not_silently_stripped(
    tmp_path: Path,
) -> None:
    """Round-6 review fleet (CodeRabbit): pydantic's bool parser has NO whitespace
    tolerance, so a padded value (unlike ALFRED_QUARANTINE_PROVIDER, which has its own
    earlier raw-value gate) must be REPORTED here, not silently normalised into a
    matching truthy/falsy spelling. Before the fix this gate stripped whitespace before
    comparing, so ' true' passed as clean while the real daemon would refuse boot on
    settings_invalid — the exact silent-miss this test pins shut."""
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        "ALFRED_QUARANTINE_PROVIDER=deepseek\n"
        "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION= true\n",
    )
    assert code == 1
    assert "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION" in err
    assert "unsupported boolean value" in err


def test_unparseable_separation_flag_is_reported(tmp_path: Path) -> None:
    """A value outside pydantic's closed bool set refuses boot on settings_invalid —
    the gate must catch it too, not just the collision it might also be hiding."""
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=maybe\n",
    )
    assert code == 1
    assert "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION" in err
    assert "unsupported boolean value" in err
    # Round-6 review fleet: the offending value is deliberately NOT echoed (same
    # credential-adjacency rationale as the ALFRED_QUARANTINE_PROVIDER diagnostic).
    assert "maybe" not in err


def test_shell_set_separation_beats_a_dotenv_value(tmp_path: Path) -> None:
    """Same shell-over-.env precedence as the quarantine-provider check above, for the
    separation flag: a shell override must decide the verdict, not a stale .env value."""
    code, _out, _err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        "ALFRED_QUARANTINE_PROVIDER=deepseek\n"
        "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=false\n",
        extra_env={"ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION": "true"},
    )
    assert code == 1, "a shell-set true must arm the check even over a false .env value"


def test_explicitly_empty_shell_separation_does_not_fall_back_to_dotenv(tmp_path: Path) -> None:
    """The ``${VAR+x}`` discriminator, mirrored for the separation flag: an explicitly
    empty shell var is the compose ``false`` default, not "consult .env"."""
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        "ALFRED_QUARANTINE_PROVIDER=deepseek\n"
        "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=true\n",
        extra_env={"ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION": ""},
    )
    assert code == 0, (
        "an explicitly-empty shell var means the container takes the false default; "
        f"the gate must not validate the unused .env value. stderr: {err}"
    )


def test_miscased_colliding_quarantine_provider_reports_both_problems(tmp_path: Path) -> None:
    """A value that is BOTH mis-cased (fails the closed-set check) AND would collide once
    normalised must report BOTH problems in one run — case-normalising only for the
    collision check (deliberately, unlike the closed-set check above, which is
    case-sensitive to match ``Settings.quarantine_provider``'s ``Literal``) means an
    operator who fixes the case on the next run immediately meets the collision too,
    rather than fix-case / re-run / discover-collision."""
    code, _out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n"
        "ALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n"
        "ALFRED_QUARANTINE_PROVIDER=DeepSeek\n"
        "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=true\n",
    )
    assert code == 1
    assert "is set to an unsupported value" in err, err
    assert "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION" in err, err

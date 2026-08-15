"""Durable drift-net for the #591 secret-forwarding gap class.

#591: ``docker-compose.yaml`` never forwarded ``ALFRED_AUDIT.HASH_PEPPER`` to
``alfred-core``, so ``SecretBroker.get("audit.hash_pepper")`` raised
``MissingAuditHashPepperError`` on the daemon's very first inbound turn, with
no reachable remedy. Task 2 of this same combined PR fixed the forwarding —
but nothing in the repo *asserted* that every broker-resolvable secret is
forwarded, which is exactly why the gap shipped and sat unnoticed.

The three assertions below iterate :data:`alfred.security.secrets.SUPPORTED_SECRETS`
rather than naming keys by hand, so the NEXT secret registered there is
covered automatically:

1. **Forwarded** — every secret's ``ALFRED_<NAME>`` env name (mirroring
   ``SecretBroker.get()``'s own ``f"ALFRED_{name.upper()}"``, with no
   dot->underscore normalisation) is a key in ``alfred-core``'s
   ``environment:`` block.
2. **Operator-settable** — each forwarded value is a bare ``${VAR...}``
   interpolation, and ``VAR`` is documented in ``.env.example`` (active or
   commented-example). This is the assertion that reads the *interpolation
   variable*, not the container key, so it would catch a future
   dot/underscore-asymmetry regression like the one #591's own fix had to
   introduce deliberately (the container key ``ALFRED_AUDIT.HASH_PEPPER``
   has a dot; Compose cannot interpolate a dotted identifier, so the ``.env``
   carrier variable is the differently-named ``ALFRED_AUDIT_HASH_PEPPER``).
3. **Derivation pin** — proves the broker really reads the dotted secret id
   through the PRODUCTION ``SecretBroker.get()`` lookup path, not by
   asserting on source text.

Plus an ADR-0036 negative (the gateway holds no vault key, ever) and an
anti-vacuity floor on ``SUPPORTED_SECRETS`` / ``_CORE_UNFORWARDED`` so this
module can't quietly stop meaning anything.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from alfred.security.secrets import SUPPORTED_SECRETS, SecretBroker

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_COMPOSE_PATH = _REPO_ROOT / "docker-compose.yaml"
_ENV_EXAMPLE_PATH = _REPO_ROOT / ".env.example"
_GATEWAY_SRC_DIR = _REPO_ROOT / "src" / "alfred" / "gateway"

# Secrets that must NOT reach alfred-core's environment despite being
# registered in SUPPORTED_SECRETS. Empty today — every registered secret is
# core-forwarded. Widening this set is a REVIEW DECISION, not something to
# do casually: a secret that genuinely must stay off the core needs a name
# here with a documented reason (decided in review), never a silent
# exclusion added just to make this test pass.
_CORE_UNFORWARDED: frozenset[str] = frozenset()

# Matches a docker-compose interpolation of the shape ``${VAR}``, ``${VAR:-x}``,
# ``${VAR-x}``, ``${VAR:?msg}``, or ``${VAR?msg}`` and captures VAR. Anchored
# to the *entire* string (\A...\Z, not search) — the "operator-settable"
# assertion requires the whole forwarded value to be a bare interpolation,
# not e.g. a literal with an embedded ``${...}`` fragment.
_INTERPOLATION_RE = re.compile(r"\A\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?[-?].*)?\}\Z")


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    return yaml.safe_load(_COMPOSE_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def env_example_text() -> str:
    return _ENV_EXAMPLE_PATH.read_text(encoding="utf-8")


def _forwarded_env_names() -> frozenset[str]:
    """The ``ALFRED_<NAME>`` env names every core-forwarded secret resolves under.

    Mirrors ``SecretBroker.get()``'s own ``f"{_ENV_PREFIX}{name.upper()}"``
    (src/alfred/security/secrets.py) verbatim — no dot->underscore
    normalisation, so ``audit.hash_pepper`` maps to the dotted
    ``ALFRED_AUDIT.HASH_PEPPER``, not an underscored variant. Derived from
    ``SUPPORTED_SECRETS`` so a newly-registered secret is covered here
    automatically, without anyone remembering to update this test.

    ``_CORE_UNFORWARDED`` is filtered out HERE, before the uppercase/prefix
    transform — not by subtracting it from the transformed output. The two
    sets live in different string spaces: ``SUPPORTED_SECRETS`` /
    ``_CORE_UNFORWARDED`` hold dotted secret identifiers
    (``"audit.hash_pepper"``), while the return value holds
    ``ALFRED_``-prefixed uppercased env-var names
    (``"ALFRED_AUDIT.HASH_PEPPER"``). Subtracting an identifier-space set
    from an env-var-name-space set can never remove anything — the transform
    changes every string's shape, so no element of one set can ever equal an
    element of the other.
    """
    forwarded_secrets = SUPPORTED_SECRETS - _CORE_UNFORWARDED
    return frozenset(f"ALFRED_{s.upper()}" for s in forwarded_secrets)


def test_every_supported_secret_is_forwarded_to_core(compose: dict[str, Any]) -> None:
    """Every broker-resolvable secret's env name reaches alfred-core's environment.

    This is the #591 gap class, closed for good: #591 shipped because
    docker-compose.yaml forwarded 4 of 5 registered secrets and nothing
    noticed the audit.hash_pepper gap. Deriving the expected key set from
    SUPPORTED_SECRETS (rather than naming the 5 keys by hand) means the
    NEXT secret added to the registry is covered automatically, not just
    the ones known about today.
    """
    core_env = compose["services"]["alfred-core"]["environment"]
    required = _forwarded_env_names()
    missing = required - set(core_env)
    assert not missing, (
        f"alfred-core's `environment:` block is missing {sorted(missing)} — "
        "every SUPPORTED_SECRETS entry must be forwarded to alfred-core (or "
        "explicitly listed in _CORE_UNFORWARDED with a reviewed reason). "
        "This is the #591 gap class: a registered secret the broker can "
        "resolve but the container never receives."
    )


def test_every_forwarded_secret_is_operator_settable(
    compose: dict[str, Any], env_example_text: str
) -> None:
    """Every forwarded secret value is a bare ``${VAR...}`` interpolation, and
    VAR is documented in .env.example (as an active key or a commented example).

    This is the assertion that reads the INTERPOLATION variable, not the
    container key — it is what would catch a future dot/underscore
    asymmetry regression. #591's fix had to introduce exactly that
    asymmetry deliberately for audit.hash_pepper: the container key
    (``ALFRED_AUDIT.HASH_PEPPER``) has a dot, but Compose rejects a dotted
    interpolation identifier, so the `.env` carrier variable is the
    differently-named ``ALFRED_AUDIT_HASH_PEPPER``. Without this check, a
    future secret could ship forwarded-but-unsettable: present in compose,
    but with no `.env` variable an operator could actually populate.
    """
    core_env = compose["services"]["alfred-core"]["environment"]
    required = _forwarded_env_names()

    for key in sorted(required):
        raw_value = core_env[key]
        assert isinstance(raw_value, str), (
            f"{key}'s compose value must be a string interpolation, got {raw_value!r}"
        )
        match = _INTERPOLATION_RE.match(raw_value)
        assert match is not None, (
            f"{key}'s compose value {raw_value!r} is not a bare ${{VAR...}} "
            "interpolation — an operator would have no way to set it via .env."
        )
        var = match.group(1)
        # Anchored to line-start + immediate `=`: `VAR=` must follow directly
        # after optional leading whitespace and an optional single `#` (a
        # commented-out example line), so a DIFFERENT variable that merely
        # shares VAR as a prefix (e.g. `VAR_EXTRA=`) cannot false-match.
        var_pattern = re.compile(rf"^[ \t]*#?[ \t]*{re.escape(var)}=", re.MULTILINE)
        assert var_pattern.search(env_example_text), (
            f"{key} forwards ${{{var}}}, but `{var}=` does not appear anywhere in "
            ".env.example (neither as an active key nor as a commented example) — "
            "an operator has no documented way to discover or set it."
        )


def test_the_broker_really_reads_the_dotted_env_name(tmp_path: Path) -> None:
    """Derivation pin: SecretBroker.get() resolves the dotted secret id through
    the PRODUCTION lookup path, not by asserting on source text.

    ``settings_default`` points at a path that provably does not exist under
    a pytest tmp_path, so this is hermetic: no host ``secrets.toml`` is ever
    read. ``require_file`` defaults to False, so an absent settings_default
    is not a construction error — the broker proceeds env-only, exactly the
    same path a real ``alfred-core`` container takes (it mounts no
    secrets.toml either).
    """
    broker = SecretBroker(
        env={"ALFRED_AUDIT.HASH_PEPPER": "s3nt1nel"},
        settings_default=tmp_path / "absent.toml",
    )
    assert broker.get("audit.hash_pepper") == "s3nt1nel"


def test_audit_secrets_never_reach_the_gateway_source() -> None:
    """ADR-0036 negative: the gateway holds no vault key, ever.

    Mirrors ``test_quarantine_provider_key_never_reaches_the_gateway``
    (compose-level, in tests/unit/test_compose_invariants.py) at the
    source-code level: no ``.py`` file under ``src/alfred/gateway/`` may
    reference ``audit_hash`` or ``hash_pepper`` by name. Equivalent to
    ``grep -rn "audit_hash\\|hash_pepper" src/alfred/gateway/`` returning
    nothing — verified empirically (2026-08-14, this task) that the real
    grep is currently clean before writing this as a permanent pin.
    """
    pattern = re.compile(r"audit_hash|hash_pepper")
    hits: list[str] = []
    for path in sorted(_GATEWAY_SRC_DIR.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                hits.append(f"{path.relative_to(_REPO_ROOT)}:{lineno}: {line.strip()}")
    assert not hits, (
        "ADR-0036: the gateway must never reference audit_hash/hash_pepper "
        f"(it holds no vault key) — found: {hits}"
    )


def test_supported_secrets_floor_is_non_vacuous() -> None:
    """Anti-vacuity floor: this drift-net only means something if there is
    real breadth in SUPPORTED_SECRETS to iterate over."""
    assert len(SUPPORTED_SECRETS) >= 5, (
        f"SUPPORTED_SECRETS shrank to {sorted(SUPPORTED_SECRETS)} (fewer than "
        "5) — the derived assertions above would be exercising too little "
        "breadth to trust as a drift-net."
    )


def test_core_unforwarded_exception_set_is_empty() -> None:
    """Anti-vacuity floor: _CORE_UNFORWARDED starts empty and stays that way
    unless a review decision explicitly widens it (see the module-level
    comment on _CORE_UNFORWARDED for the rationale)."""
    assert not _CORE_UNFORWARDED, (
        f"_CORE_UNFORWARDED has grown to {sorted(_CORE_UNFORWARDED)} — widening it "
        "is a review decision, not something to do casually."
    )

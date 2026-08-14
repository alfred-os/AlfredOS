"""#340 PR2b golive Task 15: ``max_tokens > 0`` fail-loud at BOTH quarantine boundaries.

A ``max_tokens <= 0`` MUST fail LOUD at the config-load / spawn-env boundary and at the
child's ``_build_provider`` — it must NEVER launder into a ``cannot_extract`` typed
refusal (the HARD #7 silent-failure shape). The anti-launder mechanism: if a non-positive
budget reached :func:`dispatch_extraction`, the ``CompletionRequest(max_tokens=...)`` ``>0``
validator raises a :class:`pydantic.ValidationError` that the retry loop catches as
RETRY-ELIGIBLE — N doomed attempts, then ``cannot_extract`` — masking a config
misconfiguration as an extraction refusal. Both guards fire BEFORE any provider call so a
bad value never reaches that retry loop:

* HOST (``_resolve_quarantine_model_config``, ``comms_mcp.daemon_runtime``): SYNCHRONOUS,
  PRE-spawn, so the child is never spawned on a bad budget. Mirrors the
  :class:`QuarantineProviderKeyUnsetError` §20.2 PRIMARY refuse-boot.
* CHILD (``_build_provider``, ``security.quarantine_child.__main__``): the §20.2 SECONDARY
  refuse-boot (defence-in-depth) — raises :class:`QuarantineChildBootError` at boot, so the
  request loop that calls :func:`dispatch_extraction` is never entered.

The runtime-order proof that the child guard fires AFTER ``emit_hello`` and BEFORE ``ready``
(so the loop is never reached) lives in ``test_quarantine_child_boot_ordering.py`` alongside
the sibling empty-key refuse-boot proof.
"""

from __future__ import annotations

import pytest
import structlog.testing

from alfred.comms_mcp import daemon_runtime as daemon_runtime_mod
from alfred.comms_mcp.daemon_runtime import (
    QuarantineMaxTokensInvalidError,
    _resolve_quarantine_model_config,
)
from alfred.errors import AlfredError
from alfred.security.quarantine_child import __main__ as child_main
from alfred.security.quarantine_child.brokered_egress import (
    QuarantineChildBootError,
    _ProviderFactory,
)

# --------------------------------------------------------------------------- #
# HOST boundary — _resolve_quarantine_model_config (pre-spawn refuse-boot).
# --------------------------------------------------------------------------- #


def test_host_resolve_returns_model_and_budget_when_positive() -> None:
    """A positive budget resolves to ``(model, max_tokens)`` unchanged (the production path)."""
    model, max_tokens = _resolve_quarantine_model_config()
    assert model == daemon_runtime_mod._QUARANTINE_MODEL
    assert max_tokens == daemon_runtime_mod._QUARANTINE_MAX_TOKENS_PER_EXTRACTION
    assert max_tokens > 0  # the shipped constant is well above the floor


@pytest.mark.parametrize("bad", [0, -1, -8192])
def test_host_resolve_refuses_nonpositive_budget(monkeypatch: pytest.MonkeyPatch, bad: int) -> None:
    """A <=0 budget raises the loud refuse-boot error BEFORE the spawn (never cannot_extract)."""
    monkeypatch.setattr(daemon_runtime_mod, "_QUARANTINE_MAX_TOKENS_PER_EXTRACTION", bad)
    with pytest.raises(QuarantineMaxTokensInvalidError):
        _resolve_quarantine_model_config()


def test_host_refuse_error_is_alfred_error() -> None:
    """The refuse is an :class:`AlfredError` so the CLI boot except arm catches it (exit 2)."""
    assert issubclass(QuarantineMaxTokensInvalidError, AlfredError)


def test_host_refuse_names_the_bad_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """The error text carries the offending budget — non-secret routing config, actionable."""
    monkeypatch.setattr(daemon_runtime_mod, "_QUARANTINE_MAX_TOKENS_PER_EXTRACTION", 0)
    with pytest.raises(QuarantineMaxTokensInvalidError) as exc_info:
        _resolve_quarantine_model_config()
    assert "0" in str(exc_info.value)


def test_host_refuse_logs_loud_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The refuse emits a LOUD (error-level) structlog event before raising.

    Uses ``structlog.testing.capture_logs`` (not pytest ``caplog``) because the module
    logs via structlog, which does not route through stdlib logging here.
    """
    monkeypatch.setattr(daemon_runtime_mod, "_QUARANTINE_MAX_TOKENS_PER_EXTRACTION", -5)
    with (
        structlog.testing.capture_logs() as captured,
        pytest.raises(QuarantineMaxTokensInvalidError),
    ):
        _resolve_quarantine_model_config()
    assert any(
        entry.get("event") == "comms.daemon_runtime.quarantine_max_tokens_invalid"
        and entry.get("log_level") == "error"
        for entry in captured
    ), captured


# --------------------------------------------------------------------------- #
# CHILD boundary — _build_provider (secondary refuse-boot, defence-in-depth).
# --------------------------------------------------------------------------- #


def test_child_build_provider_returns_factory_when_positive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A positive spawn-env budget builds a real ``_ProviderFactory`` (no socket, no network)."""
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-test-model")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    factory = child_main._build_provider("sk-quarantine-key")
    assert isinstance(factory, _ProviderFactory)
    assert factory.max_tokens == 8192


@pytest.mark.parametrize("bad", ["0", "-1", "-8192"])
def test_child_build_provider_refuses_nonpositive_budget(
    monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    """A <=0 spawn-env budget raises :class:`QuarantineChildBootError` at boot (not cannot_extract).

    The guard fires with a NON-empty key, proving the budget check is INDEPENDENT of the
    empty-key guard: a real key + a bad budget still refuses boot before any provider call.
    """
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-test-model")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", bad)
    with pytest.raises(QuarantineChildBootError):
        child_main._build_provider("sk-quarantine-key")


def test_child_build_provider_error_names_the_bad_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The child boot-refuse names the offending budget — host-set routing config, non-secret."""
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-test-model")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "0")
    with pytest.raises(QuarantineChildBootError) as exc_info:
        child_main._build_provider("sk-quarantine-key")
    assert "0" in str(exc_info.value)


# --------------------------------------------------------------------------- #
# CHILD boundary — UNSET / unparseable spawn-env config (#340 D1).
#
# Regression pin for the golive CI red: the bwrap spawn probe spawned the real child
# WITHOUT the golive provider config, and `_build_provider` raised a bare
# `KeyError: 'ALFRED_QUARANTINE_MODEL'` out of a §20.2 refuse-boot security gate. A
# boot-config fault must present as the SAME loud typed refusal as the sibling budget
# guard, naming the offending variable (HARD #7).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("missing", ["ALFRED_QUARANTINE_MODEL", "ALFRED_QUARANTINE_MAX_TOKENS"])
def test_child_build_provider_refuses_unset_spawn_env(
    monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    """An UNSET spawn-env var raises the typed boot refusal, NOT a bare ``KeyError``.

    ``KeyError`` is a ``LookupError``, not a ``QuarantineChildBootError``, so
    ``pytest.raises(QuarantineChildBootError)`` genuinely falsifies the old behaviour —
    this test FAILS against the pre-fix ``os.environ[...]`` indexing.
    """
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-test-model")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.delenv(missing, raising=False)
    with pytest.raises(QuarantineChildBootError) as exc_info:
        child_main._build_provider("sk-quarantine-key")
    # Actionable: the refusal names WHICH variable is unset, so the operator does not
    # have to diff two env names to find the spawn-wiring bug.
    assert missing in str(exc_info.value)


def test_child_build_provider_unset_refusal_is_not_a_key_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The typed refusal REPLACES the ``KeyError`` — it does not merely wrap and re-raise it."""
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.delenv("ALFRED_QUARANTINE_MODEL", raising=False)
    with pytest.raises(QuarantineChildBootError) as exc_info:
        child_main._build_provider("sk-quarantine-key")
    assert not isinstance(exc_info.value, KeyError)
    # Cause is preserved for forensics (`raise ... from exc`) without being the raised type.
    assert isinstance(exc_info.value.__cause__, KeyError)


@pytest.mark.parametrize("bad", ["", "eight-thousand", "8192.5", "0x2000"])
def test_child_build_provider_refuses_unparseable_budget(
    monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    """A non-integer budget refuses typed rather than raising a bare ``ValueError``.

    Same class of spawn-wiring fault as the unset case, on the same line — an
    unparseable budget must not escape a security gate as a stdlib exception.
    """
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-test-model")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", bad)
    with pytest.raises(QuarantineChildBootError) as exc_info:
        child_main._build_provider("sk-quarantine-key")
    assert not isinstance(exc_info.value, ValueError)
    assert isinstance(exc_info.value.__cause__, ValueError)


# --------------------------------------------------------------------------- #
# CHILD boundary — _build_provider reads the provider id + base_url (#587).
# --------------------------------------------------------------------------- #


def test_child_build_provider_reads_provider_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "deepseek-chat")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    monkeypatch.setenv("ALFRED_QUARANTINE_BASE_URL", "https://api.deepseek.com/v1")
    factory = child_main._build_provider("realkey")
    assert factory.provider_id == "deepseek"
    assert factory.base_url == "https://api.deepseek.com/v1"


def test_child_build_provider_defaults_to_anthropic_when_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unset ``ALFRED_QUARANTINE_PROVIDER`` -> the anthropic default, with no base_url.

    Both vars are ``delenv``'d, not just the provider (CodeRabbit r3): ``_build_provider``
    reads ``ALFRED_QUARANTINE_BASE_URL`` straight from ``os.environ``, so
    ``factory.base_url is None`` would otherwise assert a fact about the TEST RUNNER's
    environment being clean rather than about the function's behaviour — and it is exactly
    the environment of a real daemon host (which legitimately has the var set for a
    DeepSeek deployment) that would break the assumption.
    """
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-haiku-4-5")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.delenv("ALFRED_QUARANTINE_PROVIDER", raising=False)
    monkeypatch.delenv("ALFRED_QUARANTINE_BASE_URL", raising=False)
    factory = child_main._build_provider("realkey")
    assert factory.provider_id == "anthropic"
    assert factory.base_url is None


@pytest.mark.parametrize("bad", ["openai", "", "Anthropic", " deepseek", "deepseek\n"])
def test_child_build_provider_refuses_out_of_closed_set_provider(
    monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    """An out-of-closed-set ``ALFRED_QUARANTINE_PROVIDER`` refuses TYPED at boot.

    Same contract as the unset-var and unparseable-budget guards above: a boot-config
    fault must present as :class:`QuarantineChildBootError`, never a stdlib exception the
    operator has to decode. Before this guard the value flowed unvalidated into
    ``BrokeredProviderSource.__init__``, which refuses with a bare ``ValueError`` — and
    does so AFTER the fd-4 control socket is built, past the boot-refusal window.

    Unreachable from a well-behaved host (``Settings.quarantine_provider`` is
    ``Literal``-validated first), so this guard exists for the supervisor-spawn-wiring-bug
    and env-tampering cases — the same defence-in-depth rationale as every other §20.2
    SECONDARY refusal in this function. The case/whitespace variants are pinned
    deliberately: the child does NOT normalise, so ``"Anthropic"`` is out-of-set here.
    """
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-haiku-4-5")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", bad)
    with pytest.raises(QuarantineChildBootError) as exc_info:
        child_main._build_provider("realkey")
    assert not isinstance(exc_info.value, ValueError)
    # Actionable: names the offending variable AND the closed set, so the operator does
    # not have to read the source to learn what is admissible.
    assert "ALFRED_QUARANTINE_PROVIDER" in str(exc_info.value)
    assert "anthropic" in str(exc_info.value) and "deepseek" in str(exc_info.value)


@pytest.mark.parametrize("blank", [None, "", " ", "\t", "\n"])
def test_child_build_provider_refuses_deepseek_without_base_url(
    monkeypatch: pytest.MonkeyPatch, blank: str | None
) -> None:
    """``provider_id='deepseek'`` with a missing/blank base_url refuses TYPED at boot.

    Unlike the sibling guards, the absence of this one produced NO error at boot at all:
    ``AsyncOpenAI(base_url=None|"")`` constructs happily, so the child reported ``ready``
    and failed only on its FIRST extraction, where the dispatch retry loop LAUNDERS the
    per-call failure into a generic ``cannot_extract`` typed refusal — a boot-config fault
    wearing a runtime-extraction costume (HARD #7). The host's own pre-spawn
    ``_resolve_quarantine_base_url`` refuses the same case; this closes the composed gap
    for a spawn-wiring bug or manual env tampering.
    """
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "deepseek-chat")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    if blank is None:
        monkeypatch.delenv("ALFRED_QUARANTINE_BASE_URL", raising=False)
    else:
        monkeypatch.setenv("ALFRED_QUARANTINE_BASE_URL", blank)
    with pytest.raises(QuarantineChildBootError, match="ALFRED_QUARANTINE_BASE_URL") as exc_info:
        child_main._build_provider("realkey")
    # Typed, not a stdlib exception the operator has to decode (same contract as the
    # provider-id and budget guards above).
    assert not isinstance(exc_info.value, ValueError)
    assert "deepseek" in str(exc_info.value)


@pytest.mark.parametrize("missing_base_url", [None, "", "  "])
def test_child_build_provider_allows_anthropic_without_base_url(
    monkeypatch: pytest.MonkeyPatch, missing_base_url: str | None
) -> None:
    """Oracle guard for the refusal above: the new check is deepseek-ONLY.

    Anthropic's SDK supplies its own endpoint default, so a missing/blank
    ``ALFRED_QUARANTINE_BASE_URL`` is the NORMAL anthropic case — today's shipped
    default. Without this pair the refusal test would stay green under a guard that
    rejected every provider and broke every existing deployment.
    """
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-haiku-4-5")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "anthropic")
    if missing_base_url is None:
        monkeypatch.delenv("ALFRED_QUARANTINE_BASE_URL", raising=False)
    else:
        monkeypatch.setenv("ALFRED_QUARANTINE_BASE_URL", missing_base_url)
    factory = child_main._build_provider("realkey")
    assert factory.provider_id == "anthropic"


# --------------------------------------------------------------------------- #
# CHILD boundary — _base_url_rejection_reason / _build_provider's credential-
# component check on a PRESENT base_url (CodeRabbit, Major).
# --------------------------------------------------------------------------- #

# The nginx/Envoy inline-basic-auth shape a self-hosted relay conventionally
# uses — a literal credential in the URL. Secrets are distinctive, non-dictionary
# strings deliberately: the rejection message's own static example text names the
# userinfo SHAPE ("user:password@"), and a fixture using literal "pass" as its
# secret would spuriously match that unrelated prose instead of proving a real leak.
_CREDENTIAL_BEARING_BASE_URLS = (
    "https://apikey:@relay.internal/v1",
    "https://user:not-a-real-secret-hunter2@relay.internal:8443/v1",
    "https://not-a-real-secret-token9k2m@relay.internal/v1",
    "http://user:not-a-real-secret-pw7x4q@127.0.0.1:8080",
)
_UNUSABLE_BASE_URLS = (
    "https://[::1/v1",  # urlsplit itself raises
    "https://relay.internal:notaport/v1",  # only .port raises
    "not-a-url",
    "ftp://relay.internal/v1",
    "https://",
)
_QUERY_OR_FRAGMENT_BASE_URLS = (
    "https://relay.internal/v1?api_key=sk-abcd1234",
    "https://relay.internal/v1?region=eu",
    "https://relay.internal/v1#token=sk-abcd1234",
)
_BENIGN_BASE_URLS = (
    "https://api.deepseek.com/v1",
    "https://relay.internal",
    "https://relay.internal:8443/team-a/v1",
    "http://127.0.0.1:8080/v1",
)


@pytest.mark.parametrize("bad_url", _CREDENTIAL_BEARING_BASE_URLS)
def test_child_build_provider_refuses_credential_bearing_base_url(
    monkeypatch: pytest.MonkeyPatch, bad_url: str
) -> None:
    """A present ``ALFRED_QUARANTINE_BASE_URL`` carrying inline userinfo refuses TYPED
    at boot — the composed host/child gap ``_validate_deepseek_base_url`` closes
    host-side for the SAME field name (``ALFRED_DEEPSEEK_BASE_URL``), applied here for
    this UNVALIDATED env read (spawn-wiring bug or manual env tampering).

    The refusal message itself must not become the leak: asserted by extracting the
    userinfo fragment (``hunter2``, ``apikey``, ``token``) from each fixture and
    confirming it never appears in the raised message.
    """
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "deepseek-chat")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    monkeypatch.setenv("ALFRED_QUARANTINE_BASE_URL", bad_url)
    with pytest.raises(QuarantineChildBootError) as exc_info:
        child_main._build_provider("realkey")
    assert not isinstance(exc_info.value, ValueError)
    assert "ALFRED_QUARANTINE_BASE_URL" in str(exc_info.value)
    userinfo = bad_url.split("//", 1)[1].split("@", 1)[0]
    assert userinfo not in str(exc_info.value)


@pytest.mark.parametrize("bad_url", _QUERY_OR_FRAGMENT_BASE_URLS)
def test_child_build_provider_refuses_query_or_fragment_base_url(
    monkeypatch: pytest.MonkeyPatch, bad_url: str
) -> None:
    """A query string or fragment is refused on default-deny grounds: the openai SDK
    silently truncates the URL at the query before dialling (zero function), yet the
    full value still sits in this child's ``/proc``-readable spawn environment."""
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "deepseek-chat")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    monkeypatch.setenv("ALFRED_QUARANTINE_BASE_URL", bad_url)
    with pytest.raises(QuarantineChildBootError) as exc_info:
        child_main._build_provider("realkey")
    assert not isinstance(exc_info.value, ValueError)
    assert "ALFRED_QUARANTINE_BASE_URL" in str(exc_info.value)


@pytest.mark.parametrize("bad_url", _UNUSABLE_BASE_URLS)
def test_child_build_provider_refuses_unusable_base_url(
    monkeypatch: pytest.MonkeyPatch, bad_url: str
) -> None:
    """Covers both the ``except ValueError`` arm (an unparseable URL / bad port) and
    the scheme/hostname arm (a syntactically-valid-but-undialable URL) —
    ``_base_url_rejection_reason``'s two remaining default-deny paths."""
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "deepseek-chat")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    monkeypatch.setenv("ALFRED_QUARANTINE_BASE_URL", bad_url)
    with pytest.raises(QuarantineChildBootError) as exc_info:
        child_main._build_provider("realkey")
    assert not isinstance(exc_info.value, ValueError)
    assert "ALFRED_QUARANTINE_BASE_URL" in str(exc_info.value)


@pytest.mark.parametrize("good_url", _BENIGN_BASE_URLS)
def test_child_build_provider_accepts_benign_base_urls(
    monkeypatch: pytest.MonkeyPatch, good_url: str
) -> None:
    """Oracle guard for the three rejection tests above: a normal relay/proxy URL —
    no userinfo, no query, no fragment, a real scheme and hostname — still boots.
    Without this, all three rejection tests would stay green under a guard that
    rejects every base_url."""
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "deepseek-chat")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    monkeypatch.setenv("ALFRED_QUARANTINE_BASE_URL", good_url)
    factory = child_main._build_provider("realkey")
    assert factory.base_url == good_url


def test_child_build_provider_strips_base_url_whitespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Strip-and-STORE, matching ``Settings._validate_deepseek_base_url``: passing the
    raw value on would thread invisible leading/trailing bytes into the SDK client."""
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "deepseek-chat")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    monkeypatch.setenv("ALFRED_QUARANTINE_BASE_URL", "  https://relay.internal/v1  ")
    factory = child_main._build_provider("realkey")
    assert factory.base_url == "https://relay.internal/v1"


def test_child_build_provider_refuses_credentialed_base_url_on_anthropic_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The credential-component check is deliberately NOT provider-scoped, unlike the
    blank-base_url guard: a well-behaved host never sends a base_url at all on the
    anthropic path, so the only way anthropic sees one here is the same wiring-bug /
    tampering case every §20.2 SECONDARY guard exists for — and the ``/proc`` +
    crash-dump exposure does not care which provider later reads the variable."""
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-haiku-4-5")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "anthropic")
    monkeypatch.setenv("ALFRED_QUARANTINE_BASE_URL", "https://user:hunter2@relay.internal/v1")
    with pytest.raises(QuarantineChildBootError) as exc_info:
        child_main._build_provider("realkey")
    assert not isinstance(exc_info.value, ValueError)
    assert "hunter2" not in str(exc_info.value)


@pytest.mark.parametrize(
    "url",
    [*_CREDENTIAL_BEARING_BASE_URLS, *_QUERY_OR_FRAGMENT_BASE_URLS, *_UNUSABLE_BASE_URLS],
)
def test_child_base_url_guard_agrees_with_settings_validator_on_rejection(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    """Anti-drift pin: the child's own duplicated validation
    (:func:`_base_url_rejection_reason`) and the host's
    ``Settings._validate_deepseek_base_url`` must reject the SAME corpus. Not shared
    code on purpose (importing ``alfred.config.settings`` into the child would drag
    the whole ``pydantic_settings`` model onto its egress-free boot path, against the
    ADR-0030 reachable-surface bound) — this test is the anti-drift device that buys
    back what not sharing the code costs: one corpus, two independent oracles."""
    from pydantic import ValidationError

    from alfred.config.settings import Settings, SettingsError

    assert child_main._base_url_rejection_reason(url) is not None

    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    monkeypatch.setenv("ALFRED_DEEPSEEK_BASE_URL", url)
    with pytest.raises((ValidationError, SettingsError)):
        Settings()  # type: ignore[call-arg]


@pytest.mark.parametrize("url", _BENIGN_BASE_URLS)
def test_child_base_url_guard_agrees_with_settings_validator_on_acceptance(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    """The acceptance half of the parity pin above — both oracles must also AGREE on
    what is fine, or the "agrees on rejection" half alone could pass under a child
    guard that simply rejects everything."""
    from alfred.config.settings import Settings

    assert child_main._base_url_rejection_reason(url) is None

    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    monkeypatch.setenv("ALFRED_DEEPSEEK_BASE_URL", url)
    assert Settings().deepseek_base_url == url  # type: ignore[call-arg]

# Issues #586 + #587 — Real Quarantine-Provider Dispatch + Opt-In Separation Enforcement — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the quarantine child actually use DeepSeek (not just Anthropic, which is hardcoded today despite documentation claiming a choice exists), and wire the already-implemented, already-tested `assert_provider_separation()` into a real boot-time call site — gated behind a new setting that defaults OFF, so no operator is forced to run two paid provider accounts.

**Architecture:** Two coupled pieces landing in one PR (same boot/spawn call sites, cheaper to review together). Piece A provider-parametrizes the quarantine child's transport-construction layer (`brokered_egress.py`) and threads a new `ALFRED_QUARANTINE_PROVIDER` setting from `.env` → `Settings` → `daemon_runtime.py` → the spawn env → the child's `_build_provider`. Piece B adds `ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION` (bool, default `False`) and gives `assert_provider_separation()` its first production call site, exactly at the point Piece A resolves the two provider ids.

**Tech Stack:** Python 3.14, pytest + pytest-asyncio, real `socket.socketpair()` fixtures (this file's established fake-transport pattern — never a mock socket), Docker for the one Linux/bwrap/root-only integration leg.

## Global Constraints

- `mypy --strict` + `pyright` clean on every new/modified file.
- CLAUDE.md hard rule #7: no silent fail-open. Every new refusal path (unsupported provider id, missing base_url, provider-separation collision) is a loud raise, never a swallowed default.
- CLAUDE.md hard rule #5: no secret-bearing value in a repr, log line, or the child's env — `_ProviderFactory.__repr__` stays key-free; the provider ID and `base_url` are NOT secrets and may appear in logs/env freely, but must never carry a key.
- Dual-LLM trust boundary touched (`brokered_egress.py`, `daemon_runtime.py`, `quarantine_child_io.py`, `bootstrap/quarantine.py`'s new call site) — `alfred-security-engineer` sign-off, and 100% line+branch coverage on every touched file in `src/alfred/security/`, are release-blocking per CLAUDE.md.
- Conventional Commits. No `--no-verify`. `make check` before every push.
- Byte-for-byte non-breaking for every existing deployment that does not set the two new settings: `ALFRED_QUARANTINE_PROVIDER` unset defaults to `"anthropic"`; `ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION` unset defaults to `false`.
- This plan does NOT touch `config/routing.yaml`'s runtime consumption (no loader exists; out of scope, "slice 4+") — only its comments, corrected in Task 6. It does NOT add OpenAI support (scope decision, design spec §3 item 1).

---

### Task 1: Provider-parametrize `brokered_egress.py`'s construction layer

**Files:**

- Modify: `src/alfred/security/quarantine_child/brokered_egress.py`
- Test: `tests/unit/security/test_brokered_provider_source.py`, `tests/unit/security/test_brokered_egress_transport.py`

**Interfaces:**

- Produces: `build_child_client(fd, *, provider_id: str, model: str, api_key: str, timeout: httpx.Timeout, budget_seconds: float, base_url: str | None = None) -> tuple[AnthropicProvider | DeepSeekProvider, PassedFdBackend]`; `_ProviderFactory` gains `provider_id: str` and `base_url: str | None = None` fields, and `.from_key(key, *, provider_id, model, max_tokens, base_url=None)`; `BrokeredProviderSource.capabilities()` now resolves per-provider instead of returning a hardcoded `AnthropicProvider.CAPABILITIES` classvar.
- Consumes: `alfred.providers.deepseek.DeepSeekProvider` (existing, unmodified — `from_settings(api_key, base_url, model, *, http_client=None, max_retries=2, timeout=None)`), `alfred.providers.anthropic_native.AnthropicProvider` (existing, unmodified).

This is the most delicate task in the plan — every change is additive to a file whose whole purpose is a hardened wall-clock/fd-ownership ceiling. Do not touch `_BlockingFdStream`, `PassedFdBackend`, or `_PassedFdTransport` — they are already fully provider-agnostic (pure HTTP-over-brokered-fd plumbing); only `build_child_client`, `_ProviderFactory`, the `ProviderSource` Protocol, and `BrokeredProviderSource` need changes.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/security/test_brokered_provider_source.py`, near the existing `_factory()` helper (`:69-72`) and `test_factory_from_key_builds_frozen_config` (`:99-104`). The existing `_factory()` helper and every test that calls it must be updated to pass `provider_id="anthropic"` (a required field now) — do this first so the pre-existing tests keep passing, then add the new DeepSeek-path tests:

```python
def _factory(timeout: httpx.Timeout | None = None, *, provider_id: str = "anthropic") -> _ProviderFactory:
    return _ProviderFactory(
        provider_id=provider_id,
        api_key="super-secret",
        model="claude-haiku-4-5" if provider_id == "anthropic" else "deepseek-chat",
        max_tokens=8192,
        timeout=timeout,
        base_url=None if provider_id == "anthropic" else "https://api.deepseek.com/v1",
    )


def test_factory_from_key_builds_deepseek_factory() -> None:
    """A DeepSeek-configured factory carries its base_url and provider_id."""
    f = _ProviderFactory.from_key(
        "realkey", provider_id="deepseek", model="deepseek-chat", max_tokens=4096,
        base_url="https://api.deepseek.com/v1",
    )
    assert f.provider_id == "deepseek"
    assert f.base_url == "https://api.deepseek.com/v1"
    assert f.model == "deepseek-chat"
    assert "realkey" not in repr(f)


def test_build_child_client_dispatches_to_deepseek() -> None:
    """provider_id='deepseek' constructs a DeepSeekProvider, not AnthropicProvider."""
    a, b = socket.socketpair()
    try:
        provider, backend = be.build_child_client(
            a.detach(),
            provider_id="deepseek",
            model="deepseek-chat",
            api_key="k",
            timeout=be._CHILD_SDK_READ_TIMEOUT,
            budget_seconds=5.0,
            base_url="https://api.deepseek.com/v1",
        )
        assert isinstance(provider, DeepSeekProvider)
    finally:
        b.close()


def test_build_child_client_deepseek_requires_base_url() -> None:
    """A DeepSeek dispatch with no base_url refuses loudly (HARD #7), never silently
    falls back to some default the operator didn't choose."""
    a, b = socket.socketpair()
    try:
        with pytest.raises(ValueError, match="base_url"):
            be.build_child_client(
                a.detach(),
                provider_id="deepseek",
                model="deepseek-chat",
                api_key="k",
                timeout=be._CHILD_SDK_READ_TIMEOUT,
                budget_seconds=5.0,
                base_url=None,
            )
    finally:
        a.close()
        b.close()


def test_provider_source_capabilities_resolve_per_provider() -> None:
    """BrokeredProviderSource.capabilities() reflects the CONFIGURED provider/model,
    not a hardcoded Anthropic classvar — the #587 correctness gap the design doc named."""
    anthropic_source = BrokeredProviderSource(_factory(provider_id="anthropic"), _af_unix_socketpair()[0])
    deepseek_source = BrokeredProviderSource(_factory(provider_id="deepseek"), _af_unix_socketpair()[0])
    assert anthropic_source.capabilities() == AnthropicProvider.CAPABILITIES
    assert deepseek_source.capabilities() == DeepSeekProvider._capabilities_for_model("deepseek-chat")
    assert anthropic_source.capabilities() != deepseek_source.capabilities()
```

Add the import `from alfred.providers.deepseek import DeepSeekProvider` to the test file's existing import block (`:22-44`).

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/security/test_brokered_provider_source.py -v -k "deepseek or dispatches_to or capabilities_resolve"`
Expected: FAIL — `_ProviderFactory() missing required keyword argument 'provider_id'` (or similar, since the field doesn't exist yet).

- [ ] **Step 3: Widen `_ProviderFactory` and `build_child_client`**

In `src/alfred/security/quarantine_child/brokered_egress.py`, add the import after the existing `from alfred.providers.anthropic_native import AnthropicProvider` (`:56`):

```python
from alfred.providers.deepseek import DeepSeekProvider
```

Replace `build_child_client` (`:293-309`):

```python
def build_child_client(
    fd: int,
    *,
    provider_id: str,
    model: str,
    api_key: str,
    timeout: httpx.Timeout,
    budget_seconds: float,
    base_url: str | None = None,
) -> tuple[AnthropicProvider | DeepSeekProvider, PassedFdBackend]:
    """Build the #339-seam provider client over the passed fd, for either provider #587
    supports. max_retries=0 (spike A2), single connection, no keepalive, no redirects
    (E2). TLS terminates in-child (HARD #5). ``provider_id`` is the closed-set value
    (``anthropic`` | ``deepseek``) the host already validated before spawn
    (``_ALLOWED_QUARANTINED_PROVIDERS`` / the new ``ALFRED_QUARANTINE_PROVIDER``
    setting) — this function trusts it rather than re-validating, since re-validating
    here would duplicate the closed-set check instead of sharing it.

    The read component of ``timeout`` becomes the backend's per-syscall idle cap AND is
    injected into the httpx client. ``budget_seconds`` — what remains of the per-extraction
    wall-clock budget — becomes the absolute deadline every socket operation is clamped
    against, which is the ceiling that actually holds (rev.2 / prov-001)."""
    backend = PassedFdBackend(fd, read_timeout=timeout.read, budget_seconds=budget_seconds)
    transport = _PassedFdTransport(backend)
    http_client = httpx.AsyncClient(transport=transport, follow_redirects=False, timeout=timeout)
    if provider_id == "deepseek":
        if base_url is None:
            raise ValueError(
                "build_child_client: provider_id='deepseek' requires base_url — refusing "
                "to silently fall back to some default the operator did not choose (HARD #7)"
            )
        provider: AnthropicProvider | DeepSeekProvider = DeepSeekProvider.from_settings(
            api_key=api_key, base_url=base_url, model=model, http_client=http_client,
            max_retries=0, timeout=timeout,
        )
    else:
        provider = AnthropicProvider.from_settings(
            api_key=api_key, model=model, http_client=http_client, max_retries=0, timeout=timeout
        )
    return provider, backend
```

(`provider_id == "deepseek"` else-branch covers `"anthropic"` — the closed set is validated upstream at settings-parse time in Task 2, so this function never sees a third value. Do not add a third `elif`/`raise` here; that validation belongs at the boundary, not duplicated at every internal call site.)

Replace `_ProviderFactory` (`:326-364`):

```python
@dataclass(frozen=True, slots=True)
class _ProviderFactory:
    """Frozen, key-free-repr builder for the child's per-attempt provider client (§8, #587).

    ``build(fd)`` assembles the #339-seam provider over ONE brokered TCP fd via
    ``build_child_client``. ``from_key`` is the child's SECONDARY refuse-boot guard (§20.2): an
    empty provider key means the child cannot build a real provider, so it refuses to boot with a
    loud :class:`QuarantineChildBootError` rather than silently degrading to a dead LLM (HARD #7).
    The HOST pre-spawn key check (Task 6/7 of the original #340 plan) is the PRIMARY guard; this
    is defence-in-depth.
    """

    provider_id: str
    api_key: str
    model: str
    max_tokens: int
    timeout: httpx.Timeout | None
    base_url: str | None = None

    @classmethod
    def from_key(
        cls,
        key: str,
        *,
        provider_id: str,
        model: str,
        max_tokens: int,
        base_url: str | None = None,
    ) -> _ProviderFactory:
        if not key:
            raise QuarantineChildBootError(
                "quarantine provider key is empty — refusing to boot a dead-LLM child (§20.2)"
            )
        return cls(
            provider_id=provider_id, api_key=key, model=model, max_tokens=max_tokens,
            timeout=_CHILD_SDK_READ_TIMEOUT, base_url=base_url,
        )

    def build(self, fd: int, *, budget_seconds: float) -> tuple[AnthropicProvider | DeepSeekProvider, PassedFdBackend]:
        """Assemble the per-attempt client. ``budget_seconds`` is what remains of the
        extraction's wall-clock budget and becomes the attempt's absolute socket deadline."""
        return build_child_client(
            fd,
            provider_id=self.provider_id,
            model=self.model,
            api_key=self.api_key,
            timeout=self.timeout or _CHILD_SDK_READ_TIMEOUT,
            budget_seconds=budget_seconds,
            base_url=self.base_url,
        )

    def __repr__(self) -> str:
        # Key-free repr (anti-leak, the _DeterministicProvider discipline): the api_key must never
        # reach a log line or a traceback frame (HARD #5 / no-secret-in-logs). provider_id/base_url
        # are non-secret and safe to include.
        return (
            f"_ProviderFactory(provider_id={self.provider_id!r}, model={self.model!r}, "
            f"max_tokens={self.max_tokens})"
        )
```

- [ ] **Step 4: Update the `ProviderSource` Protocol and `BrokeredProviderSource`**

In the `ProviderSource` Protocol (`:367-384`), change `bind`'s return annotation:

```python
    def bind(self, *, budget_seconds: float) -> AbstractAsyncContextManager[AnthropicProvider | DeepSeekProvider]: ...
```

In `BrokeredProviderSource` (`:387-459`), replace the `_CAPS` classvar and `__init__`/`capabilities()` (`:397-414`):

```python
    def __init__(self, factory: _ProviderFactory, control_end: socket.socket) -> None:
        self._factory = factory
        self._control_end = control_end
        # #587: capabilities are resolved from the CONFIGURED provider/model, not a
        # hardcoded classvar — DeepSeek's capabilities are model-aware
        # (_capabilities_for_model), unlike Anthropic's flat CAPABILITIES. Resolved once
        # here (construction time, socket-free) rather than per-call, matching the
        # original classvar's "read it is socket-free" property.
        self._caps: frozenset[ProviderCapability] = (
            AnthropicProvider.CAPABILITIES
            if factory.provider_id == "anthropic"
            else DeepSeekProvider._capabilities_for_model(factory.model)
        )

    @property
    def max_tokens(self) -> int:
        """The boot-validated per-request token budget (``ALFRED_QUARANTINE_MAX_TOKENS``).

        Surfaced off the factory so the request loop uses the value ``_build_provider``'s
        ``> 0`` guard already vetted, instead of re-reading ``os.environ`` per extraction and
        routing around that gate.
        """
        return self._factory.max_tokens

    def capabilities(self) -> frozenset[ProviderCapability]:
        return self._caps
```

Update the `bind()` method's local variable annotation (`:459-461`, inside the `try` block):

```python
        provider: AnthropicProvider | DeepSeekProvider | None = None
```

(The `_CAPS = AnthropicProvider.CAPABILITIES` classvar line — originally at `:397` — is deleted entirely, replaced by the `self._caps` instance attribute above.)

- [ ] **Step 5: Run to verify they pass**

Run: `uv run pytest tests/unit/security/test_brokered_provider_source.py tests/unit/security/test_brokered_egress_transport.py -v`
Expected: PASS — every pre-existing test (now passing `provider_id="anthropic"` via the updated `_factory()` helper) plus the four new tests from Step 1.

- [ ] **Step 6: Type-check and coverage**

Run: `uv run mypy --strict src/alfred/security/quarantine_child/brokered_egress.py && uv run pyright src/alfred/security/quarantine_child/brokered_egress.py`
Expected: no errors.

Run: `uv run pytest tests/unit/security/test_brokered_provider_source.py tests/unit/security/test_brokered_egress_transport.py --cov=alfred.security.quarantine_child.brokered_egress --cov-report=term-missing`
Expected: 100% line + branch (trust-boundary file, CLAUDE.md hard rule) — the new `provider_id == "deepseek"` branch and the `base_url is None` refusal arm must show as covered, not just the Anthropic happy path.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/security/quarantine_child/brokered_egress.py tests/unit/security/test_brokered_provider_source.py
git commit -m "feat(security): provider-parametrize the quarantine child's brokered transport (#587)"
```

---

### Task 2: Add the two new `Settings` fields

**Files:**

- Modify: `src/alfred/config/settings.py`
- Modify: `src/alfred/cli/_validators.py` (reuse the existing closed-set constant)
- Test: `tests/unit/config/test_settings.py` (verify this file exists first — if the actual settings test file has a different name, use that one instead; do not create a new one if an existing settings test module already covers `Settings` field defaults/validation)

**Interfaces:**

- Produces: `Settings.quarantine_provider: Literal["anthropic", "deepseek"]` (default `"anthropic"`), `Settings.require_quarantine_provider_separation: bool` (default `False`).
- Consumes: `alfred.cli._validators._ALLOWED_QUARANTINED_PROVIDERS` (existing, `frozenset({"anthropic", "deepseek"})`).

**Correction to the design spec's assumption:** `Settings` has zero `bool`-typed fields today (verified — this is the first one). There is no existing bool-field convention in this file to copy; follow the `description=`-block density convention `policy_poll_interval_seconds` (`settings.py:386-396`) already establishes, since that is this file's established comment/documentation bar for a `Field(...)` declaration, not because it's a bool.

- [ ] **Step 1: Write the failing test**

First run `find tests -iname "*settings*"` to locate the real test file for `Settings` (do not assume a path). Add tests matching that file's existing style (read a few of its existing tests first to match fixture/assertion conventions exactly). At minimum:

```python
def test_quarantine_provider_defaults_to_anthropic() -> None:
    settings = Settings(deepseek_api_key=SecretStr("sk-real"))
    assert settings.quarantine_provider == "anthropic"


def test_quarantine_provider_accepts_deepseek() -> None:
    settings = Settings(deepseek_api_key=SecretStr("sk-real"), quarantine_provider="deepseek")
    assert settings.quarantine_provider == "deepseek"


def test_quarantine_provider_rejects_unknown_value() -> None:
    with pytest.raises(ValidationError):
        Settings(deepseek_api_key=SecretStr("sk-real"), quarantine_provider="openai")


def test_require_quarantine_provider_separation_defaults_to_false() -> None:
    settings = Settings(deepseek_api_key=SecretStr("sk-real"))
    assert settings.require_quarantine_provider_separation is False


def test_require_quarantine_provider_separation_accepts_true() -> None:
    settings = Settings(
        deepseek_api_key=SecretStr("sk-real"), require_quarantine_provider_separation=True
    )
    assert settings.require_quarantine_provider_separation is True
```

(Match whatever constructor pattern the existing test file already uses for a minimal valid `Settings()` — it may need more required fields than shown here; read an existing passing test in the same file and copy its exact minimal-construction shape rather than guessing.)

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest <the located settings test file> -v -k "quarantine_provider or require_quarantine"`
Expected: FAIL — `TypeError: Settings() got an unexpected keyword argument 'quarantine_provider'` (Pydantic will actually just ignore/reject via extra="forbid" or similar — verify the exact failure mode against the live file, but it must fail since the field doesn't exist).

- [ ] **Step 3: Add the fields**

In `src/alfred/config/settings.py`, first add the import (check whether `Literal` is already imported from `typing` before adding a duplicate):

```python
from alfred.cli._validators import _ALLOWED_QUARANTINED_PROVIDERS
```

**Check for an import-cycle risk before adding this**: `_validators.py` is under `src/alfred/cli/`, and `settings.py` is under `src/alfred/config/` — verify `_validators.py` does not itself import anything from `alfred.config` (directly or transitively) before wiring this import, since a cycle here would break at collection time, not at review time. If a cycle exists, inline the two-element frozenset directly in `settings.py` instead (`frozenset({"anthropic", "deepseek"})`) with a comment noting it must stay in sync with `_validators._ALLOWED_QUARANTINED_PROVIDERS`, and file that duplication as a follow-up rather than blocking this task on an import-graph untangle.

Add the two fields after the existing `fallback_provider: str = "anthropic"` line (`settings.py:210`):

```python
    # #587: the quarantine child's provider — closed set, shared with the CLI's
    # existing quarantined-provider validator (_ALLOWED_QUARANTINED_PROVIDERS) so the
    # two can never independently drift. Defaults to "anthropic" — byte-for-byte
    # today's behaviour for every deployment that doesn't set this.
    quarantine_provider: Literal["anthropic", "deepseek"] = "anthropic"

    # #586: opt-in enforcement that the quarantine and privileged providers differ
    # (spec §5.4 / PRD §6.4's defence-in-depth rationale — a single compromised or
    # merely observing LLM provider should never see both privileged state and
    # untrusted T3 content). Defaults to False: a home/self-hosted operator must
    # never be forced into running two paid provider accounts. An enterprise
    # deployment that wants the stricter posture sets this to True.
    require_quarantine_provider_separation: bool = Field(
        default=False,
        description=(
            "When True, refuse to boot if the quarantine and privileged providers "
            "are the same id (see alfred.bootstrap.quarantine.assert_provider_separation). "
            "Default False — same-provider is permitted, with an operator-facing warning "
            "(see #586)."
        ),
    )
```

(Verify `Field` is already imported from `pydantic` in this file before adding a duplicate import — it almost certainly is, given `daily_budget_usd`'s existing `Field(default=1.0, gt=0)` usage at `:262`.)

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest <the located settings test file> -v`
Expected: PASS — every pre-existing test plus the five new ones.

- [ ] **Step 5: Type-check**

Run: `uv run mypy --strict src/alfred/config/settings.py && uv run pyright src/alfred/config/settings.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/config/settings.py <the located settings test file>
git commit -m "feat(config): add quarantine_provider + require_quarantine_provider_separation settings (#586 #587)"
```

---

### Task 3: Thread the provider id from `Settings` through `daemon_runtime.py`, the spawn, and the child's `_build_provider`

**Files:**

- Modify: `src/alfred/comms_mcp/daemon_runtime.py`
- Modify: `src/alfred/security/quarantine_child_io.py`
- Modify: `src/alfred/security/quarantine_child/__main__.py`
- Modify: `src/alfred/cli/daemon/_comms_boot.py`
- Test: `tests/unit/comms_mcp/test_daemon_runtime.py` (or wherever `_resolve_quarantine_model_config`/`_build_comms_inbound_extractor` are already tested — verify the real path first), `tests/unit/security/test_quarantine_child_io.py` (or equivalent), `tests/unit/security/test_quarantine_child_main.py` (or equivalent — verify exact names against the live tree before writing paths into commits).

**Interfaces:**

- Consumes: Task 1's `build_child_client(..., provider_id=..., base_url=...)` / `_ProviderFactory.from_key(..., provider_id=..., base_url=...)`; Task 2's `Settings.quarantine_provider`.
- Produces: `_child_env(..., provider: str | None = None)` sets `ALFRED_QUARANTINE_PROVIDER`; `spawn_quarantine_child_io(..., provider: str | None = None)` threads it; `_build_comms_inbound_extractor(..., quarantine_provider: str)` (new required param) resolves and forwards it; `daemon_runtime._resolve_quarantine_base_url(provider_id: str) -> str | None` (new) resolves DeepSeek's base URL from `Settings.deepseek_base_url` when `provider_id == "deepseek"`, else `None`.

- [ ] **Step 1: Write the failing tests**

Add to the quarantine_child_io test file (locate it first: `find tests -iname "*quarantine_child_io*"`), near any existing `_child_env` test:

```python
def test_child_env_live_sets_provider_and_base_url_when_given() -> None:
    env = _child_env(
        model="deepseek-chat", max_tokens=8192, ssl_cert_file="/etc/ssl/certs/ca-certificates.crt",
        provider="deepseek", base_url="https://api.deepseek.com/v1",
    )
    assert env["ALFRED_QUARANTINE_PROVIDER"] == "deepseek"
    assert env["ALFRED_QUARANTINE_BASE_URL"] == "https://api.deepseek.com/v1"


def test_child_env_live_omits_provider_and_base_url_when_none() -> None:
    env = _child_env(model="claude-haiku-4-5", max_tokens=8192, ssl_cert_file="/etc/ssl/certs/ca-certificates.crt")
    assert "ALFRED_QUARANTINE_PROVIDER" not in env
    assert "ALFRED_QUARANTINE_BASE_URL" not in env
```

**Critical: find and update `test_child_env_live_is_dormant_plus_exactly_the_three_keys`** (in the same test file) — its name and assertion currently pin the live spawn's env to EXACTLY three golive-added keys (`ALFRED_QUARANTINE_MODEL`, `ALFRED_QUARANTINE_MAX_TOKENS`, `SSL_CERT_FILE`). Adding a fourth key breaks this test's core assertion, not just its name. Read the test's current body first, then either rename it to `test_child_env_live_is_dormant_plus_exactly_the_four_keys` and update its set-of-keys assertion to include `ALFRED_QUARANTINE_PROVIDER`, or (if the test's own docstring/structure resists a clean rename) add a sibling test asserting the same "dormant spawn env is byte-identical to before" invariant plus the new fourth key, and leave the original test's name alone with a comment noting it's now testing a subset. Prefer the rename — a stale name that still says "three" while the set has four members is exactly the kind of drift this project's memory has flagged before.

**Leave `test_routing_yaml_quarantine_provider_default_is_anthropic` (same file family, pins `routing.yaml`'s literal `provider: "anthropic"` string) UNCHANGED.** It is independently correct — the shipped YAML file still says `"anthropic"`, and that fact doesn't depend on whether anything reads it at runtime. It does NOT need a new assertion pinning it against `Settings.quarantine_provider`'s default: that Python-level default is pinned by its own field definition (Task 2), not by mirroring a YAML file the "mirror-the-YAML" drift-guard pattern was specifically built for the OLD pre-loader `_QUARANTINE_MODEL`-style mechanism, which `ALFRED_QUARANTINE_PROVIDER` does not use (it's a real `Settings` field, not a hardcoded constant standing in for an unbuilt YAML loader).

Add to the `__main__.py` test file (locate it: `find tests -iname "*quarantine_child*main*" -o -iname "*test_main*" | grep quarantine`):

```python
def test_build_provider_reads_provider_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "deepseek-chat")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    monkeypatch.setenv("ALFRED_QUARANTINE_BASE_URL", "https://api.deepseek.com/v1")
    factory = _build_provider("realkey")
    assert factory.provider_id == "deepseek"
    assert factory.base_url == "https://api.deepseek.com/v1"


def test_build_provider_defaults_to_anthropic_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-haiku-4-5")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.delenv("ALFRED_QUARANTINE_PROVIDER", raising=False)
    factory = _build_provider("realkey")
    assert factory.provider_id == "anthropic"
    assert factory.base_url is None
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest <quarantine_child_io test file> <quarantine_child __main__ test file> -v -k "provider"`
Expected: FAIL — `_child_env() got an unexpected keyword argument 'provider'`, and `_build_provider` has no `provider_id`/`base_url` attributes on its returned factory yet.

- [ ] **Step 3: Thread `provider` AND `base_url` through `_child_env` and `spawn_quarantine_child_io`**

Both new values are added together, in the same shape, since both are only meaningful on the golive `control_fd=True` path exactly like `model`/`max_tokens`/`ssl_cert_file` already are.

In `src/alfred/security/quarantine_child_io.py`, update `_child_env` (`:270-323`) — add `provider: str | None = None` and `base_url: str | None = None` to the signature:

```python
def _child_env(
    *,
    model: str | None = None,
    max_tokens: int | None = None,
    ssl_cert_file: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
) -> dict[str, str]:
```

and inside the function body, after the existing `if ssl_cert_file is not None: env["SSL_CERT_FILE"] = ssl_cert_file` line:

```python
    if provider is not None:
        env["ALFRED_QUARANTINE_PROVIDER"] = provider
    if base_url is not None:
        env["ALFRED_QUARANTINE_BASE_URL"] = base_url
```

Update `spawn_quarantine_child_io` (`:1040-1050` signature): add `provider: str | None = None` and `base_url: str | None = None` after the existing `max_tokens: int | None = None,` parameter:

```python
async def spawn_quarantine_child_io(
    *,
    provider_key: str,
    control_fd: bool = False,
    child_module: str = _CHILD_MODULE,
    egress_config: EgressProxyConfig | None = None,
    model: str | None = None,
    max_tokens: int | None = None,
    provider: str | None = None,
    base_url: str | None = None,
    ssl_cert_file: str = _DEFAULT_SSL_CERT_FILE,
    refusal_recorder: SandboxRefusalRecorder | None = None,
) -> _SubprocessChildIO:
```

Update the `child_env = (...)` construction (`:1149-1153`) to thread both:

```python
    child_env = (
        _child_env(
            model=model, max_tokens=max_tokens, ssl_cert_file=ssl_cert_file,
            provider=provider, base_url=base_url,
        )
        if control_fd
        else _child_env()
    )
```

Leave the existing `provider_config_missing` refusal guard (`:1130-1143`) checking `model is None or max_tokens is None` UNCHANGED for now — Task 4 extends it. Do not add `provider is None`/`base_url is None` checks here; both legitimately default to `None` (→ `"anthropic"` downstream, with no `base_url` needed) and are not required-at-spawn values the way `model`/`max_tokens` are — a DeepSeek spawn with a missing `base_url` is caught later, loudly, by Task 1's `build_child_client` refusal (`ValueError` on `provider_id == "deepseek"` + `base_url is None`), not here.

- [ ] **Step 4: Wire `_build_provider` (child side) to read the new env var**

In `src/alfred/security/quarantine_child/__main__.py`, update `_build_provider` (`:411-482`). Read the current function body first (do not assume the exact `try/except` structure hasn't shifted), then add the provider + base_url resolution:

```python
def _build_provider(key: str) -> _ProviderFactory:
    """Build the per-child provider FACTORY from the fd-3 key + spawn-env config."""
    from alfred.security.quarantine_child.brokered_egress import (
        QuarantineChildBootError,
        _ProviderFactory,
    )

    try:
        model = os.environ["ALFRED_QUARANTINE_MODEL"]
        raw_max_tokens = os.environ["ALFRED_QUARANTINE_MAX_TOKENS"]
    except KeyError as exc:
        missing = exc.args[0]
        raise QuarantineChildBootError(
            f"{missing} is unset in the quarantine child's scrubbed spawn env — refusing to "
            "boot a child that cannot build its provider. The host sets it in `_child_env` "
            "only on the live (control_fd=True) spawn, so an unset value means the spawn "
            "call omitted the golive provider config (§20.2)"
        ) from exc
    try:
        max_tokens = int(raw_max_tokens)
    except ValueError as exc:
        raise QuarantineChildBootError(
            f"ALFRED_QUARANTINE_MAX_TOKENS must be an integer, got {raw_max_tokens!r} — "
            "refusing to boot on an unparseable extraction budget (§20.2)"
        ) from exc
    if max_tokens <= 0:
        raise QuarantineChildBootError(
            f"ALFRED_QUARANTINE_MAX_TOKENS must be > 0, got {max_tokens} — refusing to "
            "boot a child whose every extraction would fail its >0 validator (§20.2)"
        )
    # #587: default "anthropic" when unset (matches Settings.quarantine_provider's
    # default) — a dormant/unit spawn or a pre-#587 host omits this var entirely.
    provider_id = os.environ.get("ALFRED_QUARANTINE_PROVIDER", "anthropic")
    base_url = os.environ.get("ALFRED_QUARANTINE_BASE_URL")
    return _ProviderFactory.from_key(
        key, provider_id=provider_id, model=model, max_tokens=max_tokens, base_url=base_url,
    )
```

- [ ] **Step 5: Resolve and thread the provider id + base_url from `daemon_runtime.py`**

In `src/alfred/comms_mcp/daemon_runtime.py`, add a new resolution function near `_resolve_quarantine_model_config` (`:363-395`):

```python
def _resolve_quarantine_base_url(provider_id: str, settings: Settings) -> str | None:
    """The quarantine child's base_url, when its provider needs one (#587).

    Only DeepSeek's OpenAI-compatible endpoint requires an explicit base_url — Anthropic's
    SDK has its own default. Reuses ``Settings.deepseek_base_url`` (the SAME setting the
    privileged path already reads) rather than introducing a second, quarantine-specific
    base-URL setting an operator would have to keep in sync with the first.
    """
    if provider_id != "deepseek":
        return None
    return settings.deepseek_base_url
```

(Verify whether `daemon_runtime.py` already imports `Settings` as a type — check the `if TYPE_CHECKING:` block near the top of the file; if not, add `from alfred.config.settings import Settings` under it, matching this file's existing lazy-type-import convention for size-sensitive modules.)

Update `_build_comms_inbound_extractor`'s signature (`:433-441`) to accept the resolved provider id and settings:

```python
async def _build_comms_inbound_extractor(
    *,
    audit_writer: AuditWriter,
    outbound_dlp: OutboundDlp,
    secret_broker: SecretBroker,
    staging: QuarantineStagingMap,
    environment: str,
    egress_config: EgressProxyConfig,
    quarantine_provider: str,
    quarantine_base_url: str | None,
) -> tuple[QuarantinedExtractor, QuarantineStdioTransport]:
```

and update its `spawn_quarantine_child_io(...)` call (inside the function body) to add both new kwargs, alongside the existing `model=model, max_tokens=max_tokens,` line:

```python
        provider=quarantine_provider,
        base_url=quarantine_base_url,
```

(`spawn_quarantine_child_io` already accepts both as of Step 3 above.)

- [ ] **Step 6: Update the one production call site**

In `src/alfred/cli/daemon/_comms_boot.py`, update the `_build_comms_inbound_extractor(...)` call (`:719-730`):

```python
        extractor, quarantine_transport = await _build_comms_inbound_extractor(
            audit_writer=audit,
            outbound_dlp=cast("OutboundDlp", outbound_dlp),
            secret_broker=secret_broker,
            staging=staging,
            environment=settings.environment,
            egress_config=settings,
            quarantine_provider=settings.quarantine_provider,
            quarantine_base_url=_resolve_quarantine_base_url(settings.quarantine_provider, settings),
        )
```

(`_resolve_quarantine_base_url` needs importing into `_comms_boot.py` from `daemon_runtime` — check the existing import block for `_build_comms_inbound_extractor` itself and add the new function alongside it.)

- [ ] **Step 7: Run to verify everything passes**

Run: `uv run pytest <quarantine_child_io test file> <quarantine_child __main__ test file> <daemon_runtime test file> -v`
Expected: PASS — all pre-existing tests (unaffected, since every new parameter defaults to `None`/is resolved to `"anthropic"`) plus every new test from Step 1.

Run: `uv run pytest tests/unit/cli/daemon/ -v -k comms_boot`
Expected: PASS — the one production call site's existing tests still green with the two new kwargs added.

- [ ] **Step 8: Type-check and coverage**

Run: `uv run mypy --strict src/alfred/comms_mcp/daemon_runtime.py src/alfred/security/quarantine_child_io.py src/alfred/security/quarantine_child/__main__.py src/alfred/cli/daemon/_comms_boot.py && uv run pyright <same files>`
Expected: no errors.

Run the combined coverage gate for every touched trust-boundary file (check the Makefile for the exact target name first, matching this repo's established `make coverage-gates` convention — do not invent an ad hoc invocation).
Expected: 100% line+branch maintained on every touched file under `src/alfred/security/`.

- [ ] **Step 9: Commit**

```bash
git add src/alfred/comms_mcp/daemon_runtime.py src/alfred/security/quarantine_child_io.py src/alfred/security/quarantine_child/__main__.py src/alfred/cli/daemon/_comms_boot.py <every modified test file>
git commit -m "feat(security): thread ALFRED_QUARANTINE_PROVIDER end-to-end from Settings to the spawned child (#587)"
```

---

### Task 4: Wire `assert_provider_separation()`'s real, opt-in call site

**Files:**

- Modify: `src/alfred/cli/daemon/_comms_boot.py` (or wherever the privileged provider id is already resolved alongside `settings.primary_provider` — verify against the live file)
- Test: `tests/unit/cli/daemon/test_comms_boot_graph_real_turn.py` (or the file Task 3's Step 7 already confirmed covers this call site)

**Interfaces:**

- Consumes: `alfred.bootstrap.quarantine.assert_provider_separation` (existing, unmodified — do not touch its logic, per design spec §9), `Settings.require_quarantine_provider_separation` (Task 2), `Settings.primary_provider` (existing), `Settings.quarantine_provider` (Task 2).

- [ ] **Step 1: Write the failing tests**

Add three tests to the file that already exercises `_build_comms_boot_graph`/the boot sequence (the one Task 3 Step 7 targeted — reuse its existing fixtures rather than building new ones):

```python
async def test_boot_refuses_when_separation_required_and_providers_collide(monkeypatch: pytest.MonkeyPatch) -> None:
    """require_quarantine_provider_separation=True + same provider -> refuse boot."""
    # Arrange settings with primary_provider == quarantine_provider == "deepseek"
    # and require_quarantine_provider_separation=True (match this file's existing
    # settings-construction fixture pattern).
    with pytest.raises(AlfredError, match="providers_same_error|same"):
        await _build_comms_boot_graph(settings=_settings_with(
            primary_provider="deepseek", quarantine_provider="deepseek",
            require_quarantine_provider_separation=True,
        ), ...)  # fill remaining required args from this file's existing fixture calls


async def test_boot_proceeds_when_separation_required_and_providers_differ(monkeypatch: pytest.MonkeyPatch) -> None:
    """require_quarantine_provider_separation=True + different providers -> boots fine."""
    graph = await _build_comms_boot_graph(settings=_settings_with(
        primary_provider="deepseek", quarantine_provider="anthropic",
        require_quarantine_provider_separation=True,
    ), ...)
    assert graph is not None


async def test_boot_proceeds_with_warning_when_separation_not_required_and_providers_collide(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    """Default (require=False) + same provider -> boots, but WARNS (no-silent-failures)."""
    graph = await _build_comms_boot_graph(settings=_settings_with(
        primary_provider="deepseek", quarantine_provider="deepseek",
        require_quarantine_provider_separation=False,
    ), ...)
    assert graph is not None
    assert any(
        "quarantine_provider_separation" in record.message or "same provider" in record.message.lower()
        for record in caplog.records
    )
```

(This file's real fixture/settings-construction pattern is not fully known from this plan alone — read the file first, find its existing `_settings_with`-shaped helper or equivalent, and adapt these three tests to its actual construction idiom rather than inventing a new one. The THREE BEHAVIORS under test — refuse when required+colliding, boot when required+distinct, boot-with-warning when not-required+colliding — are the fixed requirement; the exact fixture plumbing is not.)

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest <the file> -v -k separation`
Expected: FAIL — no such behavior exists yet (boot proceeds silently in all three cases today).

- [ ] **Step 3: Add the call site**

In `_comms_boot.py`, near where `quarantine_provider`/`quarantine_base_url` are resolved (Task 3 Step 6), add, BEFORE the `_build_comms_inbound_extractor(...)` call:

```python
        # #586: opt-in provider-separation enforcement. assert_provider_separation()
        # itself is unmodified (design spec §9) — only this call site and the
        # not-required+colliding warning path are new.
        if settings.require_quarantine_provider_separation:
            assert_provider_separation(
                privileged_provider_id=settings.primary_provider,
                quarantined_provider_id=settings.quarantine_provider,
            )
        elif settings.primary_provider.strip().lower() == settings.quarantine_provider.strip().lower():
            _log.warning(
                "comms.comms_boot.quarantine_provider_separation_not_enforced",
                privileged_provider=settings.primary_provider,
                quarantine_provider=settings.quarantine_provider,
            )
```

Add the import: `from alfred.bootstrap.quarantine import assert_provider_separation` (check whether `_comms_boot.py` already imports anything from `alfred.bootstrap` before adding a duplicate import block). Verify `_log` (a `structlog` logger) already exists at module scope in `_comms_boot.py` — if the module uses a differently-named logger variable, use that name instead of inventing `_log`.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest <the file> -v`
Expected: PASS — the three new tests plus every pre-existing test in the file (unaffected, since the default `require_quarantine_provider_separation=False` + typically-distinct default providers means the new code path is a no-op for every existing fixture).

- [ ] **Step 5: Type-check and coverage**

Run: `uv run mypy --strict src/alfred/cli/daemon/_comms_boot.py && uv run pyright src/alfred/cli/daemon/_comms_boot.py`
Expected: no errors.

Run the combined coverage gate again (Task 3 Step 8's command).
Expected: 100% line+branch maintained — all three new branches (refuse, boot-distinct, boot-with-warning) covered, not just one.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/cli/daemon/_comms_boot.py <the test file>
git commit -m "feat(security): wire assert_provider_separation() as an opt-in boot-time check, default off (#586)"
```

---

### Task 5: Integration test — a real DeepSeek-configured quarantine child extracts successfully end-to-end

**Files:**

- Modify: `tests/integration/test_quarantine_real_extract.py`

**Release-blocking** — this proves Piece A's transport-parametrization genuinely works against DeepSeek's real (OpenAI-compatible) API shape, not just that the branch type-checks.

This test requires the SAME `_DOCKER_ONLY` environment as the existing Anthropic proof (bwrap + Linux + root + `ALFRED_QUARANTINE_CHILD_PYTHON` provisioning) — it will not run on macOS/local dev, matching every sibling test in this file. Do not weaken the skip condition to make it runnable locally; verify it via the same Docker reproduction the file's own skip message already documents (`docker run --rm --privileged --platform linux/<arch> ...`).

- [ ] **Step 1: Add a DeepSeek-shaped canned proxy + CA**

The existing `_canned_ca` fixture (`:219-228`) and `_generate_and_install_ca` (`:165-216`) hardcode `subjectAltName=DNS:api.anthropic.com` (`_ORIGIN_HOST = "api.anthropic.com"`, `:105`). Read `_generate_and_install_ca` and `_ORIGIN_HOST`'s full definitions first, then add a parallel constant and a parametrized (or duplicated, matching whichever this file's own convention prefers — check whether it already parametrizes `_ORIGIN_HOST`-dependent fixtures elsewhere before choosing) origin host for DeepSeek:

```python
_DEEPSEEK_ORIGIN_HOST = "api.deepseek.com"
```

Extend (or add a sibling to) `_generate_and_install_ca` so a DeepSeek-scoped CA/cert pair with `SAN=DNS:api.deepseek.com` can be generated the same way the Anthropic one is — mirror the existing function's exact structure, changing only the SAN.

The existing `_CannedAnthropicProxy` (`:333-542`) returns a hardcoded Anthropic Messages-API `tool_use` response shape (`_valid_extract_body`, `:246-271`). DeepSeek's API is OpenAI-compatible chat-completions — read `_CannedAnthropicProxy`'s full class body first (it's the loopback CONNECT-proxy/TLS-terminator this test drives), then add a `_CannedDeepSeekProxy` class mirroring its structure exactly, except:
- The response body shape is an OpenAI-compatible chat-completion JSON object, not an Anthropic Messages-API `tool_use` block.
- Since `deepseek-chat` does NOT have `NATIVE_CONSTRAINED_GENERATION` (confirmed: `provider_dispatch.py`'s own docstring states any provider without it, including deepseek-chat/deepseek-reasoner, uses `prompt_embedded_fallback` — the JSON_OBJECT_MODE branch this test's expected response shape might assume was REMOVED in fork (b)), the canned response must be shaped for the **prompt-embedded fallback** path, not a JSON-object/tool-call shape. Read `provider_dispatch.py`'s `prompt_embedded_fallback` handling first to determine the exact response shape it expects (likely: plain assistant-message text content containing the extraction JSON as a string, parsed downstream) before writing the canned response — do not guess this shape; if it's unclear from reading `provider_dispatch.py` alone, also read whatever unit test already exercises the `prompt_embedded_fallback` branch and copy its exact expected-response shape.

- [ ] **Step 2: Write the test**

```python
@_DOCKER_ONLY
@pytest.mark.usefixtures("_launcher_environment")
@pytest.mark.asyncio
async def test_real_extract_deepseek_returns_extracted_via_prompt_embedded_fallback(
    _canned_deepseek_ca: tuple[Path, Path],
) -> None:
    """#587: a real bwrap child, configured for DeepSeek, extracts via the
    prompt-embedded-fallback path (deepseek-chat has no native constrained generation)."""
    cert, key = _canned_deepseek_ca
    proxy = _CannedDeepSeekProxy(cert, key)
    child_io: _SubprocessChildIO | None = None
    try:
        child_io = await _spawn_real_child(proxy, provider="deepseek", model="deepseek-chat")
        async with _extraction_stack(child_io) as (bridge, audit_writer):
            proxy.settle()
            result = await bridge.extract(
                body=_INBOUND_BODY, canonical_user_id="alice", source_tier="T3"
            )
            assert isinstance(result, Extracted), result
            assert result.data == {"text": _CANNED_TEXT, "intent": _CANNED_INTENT}
            assert result.extraction_mode == "prompt_embedded_fallback"

            extract_rows = audit_writer.rows_for("quarantine.extract")
            assert len(extract_rows) == 1, extract_rows
            assert extract_rows[0]["result"] == "extracted", extract_rows
    finally:
        if child_io is not None:
            await child_io.aclose()
        proxy.close()
```

`_spawn_real_child` (`:635-643`) needs a `provider: str = "anthropic"` parameter added (defaulting to today's behaviour) so this test can request `provider="deepseek"` — thread it into the existing `spawn_quarantine_child_io(...)` call inside `_spawn_real_child` alongside the `model=`/`max_tokens=` it already passes (Task 3 already added `provider=`/`base_url=` params to `spawn_quarantine_child_io` itself; this step only threads a value through this ONE test helper).

`_canned_deepseek_ca` needs a fixture definition mirroring `_canned_ca` (`:219-228`) exactly, using `_DEEPSEEK_ORIGIN_HOST` instead of `_ORIGIN_HOST`.

- [ ] **Step 3: Run to verify it passes (Docker only)**

Run inside the Docker reproduction this file's own skip message documents (`docker run --rm --privileged --platform linux/<arch> ...`, provisioning `ALFRED_QUARANTINE_CHILD_PYTHON` first per the existing test's own setup): `uv run pytest tests/integration/test_quarantine_real_extract.py -v -k deepseek`
Expected: PASS.

- [ ] **Step 4: Run the full file (regression check, Docker only)**

Run: `uv run pytest tests/integration/test_quarantine_real_extract.py -v`
Expected: PASS — every pre-existing Anthropic-path test unaffected.

- [ ] **Step 5: Commit**

```bash
git add tests/integration/test_quarantine_real_extract.py
git commit -m "test(security): real DeepSeek quarantine extraction, end-to-end via prompt-embedded fallback (#587)"
```

---

### Task 6: Documentation — correct every stale claim this work found

**Files:**

- Modify: `config/routing.yaml`
- Modify: `.env.example`
- Modify: `docs/runbooks/slice-3-quarantined-llm.md`
- Modify: `README.md`

- [ ] **Step 1: Fix `config/routing.yaml`'s `[quarantine]` comment**

Replace the comment above `provider: "anthropic"` (`:20-26`) — remove the false "the bootstrap-time check ... refuses to start when the ... ids collide" claim (true only when `ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=true` now, not unconditionally) and note that `provider` here is NOT the runtime source of truth (that's `Settings.quarantine_provider` / `ALFRED_QUARANTINE_PROVIDER`, per Task 2/3):

```yaml
  # Provider for the quarantined LLM. NOTE (#587): this routing.yaml value is NOT
  # read at runtime — no loader exists yet ("slice 4+"). The actual runtime source
  # of truth is the ALFRED_QUARANTINE_PROVIDER .env setting (Settings.quarantine_provider,
  # default "anthropic"). This field stays here as the alfred-config-proposal target
  # (the state.git reviewer-gate flow, docs/runbooks/slice-3-quarantined-llm.md) and
  # as documentation of the shipped default, but changing it alone does nothing.
  #
  # Provider-separation enforcement (spec §5.4, PRD §6.4's defence-in-depth
  # rationale) is OPT-IN (#586): set ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=true
  # to refuse boot on a same-provider collision. Default: permitted, with a warning.
  provider: "anthropic"
```

- [ ] **Step 2: Update `.env.example`**

Add near the existing `ALFRED_QUARANTINE_PROVIDER_API_KEY` entry:

```
# #587: which provider the quarantine child uses. "anthropic" | "deepseek".
# Default: anthropic (matches routing.yaml's shipped default).
# ALFRED_QUARANTINE_PROVIDER=anthropic

# #586: opt-in enforcement that the quarantine and privileged providers differ.
# Default: false — same-provider is permitted (a warning is logged, not a refusal).
# Set true for the stricter defence-in-depth posture (spec §5.4 / PRD §6.4).
# ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=false
```

Also correct the existing note at `.env.example:225-227` ("There are NO ALFRED_QUARANTINED_PROVIDER / ALFRED_QUARANTINED_MODEL env vars... nothing has ever read them") — that's now false for `ALFRED_QUARANTINE_PROVIDER` as of this PR; update it to describe the real, current mechanism instead of the old absence.

- [ ] **Step 3: Fix the three stale claims in `docs/runbooks/slice-3-quarantined-llm.md`**

In the "Provider configuration" section (`:36-63`):
1. Fix the capability table's `deepseek` row — it currently claims `JSON_OBJECT_MODE` → `json_object_unconstrained`; per `provider_dispatch.py`'s own docstring, DeepSeek (chat or reasoner) actually uses `prompt_embedded_fallback` (no native constrained generation). Correct the row.
2. Remove or correct the framing that `routing.yaml [quarantine].provider` "drives" runtime capability advertisement — it does not (Task 6 Step 1's finding); point instead at `ALFRED_QUARANTINE_PROVIDER`.
3. Remove the "bootstrap-time check ... refuses to start" unconditional claim, replacing it with the opt-in framing (mirroring Step 1's fix).

- [ ] **Step 4: Update README's Quickstart provider-key callout**

In the "Two provider keys are required" block (`README.md:44-67`), add a note that the quarantine role now defaults to Anthropic but can be set to DeepSeek (`ALFRED_QUARANTINE_PROVIDER=deepseek`) — and that same-provider is permitted by default (no longer an implicit, undocumented "you happen to get away with it" state — it's now an intentional, documented default).

- [ ] **Step 5: Commit**

```bash
git add config/routing.yaml .env.example docs/runbooks/slice-3-quarantined-llm.md README.md
git commit -m "docs: correct quarantine-provider claims across routing.yaml, .env.example, the runbook, and README (#586 #587)"
```

---

## Definition of Done

- [ ] All 6 tasks' tests pass: `uv run pytest tests/unit/security/test_brokered_provider_source.py tests/unit/security/test_brokered_egress_transport.py tests/unit/config/ tests/unit/security/ tests/unit/cli/daemon/ tests/unit/comms_mcp/ -v` (adjust exact paths per what Task 2/3 actually located).
- [ ] `make check` passes clean.
- [ ] 100% line+branch coverage on every touched file under `src/alfred/security/` (dual-LLM boundary, release-blocking).
- [ ] `alfred-security-engineer` sign-off obtained.
- [ ] The Docker-only DeepSeek extraction test (Task 5) run and confirmed passing at least once before merge (it does not run in a default local/macOS `make check`).
- [ ] `/review-plan` fleet run on this plan before implementation; full `/review-pr` fleet + CodeRabbit `full review` on the resulting PR before merge.
- [ ] Every existing test in every touched file still passes unmodified with both new settings at their defaults (byte-for-byte non-breaking requirement).
- [ ] PRD §6.4's wording (still describing an unconditional "MUST differ") is flagged to a human maintainer as needing a follow-up edit — this plan does not touch `PRD.md` itself (human-gated per repo policy), but the gap should not go unflagged once this PR ships and the PRD's claim becomes even more visibly stale than it is today.

# Issues #586 + #587 — Real Quarantine-Provider Dispatch + Opt-In Separation Enforcement — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the quarantine child actually use DeepSeek (not just Anthropic, which is hardcoded today despite documentation claiming a choice exists), and wire the already-implemented, already-tested `assert_provider_separation()` into a real boot-time call site — gated behind a new setting that defaults OFF, so no operator is forced to run two paid provider accounts.

**Architecture:** Two coupled pieces landing in one PR (same boot/spawn call sites, cheaper to review together). Piece A provider-parametrizes the quarantine child's transport-construction layer (`brokered_egress.py`) and threads a new `ALFRED_QUARANTINE_PROVIDER` setting from `.env` → `Settings` → `daemon_runtime.py` → the spawn env → the child's `_build_provider`. Piece B adds `ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION` (bool, default `False`) and gives `assert_provider_separation()` its first production call site, exactly at the point Piece A resolves the two provider ids.

**Tech Stack:** Python 3.14, pytest + pytest-asyncio, real `socket.socketpair()` fixtures (this file's established fake-transport pattern — never a mock socket), Docker for the one Linux/bwrap/root-only integration leg.

## Global Constraints

- `mypy --strict` + `pyright` clean on every new/modified file.
- CLAUDE.md hard rule #7: no silent fail-open. Every new refusal path (unsupported provider id, missing base_url, provider-separation collision) is a loud raise, never a swallowed default.
- CLAUDE.md hard rule #5: no secret-bearing value in a repr, log line, or the child's env — `_ProviderFactory.__repr__` stays key-free; the provider ID and `base_url` are NOT secrets and may appear in logs/env freely, but must never carry a key.
- Dual-LLM trust boundary touched (`brokered_egress.py`, `daemon_runtime.py`, `quarantine_child_io.py`, and the new `assert_provider_separation()` call site added to `_comms_boot.py` — `bootstrap/quarantine.py` itself stays unmodified, design spec §9) — `alfred-security-engineer` sign-off, and 100% line+branch coverage on every touched file in `src/alfred/security/` (plus `_comms_boot.py`/`_failures.py`/`_commands.py`'s new branches, already covered by the existing combined gate — see Definition of Done), are release-blocking per CLAUDE.md.
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

Add to `tests/unit/security/test_brokered_provider_source.py`, near the existing `_factory()` helper (`:85-88` — `:69-82` is `_af_unix_socketpair()`, not `_factory()`) and `test_factory_from_key_builds_frozen_config` (`:105-111`). The existing `_factory()` helper and every test that calls it must be updated to pass `provider_id="anthropic"` (a required field now) — do this first so the pre-existing tests keep passing, then add the new DeepSeek-path tests:

**Two pre-existing tests call `_ProviderFactory.from_key(...)` DIRECTLY, bypassing `_factory()` — each needs its own `provider_id="anthropic"` added or it TypeErrors once `provider_id` becomes required (test-003, High):** `test_factory_refuses_empty_key` (`:99-102`) and `test_factory_from_key_builds_frozen_config` (`:105-111`). Add `provider_id="anthropic"` to both direct `_ProviderFactory.from_key(...)` calls. `test_factory_refuses_empty_key` is doubly affected: without this fix the `TypeError` (missing required kwarg) fires before `from_key`'s own empty-key check ever runs, so its `pytest.raises(QuarantineChildBootError)` sees the wrong exception type and fails — not just an unrelated break.

```python
def _factory(
    timeout: httpx.Timeout | None = None, *, provider_id: str = "anthropic", model: str | None = None,
) -> _ProviderFactory:
    return _ProviderFactory(
        provider_id=provider_id,
        api_key="super-secret",
        model=model or ("claude-haiku-4-5" if provider_id == "anthropic" else "deepseek-chat"),
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
    fd = a.detach()
    try:
        provider, backend = be.build_child_client(
            fd,
            provider_id="deepseek",
            model="deepseek-chat",
            api_key="k",
            timeout=be._CHILD_SDK_READ_TIMEOUT,
            budget_seconds=5.0,
            base_url="https://api.deepseek.com/v1",
        )
        assert isinstance(provider, DeepSeekProvider)
    finally:
        # test-r2-006: reclaim both the detached raw fd AND both socketpair ends —
        # match this file's own established fd-ownership discipline (see e.g.
        # test_factory_build_resolves_read_timeout / test_build_anchors_the_attempt_deadline_from_the_budget).
        os.close(fd)
        a.close()
        b.close()


def test_build_child_client_deepseek_requires_base_url() -> None:
    """A DeepSeek dispatch with no base_url refuses loudly (HARD #7), never silently
    falls back to some default the operator didn't choose."""
    a, b = socket.socketpair()
    fd = a.detach()
    try:
        with pytest.raises(ValueError, match="base_url"):
            be.build_child_client(
                fd,
                provider_id="deepseek",
                model="deepseek-chat",
                api_key="k",
                timeout=be._CHILD_SDK_READ_TIMEOUT,
                budget_seconds=5.0,
                base_url=None,
            )
    finally:
        os.close(fd)
        a.close()
        b.close()


def test_provider_source_capabilities_resolve_per_provider() -> None:
    """BrokeredProviderSource.capabilities() reflects the CONFIGURED provider/model,
    not a hardcoded Anthropic classvar — the #587 correctness gap the design doc named."""
    anthropic_end, anthropic_peer = _af_unix_socketpair()
    deepseek_end, deepseek_peer = _af_unix_socketpair()
    try:
        anthropic_source = BrokeredProviderSource(_factory(provider_id="anthropic"), anthropic_end)
        deepseek_source = BrokeredProviderSource(_factory(provider_id="deepseek"), deepseek_end)
        assert anthropic_source.capabilities() == AnthropicProvider.CAPABILITIES
        assert deepseek_source.capabilities() == DeepSeekProvider._capabilities_for_model("deepseek-chat")
        assert anthropic_source.capabilities() != deepseek_source.capabilities()
    finally:
        # test-r2-006: _af_unix_socketpair() returns BOTH ends — the peer end was
        # discarded and leaked in the original draft; close all four sockets here.
        anthropic_end.close()
        anthropic_peer.close()
        deepseek_end.close()
        deepseek_peer.close()


def test_provider_source_capabilities_resolve_per_model() -> None:
    """DeepSeek's capabilities are MODEL-aware, not just provider-aware (test-005):
    deepseek-chat and deepseek-reasoner have genuinely non-overlapping capability
    sets. A regression that hardcodes the literal "deepseek-chat" into capability
    resolution instead of reading `factory.model` would pass
    `test_provider_source_capabilities_resolve_per_provider` unchanged — this test
    is the one that actually pins model-awareness."""
    chat_end, chat_peer = _af_unix_socketpair()
    reasoner_end, reasoner_peer = _af_unix_socketpair()
    try:
        chat_source = BrokeredProviderSource(_factory(provider_id="deepseek", model="deepseek-chat"), chat_end)
        reasoner_source = BrokeredProviderSource(
            _factory(provider_id="deepseek", model="deepseek-reasoner"), reasoner_end
        )
        assert chat_source.capabilities() == DeepSeekProvider._capabilities_for_model("deepseek-chat")
        assert reasoner_source.capabilities() == DeepSeekProvider._capabilities_for_model("deepseek-reasoner")
        assert chat_source.capabilities() != reasoner_source.capabilities()
    finally:
        chat_end.close()
        chat_peer.close()
        reasoner_end.close()
        reasoner_peer.close()


def test_build_child_client_refuses_unknown_provider_id() -> None:
    """An out-of-closed-set provider_id refuses loudly (HARD #7, sec-002) rather than
    silently falling through to the Anthropic branch — a two-way if/else cannot
    distinguish 'deepseek' from 'anything else', so this pins the 3-way dispatch."""
    a, b = socket.socketpair()
    fd = a.detach()
    try:
        with pytest.raises(ValueError, match="provider_id"):
            be.build_child_client(
                fd,
                provider_id="openai",
                model="gpt-4",
                api_key="k",
                timeout=be._CHILD_SDK_READ_TIMEOUT,
                budget_seconds=5.0,
            )
    finally:
        os.close(fd)
        a.close()
        b.close()


def test_provider_source_construction_refuses_unknown_provider_id() -> None:
    """test-r2-004: BrokeredProviderSource.__init__'s OWN closed-set refusal (sec-002)
    is a distinct dispatch site from build_child_client's — this is the test that
    actually exercises it, since none of the tests above construct a source with an
    out-of-set provider_id. Required for the 100%-branch trust-boundary coverage
    gate this task's Step 6 already demands."""
    end, peer = _af_unix_socketpair()
    try:
        with pytest.raises(ValueError, match="provider_id"):
            BrokeredProviderSource(_factory(provider_id="openai"), end)
    finally:
        end.close()
        peer.close()
```

Add the imports `from alfred.providers.deepseek import DeepSeekProvider` and `import os` (if not already imported) to the test file's existing import block (`:22-44`).

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/security/test_brokered_provider_source.py -v -k "deepseek or dispatches_to or capabilities_resolve or refuses_unknown_provider"`
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
    elif provider_id == "anthropic":
        provider = AnthropicProvider.from_settings(
            api_key=api_key, model=model, http_client=http_client, max_retries=0, timeout=timeout
        )
    else:
        raise ValueError(
            f"build_child_client: unsupported provider_id {provider_id!r} — refusing to "
            "silently construct either provider for an out-of-closed-set value (HARD #7, sec-002)"
        )
    return provider, backend
```

(sec-002: this is a genuine 3-way closed-set dispatch, not a 2-way if/else with `"anthropic"` as an implicit else. The closed set IS validated upstream at settings-parse time in Task 2 — but this function is also reachable directly, bypassing `Settings`, from tests and from the child's own `_build_provider` re-read of `os.environ` (Task 3), neither of which re-validates the closed set. An `else: raise` here is defense-in-depth, not duplicated logic: it turns a would-be silent-wrong-provider construction into a loud refusal at the one place both callers converge.)

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
        #
        # sec-002: this is a genuine 3-way closed-set dispatch (matching
        # build_child_client's Step 3 fix), not a 2-way if/else — an out-of-set
        # provider_id must refuse loudly here too, not silently resolve to
        # DeepSeek's (frequently empty) capability set for an unknown value.
        self._caps: frozenset[ProviderCapability]
        if factory.provider_id == "anthropic":
            self._caps = AnthropicProvider.CAPABILITIES
        elif factory.provider_id == "deepseek":
            self._caps = DeepSeekProvider._capabilities_for_model(factory.model)
        else:
            raise ValueError(
                f"BrokeredProviderSource: unsupported provider_id {factory.provider_id!r} — "
                "refusing to silently resolve either capability set (HARD #7, sec-002)"
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

Update the `bind()` method's local variable annotation (`:459-461`, BEFORE the `try` block, which begins at `:463`):

```python
        provider: AnthropicProvider | DeepSeekProvider | None = None
```

**`bind()`'s own declared return-type annotation must ALSO be widened (prov-002, High — mypy --strict fails without this)**: find `bind`'s `def bind(self, *, budget_seconds: float) -> AbstractAsyncContextManager[AnthropicProvider]:` (or, if it's an `@asynccontextmanager`-decorated generator, `-> AsyncIterator[AnthropicProvider]:`) and widen it the same way the `ProviderSource` Protocol's declaration was just widened above:

```python
    async def bind(self, *, budget_seconds: float) -> AsyncIterator[AnthropicProvider | DeepSeekProvider]:
```

(Match whichever of `AbstractAsyncContextManager[...]` / `AsyncIterator[...]` the live method actually declares — read it first; the Protocol and the concrete implementation may use different but equivalent spellings depending on whether the concrete method is `@asynccontextmanager`-decorated. Widen whichever one is there. Once `provider` can be `AnthropicProvider | DeepSeekProvider`, every `yield provider` / `return`-shaped exit in this method must type-check against the widened annotation — verify with `mypy --strict` in Step 6, not just visual inspection.)

(The `_CAPS = AnthropicProvider.CAPABILITIES` classvar line — originally at `:397` — is deleted entirely, replaced by the `self._caps` instance attribute above.)

- [ ] **Step 5: Run to verify they pass**

Run: `uv run pytest tests/unit/security/test_brokered_provider_source.py tests/unit/security/test_brokered_egress_transport.py -v`
Expected: PASS — every pre-existing test (now passing `provider_id="anthropic"` via the updated `_factory()` helper and the two direct `from_key(...)` call sites) plus the seven new tests from Step 1.

- [ ] **Step 6: Type-check and coverage**

Run: `uv run mypy --strict src/alfred/security/quarantine_child/brokered_egress.py && uv run pyright src/alfred/security/quarantine_child/brokered_egress.py`
Expected: no errors — including on `bind()`'s widened return annotation (prov-002).

Run: `uv run pytest tests/unit/security/test_brokered_provider_source.py tests/unit/security/test_brokered_egress_transport.py --cov=alfred.security.quarantine_child.brokered_egress --cov-report=term-missing`
Expected: 100% line + branch (trust-boundary file, CLAUDE.md hard rule) — the `provider_id == "deepseek"` branch, the `base_url is None` refusal arm, AND both new `else: raise` closed-set-refusal branches (`build_child_client` and `BrokeredProviderSource.__init__`, sec-002) must show as covered, not just the two happy paths.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/security/quarantine_child/brokered_egress.py tests/unit/security/test_brokered_provider_source.py
git commit -m "feat(security): provider-parametrize the quarantine child's brokered transport (#587)"
```

---

### Task 2: Add the two new `Settings` fields

**Files:**

- Modify: `src/alfred/config/settings.py`
- Reference (import only, in the test file — `_validators.py` itself is NOT modified; arch-004): `src/alfred/cli/_validators.py`
- Test: `tests/unit/config/test_settings.py` (verify this file exists first — if the actual settings test file has a different name, use that one instead; do not create a new one if an existing settings test module already covers `Settings` field defaults/validation)

**Interfaces:**

- Produces: `Settings.quarantine_provider: Literal["anthropic", "deepseek"]` (default `"anthropic"`), `Settings.require_quarantine_provider_separation: bool` (default `False`).
- Consumes: `alfred.cli._validators._ALLOWED_QUARANTINED_PROVIDERS` (existing, `frozenset({"anthropic", "deepseek"})`) — imported ONLY in the test file, as a drift cross-check (see Step 1/Step 3; prov-003).

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


def test_quarantine_provider_literal_matches_allowed_quarantined_providers() -> None:
    """Drift cross-check (prov-003): Settings.quarantine_provider's Literal values and
    _validators._ALLOWED_QUARANTINED_PROVIDERS are two independently-maintained
    closed sets (a THIRD copy also exists in alfred.state.proposal_payloads — not
    cross-checked here, tracked as a separate follow-up). This test is the one thing
    that actually catches the two drifting apart; a code comment alone would not."""
    from typing import get_args

    from alfred.cli._validators import _ALLOWED_QUARANTINED_PROVIDERS

    literal_values = frozenset(get_args(Settings.model_fields["quarantine_provider"].annotation))
    assert literal_values == _ALLOWED_QUARANTINED_PROVIDERS
```

(Match whatever constructor pattern the existing test file already uses for a minimal valid `Settings()` — it may need more required fields than shown here; read an existing passing test in the same file and copy its exact minimal-construction shape rather than guessing.)

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest <the located settings test file> -v -k "quarantine_provider or require_quarantine"`
Expected: FAIL — `TypeError: Settings() got an unexpected keyword argument 'quarantine_provider'` (Pydantic will actually just ignore/reject via extra="forbid" or similar — verify the exact failure mode against the live file, but it must fail since the field doesn't exist).

- [ ] **Step 3: Add the fields**

In `src/alfred/config/settings.py`, verify `Literal` is already imported from `typing` before adding a duplicate.

**Do NOT import `_ALLOWED_QUARANTINED_PROVIDERS` into `settings.py` itself (prov-003 fix).** The field below is a hand-written `Literal[...]` — `mypy --strict` needs a static literal, it cannot be constructed dynamically from a frozenset, so an import into PRODUCTION code here would be genuinely unused (ruff F401). The drift cross-check lives in the TEST file instead (Step 1's `test_quarantine_provider_literal_matches_allowed_quarantined_providers`), which is where the import belongs.

Add the two fields after the existing `fallback_provider: str = "anthropic"` line (`settings.py:210`):

```python
    # #587: the quarantine child's provider — closed set, kept in sync BY HAND with
    # the CLI's existing quarantined-provider validator
    # (alfred.cli._validators._ALLOWED_QUARANTINED_PROVIDERS) — a Literal here cannot
    # import that frozenset directly (mypy --strict needs a static literal), so
    # test_quarantine_provider_literal_matches_allowed_quarantined_providers
    # (tests/unit/config/, this task) is the drift detector, not this comment. A THIRD
    # independent copy of this same two-value set exists in
    # alfred.state.proposal_payloads (line ~155) — not cross-checked by this plan;
    # unifying all three is follow-up debt, not blocking this task (prov-003).
    # Defaults to "anthropic" — byte-for-byte today's behaviour for every deployment
    # that doesn't set this.
    quarantine_provider: Literal["anthropic", "deepseek"] = "anthropic"

    # #586: opt-in enforcement that the quarantine and privileged providers differ.
    # NOTE: no PRD section actually states this invariant today (arch-001/rev-001) —
    # do NOT cite "PRD §6.4" here (that section is "Self-Improvement with Reviewer
    # Gate", unrelated). See ADR-XXXX (Task 6 Step 0 of this plan — check `ls docs/adr/`
    # for the next free number at implementation time) for the accurately-anchored
    # record of this decision. Defaults to False: a home/self-hosted operator must
    # never be forced into running two paid provider accounts. An enterprise
    # deployment that wants the stricter posture sets this to True.
    require_quarantine_provider_separation: bool = Field(
        default=False,
        description=(
            "When True, refuse to boot if the quarantine and privileged providers "
            "are the same id (see alfred.bootstrap.quarantine.assert_provider_separation). "
            "Default False — same-provider is permitted, with an operator-facing warning "
            "(see #586, ADR-XXXX)."
        ),
    )
```

(Verify `Field` is already imported from `pydantic` in this file before adding a duplicate import — it almost certainly is, given `daily_budget_usd`'s existing `Field(default=1.0, gt=0)` usage at `:262`.)

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest <the located settings test file> -v`
Expected: PASS — every pre-existing test plus the six new ones.

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
- Test: `tests/unit/comms_mcp/test_daemon_runtime.py` (verify `_resolve_quarantine_model_config`/`_build_comms_inbound_extractor`'s exact existing test coverage there first), `tests/unit/security/test_quarantine_child_io_control_fd.py` (confirmed live location of the `_child_env`/dormancy-invariant tests), `tests/unit/security/test_max_tokens_guard.py` (confirmed live location of `_build_provider`'s existing `test_child_build_provider_*` test family — test-004; the plan's original locate command for a `test_main`-shaped file returns nothing against the live tree), `tests/unit/egress/test_broker_audit_wiring.py` (pre-flight-scan finding, verified live: `test_auditor_is_threaded_into_transport` calls `_build_comms_inbound_extractor(...)` directly at `:230-237` with only the original 6 kwargs — an EIGHTH direct call site beyond the 7 in `test_daemon_runtime.py`, not otherwise caught by this task's own file list; see Step 7).

**Interfaces:**

- Consumes: Task 1's `build_child_client(..., provider_id=..., base_url=...)` / `_ProviderFactory.from_key(..., provider_id=..., base_url=...)`; Task 2's `Settings.quarantine_provider`.
- Produces: `_child_env(..., provider: str | None = None)` sets `ALFRED_QUARANTINE_PROVIDER`; `spawn_quarantine_child_io(..., provider: str | None = None)` threads it; `_build_comms_inbound_extractor(..., quarantine_provider: str, quarantine_model: str, quarantine_base_url: str | None)` (new required params) resolves and forwards them; `daemon_runtime._resolve_quarantine_base_url(provider_id: str, settings: Settings) -> str | None` (new, TWO params — rev-005) resolves DeepSeek's base URL from `Settings.deepseek_base_url` when `provider_id == "deepseek"`, else `None`; `daemon_runtime._resolve_quarantine_model(provider_id: str, settings: Settings) -> str` (new — prov-001, the plan's most consequential fix) resolves the quarantine child's MODEL id per-provider, replacing the prior provider-blind `_resolve_quarantine_model_config()` call at its one call site.

- [ ] **Step 1: Write the failing tests**

Add to the quarantine_child_io test file (locate it first: `find tests -iname "*quarantine_child_io*"`), near any existing `_child_env` test:

**Call `_child_env` via this file's established module alias, `qcio.` (rev-r2-001/test-r2-001, High) — a bare `_child_env(...)` call `NameError`s, since this file imports `from alfred.security import quarantine_child_io as qcio` and every existing call site uses `qcio._child_env(...)`, never a bare import:**

```python
def test_child_env_live_sets_provider_and_base_url_when_given() -> None:
    env = qcio._child_env(
        model="deepseek-chat", max_tokens=8192, ssl_cert_file="/etc/ssl/certs/ca-certificates.crt",
        provider="deepseek", base_url="https://api.deepseek.com/v1",
    )
    assert env["ALFRED_QUARANTINE_PROVIDER"] == "deepseek"
    assert env["ALFRED_QUARANTINE_BASE_URL"] == "https://api.deepseek.com/v1"


def test_child_env_live_omits_provider_and_base_url_when_none() -> None:
    env = qcio._child_env(model="claude-haiku-4-5", max_tokens=8192, ssl_cert_file="/etc/ssl/certs/ca-certificates.crt")
    assert "ALFRED_QUARANTINE_PROVIDER" not in env
    assert "ALFRED_QUARANTINE_BASE_URL" not in env
```

**Critical (core-002/test-006, corroborated): update `test_child_env_live_is_dormant_plus_exactly_the_three_keys` AND its module-level `_GOLIVE_ENV_KEYS` constant together, in the SAME commit.** Both live in `tests/unit/security/test_quarantine_child_io_control_fd.py` (confirmed: the test at `:515-534`, the constant at `:478-480`). `_GOLIVE_ENV_KEYS` is shared by three tests in this file (`test_child_env_default_omits_golive_provider_config`, this test, `test_default_spawn_env_omits_golive_provider_config`) — widening it to 4 members is safe for the other two (their `.isdisjoint()` checks stay correct as the set grows), but THIS test's own `_child_env(...)` call must ALSO gain `provider="anthropic"`, or the test fails on its own: `live`/`dormant` would still differ by exactly the original 3 keys while the assertion now expects 4. Rename to `test_child_env_live_is_dormant_plus_exactly_the_four_keys` and replace its body:

```python
_GOLIVE_ENV_KEYS = frozenset(
    {
        "ALFRED_QUARANTINE_MODEL",
        "ALFRED_QUARANTINE_MAX_TOKENS",
        "SSL_CERT_FILE",
        "ALFRED_QUARANTINE_PROVIDER",
    }
)


def test_child_env_live_is_dormant_plus_exactly_the_four_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Live env == dormant env + EXACTLY the four golive keys (strict byte-identity).

    Nothing else in the dormant env changes value; the live path only ADDS the four
    host-passed keys — the precise contract the ADR-0050 dormancy invariant rests on.
    `base_url` is intentionally NOT part of this assertion: the anthropic default
    never sets `ALFRED_QUARANTINE_BASE_URL` (only a DeepSeek spawn does), so it stays
    out of the fixed four-key set this test pins.
    """
    for key in _GOLIVE_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    dormant = qcio._child_env()
    live = qcio._child_env(
        model="claude-haiku-4-5",
        max_tokens=8192,
        ssl_cert_file="/etc/ssl/certs/ca-certificates.crt",
        provider="anthropic",
    )
    assert set(live) - set(dormant) == _GOLIVE_ENV_KEYS
    for key in dormant:
        assert live[key] == dormant[key]
```

**Leave `test_routing_yaml_quarantine_provider_default_is_anthropic` (same file family, pins `routing.yaml`'s literal `provider: "anthropic"` string) UNCHANGED.** It is independently correct — the shipped YAML file still says `"anthropic"`, and that fact doesn't depend on whether anything reads it at runtime. It does NOT need a new assertion pinning it against `Settings.quarantine_provider`'s default: that Python-level default is pinned by its own field definition (Task 2), not by mirroring a YAML file the "mirror-the-YAML" drift-guard pattern was specifically built for the OLD pre-loader `_QUARANTINE_MODEL`-style mechanism, which `ALFRED_QUARANTINE_PROVIDER` does not use (it's a real `Settings` field, not a hardcoded constant standing in for an unbuilt YAML loader).

Add to `tests/unit/security/test_max_tokens_guard.py` (test-004: this is the CONFIRMED live home of `_build_provider`'s existing test family — six tests named `test_child_build_provider_*`; the plan's original locate command for a `test_main`-shaped file returns zero results against the live tree). Name the two new tests to match that established family, and **call `_build_provider` via this file's established module alias, `child_main.` (rev-r2-001/test-r2-001, High) — a bare `_build_provider(...)` call `NameError`s, since this file imports `from alfred.security.quarantine_child import __main__ as child_main` and all six existing tests call `child_main._build_provider(...)`, never a bare import:**

```python
def test_child_build_provider_reads_provider_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "deepseek-chat")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    monkeypatch.setenv("ALFRED_QUARANTINE_BASE_URL", "https://api.deepseek.com/v1")
    factory = child_main._build_provider("realkey")
    assert factory.provider_id == "deepseek"
    assert factory.base_url == "https://api.deepseek.com/v1"


def test_child_build_provider_defaults_to_anthropic_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-haiku-4-5")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    monkeypatch.delenv("ALFRED_QUARANTINE_PROVIDER", raising=False)
    factory = child_main._build_provider("realkey")
    assert factory.provider_id == "anthropic"
    assert factory.base_url is None
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/security/test_quarantine_child_io_control_fd.py tests/unit/security/test_max_tokens_guard.py -v -k "provider"`
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

In `src/alfred/security/quarantine_child/__main__.py`, update `_build_provider` (`:411-482`). Read the current function body first (do not assume the exact `try/except` structure hasn't shifted). **Keep the function's existing ~30-line docstring VERBATIM (rev-009)** — it documents the egress-free boot-path rationale and why the KeyError/ValueError paths unify into `QuarantineChildBootError`; the code block below shows only where the two new lines insert (before the `return`), not a full-function replacement to paste over the real docstring:

```python
def _build_provider(key: str) -> _ProviderFactory:
    """<KEEP THE LIVE DOCSTRING VERBATIM — do not replace it with this placeholder>"""
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

- [ ] **Step 5: Resolve and thread the provider id, MODEL, and base_url from `daemon_runtime.py`**

**This step fixes prov-001 — the single most consequential finding in the whole review.** As drafted, this plan threaded `provider_id` and `base_url` end-to-end but left the quarantine child's MODEL resolution untouched: `_build_comms_inbound_extractor` (`:497`, confirmed live) calls `model, max_tokens = _resolve_quarantine_model_config()` unconditionally, and that function (`:363-395`, confirmed live) always returns the hardcoded `_QUARANTINE_MODEL = "claude-haiku-4-5"` (an Anthropic model id) regardless of provider. Setting `ALFRED_QUARANTINE_PROVIDER=deepseek` without this fix spawns a DeepSeek-provider child asking DeepSeek's API for `claude-haiku-4-5` — a 4xx on every real extraction. This is the plan's headline deliverable; it does not work without this step.

In `src/alfred/comms_mcp/daemon_runtime.py`, add TWO new resolution functions near `_resolve_quarantine_model_config` (`:363-395`):

```python
def _resolve_quarantine_model(provider_id: str, settings: Settings) -> str:
    """The quarantine child's model id, provider-aware (#587 — prov-001 fix).

    Anthropic keeps the existing hardcoded quarantine model (``_QUARANTINE_MODEL``,
    "claude-haiku-4-5") — a fixed, cheap-model choice independent of the privileged
    path's own model selection; there has never been a per-deployment Anthropic
    quarantine-model setting. DeepSeek has no equivalent hardcoded quarantine
    constant, so this reuses ``Settings.deepseek_model`` (the SAME setting the
    privileged DeepSeek path already reads) rather than adding a second,
    quarantine-specific DeepSeek model setting an operator would have to keep in
    sync with the first — mirroring ``_resolve_quarantine_base_url``'s reuse of
    ``Settings.deepseek_base_url`` below.
    """
    if provider_id == "deepseek":
        return settings.deepseek_model
    if provider_id == "anthropic":
        return _QUARANTINE_MODEL
    raise ValueError(
        f"_resolve_quarantine_model: unsupported provider_id {provider_id!r} — "
        "refusing to silently resolve the anthropic model for an out-of-closed-set "
        "value (HARD #7, prov-r2-001)"
    )


def _resolve_quarantine_base_url(provider_id: str, settings: Settings) -> str | None:
    """The quarantine child's base_url, when its provider needs one (#587).

    Only DeepSeek's OpenAI-compatible endpoint requires an explicit base_url — Anthropic's
    SDK has its own default. Reuses ``Settings.deepseek_base_url`` (the SAME setting the
    privileged path already reads) rather than introducing a second, quarantine-specific
    base-URL setting an operator would have to keep in sync with the first.
    """
    if provider_id == "deepseek":
        return settings.deepseek_base_url
    if provider_id == "anthropic":
        return None
    raise ValueError(
        f"_resolve_quarantine_base_url: unsupported provider_id {provider_id!r} — "
        "refusing to silently resolve None for an out-of-closed-set value "
        "(HARD #7, prov-r2-001)"
    )
```

**prov-r2-001 (Medium): both functions now use an explicit 3-way closed-set dispatch with a loud `else: raise`, matching Task 1's own `build_child_client`/`BrokeredProviderSource.__init__` discipline (sec-002) and the plan's Global Constraints.** The bare `if provider_id == "deepseek": ... else: <treat as anthropic>` shape these two functions originally used silently resolved ANY unrecognized string to the Anthropic path — unreachable via the one production call site (`Settings.quarantine_provider` is `Literal`-validated), but directly reachable from tests (Task 3 Step 7's own new test calls `_resolve_quarantine_model("deepseek", settings)` with a hardcoded string, not a validated `Settings` read) and NOT covered by the Definition of Done's 100%-coverage gate (`daemon_runtime.py` is not in that gate's file list, so a wrong silent default here would ship undetected). Add a test for the new `else: raise` arm on each function, e.g. `test_resolve_quarantine_model_refuses_unknown_provider_id` / `test_resolve_quarantine_base_url_refuses_unknown_provider_id`, alongside the existing tests in this step.

(Verify whether `daemon_runtime.py` already imports `Settings` as a type — check the `if TYPE_CHECKING:` block near the top of the file; if not, add `from alfred.config.settings import Settings` under it, matching this file's existing lazy-type-import convention for size-sensitive modules.)

Update `_build_comms_inbound_extractor`'s signature (`:433-441`) to accept the resolved provider id, model, AND base_url:

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
    quarantine_model: str,
    quarantine_base_url: str | None,
) -> tuple[QuarantinedExtractor, QuarantineStdioTransport]:
```

Inside the function body, replace the existing line (`:497`) `model, max_tokens = _resolve_quarantine_model_config()` with:

```python
    # #587 prov-001 fix: the MODEL is now provider-aware (the caller already
    # resolved quarantine_provider/quarantine_model above the call — mirrors how
    # quarantine_base_url is resolved by the caller, not re-derived here).
    # `_resolve_quarantine_model_config()` still owns max_tokens validation
    # (the routing.yaml-mirrored budget, `<=0` refuses boot) — only its MODEL
    # return value is now superseded.
    model = quarantine_model
    _, max_tokens = _resolve_quarantine_model_config()
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
            quarantine_model=_resolve_quarantine_model(settings.quarantine_provider, settings),
            quarantine_base_url=_resolve_quarantine_base_url(settings.quarantine_provider, settings),
        )
```

(`_resolve_quarantine_model` and `_resolve_quarantine_base_url` both need importing into `_comms_boot.py` from `daemon_runtime` — check the existing import block for `_build_comms_inbound_extractor` itself and add both new functions alongside it.)

- [ ] **Step 7: Update the 7 pre-existing `_build_comms_inbound_extractor` calls in `tests/unit/comms_mcp/test_daemon_runtime.py`**

**core-r2-001 (High): the new `quarantine_provider`/`quarantine_model`/`quarantine_base_url` params added above have NO defaults — they are genuinely required (deliberately: a caller that forgets to pass them should not silently get the wrong model again, which is exactly prov-001's original bug). This breaks 7 pre-existing direct calls to `_build_comms_inbound_extractor(...)` in this file (confirmed live at lines 440, 515, 569, 624, 713, 762, 807), each of which currently passes only the 6 original kwargs and will `TypeError: missing 3 required keyword-only arguments` once Step 5 lands.** Before writing Step 8's new test, update all 7 existing calls to add the byte-for-byte-equivalent values these tests exercised before this change:

```python
        quarantine_provider="anthropic",
        quarantine_model=_QUARANTINE_MODEL,
        quarantine_base_url=None,
```

(`_QUARANTINE_MODEL` needs importing from `daemon_runtime` into this test file if not already available.) This is a mechanical, repeated addition to all 7 call sites — not a functional change to what each test exercises.

**Pre-flight-scan finding: an EIGHTH direct call site exists outside this file.** `tests/unit/egress/test_broker_audit_wiring.py`'s `test_auditor_is_threaded_into_transport` calls `_build_comms_inbound_extractor(...)` directly at `:230-237`:

```python
        await _build_comms_inbound_extractor(
            audit_writer=audit_writer,
            outbound_dlp=outbound_dlp,
            secret_broker=broker,
            staging=QuarantineStagingMap(),
            environment="production",
            egress_config=_EgressCfg(),
        )
```

Add the same three kwargs here too:

```python
        await _build_comms_inbound_extractor(
            audit_writer=audit_writer,
            outbound_dlp=outbound_dlp,
            secret_broker=broker,
            staging=QuarantineStagingMap(),
            environment="production",
            egress_config=_EgressCfg(),
            quarantine_provider="anthropic",
            quarantine_model=_QUARANTINE_MODEL,
            quarantine_base_url=None,
        )
```

This file imports `_build_comms_inbound_extractor` INLINE inside the test function (`:189`, `from alfred.comms_mcp.daemon_runtime import _build_comms_inbound_extractor`) rather than at module scope — add `_QUARANTINE_MODEL` to that same inline import (`from alfred.comms_mcp.daemon_runtime import _build_comms_inbound_extractor, _QUARANTINE_MODEL`), matching this file's own established inline-import convention for this function rather than switching it to a top-of-file import.

- [ ] **Step 8: Add the real-path regression test for prov-001**

**This test is release-blocking on its own — without it, the class of gap prov-001 found can hide behind a bypassed test harness again in the future.** `_build_comms_inbound_extractor` already has direct unit-test coverage in this file — read `test_build_extractor_drives_real_transport_over_spawned_child` (one of the 7 call sites from Step 7) in full first; it establishes this file's REAL construction idiom: a `MagicMock()` broker with `.redact`/`.has`/`.get` configured, wrapped as `outbound_dlp = OutboundDlp(broker=broker, audit=audit_sink)`; `audit_writer = MagicMock()` with `.append_schema = AsyncMock()`; the lightweight `_EgressCfg()` stub (not a real `Settings()`) for `egress_config`; and an `_EchoingChildDouble(provider_key=...)` returned from the faked spawn. Reuse that exact idiom — do not invent new fixture names. Add a test that drives `_build_comms_inbound_extractor` itself (not a lower-level helper) with `quarantine_provider="deepseek"` and asserts the mocked `spawn_quarantine_child_io` call received `model=settings.deepseek_model` — NOT the hardcoded `_QUARANTINE_MODEL`:

```python
async def test_build_comms_inbound_extractor_resolves_deepseek_model_for_deepseek_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """prov-001 regression: a deepseek-configured extractor spawns with DeepSeek's
    OWN model, never the hardcoded Anthropic quarantine model. Drives
    _build_comms_inbound_extractor itself (the real production entry point), not
    _spawn_real_child or a lower-level helper — this is the exact class of gap that
    let the original bug hide behind a bypassed test harness."""
    captured: dict[str, object] = {}

    async def _fake_spawn(**kwargs: object) -> _EchoingChildDouble:
        captured.update(kwargs)
        return _EchoingChildDouble(provider_key=kwargs["provider_key"])

    monkeypatch.setattr(
        "alfred.security.quarantine_child_io.spawn_quarantine_child_io", _fake_spawn
    )
    # A real Settings() (not _EgressCfg()) is needed here specifically to resolve
    # deepseek_model — mirrors the plan's own daemon_runtime._resolve_quarantine_model.
    settings = Settings(deepseek_api_key=SecretStr("sk-real"))  # deepseek_model defaults "deepseek-chat"
    broker = MagicMock()  # match test_build_extractor_drives_real_transport_over_spawned_child's exact broker setup
    outbound_dlp = OutboundDlp(broker=broker, audit=audit_sink)  # match that test's audit_sink fixture
    audit_writer = MagicMock()
    audit_writer.append_schema = AsyncMock()

    await _build_comms_inbound_extractor(
        audit_writer=audit_writer,
        outbound_dlp=outbound_dlp,
        secret_broker=secret_broker,  # match that test's secret_broker fixture
        staging=QuarantineStagingMap(),
        environment="test",
        egress_config=_EgressCfg(),
        quarantine_provider="deepseek",
        quarantine_model=_resolve_quarantine_model("deepseek", settings),
        quarantine_base_url=_resolve_quarantine_base_url("deepseek", settings),
    )

    assert captured["model"] == settings.deepseek_model
    assert captured["model"] != _QUARANTINE_MODEL
```

**Add the missing imports (rev-r2-002/test-r2-005, Medium — none of the following five symbols is imported anywhere in this file today, and this new test bare-references all of them):** `from alfred.config.settings import Settings`, `from pydantic import SecretStr`, and `from alfred.comms_mcp.daemon_runtime import _QUARANTINE_MODEL, _resolve_quarantine_base_url, _resolve_quarantine_model` (top-of-file, matching this file's existing import block at lines 25-53). `MagicMock`/`AsyncMock` are almost certainly already imported for the sibling test this one mirrors — verify and reuse rather than re-importing.

- [ ] **Step 9: Run to verify everything passes**

Run: `uv run pytest tests/unit/security/test_quarantine_child_io_control_fd.py tests/unit/security/test_max_tokens_guard.py tests/unit/comms_mcp/test_daemon_runtime.py tests/unit/egress/test_broker_audit_wiring.py -v`
Expected: PASS — every pre-existing test in `test_quarantine_child_io_control_fd.py`/`test_max_tokens_guard.py` (unaffected, since `_child_env`/`spawn_quarantine_child_io`'s new `provider`/`base_url` params DO default to `None`), the 7 updated calls in `test_daemon_runtime.py` plus the 1 updated call in `test_broker_audit_wiring.py` (Step 7 — these required explicit updates, they are not "unaffected"), plus every new test from Step 1 and Step 8.

Run: `uv run pytest tests/unit/cli/daemon/ -v -k comms_boot`
Expected: PASS — the one production call site's existing tests still green with the three new kwargs added.

- [ ] **Step 10: Type-check and coverage**

Run: `uv run mypy --strict src/alfred/comms_mcp/daemon_runtime.py src/alfred/security/quarantine_child_io.py src/alfred/security/quarantine_child/__main__.py src/alfred/cli/daemon/_comms_boot.py && uv run pyright <same files>`
Expected: no errors.

Run the combined coverage gate for every touched trust-boundary file (check the Makefile for the exact target name first, matching this repo's established `make coverage-gates` convention — do not invent an ad hoc invocation).
Expected: 100% line+branch maintained on every touched file under `src/alfred/security/`.

- [ ] **Step 11: Commit**

```bash
git add src/alfred/comms_mcp/daemon_runtime.py src/alfred/security/quarantine_child_io.py src/alfred/security/quarantine_child/__main__.py src/alfred/cli/daemon/_comms_boot.py <every modified test file including tests/unit/comms_mcp/test_daemon_runtime.py and tests/unit/egress/test_broker_audit_wiring.py>
git commit -m "feat(security): thread ALFRED_QUARANTINE_PROVIDER end-to-end (model + base_url + provider id) from Settings to the spawned child (#587)"
```

---

### Task 4: Wire `assert_provider_separation()`'s real, opt-in call site

**This task's original draft had a Critical, 3-way-corroborated gap (arch-002/sec-001/test-001): `assert_provider_separation()` raises a bare `AlfredError`, which is NOT one of the eight narrow, typed exceptions `_commands.py`'s `except`-cascade around `_build_comms_boot_graph(...)` catches (verified live: `_commands.py:1041-1190`, each arm catching one specific `AlfredError` subclass and routing it through the audited `_refuse_boot()` helper — a source comment at `:182`-equivalent explicitly documents "no broad `AlfredError` catch precedes" as deliberate). A bare `AlfredError` from this new call site would propagate UNCAUGHT out of `_start_async` — an unaudited crash (exit 1, no `daemon.boot.failed` row), reproducing the exact "#368 anti-pattern" this same file's other refusal arms were built to eliminate. The fix below gives this new decision its own typed exception + typed failure carrier, exactly mirroring the other eight arms' shape.**

**Files:**

- Modify: `src/alfred/cli/daemon/_comms_boot.py` (new local exception + the call site, placed at the TOP of `_build_comms_boot_graph`, before any I/O — see Step 3; the function's signature also gains a new `boot_id: str` param — see Step 3b / sec-r2-001)
- Modify: `src/alfred/cli/daemon/_failures.py` (new `QuarantineProviderSeparationViolatedFailure`, registered in the `DaemonBootFailure` union)
- Modify: `src/alfred/cli/daemon/_commands.py` (new `except` arm mapping the new exception to the new failure + `_refuse_boot()`, mirroring the eight existing arms at `:1041-1190`; also updates the one `_build_comms_boot_graph(...)` call site to pass the now-required `boot_id=boot_id`)
- Modify: `src/alfred/audit/audit_row_schemas.py` (new `DAEMON_BOOT_QUARANTINE_PROVIDER_SEPARATION_WARNED_FIELDS` constant, registered in `AUDIT_FIELDSET_ROSTER` — sec-r2-002)
- Modify: 6 integration test files that call `_build_comms_boot_graph(...)` directly and must thread the new required `boot_id` kwarg (pre-flight-scan finding, verified live — `_build_comms_boot_graph` has exactly ONE production call site, `_commands.py`, already covered above, but these 6 test files bypass it and call the function itself): `tests/integration/cli/daemon/test_daemon_comms_inbound_turn.py`, `tests/integration/cli/daemon/test_chat_gateway_socket_turn.py`, `tests/integration/cli/daemon/test_forwarded_inbound_gateway_to_core_turn.py`, `tests/integration/cli/daemon/test_comms_boot_graph_real_turn.py`, `tests/integration/cli/daemon/test_gateway_real_probe_spawn_forwarded_inbound.py`, `tests/integration/comms_mcp/test_real_turn_inbound_boundary.py` — see Step 3b.
- Test: `tests/unit/cli/daemon/test_daemon_boot_egress_refuse.py` (confirmed live location of the established hermetic pattern for "this fault used to be an uncaught #368-anti-pattern crash, now it's an audited refusal" tests — rev-003/test-002: the plan originally named a nonexistent `_settings_with()` helper and a nonexistent `tests/unit/` filename; the real file uses `CliRunner().invoke(daemon_app, ["start"])` + `monkeypatch.setenv(...)` + the `boot_success_env`/`quarantine_registry`/`patch_quarantine_child_spawn` fixtures + `_boot_failed_reasons(audit)`)

**Interfaces:**

- Consumes: `alfred.bootstrap.quarantine.assert_provider_separation` (existing, unmodified — do not touch its logic or its file, per design spec §9), `Settings.require_quarantine_provider_separation` (Task 2), `Settings.primary_provider` (existing, default `"deepseek"`), `Settings.quarantine_provider` (Task 2, default `"anthropic"` — so the two providers differ by default, and every EXISTING test fixture is unaffected by this task).
- Produces: `_comms_boot.QuarantineProviderSeparationCollisionError(AlfredError)` (new, local to `_comms_boot.py` — mirrors `_ForwardedInboundRegistryMisconfiguredError`'s existing local-exception convention in the same file); `_failures.QuarantineProviderSeparationViolatedFailure` (new, `failure_reason: Literal["quarantine_provider_separation_violated"]`).

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/cli/daemon/test_daemon_boot_egress_refuse.py`, matching that file's own established pattern (its docstring already frames exactly this bug class: "faults that were previously UNCAUGHT ... must now refuse boot audited"). Read `test_boot_refuses_when_egress_proxy_unset` (the file's first test) and `_boot_failed_reasons` (its helper, `:68-70`) first and copy their shape exactly:

```python
def test_boot_refuses_when_separation_required_and_providers_collide(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """require_quarantine_provider_separation=True + same provider -> refuse boot,
    AUDITED (arch-002/sec-001/test-001 — this is the fix, not just 'raises AlfredError'):
    proves _commands.py's except-cascade catches the new exception type and routes
    it through _refuse_boot, not that SOME AlfredError propagates unhandled."""
    del quarantine_registry  # installed via fixture side effect
    del patch_quarantine_child_spawn  # in-proc fake child-IO; no real bwrap spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    # Settings.primary_provider defaults "deepseek"; force quarantine_provider to
    # collide with it (Settings.quarantine_provider otherwise defaults "anthropic").
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    monkeypatch.setenv("ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION", "true")

    result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code == 2
    reasons = _boot_failed_reasons(boot_success_env)
    assert "quarantine_provider_separation_violated" in reasons
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []


def test_boot_proceeds_when_separation_required_and_providers_differ(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """require=True + the (default) distinct providers -> boots fine, no refusal."""
    del quarantine_registry
    del patch_quarantine_child_spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    monkeypatch.setenv("ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION", "true")
    # primary_provider="deepseek" / quarantine_provider="anthropic" — the defaults —
    # already differ; no override needed.
    _patch_comms_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code == 0, result.output
    assert _boot_failed_reasons(boot_success_env) == set()


def test_boot_proceeds_with_warning_when_separation_not_required_and_providers_collide(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """Default (require=False) + same provider -> boots, but WARNS AND audits
    (CLAUDE.md hard rule #7 — no silent failures; not just a log line, also a
    durable audit row via _emit_or_quarantine, since the security-relevant fact
    would otherwise leave no queryable trace)."""
    del quarantine_registry
    del patch_quarantine_child_spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    # ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION left unset -> default False.
    _patch_comms_seams(monkeypatch)

    with structlog.testing.capture_logs() as logs:
        result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code == 0, result.output
    warned = [e for e in logs if e["event"] == "comms.comms_boot.quarantine_provider_separation_not_enforced"]
    assert len(warned) == 1, f"expected one loud not-enforced warning, got {logs!r}"
    warn_rows = boot_success_env.rows_for("DAEMON_BOOT_QUARANTINE_PROVIDER_SEPARATION_WARNED_FIELDS")
    assert len(warn_rows) == 1, warn_rows
    # sec-r2-001's oracle: the row must actually carry boot_id (not just exist),
    # or a regression back to the boot_id-less shape would ship green.
    assert warn_rows[0]["subject"]["boot_id"], warn_rows
```

(`_ENABLED_ADAPTER`, `CliRunner`, `daemon_app`, `HookRegistry`, `Any` are all already imported at the top of this file per its existing tests — match those imports rather than re-importing. Add two new imports: `import structlog.testing` (test-r2-003 — `caplog` does NOT observe this codebase's structlog events; two sibling files in this same package, `test_lifecycle_wire_send.py` and `test_max_tokens_guard.py`, both document this and use `structlog.testing.capture_logs()` instead) and `from .test_daemon_comms_spawn import _patch_comms_seams` (test-r2-002 — `_patch_comms_seams` patches `CommsStdioTransport`/`CommsPluginRunner` to fakes so a comms-enabled boot can actually reach `exit_code == 0` instead of constructing real transport objects; this is an established cross-test-module import in this file family — `test_daemon_promoter_wiring.py` already does the same `from .test_daemon_comms_spawn import (...)` pattern). The exact audit `schema_name`/`fields` constant name for the warn-path row is invented above as an example (`DAEMON_BOOT_QUARANTINE_PROVIDER_SEPARATION_WARNED_FIELDS`) — Step 3 below defines the real one; keep the test's constant in sync with whatever Step 3 actually names it.)

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_boot_egress_refuse.py -v -k separation`
Expected: FAIL — no such behavior exists yet (boot proceeds silently in all three cases today; the "collide" test currently gets `exit_code == 0`, not `2`).

- [ ] **Step 3: Add the local exception, the failure carrier, and the call site**

**3a. In `src/alfred/cli/daemon/_comms_boot.py`**, add a new local exception near the existing `_ForwardedInboundRegistryMisconfiguredError` (`:276`) — module-scoped and not exported, matching that sibling's PLACEMENT convention. It deliberately does NOT mirror that sibling's base class, though: `_ForwardedInboundRegistryMisconfiguredError` is a plain `Exception`, while the new exception below inherits `AlfredError` on purpose, so a broader CLI-level `AlfredError` handler would still catch it as a fallback if this specific `except` arm were ever removed (arch-r2-003/rev-r2-004 — 5 of the cascade's other 8 exception types are themselves `AlfredError` subclasses, so this is the better-aligned choice, not a copy of `_ForwardedInboundRegistryMisconfiguredError`'s base class):

```python
class QuarantineProviderSeparationCollisionError(AlfredError):
    """#586: require_quarantine_provider_separation=True and the privileged/quarantine
    provider ids collide. A distinct, catchable type so _commands.py's typed
    except-cascade can route this through the audited _refuse_boot path —
    assert_provider_separation() itself raises only the base AlfredError (unmodified,
    design spec §9), which would otherwise escape uncaught past every arm (arch-002 /
    sec-001 / test-001 — the #368 anti-pattern)."""
```

Add the imports: `from alfred.bootstrap.quarantine import assert_provider_separation` and `from alfred.errors import AlfredError` (check the existing import block for duplicates first).

**3b. First, widen `_build_comms_boot_graph`'s own signature to accept `boot_id` (sec-r2-001/rev-r2-003, High).** Its live signature (`src/alfred/cli/daemon/_comms_boot.py:619-628`) is `async def _build_comms_boot_graph(*, settings, audit, outbound_dlp, t3_nonce, policies_ref, real_gate, router_override=None) -> _CommsBootGraph:` — it has NO `boot_id` parameter today, unlike `_commands.py`, where `boot_id = str(uuid.uuid4())` is a local variable (set at `:672`) threaded into every `_refuse_boot(...)` call. Without this widening, the new audited-warning row below cannot carry a `boot_id`, breaking `alfred.audit.audit_row_schemas`'s documented forensic-join-key convention (every sibling `daemon.boot`/`daemon.lifecycle` row carries one) and silently defeating `_emit_or_quarantine`'s `trace_id=str(subject.get("boot_id", uuid.uuid4()))` correlation (`_boot_audit.py:179`) — the row would get a random, uncorrelated `trace_id` instead of joining the boot attempt it belongs to. Add `boot_id: str,` to the signature (after `settings` or wherever this file's keyword-only param ordering convention puts new required params):

```python
async def _build_comms_boot_graph(
    *,
    settings: Settings,
    boot_id: str,
    audit: AuditWriter,
    outbound_dlp: OutboundDlpProtocol,
    t3_nonce: CapabilityGateNonce,
    policies_ref: object,
    real_gate: CapabilityGate,
    router_override: ProviderRouter | None = None,
) -> _CommsBootGraph:
```

(Match the real live parameter type annotations exactly — the ones shown above are inferred from this file's own `TYPE_CHECKING` imports; verify each against the live signature before pasting.)

**Update the one call site in `_commands.py`** (inside the `try:` at `:1041`, where `comms_graph = await _build_comms_boot_graph(...)` is called) to add the new kwarg, using the `boot_id` local variable already in scope at that point:

```python
            comms_graph = await _build_comms_boot_graph(
                settings=settings,
                boot_id=boot_id,
                audit=audit,
                outbound_dlp=outbound_dlp,
                t3_nonce=t3_nonce,
                policies_ref=snapshot_ref,
                real_gate=real_gate,
            )
```

**Update the 6 integration test call sites (pre-flight-scan finding).** `_build_comms_boot_graph` has no OTHER production call site, but these 6 test files call it directly, bypassing `_commands.py` entirely — each needs `boot_id=` added or it `TypeError`s once the param above becomes required. In every case, the same `graph` this call returns is passed a few lines later into a sibling boot-carrier call (`_spawn_comms_adapter`/`_listen_socket_comms_adapter`) that ALREADY passes a `boot_id="<literal>"` for that same logical boot attempt — reuse that exact literal on the `_build_comms_boot_graph` call too, so both calls correlate to the same boot_id rather than minting two different ones for one boot:

- `tests/integration/cli/daemon/test_daemon_comms_inbound_turn.py:523` — add `boot_id="s4-11b-e2e-proof",` (matches the `_spawn_comms_adapter(..., boot_id="s4-11b-e2e-proof", ...)` call at `:546`, same `graph`).
- `tests/integration/cli/daemon/test_chat_gateway_socket_turn.py:485` — add `boot_id="s4-g5-gateway-chain-proof",` (matches `_listen_socket_comms_adapter(..., boot_id="s4-g5-gateway-chain-proof", ...)` at `:506`; leave the file's second, unrelated `boot_id="s4-g5-gateway-chain-proof-rebind"` at `:661` untouched — it's a later rebind call, not this `_build_comms_boot_graph` call).
- `tests/integration/cli/daemon/test_forwarded_inbound_gateway_to_core_turn.py:532` — add `boot_id="g6-7-6-a1-forward-proof",` (matches `:554`).
- `tests/integration/cli/daemon/test_gateway_real_probe_spawn_forwarded_inbound.py:633` — add `boot_id="g6-7-7-real-spawn-proof",` (matches `:658`).
- `tests/integration/cli/daemon/test_comms_boot_graph_real_turn.py:232` — no existing later `boot_id` literal to reuse in this file; add `boot_id="338-pr2-t3-real-turn-adapter-proof",` (a fresh literal, matching this file-family's short-hyphenated-slug convention and this file's own docstring, "#338 PR2 Task 3").
- `tests/integration/comms_mcp/test_real_turn_inbound_boundary.py:562` — no existing later `boot_id` literal to reuse in this file; add `boot_id="338-pr2-t5-inbound-boundary-proof",` (same convention, matching this file's own docstring, "#338 PR2 Task 5").

Each is a one-line kwarg addition to an already-present `_build_comms_boot_graph(...)` call — not a functional change to what any of these tests exercise.

**Add the call site at the very TOP of `_build_comms_boot_graph`** — immediately after the function's lazy-import block, BEFORE `secret_broker = build_broker(settings)` (core-003/core-004/sec-003: this is a pure `Settings`-field comparison with no I/O, so placing it here — before `secret_broker`/`content_store` even construct — sidesteps the `content_store` try/except leak-ordering question entirely, rather than requiring the check to land inside that block):

```python
    # #586: opt-in provider-separation enforcement, checked FIRST (no I/O yet, so a
    # refusal here can never leak a partially-constructed secret_broker/content_store —
    # core-003/sec-003). assert_provider_separation() itself is unmodified (design
    # spec §9) — only this call site, the re-raise, and the not-required+colliding
    # audited-warning path are new.
    if settings.require_quarantine_provider_separation:
        try:
            assert_provider_separation(
                privileged_provider_id=settings.primary_provider,
                quarantined_provider_id=settings.quarantine_provider,
            )
        except AlfredError as exc:
            raise QuarantineProviderSeparationCollisionError(str(exc)) from exc
    elif settings.primary_provider.strip().lower() == settings.quarantine_provider.strip().lower():
        log.warning(
            "comms.comms_boot.quarantine_provider_separation_not_enforced",
            privileged_provider=settings.primary_provider,
            quarantine_provider=settings.quarantine_provider,
        )
        await _emit_or_quarantine(
            audit,
            fields=DAEMON_BOOT_QUARANTINE_PROVIDER_SEPARATION_WARNED_FIELDS,
            schema_name="DAEMON_BOOT_QUARANTINE_PROVIDER_SEPARATION_WARNED_FIELDS",
            event="daemon.boot.quarantine_provider_separation_not_enforced",
            subject={
                "boot_id": boot_id,
                "privileged_provider": settings.primary_provider,
                "quarantine_provider": settings.quarantine_provider,
                "occurred_at": datetime.now(UTC).isoformat(),
            },
            result="warned",
        )
```

**Use the module's real logger variable, `log` (confirmed: `_comms_boot.py:101` — `log = structlog.get_logger(__name__)`), never `_log` (core-001/rev-010 — `_log` does not exist anywhere in this file and would `NameError`).** `audit: AuditWriter` and `_emit_or_quarantine` are already in scope/imported in this function (`_emit_or_quarantine` is imported at module scope from `_boot_audit`, per the existing import block at `:42-46`); `datetime`/`UTC` are already imported (`:26`, used elsewhere in this file for `_CommsAdapterWireSpec`-adjacent timestamps).

**In `src/alfred/audit/audit_row_schemas.py`**, add the new constant near `DAEMON_BOOT_FAILED_FIELDS`/`DAEMON_LIFECYCLE_FIELDS`, spelling out its exact field set (sec-r2-001 — do not leave this to "mirror the sibling shape" inference, since `append_schema` validates `fields` against `subject.keys()` symmetrically and any mismatch raises `ValueError` at test-run time):

```python
DAEMON_BOOT_QUARANTINE_PROVIDER_SEPARATION_WARNED_FIELDS: Final[frozenset[str]] = frozenset(
    {"boot_id", "privileged_provider", "quarantine_provider", "occurred_at"}
)
```

**Register the new constant in `AUDIT_FIELDSET_ROSTER` (sec-r2-002, Medium — in the SAME commit).** This module's own docstring states the roster is enforced by a bidirectional AST-walk guard (`tests/unit/audit/test_slice_4_audit_row_fields.py`) that sweeps every `*_FIELDS` constant declared after the Slice-4 section marker (`~line 1655`, well before this new constant's insertion point) and fails if any such constant is missing a matching roster entry. Add `"DAEMON_BOOT_QUARANTINE_PROVIDER_SEPARATION_WARNED_FIELDS",` to the `AUDIT_FIELDSET_ROSTER` tuple (`:1657` onward), alongside `"DAEMON_BOOT_FAILED_FIELDS"`/`"DAEMON_LIFECYCLE_FIELDS"`.

**3c. In `src/alfred/cli/daemon/_failures.py`**, add the new failure carrier near the other `Quarantine*Failure` classes:

```python
class QuarantineProviderSeparationViolatedFailure(_BootFailureBase):
    """#586: require_quarantine_provider_separation=True and the privileged/quarantine
    provider ids collide at boot. Distinct failure_reason lets forensics tell an
    operator-opted-in separation violation apart from every other boot refusal."""

    failure_reason: Literal["quarantine_provider_separation_violated"] = (
        "quarantine_provider_separation_violated"
    )
```

Add `| QuarantineProviderSeparationViolatedFailure` to the `DaemonBootFailure` discriminated union (`:445-469`) and a line to its provenance-chain docstring comment, matching every other member's pattern.

**3d. In `src/alfred/cli/daemon/_commands.py`**, add a new `except` arm mirroring the eight existing ones (`:1041-1190`), immediately after the `except QuarantineMaxTokensInvalidError:` arm:

```python
        except QuarantineProviderSeparationCollisionError as exc:
            # #586: require_quarantine_provider_separation=True and the privileged
            # + quarantine providers collide. REACHABLE via a real boot (an operator
            # opted into the stricter dual-LLM posture and misconfigured it). REFUSE
            # boot fail-closed (audited, exit 2) rather than let the bare AlfredError
            # assert_provider_separation() raises propagate uncaught (the #368
            # anti-pattern — arch-002/sec-001/test-001).
            await _refuse_boot(
                audit,
                QuarantineProviderSeparationViolatedFailure(),
                str(exc),
                boot_id=boot_id,
                environment_source=source,
            )
```

Add the import: `from alfred.cli.daemon._comms_boot import QuarantineProviderSeparationCollisionError` (alongside the existing import of `_ForwardedInboundRegistryMisconfiguredError` from the same module, `:75-78`) and `from alfred.cli.daemon._failures import QuarantineProviderSeparationViolatedFailure` (alongside the existing `_failures` import block, `:100-135`).

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_boot_egress_refuse.py -v`
Expected: PASS — the three new tests plus every pre-existing test in the file (unaffected, since the default `require_quarantine_provider_separation=False` + distinct default providers — `"deepseek"` vs `"anthropic"` — means the new code path is a no-op for every existing fixture that doesn't set the new env vars).

**Verify the 6 integration test call sites updated above are not left broken.** These files are `_DOCKER_ONLY`/testcontainer-gated and will not fully execute locally, but a missing required `boot_id` kwarg is a `TypeError` at CALL time, not something Docker-gating hides — confirm each file at least collects and type-checks clean:

Run: `uv run pytest tests/integration/cli/daemon/test_daemon_comms_inbound_turn.py tests/integration/cli/daemon/test_chat_gateway_socket_turn.py tests/integration/cli/daemon/test_forwarded_inbound_gateway_to_core_turn.py tests/integration/cli/daemon/test_comms_boot_graph_real_turn.py tests/integration/cli/daemon/test_gateway_real_probe_spawn_forwarded_inbound.py tests/integration/comms_mcp/test_real_turn_inbound_boundary.py --collect-only`
Expected: clean collection, no errors (proves the `boot_id=` additions are syntactically and structurally correct even where the tests themselves skip locally for lack of Docker/Postgres).

Run: `uv run mypy --strict tests/integration/cli/daemon/test_daemon_comms_inbound_turn.py tests/integration/cli/daemon/test_chat_gateway_socket_turn.py tests/integration/cli/daemon/test_forwarded_inbound_gateway_to_core_turn.py tests/integration/cli/daemon/test_comms_boot_graph_real_turn.py tests/integration/cli/daemon/test_gateway_real_probe_spawn_forwarded_inbound.py tests/integration/comms_mcp/test_real_turn_inbound_boundary.py`
Expected: no errors — confirms none of the 6 calls is still missing the now-required `boot_id` argument.

- [ ] **Step 5: Type-check and coverage**

Run: `uv run mypy --strict src/alfred/cli/daemon/_comms_boot.py src/alfred/cli/daemon/_failures.py src/alfred/cli/daemon/_commands.py src/alfred/audit/audit_row_schemas.py && uv run pyright <same files>`
Expected: no errors.

Run: `uv run pytest tests/unit/audit/test_slice_4_audit_row_fields.py -v`
Expected: PASS — the bidirectional AST-walk guard confirms the new `DAEMON_BOOT_QUARANTINE_PROVIDER_SEPARATION_WARNED_FIELDS` constant is registered in `AUDIT_FIELDSET_ROSTER` (sec-r2-002).

Run the combined coverage gate again (Task 3 Step 10's command).
Expected: 100% line+branch maintained — all three new branches (refuse, boot-distinct, boot-with-warning) covered on `_comms_boot.py`, AND the new `except QuarantineProviderSeparationCollisionError` arm covered on `_commands.py`, not just one file.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/cli/daemon/_comms_boot.py src/alfred/cli/daemon/_failures.py src/alfred/cli/daemon/_commands.py src/alfred/audit/audit_row_schemas.py tests/unit/cli/daemon/test_daemon_boot_egress_refuse.py tests/integration/cli/daemon/test_daemon_comms_inbound_turn.py tests/integration/cli/daemon/test_chat_gateway_socket_turn.py tests/integration/cli/daemon/test_forwarded_inbound_gateway_to_core_turn.py tests/integration/cli/daemon/test_comms_boot_graph_real_turn.py tests/integration/cli/daemon/test_gateway_real_probe_spawn_forwarded_inbound.py tests/integration/comms_mcp/test_real_turn_inbound_boundary.py
git commit -m "feat(security): wire assert_provider_separation() as an audited, opt-in boot-time check, default off (#586)"
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
- Since `deepseek-chat` does NOT have `NATIVE_CONSTRAINED_GENERATION` (confirmed: `provider_dispatch.py`'s own docstring states any provider without it, including deepseek-chat/deepseek-reasoner, uses `prompt_embedded_fallback` — the JSON_OBJECT_MODE branch this test's expected response shape might assume was REMOVED in fork (b)), the canned response must be shaped for the **prompt-embedded fallback** path, not a JSON-object/tool-call shape.

**The response shape is spelled out below directly (test-r2-gap-001, Medium) — do not delegate shape-discovery to "read whatever unit test exercises the fallback branch."** That escape hatch does not resolve to anything usable: both candidate unit tests (`tests/unit/quarantine/test_quarantined_extractor_dispatch.py`'s `_text_response(content: str)` helper and `tests/unit/providers/test_deepseek.py`'s `MagicMock(message=MagicMock(content=...))`) fake at an abstraction level ABOVE the raw HTTP wire — neither shows the real openai-SDK `chat.completion` JSON envelope. The path that actually matters here is `DeepSeekProvider.complete()` (`src/alfred/providers/deepseek.py:305-366`), which `await self._client.chat.completions.create(**kwargs)`s the REAL openai SDK and reads `response.choices[0].message.content` / `response.choices[0].finish_reason` / `response.usage.prompt_tokens` — i.e. it needs a full OpenAI chat-completion JSON body over the wire, exactly analogous to how the existing `_CannedAnthropicProxy`'s `_valid_extract_body` is a full raw Anthropic Messages-API JSON body, not a `CompletionResponse`-shaped Python object. Use this literal canned body (the extraction payload embedded as a JSON string inside `message.content`, matching `_CANNED_TEXT`/`_CANNED_INTENT` from the existing Anthropic test's assertions):

```python
_DEEPSEEK_CANNED_CHAT_COMPLETION = {
    "id": "chatcmpl-canned-extract",
    "object": "chat.completion",
    "created": 0,
    "model": "deepseek-chat",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": json.dumps({"text": _CANNED_TEXT, "intent": _CANNED_INTENT}),
            },
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 21, "completion_tokens": 9, "total_tokens": 30},
}
```

`_CannedDeepSeekProxy` (below) serves this dict as its JSON response body — mirroring exactly how `_CannedAnthropicProxy` serves `_valid_extract_body`.

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
        # rev-004 fix: base_url is REQUIRED here — Task 1's build_child_client
        # raises ValueError on provider_id="deepseek" + base_url=None (its own new
        # HARD #7 refusal). Omitting it would make this "proves DeepSeek genuinely
        # works" test hit that refusal instead of extracting.
        child_io = await _spawn_real_child(
            proxy, provider="deepseek", model="deepseek-chat",
            base_url="https://api.deepseek.com/v1",
        )
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

**`_spawn_real_child` (`:635-643`) needs THREE new parameters, not just one (rev-004, Critical — the original draft only added `provider`, which leaves the test above unable to even call `model=`/`base_url=` as written):**

```python
async def _spawn_real_child(
    proxy: _CannedAnthropicProxy | _CannedDeepSeekProxy,
    *,
    provider: str = "anthropic",
    model: str = _MODEL,
    base_url: str | None = None,
) -> _SubprocessChildIO:
```

(`_MODEL = "claude-haiku-4-5"` — the file's existing module constant, `:110` — stays the default so every pre-existing call site that doesn't pass `model=` is unaffected.) Thread all three into the existing `spawn_quarantine_child_io(...)` call inside `_spawn_real_child`, replacing its current hardcoded `model=_MODEL` with `model=model`, and adding `provider=provider, base_url=base_url,` alongside the `max_tokens=` it already passes (Task 3 already added `provider=`/`base_url=` params to `spawn_quarantine_child_io` itself; this step only threads values through this ONE test helper). Read `_spawn_real_child`'s current body first — do not assume its exact structure hasn't shifted.

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

### Task 6: An ADR for the actual decision, then documentation — correct every stale claim this work found

**Files:**

- Create: `docs/adr/0064-quarantine-provider-separation-is-opt-in.md` (confirmed: `ADR-0063` is the latest as of this plan's writing — re-verify via `ls docs/adr/` at implementation time in case another ADR has landed since)
- Modify: `docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md` (a one-line "superseded by ADR-0064" pointer at the top of §5.4 only — arch-r2-001)
- Modify: `config/routing.yaml`
- Modify: `.env.example`
- Modify: `docs/runbooks/slice-3-quarantined-llm.md`
- Modify: `README.md`
- Modify: `tests/unit/security/test_routing_yaml_quarantine_block.py` (docstring only — test-007)

- [ ] **Step 0: Write an ADR recording the opt-in decision, and explicitly acknowledge/supersede the real prior decision it replaces (arch-001/rev-001, disputed-confirmed Critical/High; arch-r2-001, High; arch-r2-002, Low — fix all three together, same file)**

Both `alfred-architect` and `alfred-reviewer` independently confirmed, on cross-check, that **no PRD section anywhere states a quarantine/privileged provider-separation "MUST differ" invariant.** `PRD.md §6.4` ("Self-Improvement with Reviewer Gate") is about the unrelated self-improvement reviewer agent running cross-provider from the primary orchestrator — a different pairing entirely. `PRD §7.1` ("Security & Prompt Injection Defense") describes the dual-LLM role split but contains no provider-diversity mandate either.

**arch-r2-001 (High): it is wrong, however, to treat the inherited "spec §5.4 / PRD §6.4" citation as a single blanket mis-citation and debunk only the PRD half.** `docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md` §5.4 ("Different provider from privileged (defence-in-depth)") is a REAL, deliberate PRIOR design decision, not a citation error (verified live, `:386-401`): it specifies (a) AlfredOS refuses to bootstrap by DEFAULT on a same-provider collision, (b) relaxing that requires an explicit `state.git` reviewer-gate proposal (`alfred config quarantined-provider <same-provider>`), not a plain `.env` flag, and (c) an approved relaxation must emit a RECURRING `supervisor.config_insecure`-shaped audit row at EVERY restart to keep signalling the weakened posture. This plan flips all three: default becomes permit-with-warning, the escape hatch becomes a self-service `Settings.require_quarantine_provider_separation=True` boolean with no reviewer gate at all, and a one-time-per-boot warning replaces the recurring signal. `bootstrap/quarantine.py`'s docstring, `config/routing.yaml`'s comment, and `docs/runbooks/slice-3-quarantined-llm.md` all currently cite spec §5.4 as live/binding; left untouched, that document stands uncorrected and now silently contradicts shipped behavior, with no pointer from it to the new ADR. (The underlying business call — opt-in, default off, so a self-hoster is never forced into two paid provider accounts — IS operator-ratified, per this same design spec's own §0/§3; this is not a request to reverse the decision, only to record it honestly as something being SUPERSEDED, not as filling a void that was always empty.)

Write the ADR matching this repo's established house style (arch-r2-002 — sampled `docs/adr/0001`, `0057`, `0059`, `0063`: every existing ADR uses a title line + a metadata bullet block, `## Context` next; NONE uses a standalone `## Status` H2):

```markdown
# ADR-0064: Quarantine/privileged provider separation is opt-in, default off

- **Status**: Accepted
- **Date**: 2026-08-12
- **Issue**: #586 / #587
- **Supersedes**: docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md §5.4

## Context

The dual-LLM split (PRD §5, §7.1) routes untrusted T3 content through a
quarantined LLM, separate from the privileged orchestrator LLM. Whether the
two must use DIFFERENT providers (not just different roles/processing paths)
is a distinct question the PRD does not answer — no PRD section states a
"providers must differ" requirement, despite prior code comments
(`alfred.bootstrap.quarantine`, `config/routing.yaml`) citing "spec §5.4 /
PRD §6.4" for exactly that claim. PRD §6.4 covers the unrelated
self-improvement reviewer-gate's own cross-provider requirement; no other
PRD section fills the gap.

The Slice-3 design spec's own §5.4 IS a real, prior, deliberate decision on
this exact question, however — not a citation error to wave away. It
specifies: (a) AlfredOS refuses to bootstrap BY DEFAULT when the quarantine
and privileged providers collide; (b) relaxing that requires an explicit
`state.git` reviewer-gate proposal (`alfred config quarantined-provider
<provider>`), never a plain `.env` flag; (c) an approved relaxation emits a
RECURRING `supervisor.config_insecure` audit row at every restart, to keep
signalling the weakened posture rather than let it fade into an
unremarkable steady state. `assert_provider_separation()` was built and
tested against this spec, but never wired to a real call site until now.

Since #586 landed, running a home/self-hosted deployment with two paid
provider accounts (one per role) is understood to be an unreasonable
default cost — confirmed by direct operator instruction: "nobody at home
should have to" run two paid provider accounts. This ADR records the
resulting decision and what it supersedes.

## Decision

Provider separation between the quarantine and privileged LLMs is an
OPT-IN, defence-in-depth posture (`Settings.require_quarantine_provider_separation`,
default `False`) — REPLACING spec §5.4's default-refuse / reviewer-gated /
recurring-audit-signal mechanism with a simpler one:

- Default (`False`): same-provider is PERMITTED. A collision boots fine but
  is logged AND audited once per boot (not a recurring per-restart signal —
  see Consequences).
- Opt-in (`True`): boot REFUSES on a same-provider collision via
  `assert_provider_separation()`, audited through the normal
  `daemon.boot.failed` refusal path — but the escape hatch is a plain
  `.env` boolean, not a `state.git` reviewer-gated proposal.

A home/self-hosted operator is never forced into running two paid provider
accounts. An enterprise deployment that wants the stricter posture sets the
flag to `True`.

## Consequences

- **Weaker than spec §5.4 on three specific axes**, by deliberate choice:
  no default-refuse, no reviewer gate on the escape hatch, and a one-time
  per-boot audit signal instead of a recurring per-restart one. This ADR
  is the record of that trade-off — not an oversight.
- No PRD text needs to change — this ADR is the accurate record instead of
  a fabricated PRD citation.
- `config/routing.yaml`'s comment and `docs/runbooks/slice-3-quarantined-llm.md`
  are corrected (Task 6 Steps 1/3 of the #586/#587 plan) to cite this ADR
  instead of "spec §5.4 / PRD §6.4".
- The Slice-3 design spec's §5.4 itself gets a one-line "superseded by
  ADR-0064" pointer added at its top (this task, same commit) so the two
  documents do not silently contradict each other.
- `assert_provider_separation()`'s own docstring (`bootstrap/quarantine.py`)
  still carries the old citation — out of scope for this PR (design spec
  §9: reused as-is, unmodified) — filed as a follow-up doc-fix.

## Alternatives considered

- **Keep spec §5.4's mechanism as-is** (default-refuse, `state.git`
  reviewer-gated relaxation, recurring audit signal). Rejected: the
  `state.git` proposal flow for `quarantined-provider` doesn't exist yet
  (component-not-wired, matching this project's broader "even where a
  mechanism is documented, it may not be built" pattern), and a
  self-hoster would be hard-blocked from booting at all until either that
  flow ships or they configure two providers — unacceptable per the direct
  operator instruction above.
- **Hard-require separation always**, no opt-out. Rejected for the same
  reason.
- **Edit PRD.md to add the invariant.** PRD edits are human-gated in this
  repo; an ADR is the correct vehicle for a decision made during
  implementation, not a PRD edit made by an agent.
```

**Add the superseding pointer to the spec document itself** — in `docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md`, immediately below the `### 5.4 Different provider from privileged (defence-in-depth)` heading, add one line: `> **Superseded by [ADR-0064](../../adr/0064-quarantine-provider-separation-is-opt-in.md)** (#586/#587): this section's default-refuse / reviewer-gated posture was replaced with an opt-in, default-off posture. Kept here for historical record.` Do not edit anything else in this spec document — the rest of §5.4's text stays as the accurate historical record of what was decided at the time.

- [ ] **Step 1: Fix `config/routing.yaml`'s `[quarantine]` comment**

Replace the comment above `provider: "anthropic"` (`:20-26`) — remove the false "the bootstrap-time check ... refuses to start when the ... ids collide" claim (true only when `ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=true` now, not unconditionally) and note that `provider` here is NOT the runtime source of truth (that's `Settings.quarantine_provider` / `ALFRED_QUARANTINE_PROVIDER`, per Task 2/3). **Do not cite "spec §5.4 / PRD §6.4" (arch-001/rev-001 — wrong section); cite the new ADR from Step 0 instead:**

```yaml
  # Provider for the quarantined LLM. NOTE (#587): this routing.yaml value is NOT
  # read at runtime — no loader exists yet ("slice 4+"). The actual runtime source
  # of truth is the ALFRED_QUARANTINE_PROVIDER .env setting (Settings.quarantine_provider,
  # default "anthropic"). This field stays here as the alfred-config-proposal target
  # (the state.git reviewer-gate flow, docs/runbooks/slice-3-quarantined-llm.md) and
  # as documentation of the shipped default, but changing it alone does nothing.
  #
  # Provider-separation enforcement (ADR-0064 — see Step 0 of this task; no PRD
  # section states this invariant, do not re-cite "spec §5.4 / PRD §6.4") is
  # OPT-IN (#586): set ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=true to
  # refuse boot on a same-provider collision. Default: permitted, with a warning.
  provider: "anthropic"
```

- [ ] **Step 2: Update `.env.example`**

Add near the existing `ALFRED_QUARANTINE_PROVIDER_API_KEY` entry:

```
# #587: which provider the quarantine child uses. "anthropic" | "deepseek".
# Default: anthropic (matches routing.yaml's shipped default).
# ALFRED_QUARANTINE_PROVIDER=anthropic

# #587: the quarantine child's DeepSeek endpoint, when ALFRED_QUARANTINE_PROVIDER=deepseek.
# Reuses ALFRED_DEEPSEEK_BASE_URL (the SAME setting the privileged DeepSeek path
# uses) — there is no separate quarantine-specific base-URL setting (prov-004).
# ALFRED_DEEPSEEK_BASE_URL=https://api.deepseek.com/v1

# #586: opt-in enforcement that the quarantine and privileged providers differ.
# Default: false — same-provider is permitted (a warning is logged AND audited,
# not just printed). Set true for the stricter defence-in-depth posture (see
# ADR-0064 — Task 6 Step 0; do NOT cite "spec §5.4 / PRD §6.4", no PRD section
# states this invariant).
# ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=false
```

Also correct the existing note at `.env.example:225-227` ("There are NO ALFRED_QUARANTINED_PROVIDER / ALFRED_QUARANTINED_MODEL env vars... nothing has ever read them") — that's now false for `ALFRED_QUARANTINE_PROVIDER` as of this PR; update it to describe the real, current mechanism instead of the old absence.

**Also fix the adjacent stale "openai" reference in this same file (rev-007, Medium — the plan's original draft edited text immediately beside this line without touching it):** around `.env.example:219`, "The three supported values for `.provider` are `\"anthropic\"`, `\"deepseek\"`, `\"openai\"`." is false — `_ALLOWED_QUARANTINED_PROVIDERS` (`src/alfred/cli/_validators.py:376`) is `frozenset({"anthropic", "deepseek"})`, only two values, and this plan's own Global Constraints section states OpenAI support is explicitly out of scope. Correct it to name only the two real values.

- [ ] **Step 3: Fix the four stale claims in `docs/runbooks/slice-3-quarantined-llm.md`**

In the "Provider configuration" section (`:36-63`):
1. Fix the capability table's `deepseek` row — it currently claims `JSON_OBJECT_MODE` → `json_object_unconstrained`; per `provider_dispatch.py`'s own docstring, DeepSeek (chat or reasoner) actually uses `prompt_embedded_fallback` (no native constrained generation). Correct the row.
2. Remove or correct the framing that `routing.yaml [quarantine].provider` "drives" runtime capability advertisement — it does not (Task 6 Step 1's finding); point instead at `ALFRED_QUARANTINE_PROVIDER`.
3. Remove the "bootstrap-time check ... refuses to start" unconditional claim, replacing it with the opt-in framing (mirroring Step 1's fix) and citing ADR-0064, not "spec §5.4 / PRD §6.4" (arch-001/rev-001).
4. **Fix the same "openai" stale reference in this file's YAML snippet and capability table (rev-007, Medium)** — the snippet's `provider: "anthropic" # anthropic | deepseek | openai` comment and the capability table's `openai or unknown model -> prompt_embedded_fallback` row both name a provider this codebase does not support. Strip "openai" from both.

- [ ] **Step 4: Rewrite (not just annotate) README's Quickstart provider-key callout**

**The plan's original draft said "add a note" — that leaves the existing sentence self-contradicting the new note (rev-008, Medium).** In the "Two provider keys are required" block (`README.md:44-67`), the existing text reads: *"The quarantined provider **must differ** from the privileged one (`config/routing.yaml`), so with the default DeepSeek-privileged setup this is an **Anthropic** key."* Once `require_quarantine_provider_separation` defaults to `False`, "must differ" is materially false. REWRITE this sentence (do not merely append a note beside it):

```
The quarantined provider **should differ** from the privileged one by
default (`config/routing.yaml` / `ALFRED_QUARANTINE_PROVIDER`) — so with
the default DeepSeek-privileged setup this is an **Anthropic** key. You can
set `ALFRED_QUARANTINE_PROVIDER=deepseek` to use DeepSeek for both roles
instead; set `ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=true` to make
the stricter separation posture mandatory (refuses to boot on a collision)
rather than advisory (see ADR-0064).
```

- [ ] **Step 5: Fix the stale docstring in `tests/unit/security/test_routing_yaml_quarantine_block.py` (test-007, Low)**

This test module's own docstring (`:1-18`) carries the same stale unconditional-enforcement claim this task corrects everywhere else: *"The bootstrap-time check in `alfred.bootstrap.quarantine` enforces this at startup once the loader is wired; until then the YAML's documented default is the contract."* That framing is now false — enforcement is opt-in (`require_quarantine_provider_separation`, default `False`). Fix the docstring prose to match the opt-in framing landing everywhere else in this task; the test function's own assertion needs no change (it only pins the YAML's literal default value, which is unaffected).

- [ ] **Step 6: Commit**

```bash
git add docs/adr/0064-quarantine-provider-separation-is-opt-in.md docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md config/routing.yaml .env.example docs/runbooks/slice-3-quarantined-llm.md README.md tests/unit/security/test_routing_yaml_quarantine_block.py
git commit -m "docs: correct quarantine-provider claims across routing.yaml, .env.example, the runbook, and README; add ADR-0064 (#586 #587)"
```

---

## Definition of Done

- [ ] All 6 tasks' tests pass: `uv run pytest tests/unit/security/test_brokered_provider_source.py tests/unit/security/test_brokered_egress_transport.py tests/unit/config/ tests/unit/security/ tests/unit/cli/daemon/ tests/unit/comms_mcp/ -v` (adjust exact paths per what Task 2/3 actually located).
- [ ] `make check` passes clean.
- [ ] 100% line+branch coverage on every touched file under `src/alfred/security/`, AND on `src/alfred/cli/daemon/_comms_boot.py` / `_failures.py` / `_commands.py` (Task 4's new branches — arch-003's coverage-gate-scope concern was RAISED then RETRACTED on cross-check: `make coverage-gates` derives its file list live from `ci.yml`, which already names every one of these files, so this is confirmed already covered by the existing gate, not a new one to add).
- [ ] `alfred-security-engineer` sign-off obtained.
- [ ] The Docker-only DeepSeek extraction test (Task 5) confirmed passing at least once before merge. **Reworded per test-008 (Low): this is NOT a discretionary manual side-quest** — the file it lives in (`tests/integration/test_quarantine_real_extract.py`) is already `_DOCKER_ONLY`-gated and its sibling tests already run automatically as REQUIRED checks on the `integration-privileged` (amd64) and `integration-privileged-arm64` (aarch64) CI legs (#269) — the new test is auto-discovered and gated by that SAME existing mechanism, not a separate manual step. A local Docker run (Task 5 Step 3) is a recommended pre-push sanity check on top of that, not the sole verification gate.
- [ ] `/review-plan` fleet run on this plan before implementation; full `/review-pr` fleet + CodeRabbit `full review` on the resulting PR before merge.
- [ ] Every existing test in every touched file still passes unmodified with both new settings at their defaults (byte-for-byte non-breaking requirement).
- [ ] **Corrected per arch-001/rev-001 (disputed-confirmed Critical/High — the underlying fact is TRIPLE-confirmed regardless of which severity wins):** there is no PRD section anywhere that states a quarantine/privileged provider-separation "MUST differ" invariant — PRD §6.4 is "Self-Improvement with Reviewer Gate," an unrelated feature, and PRD §7.1 (the dual-LLM split itself) contains no provider-diversity mandate either. Do NOT flag "PRD §6.4 needs softening" to a human maintainer — that would misdirect them at the wrong section. Task 6 Step 0's new ADR-0064 is the accurate record of this decision (which now also explicitly names what it supersedes — spec §5.4's default-refuse/reviewer-gated mechanism, per arch-r2-001); if PRD text should exist for this invariant at all, that is a separate, human-gated follow-up decision this plan does not resolve, not a "fix the wording" edit to an unrelated section.

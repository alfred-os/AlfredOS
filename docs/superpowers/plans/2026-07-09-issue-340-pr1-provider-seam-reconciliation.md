# #340 PR1 — Provider-Seam Reconciliation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the quarantine child's `provider_dispatch.py` off the aspirational
`.complete(response_format=)` / `.tool_use_input` shape onto the real #339
`CompletionRequest`/`CompletionResponse` seam, adding one minimal additive
`ProviderUnavailableError` — network-free and behaviour-neutral on the live path
(the child still echoes; the dispatcher stays dead code until PR2 wires the real
client).

**Architecture:** The quarantine child (`src/alfred/security/quarantine_child/`)
runs a deterministic-echo loop today; `provider_dispatch.dispatch_extraction` is
real but unreachable (lazily imported on the `handle_extract` path the echo loop
never calls). This PR makes that dead code speak the real provider seam so PR2's
go-live is a surgical `_build_provider` swap. Provider-unavailable classification
moves to a typed seam error the ADAPTERS raise (so the child imports no SDK); the
DeepSeek JSON-object branch is dropped (fork b) since no shipped provider is
JSON-object-only. Every change is proven against a fake seam-conforming provider —
no network, no SDK import in the child, no child-loop change.

**Tech Stack:** Python 3.14+, Pydantic v2, pytest + pytest-asyncio, mypy
`--strict` + pyright, ruff, structlog, `t()` i18n (Babel), `uv`.

## Global Constraints

- **Behaviour-neutral on the LIVE path.** `_build_provider` still returns
  `_DeterministicProvider()`; `_run_mcp_server`'s extract branch stays
  `_echo_extracted_frame`. NO child-loop change. NO real SDK import in the child.
  NO network.

- **HARD #7 (no silent failures in security paths).** Every dispatch failure path
  audits/refuses via a typed `ExtractionResult` — never an uncaught exception that
  skips the audit write. In particular, empty `tool_calls` must NOT `IndexError`.

- **In-core HTTP-egress import guard.** `provider_dispatch.py` must import NO SDK
  (`anthropic`/`openai`) and drop `import httpx`. SDK-error → `ProviderUnavailableError`
  mapping lives at the ADAPTER boundary (`anthropic_native.py` / `deepseek.py`),
  which already import their SDKs.

- **100% line + branch coverage on `src/alfred/security/quarantine_child/provider_dispatch.py`** (gate wired at `ci.yml:1816`). Removing the JSON-object runtime branch removes the dead branch that would otherwise defeat this.
- **Adversarial suite is release-blocking** — this PR edits `src/alfred/security/`.
  Run `uv run pytest tests/adversarial` before the final commit.

- **i18n:** all operator-facing strings via `t()`; `msgstr` must be brace-free of
  literal braces (`t()` runs `.format(**vars)` — `{provider}`/`{model}` are format
  fields, not literal braces). Run the pybabel drift steps in Task 1.

- **Frozen models:** `CompletionRequest`/`CompletionResponse`/`ToolDefinition`/
  `ForcedTool` are `frozen=True, extra="forbid"`. `ProviderUnavailableError` is
  additive (a new `AlfredError` subclass); it does NOT touch those models.

- **Conventional Commits** with a literal `#340` AFTER the colon in every subject,
  ending with the `MrReasonable <4990954+MrReasonable@users.noreply.github.com>`
  trailer. Never `git add -A` (untracked rulesync outputs); add named paths only.
  Never `--no-verify`.

- **Branch:** work on `340-real-quarantine-child` (the rev.2 spec is already
  committed there). Base = `main` @ `39c87b4e` (spec branch is off it).

**Out of scope (all PR2):** the fd-broker/network topology, `_build_provider`
real client, the extract-branch swap, refuse-boot, provenance re-validation,
`max_tokens` wiring, the timeout hierarchy.

---

## Plan-review fixes (rev.2 — FOLD THESE FIRST; they OVERRIDE the task bodies)

A focused 4-lens `/review-plan` (reviewer, test, security, provider) verified the
design/seam-mapping as byte-correct (0 Critical) and confirmed behaviour-neutrality
(the only privileged-path catcher, `core.py:829 except Exception`, fires
identically on `ProviderUnavailableError`). Two High plan-bugs + precision items are
folded here — apply as you execute the tasks.

**FIX-1 (High, 4-lens — Task 2 Step 6): ONE shared `try`** (already corrected inline
in Step 6). Wrap BOTH `_call_provider` and `_validate_response` in a single `try`
so a `ProviderMalformedToolArgumentsError` (empty/malformed forced-tool response)
is retry-eligible and can never escape uncaught (HARD #7).

**FIX-2 (High, 4-lens — Task 2 Step 2): MIGRATE the json-object tests, do not
blanket-delete.** The 15 tests in `test_quarantined_extractor_dispatch.py` are the
sole coverage of the retry/budget/bad-JSON/non-object branches. Per-test disposition:

- `test_dispatch_uses_native_path_for_native_constrained_provider` → rewrite to
  `_tool_use_response` (folded into Step 2's `test_native_constrained_reads_tool_call_arguments`).
- `test_dispatch_uses_json_object_path_for_json_mode_provider` → repurpose: a
  `JSON_OBJECT_MODE`-only provider now routes to `prompt_embedded_fallback`
  (fork b); use `_text_response`, assert `extraction_mode == "prompt_embedded_fallback"`
  and `sent.tools == ()`.
- `test_dispatch_uses_fallback_for_no_capability_provider` → migrate
  `_json_object_response` → `_text_response`.
- `test_native_path_wins_when_provider_has_both_capabilities` → rewrite to
  `_tool_use_response` (NATIVE+JSON → native_constrained).
- `test_dispatch_retries_on_json_decode_error_then_succeeds`,
  `test_dispatch_returns_typed_refusal_on_retry_exhaustion`,
  `test_dispatch_short_circuits_on_wall_clock_budget_breach`,
  `test_dispatch_treats_non_object_json_as_retry_eligible`,
  `test_dispatch_retry_path_does_not_carry_prior_response_text` → migrate their fakes
  `_json_object_response` → `_text_response` (the fallback path still runs
  `_validate_response`, preserving retry-loop / wall-clock-budget / non-object
  coverage). KEEP their assertions.
- `test_dispatch_returns_provider_unavailable_on_httpx_error` → rename to
  `..._on_provider_error`, inject `ProviderUnavailableError("down")` (folded into
  Step 2's `test_provider_unavailable_maps_to_typed_refusal`).
- `test_dispatch_propagates_non_validation_errors` → inject a generic `RuntimeError`
  (not httpx) and assert it PROPAGATES (HARD #7 "everything else propagates").
- `test_cached_parsed_schema_refuses_non_object_json`,
  `test_categorise_validator_error_maps_*`,
  `test_build_extraction_prompt_retry_does_not_leak_pydantic_loc` → KEEP unchanged.
- ADD `test_categorise_validator_error_maps_malformed_tool_args_to_schema_mismatch`
  (the new `ProviderMalformedToolArgumentsError` → `"schema_mismatch"` branch).
- Delete the `_native_tool_use_response` / `_json_object_response` helper defs only
  after every referencing test is migrated.

**FIX-3 (Medium — Task 1 Step 7): DeepSeek fixture note.** Mirror Step 1: if
`test_deepseek.py` has no reusable `deepseek_provider` fixture, add one building
`DeepSeekProvider(client=AsyncMock(), model="deepseek-chat")`.

**FIX-4 (Low, 3-lens — Task 3 Step 2): a SECOND stale httpx comment.** Besides the
go-live egress gate, `tests/unit/security/test_quarantine_child_import_closure.py`
module docstring (~L20-22: "The `provider_dispatch` import (which pulls `httpx`…)")
is now false — update it too. (Step 2's wording: the go-live gate's httpx-importer
line is an INLINE comment, not a "module docstring".)

**FIX-5 (Low — Task 1): test the "no raw exc text" claim.** Add an adapter test
asserting `str(ProviderUnavailableError(...))` contains the provider name + model
but NOT the injected SDK exception's text (proves `t()` does not render raw `exc`).

**FIX-6 (Low — Task 2): update `provider_dispatch.py`'s own docstrings.** The module
docstring, `dispatch_extraction`, and `_call_provider` docstrings still describe the
3-branch / json-object / `httpx` model — rewrite them to the fork-b two-branch seam.

**FIX-7 (Low — Task 4 verification): the coverage gate also covers `base.py`.** The
`ci.yml` gate asserts 100% on BOTH `provider_dispatch.py` AND `providers/base.py`;
`ProviderUnavailableError` is a bare class (import-covered) so base.py stays 100% —
include base.py in the Step-4 coverage check.

**FIX-8 (note only): observable audit `error_type`.** On the privileged turn a
provider outage's audit `error_type` now records `ProviderUnavailableError` instead
of the raw `anthropic`/`openai` class name (redaction-positive; behaviour otherwise
unchanged). Expected, not a regression.

**FORK-B non-default note (rev-005):** routing deepseek-chat from json-object to
`prompt_embedded_fallback` is a slight reliability downgrade for the (non-default)
deepseek-as-quarantine config (default is Anthropic / native_constrained). The
fuller labelled-tool-use path for deepseek-chat is deferred (needs a new
`ExtractionMode` member) — ratified under fork (b); no action this PR.

---

## File Structure

- `src/alfred/providers/base.py` — ADD `ProviderUnavailableError(AlfredError)`
  (near the other `Provider*Error` classes, ~L131-157).

- `src/alfred/providers/anthropic_native.py` — wrap `self._client.messages.create`
  → map `anthropic.APIError` / `httpx.HTTPError` to `ProviderUnavailableError`.

- `src/alfred/providers/deepseek.py` — wrap `self._client.chat.completions.create`
  → map `openai.APIError` / `httpx.HTTPError` to `ProviderUnavailableError`.

- `locale/en/LC_MESSAGES/alfred.po` (+ `.mo`) — ADD `providers.provider_unavailable`.
- `src/alfred/security/quarantine_child/provider_dispatch.py` — the reconciliation:
  capability selection (drop JSON-object branch), `_call_provider` rewrite to the
  #339 seam, empty-`tool_calls`/malformed guards, `ProviderUnavailableError`
  catch, drop `import httpx`.

- `src/alfred/security/quarantine.py` — doc note on the now-reserved
  `json_object_unconstrained` `ExtractionMode` member.

- `tests/unit/providers/test_anthropic.py`, `tests/unit/providers/test_deepseek.py`
  — adapter error-mapping tests.

- `tests/unit/providers/test_router.py` — router-falls-back-on-`ProviderUnavailableError`
  regression test.

- `tests/unit/quarantine/test_quarantined_extractor_dispatch.py` — rewrite the
  aspirational fakes to the #339 seam; drop the JSON-object tests; add
  empty-`tool_calls` / malformed / `provider_unavailable` tests.

- `tests/adversarial/sandbox_escape/test_quarantined_llm_not_yet_spawned_while_egress_open.py`
  — update the stale "`provider_dispatch` is the only httpx importer" comment/anchor
  (it is now egress-free).

- `docs/adr/0045-*.md` — a dated factual amendment (additive `ProviderUnavailableError`).

_(Exact line numbers below are anchors as of `main` @ `39c87b4e`; re-grep before
editing — surrounding edits may shift them.)_

---

## Task 1: `ProviderUnavailableError` seam type + adapter error-mapping

**Files:**

- Modify: `src/alfred/providers/base.py` (add the error, ~after L156)
- Modify: `src/alfred/providers/anthropic_native.py` (imports + wrap `.create` ~L284)
- Modify: `src/alfred/providers/deepseek.py` (imports + wrap `.create` ~L301)
- Modify: `locale/en/LC_MESSAGES/alfred.po` (+ `.mo` via pybabel)
- Test: `tests/unit/providers/test_anthropic.py`, `tests/unit/providers/test_deepseek.py`, `tests/unit/providers/test_router.py`

**Interfaces:**

- Produces: `alfred.providers.base.ProviderUnavailableError(AlfredError)` — raised by
  `AnthropicProvider.complete` / `DeepSeekProvider.complete` when the SDK/transport
  call fails (network/timeout/5xx). Message via
  `t("providers.provider_unavailable", provider=<name>, model=<model>)`. It is
  deliberately NOT in `router._TOOL_PROTOCOL_ERRORS`, so the router falls back on it.

- [ ] **Step 1: Write the failing adapter-mapping test (Anthropic)**

Add to `tests/unit/providers/test_anthropic.py` (match the file's existing
fixture/style for building an `AnthropicProvider` with a mocked `self._client`):

```python
import httpx
import pytest
from anthropic import APIConnectionError

from alfred.providers.base import CompletionRequest, Message, ProviderUnavailableError

@pytest.mark.asyncio
async def test_complete_maps_sdk_error_to_provider_unavailable(anthropic_provider):
    # anthropic_provider is the test fixture whose _client is a mock; make the
    # network call raise the SDK's connection error.
    anthropic_provider._client.messages.create.side_effect = APIConnectionError(
        request=httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    )
    req = CompletionRequest(messages=[Message(role="user", content="hi")])
    with pytest.raises(ProviderUnavailableError):
        await anthropic_provider.complete(req)

@pytest.mark.asyncio
async def test_complete_maps_httpx_error_to_provider_unavailable(anthropic_provider):
    anthropic_provider._client.messages.create.side_effect = httpx.ConnectError("boom")
    req = CompletionRequest(messages=[Message(role="user", content="hi")])
    with pytest.raises(ProviderUnavailableError):
        await anthropic_provider.complete(req)
```

_If `test_anthropic.py` has no reusable `anthropic_provider` fixture, add one that
builds `AnthropicProvider(client=AsyncMock(), model="claude-haiku-4-5")` (mirror
the construction the existing `complete` tests already use)._

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/providers/test_anthropic.py -k provider_unavailable -q`
Expected: FAIL — `ProviderUnavailableError` does not exist (ImportError) or the SDK
error propagates unmapped.

- [ ] **Step 3: Add `ProviderUnavailableError` to `base.py`**

In `src/alfred/providers/base.py`, after `ProviderToolNameCollisionError` (~L156),
before `ensure_tool_capability`:

```python
class ProviderUnavailableError(AlfredError):
    """The provider SDK/transport call failed (connection error, timeout, 5xx).

    Raised by each adapter's ``complete()`` at the SDK-call boundary so callers
    (the router; the quarantine child's ``provider_dispatch``) get ONE typed
    error instead of the provider-specific ``anthropic``/``openai`` hierarchies.
    The quarantine child maps this to ``TypedRefusal(reason="provider_unavailable")``
    so audit consumers can tell provider outages apart from model-output failures.

    Deliberately NOT in ``router._TOOL_PROTOCOL_ERRORS`` — a transient transport
    failure SHOULD fall back to the secondary provider (contrast a deterministic
    tool-protocol error, which would fail identically on the fallback)."""
```

- [ ] **Step 4: Map SDK/transport errors in the Anthropic adapter**

In `src/alfred/providers/anthropic_native.py`: add to the anthropic import
(`from anthropic import AsyncAnthropic`) the `APIError` symbol, ensure
`from alfred.i18n import t` is imported, add `ProviderUnavailableError` to the
`from alfred.providers.base import (...)` block, then wrap ONLY the network call
(~L284):

```python
from anthropic import APIError, AsyncAnthropic
```

```python
        try:
            response = await self._client.messages.create(**kwargs)
        except (APIError, httpx.HTTPError) as exc:
            # Map the SDK/transport failure to the neutral seam error at the
            # adapter boundary (the only place the SDK types are in scope). Never
            # surface the raw exc text — it can carry provider-supplied strings.
            raise ProviderUnavailableError(
                t("providers.provider_unavailable", provider=self.name, model=self._model)
            ) from exc
```

Leave the response PARSING (`_parse_anthropic_content`, etc.) OUTSIDE the `try` so a
`ProviderMalformedToolArgumentsError` from parsing is never swallowed into
`provider_unavailable`.

- [ ] **Step 5: Map SDK/transport errors in the DeepSeek adapter**

In `src/alfred/providers/deepseek.py`: add `APIError` to
`from openai import AsyncOpenAI`, add `ProviderUnavailableError` to the base import
block (`t` is already imported at L31), then wrap ONLY the network call (~L301):

```python
from openai import APIError, AsyncOpenAI
```

```python
        try:
            response = await self._client.chat.completions.create(**kwargs)
        except (APIError, httpx.HTTPError) as exc:
            raise ProviderUnavailableError(
                t("providers.provider_unavailable", provider=self.name, model=self._model)
            ) from exc
```

- [ ] **Step 6: Add the i18n key + rebuild the catalog**

Add to `locale/en/LC_MESSAGES/alfred.po` (near the other `providers.*` keys ~L3023):

```po
msgid "providers.provider_unavailable"
msgstr "The {provider} provider ({model}) is currently unavailable."
```

Then run the drift steps (NEVER `--omit-header`; the `tail` pipe masks the exit
code — check `$?`):

```bash
uv run pybabel extract -F babel.cfg -o /tmp/alfred340.pot src/alfred plugins
uv run pybabel update -i /tmp/alfred340.pot -d locale -D alfred --no-fuzzy-matching
uv run pybabel compile -d locale -D alfred --statistics
```

- [ ] **Step 7: Add the DeepSeek mapping test (mirror Step 1)**

Add to `tests/unit/providers/test_deepseek.py`:

```python
import httpx
import pytest
from openai import APIConnectionError

from alfred.providers.base import CompletionRequest, Message, ProviderUnavailableError

@pytest.mark.asyncio
async def test_complete_maps_sdk_error_to_provider_unavailable(deepseek_provider):
    deepseek_provider._client.chat.completions.create.side_effect = APIConnectionError(
        request=httpx.Request("POST", "https://api.deepseek.com/chat/completions")
    )
    req = CompletionRequest(messages=[Message(role="user", content="hi")])
    with pytest.raises(ProviderUnavailableError):
        await deepseek_provider.complete(req)
```

- [ ] **Step 8: Write the router-fallback regression test**

Add to `tests/unit/providers/test_router.py`:

```python
import pytest
from unittest.mock import AsyncMock

from alfred.providers.base import CompletionRequest, CompletionResponse, Message, ProviderUnavailableError
from alfred.providers.router import ProviderRouter

@pytest.mark.asyncio
async def test_router_falls_back_on_provider_unavailable():
    primary = AsyncMock()
    primary.name = "primary"
    primary.complete = AsyncMock(side_effect=ProviderUnavailableError("down"))
    fallback = AsyncMock()
    fallback.name = "fallback"
    ok = CompletionResponse(
        content="ok", tokens_in=1, tokens_out=1, cost_usd=0.0, model="fallback-model"
    )
    fallback.complete = AsyncMock(return_value=ok)
    router = ProviderRouter(primary=primary, fallback=fallback)

    result = await router.complete(CompletionRequest(messages=[Message(role="user", content="hi")]))

    assert result is ok
    fallback.complete.assert_awaited_once()
```

- [ ] **Step 9: Run the full Task-1 test set + type/lint**

```bash
uv run pytest tests/unit/providers/test_anthropic.py tests/unit/providers/test_deepseek.py tests/unit/providers/test_router.py -q
uv run mypy src/alfred/providers && uv run pyright src/alfred/providers
uv run ruff check src/alfred/providers && uv run ruff format --check src/alfred/providers
```

Expected: all PASS.

- [ ] **Step 10: Commit**

```bash
git add src/alfred/providers/base.py src/alfred/providers/anthropic_native.py \
  src/alfred/providers/deepseek.py locale/en/LC_MESSAGES/alfred.po \
  locale/en/LC_MESSAGES/alfred.mo \
  tests/unit/providers/test_anthropic.py tests/unit/providers/test_deepseek.py \
  tests/unit/providers/test_router.py
git commit -m "feat(providers): add ProviderUnavailableError seam error + adapter mapping #340

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 2: Port `provider_dispatch` to the #339 seam (drop JSON-object; guards)

**Files:**

- Modify: `src/alfred/security/quarantine_child/provider_dispatch.py`
- Modify: `src/alfred/security/quarantine.py` (`ExtractionMode` reserved-note only)
- Test: `tests/unit/quarantine/test_quarantined_extractor_dispatch.py` (rewrite fakes)

**Interfaces:**

- Consumes: `alfred.providers.base` — `CompletionRequest`, `Message`,
  `ToolDefinition`, `ForcedTool`, `ProviderCapability`,
  `ProviderMalformedToolArgumentsError`, `ProviderUnavailableError` (Task 1).

- Consumes: a `provider` object with `.capabilities() -> frozenset[ProviderCapability]`
  and `async .complete(CompletionRequest) -> CompletionResponse`.

- Produces: `dispatch_extraction(*, content, schema_json, schema_version, provider)
  -> dict` unchanged in signature/return contract (an `ExtractionResult`-shaped
  dict), now driving the real seam.

- [ ] **Step 1: Rewrite the fake-provider helpers in the dispatch test to the #339 seam**

In `tests/unit/quarantine/test_quarantined_extractor_dispatch.py`, replace the
aspirational `_native_tool_use_response` / `_json_object_response` helpers with
real-seam builders (delete the JSON-object helper — that branch is removed):

```python
from alfred.providers.base import (
    CompletionResponse,
    ProviderCapability,
    ToolCall,
)

def _tool_use_response(payload: dict[str, Any]) -> CompletionResponse:
    """A forced-tool response: one ToolCall whose arguments are the payload."""
    return CompletionResponse(
        content="",
        tokens_in=1,
        tokens_out=1,
        cost_usd=0.0,
        model="fake-model",
        stop_reason="tool_use",
        tool_calls=(ToolCall(id="t0", name="extract_structured_data", arguments=payload),),
    )

def _text_response(content: str) -> CompletionResponse:
    """A plain-completion response (prompt_embedded_fallback path)."""
    return CompletionResponse(
        content=content, tokens_in=1, tokens_out=1, cost_usd=0.0, model="fake-model"
    )

def _empty_tool_use_response() -> CompletionResponse:
    """A max_tokens-truncated forced-tool response: no tool_calls."""
    return CompletionResponse(
        content="", tokens_in=1, tokens_out=1, cost_usd=0.0, model="fake-model",
        stop_reason="max_tokens",
    )
```

- [ ] **Step 2: Update the branch-selection + happy-path tests, and add the guard tests**

Rewrite the capability-branch tests to the two remaining modes and add the new
failure-path tests. Anthropic-cap provider → `native_constrained`; a provider with
only `JSON_OBJECT_MODE` (no `NATIVE_CONSTRAINED_GENERATION`, no `TOOL_USE`) now →
`prompt_embedded_fallback`:

```python
@pytest.mark.asyncio
async def test_native_constrained_reads_tool_call_arguments() -> None:
    payload = {"text": "hi", "intent": "greeting"}
    provider = _fake_provider_with_capabilities(
        frozenset({ProviderCapability.NATIVE_CONSTRAINED_GENERATION}),
        _tool_use_response(payload),
    )
    result = await dispatch_extraction(
        content=b"hello", schema_json=_SCHEMA_JSON, schema_version=1, provider=provider
    )
    assert result == {"kind": "extracted", "data": payload, "extraction_mode": "native_constrained"}
    # Non-vacuous: the request advertised the forced extract tool with the schema.
    sent: CompletionRequest = provider.complete.call_args.args[0]
    assert sent.tool_choice == ForcedTool(name="extract_structured_data")
    assert sent.tools[0].name == "extract_structured_data"
    assert sent.tools[0].input_schema == json.loads(_SCHEMA_JSON)

@pytest.mark.asyncio
async def test_provider_without_native_uses_prompt_embedded_fallback() -> None:
    provider = _fake_provider_with_capabilities(
        frozenset({ProviderCapability.JSON_OBJECT_MODE}),
        _text_response('{"text": "hi", "intent": "greeting"}'),
    )
    result = await dispatch_extraction(
        content=b"hello", schema_json=_SCHEMA_JSON, schema_version=1, provider=provider
    )
    assert result["extraction_mode"] == "prompt_embedded_fallback"
    sent: CompletionRequest = provider.complete.call_args.args[0]
    assert sent.tools == ()  # no tool advertised on the fallback path

@pytest.mark.asyncio
async def test_empty_tool_calls_exhausts_to_cannot_extract() -> None:
    provider = _fake_provider_with_capabilities(
        frozenset({ProviderCapability.NATIVE_CONSTRAINED_GENERATION}),
        _empty_tool_use_response(),
    )
    result = await dispatch_extraction(
        content=b"hello", schema_json=_SCHEMA_JSON, schema_version=1, provider=provider
    )
    assert result == {"kind": "typed_refusal", "reason": "cannot_extract"}

@pytest.mark.asyncio
async def test_provider_unavailable_maps_to_typed_refusal() -> None:
    provider = _fake_provider_with_capabilities(
        frozenset({ProviderCapability.NATIVE_CONSTRAINED_GENERATION}), None
    )
    provider.complete = AsyncMock(side_effect=ProviderUnavailableError("down"))
    result = await dispatch_extraction(
        content=b"hello", schema_json=_SCHEMA_JSON, schema_version=1, provider=provider
    )
    assert result == {"kind": "typed_refusal", "reason": "provider_unavailable"}
```

Add `_SCHEMA_JSON = json.dumps({"type": "object", "properties": {"text": {"type": "string"}, "intent": {"type": "string"}}, "required": ["text", "intent"]})` near the top, and import `CompletionRequest`, `ForcedTool`, `ProviderUnavailableError`.

**Do NOT blanket-delete the json-object tests — MIGRATE them** (rev-002/test-002/prov-001/sec-002, 4-lens: they are the sole coverage of the retry-loop / wall-clock-budget / bad-JSON / non-object branches; deleting them fails the 100% gate at Step 9). Apply the per-test disposition in the "Plan-review fixes" fold section at the top of this plan: the retry/exhaustion/budget-breach/non-object tests move their fakes from `_json_object_response` to `_text_response` (the surviving fallback path still routes through `_validate_response`, exercising the same retry branches); `test_dispatch_returns_provider_unavailable_on_httpx_error` is renamed to inject `ProviderUnavailableError`; `test_dispatch_propagates_non_validation_errors` injects a generic `RuntimeError`; the two `_native_tool_use_response` tests move to `_tool_use_response`.

- [ ] **Step 3: Run to verify the rewritten tests fail against the old dispatcher**

Run: `uv run pytest tests/unit/quarantine/test_quarantined_extractor_dispatch.py -q`
Expected: FAIL — the old `_call_provider` calls `.complete(response_format=...)` /
reads `.tool_use_input`, which the new fakes don't provide.

- [ ] **Step 4: Rewrite capability selection in `dispatch_extraction`**

In `provider_dispatch.py`, replace the three-way capability selection (~L187-193)
with the two-way fork-(b) selection:

```python
    caps = provider.capabilities()
    if ProviderCapability.NATIVE_CONSTRAINED_GENERATION in caps:
        extraction_mode = "native_constrained"
    else:
        # fork (b), #340: the JSON-object branch is removed — no shipped provider
        # is JSON-object-only, and every constrained-capable provider declares a
        # native tool-use path. A provider WITHOUT native constrained generation
        # (incl. deepseek-chat / deepseek-reasoner) uses the prompt-embedded
        # fallback (host-validated). Routing a TOOL_USE-but-not-native provider
        # through a distinctly-labelled tool-use mode is deferred (needs a new
        # ExtractionMode member) — see the spec §4.2 fork (b) note.
        extraction_mode = "prompt_embedded_fallback"
```

- [ ] **Step 5: Rewrite `_call_provider` to the #339 seam**

Replace the body of `_call_provider` (~L284-342). Remove the `json_object_unconstrained`
branch entirely:

```python
from alfred.providers.base import (
    CompletionRequest,
    ForcedTool,
    Message,
    ProviderCapability,
    ProviderMalformedToolArgumentsError,
    ProviderUnavailableError,
    ToolDefinition,
)

_EXTRACT_TOOL_NAME = "extract_structured_data"

async def _call_provider(
    *,
    prompt: str,
    schema_json: str,
    provider: Any,
    extraction_mode: str,
) -> str:
    """Dispatch the provider call for ``extraction_mode`` (#340 seam).

    Two shapes (fork b):

    * ``native_constrained``: force the single ``extract_structured_data`` tool
      whose ``input_schema`` is the extraction schema; read the first
      ``tool_call``'s ``arguments`` and re-serialise to JSON. An empty
      ``tool_calls`` (a ``max_tokens``-truncated forced tool — ``tool_calls`` is
      non-empty only when ``stop_reason=="tool_use"``) raises
      ``ProviderMalformedToolArgumentsError`` so the retry loop treats it like a
      schema failure and exhausts to ``cannot_extract`` — never an uncaught
      ``IndexError`` that skips the audit (HARD #7).
    * ``prompt_embedded_fallback``: bare completion; the schema is embedded in the
      prompt and the response text is validated host-side.

    Returns a JSON string in both branches so :func:`_validate_response` has a
    uniform shape.
    """
    schema = _cached_parsed_schema(schema_json)
    if extraction_mode == "native_constrained":
        request = CompletionRequest(
            messages=[Message(role="user", content=prompt)],
            tools=(
                ToolDefinition(
                    name=_EXTRACT_TOOL_NAME,
                    description="Extract structured data from content per schema.",
                    input_schema=schema,
                ),
            ),
            tool_choice=ForcedTool(name=_EXTRACT_TOOL_NAME),
        )
        response = await provider.complete(request)
        if not response.tool_calls:
            raise ProviderMalformedToolArgumentsError(
                "quarantine extractor: forced tool returned no tool_call"
            )
        return json.dumps(dict(response.tool_calls[0].arguments))
    # prompt_embedded_fallback: bare completion.
    request = CompletionRequest(messages=[Message(role="user", content=prompt)])
    response = await provider.complete(request)
    return str(response.content)
```

- [ ] **Step 6: Update `dispatch_extraction` error handling; drop `import httpx`**

In `dispatch_extraction` (~L209-247): replace the TWO separate `try` blocks
(the `_call_provider` call and the `_validate_response` call) with **ONE** `try`
wrapping BOTH. This is load-bearing (rev-001/sec-001/test-001, 4-lens): if
`_call_provider` raises `ProviderMalformedToolArgumentsError` (empty/malformed
forced-tool response) while it sits in a `try` that only catches
`ProviderUnavailableError`, the error escapes `dispatch_extraction` uncaught —
skipping the typed-refusal/audit write (HARD #7 hole). One shared try makes the
malformed-args path retry-eligible and audit-safe:

```python
        try:
            raw_response = await _call_provider(
                prompt=prompt,
                schema_json=schema_json,
                provider=provider,
                extraction_mode=extraction_mode,
            )
            validated = _validate_response(raw_response, schema_json)
            return {"kind": "extracted", "data": validated, "extraction_mode": extraction_mode}
        except ProviderUnavailableError:
            # Terminal (NOT retry-eligible): a provider outage, not a model-output
            # failure, so audit consumers can tell them apart (err-002).
            return {"kind": "typed_refusal", "reason": "provider_unavailable"}
        except (ValidationError, json.JSONDecodeError, ProviderMalformedToolArgumentsError) as exc:
            # ONE try wraps BOTH the provider call and validation so an empty/
            # malformed forced-tool response (ProviderMalformedToolArgumentsError,
            # raised by _call_provider) is retry-eligible and can never escape
            # dispatch_extraction uncaught — HARD #7 (rev-001/sec-001/test-001).
            retry_category = _categorise_validator_error(exc)
```

Update `_categorise_validator_error`'s type hint + body to accept
`ProviderMalformedToolArgumentsError` (mapped to `"schema_mismatch"`):

```python
def _categorise_validator_error(
    exc: ValidationError | json.JSONDecodeError | ProviderMalformedToolArgumentsError,
) -> ValidatorErrorCategory:
    if isinstance(exc, json.JSONDecodeError):
        return "json_parse_error"
    # ValidationError | ProviderMalformedToolArgumentsError → the conservative
    # closed-vocab label; never widens into attacker-controlled text.
    return "schema_mismatch"
```

Delete the module-level `import httpx` (L66) — the child no longer references it.

- [ ] **Step 7: Add the `ExtractionMode` reserved-note in `quarantine.py`**

In `src/alfred/security/quarantine.py`, add a comment above the `json_object_unconstrained`
member (~L271) so the reserved-but-unselected status is explicit:

```python
ExtractionMode = Literal[
    "native_constrained",
    # RESERVED (not selected at runtime since #340 fork b): the dispatcher no
    # longer routes any provider through DeepSeek json-object mode. The member is
    # retained for audit-row continuity + a future response_format seam extension.
    "json_object_unconstrained",
    "prompt_embedded_fallback",
]
```

- [ ] **Step 8: Run the dispatch tests + type/lint**

```bash
uv run pytest tests/unit/quarantine/test_quarantined_extractor_dispatch.py tests/unit/quarantine/ -q
uv run mypy src/alfred/security/quarantine_child src/alfred/security/quarantine.py
uv run pyright src/alfred/security/quarantine_child
uv run ruff check src/alfred/security && uv run ruff format --check src/alfred/security
```

Expected: all PASS.

- [ ] **Step 9: Verify 100% line + branch coverage on the dispatcher**

```bash
uv run coverage run -m pytest tests/unit/quarantine/test_quarantined_extractor_dispatch.py
uv run coverage report --include='src/alfred/security/quarantine_child/provider_dispatch.py' --show-missing --fail-under=100
```

Expected: `100%`, no missing lines/branches. (If a branch is uncovered, add the
missing test — do NOT add a `# pragma: no cover`.)

- [ ] **Step 10: Commit**

```bash
git add src/alfred/security/quarantine_child/provider_dispatch.py \
  src/alfred/security/quarantine.py \
  tests/unit/quarantine/test_quarantined_extractor_dispatch.py
git commit -m "feat(quarantine): port provider_dispatch to the #339 seam, drop json-object branch #340

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 3: Egress-posture regression + adversarial suite

**Files:**

- Modify: `tests/adversarial/sandbox_escape/test_quarantined_llm_not_yet_spawned_while_egress_open.py`
  (the stale "`provider_dispatch` is the only httpx importer" comment/anchor)

- Test: the existing import-closure + egress-gate suites (run unchanged, assert green)

**Interfaces:**

- Consumes: nothing new. This task proves PR1 did not regress the child's
  import-closure / egress posture and, if anything, tightened it (provider_dispatch
  no longer imports httpx).

- [ ] **Step 1: Run the import-closure + egress-gate suites as-is**

```bash
uv run pytest tests/unit/security/test_quarantine_child_import_closure.py \
  tests/adversarial/sandbox_escape/test_quarantined_llm_not_yet_spawned_while_egress_open.py -q
```

Expected: PASS. The module-scope import-closure delta of `__main__` is unchanged
(`provider_dispatch` is still lazy). If either FAILS, read the assertion: if a test
asserts `provider_dispatch` imports `httpx` as the "egress-capable" marker, that
premise no longer holds (see Step 2).

- [ ] **Step 2: Update the stale egress-posture comment/anchor**

In `test_quarantined_llm_not_yet_spawned_while_egress_open.py`, the module docstring
(~L344-347) states `provider_dispatch` is "the only httpx importer (LAZY)". After
PR1 the child imports NO egress-capable module at all — `provider_dispatch` calls
`provider.complete` on an INJECTED provider, and the egress capability lands in
PR2's `_build_provider` (which imports the SDK). Update the comment to reflect this:

```python
# The live echo loop imports no egress-capable module at module scope. As of #340
# PR1, provider_dispatch itself is egress-free (it drives an INJECTED provider and
# imports no httpx/SDK); the egress-capable import lands in PR2's _build_provider
# (the real-client construction), which this gate will assert against at go-live.
```

If the test has an EXECUTABLE assertion keyed on `provider_dispatch` importing
`httpx` (not just a comment), relax it to assert the LIVE `__main__` module-scope
closure carries no egress import (the load-bearing invariant), which still holds.
Do not weaken the `__main__`-module-scope-clean assertion.

- [ ] **Step 3: Run the full adversarial suite (release-blocking)**

```bash
env -u ALFRED_SMOKE_PROVIDER_KEY uv run pytest tests/adversarial -q
```

Expected: PASS (bwrap-gated real-spawn legs skip on macOS — that is fine; the
import-graph + policy gates run everywhere).

- [ ] **Step 4: Commit**

```bash
git add tests/adversarial/sandbox_escape/test_quarantined_llm_not_yet_spawned_while_egress_open.py
git commit -m "test(340): document provider_dispatch is egress-free after the seam port #340

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 4: ADR amendment + full verification

**Files:**

- Modify: `docs/adr/0045-*.md` (the #339 provider tool-protocol seam ADR)

**Interfaces:**

- Consumes: nothing. Documents the additive seam error and runs the whole quality
  bar before the PR opens.

- [ ] **Step 1: Amend ADR-0045 with a dated factual note**

Find the file (`ls docs/adr/ | grep 0045`) and append under a "Consequences" or
"Amendments" heading:

```markdown
### 2026-07-09 — additive `ProviderUnavailableError` (#340 PR1)

#340 PR1 adds one additive error type to the seam,
`alfred.providers.base.ProviderUnavailableError(AlfredError)`. Each adapter maps
its SDK/transport failures (`anthropic`/`openai` API errors, `httpx`) to it at the
adapter boundary so downstream callers — the router and the quarantine child's
`provider_dispatch` — get one typed error instead of the provider-specific
hierarchies. It is deliberately excluded from `router._TOOL_PROTOCOL_ERRORS`
(a transport failure should fall back to the secondary provider). No change to the
frozen `CompletionRequest`/`CompletionResponse` models. This keeps the quarantine
child free of any SDK import (the in-core HTTP-egress import guard).
```

- [ ] **Step 2: Run the markdown lint on the ADR**

```bash
npx --yes markdownlint-cli2 docs/adr/0045-*.md 2>&1 | tail -3
```

Expected: `0 error(s)`.

- [ ] **Step 3: Full quality bar**

```bash
env -u ALFRED_SMOKE_PROVIDER_KEY make check
```

Expected: exit 0 (verify with `echo $?` — a piped `tail` masks the real code).
If macOS integration lanes flake under load, verify the suspect in isolation and
trust Linux CI (per the repo convention).

- [ ] **Step 4: Re-confirm the child dispatcher coverage gate**

```bash
uv run coverage run -m pytest tests/unit/quarantine/test_quarantined_extractor_dispatch.py
uv run coverage report --include='src/alfred/security/quarantine_child/provider_dispatch.py' --fail-under=100
```

Expected: `100%`.

- [ ] **Step 5: Commit**

```bash
git add docs/adr/0045-*.md
git commit -m "docs(340): ADR-0045 amendment — additive ProviderUnavailableError seam error #340

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Self-Review

**Spec coverage (rev.2 §4):**

- §4.1 seam port (native_constrained → `tool_calls[0].arguments`;
  prompt_embedded_fallback → `content`) → Task 2 Steps 4-5.

- §4.2 fork (b) — JSON-object runtime branch removed, Literal member reserved →
  Task 2 Steps 4, 7.

- §4.3 / D1 — `ProviderUnavailableError` seam error, adapters own the mapping,
  `provider_dispatch` imports no SDK, drop `import httpx` → Task 1 + Task 2 Step 6.

- §4.4 behaviour-neutral — `_build_provider`/extract branch untouched, import locks
  green → not modified (Task 3 proves the egress posture).

- Empty `tool_calls` / malformed-args guard (fold 6) → Task 2 Steps 1, 5, 6.
- §4.5 tests — fake full `CompletionResponse` objects, non-vacuous request shape,
  empty-tool_calls, provider_unavailable, adversarial suite, 100% coverage →
  Task 2 + Task 3.

- Accurate `extraction_mode` label (fold: no `native_constrained` overstatement) →
  Task 2 Step 4 routes deepseek-chat to `prompt_embedded_fallback`, so it is never
  labelled `native_constrained`.

- §4.6 ADR note → Task 4.

**Placeholder scan:** every code step carries real code; every run step carries an
exact command + expected output. No TBD/TODO.

**Type consistency:** `ProviderUnavailableError`, `_EXTRACT_TOOL_NAME`,
`extract_structured_data`, `ForcedTool(name=...)`, `ToolCall.arguments`,
`CompletionResponse(content, tokens_in, tokens_out, cost_usd, model, stop_reason,
tool_calls)` are used identically across Tasks 1-4.

**Deferred (documented, NOT this PR):** routing a `TOOL_USE`-but-not-native provider
(deepseek-chat) through a distinctly-labelled tool-use mode (needs a new
`ExtractionMode` member) — noted in Task 2 Step 4's comment and the spec §4.2 fork (b).

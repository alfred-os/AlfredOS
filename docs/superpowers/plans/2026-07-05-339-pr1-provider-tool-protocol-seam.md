# Provider Tool-Protocol Seam (#339 PR1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the frozen provider contract so a `CompletionRequest`/`CompletionResponse` can carry tool-use, and map it through both shipped adapters — with NO orchestrator/loop, tool-registry, or web.fetch wiring (those are PR2/PR3).

**Architecture:** Add provider-neutral tool models to `src/alfred/providers/base.py` (Anthropic content-block shape and OpenAI/DeepSeek `tool_calls[]` shape both normalize to these). Extend the three frozen Pydantic models with additive, default-valued fields so every existing construction is unchanged. Each adapter maps the neutral shape to/from its SDK; a per-role wire serializer replaces the blanket `model_dump()` (which would otherwise 400 the provider). `ProviderCapability.TOOL_USE` is finally wired, and a provider that lacks it refuses loudly rather than 400-ing.

**Tech Stack:** Python 3.14+, Pydantic v2 (frozen, `extra="forbid"`), anthropic SDK, openai SDK (DeepSeek), pytest + `unittest.mock`, `mypy --strict` + `pyright`, `ruff`, Babel (`t()` i18n).

## Global Constraints

- **Python floor `>=3.14.6`**; modern idioms — PEP 604 unions (`X | Y`), PEP 585 builtins (`tuple`, `dict`), PEP 695 type aliases. Never `Optional[X]` / `typing.List`.
- **All new models frozen + `extra="forbid"`**; tuples (`tuple[X, ...]`), never `list`, for the new collection fields.
- **No `Any` without justification.** JSON payloads typed `Mapping[str, object]` (narrow before use); `object` not `Any`.
- **All operator-facing strings via `t()`** (i18n HARD rule). New keys added to `locale/en/LC_MESSAGES/alfred.po`; `pybabel extract → update → compile` after adding a `t()` call. NEVER `--omit-header`.
- **Quality gate:** `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/ && uv run pytest tests/unit/providers -q` must pass. No `--no-verify`.
- **Errors loud at boundaries**, rooted at `AlfredError`. No `except Exception: pass`.
- **Conventional Commits**, every subject contains `#339` (repo required-check regex `.*#[0-9]+.*`). End every commit message body with:
  `MrReasonable <4990954+MrReasonable@users.noreply.github.com>`
- **Owner agent:** `alfred-provider-engineer`. Branch: `339-pr1-provider-tool-protocol-seam` (already created; spec already committed as `5b523543`).

## Implementation convention — official SDK types (maintainer directive)

**Use the official SDK clients AND their typed param/response types — not hand-rolled dicts or `getattr` duck-typing.** The code blocks below show the *runtime* wire shapes (still accurate); construct them via the official TypedDicts, and type the parse helpers with the official response types. This SUPERSEDES the earlier "type parse helpers `Any`" note. Verified against **openai 2.44.0** and **anthropic 0.116.0**.

Key fact that makes this free: the request-param types are **TypedDicts** → constructing via them returns plain runtime dicts, so every MagicMock dict-equality assertion in the tasks below stays valid. And because `self._client` is typed `Any`, the SDK response object is `Any` at the call site → assignable to an official-typed helper param, so the helper's internals are fully typed with **no call-site cast**.

- **DeepSeek/OpenAI** (`from openai.types.chat import ...`):
  - request: `ChatCompletionFunctionToolParam` (tool), `ChatCompletionToolChoiceOptionParam` / `ChatCompletionNamedToolChoiceParam` (tool_choice), and role messages `ChatCompletionSystemMessageParam` / `ChatCompletionUserMessageParam` / `ChatCompletionAssistantMessageParam` (with `ChatCompletionMessageFunctionToolCallParam` in `tool_calls`) / `ChatCompletionToolMessageParam`. `function` payloads use `from openai.types.shared_params import FunctionDefinition` and the tool-call `Function` param.
  - response: `_parse_openai_tool_calls(raw: list[ChatCompletionMessageFunctionToolCall] | None, model)` — import `from openai.types.chat import ChatCompletionMessageFunctionToolCall`; narrow `if tc.type == "function"` before reading `tc.function.name` / `tc.function.arguments`.
- **Anthropic** (`from anthropic.types import ...`):
  - request: `ToolParam`, `ToolChoiceToolParam` / `ToolChoiceAnyParam` / `ToolChoiceAutoParam`, `MessageParam`, and content blocks `TextBlockParam` / `ToolUseBlockParam` / `ToolResultBlockParam`.
  - response: `_parse_anthropic_content(blocks: list[ContentBlock])` — import `from anthropic.types import ContentBlock`; iterate and narrow the discriminated union on `block.type` (`"tool_use"` → `ToolUseBlock` fields `.id/.name/.input`; `"text"` → `TextBlock.text`); ignore other block types.

If a construction can't be expressed cleanly with an official type without contorting the code, fall back to a plain dict for THAT spot and leave a one-line comment saying why — "where possible," not dogmatically.

## File structure

- `src/alfred/providers/base.py` — MODIFY. Add neutral models (`ToolDefinition`, `ToolCall`, `ForcedTool`, `ToolChoice`, `StopReason`), extend `Role`/`Message`/`CompletionRequest`/`CompletionResponse`, add `ProviderToolUnsupportedError` + `ProviderMalformedToolArgumentsError`, add `_openai_tools`/`_openai_message`/`_anthropic_tools`/`_anthropic_messages`/`_map_stop_reason` helpers OR keep adapter-local (decided per task below — serializers live in each adapter module to keep base.py wire-shape-agnostic; only the shared stop-reason and the errors + models live in base.py).
- `src/alfred/providers/deepseek.py` — MODIFY. OpenAI-shape request serialization (per-role) + tools/tool_choice + response `tool_calls`/`finish_reason` parse + JSON-arg parse + `TOOL_USE` cap + refuse-loud guard.
- `src/alfred/providers/anthropic_native.py` — MODIFY. Anthropic content-block request mapping (tools/tool_choice + tool_result/tool_use packing) + response `tool_use`-block parse + `stop_reason` + `TOOL_USE` cap + refuse-loud guard.
- `src/alfred/providers/router.py` — MODIFY. Do NOT fall back on `ProviderToolUnsupportedError` (re-raise loudly); otherwise unchanged pass-through.
- `locale/en/LC_MESSAGES/alfred.po` — MODIFY. Add `providers.tool_use_unsupported` (+ compiled `.mo`).
- `docs/adr/0045-provider-tool-protocol.md` — CREATE. Records the frozen-contract schema change.
- Tests: `tests/unit/providers/test_base.py`, `test_deepseek.py`, `test_anthropic.py`, `test_router.py` — MODIFY (add tool-protocol cases).

**Neutral-model reference (defined in Task 1; every later task consumes these exact names/types):**

```python
Role = Literal["system", "user", "assistant", "tool"]
StopReason = Literal["end_turn", "tool_use", "max_tokens", "stop_sequence", "other"]

class ToolDefinition(BaseModel):      # frozen, extra="forbid"
    name: str
    description: str
    input_schema: Mapping[str, object]

class ToolCall(BaseModel):            # frozen, extra="forbid"
    id: str
    name: str
    arguments: Mapping[str, object]

class ForcedTool(BaseModel):          # frozen, extra="forbid"
    name: str

ToolChoice = Literal["auto", "none", "required"] | ForcedTool

# Message   += tool_calls: tuple[ToolCall, ...] = ();  tool_call_id: str | None = None
# CompletionRequest  += tools: tuple[ToolDefinition, ...] = ();  tool_choice: ToolChoice = "auto"
# CompletionResponse += stop_reason: StopReason = "end_turn";    tool_calls: tuple[ToolCall, ...] = ()

class ProviderToolUnsupportedError(AlfredError): ...          # tools requested, provider lacks TOOL_USE
class ProviderMalformedToolArgumentsError(AlfredError): ...   # provider returned un-parseable tool args
```

---

### Task 1: Neutral tool-protocol models + frozen-contract extension

**Files:**
- Modify: `src/alfred/providers/base.py`
- Test: `tests/unit/providers/test_base.py`

**Interfaces:**
- Consumes: existing `Message`, `CompletionRequest`, `CompletionResponse`, `Role`, `AlfredError` (`from alfred.errors import AlfredError`).
- Produces: the neutral-model reference block above, importable from `alfred.providers.base`.

- [ ] **Step 1: Write the failing tests** in `tests/unit/providers/test_base.py` (append):

```python
from collections.abc import Mapping

import pytest
from pydantic import ValidationError

from alfred.providers.base import (
    CompletionRequest,
    CompletionResponse,
    ForcedTool,
    Message,
    StopReason,
    ToolCall,
    ToolChoice,
    ToolDefinition,
)


def test_backcompat_plain_message_and_request_unchanged() -> None:
    # Existing construction must be untouched: defaults fill the new fields.
    m = Message(role="user", content="hi")
    assert m.tool_calls == ()
    assert m.tool_call_id is None
    req = CompletionRequest(messages=[m])
    assert req.tools == ()
    assert req.tool_choice == "auto"
    res = CompletionResponse(content="ok", tokens_in=1, tokens_out=1, cost_usd=0.0, model="x")
    assert res.stop_reason == "end_turn"
    assert res.tool_calls == ()


def test_tool_role_and_tool_call_models() -> None:
    call = ToolCall(id="c1", name="web.fetch", arguments={"url": "https://a.test"})
    tool_msg = Message(role="tool", content='{"ok": true}', tool_call_id="c1")
    asst = Message(role="assistant", content="", tool_calls=(call,))
    assert tool_msg.role == "tool"
    assert asst.tool_calls[0].name == "web.fetch"


def test_request_carries_tools_and_forced_choice() -> None:
    td = ToolDefinition(name="web.fetch", description="fetch a URL", input_schema={"type": "object"})
    req = CompletionRequest(messages=[Message(role="user", content="x")],
                            tools=(td,), tool_choice=ForcedTool(name="web.fetch"))
    assert req.tools[0].name == "web.fetch"
    assert isinstance(req.tool_choice, ForcedTool)


def test_models_are_frozen_and_forbid_extra() -> None:
    td = ToolDefinition(name="t", description="d", input_schema={})
    with pytest.raises(ValidationError):
        ToolDefinition(name="t", description="d", input_schema={}, bogus=1)  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        td.name = "other"  # type: ignore[misc]
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/providers/test_base.py -q`
Expected: FAIL — `ImportError: cannot import name 'ToolDefinition'`.

- [ ] **Step 3: Implement the models** in `src/alfred/providers/base.py`. Add `from collections.abc import Mapping` and `from alfred.errors import AlfredError` to imports; widen `Role`; add the models + errors; extend the three models:

```python
Role = Literal["system", "user", "assistant", "tool"]
StopReason = Literal["end_turn", "tool_use", "max_tokens", "stop_sequence", "other"]


class ToolDefinition(BaseModel):
    """Provider-neutral tool advertisement. ``input_schema`` is a JSON Schema."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    description: str
    # JSON object typed ``object`` (not ``Any``) so callers narrow before use.
    input_schema: Mapping[str, object]


class ToolCall(BaseModel):
    """A parsed tool-use request from the model, OR its echo in message history."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    name: str
    arguments: Mapping[str, object]


class ForcedTool(BaseModel):
    """``tool_choice`` variant forcing exactly one named tool (used by #340 constrained-gen)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str


# "auto" (model decides) | "none" (no tool call) | "required" (must call some tool)
# | ForcedTool (must call THIS tool).
ToolChoice = Literal["auto", "none", "required"] | ForcedTool


class ProviderToolUnsupportedError(AlfredError):
    """Raised when a request carries ``tools`` but the resolved provider does
    not declare ``ProviderCapability.TOOL_USE``. Refuse loud rather than emit a
    request the provider SDK will 400 on (spec §4.1)."""


class ProviderMalformedToolArgumentsError(AlfredError):
    """Raised when a provider returns tool-call arguments that are not valid
    JSON (DeepSeek returns arguments as a JSON *string*). Fail loud at the
    boundary; the PR3 loop turns this into an error ``tool_result`` (spec §4.3)."""
```

Then extend `Message` (add after `content`):

```python
    # tool_calls populate ONLY on an assistant turn that requested tools;
    # tool_call_id populates ONLY on a role="tool" result message (links the
    # result to the ToolCall.id that produced it). Default-empty so every
    # existing construction is unchanged.
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str | None = None
```

`CompletionRequest` (add after `temperature`):

```python
    tools: tuple[ToolDefinition, ...] = ()
    tool_choice: ToolChoice = "auto"
```

`CompletionResponse` (add after `model`):

```python
    stop_reason: StopReason = "end_turn"
    tool_calls: tuple[ToolCall, ...] = ()
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/unit/providers/test_base.py -q`
Expected: PASS (all, including the pre-existing base tests).

- [ ] **Step 5: Typecheck + lint**

Run: `uv run mypy src/alfred/providers/base.py && uv run ruff check src/alfred/providers/base.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/providers/base.py tests/unit/providers/test_base.py
git commit -m "feat(providers): neutral tool-protocol models + frozen-contract extension (#339)

Adds ToolDefinition/ToolCall/ForcedTool/ToolChoice/StopReason and extends
Message/CompletionRequest/CompletionResponse with additive default-valued
tool fields. No adapter behaviour change yet.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 2: DeepSeek — per-role request serialization + tools/tool_choice

**Files:**
- Modify: `src/alfred/providers/deepseek.py`
- Test: `tests/unit/providers/test_deepseek.py`

**Interfaces:**
- Consumes: Task 1 models; existing `DeepSeekProvider`.
- Produces: `DeepSeekProvider.complete` now sends `tools`/`tool_choice` and per-role-serialized messages (no stray `tool_calls=[]`/`tool_call_id=null` on plain messages).

- [ ] **Step 1: Write the failing tests** (append to `test_deepseek.py`):

```python
from alfred.providers.base import ForcedTool, Message, ToolCall, ToolDefinition


def _openai_ok_response(content: str = "ok"):
    r = MagicMock()
    r.choices = [MagicMock(message=MagicMock(content=content, tool_calls=None), finish_reason="stop")]
    r.usage = MagicMock(prompt_tokens=1, completion_tokens=1)
    return r


@pytest.mark.asyncio
async def test_plain_messages_serialize_without_tool_keys() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=_openai_ok_response())
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    await provider.complete(CompletionRequest(messages=[
        Message(role="system", content="s"), Message(role="user", content="u")]))
    sent = fake_client.chat.completions.create.await_args.kwargs["messages"]
    # Plain messages MUST NOT carry tool_calls / tool_call_id (would 400 DeepSeek).
    assert sent == [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    assert "tools" not in fake_client.chat.completions.create.await_args.kwargs


@pytest.mark.asyncio
async def test_tools_and_tool_role_serialize_to_openai_shape() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=_openai_ok_response())
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    td = ToolDefinition(name="web.fetch", description="fetch", input_schema={"type": "object"})
    call = ToolCall(id="c1", name="web.fetch", arguments={"url": "https://a.test"})
    req = CompletionRequest(
        messages=[
            Message(role="assistant", content="", tool_calls=(call,)),
            Message(role="tool", content='{"ok": true}', tool_call_id="c1"),
        ],
        tools=(td,), tool_choice=ForcedTool(name="web.fetch"))
    await provider.complete(req)
    kw = fake_client.chat.completions.create.await_args.kwargs
    assert kw["tools"] == [{"type": "function", "function": {
        "name": "web.fetch", "description": "fetch", "parameters": {"type": "object"}}}]
    assert kw["tool_choice"] == {"type": "function", "function": {"name": "web.fetch"}}
    assert kw["messages"][0] == {"role": "assistant", "content": "",
        "tool_calls": [{"id": "c1", "type": "function",
                        "function": {"name": "web.fetch", "arguments": '{"url": "https://a.test"}'}}]}
    assert kw["messages"][1] == {"role": "tool", "content": '{"ok": true}', "tool_call_id": "c1"}
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/providers/test_deepseek.py -q -k "serialize"`
Expected: FAIL (messages still built by bare `model_dump()`; no `tools` kwarg).

- [ ] **Step 3: Implement** in `deepseek.py`. Add imports (`json`, the new base symbols). Add module-level serializers and rewrite `complete`'s request build:

```python
def _openai_tools(tools: tuple[ToolDefinition, ...]) -> list[dict[str, object]]:
    return [{"type": "function", "function": {
        "name": t.name, "description": t.description, "parameters": dict(t.input_schema)}}
        for t in tools]


def _openai_tool_choice(choice: ToolChoice) -> object:
    if isinstance(choice, ForcedTool):
        return {"type": "function", "function": {"name": choice.name}}
    return choice  # "auto" | "none" | "required" are native OpenAI values


def _openai_message(m: Message) -> dict[str, object]:
    # Per-role serialization: emit tool fields ONLY on the roles that carry them,
    # so a plain user/system/assistant message never sends tool_calls=[] /
    # tool_call_id=null (which DeepSeek 400s on) — the arch-005/prov-002 fix.
    out: dict[str, object] = {"role": m.role, "content": m.content}
    if m.role == "assistant" and m.tool_calls:
        out["tool_calls"] = [{"id": c.id, "type": "function",
            "function": {"name": c.name, "arguments": json.dumps(dict(c.arguments))}}
            for c in m.tool_calls]
    if m.role == "tool":
        out["tool_call_id"] = m.tool_call_id
    return out
```

Rewrite the `create(...)` call in `complete`:

```python
        kwargs: dict[str, object] = {
            "model": self._model,
            "messages": [_openai_message(m) for m in request.messages],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }
        if request.tools:
            kwargs["tools"] = _openai_tools(request.tools)
            kwargs["tool_choice"] = _openai_tool_choice(request.tool_choice)
        response = await self._client.chat.completions.create(**kwargs)
```

(Response parsing stays as-is for this task; Task 3 upgrades it.)

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/unit/providers/test_deepseek.py -q`
Expected: PASS (new + pre-existing).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/providers/deepseek.py tests/unit/providers/test_deepseek.py
git commit -m "feat(providers): DeepSeek per-role request serialization + tools passing (#339)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 3: DeepSeek — response tool_calls / finish_reason parse (loud on malformed args)

**Files:**
- Modify: `src/alfred/providers/deepseek.py`
- Test: `tests/unit/providers/test_deepseek.py`

**Interfaces:**
- Consumes: Task 1 models + `ProviderMalformedToolArgumentsError`.
- Produces: `complete` returns `CompletionResponse` with `stop_reason` mapped from `finish_reason` and `tool_calls` parsed (JSON-string args → dict; malformed → raise).

- [ ] **Step 1: Write the failing tests** (append to `test_deepseek.py`):

```python
from alfred.providers.base import ProviderMalformedToolArgumentsError


def _openai_toolcall_response(args_json: str):
    tc = MagicMock(id="c1", type="function")
    tc.function = MagicMock(name="web.fetch", arguments=args_json)
    tc.function.name = "web.fetch"
    r = MagicMock()
    r.choices = [MagicMock(message=MagicMock(content=None, tool_calls=[tc]), finish_reason="tool_calls")]
    r.usage = MagicMock(prompt_tokens=3, completion_tokens=2)
    return r


@pytest.mark.asyncio
async def test_response_tool_calls_parsed_and_stop_reason_mapped() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(
        return_value=_openai_toolcall_response('{"url": "https://a.test"}'))
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    res = await provider.complete(CompletionRequest(messages=[Message(role="user", content="x")]))
    assert res.stop_reason == "tool_use"
    assert res.tool_calls == (ToolCall(id="c1", name="web.fetch",
                                       arguments={"url": "https://a.test"}),)
    assert res.content == ""  # content None -> ""


@pytest.mark.asyncio
async def test_plain_text_response_maps_end_turn() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=_openai_ok_response("hello"))
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    res = await provider.complete(CompletionRequest(messages=[Message(role="user", content="x")]))
    assert res.stop_reason == "end_turn"
    assert res.tool_calls == ()
    assert res.content == "hello"


@pytest.mark.asyncio
async def test_malformed_tool_arguments_fail_loud() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(
        return_value=_openai_toolcall_response("{not json"))
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    with pytest.raises(ProviderMalformedToolArgumentsError):
        await provider.complete(CompletionRequest(messages=[Message(role="user", content="x")]))
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/providers/test_deepseek.py -q -k "tool_calls_parsed or end_turn or malformed"`
Expected: FAIL — `CompletionResponse` has no populated `stop_reason`/`tool_calls`; malformed doesn't raise.

- [ ] **Step 3: Implement** in `deepseek.py`. Add the `finish_reason` map + response parse:

```python
_OPENAI_STOP_REASON: dict[str, StopReason] = {
    "stop": "end_turn", "tool_calls": "tool_use", "length": "max_tokens"}


def _parse_openai_tool_calls(raw: Any, model: str) -> tuple[ToolCall, ...]:
    # raw is Any: the OpenAI SDK response flows through ``self._client`` (typed
    # Any, no pinnable Protocol) — same justification as the ctor's ``client:
    # Any``. Typing it ``object`` here would break iteration/attr access under
    # mypy --strict. The RETURN type is concrete, so the boundary stays typed.
    if not raw:
        return ()
    parsed: list[ToolCall] = []
    for tc in raw:
        try:
            args = json.loads(tc.function.arguments)
        except (ValueError, TypeError) as exc:
            raise ProviderMalformedToolArgumentsError(
                t("providers.malformed_tool_arguments", provider="deepseek", model=model)
            ) from exc
        parsed.append(ToolCall(id=tc.id, name=tc.function.name, arguments=args))
    return tuple(parsed)
```

Update the `return CompletionResponse(...)` in `complete`:

```python
        return CompletionResponse(
            content=msg.content or "",
            tokens_in=usage.prompt_tokens,
            tokens_out=usage.completion_tokens,
            cost_usd=_estimate_cost(self._model, usage.prompt_tokens, usage.completion_tokens),
            model=self._model,
            stop_reason=_OPENAI_STOP_REASON.get(response.choices[0].finish_reason, "other"),
            tool_calls=_parse_openai_tool_calls(msg.tool_calls, self._model),
        )
```

Add `from alfred.i18n import t` (module-level is fine here). The `providers.malformed_tool_arguments` key is added in Task 6's i18n step; for now add a placeholder-free msgstr there. (If running this task standalone before Task 6, `t()` returns the key string — harmless; the assertion only checks the exception type.)

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/unit/providers/test_deepseek.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/providers/deepseek.py tests/unit/providers/test_deepseek.py
git commit -m "feat(providers): DeepSeek response tool_calls + finish_reason parse, loud on malformed args (#339)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 4: Anthropic — request mapping (tools/tool_choice + tool-history packing)

**Files:**
- Modify: `src/alfred/providers/anthropic_native.py`
- Test: `tests/unit/providers/test_anthropic.py`

**Interfaces:**
- Consumes: Task 1 models.
- Produces: `AnthropicProvider.complete` sends `tools`/`tool_choice` and packs `role="tool"` history into `user`+`tool_result` blocks and assistant `tool_calls` into `tool_use` blocks.

- [ ] **Step 1: Write the failing test** (append to `test_anthropic.py`):

```python
from alfred.providers.base import ForcedTool, ToolCall, ToolDefinition


def _anthropic_text_response(text: str = "ok"):
    r = MagicMock()
    r.content = [MagicMock(type="text", text=text)]
    r.usage = MagicMock(input_tokens=1, output_tokens=1)
    r.stop_reason = "end_turn"
    return r


@pytest.mark.asyncio
async def test_multi_tool_turn_maps_to_anthropic_blocks() -> None:
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock(return_value=_anthropic_text_response())
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    c1 = ToolCall(id="c1", name="web.fetch", arguments={"url": "https://a.test"})
    c2 = ToolCall(id="c2", name="calc", arguments={"x": 1})
    td = ToolDefinition(name="web.fetch", description="fetch", input_schema={"type": "object"})
    req = CompletionRequest(
        messages=[
            Message(role="user", content="do it"),
            Message(role="assistant", content="working", tool_calls=(c1, c2)),
            Message(role="tool", content='{"ok": true}', tool_call_id="c1"),
            Message(role="tool", content="2", tool_call_id="c2"),
        ],
        tools=(td,), tool_choice=ForcedTool(name="web.fetch"))
    await provider.complete(req)
    kw = fake_client.messages.create.await_args.kwargs
    assert kw["tools"] == [{"name": "web.fetch", "description": "fetch",
                            "input_schema": {"type": "object"}}]
    assert kw["tool_choice"] == {"type": "tool", "name": "web.fetch"}
    msgs = kw["messages"]
    # assistant turn: text block + two tool_use blocks
    assert msgs[1]["role"] == "assistant"
    assert msgs[1]["content"] == [
        {"type": "text", "text": "working"},
        {"type": "tool_use", "id": "c1", "name": "web.fetch", "input": {"url": "https://a.test"}},
        {"type": "tool_use", "id": "c2", "name": "calc", "input": {"x": 1}}]
    # consecutive tool results collapse into ONE user turn of tool_result blocks
    assert msgs[2]["role"] == "user"
    assert msgs[2]["content"] == [
        {"type": "tool_result", "tool_use_id": "c1", "content": '{"ok": true}'},
        {"type": "tool_result", "tool_use_id": "c2", "content": "2"}]
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/providers/test_anthropic.py -q -k "multi_tool"`
Expected: FAIL — no `tools` kwarg; messages are flat `model_dump()`.

- [ ] **Step 3: Implement** in `anthropic_native.py`. Add serializers and rewrite the request build. Anthropic packs consecutive `role="tool"` messages into a single `user` message of `tool_result` blocks:

```python
def _anthropic_tools(tools: tuple[ToolDefinition, ...]) -> list[dict[str, object]]:
    return [{"name": t.name, "description": t.description,
             "input_schema": dict(t.input_schema)} for t in tools]


def _anthropic_tool_choice(choice: ToolChoice) -> dict[str, object]:
    if isinstance(choice, ForcedTool):
        return {"type": "tool", "name": choice.name}
    if choice == "required":
        return {"type": "any"}
    return {"type": "auto"}  # "auto"/"none" -> auto (with "none" we simply omit tools; see below)


def _anthropic_assistant_content(m: Message) -> object:
    if not m.tool_calls:
        return m.content
    blocks: list[dict[str, object]] = []
    if m.content:
        blocks.append({"type": "text", "text": m.content})
    blocks.extend({"type": "tool_use", "id": c.id, "name": c.name, "input": dict(c.arguments)}
                  for c in m.tool_calls)
    return blocks


def _anthropic_messages(messages: list[Message]) -> list[dict[str, object]]:
    """Map neutral chat history to Anthropic's shape. Consecutive tool-result
    messages collapse into ONE user turn carrying tool_result blocks (Anthropic
    requires tool_result blocks in a user message following the tool_use turn)."""
    out: list[dict[str, object]] = []
    pending_results: list[dict[str, object]] = []

    def flush() -> None:
        if pending_results:
            out.append({"role": "user", "content": list(pending_results)})
            pending_results.clear()

    for m in messages:
        if m.role == "tool":
            pending_results.append(
                {"type": "tool_result", "tool_use_id": m.tool_call_id, "content": m.content})
            continue
        flush()
        if m.role == "assistant":
            out.append({"role": "assistant", "content": _anthropic_assistant_content(m)})
        else:  # user
            out.append({"role": m.role, "content": m.content})
    flush()
    return out
```

Rewrite the `complete` request build (system stays as-is; replace the `chat`/`create` lines):

```python
        system = next((m.content for m in request.messages if m.role == "system"), None)
        chat = _anthropic_messages([m for m in request.messages if m.role != "system"])
        kwargs: dict[str, object] = {
            "model": self._model, "system": system, "messages": chat,
            "max_tokens": request.max_tokens, "temperature": request.temperature,
        }
        if request.tools and request.tool_choice != "none":
            kwargs["tools"] = _anthropic_tools(request.tools)
            kwargs["tool_choice"] = _anthropic_tool_choice(request.tool_choice)
        response = await self._client.messages.create(**kwargs)
```

(Response parsing upgraded in Task 5.)

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/unit/providers/test_anthropic.py -q`
Expected: PASS (new + pre-existing text test).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/providers/anthropic_native.py tests/unit/providers/test_anthropic.py
git commit -m "feat(providers): Anthropic request mapping for tools + tool-history packing (#339)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 5: Anthropic — response tool_use-block parse + stop_reason

**Files:**
- Modify: `src/alfred/providers/anthropic_native.py`
- Test: `tests/unit/providers/test_anthropic.py`

**Interfaces:**
- Consumes: Task 1 models.
- Produces: `complete` returns `CompletionResponse` with `stop_reason` mapped and `tool_calls` parsed from `tool_use` blocks (stops discarding them); text still concatenated from text blocks.

- [ ] **Step 1: Write the failing test** (append):

```python
@pytest.mark.asyncio
async def test_response_tool_use_blocks_parsed() -> None:
    fake_client = MagicMock()
    resp = MagicMock()
    text_block = MagicMock(type="text", text="let me fetch")
    tool_block = MagicMock(type="tool_use", id="c1", input={"url": "https://a.test"})
    tool_block.name = "web.fetch"  # MUST set post-ctor: `name=` is a reserved MagicMock kwarg
    resp.content = [text_block, tool_block]
    resp.usage = MagicMock(input_tokens=5, output_tokens=3)
    resp.stop_reason = "tool_use"
    fake_client.messages.create = AsyncMock(return_value=resp)
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    res = await provider.complete(CompletionRequest(messages=[Message(role="user", content="x")]))
    assert res.stop_reason == "tool_use"
    assert res.content == "let me fetch"
    assert res.tool_calls == (ToolCall(id="c1", name="web.fetch",
                                       arguments={"url": "https://a.test"}),)


@pytest.mark.asyncio
async def test_plain_text_response_still_end_turn() -> None:
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock(return_value=_anthropic_text_response("hi"))
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    res = await provider.complete(CompletionRequest(messages=[Message(role="user", content="x")]))
    assert res.content == "hi"
    assert res.stop_reason == "end_turn"
    assert res.tool_calls == ()
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/providers/test_anthropic.py -q -k "tool_use_blocks or still_end_turn"`
Expected: FAIL — `stop_reason`/`tool_calls` not populated.

- [ ] **Step 3: Implement** in `anthropic_native.py`. Add the stop-reason map + block parser and update the `return`:

```python
_ANTHROPIC_STOP_REASON: dict[str, StopReason] = {
    "end_turn": "end_turn", "tool_use": "tool_use",
    "max_tokens": "max_tokens", "stop_sequence": "stop_sequence"}


def _parse_anthropic_content(blocks: Any) -> tuple[str, tuple[ToolCall, ...]]:
    # blocks is Any for the same reason as _parse_openai_tool_calls: the SDK
    # response is Any via ``self._client``. Return type is concrete.
    text_parts: list[str] = []
    calls: list[ToolCall] = []
    for b in blocks:
        if getattr(b, "type", None) == "tool_use":
            calls.append(ToolCall(id=b.id, name=b.name, arguments=dict(b.input)))
        else:
            text_parts.append(getattr(b, "text", ""))
    return "".join(text_parts), tuple(calls)
```

Replace the text-join + `return` in `complete`:

```python
        text, tool_calls = _parse_anthropic_content(response.content)
        usage = response.usage
        return CompletionResponse(
            content=text,
            tokens_in=usage.input_tokens,
            tokens_out=usage.output_tokens,
            cost_usd=_estimate_cost(self._model, usage.input_tokens, usage.output_tokens),
            model=self._model,
            stop_reason=_ANTHROPIC_STOP_REASON.get(response.stop_reason, "other"),
            tool_calls=tool_calls,
        )
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/unit/providers/test_anthropic.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/providers/anthropic_native.py tests/unit/providers/test_anthropic.py
git commit -m "feat(providers): Anthropic response tool_use-block parse + stop_reason (#339)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 6: Wire TOOL_USE capability + refuse-loud guard + router non-fallback + i18n

**Files:**
- Modify: `src/alfred/providers/deepseek.py`, `src/alfred/providers/anthropic_native.py`, `src/alfred/providers/router.py`, `locale/en/LC_MESSAGES/alfred.po`
- Test: `tests/unit/providers/test_deepseek.py`, `test_anthropic.py`, `test_router.py`

**Interfaces:**
- Consumes: Task 1 `ProviderToolUnsupportedError` + `ProviderCapability.TOOL_USE`.
- Produces: capability tables declare `TOOL_USE`; each adapter's `complete` raises `ProviderToolUnsupportedError` if `request.tools` and TOOL_USE absent; router re-raises it (no fallback).

- [ ] **Step 1: Write the failing tests.**

`test_deepseek.py` (append):

```python
from alfred.providers.base import ProviderCapability, ProviderToolUnsupportedError


def test_deepseek_chat_declares_tool_use() -> None:
    assert ProviderCapability.TOOL_USE in DeepSeekProvider._capabilities_for_model("deepseek-chat")


def test_deepseek_reasoner_lacks_tool_use() -> None:
    assert ProviderCapability.TOOL_USE not in DeepSeekProvider._capabilities_for_model("deepseek-reasoner")


@pytest.mark.asyncio
async def test_reasoner_refuses_loud_when_tools_requested() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock()
    provider = DeepSeekProvider(client=fake_client, model="deepseek-reasoner")
    td = ToolDefinition(name="web.fetch", description="f", input_schema={})
    with pytest.raises(ProviderToolUnsupportedError):
        await provider.complete(CompletionRequest(
            messages=[Message(role="user", content="x")], tools=(td,)))
    fake_client.chat.completions.create.assert_not_awaited()  # refuse BEFORE building the request
```

(The Anthropic Task-6 test only checks `capabilities()`; Anthropic always has TOOL_USE so it never refuses — no client-call assertion needed there.)

`test_anthropic.py` (append):

```python
from alfred.providers.base import ProviderCapability


def test_anthropic_declares_tool_use() -> None:
    provider = AnthropicProvider(client=MagicMock(), model="claude-sonnet-4-6")
    assert ProviderCapability.TOOL_USE in provider.capabilities()
```

`test_router.py` (append — router must NOT fall back on a tool-unsupported refusal). Use a `MagicMock` fallback + `assert_not_awaited()` (matches the existing router tests; no leaky class-level state):

```python
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.providers.base import (
    CompletionRequest, Message, ProviderToolUnsupportedError, ToolDefinition,
)
from alfred.providers.router import ProviderRouter


@pytest.mark.asyncio
async def test_router_does_not_fall_back_on_tool_unsupported() -> None:
    primary = MagicMock(name="primary")
    primary.complete = AsyncMock(side_effect=ProviderToolUnsupportedError("no tools"))
    fallback = MagicMock(name="fallback")
    fallback.complete = AsyncMock()
    router = ProviderRouter(primary=primary, fallback=fallback)
    with pytest.raises(ProviderToolUnsupportedError):
        await router.complete(CompletionRequest(
            messages=[Message(role="user", content="x")],
            tools=(ToolDefinition(name="t", description="d", input_schema={}),)))
    fallback.complete.assert_not_awaited()  # capability refusal is loud, not a fallback trigger
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/providers -q -k "tool_use or refuses_loud or does_not_fall_back"`
Expected: FAIL.

- [ ] **Step 3: Implement.**

`deepseek.py` — add `TOOL_USE` to deepseek-chat and a guard at the top of `complete`:

```python
_DEEPSEEK_MODEL_CAPABILITIES: dict[str, frozenset[ProviderCapability]] = {
    "deepseek-chat": frozenset(
        {ProviderCapability.JSON_OBJECT_MODE, ProviderCapability.TOOL_USE}),
    "deepseek-reasoner": frozenset(),
}
```

```python
    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        if request.tools and ProviderCapability.TOOL_USE not in self.capabilities():
            raise ProviderToolUnsupportedError(
                t("providers.tool_use_unsupported", provider=self.name, model=self._model))
        ...  # existing body
```

`anthropic_native.py` — add `TOOL_USE` to `CAPABILITIES` and the same guard:

```python
    CAPABILITIES: frozenset[ProviderCapability] = frozenset(
        {ProviderCapability.NATIVE_CONSTRAINED_GENERATION, ProviderCapability.TOOL_USE})
```

```python
    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        if request.tools and ProviderCapability.TOOL_USE not in self.capabilities():
            raise ProviderToolUnsupportedError(
                t("providers.tool_use_unsupported", provider=self.name, model=self._model))
        ...  # existing body
```

Add `from alfred.i18n import t` and the two new base imports to both modules.

`router.py` — do not fall back on the tool-unsupported refusal:

```python
from alfred.providers.base import (
    CompletionRequest, CompletionResponse, Provider, ProviderToolUnsupportedError,
)
...
        try:
            return await self._primary.complete(request)
        except ProviderToolUnsupportedError:
            # A capability refusal is a loud operator-misconfiguration signal,
            # NOT a transient failure — do NOT silently paper over it by using
            # the fallback for every tool turn (spec §4.1; "no capability routing").
            raise
        except Exception as exc:
            ...  # existing fallback
```

- [ ] **Step 4: Add the i18n keys** to `locale/en/LC_MESSAGES/alfred.po` (append, keeping the `#:` source refs accurate — re-run extract in Step 5 to fix refs):

```
msgid "providers.tool_use_unsupported"
msgstr ""
"Provider {provider} (model {model}) does not support tool use; refusing to "
"advertise tools. Configure a tool-capable primary provider."

msgid "providers.malformed_tool_arguments"
msgstr ""
"Provider {provider} (model {model}) returned tool-call arguments that are not "
"valid JSON."
```

- [ ] **Step 5: Regenerate + compile the catalog** (i18n drift gate; never `--omit-header`):

```bash
uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
uv run pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching
uv run pybabel compile -d locale -D alfred
```

Then hand-fill any msgstr the update blanked (the two keys above) and re-run `compile`.

- [ ] **Step 6: Run to verify pass**

Run: `uv run pytest tests/unit/providers -q`
Expected: PASS (all).

- [ ] **Step 7: Commit**

```bash
git add src/alfred/providers/deepseek.py src/alfred/providers/anthropic_native.py \
        src/alfred/providers/router.py locale/en/LC_MESSAGES/alfred.po \
        locale/en/LC_MESSAGES/alfred.mo tests/unit/providers/
git commit -m "feat(providers): wire TOOL_USE capability + refuse-loud for non-tool primary (#339)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 7: ADR-0045 + full quality gate

**Files:**
- Create: `docs/adr/0045-provider-tool-protocol.md`

- [ ] **Step 1: Write the ADR.** Use the repo's ADR shape (Context / Decision / Consequences / Alternatives). Content anchors:
  - **Context:** the frozen provider contract (`base.py`) could not represent a tool call; #339 needs it. Both wire shapes (Anthropic content-blocks + `stop_reason`; OpenAI/DeepSeek `tool_calls[]` + `finish_reason`) must normalize behind one seam.
  - **Decision:** additive, default-valued tool fields on `Message`/`CompletionRequest`/`CompletionResponse`; a flat internal representation (chosen over content-blocks — DeepSeek is the primary provider); per-role wire serialization; `TOOL_USE` wired with a refuse-loud guard; router stays primary→fallback with the one carve-out that a `ProviderToolUnsupportedError` is not caught into a fallback.
  - **Consequences:** existing single-completion callers unchanged; `provider_dispatch` (quarantine child) will be ported onto this seam in #340; `response_format`/JSON-object constrained-gen deferred to #340; no capability *routing* yet.
  - **Alternatives considered:** content-block internal shape (rejected: heavier storage/migration, primary provider is flat); leaving `provider_dispatch`'s aspirational shape (rejected: no adapter implements it).
  - Reference the design spec `docs/superpowers/specs/2026-07-05-issue-339-llm-tool-calling-design.md` §4/§14.

- [ ] **Step 2: Run the full quality gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/ && uv run pytest tests/unit/providers -q`
Expected: all pass. (If `ruff format --check` flags files, run `uv run ruff format` on the touched files and re-commit.)

- [ ] **Step 3: Commit**

```bash
git add docs/adr/0045-provider-tool-protocol.md
git commit -m "docs(adr): ADR-0045 provider tool-protocol schema change (#339)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

- [ ] **Step 4: Push + open PR**

```bash
git push -u origin 339-pr1-provider-tool-protocol-seam
gh pr create --fill --base main
```

PR body: link the spec + ADR-0045; state scope (PR1 of the #339 series — provider seam only, no loop/registry/web.fetch); note the plan-review lineage. Then run `/review-pr` (full fleet + CodeRabbit) before merge per the standing cadence.

---

### Coverage addenda (from the 2-lens plan-review — add each to the noted task's Step 1)

These close serializer/mapping branch-coverage gaps. Add the test, watch it fail, then confirm it passes (the impl already handles these; the tests lock the branches).

**Task 2 (DeepSeek request) — tool_choice non-Forced branches:**

```python
@pytest.mark.asyncio
@pytest.mark.parametrize("choice,expected", [("auto", "auto"), ("required", "required"), ("none", "none")])
async def test_deepseek_tool_choice_string_variants(choice: str, expected: str) -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=_openai_ok_response())
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    td = ToolDefinition(name="t", description="d", input_schema={})
    await provider.complete(CompletionRequest(
        messages=[Message(role="user", content="x")], tools=(td,), tool_choice=choice))  # type: ignore[arg-type]
    assert fake_client.chat.completions.create.await_args.kwargs["tool_choice"] == expected
```

**Task 3 (DeepSeek response) — finish_reason map:**

```python
@pytest.mark.asyncio
@pytest.mark.parametrize("finish,expected", [("length", "max_tokens"), ("weird", "other")])
async def test_deepseek_finish_reason_map(finish: str, expected: str) -> None:
    r = _openai_ok_response("hi"); r.choices[0].finish_reason = finish
    fake_client = MagicMock(); fake_client.chat.completions.create = AsyncMock(return_value=r)
    res = await DeepSeekProvider(client=fake_client, model="deepseek-chat").complete(
        CompletionRequest(messages=[Message(role="user", content="x")]))
    assert res.stop_reason == expected
```

**Task 4 (Anthropic request) — empty-content assistant (tool-only) + tool_choice branches:**

```python
@pytest.mark.asyncio
async def test_anthropic_tool_only_assistant_omits_empty_text_block() -> None:
    fake_client = MagicMock(); fake_client.messages.create = AsyncMock(return_value=_anthropic_text_response())
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    call = ToolCall(id="c1", name="web.fetch", arguments={"url": "https://a.test"})
    td = ToolDefinition(name="web.fetch", description="f", input_schema={})
    await provider.complete(CompletionRequest(
        messages=[Message(role="assistant", content="", tool_calls=(call,))], tools=(td,)))
    asst = fake_client.messages.create.await_args.kwargs["messages"][0]
    assert asst["content"] == [{"type": "tool_use", "id": "c1", "name": "web.fetch",
                                "input": {"url": "https://a.test"}}]  # NO empty text block


@pytest.mark.asyncio
async def test_anthropic_tool_choice_none_omits_tools_and_auto_required_map() -> None:
    fake_client = MagicMock(); fake_client.messages.create = AsyncMock(return_value=_anthropic_text_response())
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    td = ToolDefinition(name="t", description="d", input_schema={})
    base = [Message(role="user", content="x")]
    await provider.complete(CompletionRequest(messages=base, tools=(td,), tool_choice="none"))
    assert "tools" not in fake_client.messages.create.await_args.kwargs
    await provider.complete(CompletionRequest(messages=base, tools=(td,), tool_choice="auto"))
    assert fake_client.messages.create.await_args.kwargs["tool_choice"] == {"type": "auto"}
    await provider.complete(CompletionRequest(messages=base, tools=(td,), tool_choice="required"))
    assert fake_client.messages.create.await_args.kwargs["tool_choice"] == {"type": "any"}
```

**Task 5 (Anthropic response) — stop_reason map:**

```python
@pytest.mark.asyncio
@pytest.mark.parametrize("stop,expected", [("max_tokens", "max_tokens"),
                                           ("stop_sequence", "stop_sequence"), ("weird", "other")])
async def test_anthropic_stop_reason_map(stop: str, expected: str) -> None:
    r = _anthropic_text_response("hi"); r.stop_reason = stop
    fake_client = MagicMock(); fake_client.messages.create = AsyncMock(return_value=r)
    res = await AnthropicProvider(client=fake_client, model="claude-sonnet-4-6").complete(
        CompletionRequest(messages=[Message(role="user", content="x")]))
    assert res.stop_reason == expected
```

**Task 1/back-compat lock:** the Task 3 `test_plain_text_response_maps_end_turn` and Task 5 `test_plain_text_response_still_end_turn` already assert `stop_reason == "end_turn"` on the plain path — that is the back-compat lock the reviewer asked for; keep both.

---

## Self-review

**Spec coverage (§4/§11 PR1 row):**
- Neutral models — Task 1. ✓
- Additive frozen-field extension — Task 1. ✓
- Per-role wire serialization (the arch-005/prov-002 400 fix) — Task 2 (DeepSeek) + Task 4 (Anthropic). ✓
- DeepSeek tool_calls/finish_reason + JSON-arg parse (loud) — Task 3. ✓
- Anthropic tools/tool_choice + tool_result/tool_use packing incl. **multi-tool round-trip** — Task 4 + Task 5. ✓
- STOP discarding non-text blocks — Task 5. ✓
- `TOOL_USE` wired + refuse-loud for non-tool primary + router non-fallback — Task 6. ✓
- Router pass-through unchanged — Task 6 (only the non-fallback carve-out). ✓
- Happy/error/refusal trio — happy (Tasks 2–5 round-trips), error (Task 3 malformed args), refusal (Task 6 tool-unsupported). ✓
- ADR — Task 7. ✓
- Out of scope confirmed absent: no orchestrator/loop, no ToolRegistry, no web.fetch call, no `response_format`. ✓

**Placeholder scan:** every code/test step shows complete code; commands have expected output. The one forward-reference (Task 3's `t("providers.malformed_tool_arguments")` before Task 6 adds the key) is called out inline and is harmless (key-string fallback; assertion checks the exception type).

**Type consistency:** `ToolCall{id,name,arguments}`, `ToolDefinition{name,description,input_schema}`, `ForcedTool{name}`, `StopReason` literals, `ProviderToolUnsupportedError`, `ProviderMalformedToolArgumentsError` used identically across Tasks 1–7. Serializer names (`_openai_message`, `_openai_tools`, `_openai_tool_choice`, `_parse_openai_tool_calls`, `_anthropic_messages`, `_anthropic_tools`, `_anthropic_tool_choice`, `_anthropic_assistant_content`, `_parse_anthropic_content`) are each defined once in their adapter module.

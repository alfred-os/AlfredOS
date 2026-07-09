# #340 — Real-LLM quarantine child (2c): design

**Status:** DRAFT — holding at the design-approval gate (author proceeded on
best-judgment while the requester was away; do NOT start writing-plans until
ratified).
**Date:** 2026-07-09
**Epic:** [#340](https://github.com/alfred-os/AlfredOS/issues/340) — "Real-LLM
quarantine child (2c) — real provider extract over the audited egress proxy".
**Depends on:** Spec C epic #333 (the L7 egress proxy) — COMPLETE.
**Relates to:** #339 (LLM tool-calling — defined the provider seam this ports
onto; CLOSED), #338 (real privileged turn — PR2 merged, its HARD#5 provenance
test must be re-validated here), #251 (child-IO swallows child stderr), #269
(arm64 `/lib64` real-bwrap-spawn portability).

---

## 1. What this is

The quarantine child is the dual-LLM structured extractor — the **only**
component that ever touches raw T3 (untrusted) content. Today it runs a
**deterministic-echo** loop: a real bwrapped subprocess over the real wire, but
no LLM call and no network (`--unshare-net`, empty netns). #340 graduates it to
a **real provider call** over the audited Spec-C gateway egress proxy.

This is the "2c real-LLM quarantine child" explicitly carved **out of Spec C**
by maintainer co-sign (Spec C design doc decision 9 / §12): Spec C gave the echo
child `--unshare-net` immediately (closing its #230 egress hole); the real-LLM
go-live keeps **its own human sign-off**.

## 2. Verified current state (anchors, confirmed against the tree 2026-07-09)

- **The live child echoes.** `src/alfred/security/quarantine_child/__main__.py`:
  `_build_provider(key)` returns a `_DeterministicProvider()` sentinel (reads +
  scrubs the fd-3 key, builds **no** network client); `_run_mcp_server`'s extract
  branch calls `_echo_extracted_frame(context)` and **never** reaches
  `handle_extract` → `provider_dispatch`. The echo is not a host-fabricated
  extraction (HARD #7): the real subprocess produces it itself over the real wire.
- **`provider_dispatch.py` is real but dead + aspirational-shaped.**
  `dispatch_extraction` (the seam `handle_extract` binds to) calls
  `provider.complete(messages=[dict], tools=[dict], tool_choice=dict,
  response_format=dict)` and reads `response.tool_use_input` / `response.content`
  (`_call_provider`, `provider_dispatch.py:284-342`). **No shipped adapter
  implements that shape.** It is imported LAZILY (in-function) so its `httpx`
  import stays off the echo loop's module-scope closure.
- **The #339 unified provider seam (the real target):** `provider.complete(
  CompletionRequest) -> CompletionResponse`.
  `CompletionRequest(messages: tuple[Message,...], tools: tuple[ToolDefinition,
  ...], tool_choice)`; `ToolDefinition(name, description, input_schema:
  Mapping[str,object])`; `ForcedTool(name)`; `CompletionResponse(content: str,
  stop_reason, tool_calls: tuple[ToolCall,...])`; `ToolCall(name, arguments:
  Mapping[str,object])`. **There is no `response_format` field and no
  `tool_use_input` attribute.** (`src/alfred/providers/base.py`.)
- **Capabilities (real adapters):** `AnthropicProvider.capabilities() =
  {NATIVE_CONSTRAINED_GENERATION, TOOL_USE}`; `deepseek-chat =
  {JSON_OBJECT_MODE, TOOL_USE}`; `deepseek-reasoner` has neither (no tool-use).
  **No shipped provider is JSON-object-only** — every constrained-capable
  provider today also declares `TOOL_USE`.
- **Default quarantine provider = Anthropic Haiku** (`config/routing.yaml`
  `[quarantine]`: `provider: anthropic`, `model: claude-haiku-3-5`,
  `secret_id: quarantine_provider_api_key`). Provider MUST differ from the
  privileged provider (`assert_provider_separation`).
- **The egress topology is already locked by the shipped bwrap policy.**
  `config/sandbox/quarantined-llm.linux.bwrap.policy:100-108`: the 2c child stays
  in the empty netns and reaches the provider **"PROVIDER-ONLY through the
  gateway L7 CONNECT proxy — NOT by re-opening this namespace."** Dropping `net`
  from the unshare set is refused by the closed-egress anchor gate
  (`tests/adversarial/sandbox_escape/test_quarantined_llm_not_yet_spawned_while_egress_open.py`).
  The epic body names the mechanism: **"empty-netns + SCM_RIGHTS fd-broker."**
- **Two import locks constrain the child:** (a) the module-scope import-closure
  guard `tests/unit/security/test_quarantine_child_import_closure.py`
  (`_FORBIDDEN_ROOTS` = `alfred.audit/core/memory/orchestrator/security.{secrets,
  capability_gate,dlp}` — `alfred.providers` is NOT forbidden); (b) the go-live
  egress gate (`test_quarantined_llm_not_yet_spawned_while_egress_open.py`) that
  keeps the egress-capable (`httpx`/SDK) import LAZY, off the echo loop's
  module-scope closure. Also the tree-wide in-core HTTP-egress AST import-guard
  (Spec C) forbids constructing `httpx.AsyncClient`/provider-SDK clients in
  `src/alfred/` outside an allowlist.
- **Provenance premise to re-validate (#338 PR2, ADR-0049 Neutral consequence):**
  `tests/integration/comms_mcp/test_real_turn_inbound_boundary.py` proves HARD #5
  using a schema-extracting child **double** whose premise is "the echo child
  makes extracted T2 text byte-for-byte equal to the raw T3 body, and the marker
  rides a schema-dropped framing key." When the real extractor lands, extracted
  T2 no longer equals raw T3 — the test must be re-anchored on the real
  extractor's schema or the HARD #5 proof silently weakens.

## 3. Goal & decomposition

**Goal.** The quarantine child makes a real provider call over the audited
gateway egress proxy to extract structured data from T3, preserving: the strict
empty-netns isolation model, single-use `ContentHandle` / `tag_t3_with_nonce`
invariants, HARD #5 (the privileged planner never sees raw T3), and fail-loud
audit on every failure path. Flip the unset-provider-key behaviour from the
current go-live note → **refuse-boot**.

**Decomposition (2 PRs — machinery → go-live).** Mirrors the #338 PR1/PR2 and
2a/2b "machinery ahead of caller" precedent. The human sign-off gate falls on the
go-live PR only.

- **PR1 — provider-seam reconciliation (this spec's detailed subject).** Port
  `provider_dispatch.py` off the aspirational `.complete(response_format=)` /
  `.tool_use_input` shape onto the real #339 `CompletionRequest` /
  `CompletionResponse` seam. Prove the three dispatch branches + retry +
  validation against a **fake seam-conforming provider**. NO real SDK import, NO
  network, NO child-loop change → behaviour-neutral (echo stays the live path;
  every isolation lock intact). Normal cadence, no sign-off gate.
- **PR2 — go-live (sketched in §5; its own detailed spec at plan time).** The
  SCM_RIGHTS fd-broker egress topology (empty netns preserved); `_build_provider`
  builds the real adapter (lazy import; invert the egress-capable-import gate + the
  in-core import-guard allowlist under the sign-off gate); swap the extract branch
  to `handle_extract`; flip unset-key → refuse-boot; re-validate the HARD #5
  provenance test against the real schema; adversarial corpus; **human sign-off**.

_PR2 may itself split (topology mechanism vs cutover) if the fd-broker proves
large — decide at PR2 plan time._

## 4. PR1 — provider-seam reconciliation (detailed)

### 4.1 The gap

`provider_dispatch._call_provider` speaks a provider shape no adapter implements.
PR1 rewrites it to the #339 seam. The extractor's three `ExtractionMode` branches
map as:

| ExtractionMode | Today (aspirational) | #339 seam target |
| --- | --- | --- |
| `native_constrained` | `complete(tools=[{name,description,input_schema}], tool_choice={type:tool,name})` → `response.tool_use_input` | `complete(CompletionRequest(tools=(ToolDefinition(name, description, input_schema=schema),), tool_choice=ForcedTool(name)))` → `response.tool_calls[0].arguments` |
| `prompt_embedded_fallback` | `complete(messages=[...])` → `response.content` | `complete(CompletionRequest(messages=(Message(role="user", content=prompt),)))` → `response.content` |
| `json_object_unconstrained` | `complete(response_format={type:json_object})` → `response.content` | **no seam expression** — see §4.2 |

`native_constrained` and `prompt_embedded_fallback` map cleanly. The `arguments`
mapping is re-serialised to a JSON string (parity with the other branches, feeding
`_validate_response`).

### 4.2 The JSON_OBJECT_MODE fork (the one real PR1 decision)

The #339 seam has no `response_format`, so the DeepSeek JSON-object branch cannot
be expressed on it. Three options:

- **(a) Extend the seam.** Add an additive-optional `response_format` to
  `CompletionRequest` (default `None`, `extra="forbid"` preserved) + honour it in
  the DeepSeek adapter. Faithful to the 3-mode model; but re-opens the frozen,
  security-reviewed #339 provider models → needs an ADR (provider-seam change) and
  widens blast radius to the privileged provider path.
- **(b) RECOMMENDED — reconcile the constrained path to tool-use.** Select the
  tool-use (`native_constrained`) shape when the provider declares
  `NATIVE_CONSTRAINED_GENERATION` **or** `TOOL_USE`; else
  `prompt_embedded_fallback`. This covers every shipped constrained-capable
  provider (Anthropic + `deepseek-chat` both declare `TOOL_USE`), so **no live
  capability is lost today** — no shipped provider is JSON-object-only. Retain the
  `json_object_unconstrained` member in the `ExtractionMode` Literal (no closed-
  vocab removal, no audit-row churn) but mark it unreachable-by-selection with a
  note; real `response_format` support is deferred to option (a) if/when a
  JSON-object-only provider ever ships. No frozen-seam change; smallest blast
  radius; aligns with the default (Anthropic tool-use) and #339's `TOOL_USE`
  wiring.
- **(c) Keep the aspirational json_object branch.** Rejected — that is the
  "shape no adapter implements" problem PR1 exists to fix.

**Recommendation: (b).** Flag for ratification (§6).

### 4.3 Error reconciliation

Today `dispatch_extraction` catches `httpx.HTTPError` → `TypedRefusal(reason=
"provider_unavailable")`, distinct from `cannot_extract` (model-output failure).
On the #339 seam the adapter's `complete()` raises provider errors, not raw
`httpx.HTTPError`. PR1 must decide the provider-unavailable surface:

- Retry-eligible (unchanged): only `pydantic.ValidationError` +
  `json.JSONDecodeError`.
- Map transport/HTTP failures raised by the adapter (SDK/`httpx` errors that reach
  through `complete()`) → `provider_unavailable`. The exact exception surface of a
  #339 adapter on a network failure is confirmed at implementation (the adapters
  wrap the SDK; the SDK raises `anthropic`/`openai` API errors and/or `httpx`
  errors). Keep `httpx.HTTPError` in the catch set as defence-in-depth if it can
  still surface; add the adapter's typed transport error(s).
- Everything else propagates (HARD #7 — no silent swallow of unexpected failures).

This likely lets PR1 drop the direct `import httpx` from `provider_dispatch.py` in
favour of the provider-layer error types (confirm at implementation).

### 4.4 Behaviour-neutral invariant (what PR1 does NOT touch)

- **`_build_provider` still returns `_DeterministicProvider()`** — no real client,
  no SDK import, no network. The live child stays echo, byte-for-byte.
- **`_run_mcp_server`'s extract branch stays `_echo_extracted_frame`** — the swap
  to `handle_extract` is go-live (PR2).
- **All import locks stay green:** the module-scope import-closure delta is
  unchanged (provider_dispatch stays lazy); the egress-capable-import gate stays
  green (no SDK/`httpx` client on the echo loop's closure); the in-core AST
  import-guard is untouched (no new client construction).
- **The host-side `QuarantinedExtractor` (`quarantine.py:404`) is untouched** —
  PR1 is child-internal (`provider_dispatch.py`).

### 4.5 Testing (PR1)

- Unit-test `dispatch_extraction` + `_call_provider` against a **fake
  seam-conforming provider** (implements `.capabilities()` + `.complete(
  CompletionRequest) -> CompletionResponse`): happy path per branch (tool-use,
  fallback), retry-then-succeed, retry-exhaustion → `cannot_extract`,
  provider-error → `provider_unavailable`, malformed-args → retry, back-off
  budget breach → `cannot_extract`. Assert the `CompletionRequest` the fake
  received has the right shape (ForcedTool name, input_schema) — non-vacuous.
- Assert **no** import-closure / egress-gate regression (the existing guards run
  unchanged and stay green).
- 100% line + branch on `provider_dispatch.py` (it is under the child security
  surface — confirm the coverage gate include-path).

### 4.6 Files touched (PR1)

- `src/alfred/security/quarantine_child/provider_dispatch.py` — the reconciliation
  (`_call_provider`, error handling, capability selection).
- `src/alfred/security/quarantine.py` — only if the `ExtractionMode`
  selection/note changes (option b keeps the Literal; a doc note on the
  unreachable member).
- `tests/unit/security/…` — the fake-provider dispatch tests.
- ADR only if option (a) is chosen (seam change). Option (b) needs no ADR (a note
  on ADR-0045/the #339 seam docs suffices).

## 5. PR2 — go-live (sketch; detailed spec at PR2 plan time)

The security go-live. Carries the **human sign-off gate** (do NOT self-certify).

- **Egress topology — the SCM_RIGHTS fd-broker (crux; maintainer-cosign-level).**
  The child stays `--unshare-net` (empty netns — the bwrap policy forbids
  re-opening it). The child MUST make the call itself (it holds both the T3
  content and the fd-3 key; the core making the call would put raw T3 in the
  privileged process — HARD #5). So only _reachability_ is brokered: the core (the
  sanctioned reacher of the gateway proxy via the EgressClient path) opens the
  connection toward `alfred-gateway:8889`, and passes a connected socket fd to the
  child via `SCM_RIGHTS` (peer of the fd-3 key channel). The child speaks the
  CONNECT handshake + TLS + HTTP over the passed fd; the gateway enforces the
  destination allowlist + audits the CONNECT. Open sub-questions for the PR2 spec:
  how the provider SDK / `httpx` is made to use a pre-connected socket (a custom
  transport, vs a minimal hand-rolled HTTP-over-fd client for the single
  extraction request); per-call vs pooled sockets; timeout/teardown ownership.
  Alternatives to weigh at PR2 (all worse against the locked policy): drop
  `--unshare-net` and rely on `internal:true` (over-widens the child to all
  internal datastores + reverses the sbx-2026-005 gate) — rejected by the policy;
  a dedicated scoped netns (heavy; slirp/pasta already rejected in Spec C).
- **`_build_provider(key)` builds the real adapter** (Anthropic Haiku per
  `routing.yaml`) from the fd-3 key, LAZILY (keep it off the module-scope
  closure). This makes the child egress-capable → **invert** the egress-capable-
  import gate (like the sbx-2026-005 flip in G7-1a) and allowlist the child's
  client construction in the in-core AST import-guard. Security-boundary change →
  adversarial suite release-blocking.
- **Swap the extract branch** `_echo_extracted_frame` → `handle_extract(...)` →
  `dispatch_extraction` → the real provider over the brokered socket.
- **Refuse-boot flip:** an unset/absent `quarantine_provider_api_key` (the fd-3
  key) flips from the 2b placeholder-fallback to a **loud refuse-boot** (audited),
  per the policy go-live note + the `daemon_runtime` docstring.
- **HARD #5 provenance re-validation:** re-anchor
  `test_real_turn_inbound_boundary.py` — with the real extractor, extracted T2 is
  a schema-shaped object (`CommsBodyExtraction {text, intent}`), NOT the raw T3
  body byte-for-byte, so the marker must ride a field the real schema drops, and
  the assertion must prove the raw-T3 marker is absent from the planner request
  while the schema-valid extract reaches it. (ADR-0049 recorded this as owed.)
- **Adversarial + audit:** provider-response-parsing containment (a crafted
  streamed response cannot escalate beyond the sandbox); egress is exactly the
  brokered CONNECT and no more; fail-loud on spawn/fd/timeout/parse.
- **Dependency watch:** #251 (child-IO swallows child stderr — blind failures make
  a real child hard to debug; consider landing first) and #269/arm64 (the real
  child amplifies the `/lib64` hard-bind arch sensitivity).

## 6. Open decisions to ratify

1. **Decomposition = Option A (2 PRs, machinery → go-live).** Best-judgment while
   away; matches #338/2a-2b precedent. (Alternatives considered: 3 PRs isolating
   the fd-broker; topology-first; one PR — see the AskUserQuestion options.)
2. **PR1 JSON_OBJECT_MODE fork = option (b)** (reconcile constrained path to
   tool-use; retain the unreachable Literal member; defer `response_format` seam
   extension). Best-judgment; the alternative (a, extend the frozen seam) is
   available if you prefer to preserve a live json-object mode.
3. **PR2 egress topology = SCM_RIGHTS fd-broker, empty-netns preserved.**
   Constrained by the shipped bwrap policy; **maintainer-cosign-level** — surfaced
   here, decided in the PR2 spec, and gated by the go-live human sign-off.

## 7. Security & risk notes

- **HARD #5** is the whole point: raw T3 lives only in the child; only the
  schema-shaped `ExtractionResult` crosses back. PR1 does not move that boundary
  (still echo). PR2 must prove it against the real schema (§5).
- **HARD #7:** every failure path in the real dispatch audits/refuses loudly —
  `provider_unavailable`, `cannot_extract`, spawn/fd/timeout/parse. No silent
  swallow.
- **The go-live is the first live quarantine-child egress.** Honour the
  connectivity-free-core / gateway-sole-egress-plane invariant: the child never
  `connect()`s; it reads/writes a brokered socket the core opened toward the
  gateway proxy.
- **PR1 risk is low** (network-free, behaviour-neutral, echo stays live). **PR2
  risk is high** (security go-live) — hence the isolated sign-off gate.

## 8. Out of scope

- The tools-on epic (#410 — egress tools / `build_tool_registry` live-wire /
  deterministic-replay journal). Tool **results** are T3 and re-enter via this
  extractor, but the two epics are distinct and must not be bundled.
- The privileged real turn (#338 — merged).
- Provider-model config changes to `routing.yaml` (human-gated via state.git).
- Per-user / per-day extraction quotas (a later slice).

# #340 — Real-LLM quarantine child (2c): design

**Status:** rev.2 — shape RATIFIED (Option A + fork (b) + D1 + D2, 2026-07-09);
8-lens /review-plan folded (see "Plan-review outcome" below). Ready for
writing-plans on PR1.
**Date:** 2026-07-09
**Epic:** [#340](https://github.com/alfred-os/AlfredOS/issues/340) — "Real-LLM
quarantine child (2c) — real provider extract over the audited egress proxy".
**Depends on:** Spec C epic #333 (the L7 egress proxy) — COMPLETE.
**Relates to:** #339 (LLM tool-calling — defined the provider seam this ports
onto; CLOSED), #338 (real privileged turn — PR2 merged, its HARD#5 provenance
test must be re-validated here), #251 (child-IO swallows child stderr), #269
(arm64 `/lib64` real-bwrap-spawn portability).

---

## Plan-review outcome (rev.2 — 8-lens /review-plan, folded)

An 8-lens `/review-plan` fleet (architect, reviewer, test, security, provider,
core, devops, ai-expert) reviewed rev.1. **0 Critical; the shape — Option A
(2 PRs) + fork (b) — was endorsed by every lens; all anchors verified; security
confirmed the HARD #5 reasoning is "correct and complete" (no T3-to-planner leak
path).** The corroborated High/Medium findings are folded below; these folds
OVERRIDE the rev.1 body where they conflict.

**Ratified decisions:**

- **D1 — PR1 makes ONE minimal additive seam change.** Add
  `ProviderUnavailableError` (additive, `extra="forbid"`-preserving) to
  `src/alfred/providers/base.py`; adapters map their SDK/transport errors
  (`anthropic`/`openai` API errors, `httpx`) to it at the adapter boundary — so
  `provider_dispatch.py` never imports an SDK (which the in-core import guard
  forbids). "PR1 = zero seam change" (rev.1 §4.4) is corrected to "one small
  additive error type." Fork (b) otherwise stands (no `response_format`).
- **D2 — the fd-broker is bigger than rev.1 sketched; a feasibility SPIKE
  precedes PR2, and PR2 SPLITS** into (PR2a) the topology mechanism and (PR2b)
  the cutover. The spike de-risks httpx-over-a-passed-socket before ratifying the
  PR2 shape.

**High folds:**

1. **§4.3 rewritten (D1).** Real adapters raise raw `anthropic`/`openai` SDK
   errors, not `httpx.HTTPError`; the router uses a broad `except Exception`.
   Mapping `provider_unavailable` by importing those SDK types into
   `provider_dispatch.py` trips the in-core HTTP-egress import guard. → the
   `ProviderUnavailableError` seam type (D1) is the fix; adapters own the mapping.
2. **§5 fd-broker honest-framing.** fd 3 is a one-shot **pipe** and cannot carry
   `SCM_RIGHTS`; brokering a connected socket needs a NEW inherited fd → a
   `keep_fds`/`pass_fds` **bwrap-policy edit** (today `keep_fds=[3]` with
   `kind_full_requires_keep_fd_3` parse-validation). "Peer of the fd-3 key
   channel" misleads (fd-3 is once-at-spawn; this is per-connection). The core
   raw-socket + `SCM_RIGHTS` primitive is NET-NEW and no existing guard covers it
   (`import socket` is allowed). The SDK's connection-pool + `max_retries` fights
   a single handed socket → an httpx-over-fd transport (or a hand-rolled
   single-request HTTP client) is required. Needs an **ADR** (ADR-0040
   connectivity-free-core touchpoint) the rev.1 body did not anticipate.
3. **HARD #5 provenance premise corrected (§2/§5).** The current
   `test_real_turn_inbound_boundary.py` ALREADY uses `_ExtractionAwareChildDouble`
   (schema-shaped `CommsBodyExtraction{text,intent}` projection, marker on the
   schema-dropped `__injected_frame__` key) — NOT a byte-for-byte echo double, and
   the child is substituted via a monkeypatched `_fake_spawn`, so it does NOT
   mechanically break under the real extractor. The launch-brief / ADR-0049 note /
   rev.1 §2 all overstated this. The genuinely-owed work is narrower: keep the
   double faithful to the REAL extractor output schema + add a nightly real-LLM
   smoke; and do NOT conflate "the planner never sees unmediated raw T3" (proven,
   structural) with "the LLM's schema-valid OUTPUT is injection-free" (see fold 9).
4. **Stale model id (PR2 prerequisite).** `config/routing.yaml` pins
   `claude-haiku-3-5`, but `_ANTHROPIC_PRICING` (anthropic_native.py:58-60) knows
   only `claude-haiku-4-5`; an unknown model falls back to the most-expensive
   (opus) tariff and will likely 404 at go-live. PR2 must correct/validate the id
   (human-gated config) + run a real-provider connectivity smoke before cutover.
5. **Timeout hierarchy (PR2).** The child's extraction budget
   `_MAX_TOTAL_WALL_CLOCK_SECONDS = 30` equals `action_deadline_seconds = 30` (the
   "well under" code comment is wrong), AND the host `_READ_FRAME_TIMEOUT_S = 15`
   (`quarantine_child_io.py:112`) is TIGHTER than the child's 30s budget → a real
   (slow/retrying) extraction is torn as a spurious `transport_failed`. PR2 must
   define a coherent hierarchy (read-frame > extraction budget < action deadline;
   the SDK 60s read timeout fits inside).
6. **Empty `tool_calls` guard (PR1).** `response.tool_calls[0].arguments` crashes
   with `IndexError` when the forced-tool response is `max_tokens`-truncated
   (`tool_calls` is non-empty only when `stop_reason=="tool_use"`) or the args are
   malformed (`ProviderMalformedToolArgumentsError` on deepseek-chat under fork b)
   — and an uncaught crash SKIPS the audit write (HARD #7). PR1 guards empty
   `tool_calls` / malformed args → `cannot_extract`; add to §4.5.
7. **Option (b) coverage (§4.2).** A "retained-but-unreachable" runtime branch
   cannot hit the §4.5 100%-line+branch target without a `# pragma: no cover`
   hole. → PR1 REMOVES the `json_object_unconstrained` runtime dispatcher branch;
   the `ExtractionMode` Literal member is kept type-only-reserved (a doc note),
   not selected at runtime.
8. **`max_tokens` unwired (PR2).** `CompletionRequest.max_tokens` defaults to 1024
   (base.py:213); `routing.yaml`'s `max_tokens_per_extraction: 8192` is never
   threaded onto the seam → real extractions truncate, and the "raises
   TypedRefusal on breach" routing.yaml comment is a false promise. PR2 wires it.
9. **Adversarial: the "T3 steers the extraction" threat (PR2).** A real model
   introduces a jailbroken-but-schema-valid mis-extraction / field-evasion threat
   the echo child structurally never had, and the extraction prompt has no
   untrusted-input framing (`_build_extraction_prompt` concatenates raw T3 after
   the schema in a single user message). HARD #5 still holds (integrity, not
   escalation) → High, not Critical. PR2's adversarial corpus must cover it beyond
   "provider-response-parsing containment."

**Medium folds:**

- **#251 (child stderr swallow) is a hard PR2 predependency** — an unread stderr
  PIPE is a pipe-buffer-stall CORRECTNESS risk under a chatty real child, not
  just a debugging-ease nicety.
- **CA-cert bundle bind (PR2 bwrap policy).** The echo child made no TLS; the real
  child does. The policy binds `/usr,/lib,/lib64` and no `/etc` → no CA trust
  store. PR2's policy edit adds a CA-cert bundle bind (alongside the arm64
  `/lib64` #269 concern).
- **Refuse-boot detail (PR2).** Needs a typed error + a `_BootFailure` carrier /
  `failure_reason` Literal + a `t()` message + an except-arm at the
  `_commands.py` boot call-site (mirror the `QuarantineChildSpawnError` arm),
  driven by host-side broker resolution BEFORE spawn — not a local raise.
- **Cost channel (PR2).** `CompletionResponse` carries `tokens_in/tokens_out/
  cost_usd` (base.py:234-237); the extraction wire must thread that into the turn
  cost model so the now-billable quarantine call is attributed (honour the #339
  cost model — turn total = Σ `cost_actual` / `subject.turn_cost_usd`).
- **Audit `extraction_mode` label.** Under fork (b), labelling deepseek-chat
  tool-use as `native_constrained` overstates the provider guarantee — use an
  accurate mode label (the native-constrained guarantee is Anthropic-only).
- **§4.5 states the adversarial suite runs** (PR1 edits `src/alfred/security/`).

**Low folds (anchor/precision):** `QuarantinedExtractor` is at `:406` (not
`:404`); `CompletionRequest.messages` is `list[Message]` (not `tuple`);
`CompletionResponse` requires `content, tokens_in, tokens_out, cost_usd, model`
(the fake provider must build full responses); reconcile the `#230`-anchored
policy/README/gate references vs the `#340` framing at go-live; document the
silent-degradation note for a future JSON-object-only provider under (b).

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
  `CompletionRequest(messages: list[Message], max_tokens: int = 1024, tools:
  tuple[ToolDefinition, ...], tool_choice)`; `ToolDefinition(name, description,
  input_schema: Mapping[str,object])`; `ForcedTool(name)`; `CompletionResponse(
  content: str, tokens_in, tokens_out, cost_usd, model, stop_reason, tool_calls:
  tuple[ToolCall,...])` (the response carries cost — see fold: cost channel);
  `ToolCall(name, arguments: Mapping[str,object])`. `tool_calls` is guaranteed
  non-empty ONLY when `stop_reason=="tool_use"` (a model_validator enforces it) —
  so a `max_tokens`-truncated forced-tool response has empty `tool_calls` (fold 6).
  **There is no `response_format` field and no `tool_use_input` attribute.**
  (`src/alfred/providers/base.py`.)
- **Capabilities (real adapters):** `AnthropicProvider.capabilities() =
  {NATIVE_CONSTRAINED_GENERATION, TOOL_USE}`; `deepseek-chat =
  {JSON_OBJECT_MODE, TOOL_USE}`; `deepseek-reasoner` has neither (no tool-use).
  **No shipped provider is JSON-object-only** — every constrained-capable
  provider today also declares `TOOL_USE`.
- **Default quarantine provider = Anthropic Haiku** (`config/routing.yaml`
  `[quarantine]`: `provider: anthropic`, `model: claude-haiku-3-5` — **STALE, fold
  4:** the adapter's pricing table knows only `claude-haiku-4-5`, so this id 404s /
  falls back to the opus tariff at go-live; PR2 prerequisite to correct + validate,
  `secret_id: quarantine_provider_api_key`). Provider MUST differ from the
  privileged provider (`assert_provider_separation`).
- **The egress topology INTENT is locked by the shipped bwrap policy; the
  MECHANISM is net-new (rev.2, fold 2).**
  `config/sandbox/quarantined-llm.linux.bwrap.policy:100-108`: the 2c child stays
  in the empty netns and reaches the provider **"PROVIDER-ONLY through the
  gateway L7 CONNECT proxy — NOT by re-opening this namespace."** Dropping `net`
  from the unshare set is refused by the closed-egress anchor gate
  (`tests/adversarial/sandbox_escape/test_quarantined_llm_not_yet_spawned_while_egress_open.py`).
  The epic names the mechanism ("empty-netns + SCM_RIGHTS fd-broker") but the
  policy does NOT provide the fd-passing plumbing: fd 3 is a one-shot pipe, so a
  brokered socket needs a new inherited fd + a `keep_fds`/`pass_fds` policy edit
  (fold 2) — the mechanism is designed in PR2 after a feasibility spike (D2).
- **Two import locks constrain the child:** (a) the module-scope import-closure
  guard `tests/unit/security/test_quarantine_child_import_closure.py`
  (`_FORBIDDEN_ROOTS` = `alfred.audit/core/memory/orchestrator/security.{secrets,
  capability_gate,dlp}` — `alfred.providers` is NOT forbidden); (b) the go-live
  egress gate (`test_quarantined_llm_not_yet_spawned_while_egress_open.py`) that
  keeps the egress-capable (`httpx`/SDK) import LAZY, off the echo loop's
  module-scope closure. Also the tree-wide in-core HTTP-egress AST import-guard
  (Spec C) forbids constructing `httpx.AsyncClient`/provider-SDK clients in
  `src/alfred/` outside an allowlist.
- **Provenance test (#338 PR2, ADR-0049) — CORRECTED in rev.2 (fold 3):**
  `tests/integration/comms_mcp/test_real_turn_inbound_boundary.py` ALREADY uses
  `_ExtractionAwareChildDouble` — a schema-shaped `CommsBodyExtraction{text,intent}`
  projection with the marker on the schema-dropped `__injected_frame__` key, NOT a
  byte-for-byte echo double — and substitutes the child via a monkeypatched
  `_fake_spawn`. So it does **not** mechanically break under the real extractor.
  The owed work is narrower: keep the double faithful to the real extractor's
  output schema + add a nightly real-LLM smoke. (The launch-brief / ADR-0049 note
  overstated the "T2 == raw T3 byte-for-byte" premise.)

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
  `CompletionResponse` seam, plus ONE additive seam error
  (`ProviderUnavailableError`, D1). Prove the dispatch branches + retry +
  validation against a **fake seam-conforming provider**. NO real SDK import in the
  child, NO network, NO child-loop change → behaviour-neutral on the live path
  (echo stays live; every isolation lock intact). Normal cadence, no sign-off gate.
- **Spike (D2) — fd-broker feasibility** before ratifying the PR2 shape: prove
  httpx (or a minimal HTTP client) driving TLS+HTTP over a passed, pre-connected
  socket, against the SDK's connection-pool/`max_retries` model.
- **PR2 (splits into PR2a topology mechanism → PR2b cutover) — go-live (§5; own
  detailed spec at plan time).** The SCM_RIGHTS fd-broker egress topology (empty
  netns preserved; new inherited fd + `keep_fds`/`pass_fds` policy edit + CA-cert
  bind); `_build_provider` builds the real adapter (lazy; invert the
  egress-capable-import gate + allowlist client construction under the sign-off
  gate); swap the extract branch to `handle_extract`; flip unset-key → refuse-boot
  (typed error + `_BootFailure` + `t()` + `_commands.py` arm); the timeout
  hierarchy + `max_tokens` wiring + cost-channel + accurate `extraction_mode`;
  re-validate the HARD #5 provenance test (schema-fidelity, fold 3); the
  T3-steers-extraction adversarial corpus; **human sign-off**. Predependency:
  #251 (child stderr).

## 4. PR1 — provider-seam reconciliation (detailed)

### 4.1 The gap

`provider_dispatch._call_provider` speaks a provider shape no adapter implements.
PR1 rewrites it to the #339 seam. The extractor's three `ExtractionMode` branches
map as:

| ExtractionMode | Today (aspirational) | #339 seam target |
| --- | --- | --- |
| `native_constrained` | `complete(tools=[{name,description,input_schema}], tool_choice={type:tool,name})` → `response.tool_use_input` | `complete(CompletionRequest(tools=(ToolDefinition(name, description, input_schema=schema),), tool_choice=ForcedTool(name)))` → `response.tool_calls[0].arguments` |
| `prompt_embedded_fallback` | `complete(messages=[...])` → `response.content` | `complete(CompletionRequest(messages=[Message(role="user", content=prompt)]))` → `response.content` |
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
- **(b) RECOMMENDED — reconcile the constrained path to tool-use, gated on
  `NATIVE_CONSTRAINED_GENERATION` alone.** Select the tool-use
  (`native_constrained`) shape when the provider declares
  `NATIVE_CONSTRAINED_GENERATION`; else `prompt_embedded_fallback`.
  **IMPLEMENTED (minimal form):** the dispatcher branches on
  `NATIVE_CONSTRAINED_GENERATION` ONLY — `deepseek-chat` declares `TOOL_USE`
  but not `NATIVE_CONSTRAINED_GENERATION`, so it routes through
  `prompt_embedded_fallback`, not a distinctly-labelled tool-use mode. A fuller
  variant that also routes a `TOOL_USE`-but-not-native provider through a
  labelled tool-use mode (needing a new `ExtractionMode` member) is DEFERRED —
  not part of this PR. **rev.2 (fold 7):** PR1 REMOVES the
  `json_object_unconstrained` runtime dispatcher branch (a retained-but-dead
  branch cannot hit the §4.5 100%-branch target); the `ExtractionMode` Literal
  member is kept type-only-reserved with a doc note. Real `response_format`
  support is deferred to option (a) if/when a JSON-object-only provider ever
  ships. No frozen-seam change; smallest blast radius; aligns with the default
  (Anthropic tool-use).
- **(c) Keep the aspirational json_object branch.** Rejected — that is the
  "shape no adapter implements" problem PR1 exists to fix.

**RATIFIED: (b)** (2026-07-09), with the runtime branch removed per fold 7. Also
add an accurate `extraction_mode` audit label for deepseek-chat tool-use — do NOT
reuse `native_constrained`, which overstates the Anthropic-only provider guarantee
(fold: extraction_mode label).

### 4.3 Error reconciliation (rev.2 — resolved via D1)

Today `dispatch_extraction` catches `httpx.HTTPError` → `TypedRefusal(reason=
"provider_unavailable")`, distinct from `cannot_extract` (model-output failure).
On the #339 seam the adapter's `complete()` raises RAW `anthropic`/`openai` SDK
errors (not `httpx.HTTPError`), and the router already uses a broad
`except Exception` because the SDK hierarchies differ. `provider_dispatch.py`
CANNOT import those SDK types — the in-core HTTP-egress import guard forbids it.

**Resolution (D1):** add a neutral, additive `ProviderUnavailableError` to
`src/alfred/providers/base.py` (an `AlfredError` subclass, `extra="forbid"`
preserved on the models). Each adapter maps its own SDK/transport errors to it AT
THE ADAPTER BOUNDARY (where the SDK import already lives); `provider_dispatch.py`
catches only `ProviderUnavailableError` → `provider_unavailable`, importing no SDK.
This is PR1's ONE minimal additive seam change (correcting rev.1's "zero seam
change" claim in §4.4).

- Retry-eligible (unchanged): only `pydantic.ValidationError` +
  `json.JSONDecodeError`.
- `ProviderUnavailableError` → `TypedRefusal(reason="provider_unavailable")`.
- Empty `tool_calls` / `ProviderMalformedToolArgumentsError` (fold 6) →
  `cannot_extract` (never an uncaught `IndexError` that skips the audit).
- Everything else propagates (HARD #7 — no silent swallow).

PR1 drops the direct `import httpx` from `provider_dispatch.py`. The mapping is
ADR-noted (small additive seam error) — no re-opening of the frozen request/
response models.

### 4.4 Behaviour-neutral invariant (what PR1 does NOT touch)

PR1 makes ONE additive seam change (`ProviderUnavailableError`, §4.3); it is
otherwise behaviour-neutral on the LIVE path:

- **`_build_provider` still returns `_DeterministicProvider()`** — no real client,
  no SDK import, no network. The live child stays echo, byte-for-byte.
- **`_run_mcp_server`'s extract branch stays `_echo_extracted_frame`** — the swap
  to `handle_extract` is go-live (PR2).
- **All import locks stay green:** the module-scope import-closure delta is
  unchanged (provider_dispatch stays lazy, imports no SDK — the error mapping
  lives at the adapter boundary); the egress-capable-import gate stays green (no
  SDK/`httpx` client on the echo loop's closure); the in-core AST import-guard is
  untouched (no new client construction).
- **The host-side `QuarantinedExtractor` (`quarantine.py:406`) is untouched** —
  PR1 is child-internal (`provider_dispatch.py`) plus the additive seam error.

### 4.5 Testing (PR1)

- Unit-test `dispatch_extraction` + `_call_provider` against a **fake
  seam-conforming provider** (implements `.capabilities()` + `.complete(
  CompletionRequest) -> CompletionResponse`, returning FULL `CompletionResponse`
  objects incl. `tokens_in/tokens_out/cost_usd/model` — not duck-typed stubs):
  happy path per branch (tool-use, fallback), retry-then-succeed, retry-exhaustion
  → `cannot_extract`, `ProviderUnavailableError` → `provider_unavailable`,
  **empty `tool_calls` (max_tokens-truncated forced tool) → `cannot_extract`**
  (fold 6), **`ProviderMalformedToolArgumentsError` → `cannot_extract`**,
  malformed-JSON-args → retry, back-off budget breach → `cannot_extract`. Assert
  the `CompletionRequest` the fake received has the right shape (ForcedTool name,
  input_schema) — non-vacuous (the frozen `extra="forbid"` request self-validates
  on construction, so shape assertions are real).
- Assert **no** import-closure / egress-gate regression (the existing guards run
  unchanged and stay green).
- 100% line + branch on `provider_dispatch.py` — the coverage gate is already
  wired (`ci.yml:1816`, confirmed); the removed `json_object_unconstrained` branch
  (fold 7) means there is no dead runtime branch defeating the target. Consider a
  named per-file gate to match the sibling two-gates pattern.
- **PR1 edits `src/alfred/security/` → the adversarial suite is release-blocking**
  (CLAUDE.md); run it even though PR1 is behaviour-neutral on the live path.

### 4.6 Files touched (PR1)

- `src/alfred/security/quarantine_child/provider_dispatch.py` — the reconciliation
  (`_call_provider`, error handling, capability selection; drop `import httpx`;
  empty-`tool_calls`/malformed-args guards).
- `src/alfred/providers/base.py` — add `ProviderUnavailableError` (D1, additive).
- `src/alfred/providers/anthropic_native.py`, `deepseek.py` — map SDK/transport
  errors to `ProviderUnavailableError` at the adapter boundary.
- `src/alfred/security/quarantine.py` — `ExtractionMode` doc note (member kept
  type-only-reserved); accurate deepseek-chat `extraction_mode` label.
- `tests/unit/security/…` (+ provider tests) — the fake-provider dispatch tests +
  the adapter error-mapping tests.
- ADR: a short note recording the additive `ProviderUnavailableError` seam error
  (D1) — small, cross-refs ADR-0045/the #339 seam docs.

## 5. PR2 — go-live (sketch; detailed spec at PR2 plan time)

The security go-live. Carries the **human sign-off gate** (do NOT self-certify).
**rev.2:** preceded by the fd-broker feasibility spike (D2) and split into
PR2a (topology mechanism) → PR2b (cutover); the folds above (fd-broker plumbing,
timeout hierarchy, `max_tokens`, cost channel, CA-cert bind, refuse-boot detail,
T3-steers adversarial, provenance schema-fidelity) are the PR2-spec agenda.

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

## 6. Decisions — RATIFIED 2026-07-09

1. **Decomposition = Option A** (machinery → go-live), refined by D2 to
   PR1 → spike → PR2a → PR2b. Matches #338/2a-2b precedent.
2. **PR1 JSON_OBJECT_MODE fork = option (b)** (reconcile constrained path to
   tool-use; runtime branch REMOVED, Literal member kept type-only-reserved;
   defer `response_format` to option (a) if a JSON-object-only provider ever
   ships).
3. **D1 = the minimal additive `ProviderUnavailableError` seam error** in PR1
   (adapters own the SDK-error mapping; `provider_dispatch.py` imports no SDK).
4. **D2 = an fd-broker feasibility spike precedes PR2, and PR2 splits** into
   topology mechanism (PR2a) → cutover (PR2b).
5. **PR2 egress topology = SCM_RIGHTS fd-broker, empty-netns preserved** —
   **maintainer-cosign-level**, decided in the PR2a spec, gated by the go-live
   human sign-off. The bwrap-policy edit (new fd + `keep_fds`/`pass_fds` +
   CA-cert bind) is part of that security-boundary change.

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

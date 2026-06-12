# ADR-0029: Inline-over-wire quarantine content path (host single-use staging + `quarantine.ingest`)

- **Status:** Proposed
- **Date:** 2026-06-11
- **PR:** PR-S4-11c-2a (epic #237 — Slice-4 graduation closer)
- **Supersedes / amends:** ADR-0027 (daemon comms-runtime fixture extractor first cut). This ADR
  introduces the real request/response `QuarantineStdioTransport` that will *eventually* replace the
  `_RecordedExtractTransport` fixed-replay transport ADR-0027 ships. PR-S4-11c-2a (this PR) delivers
  the transport **machinery only**; the production daemon path **continues to use the ADR-0027
  fixture extractor**. The atomic production flip — real launcher-spawned child-IO seam +
  `record_body` wiring + dropping `_RecordedExtractTransport` — is **PR-S4-11c-2b**. ADR-0027 is not
  retired until 2b lands.
- **Related:** ADR-0017 (process-boundary isolation), ADR-0028 (boot-time authorised T3 nonce),
  spec §7.1 / §7.2 / §7.3 (dual-LLM split, single-use content handle), PRD §5.

## Context

PR-S4-11c-2a builds the wire that carries an inbound T3 message body from the daemon host to the
(eventually launcher-spawned) quarantined LLM. The quarantined LLM is the only component permitted
to read raw T3 content; the privileged orchestrator must never see it (CLAUDE.md hard rule #5).

The `QuarantinedExtractor` (`src/alfred/security/quarantine.py`) already dispatches
`transport.dispatch("quarantine.extract", {"handle_id", "schema_json", "schema_version"})` and
requires a `ControlResult` carrying `payload.kind ∈ {extracted, typed_refusal}` back. The handle id
is the **only** T3-attribution token that crosses the wire — the raw body is intentionally NOT a
parameter of `quarantine.extract`.

That raises the content-path question: **how does the body reach the child** so the child can extract
against it, given the handle id alone is opaque?

The web.fetch trust boundary answers this with a shared Redis `ContentStore` (single-use GETDEL):
the host writes `TaggedContent[T3]` under `handle_id`, the child reads it back. The pre-existing
quarantine child skeleton (`plugins/alfred_quarantined_llm/quarantine_plugin.py`) instead caches the
body **in-process** via `handle_ingest(handle_id, context)` → `_content_cache[handle_id]`, popped
single-use by `handle_extract`. It never reaches for Redis.

The PR-S4-11c decomposition named a web_fetch-style `ContentStore`. On validation that is the wrong
target for the quarantine path:

1. The quarantined child is launched in a tightly-sandboxed subprocess (ADR-0015) with **no
   datastore credentials** — granting it a Redis connection to read T3 bodies would widen its
   capability surface and hand a compromised quarantined LLM a network egress + a shared key.
2. The child's *existing* contract is already storeless-and-inline (`_content_cache`). Targeting a
   shared store would mean rewriting a contract the child already implements correctly.
3. A shared store is a second place the raw T3 body lives, on a datastore the privileged side can
   also read — an avoidable widening of where T3 bytes are resident.

## Decision

The body travels **inline over the wire**, as a `quarantine.ingest` request sent **immediately
before** the `quarantine.extract` request, within the same transport `dispatch`:

```
host → child:  quarantine.ingest  {handle_id, context}     # carries the raw T3 body inline
host → child:  quarantine.extract {handle_id, schema_json, schema_version}
child → host:  ControlResult(method="quarantine.extract", payload={kind, data|reason, ...})
```

- **The child stays storeless.** It caches the ingested `context` under `handle_id` in-process
  (`handle_ingest`) and `pop`s it single-use on `handle_extract` (existing behaviour at
  `quarantine_plugin.py:127-192`). No Redis, no shared store, no datastore credential in the sandbox.

- **The host owns a single-use staging map** (`handle.id → TaggedContent[T3]`). `record_body`
  (the seam `CommsExtractorBridge` calls before `extractor.extract`) tags the inbound body
  `TaggedContent[T3]` via `tag_t3_with_nonce(..., caller_token=<boot nonce>)` and stages it under
  `handle.id`. `QuarantineStdioTransport` **drains** that staging entry when it sends
  `quarantine.ingest`, then sends `quarantine.extract`. A second dereference of the same `handle.id`
  fails loudly (single-use pop) — replay after consumption is refused, mirroring the child's own
  single-use `pop` and the web.fetch GETDEL intent (spec §7.2).

- **`quarantine.ingest` is a new wire method** coined here as the forward contract the child's MCP
  loop implements. *(Updated PR-S4-11c-2b: the child's `_run_mcp_server` now runs the
  deterministic-echo loop and `quarantine.ingest`/`quarantine.extract` ARE routed over the real wire
  in production — the "`NotImplementedError` today; no wire routing exists yet" status described the
  2a precursor; 2c swaps the echo for a real provider call.)* PR-S4-11c-2a ships the host half plus a
  test child double that mirrors the `handle_ingest`/`handle_extract` single-use cache contract.

- **Framing is length-prefixed JSON-RPC** (`struct.pack(">I", ...)` 4-byte big-endian length header
  then a UTF-8 JSON body), peer to `StdioTransport`. `QuarantineStdioTransport` does NOT subclass
  `StdioTransport` — its content/control branch, env-scrub spawn, and direct-exec are the wrong
  behaviour for this request/response wire (the real spawn is PR-S4-11c-2b's launcher). It reuses the
  length-prefix framing helpers only and is driven against an **injected child-IO seam** so tests
  supply an in-process fake child without a subprocess.

- **2a delivers the machinery; production is flipped in 2b (design B'').** PR-S4-11c-2a ships the
  host-side quarantine transport machinery — the inline-over-wire `quarantine.ingest` →
  `quarantine.extract` sequence, the host single-use staging map, and the `T3BodyRecorder` boundary —
  TESTED end-to-end against a length-prefixed child double (`tests/unit/security/` +
  `tests/integration/test_quarantine_transport_real.py`). The **production** daemon
  (`_build_comms_inbound_extractor`, `_build_comms_boot_graph`) **continues to use the ADR-0027
  `_RecordedExtractTransport` fixture extractor** in this PR — byte-for-byte unchanged from `main`.

  PR-S4-11c-2b performs the **atomic production flip**: it swaps `_build_comms_inbound_extractor` onto
  the real `QuarantineStdioTransport`, supplies the real launcher-spawned child-IO seam, wires
  `record_body` (the `T3BodyRecorder`) into the `CommsExtractorBridge`, and **drops**
  `_RecordedExtractTransport`. This mirrors PR-S4-11c-1's `build_orchestrator` (machinery merged in
  one PR, wired by the next).

  Keeping the fixture one more PR is **not** a fail-loud violation: the fixture is test/dev-gated
  (behind `comms_enabled_adapters` + `ALFRED_ENVIRONMENT`), still exercises the genuine
  `extract(handle, schema)` + post-stage DLP scan path, and is the documented ADR-0027 interim. The
  alternative — flipping production in 2a — would regress the green #240 e2e proof (a comms-enabled
  daemon inbound turn would REFUSE on an unspawned wire until the 2b launcher lands) and force a
  double-churn of the smoke + integration tests that assert a successful `comms.inbound.t3_promoted`
  turn. When 2b lands there is no production flag that runs a non-real extractor — the fixture
  transport is a TEST-only injection thereafter (a flag that bypassed the real extractor in
  production would violate CLAUDE.md hard rule #7).

## Consequences

**Positive**

- The quarantined subprocess never holds a datastore credential — the sandbox surface stays minimal
  (ADR-0015 intent preserved).
- The raw T3 body is resident in exactly two places, both single-use: the host staging map (drained
  on ingest) and the child's in-process cache (popped on extract). No shared store, no third copy.
- The single-use pop on both sides makes handle replay a loud refusal, not a silent re-read — the
  laundering window (re-dereferencing a consumed T3 body) is closed at both ends.
- The `QuarantinedExtractor` lift (`quarantine.py:1064-1106`) is unchanged: the transport still
  returns the same `ControlResult` shape, so the orchestrator-side schema/kind/data guards continue
  to defend the boundary verbatim.

**Negative / costs**

- The body crosses the wire inline, so the per-message wire payload is larger than a handle-id-only
  frame. Acceptable: the body is bounded by the inbound-frame size cap and the alternative (a shared
  store) is rejected for the security reasons above.
- `quarantine.ingest` adds a method to the quarantine wire vocabulary. It is a closed addition the
  real child routes — PR-S4-11c-2b (2026-06-12) wired this inline-over-wire content path into the
  PRODUCTION daemon (`_build_comms_boot_graph` builds the real `QuarantineStdioTransport` +
  `T3BodyRecorder` over a LIVE bwrap child, ADR-0027 amendment), so the host half now runs against a
  real deterministic-echo child in production, not only the test child double.
- Two `dispatch` round-trips per extract (ingest then extract). The transport sequences them inside a
  single `dispatch("quarantine.extract", ...)` call so the `QuarantinedExtractor` contract is
  unchanged — the ingest is an internal pre-step of the transport, invisible to the extractor.

## Alternatives considered

1. **Shared Redis `ContentStore` (the decomposition's named target).** Rejected: hands the sandboxed
   quarantined LLM a datastore credential + network egress, and creates a second place the raw T3
   body lives that the privileged side can also read. See Context (1)–(3).

2. **Body as a `quarantine.extract` parameter.** Rejected: would change the `QuarantinedExtractor`
   dispatch contract (`quarantine.py:1020-1027`) and put the raw body on the same frame as the
   schema, conflating the attribution token (handle id) with the content. The two-method split keeps
   the handle id as the sole forensic token on the extract frame.

3. **Host writes to the child's cache directly.** Impossible across the process boundary (and
   undesirable — it would couple the host to the child's internal cache representation). The wire
   `quarantine.ingest` method is the contract seam.

4. **Keep `_RecordedExtractTransport` indefinitely / never build the real wire.** Rejected: would
   leave the daemon's production path running a fixed-replay extractor that never reads the actual
   inbound body — a non-real security primitive in production (CLAUDE.md hard rule #7). The real
   request/response transport is the destination; this ADR builds it.

5. **Flip production onto the real transport in 2a (the originally-drafted plan).** Rejected (design
   B''): the real transport needs a launcher-spawned child-IO seam to function, and that spawn is
   2b. Flipping in 2a would force production to hold an unspawned-child placeholder that REFUSES on
   any wire access, regressing the green #240 e2e proof — a comms-enabled daemon inbound turn would
   refuse until 2b, breaking the smoke + integration tests that assert a successful
   `comms.inbound.t3_promoted` turn. Instead, 2a ships the transport machinery (fully tested against a
   child double) while production keeps the ADR-0027 fixture extractor one more PR, and 2b does the
   atomic flip + real spawn + `record_body` wiring together. The fixture is test/dev-gated and still
   exercises the genuine `extract` + DLP path, so this is a sequencing choice, not a production
   fail-loud regression. Mirrors 11c-1's machinery-then-wiring split.

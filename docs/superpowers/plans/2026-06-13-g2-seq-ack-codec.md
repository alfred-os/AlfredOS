# G2 — CommsSeqCodec (out-of-band seq/ack/dedup framing) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `CommsSeqCodec` — a PURE, hypothesis-property-testable encode/decode for an **out-of-band, length-prefixed framing header** that wraps the opaque ADR-0025 line-delimited comms payload byte-for-byte. The header carries a **per-direction monotonic sequence**, a **cumulative ack** (highest contiguous seq durably intaken), and an **idempotent dedup key `(leg, seq)`**. The seq/ack header is **version-gated at the handshake** so a peer that does not speak it falls back to the plain ADR-0025 frame. G2 wires the codec into the existing transport send/read path BEHIND that gate, but ships **no consumer** of the ack/dedup yet — the gateway relay (G3) and the `ReplayBuffer` (G4) are the consumers, both out of scope here.

**Architecture:** This is a **codec-substrate** PR, exactly like PR-S4-11a and G1: the consumer (the gateway, G3) does not exist yet. G2 ships (0) a small **shared constants module** `src/alfred/plugins/comms_wire.py` holding `_MAX_COMMS_LINE_BYTES` + `CommsProtocolError`, broken out of `comms_stdio_transport` FIRST so the codec can depend on them WITHOUT a bidirectional import (architect F6 — the codec needs both, and the transports will import the codec, so the bound + error type must move to a leaf module both sides import); (a) a pure `CommsSeqCodec` in a NEW `src/alfred/plugins/comms_seq_codec.py` — `encode(frame_line, *, seq, ack) -> bytes` and `decode(raw) -> SeqFrame`, single-sourced and shared by BOTH comms transports; (b) a pure `SeqDedupWindow` (the `(leg, seq)` accept-once + cumulative-ack-trim state machine, no I/O) — fully unit/property-tested but **NOT wired into the transport** (the transport emits an `a=0` placeholder ack in G2; the contiguous ack `SeqDedupWindow` computes is wired by the G3 relay — no dead I/O surface, the G1 lesson); (c) a handshake version-gate negotiation (`AlfredSeqAck/1`) added to the existing `lifecycle.start` round-trip in `comms_runner.py`, with a TYPED `enable_seq_ack` on the `_CommsTransportLike` Protocol (architect F4 — flipped as a typed call, not `getattr`-duck-typing); (d) optional, gate-conditional codec insertion into `CommsStdioTransport.send`/`read_frame` and `CommsSocketTransport.send`/`read_frame` such that when BOTH peers negotiated seq/ack, frames carry the header (with `a=0` placeholder ack), and when either did not, the wire is byte-for-byte the plain ADR-0025 frame. **No ack timer is fired, no dedup decision is acted on, no `id` correlation changes, no `_recv_ack` high-water is stored** — the codec is exercised only by assertion (round-trip, FIFO ordering, dedup idempotency, ack-trim monotonicity, version-gate fallback). The actual USE of seq/ack by a relay/buffer is G3/G4.

**Out-of-band, not in-band (decision 3 / spec §4).** The header is NOT a JSON field added to the payload. The relay (G3) must forward the JSON-RPC payload **verbatim** so it stays payload-blind (T1 carrier) and so the runner's request/response `id` correlation survives the relay untouched. The codec therefore parses ONLY the header bytes and treats the payload as an opaque byte run — it never `json.loads` the body. `id` is preserved end-to-end because the codec never reads, rewrites, or even decodes the payload that carries it; `seq` is a SECOND, header-level counter distinct from + additive to `id`.

**Tech Stack:** Python 3.12+, asyncio, Pydantic v2 frozen models (`_WireModel`-style for the negotiated-capability frame field; a frozen `@dataclass` for the pure `SeqFrame` value), structlog, the i18n `t()` catalog (`pybabel`) for the one new malformed-header operator string, pytest + **hypothesis** property tests, `mypy --strict` + `pyright` + `ruff`.

**Spec:** `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md` — §4 "Wire protocol" (the seq/ack/dedup bullets), §6 "Trust-boundary posture" (payload-blind, header-is-carrier-metadata), §7 component `CommsSeqCodec`, §9 "Testing" (the codec property list), §8 G2 row. The roadmap parent is `docs/superpowers/specs/2026-06-13-gateway-control-plane-roadmap.md`.

**ADR:** G2 records its decisions in a **new ADR-0032** (the spec §8 names "ADR-0032 = gateway comms-resume transport — payload-blind wire" as the home for the wire-format decisions, and the ADR number is currently UNUSED — the ADR directory skips from 0031 to 0033, with G1 having taken 0033). G2 writes the **first cut of ADR-0032 scoped to the codec/wire-format** (out-of-band header grammar, version-gate, `(leg,seq)` dedup, ack semantics); G3 amends ADR-0032 with the buffer-security / epoch-auth / shared-volume-AF_UNIX / audit-reconcile sections (spec §8 lists those as ADR-0032 content, but they are G3/G4 concerns). This split is recorded in ADR-0032's own scope note. **RESOLVED (architect+test plan-review, 2026-06-13):** ADR-0032 is CONFIRMED free and is the home for this first cut — `ADR-0032` is baked into Task 1's docstrings and EVERY commit subject from the start (not a Task-8 flip). It matches the ADR-0027 "first cut" precedent + the spec's explicit ADR-0032 framing. The earlier "flip to ADR-0035" alternative is dropped.

---

## Context the engineer needs (read this first)

You have zero context. Read these before touching code:

- **Spec:** `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md` — §4 (wire protocol: per-direction monotonic seq distinct from `id`; cumulative ack of the highest CONTIGUOUS seq durably intaken; acks coalesced — piggyback + bounded timer, NO standalone ack per data frame; dedup key `(leg, seq)` only, never payload-derived; header version-gated at handshake; `_MAX_COMMS_LINE_BYTES` unchanged), §6 (payload-blind wire; the header is carrier metadata, NEVER payload-derived; T3 tagging stays in the core), §7 (`CommsSeqCodec` "Pure, hypothesis-property-testable — replay idempotent; ack-trim; FIFO"), §9 (the unit property list).
- **The two comms transports (the carriers the codec inserts into):**
  - `src/alfred/plugins/comms_stdio_transport.py` — `CommsStdioTransport`. The ADR-0025 frame codec is `send` (`comms_stdio_transport.py:159` — `payload = (json.dumps(frame) + "\n").encode()`; `comms_stdio_transport.py:172`) and `read_frame` (`comms_stdio_transport.py:183` — `line = await self._proc.stdout.readline()`; `comms_stdio_transport.py:197`). The DoS bound is `_MAX_COMMS_LINE_BYTES` (`comms_stdio_transport.py:84`, `10 * 1024 * 1024`). The loud-failure type is `CommsProtocolError` (`comms_stdio_transport.py:91`).
  - `src/alfred/plugins/comms_socket_transport.py` — `CommsSocketTransport`. Its `send` (`comms_socket_transport.py:164`) and `read_frame` (`comms_socket_transport.py:180`) are the IDENTICAL line-delimited discipline over a socket. It IMPORTS the shared bound + error type from the stdio module (`comms_socket_transport.py:53-56`): `from alfred.plugins.comms_stdio_transport import (_MAX_COMMS_LINE_BYTES, CommsProtocolError)`.
  - **THE SHARED SEAM (grounded):** the two transports already single-source the bound + protocol-error type via that import (`comms_socket_transport.py:53-56`), but they **DUPLICATE the framing bytes** — each has its own `(json.dumps(frame) + "\n").encode()` send and its own `readline()` + `json.loads` + `isinstance(decoded, dict)` read. There is NO shared codec FUNCTION today; the discipline is copy-pasted (the socket module's own docstring at `comms_socket_transport.py:50-52` calls this out: "reuse the bound and the protocol-error class rather than forking a second, divergent framer"). G2's `CommsSeqCodec` is the single-source the spec wants: BOTH transports call into it for the out-of-band header so the seq/ack framing is defined exactly once.
  - **THE IMPORT CYCLE (architect F6 — Task 0 fixes this FIRST):** the codec needs `_MAX_COMMS_LINE_BYTES` + `CommsProtocolError`, which live in `comms_stdio_transport` today. If the codec imports them FROM `comms_stdio_transport` AND `comms_stdio_transport` imports the codec, that is a bidirectional import cycle (at module-import time, since the codec is referenced in `send`/`read_frame`). Task 0 breaks it STRUCTURALLY: extract `_MAX_COMMS_LINE_BYTES` + `CommsProtocolError` into a NEW leaf module `src/alfred/plugins/comms_wire.py` that `comms_stdio_transport`, `comms_socket_transport`, AND `comms_seq_codec` all import. `comms_stdio_transport` and `comms_socket_transport` keep a re-export (`from alfred.plugins.comms_wire import _MAX_COMMS_LINE_BYTES, CommsProtocolError` + leaving them in `__all__`) so existing importers (e.g. the codec's test imports `CommsProtocolError` from `comms_stdio_transport`, and `comms_socket_transport.py:53-56` imports both) keep working with no churn. Verify `python -c "import alfred.plugins.comms_seq_codec"` has no cycle.
- **The runner (where the handshake version-gate negotiates, and where `id` lives):** `src/alfred/plugins/comms_runner.py` —
  - The single-reader pump (`_pump` — `comms_runner.py:398`); the JSON-RPC `id` correlation: `send_request` (`comms_runner.py:195`) allocates `request_id` (`comms_runner.py:230`), registers `self._pending[request_id]` (`comms_runner.py:234`), and `_resolve_pending` (`comms_runner.py:586`) matches `frame.get("id")` back. **G2 MUST NOT disturb this:** `seq` is a header counter, additive to and distinct from `id`; the codec never touches the payload that carries `id`.
  - The handshake: `start_and_handshake` (`comms_runner.py:283`) → `_handshake` (`comms_runner.py:347`). The handshake sends `lifecycle.start` (`comms_runner.py:358-365`, id `_LIFECYCLE_START_ID = 0` at `comms_runner.py:68`) and reads frames until the matching ack (`comms_runner.py:366-384`), checking `result.get("ok")` (`comms_runner.py:376`). **The version-gate negotiation rides this exact round-trip:** the host advertises seq/ack support in the `lifecycle.start` params; the plugin echoes whether it speaks it in the `lifecycle.start` RESULT; the runner records the negotiated flag on itself. The transport seam the runner drives is `_CommsTransportLike` (`comms_runner.py:122`) — `spawn` / `send` / `read_frame` / `close` (`comms_runner.py:131-137`).
  - The reference plugin: `plugins/alfred_comms_test/main.py` — `handle_lifecycle_start` returns `{"ok": True, "plugin_version": _PLUGIN_VERSION}` (`main.py:124-127`); the serve loop's `_emit` writes `(json.dumps(frame) + "\n").encode()` (`main.py` `_serve_stdin_stdout`). The plugin is NOT modified in G2's core codec tasks — the gate negotiation is **default-off**, so a plugin that does not advertise seq/ack support falls back to the plain frame. **CORRECTED post-review (PR #262):** the original Task 6 (an OPT-IN seq/ack echo from the reference plugin) was REMOVED. A daemon-SPAWNED plugin is not the seq/ack peer — seq/ack is the resumable **core↔gateway** leg (G3), and a spawned plugin dies with the core (no resume benefit). Worse, the reference plugin's serve loop does a plain `json.loads` and never DEFRAMES the `A1` header, so echoing the capability flipped the runner's gate ON and then every host→plugin `send()` arrived `A1`-wrapped — bytes the plugin could not parse (it broke `outbound.message` / `adapter.health` / `lifecycle.stop` / the inject triggers; the real-plugin integration tests caught it but `skipif` on the non-root launcher gate hid it on the required gate). So the reference plugin **does not advertise seq/ack**; the wire to it stays plain ADR-0025. The host MAY keep advertising (harmless — the gate only flips when a peer echoes). The gateway (G3) is the seq/ack peer that echoes **and** deframes.
- **Wire models + the negotiated-capability field:** `src/alfred/comms_mcp/protocol.py` — `_WireModel` (`protocol.py:139`: `ConfigDict(frozen=True, extra="forbid")`, closed vocab is `Literal[...]`). `LifecycleStartRequest` (`protocol.py:150`) and `LifecycleStartResult` (`protocol.py:158`, already has `ok: bool` + `plugin_version`) are the handshake frames the version-gate extends with an OPTIONAL seq/ack capability field. **`extra="forbid"` is load-bearing:** adding the field to BOTH models is required so a conformant peer can send it without tripping validation, AND so the absence of the field is the explicit default-OFF signal.
- **Audit (the malformed-header path):** the codec is PURE and writes NO audit row itself (it raises; the caller audits). The transport's existing `read_frame` already logs `comms.transport.malformed_frame` / `comms.socket.malformed_frame` + raises `CommsProtocolError`; a malformed SEQ HEADER reuses that exact loud-failure path (new structlog event `comms.seq.malformed_header`, same `CommsProtocolError` raise) so the runner's existing malformed-frame arm (`comms_runner.py:423`) handles it uniformly. No new audit field-set.
- **i18n catalog:** `t()` — `src/alfred/i18n/translator.py`; catalog source `locale/en/LC_MESSAGES/alfred.po`. The malformed-header path reuses the EXISTING `comms.transport.malformed_frame` key (already in the catalog) — G2 adds **no new operator string** unless the version-gate refusal needs one (it does not: a peer that does not speak seq/ack is the silent default-OFF path, not an error). The slice-4 key enumeration test is `tests/unit/test_catalog_slice_4_keys.py` — touched only if a new key is added (it is not).
- **Hypothesis usage examples in-repo:** `tests/unit/identity/test_version_counter.py`, `tests/unit/memory/test_working_pool.py` (`from hypothesis import given, strategies as st`). Mirror their style.
- **CI commit-hygiene gate (BAKE IN — G0/G1 burned rounds on this):** `.github/workflows/pr-validate-commits.yml`. The `conventional-commits` job requires every commit SUBJECT to match a Conventional-Commit type AND carry a `#NNN` ref **in the subject**. The repo convention also requires the trailer `MrReasonable <4990954+MrReasonable@users.noreply.github.com>` on every commit. **Every `git commit` in this plan satisfies BOTH** (`#237` in the subject + the trailer). Do not skip either.
- **CI markdownlint (BAKE IN):** every `.md` (this plan + ADR-0032) must be MD032-clean — a blank line BEFORE and AFTER every list and every table. The ADR body in Task 8 is written that way.
- **Two-plugins coverage gate (context):** `.github/workflows/ci.yml` runs per-file coverage gates on comms surfaces (the PR-S4-11a "TWO plugins coverage gates" pattern). A NEW `src/alfred/plugins/comms_seq_codec.py` is a trust-boundary-adjacent carrier file — name it explicitly in the per-file coverage gate alongside the existing comms transports, held to the codec coverage bar (spec §9: ≥80% relay/codec core; the codec is pure so 100% line is cheap and expected). Confirm the exact gate stanza in `ci.yml` before editing (the file lists each gated path explicitly).

---

## Trust-boundary posture (CONFIRMED — read before writing code)

- **The seq/ack header is CARRIER METADATA, never payload-derived (spec §6 + the `[fleet security]` finding).** `seq`, `ack`, and the byte-length prefix are computed from the wire transport's own per-direction counters and the payload's BYTE LENGTH — never from the payload's CONTENT. The dedup key is `(leg, seq)` ONLY (spec §4); the codec has no code path that hashes, parses, or inspects payload bytes to derive any header value. This is the structural reason the relay stays payload-blind: a T1 carrier that derived a header from payload content would be reading the body.
- **The payload stays opaque + T3-tagged-in-core.** The codec treats the payload as an opaque byte run: `encode` takes the already-serialized ADR-0025 frame bytes and prepends a header; `decode` splits the header off and returns the payload bytes UNTOUCHED. It never `json.loads` the body. T3 tagging stays in the core at `process_inbound_message` (hard rule #5 intact — the privileged orchestrator never sees raw T3; the codec is even further from it, a pure byte-framer). The gateway (G3) remains a T1 carrier; G2 adds no trust-tier authority to the wire.
- **`id` is preserved end-to-end.** Because the codec never decodes the payload, the JSON-RPC `id` the runner correlates on (`comms_runner.py:230/586`) is carried byte-for-byte inside the opaque payload and is structurally untouchable by the codec. `seq` is a separate header counter; the two never alias.
- **Fail-loud on a malformed header (CLAUDE.md hard rule #7).** A header that is over-bound, non-parsable, or whose declared length does not match the payload run raises `CommsProtocolError` (the existing comms loud-failure type) — never silently dropped, never ack-advanced. The codec carries NO raw bytes on the exception (spec §5.6 — no T3 in error attributes), exactly like the existing transport malformed-frame path.
- **`_MAX_COMMS_LINE_BYTES` is unchanged and still bounds the WHOLE wire unit** (header + payload + `\n`). The header adds a small fixed-grammar ASCII prefix; the codec asserts `len(unit) <= max_unit_bytes` (default `_MAX_COMMS_LINE_BYTES`) on the OUTER unit so the out-of-band header can never be used to smuggle past the per-frame DoS bound.
- **Bound contract = Option A (architect F1 + test F4): the header costs budget on a negotiated wire.** The `A1 s=… a=… n=… |` header ADDS bytes, so on a NEGOTIATED wire the usable PAYLOAD budget shrinks. The codec defines a `_MAX_HEADER_BYTES` constant bounding the worst-case NON-payload width: `len(b"A1 s= a= n= |") + 3 * _MAX_DECIMAL_WIDTH + 1`, where `_MAX_DECIMAL_WIDTH` is the decimal width of the largest counter the codec will ever emit (the payload-len field is itself bounded by `_MAX_COMMS_LINE_BYTES`, so its width bounds all three) and the trailing `+ 1` folds in the unit's `\n` so the reservation accounts for EVERYTHING that is not payload. The codec docstring + ADR-0032 document that on a negotiated wire the **effective payload ceiling is `max_unit_bytes - _MAX_HEADER_BYTES`** — a payload at or under that is GUARANTEED to encode for any counter widths. The encode bound stays on the OUTER unit (`header + payload + "\n" <= max_unit_bytes`); `_MAX_HEADER_BYTES` is the documented worst-case reservation, not a second runtime check. (Tested in Task 1: a payload of exactly `max_unit_bytes - _MAX_HEADER_BYTES` encodes OK even with the WIDEST counters — the reservation GUARANTEE, NOT a "one byte more raises at the ceiling" claim, since the real header is narrower when the counters are small; a payload large enough to overflow the OUTER bound raises `CommsProtocolError` on SEND; the bound is ALSO driven through `decode` — a too-long raw raises — AND through the transport `read_frame` with seq enabled + a tiny `max_line_bytes`.)

---

## Framing design (DECISION — read before writing the codec)

**Chosen wire shape: a single newline-terminated unit = `<ascii-header><SP><opaque-payload-line>`**, where the payload line is the EXISTING ADR-0025 `json.dumps(frame)` text (NOT re-terminated mid-unit) and the unit is terminated by the existing single trailing `\n`. The header is a compact, fixed-grammar ASCII token:

```
A1 s=<seq> a=<ack> n=<payload_byte_len> |<opaque-payload-bytes>\n
```

- `A1` — the codec MAGIC + version (`A` = AlfredSeqAck, `1` = wire version). A frame that does not begin with the magic is a PLAIN ADR-0025 frame (the default-OFF fallback — `decode` recognises it and returns `SeqFrame(seq=None, ack=None, payload=raw_line)` so a mixed/un-negotiated wire still reads).
- `s=<seq>` / `a=<ack>` — base-10 ASCII non-negative integers (the per-direction monotonic seq and the cumulative ack). **In G2 the transport emits `a=0` — a PLACEHOLDER, not a computed high-water (architect F2 + test F3).** The transport must NOT piggyback `ack=max(seq seen)`: a high-water falsely acks past gaps, which contradicts the contiguous-ack semantics ADR-0032 records (Decision 3). The real CONTIGUOUS ack is computed by the pure, property-tested `SeqDedupWindow.cumulative_ack()` and is wired as the ack source by the G3 relay. G2's transport carries `a=0` and stores NO `_recv_ack`.
- `n=<payload_byte_len>` — the declared byte length of the opaque payload that follows the `|` delimiter, used to (i) validate the payload run length on decode and (ii) keep the codec from having to scan the payload for structure. `|` is the single header/payload delimiter (it cannot appear in the fixed `A1 s= a= n=` grammar, so the FIRST `|` unambiguously ends the header).
- `<opaque-payload-bytes>` — the verbatim ADR-0025 payload (the `json.dumps(frame)` text), forwarded byte-for-byte. The codec NEVER decodes it.

**Why this shape (the rationale the spec asks the plan to state):**

1. **Out-of-band, not in-band.** The seq/ack live in an ASCII prefix the codec strips before handing the payload to the existing JSON path. The payload JSON is untouched, so the relay forwards it verbatim and `id` survives. An in-band JSON field would force the relay to parse + re-serialize every frame (a payload-blindness violation AND a hot-path cost the spec explicitly avoids).
2. **Preserves the existing line-delimited `readline()` reader.** The whole unit is still ONE newline-terminated line, so `CommsStdioTransport.read_frame`'s `readline()` (`comms_stdio_transport.py:197`) and the socket transport's `readline()` (`comms_socket_transport.py:190`) work unchanged — the codec splits the already-read line into (header, payload). This avoids a second framing layer (a length-prefixed binary header before the line) that would break the `readline()` discipline both transports and both already-shipped non-upgraded peers depend on.
3. **`_MAX_COMMS_LINE_BYTES` still bounds the unit.** The `readline()` limit (pinned to `_MAX_COMMS_LINE_BYTES` at spawn/accept) still bounds the entire header+payload line; the codec additionally validates `n=` against the actual payload run so a lying length is caught loud.
4. **Default-OFF fallback is a magic-prefix check; decode is direction-agnostic.** A peer that did not negotiate seq/ack emits a plain `json.dumps(frame)+"\n"` line with no `A1` magic prefix; `decode` sees no magic and returns the line as an un-sequenced `SeqFrame`. A negotiated peer emits the `A1 ...|...` form. **`decode` is direction-AGNOSTIC — it inspects the magic on the bytes in front of it and reads EITHER form regardless of whether THIS transport has its gate flag on** (a seq-enabled reader decoding a plain `{`-line is the load-bearing mixed-wire case; tested in BOTH directions — test F4). The gate FLAG is per-transport (it controls only what `encode`/`send` EMIT); the wire is therefore mixed-safe during the negotiation window and on a wire where only one direction upgraded. (Earlier prose calling the fallback "per-direction-independent" was imprecise: it is the SEND side that is per-transport-gated; the DECODE side reads any frame via the magic gate.)

**The `leg` and the dedup key.** `leg` is the DIRECTION label (`"inbound"` = client→core, `"outbound"` = core→client) — it is NOT carried on the wire (each direction's reader already knows which leg it is reading) and is supplied by the CALLER to the `SeqDedupWindow`. The dedup key is the pure tuple `(leg, seq)`; `SeqDedupWindow` is constructed per-leg, so in practice the window keys on `seq` within its own leg. This matches the spec's "key = `(leg, seq)` ONLY — never payload-derived".

**Send-window scope (RESOLVED for G2 — defer to G4).** The spec §4/§5 mention a bounded in-flight window distinct from G4's buffer cap. **G2 does NOT implement a send-window / back-pressure.** G2 is the pure codec + the dedup/ack state machine + the gate; a healthy-path in-flight window is a SENDER behaviour with a consumer (the relay applying back-pressure when the un-acked window is full), and there is no sender/relay in G2. The window cap rides with G3 (the relay) / G4 (the buffer) where the un-acked retention it bounds actually exists. This is called out as an OPEN QUESTION below for the architect to confirm the split, but the plan defers it — building a window with no consumer would be the same dead-surface mistake G1's review removed (the runner send seam).

---

## File-structure table

| File | Create / Modify | Responsibility |
| --- | --- | --- |
| `src/alfred/plugins/comms_wire.py` | Create (Task 0) | The shared leaf module: `_MAX_COMMS_LINE_BYTES` + `CommsProtocolError`, extracted from `comms_stdio_transport` so `comms_seq_codec` + both transports import them from one place — breaking the codec↔transport import cycle (architect F6). No behaviour change; the values + class move verbatim. |
| `src/alfred/plugins/comms_seq_codec.py` | Create | The PURE codec: `SEQ_MAGIC`/`SEQ_VERSION` constants; `_MAX_HEADER_BYTES` (header worst-case width); frozen `SeqFrame` value (`seq: int \| None`, `ack: int \| None`, `payload: bytes`); `encode_seq_frame(payload, *, seq, ack, max_unit_bytes) -> bytes`; `decode_seq_frame(raw, *, max_unit_bytes) -> SeqFrame` (magic-gated; plain-line fallback); `SeqDedupWindow` (per-leg `(seq)` accept-once + cumulative-ack contiguity/trim state machine, no I/O). Imports the bound + error type from `comms_wire`. Single-sourced; imported by both transports. |
| `src/alfred/plugins/comms_stdio_transport.py` | Modify | Task 0: re-point `_MAX_COMMS_LINE_BYTES` + `CommsProtocolError` to a re-export from `comms_wire` (keep both in `__all__`). Task 3: add an OPTIONAL `seq_ack_enabled: bool` + a per-direction `_send_seq` counter; when enabled, `send` calls `encode_seq_frame` (with `ack=0` PLACEHOLDER — NO `_recv_ack` high-water) and `read_frame` calls `decode_seq_frame` (splitting the header before the existing `json.loads`). Default-OFF = byte-for-byte the current behaviour. |
| `src/alfred/plugins/comms_socket_transport.py` | Modify | Task 0: import the bound + error type from `comms_wire` (replacing the `comms_stdio_transport` import). Task 4: the IDENTICAL gate-conditional codec insertion in its `send`/`read_frame` (`ack=0` placeholder, no `_recv_ack`). Single-sources framing from `comms_seq_codec` (no second framer). |
| `src/alfred/comms_mcp/protocol.py` | Modify | Add an OPTIONAL `seq_ack: SeqAckCapability \| None = None` field to `LifecycleStartRequest` (host advertises) + `LifecycleStartResult` (plugin echoes), and a `SeqAckCapability` frozen `_WireModel` (`version: Literal["1"]`). Closed vocab; `extra="forbid"`-safe because the field is OPTIONAL with a `None` default. |
| `src/alfred/plugins/comms_runner.py` | Modify | Add `enable_seq_ack` to the `_CommsTransportLike` Protocol (architect F4) so the runner flips it as a TYPED call. The handshake version-gate: advertise `seq_ack` in the `lifecycle.start` params; read the plugin's echo from the `lifecycle.start` result; record `self._seq_ack_negotiated: bool`; call `self._transport.enable_seq_ack()` ONLY when BOTH sides advertised (no `getattr` helper). No change to `id` correlation, `_pending`, or `_resolve_pending`. |
| `plugins/alfred_comms_test/main.py` | ~~Modify (Task 6)~~ **REVERTED (PR #262)** | The original Task 6 echoed `seq_ack` from `handle_lifecycle_start`; it was REMOVED. A daemon-spawned plugin is not the seq/ack peer (core↔gateway leg / G3 only) and never deframes the `A1` header, so echoing flipped the host gate ON and broke every host→plugin frame. The reference plugin does NOT advertise seq/ack; the wire to it stays plain ADR-0025. |
| `docs/adr/0032-gateway-comms-resume-transport.md` | Create | ADR-0032 first cut (Proposed), scoped to the codec/wire-format: out-of-band header grammar, version-gate, `(leg,seq)` dedup, cumulative-ack semantics, the G2/G3-G4 scope split. |
| `tests/unit/plugins/test_comms_seq_codec.py` | Create | Pure-codec unit + **hypothesis property** tests: round-trip (generator injects `b" \|"` + `n=`-shaped runs into the payload — test F1); a REAL FIFO/ordering PROPERTY (encode a list with `seq=i`, decode all, assert `[f.seq]==range(n)` + payloads in send order — test F2); no-delimiter-arm + empty-payload decode (test F3); dedup idempotency (re-seen `(leg,seq)` dropped); ack monotonically trims; cumulative-ack contiguity (a gap does not advance ack); magic-gated plain-line fallback in BOTH directions (test F4); over-bound (on encode AND decode) + lying-length + non-magic-malformed raise `CommsProtocolError`; the `max_unit_bytes - _MAX_HEADER_BYTES` payload-ceiling boundary. Drives `decode`'s over-bound + no-delim branches so the codec hits 100% line+branch. |
| `tests/unit/plugins/test_comms_seq_codec_transport.py` | Create | Transport-integration: a `CommsStdioTransport`/`CommsSocketTransport` with `seq_ack_enabled=True` round-trips a frame WITH the header; with it OFF the wire is byte-for-byte the plain ADR-0025 frame; a negotiated-OFF reader still decodes a plain frame from an un-upgraded peer (fallback); `id` is preserved across encode→decode. |
| `tests/unit/plugins/test_comms_runner_seq_gate.py` | Create | Handshake version-gate: both-advertise → `seq_ack_enabled` flipped ON; host-advertises-but-plugin-silent → stays OFF (fallback); plugin-advertises-but-host-silent → stays OFF; the negotiation does NOT change `id` allocation or `_pending` behaviour. **PR #262 adds a host-send byte-shape regression** (runs on the required non-root gate): the runner drives the REAL `CommsStdioTransport` through a handshake — a non-echoing peer → gate stays OFF → a host `send()` emits PLAIN ADR-0025 bytes (no `A1`); an echoing peer → gate flips → `A1`-wrapped (negative control), proving the host never wraps a frame a non-deframing peer can't read. |

---

## Key invariants (the plan must preserve all of these)

1. **Out-of-band, payload-verbatim.** The codec NEVER `json.loads` the payload. `encode` prepends a header to the already-serialized frame bytes; `decode` splits the header off and returns the payload bytes UNCHANGED. A round-trip `decode(encode(p)).payload == p` holds for every `p` (property test).
2. **`seq` is additive to + distinct from `id`.** The codec touches no payload byte, so the JSON-RPC `id` the runner correlates on (`comms_runner.py:230/586`) is structurally untouched. No task modifies `_pending`, `_resolve_pending`, `send_request`'s id allocation, or the `_LIFECYCLE_START_ID` constant.
3. **Dedup key is `(leg, seq)` ONLY — never payload-derived.** `SeqDedupWindow` keys on `seq` within its per-leg construction; no code path hashes/parses/inspects the payload to derive a dedup value. A re-seen `(leg, seq)` is dropped idempotently (a third sighting behaves like the second). (Property test.)
4. **Cumulative ack = highest CONTIGUOUS seq durably intaken; acks are NOT per-frame; the WIRE ack is an `a=0` placeholder in G2.** `SeqDedupWindow.cumulative_ack()` returns the top of the unbroken `0..k` run, NOT merely the max seq seen. A gap (seq received out of contiguity) does NOT advance the ack. **G2 fires NO ack timer, sends NO standalone ack, and the transport emits `a=0` as a PLACEHOLDER — it does NOT piggyback a `max(seq seen)` high-water and stores NO `_recv_ack`.** A high-water would falsely ack past gaps, contradicting the contiguous-ack semantics (architect F2 + test F3). The codec carries an `ack` field and `SeqDedupWindow` computes the real value, but COALESCING (piggyback + bounded timer) AND the choice of ack source are SENDER/relay behaviours owned by G3; the G3 relay wires `SeqDedupWindow.cumulative_ack()` as the ack source. G2 proves the ack-VALUE semantics on the PURE window by assertion; the transport does not emit a computed ack. (Property test: ack monotonically non-decreasing; a gap stalls it; filling the gap advances it.)
5. **Version-gated, default-OFF, mixed-safe fallback.** The seq/ack header is emitted ONLY when BOTH peers advertised support at the handshake. `decode` is magic-gated: a line without the `A1` magic prefix returns an un-sequenced `SeqFrame` (plain ADR-0025), so an un-negotiated or one-direction-only wire still reads. The default (no advertise) is the EXACT current ADR-0025 byte stream.
6. **`_MAX_COMMS_LINE_BYTES` unchanged, bounds the whole unit.** The codec validates `header_len + payload_len <= _MAX_COMMS_LINE_BYTES`; the out-of-band header cannot smuggle past the per-frame DoS bound.
7. **Fail-loud, content-free errors.** A malformed header (bad magic-with-prefix, non-integer seq/ack, lying `n=`, over-bound unit) raises `CommsProtocolError` with NO raw payload bytes on the exception (spec §5.6). The transport's existing malformed-frame structlog + raise path handles it uniformly (`comms_runner.py:423`).
8. **The codec is PURE** — no I/O, no clock, no global state, no async. `encode`/`decode` are functions; `SeqDedupWindow` is a small state machine constructed per-leg with explicit state. This is what makes the spec's "hypothesis-property-testable unit" claim true.
9. **Single-sourced + cycle-free.** BOTH transports import the codec from `comms_seq_codec`; there is no second framer. The bound + error type live in the leaf module `comms_wire` (Task 0), which the codec AND both transports import — so `comms_seq_codec` ↔ transport is NOT a bidirectional import (architect F6). `python -c "import alfred.plugins.comms_seq_codec"` imports cleanly. (The duplication that exists today for the PLAIN frame is acceptable to leave — G2 does not refactor the plain framers — but the SEQ header is defined exactly once.)
11. **Typed transport flip.** `_CommsTransportLike` declares `enable_seq_ack` (architect F4); the runner calls it as a typed method, not via `getattr`. Test fakes implement it explicitly.
10. **mypy --strict + pyright clean; ruff clean; the one reused operator string still routes via `t()`.**

---

## Task 0: Break the import cycle — extract `comms_wire.py` (architect F6)

**Why FIRST:** `comms_seq_codec` needs `_MAX_COMMS_LINE_BYTES` + `CommsProtocolError`; both transports will import the codec. If those two names stay in `comms_stdio_transport` and the codec imports them from there while the transport imports the codec, that is a bidirectional module-import cycle. Extracting the bound + error type into a LEAF module both sides import breaks it structurally.

**Files:**

- Create: `src/alfred/plugins/comms_wire.py`
- Modify: `src/alfred/plugins/comms_stdio_transport.py`, `src/alfred/plugins/comms_socket_transport.py`
- Test: `tests/unit/plugins/test_comms_wire.py` (re-export contract) + the existing transport suites (unchanged behaviour)

- [ ] **Step 1: Write the failing test**

Create `tests/unit/plugins/test_comms_wire.py`:

```python
"""The shared comms-wire constants leaf module (Spec A G2 / ADR-0032) (#237)."""

from __future__ import annotations

from alfred.plugins import comms_seq_codec, comms_socket_transport, comms_stdio_transport
from alfred.plugins.comms_wire import _MAX_COMMS_LINE_BYTES, CommsProtocolError


def test_bound_is_the_ten_mib_dos_cap() -> None:
    assert _MAX_COMMS_LINE_BYTES == 10 * 1024 * 1024


def test_protocol_error_is_an_alfred_error() -> None:
    from alfred.errors import AlfredError

    assert issubclass(CommsProtocolError, AlfredError)


def test_transports_reexport_the_same_objects() -> None:
    """Existing importers (stdio/socket) re-export the IDENTICAL bound + class."""
    assert comms_stdio_transport._MAX_COMMS_LINE_BYTES is _MAX_COMMS_LINE_BYTES
    assert comms_stdio_transport.CommsProtocolError is CommsProtocolError
    assert comms_socket_transport.CommsProtocolError is CommsProtocolError


def test_no_import_cycle_when_importing_the_codec() -> None:
    """The codec imports the bound from comms_wire, not the transport."""
    assert comms_seq_codec._MAX_COMMS_LINE_BYTES is _MAX_COMMS_LINE_BYTES
```

> Note: this test imports `comms_seq_codec`, which does not exist until Task 1 — split it: the first three cases run after Task 0; the `comms_seq_codec` references in the import line + `test_no_import_cycle...` are added in Task 1. For Task 0, write only the `comms_wire` + re-export cases (drop the codec import). Re-add the codec line in Task 1's test step.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/plugins/test_comms_wire.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'alfred.plugins.comms_wire'`.

- [ ] **Step 3: Write minimal implementation**

Create `src/alfred/plugins/comms_wire.py` — move the bound + the `CommsProtocolError` class verbatim out of `comms_stdio_transport`:

```python
"""Shared comms-wire constants — the per-frame DoS bound + protocol-error type.

Spec A G2 / ADR-0032 (#237). A LEAF module (depends only on
:mod:`alfred.errors`) so the comms transports AND the seq/ack codec
(:mod:`alfred.plugins.comms_seq_codec`) can all import the bound + the
loud-failure type from ONE place. Before G2 these lived in
``comms_stdio_transport``; the codec needs them and both transports import the
codec, so leaving them in the transport would close a bidirectional import
cycle (architect F6). They move here UNCHANGED; the transports re-export them so
no existing importer churns.
"""

from __future__ import annotations

from typing import Final

from alfred.errors import AlfredError

# Mirrors :data:`alfred.plugins.stdio_transport._MAX_INBOUND_FRAME_BYTES` (10MB):
# a plugin that emits a single line larger than this is misbehaving, and the host
# refuses the frame rather than let a "claim 4GB on one line" wedge the loop.
_MAX_COMMS_LINE_BYTES: Final[int] = 10 * 1024 * 1024


class CommsProtocolError(AlfredError):
    """The comms wire produced a malformed or over-bound frame.

    Mirrors :class:`alfred.plugins.stdio_transport.PluginProtocolError`: a
    wire-level violation the transport raises BEFORE the frame reaches the
    session dispatcher. The raw bytes are never carried on the exception
    (spec §5.6 — no T3 in error attributes).
    """


__all__ = ["_MAX_COMMS_LINE_BYTES", "CommsProtocolError"]
```

In `comms_stdio_transport.py`: DELETE the in-file `_MAX_COMMS_LINE_BYTES` assignment (and its comment) + the `CommsProtocolError` class body; replace with a re-export near the top imports:

```python
from alfred.plugins.comms_wire import _MAX_COMMS_LINE_BYTES, CommsProtocolError
```

Keep both names in `comms_stdio_transport.__all__` (they re-export). In `comms_socket_transport.py`, change its import (`comms_socket_transport.py:53-56`) to pull from `comms_wire` instead of `comms_stdio_transport`:

```python
from alfred.plugins.comms_wire import _MAX_COMMS_LINE_BYTES, CommsProtocolError
```

(`comms_socket_transport.__all__` already lists `CommsProtocolError` — leave it.)

- [ ] **Step 4: Run tests to verify green + no behaviour change**

Run: `uv run pytest tests/unit/plugins/test_comms_wire.py tests/unit/plugins/test_comms_stdio_transport.py tests/unit/plugins/test_comms_socket_transport.py -q`
Expected: PASS — the bound + error type are byte-identical, just relocated; the transport suites are untouched.

Run: `python -c "import alfred.plugins.comms_stdio_transport, alfred.plugins.comms_socket_transport, alfred.plugins.comms_wire"`
Expected: no error (the codec cycle check lands in Task 1, after the codec exists).

- [ ] **Step 5: Type-check + lint + commit**

```bash
uv run mypy src/alfred/plugins/comms_wire.py src/alfred/plugins/comms_stdio_transport.py src/alfred/plugins/comms_socket_transport.py && uv run pyright src/ && uv run ruff check src/alfred/plugins/comms_wire.py src/alfred/plugins/comms_stdio_transport.py src/alfred/plugins/comms_socket_transport.py
git add src/alfred/plugins/comms_wire.py src/alfred/plugins/comms_stdio_transport.py src/alfred/plugins/comms_socket_transport.py tests/unit/plugins/test_comms_wire.py
git commit -m "refactor(comms): extract comms_wire leaf module to break codec import cycle (Spec A G2 / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

> **Coverage note:** `comms_wire.py` is a trust-boundary-adjacent carrier file (it holds the DoS bound + the loud-failure type). Add it to the per-file CI coverage gate alongside the transports in Task 8 (the two-gates pattern). Its branch surface is trivial (a constant + an empty exception subclass), so 100% line+branch is automatic from the transport suites.

---

## Task 1: The pure codec — `SeqFrame`, `encode`, `decode`

**Files:**

- Create: `src/alfred/plugins/comms_seq_codec.py`
- Test: `tests/unit/plugins/test_comms_seq_codec.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/plugins/test_comms_seq_codec.py`:

```python
"""Pure CommsSeqCodec encode/decode + dedup-window (Spec A G2 / ADR-0032) (#237)."""

from __future__ import annotations

import pytest
from hypothesis import given, strategies as st

from alfred.plugins.comms_seq_codec import (
    _MAX_HEADER_BYTES,
    SEQ_MAGIC,
    SeqFrame,
    decode_seq_frame,
    encode_seq_frame,
)
from alfred.plugins.comms_wire import _MAX_COMMS_LINE_BYTES, CommsProtocolError

_PLAIN = b'{"jsonrpc":"2.0","id":7,"method":"inbound.message","params":{}}'


def test_encode_prepends_magic_header() -> None:
    raw = encode_seq_frame(_PLAIN, seq=3, ack=1)
    assert raw.startswith(SEQ_MAGIC)
    assert raw.endswith(b"\n")


def test_round_trip_preserves_payload_verbatim() -> None:
    raw = encode_seq_frame(_PLAIN, seq=3, ack=1)
    frame = decode_seq_frame(raw)
    assert frame.payload == _PLAIN  # byte-for-byte, never re-serialized
    assert frame.seq == 3
    assert frame.ack == 1


def test_plain_line_without_magic_is_fallback() -> None:
    """A non-negotiated peer's plain ADR-0025 line decodes as un-sequenced."""
    frame = decode_seq_frame(_PLAIN + b"\n")
    assert frame.seq is None
    assert frame.ack is None
    assert frame.payload == _PLAIN


def test_id_inside_payload_is_untouched() -> None:
    """The codec never decodes the payload, so the JSON-RPC id survives."""
    raw = encode_seq_frame(_PLAIN, seq=99, ack=0)
    assert b'"id":7' in decode_seq_frame(raw).payload


def test_lying_length_raises() -> None:
    raw = encode_seq_frame(_PLAIN, seq=1, ack=0)
    # Corrupt the declared n= so it no longer matches the payload run.
    tampered = raw.replace(b"n=%d" % len(_PLAIN), b"n=%d" % (len(_PLAIN) + 5))
    with pytest.raises(CommsProtocolError):
        decode_seq_frame(tampered)


def test_non_integer_seq_raises() -> None:
    bad = SEQ_MAGIC + b" s=NOPE a=0 n=2 |{}\n"
    with pytest.raises(CommsProtocolError):
        decode_seq_frame(bad)


def test_over_bound_unit_raises_on_encode() -> None:
    huge = b"x" * 16
    with pytest.raises(CommsProtocolError):
        encode_seq_frame(huge, seq=0, ack=0, max_unit_bytes=8)


def test_over_bound_raw_raises_on_decode() -> None:
    """The decode path enforces the bound too (test F4 — drive the decode branch)."""
    raw = encode_seq_frame(b"x" * 32, seq=0, ack=0)
    with pytest.raises(CommsProtocolError):
        decode_seq_frame(raw, max_unit_bytes=8)


def test_payload_ceiling_boundary_encodes_then_one_byte_more_raises() -> None:
    """On a negotiated wire the payload ceiling is max_unit_bytes - _MAX_HEADER_BYTES.

    Option A (architect F1 + test F4): the header costs budget, so the usable
    payload shrinks. A payload at exactly the ceiling encodes; one byte more
    raises on SEND.
    """
    cap = 256
    ceiling = cap - _MAX_HEADER_BYTES
    ok = b"x" * ceiling
    assert encode_seq_frame(ok, seq=0, ack=0, max_unit_bytes=cap).endswith(b"\n")
    with pytest.raises(CommsProtocolError):
        encode_seq_frame(ok + b"x", seq=0, ack=0, max_unit_bytes=cap)


def test_no_delimiter_arm_raises() -> None:
    """A magic-prefixed line with no `` |`` delimiter is malformed (branch cover)."""
    bad = SEQ_MAGIC + b" s=0 a=0 n=0"  # header, no delimiter, no payload
    with pytest.raises(CommsProtocolError):
        decode_seq_frame(bad + b"\n")


def test_empty_payload_round_trips() -> None:
    raw = encode_seq_frame(b"", seq=0, ack=0)
    frame = decode_seq_frame(raw)
    assert frame.payload == b""
    assert frame.seq == 0


def test_negative_seq_rejected_on_encode() -> None:
    with pytest.raises(ValueError):
        encode_seq_frame(_PLAIN, seq=-1, ack=0)


# --- hypothesis property tests -------------------------------------------------

# Building blocks that LOOK like header structure inside the payload, so the
# round-trip proves the `` |`` delimiter + `n=` length-prefix split is unambiguous
# regardless of payload content (test F1). The codec must split on the FIRST
# `` |`` and trust `n=`, never re-scan the payload.
_ADVERSARIAL_CHUNK = st.sampled_from([b"x", b" |", b"n=5", b"a=0", b"A1 ", b"\t", b"{}"])
_ADVERSARIAL_PAYLOAD = (
    st.lists(_ADVERSARIAL_CHUNK, max_size=64).map(b"".join).filter(lambda b: b"\n" not in b)
)


@given(
    payload=_ADVERSARIAL_PAYLOAD,
    seq=st.integers(min_value=0, max_value=2**31),
    ack=st.integers(min_value=0, max_value=2**31),
)
def test_property_round_trip_is_identity_on_payload(
    payload: bytes, seq: int, ack: int
) -> None:
    frame = decode_seq_frame(encode_seq_frame(payload, seq=seq, ack=ack))
    assert frame.payload == payload  # delimiter/length split is unambiguous
    assert frame.seq == seq
    assert frame.ack == ack


@given(
    payloads=st.lists(_ADVERSARIAL_PAYLOAD, min_size=1, max_size=16),
)
def test_property_fifo_ordering_preserved(payloads: list[bytes]) -> None:
    """Encode a list with seq=i, decode all: seqs == range(n) AND payloads in order."""
    units = [encode_seq_frame(p, seq=i, ack=0) for i, p in enumerate(payloads)]
    frames = [decode_seq_frame(u) for u in units]
    assert [f.seq for f in frames] == list(range(len(payloads)))
    assert [f.payload for f in frames] == payloads
```

> **Strategy note:** the payload strategies filter out `\n` because the wire unit is newline-terminated — a payload containing a raw newline is not a single ADR-0025 line (the existing transports never emit one; `json.dumps` escapes newlines inside strings to `\\n`). The codec treats `\n` as the unit terminator, so an embedded newline is out of contract by construction. The `_ADVERSARIAL_PAYLOAD` strategy deliberately INJECTS `b" |"`, `n=`-shaped, and magic-shaped runs into the payload so the round-trip + FIFO properties prove the delimiter/length-prefix split is unambiguous against a hostile payload (test F1/F2). Documenting this keeps the property honest.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/plugins/test_comms_seq_codec.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'alfred.plugins.comms_seq_codec'`.

- [ ] **Step 3: Write minimal implementation**

Create `src/alfred/plugins/comms_seq_codec.py`:

```python
"""``CommsSeqCodec`` — out-of-band seq/ack/dedup framing for the comms wire.

Spec A G2 / ADR-0032 (#237). A PURE codec that wraps the opaque ADR-0025
line-delimited comms payload (``json.dumps(frame) + "\\n"``) with a small
out-of-band ASCII header carrying a per-direction monotonic ``seq``, a
cumulative ``ack``, and a payload byte-length. The header is CARRIER metadata:
``seq``/``ack``/``n`` are computed from the transport's own counters and the
payload's BYTE LENGTH — never from the payload's CONTENT (spec §6). The codec
NEVER ``json.loads`` the payload, so the relay (G3) forwards the body verbatim,
the wire stays payload-blind (T1 carrier), and the JSON-RPC ``id`` the runner
correlates on survives end-to-end (it lives inside the opaque payload, which the
codec treats as an untouchable byte run).

**Wire shape** (one newline-terminated unit when seq/ack is negotiated)::

    A1 s=<seq> a=<ack> n=<payload_len> |<opaque-payload-bytes>\\n

``A1`` is the magic (``A`` = AlfredSeqAck) + wire version (``1``). A line WITHOUT
the magic is a PLAIN ADR-0025 frame — :func:`decode_seq_frame` recognises it and
returns an un-sequenced :class:`SeqFrame` (the version-gate default-OFF fallback),
so a mixed / one-direction-only wire still reads.

**Version-gated, default-OFF.** The negotiation lives in the ``lifecycle.start``
handshake (``alfred.plugins.comms_runner``); this module only knows how to encode
a frame WITH the header and decode either form. The header is emitted only when
BOTH peers advertised support.

**Trust posture.** Fail-loud on a malformed header (over-bound unit, non-integer
``seq``/``ack``, a ``n=`` that does not match the payload run) via
:class:`alfred.plugins.comms_wire.CommsProtocolError`, carrying NO raw payload
bytes on the exception (spec §5.6). ``_MAX_COMMS_LINE_BYTES`` still bounds the
WHOLE unit (header + payload + ``\\n``) so the out-of-band header cannot smuggle
past the per-frame DoS bound. On a NEGOTIATED wire the header costs budget, so the
effective payload ceiling is ``max_unit_bytes - _MAX_HEADER_BYTES`` (Option A).

**Pure.** No I/O, no clock, no global state, no async — encode/decode are
functions and :class:`SeqDedupWindow` is an explicit per-leg state machine. This
is what makes the codec a hypothesis-property-testable unit (spec §7/§9).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from alfred.plugins.comms_wire import (
    _MAX_COMMS_LINE_BYTES,
    CommsProtocolError,
)

#: Magic + wire version. ``A`` = AlfredSeqAck; ``1`` = wire version 1. A unit that
#: does not start with this is a plain ADR-0025 frame (default-OFF fallback).
SEQ_VERSION: Final[str] = "1"
SEQ_MAGIC: Final[bytes] = b"A" + SEQ_VERSION.encode()

# The single header/payload delimiter. It cannot occur in the fixed
# ``A1 s= a= n=`` header grammar, so the FIRST ``|`` unambiguously ends the
# header and begins the opaque payload run.
_DELIM: Final[bytes] = b" |"

# Worst-case header width (Option A — architect F1 + test F4). The fixed grammar
# is ``A1 s=<seq> a=<ack> n=<len> |`` — i.e. the literal skeleton plus three
# base-10 counters. Each counter is at most as wide as the decimal expansion of
# ``_MAX_COMMS_LINE_BYTES`` (the payload-len field is itself bounded by it, and
# ``seq``/``ack`` are operationally never wider in a single boot's lifetime). On a
# NEGOTIATED wire the header costs budget, so the EFFECTIVE payload ceiling is
# ``max_unit_bytes - _MAX_HEADER_BYTES``. The runtime bound is still enforced on
# the OUTER unit in :func:`encode_seq_frame`; ``_MAX_HEADER_BYTES`` is the
# DOCUMENTED reservation a caller (and the G3 relay) sizes payloads against, and
# the value the ceiling boundary test pins.
_MAX_DECIMAL_WIDTH: Final[int] = len(str(_MAX_COMMS_LINE_BYTES))
_HEADER_SKELETON: Final[bytes] = b"A1 s= a= n= |"  # literal chars + the delimiter
_MAX_HEADER_BYTES: Final[int] = len(_HEADER_SKELETON) + 3 * _MAX_DECIMAL_WIDTH


@dataclass(frozen=True, slots=True)
class SeqFrame:
    """A decoded wire unit: header seq/ack (or ``None`` for a plain frame) + payload.

    ``payload`` is the opaque ADR-0025 frame bytes, byte-for-byte — the codec
    never decodes it. ``seq``/``ack`` are ``None`` when the unit was a plain
    (non-negotiated) ADR-0025 line.
    """

    seq: int | None
    ack: int | None
    payload: bytes


def encode_seq_frame(
    payload: bytes,
    *,
    seq: int,
    ack: int,
    max_unit_bytes: int = _MAX_COMMS_LINE_BYTES,
) -> bytes:
    """Wrap ``payload`` (an ADR-0025 frame line, no trailing newline) with the header.

    Returns the newline-terminated wire unit. ``seq``/``ack`` must be
    non-negative (a negative counter is a programming error, raised loudly). The
    whole unit (header + payload + newline) is bounded by ``max_unit_bytes`` so
    the out-of-band header cannot exceed the per-frame DoS bound.
    """
    if seq < 0 or ack < 0:
        raise ValueError(f"seq/ack must be non-negative: seq={seq} ack={ack}")
    header = b"%s s=%d a=%d n=%d" % (SEQ_MAGIC, seq, ack, len(payload))
    unit = header + _DELIM + payload + b"\n"
    if len(unit) > max_unit_bytes:
        raise CommsProtocolError("comms seq frame exceeds the per-frame byte bound")
    return unit


def decode_seq_frame(
    raw: bytes,
    *,
    max_unit_bytes: int = _MAX_COMMS_LINE_BYTES,
) -> SeqFrame:
    """Decode one wire unit; magic-gated, with a plain-ADR-0025 fallback.

    A unit beginning with :data:`SEQ_MAGIC` is parsed for ``seq``/``ack``/``n``
    and its payload run validated against ``n``. A unit WITHOUT the magic is a
    plain ADR-0025 frame (default-OFF fallback): its line (sans trailing newline)
    is returned as ``SeqFrame(seq=None, ack=None, payload=...)``. Raises
    :class:`CommsProtocolError` on an over-bound unit or a malformed header,
    carrying NO raw payload bytes.
    """
    if len(raw) > max_unit_bytes:
        raise CommsProtocolError("comms seq frame exceeds the per-frame byte bound")
    line = raw[:-1] if raw.endswith(b"\n") else raw
    if not line.startswith(SEQ_MAGIC):
        # Plain ADR-0025 frame — the negotiation default-OFF fallback.
        return SeqFrame(seq=None, ack=None, payload=line)
    delim_at = line.find(_DELIM)
    if delim_at == -1:
        raise CommsProtocolError("comms seq frame header has no payload delimiter")
    header = line[:delim_at]
    payload = line[delim_at + len(_DELIM) :]
    try:
        magic, s_tok, a_tok, n_tok = header.split(b" ")
        if magic != SEQ_MAGIC:
            raise ValueError("magic mismatch")
        seq = _parse_kv(s_tok, b"s=")
        ack = _parse_kv(a_tok, b"a=")
        declared_len = _parse_kv(n_tok, b"n=")
    except ValueError as exc:
        raise CommsProtocolError("comms seq frame header is malformed") from exc
    if declared_len != len(payload):
        raise CommsProtocolError("comms seq frame declared length mismatch")
    return SeqFrame(seq=seq, ack=ack, payload=payload)


def _parse_kv(token: bytes, prefix: bytes) -> int:
    """Parse ``<prefix><non-negative-int>``; raise ``ValueError`` otherwise."""
    if not token.startswith(prefix):
        raise ValueError(f"expected {prefix!r} prefix")
    value = int(token[len(prefix) :])  # raises ValueError on non-digits
    if value < 0:
        raise ValueError("negative counter")
    return value


__all__ = [
    "_MAX_HEADER_BYTES",
    "SEQ_MAGIC",
    "SEQ_VERSION",
    "SeqFrame",
    "decode_seq_frame",
    "encode_seq_frame",
]
```

> **Note on `b"%d" % int` formatting:** Python supports `bytes.__mod__` with `%d`/`%s` (PEP 461). Confirm `ruff`/`mypy` are clean on the `%`-format-bytes; if a rule objects, switch to `f"...".encode()`. The grammar's single-space separators + the leading `b" |"` delimiter keep the header unambiguously splittable.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/plugins/test_comms_seq_codec.py -q`
Expected: PASS (all unit + the round-trip property green).

- [ ] **Step 5: Verify NO import cycle + type-check + lint**

Run: `python -c "import alfred.plugins.comms_seq_codec"` — Expected: clean import (the codec imports the bound from `comms_wire`, not the transport, so there is no cycle).

Re-add the codec lines to `tests/unit/plugins/test_comms_wire.py` (the import line + `test_no_import_cycle_when_importing_the_codec`) now that the codec exists, and re-run that file.

Run: `uv run mypy src/alfred/plugins/comms_seq_codec.py && uv run pyright src/alfred/plugins/comms_seq_codec.py && uv run ruff check src/alfred/plugins/comms_seq_codec.py`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/plugins/comms_seq_codec.py tests/unit/plugins/test_comms_seq_codec.py tests/unit/plugins/test_comms_wire.py
git commit -m "feat(comms): pure out-of-band seq/ack frame codec (Spec A G2 / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 2: The dedup + cumulative-ack window — `SeqDedupWindow`

**Files:**

- Modify: `src/alfred/plugins/comms_seq_codec.py`
- Test: extend `tests/unit/plugins/test_comms_seq_codec.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/plugins/test_comms_seq_codec.py`:

```python
from hypothesis import settings
from alfred.plugins.comms_seq_codec import SeqDedupWindow


def test_window_accepts_in_order_and_advances_ack() -> None:
    w = SeqDedupWindow(leg="inbound")
    assert w.accept(0) is True
    assert w.accept(1) is True
    assert w.accept(2) is True
    assert w.cumulative_ack() == 2


def test_window_drops_reseen_seq_idempotently() -> None:
    w = SeqDedupWindow(leg="inbound")
    assert w.accept(0) is True
    assert w.accept(0) is False  # re-seen (leg, seq) dropped
    assert w.accept(0) is False  # third sighting behaves like the second
    assert w.cumulative_ack() == 0


def test_window_gap_does_not_advance_ack() -> None:
    w = SeqDedupWindow(leg="inbound")
    assert w.accept(0) is True
    assert w.accept(2) is True  # accepted (new) but NON-contiguous
    assert w.cumulative_ack() == 0  # ack stalls at the top of the 0.. run
    assert w.accept(1) is True  # fills the gap
    assert w.cumulative_ack() == 2  # now the run is 0,1,2


def test_ack_is_monotonic_non_decreasing() -> None:
    w = SeqDedupWindow(leg="inbound")
    for s in (0, 1, 2):
        w.accept(s)
    high = w.cumulative_ack()
    w.accept(2)  # re-seen — must not lower the ack
    assert w.cumulative_ack() == high


@settings(max_examples=200)
@given(seqs=st.lists(st.integers(min_value=0, max_value=64), max_size=128))
def test_property_ack_never_exceeds_contiguous_run(seqs: list[int]) -> None:
    """ack == top of the unbroken 0..k run, regardless of arrival order."""
    w = SeqDedupWindow(leg="inbound")
    seen: set[int] = set()
    for s in seqs:
        accepted = w.accept(s)
        assert accepted is (s not in seen)  # dedup idempotency
        seen.add(s)
    # Independent recomputation of the contiguous high-water.
    expected = -1
    while (expected + 1) in seen:
        expected += 1
    assert w.cumulative_ack() == expected


@given(seqs=st.lists(st.integers(min_value=0, max_value=64), max_size=128))
def test_property_replay_is_idempotent(seqs: list[int]) -> None:
    """Replaying the whole sequence a second time accepts nothing new + same ack."""
    w = SeqDedupWindow(leg="inbound")
    for s in seqs:
        w.accept(s)
    ack_after_first = w.cumulative_ack()
    for s in seqs:
        assert w.accept(s) is False  # every replayed (leg, seq) is a dup
    assert w.cumulative_ack() == ack_after_first
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/plugins/test_comms_seq_codec.py -q`
Expected: FAIL with `ImportError: cannot import name 'SeqDedupWindow'`.

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/plugins/comms_seq_codec.py`, before `__all__`, add:

```python
class SeqDedupWindow:
    """Per-leg accept-once + cumulative-ack state machine (Spec A §4).

    Constructed PER DIRECTION (``leg`` = ``"inbound"`` / ``"outbound"``), so the
    dedup key is effectively ``seq`` within this leg — matching the spec's
    "key = ``(leg, seq)`` ONLY — never payload-derived". :meth:`accept` returns
    ``True`` the FIRST time a ``seq`` is seen and ``False`` on every re-sighting
    (idempotent). :meth:`cumulative_ack` returns the highest CONTIGUOUS seq seen
    (the top of the unbroken ``0..k`` run) — NOT merely the max — so a gap stalls
    the ack until it is filled.

    **No ack emission here.** This computes the ack VALUE; COALESCING (piggyback +
    bounded timer) is a sender/relay behaviour owned by G3. G2 proves the value
    semantics; it does not fire acks.

    Pure: explicit state, no I/O, no clock. The seen-set grows unbounded — that is
    correct for G2 (a pure unit under test); the bounded retention the seen-set
    needs in production is a G4 (ReplayBuffer) concern, stated in ADR-0032's scope
    note, not built here.
    """

    def __init__(self, *, leg: str) -> None:
        self._leg = leg
        self._seen: set[int] = set()
        self._contiguous_high: int = -1

    @property
    def leg(self) -> str:
        return self._leg

    def accept(self, seq: int) -> bool:
        """Record ``seq``; return ``True`` if NEW, ``False`` if a re-seen dup."""
        if seq < 0:
            raise ValueError(f"seq must be non-negative: {seq}")
        if seq in self._seen:
            return False
        self._seen.add(seq)
        # Advance the contiguous high-water as far as the unbroken run reaches.
        while (self._contiguous_high + 1) in self._seen:
            self._contiguous_high += 1
        return True

    def cumulative_ack(self) -> int:
        """Highest CONTIGUOUS seq seen (top of the unbroken 0.. run); -1 if none."""
        return self._contiguous_high
```

Add `"SeqDedupWindow"` to `__all__` (keep it sorted).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/plugins/test_comms_seq_codec.py -q`
Expected: PASS (all unit + properties green).

- [ ] **Step 5: Type-check + lint**

Run: `uv run mypy src/alfred/plugins/comms_seq_codec.py && uv run pyright src/alfred/plugins/comms_seq_codec.py && uv run ruff check src/alfred/plugins/comms_seq_codec.py`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/plugins/comms_seq_codec.py tests/unit/plugins/test_comms_seq_codec.py
git commit -m "feat(comms): per-leg (leg,seq) dedup + cumulative-ack window (Spec A G2 / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 3: Gate-conditional codec insertion into `CommsStdioTransport`

**Files:**

- Modify: `src/alfred/plugins/comms_stdio_transport.py`
- Test: `tests/unit/plugins/test_comms_seq_codec_transport.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/plugins/test_comms_seq_codec_transport.py`. Drive the transport over an in-memory pipe pair so no subprocess is needed — use the existing test seam the comms-transport unit tests use (check `tests/unit/plugins/test_comms_stdio_transport.py` for the in-memory `StreamReader`/`StreamWriter` fixture pattern and reuse it; if none exists, construct an `asyncio` socket pair). The load-bearing assertions:

```python
"""Gate-conditional seq/ack codec in the comms transports (Spec A G2) (#237)."""

from __future__ import annotations

import pytest

from alfred.plugins.comms_seq_codec import SEQ_MAGIC, decode_seq_frame


@pytest.mark.asyncio
async def test_send_with_seq_ack_off_is_plain_adr0025_bytes(...) -> None:
    """Default-OFF: the wire is byte-for-byte the existing plain frame."""
    # transport with seq_ack_enabled=False; capture the bytes written.
    # assert the written line == json.dumps(frame) + "\n" (no A1 prefix).
    ...


@pytest.mark.asyncio
async def test_send_with_seq_ack_on_carries_header(...) -> None:
    """Negotiated-ON: the wire carries the A1 header; the payload round-trips."""
    # transport with seq_ack_enabled=True; capture the bytes.
    # assert the written line startswith SEQ_MAGIC.
    # decode_seq_frame(line).payload == json.dumps(frame).encode()
    ...


@pytest.mark.asyncio
async def test_read_frame_decodes_seq_header_to_the_inner_object(...) -> None:
    """A negotiated reader strips the header and returns the inner JSON object."""
    # feed an encode_seq_frame(json.dumps({"id":7,...}).encode(), seq=3, ack=1)
    # assert read_frame() returns {"id": 7, ...} (the inner object, header stripped).
    ...


@pytest.mark.asyncio
async def test_read_frame_fallback_decodes_plain_line_when_enabled(...) -> None:
    """A negotiated reader still reads a PLAIN line from an un-upgraded peer."""
    # feed a plain json.dumps({"id":1}).encode()+b"\n" to a seq_ack_enabled reader.
    # assert read_frame() returns {"id": 1} (magic-gated fallback inside decode).
    ...


@pytest.mark.asyncio
async def test_id_preserved_across_seq_encode_decode(...) -> None:
    """The JSON-RPC id is untouched by the header round-trip."""
    # send {"id": 42, ...} ON; read it back; assert the returned frame["id"] == 42.
    ...
```

> **Implementer note:** fill the `...` bodies against whatever in-memory transport seam `tests/unit/plugins/test_comms_stdio_transport.py` already uses (it drives `send`/`read_frame` without a real launcher). Keep the assertions exactly as the docstrings state. If the stdio transport's `read_frame` reads from `self._proc.stdout`, use the same fake-process fixture that file uses; do NOT invent a new spawn path.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/plugins/test_comms_seq_codec_transport.py -q`
Expected: FAIL — `CommsStdioTransport` has no `seq_ack_enabled` parameter yet.

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/plugins/comms_stdio_transport.py`:

(a) Import the codec at module top (after the existing imports):

```python
from alfred.plugins.comms_seq_codec import (
    SeqFrame,
    decode_seq_frame,
    encode_seq_frame,
)
```

(b) Add the gate flag + the SEND seq counter to `__init__` (`comms_stdio_transport.py:120`), after `self._max_line_bytes = max_line_bytes`. **NO `_recv_ack` — the transport emits an `a=0` placeholder, not a high-water (architect F2 + test F3):**

```python
        # Spec A G2 (#237): out-of-band seq/ack framing, OFF by default. The
        # runner flips this ON (via enable_seq_ack) only when BOTH peers
        # advertised support at the lifecycle.start handshake (version-gate).
        # When OFF the wire is byte-for-byte the existing ADR-0025 plain frame.
        self._seq_ack_enabled = False
        self._send_seq = 0  # this transport's per-direction monotonic send seq
        # NOTE: the transport emits ``a=0`` as a PLACEHOLDER ack. It deliberately
        # does NOT track a received-seq high-water: a ``max(seq seen)`` ack would
        # falsely ack past gaps, contradicting the CONTIGUOUS-ack semantics
        # (ADR-0032 Decision 3). The real contiguous ack is computed by the pure
        # ``SeqDedupWindow.cumulative_ack()`` and wired as the ack source by the
        # G3 relay. G2's transport carries a placeholder; it consumes no ack.
```

Add a public flip method (the runner calls it post-handshake):

```python
    def enable_seq_ack(self) -> None:
        """Turn the out-of-band seq/ack header ON (post-handshake, version-gated).

        Idempotent flip the runner calls once the lifecycle.start negotiation
        confirmed BOTH peers speak ``AlfredSeqAck/1``. Until then the transport
        emits/reads the plain ADR-0025 frame (G2 default-OFF).
        """
        self._seq_ack_enabled = True
```

(c) In `send` (`comms_stdio_transport.py:159`), branch on the flag. Replace the `payload = (json.dumps(frame) + "\n").encode()` line (`comms_stdio_transport.py:172`) with — note `ack=0` is a PLACEHOLDER (G2 ships no ack consumer; the G3 relay supplies the real contiguous ack):

```python
        body = json.dumps(frame).encode()
        if self._seq_ack_enabled:
            payload = encode_seq_frame(
                body,
                seq=self._send_seq,
                ack=0,  # PLACEHOLDER (ADR-0032 Decision 3) — NOT a high-water; the
                #         G3 relay wires SeqDedupWindow.cumulative_ack() as the ack.
                max_unit_bytes=self._max_line_bytes,
            )
            self._send_seq += 1
        else:
            payload = body + b"\n"
```

(d) In `read_frame` (`comms_stdio_transport.py:183`), after the `readline()` + clean-EOF + over-bound checks (`comms_stdio_transport.py:197-216`) and BEFORE `json.loads(line)` (`comms_stdio_transport.py:218`), split the header when enabled:

```python
        if self._seq_ack_enabled:
            # Strip the out-of-band header; the inner payload continues through the
            # existing json.loads path unchanged. G2 CONSUMES NO seq/ack here — it
            # does not dedup, advance an ack, or store a high-water. The codec is
            # magic-gated, so a plain (un-upgraded peer) line still decodes via the
            # SeqFrame(seq=None, ...) fallback (mixed-wire safety). The relay (G3)
            # is where seq/ack are actually consumed.
            frame_unit: SeqFrame = decode_seq_frame(line, max_unit_bytes=self._max_line_bytes)
            line = frame_unit.payload  # opaque body, header stripped
        # ... existing json.loads(line) path continues unchanged ...
```

> **Implementer note (anchor exactly):** the existing `read_frame` returns `decoded` after the `isinstance(decoded, dict)` check (`comms_stdio_transport.py:224-231`). Insert the header-split so `line` becomes the inner payload BEFORE `json.loads`. `decode_seq_frame` is itself fail-loud (`CommsProtocolError`), so a malformed header surfaces through the SAME arm as a malformed plain frame — no new error handling needed. **The read path stores NO `_recv_ack` and acts on no seq value** — G2 carries seq/ack on the wire but consumes neither; the consumer is the G3 relay. This keeps the transport free of a dead high-water surface (the G1 lesson) and avoids the false-ack-past-gaps bug (architect F2).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/plugins/test_comms_seq_codec_transport.py -q`
Expected: PASS.

- [ ] **Step 5: Run the existing transport suite to prove default-OFF is byte-identical**

Run: `uv run pytest tests/unit/plugins/test_comms_stdio_transport.py -q`
Expected: PASS unchanged (the default-OFF path is the prior behaviour; no existing assertion moves).

- [ ] **Step 6: Type-check + lint + commit**

```bash
uv run mypy src/alfred/plugins/comms_stdio_transport.py && uv run pyright src/alfred/plugins/comms_stdio_transport.py && uv run ruff check src/alfred/plugins/comms_stdio_transport.py
git add src/alfred/plugins/comms_stdio_transport.py tests/unit/plugins/test_comms_seq_codec_transport.py
git commit -m "feat(comms): gate-conditional seq/ack header in CommsStdioTransport (Spec A G2 / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 4: The IDENTICAL insertion into `CommsSocketTransport`

**Files:**

- Modify: `src/alfred/plugins/comms_socket_transport.py`
- Test: extend `tests/unit/plugins/test_comms_seq_codec_transport.py` (parametrise the existing cases over both transports, or add socket-specific mirrors).

- [ ] **Step 1: Write the failing test**

Extend `tests/unit/plugins/test_comms_seq_codec_transport.py` with the socket mirror of the Task 3 cases (the socket transport drives an `asyncio.StreamReader`/`StreamWriter` pair directly — easier to fake than the stdio subprocess). Reuse the same five assertions (`send` OFF = plain bytes; `send` ON = header; `read_frame` decodes inner object; fallback reads a plain line; `id` preserved) against `CommsSocketTransport(adapter_id="tui", reader=..., writer=...)`. Prefer `pytest.mark.parametrize` over a transport factory so both carriers share one assertion body.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/plugins/test_comms_seq_codec_transport.py -q`
Expected: FAIL — `CommsSocketTransport` has no `enable_seq_ack` yet.

- [ ] **Step 3: Write minimal implementation**

Apply the SAME four edits as Task 3 to `comms_socket_transport.py`:

(a) Import the codec (Task 0 already re-pointed `_MAX_COMMS_LINE_BYTES` + `CommsProtocolError` to `from alfred.plugins.comms_wire import ...`; add `from alfred.plugins.comms_seq_codec import SeqFrame, decode_seq_frame, encode_seq_frame` alongside).

(b) Add `self._seq_ack_enabled = False` / `self._send_seq = 0` (NO `_recv_ack` — same `a=0` placeholder discipline as the stdio transport) to `CommsSocketTransport.__init__` (`comms_socket_transport.py:147`), and the same `enable_seq_ack` method.

(c) Branch `send` (`comms_socket_transport.py:164`) — replace the `payload = (json.dumps(frame) + "\n").encode()` line (`comms_socket_transport.py:172`) with the identical encode-or-plain branch (`ack=0` placeholder, `self._send_seq += 1`).

(d) Branch `read_frame` (`comms_socket_transport.py:180`) — after the `readline()` + EOF + over-bound checks (`comms_socket_transport.py:190-207`) and before `json.loads(line)` (`comms_socket_transport.py:209`), insert the identical header-split (strip only; consume no seq/ack).

> **Single-source check:** the encode/decode CALLS are identical to the stdio transport's; the FRAMING is single-sourced in `comms_seq_codec`. The transports differ only in their carrier (pipe vs socket) — exactly the existing split. Do not copy the codec logic; call into it.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/plugins/test_comms_seq_codec_transport.py -q`
Expected: PASS (both transports).

- [ ] **Step 5: Run the existing socket-transport suite + type-check + commit**

```bash
uv run pytest tests/unit/plugins/test_comms_socket_transport.py -q
uv run mypy src/alfred/plugins/comms_socket_transport.py && uv run pyright src/alfred/plugins/comms_socket_transport.py && uv run ruff check src/alfred/plugins/comms_socket_transport.py
git add src/alfred/plugins/comms_socket_transport.py tests/unit/plugins/test_comms_seq_codec_transport.py
git commit -m "feat(comms): gate-conditional seq/ack header in CommsSocketTransport (Spec A G2 / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 5: The handshake capability field — `SeqAckCapability`

**Files:**

- Modify: `src/alfred/comms_mcp/protocol.py`
- Test: extend `tests/unit/comms/test_lifecycle_notifications.py` (or a new `tests/unit/comms/test_seq_ack_capability.py`)

- [ ] **Step 1: Write the failing test**

Create `tests/unit/comms/test_seq_ack_capability.py`:

```python
"""Seq/ack handshake capability field (Spec A G2 / ADR-0032) (#237)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.comms_mcp.protocol import (
    LifecycleStartRequest,
    LifecycleStartResult,
    SeqAckCapability,
)


def test_capability_pins_version_one() -> None:
    assert SeqAckCapability(version="1").version == "1"
    with pytest.raises(ValidationError):
        SeqAckCapability(version="2")  # closed vocab — only "1" in G2


def test_start_request_seq_ack_defaults_none() -> None:
    """Absent capability == default-OFF; the field is optional."""
    req = LifecycleStartRequest(
        adapter_id="alfred_comms_test",
        credentials_ref="ref",
        policies_snapshot_hash="h",
    )
    assert req.seq_ack is None


def test_start_result_can_echo_capability() -> None:
    res = LifecycleStartResult(
        ok=True, plugin_version="0.1.0", seq_ack=SeqAckCapability(version="1")
    )
    assert res.seq_ack is not None and res.seq_ack.version == "1"


def test_start_result_seq_ack_defaults_none() -> None:
    res = LifecycleStartResult(ok=True, plugin_version="0.1.0")
    assert res.seq_ack is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/comms/test_seq_ack_capability.py -q`
Expected: FAIL with `ImportError: cannot import name 'SeqAckCapability'`.

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/comms_mcp/protocol.py`, before `LifecycleStartRequest` (`protocol.py:150`), add:

```python
class SeqAckCapability(_WireModel):
    """Negotiated out-of-band seq/ack support (Spec A G2 / ADR-0032).

    Advertised by the host in ``lifecycle.start`` params and ECHOED by the
    plugin in the ``lifecycle.start`` result when it speaks the same wire
    version. The out-of-band seq/ack header is emitted on the wire ONLY when
    BOTH peers carry this field (version-gate, default-OFF). ``version`` is a
    CLOSED ``Literal`` — only ``"1"`` exists in G2; widening it is a non-breaking
    change a future wire revision makes with its consumer. Carries NO T3: the
    field is pure transport-capability metadata.
    """

    version: Literal["1"]
```

Then add `seq_ack: SeqAckCapability | None = None` to BOTH `LifecycleStartRequest` (`protocol.py:150`) and `LifecycleStartResult` (`protocol.py:158`) as the LAST field. (The `None` default keeps `extra="forbid"` happy AND makes "field absent == default-OFF" the explicit contract.) Add `"SeqAckCapability"` to `__all__` (sorted).

> **`extra="forbid"` check:** because the field has a `None` default, a conformant existing peer that omits it still validates (the default fills in), and the reference plugin's current `{"ok": True, "plugin_version": ...}` result (`main.py:127`) still validates against `LifecycleStartResult` (the new optional field defaults to `None`). This is the load-bearing reason the addition is backward-safe.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/comms/test_seq_ack_capability.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Run the existing protocol + lifecycle suites + commit**

```bash
uv run pytest tests/unit/comms -q
git add src/alfred/comms_mcp/protocol.py tests/unit/comms/test_seq_ack_capability.py
git commit -m "feat(comms): seq/ack handshake capability field on lifecycle.start (Spec A G2 / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 6: The runner version-gate negotiation + reference-plugin opt-in

**Files:**

- Modify: `src/alfred/plugins/comms_runner.py`
- Modify: `plugins/alfred_comms_test/main.py`
- Test: `tests/unit/plugins/test_comms_runner_seq_gate.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/plugins/test_comms_runner_seq_gate.py`. Drive a `CommsPluginRunner` with an in-memory fake transport (reuse the fake-transport seam the existing `tests/unit/plugins/test_comms_runner.py` uses — it already drives the handshake with a queued-frame fake). The cases:

```python
"""Runner seq/ack version-gate negotiation (Spec A G2) (#237)."""

from __future__ import annotations

import pytest

# Reuse the existing fake transport + session fixtures from the runner test module.
# The fake transport records sent frames + replays queued response frames.


@pytest.mark.asyncio
async def test_both_advertise_flips_transport_on(...) -> None:
    """Host advertises seq_ack; plugin echoes it -> transport enabled."""
    # fake plugin lifecycle.start result includes {"seq_ack": {"version": "1"}}.
    # after start_and_handshake(), assert transport.enable_seq_ack was called
    # (or transport._seq_ack_enabled is True).
    ...


@pytest.mark.asyncio
async def test_plugin_silent_stays_off(...) -> None:
    """Host advertises; plugin omits seq_ack -> transport stays OFF (fallback)."""
    # fake result is {"ok": True, "plugin_version": "..."} (no seq_ack).
    # assert transport stays disabled.
    ...


@pytest.mark.asyncio
async def test_negotiation_does_not_change_id_allocation(...) -> None:
    """seq is additive: the handshake id is still _LIFECYCLE_START_ID; the first
    send_request id is still _FIRST_REQUEST_ID; _pending behaves unchanged."""
    # after a negotiated handshake, issue one send_request and assert the sent
    # frame's "id" == _FIRST_REQUEST_ID (1), proving seq did not perturb id.
    ...
```

> **Implementer note:** mirror the fake-transport handshake setup already in `tests/unit/plugins/test_comms_runner.py` (`_FakeTransport` at `test_comms_runner.py:59`, `_QueueTransport` at `:451`). Both fakes must gain an explicit `def enable_seq_ack(self) -> None` (recording the flip, e.g. `self.seq_ack_enabled = True`) so they satisfy the extended typed `_CommsTransportLike` Protocol — the runner now calls `enable_seq_ack()` as a typed method, not via `getattr`. The both-advertise case asserts `transport.seq_ack_enabled is True`; the plugin-silent case asserts it stays `False`. The load-bearing assertions are the three above; adapt the mechanism to the existing fakes.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/plugins/test_comms_runner_seq_gate.py -q`
Expected: FAIL — the runner does not advertise/negotiate seq_ack yet.

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/plugins/comms_runner.py`:

(a0) **Add `enable_seq_ack` to the `_CommsTransportLike` Protocol (architect F4)** at `comms_runner.py:122`, as the fifth awaitable after `close`:

```python
    async def spawn(self) -> None: ...

    async def send(self, frame: Mapping[str, object]) -> None: ...

    async def read_frame(self) -> Mapping[str, object] | None: ...

    async def close(self) -> None: ...

    def enable_seq_ack(self) -> None: ...
```

> Note: `enable_seq_ack` is SYNC (it just flips a bool), so it is NOT an `async def` like the other four — declare it `def`, matching the concrete transports. Update the Protocol's class docstring's "four awaitables" phrasing to "four awaitables + the sync seq/ack flip". Every test fake that implements `_CommsTransportLike` (the runner test's `_FakeTransport` / `_QueueTransport`) must add an explicit `def enable_seq_ack(self) -> None` that records the flip (e.g. sets `self.seq_ack_enabled = True`) so the typed call resolves — no `getattr` fallback exists anymore.

(a) Add a negotiated flag to `__init__` (`comms_runner.py:149`), after `self._reader_stopped = False` (`comms_runner.py:193`):

```python
        # Spec A G2 (#237): whether the lifecycle.start handshake negotiated the
        # out-of-band seq/ack header. Flipped True only when BOTH the host
        # advertised it AND the plugin echoed it; drives transport.enable_seq_ack.
        self._seq_ack_negotiated = False
```

(b) In `_handshake` (`comms_runner.py:347`), advertise in the `lifecycle.start` params. Change the send (`comms_runner.py:358-365`) `params` to include the capability:

```python
        await self._transport.send(
            {
                "jsonrpc": "2.0",
                "id": _LIFECYCLE_START_ID,
                "method": "lifecycle.start",
                "params": {
                    "adapter_id": self._adapter_id,
                    # Spec A G2 (#237): advertise out-of-band seq/ack support. A
                    # plugin that speaks it echoes the same field in its result;
                    # a plugin that does not omits it and the wire stays plain.
                    "seq_ack": {"version": SEQ_VERSION},
                },
            }
        )
```

(c) After the handshake-ok check passes (`comms_runner.py:376-384`, just before `break` at `comms_runner.py:384`), read the plugin's echo and flip the gate:

```python
                seq_ack = result.get("seq_ack")
                if isinstance(seq_ack, Mapping) and seq_ack.get("version") == SEQ_VERSION:
                    # Both peers speak the wire version — enable the header. The
                    # transport now frames every subsequent send with seq/ack and
                    # strips the header on read. A plugin that omitted the echo
                    # leaves this False and the wire stays plain ADR-0025. The flip
                    # is a TYPED call on the _CommsTransportLike seam (architect F4)
                    # — no getattr duck-typing.
                    self._seq_ack_negotiated = True
                    self._transport.enable_seq_ack()
```

(d) Import `SEQ_VERSION` at the runner module top: `from alfred.plugins.comms_seq_codec import SEQ_VERSION`. (`Mapping` is already imported — `comms_runner.py:50`.)

> **No `_enable_seq_ack_on_transport` helper.** Earlier drafts used `getattr(self._transport, "enable_seq_ack", None)` to defend against a fake transport lacking the method. That is dropped: `enable_seq_ack` is now part of the typed `_CommsTransportLike` Protocol (step a0), so the runner calls it directly and every fake implements it. A shared framing mixin for the per-transport gate-glue (the `_seq_ack_enabled`/`_send_seq` fields + `enable_seq_ack` + the send/read branches) is OPTIONAL — apply it ONLY if it reads cleanly across the two call-sites; otherwise leave the bounded gate-glue duplication with a one-line note pointing at the sibling transport (don't over-engineer a two-site mixin).

(e) **Reference-plugin opt-in** in `plugins/alfred_comms_test/main.py` — `handle_lifecycle_start` (`main.py:124`). Echo the capability ONLY when the host advertised it, so the default-OFF fallback the OTHER adapters rely on is untouched:

```python
def handle_lifecycle_start(_params: dict[str, Any]) -> dict[str, Any]:
    _state["running"] = True
    result: dict[str, Any] = {"ok": True, "plugin_version": _PLUGIN_VERSION}
    # Spec A G2 (#237): echo seq/ack support ONLY when the host advertised it,
    # proving the negotiated-ON path. A host that does not advertise gets the
    # plain result (default-OFF fallback) unchanged.
    advertised = _params.get("seq_ack")
    if isinstance(advertised, dict) and advertised.get("version") == "1":
        result["seq_ack"] = {"version": "1"}
    return result
```

(Change the `_params` name from `_underscore` if it was previously unused — it now reads the advertised capability.)

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/plugins/test_comms_runner_seq_gate.py -q`
Expected: PASS.

- [ ] **Step 5: Run the full runner + reference-plugin suites (prove no regression to id/handshake)**

Run: `uv run pytest tests/unit/plugins/test_comms_runner.py tests/integration -q -k "comms or runner or reference"`
Expected: PASS — the handshake still completes, `id` correlation unchanged, the reference-plugin integration still routes a notification.

- [ ] **Step 6: Type-check + lint + commit**

```bash
uv run mypy src/alfred/plugins/comms_runner.py && uv run pyright src/alfred/plugins/comms_runner.py && uv run ruff check src/alfred/plugins/comms_runner.py plugins/alfred_comms_test/main.py
git add src/alfred/plugins/comms_runner.py plugins/alfred_comms_test/main.py tests/unit/plugins/test_comms_runner_seq_gate.py
git commit -m "feat(comms): version-gate seq/ack at the lifecycle.start handshake (Spec A G2 / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 7: End-to-end negotiated round-trip (integration-style, in-process)

**Files:**

- Test: `tests/unit/plugins/test_comms_seq_codec_e2e.py`

- [ ] **Step 1: Write the test (no production code — proves the whole G2 surface composes)**

Create `tests/unit/plugins/test_comms_seq_codec_e2e.py`. With two `CommsSocketTransport`s over an `asyncio` socket pair (one as host, one as peer), negotiate the gate by directly calling `enable_seq_ack()` on BOTH (simulating a successful handshake), then:

```python
"""End-to-end negotiated seq/ack round-trip across a socket pair (Spec A G2) (#237)."""

# - send three frames host->peer with seq_ack enabled on both ends.
# - assert the peer's read_frame returns the three inner objects in FIFO order
#   with their ids intact.
# - feed the peer's received seqs into a SeqDedupWindow; assert cumulative_ack()
#   == 2 and a replay of all three accepts nothing new (idempotent).
# - flip ONE end OFF mid-stream; assert the still-ON reader falls back to reading
#   the now-plain line (magic-gated decode) without error (mixed-wire safety).
```

- [ ] **Step 2: Run + verify green**

Run: `uv run pytest tests/unit/plugins/test_comms_seq_codec_e2e.py -q`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/plugins/test_comms_seq_codec_e2e.py
git commit -m "test(comms): end-to-end negotiated seq/ack round-trip + dedup-window (Spec A G2 / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 8: ADR-0032 (first cut — codec / wire format) + per-file coverage gate

**Files:**

- Create: `docs/adr/0032-gateway-comms-resume-transport.md`
- Modify: `.github/workflows/ci.yml` (add `comms_seq_codec.py` to the per-file comms coverage gate)

- [ ] **Step 1: Write ADR-0032 (markdownlint MD032-clean — blank line before AND after every list)**

Create `docs/adr/0032-gateway-comms-resume-transport.md`:

```markdown
# ADR-0032 — The comms-resume gateway transport carries an out-of-band seq/ack header

- **Status**: Proposed (first cut — codec / wire-format only; G3/G4 amend)
- **Date**: 2026-06-13
- **Slice**: Spec A (Comms-Resume Gateway) — `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md`
- **Relates to**: ADR-0025 (the line-delimited comms transport this extends), ADR-0031 (the TUI socket carrier), ADR-0033 (core lifecycle signalling / epoch, G1), issue #237 (graduation criterion #7).
- **Supersedes**: —

## Context

The comms-resume gateway (Spec A) fronts dial-in clients with a resumable, payload-blind wire so a core restart never drops the operator or loses in-flight input. The ADR-0025 wire is a thin line-delimited JSON-RPC frame (`json.dumps(frame) + "\n"`) with a per-frame DoS bound (`_MAX_COMMS_LINE_BYTES`) and no notion of sequence, acknowledgement, or replay-dedup. Buffer-and-replay across a restart (G4) needs all three. They cannot live in the JSON-RPC payload: the relay (G3) must forward the body byte-for-byte to stay payload-blind (a T1 carrier, not a trust-tier authority) and to preserve the runner's request/response `id` correlation end-to-end. So the sequence metadata must ride OUT OF BAND, wrapping the opaque payload. The codec needs the existing frame bound + the loud-failure type, which moved into a shared leaf module (`src/alfred/plugins/comms_wire.py`) so the codec and both transports import them from one place rather than closing a codec↔transport import cycle.

## Decision

The following decisions are recorded by G2 (the codec); the gateway, buffer, epoch-auth, shared-volume AF_UNIX, and audit-reconcile decisions the spec §8 also assigns to ADR-0032 are amended in by G3/G4 when those components land. This first cut is scoped to the wire format.

- **Decision 1 — An out-of-band, magic-gated ASCII header wraps the verbatim payload.** A negotiated wire unit is `A1 s=<seq> a=<ack> n=<payload_len> |<opaque-payload>\n` — a single newline-terminated line, so the existing `readline()` reader on both transports is unchanged. `A1` is the magic + wire version. The codec (`src/alfred/plugins/comms_seq_codec.py`) never decodes the payload; it splits the header off and returns the payload bytes untouched.

- **Decision 2 — `seq` is a per-direction monotonic counter, additive to and distinct from the JSON-RPC `id`.** The relay preserves `id` end-to-end (the runner's `_pending`/`_resolve_pending` correlation survives the relay) because the codec touches no payload byte. `seq` is a second, header-level counter.

- **Decision 3 — Cumulative ack = the highest CONTIGUOUS seq durably intaken; the G2 wire ack is an `a=0` placeholder.** A gap does not advance the ack. Acks are coalesced (piggyback + bounded timer) by the sender/relay — there is NO standalone ack per data frame. The G2 transport emits `a=0` as a PLACEHOLDER and deliberately does NOT piggyback a `max(seq seen)` high-water: a high-water would falsely ack PAST gaps, contradicting this contiguous-ack definition. G2 ships the ack VALUE semantics on the PURE, property-tested `SeqDedupWindow.cumulative_ack()`; the G3 relay wires that as the ack source AND owns the coalescing timer. The transport carries `a=0` and consumes no ack.

- **Decision 6 — The header costs payload budget (Option A).** `_MAX_COMMS_LINE_BYTES` is unchanged and bounds the WHOLE unit (header + payload + `\n`). Because the `A1 s=… a=… n=… |` header adds a bounded ASCII prefix, on a NEGOTIATED wire the effective payload ceiling is `max_unit_bytes - _MAX_HEADER_BYTES`, where `_MAX_HEADER_BYTES` is the header's worst-case width (`len("A1 s= a= n= |") + 3 × the decimal width of _MAX_COMMS_LINE_BYTES`). The runtime check is on the OUTER unit; `_MAX_HEADER_BYTES` is the documented reservation the G3 relay sizes payloads against.

- **Decision 4 — Idempotent dedup keyed on `(leg, seq)` ONLY, never payload-derived.** `SeqDedupWindow` is constructed per-leg; a re-seen `(leg, seq)` is dropped idempotently. No header value is derived from payload content — the structural guarantee that the carrier stays payload-blind.

- **Decision 5 — Version-gated at the handshake, default-OFF, mixed-safe; decode is direction-agnostic.** The header is emitted only when both peers advertise `AlfredSeqAck/1` in the `lifecycle.start` capability exchange. The gate flag is per-transport and controls only what `send` EMITS; `decode` is magic-gated and direction-agnostic, so a seq-enabled reader still reads a plain `{`-line from an un-upgraded peer (and vice versa). The runner flips the transport via a TYPED `enable_seq_ack` on the `_CommsTransportLike` Protocol.

## Consequences

### Positive

- The relay can forward the JSON-RPC body verbatim, staying payload-blind, while seq/ack/dedup ride alongside.
- `id` correlation survives the relay untouched; the existing runner is undisturbed.
- The codec is a pure, hypothesis-property-testable unit, decoupled from the gateway/buffer that consume it.

### Negative / accepted

- A second framing concept (the seq header) now layers over ADR-0025. The cost is one small codec; the alternative — an in-band JSON field — would force the relay to parse + re-serialize every frame, breaking payload-blindness and adding a hot-path cost.
- G2 wires the codec into both transports behind the gate but ships NO consumer of ack/dedup. The seq/ack values are computed and carried, not acted on, until G3/G4. Recorded so a later reader does not mistake the unconsumed ack for a bug.

### Scope boundary (this ADR / G2)

G2 ships the codec (`CommsSeqCodec` + `SeqDedupWindow`), the handshake version-gate, and the gate-conditional transport insertion. It builds NO gateway (G3), NO `ReplayBuffer` (G4), NO ack-coalescing timer, NO send-window/back-pressure, and changes NO resume behaviour. The buffer-security, epoch-auth, shared-volume AF_UNIX, and gateway-local audit-reconcile sections the spec assigns to ADR-0032 are amended by G3/G4.
```

- [ ] **Step 2: Add the codec + `comms_wire` to the per-file comms coverage gate (100% line AND branch)**

In `.github/workflows/ci.yml`, there are TWO per-file coverage gates that enumerate the comms transports (the PR-S4-11a "TWO plugins coverage gates" pattern): the `python` job's "plugins trust-boundary 100% coverage" step (the `if: ... hashFiles(...) && ...` guard near line 268 + its `coverage report --include='...,comms_stdio_transport.py,comms_socket_transport.py,comms_runner.py,_comms_child_env.py' --fail-under=100` run near line 271) AND the `coverage-gates` job's mirror (the guard near line 990 + run near line 993). Add BOTH new files to BOTH gates' `hashFiles(...)` guard chains AND both `--include=` lists:

- `src/alfred/plugins/comms_seq_codec.py` (the pure codec + `SeqDedupWindow` — one module)
- `src/alfred/plugins/comms_wire.py` (the Task 0 leaf module)

Because `[tool.coverage.run] branch = true` (pyproject.toml) and the gate runs `coverage report --fail-under=100`, the per-file gate enforces 100% **line AND branch** automatically — the same bar the sibling transports already meet. The codec's decode over-bound + no-delimiter branches (Task 1 tests `test_over_bound_raw_raises_on_decode`, `test_no_delimiter_arm_raises`) and the `SeqDedupWindow` gap/dedup branches (Task 2) drive every branch. Confirm the exact YAML shape before editing — mirror the existing entries' alphabetical-ish ordering exactly, in BOTH gates.

- [ ] **Step 3: Lint the markdown + verify coverage locally**

Run: `uv run pytest tests/unit/plugins/test_comms_seq_codec.py tests/unit/plugins/test_comms_wire.py --cov=alfred.plugins.comms_seq_codec --cov=alfred.plugins.comms_wire --cov-branch --cov-report=term-missing -q`
Expected: PASS with `comms_seq_codec.py` AND `comms_wire.py` at 100% line AND branch (pure modules, fully covered by Tasks 0-2 — `--cov-branch` proves the decode over-bound + no-delim branches and the window gap/dedup branches are all hit).

Run the repo's markdownlint over the new ADR + this plan (the CI gate command — confirm it in the lint workflow; typically `npx markdownlint-cli2` or the repo's `make` target):
Expected: clean (MD032 satisfied — blank lines around every list/table).

- [ ] **Step 4: Commit**

```bash
git add docs/adr/0032-gateway-comms-resume-transport.md .github/workflows/ci.yml
git commit -m "docs(adr): ADR-0032 first cut — out-of-band seq/ack comms codec wire format (Spec A G2) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 9: Full-suite green + quality gates

- [ ] **Step 1: Run the comms + plugins suites**

Run: `uv run pytest tests/unit/plugins tests/unit/comms -q`
Expected: PASS.

- [ ] **Step 2: All quality gates**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/`
Expected: clean.

- [ ] **Step 3: i18n drift check (no new key, but prove the catalog is clean)**

Run: `uv run pybabel extract -F babel.cfg -o /tmp/g2-check.pot src/alfred plugins && uv run pybabel update -i /tmp/g2-check.pot -d locale -D alfred --no-fuzzy-matching && uv run pybabel compile -d locale -D alfred`
Expected: no fuzzy/added strings (G2 adds no operator-facing string — it reuses the existing `comms.transport.malformed_frame` key). NEVER use `--omit-header` (it strips the required header block and trips the drift gate). If `git diff locale/` shows ONLY `#:` location-ref churn, that is acceptable catalog hygiene; commit it. If it shows a NEW msgid, something added an un-catalogued string — investigate.

- [ ] **Step 4: Final commit (only if Step 3 produced location-ref churn)**

```bash
git add locale/
git commit -m "chore(i18n): refresh catalog location refs after G2 codec (Spec A G2) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Self-review: spec requirement -> task map

| Spec requirement (§4/§6/§7/§9 + fleet findings) | Task | How it is satisfied / tested |
| --- | --- | --- |
| Out-of-band header wrapping the opaque payload (NOT in-band JSON) | 1, 8 | `encode_seq_frame` prepends an ASCII header; payload never decoded — round-trip property test asserts `decode(encode(p)).payload == p`. |
| Payload forwarded byte-for-byte (payload-blind relay) | 1 | Codec returns payload bytes untouched; `test_id_inside_payload_is_untouched` + the round-trip property. |
| Per-direction monotonic seq, distinct from + additive to `id` | 1, 6 | Header `s=` counter; `id` lives in the opaque payload; `test_negotiation_does_not_change_id_allocation` proves `id` allocation is unperturbed. |
| `id` preserved end-to-end | 1, 3, 4 | Codec never touches the payload; `test_id_preserved_across_seq_encode_decode`. |
| Cumulative ack = highest CONTIGUOUS seq durably intaken | 2 | `SeqDedupWindow.cumulative_ack`; `test_window_gap_does_not_advance_ack` + `test_property_ack_never_exceeds_contiguous_run`. |
| Acks coalesced (piggyback + bounded timer), NO standalone per-frame ack | 2, 3, 8 | G2 ships the ack VALUE (piggybacked in the header), fires NO timer; the coalescing is deferred to G3 (recorded in ADR-0032 Decision 3 + invariant 4). |
| Idempotent dedup, key = `(leg, seq)` ONLY, never payload-derived | 2 | Per-leg `SeqDedupWindow`; `test_window_drops_reseen_seq_idempotently` + `test_property_replay_is_idempotent`. |
| Version-gated at the handshake; fallback to plain ADR-0025 | 5, 6 | `SeqAckCapability` on `lifecycle.start`; both-advertise flips ON; magic-gated `decode` fallback; `test_plugin_silent_stays_off` + `test_plain_line_without_magic_is_fallback`. |
| `_MAX_COMMS_LINE_BYTES` per-frame bound unchanged | 1, 3, 4 | Codec validates `unit_len <= max_unit_bytes`; `test_over_bound_unit_raises`; bound reused from the stdio transport. |
| Shared codec seam (single-sourced across both transports) | 1, 3, 4 | `comms_seq_codec` is the single framer; both transports call into it (invariant 9). |
| Header is carrier metadata, never payload-derived (trust posture) | 1, 8 | No code path hashes/parses payload for a header value (trust-posture section + invariant 3). |
| Fail-loud on malformed header, content-free errors | 1 | `CommsProtocolError` with no raw bytes; `test_lying_length_raises`, `test_non_integer_seq_raises`. |
| FIFO / ordering preserved | 1, 7 | `test_property_fifo_ordering_preserved` (the PROPERTY — encode `seq=i`, decode all, assert `[f.seq]==range(n)` + payloads in send order); the N=3 `test_comms_seq_codec_e2e` is the e2e SMOKE that the whole surface composes. |
| Pure, hypothesis-property-testable unit | 1, 2 | No I/O / clock / global state; the property tests in Tasks 1-2. |
| No consumer of ack/dedup yet (G2 scope discipline) | all | The codec is wired behind the gate but no relay/buffer acts on the ack; ADR-0032 scope note + invariant 4. |

## Definition of Done

- [ ] `src/alfred/plugins/comms_wire.py` exists: the `_MAX_COMMS_LINE_BYTES` + `CommsProtocolError` leaf module both transports re-export; `python -c "import alfred.plugins.comms_seq_codec"` is cycle-free.
- [ ] `src/alfred/plugins/comms_seq_codec.py` exists: pure `encode_seq_frame`/`decode_seq_frame` + `SeqFrame` + `SeqDedupWindow` + `_MAX_HEADER_BYTES`, single-sourced and imported by both transports; imports the bound from `comms_wire`.
- [ ] Both `CommsStdioTransport` and `CommsSocketTransport` carry a default-OFF `seq_ack_enabled` gate; ON emits the header with an `a=0` PLACEHOLDER ack (NO `_recv_ack` high-water), OFF is byte-for-byte the existing ADR-0025 frame; the existing transport suites pass unchanged.
- [ ] `enable_seq_ack` is on the `_CommsTransportLike` Protocol (typed flip, no `getattr`); the `lifecycle.start` handshake negotiates `AlfredSeqAck/1`; the runner flips the transport ON only when BOTH peers advertise; `id` allocation / `_pending` / `_resolve_pending` are untouched.
- [ ] Hypothesis property tests green: round-trip identity on payload; ack never exceeds the contiguous run; replay idempotency; dedup drops re-seen `(leg, seq)`.
- [ ] FIFO/ordering + mixed-wire fallback proven end-to-end (Task 7).
- [ ] ADR-0032 first cut written (codec/wire-format scope; G3/G4 amend), markdownlint MD032-clean.
- [ ] `comms_seq_codec.py` AND `comms_wire.py` named in BOTH per-file CI coverage gates (the python-job gate + the coverage-gates gate); codec + leaf module at 100% line AND branch.
- [ ] `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/` all clean.
- [ ] No new operator-facing string (the malformed-header path reuses `comms.transport.malformed_frame`); the i18n drift gate is clean.
- [ ] Every commit is a Conventional Commit with `(#237)` in the subject AND the `MrReasonable <4990954+MrReasonable@users.noreply.github.com>` trailer.
- [ ] G2 ships NO gateway, NO ReplayBuffer, NO ack-coalescing timer, NO send-window, NO resume behaviour (scope discipline).
- [ ] An `alfred-security-engineer` review confirms the header-is-carrier-metadata / payload-blind posture before merge (trust-boundary-adjacent change).

## Resolved by the architect+test plan-review (2026-06-13)

The focused architect+security+test plan-review settled the four prior open questions plus four correctness findings. All are now baked into the tasks above:

- **F6 — import cycle:** RESOLVED. Task 0 extracts `comms_wire.py` (the bound + error type) as a leaf module so `comms_seq_codec` ↔ transport is not bidirectional.
- **F1 — bound contract:** RESOLVED as Option A. `_MAX_HEADER_BYTES` is defined; the negotiated payload ceiling is `max_unit_bytes - _MAX_HEADER_BYTES`, documented + boundary-tested (Task 1).
- **F2 — wire ack:** RESOLVED. The transport emits `a=0` placeholder, stores no `_recv_ack`; `SeqDedupWindow.cumulative_ack()` ships fully tested but UNWIRED (the G3 relay wires it).
- **F4 — typed flip:** RESOLVED. `enable_seq_ack` is on the `_CommsTransportLike` Protocol; the `getattr` helper is removed; fakes implement it.
- **ADR number:** RESOLVED. ADR-0032, codec-only first cut, baked into Task 1 docstrings + every commit subject from the start.
- **Header grammar:** RESOLVED — ASCII-prefixed line (keeps the `readline()` reader, mixed-wire-safe via the magic gate). The binary-length-prefix alternative is dropped.
- **Send-window scope:** RESOLVED — DEFERRED to G3/G4 (no sender/consumer in G2; building it now would be the dead-surface mistake G1's review removed).
- **`leg` on the wire:** RESOLVED — `leg` stays OFF the wire and is supplied to `SeqDedupWindow` at construction (single-leg-per-socket holds; spec §11 resolves "one TUI socket to start").
